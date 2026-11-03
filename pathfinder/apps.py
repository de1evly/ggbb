"""Observe Windows desktop apps and request a reversible Discord proxy launch.

An observed command-line flag describes the requested setting, not successful
network traffic. No application is downloaded, stopped, or permanently changed.
"""
import json
import os
from pathlib import Path
import platform
import re
import subprocess


_DISCORD_VARIANTS = (
    ("Discord", "Discord.exe"),
    ("DiscordPTB", "DiscordPTB.exe"),
    ("DiscordCanary", "DiscordCanary.exe"),
)
_DISCORD_NAMES = {name.casefold() for _, name in _DISCORD_VARIANTS}
_VERSION = re.compile(r"app-(\d+(?:\.\d+){1,3})", re.IGNORECASE)
# Fixed script: caller values and application command lines are never executed.
# Raw command lines stay in memory and never appear in returned diagnostics.
_PROCESS_SCRIPT = """$ErrorActionPreference = 'Stop';
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false);
$items = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='Discord.exe' OR Name='DiscordPTB.exe' OR Name='DiscordCanary.exe' OR Name='ChatGPT.exe'" | Select-Object Name, ProcessId, CommandLine);
$owners = $null;
try {
  $port = [int]$env:PATHFINDER_PROXY_OBSERVE_PORT;
  $sockets = @(Get-NetTCPConnection -ErrorAction Stop);
  $owners = @($sockets | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq $port } | Select-Object -ExpandProperty OwningProcess);
} catch { $owners = $null; }
[PSCustomObject]@{ Processes = $items; ProxyOwners = $owners } | ConvertTo-Json -Compress -Depth 4
"""


def _port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("Некорректный порт локального прокси")
    return value


def _installations():
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return []
    found = []
    for variant, executable in _DISCORD_VARIANTS:
        base = Path(local) / variant
        try:
            candidates = list(base.glob("app-*/" + executable))
        except OSError:
            continue
        versions = []
        for candidate in candidates:
            match = _VERSION.fullmatch(candidate.parent.name)
            try:
                if match and candidate.is_file():
                    version = tuple(int(part) for part in match[1].split("."))
                    versions.append((version, candidate))
            except OSError:
                continue
        if versions:
            # Numeric comparison avoids launching 1.0.9 over 1.0.10.
            _, candidate = max(versions, key=lambda item: item[0])
            found.append((variant, candidate))
    return found


def _process_snapshot(proxy_port):
    proxy_port = _port(proxy_port)
    powershell = (Path(os.environ.get("SystemRoot", r"C:\Windows")) /
                  "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    try:
        environment = os.environ.copy()
        environment["PATHFINDER_PROXY_OBSERVE_PORT"] = str(proxy_port)
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", _PROCESS_SCRIPT],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            shell=False, env=environment,
        )
        if len(result.stdout) > 2_000_000:
            return None
        snapshot = json.loads(result.stdout.decode("utf-8-sig"))
        if not isinstance(snapshot, dict):
            return None
        rows = snapshot.get("Processes")
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            return None
        valid_names = _DISCORD_NAMES | {"chatgpt.exe"}
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("Name"), str)
                    or row["Name"].casefold() not in valid_names
                    or isinstance(row.get("ProcessId"), bool)
                    or not isinstance(row.get("ProcessId"), int)
                    or row["ProcessId"] <= 0
                    or not isinstance(row.get("CommandLine"), (str, type(None)))):
                return None
        owners = snapshot.get("ProxyOwners")
        if owners is not None and (not isinstance(owners, list)
                                   or any(isinstance(pid, bool) or not isinstance(pid, int)
                                          or pid <= 0 for pid in owners)):
            return None
        return {"processes": rows, "proxy_owners": owners}
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return None


def _switch_values(command_line, name):
    # Handles the normal --switch=value and --switch="value" CLI forms, plus
    # a separately quoted whole argument. Values are inspected, never executed.
    pattern = r'(?:^|\s)"?--' + re.escape(name) + r'(?:=|\s+)(?:"([^"\r\n]*)"|([^\s"\r\n]+))'
    return [match[1] if match[1] is not None else match[2]
            for match in re.finditer(pattern, command_line, re.IGNORECASE)]


def _has_switch(command_line, name):
    return bool(re.search(r'(?:^|\s)"?--' + re.escape(name) + r'(?:[=\s"]|$)',
                          command_line, re.IGNORECASE))


def _proxy_observation(rows, proxy_port):
    if rows is None:
        return "unknown"
    if not rows:
        return "not_running"
    main = [row for row in rows if not row.get("CommandLine")
            or not _has_switch(row["CommandLine"], "type")]
    if not main:
        return "unknown"
    observed = set()
    accepted = {f"127.0.0.1:{proxy_port}", f"http://127.0.0.1:{proxy_port}"}
    for row in main:
        command_line = row.get("CommandLine")
        if not command_line:
            observed.add("unknown")
        elif _has_switch(command_line, "no-proxy-server"):
            observed.add("disabled")
        else:
            values = _switch_values(command_line, "proxy-server")
            if not values:
                observed.add("no_explicit_proxy")
            elif len(values) == 1 and values[0].lower() in accepted:
                observed.add("explicit_local")
            else:
                observed.add("different_proxy")
    return next(iter(observed)) if len(observed) == 1 else "mixed"


def inspect_apps(proxy_port):
    """Return JSON-safe observations, with None for unavailable running state.

    ``explicit_local`` means the expected launch flag was observed. Conversely,
    ``no_explicit_proxy`` does not prove bypassing the Windows system proxy.
    ``proxy_connection_observed`` records an established TCP socket from a known
    app PID to our loopback proxy, not successful service requests. False means
    no such socket at this instant; None means observation was unavailable.
    ChatGPT has no supported proxy launcher here; installed=None means unknown.
    """
    proxy_port = _port(proxy_port)
    supported = platform.system() == "Windows"
    installed = _installations() if supported else []
    snapshot = _process_snapshot(proxy_port) if supported else None
    rows = snapshot["processes"] if snapshot is not None else None
    owners = snapshot["proxy_owners"] if snapshot is not None else None
    discord = None if rows is None else [row for row in rows
                                             if row["Name"].casefold() in _DISCORD_NAMES]
    chatgpt = None if rows is None else [row for row in rows
                                             if row["Name"].casefold() == "chatgpt.exe"]
    def socket_observed(processes):
        if processes is None or owners is None:
            return None
        return any(row["ProcessId"] in owners for row in processes)
    return {
        "supported": supported,
        "process_check": "ok" if snapshot is not None else "unavailable",
        "discord": {
            "installed": bool(installed),
            "installation_scope": "LOCALAPPDATA",
            "variants": [variant for variant, _ in installed],
            "running": bool(discord) if discord is not None else None,
            "proxy": _proxy_observation(discord, proxy_port),
            "proxy_connection_observed": socket_observed(discord),
            "traffic_verified": False,
            "launch_supported": supported,
        },
        "chatgpt": {
            "installed": True if chatgpt else None,
            "running": bool(chatgpt) if chatgpt is not None else None,
            "proxy": "unknown",
            "proxy_connection_observed": socket_observed(chatgpt),
            "traffic_verified": False,
            "launch_supported": False,
        },
    }


def launch_discord(proxy_port):
    """Launch an installed, closed Discord with explicit HTTP proxy flags.

    Existing processes are never terminated. Closing this Discord instance and
    launching the usual shortcut restores its usual launch configuration. The
    flags cover Electron HTTP(S)/WebSocket traffic, not UDP voice transport.
    """
    proxy_port = _port(proxy_port)
    if platform.system() != "Windows":
        return {"status": "unavailable", "message": "Запуск Discord через прокси доступен в Windows"}
    state = inspect_apps(proxy_port)
    discord = state["discord"]
    if discord["running"] is None:
        return {"status": "observation_failed", "message": "Не удалось проверить процессы Discord. Запуск не выполнен"}
    if discord["running"]:
        if discord["proxy"] == "explicit_local":
            return {"status": "already_configured", "message": "У запущенного Discord найден параметр нашего прокси; работа приложения ещё не подтверждена",
                    "traffic_verified": False}
        return {"status": "restart_required", "message": "Полностью закройте Discord через трей, затем повторите запуск через Pathfinder"}
    installed = _installations()
    if not installed:
        return {"status": "not_installed", "message": "Установленный Discord не найден в LOCALAPPDATA"}
    variant, executable = installed[0]
    try:
        subprocess.Popen(
            [str(executable), f"--proxy-server=http://127.0.0.1:{proxy_port}",
             "--proxy-bypass-list=<local>;*.ru"],
            cwd=str(executable.parent), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True, shell=False,
        )
    except OSError:
        return {"status": "launch_failed", "message": "Не удалось запустить установленный Discord"}
    return {"status": "launched", "variant": variant, "traffic_verified": False,
            "message": "Discord запущен с параметром локального прокси. Загрузка приложения и голос ещё не проверены"}
