"""Owned zapret2 process for the opt-in Windows packet mode."""
import asyncio
import ctypes
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import deque
from pathlib import Path

from .packet_profiles import build_args
from .packet_guard import CHILD_MARKER, ProcessHandle

COMPONENTS = frozenset(("winws2.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys",
                        "lua/zapret-lib.lua", "lua/zapret-antidpi.lua"))


def verify_components(directory, manifest_path=None):
    manifest_path = manifest_path or Path(__file__).with_name("packet_manifest.json")
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    files = manifest.get("files", [])
    if (manifest.get("schema") != 1 or manifest.get("architecture") != "AMD64"
            or len(files) != len(COMPONENTS) or {entry["path"] for entry in files} != COMPONENTS):
        raise RuntimeError("Некорректный список компонентов системного режима")
    for entry in files:
        path = Path(directory) / entry["path"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise RuntimeError(f"Компонент {entry['path']} отсутствует или повреждён. Повторите установку Pathfinder.")
    return manifest


def require_supported(owner_sid=None):
    if os.name != "nt":
        raise RuntimeError("Системный режим работает только в Windows x64")
    arch = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE") or platform.machine()
    if arch.upper() not in ("AMD64", "X86_64"):
        raise RuntimeError("Системный режим доступен только на x64. На ARM64 используйте обычный режим Pathfinder.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Нужны права администратора: запустите Pathfinder.cmd -PacketMode и подтвердите запрос Windows.")
    if owner_sid:
        # A different administrator's HKCU must never consume the original
        # user's proxy backup. UAC consent for the same user is supported.
        command = str(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe")
        try:
            result = subprocess.run([command, "/user", "/fo", "csv", "/nh"], capture_output=True,
                                    timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            rows = list(csv.reader(result.stdout.decode("utf-8", errors="replace").splitlines()))
            matches = result.returncode == 0 and len(rows) == 1 and rows[0][-1] == owner_sid
        except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
            matches = False
        if not matches:
            raise RuntimeError("Запуск под другим пользователем Windows не поддерживается. Нужны права администратора для текущей учётной записи.")


def check_conflicts(ignore_pid=None):
    # Inspect known competing filters. Never kill another tool or stop its service.
    script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); @(Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -in @('winws','winws2','goodbyedpi','ciadpi') } | Select-Object Id,ProcessName) | ConvertTo-Json -Compress"
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise ValueError("process observation failed")
        rows = json.loads(result.stdout.decode("utf-8-sig").strip() or "[]")
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list) or any(not isinstance(row, dict) or type(row.get("Id")) is not int for row in rows):
            raise ValueError("invalid process observation")
        names = [row for row in rows if row["Id"] != ignore_pid]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError("Не удалось проверить другие средства обхода. Системный режим не запущен.") from None
    if names:
        raise RuntimeError("Уже работает zapret / ByeDPI / GoodbyeDPI. Завершите его и прежнее меню Pathfinder перед подбором ALT.")


def require_no_proxy():
    import winreg
    from .system_proxy import REGISTRY_PATH, read_values
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REGISTRY_PATH, 0, winreg.KEY_QUERY_VALUE) as key:
        values = read_values(key)
    if ((values.get("ProxyEnable") or {}).get("value") or (values.get("AutoConfigURL") or {}).get("value")):
        raise RuntimeError("В Windows остался другой прокси или PAC. Отключите его перед запуском системного режима.")


class PacketRunner:
    def __init__(self, direct_domains=None, directory=None):
        self.directory = Path(directory or Path(__file__).resolve().parent.parent / "bin" / "zapret2").resolve()
        self.direct_domains = list(direct_domains or ["*.ru"])
        self.current_profile = None
        self.process = self.reader_task = self.native_handle = None
        self.native_pid = None
        self.output_error = None
        self.error = None
        self.ready = asyncio.Event()
        self.messages = deque(maxlen=24)

    async def preflight(self):
        require_no_proxy()
        owned_pid = self.native_pid if self.native_handle and not self.native_handle.exited() else None
        await asyncio.to_thread(check_conflicts, owned_pid)

    def alive(self):
        return (self.process is not None and self.process.returncode is None
                and (self.native_handle is None or not self.native_handle.exited()))

    async def _read_output(self):
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                message = line[:2048].decode("utf-8", errors="replace").strip()
                if message.startswith(CHILD_MARKER):
                    identity = json.loads(message[len(CHILD_MARKER):])
                    if (self.native_handle is not None or type(identity.get("pid")) is not int
                            or identity["pid"] <= 0 or type(identity.get("created")) is not int):
                        raise ValueError("invalid child identity")
                    handle = ProcessHandle.open(identity["pid"], terminate=True)
                    try:
                        if handle.creation_time() != identity["created"]:
                            raise ValueError("child process identity changed")
                    except BaseException:
                        handle.close()
                        raise
                    self.native_handle, self.native_pid = handle, identity["pid"]
                    continue
                self.messages.append(message)
                if "windivert initialized" in message.lower():
                    self.ready.set()
        except (OSError, ValueError, TypeError, KeyError):
            self.output_error = "Не удалось подтвердить принадлежность процесса обхода"

    async def start(self, profile_id):
        self.error = None
        try:
            require_supported()
            verify_components(self.directory)
            build_args(self.directory, profile_id, self.direct_domains)
        except (OSError, ValueError, RuntimeError) as error:
            self.error = str(error) if isinstance(error, (ValueError, RuntimeError)) else "Не удалось прочитать компоненты системного обхода"
            raise
        await self.stop()
        self.ready = asyncio.Event()
        self.messages.clear()
        self.output_error = None
        parent = None
        try:
            # winws2 creates a UI-restricted Job itself, which cannot be nested
            # in our kill-on-close Job. An independent guard owns its lifecycle.
            parent = ProcessHandle.open(os.getpid(), inheritable=True)
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [parent.value]}
            launch = asyncio.create_task(asyncio.create_subprocess_exec(
                sys.executable, "-u", "-m", "pathfinder.packet_guard", str(parent.value),
                str(self.directory), profile_id, json.dumps(self.direct_domains), cwd=self.directory,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, limit=65536, close_fds=True, startupinfo=startup,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
            try:
                self.process = await asyncio.shield(launch)
            except asyncio.CancelledError:
                # Capture the created guard before cleanup, even when cancellation
                # arrives while asyncio is constructing its subprocess transport.
                self.process = await launch
                raise
            finally:
                parent.close()
                parent = None
            self.reader_task = asyncio.create_task(self._read_output())
            for _ in range(120):
                if self.output_error:
                    raise RuntimeError(self.output_error)
                if not self.alive():
                    raise RuntimeError("winws2 завершился при запуске. Драйвер WinDivert или настройки ALT не приняты Windows.")
                if self.ready.is_set() and self.native_handle:
                    # Lua is initialized just after the driver's startup marker.
                    await asyncio.sleep(0.3)
                    if self.alive() and not self.native_handle.exited():
                        self.current_profile = profile_id
                        return
                    raise RuntimeError("winws2 завершился при загрузке стратегии")
                await asyncio.sleep(0.1)
            raise RuntimeError("WinDivert не подтвердил запуск за 12 секунд")
        except BaseException as error:
            if not isinstance(error, asyncio.CancelledError):
                code = self.process.returncode if self.process else None
                self.error = (str(error) if isinstance(error, RuntimeError) else
                              "Не удалось запустить процесс системного обхода. Проверьте права и компоненты WinDivert.")
                if type(code) is int:
                    self.error += f" Код завершения: {code}."
            await self.stop()
            raise
        finally:
            if parent:
                parent.close()

    async def stop(self):
        process, reader = self.process, self.reader_task
        if process and process.stdin:
            process.stdin.close()  # Guard handles EOF and terminates its child.
        if process:
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), 5)
            except asyncio.TimeoutError:
                # Never kill a guard blindly: its child could remain attached to
                # WinDivert. The retained native handle identifies our exact child.
                if self.native_handle is None:
                    raise RuntimeError("Остановка обхода не подтверждена; завершающий процесс оставлен для очистки")
                self.native_handle.terminate()
                try:
                    await asyncio.wait_for(asyncio.shield(process.wait()), 4)
                except asyncio.TimeoutError:
                    if not self.native_handle.exited():
                        raise RuntimeError("Процесс обхода ещё не завершён")
                    process.terminate()
                    await asyncio.wait_for(process.wait(), 3)
        # Covers unexpected guard exit after its child was identified. Retaining
        # a real handle, rather than opening a PID here, prevents PID-reuse kills.
        if self.native_handle:
            self.native_handle.terminate()
            if not await asyncio.to_thread(self.native_handle.wait, 3):
                raise RuntimeError("Завершение процесса обхода ещё не подтверждено")
            self.native_handle.close()
            self.native_handle = None
        if reader:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        self.process = self.reader_task = None
        self.native_pid = self.current_profile = None
