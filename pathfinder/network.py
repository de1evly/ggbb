"""Local network fingerprint; never sends network identifiers to a remote service."""
import asyncio
import hashlib
import ipaddress
import json
import platform
from pathlib import Path


WINDOWS_NETWORK_SCRIPT = """[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway } | ForEach-Object {
    [PSCustomObject]@{
        InterfaceIndex=$_.InterfaceIndex
        Interface=$_.InterfaceAlias
        Profile=$_.NetProfile.Name
        Gateway4=@($_.IPv4DefaultGateway.NextHop)
        Gateway6=@($_.IPv6DefaultGateway.NextHop)
        DNS=@($_.DNSServer.ServerAddresses)
    }
} | ConvertTo-Json -Depth 5 -Compress
"""


def _address_set(value):
    """PowerShell may unwrap one value or nest IPv4/IPv6 address arrays."""
    if value is None or value == "":
        return set()
    if isinstance(value, list):
        result = set()
        for item in value:
            result.update(_address_set(item))
        return result
    if not isinstance(value, str):
        raise ValueError("invalid network address")
    value = value.strip()
    if not value:
        return set()
    address = ipaddress.ip_address(value)
    # Canonical IPv6 spelling, including a numeric interface scope if present.
    canonical = str(address)
    base, separator, scope = canonical.partition("%")
    if separator and scope.isdecimal():
        canonical = base + "%" + str(int(scope))
    return {canonical}


def _windows_network_material(payload):
    """Normalize enumeration noise without merging distinct network paths.

    Interface aliases and NLA connectivity indicators are display state. An
    interface index identifies the local adapter; the profile name remains part
    of the key because two Wi-Fi networks can share adapter, gateway and DNS.
    Gateway and resolver *sets* matter, not their PowerShell enumeration order.
    """
    rows = payload if isinstance(payload, list) else [payload]
    interfaces = {}
    for row in rows:
        if row is None:
            continue
        if not isinstance(row, dict):
            raise ValueError("invalid network interface")
        gateway4 = _address_set(row.get("Gateway4"))
        gateway6 = _address_set(row.get("Gateway6"))
        if not gateway4 and not gateway6:
            continue
        index = row.get("InterfaceIndex")
        if index is not None:
            if isinstance(index, bool) or not isinstance(index, (str, int)) or str(index).strip() == "":
                raise ValueError("invalid interface index")
            index = int(index)
            if index <= 0:
                raise ValueError("invalid interface index")
            identity = ("index", index)
        else:
            # Also accept the previous helper's output for diagnostics/tests.
            alias = row.get("Interface")
            if not isinstance(alias, str) or not alias.strip():
                raise ValueError("missing interface identity")
            identity = ("alias", alias.strip())
        profile = row.get("Profile") or ""
        if not isinstance(profile, str):
            raise ValueError("invalid network profile")
        key = (identity, profile)
        record = interfaces.setdefault(key, {"Gateway4": set(), "Gateway6": set(), "DNS": set()})
        record["Gateway4"].update(gateway4)
        record["Gateway6"].update(gateway6)
        record["DNS"].update(_address_set(row.get("DNS")))
    if not interfaces:
        raise ValueError("no default network interface")
    records = []
    for (identity, profile), values in interfaces.items():
        record = {"Interface": identity, "Profile": profile}
        record.update({name: sorted(addresses) for name, addresses in values.items()})
        records.append(record)
    records.sort(key=lambda row: json.dumps(row, sort_keys=True))
    return json.dumps({"version": 2, "interfaces": records}, sort_keys=True, separators=(",", ":"))


async def detect_network(label=""):
    if label:
        raw = "manual:" + label
    elif platform.system() == "Windows":
        proc = await asyncio.create_subprocess_exec("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_NETWORK_SCRIPT,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), 10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("Не удалось определить сеть: задайте network_label в config.json")
        if proc.returncode or not out.strip():
            raise RuntimeError("Не удалось определить сеть: задайте network_label в config.json")
        try:
            raw = _windows_network_material(json.loads(out.decode("utf-8-sig")))
        except (ValueError, TypeError, UnicodeError):
            raise RuntimeError("Не удалось определить сеть: задайте network_label в config.json") from None
    else:
        parts = []
        for name in ("/proc/net/route", "/proc/net/ipv6_route", "/etc/resolv.conf"):
            try:
                lines = Path(name).read_text().splitlines()
                # Drop dynamic refcounts/use counters from Linux routes.
                if name.endswith("/route"):
                    lines = [" ".join(line.split()[:4]) for line in lines[1:] if len(line.split()) > 3 and line.split()[1] == "00000000"]
                elif name.endswith("ipv6_route"):
                    lines = [" ".join(line.split()[:5] + line.split()[-1:]) for line in lines if len(line.split()) >= 10 and line.split()[1] == "00"]
                else:
                    lines = [line for line in lines if line.startswith("nameserver")]
                parts.extend(sorted(lines))
            except OSError:
                pass
        if not parts:
            raise RuntimeError("Задайте network_label для этой ОС")
        raw = "\n".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]
