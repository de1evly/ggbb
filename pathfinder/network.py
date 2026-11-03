"""Local network fingerprint; never sends network identifiers to a remote service."""
import asyncio
import hashlib
import json
import platform
from pathlib import Path


async def detect_network(label=""):
    if label:
        raw = "manual:" + label
    elif platform.system() == "Windows":
        script = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -or $_.IPv6DefaultGateway } | Sort-Object InterfaceAlias | ForEach-Object { [PSCustomObject]@{ Interface=$_.InterfaceAlias; Profile=$_.NetProfile.Name; Gateway4=$_.IPv4DefaultGateway.NextHop; Gateway6=$_.IPv6DefaultGateway.NextHop; DNS=$_.DNSServer.ServerAddresses } } | ConvertTo-Json -Compress"
        proc = await asyncio.create_subprocess_exec("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
                                                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), 10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError("Не удалось определить сеть: задайте network_label в config.json")
        if proc.returncode or not out.strip():
            raise RuntimeError("Не удалось определить сеть: задайте network_label в config.json")
        raw = json.dumps(json.loads(out.decode("utf-8-sig")), sort_keys=True)
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
