import asyncio
import ipaddress
import socket
import ssl
import struct
import time
from dataclasses import dataclass


async def close(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, asyncio.TimeoutError):
        pass


async def connect(route, host, port=443):
    """Caller bounds total duration. DNS answers are pinned before connecting."""
    if route["kind"] == "socks5":
        reader, writer = await asyncio.open_connection(route["host"], route["port"])
        try:
            writer.write(b"\x05\x01\x00")  # local SOCKS, no authentication
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise OSError("SOCKS authentication unsupported")
            name = host.encode("ascii")
            writer.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", port))
            await writer.drain()
            head = await reader.readexactly(4)
            if head[:3] != b"\x05\x00\x00":
                raise OSError("SOCKS connect failed")
            if head[3] == 1:
                length = 4
            elif head[3] == 4:
                length = 16
            elif head[3] == 3:
                length = (await reader.readexactly(1))[0]
            else:
                raise OSError("Invalid SOCKS response")
            await reader.readexactly(length + 2)
            return reader, writer
        except BaseException:
            await close(writer)
            raise
    family = {0: socket.AF_UNSPEC, 4: socket.AF_INET, 6: socket.AF_INET6}[route["family"]]
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    last_error = OSError("No public addresses")
    seen = set()
    for af, _, _, _, address in addresses:
        ip = address[0]
        if ip in seen or not ipaddress.ip_address(ip).is_global:
            continue
        seen.add(ip)
        try:
            return await asyncio.wait_for(asyncio.open_connection(ip, port, family=af), 3)
        except OSError as error:
            last_error = error
        except asyncio.TimeoutError:
            last_error = TimeoutError("Address timed out")
    raise last_error


def split_hello(data, host):
    """Split the first plaintext ClientHello record, preserving handshake bytes.

    This experimental TLS record strategy is NOT packet injection or zapret.
    ECH can hide the host; it is never disabled by this program.
    """
    if len(data) < 6 or data[0] != 22 or data[1] != 3 or data[5] != 1:
        return [data]
    size = int.from_bytes(data[3:5], "big")
    if size < 2 or size > 16384 or len(data) < size + 5:
        return [data]
    payload = data[5:5 + size]
    index = payload.find(host.encode("ascii"))
    cut = index + max(1, len(host) // 2) if index >= 0 else min(32, size - 1)
    return [data[:3] + struct.pack("!H", cut) + payload[:cut],
            data[:3] + struct.pack("!H", size - cut) + payload[cut:] + data[5 + size:]]


async def send_first(writer, data, host, split):
    for part in split_hello(data, host) if split else [data]:
        writer.write(part)
        await writer.drain()


class TLSProbe:
    """TLS client via MemoryBIO so probes exercise the same split as tunnels."""
    def __init__(self, reader, writer, host, split, context=None):
        self.reader, self.writer, self.host, self.split = reader, writer, host, split
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = context or ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname=host)
        self.first = True

    async def flush(self):
        data = self.outgoing.read()
        if data:
            await send_first(self.writer, data, self.host, self.first and self.split)
            self.first = False

    async def incoming_data(self):
        data = await self.reader.read(32768)
        if not data:
            raise EOFError("TLS peer closed")
        self.incoming.write(data)

    async def operate(self, operation):
        while True:
            try:
                result = operation()
                await self.flush()
                return result
            except ssl.SSLWantReadError:
                await self.flush()
                await self.incoming_data()
            except ssl.SSLWantWriteError:
                await self.flush()

    async def request(self, path):
        await self.operate(self.tls.do_handshake)
        request = (f"HEAD {path} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\nUser-Agent: Pathfinder-Probe/0.1\r\n\r\n").encode("ascii")
        offset = 0
        while offset < len(request):
            offset += await self.operate(lambda: self.tls.write(request[offset:]))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = await self.operate(lambda: self.tls.read(8192))
            if not chunk:
                raise EOFError("Empty HTTP response")
            response += chunk
            if len(response) > 65536:
                raise ValueError("HTTP headers too large")
        line = response.split(b"\r\n", 1)[0].split()
        if len(line) < 2 or line[0] not in (b"HTTP/1.0", b"HTTP/1.1") or len(line[1]) != 3:
            raise ValueError("Invalid HTTP status")
        return int(line[1])


@dataclass
class ProbeResult:
    ok: bool
    outcome: str
    latency_ms: int
    status: int = None


async def probe(route, service, timeout):
    started = time.monotonic()
    writer = None

    async def run():
        nonlocal writer
        host = service.get("probe_host") or service["domains"][0].removeprefix("*.")
        reader, writer = await connect(route, host)
        tls = TLSProbe(reader, writer, host, route.get("tls_split", False))
        return await tls.request(service.get("probe_path", "/"))

    try:
        status = await asyncio.wait_for(run(), timeout)
        ok = status in service.get("expected_statuses", range(200, 400))
        outcome = "http_reachable" if ok else "http_inconclusive"
    except ssl.SSLCertVerificationError:
        ok, outcome, status = False, "certificate_error", None
    except asyncio.TimeoutError:
        ok, outcome, status = False, "timeout", None
    except socket.gaierror:
        ok, outcome, status = False, "dns_error", None
    except (OSError, EOFError, ValueError):
        ok, outcome, status = False, "transport_error", None
    finally:
        await close(writer)
    return ProbeResult(ok, outcome, int((time.monotonic() - started) * 1000), status)


async def relay(client_reader, client_writer, remote_reader, remote_writer, host, split):
    """Never replay application bytes. Existing tunnels retain their upstream."""
    async def upload():
        if split:
            header = await asyncio.wait_for(client_reader.readexactly(5), 10)
            size = int.from_bytes(header[3:5], "big")
            if header[0] == 22 and header[1] == 3 and 0 < size <= 16384:
                payload = await asyncio.wait_for(client_reader.readexactly(size), 10)
                await send_first(remote_writer, header + payload, host, True)
            else:
                remote_writer.write(header)
                await remote_writer.drain()
        await pump(client_reader, remote_writer)

    async def pump(reader, writer):
        while True:
            data = await asyncio.wait_for(reader.read(65536), 300)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 30)

    tasks = [asyncio.create_task(upload()), asyncio.create_task(pump(remote_reader, client_writer))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        # Allow response data after an upload half-close, but bound cleanup.
        await asyncio.wait_for(asyncio.gather(*pending), 10)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
