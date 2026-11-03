import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import time
import zlib
from dataclasses import dataclass

STREAM_LIMIT = 256 * 1024
MAX_PROBE_RESPONSE = 64 * 1024
MAX_PROBE_HEADERS = 16 * 1024
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ProbeFailure(ValueError):
    """A bounded, non-sensitive reason why an application check failed."""
    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


@dataclass
class HTTPResponse:
    status: int
    headers: dict
    body: bytes = b""
    version: str = "HTTP/1.1"
    prefix: bool = False


async def close(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, asyncio.TimeoutError):
        pass


async def connect(route, host, port=443, on_stage=None):
    """Caller bounds total duration. DNS answers are pinned before connecting."""
    mark = on_stage or (lambda stage: None)
    if route["kind"] == "socks5":
        target = b"\x03" + bytes([len(host.encode("ascii"))]) + host.encode("ascii")
        if route.get("local_dpi"):
            # Keep the native worker's blocking DNS resolver out of the data path.
            # Only our async resolver may select a public IPv4 target for it.
            mark("dns")
            addresses = await asyncio.get_running_loop().getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            ip = next((a[4][0] for a in addresses if ipaddress.ip_address(a[4][0]).is_global), None)
            if ip is None:
                raise OSError("No public IPv4 address")
            target = b"\x01" + socket.inet_aton(ip)
        mark("socks_local")
        reader, writer = await asyncio.open_connection(route["host"], route["port"], limit=STREAM_LIMIT)
        try:
            mark("socks_handshake")
            writer.write(b"\x05\x01\x00")  # local SOCKS, no authentication
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise OSError("SOCKS authentication unsupported")
            mark("socks_target")
            writer.write(b"\x05\x01\x00" + target + struct.pack("!H", port))
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
    mark("dns6" if family == socket.AF_INET6 else "dns")
    addresses = await asyncio.get_running_loop().getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    last_error = OSError("No public addresses")
    seen = set()
    mark("tcp")
    for af, _, _, _, address in addresses:
        ip = address[0]
        if ip in seen or not ipaddress.ip_address(ip).is_global:
            continue
        seen.add(ip)
        try:
            return await asyncio.wait_for(asyncio.open_connection(ip, port, family=af, limit=STREAM_LIMIT), 3)
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
        self.status = None
        self.buffer = b""
        self.response_bytes = 0
        self.websocket_key = None

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

    async def read_plain(self):
        remaining = MAX_PROBE_RESPONSE - self.response_bytes
        if remaining <= 0:
            raise ProbeFailure("response_too_large")
        chunk = await self.operate(lambda: self.tls.read(min(8192, remaining)))
        self.response_bytes += len(chunk)
        return chunk

    async def read_until(self, separator, limit, detail):
        while True:
            index = self.buffer.find(separator)
            if index >= 0:
                end = index + len(separator)
                if end > limit:
                    raise ProbeFailure(detail)
                result, self.buffer = self.buffer[:index], self.buffer[end:]
                return result
            if len(self.buffer) >= limit:
                raise ProbeFailure(detail)
            chunk = await self.read_plain()
            if not chunk:
                raise EOFError("Incomplete HTTP response")
            self.buffer += chunk

    async def read_exactly(self, size):
        if size < 0 or size > MAX_PROBE_RESPONSE:
            raise ProbeFailure("response_too_large")
        while len(self.buffer) < size:
            chunk = await self.read_plain()
            if not chunk:
                raise EOFError("Incomplete HTTP body")
            self.buffer += chunk
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result

    @staticmethod
    def parse_headers(raw):
        lines = raw.split(b"\r\n")
        line = lines.pop(0).split(b" ", 2)
        if (len(line) < 2 or line[0] not in (b"HTTP/1.0", b"HTTP/1.1")
                or len(line[1]) != 3 or not line[1].isdigit()
                or not 100 <= int(line[1]) <= 599):
            raise ProbeFailure("invalid_http")
        status = int(line[1])
        headers = {}
        for line in lines:
            name, separator, value = line.partition(b":")
            if (not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    or any(byte < 32 and byte != 9 or byte == 127 for byte in value)):
                raise ProbeFailure("invalid_http")
            name, value = name.decode("ascii").lower(), value.strip().decode("latin-1")
            headers.setdefault(name, []).append(value)
        return status, headers

    def remaining_plain(self):
        """Bytes available within the cap, including already buffered plaintext."""
        return len(self.buffer) + MAX_PROBE_RESPONSE - self.response_bytes

    async def read_body(self, response, allow_prefix=False):
        headers = response.headers
        if response.status in (204, 304) or response.status < 200:
            return b""
        lengths, encodings = headers.get("content-length", []), headers.get("transfer-encoding", [])
        if lengths and encodings:
            raise ProbeFailure("ambiguous_framing")
        if encodings:
            if len(encodings) != 1 or encodings[0].lower() != "chunked":
                raise ProbeFailure("transfer_encoding_unsupported")
            chunks, size = [], 0
            while True:
                try:
                    line = await self.read_until(b"\r\n", 1024, "invalid_chunk")
                except ProbeFailure as error:
                    if allow_prefix and chunks and error.detail == "response_too_large":
                        response.prefix = True
                        break
                    raise
                number = line.split(b";", 1)[0]
                if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", number):
                    raise ProbeFailure("invalid_chunk")
                length = int(number, 16)
                if size + length > MAX_PROBE_RESPONSE and not allow_prefix:
                    raise ProbeFailure("response_too_large")
                if length == 0:
                    # Trailer bytes share the response limit. Reject malformed
                    # trailers instead of accepting a truncated chunk stream.
                    while True:
                        trailer = await self.read_until(b"\r\n", MAX_PROBE_HEADERS, "headers_too_large")
                        if not trailer:
                            break
                        self.parse_headers(b"HTTP/1.1 200 OK\r\n" + trailer)
                    break
                if allow_prefix and length >= self.remaining_plain():
                    # A known marker may be checked in an explicitly partial
                    # response. Stop at the cap before any further HTTP bytes.
                    chunks.append(await self.read_exactly(self.remaining_plain()))
                    response.prefix = True
                    break
                chunks.append(await self.read_exactly(length))
                size += length
                if await self.read_exactly(2) != b"\r\n":
                    raise ProbeFailure("invalid_chunk")
            body = b"".join(chunks)
        elif lengths:
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                raise ProbeFailure("ambiguous_framing")
            length = int(lengths[0])
            if allow_prefix and length > self.remaining_plain():
                length, response.prefix = self.remaining_plain(), True
            body = await self.read_exactly(length)
        else:
            chunks = [self.buffer]
            self.buffer = b""
            while True:
                if allow_prefix and self.response_bytes >= MAX_PROBE_RESPONSE:
                    response.prefix = True
                    break
                chunk = await self.read_plain()
                if not chunk:
                    break
                chunks.append(chunk)
            body = b"".join(chunks)
        content_encodings = headers.get("content-encoding", [])
        if not content_encodings or (len(content_encodings) == 1 and content_encodings[0].lower() == "identity"):
            return body
        if len(content_encodings) != 1 or content_encodings[0].lower() != "gzip":
            raise ProbeFailure("content_encoding_unsupported")
        if response.prefix:
            # A complete small gzip stream can yield a bounded decoded prefix.
            # Partially received compressed streams are not accepted as checks.
            raise ProbeFailure("prefix_encoding_unsupported")
        try:
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = inflater.decompress(body, MAX_PROBE_RESPONSE + 1)
            if len(decoded) > MAX_PROBE_RESPONSE or inflater.unconsumed_tail:
                if allow_prefix:
                    response.prefix = True
                    return decoded[:MAX_PROBE_RESPONSE]
                raise ProbeFailure("response_too_large")
            if not inflater.eof or inflater.unused_data:
                raise ProbeFailure("invalid_gzip")
            return decoded
        except zlib.error as error:
            raise ProbeFailure("invalid_gzip") from error

    async def request_response(self, path, on_stage=None, port=443, method="HEAD", read_statuses=None,
                               allow_prefix=False):
        mark = on_stage or (lambda stage: None)
        if method not in ("HEAD", "GET", "WSS"):
            raise ProbeFailure("method_unsupported")
        if not isinstance(path, str) or not path.startswith("/") or any(ord(char) <= 32 or ord(char) == 127 for char in path):
            raise ProbeFailure("invalid_path")
        mark("tls")
        await self.operate(self.tls.do_handshake)
        mark("http")
        authority = self.host if port == 443 else f"{self.host}:{port}"
        verb = "GET" if method == "WSS" else method
        headers = [f"{verb} {path} HTTP/1.1", f"Host: {authority}",
                   "User-Agent: Pathfinder-Probe/0.3", "Accept-Encoding: identity"]
        if method == "WSS":
            self.websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
            headers.extend(["Connection: Upgrade", "Upgrade: websocket",
                            f"Sec-WebSocket-Key: {self.websocket_key}", "Sec-WebSocket-Version: 13"])
        else:
            headers.append("Connection: close")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
        offset = 0
        while offset < len(request):
            offset += await self.operate(lambda: self.tls.write(request[offset:]))
        for _ in range(5):
            raw = await self.read_until(b"\r\n\r\n", MAX_PROBE_HEADERS, "headers_too_large")
            status, response_headers = self.parse_headers(raw)
            self.status = status
            if status == 101 or status >= 200:
                break
        else:
            raise ProbeFailure("too_many_interim_responses")
        response = HTTPResponse(status, response_headers, version=raw.split(b" ", 1)[0].decode("ascii"))
        if method == "GET" and (read_statuses is None or status in read_statuses):
            response.body = await self.read_body(response, allow_prefix=allow_prefix)
        return response

    async def request(self, path, on_stage=None, port=443):
        """Keep the original status-only HEAD API for proxy integration callers."""
        response = await self.request_response(path, on_stage, port)
        return response.status

    def websocket_valid(self, response):
        if response.status != 101 or response.version != "HTTP/1.1" or not self.websocket_key:
            return False
        headers = response.headers
        upgrades = ",".join(headers.get("upgrade", [])).lower().split(",")
        connections = ",".join(headers.get("connection", [])).lower().split(",")
        accept = headers.get("sec-websocket-accept", [])
        expected = base64.b64encode(hashlib.sha1((self.websocket_key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        return ("websocket" in [value.strip() for value in upgrades]
                and "upgrade" in [value.strip() for value in connections]
                and "sec-websocket-protocol" not in headers
                and "sec-websocket-extensions" not in headers
                and accept == [expected])


@dataclass
class ProbeResult:
    ok: bool
    outcome: str
    latency_ms: int
    status: int = None
    stage: str = ""
    detail: str = ""


async def probe(route, service, timeout):
    started = time.monotonic()
    writer = None
    tls = None
    status = None
    detail = ""
    stage = "connect"

    def mark(value):
        nonlocal stage
        stage = value

    async def run():
        nonlocal writer, tls
        if ("body_contains" in service and not isinstance(service["body_contains"], str)
                or "json_keys" in service and (not isinstance(service["json_keys"], list)
                    or not all(isinstance(key, str) for key in service["json_keys"]))):
            raise ProbeFailure("invalid_check")
        allow_prefix = service.get("allow_prefix", False)
        if not isinstance(allow_prefix, bool) or (allow_prefix and
                (service.get("probe_method") != "GET" or not service.get("body_contains") or "json_keys" in service)):
            raise ProbeFailure("invalid_check")
        host = service.get("probe_host") or service["domains"][0].removeprefix("*.")
        port = service.get("port", 443)
        reader, writer = await connect(route, host, port, on_stage=mark)
        tls = TLSProbe(reader, writer, host, route.get("tls_split", False))
        return await tls.request_response(service.get("probe_path", "/"), on_stage=mark, port=port,
                                          method=service.get("probe_method", "HEAD"),
                                          read_statuses=service.get("expected_statuses", range(200, 300)),
                                          allow_prefix=allow_prefix)

    try:
        response = await asyncio.wait_for(run(), timeout)
        status = response.status
        method = service.get("probe_method", "HEAD")
        expected = service.get("expected_statuses", range(200, 400) if method == "HEAD" else range(200, 300))
        ok = status in expected
        outcome = "http_reachable" if ok else "http_inconclusive"
        if method == "WSS":
            ok = tls.websocket_valid(response)
            outcome = "websocket_ok" if ok else "http_denied" if status >= 400 else "content_mismatch"
            detail = "websocket_upgrade_valid" if ok else "websocket_upgrade_invalid"
        elif method == "GET":
            outcome = "functional_ok" if ok else "http_denied" if status >= 400 else "content_mismatch"
            detail = "response_valid" if ok else "status_not_expected"
            if ok and "body_contains" in service and service["body_contains"].encode("utf-8") not in response.body:
                ok, outcome, detail = False, "content_mismatch", "body_marker_missing"
            if ok and "json_keys" in service:
                try:
                    payload = json.loads(response.body)
                except (ValueError, UnicodeError, RecursionError):
                    ok, outcome, detail = False, "content_mismatch", "invalid_json"
                else:
                    if not isinstance(payload, dict) or not all(key in payload for key in service["json_keys"]):
                        ok, outcome, detail = False, "content_mismatch", "json_keys_missing"
            if ok and response.prefix:
                outcome, detail = "content_prefix_ok", "validated_prefix"
        elif not ok and "expected_statuses" not in service and service.get("probe_path", "/") == "/" and status in (400, 401, 404, 405, 409, 410, 429):
            # A root HEAD rejection is not a transport failure. Let the real
            # authenticated request proceed on this route without probing others.
            ok, outcome = True, "http_response"
    except ssl.SSLCertVerificationError:
        ok, outcome, status, detail = False, "certificate_error", None, "certificate_invalid"
    except ProbeFailure as error:
        ok, outcome, detail = False, "content_mismatch", error.detail
    except asyncio.TimeoutError:
        ok, outcome, detail = False, f"{stage}_timeout", "timeout"
    except socket.gaierror:
        ok, outcome, detail = False, f"{stage}_error", "dns_failed"
    except (OSError, EOFError, ValueError):
        ok, outcome, detail = False, f"{stage}_error", "response_incomplete" if stage == "http" else "connection_failed"
    finally:
        if status is None and tls is not None:
            status = tls.status
        await close(writer)
    return ProbeResult(ok, outcome, int((time.monotonic() - started) * 1000), status, stage, detail)


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
            data = await asyncio.wait_for(reader.read(STREAM_LIMIT), 300)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            writer.write(data)
            if writer.transport.get_write_buffer_size():
                # A blocked peer still has a bounded drain. Avoid allocating a
                # timer/task for every block when the socket accepted it at once.
                await asyncio.wait_for(writer.drain(), 30)
            else:
                await writer.drain()

    tasks = [asyncio.create_task(upload()), asyncio.create_task(pump(remote_reader, client_writer))]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        # A client half-close must not cut off a long download after ten seconds.
        # The download pump retains its per-read idle timeout and backpressure.
        if tasks[1] in pending:
            await tasks[1]
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
