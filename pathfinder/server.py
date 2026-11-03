import asyncio
import hmac
import json
import re
import time
from .config import hostname
from .engine import NoRoute
from .transport import close, connect, relay


async def read_request(reader):
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
    if len(raw) > 16384:
        raise ValueError("Headers too large")
    lines = raw.decode("iso-8859-1").split("\r\n")
    method, target, version = lines[0].split(" ")
    if version != "HTTP/1.1":
        raise ValueError("HTTP/1.1 required")
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, value = line.split(":", 1)
        name = name.lower()
        if not re.fullmatch(r"[a-z0-9-]+", name) or name in headers:
            raise ValueError("Duplicate or invalid header")
        headers[name] = value.strip()
    if "transfer-encoding" in headers:
        raise ValueError("Chunked request unsupported")
    length = int(headers.get("content-length", "0"))
    if not 0 <= length <= 16384:
        raise ValueError("Body too large")
    return method, target, headers, length


async def respond(writer, status, data, origin=None):
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    reason = {200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
              405: "Method Not Allowed", 409: "Conflict", 502: "Bad Gateway", 503: "Service Unavailable"}.get(status, "Error")
    if status == 204:
        body = b""
    headers = f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
    if origin:
        headers += f"Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\n"
    writer.write(headers.encode("ascii") + b"\r\n" + body)
    await writer.drain()


class Servers:
    def __init__(self, engine, token):
        self.engine, self.token = engine, token
        self.connections = 0
        self.api_connections = 0
        self.tasks = set()

    async def proxy(self, reader, writer):
        remote = None
        lease = None
        established = False
        self.connections += 1
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            if self.connections > 64:
                await respond(writer, 503, {"error": "Too many connections"})
                return
            method, target, headers, length = await read_request(reader)
            if method != "CONNECT" or length:
                await respond(writer, 405, {"error": "Only HTTPS CONNECT supported"})
                return
            name, sep, port = target.rpartition(":")
            if not sep or port != "443":
                raise ValueError("Only HTTPS port 443 supported")
            name = hostname(name)
            if not self.engine.service(name):
                await respond(writer, 403, {"error": "Domain is not enrolled"})
                return
            key, route, changed = await self.engine.acquire(name)
            lease = key
            try:
                remote_reader, remote = await asyncio.wait_for(connect(route, name), self.engine.config.data["probe_timeout"])
            except (OSError, asyncio.TimeoutError, EOFError):
                await self.engine.report(name, "transport_error", time.time(), key=key, route_id=route["id"])
                raise NoRoute("Не удалось открыть выбранный путь")
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            established = True
            # No HTTP parsing/decryption beyond this point, including on error.
            await relay(reader, writer, remote_reader, remote, name, route.get("tls_split", False))
        except NoRoute as error:
            if not established:
                await respond(writer, 502, {"error": str(error)})
        except (ValueError, asyncio.LimitOverrunError):
            if not established:
                await respond(writer, 400, {"error": "Invalid request"})
        except (OSError, EOFError, asyncio.TimeoutError):
            pass
        finally:
            if lease:
                self.engine.release(lease)
            await close(remote)
            await close(writer)
            self.connections -= 1
            self.tasks.discard(task)

    async def api(self, reader, writer):
        origin = None
        self.api_connections += 1
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            if self.api_connections > 12:
                await respond(writer, 503, {"error": "API busy"})
                return
            method, target, headers, length = await read_request(reader)
            expected_host = f"127.0.0.1:{self.engine.config.data['api_port']}"
            if headers.get("host") != expected_host:
                await respond(writer, 403, {"error": "Invalid Host"})
                return
            incoming_origin = headers.get("origin")
            if incoming_origin:
                if not re.fullmatch(r"chrome-extension://[a-p]{32}", incoming_origin):
                    await respond(writer, 403, {"error": "Origin is not a browser extension"})
                    return
                origin = incoming_origin
            if method == "OPTIONS":
                await respond(writer, 204, {}, origin)
                return
            if method == "GET" and target == "/proxy.pac":
                from .system_proxy import pac_script
                body = pac_script(self.engine.config.data).encode("ascii")
                writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {len(body)}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".encode() + body)
                await writer.drain()
                return
            authorization = headers.get("authorization", "")
            if not hmac.compare_digest(authorization.encode(), ("Bearer " + self.token).encode()):
                await respond(writer, 401, {"error": "Неверный ключ подключения"}, origin)
                return
            if method == "GET" and target == "/status":
                await respond(writer, 200, self.engine.snapshot(), origin)
                return
            if method != "POST":
                await respond(writer, 405, {"error": "Method unsupported"}, origin)
                return
            body = await asyncio.wait_for(reader.readexactly(length), 5)
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("JSON object required")
            if target == "/services":
                self.engine.config.add(data.get("host"))
                result = self.engine.snapshot()
            elif target == "/recover":
                result = {"route": await self.engine.recover(hostname(data.get("host")))}
            elif target == "/scan":
                result = {"results": await self.engine.scan(hostname(data.get("host")))}
            elif target == "/socks":
                self.engine.config.set_socks(data.get("port"))
                result = {"ok": True}
            elif target == "/event":
                outcome = data.get("outcome")
                if outcome not in ("success", "transport_error", "http_inconclusive"):
                    raise ValueError("Invalid outcome")
                started = float(data.get("started", 0))
                if not time.time() - 600 <= started <= time.time() + 5:
                    raise ValueError("Stale event")
                status = data.get("status")
                if status is not None and (type(status) is not int or not 100 <= status <= 599):
                    raise ValueError("Invalid HTTP status")
                if data.get("network") != self.engine.network:
                    result = {"ignored": "network_changed"}
                else:
                    await self.engine.report(hostname(data.get("host")), outcome, started, status)
                    result = {"ok": True}
            else:
                await respond(writer, 404, {"error": "Unknown endpoint"}, origin)
                return
            await respond(writer, 200, result, origin)
        except NoRoute as error:
            await respond(writer, 503, {"error": str(error)}, origin)
        except (ValueError, TypeError, KeyError, UnicodeError, asyncio.LimitOverrunError):
            await respond(writer, 400, {"error": "Некорректный запрос"}, origin)
        except (OSError, EOFError, asyncio.TimeoutError):
            pass
        finally:
            await close(writer)
            self.api_connections -= 1
            self.tasks.discard(task)

    async def shutdown(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
