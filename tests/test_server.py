import asyncio
import json
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pathfinder.config import Config
from pathfinder.engine import Engine
from pathfinder.server import Servers
from pathfinder.store import Store
from pathfinder.transport import TLSProbe, ProbeResult, close, connect, probe


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = Config(self.root / "config.json")
        self.config.data["bypass_only"] = False
        self.store = Store(self.root / "state.sqlite3")
        async def good(*args):
            return ProbeResult(True, "http_reachable", 1, 200)
        self.engine = Engine(self.config, self.store, "test-network", good)
        self.handlers = Servers(self.engine, "a" * 40)
        self.api = await asyncio.start_server(self.handlers.api, "127.0.0.1", 0)
        self.proxy = await asyncio.start_server(self.handlers.proxy, "127.0.0.1", 0)
        self.port = self.api.sockets[0].getsockname()[1]
        self.proxy_port = self.proxy.sockets[0].getsockname()[1]
        self.config.data["api_port"] = self.port
        self.config.data["proxy_port"] = self.proxy_port

    async def asyncTearDown(self):
        self.api.close()
        self.proxy.close()
        await self.api.wait_closed()
        await self.proxy.wait_closed()
        await self.handlers.shutdown()
        self.store.close()
        self.tmp.cleanup()

    async def request(self, path="/status", token=None, origin=None, host=None, method="GET", data=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        body = json.dumps(data).encode() if data is not None else b""
        headers = f"{method} {path} HTTP/1.1\r\nHost: {host or f'127.0.0.1:{self.port}'}\r\nContent-Length: {len(body)}\r\n"
        if token:
            headers += f"Authorization: Bearer {token}\r\n"
        if origin:
            headers += f"Origin: {origin}\r\n"
        writer.write(headers.encode() + b"\r\n" + body)
        await writer.drain()
        result = await asyncio.wait_for(reader.read(), 3)
        await close(writer)
        return result

    async def test_api_requires_token(self):
        self.assertIn(b"401 Unauthorized", await self.request())
        self.assertIn(b"200 OK", await self.request(token="a" * 40))

    async def test_web_origin_and_dns_rebinding_rejected(self):
        self.assertIn(b"403 Forbidden", await self.request(token="a" * 40, origin="https://evil.example"))
        self.assertIn(b"403 Forbidden", await self.request(token="a" * 40, host="evil.example"))

    async def test_extension_origin_preflight_and_authenticated_request(self):
        origin = "chrome-extension://" + "a" * 32
        self.assertIn(b"204 No Content", await self.request(method="OPTIONS", origin=origin))
        self.assertIn(b"Access-Control-Allow-Origin: " + origin.encode(), await self.request(token="a" * 40, origin=origin))

    async def test_pac_available_without_token_but_no_control_access(self):
        response = await self.request("/proxy.pac")
        self.assertIn(b"application/x-ns-proxy-autoconfig", response)
        self.assertIn(b"FindProxyForURL", response)
        self.assertNotIn(b"a" * 40, response)
        versioned = await self.request("/proxy.pac?v=0.1.1")
        self.assertIn(b"200 OK", versioned)
        self.assertIn(b"*.ru", versioned)
        self.assertNotIn(b"userapi.com", versioned)

    async def test_auto_scan_api_applies_routes_and_status_exposes_progress(self):
        denied = await self.request("/auto-scan", method="POST", data={"target": "example.com"})
        self.assertIn(b"401 Unauthorized", denied)
        started = await self.request("/auto-scan", token="a" * 40, method="POST", data={"target": "example.com"})
        self.assertIn(b"200 OK", started)
        await self.handlers.autoscanner.task
        result = await self.request("/auto-scan", token="a" * 40)
        job = json.loads(result.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(job["state"], "completed")
        self.assertEqual(job["saved"], 1)
        self.assertEqual(self.store.get(self.engine.key, "example.com")["evidence"], "functional_ok")
        self.assertEqual(self.engine.service("example.com")["probes"][0]["probe_method"], "GET")
        status = await self.request(token="a" * 40)
        self.assertIn(b'"auto_scan"', status)

    async def test_app_launch_is_authenticated_and_uses_configured_proxy_port(self):
        with patch("pathfinder.server.launch_discord", return_value={"status": "launched", "message": "ok"}) as launch:
            self.assertIn(b"401 Unauthorized", await self.request("/apps/discord", method="POST", data={}))
            launch.assert_not_called()
            result = await self.request("/apps/discord", token="a" * 40, method="POST", data={})
            self.assertIn(b"200 OK", result)
            launch.assert_called_once_with(self.proxy_port)

    async def test_event_from_other_network_is_ignored(self):
        import time
        result = await self.request("/event", token="a" * 40, method="POST", data={
            "host": "example.com", "outcome": "transport_error", "started": time.time(), "network": "other"})
        self.assertIn(b"network_changed", result)

    async def test_connect_denies_other_ports(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n")
        await writer.drain()
        self.assertIn(b"400 Bad Request", await reader.read())
        await close(writer)

    async def test_proxy_does_not_forward_post(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        writer.write(b"POST https://example.com/charge HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        self.assertIn(b"405 Method Not Allowed", await reader.read())
        await close(writer)

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable required for temporary test certificate")
    async def test_real_tls_through_connect_and_split_no_mitm(self):
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com",
                        "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        client_context = ssl.create_default_context(cafile=str(cert))
        requests = []

        async def target(reader, writer):
            try:
                requests.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            finally:
                await close(writer)

        upstream = await asyncio.start_server(target, "127.0.0.1", 0, ssl=server_context)
        upstream_port = upstream.sockets[0].getsockname()[1]

        async def local_connect(*args, **kwargs):
            return await asyncio.open_connection("127.0.0.1", upstream_port)

        try:
            self.config.data["routes"] = [{"id": "split", "kind": "direct", "family": 4, "tls_split": True}]
            with patch("pathfinder.server.connect", local_connect):
                reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
                writer.write(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                await writer.drain()
                self.assertIn(b"200 Connection Established", await reader.readuntil(b"\r\n\r\n"))
                tls = TLSProbe(reader, writer, "example.com", False, client_context)
                status = await asyncio.wait_for(tls.request("/"), 5)
                self.assertEqual(status, 200)
                self.assertEqual(len(requests), 1)
                self.assertTrue(requests[0].startswith(b"HEAD / HTTP/1.1"))
                await close(writer)
                self.assertTrue(any(row["host"] == "example.com" and row["outcome"] == "tunnel_open"
                                    for row in self.handlers.recent_connections))
            with patch("pathfinder.transport.connect", local_connect):
                result = await probe({"id": "direct", "kind": "direct", "family": 4}, {"domains": ["example.com"]}, 3)
                self.assertFalse(result.ok)
                self.assertEqual(result.outcome, "certificate_error")
        finally:
            upstream.close()
            await upstream.wait_closed()

    async def test_socks_uses_remote_dns_and_handles_partial_reads(self):
        received = []
        async def socks(reader, writer):
            try:
                self.assertEqual(await reader.readexactly(3), b"\x05\x01\x00")
                for byte in b"\x05\x00":
                    writer.write(bytes([byte]))
                    await writer.drain()
                header = await reader.readexactly(5)
                self.assertEqual(header[:4], b"\x05\x01\x00\x03")
                received.append(await reader.readexactly(header[4]))
                await reader.readexactly(2)
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
                await writer.drain()
            finally:
                await close(writer)
        server = await asyncio.start_server(socks, "127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            with patch("socket.getaddrinfo", side_effect=AssertionError("Local DNS should not be used")):
                _, writer = await connect({"kind": "socks5", "host": "127.0.0.1", "port": port}, "example.com")
                await close(writer)
            self.assertEqual(received, [b"example.com"])
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
