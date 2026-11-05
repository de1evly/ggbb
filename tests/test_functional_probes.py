import asyncio
import base64
import gzip
import hashlib
import json
import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pathfinder.transport import MAX_PROBE_RESPONSE, WEBSOCKET_GUID, close, probe


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL required for a temporary TLS certificate")
class FunctionalProbeTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=example.com", "-addext", "subjectAltName=DNS:example.com",
                        "-keyout", str(key), "-out", str(cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(cert, key)
        cls.client_context = ssl.create_default_context(cafile=str(cert))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    async def check(self, service, response, *, trusted=True, split=True):
        self.requests, self.server_errors = [], []
        active = set()

        async def target(reader, writer):
            active.add(asyncio.current_task())
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                self.requests.append(request)
                output = response(request) if callable(response) else response
                # Boundaries differ from the logical headers/chunks so probes
                # exercise buffering rather than depending on server writes.
                for offset in range(0, len(output), 37):
                    writer.write(output[offset:offset + 37])
                    await writer.drain()
            except (ConnectionError, ssl.SSLError):
                pass  # A rejected check can close before a large response ends.
            except Exception as error:
                self.server_errors.append(error)
            finally:
                await close(writer)
                active.discard(asyncio.current_task())

        server = await asyncio.start_server(target, "127.0.0.1", 0, ssl=self.server_context)
        port = server.sockets[0].getsockname()[1]

        async def local_connect(route, host, target_port=443, on_stage=None):
            if on_stage:
                on_stage("tcp")
            self.target_port = target_port
            return await asyncio.open_connection("127.0.0.1", port)

        parameters = {"id": "example", "domains": ["example.com"], **service}
        try:
            with patch("pathfinder.transport.connect", local_connect):
                if trusted:
                    with patch("pathfinder.transport.ssl.create_default_context", return_value=self.client_context):
                        result = await probe({"id": "test", "kind": "direct", "family": 4, "tls_split": split}, parameters, 3)
                else:
                    result = await probe({"id": "test", "kind": "direct", "family": 4}, parameters, 3)
            if active:
                await asyncio.wait_for(asyncio.gather(*list(active)), 3)
            self.assertEqual(self.server_errors, [])
            return result
        finally:
            server.close()
            await server.wait_closed()

    @staticmethod
    def response(body=b"", status=200, extra=b""):
        return (f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\n".encode()
                + extra + b"Connection: close\r\n\r\n" + body)

    async def test_get_json_and_marker_use_real_tls_and_selected_port(self):
        result = await self.check({"probe_method": "GET", "probe_path": "/api/gateway", "port": 8443,
                                   "json_keys": ["url"], "body_contains": "gateway.example"},
                                  self.response(b'{"url":"wss://gateway.example"}'))
        self.assertTrue(result.ok)
        self.assertEqual((result.outcome, result.status, result.stage), ("functional_ok", 200, "http"))
        self.assertEqual(self.target_port, 8443)
        self.assertIn(b"GET /api/gateway HTTP/1.1\r\n", self.requests[0])
        self.assertIn(b"Host: example.com:8443\r\n", self.requests[0])
        self.assertIn(b"Accept-Encoding: identity\r\n", self.requests[0])
        self.assertFalse(hasattr(result, "body"))

    async def test_body_and_json_failures_are_not_successful_routes(self):
        cases = [({"json_keys": ["url"]}, b"<html>challenge</html>", "invalid_json"),
                 # Newer Python versions can parse this valid nested array;
                 # older ones reject its depth. Neither can satisfy API keys.
                 ({"json_keys": ["url"]}, b"[" * 2000 + b"]" * 2000, ("invalid_json", "json_keys_missing")),
                 ({"json_keys": ["url"]}, b'{"message":"denied"}', "json_keys_missing"),
                 ({"json_keys": ["url"]}, b'["url"]', "json_keys_missing"),
                 ({"body_contains": "real application"}, b"challenge page", "body_marker_missing")]
        for fields, body, detail in cases:
            with self.subTest(detail=detail):
                result = await self.check({"probe_method": "GET", **fields}, self.response(body))
                self.assertFalse(result.ok)
                self.assertEqual((result.outcome, result.status), ("content_mismatch", 200))
                self.assertIn(result.detail, (detail,) if isinstance(detail, str) else detail)

    async def test_denial_and_redirect_do_not_count_as_functional_success(self):
        for status in (302, 403, 451, 503):
            with self.subTest(status=status):
                result = await self.check({"probe_method": "GET", "json_keys": ["url"]},
                                          self.response(b'{"url":"fake"}', status=status,
                                                        extra=b"Location: https://elsewhere.example/\r\n"))
                self.assertFalse(result.ok)
                self.assertEqual(result.status, status)
                self.assertEqual(result.outcome, "http_denied" if status >= 400 else "content_mismatch")
                self.assertEqual(len(self.requests), 1)

    async def test_chunked_gzip_and_trailers_are_validated(self):
        body = gzip.compress(json.dumps({"url": "wss://gateway.example"}).encode())
        chunks = [body[:7], body[7:19], body[19:]]
        response = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                    + b"".join(f"{len(chunk):x};check=yes\r\n".encode() + chunk + b"\r\n" for chunk in chunks)
                    + b"0\r\nX-Finished: yes\r\n\r\n")
        result = await self.check({"probe_method": "GET", "json_keys": ["url"]}, response)
        self.assertTrue(result.ok)

    async def test_oversize_and_ambiguous_responses_are_rejected(self):
        cases = [
            (f"HTTP/1.1 200 OK\r\nContent-Length: {MAX_PROBE_RESPONSE + 1}\r\n\r\n".encode(), "response_too_large"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n", "ambiguous_framing"),
            (self.response(b"compressed?", extra=b"Content-Encoding: br\r\n"), "content_encoding_unsupported"),
            (self.response(gzip.compress(b"a" * (MAX_PROBE_RESPONSE + 1)), extra=b"Content-Encoding: gzip\r\n"), "response_too_large"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n", "invalid_chunk"),
        ]
        for raw, detail in cases:
            with self.subTest(detail=detail):
                result = await self.check({"probe_method": "GET"}, raw)
                self.assertFalse(result.ok)
                self.assertEqual((result.outcome, result.detail, result.status), ("content_mismatch", detail, 200))

    async def test_truncated_content_length_cannot_validate_partial_marker(self):
        result = await self.check({"probe_method": "GET", "body_contains": "expected"},
                                  b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nexpected")
        self.assertFalse(result.ok)
        self.assertEqual((result.status, result.stage), (200, "http"))

    async def test_close_delimited_and_interim_responses_are_supported(self):
        raw = (b"HTTP/1.1 103 Early Hints\r\nLink: </app.js>; rel=preload\r\n\r\n"
               b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nfunctional marker")
        result = await self.check({"probe_method": "GET", "body_contains": "functional marker"}, raw)
        self.assertTrue(result.ok)

    async def test_explicit_prefix_can_check_large_html_without_claiming_full_body(self):
        body = b"<html>known service marker" + b"x" * (MAX_PROBE_RESPONSE * 2)
        result = await self.check({"probe_method": "GET", "body_contains": "known service marker", "allow_prefix": True},
                                  self.response(body))
        self.assertTrue(result.ok)
        self.assertEqual((result.outcome, result.detail, result.status), ("content_prefix_ok", "validated_prefix", 200))
        # The same response remains too large for ordinary full-body checks.
        result = await self.check({"probe_method": "GET", "body_contains": "known service marker"}, self.response(body))
        self.assertFalse(result.ok)
        self.assertEqual(result.detail, "response_too_large")

    async def test_prefix_cannot_succeed_without_marker_or_on_early_truncation(self):
        fields = {"probe_method": "GET", "body_contains": "known service marker", "allow_prefix": True}
        body = b"x" * (MAX_PROBE_RESPONSE * 2) + b"known service marker"
        result = await self.check(fields, self.response(body))
        self.assertFalse(result.ok)
        self.assertEqual(result.detail, "body_marker_missing")
        result = await self.check(fields, b"HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\nknown service marker")
        self.assertFalse(result.ok)
        self.assertEqual(result.detail, "response_incomplete")

    async def test_chunked_and_gzip_prefixes_stay_bounded(self):
        fields = {"probe_method": "GET", "body_contains": "known marker", "allow_prefix": True}
        body = b"known marker" + b"x" * (MAX_PROBE_RESPONSE * 2)
        chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                   + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        for raw in (chunked, self.response(gzip.compress(body), extra=b"Content-Encoding: gzip\r\n")):
            with self.subTest(gzip=raw != chunked):
                result = await self.check(fields, raw)
                self.assertTrue(result.ok)
                self.assertEqual((result.outcome, result.detail), ("content_prefix_ok", "validated_prefix"))

    async def test_prefix_requires_explicit_nonempty_marker_without_json(self):
        for fields in ({}, {"body_contains": ""}, {"body_contains": "marker", "json_keys": ["url"]}):
            with self.subTest(fields=fields):
                result = await self.check({"probe_method": "GET", "allow_prefix": True, **fields}, self.response(b"marker"))
                self.assertFalse(result.ok)
                self.assertEqual(result.detail, "invalid_check")
                self.assertEqual(self.requests, [])

    @staticmethod
    def websocket_response(request, *, valid=True, connection=b"keep-alive, Upgrade"):
        headers = {}
        for line in request.split(b"\r\n")[1:]:
            name, separator, value = line.partition(b":")
            if separator:
                headers[name.lower()] = value.strip()
        key = headers[b"sec-websocket-key"]
        if valid:
            accept = base64.b64encode(hashlib.sha1(key + WEBSOCKET_GUID.encode()).digest())
        else:
            accept = b"forged"
        return (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: " + connection
                + b"\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")

    async def test_websocket_requires_valid_upgrade_and_accept_challenge(self):
        for valid, connection, expected in ((True, b"keep-alive, Upgrade", True),
                                             (False, b"Upgrade", False), (True, b"close", False)):
            with self.subTest(valid=valid, connection=connection):
                result = await self.check({"probe_method": "WSS", "probe_path": "/?v=10&encoding=json"},
                                          lambda request: self.websocket_response(request, valid=valid, connection=connection))
                self.assertEqual(result.ok, expected)
                self.assertEqual(result.status, 101)
                self.assertEqual(result.outcome, "websocket_ok" if expected else "content_mismatch")
                self.assertIn(b"GET /?v=10&encoding=json HTTP/1.1\r\n", self.requests[0])

    async def test_plain_http_200_or_denial_cannot_pass_websocket_check(self):
        for status in (200, 403):
            with self.subTest(status=status):
                result = await self.check({"probe_method": "WSS"}, self.response(status=status))
                self.assertFalse(result.ok)
                self.assertEqual(result.outcome, "http_denied" if status == 403 else "content_mismatch")

    async def test_unsolicited_websocket_negotiation_cannot_pass(self):
        for header in (b"Sec-WebSocket-Protocol: unknown\r\n", b"Sec-WebSocket-Extensions: permessage-deflate\r\n"):
            with self.subTest(header=header):
                result = await self.check({"probe_method": "WSS"},
                                          lambda request: self.websocket_response(request).replace(b"\r\n\r\n", b"\r\n" + header + b"\r\n"))
                self.assertFalse(result.ok)
                self.assertEqual(result.detail, "websocket_upgrade_invalid")

    async def test_untrusted_certificate_is_rejected_before_application_validation(self):
        # Reuse the same known certificate with an unrelated system trust store.
        result = await self.check({"probe_method": "GET", "body_contains": "expected"},
                                  self.response(b"expected"), trusted=False)
        self.assertFalse(result.ok)
        self.assertEqual(result.outcome, "certificate_error")
        self.assertEqual(self.requests, [])

    async def test_head_root_404_keeps_legacy_transport_semantics(self):
        result = await self.check({}, self.response(status=404))
        self.assertTrue(result.ok)
        self.assertEqual(result.outcome, "http_response")
        self.assertTrue(self.requests[0].startswith(b"HEAD / HTTP/1.1\r\n"))


if __name__ == "__main__":
    unittest.main()
