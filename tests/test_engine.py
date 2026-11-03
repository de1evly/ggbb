import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from pathfinder.config import Config, hostname
from pathfinder.engine import Engine, NoRoute
from pathfinder.store import Store
from pathfinder.transport import ProbeResult, split_hello
from pathfinder.console import export_diagnostics


class EngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config(self.root / "config.json")
        self.store = Store(self.root / "state.sqlite3")
        self.calls = []
        self.good = {"direct-v4"}

        async def probe(route, service, timeout):
            self.calls.append((route["id"], service["id"]))
            ok = route["id"] in self.good
            return ProbeResult(ok, "http_reachable" if ok else "timeout", 10, 200 if ok else None)

        self.engine = Engine(self.config, self.store, "home", probe)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    async def test_reuses_persistent_choice_after_restart(self):
        key, route, _ = await self.engine.acquire("example.com")
        self.engine.release(key)
        self.assertEqual(route["id"], "direct-v4")
        self.store.close()
        self.store = Store(self.root / "state.sqlite3")
        engine = Engine(self.config, self.store, "home", self.engine.prober)
        key, route, _ = await engine.acquire("example.com")
        engine.release(key)
        self.assertEqual(len(self.calls), 1)

    async def test_new_network_has_separate_choice(self):
        key, _, _ = await self.engine.acquire("example.com")
        self.engine.release(key)
        self.engine.network = "mobile"
        self.good = {"tls-split-v4"}
        key2, route, _ = await self.engine.acquire("example.com")
        self.engine.release(key2)
        self.assertNotEqual(key, key2)
        self.assertEqual(route["id"], "tls-split-v4")
        self.engine.network = "home"
        before = len(self.calls)
        key3, route, _ = await self.engine.acquire("example.com")
        self.engine.release(key3)
        self.assertEqual(route["id"], "direct-v4")
        self.assertEqual(before, len(self.calls))

    async def test_network_switch_during_probe_discards_stale_evidence(self):
        old_key = self.engine.key
        calls = 0
        async def changing(*args):
            nonlocal calls
            calls += 1
            if calls == 1:
                self.engine.network = "mobile"
            return ProbeResult(True, "http_reachable", 1, 200)
        self.engine.prober = changing
        key, _, _ = await self.engine.acquire("example.com")
        self.assertTrue(key[0].startswith("mobile:"))
        self.assertIsNone(self.store.get(old_key, "example.com"))
        self.assertEqual(calls, 2)
        self.engine.release(key)

    async def test_two_independent_failures_automatically_recover(self):
        key, route, _ = await self.engine.acquire("example.com")
        self.good = {"tls-split-v4"}
        await self.engine.report("example.com", "transport_error", time.time())
        self.assertEqual(self.store.get(*key)["route"], "direct-v4")
        # A resource burst must not trigger failover.
        await self.engine.report("example.com", "transport_error", time.time())
        self.assertEqual(self.store.get(*key)["failures"], 1)
        self.engine.last_failure[key] = 0
        await self.engine.report("example.com", "transport_error", time.time())
        self.assertEqual(self.store.get(*key)["route"], "tls-split-v4")
        self.assertEqual(route["id"], "direct-v4")  # old lease retains old route
        self.engine.release(key)

    async def test_old_events_cannot_poison_new_route(self):
        key, _, changed = await self.engine.acquire("example.com")
        await self.engine.report("example.com", "transport_error", changed - 1)
        await self.engine.report("example.com", "transport_error", time.time(), route_id="old-route")
        self.assertEqual(self.store.get(*key)["failures"], 0)
        self.engine.release(key)

    async def test_403_is_not_classified_as_geoblocking(self):
        key, _, _ = await self.engine.acquire("example.com")
        await self.engine.report("example.com", "http_inconclusive", time.time(), 403)
        self.assertEqual(self.store.get(*key)["failures"], 0)
        self.assertEqual(self.store.snapshot(self.engine.key)["attempts"][0]["outcome"], "http_inconclusive")
        self.engine.release(key)

    async def test_all_http_denials_remain_tentative_not_network_outage(self):
        async def denied(*args):
            return ProbeResult(False, "http_inconclusive", 10, 405)
        self.engine.prober = denied
        key, route, _ = await self.engine.acquire("example.com")
        self.assertEqual(route["id"], "direct-v4")
        self.assertEqual(self.store.get(*key)["evidence"], "http_inconclusive")
        self.engine.release(key)

    async def test_all_routes_failed_backoff(self):
        self.good = set()
        with self.assertRaises(NoRoute):
            await self.engine.acquire("example.com")
        before = len(self.calls)
        with self.assertRaises(NoRoute):
            await self.engine.acquire("example.com")
        self.assertEqual(before, len(self.calls))
        self.assertEqual(before, 3)  # Tor disabled by default

    async def test_concurrent_requests_share_one_search(self):
        leases = await asyncio.gather(*(self.engine.acquire("example.com") for _ in range(12)))
        self.assertEqual(len(self.calls), 1)
        for key, _, _ in leases:
            self.engine.release(key)

    async def test_expiration_does_not_interrupt_active_session(self):
        key, _, _ = await self.engine.acquire("example.com")
        self.store.db.execute("UPDATE choices SET expires=0, last_used=0")
        self.store.db.commit()
        _, _, _ = await self.engine.acquire("example.com")
        self.assertEqual(len(self.calls), 1)
        self.engine.release(key)
        self.engine.release(key)
        self.store.db.execute("UPDATE choices SET last_used=0")
        self.store.db.commit()
        key, _, _ = await self.engine.acquire("example.com")
        self.assertEqual(len(self.calls), 2)
        self.engine.release(key)

    async def test_background_health_recovers_without_extension(self):
        key, _, _ = await self.engine.acquire("example.com")
        self.engine.release(key)
        self.good = {"tls-split-v4"}
        for _ in range(2):
            self.store.db.execute("UPDATE choices SET verified=0")
            self.store.db.commit()
            await self.engine.health_check()
        self.assertEqual(self.store.get(*key)["route"], "tls-split-v4")

    async def test_domain_not_enrolled_in_selected_mode(self):
        self.config.data["auto_manage"] = False
        with self.assertRaises(NoRoute):
            await self.engine.acquire("example.com")
        self.config.add("example.com")
        key, _, _ = await self.engine.acquire("example.com")
        self.engine.release(key)

    async def test_scan_does_not_replace_route(self):
        key, _, _ = await self.engine.acquire("example.com")
        self.engine.release(key)
        self.good = {"tls-split-v4"}
        await self.engine.scan("example.com")
        self.assertEqual(self.store.get(*key)["route"], "direct-v4")

    async def test_diagnostics_excludes_domains_networks_and_secrets(self):
        import zipfile
        key, _, _ = await self.engine.acquire("private.example.com")
        self.engine.release(key)
        state = self.engine.snapshot()
        class FakeClient:
            def request(self, path):
                return state
        output = export_diagnostics(FakeClient(), self.root)
        with zipfile.ZipFile(output) as z:
            body = z.read("diagnostics.json").decode()
        self.assertNotIn("private.example.com", body)
        self.assertNotIn(self.engine.key, body)
        self.assertNotIn("token", body)
        self.assertIn("service-1", body)


class ValidationTests(unittest.TestCase):
    def test_rejects_local_literal_and_header_injection_targets(self):
        for host in ("localhost", "127.0.0.1", "example.com\r\nX: y", "192.168.1.1", "router.local", "a..com", "-a.com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                hostname(host)

    def test_idna_normalization(self):
        self.assertEqual(hostname("EXAMPLE.COM."), "example.com")
        self.assertEqual(hostname("пример.рф"), "xn--e1afmkfd.xn--p1ai")

    def test_tls_record_split_preserves_handshake_and_following_records(self):
        payload = b"\x01" + b"a" * 40 + b"example.com" + b"b" * 40
        record = b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload
        tail = b"\x14\x03\x03\x00\x01\x01"
        parts = split_hello(record + tail, "example.com")
        self.assertEqual(len(parts), 2)
        size1 = int.from_bytes(parts[0][3:5], "big")
        size2 = int.from_bytes(parts[1][3:5], "big")
        self.assertEqual(parts[0][5:5+size1] + parts[1][5:5+size2], payload)
        self.assertEqual(parts[1][5+size2:], tail)
        self.assertNotIn(b"example.com", parts[0])
        self.assertNotIn(b"example.com", parts[1])

    def test_non_clienthello_is_unchanged(self):
        raw = b"GET / HTTP/1.1\r\n"
        self.assertEqual(split_hello(raw, "example.com"), [raw])


if __name__ == "__main__":
    unittest.main()
