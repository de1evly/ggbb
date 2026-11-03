import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from pathfinder.autoscan import AutoScanner
from pathfinder.config import Config, DEFAULT_DIRECT_DOMAINS, LEGACY_DIRECT_DOMAINS
from pathfinder.engine import Engine, NoRoute
from pathfinder.store import Store
from pathfinder.transport import ProbeResult


class AutoScanTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = Config(self.root / "config.json")
        self.config.data["bypass_only"] = False
        self.store = Store(self.root / "state.sqlite3")
        self.calls = []

        async def prober(route, specification, timeout):
            self.calls.append((route["id"], specification.copy()))
            return ProbeResult(True, "functional_ok", {"direct-v4": 30, "tls-split-v4": 10, "direct-v6": 20}[route["id"]], 200)

        self.engine = Engine(self.config, self.store, "home", prober)
        self.scanner = AutoScanner(self.engine)

    async def asyncTearDown(self):
        await self.scanner.shutdown()
        self.store.close()
        self.temp.cleanup()

    async def finish(self, target):
        self.scanner.start(target)
        await self.scanner.task
        return self.scanner.snapshot()

    async def test_all_routes_are_checked_fastest_saved_and_specs_survive_restart(self):
        fingerprint = self.config.fingerprint
        result = await self.finish("example.com")
        self.assertEqual(result["state"], "completed")
        self.assertEqual((result["progress"], result["total"]), (3, 3))
        self.assertEqual(result["saved"], 1)
        key = (self.engine.key, "example.com")
        self.assertEqual(self.store.get(*key)["route"], "tls-split-v4")
        self.assertEqual(self.store.get(*key)["evidence"], "functional_ok")
        self.assertEqual({route for route, _ in self.calls}, {"direct-v4", "tls-split-v4", "direct-v6"})
        self.assertTrue(all(specification["probe_method"] == "GET" for _, specification in self.calls))
        self.assertEqual(self.config.fingerprint, fingerprint)
        self.store.close()
        self.store = Store(self.root / "state.sqlite3")
        restarted = Engine(self.config, self.store, "home", self.engine.prober)
        self.assertEqual(restarted.service("example.com")["probes"][0]["probe_method"], "GET")
        restarted.network = "other"
        self.assertNotIn("probes", restarted.service("example.com"))

    async def test_discord_requires_api_web_and_websocket_not_just_root(self):
        async def prober(route, specification, timeout):
            self.calls.append((route["id"], specification.copy()))
            success = specification["probe_method"] != "WSS" or route["id"] == "tls-split-v4"
            return ProbeResult(success, "functional_ok" if success else "content_mismatch", 10, 200 if success else 403)
        self.engine.prober = prober
        result = await self.finish("discord.com")
        self.assertEqual(result["profiles"][0]["state"], "ready")
        self.assertEqual(result["saved"], 2)
        saved = {row["service"]: row["route"] for row in self.store.snapshot(self.engine.key)["choices"]}
        self.assertEqual(saved["gateway.discord.gg"], "tls-split-v4")
        api = [spec for _, spec in self.calls if spec["probe_path"] == "/api/v10/gateway"]
        self.assertEqual(api[0]["json_keys"], ["url"])
        self.assertEqual(result["total"], 9)

    async def test_403_never_saved_and_previous_choice_remains(self):
        key = (self.engine.key, "chatgpt.com")
        old = self.store.choose(*key, "direct-v4", 86400)
        async def denied(*args):
            return ProbeResult(False, "http_denied", 10, 403)
        self.engine.prober = denied
        result = await self.finish("chatgpt")
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(result["profiles"][0]["state"], "unresolved")
        self.assertEqual(self.store.get(*key)["changed"], old["changed"])
        self.assertEqual(self.store.probes(*key), [])

    async def test_grouped_domains_require_one_common_route(self):
        self.config.data["services"] = [{"id": "discord", "domains": ["discord.com", "gateway.discord.gg"]}]
        async def disjoint(route, specification, timeout):
            expected = "direct-v4" if specification["probe_host"] == "discord.com" else "tls-split-v4"
            ok = route["id"] == expected
            return ProbeResult(ok, "functional_ok" if ok else "tls_timeout", 10, 200 if ok else None)
        self.engine.prober = disjoint
        result = await self.finish("discord")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(self.store.snapshot(self.engine.key)["choices"], [])

    async def test_recovery_and_health_continue_using_functional_specs(self):
        await self.finish("example.com")
        checks = []
        async def next_prober(route, specification, timeout):
            checks.append(specification)
            success = route["id"] == "direct-v6"
            return ProbeResult(success, "functional_ok" if success else "http_denied", 1, 200 if success else 403)
        self.engine.prober = next_prober
        route = await self.engine.recover("example.com")
        self.assertEqual(route, "direct-v6")
        self.assertTrue(checks)
        self.assertTrue(all(s.get("probe_method") == "GET" for s in checks))
        self.store.db.execute("UPDATE choices SET verified=0")
        self.store.db.commit()
        checks.clear()
        await self.engine.health_check()
        self.assertTrue(checks)
        self.assertEqual(checks[0]["expected_statuses"], [200])

    async def test_strict_functional_recovery_never_falls_back_to_http_denial(self):
        await self.finish("example.com")
        async def denied(*args):
            return ProbeResult(False, "http_denied", 1, 403)
        self.engine.prober = denied
        with self.assertRaises(NoRoute):
            await self.engine.recover("example.com")

    async def test_prefix_proof_remains_distinct_after_save_recovery_and_health(self):
        async def mixed(route, specification, timeout):
            if specification.get("allow_prefix"):
                outcome, status = "content_prefix_ok", 200
            elif specification["probe_method"] == "WSS":
                outcome, status = "websocket_ok", 101
            else:
                outcome, status = "functional_ok", 200
            return ProbeResult(True, outcome, 1, status)
        self.engine.prober = mixed
        result = await self.finish("discord")
        discord = next(group for group in result["results"] if group["service"] == "discord.com")
        gateway = next(group for group in result["results"] if group["service"] == "gateway.discord.gg")
        self.assertEqual(discord["evidence"], "content_prefix_ok")
        self.assertEqual(gateway["evidence"], "functional_ok")
        key = (self.engine.key, "discord.com")
        self.assertEqual(self.store.get(*key)["evidence"], "content_prefix_ok")
        await self.engine.recover("discord.com")
        self.assertEqual(self.store.get(*key)["evidence"], "content_prefix_ok")
        self.store.db.execute("UPDATE choices SET verified=0")
        self.store.db.commit()
        await self.engine.health_check()
        attempts = [row for row in self.store.snapshot(self.engine.key)["attempts"] if row["service"] == "discord.com"]
        self.assertEqual(attempts[0]["outcome"], "content_prefix_ok")
        self.assertEqual(self.store.get(*key)["evidence"], "content_prefix_ok")

    async def test_network_change_rejects_all_scan_results(self):
        epoch = self.engine.key
        async def changing(*args):
            self.engine.network = "changed"
            return ProbeResult(True, "functional_ok", 1, 200)
        self.engine.prober = changing
        result = await self.finish("example.com")
        self.assertEqual(result["state"], "stale")
        self.assertEqual(result["saved"], 0)
        self.assertIsNone(self.store.get(epoch, "example.com"))
        self.assertEqual(self.store.probes(epoch, "example.com"), [])

    async def test_config_change_rejects_all_scan_results(self):
        async def changing(*args):
            self.config.data["routes"][0]["enabled"] = False
            return ProbeResult(True, "functional_ok", 1, 200)
        self.engine.prober = changing
        self.assertEqual((await self.finish("example.com"))["state"], "stale")

    async def test_bounded_concurrency_cancel_and_single_active_job(self):
        current, peak = 0, 0
        started = asyncio.Event()
        release = asyncio.Event()
        async def blocked(*args):
            nonlocal current, peak
            current += 1
            peak = max(peak, current)
            started.set()
            try:
                await release.wait()
                return ProbeResult(True, "functional_ok", 1, 200)
            finally:
                current -= 1
        self.engine.prober = blocked
        first = self.scanner.start("discord")
        await started.wait()
        second = self.scanner.start("chatgpt")
        self.assertEqual(first["id"], second["id"])
        self.assertLessEqual(peak, 3)
        await self.scanner.shutdown()
        self.assertEqual(self.scanner.snapshot()["state"], "cancelled")
        self.assertEqual(self.store.snapshot(self.engine.key)["choices"], [])
        self.assertEqual(current, 0)

    async def test_no_bypass_has_no_direct_fallback_and_ru_is_direct(self):
        self.config.data["bypass_only"] = True
        self.assertEqual(self.engine.routes(), [])
        result = await self.finish("example.com")
        self.assertEqual(result["saved"], 0)
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(self.calls, [])
        key, route, _ = await self.engine.acquire("example.ru")
        self.assertEqual(route["id"], "direct-native")
        self.engine.release(key)
        for host in ("vk.com", "example.su", "example.xn--p1ai"):
            self.assertFalse(self.config.direct(host))

    async def test_explicit_port_and_network_scopes_do_not_mix(self):
        result = await self.finish("example.com:8443")
        self.assertEqual(result["saved"], 1)
        self.assertIsNone(self.store.get(self.engine.key, "example.com"))
        self.assertEqual(self.store.probes(self.engine.key, "example.com:8443")[0]["port"], 8443)

    async def test_scan_replaces_future_choice_without_interrupting_existing_lease(self):
        async def initial(route, specification, timeout):
            return ProbeResult(True, "http_reachable", 10, 200)
        self.engine.prober = initial
        key, old_route, _ = await self.engine.acquire("example.com")
        async def faster(route, specification, timeout):
            ok = route["id"] == "tls-split-v4"
            return ProbeResult(ok, "functional_ok" if ok else "tls_timeout", 10, 200 if ok else None)
        self.engine.prober = faster
        await self.finish("example.com")
        self.assertEqual(old_route["id"], "direct-v4")
        self.assertEqual(self.engine.active[key], 1)
        next_key, next_route, _ = await self.engine.acquire("example.com")
        self.assertEqual(next_route["id"], "tls-split-v4")
        self.engine.release(next_key)
        self.engine.release(key)

    async def test_all_scan_uses_only_bounded_valid_recent_observed_hosts(self):
        self.engine.observed_hosts = {host: {} for host in ["127.0.0.1", "example.ru", "first.example.com"] +
                                     [f"recent{index}.example.com" for index in range(20)]}
        profiles = self.scanner._profiles("all")
        observed = profiles["observed"]["checks"]
        self.assertEqual(len(observed), 12)
        self.assertNotIn("first.example.com", {s["probe_host"] for s in observed})

    async def test_legacy_defaults_migrate_to_global_bypass_only_ru(self):
        data = json.loads(self.config.path.read_text())
        data.pop("bypass_only")
        data["auto_manage"] = False
        data["direct_domains"] = LEGACY_DIRECT_DOMAINS
        self.config.path.write_text(json.dumps(data))
        migrated = Config(self.config.path)
        self.assertTrue(migrated.data["auto_manage"])
        self.assertTrue(migrated.data["bypass_only"])
        self.assertEqual(migrated.data["direct_domains"], DEFAULT_DIRECT_DOMAINS)

    async def test_cancel_before_job_starts_has_terminal_snapshot(self):
        self.scanner.start("example.com")
        result = self.scanner.cancel()
        self.assertEqual(result["state"], "cancelled")
        await self.scanner.shutdown()
        self.assertEqual(self.store.snapshot(self.engine.key)["choices"], [])


if __name__ == "__main__":
    unittest.main()
