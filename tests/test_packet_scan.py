import asyncio
import copy
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from pathfinder.config import Config
from pathfinder.packet_profiles import PROFILES
from pathfinder.packet_scan import PacketScanner, SERVICE_PROFILES, SYSTEM_ROUTE
from pathfinder.transport import ProbeResult


class Runner:
    def __init__(self):
        self.current_profile = None
        self.running = False
        self.starts = Counter()
        self.events = []
        self.fail_start = set()

    def alive(self):
        return self.running

    async def start(self, profile):
        if self.running:
            raise AssertionError("previous candidate still running")
        self.starts[profile] += 1
        self.events.append(("start", profile))
        if profile in self.fail_start:
            raise OSError("redacted local failure")
        self.current_profile = profile
        self.running = True

    async def stop(self):
        self.events.append(("stop", self.current_profile))
        self.current_profile = None
        self.running = False


class PacketScanTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.config = Config(self.directory / "config.json")
        self.runner = Runner()
        self.network = "network-a"
        self.calls = []
        self.behavior = lambda profile, spec: profile == "alt2"

        async def detect(label=""):
            return self.network

        async def prober(route, specification, timeout):
            self.assertEqual(route, SYSTEM_ROUTE)
            profile = self.runner.current_profile
            self.calls.append((profile, copy.deepcopy(specification)))
            ok = self.behavior(profile, specification)
            status = 101 if specification["probe_method"] == "WSS" else 200
            latency = {None: 20, "alt1": 10, "alt2": 30, "alt3": 40, "alt4": 50}[profile]
            return ProbeResult(ok, "functional_ok" if ok else "http_denied", latency,
                               status if ok else 403, "http", "")

        self.prober = prober
        self.detect = detect
        self.scanner = PacketScanner(self.runner, self.directory, self.config, prober, detect)

    def tearDown(self):
        self.temp.cleanup()

    async def test_all_candidates_share_checks_and_winner_is_freshly_confirmed(self):
        report = await self.scanner.scan("discord")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual((report["passed"], report["total"]), (3, 3))
        self.assertEqual(report["state"], "completed")
        self.assertEqual(report["progress"], report["steps"])
        self.assertEqual(self.runner.starts, Counter({"alt2": 2, "alt1": 1, "alt3": 1, "alt4": 1}))
        self.assertEqual(len(report["baseline"]), 3)
        for result in report["results"]:
            self.assertEqual(len(result["checks"]), 3)
            self.assertEqual({row["method"] for row in result["checks"]}, {"GET", "WSS"})
        self.assertEqual(self.runner.current_profile, "alt2")
        self.assertTrue(any("UDP/QUIC" in text for text in report["limits"]))

    async def test_global_selection_cannot_combine_successes_or_regress_baseline(self):
        # Baseline API works; alt1 passes two other checks but breaks that API.
        # Alt2 preserves it and adds the WebSocket. No candidate covers all three.
        def behavior(profile, spec):
            path = spec["probe_path"]
            if profile is None:
                return path == "/api/v10/gateway"
            if profile == "alt1":
                return path != "/api/v10/gateway"
            if profile == "alt2":
                return path != "/app"
            return path == "/api/v10/gateway"
        self.behavior = behavior
        report = await self.scanner.scan("discord")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual(report["state"], "partial")
        self.assertEqual(report["passed"], 2)
        alt1 = next(row for row in report["results"] if row["profile"] == "alt1")
        self.assertFalse(alt1["eligible"])

    async def test_http_403_is_not_success_even_if_prober_calls_it_reachable(self):
        async def denied(*args):
            return ProbeResult(True, "http_reachable", 1, 403, "http")
        self.scanner.prober = denied
        report = await self.scanner.scan("chatgpt")
        self.assertEqual(report["state"], "unresolved")
        self.assertIsNone(report["selected"])
        self.assertFalse(self.runner.alive())
        self.assertFalse((self.directory / "packet-state.json").exists())
        self.assertTrue(all(not row["ok"] for result in report["results"] for row in result["checks"]))

    async def test_strategies_never_overlap_and_check_concurrency_is_bounded(self):
        active = peak = 0
        async def slow(route, specification, timeout):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            profile = self.runner.current_profile
            try:
                await asyncio.sleep(0.001)
                self.assertEqual(self.runner.current_profile, profile)
                return await self.prober(route, specification, timeout)
            finally:
                active -= 1
        self.scanner.prober = slow
        report = await self.scanner.scan("all")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual(peak, 3)
        self.assertEqual(active, 0)

    async def test_confirmation_failure_tries_next_eligible_profile(self):
        self.behavior = lambda profile, spec: profile == "alt2" or profile == "alt1" and self.runner.starts["alt1"] == 1
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt2")
        self.assertTrue(next(row for row in report["results"] if row["profile"] == "alt1")["confirmation_failed"])

    async def test_baseline_success_still_selects_a_nonregressing_bypass(self):
        self.behavior = lambda profile, spec: True
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt1")
        self.assertEqual(report["passed"], 1)

    async def test_cached_selection_is_reprobed_after_stopping_previous_process(self):
        await self.scanner.scan("discord")
        self.runner.starts.clear()
        self.calls.clear()
        restarted = PacketScanner(self.runner, self.directory, self.config, self.prober, self.detect)
        report = await restarted.scan("discord")
        self.assertTrue(report["cached"])
        self.assertEqual(self.runner.starts, Counter({"alt2": 1}))
        self.assertEqual([profile for profile, _ in self.calls], [None] * 3 + ["alt2"] * 3)

    async def test_failed_cached_choice_rescans_every_profile(self):
        await self.scanner.scan("example.com")
        self.behavior = lambda profile, spec: profile == "alt3"
        self.runner.starts.clear()
        report = await self.scanner.scan("example.com")
        self.assertFalse(report["cached"])
        self.assertEqual(report["selected"], "alt3")
        self.assertEqual(set(self.runner.starts), set(PROFILES))
        self.assertEqual(self.runner.starts["alt2"], 2)

    async def test_changed_check_definition_invalidates_cached_result(self):
        await self.scanner.scan("chatgpt")
        profiles = copy.deepcopy(SERVICE_PROFILES)
        profiles["chatgpt"]["checks"][0]["probe_path"] = "/new-check"
        self.runner.starts.clear()
        with patch("pathfinder.packet_scan.SERVICE_PROFILES", profiles):
            report = await self.scanner.scan("chatgpt")
        self.assertFalse(report["cached"])
        self.assertEqual(set(self.runner.starts), set(PROFILES))

    async def test_new_domain_cannot_regress_previously_accepted_services(self):
        await self.scanner.scan("discord")
        def behavior(profile, spec):
            new_host = spec["probe_host"] == "example.com"
            return profile == "alt3" or profile == "alt1" and new_host or profile == "alt2" and not new_host
        self.behavior = behavior
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt3")
        self.assertEqual(report["preserved"], 3)
        self.assertEqual(report["total"], 4)
        self.assertFalse(report["cached"])
        alt1 = next(row for row in report["results"] if row["profile"] == "alt1")
        self.assertFalse(alt1["eligible"])

    async def test_restart_retains_scope_and_successes_of_global_cached_profile(self):
        await self.scanner.scan("discord")
        self.behavior = lambda profile, spec: profile == "alt3" or profile == "alt1" and spec["probe_host"] == "example.com"
        restarted = PacketScanner(self.runner, self.directory, self.config, self.prober, self.detect)
        report = await restarted.scan("example.com")
        self.assertEqual(report["selected"], "alt3")
        self.assertEqual(report["preserved"], 3)
        self.assertEqual(report["total"], 4)

    async def test_network_change_retains_checks_but_requires_fresh_evidence(self):
        await self.scanner.scan("discord")
        self.behavior = lambda profile, spec: profile == "alt2"
        await self.scanner.scan("example.com")
        self.network = "new-network"
        report = await self.scanner.health()
        self.assertEqual(report["total"], 4)
        self.assertEqual(report["preserved"], 0)
        self.assertEqual(report["selected"], "alt2")

    async def test_network_change_discards_results_then_retries_freshly(self):
        await self.runner.start("alt4")
        async def changing(route, specification, timeout):
            result = await self.prober(route, specification, timeout)
            if self.runner.current_profile == "alt1":
                self.network = "network-b"
            return result
        self.scanner.prober = changing
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["state"], "completed")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual(report["network"], "network-b")
        self.assertEqual(report["retry_count"], 1)
        self.assertTrue(report["transition_recovered"])
        self.assertEqual(report["discarded_attempt"]["stale_reason"], "network_changed")
        self.assertEqual(sum(profile is None for profile, _ in self.calls), 2)
        cache = json.loads((self.directory / "packet-state.json").read_text())
        self.assertEqual({entry["network"] for entry in cache["entries"].values()}, {"network-b"})

    async def test_config_change_discards_results(self):
        async def changing(*args):
            result = await self.prober(*args)
            self.config.data["direct_domains"].append("*.example.org")
            return result
        self.scanner.prober = changing
        self.assertEqual((await self.scanner.scan("example.com"))["state"], "stale")
        self.assertFalse(self.runner.alive())

    async def test_cancel_drains_probe_tasks_then_restores_previous_profile(self):
        await self.runner.start("alt4")
        blocked = asyncio.Event()
        active = 0
        async def waiting(*args):
            nonlocal active
            active += 1
            try:
                if self.runner.current_profile == "alt1":
                    blocked.set()
                    await asyncio.Event().wait()
                return await self.prober(*args)
            finally:
                active -= 1
        self.scanner.prober = waiting
        task = asyncio.create_task(self.scanner.scan("all"))
        await blocked.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(active, 0)
        self.assertEqual(self.runner.current_profile, "alt4")
        self.assertEqual(self.scanner.snapshot()["state"], "cancelled")
        self.assertFalse((self.directory / "packet-state.json").exists())

    async def test_cancel_on_new_network_does_not_restore_old_profile(self):
        await self.runner.start("alt4")
        blocked = asyncio.Event()
        async def waiting(*args):
            if self.runner.current_profile == "alt1":
                blocked.set()
                await asyncio.Event().wait()
            return await self.prober(*args)
        self.scanner.prober = waiting
        task = asyncio.create_task(self.scanner.scan("example.com"))
        await blocked.wait()
        self.network = "network-b"
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.runner.alive())
        self.assertIsNone(self.scanner.snapshot()["active_profile"])

    async def test_health_failure_searches_again_and_updates_selection(self):
        await self.scanner.scan("discord")
        self.behavior = lambda profile, spec: profile == "alt3"
        report = await self.scanner.health()
        self.assertEqual(report["selected"], "alt3")
        self.assertEqual(self.runner.current_profile, "alt3")

    async def test_health_preserves_known_partial_results_without_constant_full_scan(self):
        self.behavior = lambda profile, spec: profile == "alt2" and spec["probe_path"] != "/app"
        await self.scanner.scan("discord")
        self.runner.starts.clear()
        report = await self.scanner.health()
        self.assertEqual(report["state"], "partial")
        self.assertEqual(report["passed"], 2)
        self.assertFalse(self.runner.starts)

    async def test_russian_domain_is_skipped_without_interrupting_current_profile(self):
        await self.runner.start("alt4")
        report = await self.scanner.scan("example.ru")
        self.assertEqual(report["state"], "skipped")
        self.assertEqual(self.runner.current_profile, "alt4")
        self.assertFalse(self.calls)

    async def test_wildcard_base_is_skipped_like_native_hostlist(self):
        self.config.data["direct_domains"].append("*.example.org")
        report = await self.scanner.scan("example.org")
        self.assertEqual(report["state"], "skipped")
        self.assertEqual(self.calls, [])

    async def test_skipped_target_does_not_replace_accepted_health_checks(self):
        await self.scanner.scan("discord")
        await self.scanner.scan("example.ru")
        report = await self.scanner.health()
        self.assertEqual(report["target"], "discord")
        self.assertEqual((report["passed"], report["total"]), (3, 3))

    async def test_health_on_changed_network_restarts_with_new_baseline(self):
        await self.scanner.scan("example.com")
        self.network = "network-b"
        self.calls.clear()
        report = await self.scanner.health()
        self.assertEqual(report["network"], "network-b")
        self.assertEqual(self.calls[0][0], None)
        self.assertFalse(report["cached"])

    async def test_corrupt_cache_is_ignored(self):
        (self.directory / "packet-state.json").write_text('{"version": 1, "entries": {"bad": []}}')
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt2")
        self.assertFalse(report["cached"])

    async def test_crashed_process_cannot_be_selected_despite_successful_rows(self):
        self.behavior = lambda profile, spec: profile in ("alt1", "alt2")
        async def crashed(*args):
            result = await self.prober(*args)
            if self.runner.current_profile == "alt1":
                self.runner.running = False
            return result
        self.scanner.prober = crashed
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual(next(row for row in report["results"] if row["profile"] == "alt1")["error"], "process_exited")

    async def test_start_failure_does_not_skip_alternatives(self):
        self.runner.fail_start.add("alt1")
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["selected"], "alt2")
        self.assertEqual(report["results"][0]["error"], "start_failed")
        self.assertNotIn("redacted local failure", json.dumps(report))

    async def test_cache_is_bounded_to_eight_networks(self):
        for index in range(10):
            self.network = "network-" + str(index)
            await self.scanner.scan("example.com")
        cache = json.loads((self.directory / "packet-state.json").read_text())
        self.assertEqual(len(cache["entries"]), 8)

    async def test_invalid_target_does_not_stop_running_profile(self):
        await self.runner.start("alt4")
        with self.assertRaises(ValueError):
            await self.scanner.scan("127.0.0.1")
        self.assertEqual(self.runner.current_profile, "alt4")

    async def test_preflight_conflict_stops_owned_profile_without_probing_or_saving(self):
        await self.runner.start("alt4")
        async def conflict():
            raise RuntimeError("Competing packet filter")
        self.runner.preflight = conflict
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["error"], "preflight_failed")
        self.assertFalse(self.runner.alive())
        self.assertFalse(self.calls)
        self.assertFalse((self.directory / "packet-state.json").exists())

    async def test_conflict_appearing_during_scan_prevents_saving_success(self):
        async def preflight():
            if self.calls:
                raise RuntimeError("Another filter started during probes")
        self.runner.preflight = preflight
        report = await self.scanner.scan("example.com")
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["error"], "preflight_failed")
        self.assertFalse(self.runner.alive())
        self.assertFalse((self.directory / "packet-state.json").exists())

    async def test_health_checks_preflight_before_reusing_selection(self):
        await self.scanner.scan("example.com")
        self.calls.clear()
        async def conflict():
            raise RuntimeError("Proxy enabled after initial scan")
        self.runner.preflight = conflict
        report = await self.scanner.health()
        self.assertEqual(report["error"], "preflight_failed")
        self.assertFalse(self.runner.alive())
        self.assertFalse(self.calls)


if __name__ == "__main__":
    unittest.main()
