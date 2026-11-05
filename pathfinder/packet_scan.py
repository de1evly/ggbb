"""Select one global packet strategy using fresh, isolated functional checks.

Every preset affects the whole host. Candidates therefore run sequentially,
and all checks for one candidate finish before the next process is started.
No HTTP-proxy route participates in these measurements.
"""
import asyncio
import copy
import hashlib
import inspect
import json
import re
import time
from pathlib import Path

from .autoscan import PROFILES as SERVICE_PROFILES, check, specification_key
from .config import atomic_json, endpoint, matches
from .network import detect_network
from .packet_profiles import PROFILE_VERSION, PROFILES
from .transport import probe


SYSTEM_ROUTE = {"id": "system-v4", "kind": "direct", "family": 4}
CACHE_VERSION = 1
LIMITS = [
    "Проверены только новые соединения IPv4 HTTPS/API и WebSocket из отчёта.",
    "UDP/QUIC, голос, вход в учётную запись и все функции приложений не проверены.",
    "Пакетный обход сохраняет IP провайдера; HTTP 403 не считается успехом.",
]


class StaleScan(RuntimeError):
    def __init__(self, reason, network=None):
        super().__init__(reason)
        self.reason = reason
        self.network = network


class PreflightFailed(RuntimeError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _check_id(specification):
    return _digest(specification)[:16]


class PacketScanner:
    def __init__(self, runner, directory, config, probe_func=probe, detect_func=detect_network):
        self.runner = runner
        self.directory = Path(directory)
        self.config = config
        self.prober = probe_func
        self.detect = detect_func
        self._lock = asyncio.Lock()
        self._accepted = None
        self._blocked_network = None
        self._scan_checks = []
        # PacketRunner captures the exclusions when it is constructed.
        self._direct_configuration = _digest(self._data().get("direct_domains", []))
        self._report = {"state": "idle", "phase": "idle", "selected": None,
                        "active_profile": None, "passed": 0, "total": 0,
                        "progress": 0, "steps": 0, "results": [], "limits": list(LIMITS)}

    def snapshot(self):
        return copy.deepcopy(self._report)

    def _data(self):
        return self.config.data if hasattr(self.config, "data") else self.config

    def _config_digest(self):
        # Include complete config and check definitions, not only a target name.
        return _digest(self._data())

    async def _network(self):
        value = self.detect(self._data().get("network_label", ""))
        return await value if inspect.isawaitable(value) else value

    async def _unchanged(self, network, configuration):
        if self._config_digest() != configuration:
            raise StaleScan("config_changed")
        current = await self._network()
        if self._config_digest() != configuration:
            raise StaleScan("config_changed")
        if current != network:
            raise StaleScan("network_changed", current)

    async def _stale(self, reason, network=None):
        await self._stop()
        self._accepted = None
        self._blocked_network = network
        messages = {
            "network_changed": "Сеть изменилась во время проверки. Результаты этой попытки не применены.",
            "config_changed": "Настройки изменились. Обход остановлен; перезапустите Pathfinder для их применения.",
            "network_unstable": "Сеть продолжает меняться. Автоповтор исчерпан; дождитесь стабильного подключения и выберите пункт 2.",
        }
        self._report.update(state="stale", phase="finished", selected=None, active_profile=None,
                            passed=0, stale_reason=reason, finished=time.time(), message=messages[reason])

    async def _stable_network(self, configuration, progress):
        previous = None
        self._report.update(state="running", phase="stabilizing", current={},
                            message="Ожидаю стабильную сеть перед новым подбором.")
        for attempt in range(6):
            if self._config_digest() != configuration:
                raise StaleScan("config_changed")
            current = await self._network()
            if self._config_digest() != configuration:
                raise StaleScan("config_changed")
            self._report["network_rechecks"] = attempt + 1
            await self._notify(progress)
            if current == previous:
                return current
            previous = current
            if attempt < 5:
                await asyncio.sleep(0.4)
        raise StaleScan("network_unstable", previous)

    async def _preflight(self):
        preflight = getattr(self.runner, "preflight", None)
        if preflight:
            try:
                value = preflight()
                if inspect.isawaitable(value):
                    await value
            except Exception as error:
                raise PreflightFailed() from error

    async def _notify(self, callback):
        if callback:
            value = callback(self.snapshot())
            if inspect.isawaitable(value):
                await value

    def _direct(self, host):
        # zapret hostlist suffixes also match the base of a wildcard entry.
        return host.endswith(".ru") or any(
            matches(host, pattern) or pattern.startswith("*.") and host == pattern[2:]
            for pattern in self._data().get("direct_domains", []))

    def _specifications(self, target):
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Укажите all, название сервиса или публичный домен")
        target = target.strip().lower()
        if target == "all":
            profiles = copy.deepcopy(SERVICE_PROFILES)
        elif target in SERVICE_PROFILES:
            profiles = {target: copy.deepcopy(SERVICE_PROFILES[target])}
        else:
            host, port = endpoint(target)
            known = next((name for name, profile in SERVICE_PROFILES.items()
                          if port == 443 and host in {s["probe_host"] for s in profile["checks"]}), None)
            if known:
                profiles = {known: copy.deepcopy(SERVICE_PROFILES[known])}
            else:
                profiles = {target: {"name": target, "checks": [{**check(host), "port": port}]}}
        specifications, skipped, seen = [], [], set()
        for profile in profiles.values():
            for specification in profile["checks"]:
                host = specification["probe_host"]
                if self._direct(host):
                    skipped.append({"host": host, "state": "policy_direct"})
                    continue
                identity = specification_key(specification)
                if identity not in seen:
                    specifications.append(copy.deepcopy(specification))
                    seen.add(identity)
        return target, specifications, skipped

    def _cache(self):
        try:
            path = self.directory / "packet-state.json"
            if path.stat().st_size > 128 * 1024:
                return {}
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("version") != CACHE_VERSION or not isinstance(value.get("entries"), dict):
                return {}
            return {key: entry for key, entry in value["entries"].items()
                    if isinstance(key, str) and len(key) == 64 and isinstance(entry, dict)}
        except (OSError, ValueError, TypeError, AttributeError):
            return {}

    def _cached_entry(self, key, specifications):
        entry = self._cache().get(key)
        if not entry or entry.get("profile") not in PROFILES:
            return None
        identifiers = {_check_id(specification) for specification in specifications}
        passed = entry.get("passed")
        if not isinstance(passed, list) or not passed or any(not isinstance(item, str) or item not in identifiers for item in passed):
            return None
        updated = entry.get("updated")
        if type(updated) not in (float, int) or not 0 <= time.time() - updated <= self._data().get("cache_seconds", 86400):
            return None
        return entry

    def _history(self, network, configuration):
        """Recover the scope of the last global selection, across app restarts."""
        candidates = []
        for entry in self._cache().values():
            if (entry.get("network") != network or entry.get("configuration") != configuration
                    or entry.get("profile_version") != PROFILE_VERSION or entry.get("profile") not in PROFILES):
                continue
            specifications = entry.get("checks")
            passed = entry.get("passed")
            updated = entry.get("updated")
            if (not isinstance(specifications, list) or not 1 <= len(specifications) <= 32
                    or not isinstance(passed, list) or not passed or type(updated) not in (float, int)
                    or not 0 <= time.time() - updated <= self._data().get("cache_seconds", 86400)):
                continue
            try:
                for specification in specifications:
                    host, port = endpoint(specification["probe_host"] + ":" + str(specification["port"]))
                    if (host != specification["probe_host"] or port != specification["port"]
                            or specification.get("probe_method") not in ("GET", "WSS")
                            or not isinstance(specification.get("probe_path"), str)
                            or not re.fullmatch(r"/[\x21-\x7e]*", specification["probe_path"])
                            or "#" in specification["probe_path"]
                            or len(json.dumps(specification)) > 4096):
                        raise ValueError()
                identifiers = {_check_id(specification) for specification in specifications}
                if any(not isinstance(item, str) or item not in identifiers for item in passed):
                    continue
            except (KeyError, TypeError, ValueError):
                continue
            candidates.append(entry)
        return max(candidates, key=lambda entry: entry["updated"]) if candidates else None

    def _merge_checks(self, previous, incoming):
        result = {}
        for specification in [*previous, *incoming]:
            host = specification["probe_host"]
            if self._direct(host):
                continue
            result[specification_key(specification)] = copy.deepcopy(specification)
        if len(result) > 32:
            raise ValueError("Сохранено более 32 проверок: сократите набор перед новым подбором")
        return list(result.values())

    def _remember(self, key, profile, rows, specifications, network, configuration, target):
        entries = self._cache()
        # There is one global selection per network. Replacing its scope must
        # retain earlier successful checks, not create unrelated host presets.
        entries = {k: v for k, v in entries.items() if v.get("network") != network}
        entries[key] = {"profile": profile, "passed": sorted(self._passed(rows)), "updated": time.time(),
                        "checks": specifications, "network": network, "configuration": configuration,
                        "profile_version": PROFILE_VERSION, "target": target}
        # An invalid timestamp from an old/corrupt file must not prevent a save.
        entries = {k: v for k, v in entries.items() if type(v.get("updated")) in (int, float)}
        entries = dict(sorted(entries.items(), key=lambda pair: pair[1]["updated"], reverse=True)[:8])
        while len(entries) > 1 and len(json.dumps({"version": CACHE_VERSION, "entries": entries},
                                                  ensure_ascii=False, indent=2).encode()) + 1 > 128 * 1024:
            entries.pop(next(reversed(entries)))
        self.directory.mkdir(parents=True, exist_ok=True)
        atomic_json(self.directory / "packet-state.json", {"version": CACHE_VERSION, "entries": entries})

    @staticmethod
    def _passed(rows):
        return {row["id"] for row in rows if row["ok"]}

    async def _stop(self):
        await self.runner.stop()
        if self.runner.alive():
            raise RuntimeError("packet_process_did_not_stop")

    async def _activate(self, profile):
        await self._stop()
        await self.runner.start(profile)
        if not self.runner.alive() or self.runner.current_profile != profile:
            raise RuntimeError("packet_process_not_ready")

    async def _checks(self, specifications, profile, callback):
        slots = asyncio.Semaphore(3)

        async def run(specification):
            async with slots:
                try:
                    result = await self.prober(copy.deepcopy(SYSTEM_ROUTE), copy.deepcopy(specification),
                                               self._data().get("probe_timeout", 6))
                    # Functional probes should already enforce status/content;
                    # keep the selector strict even if another prober is injected.
                    expected = specification.get("expected_statuses", [200])
                    ok = bool(result.ok and result.status in expected and
                              (200 <= result.status < 300 or
                               specification.get("probe_method") == "WSS" and result.status == 101))
                    row = {"id": _check_id(specification), "host": specification["probe_host"],
                           "port": specification.get("port", 443), "path": specification.get("probe_path", "/"),
                           "method": specification.get("probe_method", "GET"), "ok": ok,
                           "outcome": result.outcome, "status": result.status,
                           "latency_ms": result.latency_ms, "stage": result.stage, "detail": result.detail}
                except Exception:
                    row = {"id": _check_id(specification), "host": specification["probe_host"],
                           "port": specification.get("port", 443), "path": specification.get("probe_path", "/"),
                           "method": specification.get("probe_method", "GET"), "ok": False,
                           "outcome": "probe_error", "status": None, "latency_ms": 0,
                           "stage": "probe", "detail": "probe_failed"}
                self._report["progress"] += 1
                self._report["current"] = {"profile": profile or "baseline", "host": row["host"], "outcome": row["outcome"]}
                await self._notify(callback)
                return row

        tasks = [asyncio.create_task(run(specification)) for specification in specifications]
        try:
            return await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _candidate(self, profile, specifications, callback, phase="checking"):
        self._report["phase"] = phase
        self._report["current"] = {"profile": profile}
        await self._notify(callback)
        try:
            await self._activate(profile)
            rows = await self._checks(specifications, profile, callback)
            alive = self.runner.alive() and self.runner.current_profile == profile
            return {"profile": profile, "checks": rows, "passed": len(self._passed(rows)) if alive else 0,
                    "total": len(specifications), "error": None if alive else "process_exited"}
        except asyncio.CancelledError:
            raise
        except Exception:
            # Starting one unavailable strategy must not skip every alternative.
            await self._stop()
            return {"profile": profile, "checks": [], "passed": 0, "total": len(specifications),
                    "error": "start_failed", "engine_error": getattr(self.runner, "error", None)}

    async def _restore(self, previous):
        await self._stop()
        if previous in PROFILES:
            try:
                await self._activate(previous)
            except Exception:
                await self._stop()
                self._report["rollback_failed"] = True
        self._report["active_profile"] = self.runner.current_profile if self.runner.alive() else None

    async def _accept(self, profile, rows, key, target, specifications, network, configuration, callback, cached=False):
        await self._preflight()
        await self._unchanged(network, configuration)
        if not self.runner.alive() or self.runner.current_profile != profile:
            raise RuntimeError("packet_process_exited")
        self._remember(key, profile, rows, specifications, network, configuration, target)
        self._accepted = {"profile": profile, "passed": self._passed(rows), "target": target,
                          "checks": specifications, "network": network, "configuration": configuration, "key": key,
                          "baseline": copy.deepcopy(self._report.get("baseline", []))}
        passed = len(self._passed(rows))
        self._report.update(state="completed" if passed == len(specifications) else "partial", phase="finished",
                            selected=profile, active_profile=profile, confirmation=rows, passed=passed,
                            target=target, total=len(specifications), network=network,
                            cached=cached, steps=self._report["progress"], finished=time.time(),
                            message="Профиль применён после повторных проверок; непрошедшие проверки перечислены в отчёте.")
        # No await after persisting: cancellation cannot roll back a committed
        # selection while leaving its cache entry marked as accepted.
        return self.snapshot()

    async def scan(self, target="all", progress=None, force=False):
        """Select sequentially, with at most one fresh retry on a new network."""
        # Validate before interrupting the currently running profile.
        target, specifications, skipped = self._specifications(target)
        async with self._lock:
            configuration = self._config_digest()
            self._blocked_network = None
            prior_checks = self._accepted["checks"] if self._accepted else []
            if not self._accepted and self._report.get("stale_reason") in ("network_changed", "network_unstable"):
                prior_checks = self._scan_checks
            self._scan_checks = self._merge_checks(prior_checks, specifications)
            if specifications:
                specifications = self._scan_checks
            report = await self._scan_once(target, specifications, skipped, progress, force, configuration)
            if report.get("stale_reason") != "network_changed":
                return report
            # Retain diagnostics, never successes, from the invalidated epoch.
            discarded = {key: copy.deepcopy(report.get(key)) for key in
                         ("baseline", "results", "confirmation", "total", "stale_reason")}
            self._report["retry_count"] = 1
            try:
                stable = await self._stable_network(configuration, progress)
                self._report.update(phase="retrying", message="Сеть стабильна. Повторяю весь подбор с исходной проверки.")
                await self._notify(progress)
                # Run a new baseline and every ALT; never reuse the old matrix.
                report = await self._scan_once(target, self._scan_checks, skipped, progress, True,
                                               configuration, retry_count=1, expected_network=stable)
                if report.get("stale_reason") == "network_changed":
                    await self._stale("network_unstable", self._blocked_network)
                self._report["transition_recovered"] = bool(self._report.get("selected"))
            except StaleScan as error:
                await self._stale(error.reason, error.network)
            except asyncio.CancelledError:
                await self._stop()
                self._accepted = None
                self._report.update(state="cancelled", phase="finished", selected=None, active_profile=None,
                                    finished=time.time(), message="Повторный подбор отменён; обход остановлен.")
                raise
            except Exception:
                await self._stop()
                self._accepted = None
                self._report.update(state="failed", phase="finished", selected=None, active_profile=None,
                                    error="network_detection_failed", finished=time.time(),
                                    message="Не удалось повторить подбор: сеть не определена. Повторите через пункт 2.")
            self._report["discarded_attempt"] = discarded
            await self._notify(progress)
            return self.snapshot()

    async def _scan_once(self, target, specifications, skipped, progress, force, expected_configuration,
                         retry_count=0, expected_network=None):
        previous = self.runner.current_profile if self.runner.alive() else None
        previous_accepted = self._accepted
        restore_profile = restore_accepted = None
        self._report = {"state": "running", "phase": "baseline", "target": target,
                        "selected": None, "active_profile": previous, "passed": 0,
                        "retry_count": retry_count,
                        "total": len(specifications), "progress": 0,
                        "steps": len(specifications) * (2 * len(PROFILES) + 2), "cached": False,
                        "baseline": [], "results": [], "confirmation": [], "skipped": skipped,
                        "started": time.time(), "finished": None, "limits": list(LIMITS),
                        "message": "Сначала прямой доступ; затем последовательная проверка пакетных профилей."}
        if not specifications:
            self._report.update(state="skipped", phase="finished", finished=time.time(),
                                message="Домен исключён из обхода политикой прямого доступа; активный профиль не изменён.")
            await self._notify(progress)
            return self.snapshot()
        network = configuration = None
        self._accepted = None
        try:
            configuration = expected_configuration
            if (_digest(self._data().get("direct_domains", [])) != self._direct_configuration
                    or self._config_digest() != configuration):
                raise StaleScan("config_changed")
            network = await self._network()
            if not previous_accepted or (previous_accepted["network"] == network
                                         and previous_accepted["configuration"] == configuration):
                restore_profile, restore_accepted = previous, previous_accepted
            if expected_network is not None and network != expected_network:
                raise StaleScan("network_changed", network)
            await self._unchanged(network, configuration)
            self._report["network"] = network
            await self._preflight()
            history = self._history(network, configuration)
            remembered = [entry for entry in (history, previous_accepted) if entry]
            if remembered:
                prior_checks = [specification for entry in remembered for specification in entry["checks"]]
                specifications = self._merge_checks(prior_checks, specifications)
            self._scan_checks = copy.deepcopy(specifications)
            self._report.update(total=len(specifications), steps=len(specifications) * (2 * len(PROFILES) + 2))
            identifiers = {_check_id(specification) for specification in specifications}
            preserved = set()
            for entry in remembered:
                if entry.get("network") == network and entry.get("configuration") == configuration:
                    preserved |= set(entry["passed"]) & identifiers
            self._report["preserved"] = len(preserved)
            key = _digest({"network": network, "config": configuration, "profiles": PROFILE_VERSION,
                           "target": target, "checks": specifications})
            await self._stop()
            await self._notify(progress)
            baseline = await self._checks(specifications, None, progress)
            self._report["baseline"] = baseline
            baseline_passed = self._passed(baseline) | preserved
            await self._unchanged(network, configuration)

            same_scope = history and {_check_id(specification) for specification in history["checks"]} == identifiers
            cached = None if force else (self._cached_entry(key, specifications) or (history if same_scope else None))
            candidates = []
            if cached:
                result = await self._candidate(cached["profile"], specifications, progress)
                await self._unchanged(network, configuration)
                result["eligible"] = not result["error"] and baseline_passed <= self._passed(result["checks"])
                self._report["results"].append(result)
                if result["eligible"] and set(cached["passed"]) <= self._passed(result["checks"]):
                    return await self._accept(cached["profile"], result["checks"], key, target, specifications,
                                              network, configuration, progress, cached=True)
                # A failed cache is evidence, never an accepted fallback.
            for profile in PROFILES:
                result = await self._candidate(profile, specifications, progress)
                await self._unchanged(network, configuration)
                passed = self._passed(result["checks"])
                result["eligible"] = not result["error"] and bool(passed) and baseline_passed <= passed
                self._report["results"].append(result)
                if result["eligible"]:
                    latency = sum(row["latency_ms"] for row in result["checks"] if row["ok"])
                    candidates.append((-len(passed), latency, profile, result))
            # All candidates see exactly the same checks. The winning
            # global profile cannot borrow per-host success from another.
            for _, _, profile, result in sorted(candidates, key=lambda item: item[:3]):
                self._report["phase"] = "confirming"
                confirmation = await self._candidate(profile, specifications, progress, phase="confirming")
                await self._unchanged(network, configuration)
                rows = confirmation["checks"]
                required = baseline_passed | self._passed(result["checks"])
                if not confirmation["error"] and required <= self._passed(rows):
                    return await self._accept(profile, rows, key, target, specifications,
                                              network, configuration, progress)
                result["confirmation_failed"] = True
            await self._unchanged(network, configuration)
            await self._restore(restore_profile)
            self._accepted = restore_accepted
            self._report.update(state="unresolved", phase="finished", finished=time.time(),
                                message="Ни один профиль не прошёл повторную проверку без ухудшения прямого доступа. Прежний профиль восстановлен, если он был запущен.")
        except StaleScan as error:
            await self._stale(error.reason, error.network)
        except PreflightFailed:
            await self._stop()
            self._report.update(state="failed", phase="finished", active_profile=None, finished=time.time(),
                                error="preflight_failed",
                                message="Обнаружен конфликт с другим сетевым инструментом или настройками прокси. Пакетный обход остановлен.")
        except asyncio.CancelledError:
            # Each _checks call drains its tasks before control reaches here.
            # Do not restore a profile after the network has changed.
            try:
                if network is None or configuration is None:
                    raise RuntimeError("network_not_confirmed")
                await self._unchanged(network, configuration)
                await self._restore(restore_profile)
                self._accepted = restore_accepted
            except Exception:
                await self._stop()
            self._report["active_profile"] = self.runner.current_profile if self.runner.alive() else None
            self._report.update(state="cancelled", phase="finished", finished=time.time(),
                                message="Проверка отменена; неподтверждённые результаты не сохранены.")
            raise
        except Exception:
            try:
                if network is None or configuration is None:
                    raise RuntimeError("network_not_confirmed")
                await self._unchanged(network, configuration)
                await self._restore(restore_profile)
                self._accepted = restore_accepted
            except Exception:
                await self._stop()
            self._report["active_profile"] = self.runner.current_profile if self.runner.alive() else None
            self._report.update(state="failed", phase="finished", finished=time.time(),
                                message="Проверка прервана; неподтверждённые результаты не сохранены.")
        await self._notify(progress)
        return self.snapshot()

    async def health(self, progress=None):
        """Recheck accepted successes; rescan when they fail or the network changes."""
        rescan = None
        async with self._lock:
            accepted = self._accepted
            if accepted is None:
                reason = self._report.get("stale_reason")
                if reason == "config_changed":
                    return self.snapshot()
                if reason == "network_unstable":
                    # Manual scans can retry immediately; health waits for a
                    # different network rather than looping on the same one.
                    if await self._network() == self._blocked_network:
                        return self.snapshot()
                rescan = self._report.get("target", "all")
            else:
                try:
                    await self._preflight()
                    await self._unchanged(accepted["network"], accepted["configuration"])
                    if not self.runner.alive() or self.runner.current_profile != accepted["profile"]:
                        raise RuntimeError("packet_process_exited")
                    if self._report.get("target") != accepted["target"]:
                        self._report["results"] = []
                    self._report.update(state="running", phase="health", progress=0, steps=len(accepted["checks"]),
                                        target=accepted["target"], total=len(accepted["checks"]),
                                        baseline=copy.deepcopy(accepted["baseline"]))
                    rows = await self._checks(accepted["checks"], accepted["profile"], progress)
                    await self._unchanged(accepted["network"], accepted["configuration"])
                    if (self.runner.alive() and self.runner.current_profile == accepted["profile"]
                            and accepted["passed"] <= self._passed(rows)):
                        return await self._accept(accepted["profile"], rows, accepted["key"], accepted["target"],
                                                  accepted["checks"], accepted["network"], accepted["configuration"],
                                                  progress, cached=True)
                    rescan = accepted["target"]
                except StaleScan as error:
                    if error.reason == "config_changed":
                        await self._stale(error.reason)
                        return self.snapshot()
                    await self._stop()
                    rescan = accepted["target"]
                except PreflightFailed:
                    await self._stop()
                    self._accepted = None
                    self._report.update(state="failed", phase="finished", selected=None, active_profile=None,
                                        error="preflight_failed", finished=time.time(),
                                        message="Обнаружен конфликт с другим сетевым инструментом или настройками прокси. Пакетный обход остановлен.")
                    return self.snapshot()
                except Exception:
                    # scan() handles network detection/start errors and performs
                    # rollback; an intermittent monitor error must not kill it.
                    rescan = accepted["target"]
        return await self.scan(rescan or "all", progress=progress, force=True)
