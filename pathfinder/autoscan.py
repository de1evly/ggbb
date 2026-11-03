"""Bounded functional scans that persist the evidence used to select routes."""
import asyncio
import copy
import time
import uuid

from .config import endpoint, hostname
from .engine import DIRECT_ROUTE


def check(host, path="/", *, method="GET", codes=(200,), contains=None, keys=None):
    value = {"id": host, "domains": [host], "probe_host": host, "port": 443,
             "probe_path": path, "probe_method": method, "expected_statuses": list(codes)}
    if contains:
        value["body_contains"] = contains
    if keys:
        value["json_keys"] = keys
    return value


# These checks do not log in, send chat messages, or exercise a UDP voice call.
# Discord's public Gateway endpoint and WebSocket upgrade are separate checks.
PROFILES = {
    "discord": {"name": "Discord", "checks": [
        check("discord.com", "/api/v10/gateway", keys=["url"]),
        {**check("discord.com", "/app", contains="discord"), "allow_prefix": True},
        check("gateway.discord.gg", "/?v=10&encoding=json", method="WSS", codes=(101,)),
    ]},
    "youtube": {"name": "YouTube", "checks": [
        check("www.youtube.com", "/oembed?url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DjNQXAC9IVRw&format=json", keys=["title", "thumbnail_url"]),
        check("i.ytimg.com", "/vi/jNQXAC9IVRw/hqdefault.jpg"),
    ]},
    "chatgpt": {"name": "ChatGPT", "checks": [
        {**check("chatgpt.com", contains="chatgpt"), "allow_prefix": True},
    ]},
    "telegram": {"name": "Telegram Web", "checks": [
        {**check("web.telegram.org", "/a/", contains="telegram"), "allow_prefix": True},
    ]},
}


def specification_key(specification):
    return (specification["probe_host"], specification.get("port", 443),
            specification.get("probe_method", "HEAD"), specification.get("probe_path", "/"))


class AutoScanner:
    def __init__(self, engine):
        self.engine = engine
        self.jobs = {}
        self.latest = None
        self.task = None

    def start(self, target="all"):
        if self.task and not self.task.done():
            return self.snapshot()
        profiles = self._profiles(target)
        job_id = uuid.uuid4().hex[:12]
        groups, skipped = self._groups(profiles)
        routes = copy.deepcopy(self.engine.routes())
        total = sum(len(group["checks"]) * len(routes) for group in groups.values())
        job = {"id": job_id, "target": target, "state": "running", "phase": "probing",
               "started": time.time(), "finished": None, "progress": 0, "total": total,
               "saved": 0, "unresolved": 0, "results": [], "profiles": [],
               "message": "Проверка GET/API и WebSocket; затем сохранение подходящих способов."}
        self.jobs[job_id] = job
        self.latest = job_id
        while len(self.jobs) > 3:
            del self.jobs[next(iter(self.jobs))]
        epoch = self.engine.key
        self.task = asyncio.create_task(self._run(job, profiles, groups, skipped, routes, epoch))
        return self.snapshot(job_id)

    def snapshot(self, job_id=None):
        job_id = job_id or self.latest
        if job_id is None:
            return {"state": "idle", "progress": 0, "total": 0, "results": [], "profiles": []}
        if job_id not in self.jobs:
            raise ValueError("Автопроверка не найдена")
        return copy.deepcopy(self.jobs[job_id])

    def cancel(self):
        if self.task and not self.task.done():
            self.task.cancel()
            self.jobs[self.latest].update(state="cancelled", phase="finished", finished=time.time(),
                                          message="Автопроверка остановлена; незавершённые результаты не применены.")
        return self.snapshot()

    async def shutdown(self):
        if self.task and not self.task.done():
            self.cancel()
            await asyncio.gather(self.task, return_exceptions=True)

    def _profiles(self, target):
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Укажите all, название сервиса или публичный домен")
        target = target.strip().lower()
        if target == "all":
            profiles = copy.deepcopy(PROFILES)
            # A bounded set of domains recently seen by the local proxy, never
            # a scan of the user's browser history or arbitrary address ranges.
            observed = getattr(self.engine, "observed_hosts", {})
            if callable(observed):
                observed = observed()
            known = {s["probe_host"] for p in profiles.values() for s in p["checks"]}
            if isinstance(observed, dict):
                observed = list(observed)[-12:]
            else:
                observed = list(observed or [])[-12:]
            additional = []
            for value in observed:
                value = value.get("host") if isinstance(value, dict) else value
                try:
                    host = hostname(value)
                except (ValueError, TypeError, AttributeError):
                    continue
                if host in known or self.engine.config.direct(host):
                    continue
                known.add(host)
                additional.append(check(host))
            if additional:
                profiles["observed"] = {"name": "Недавние домены", "checks": additional}
            return profiles
        if target in PROFILES:
            return {target: copy.deepcopy(PROFILES[target])}
        host, port = endpoint(target)
        # Choosing the familiar host should exercise its complete known profile.
        if port == 443:
            for name, profile in PROFILES.items():
                if host in {spec["probe_host"] for spec in profile["checks"]}:
                    return {name: copy.deepcopy(profile)}
        specification = check(host)
        specification["port"] = port
        return {target: {"name": target, "checks": [specification]}}

    def _groups(self, profiles):
        groups = {}
        skipped = []
        for target, profile in profiles.items():
            for specification in profile["checks"]:
                host, port = specification["probe_host"], specification["port"]
                service = self.engine.service(host, port)
                if self.engine.config.direct(host):
                    skipped.append({"target": target, "host": host, "state": "policy_direct",
                                    "route": DIRECT_ROUTE["id"]})
                    continue
                if service is None:
                    skipped.append({"target": target, "host": host, "state": "unmanaged", "route": None})
                    continue
                group = groups.setdefault(service["id"], {
                    "service": service["id"], "hosts": [], "targets": [], "checks": [], "matrix": []})
                if not group["checks"]:
                    group["checks"] = copy.deepcopy(self.engine.store.probes(self.engine.key, service["id"]))
                by_key = {specification_key(s): i for i, s in enumerate(group["checks"])}
                identity = specification_key(specification)
                if identity in by_key:
                    group["checks"][by_key[identity]] = copy.deepcopy(specification)
                else:
                    group["checks"].append(copy.deepcopy(specification))
                if host not in group["hosts"]:
                    group["hosts"].append(host)
                if target not in group["targets"]:
                    group["targets"].append(target)
        return groups, skipped

    async def _run(self, job, profiles, groups, skipped, routes, epoch):
        slots = asyncio.Semaphore(3)
        tasks = []
        try:
            async def run_check(group, route, specification):
                async with slots:
                    # Share the engine's work budget with automatic recovery.
                    async with self.engine.search_slots:
                        result = await self.engine.prober(route, specification, self.engine.config.data["probe_timeout"])
                    row = {"host": specification["probe_host"], "port": specification.get("port", 443),
                           "path": specification.get("probe_path", "/"),
                           "method": specification.get("probe_method", "GET"),
                           "route": route["id"], **vars(result)}
                    group["matrix"].append(row)
                    job["progress"] += 1
                    job["current"] = {"host": row["host"], "route": row["route"], "outcome": row["outcome"]}
                    return row

            for group in groups.values():
                for route in routes:
                    for specification in group["checks"]:
                        tasks.append(asyncio.create_task(run_check(group, route, specification)))
            if tasks:
                await asyncio.gather(*tasks)
            if self.engine.key != epoch or self.engine.routes() != routes or self.engine.network_error:
                job.update(state="stale", message="Сеть или способы изменились; результаты не применены. Запустите автопроверку снова.")
                return
            job["phase"] = "applying"
            for group in groups.values():
                candidates = []
                for route in routes:
                    rows = [r for r in group["matrix"] if r["route"] == route["id"]]
                    if len(rows) == len(group["checks"]) and all(row["ok"] for row in rows):
                        candidates.append((sum(row["latency_ms"] for row in rows), route["id"]))
                group["state"] = "unresolved"
                group["route"] = None
                if candidates:
                    group["latency_ms"], group["route"] = min(candidates)
                    group["state"] = "saved"
                    selected = [row for row in group["matrix"] if row["route"] == group["route"]]
                    group["evidence"] = "content_prefix_ok" if any(row["outcome"] == "content_prefix_ok" for row in selected) else "functional_ok"
                else:
                    group["reason"] = "Ни один способ не прошёл все проверки этой группы. Прежняя настройка сохранена."
                job["results"].append(group)
            # Acquire all service locks before applying: no wait or network epoch
            # change can interleave the actual persistence below.
            acquired = []
            try:
                for service in sorted(groups):
                    lock = self.engine.locks[(epoch, service)]
                    await lock.acquire()
                    acquired.append(lock)
                if self.engine.key != epoch or self.engine.routes() != routes or self.engine.network_error:
                    for group in groups.values():
                        group["state"] = "not_applied"
                    job.update(state="stale", message="Сеть изменилась; настройки не применены.")
                    return
                for group in groups.values():
                    key = (epoch, group["service"])
                    for row in group["matrix"]:
                        self.engine.store.record(*key, row["route"], row["outcome"], row["latency_ms"], row["status"])
                    if group["state"] == "saved":
                        self.engine.store.choose_functional(*key, group["route"],
                                                            self.engine.config.data["cache_seconds"], group["checks"], group["evidence"])
                        self.engine.cooldown.pop(key, None)
                        self.engine.last_failure.pop(key, None)
                        job["saved"] += 1
                    else:
                        job["unresolved"] += 1
            finally:
                for lock in reversed(acquired):
                    lock.release()
            job["skipped"] = skipped
            for target, profile in profiles.items():
                relevant = [g for g in groups.values() if target in g["targets"]]
                bypassed = [s for s in skipped if s["target"] == target]
                good = sum(g["state"] == "saved" for g in relevant) + sum(s["state"] == "policy_direct" for s in bypassed)
                count = len(relevant) + len(bypassed)
                state = "ready" if good == count and count else "partial" if good else "unresolved"
                job["profiles"].append({"id": target, "name": profile["name"], "state": state,
                                        "passed": good, "total": count})
            job["unresolved"] += sum(s["state"] != "policy_direct" for s in skipped)
            job.update(state="completed", message="Подходящие способы сохранены по базовым проверкам сайта/API/WebSocket. Функции учётной записи, запуск приложения и голос требуют отдельного подключения.")
        except asyncio.CancelledError:
            job.update(state="cancelled", message="Автопроверка остановлена; незавершённые результаты не применены.")
            raise
        except Exception as error:
            # Do not expose request bodies, tokens, or raw upstream exceptions.
            job.update(state="failed", message=f"Автопроверка прервана ({type(error).__name__}); повторите после проверки состояния.")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            job["phase"] = "finished"
            job["finished"] = time.time()
