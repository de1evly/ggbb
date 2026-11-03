import asyncio
import time
from collections import defaultdict
from .transport import probe
from . import __version__
from .config import TLS_PORTS

DIRECT_ROUTE = {"id": "direct-native", "kind": "direct", "family": 0}


class NoRoute(Exception):
    def __init__(self, message, attempts=None):
        super().__init__(message)
        self.attempts = attempts or []


class Engine:
    def __init__(self, config, store, network, prober=probe):
        self.config, self.store, self.network, self.prober = config, store, network, prober
        self.locks = defaultdict(asyncio.Lock)
        self.active = defaultdict(int)
        self.last_failure = {}
        self.cooldown = {}
        self.search_slots = asyncio.Semaphore(3)
        self.network_error = None

    @property
    def key(self):
        # Route/probe config changes invalidate earlier evidence.
        return self.network + ":" + self.config.fingerprint

    def routes(self):
        return [r for r in self.config.data["routes"] if r.get("enabled", True)]

    def service(self, host, port=443):
        if type(port) is not int or port not in TLS_PORTS:
            raise ValueError("Поддерживаются TLS-порты 443, 8443 и 8080")
        service = self.config.service(host) or ({"id": host, "domains": [host]} if self.config.data["auto_manage"] or self.config.direct(host) else None)
        if service is None:
            return None
        return {**service, "id": service["id"] + (f":{port}" if port != 443 else ""), "port": port}

    async def acquire(self, host, port=443):
        service = self.service(host, port)
        if self.config.direct(host):
            # Guard old PAC caches / manually configured clients too. Never gate
            # browser traffic on our own TLS trust store or synthetic HEAD here.
            key = (self.key, host + (f":{port}" if port != 443 else ""))
            async with self.locks[key]:
                choice = self.store.get(*key)
                if not choice or choice["route"] != DIRECT_ROUTE["id"]:
                    choice = self.store.choose(*key, DIRECT_ROUTE["id"], self.config.data["cache_seconds"], "policy_direct")
                self.active[key] += 1
                self.store.touch(*key)
                return key, DIRECT_ROUTE.copy(), choice["changed"]
        if not service:
            raise NoRoute("Домен не добавлен")
        if self.network_error:
            raise NoRoute(self.network_error)
        for _ in range(2):
            key = (self.key, service["id"])
            async with self.locks[key]:
                try:
                    route, choice = await self.select(key, service)
                except NoRoute:
                    if key[0] != self.key:
                        continue
                    raise
                if key[0] != self.key:
                    continue
                self.active[key] += 1
                self.store.touch(*key)
                return key, route, choice["changed"]
        raise NoRoute("Сеть меняется во время проверки; повторите подключение")

    def release(self, key):
        self.active[key] = max(0, self.active[key] - 1)
        self.store.touch(*key)

    async def select(self, key, service):
        routes = self.routes()
        available = {r["id"]: r for r in routes}
        choice = self.store.get(*key)
        now = time.time()
        threshold = self.config.data["failure_threshold"]
        if choice and choice["route"] in available and choice["failures"] < threshold:
            pinned = self.active[key] > 0 or now - choice["last_used"] < self.config.data["session_idle_seconds"]
            if choice["expires"] > now or pinned:
                return available[choice["route"]], choice
        if self.cooldown.get(key, (0, 0))[0] > now:
            raise NoRoute("Способы пока недоступны; повторный поиск после паузы")
        if choice:
            # Expired but healthy: recheck the known route first. Failed: last.
            failed = choice["failures"] >= threshold
            routes.sort(key=lambda r: (r["id"] == choice["route"]) if failed else (r["id"] != choice["route"]))

        attempts = []

        async def search():
            tentative = None
            async with self.search_slots:
                for route in routes:
                    result = await self.prober(route, service, self.config.data["probe_timeout"])
                    attempts.append({"route": route["id"], **vars(result)})
                    if key[0] != self.key:
                        raise NoRoute("Сеть изменилась во время проверки")
                    self.store.record(*key, route["id"], result.outcome, result.latency_ms, result.status)
                    if result.ok:
                        found = self.store.choose(*key, route["id"], self.config.data["cache_seconds"], result.outcome)
                        self.cooldown.pop(key, None)
                        self.last_failure.pop(key, None)
                        return route, found
                    if result.status is not None and tentative is None:
                        tentative = route
                # HEAD can be unsupported or denied even though a real page works.
                # Preserve the ability to load it; label this evidence honestly.
                if tentative:
                    found = self.store.choose(*key, tentative["id"], 300, "http_inconclusive")
                    self.cooldown.pop(key, None)
                    self.last_failure.pop(key, None)
                    return tentative, found
            return None

        try:
            result = await asyncio.wait_for(search(), self.config.data["search_timeout"])
        except asyncio.TimeoutError:
            result = None
            self.store.record(*key, "search", "search_timeout")
            attempts.append({"route": "search", "outcome": "search_timeout", "status": None, "latency_ms": 0})
        if result:
            return result
        if choice:
            self.store.invalidate(*key)
        rounds = min(self.cooldown.get(key, (0, 0))[1] + 1, 5)
        self.cooldown[key] = (time.time() + min(30 * 2 ** (rounds - 1), 300), rounds)
        message = "Доступные способы не ответили. Результаты ниже; последние события — пункт 7."
        if not any(r["kind"] == "socks5" for r in routes):
            message += " Внешний выход не подключён: прямые способы сохраняют IP провайдера."
        raise NoRoute(message, attempts)

    async def report(self, host, outcome, started, status=None, key=None, route_id=None, port=443):
        if self.config.direct(host):
            return
        service = self.service(host, port)
        if not service:
            return
        key = key or (self.key, service["id"])
        if key[0] != self.key:
            return
        async with self.locks[key]:
            choice = self.store.get(*key)
            # Ignore events from older tunnels / network epochs / cached pages.
            if not choice or started < choice["changed"] or (route_id and route_id != choice["route"]):
                return
            if outcome == "success":
                self.store.success(*key)
            elif outcome == "transport_error":
                # A burst of resources must not be counted as many independent failures.
                if time.time() - self.last_failure.get(key, 0) < 2:
                    return
                self.last_failure[key] = time.time()
                self.store.failure(*key)
            self.store.record(*key, choice["route"], outcome, status=status)
            updated = self.store.get(*key)
            if outcome == "transport_error" and updated["failures"] >= self.config.data["failure_threshold"]:
                try:
                    await self.select(key, service)
                except NoRoute:
                    pass

    async def recover(self, host, port=443):
        if self.config.direct(host):
            key, route, _ = await self.acquire(host, port)
            self.release(key)
            return route["id"]
        service = self.service(host, port)
        if not service:
            raise ValueError("Сначала добавьте домен")
        key = (self.key, service["id"])
        async with self.locks[key]:
            self.store.invalidate(*key)
            self.cooldown.pop(key, None)
            route, _ = await self.select(key, service)
            return route["id"]

    async def scan(self, host, port=443):
        service = self.service(host, port) or {"id": host, "domains": [host], "port": port}
        results = []
        async with self.search_slots:
            for route in ([DIRECT_ROUTE] if self.config.direct(host) else self.routes()):
                result = await self.prober(route, service, self.config.data["probe_timeout"])
                results.append({"route": route["id"], **vars(result)})
        return results

    async def health_check(self):
        """Recheck recently used routes even without the optional extension."""
        if self.network_error:
            return
        network_key = self.key
        now = time.time()
        choices = self.store.snapshot(network_key)["choices"]
        choices = [row for row in choices if now - row["verified"] >= 120 and now - row["last_used"] <= 900]
        choices.sort(key=lambda row: row["verified"])
        for choice in choices[:8]:
            base, _, port_text = choice["service"].partition(":")
            service = next((s for s in self.config.data["services"] if s["id"] == base),
                           {"id": base, "domains": [base]})
            service = {**service, "id": choice["service"], "port": int(port_text) if port_text else 443}
            key = (network_key, choice["service"])
            async with self.locks[key]:
                if self.key != network_key:
                    return
                current = self.store.get(*key)
                if not current or current["changed"] != choice["changed"]:
                    continue
                route = next((r for r in self.routes() if r["id"] == choice["route"]), None)
                if not route:
                    continue
                async with self.search_slots:
                    result = await self.prober(route, service, self.config.data["probe_timeout"])
                if self.key != network_key:
                    return
                self.store.record(*key, route["id"], result.outcome, result.latency_ms, result.status)
                self.store.verified(*key)
                if result.ok:
                    self.store.success(*key)
                elif result.status is None or (choice["evidence"] == "http_reachable" and result.status in (403, 451)):
                    # A changed response is a reason to compare routes, not a diagnosis.
                    self.store.failure(*key)
                    if self.store.get(*key)["failures"] >= self.config.data["failure_threshold"]:
                        try:
                            await self.select(key, service)
                        except NoRoute:
                            pass

    def snapshot(self):
        return {"version": __version__, "direct_domains": self.config.data["direct_domains"],
                "network": self.network, "network_error": self.network_error, "auto_manage": self.config.data["auto_manage"],
                "services": self.config.data["services"], "routes": self.routes(),
                "proxy_port": self.config.data["proxy_port"],
                "cooldown": {k[1]: v[0] for k, v in self.cooldown.items() if k[0] == self.key},
                **self.store.snapshot(self.key)}
