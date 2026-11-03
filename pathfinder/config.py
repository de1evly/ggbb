import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path

TLS_PORTS = (443, 8443, 8080)


def endpoint(value):
    """Parse a console domain[:port]; paths and credentials are not accepted."""
    host, separator, port = value.strip().rpartition(":")
    if not separator:
        return hostname(value.strip()), 443
    if not port.isdecimal() or int(port) not in TLS_PORTS:
        raise ValueError("Поддерживаются TLS-порты 443, 8443 и 8080")
    return hostname(host), int(port)

LEGACY_DIRECT_DOMAINS = [
    "*.ru", "*.su", "*.xn--p1ai",
    "vk.com", "*.vk.com", "userapi.com", "*.userapi.com",
    "vk-cdn.net", "*.vk-cdn.net", "yastatic.net", "*.yastatic.net",
    "yandex.net", "*.yandex.net",
]
DEFAULT_DIRECT_DOMAINS = ["*.ru"]

DEFAULT = {
    "auto_manage": True,
    "bypass_only": True,
    "dpi_engine_enabled": True,
    "direct_domains": DEFAULT_DIRECT_DOMAINS,
    "proxy_port": 47830,
    "api_port": 47831,
    "probe_timeout": 6,
    "search_timeout": 28,
    "cache_seconds": 86400,
    "failure_threshold": 2,
    "session_idle_seconds": 60,
    "network_label": "",
    "routes": [
        {"id": "direct-v4", "kind": "direct", "family": 4},
        {"id": "tls-split-v4", "kind": "direct", "family": 4, "tls_split": True},
        {"id": "direct-v6", "kind": "direct", "family": 6},
        {"id": "tor-local", "kind": "socks5", "host": "127.0.0.1", "port": 9050, "enabled": False},
    ],
    "services": [],
}


def hostname(value):
    if not isinstance(value, str):
        raise ValueError("Нужно доменное имя")
    value = value.rstrip(".").lower().encode("idna").decode("ascii")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Некорректный домен")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Укажите домен, а не IP")
    if "." not in value or value.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid", ".onion")):
        raise ValueError("Нужен публичный домен")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise ValueError("Некорректная метка домена")
    return value


def matches(host, pattern):
    return host == pattern or (pattern.startswith("*.") and host.endswith(pattern[1:]))


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class Config:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.exists():
            atomic_json(self.path, DEFAULT)
        self.data = json.loads(self.path.read_text(encoding="utf-8"))
        migrate = any(k not in self.data for k in ("direct_domains", "dpi_engine_enabled", "bypass_only"))
        if "bypass_only" not in self.data:
            self.data["auto_manage"] = True
        self.data.setdefault("direct_domains", DEFAULT_DIRECT_DOMAINS.copy())
        self.data.setdefault("dpi_engine_enabled", True)
        self.data.setdefault("bypass_only", True)
        if self.data["direct_domains"] == LEGACY_DIRECT_DOMAINS:
            self.data["direct_domains"] = DEFAULT_DIRECT_DOMAINS.copy()
            migrate = True
        self.validate()
        if migrate:
            atomic_json(self.path, self.data)

    def validate(self):
        patterns = self.data["direct_domains"]
        if not isinstance(patterns, list) or len(patterns) > 256:
            raise ValueError("direct_domains должен быть списком до 256 шаблонов")
        for pattern in patterns:
            if not isinstance(pattern, str):
                raise ValueError("Некорректный шаблон прямого доступа")
            if pattern in ("*.ru", "*.su", "*.xn--p1ai"):
                continue
            base = pattern.removeprefix("*.")
            if hostname(base) != base:
                raise ValueError("Используйте нормализованные домены direct_domains")
        if type(self.data.get("auto_manage")) is not bool:
            raise ValueError("auto_manage должен быть true или false")
        if type(self.data["bypass_only"]) is not bool:
            raise ValueError("bypass_only должен быть true или false")
        if type(self.data["dpi_engine_enabled"]) is not bool:
            raise ValueError("dpi_engine_enabled должен быть true или false")
        for k, low, high in [("proxy_port", 1024, 65535), ("api_port", 1024, 65535),
                             ("probe_timeout", 1, 15), ("search_timeout", 5, 60),
                             ("cache_seconds", 60, 604800), ("failure_threshold", 2, 10),
                             ("session_idle_seconds", 10, 600)]:
            v = self.data.get(k)
            if type(v) is not int or not low <= v <= high:
                raise ValueError(f"Недопустимый параметр: {k}")
        if self.data["proxy_port"] == self.data["api_port"]:
            raise ValueError("Порты API и прокси должны различаться")
        routes = self.data["routes"]
        if not 1 <= len(routes) <= 8 or len({r["id"] for r in routes}) != len(routes):
            raise ValueError("Нужно 1–8 способов с уникальными id")
        for r in routes:
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", r["id"]):
                raise ValueError("Некорректный id способа")
            if r["kind"] == "direct":
                if r.get("family") not in (4, 6):
                    raise ValueError("family должен быть 4 или 6")
            elif r["kind"] == "socks5":
                if r.get("host") not in ("127.0.0.1", "::1") or not 1 <= r.get("port", 0) <= 65535:
                    raise ValueError("SOCKS-адаптер должен слушать loopback")
                if r["port"] in (self.data["proxy_port"], self.data["api_port"]):
                    raise ValueError("SOCKS не может указывать на Pathfinder")
            else:
                raise ValueError("Неизвестный способ подключения")
        if not any(r.get("enabled", True) for r in routes):
            raise ValueError("Нет включённых способов")
        services = self.data["services"]
        if len(services) > 128 or len({s["id"] for s in services}) != len(services):
            raise ValueError("Слишком много сервисов или повторяющиеся id")
        patterns = []
        for s in services:
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,253}", s["id"]):
                raise ValueError("Некорректный id сервиса")
            if not 1 <= len(s["domains"]) <= 64:
                raise ValueError("Нужно 1–64 домена на сервис")
            for p in s["domains"]:
                base = p[2:] if p.startswith("*.") else p
                if hostname(base) != base:
                    raise ValueError("Используйте нормализованные домены")
                if p.startswith("*.") and base.count(".") < 1:
                    raise ValueError("Слишком широкий шаблон")
                for service_id, other in patterns:
                    if service_id == s["id"]:
                        continue
                    a, b = p.removeprefix("*."), other.removeprefix("*.")
                    if p == other or matches(a, other) or matches(b, p):
                        raise ValueError("Группы доменов пересекаются")
                patterns.append((s["id"], p))
            probe = s.get("probe_host") or s["domains"][0].removeprefix("*.")
            if hostname(probe) != probe or not any(matches(probe, p) for p in s["domains"]):
                raise ValueError("probe_host должен входить в группу")
            path = s.get("probe_path", "/")
            if not re.fullmatch(r"/[\x21-\x7e]*", path) or "#" in path:
                raise ValueError("Некорректный probe_path")
            codes = s.get("expected_statuses", list(range(200, 400)))
            if not codes or any(type(c) is not int or not 200 <= c <= 599 for c in codes):
                raise ValueError("Некорректные expected_statuses")

    @property
    def fingerprint(self):
        relevant = {"probe_policy": 4, "dpi_engine_enabled": self.data["dpi_engine_enabled"],
                    "bypass_only": self.data["bypass_only"],
                    "auto_manage": self.data["auto_manage"],
                    "routes": self.data["routes"], "services": self.data["services"],
                    "direct_domains": self.data["direct_domains"]}
        return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()[:16]

    def service(self, host):
        return next((s for s in self.data["services"] if any(matches(host, p) for p in s["domains"])), None)

    def direct(self, host):
        return any(matches(host, p) for p in self.data["direct_domains"])

    def add(self, host):
        host = hostname(host)
        if self.service(host):
            return
        self.data["services"].append({"id": host, "domains": [host]})
        try:
            self.validate()
        except Exception:
            self.data["services"].pop()
            raise
        atomic_json(self.path, self.data)

    def set_socks(self, port):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("Порт должен быть от 1 до 65535 или 0 для отключения")
        previous = json.loads(json.dumps(self.data))
        self.data["routes"] = [r for r in self.data["routes"] if r["id"] != "tor-local"]
        self.data["routes"].append({"id": "tor-local", "kind": "socks5", "host": "127.0.0.1", "port": port or 9050, "enabled": bool(port)})
        try:
            self.validate()
            atomic_json(self.path, self.data)
        except Exception:
            self.data = previous
            raise
