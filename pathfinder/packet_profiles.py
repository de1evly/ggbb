"""Bounded zapret2 presets for traffic with a visible HTTP Host / TLS SNI.

The upstream winws2 manual defines exclusion-only hostlists as matching known
hosts outside the list. A nonempty exclusion also prevents profiles from
matching flows whose hostname is unknown. ECH's outer name can still differ
from the destination name; no packet filter can infer that hidden name here.

Source: bol-van/zapret2 docs/manual.en.md, sections "Filtering by lists",
"multisplit", "multidisorder", and "fake"; zapret-win-bundle's
preset2_example.cmd supplies the fake + disorder combination.
"""
from pathlib import Path

from .config import hostname


PROFILE_VERSION = "1"
TCP_PORTS = "80,443,8443,8080"
TLS_PORTS = "443,8443,8080"
PROFILES = {
    "alt1": {"id": "alt1", "name": "ALT1 — разделение пакетов",
             "description": "Разделяет начальный HTTP-запрос и TLS ClientHello на части."},
    "alt2": {"id": "alt2", "name": "ALT2 — обратный порядок",
             "description": "Отправляет части начального запроса в обратном порядке."},
    "alt3": {"id": "alt3", "name": "ALT3 — ложные пакеты и разделение",
             "description": "Добавляет два ложных пакета перед разделённым запросом."},
    "alt4": {"id": "alt4", "name": "ALT4 — ложные пакеты и обратный порядок",
             "description": "Добавляет шесть ложных пакетов и меняет порядок частей запроса."},
}


def _exclusions(direct_domains):
    """Convert config patterns to zapret hostlists, which do not accept '*'.

    A wildcard excludes its base domain as well as subdomains in zapret.
    Exact entries use '^' to preserve their exact-only config semantics.
    Always retain .ru even when an older/custom config omits it.
    """
    if direct_domains is None:
        direct_domains = ["*.ru"]
    if not isinstance(direct_domains, (list, tuple)) or len(direct_domains) > 256:
        raise ValueError("Нужен список до 256 исключений доменов")
    result = ["ru"]
    for pattern in direct_domains:
        if not isinstance(pattern, str):
            raise ValueError("Некорректное исключение домена")
        wildcard = pattern.startswith("*.")
        base = pattern[2:] if wildcard else pattern
        if wildcard and base in ("ru", "su", "xn--p1ai"):
            value = base
        else:
            if hostname(base) != base:
                raise ValueError("Используйте нормализованный домен в исключении")
            value = base if wildcard else "^" + base
        if value not in result:
            result.append(value)
    return ",".join(result)


def build_args(directory, profile_id, direct_domains=None):
    """Return argv after winws2.exe, without invoking a shell or writing files.

    Only HTTP/TLS TCP and QUIC Initial UDP are handled. Voice, STUN, arbitrary
    UDP and flows without a visible hostname pass unchanged. QUIC has the same
    bounded candidate in every preset; a successful TCP probe does not verify it.
    """
    if not isinstance(profile_id, str) or profile_id not in PROFILES:
        raise ValueError("Неизвестный системный способ обхода")
    root = Path(directory).resolve()
    excluded = "--hostlist-exclude-domains=" + _exclusions(direct_domains)
    args = ["--debug=0", "--wf-tcp-out=" + TCP_PORTS, "--wf-udp-out=443",
            "--wf-filter-lan=1", "--wf-dup-check=1", "--ipcache-hostname=0",
            "--lua-init=@" + str(root / "lua" / "zapret-lib.lua"),
            "--lua-init=@" + str(root / "lua" / "zapret-antidpi.lua")]
    split = "multidisorder" if profile_id in ("alt2", "alt4") else "multisplit"
    repeats = {"alt3": 2, "alt4": 6}.get(profile_id, 0)
    for ports, protocol, payload, position in (
        ("80", "http", "http_req", "method+2"),
        (TLS_PORTS, "tls", "tls_client_hello", "1,midsld"),
    ):
        if protocol == "tls":
            args.append("--new")
        args.extend(["--filter-tcp=" + ports, "--filter-l7=" + protocol,
                     excluded, "--out-range=-d10", "--payload=" + payload])
        if repeats:
            args.append(f"--lua-desync=fake:blob=fake_default_{protocol}:tcp_md5:tcp_seq=-10000:repeats={repeats}")
        args.append(f"--lua-desync={split}:pos={position}")
    args.extend(["--new", "--filter-udp=443", "--filter-l7=quic", excluded,
                 "--out-range=-d4", "--payload=quic_initial",
                 "--lua-desync=fake:blob=fake_default_quic:repeats=6"])
    return args
