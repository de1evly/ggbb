"""Interactive packet mode, without a proxy server or background service."""
import asyncio
import json
import threading
import zipfile
from datetime import datetime
from pathlib import Path

from . import __version__, system_proxy
from .config import Config
from .instance_lock import acquire
from .packet import PacketRunner, check_conflicts, require_no_proxy, require_supported, verify_components
from .packet_profiles import PROFILES
from .packet_scan import PacketScanner


STALE_REASONS = {
    "network_changed": "Сеть изменилась: результаты предыдущей сети не применены.",
    "config_changed": "Настройки изменились: перезапустите Pathfinder перед новым подбором.",
    "network_unstable": "Сеть меняется во время проверки. Автоповтор остановлен; после стабилизации запустите пункт 2.",
}


async def read_input(prompt):
    # A daemon thread allows Ctrl+C/shutdown while input() is pending. A pending
    # executor input would keep asyncio.run's executor shutdown waiting forever.
    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def deliver(value):
        if not future.done():
            future.set_result(value)

    def read():
        try:
            value = input(prompt)
        except (EOFError, KeyboardInterrupt):
            value = "0"
        try:
            loop.call_soon_threadsafe(deliver, value)
        except RuntimeError:
            pass

    threading.Thread(target=read, daemon=True).start()
    return await future


def display(report):
    print("\n" + report.get("message", "Подбор ещё не запускался."))
    reason = report.get("stale_reason")
    if reason in STALE_REASONS:
        print("Причина:", STALE_REASONS[reason])
    if report.get("retry_count"):
        print("Повторных подборов после изменения сети:", report["retry_count"])
    if report.get("transition_recovered"):
        print("После изменения сети выполнена новая проверка.")
    selected = report.get("selected")
    if selected:
        print("Выбран:", PROFILES[selected]["name"])
        print(f"Подтверждённые проверки TCP: {report.get('passed', 0)}/{report.get('total', 0)}.")
    else:
        print("Применённого результата нет.")
    print("Проверки относятся к отдельным страницам, API и WebSocket; QUIC, голос и все функции приложений не проверены.")
    results = report.get("results", [])
    discarded_results = False
    if not selected and not results:
        results = (report.get("discarded_attempt") or {}).get("results", [])
        discarded_results = bool(results)
        if discarded_results:
            print("Результаты из отброшенной попытки: приведены для диагностики, не применены.")
    for row in results:
        note = ""
        if row.get("error"):
            note = "; ошибка выполнения: " + row["error"]
        elif not row.get("eligible") and row["passed"]:
            note = "; не сохраняет ранее доступные проверки"
        elif row.get("confirmation_failed"):
            note = "; повторная проверка не пройдена"
        print(f"  {row['profile'].upper()}: {row['passed']}/{row['total']}" + note)
        if row.get("engine_error"):
            print("    Запуск:", row["engine_error"])
    checks = report.get("confirmation", [])
    if not selected:
        candidates = [row for row in results if row.get("checks")]
        if candidates:
            best = max(candidates, key=lambda row: (row["passed"], bool(row.get("eligible"))))
            origin = " из отброшенной попытки" if discarded_results else ""
            print(f"Лучший проверенный кандидат{origin}: {best['profile'].upper()}, {best['passed']}/{best['total']}; этот результат не применён.")
            checks = best["checks"]
    grouped = {}
    for check in checks:
        identity = (check.get("host", check.get("probe_host", "не указан")), check.get("port", 443))
        grouped.setdefault(identity, []).append(check)
    for (host, port), rows in grouped.items():
        failures = [row for row in rows if not row.get("ok")]
        if not failures:
            continue
        label = host if port == 443 else f"{host}:{port}"
        print(f"  {label}: пройдено {len(rows) - len(failures)}/{len(rows)} проверок.")
        for check in failures:
            status = f"; HTTP {check['status']}" if check.get("status") is not None else ""
            stage = f"; этап: {check['stage']}" if check.get("stage") else ""
            detail = f"; причина: {check['detail']}" if check.get("detail") else ""
            print(f"    {check.get('method', 'GET')}: {check.get('outcome', 'unknown')}{status}{stage}{detail}")
    active = report.get("active_profile")
    if active and active != selected:
        print("Сохранён прежний активный вариант:", active.upper())


def export_report(report, directory):
    # Keep only fixed fields; neither hostnames, paths, network IDs nor subprocess
    # output are exported. Aliases relate checks across the candidate matrix,
    # baseline and confirmation without exposing the original hostnames.
    fields = ("state", "phase", "selected", "active_profile", "passed", "total", "cached",
              "retry_count", "transition_recovered")
    safe = {"version": __version__, **{key: report.get(key) for key in fields}}
    safe["stale_reason"] = report.get("stale_reason") if report.get("stale_reason") in STALE_REASONS else None
    safe["error"] = report.get("error") if report.get("error") in {
        "preflight_failed", "network_detection_failed", "process_exited", "start_failed"} else None
    aliases = {}
    stages = {"connect", "dns", "dns6", "tcp", "tls", "http", "probe", "socks_local", "socks_handshake", "socks_target"}
    outcomes = {"functional_ok", "content_prefix_ok", "websocket_ok", "http_reachable", "http_response",
                "http_inconclusive", "http_denied", "content_mismatch", "certificate_error", "probe_error"}
    outcomes |= {stage + suffix for stage in stages for suffix in ("_timeout", "_error")}
    details = {"response_valid", "status_not_expected", "body_marker_missing", "invalid_json", "json_keys_missing",
               "validated_prefix", "websocket_upgrade_valid", "websocket_upgrade_invalid", "certificate_invalid",
               "timeout", "dns_failed", "response_incomplete", "connection_failed", "probe_failed",
               "response_too_large", "invalid_http", "ambiguous_framing", "transfer_encoding_unsupported",
               "invalid_chunk", "content_encoding_unsupported", "prefix_encoding_unsupported", "invalid_gzip",
               "method_unsupported", "invalid_path", "too_many_interim_responses", "invalid_check"}

    def safe_checks(checks):
        result = []
        for check in checks:
            host = check.get("host", check.get("probe_host"))
            identity = (host, check.get("port", 443)) if host else (None, check.get("id"))
            alias = aliases.setdefault(identity, "service-" + str(len(aliases) + 1))
            value = {key: check.get(key) for key in ("ok", "status", "latency_ms")}
            value.update(service=alias,
                         method=check.get("method") if check.get("method") in {"GET", "HEAD", "WSS"} else None,
                         outcome=check.get("outcome") if check.get("outcome") in outcomes else "unknown",
                         stage=check.get("stage") if check.get("stage") in stages else None,
                         detail=check.get("detail") if check.get("detail") in details else None)
            result.append(value)
        return result

    def safe_results(results):
        return [
            {"profile": row["profile"], "passed": row["passed"], "total": row["total"],
             "eligible": row.get("eligible"), "confirmation_failed": row.get("confirmation_failed", False),
             "error": row.get("error") if row.get("error") in {"start_failed", "process_exited"} else None,
             "checks": safe_checks(row.get("checks", []))}
            for row in results]

    safe["baseline"] = safe_checks(report.get("baseline", []))
    safe["results"] = safe_results(report.get("results", []))
    safe["confirmation"] = safe_checks(report.get("confirmation", []))
    discarded = report.get("discarded_attempt")
    if discarded:
        safe["discarded_attempt"] = {
            "total": discarded.get("total"),
            "stale_reason": discarded.get("stale_reason") if discarded.get("stale_reason") in STALE_REASONS else None,
            "baseline": safe_checks(discarded.get("baseline", [])),
            "results": safe_results(discarded.get("results", [])),
            "confirmation": safe_checks(discarded.get("confirmation", [])),
        }
    output = Path(directory) / ("packet-diagnostics-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".zip")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(safe, ensure_ascii=False, indent=2))
    return output


async def ui(directory, owner_sid=None):
    require_supported(owner_sid)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    lock = acquire(directory)
    runner = monitor = None
    try:
        config = Config(directory / "config.json")
        runner = PacketRunner(config.data["direct_domains"])
        verify_components(runner.directory)
        await asyncio.to_thread(check_conflicts)
        # Remove stale settings belonging to our proxy mode, preserving any
        # external changes. External proxies must not contaminate measurements.
        system_proxy.disable(directory)
        require_no_proxy()
        scanner = PacketScanner(runner, directory, config)
        busy = asyncio.Lock()
        last_progress = None

        def progress(report):
            nonlocal last_progress
            profile = report.get("current", {}).get("profile", "")
            marker = (report.get("phase"), report.get("progress"), profile, report.get("retry_count"))
            if marker != last_progress:
                phase = {"baseline": "исходный доступ", "checking": "сравнение", "confirming": "подтверждение",
                         "health": "контроль", "stabilizing": "ожидание стабильной сети",
                         "retrying": "повторная проверка в новой сети"}.get(report.get("phase"), "проверка")
                print(f"\rПодбор ALT: {phase} {profile.upper()}  {report.get('progress', 0)}/{report.get('steps', 0)}".ljust(100), end="", flush=True)
                last_progress = marker

        print(f"\nPATHFINDER {__version__} — системный обход на zapret2")
        print("Варианты ALT проверяются по очереди. Во время подбора возможны краткие разрывы соединений.")
        print("HTTP/TLS и QUIC с видимым именем: обход; .ru и локальная сеть: без изменений.")
        print("При скрытом имени сайта (ECH) исключение .ru не гарантируется. Голос и произвольный UDP не обрабатываются.")
        print("Полностью перезапустите Discord, если раньше запускали его с параметром прокси.")
        print("После выхода обработка пакетов остановится. Автозапуска службы Pathfinder нет.")
        async with busy:
            display(await scanner.scan(progress=progress))

        async def watch():
            while True:
                await asyncio.sleep(120)
                if busy.locked():
                    continue
                async with busy:
                    before = scanner.snapshot()
                    try:
                        report = await scanner.health()
                        # health() decides when another scan is justified. Do not
                        # repeat an unchanged paused report at every monitor tick.
                        changed = any(report.get(key) != before.get(key) for key in
                                      ("selected", "active_profile", "state", "stale_reason", "finished", "passed"))
                        if changed and (report.get("selected") != before.get("selected")
                                        or report.get("state") in ("stale", "failed", "unresolved")):
                            display(report)
                    except (OSError, RuntimeError, ValueError):
                        print("\nФоновая проверка не завершена; повторите подбор через пункт 2.")

        monitor = asyncio.create_task(watch())
        while True:
            print("\n1  Состояние\n2  Заново подобрать ALT для всех сервисов\n3  Проверить и подобрать для домена / сервиса\n4  Проверить сохранённый вариант\n5  Экспортировать диагностику ZIP\n0  Выйти и остановить обход")
            command = (await read_input("\n> ")).strip()
            if command == "0":
                break
            try:
                if command == "1":
                    display(scanner.snapshot())
                    print("Обработка пакетов:", "работает" if runner.alive() else "остановлена")
                elif command in ("2", "3", "4"):
                    target = "all"
                    if command == "3":
                        target = (await read_input("Сервис / домен[:порт] (Enter — все): ")).strip() or "all"
                    async with busy:
                        report = await scanner.health(progress=progress) if command == "4" else await scanner.scan(target, progress=progress, force=True)
                        display(report)
                elif command == "5":
                    print("Архив:", export_report(scanner.snapshot(), directory))
            except (OSError, ValueError, RuntimeError) as error:
                print("Ошибка:", error)
    finally:
        if monitor:
            monitor.cancel()
            await asyncio.gather(monitor, return_exceptions=True)
        if runner:
            await runner.stop()
        lock.close()
        print("Системный обход остановлен.")
