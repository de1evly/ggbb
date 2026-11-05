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
    selected = report.get("selected")
    if selected:
        print("Выбран:", PROFILES[selected]["name"])
    print(f"Проверки TCP: {report.get('passed', 0)}/{report.get('total', 0)}. QUIC и голос этими пробами не проверены.")
    for row in report.get("results", []):
        print(f"  {row['profile'].upper()}: {row['passed']}/{row['total']}" + ("; ухудшает исходный доступ" if not row.get("eligible") and row["passed"] else ""))
        if row.get("engine_error"):
            print("    Запуск:", row["engine_error"])
    for check in report.get("confirmation", []):
        if not check.get("ok"):
            print("  Недоступно:", check.get("host", check.get("probe_host", "")), check.get("outcome", ""), check.get("status") or "")
    active = report.get("active_profile")
    if active and active != selected:
        print("Сохранён прежний активный вариант:", active.upper())


def export_report(report, directory):
    # Keep only fixed fields; neither hostnames, paths, network IDs nor subprocess
    # output are exported. The local scanner cache remains on this computer.
    fields = ("state", "phase", "selected", "active_profile", "passed", "total", "cached")
    safe = {"version": __version__, **{key: report.get(key) for key in fields}}
    safe["results"] = [
        {"profile": row["profile"], "passed": row["passed"], "total": row["total"],
         "eligible": row.get("eligible"), "checks": [
             {key: check.get(key) for key in ("ok", "outcome", "status", "stage", "latency_ms")}
             for check in row.get("checks", [])]}
        for row in report.get("results", [])]
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
            marker = (report.get("phase"), report.get("progress"), profile)
            if marker != last_progress:
                phase = {"baseline": "исходный доступ", "checking": "сравнение", "confirming": "подтверждение", "health": "контроль"}.get(report.get("phase"), "проверка")
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
                    before = scanner.snapshot().get("selected")
                    try:
                        report = await scanner.health()
                        if report.get("selected") != before or report.get("state") in ("stale", "failed", "unresolved"):
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
