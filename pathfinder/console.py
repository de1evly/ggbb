import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from . import __version__
from .config import Config, endpoint
from . import system_proxy


class APIError(RuntimeError):
    def __init__(self, message, attempts=None):
        super().__init__(message)
        self.attempts = attempts or []


def display_attempts(results):
    stages = {"dns": "DNS IPv4", "dns6": "DNS IPv6", "tcp": "TCP-соединение", "tls": "TLS-рукопожатие",
              "http": "ответ HTTP", "socks_local": "локальный SOCKS", "socks_handshake": "ответ SOCKS",
              "socks_target": "соединение через SOCKS"}
    for result in results:
        stage = stages.get(result.get("stage"), result.get("stage", ""))
        print(f"{result['route']:20} {result['outcome']:22} HTTP {result.get('status') or '—'}  {result.get('latency_ms', 0)} мс  {stage}")
    if any(r["outcome"] == "dns6_error" for r in results):
        print("DNS IPv6: возможно, у домена нет IPv6-адреса; это не означает отказ всего DNS.")


class Client:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.config = Config(self.directory / "config.json")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.launched_discord = False

    def request(self, path, data=None):
        token = (self.directory / "token.txt").read_text(encoding="ascii").strip()
        url = f"http://127.0.0.1:{self.config.data['api_port']}{path}"
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(url, body, {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=125) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                payload = json.load(error)
            except ValueError:
                payload = {}
            raise APIError(payload.get("error", str(error)), payload.get("attempts")) from None


def export_diagnostics(client, directory):
    """Local archive only. No token, browser history, cookies or URL paths."""
    state = client.request("/status")
    # Preserve relationships between domains without exporting the domain names.
    labels = {}

    def alias(value):
        if value not in labels:
            labels[value] = f"service-{len(labels) + 1}"
        return labels[value]

    dpi = state.get("dpi")
    safe_dpi = {"enabled": dpi["enabled"], "version": dpi["version"], "active": dpi["active"],
                "error": bool(dpi["error"])} if dpi else None
    redacted = {"version": __version__, "python": platform.python_version(), "os": platform.system(),
                "auto_manage": state["auto_manage"], "network_error": state["network_error"],
                "dpi": safe_dpi,
                "routes": state["routes"], "choices": [], "attempts": []}
    for kind in ("choices", "attempts"):
        for row in state[kind]:
            item = {k: v for k, v in row.items() if k != "network"}
            item["service"] = alias(item["service"])
            redacted[kind].append(item)
    redacted["connections"] = [{**row, "host": alias(row["host"])} for row in state.get("recent_connections", [])]
    scan = state.get("auto_scan") or {}
    redacted["auto_scan"] = {k: scan.get(k) for k in ("state", "progress", "total", "saved", "unresolved")}
    redacted["auto_scan"]["results"] = [
        {"service": alias(row["service"]), "state": row["state"], "route": row.get("route"),
         "matrix": [{"host": alias(check["host"]), "port": check["port"], "route": check["route"],
                     "outcome": check["outcome"], "status": check.get("status"), "detail": check.get("detail")}
                    for check in row.get("matrix", [])]}
        for row in scan.get("results", [])]
    output = Path(directory) / ("diagnostics-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".zip")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(redacted, ensure_ascii=False, indent=2))
        archive.writestr("README.txt", "Local diagnostic export. Hostnames replaced by service-N. No automatic upload.\n")
    return output


def display_status(state):
    print(f"\nСеть: {state['network']}  |  Режим: {'все публичные HTTPS-домены' if state['auto_manage'] else 'выбранные домены'}")
    if state["network_error"]:
        print("Ошибка сети:", state["network_error"])
    display_dpi(state)
    print(f"{'Сервис':38} {'Способ':20} {'Сбои':5} Проверка")
    for row in sorted(state["choices"], key=lambda r: r["last_used"], reverse=True)[:25]:
        evidence = {"http_reachable": "HTTP доступен", "http_response": "TLS + HTTP ответ; функции не проверены",
                    "functional_ok": "GET / API / WSS проверены",
                    "content_prefix_ok": "проверен префикс страницы",
                    "policy_direct": "прямой доступ по правилу"}.get(row["evidence"], "ответ неоднозначен")
        print(f"{row['service'][:38]:38} {row['route']:20} {row['failures']:<5} {evidence}")
    if not state["choices"]:
        print("Сохранённых решений пока нет. Откройте сайт или запустите поиск.")
    if not any(r["kind"] == "socks5" and not r.get("local_dpi") for r in state["routes"]):
        print("Внешний выход не подключён. Прямые способы сохраняют IP вашего провайдера.")


def display_dpi(state):
    dpi = state.get("dpi")
    if not dpi:
        return
    if dpi["error"]:
        print("Обход DPI:", dpi["error"])
    elif dpi["active"]:
        print(f"Встроенный ByeDPI {dpi['version']}: " + ", ".join(dpi["active"]))
    else:
        print("Встроенный обход DPI отключён в настройках.")


def require_dpi_ready(state):
    dpi = state.get("dpi")
    if state.get("bypass_only") and not state.get("routes"):
        raise RuntimeError("Прокси не включён: нет доступного способа обхода. " + ((dpi or {}).get("error") or "Проверьте встроенный компонент или локальный SOCKS."))
    if dpi and dpi["enabled"] and not dpi["active"] and not any(r["kind"] == "socks5" for r in state.get("routes", [])):
        raise RuntimeError("Прокси не включён: " + (dpi["error"] or "ByeDPI не запустился"))


def enable_proxy(client, directory):
    state = client.request("/status")
    require_dpi_ready(state)
    manual_port = state["proxy_port"] if state["auto_manage"] and state.get("bypass_only") else None
    system_proxy.enable(directory, client.config.data["api_port"], proxy_port=manual_port,
                        direct_domains=state["direct_domains"])


def display_apps(state):
    if not state.get("supported"):
        print("Проверка приложений доступна в Windows.")
        return
    for key, name in (("discord", "Discord"), ("chatgpt", "ChatGPT")):
        app = state.get(key, {})
        running = {True: "запущен", False: "закрыт", None: "состояние неизвестно"}.get(app.get("running"))
        connection = app.get("proxy_connection_observed")
        observed = {True: "есть соединение с нашим прокси", False: "соединение с прокси сейчас не наблюдается",
                    None: "наблюдение за соединениями недоступно"}[connection]
        print(f"{name}: {running}; {observed}.")
    print("Наблюдение за соединением не подтверждает работу всех функций приложения.")


def launch_discord_with_notice(client):
    result = client.request("/apps/discord", {})
    print(result["message"])
    if result["status"] == "launched":
        client.launched_discord = True
        print("После выхода из Pathfinder этот экземпляр Discord потребуется перезапустить обычным ярлыком.")
    return result


def automatic_setup(client, proxy_enabled, target="all"):
    job = client.request("/auto-scan", {"target": target})
    last = None
    print("Автонастройка: проверяю реальные GET, API и WebSocket; рабочие способы сохранятся автоматически.")
    while job.get("state") == "running":
        marker = (job.get("progress"), job.get("phase"))
        if marker != last:
            current = job.get("current", {})
            line = f"Проверки: {job.get('progress', 0)}/{job.get('total', 0)}  {current.get('host', '')}  {current.get('outcome', '')}"
            print("\r" + line.ljust(110), end="", flush=True)
            last = marker
        time.sleep(0.3)
        job = client.request("/auto-scan")
    print()
    print(job.get("message", "Автопроверка завершена."))
    labels = {"ready": "базовые проверки пройдены", "partial": "доступен частично", "unresolved": "способ не найден"}
    for profile in job.get("profiles", []):
        print(f"  {profile['name']}: {labels.get(profile['state'], profile['state'])} ({profile['passed']}/{profile['total']}).")
    for row in job.get("results", []):
        hosts = ", ".join(row["hosts"])
        if row["state"] == "saved":
            print(f"  Сохранено: {hosts} → {row['route']}")
        else:
            outcomes = sorted({check["outcome"] for check in row.get("matrix", [])})
            print(f"  Не настроено: {hosts} — {', '.join(outcomes) or 'нет доступного способа'}")
    if any(profile["id"] == "discord" and profile["state"] == "ready" for profile in job.get("profiles", [])) and proxy_enabled:
        launch_discord_with_notice(client)
    display_apps(client.request("/apps"))
    return job


def ui(directory, activate=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    from .instance_lock import acquire
    lock = acquire(directory)
    client = Client(directory)
    process = None
    log = None
    proxy_enabled = False
    try:
        try:
            client.request("/status")
        except (OSError, RuntimeError, ValueError):
            log = (directory / "backend.log").open("a", encoding="utf-8")
            process = subprocess.Popen([sys.executable, "-m", "pathfinder", "serve", "--data-dir", str(directory)],
                                       cwd=Path(__file__).resolve().parent.parent,
                                       stdout=log, stderr=log,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for _ in range(160):
                if process.poll() is not None:
                    raise RuntimeError(f"Не удалось запустить движок. Подробности: {directory / 'backend.log'}")
                try:
                    client.request("/status")
                    break
                except (OSError, RuntimeError, ValueError):
                    time.sleep(0.25)
            else:
                raise RuntimeError("Движок не ответил за 40 секунд")
        state = client.request("/status")
        if state.get("version") != __version__:
            raise RuntimeError("Работает старая версия движка. Завершите её через 0 в старом меню и запустите Pathfinder снова.")
        if activate:
            enable_proxy(client, directory)
            proxy_enabled = True
        print(f"\nPATHFINDER {__version__} — автоматический подбор пути для HTTPS")
        display_dpi(state)
        if state.get("bypass_only") and state["auto_manage"]:
            print("HTTPS/WSS — через обход; напрямую: " + ", ".join(state["direct_domains"]) + ".")
        if activate and (state.get("auto_scan") or {}).get("state") == "idle":
            automatic_setup(client, proxy_enabled)
        while True:
            print("\n1  Состояние и сохранённые решения\n2  Проверить отдельные способы для домена\n3  Заново выбрать путь\n4  Включить прокси Windows\n5  Выключить / восстановить прокси Windows\n6  Экспортировать диагностику в ZIP\n7  Последние проверки и подключения\n8  Показать ключ для расширения\n9  Подключить локальный SOCKS (Tor / другой клиент)\n10 Автоматически проверить и настроить сервисы\n11 Запустить Discord через обход\n12 Проверить подключения приложений\n0  Выйти")
            command = input("\n> ").strip()
            try:
                if command == "0":
                    break
                if command == "1":
                    display_status(client.request("/status"))
                elif command in ("2", "3"):
                    host, port = endpoint(input("Домен[:порт] (например, web.telegram.org; TLS-порты 443, 8443, 8080): "))
                    print("Проверяю доступные способы…")
                    if command == "2":
                        results = client.request("/scan", {"host": host, "port": port})["results"]
                        display_attempts(results)
                    else:
                        if not client.config.data["auto_manage"]:
                            client.request("/services", {"host": host})
                        result = client.request("/recover", {"host": host, "port": port})
                        print("Выбран способ:", result["route"])
                        if result.get("evidence") in ("http_response", "http_inconclusive"):
                            print("Сервер ответил на пробный запрос. Работу самого сервиса нужно проверить в приложении.")
                elif command == "4":
                    enable_proxy(client, directory)
                    proxy_enabled = True
                    print("Включено для приложений, учитывающих системный прокси. При выходе настройки восстановятся.")
                elif command == "5":
                    system_proxy.disable(directory)
                    proxy_enabled = False
                    print("Настройки Pathfinder сняты; чужие изменения сохранены.")
                elif command == "6":
                    print("Архив:", export_diagnostics(client, directory))
                    print("Домены заменены метками service-N. Отправить архив можно вручную.")
                elif command == "7":
                    status = client.request("/status")
                    for event in reversed(status["attempts"][:20]):
                        print(event["service"], event["route"], event["outcome"], event["status"] or "")
                    print("Последние обращения приложений/браузера к прокси (без привязки к процессу):")
                    for event in status.get("recent_connections", [])[-15:]:
                        print(event["host"], event["port"], event["outcome"], event.get("route") or "")
                elif command == "8":
                    print((directory / "token.txt").read_text(encoding="ascii"))
                elif command == "9":
                    port = int(input("Порт уже запущенного SOCKS на 127.0.0.1 (Tor обычно 9050; 0 — отключить): "))
                    client.request("/socks", {"port": port})
                    print("Способы обновлены. Сам SOCKS-клиент Pathfinder не устанавливает.")
                elif command == "10":
                    target = input("Сервис / домен (Enter — все): ").strip() or "all"
                    automatic_setup(client, proxy_enabled, target)
                elif command == "11":
                    if not proxy_enabled:
                        enable_proxy(client, directory)
                        proxy_enabled = True
                    launch_discord_with_notice(client)
                elif command == "12":
                    display_apps(client.request("/apps"))
            except (OSError, ValueError, RuntimeError) as error:
                print("Ошибка:", error)
                if isinstance(error, APIError):
                    display_attempts(error.attempts)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        if proxy_enabled:
            try:
                system_proxy.disable(directory)
                print("Исходные настройки прокси восстановлены.")
            except (OSError, ValueError, RuntimeError) as error:
                print("Не удалось восстановить прокси:", error, "\nЗапустите: pathfinder restore-proxy")
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if log:
            log.close()
        if client.launched_discord:
            print("Discord запускался с прокси Pathfinder. Полностью закройте его и откройте обычным ярлыком для работы без Pathfinder.")
        lock.close()
