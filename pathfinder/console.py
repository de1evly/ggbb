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

    redacted = {"version": __version__, "python": platform.python_version(), "os": platform.system(),
                "auto_manage": state["auto_manage"], "network_error": state["network_error"],
                "routes": state["routes"], "choices": [], "attempts": []}
    for kind in ("choices", "attempts"):
        for row in state[kind]:
            item = {k: v for k, v in row.items() if k != "network"}
            item["service"] = alias(item["service"])
            redacted[kind].append(item)
    output = Path(directory) / ("diagnostics-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".zip")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", json.dumps(redacted, ensure_ascii=False, indent=2))
        archive.writestr("README.txt", "Local diagnostic export. Hostnames replaced by service-N. No automatic upload.\n")
    return output


def display_status(state):
    print(f"\nСеть: {state['network']}  |  Режим: {'все публичные HTTPS-домены' if state['auto_manage'] else 'выбранные домены'}")
    if state["network_error"]:
        print("Ошибка сети:", state["network_error"])
    print(f"{'Сервис':38} {'Способ':20} {'Сбои':5} Проверка")
    for row in sorted(state["choices"], key=lambda r: r["last_used"], reverse=True)[:25]:
        evidence = {"http_reachable": "HTTP доступен", "http_response": "TLS + HTTP ответ; функции не проверены",
                    "policy_direct": "прямой доступ по правилу"}.get(row["evidence"], "ответ неоднозначен")
        print(f"{row['service'][:38]:38} {row['route']:20} {row['failures']:<5} {evidence}")
    if not state["choices"]:
        print("Сохранённых решений пока нет. Откройте сайт или запустите поиск.")
    if not any(r["kind"] == "socks5" for r in state["routes"]):
        print("Внешний выход не подключён. Прямые способы сохраняют IP вашего провайдера.")


def ui(directory, activate=False):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    # OS-backed lock is released even if the console crashes.
    lock = (directory / "console.lock").open("a+b")
    lock.seek(0)
    lock.write(b"0")
    lock.flush()
    lock.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise RuntimeError("Консоль Pathfinder уже запущена") from None
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
            for _ in range(80):
                if process.poll() is not None:
                    raise RuntimeError(f"Не удалось запустить движок. Подробности: {directory / 'backend.log'}")
                try:
                    client.request("/status")
                    break
                except (OSError, RuntimeError, ValueError):
                    time.sleep(0.25)
            else:
                raise RuntimeError("Движок не ответил за 20 секунд")
        state = client.request("/status")
        if state.get("version") != __version__:
            raise RuntimeError("Работает старая версия движка. Завершите её через 0 в старом меню и запустите Pathfinder снова.")
        if activate:
            system_proxy.enable(directory, client.config.data["api_port"])
            proxy_enabled = True
        print(f"\nPATHFINDER {__version__} — автоматический подбор пути для HTTPS")
        print("Проверка HEAD подтверждает доступность адреса, но не всех функций сервиса.")
        while True:
            print("\n1  Состояние и сохранённые решения\n2  Сканировать способы для домена\n3  Заново выбрать путь\n4  Включить прокси Windows\n5  Выключить / восстановить прокси Windows\n6  Экспортировать диагностику в ZIP\n7  Показать последние события\n8  Показать ключ для расширения\n9  Подключить локальный SOCKS (Tor / другой клиент)\n0  Выйти")
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
                    system_proxy.enable(directory, client.config.data["api_port"])
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
                    for event in reversed(client.request("/status")["attempts"][:20]):
                        print(event["service"], event["route"], event["outcome"], event["status"] or "")
                elif command == "8":
                    print((directory / "token.txt").read_text(encoding="ascii"))
                elif command == "9":
                    port = int(input("Порт уже запущенного SOCKS на 127.0.0.1 (Tor обычно 9050; 0 — отключить): "))
                    client.request("/socks", {"port": port})
                    print("Способы обновлены. Сам SOCKS-клиент Pathfinder не устанавливает.")
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
        lock.close()
