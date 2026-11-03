import argparse
import asyncio
import os
import secrets
import sys
from pathlib import Path
from .config import Config
from .engine import Engine
from .network import detect_network
from .server import Servers
from .store import Store


async def run(directory):
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    config = Config(directory / "config.json")
    token_file = directory / "token.txt"
    if not token_file.exists():
        token_file.write_text(secrets.token_urlsafe(32), encoding="ascii")
    os.chmod(token_file, 0o600)
    token = token_file.read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise ValueError("Некорректный token.txt; удалите файл и перезапустите")
    network = await detect_network(config.data.get("network_label", ""))
    store = Store(directory / "routes.sqlite3")
    os.chmod(directory / "routes.sqlite3", 0o600)
    engine = Engine(config, store, network)
    handlers = Servers(engine, token)
    proxy = api = None
    monitor_task = None
    health_task = None

    async def health_monitor():
        while True:
            await asyncio.sleep(30)
            await engine.health_check()

    async def monitor():
        while True:
            await asyncio.sleep(15)
            try:
                detected = await detect_network(config.data.get("network_label", ""))
                if detected != engine.network:
                    engine.network = detected
                    print("Сеть изменилась; используются отдельные результаты.", flush=True)
                engine.network_error = None
            except (OSError, ValueError, RuntimeError):
                engine.network_error = "Не удалось определить сеть; новые подключения приостановлены"

    try:
        proxy = await asyncio.start_server(handlers.proxy, "127.0.0.1", config.data["proxy_port"], limit=16384)
        api = await asyncio.start_server(handlers.api, "127.0.0.1", config.data["api_port"], limit=16384)
        print(f"Pathfinder 0.1 — локальный прототип\nПрокси: 127.0.0.1:{config.data['proxy_port']}\nAPI: 127.0.0.1:{config.data['api_port']}\nДанные: {directory}\nКлюч для расширения: в файле token.txt\nОстановить: Ctrl+C", flush=True)
        monitor_task = asyncio.create_task(monitor())
        health_task = asyncio.create_task(health_monitor())
        await asyncio.gather(proxy.serve_forever(), api.serve_forever())
    finally:
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if health_task:
            health_task.cancel()
            await asyncio.gather(health_task, return_exceptions=True)
        for server in (proxy, api):
            if server:
                server.close()
                await server.wait_closed()
        await handlers.shutdown()
        store.close()


def main():
    for stream in (sys.stdout, sys.stderr):
        if not stream.isatty() and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Pathfinder — адаптивный локальный HTTPS-прокси")
    parser.add_argument("command", nargs="?", choices=["ui", "serve", "restore-proxy"], default="ui")
    parser.add_argument("--activate", action="store_true", help="Включить прокси Windows на время работы меню")
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "Pathfinder")
    args = parser.parse_args()
    try:
        directory = args.data_dir.resolve()
        if args.command == "ui":
            from .console import ui
            ui(directory, args.activate)
        elif args.command == "restore-proxy":
            from .system_proxy import disable
            disable(directory)
            print("Настройки Pathfinder сняты")
        else:
            asyncio.run(run(directory))
    except KeyboardInterrupt:
        print("Pathfinder остановлен. Отключите его в расширении для обычного доступа.")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Ошибка запуска: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
