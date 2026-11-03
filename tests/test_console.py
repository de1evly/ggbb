import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from pathfinder.console import automatic_setup, enable_proxy, export_diagnostics


class ConsoleSetupTests(unittest.TestCase):
    def test_global_setup_enables_manual_https_and_pac_with_ru_exception(self):
        class Client:
            config = type("Config", (), {"data": {"api_port": 47831}})()

            def request(self, path):
                return {"auto_manage": True, "bypass_only": True, "proxy_port": 47830,
                        "direct_domains": ["*.ru"], "routes": [{"kind": "socks5"}], "dpi": None}

        with patch("pathfinder.console.system_proxy.enable") as configure:
            enable_proxy(Client(), Path("example"))
            configure.assert_called_once_with(Path("example"), 47831, proxy_port=47830, direct_domains=["*.ru"])

    def test_no_bypass_available_never_enables_global_proxy(self):
        class Client:
            def request(self, path):
                return {"bypass_only": True, "routes": [], "dpi": {"error": "engine missing"}}

        with patch("pathfinder.console.system_proxy.enable") as configure:
            with self.assertRaisesRegex(RuntimeError, "engine missing"):
                enable_proxy(Client(), Path("example"))
            configure.assert_not_called()

    def test_auto_setup_polls_and_launches_discord_after_ready_profile(self):
        class Client:
            launched_discord = False

            def __init__(self):
                self.calls = []

            def request(self, path, data=None):
                self.calls.append((path, data))
                if path == "/auto-scan" and data is not None:
                    return {"state": "running", "progress": 0, "total": 2}
                if path == "/auto-scan":
                    return {"state": "completed", "profiles": [{"id": "discord", "name": "Discord",
                            "state": "ready", "passed": 2, "total": 2}], "results": []}
                if path == "/apps/discord":
                    return {"status": "launched", "message": "Discord launched"}
                if path == "/apps":
                    return {"supported": False}
                raise AssertionError(path)

        client = Client()
        with patch("pathfinder.console.time.sleep"), patch("builtins.print"):
            result = automatic_setup(client, True)
        self.assertEqual(result["state"], "completed")
        self.assertIn(("/auto-scan", {"target": "all"}), client.calls)
        self.assertIn(("/apps/discord", {}), client.calls)
        self.assertTrue(client.launched_discord)

    def test_new_diagnostic_matrix_and_connections_are_redacted(self):
        secret_host = "private-cdn.example.com"
        state = {"auto_manage": True, "network_error": None, "routes": [], "choices": [], "attempts": [],
                 "recent_connections": [{"host": secret_host, "outcome": "tunnel_open", "port": 443}],
                 "auto_scan": {"state": "completed", "results": [{"service": secret_host, "state": "saved",
                      "route": "dpi-test", "matrix": [{"host": secret_host, "port": 443, "route": "dpi-test",
                       "outcome": "functional_ok", "status": 200, "path": "/private?secret=do-not-export"}]}]}}

        class Client:
            def request(self, path):
                return state

        with tempfile.TemporaryDirectory() as directory:
            path = export_diagnostics(Client(), directory)
            with zipfile.ZipFile(path) as archive:
                text = archive.read("diagnostics.json").decode()
        self.assertNotIn(secret_host, text)
        self.assertNotIn("do-not-export", text)
        self.assertIn("service-1", text)
        self.assertEqual(json.loads(text)["connections"][0]["host"], "service-1")
