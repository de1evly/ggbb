import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pathfinder import apps


class DesktopAppsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patches = [patch.object(apps.platform, "system", return_value="Windows"),
                        patch.dict(os.environ, {"LOCALAPPDATA": str(self.root)})]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def install(self, variant="Discord", version="1.0.10"):
        executable = self.root / variant / ("app-" + version) / (variant + ".exe")
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"not executed in tests")
        return executable

    def snapshot(self, rows, owners=None):
        return {"processes": [dict(row, ProcessId=row.get("ProcessId", i + 100))
                              for i, row in enumerate(rows)], "proxy_owners": owners}

    def test_launch_uses_newest_installed_version_and_only_per_launch_flags(self):
        self.install(version="1.0.9")
        newest = self.install(version="1.0.10")
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot([])), \
                patch.object(apps.subprocess, "Popen") as popen:
            result = apps.launch_discord(47830)
        self.assertEqual(result["status"], "launched")
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [str(newest), "--proxy-server=http://127.0.0.1:47830",
                                   "--proxy-bypass-list=<local>;*.ru"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["cwd"], str(newest.parent))
        self.assertFalse(result["traffic_verified"])

    def test_running_without_flag_is_not_claimed_to_bypass_system_proxy(self):
        self.install()
        rows = [{"Name": "Discord.exe", "CommandLine": '"C:\\Discord.exe" --some-setting=secret'}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows)), \
                patch.object(apps.subprocess, "Popen") as popen:
            state = apps.inspect_apps(47830)
            result = apps.launch_discord(47830)
        self.assertEqual(state["discord"]["proxy"], "no_explicit_proxy")
        self.assertEqual(result["status"], "restart_required")
        self.assertNotIn("secret", json.dumps(state))
        popen.assert_not_called()

    def test_main_process_proxy_flag_counts_without_requiring_renderer_flag(self):
        rows = [{"Name": "Discord.exe", "CommandLine": '"C:\\Discord.exe" --proxy-server="http://127.0.0.1:47830"'},
                {"Name": "Discord.exe", "CommandLine": '"C:\\Discord.exe" --type=renderer'}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows)), \
                patch.object(apps.subprocess, "Popen") as popen:
            result = apps.launch_discord(47830)
        self.assertEqual(result["status"], "already_configured")
        self.assertFalse(result["traffic_verified"])
        popen.assert_not_called()

    def test_no_proxy_switch_overrides_observed_local_proxy(self):
        rows = [{"Name": "Discord.exe", "CommandLine":
                 "Discord.exe --proxy-server=http://127.0.0.1:47830 --no-proxy-server"}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows)):
            self.assertEqual(apps.inspect_apps(47830)["discord"]["proxy"], "disabled")

    def test_exact_unquoted_local_proxy_is_observed_but_substring_is_not(self):
        for command, expected in (
                ("Discord.exe --proxy-server=http://127.0.0.1:47830", "explicit_local"),
                ('Discord.exe "--proxy-server=http://127.0.0.1:47830"', "explicit_local"),
                ("Discord.exe --proxy-server=http://127.0.0.1:478300", "different_proxy"),
                ("Discord.exe --proxy-server=http://127.0.0.1:47830.evil", "different_proxy")):
            with self.subTest(command=command):
                rows = [{"Name": "Discord.exe", "CommandLine": command}]
                self.assertEqual(apps._proxy_observation(rows, 47830), expected)

    def test_unreadable_command_line_does_not_claim_success(self):
        rows = [{"Name": "Discord.exe", "CommandLine": None}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows)):
            self.assertEqual(apps.inspect_apps(47830)["discord"]["proxy"], "unknown")
            self.assertEqual(apps.launch_discord(47830)["status"], "restart_required")

    def test_failed_process_observation_prevents_uncontrolled_duplicate_launch(self):
        self.install()
        with patch.object(apps, "_process_snapshot", return_value=None), \
                patch.object(apps.subprocess, "Popen") as popen:
            state = apps.inspect_apps(47830)
            result = apps.launch_discord(47830)
        self.assertIsNone(state["discord"]["running"])
        self.assertEqual(result["status"], "observation_failed")
        popen.assert_not_called()

    def test_chatgpt_observation_does_not_offer_unsupported_flags(self):
        rows = [{"Name": "ChatGPT.exe", "CommandLine": "ChatGPT.exe private-data"}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows)):
            state = apps.inspect_apps(47830)
        self.assertTrue(state["chatgpt"]["installed"])
        self.assertTrue(state["chatgpt"]["running"])
        self.assertFalse(state["chatgpt"]["launch_supported"])
        self.assertNotIn("private-data", json.dumps(state))

    def test_non_windows_is_explicitly_unavailable(self):
        with patch.object(apps.platform, "system", return_value="Linux"), \
                patch.object(apps, "_process_snapshot") as snapshot:
            state = apps.inspect_apps(47830)
            result = apps.launch_discord(47830)
        self.assertFalse(state["supported"])
        self.assertEqual(result["status"], "unavailable")
        snapshot.assert_not_called()

    def test_inspection_uses_fixed_powershell_script_and_json(self):
        response = subprocess.CompletedProcess([], 0, b'{"Processes":[{"Name":"Discord.exe","ProcessId":123,"CommandLine":null}],"ProxyOwners":[123]}')
        with patch.object(apps.subprocess, "run", return_value=response) as run:
            snapshot = apps._process_snapshot(47830)
        self.assertEqual(snapshot, {"processes": [{"Name": "Discord.exe", "ProcessId": 123, "CommandLine": None}],
                                    "proxy_owners": [123]})
        args, kwargs = run.call_args
        self.assertEqual(args[0][-1], apps._PROCESS_SCRIPT)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], 8)
        self.assertEqual(kwargs["env"]["PATHFINDER_PROXY_OBSERVE_PORT"], "47830")

    def test_snapshot_errors_do_not_include_raw_command_lines(self):
        with patch.object(apps.subprocess, "run", side_effect=subprocess.TimeoutExpired("private", 8)):
            self.assertIsNone(apps._process_snapshot(47830))
        with patch.object(apps.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"not JSON")):
            self.assertIsNone(apps._process_snapshot(47830))

    def test_invalid_ports_cannot_become_command_arguments(self):
        for invalid in (True, 0, 65536, "47830 --no-sandbox", None):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                apps.launch_discord(invalid)

    def test_other_app_executables_are_not_discovered(self):
        self.install(version="weird")
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot([])), \
                patch.object(apps.subprocess, "Popen") as popen:
            self.assertEqual(apps.launch_discord(47830)["status"], "not_installed")
        popen.assert_not_called()

    def test_launch_failure_is_reported_without_executable_details(self):
        self.install(variant="DiscordPTB")
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot([])), \
                patch.object(apps.subprocess, "Popen", side_effect=OSError("private-path")):
            result = apps.launch_discord(47830)
        self.assertEqual(result["status"], "launch_failed")
        self.assertNotIn("private-path", json.dumps(result))

    def test_socket_observation_includes_discord_children_but_not_other_apps(self):
        rows = [{"Name": "Discord.exe", "ProcessId": 100, "CommandLine": "Discord.exe"},
                {"Name": "Discord.exe", "ProcessId": 101, "CommandLine": "Discord.exe --type=utility"},
                {"Name": "ChatGPT.exe", "ProcessId": 200, "CommandLine": "ChatGPT.exe"}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows, [101, 999])):
            state = apps.inspect_apps(47830)
        self.assertTrue(state["discord"]["proxy_connection_observed"])
        self.assertFalse(state["discord"]["traffic_verified"])
        self.assertFalse(state["chatgpt"]["proxy_connection_observed"])

    def test_socket_observation_distinguishes_unavailable_and_no_connection(self):
        rows = [{"Name": "ChatGPT.exe", "ProcessId": 200, "CommandLine": "ChatGPT.exe"}]
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows, None)):
            self.assertIsNone(apps.inspect_apps(47830)["chatgpt"]["proxy_connection_observed"])
        with patch.object(apps, "_process_snapshot", return_value=self.snapshot(rows, [])):
            self.assertFalse(apps.inspect_apps(47830)["chatgpt"]["proxy_connection_observed"])


if __name__ == "__main__":
    unittest.main()
