import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from pathfinder.instance_lock import acquire
from pathfinder.packet import COMPONENTS, PacketRunner, check_conflicts, verify_components
from pathfinder.packet_console import export_report
from pathfinder.packet_guard import CHILD_MARKER, ProcessHandle, supervise


class ComponentTests(unittest.TestCase):
    def test_every_runtime_dependency_is_verified(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            files = []
            for name in COMPONENTS:
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(name.encode())
                files.append({"path": name, "sha256": hashlib.sha256(name.encode()).hexdigest()})
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"schema": 1, "architecture": "AMD64", "files": files}))
            verify_components(root, manifest)
            for name in COMPONENTS:
                path = root / name
                original = path.read_bytes()
                path.write_bytes(b"modified")
                with self.assertRaises(RuntimeError):
                    verify_components(root, manifest)
                path.write_bytes(original)
            files[0]["path"] = "../outside.exe"
            manifest.write_text(json.dumps({"schema": 1, "architecture": "AMD64", "files": files}))
            with self.assertRaises(RuntimeError):
                verify_components(root, manifest)

    def test_interactive_modes_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as scratch:
            first = acquire(scratch)
            try:
                with self.assertRaises(RuntimeError):
                    acquire(scratch)
            finally:
                first.close()
            acquire(scratch).close()

    def test_conflicts_and_failed_observation_prevent_start(self):
        for code, output in ((0, b'{"Id":123,"ProcessName":"winws2"}'), (1, b''), (0, b'not-json')):
            with patch("pathfinder.packet.subprocess.run", return_value=MagicMock(returncode=code, stdout=output)):
                with self.assertRaises(RuntimeError):
                    check_conflicts()
        for output in (b'[]', b'\r\n'):
            with patch("pathfinder.packet.subprocess.run", return_value=MagicMock(returncode=0, stdout=output)):
                check_conflicts()

    def test_preflight_ignores_only_the_owned_native_process(self):
        output = b'[{"Id":123,"ProcessName":"winws2"}]'
        with patch("pathfinder.packet.subprocess.run", return_value=MagicMock(returncode=0, stdout=output)):
            check_conflicts(ignore_pid=123)
            with self.assertRaises(RuntimeError):
                check_conflicts(ignore_pid=124)
        output = b'[{"Id":123,"ProcessName":"winws2"},{"Id":456,"ProcessName":"winws"}]'
        with patch("pathfinder.packet.subprocess.run", return_value=MagicMock(returncode=0, stdout=output)):
            with self.assertRaises(RuntimeError):
                check_conflicts(ignore_pid=123)

    def test_diagnostics_excludes_private_names_and_startup_output(self):
        report = {"state": "partial", "selected": "alt1", "network": "secret-network", "message": "private-url",
                  "results": [{"profile": "alt1", "passed": 0, "total": 1, "eligible": False,
                               "checks": [{"host": "private.example", "path": "/secret", "outcome": "http_denied", "status": 403,
                                           "detail": "secret-body", "ok": False}]}]}
        with tempfile.TemporaryDirectory() as scratch:
            with zipfile.ZipFile(export_report(report, scratch)) as archive:
                value = archive.read("diagnostics.json").decode()
        for private in ("secret", "private", "network"):
            self.assertNotIn(private, value)
        self.assertIn("403", value)


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    def guard(self, lines=()):
        process = MagicMock(returncode=None, pid=123)
        process.wait = AsyncMock(return_value=0)
        process.stdout.readline = AsyncMock(side_effect=[*lines, b""])
        return process

    async def test_start_uses_inherited_parent_handle_and_verified_child_identity(self):
        parent, native = MagicMock(value=321), MagicMock()
        native.creation_time.return_value = 777
        native.exited.return_value = False
        process = self.guard([(CHILD_MARKER + '{"pid":456,"created":777}\n').encode(),
                              b"windivert initialized. capture is started.\n"])
        runner = PacketRunner()
        with patch("pathfinder.packet.require_supported"), patch("pathfinder.packet.verify_components"), \
             patch("pathfinder.packet.ProcessHandle.open", side_effect=[parent, native]) as open_handle, \
             patch("pathfinder.packet.subprocess.STARTUPINFO", create=True) as startup, \
             patch("pathfinder.packet.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)) as spawn:
            await runner.start("alt1")
            self.assertEqual(runner.native_pid, 456)
            self.assertEqual(runner.current_profile, "alt1")
            self.assertIn("pathfinder.packet_guard", spawn.call_args.args)
            self.assertEqual(startup.return_value.lpAttributeList, {"handle_list": [321]})
            self.assertTrue(spawn.call_args.kwargs["close_fds"])
            open_handle.assert_any_call(456, terminate=True)
            parent.close.assert_called_once()
            await runner.stop()
        process.stdin.close.assert_called_once()
        process.terminate.assert_not_called()
        native.terminate.assert_called_once()
        native.close.assert_called_once()

    async def test_pid_reuse_identity_mismatch_aborts_without_terminating_unrelated_process(self):
        parent, other = MagicMock(value=321), MagicMock()
        other.creation_time.return_value = 999
        process = self.guard([(CHILD_MARKER + '{"pid":456,"created":777}\n').encode()])
        runner = PacketRunner()
        with patch("pathfinder.packet.require_supported"), patch("pathfinder.packet.verify_components"), \
             patch("pathfinder.packet.ProcessHandle.open", side_effect=[parent, other]), \
             patch("pathfinder.packet.subprocess.STARTUPINFO", create=True), \
             patch("pathfinder.packet.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            with self.assertRaises(RuntimeError):
                await runner.start("alt1")
        other.terminate.assert_not_called()
        other.close.assert_called_once()
        process.stdin.close.assert_called_once()
        self.assertIsNone(runner.native_pid)

    async def test_cancellation_during_guard_spawn_waits_for_ownership_then_closes_control_pipe(self):
        pending, release = asyncio.Event(), asyncio.Event()
        process = self.guard()
        async def spawn(*args, **kwargs):
            pending.set()
            await release.wait()
            return process
        runner = PacketRunner()
        with patch("pathfinder.packet.require_supported"), patch("pathfinder.packet.verify_components"), \
             patch("pathfinder.packet.ProcessHandle.open", return_value=MagicMock(value=321)), \
             patch("pathfinder.packet.subprocess.STARTUPINFO", create=True), \
             patch("pathfinder.packet.asyncio.create_subprocess_exec", new=spawn):
            task = asyncio.create_task(runner.start("alt1"))
            await pending.wait()
            task.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        process.stdin.close.assert_called_once()
        process.terminate.assert_not_called()
        process.wait.assert_awaited_once()
        self.assertFalse(runner.alive())

    async def test_stop_reaps_process_and_reader(self):
        runner = PacketRunner()
        runner.process = process = MagicMock(returncode=None)
        process.wait = AsyncMock(return_value=0)
        runner.reader_task = asyncio.create_task(asyncio.sleep(60))
        reader = runner.reader_task
        runner.current_profile = "alt2"
        await runner.stop()
        self.assertTrue(reader.cancelled())
        self.assertIsNone(runner.current_profile)
        process.stdin.close.assert_called_once()
        process.wait.assert_awaited_once()
        await runner.stop()
        process.stdin.close.assert_called_once()

    async def test_guard_timeout_stops_identified_native_before_guard(self):
        runner = PacketRunner()
        runner.process = process = self.guard()
        process.wait.side_effect = [asyncio.TimeoutError(), asyncio.TimeoutError(), 0]
        runner.native_handle = native = MagicMock()
        native.exited.return_value = True
        await runner.stop()
        native.terminate.assert_called()
        native.close.assert_called_once()
        process.terminate.assert_called_once()

    async def test_guard_without_child_identity_is_not_blindly_killed_on_timeout(self):
        runner = PacketRunner()
        runner.process = process = self.guard()
        process.wait.side_effect = asyncio.TimeoutError()
        with self.assertRaises(RuntimeError):
            await runner.stop()
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertIs(runner.process, process)


class GuardTests(unittest.TestCase):
    def exercise_shutdown(self, reason):
        parent_done, started = threading.Event(), threading.Event()
        parent = MagicMock()
        parent.exited.side_effect = parent_done.is_set
        child_holder, results = [], []
        read_fd, write_fd = os.pipe()
        control = os.fdopen(read_fd, "rb")
        writer = os.fdopen(write_fd, "wb")
        def on_start(child):
            child_holder.append(child)
            started.set()
        with tempfile.TemporaryFile() as output:
            def run():
                results.append(supervise([sys.executable, "-c", "import time; time.sleep(60)"],
                                         parent, control, output, on_start=on_start))
            worker = threading.Thread(target=run)
            worker.start()
            try:
                self.assertTrue(started.wait(5))
                if reason == "parent":
                    parent_done.set()
                else:
                    writer.close()
                worker.join(6)
                self.assertFalse(worker.is_alive())
                self.assertIsNotNone(child_holder[0].poll())
                self.assertEqual(results, [0])
            finally:
                writer.close()
                parent_done.set()
                worker.join(6)
                control.close()

    def test_control_pipe_eof_terminates_real_owned_child(self):
        self.exercise_shutdown("pipe")

    def test_controller_exit_terminates_real_owned_child(self):
        self.exercise_shutdown("parent")

    def test_already_exited_parent_prevents_native_launch(self):
        parent = MagicMock()
        parent.exited.return_value = True
        with tempfile.TemporaryFile() as control, tempfile.TemporaryFile() as output, \
             patch("pathfinder.packet_guard.subprocess.Popen") as spawn:
            self.assertEqual(supervise(["unused"], parent, control, output), 0)
        spawn.assert_not_called()

    def test_failed_identity_handshake_still_reaps_native_child(self):
        parent = MagicMock()
        parent.exited.return_value = False
        children = []
        def broken_handshake(child):
            children.append(child)
            raise RuntimeError("handshake failed")
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as control, os.fdopen(write_fd, "wb") as writer, \
             tempfile.TemporaryFile() as output:
            try:
                with self.assertRaises(RuntimeError):
                    supervise([sys.executable, "-c", "import time; time.sleep(60)"],
                              parent, control, output, on_start=broken_handshake)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
            finally:
                writer.close()

    @unittest.skipUnless(os.name == "nt", "Win32 handle identity check")
    def test_process_handle_refers_to_exact_process_and_can_be_inherited(self):
        handle = ProcessHandle.open(os.getpid(), inheritable=True)
        try:
            self.assertFalse(handle.exited())
            self.assertGreater(handle.creation_time(), 0)
            self.assertTrue(os.get_handle_inheritable(handle.value))
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [handle.value]}
            code = "import ctypes,sys; k=ctypes.WinDLL('kernel32'); k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]; sys.exit(0 if k.WaitForSingleObject(int(sys.argv[1]),0)==258 else 1)"
            result = subprocess.run([sys.executable, "-c", code, str(handle.value)],
                                    startupinfo=startup, close_fds=True, timeout=5)
            self.assertEqual(result.returncode, 0)
        finally:
            handle.close()
