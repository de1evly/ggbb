"""Independent owner of winws2, compatible with its own restricted Windows Job.

The controller supplies an inherited handle to its actual process, not a PID.
The guard stops its child on controller exit, control-pipe EOF, or its own normal
shutdown. It never puts winws2 into a second Job (upstream sets UI restrictions).
"""
import ctypes
import json
import os
import subprocess
import sys
import threading


CHILD_MARKER = "PATHFINDER_PACKET_CHILD "


class ProcessHandle:
    """Owned Win32 process handle, retaining identity even after PID reuse."""
    def __init__(self, value, owned=True):
        from ctypes import wintypes as w
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
            ("OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ("CloseHandle", [w.HANDLE], w.BOOL),
            ("WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
            ("TerminateProcess", [w.HANDLE, w.UINT], w.BOOL),
            ("GetProcessTimes", [w.HANDLE, ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME),
                                 ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME)], w.BOOL),
        ):
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        self.value = value
        self.owned = owned

    @classmethod
    def open(cls, pid, *, terminate=False, inheritable=False):
        result = cls(None)
        rights = 0x100000 | 0x1000 | (0x0001 if terminate else 0)  # SYNCHRONIZE, QUERY_LIMITED_INFORMATION
        result.value = result.api.OpenProcess(rights, inheritable, pid)
        if not result.value:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def exited(self):
        result = self.api.WaitForSingleObject(self.value, 0)
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 0

    def wait(self, seconds):
        result = self.api.WaitForSingleObject(self.value, int(seconds * 1000))
        if result == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        return result == 0

    def creation_time(self):
        from ctypes import wintypes as w
        created, ended, kernel, user = (w.FILETIME() for _ in range(4))
        if not self.api.GetProcessTimes(self.value, ctypes.byref(created), ctypes.byref(ended),
                                       ctypes.byref(kernel), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (created.dwHighDateTime << 32) | created.dwLowDateTime

    def terminate(self):
        if not self.exited() and not self.api.TerminateProcess(self.value, 1):
            # The process may have exited between the check and termination.
            if not self.exited():
                raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.value and self.owned:
            self.api.CloseHandle(self.value)
        self.value = None


def _stop_child(child):
    if child.poll() is None:
        try:
            child.terminate()
        except ProcessLookupError:
            pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


def supervise(command, parent, control, output, *, on_start=None, cwd=None):
    """Internal supervision primitive; tests may supply a harmless Python child."""
    stopping = threading.Event()

    def control_reader():
        try:
            control.read(1)  # EOF or any byte means stop; the pipe is controller-only.
        finally:
            stopping.set()

    threading.Thread(target=control_reader, daemon=True).start()
    child = None
    try:
        if parent.exited() or stopping.is_set():
            return 0
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, close_fds=True, cwd=cwd,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if on_start:
            on_start(child)
        while child.poll() is None and not parent.exited() and not stopping.is_set():
            stopping.wait(0.1)
        return child.returncode or 0
    finally:
        if child is not None:
            _stop_child(child)


def main():
    if os.name != "nt" or len(sys.argv) != 5:
        return 2
    parent = None
    try:
        # This inherited handle refers to the original controller process even
        # if that process has already exited and its numeric PID is reused.
        parent = ProcessHandle(int(sys.argv[1]))
        from pathlib import Path
        from .packet import verify_components
        from .packet_profiles import build_args
        directory = Path(sys.argv[2])
        verify_components(directory)
        args = build_args(directory, sys.argv[3], json.loads(sys.argv[4]))

        def started(child):
            identity = ProcessHandle(int(child._handle), owned=False)
            value = {"pid": child.pid, "created": identity.creation_time()}
            sys.stdout.write(CHILD_MARKER + json.dumps(value, separators=(",", ":")) + "\n")
            sys.stdout.flush()

        return supervise([str(directory / "winws2.exe"), *args], parent, sys.stdin.buffer,
                         sys.stdout.buffer, on_start=started, cwd=directory)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("Pathfinder packet guard could not start or stop its owned process.", flush=True)
        return 1
    finally:
        if parent:
            parent.close()


if __name__ == "__main__":
    raise SystemExit(main())
