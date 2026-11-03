"""Owned, loopback-only ByeDPI workers; no service or system packet driver."""
import asyncio
import ctypes
import hashlib
import os
import socket
import subprocess
from pathlib import Path

VERSION = "0.17.3"
EXE_SHA256 = {
    "eb53ceeeb981cc6735ac24bb1e51e725280b86630e80fdf19ddc4ee4a5b54ef4",  # x64
    "cd3a503f3518d1cb3eb5d5d2a4d6a9fbb7f504125969f273413b4507a6315863",  # x86 (ARM64 emulation)
}
PROFILES = (
    ("dpi-disorder", ["--split", "1+s", "--disorder", "3+s"]),
    ("dpi-oob", ["--oob", "3+s"]),
    ("dpi-tlsrec", ["--tlsrec", "1+s", "--split", "1+s"]),
)


class WindowsJob:
    """Close-on-exit job also terminates workers if the Python backend is killed."""
    def __init__(self):
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                        ("flags", w.DWORD), ("min_ws", ctypes.c_size_t), ("max_ws", ctypes.c_size_t),
                        ("active", w.DWORD), ("affinity", ctypes.c_size_t),
                        ("priority", w.DWORD), ("scheduling", w.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                        ("peak_job", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        for name, args, result in (
            ("CreateJobObjectW", [ctypes.c_void_p, w.LPCWSTR], w.HANDLE),
            ("SetInformationJobObject", [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD], w.BOOL),
            ("OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            ("AssignProcessToJobObject", [w.HANDLE, w.HANDLE], w.BOOL),
            ("CloseHandle", [w.HANDLE], w.BOOL),
        ):
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = Extended()
        info.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, pid):
        handle = self.api.OpenProcess(0x0100 | 0x0001, False, pid)  # SET_QUOTA | TERMINATE
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.api.AssignProcessToJobObject(self.handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(handle)

    def close(self):
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


class DPIWorkers:
    def __init__(self, enabled=True, excluded_ports=()):
        self.enabled = enabled
        self.excluded_ports = set(excluded_ports)
        self.workers = []
        self.error = None
        self.job = None

    async def start(self):
        if not self.enabled:
            return
        if os.name != "nt":
            self.error = "Встроенный ByeDPI в этой сборке доступен только в Windows."
            return
        executable = Path(__file__).resolve().parent.parent / "bin" / "ciadpi.exe"
        if not executable.is_file():
            self.error = "ByeDPI не установлен. Повторите установку Pathfinder."
            return
        if hashlib.sha256(executable.read_bytes()).hexdigest() not in EXE_SHA256:
            self.error = "Хеш ByeDPI не совпал; компонент не запущен. Повторите установку."
            return
        try:
            self.job = WindowsJob()
            for route_id, options in PROFILES:
                while True:
                    with socket.socket() as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        port = reservation.getsockname()[1]
                    if port not in self.excluded_ports:
                        break
                process = subprocess.Popen(
                    [str(executable), "--ip", "127.0.0.1", "--port", str(port),
                     "--conn-ip", "0.0.0.0", "--no-domain", "--no-udp",
                     "--buf-size", "262144", *options],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                worker = {"process": process, "ready": False,
                          "route": {"id": route_id, "kind": "socks5", "host": "127.0.0.1",
                                    "port": port, "local_dpi": True}}
                self.workers.append(worker)
                self.job.assign(process.pid)
                await self.wait_ready(worker)
                worker["ready"] = True
        except (OSError, RuntimeError, asyncio.TimeoutError, EOFError) as error:
            self.error = f"Не удалось запустить ByeDPI: {error}"
            await self.close()

    async def wait_ready(self, worker):
        async def handshake():
            while worker["process"].poll() is None:
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", worker["route"]["port"])
                except OSError:
                    await asyncio.sleep(0.05)
                    continue
                try:
                    writer.write(b"\x05\x01\x00")
                    await writer.drain()
                    if await reader.readexactly(2) != b"\x05\x00":
                        raise RuntimeError("Неверный ответ локального SOCKS")
                    if worker["process"].poll() is not None:
                        break
                    return
                finally:
                    writer.close()
                    await writer.wait_closed()
            raise RuntimeError(f"{worker['route']['id']} завершился при запуске (код {worker['process'].returncode})")
        await asyncio.wait_for(handshake(), 4)

    def routes(self):
        return [w["route"].copy() for w in self.workers if w["ready"] and w["process"].poll() is None]

    def snapshot(self):
        active = [r["id"] for r in self.routes()]
        error = self.error
        if self.workers and len(active) != len(self.workers) and not error:
            error = "Один из процессов ByeDPI остановился. Перезапустите Pathfinder."
        return {"enabled": self.enabled, "version": VERSION, "active": active, "error": error}

    async def close(self):
        if self.job:
            self.job.close()
            self.job = None
        for worker in self.workers:
            process = worker["process"]
            if process.poll() is None:
                process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), 3)
            except asyncio.TimeoutError:
                process.kill()
                await asyncio.to_thread(process.wait)
        self.workers.clear()
