"""One interactive owner for either the proxy or packet mode."""
import os
from pathlib import Path


def acquire(directory):
    lock = (Path(directory) / "console.lock").open("a+b")
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
        raise RuntimeError("Pathfinder уже запущен. Завершите прежнее меню через 0.") from None
    return lock
