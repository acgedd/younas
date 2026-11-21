"""One server per data directory.

Chunk locks and upload serialisation live in the process, so two servers on the same database and
storage root must never run at once; a second one on another port would not even fail on the bind.
The server holds an exclusive OS lock on `<data_dir>/yournas.lock` for its whole life. The OS drops
the lock when the process ends, crash included, so a stale lock file never blocks a restart.
"""

from __future__ import annotations

import sys
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

LOCK_FILE_NAME = "yournas.lock"

if sys.platform == "win32":
    import msvcrt

    def _lock(handle: BinaryIO) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(handle: BinaryIO) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class InstanceLockError(Exception):
    """Another server already holds the lock for this data directory."""


class InstanceLock:
    def __init__(self, handle: BinaryIO) -> None:
        self._handle: BinaryIO | None = handle

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        with suppress(OSError):  # closing the handle releases it anyway
            _unlock(handle)
        handle.close()


def acquire_instance_lock(data_dir: Path) -> InstanceLock:
    """Lock `data_dir` for this process. The directory must exist.

    Raises InstanceLockError if another process holds it; OSError if the lock file cannot be opened.
    """
    handle = (data_dir / LOCK_FILE_NAME).open("a+b")  # never truncates, creates if missing
    try:
        _lock(handle)
    except OSError:
        handle.close()
        raise InstanceLockError(
            "another YourNAS server is already running on this data directory"
        ) from None
    return InstanceLock(handle)
