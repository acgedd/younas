"""Storage errors.

Messages are fixed and generic: they never contain client input or server paths, so they are
safe to show. `detail` carries a short reason code (also free of paths and input) for logs.

Suggested HTTP mapping for the API layer:
    InvalidPath, NotADirectoryErr, IsADirectoryErr(reads) -> 400
    NotFound, UnsafePath                                  -> 404 (same body: do not leak which)
    AlreadyExists, NotEmpty, IsADirectoryErr(writes)      -> 409
    Busy                                                  -> 423 (or 409 with retry hint)
    OffsetMismatch                                        -> 409 (send `actual`)
    RangeNotSatisfiable                                   -> 416 (Content-Range: bytes */size)
    TooLarge                                              -> 413
    DiskFull                                              -> 507
    StorageIOError                                        -> 500 (log `detail` and `__cause__`)
"""

from __future__ import annotations


class StorageError(Exception):
    message = "storage error"

    def __init__(self, detail: str = "") -> None:
        super().__init__(self.message)
        self.detail = detail


class InvalidPath(StorageError, ValueError):
    message = "invalid path"


class NotFound(StorageError):
    message = "not found"


class UnsafePath(StorageError):
    """Reparse point or containment failure. Callers answer exactly like NotFound."""

    message = "not found"


class AlreadyExists(StorageError):
    message = "already exists"


class NotEmpty(StorageError):
    message = "directory is not empty"


class Busy(StorageError):
    message = "item is in use"


class IsADirectoryErr(StorageError):
    message = "item is a directory"


class NotADirectoryErr(StorageError):
    message = "item is not a directory"


class DiskFull(StorageError):
    message = "not enough free space"


class TooLarge(StorageError):
    message = "too large"


class StorageIOError(StorageError):
    message = "storage error"


class OffsetMismatch(StorageError):
    message = "offset mismatch"

    def __init__(self, actual: int) -> None:
        super().__init__(f"actual={actual}")
        self.actual = actual


class RangeNotSatisfiable(StorageError):
    message = "range not satisfiable"

    def __init__(self, size: int) -> None:
        super().__init__(f"size={size}")
        self.size = size
