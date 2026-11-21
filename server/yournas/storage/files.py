"""File operations inside one space.

Every function takes an already-chosen space root plus validated path components and calls
`paths.resolve` itself; none accepts a raw client path. Windows quirks handled here: read-only
files, files held open by another process (-> Busy), case-insensitive names (NTFS answers
"exists" for a different casing), and names that cannot be addressed (never listed).

Concurrency: appends to one upload (and finalize of one upload) must be serialized by the
caller, e.g. a per-upload lock. Nothing here locks.
"""

from __future__ import annotations

import errno
import heapq
import logging
import os
import re
import shutil
import stat
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Literal

from yournas.core.logging_setup import error_fields

from .errors import (
    AlreadyExists,
    Busy,
    DiskFull,
    InvalidPath,
    IsADirectoryErr,
    NotADirectoryErr,
    NotEmpty,
    NotFound,
    OffsetMismatch,
    RangeNotSatisfiable,
    StorageError,
    StorageIOError,
    TooLarge,
    UnsafePath,
)
from .paths import check_space_name, resolve, validate_relative_path
from .root import force_remove, is_reparse_stat

log = logging.getLogger("yournas.storage")

CHUNK = 256 * 1024
_UPLOAD_ID = re.compile(r"[a-f0-9]{32}")
_RANGE = re.compile(r"([0-9]*)-([0-9]*)")
_WIN_DISK_FULL = (39, 112)  # ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL
_WIN_DIR_NOT_EMPTY = 145
_HUGE = 10**18

Kind = Literal["file", "dir"]


@dataclass(frozen=True)
class Entry:
    name: str
    kind: Kind
    size: int | None
    modified: float  # UTC epoch seconds


@dataclass(frozen=True)
class Page:
    entries: tuple[Entry, ...]
    next_after: str | None


@dataclass(frozen=True)
class RangeSpec:
    start: int
    length: int

    @property
    def end(self) -> int:
        """Last byte position, inclusive (as in Content-Range)."""
        return self.start + self.length - 1


class OpenFile:
    """A read handle plus the size and mtime taken from that same handle. Close it."""

    def __init__(self, fh: BinaryIO, size: int, mtime: float) -> None:
        self.fh = fh
        self.size = size
        self.mtime = mtime

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> OpenFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def translate_os_error(exc: OSError) -> StorageError:
    """Map an OSError to a path-free StorageError. The original stays as __cause__."""
    if isinstance(exc, PermissionError):
        return Busy("permission")
    if isinstance(exc, FileNotFoundError | NotADirectoryError):
        return NotFound("os-missing")
    if exc.errno == errno.ENOSPC or getattr(exc, "winerror", None) in _WIN_DISK_FULL:
        return DiskFull("disk-full")
    if exc.errno == errno.ENOTEMPTY or getattr(exc, "winerror", None) == _WIN_DIR_NOT_EMPTY:
        return NotEmpty("not-empty")
    return StorageIOError(f"errno={exc.errno}")


def _guard[T](fn: Callable[[], T]) -> T:
    try:
        return fn()
    except OSError as exc:
        raise translate_os_error(exc) from exc


def _kind(st: os.stat_result) -> Kind:
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    raise UnsafePath("special-file")


def _entry(name: str, st: os.stat_result) -> Entry:
    kind = _kind(st)
    return Entry(name, kind, st.st_size if kind == "file" else None, st.st_mtime)


def _lstat(path: Path) -> os.stat_result:
    return _guard(lambda: os.lstat(path))


def lstat_or_none(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise translate_os_error(exc) from exc


# --------------------------------------------------------------------------- listing / stat


def list_dir(space_root: Path, parts: tuple[str, ...], *, limit: int, after: str | None) -> Page:
    """One page of a folder, sorted by (name.casefold(), name).

    `after` is the last name of the previous page; the cursor is a sort key, so it stays valid
    if that entry is deleted meanwhile. Reparse points, special files and names that could not be
    addressed again (invalid or not NFC) are skipped. Memory is bounded by `limit`.
    """
    if limit < 1:
        raise ValueError("limit must be positive")
    path = resolve(space_root, parts, must_exist=True)
    if not stat.S_ISDIR(_lstat(path).st_mode):
        raise NotADirectoryErr("target-is-file")
    after_key = None if after is None else (after.casefold(), after)

    def candidates() -> Iterator[tuple[str, str, Entry]]:
        with os.scandir(path) as it:
            for de in it:
                name = de.name
                try:
                    if validate_relative_path(name) != (name,):
                        continue
                    st = de.stat(follow_symlinks=False)  # no extra syscall on Windows
                    if is_reparse_stat(st):
                        continue
                    entry = _entry(name, st)
                except (InvalidPath, UnsafePath, OSError):  # unaddressable, special, or vanished
                    continue
                key = (name.casefold(), name)
                if after_key is None or key > after_key:
                    yield key[0], key[1], entry

    picked = _guard(lambda: heapq.nsmallest(limit + 1, candidates(), key=lambda t: (t[0], t[1])))
    page = tuple(e for _, _, e in picked[:limit])
    return Page(page, page[-1].name if len(picked) > limit else None)


def stat_item(space_root: Path, parts: tuple[str, ...]) -> Entry:
    path = resolve(space_root, parts, must_exist=True)
    return _entry(parts[-1] if parts else "", _lstat(path))


# --------------------------------------------------------------------------- mkdir / delete


def make_dir(space_root: Path, parts: tuple[str, ...]) -> Entry:
    """Create one folder level. The parent must exist; the space root cannot be created."""
    if not parts:
        raise InvalidPath("space-root")
    target = resolve(space_root, parts, must_exist=False)  # also checks the final length
    try:
        # Atomic. A missing parent raises FileNotFoundError (-> NotFound); NTFS reports a
        # different casing of an existing name as FileExistsError (-> AlreadyExists).
        os.mkdir(target)
    except FileExistsError:
        raise AlreadyExists("exists") from None
    except OSError as exc:
        raise translate_os_error(exc) from exc
    return _entry(parts[-1], _lstat(target))


def _remove_link(path: Path) -> None:
    """Remove a symlink/junction itself, never its target."""
    try:
        force_remove(os.unlink, path)
    except OSError:
        force_remove(os.rmdir, path)


def _rmtree(top: Path) -> int:
    """Delete a tree without ever following a reparse point. Every node is lstat'ed first."""
    removed = 0
    stack: list[tuple[Path, bool]] = [(top, False)]
    while stack:
        path, children_done = stack.pop()
        if children_done:
            force_remove(os.rmdir, path)
            removed += 1
            continue
        st = os.lstat(path)
        if is_reparse_stat(st):
            _remove_link(path)
            removed += 1
        elif stat.S_ISDIR(st.st_mode):
            stack.append((path, True))
            with os.scandir(path) as it:
                stack.extend((Path(de.path), False) for de in it)
        else:
            force_remove(os.unlink, path)
            removed += 1
    return removed


def delete_item(space_root: Path, parts: tuple[str, ...], *, recursive: bool) -> int:
    """Delete a file or folder and return how many filesystem entries were removed.

    A non-empty folder needs recursive=True (else NotEmpty). Links found inside a tree are
    unlinked, never followed. If a recursive delete fails midway (Busy), what was already
    removed stays removed.
    """
    if not parts:
        raise InvalidPath("space-root")
    path = resolve(space_root, parts, must_exist=True)
    st = _lstat(path)
    try:
        if stat.S_ISDIR(st.st_mode):
            if recursive:
                return _rmtree(path)
            force_remove(os.rmdir, path)
            return 1
        force_remove(os.unlink, path)
        return 1
    except OSError as exc:
        raise translate_os_error(exc) from exc


# --------------------------------------------------------------------------- space folders


def _space_dir(base: Path, name: str) -> tuple[Path, os.stat_result | None]:
    """`base/<name>` and its lstat (None if missing). `base` (e.g. shared/) must be a plain
    directory, else UnsafePath: a broken base is an error, never "empty"."""
    check_space_name(name)
    base_st = lstat_or_none(base)
    if base_st is None:
        raise NotFound("base-missing")
    if is_reparse_stat(base_st) or not stat.S_ISDIR(base_st.st_mode):
        raise UnsafePath("base-not-plain-dir")
    target = base / name
    return target, lstat_or_none(target)


def dir_is_empty(base: Path, name: str) -> bool:
    """True if the space folder `base/<name>` is missing or has no entry at all.

    Counts every entry, including hidden ones and names no listing would ever show (invalid,
    not NFC, reserved, reparse points, special files), because a delete decision must not be
    blind to what a listing hides. A reparse point or a plain file in the folder's place is not
    "empty": the answer is False so the caller refuses.
    """
    target, st = _space_dir(base, name)
    if st is None:
        return True
    if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
        return False

    def probe() -> bool:
        with os.scandir(target) as it:
            return next(it, None) is None

    return _guard(probe)


def remove_empty_dir(base: Path, name: str) -> bool:
    """Remove the space folder `base/<name>` only if it is empty, with os.rmdir and nothing else
    (never a recursive delete). True if it is gone (also when it was already missing).

    A reparse point or a plain file in its place raises UnsafePath and is left alone. A folder
    with any entry raises NotEmpty (the filesystem decides atomically, so an entry created
    between a check and this call is never lost).
    """
    target, st = _space_dir(base, name)
    if st is None:
        return True
    if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePath("space-dir-not-plain-dir")
    _guard(lambda: os.rmdir(target))
    return True


# --------------------------------------------------------------------------- download


def open_for_read(space_root: Path, parts: tuple[str, ...]) -> OpenFile:
    path = resolve(space_root, parts, must_exist=True)
    if stat.S_ISDIR(_lstat(path).st_mode):
        raise IsADirectoryErr("target-is-dir")
    try:
        fh = open(path, "rb")  # noqa: SIM115 - ownership passes to OpenFile
    except OSError as exc:
        raise translate_os_error(exc) from exc
    try:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePath("not-a-regular-file")
        return OpenFile(fh, st.st_size, st.st_mtime)
    except BaseException:
        fh.close()
        raise


def iter_range(
    fh: BinaryIO, start: int, length: int, chunk: int = CHUNK, *, close: bool = False
) -> Generator[bytes]:
    """Yield `length` bytes from `start`. With close=True the handle is closed when the
    generator finishes, fails or is closed (not if it is never started)."""
    if start < 0 or length < 0 or chunk < 1:
        raise ValueError("invalid range")
    try:
        fh.seek(start)
        remaining = length
        while remaining > 0:
            data = fh.read(min(chunk, remaining))
            if not data:
                return  # file shrank while streaming
            remaining -= len(data)
            yield data
    finally:
        if close:
            fh.close()


def _to_int(digits: str) -> int | None:
    if not digits:
        return None
    return _HUGE if len(digits) > 18 else int(digits)


def parse_range_header(header: str | None, size: int) -> RangeSpec | None:
    """Parse a single `bytes=a-b`, `a-` or `-n` range against a file of `size` bytes.

    None means "serve the whole file": no header, another unit, several ranges, or a malformed
    value (RFC 9110 says to ignore those). Unsatisfiable ranges raise RangeNotSatisfiable.
    """
    if not header:
        return None
    unit, sep, spec = header.partition("=")
    if not sep or unit.strip().lower() != "bytes":
        return None
    spec = spec.strip()
    if "," in spec:
        return None
    m = _RANGE.fullmatch(spec)
    if m is None:
        return None
    first, last = (_to_int(g) for g in m.groups())
    if first is None:
        if last is None:
            return None
        if last == 0 or size == 0:
            raise RangeNotSatisfiable(size)
        start = max(size - last, 0)
        return RangeSpec(start, size - start)
    if last is not None and last < first:
        return None
    if first >= size:
        raise RangeNotSatisfiable(size)
    end = size - 1 if last is None else min(last, size - 1)
    return RangeSpec(first, end - first + 1)


# --------------------------------------------------------------------------- resumable upload


def staging_path(tmp: Path, upload_id: str) -> Path:
    if not isinstance(upload_id, str) or not _UPLOAD_ID.fullmatch(upload_id):
        raise InvalidPath("bad-upload-id")
    return tmp / f"{upload_id}.part"


def _plain_file(path: Path) -> os.stat_result:
    st = lstat_or_none(path)
    if st is None:
        raise NotFound("staging-missing")
    if is_reparse_stat(st) or not stat.S_ISREG(st.st_mode):
        raise UnsafePath("staging-not-plain-file")
    return st


def create_staging(tmp: Path, upload_id: str) -> Path:
    """Create the empty staging file; fails if it already exists."""
    path = staging_path(tmp, upload_id)
    tmp_st = lstat_or_none(tmp)
    if tmp_st is None:
        raise NotFound("tmp-missing")
    if is_reparse_stat(tmp_st) or not stat.S_ISDIR(tmp_st.st_mode):
        raise UnsafePath("tmp-not-plain-dir")
    try:
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)))
    except FileExistsError:
        raise AlreadyExists("staging-exists") from None
    except OSError as exc:
        raise translate_os_error(exc) from exc
    return path


def _write(fh: BinaryIO, piece: bytes | bytearray) -> None:
    try:
        fh.write(piece)
    except OSError as exc:
        raise translate_os_error(exc) from exc


def append_chunk(
    path: Path,
    expected_offset: int,
    data: bytes | bytearray | Iterable[bytes],
    *,
    max_size: int | None = None,
) -> int:
    """Append `data` at `expected_offset` and return the new size (after flush + fsync).

    The file size must equal `expected_offset`, else OffsetMismatch(actual) and nothing is
    written. If writing fails (disk full, `max_size` exceeded, the iterable raises) the file is
    truncated back to `expected_offset`, so the offset the client holds stays valid.
    Not safe for concurrent appends to the same file: the caller must serialize them.
    """
    if expected_offset < 0:
        raise ValueError("offset must not be negative")
    _plain_file(path)
    try:
        fh = open(path, "r+b")  # noqa: SIM115 - closed in finally
    except OSError as exc:
        raise translate_os_error(exc) from exc
    try:
        actual = os.fstat(fh.fileno()).st_size
        if actual != expected_offset:
            raise OffsetMismatch(actual)
        fh.seek(0, os.SEEK_END)
        written = expected_offset
        pieces: Iterable[bytes | bytearray]
        pieces = (data,) if isinstance(data, bytes | bytearray) else data
        try:
            # Only our own I/O is translated; an error raised by the caller's iterator (a
            # dropped client connection is an OSError too) propagates unchanged.
            for piece in pieces:
                written += len(piece)
                if max_size is not None and written > max_size:
                    raise TooLarge("max-size")
                _write(fh, piece)
            _guard(fh.flush)
            _guard(lambda: os.fsync(fh.fileno()))
        except BaseException:
            with suppress(OSError):
                fh.truncate(expected_offset)
            raise
        return written
    finally:
        fh.close()


def finalize(staging: Path, space_root: Path, parts: tuple[str, ...], *, overwrite: bool) -> Entry:
    """Atomically move a completed staging file to its final place in the space.

    The parent folder must exist. A folder is never replaced. Without `overwrite` the move
    itself refuses to replace an existing item (os.rename fails if the target exists), so a
    concurrent creator cannot be clobbered between check and move. With `overwrite` only an
    existing regular file is replaced (os.replace).
    """
    if not parts:
        raise InvalidPath("space-root")
    staged = _plain_file(staging)
    dest = resolve(space_root, parts, must_exist=False)
    parent_st = lstat_or_none(dest.parent)
    if parent_st is None or not stat.S_ISDIR(parent_st.st_mode):
        raise NotFound("parent-missing")
    existing = lstat_or_none(dest)
    if existing is not None:
        if stat.S_ISDIR(existing.st_mode):
            raise IsADirectoryErr("target-is-dir")
        if not overwrite:
            raise AlreadyExists("exists")
    try:
        if overwrite:
            _replace_file(staging, dest)
        else:
            os.rename(staging, dest)
    except FileExistsError:
        raise AlreadyExists("exists") from None
    except OSError as exc:
        now = lstat_or_none(dest)  # Windows reports "dir in the way" as access denied
        if now is not None and stat.S_ISDIR(now.st_mode):
            raise IsADirectoryErr("target-is-dir") from exc
        if now is not None and not overwrite and isinstance(exc, PermissionError):
            raise AlreadyExists("exists") from exc
        raise translate_os_error(exc) from exc
    try:
        return _entry(parts[-1], _lstat(dest))
    except StorageError as exc:
        # The file is in place. Failing to look at it again must not turn that success into an
        # error; the move keeps size and modification time, so the staged values are the answer.
        log.warning("finalize_stat_failed", extra=error_fields(exc))
        return Entry(parts[-1], "file", staged.st_size, staged.st_mtime)


def _replace_file(src: Path, dest: Path) -> None:
    try:
        os.replace(src, dest)
    except PermissionError:
        st = lstat_or_none(dest)
        if st is None or is_reparse_stat(st) or not stat.S_ISREG(st.st_mode):
            raise
        os.chmod(dest, stat.S_IWRITE)  # read-only target: clear the bit and retry once
        os.replace(src, dest)


def discard_staging(path: Path) -> bool:
    """Best-effort removal of a staging file. True if it is gone; the startup sweep is the net."""
    try:
        st = lstat_or_none(path)
        if st is None:
            return True
        if is_reparse_stat(st):
            _remove_link(path)
        else:
            force_remove(os.unlink, path)
    except (OSError, StorageError) as exc:
        log.warning("staging_discard_failed", extra=error_fields(exc))
        return False
    return True


def free_bytes(path: Path) -> int:
    return _guard(lambda: shutil.disk_usage(path).free)
