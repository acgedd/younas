"""Thumbnail bytes under `<data_dir>/thumbs` and the identity of the file they were made from.

Two jobs, both without any policy (that is in `yournas.thumbnails`):

- Identity: `locate` asks `paths.resolve` for the real path of an item, so every casing and every
  8.3 alias of one file gives one `path_key`, and reads the version of the file from os.lstat (a
  directory listing does not carry the file id on Windows).
- Bytes: the file name is a SHA-256 of the scope and the key, so no user text ever reaches the disk.
  The data directory is never inside a space, so no space can reach these files.

Stored keys are never turned back into paths of user files.

A folder of the store that is not a plain folder (a junction, a link or a file in its place) is a
damaged or tampered store, not one damaged thumbnail: it raises StoreUnsafe (a 500) and logs a
warning with a fixed reason code and no name.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import stat
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .errors import StorageIOError, UnsafePath
from .files import lstat_or_none, translate_os_error
from .paths import resolve
from .root import force_remove, is_reparse_stat

log = logging.getLogger("yournas.storage")

THUMBS_DIR_NAME = "thumbs"
# What `write` creates: `<aa>/<64 hex>.<32 hex>.tmp`. The sweep removes these names and no other.
_SUBDIR_NAME = re.compile(r"[0-9a-f]{2}")
_TEMP_NAME = re.compile(r"[0-9a-f]{64}\.[0-9a-f]{32}\.tmp")


class StoreUnsafe(StorageIOError):
    """A folder of the thumbnail store is not a plain folder. The whole store is suspect, so this
    is a server error (500) and is logged, unlike a single damaged thumbnail (a 404)."""


@dataclass(frozen=True)
class SourceFile:
    """What is on the disk at a path now. `ino` is text: on Windows it can pass 64 bits."""

    name: str  # the real name, whatever alias the client used
    regular: bool
    ino: str
    size: int
    mtime: float  # as in a listing, for the client's `modified`
    mtime_ns: int


def _key_of(real: Path, space_root: Path) -> str:
    # Not casefolded: NTFS keeps `straße.jpg` and `strasse.jpg` (or K and the Kelvin sign) apart,
    # and casefold() would give them one key. `real` comes from realpath, which spells existing
    # components as they are on disk, so every casing and alias of one file still gives one key.
    try:
        relative = real.relative_to(os.path.realpath(space_root))
    except ValueError:
        raise UnsafePath("outside-space-root") from None
    return "/".join(relative.parts)


def path_key(space_root: Path, parts: tuple[str, ...]) -> str:
    """The key of an item, existing or not: the path of the real item relative to the real space
    root, spelled as on disk, with `/` separators. The space root itself is the empty string. A
    missing tail keeps the client's spelling (no row can match it)."""
    return _key_of(resolve(space_root, parts, must_exist=False), space_root)


def locate(space_root: Path, parts: tuple[str, ...]) -> tuple[str, SourceFile | None]:
    """The key of an item and what is there now (None if nothing is)."""
    real = resolve(space_root, parts, must_exist=False)
    key = _key_of(real, space_root)
    st = lstat_or_none(real)
    if st is None:
        return key, None
    if is_reparse_stat(st):
        raise UnsafePath("reparse-point")
    return key, SourceFile(
        real.name, stat.S_ISREG(st.st_mode), str(st.st_ino), st.st_size, st.st_mtime, st.st_mtime_ns
    )


def digest(scope: str, key: str) -> str:
    # Neither a scope nor a key can hold NUL (the path validator refuses control characters).
    return hashlib.sha256(f"{scope}\0{key}".encode()).hexdigest()


def bytes_path(base: Path, scope: str, key: str) -> Path:
    name = digest(scope, key)
    return base / name[:2] / f"{name}.jpg"


def _store_unsafe(reason: str) -> StoreUnsafe:
    log.warning("thumbnail_store_unsafe", extra={"reason": reason})
    return StoreUnsafe(reason)


def _plain_dir(path: Path, *, create: bool) -> bool:
    """Whether one level of the store is there, created first if `create`. Anything but a plain
    folder in its place raises StoreUnsafe: nothing is ever read or written through a link."""
    st = lstat_or_none(path)
    if st is None and create:
        with suppress(FileExistsError):
            path.mkdir()
        st = lstat_or_none(path)
    if st is None:
        if create:
            raise _store_unsafe("thumbs-dir-vanished")
        return False
    if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
        raise _store_unsafe("thumbs-dir-not-plain-dir")
    return True


def _folders_exist(base: Path, final: Path) -> bool:
    """Whether the store and the `<aa>` folder of `final` exist; StoreUnsafe if either is not a
    plain folder."""
    return _plain_dir(base, create=False) and _plain_dir(final.parent, create=False)


def write(base: Path, scope: str, key: str, data: bytes) -> None:
    """Write to a temp file next to the target, flush it and move it into place atomically."""
    final = bytes_path(base, scope, key)
    try:
        _plain_dir(base, create=True)
        _plain_dir(final.parent, create=True)
        temp = final.with_name(f"{final.stem}.{uuid.uuid4().hex}.tmp")
        try:
            with open(temp, "xb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp, final)
        except BaseException:
            with suppress(OSError):
                os.unlink(temp)
            raise
    except OSError as exc:
        raise translate_os_error(exc) from exc


def read(base: Path, scope: str, key: str, limit: int) -> bytes | None:
    """At most `limit` bytes of a stored thumbnail, or None if there is no such file."""
    path = bytes_path(base, scope, key)
    if not _folders_exist(base, path):
        return None
    st = lstat_or_none(path)
    if st is None:
        return None
    if is_reparse_stat(st) or not stat.S_ISREG(st.st_mode):
        raise UnsafePath("thumb-not-plain-file")  # one damaged thumbnail: the same 404
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise translate_os_error(exc) from exc


def remove(base: Path, scope: str, key: str) -> None:
    """Delete a stored thumbnail. A missing file is not an error."""
    path = bytes_path(base, scope, key)
    if not _folders_exist(base, path):
        return
    try:
        force_remove(os.unlink, path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise translate_os_error(exc) from exc


def sweep_temp_files(base: Path) -> int:
    """Remove the temp files a crash left between `open` and `os.replace`, and return how many.

    Only at startup, before any request. Only regular files named `<64 hex>.<32 hex>.tmp`, only
    inside a plain `<aa>` folder of a plain store folder, and only those whose name starts with
    that folder's name. Links are never followed or removed, and nothing else is touched. A store
    folder that is not plain raises StoreUnsafe; an `<aa>` folder that is not plain is logged and
    skipped."""
    try:
        if not _plain_dir(base, create=False):
            return 0
        with os.scandir(base) as top:
            subdirs = sorted(e.name for e in top if _SUBDIR_NAME.fullmatch(e.name))
        removed = 0
        for sub in subdirs:
            folder = base / sub
            st = lstat_or_none(folder)
            if st is None:
                continue
            if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
                _store_unsafe("thumbs-subdir-not-plain-dir")
                continue
            with os.scandir(folder) as entries:
                temps = sorted(
                    e.name
                    for e in entries
                    if _TEMP_NAME.fullmatch(e.name) and e.name.startswith(sub)
                )
            for name in temps:
                path = folder / name
                st = lstat_or_none(path)
                if st is None or is_reparse_stat(st) or not stat.S_ISREG(st.st_mode):
                    continue
                with suppress(FileNotFoundError):
                    force_remove(os.unlink, path)
                    removed += 1
        return removed
    except OSError as exc:
        raise translate_os_error(exc) from exc
