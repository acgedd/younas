"""Storage root validation and preparation.

Fails closed: if any check is uncertain the root is rejected and nothing is created.
Windows only: the volume checks use kernel32.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import stat
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DRIVE_FIXED = 3
REQUIRED_FILESYSTEM = "NTFS"
SUBDIRS = ("users", "shared")
TMP_DIR = ".yournas-tmp"
_PROBE_PREFIX = ".yournas-write-test-"
_SYSTEM_DIR_VARS = (
    "SystemRoot",
    "windir",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "ProgramData",
)


class StorageRootError(Exception):
    """The storage root is unsafe or unusable."""


@dataclass(frozen=True)
class VolumeInfo:
    fs_name: str
    drive_type: int


VolumeQuery = Callable[[Path], VolumeInfo]


@dataclass(frozen=True)
class StorageRoot:
    root: Path
    users: Path
    shared: Path
    tmp: Path
    swept_tmp_entries: int = 0
    skipped_tmp_entries: int = 0


def query_volume(path: Path) -> VolumeInfo:
    """Filesystem name and drive type of the volume that holds `path`."""
    if sys.platform != "win32":
        raise StorageRootError("Windows is required to validate the storage volume")
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    k32.GetVolumePathNameW.restype = wintypes.BOOL
    k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    k32.GetDriveTypeW.restype = wintypes.UINT
    k32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPDWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    k32.GetVolumeInformationW.restype = wintypes.BOOL

    volume = ctypes.create_unicode_buffer(32768)
    if not k32.GetVolumePathNameW(str(path), volume, len(volume)):
        raise StorageRootError(f"cannot determine the volume of {path}")
    fs_name = ctypes.create_unicode_buffer(261)
    if not k32.GetVolumeInformationW(
        volume.value, None, 0, None, None, None, fs_name, len(fs_name)
    ):
        raise StorageRootError(f"cannot read volume information for {volume.value}")
    return VolumeInfo(fs_name.value, int(k32.GetDriveTypeW(volume.value)))


def is_reparse_stat(st: os.stat_result) -> bool:
    """True if an lstat result describes a symlink, junction, or any other reparse point."""
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def is_reparse(path: Path) -> bool:
    """True for symlinks, junctions, and any other reparse point. Does not follow."""
    return is_reparse_stat(os.lstat(path))


def _windows_directory() -> Path | None:
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetSystemWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    k32.GetSystemWindowsDirectoryW.restype = wintypes.UINT
    buf = ctypes.create_unicode_buffer(260)
    length = k32.GetSystemWindowsDirectoryW(buf, len(buf))
    return Path(buf.value) if 0 < length < len(buf) else None


def _system_dirs(environ: Mapping[str, str]) -> list[Path]:
    """Canonical system directories. Does not depend on the environment alone (fail closed)."""
    dirs: list[Path] = []
    win = _windows_directory()
    if win is not None:
        anchor = Path(win.anchor)
        dirs += [win, anchor / "Program Files", anchor / "Program Files (x86)"]
        dirs.append(anchor / "ProgramData")
    elif not (environ.get("SystemRoot") or environ.get("windir")):
        raise StorageRootError("cannot determine the Windows directory; refusing to continue")
    for var in _SYSTEM_DIR_VARS:
        value = environ.get(var)
        if value:
            dirs.append(Path(value))
    return [Path(os.path.realpath(d)) for d in dirs]


def _is_within(path: Path, parent: Path) -> bool:
    a = os.path.normcase(str(path))
    b = os.path.normcase(str(parent))
    try:
        return os.path.commonpath([a, b]) == b
    except ValueError:  # different drives
        return False


def validate_storage_root(
    root: Path | str,
    *,
    volume_query: VolumeQuery = query_volume,
    environ: Mapping[str, str] = os.environ,
) -> Path:
    """Return the normalized root, or raise StorageRootError. Creates nothing permanent."""
    raw = str(root)
    if "\x00" in raw:
        raise StorageRootError("storage root contains an invalid character")
    # Unify slashes first so mixed forms such as "/\\?\\C:\\x" or "/\\host\\share" cannot slip by.
    if raw.replace("/", "\\").startswith("\\\\"):
        raise StorageRootError("network (UNC) and device paths are not allowed as storage root")
    path = Path(os.path.normpath(raw))
    _drive, rest = os.path.splitdrive(str(path))
    if ":" in rest:
        raise StorageRootError("storage root must not contain ':' (alternate data streams)")
    if any(part.endswith((".", " ")) for part in rest.split("\\") if part):
        raise StorageRootError("storage root names must not end with a dot or a space")
    if not path.is_absolute():
        raise StorageRootError("storage root must be an absolute path including a drive letter")
    if path == Path(path.anchor):
        raise StorageRootError("storage root must not be a drive root; use a dedicated folder")

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise StorageRootError(f"storage root does not exist: {path}") from None
    except OSError as exc:
        raise StorageRootError(f"cannot access storage root {path}: {exc.strerror}") from None

    for candidate in (path, *path.parents):
        if candidate == Path(candidate.anchor):
            continue
        try:
            reparse = is_reparse(candidate)
        except OSError as exc:
            raise StorageRootError(f"cannot inspect {candidate}: {exc.strerror}") from None
        if reparse:
            raise StorageRootError(
                f"{candidate} is a symlink, junction, or reparse point; "
                "the storage root and its parents must be real directories"
            )
    if not stat.S_ISDIR(st.st_mode):
        raise StorageRootError(f"storage root is not a directory: {path}")

    # Canonicalize (long names, trailing dots stripped) before any comparison or use.
    path = Path(os.path.realpath(path))
    if path == Path(path.anchor):
        raise StorageRootError("storage root must not be a drive root; use a dedicated folder")
    for system_dir in _system_dirs(environ):
        if _is_within(path, system_dir):
            raise StorageRootError(f"storage root must not be inside a system directory: {path}")

    info = volume_query(path)
    if info.drive_type != DRIVE_FIXED:
        raise StorageRootError(
            f"storage root must be on a local fixed disk (drive type {info.drive_type})"
        )
    if info.fs_name.upper() != REQUIRED_FILESYSTEM:
        raise StorageRootError(
            f"storage volume is {info.fs_name or 'unknown'}; {REQUIRED_FILESYSTEM} is required"
        )

    probe = path / f"{_PROBE_PREFIX}{uuid.uuid4().hex}"
    try:
        os.close(os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except OSError as exc:
        raise StorageRootError(f"storage root is not writable: {exc.strerror}") from None
    finally:
        with suppress(OSError):
            os.unlink(probe)
    return path


def force_remove(func: Callable[[Path], object], path: Path | str, _exc: object = None) -> None:
    """Run a delete function; on 'access denied' clear the read-only bit and retry once."""
    try:
        func(Path(path))
    except PermissionError:
        os.chmod(path, stat.S_IWRITE)
        func(Path(path))


DEFAULT_TMP_MAX_AGE_SECONDS = 72 * 3600


def _newest_mtime(path: Path) -> float:
    """Newest modification time of an entry and, for a folder, of everything below it.

    Links below the entry are not followed (their own mtime counts).
    """
    st = os.lstat(path)
    newest = st.st_mtime
    stack = [path] if stat.S_ISDIR(st.st_mode) and not is_reparse_stat(st) else []
    while stack:
        with suppress(OSError), os.scandir(stack.pop()) as it:
            for de in it:
                child = de.stat(follow_symlinks=False)
                newest = max(newest, child.st_mtime)
                if stat.S_ISDIR(child.st_mode) and not is_reparse_stat(child):
                    stack.append(Path(de.path))
    return newest


def _sweep(tmp: Path, max_age_seconds: float, now: float) -> tuple[int, int]:
    """Best effort: remove stale leftovers; entries that are locked or busy are skipped.

    Staged chunks of unfinished uploads must survive a restart, so only entries whose newest
    modification is older than `max_age_seconds` go. Links (symlink, junction) never belong
    here and are removed at any age, as links, never through their target.
    """
    removed = skipped = 0
    try:
        entries = list(os.scandir(tmp))
    except OSError as exc:
        raise StorageRootError(f"cannot read staging directory {tmp}: {exc.strerror}") from None
    for entry in entries:
        p = Path(entry.path)
        try:
            if is_reparse(p):
                try:
                    os.unlink(p)
                except OSError:
                    os.rmdir(p)
            elif now - _newest_mtime(p) < max_age_seconds:
                continue
            elif entry.is_dir(follow_symlinks=False):
                shutil.rmtree(p, onexc=force_remove)
            else:
                force_remove(os.unlink, p)
            removed += 1
        except OSError:
            skipped += 1
    return removed, skipped


def prepare_storage_root(
    root: Path, *, tmp_max_age_seconds: float = DEFAULT_TMP_MAX_AGE_SECONDS
) -> StorageRoot:
    """Create users/, shared/ and the staging dir (rejecting links) and sweep old staging."""
    dirs = {name: root / name for name in (*SUBDIRS, TMP_DIR)}
    for p in dirs.values():
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            try:
                p.mkdir()
            except OSError as exc:
                raise StorageRootError(f"cannot create {p}: {exc.strerror}") from None
            continue
        except OSError as exc:
            raise StorageRootError(f"cannot access {p}: {exc.strerror}") from None
        if not stat.S_ISDIR(st.st_mode) or is_reparse(p):
            raise StorageRootError(f"{p} must be a real directory, not a file or link")
    removed, skipped = _sweep(dirs[TMP_DIR], tmp_max_age_seconds, time.time())
    return StorageRoot(root, dirs["users"], dirs["shared"], dirs[TMP_DIR], removed, skipped)


def open_storage(
    root: Path | str,
    *,
    volume_query: VolumeQuery = query_volume,
    environ: Mapping[str, str] = os.environ,
    tmp_max_age_seconds: float = DEFAULT_TMP_MAX_AGE_SECONDS,
) -> StorageRoot:
    return prepare_storage_root(
        validate_storage_root(root, volume_query=volume_query, environ=environ),
        tmp_max_age_seconds=tmp_max_age_seconds,
    )
