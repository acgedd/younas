"""What the photo index needs from the disk (docs/DESIGN-NOTES.md#photos-by-month): a bounded walk
of one space and a bounded read of the first bytes of one file. No policy here; that is in
`yournas.photo_index`.

Walk. From the real space root, with an explicit stack (no recursion) and `os.scandir`. Every
entry is looked at with `DirEntry.stat(follow_symlinks=False)`; reparse points (junctions,
symlinks) and special files are skipped and never entered. A folder is lstat'ed again right before
it is scanned. Names go through the same filter as `files.list_dir` (one valid NFC component, real
path under 240 characters), so every key the walk produces can be resolved again. A folder is read
whole and closed before anything is yielded, so no directory handle stays open while the caller
works. Depth and the number of entries are capped; hitting a cap or failing to read a folder makes
the walk incomplete. Which part of the space was not listed is recorded in `WalkStats.gaps` (a
folder that could not be listed, a folder past the depth cap) or as `whole_gap` (the entry cap, an
unreadable root, too many gaps): the caller must not treat "not seen" as "gone" inside a gap.

Throttle. Every `pause_every` entries enumerated the walk asks `should_stop` (also inside a
folder, so a huge folder is not listed to its end after a stop) and calls `pause` at the next
folder boundary, where no directory handle is open. A single folder of many entries is therefore
listed without a sleep, but never past a stop request.

Read. `read_header` opens the file through `paths.resolve` (which refuses reparse points along
the path), unbuffered, checks with fstat that the open handle is a regular file, lets the caller
read through a `BoundedReader` (at most 256 KiB and 32 reads, every offset within the size fstat
gave) and closes the file at once. The fstat check cannot see a reparse point swapped in between
`resolve` and `open` (open follows it, and fstat then describes the target): that is the same
local-writer race `storage.resolve` accepts (docs/SECURITY.md §11).
"""

from __future__ import annotations

import io
import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from yournas.photo_dates import NoDate

from .errors import InvalidPath, UnsafePath
from .files import translate_os_error
from .paths import MAX_REAL_PATH, resolve, validate_relative_path
from .root import is_reparse_stat

HEADER_MAX_BYTES = 256 * 1024
HEADER_MAX_READS = 32
WALK_MAX_DEPTH = 32  # components of a file's key
WALK_MAX_ENTRIES = 200_000
WALK_PAUSE_ENTRIES = 2_000  # entries enumerated between two stop checks / pauses
WALK_MAX_GAPS = 1_000  # past this many unlisted folders the whole walk counts as a gap


@dataclass(frozen=True)
class WalkFile:
    """A file the walk found. `key` has the form of `thumbnails.path_key`: the names as spelled on
    disk, joined with `/`."""

    key: str
    size: int
    mtime_ns: int


@dataclass
class WalkStats:
    entries: int = 0  # every directory entry enumerated, whatever it was
    unreadable_dirs: int = 0
    truncated: bool = False  # a cap (entries or depth) was hit
    stopped: bool = False  # `should_stop` said so: the walk ended early
    # Folders (as key components) whose content was not listed: an unreadable folder, a folder
    # past the depth cap. `()` is the whole space.
    gaps: list[tuple[str, ...]] = field(default_factory=list)
    whole_gap: bool = False  # the entry cap was hit, or more than WALK_MAX_GAPS gaps

    @property
    def complete(self) -> bool:
        return not self.truncated and not self.unreadable_dirs and not self.stopped

    def add_gap(self, parts: tuple[str, ...]) -> None:
        if len(self.gaps) >= WALK_MAX_GAPS:
            self.whole_gap = True
        else:
            self.gaps.append(parts)


def _addressable(name: str) -> bool:
    try:
        return validate_relative_path(name) == (name,)
    except InvalidPath:
        return False


def walk_files(
    space_root: Path,
    stats: WalkStats,
    *,
    want: Callable[[str], bool],
    max_depth: int = WALK_MAX_DEPTH,
    max_entries: int = WALK_MAX_ENTRIES,
    should_stop: Callable[[], bool] | None = None,
    pause: Callable[[], None] | None = None,
    pause_every: int = WALK_PAUSE_ENTRIES,
) -> Iterator[WalkFile]:
    """Regular files of size > 0 whose name passes `want`, anywhere in the space. `stats` is
    filled in as the walk goes; read it after the iterator ended (or raised)."""
    root = os.path.realpath(space_root)
    stack: list[tuple[str, tuple[str, ...]]] = [(root, ())]
    since_pause = 0
    while stack:
        if pause is not None and since_pause >= pause_every:
            since_pause = 0
            pause()  # no directory handle is open here
        folder, parts = stack.pop()
        try:
            st = os.lstat(folder)
        except (FileNotFoundError, NotADirectoryError):
            continue  # gone since its parent was read: nothing left to index there
        except OSError:
            stats.unreadable_dirs += 1
            stats.add_gap(parts)
            continue
        if is_reparse_stat(st) or not stat.S_ISDIR(st.st_mode):
            continue  # replaced by a link or a file since its parent was read
        found_files: list[WalkFile] = []
        found_dirs: list[tuple[str, tuple[str, ...]]] = []
        try:
            with os.scandir(folder) as it:
                for de in it:
                    stats.entries += 1
                    since_pause += 1
                    if stats.entries > max_entries:
                        stats.truncated = True
                        stats.whole_gap = True
                        return
                    if (
                        should_stop is not None
                        and stats.entries % pause_every == 0
                        and should_stop()
                    ):
                        stats.stopped = True
                        return
                    name = de.name
                    if not _addressable(name):
                        continue
                    full = os.path.join(folder, name)
                    if len(full) >= MAX_REAL_PATH:
                        continue  # resolve would refuse it, as list_dir hides it
                    try:
                        entry_st = de.stat(follow_symlinks=False)
                    except OSError:
                        continue  # vanished meanwhile
                    if is_reparse_stat(entry_st):
                        continue
                    child = (*parts, name)
                    if stat.S_ISDIR(entry_st.st_mode):
                        if len(child) >= max_depth:
                            stats.truncated = True  # its files would be deeper than allowed
                            stats.add_gap(child)
                            continue
                        found_dirs.append((full, child))
                    elif stat.S_ISREG(entry_st.st_mode):
                        if entry_st.st_size > 0 and want(name):
                            found_files.append(
                                WalkFile("/".join(child), entry_st.st_size, entry_st.st_mtime_ns)
                            )
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            stats.unreadable_dirs += 1
            stats.add_gap(parts)
            continue
        # The folder is closed now. Sorted, so a walk visits the same tree in the same order.
        stack.extend(sorted(found_dirs, reverse=True))
        yield from found_files


class BoundedReader:
    """`read_at(offset, n)` over an open unbuffered file: at most HEADER_MAX_BYTES in all and
    HEADER_MAX_READS calls, each offset within [0, size]. Past a limit it raises NoDate; a failed
    read raises a StorageError."""

    def __init__(self, fh: io.RawIOBase, size: int) -> None:
        self._fh = fh
        self._size = size
        self.reads = 0
        self.bytes = 0

    def __call__(self, offset: int, n: int) -> bytes:
        if self.reads >= HEADER_MAX_READS:
            raise NoDate("read-budget")
        if offset < 0 or n < 0 or offset > self._size:
            raise NoDate("read-range")
        n = min(n, self._size - offset)
        if self.bytes + n > HEADER_MAX_BYTES:
            raise NoDate("read-budget")
        self.reads += 1
        self.bytes += n
        try:
            self._fh.seek(offset)
            data = bytearray()
            while len(data) < n:  # a raw read may return less than asked; stop at end of file
                chunk = self._fh.read(n - len(data))
                if not chunk:
                    break
                data += chunk
            return bytes(data)
        except OSError as exc:
            raise translate_os_error(exc) from exc


@dataclass(frozen=True)
class Header[T]:
    value: T
    size: int  # from fstat of the handle that was read
    mtime_ns: int


def read_header[T](
    space_root: Path, parts: tuple[str, ...], inspect: Callable[[BoundedReader, int], T]
) -> Header[T]:
    """Open one file through `resolve` (unbuffered: only what `inspect` asks for is read), check
    that the handle is a regular file, let `inspect` read a bounded header, close. StorageError for
    a missing, unsafe or unreadable file (Busy for a sharing violation)."""
    path = resolve(space_root, parts, must_exist=True)
    try:
        fh = open(path, "rb", buffering=0)  # noqa: SIM115 - closed in finally
    except OSError as exc:
        raise translate_os_error(exc) from exc
    try:
        try:
            st = os.fstat(fh.fileno())
        except OSError as exc:
            raise translate_os_error(exc) from exc
        if is_reparse_stat(st) or not stat.S_ISREG(st.st_mode):
            raise UnsafePath("not-a-regular-file")
        value = inspect(BoundedReader(fh, st.st_size), st.st_size)
        return Header(value, st.st_size, st.st_mtime_ns)
    finally:
        fh.close()
