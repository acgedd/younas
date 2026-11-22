"""Photos by month: the index of photo dates per space and the one background job that fills it
(docs/DESIGN-NOTES.md#photos-by-month).

Owner decisions: group by the month a photo was taken, else its upload month; the server may read
the date taken and nothing else ("可以，只讀日期（建議）"); once started, indexing finishes in the
background even if the page closes ("按一次就在背景整理完").

The job. Started only by GET .../photos/months, for a scope that has no in-memory state, is dirty
(an upload completed, an item was deleted) or was walked more than 10 minutes ago: never at
startup and never on a timer. One job in the whole server (a non-blocking try-acquire); a request
for another scope while it runs is answered from the database with state "waiting", and that
scope is queued: when the slot frees, the oldest scope still asking (within 10 s) goes first. A
scope whose job ended less than 60 s ago is not walked again (cool-down; answered "waiting" from
the database meanwhile), so one user cannot keep the slot by uploading or deleting in a loop.
The job walks the space (storage.photo_scan, which checks for a stop and pauses every 2,000
entries enumerated), reads the first bytes of each new or changed photo-named file and writes
rows in transactions of at most 200, each of which decides the job user's access again, as the
thumbnail commit does. It works in slices of at most 200 files with a short sleep between them,
so the server stays responsive, and it stops on shutdown, when its share is deleted or when that
access check fails. No database lock and no thumbnail stripe is held during file I/O.

Rows of files the walk did not see are deleted unless they lie in a part of the space the walk
could not list (an unlistable folder or one past the depth cap: rows below it are kept; the entry
cap or a stop: nothing is deleted). An unreadable file keeps its row and does not block deleting
the others. Caps: 100,000 rows per scope and 1,000,000 in all; past one the index is truncated.
The server-wide row count is kept in memory (counted once, in short pages), never by a COUNT(*)
over the whole table at each job start.

Requests: at most 2 photo requests in flight per user (the routes answer 429 past that). The
months body is computed from one GROUP BY on the covering index (scope, month, sort_at DESC,
path_key, file_size, file_mtime_ns) and one cover lookup per month, each under its own short lock.

Month covers (docs/DESIGN-NOTES.md#month-covers): a space may choose the cover of a month among that
month's own photos. The choice is one row of month_covers per (scope, month), written by `set_cover`
and removed by `clear_cover`, each in one transaction that decides the user's access again. A row is
only used while photo_index still has a photo of that scope, key and month with a thumbnail of its
current version; otherwise the month shows today's newest-photo cover. Every cleanup of photo_index
rows (an API delete, a share delete, the walk's delete batch) removes the cover rows of the same
keys in the same transaction, so a stale choice never attaches to a later file at the same path.

Logs: one summary line per job, with the user id, the scope type, counts, the duration and the
complete/truncated flags; one line per cover set or cleared, with the user id and the scope type.
Never a name, a path, a key, a month or a date. No audit rows.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from yournas import photo_dates
from yournas.api.common import iso_utc, not_found
from yournas.core.config import Settings
from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.permissions import Action, Permissions, SpaceAccess
from yournas.storage import photo_scan
from yournas.storage.errors import InvalidPath, NotFound, StorageError, UnsafePath
from yournas.storage.paths import validate_relative_path
from yournas.thumbnails import is_photo_name as is_photo_name  # the one shared helper

log = logging.getLogger("yournas.photos")

MONTH_ITEMS_DEFAULT = 60
MONTH_ITEMS_MAX = 200
CURSOR_MAX = 2048
FALLBACK_YEAR_MIN = 1900
FALLBACK_YEAR_MAX = 2100
MAX_REQUESTS_PER_USER = 2  # photo requests in flight per user; the routes answer 429 past it

State = Literal["ready", "updating", "waiting"]


@dataclass(frozen=True)
class Limits:
    """Every bound of the job, injectable for tests."""

    slice_files: int = 200
    slice_sleep_seconds: float = 0.05
    write_batch: int = 200
    read_page: int = 5000
    stale_after_seconds: float = 600.0
    cooldown_seconds: float = 60.0  # a scope is not walked again sooner after its last job
    waiter_ttl_seconds: float = 10.0  # a queued scope that stopped asking loses its turn
    count_page: int = 50_000  # rows per short read when the server-wide count is taken
    rows_per_scope: int = 100_000
    rows_total: int = 1_000_000
    walk_entries: int = photo_scan.WALK_MAX_ENTRIES
    walk_depth: int = photo_scan.WALK_MAX_DEPTH
    walk_pause_entries: int = photo_scan.WALK_PAUSE_ENTRIES


@dataclass(frozen=True)
class IndexStatus:
    state: State
    pending: int
    complete: bool
    truncated: bool


@dataclass
class _ScopeState:
    dirty_gen: int = 0  # raised by every mark_dirty
    clean_gen: int = -1  # dirty_gen when the last finished job started
    walked_at: float | None = None
    ended_at: float | None = None  # when its last job ended (the cool-down starts there)
    complete: bool = False
    truncated: bool = False


@dataclass
class JobStats:
    entries: int = 0
    parsed: int = 0
    exif: int = 0
    mtime: int = 0
    other: int = 0
    unchanged: int = 0
    skipped_missing: int = 0
    skipped_unreadable: int = 0
    skipped_cap: int = 0
    deleted: int = 0
    complete: bool = False
    truncated: bool = False


@dataclass
class _Job:
    scope: str
    user_id: str
    space: str
    root: Path
    start_gen: int
    cancel: threading.Event = field(default_factory=threading.Event)
    pending: int = 0
    stats: JobStats = field(default_factory=JobStats)


@dataclass(frozen=True)
class _Existing:
    size: int
    mtime_ns: int
    parser: int
    source: str | None
    sort_at: int | None


class _Stopped(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _under(key: str, gap: tuple[str, ...]) -> bool:
    """Is `key` the folder `gap` or below it? Compared casefolded, so it keeps rather than
    deletes when the spelling differs only in case (NTFS)."""
    if not gap:
        return True
    prefix = "/".join(gap).casefold()
    folded = key.casefold()
    return folded == prefix or folded.startswith(prefix + "/")


def _space_type(scope: str) -> str:
    return "home" if scope.startswith("u:") else "share"


def _modified(mtime_ns: int) -> str:
    """The listing's `modified` for a stored mtime_ns: built as os.stat builds st_mtime."""
    seconds, nanos = divmod(mtime_ns, 1_000_000_000)
    return iso_utc(seconds + nanos * 1e-9)


def _bad_request() -> AppError:
    return AppError(400, "invalid_request", "Invalid request")


def _internal_error() -> AppError:
    return AppError(500, "internal_error", "Internal Server Error")


# The photo a stored cover choice may show: a primary-key lookup of (scope, path_key) that must be a
# photo of that month with a thumbnail of its current version (the EXISTS rule of `_cover`). Exact
# key equality: no casefold, no COLLATE NOCASE, no LIKE.
_CHOSEN_PHOTO = (
    "SELECT p.path_key, p.file_size, p.file_mtime_ns FROM photo_index p "
    "WHERE p.scope = ? AND p.path_key = ? AND p.month = ? AND p.kind = 'photo' "
    "AND EXISTS (SELECT 1 FROM thumbnails t "
    "WHERE t.scope = p.scope AND t.path_key = p.path_key "
    "AND t.file_size = p.file_size AND t.file_mtime_ns = p.file_mtime_ns)"
)


# --------------------------------------------------------------------------- cursor


def encode_cursor(sort_at: int, key: str) -> str:
    return base64.urlsafe_b64encode(f"{sort_at}:{key}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[int, str]:
    """(sort_at, path_key) behind an opaque cursor, or 400. Only the canonical encoding of a value
    this server could have produced is accepted."""
    if not 1 <= len(cursor) <= CURSOR_MAX or any(
        not (ch.isascii() and (ch.isalnum() or ch in "-_")) for ch in cursor
    ):
        raise _bad_request()
    try:
        text = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise _bad_request() from None
    number, sep, key = text.partition(":")
    digits = number[1:] if number.startswith("-") else number
    if not sep or not key or not digits.isascii() or not digits.isdigit() or len(digits) > 12:
        raise _bad_request()
    try:
        if validate_relative_path(key) != tuple(key.split("/")):
            raise _bad_request()
    except InvalidPath:
        raise _bad_request() from None
    sort_at = int(number)
    if encode_cursor(sort_at, key) != cursor:
        raise _bad_request()
    return sort_at, key


# --------------------------------------------------------------------------- the service


class PhotoIndexService:
    def __init__(
        self,
        db: Database,
        permissions: Permissions,
        settings: Settings,
        *,
        limits: Limits | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        sleep: Callable[[float], None] | None = None,
        spawn: Callable[[Callable[[], None]], None] | None = None,
    ) -> None:
        self._db = db
        self._permissions = permissions
        self._offset = settings.photo_fallback_offset_seconds
        self.limits = limits or Limits()
        self._clock = clock
        self._wall = wall
        self._stop = threading.Event()
        self._sleep = sleep if sleep is not None else self._stop.wait
        self._spawn = spawn if spawn is not None else self._spawn_thread
        self._guard = threading.Lock()
        self._slot = threading.Lock()  # the one job of the server
        self._states: dict[str, _ScopeState] = {}
        self._job: _Job | None = None
        self._thread: threading.Thread | None = None
        # Scopes answered "waiting" because the slot was busy: scope -> (arrival number, last
        # time asked). The arrival number orders the queue (clock ticks can be equal).
        self._waiters: dict[str, tuple[int, float]] = {}
        self._arrivals = itertools.count()
        # Rows in photo_index, kept by this service (None: count again before the next use).
        self._total_rows: int | None = None
        self._requests: dict[str, int] = {}  # photo requests in flight per user

    # ---- lifecycle ---------------------------------------------------------------------

    def _spawn_thread(self, target: Callable[[], None]) -> None:
        thread = threading.Thread(target=target, name="photo-index", daemon=True)
        self._thread = thread
        thread.start()

    def close(self, timeout: float = 10.0) -> None:
        """At shutdown: stop the job between two files and wait for it. The stop flag is set and
        the thread read under the same guard `status` spawns under, so no job can start after
        this and escape the join."""
        with self._guard:
            self._stop.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    # ---- at most a few requests per user -----------------------------------------------

    def try_begin_request(self, user_id: str) -> bool:
        """Take one of the user's photo request slots; False if all are taken. Pair with
        `end_request`."""
        with self._guard:
            active = self._requests.get(user_id, 0)
            if active >= MAX_REQUESTS_PER_USER:
                return False
            self._requests[user_id] = active + 1
            return True

    def end_request(self, user_id: str) -> None:
        with self._guard:
            left = self._requests.get(user_id, 0) - 1
            if left > 0:
                self._requests[user_id] = left
            else:
                self._requests.pop(user_id, None)

    # ---- hooks -------------------------------------------------------------------------

    def mark_dirty(self, scope: str) -> None:
        """Something changed in the scope (an upload completed, an item was deleted): the next
        months request walks it again (after the cool-down)."""
        with self._guard:
            state = self._states.get(scope)
            if state is not None:
                state.dirty_gen += 1

    def mark_changed(self, scope: str, name: str, *, folder: bool) -> None:
        """An item named `name` changed in the scope: only a folder or a photo-named file can
        change what the index holds, so only those mark it dirty."""
        if folder or is_photo_name(name):
            self.mark_dirty(scope)

    def mark_uploaded(self, access: SpaceAccess, parts: tuple[str, ...]) -> None:
        """The upload completion listener: a file was put in place at `parts`."""
        if parts:
            self.mark_changed(access.scope, parts[-1], folder=False)

    def forget_scope(self, scope: str) -> None:
        """A share was deleted: drop what is known about it and stop its job. Its rows went in the
        share-delete transaction, so the server-wide count is taken again before its next use."""
        with self._guard:
            self._states.pop(scope, None)
            self._waiters.pop(scope, None)
            self._total_rows = None
            if self._job is not None and self._job.scope == scope:
                self._job.cancel.set()

    def purge(self, scope: str, key: str, *, folder: bool) -> None:
        """Remove the rows of a deleted item, and for a folder of everything below it: a range and
        never LIKE (`_` and `%` are legal in names). The cover choices of the same keys go in the
        same transaction. Then mark the scope dirty if the item was a folder or photo-named. A
        failure is only logged: the next walk removes what stays."""
        try:
            where = "scope = ? AND path_key = ?"
            params: tuple[str, ...] = (scope, key)
            if folder:
                where = "scope = ? AND (path_key = ? OR (path_key >= ? AND path_key < ?))"
                params = (scope, key, f"{key}/", f"{key}0")
            with self._db.transaction() as conn:
                removed = conn.execute(f"DELETE FROM photo_index WHERE {where}", params).rowcount
                conn.execute(f"DELETE FROM month_covers WHERE {where}", params)
            self._count_removed(removed)
        except Exception as exc:
            log.warning("photo_index_cleanup_failed", extra=error_fields(exc))
        self.mark_changed(scope, key.rsplit("/", 1)[-1], folder=folder)

    def _count_removed(self, removed: int) -> None:
        with self._guard:
            if self._total_rows is not None:
                self._total_rows = max(0, self._total_rows - max(0, removed))

    @staticmethod
    def take_scope(conn: sqlite3.Connection, scope: str) -> None:
        """Inside the share-delete transaction: remove every row of the scope and its cover
        choices. A failure is logged and leaves rows no authorization can reach (share ids are
        never reused)."""
        for table in ("month_covers", "photo_index"):
            try:
                conn.execute(f"DELETE FROM {table} WHERE scope = ?", (scope,))
            except sqlite3.Error as exc:
                log.warning("photo_index_cleanup_failed", extra=error_fields(exc))

    # ---- the job -----------------------------------------------------------------------

    def _needs_walk(self, state: _ScopeState | None) -> bool:
        if state is None or state.walked_at is None or state.dirty_gen != state.clean_gen:
            return True
        return self._clock() - state.walked_at > self.limits.stale_after_seconds

    def _cooling(self, state: _ScopeState | None, now: float) -> bool:
        return (
            state is not None
            and state.ended_at is not None
            and now - state.ended_at < self.limits.cooldown_seconds
        )

    def _turn_of(self, scope: str, now: float) -> bool:
        """May `scope` take the free slot? Yes unless an older queued scope is still asking.
        The caller holds the guard."""
        ttl = self.limits.waiter_ttl_seconds
        for other, (_arrival, last) in list(self._waiters.items()):
            if now - last > ttl:
                del self._waiters[other]  # it stopped asking: it loses its turn
        if not self._waiters:
            return True
        head = min(self._waiters.items(), key=lambda item: item[1][0])[0]
        return head == scope

    def status(self, user_id: str, access: SpaceAccess, *, start: bool = True) -> IndexStatus:
        """Where the index of this space stands, starting the job for it if it needs one, is not
        cooling down, the server has no job running and no older scope is queued for the slot."""
        scope = access.scope
        with self._guard:
            state = self._states.get(scope)
            complete = state.complete if state is not None else False
            truncated = state.truncated if state is not None else False
            job = self._job
            if job is not None and job.scope == scope:
                return IndexStatus("updating", job.pending, complete, truncated)
            if not self._needs_walk(state):
                return IndexStatus("ready", 0, complete, truncated)
            now = self._clock()
            if not start or self._stop.is_set() or self._cooling(state, now):
                return IndexStatus("waiting", 0, complete, truncated)
            if not self._turn_of(scope, now) or not self._slot.acquire(blocking=False):
                arrival = self._waiters[scope][0] if scope in self._waiters else None
                if arrival is None:
                    arrival = next(self._arrivals)
                self._waiters[scope] = (arrival, now)
                return IndexStatus("waiting", 0, complete, truncated)
            self._waiters.pop(scope, None)
            if state is None:
                state = self._states[scope] = _ScopeState()
            job = _Job(scope, user_id, access.space, access.root, state.dirty_gen)
            self._job = job
            # Spawned under the guard: `close` sets the stop flag and reads the thread under it,
            # so a thread started here is always the one `close` joins.
            try:
                self._spawn(lambda: self._run(job))
            except BaseException:
                self._job = None
                self._slot.release()
                raise
        return IndexStatus("updating", 0, complete, truncated)

    def _run(self, job: _Job) -> None:
        started = self._clock()
        outcome = "done"
        try:
            self._index(job)
        except _Stopped as stop:
            outcome = stop.reason
        except Exception as exc:
            outcome = "failed"
            log.warning("photo_index_failed", extra=error_fields(exc))
        finally:
            with self._guard:
                self._job = None
                if outcome == "failed":
                    self._total_rows = None  # a write may have failed after its rows were counted
                if outcome == "access":
                    self._states.pop(job.scope, None)
                elif outcome in ("done", "failed") and not job.cancel.is_set():
                    state = self._states.setdefault(job.scope, _ScopeState())
                    state.walked_at = state.ended_at = self._clock()
                    state.clean_gen = job.start_gen
                    state.complete = job.stats.complete and outcome == "done"
                    state.truncated = job.stats.truncated
            self._slot.release()
            s = job.stats
            log.info(
                "photo_index_job",
                extra={
                    "user_id": job.user_id,
                    "space_type": _space_type(job.scope),
                    "outcome": outcome,
                    "entries": s.entries,
                    "parsed": s.parsed,
                    "exif": s.exif,
                    "mtime": s.mtime,
                    "other": s.other,
                    "unchanged": s.unchanged,
                    "skipped_missing": s.skipped_missing,
                    "skipped_unreadable": s.skipped_unreadable,
                    "skipped_cap": s.skipped_cap,
                    "deleted": s.deleted,
                    "duration_ms": int((self._clock() - started) * 1000),
                    "complete": s.complete,
                    "truncated": s.truncated,
                },
            )

    def _check(self, job: _Job) -> None:
        if self._stop.is_set():
            raise _Stopped("shutdown")
        if job.cancel.is_set():
            raise _Stopped("cancelled")

    def _pause(self, job: _Job) -> None:
        self._check(job)
        self._sleep(self.limits.slice_sleep_seconds)
        self._check(job)

    def _require(self, job: _Job) -> None:
        try:
            self._permissions.require(job.user_id, job.space, Action.LIST)
        except AppError:
            raise _Stopped("access") from None

    def _load(self, scope: str) -> dict[str, _Existing]:
        """Every row of the scope, read in key-range pages so the lock is held only briefly."""
        rows: dict[str, _Existing] = {}
        after = ""
        while True:
            with self._db.read() as conn:
                page = conn.execute(
                    "SELECT path_key, file_size, file_mtime_ns, parser, source, sort_at "
                    "FROM photo_index WHERE scope = ? AND path_key > ? ORDER BY path_key LIMIT ?",
                    (scope, after, self.limits.read_page),
                ).fetchall()
            for r in page:
                rows[str(r["path_key"])] = _Existing(
                    int(r["file_size"]),
                    int(r["file_mtime_ns"]),
                    int(r["parser"]),
                    r["source"],
                    None if r["sort_at"] is None else int(r["sort_at"]),
                )
            if len(page) < self.limits.read_page:
                return rows
            after = str(page[-1]["path_key"])

    def _fallback_sort_at(self, mtime_ns: int) -> int:
        return mtime_ns // 1_000_000_000 + self._offset

    def _unchanged(self, row: _Existing | None, found: photo_scan.WalkFile) -> bool:
        if row is None or row.parser != photo_dates.PARSER_VERSION:
            return False
        if (row.size, row.mtime_ns) != (found.size, found.mtime_ns):
            return False
        # A changed fallback offset moves the month of the rows that use it, without any I/O.
        return row.source != "mtime" or row.sort_at == self._fallback_sort_at(found.mtime_ns)

    def _count_total(self) -> int:
        """Rows in photo_index, counted in pages of `count_page` keys, each under its own short
        read, so the lock is never held for a scan of the whole table."""
        page = self.limits.count_page
        total = 0
        after: tuple[str, str] | None = None
        while True:
            where = ""
            params: tuple[str, ...] = ()
            if after is not None:
                where, params = "WHERE (scope, path_key) > (?, ?) ", after
            with self._db.read() as conn:
                edge = conn.execute(
                    f"SELECT scope, path_key FROM photo_index {where}"
                    "ORDER BY scope, path_key LIMIT 1 OFFSET ?",
                    (*params, page - 1),
                ).fetchone()
                if edge is None:
                    (rest,) = conn.execute(
                        f"SELECT COUNT(*) FROM photo_index {where}", params
                    ).fetchone()
                    return total + int(rest)
            total += page
            after = (str(edge["scope"]), str(edge["path_key"]))

    def _total(self) -> int:
        """The server-wide row count, taken once (and again after it was dropped)."""
        with self._guard:
            known = self._total_rows
        if known is not None:
            return known
        counted = self._count_total()
        with self._guard:
            if self._total_rows is None:
                self._total_rows = counted
            return self._total_rows

    def _index(self, job: _Job) -> None:
        limits = self.limits
        stats = job.stats
        self._require(job)
        existing = self._load(job.scope)
        self._total()  # counted now (once), not under any write
        scope_rows = len(existing)

        walk = photo_scan.WalkStats()
        seen: set[str] = set()
        todo: list[photo_scan.WalkFile] = []
        try:
            for found in photo_scan.walk_files(
                job.root,
                walk,
                want=is_photo_name,
                max_depth=limits.walk_depth,
                max_entries=limits.walk_entries,
                should_stop=lambda: self._stop.is_set() or job.cancel.is_set(),
                pause=lambda: self._pause(job),
                pause_every=limits.walk_pause_entries,
            ):
                seen.add(found.key)
                if self._unchanged(existing.get(found.key), found):
                    stats.unchanged += 1
                else:
                    todo.append(found)
                    job.pending = len(todo)
        finally:
            stats.entries = walk.entries
        self._check(job)

        unreadable = False
        for start in range(0, len(todo), limits.slice_files):
            rows: list[tuple[Any, ...]] = []
            for found in todo[start : start + limits.slice_files]:
                self._check(job)
                try:
                    row = self._examine(job, found)
                except (NotFound, UnsafePath, InvalidPath):
                    stats.skipped_missing += 1
                    seen.discard(found.key)
                    row = None
                except (StorageError, OSError):
                    stats.skipped_unreadable += 1
                    unreadable = True  # its old row (if any) stays: the key is still seen
                    row = None
                if row is not None:
                    rows.append(row)
                job.pending -= 1
            scope_rows = self._write(job, rows, existing, scope_rows)
            self._pause(job)

        stats.truncated = walk.truncated or stats.skipped_cap > 0
        stats.complete = walk.complete and not unreadable and stats.skipped_cap == 0
        # Only a part of the space that was not listed keeps rows of files not seen. An
        # unreadable file was seen (its row stays) and a cap hit only stops new rows.
        if not walk.whole_gap:
            gone = [
                key
                for key in existing
                if key not in seen and not any(_under(key, gap) for gap in walk.gaps)
            ]
            for start in range(0, len(gone), limits.write_batch):
                batch = gone[start : start + limits.write_batch]
                with self._db.transaction() as conn:
                    self._require(job)
                    keys = [(job.scope, key) for key in batch]
                    removed = conn.executemany(
                        "DELETE FROM photo_index WHERE scope = ? AND path_key = ?", keys
                    ).rowcount
                    # The cover choices of the removed keys, so a stale choice never attaches to
                    # a later file at the same path.
                    conn.executemany(
                        "DELETE FROM month_covers WHERE scope = ? AND path_key = ?", keys
                    )
                self._count_removed(removed)
                stats.deleted += len(batch)
                self._pause(job)
        job.pending = 0

    def _examine(self, job: _Job, found: photo_scan.WalkFile) -> tuple[Any, ...]:
        """Read one file (no lock held) and build its row. The version stored (size, mtime_ns) is
        the walk's, from the directory listing: the same source the next walk compares with in
        `_unchanged` and the listing builds `modified` from. A file changed between the walk and
        the read gets the old version stored, so the next walk reads it again."""
        now = self._wall()
        header = photo_scan.read_header(
            job.root,
            tuple(found.key.split("/")),
            lambda read_at, size: photo_dates.examine(read_at, size, now=now),
        )
        fmt, taken = header.value
        stats = job.stats
        stats.parsed += 1
        kind, source, month, sort_at = "other", None, None, None
        if fmt is not None:
            if taken is not None:
                kind, source, sort_at = "photo", "exif", taken
            else:
                fallback = self._fallback_sort_at(found.mtime_ns)
                with suppress(OverflowError, ValueError):
                    year = int(photo_dates.wall_seconds_to_month(fallback)[:4])
                    if FALLBACK_YEAR_MIN <= year <= FALLBACK_YEAR_MAX:
                        kind, source, sort_at = "photo", "mtime", fallback
        if sort_at is not None:
            month = photo_dates.wall_seconds_to_month(sort_at)
        if source == "exif":
            stats.exif += 1
        elif source == "mtime":
            stats.mtime += 1
        else:
            stats.other += 1
        return (
            job.scope,
            found.key,
            found.size,
            found.mtime_ns,
            kind,
            source,
            month,
            sort_at,
            photo_dates.PARSER_VERSION,
            int(now),
        )

    def _write(
        self,
        job: _Job,
        rows: list[tuple[Any, ...]],
        existing: dict[str, _Existing],
        scope_rows: int,
    ) -> int:
        """Write rows in batches; returns the scope's row count after them. New rows count toward
        both caps (reserved in the server-wide count before the write; a failed job drops it)."""
        if not rows:
            self._require(job)  # a job whose user lost access stops even with nothing to write
            return scope_rows
        limits = self.limits
        total = self._total()
        for start in range(0, len(rows), limits.write_batch):
            batch = rows[start : start + limits.write_batch]
            kept: list[tuple[Any, ...]] = []
            with self._guard:
                total = self._total_rows if self._total_rows is not None else total
                for row in batch:
                    if row[1] not in existing:
                        if scope_rows >= limits.rows_per_scope or total >= limits.rows_total:
                            job.stats.skipped_cap += 1
                            continue
                        scope_rows += 1
                        total += 1
                    kept.append(row)
                if self._total_rows is not None:
                    self._total_rows = total
            with self._db.transaction() as conn:
                self._require(job)
                conn.executemany(
                    "INSERT INTO photo_index (scope, path_key, file_size, file_mtime_ns, kind, "
                    "source, month, sort_at, parser, indexed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (scope, path_key) DO UPDATE SET "
                    "file_size = excluded.file_size, file_mtime_ns = excluded.file_mtime_ns, "
                    "kind = excluded.kind, source = excluded.source, month = excluded.month, "
                    "sort_at = excluded.sort_at, parser = excluded.parser, "
                    "indexed_at = excluded.indexed_at",
                    kept,
                )
            for row in kept:
                existing.setdefault(row[1], _Existing(row[2], row[3], row[8], row[5], row[7]))
        return scope_rows

    # ---- reading -----------------------------------------------------------------------

    def months(self, user_id: str, access: SpaceAccess, year: int | None) -> dict[str, Any]:
        """The body of GET .../photos/months."""
        index = self.status(user_id, access)
        scope = access.scope
        # One pass over the covering index photo_index_month: month is set exactly for kind
        # 'photo' (a CHECK of the table), so the per-month aggregates also give the years and
        # the total without reading a table row.
        with self._db.read() as conn:
            per_month = [
                (str(r["month"]), int(r["n"]), int(r["b"]))
                for r in conn.execute(
                    "SELECT month, COUNT(*) AS n, COALESCE(SUM(file_size), 0) AS b "
                    "FROM photo_index WHERE scope = ? AND month IS NOT NULL "
                    "GROUP BY month ORDER BY month DESC",
                    (scope,),
                )
            ]
        by_year: dict[int, int] = {}
        count = size = 0
        for month, n, b in per_month:
            by_year[int(month[:4])] = by_year.get(int(month[:4]), 0) + n
            count += n
            size += b
        years = [{"year": y, "count": n} for y, n in sorted(by_year.items(), reverse=True)]
        chosen = year if year is not None else (years[0]["year"] if years else None)
        months: list[dict[str, Any]] = []
        if chosen is not None:
            prefix = f"{chosen:04d}-"
            choices = self._choices(scope, chosen)
            for month, n, b in per_month:
                if month.startswith(prefix):
                    cover = None
                    key = choices.get(month)
                    if key is not None:
                        cover = self._chosen_cover(scope, month, key)
                    custom = cover is not None
                    if cover is None:
                        cover = self._cover(scope, month)
                    months.append(
                        {"month": month, "count": n, "bytes": b, "cover": cover, "custom": custom}
                    )
        return {
            "years": years,
            "year": chosen,
            "total": {"count": count, "bytes": size},
            "months": months,
            "index": {
                "state": index.state,
                "pending": index.pending,
                "complete": index.complete,
                "truncated": index.truncated,
            },
        }

    def _choices(self, scope: str, year: int) -> dict[str, str]:
        """The stored cover choices of the year: month -> path_key. One range read on the primary
        key of month_covers; no ORDER BY (the caller looks them up by month)."""
        with self._db.read() as conn:
            return {
                str(r["month"]): str(r["path_key"])
                for r in conn.execute(
                    "SELECT month, path_key FROM month_covers "
                    "WHERE scope = ? AND month >= ? AND month < ?",
                    (scope, f"{year:04d}-", f"{year:04d}."),
                )
            }

    def _chosen_cover(self, scope: str, month: str, key: str) -> dict[str, Any] | None:
        """The cover a stored choice gives, or None when the choice is stale (the photo is gone,
        moved to another month or has no thumbnail of its current version). path, size and
        modified come from the photo_index row, never from month_covers."""
        with self._db.read() as conn:
            r = conn.execute(_CHOSEN_PHOTO, (scope, key, month)).fetchone()
        if r is None:
            return None
        return {
            "path": str(r["path_key"]),
            "size": int(r["file_size"]),
            "modified": _modified(int(r["file_mtime_ns"])),
        }

    def _cover(self, scope: str, month: str) -> dict[str, Any] | None:
        """The newest photo of the month that has a thumbnail of its current version, in the SAME
        scope (matched on scope and key). Walks the month index newest first and stops at the
        first match; its own short read, so the lock is released between months."""
        with self._db.read() as conn:
            r = conn.execute(
                "SELECT p.path_key, p.file_size, p.file_mtime_ns FROM photo_index p "
                "WHERE p.scope = ? AND p.month = ? AND EXISTS (SELECT 1 FROM thumbnails t "
                "WHERE t.scope = p.scope AND t.path_key = p.path_key "
                "AND t.file_size = p.file_size AND t.file_mtime_ns = p.file_mtime_ns) "
                "ORDER BY p.sort_at DESC, p.path_key LIMIT 1",
                (scope, month),
            ).fetchone()
        if r is None:
            return None
        return {
            "path": str(r["path_key"]),
            "size": int(r["file_size"]),
            "modified": _modified(int(r["file_mtime_ns"])),
        }

    # ---- month covers ------------------------------------------------------------------

    def set_cover(self, user_id: str, access: SpaceAccess, month: str, key: str) -> None:
        """Store `key` as the cover of `month` in the space. In ONE transaction: the user's access
        is decided again (a grant lowered or revoked, or the share deleted, since the route
        authorized leaves no row), the key must be a photo of this scope and month with a
        thumbnail of its current version (else the generic 404), then the row is written. The same
        key already stored writes nothing. No disk access."""
        try:
            with self._db.transaction() as conn:
                self._permissions.require(user_id, access.space, Action.COVER_WRITE)
                if conn.execute(_CHOSEN_PHOTO, (access.scope, key, month)).fetchone() is None:
                    raise not_found()
                stored = conn.execute(
                    "SELECT path_key FROM month_covers WHERE scope = ? AND month = ?",
                    (access.scope, month),
                ).fetchone()
                if stored is None:
                    conn.execute(
                        "INSERT INTO month_covers (scope, month, path_key) VALUES (?, ?, ?)",
                        (access.scope, month, key),
                    )
                elif str(stored["path_key"]) != key:
                    conn.execute(
                        "UPDATE month_covers SET path_key = ? WHERE scope = ? AND month = ?",
                        (key, access.scope, month),
                    )
        except sqlite3.Error as exc:
            log.error("month_cover_failed", extra=error_fields(exc))
            raise _internal_error() from None
        log.info(
            "month_cover_set",
            extra={"user_id": user_id, "space_type": _space_type(access.scope)},
        )

    def clear_cover(self, user_id: str, access: SpaceAccess, month: str) -> None:
        """Remove the cover choice of `month` in the space, if there is one: the month goes back to
        its newest photo. Access is decided again inside the transaction, as for `set_cover`."""
        try:
            with self._db.transaction() as conn:
                self._permissions.require(user_id, access.space, Action.COVER_WRITE)
                conn.execute(
                    "DELETE FROM month_covers WHERE scope = ? AND month = ?",
                    (access.scope, month),
                )
        except sqlite3.Error as exc:
            log.error("month_cover_failed", extra=error_fields(exc))
            raise _internal_error() from None
        log.info(
            "month_cover_cleared",
            extra={"user_id": user_id, "space_type": _space_type(access.scope)},
        )

    def month_items(
        self, access: SpaceAccess, month: str, limit: int, cursor: tuple[int, str] | None
    ) -> dict[str, Any]:
        """The body of GET .../photos/months/{month}. Never walks or reads a file."""
        scope = access.scope
        where = "p.scope = ? AND p.month = ?"
        params: list[Any] = [scope, month]
        if cursor is not None:
            # `sort_at <= ?` alone is a range on the month index, so a deep page seeks instead of
            # scanning the month from its newest photo.
            where += " AND p.sort_at <= ? AND (p.sort_at < ? OR p.path_key > ?)"
            params += [cursor[0], cursor[0], cursor[1]]
        with self._db.read() as conn:
            count, size = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM photo_index "
                "WHERE scope = ? AND month = ?",
                (scope, month),
            ).fetchone()
            rows = conn.execute(
                "SELECT p.path_key, p.file_size, p.file_mtime_ns, p.source, p.sort_at, "
                "t.path_key IS NOT NULL AS thumb FROM photo_index p "
                "LEFT JOIN thumbnails t ON t.scope = p.scope AND t.path_key = p.path_key "
                "AND t.file_size = p.file_size AND t.file_mtime_ns = p.file_mtime_ns "
                f"WHERE {where} ORDER BY p.sort_at DESC, p.path_key LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        page = rows[:limit]
        items = [
            {
                "path": str(r["path_key"]),
                "name": str(r["path_key"]).rsplit("/", 1)[-1],
                "size": int(r["file_size"]),
                "modified": _modified(int(r["file_mtime_ns"])),
                "taken": photo_dates.wall_seconds_to_iso(int(r["sort_at"]))
                if r["source"] == "exif"
                else None,
                "thumb": bool(r["thumb"]),
            }
            for r in page
        ]
        last = page[-1] if len(rows) > limit else None
        return {
            "month": month,
            "count": int(count),
            "bytes": int(size),
            "items": items,
            "next_cursor": None
            if last is None
            else encode_cursor(int(last["sort_at"]), str(last["path_key"])),
        }

    # ---- for tests and diagnostics -----------------------------------------------------

    def running_scope(self) -> str | None:
        with self._guard:
            return None if self._job is None else self._job.scope

    def join(self, timeout: float = 30.0) -> None:
        """Wait for the running job, if any, to end on its own (it is not stopped)."""
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
