"""Resumable uploads: database rows, staging files and the rules that tie them together.

The staging file is the source of truth for progress: the offset of an upload is the real size of
its file, never a number in the database, so a crash between a write and a bookkeeping update
cannot leave the two disagreeing. The `uploads` row only remembers who the upload belongs to, where
it goes and how big it must become.

Concurrency: chunks of one upload are serialized with an in-process lock per upload id (the server
is a single process). Locks exist only while an upload is live.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from yournas.api.common import not_found, to_app_error
from yournas.audit import AuditLog
from yournas.core.config import Settings
from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.permissions import Action, Permissions, SpaceAccess, parse_share_space
from yournas.storage import files
from yournas.storage.errors import (
    AlreadyExists,
    InvalidPath,
    IsADirectoryErr,
    NotFound,
    OffsetMismatch,
    StorageError,
    TooLarge,
)
from yournas.storage.paths import resolve
from yournas.storage.root import StorageRoot, is_reparse_stat

log = logging.getLogger("yournas.uploads")

UPLOAD_ID = re.compile(r"[a-f0-9]{32}")
ORPHAN_AGE_SECONDS = 3600
MAINTENANCE_INTERVAL_SECONDS = 600
# An upload cannot live longer than this from the moment it was created, however often chunks
# arrive: the idle limit (`upload_stale_hours`) is renewed by every chunk, this one never is. Past
# it the upload answers 404 and the next maintenance run removes its row and staging file.
UPLOAD_MAX_AGE_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class UploadRow:
    id: str
    user_id: str
    space: str
    parts: tuple[str, ...]
    size: int
    overwrite: bool
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class UploadStatus:
    row: UploadRow
    offset: int


@dataclass(frozen=True)
class Created:
    upload_id: str
    size: int
    item: files.Entry | None  # set when a zero-byte upload was completed on the spot


@dataclass(frozen=True)
class Appended:
    offset: int
    size: int
    item: files.Entry | None  # set when this chunk completed the upload


@dataclass(frozen=True)
class MaintenanceResult:
    stale_uploads: int
    orphan_files: int


class UploadService:
    def __init__(
        self,
        db: Database,
        storage: StorageRoot,
        settings: Settings,
        clock: Callable[[], float] = time.time,
        permissions: Permissions | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._db = db
        self._storage = storage
        self._settings = settings
        self._clock = clock
        # Every upload belongs to a space (`home` or `share:<id>`); this decides, on every
        # request, whether its user may still write there.
        self._permissions = permissions if permissions is not None else Permissions(db, storage)
        self._audit = audit if audit is not None else AuditLog(db, clock)
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._active_chunks: dict[str, int] = {}  # user id -> PATCH requests in flight
        self._chunks_guard = threading.Lock()
        self._maintenance_lock = threading.Lock()
        self._last_maintenance = float(clock())
        # Called with the space and the path of every file an upload put in place (the photo
        # index marks the space dirty for a photo name). A listener that fails is logged and never
        # fails the upload.
        self._completion_listeners: list[Callable[[SpaceAccess, tuple[str, ...]], None]] = []

    # ---- helpers -----------------------------------------------------------------------

    def _now(self) -> int:
        return int(self._clock())

    def _lock_for(self, upload_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(upload_id, threading.Lock())

    def add_completion_listener(
        self, listener: Callable[[SpaceAccess, tuple[str, ...]], None]
    ) -> None:
        self._completion_listeners.append(listener)

    def _completed(self, access: SpaceAccess, parts: tuple[str, ...]) -> None:
        for listener in self._completion_listeners:
            try:
                listener(access, parts)
            except Exception as exc:
                log.warning("upload_listener_failed", extra=error_fields(exc))

    def _forget_lock(self, upload_id: str) -> None:
        with self._locks_guard:
            self._locks.pop(upload_id, None)

    def _access(self, user_id: str, space: str) -> SpaceAccess:
        """The user's right to upload into `space` right now, or the generic 404: for an upload
        that is already running, a lost or lowered grant, a deleted share and a disabled account
        look exactly like an unknown upload id."""
        try:
            return self._permissions.authorize(user_id, space, Action.UPLOAD)
        except AppError as exc:
            if exc.status_code in (403, 404):
                raise not_found() from None
            raise

    def _audit_upload(
        self, user_id: str, space: str, size: int, overwrite: bool, *, strict: bool
    ) -> None:
        """`upload_completed` for a share space (nothing for `home`). An overwrite is written
        BEFORE the file is replaced and refuses the upload when it cannot be written."""
        self._audit.share_file_event(
            user_id,
            parse_share_space(space),
            "upload_completed",
            {"size": size, "overwrite": overwrite},
            strict=strict,
        )

    def _staging(self, upload_id: str) -> Path:
        return files.staging_path(self._storage.tmp, upload_id)

    @staticmethod
    def _row(r: sqlite3.Row) -> UploadRow:
        return UploadRow(
            id=r["id"],
            user_id=r["user_id"],
            space=r["space"],
            parts=tuple(str(r["rel_path"]).split("/")),
            size=int(r["size"]),
            overwrite=bool(r["overwrite"]),
            created_at=int(r["created_at"]),
            updated_at=int(r["updated_at"]),
        )

    def _find(self, user_id: str, upload_id: str, *, check_access: bool = True) -> UploadRow | None:
        """The caller's own upload, else None: someone else's upload looks like a missing one.

        With `check_access` (the default) the user's right to upload into the upload's space is
        decided again, from the database, and a user who lost it gets None as well. Only abort
        skips this: a user can always discard their own staging."""
        if not UPLOAD_ID.fullmatch(upload_id):
            return None
        with self._db.read() as conn:
            r = conn.execute(
                "SELECT * FROM uploads WHERE id = ? AND user_id = ?", (upload_id, user_id)
            ).fetchone()
        if r is None:
            return None
        row = self._row(r)
        if check_access:
            if self._past_deadline(row):
                return None
            try:
                self._access(user_id, row.space)
            except AppError as exc:
                if exc.status_code == 404:
                    return None
                raise
        return row

    def _past_deadline(self, row: UploadRow) -> bool:
        """True once the upload is older than UPLOAD_MAX_AGE_SECONDS (exactly that old is still
        alive, like the idle limit). Measured from `created_at`, which no chunk ever changes."""
        return self._now() - row.created_at > UPLOAD_MAX_AGE_SECONDS

    def _delete_row(self, upload_id: str) -> None:
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))

    def _staging_size(self, upload_id: str) -> int | None:
        """Real size of the staging file, or None if it is gone (or not a plain file)."""
        try:
            st = os.lstat(self._staging(upload_id))
        except OSError:
            return None
        if is_reparse_stat(st) or not os.path.isfile(self._staging(upload_id)):
            return None
        return st.st_size

    def _end(self, upload_id: str) -> None:
        """Row and lock of a finished upload are gone."""
        try:
            self._delete_row(upload_id)
        finally:
            self._forget_lock(upload_id)

    def try_begin_chunk(self, user_id: str) -> bool:
        """Take one of the user's chunk slots; False if all `max_concurrent_chunks_per_user` are
        taken. A successful call must be paired with `end_chunk`."""
        with self._chunks_guard:
            active = self._active_chunks.get(user_id, 0)
            if active >= self._settings.max_concurrent_chunks_per_user:
                return False
            self._active_chunks[user_id] = active + 1
            return True

    def end_chunk(self, user_id: str) -> None:
        with self._chunks_guard:
            left = self._active_chunks.get(user_id, 0) - 1
            if left > 0:
                self._active_chunks[user_id] = left
            else:
                self._active_chunks.pop(user_id, None)

    def _reserved_bytes(self) -> int:
        """Bytes that all live uploads (every user) have yet to write: space already promised."""
        with self._db.read() as conn:
            rows = conn.execute("SELECT id, size FROM uploads").fetchall()
        return sum(max(int(r["size"]) - (self._staging_size(r["id"]) or 0), 0) for r in rows)

    def _enough_space_for(self, size: int, *, reserved: int = 0) -> bool:
        free = files.free_bytes(self._storage.tmp)
        return free - size - reserved >= self._settings.free_space_floor_bytes

    # ---- create ------------------------------------------------------------------------

    def create(
        self, user_id: str, space: str, parts: tuple[str, ...], size: int, *, overwrite: bool
    ) -> Created:
        """Validate, reserve and register a new upload into `space`. Raises StorageError or
        AppError: 404 when the user has no access to the space, 403 when it is read-only."""
        access = self._permissions.authorize(user_id, space, Action.UPLOAD)  # before anything
        if not parts:
            raise InvalidPath("space-root")
        if size > self._settings.max_upload_bytes:
            raise AppError(413, "payload_too_large", "File exceeds the maximum upload size")
        root = access.root
        self._check_destination(root, parts, overwrite=overwrite)
        self.maybe_run_maintenance()  # may free space, so it runs before the space check
        if not self._enough_space_for(size, reserved=self._reserved_bytes()):
            raise AppError(507, "insufficient_storage", "Not enough free space on the server")

        upload_id = uuid.uuid4().hex
        staging = files.create_staging(self._storage.tmp, upload_id)
        try:
            if size == 0:
                if overwrite:
                    self._audit_upload(user_id, space, 0, True, strict=True)
                item = files.finalize(staging, root, parts, overwrite=overwrite)
                self._completed(access, parts)
                if not overwrite:
                    self._audit_upload(user_id, space, 0, False, strict=False)
                log.info("upload_completed", extra={"user_id": user_id, "size": 0})
                return Created(upload_id, 0, item)
            now = self._now()
            with self._db.transaction() as conn:
                live, declared = conn.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM uploads WHERE user_id = ?",
                    (user_id,),
                ).fetchone()
                if live >= self._settings.max_uploads_per_user:
                    raise AppError(409, "too_many_uploads", "Too many unfinished uploads")
                if declared + size > self._settings.max_inflight_upload_bytes_per_user:
                    raise AppError(
                        507, "upload_quota_exceeded", "Too much data in unfinished uploads"
                    )
                conn.execute(
                    "INSERT INTO uploads (id, user_id, space, rel_path, size, overwrite, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        upload_id,
                        user_id,
                        access.space,
                        "/".join(parts),
                        size,
                        int(overwrite),
                        now,
                        now,
                    ),
                )
        except BaseException:
            files.discard_staging(staging)
            raise
        log.info("upload_created", extra={"user_id": user_id, "size": size})
        return Created(upload_id, size, None)

    def _check_destination(self, root: Path, parts: tuple[str, ...], *, overwrite: bool) -> None:
        """Early conflict check; finalize repeats it atomically when the last byte arrives."""
        parent = files.stat_item(root, parts[:-1])
        if parent.kind != "dir":
            raise NotFound("parent-not-a-folder")
        try:
            existing = files.stat_item(root, parts)
        except NotFound:
            # A new file: refuse a destination that can never be written (path too long) now,
            # not after every byte was sent. Same check the final move makes.
            resolve(root, parts, must_exist=False)
            return
        if existing.kind == "dir":
            raise IsADirectoryErr("target-is-dir")
        if not overwrite:
            raise AlreadyExists("exists")

    # ---- status ------------------------------------------------------------------------

    def status(self, user_id: str, upload_id: str) -> UploadStatus:
        row = self._find(user_id, upload_id)
        if row is None:
            raise not_found()
        offset = self._staging_size(upload_id)
        if offset is None:
            self._drop_orphan_row(upload_id)
            raise not_found()
        return UploadStatus(row, offset)

    def lookup(self, user_id: str, upload_id: str) -> UploadRow:
        row = self._find(user_id, upload_id)
        if row is None:
            raise not_found()
        return row

    def _drop_orphan_row(self, upload_id: str) -> None:
        """A row whose staging file vanished can never complete."""
        with self._lock_for(upload_id):
            if self._staging_size(upload_id) is None:
                self._end(upload_id)

    # ---- append ------------------------------------------------------------------------

    def append(self, user_id: str, upload_id: str, offset: int, data: bytes) -> Appended:
        """Write one chunk at `offset`. The chunk that reaches the declared size completes the
        upload. An empty chunk at the full size retries a completion that failed earlier."""
        if self._find(user_id, upload_id) is None:
            raise not_found()
        lock = self._lock_for(upload_id)
        # Never wait: a second chunk of the same upload is a client bug or an attack, and a
        # waiting request would tie up a worker thread. The client asks for the offset instead.
        if not lock.acquire(blocking=False):
            raise self._busy(upload_id)
        try:
            row = self._find(user_id, upload_id)  # may have ended since the check above
            if row is None:
                self._forget_lock(upload_id)
                raise not_found()
            actual = self._staging_size(upload_id)
            if actual is None:
                self._end(upload_id)
                raise not_found()
            if offset != actual:
                raise to_app_error(OffsetMismatch(actual))
            if actual + len(data) > row.size:
                raise to_app_error(TooLarge("declared-size"))
            if data and not self._enough_space_for(len(data)):
                raise AppError(507, "insufficient_storage", "Not enough free space on the server")
            staging = self._staging(upload_id)
            new_size = actual
            if data:
                new_size = files.append_chunk(staging, offset, data, max_size=row.size)
                with self._db.transaction() as conn:
                    conn.execute(
                        "UPDATE uploads SET updated_at = ? WHERE id = ?", (self._now(), upload_id)
                    )
            if new_size < row.size:
                return Appended(new_size, row.size, None)
            return Appended(new_size, row.size, self._complete(row, staging))
        finally:
            lock.release()

    def _busy(self, upload_id: str) -> AppError:
        offset = self._staging_size(upload_id)
        if offset is None:
            return not_found()
        return AppError(
            409,
            "upload_busy",
            "Another chunk of this upload is being written, retry shortly",
            {"Upload-Offset": str(offset)},
            {"offset": offset},
        )

    def _complete(self, row: UploadRow, staging: Path) -> files.Entry:
        """Atomically move the finished file into place. On failure the staging file stays, so
        the client can fix the cause (e.g. remove the file in the way) and send the last request
        again.

        Once the file is in place the upload is a success whatever happens to the bookkeeping:
        if its row cannot be deleted, the orphan handling removes it later (the staging file is
        gone, so the upload can never continue)."""
        # The last check, right before the file appears: the root comes from this decision, so a
        # grant removed or lowered since the last chunk (or a deleted share) means no file.
        if self._past_deadline(row):
            raise not_found()  # the deadline passed while the last chunk was being written
        access = self._access(row.user_id, row.space)
        root = access.root
        if row.overwrite:
            self._audit_upload(row.user_id, row.space, row.size, True, strict=True)
        item = files.finalize(staging, root, row.parts, overwrite=row.overwrite)
        self._completed(access, row.parts)
        if not row.overwrite:
            self._audit_upload(row.user_id, row.space, row.size, False, strict=False)
        try:
            self._end(row.id)
        except sqlite3.Error as exc:
            log.warning("upload_row_cleanup_failed", extra=error_fields(exc))
        log.info("upload_completed", extra={"user_id": row.user_id, "size": row.size})
        return item

    # ---- abort -------------------------------------------------------------------------

    def abort(self, user_id: str, upload_id: str) -> None:
        # No access check: a user can always discard their own staging, even after losing the
        # right to write into the space.
        if self._find(user_id, upload_id, check_access=False) is None:
            raise not_found()
        with self._lock_for(upload_id):
            files.discard_staging(self._staging(upload_id))  # the maintenance sweep is the net
            self._end(upload_id)
        log.info("upload_aborted", extra={"user_id": user_id, "reason": "client"})

    def discard_for_space(self, space: str) -> int:
        """Drop every unfinished upload into `space` (rows and staging), for a deleted share.
        Tolerates errors: what cannot be removed now is refused by the access check and removed
        by the maintenance sweep. Returns how many uploads were dropped."""
        with self._db.read() as conn:
            ids = [
                r["id"] for r in conn.execute("SELECT id FROM uploads WHERE space = ?", (space,))
            ]
        dropped = 0
        for upload_id in ids:
            try:
                with self._lock_for(upload_id):
                    if not files.discard_staging(self._staging(upload_id)):
                        continue  # locked right now
                    self._end(upload_id)
            except (OSError, StorageError, sqlite3.Error) as exc:
                log.warning("upload_cleanup_failed", extra=error_fields(exc))
                continue
            dropped += 1
        return dropped

    # ---- maintenance -------------------------------------------------------------------

    def maybe_run_maintenance(self) -> None:
        """Cheap, rate limited housekeeping for the create path."""
        now = float(self._clock())
        if now - self._last_maintenance < MAINTENANCE_INTERVAL_SECONDS:
            return
        try:
            self.run_maintenance()
        except (OSError, StorageError, sqlite3.Error) as exc:
            log.warning("upload_maintenance_failed", extra=error_fields(exc))

    def run_maintenance(self) -> MaintenanceResult:
        """Delete uploads idle for `upload_stale_hours` or older than UPLOAD_MAX_AGE_SECONDS, with
        their staging files, then staging files that no row refers to and that are older than an
        hour."""
        if not self._maintenance_lock.acquire(blocking=False):
            return MaintenanceResult(0, 0)  # another run is in progress
        try:
            now = self._now()
            self._last_maintenance = float(now)
            stale = self._drop_stale(
                now - self._settings.upload_stale_hours * 3600, now - UPLOAD_MAX_AGE_SECONDS
            )
            orphans = self._drop_orphans(now - ORPHAN_AGE_SECONDS)
            if stale or orphans:
                log.info(
                    "upload_maintenance", extra={"stale_uploads": stale, "orphan_files": orphans}
                )
            return MaintenanceResult(stale, orphans)
        finally:
            self._maintenance_lock.release()

    def _drop_stale(self, cutoff: int, born_cutoff: int) -> int:
        """Drop uploads idle since before `cutoff` or created before `born_cutoff` (the absolute
        lifetime). A finished upload has no row, so a finalized file is never touched."""
        with self._db.read() as conn:
            rows = conn.execute(
                "SELECT id, user_id FROM uploads WHERE updated_at < ? OR created_at < ?",
                (cutoff, born_cutoff),
            ).fetchall()
        dropped = 0
        for r in rows:
            upload_id = r["id"]
            try:
                with self._lock_for(upload_id):
                    with self._db.read() as conn:  # a chunk may have arrived while we waited
                        fresh = conn.execute(
                            "SELECT 1 FROM uploads WHERE id = ? "
                            "AND (updated_at < ? OR created_at < ?)",
                            (upload_id, cutoff, born_cutoff),
                        ).fetchone()
                    if fresh is None:
                        continue
                    if not files.discard_staging(self._staging(upload_id)):
                        continue  # locked right now; the next run retries
                    self._end(upload_id)
            except (OSError, StorageError) as exc:
                # One bad upload must not stop the rest; the next run tries it again.
                log.warning("upload_cleanup_failed", extra=error_fields(exc))
                continue
            dropped += 1
            log.info("upload_aborted", extra={"user_id": r["user_id"], "reason": "stale"})
        return dropped

    def _drop_orphans(self, cutoff: int) -> int:
        with self._db.read() as conn:
            live = {r["id"] for r in conn.execute("SELECT id FROM uploads")}
        removed = 0
        try:
            entries = list(os.scandir(self._storage.tmp))
        except OSError:
            return 0
        for entry in entries:
            name = entry.name
            stem = name[: -len(".part")]
            if not name.endswith(".part") or not UPLOAD_ID.fullmatch(stem) or stem in live:
                continue  # not ours; the startup sweep deals with strangers by age
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if st.st_mtime >= cutoff:
                continue
            try:
                if files.discard_staging(self._storage.tmp / name):
                    removed += 1
            except (OSError, StorageError):
                continue
        return removed
