"""Photo thumbnails: a row per file version plus bytes in a file (docs/THUMBNAILS-SPEC.md).

Thumbnails are made on the client. The server checks the JPEG structure, removes metadata and keeps
the result; it decodes no pixels.

Concurrency. The database is one connection with `synchronous=FULL`, so no disk work ever happens
inside its lock. What keeps a row and its bytes together is a striped in-process lock (the server
is one process): a PUT holds it from its check of the row to its re-stat of the source, and a GET
holds it while it compares and reads. The order is always stripe first, database second, and only
one stripe at a time. Bytes are moved into place before their row is committed and removed only
when no row refers to them, so a row is only ever wrong in the safe direction: it may have no
bytes (one 404, then it is gone), but it never has bytes of another version of the file. A crash
can leave bytes no row refers to, which no route can reach.

Logs carry a user id, a size and fixed reason codes, never a name, a path or a key. A refused body
is logged at INFO with the walker's reason, to tell whether a phone's canvas output passes. No
audit rows (a backfill would evict real evidence from the audit trail); `set_by` records who wrote
a thumbnail.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from yournas import jpeg_markers
from yournas.api.common import iso_utc, not_found
from yournas.auth.service import session_not_revoked
from yournas.core.config import GIB, KIB, Settings
from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.permissions import Action, Permissions, SpaceAccess
from yournas.storage import files, thumbs
from yournas.storage.errors import StorageError
from yournas.storage.thumbs import SourceFile

log = logging.getLogger("yournas.thumbnails")

THUMBNAIL_MAX_BYTES = 128 * KIB
THUMBNAILS_TOTAL_MAX_BYTES = 2 * GIB
MAX_PUTS_PER_USER = 2
# The list in web/static/js/preview.js.
PHOTO_EXTENSIONS = frozenset(("jpg", "jpeg", "png", "gif", "webp", "heic", "heif"))
_STRIPES = 64


@dataclass(frozen=True)
class _Row:
    file_ino: str
    file_size: int
    file_mtime_ns: int
    byte_len: int

    def describes(self, source: SourceFile) -> bool:
        return (self.file_ino, self.file_size, self.file_mtime_ns) == (
            source.ino,
            source.size,
            source.mtime_ns,
        )


def is_photo_name(name: str) -> bool:
    """A name with a stem and one of PHOTO_EXTENSIONS (any case). The one test of "photo-named"
    shared by thumbnails, the photo index walk and its dirty marks."""
    stem, dot, extension = name.rpartition(".")
    return bool(dot and stem) and extension.lower() in PHOTO_EXTENSIONS


def _invalid_thumbnail() -> AppError:
    return AppError(400, "invalid_thumbnail", "That is not an acceptable thumbnail")


def _session_ended() -> AppError:
    # The same answer require_session gives for a dead token.
    return AppError(401, "unauthorized", "Authentication required", {"WWW-Authenticate": "Bearer"})


def _log_refused(user_id: str, size: int, reason: str, marker: int | None = None) -> None:
    """Why a body was refused: a fixed reason code, the marker byte where there is one (0xc2 is
    progressive), the user id and the size. Never a name or a path."""
    fields: dict[str, object] = {"user_id": user_id, "size": size, "reason": reason}
    if marker is not None:
        fields["marker"] = f"0x{marker:02x}"
    log.info("thumbnail_refused", extra=fields)


def _not_a_photo() -> AppError:
    return AppError(400, "invalid_request", "That item cannot have a thumbnail")


def _item_changed() -> AppError:
    return AppError(409, "item_changed", "The file changed, read it again")


def _no_space() -> AppError:
    return AppError(507, "insufficient_storage", "Not enough free space on the server")


class ThumbnailService:
    def __init__(
        self,
        db: Database,
        permissions: Permissions,
        settings: Settings,
        directory: Path,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._permissions = permissions
        self._settings = settings
        self._dir = directory
        self._clock = clock
        self._stripes = tuple(threading.Lock() for _ in range(_STRIPES))
        self._active_puts: dict[str, int] = {}
        self._puts_guard = threading.Lock()

    # ---- helpers -----------------------------------------------------------------------

    @contextmanager
    def _stripe(self, scope: str, key: str) -> Iterator[None]:
        with self._stripes[int(thumbs.digest(scope, key)[:8], 16) % _STRIPES]:
            yield

    def _row(self, scope: str, key: str) -> _Row | None:
        with self._db.read() as conn:
            r = conn.execute(
                "SELECT file_ino, file_size, file_mtime_ns, byte_len FROM thumbnails "
                "WHERE scope = ? AND path_key = ?",
                (scope, key),
            ).fetchone()
        if r is None:
            return None
        return _Row(r["file_ino"], int(r["file_size"]), int(r["file_mtime_ns"]), int(r["byte_len"]))

    def _forget(self, scope: str, key: str) -> None:
        """Remove a row and its bytes. The caller holds the stripe. A failure is logged only: what
        stays is a row that fails its next check, or bytes no route can reach."""
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    "DELETE FROM thumbnails WHERE scope = ? AND path_key = ?", (scope, key)
                )
            thumbs.remove(self._dir, scope, key)
        except Exception as exc:
            log.warning("thumbnail_cleanup_failed", extra=error_fields(exc))

    @staticmethod
    def _total(conn: sqlite3.Connection) -> int:
        (total,) = conn.execute("SELECT COALESCE(SUM(byte_len), 0) FROM thumbnails").fetchone()
        return int(total)

    # ---- at most a few writes per user -------------------------------------------------

    def try_begin_put(self, user_id: str) -> bool:
        """Take one of the user's PUT slots; False if all are taken. Pair with `end_put`."""
        with self._puts_guard:
            active = self._active_puts.get(user_id, 0)
            if active >= MAX_PUTS_PER_USER:
                return False
            self._active_puts[user_id] = active + 1
            return True

    def end_put(self, user_id: str) -> None:
        with self._puts_guard:
            left = self._active_puts.get(user_id, 0) - 1
            if left > 0:
                self._active_puts[user_id] = left
            else:
                self._active_puts.pop(user_id, None)

    # ---- PUT ---------------------------------------------------------------------------

    def check_source(
        self, access: SpaceAccess, parts: tuple[str, ...], size: int, modified: str
    ) -> tuple[str, SourceFile]:
        """The key and version of the file a thumbnail is for, or the reason it cannot have one.
        The name that counts is the real one: an 8.3 alias can end in `.JPG` for `a.jpgx`."""
        key, source = thumbs.locate(access.root, parts)
        if source is None:
            raise not_found()
        if not source.regular or not is_photo_name(source.name) or source.size <= 0:
            raise _not_a_photo()
        if source.size != size or iso_utc(source.mtime) != modified:
            raise _item_changed()
        return key, source

    def store(
        self,
        user_id: str,
        access: SpaceAccess,
        parts: tuple[str, ...],
        size: int,
        modified: str,
        body: bytes,
        *,
        session: str,
    ) -> None:
        """Keep a thumbnail that has fully arrived. The caller's authorization is older than the
        body, so it is decided again here and once more inside the commit transaction, where the
        session (`session` is its token hash) must also still be live.

        Every size rule uses the stored (stripped) length: the 128 KiB body cap is the only one
        that counts what was sent."""
        self._permissions.require(user_id, access.space, Action.THUMBNAIL_WRITE)
        try:
            clean = jpeg_markers.sanitize(body)
        except jpeg_markers.InvalidJpeg as exc:
            _log_refused(user_id, len(body), str(exc), exc.marker)
            raise _invalid_thumbnail() from None
        scope = access.scope
        key = thumbs.path_key(access.root, parts)
        with self._stripe(scope, key):
            current_key, source = self.check_source(access, parts, size, modified)
            if current_key != key:
                raise _item_changed()  # the path now names another file, under another stripe
            if len(clean) > source.size:
                _log_refused(user_id, len(clean), "larger-than-source")
                raise _invalid_thumbnail()
            row = self._row(scope, key)
            if row is not None and row.describes(source):
                return  # first writer wins, per version of the file
            replaced = row.byte_len if row is not None else 0
            self._check_room(len(clean), replaced)
            thumbs.write(self._dir, scope, key, clean)
            try:
                self._commit(user_id, session, access, key, source, len(clean), replaced)
            except BaseException:
                self._forget(scope, key)  # nothing may refer to bytes that were refused
                raise
            self._recheck_source(access, parts, key, source)
        log.info("thumbnail_stored", extra={"user_id": user_id, "size": len(clean)})

    def _check_room(self, new: int, replaced: int) -> None:
        with self._db.read() as conn:
            total = self._total(conn)
        if total - replaced + new > THUMBNAILS_TOTAL_MAX_BYTES:
            raise _no_space()
        # The parent exists: it holds the database.
        free = files.free_bytes(self._dir.parent)
        if free - new < self._settings.free_space_floor_bytes:
            raise _no_space()

    def _commit(
        self,
        user_id: str,
        session: str,
        access: SpaceAccess,
        key: str,
        source: SourceFile,
        new: int,
        replaced: int,
    ) -> None:
        with self._db.transaction() as conn:
            # A logout, a sign-out everywhere or a password reset while the body was arriving.
            if not session_not_revoked(conn, session):
                raise _session_ended()
            self._permissions.require(user_id, access.space, Action.THUMBNAIL_WRITE)
            if self._total(conn) - replaced + new > THUMBNAILS_TOTAL_MAX_BYTES:
                raise _no_space()
            conn.execute(
                "INSERT INTO thumbnails (scope, path_key, file_ino, file_size, file_mtime_ns, "
                "byte_len, set_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (scope, path_key) DO UPDATE SET file_ino = excluded.file_ino, "
                "file_size = excluded.file_size, file_mtime_ns = excluded.file_mtime_ns, "
                "byte_len = excluded.byte_len, set_by = excluded.set_by, "
                "created_at = excluded.created_at",
                (
                    access.scope,
                    key,
                    source.ino,
                    source.size,
                    source.mtime_ns,
                    new,
                    user_id,
                    int(self._clock()),
                ),
            )

    def _recheck_source(
        self, access: SpaceAccess, parts: tuple[str, ...], key: str, source: SourceFile
    ) -> None:
        """A delete or an overwrite may have run while this PUT was storing: its cleanup saw no
        row yet, so the row that was just committed is removed here."""
        try:
            _, now = thumbs.locate(access.root, parts)
        except StorageError:
            now = None
        if now == source:
            return
        self._forget(access.scope, key)
        if now is None or not now.regular:
            raise not_found()
        raise _item_changed()

    # ---- GET ---------------------------------------------------------------------------

    def fetch(self, access: SpaceAccess, parts: tuple[str, ...]) -> bytes:
        """The bytes of a thumbnail that matches the file as it is now. Everything else is the
        same 404, and a row found to be stale goes away with its bytes."""
        scope = access.scope
        key = thumbs.path_key(access.root, parts)
        if self._row(scope, key) is None:
            raise not_found()
        with self._stripe(scope, key):
            key_now, source = thumbs.locate(access.root, parts)
            row = self._row(scope, key)
            if key_now != key or row is None:
                raise not_found()
            if source is None or not source.regular or not row.describes(source):
                self._forget(scope, key)
                raise not_found()
            data = thumbs.read(self._dir, scope, key, row.byte_len + 1)
            if data is None or len(data) != row.byte_len:
                self._forget(scope, key)
                raise not_found()
            return data

    # ---- listing -----------------------------------------------------------------------

    def present(
        self, access: SpaceAccess, parts: tuple[str, ...], names: Iterable[str]
    ) -> frozenset[str]:
        """Which of these files in a folder have a row. Only a hint, so it never fails a listing
        and never looks at the files: a stale answer costs one 404 on GET."""
        names = list(names)
        if not names:
            return frozenset()
        try:
            folder = thumbs.path_key(access.root, parts)
            prefix = f"{folder}/" if folder else ""
            # Listed names are spelled as on disk, like the stored keys (see thumbs.path_key).
            keys = {name: prefix + name for name in names}
            wanted = sorted(set(keys.values()))
            marks = ",".join("?" * len(wanted))
            query = f"SELECT path_key FROM thumbnails WHERE scope = ? AND path_key IN ({marks})"
            with self._db.read() as conn:
                found = {r["path_key"] for r in conn.execute(query, (access.scope, *wanted))}
        except (StorageError, sqlite3.Error) as exc:
            log.warning("thumbnail_lookup_failed", extra=error_fields(exc))
            return frozenset()
        return frozenset(name for name, key in keys.items() if key in found)

    # ---- cleanup -----------------------------------------------------------------------

    def sweep_temp_files(self) -> int:
        """At startup: remove the temp files a crash left (see thumbs.sweep_temp_files)."""
        return thumbs.sweep_temp_files(self._dir)

    def key_of(self, access: SpaceAccess, parts: tuple[str, ...]) -> str | None:
        """The key of an item that is about to be deleted (it cannot be resolved afterwards), or
        None if there is none. Cleanup never fails a delete, so neither does this."""
        if not parts:
            return None
        try:
            return thumbs.path_key(access.root, parts)
        except Exception as exc:
            log.warning("thumbnail_cleanup_failed", extra=error_fields(exc))
            return None

    def purge(self, scope: str, key: str, *, folder: bool) -> None:
        """Remove what is stored for a deleted item, and for a folder everything below it. A range
        and never LIKE: `_` and `%` are legal in names. `/` and `0` are neighbours in byte order,
        so the range holds exactly the keys that start with `key/`."""
        try:
            where = "scope = ? AND path_key = ?"
            params: tuple[str, ...] = (scope, key)
            if folder:
                where = "scope = ? AND (path_key = ? OR (path_key >= ? AND path_key < ?))"
                params = (scope, key, f"{key}/", f"{key}0")
            with self._db.transaction() as conn:
                keys = [
                    r["path_key"]
                    for r in conn.execute(f"SELECT path_key FROM thumbnails WHERE {where}", params)
                ]
                if keys:
                    conn.execute(f"DELETE FROM thumbnails WHERE {where}", params)
        except Exception as exc:
            log.warning("thumbnail_cleanup_failed", extra=error_fields(exc))
            return
        self.unlink_unreferenced(scope, keys)

    def take_scope(self, conn: sqlite3.Connection, scope: str) -> list[str]:
        """Inside the caller's transaction: remove every row of a scope and return the keys, for
        `unlink_unreferenced` after the commit. A failure is logged and leaves rows that no
        authorization can reach, because share ids are never reused."""
        try:
            keys = [
                str(r["path_key"])
                for r in conn.execute("SELECT path_key FROM thumbnails WHERE scope = ?", (scope,))
            ]
            conn.execute("DELETE FROM thumbnails WHERE scope = ?", (scope,))
        except sqlite3.Error as exc:
            log.warning("thumbnail_cleanup_failed", extra=error_fields(exc))
            return []
        return keys

    def unlink_unreferenced(self, scope: str, keys: Iterable[str]) -> None:
        """Remove the bytes of these keys, outside any transaction. Checked under the stripe: a PUT
        may have written a new version of a key since its row was removed."""
        for key in keys:
            try:
                with self._stripe(scope, key):
                    if self._row(scope, key) is None:
                        thumbs.remove(self._dir, scope, key)
            except Exception as exc:
                log.warning("thumbnail_cleanup_failed", extra=error_fields(exc))
