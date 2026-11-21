"""Share administration: create, rename, delete shares and set or remove grants (owner only; the
routes enforce that).

A share is a display name plus a folder `shared/<share_id>/` that the SERVER names: the client
never sends a path, so a share cannot point anywhere but its own folder under the storage root.
Names are display-only text and never touch the filesystem.

Every change writes its audit row in the same transaction (an audit failure undoes the change).
Deleting a share never deletes files: it is refused while the folder holds anything at all.
Audit rows hold ids and counters only, never a share name.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from yournas.audit import AuditLog
from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.permissions import SHARE_ID, Permissions, ShareDirs, share_scope, share_space_id
from yournas.photo_index import PhotoIndexService
from yournas.storage.errors import StorageError
from yournas.thumbnails import ThumbnailService
from yournas.uploads import UploadService

log = logging.getLogger("yournas.shares")

SHARE_NAME_MAX = 64
USER_ID = re.compile(r"u_[0-9a-f]{16}")
Level = Literal["read", "write"]


@dataclass(frozen=True)
class GrantRecord:
    user_id: str
    level: Level


@dataclass(frozen=True)
class ShareRecord:
    id: str
    name: str
    created_at: int
    grants: tuple[GrantRecord, ...]


def is_share_id(value: str) -> bool:
    return SHARE_ID.fullmatch(value) is not None


def is_user_id(value: str) -> bool:
    return USER_ID.fullmatch(value) is not None


def normalize_share_name(raw: str) -> str:
    """Canonical display name (NFC, trimmed), or 400 `invalid_share_name`. 1-64 characters, no
    control, format (bidi, zero width) or separator characters other than a plain space."""
    name = unicodedata.normalize("NFC", raw).strip()
    ok = 1 <= len(name) <= SHARE_NAME_MAX and all(
        ch == " " or unicodedata.category(ch)[0] not in ("C", "Z") for ch in name
    )
    if not ok:
        raise AppError(
            400,
            "invalid_share_name",
            f"Share name must be 1-{SHARE_NAME_MAX} characters without control characters",
        )
    return name


def _name_taken() -> AppError:
    return AppError(409, "share_name_taken", "That share name is not available")


def _not_found() -> AppError:
    return AppError(404)


class ShareService:
    def __init__(
        self,
        db: Database,
        permissions: Permissions,
        uploads: UploadService,
        audit: AuditLog,
        thumbnails: ThumbnailService,
        photo_index: PhotoIndexService,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._perms = permissions
        self._uploads = uploads
        self._audit = audit
        self._thumbnails = thumbnails
        self._photo_index = photo_index
        self._clock = clock

    # ---- reading -----------------------------------------------------------------------

    def list_shares(self) -> list[ShareRecord]:
        with self._db.read() as conn:
            shares = conn.execute(
                "SELECT id, name, created_at FROM shares ORDER BY name COLLATE NOCASE, id"
            ).fetchall()
            grants = conn.execute(
                "SELECT share_id, user_id, level FROM grants ORDER BY user_id"
            ).fetchall()
        by_share: dict[str, list[GrantRecord]] = {}
        for g in grants:
            by_share.setdefault(g["share_id"], []).append(GrantRecord(g["user_id"], g["level"]))
        return [
            ShareRecord(s["id"], s["name"], int(s["created_at"]), tuple(by_share.get(s["id"], ())))
            for s in shares
        ]

    def get(self, share_id: str) -> ShareRecord:
        for record in self.list_shares():
            if record.id == share_id:
                return record
        raise _not_found()

    # ---- create, rename ----------------------------------------------------------------

    def create(self, actor_id: str, raw_name: str) -> ShareRecord:
        """A new share with its folder; the creator gets a revocable `write` grant. The folder
        is made first (the id is random and never reused, so an orphan is harmless) and removed
        again if the database refuses the share."""
        name = normalize_share_name(raw_name)
        share_id = ShareDirs.new_id()
        try:
            self._perms.shares.create(share_id)
        except StorageError as exc:
            log.error("share_dir_create_failed", extra=error_fields(exc))
            raise AppError(500, "internal_error", "Internal Server Error") from None
        now = int(self._clock())
        try:
            with self._db.transaction() as conn:
                self._require_name_free(conn, name, None)
                conn.execute(
                    "INSERT INTO shares (id, name, created_at, created_by) VALUES (?, ?, ?, ?)",
                    (share_id, name, now, actor_id),
                )
                conn.execute(
                    "INSERT INTO grants (share_id, user_id, level, created_at) "
                    "VALUES (?, ?, 'write', ?)",
                    (share_id, actor_id, now),
                )
                self._audit.record(conn, actor_id, "share_created", "share", share_id)
                self._audit.record(
                    conn,
                    actor_id,
                    "grant_set",
                    "grant",
                    f"{share_id}:{actor_id}",
                    {"level": "write"},
                )
        except BaseException as exc:
            self._remove_dir_quietly(share_id)
            if isinstance(exc, sqlite3.IntegrityError):
                raise _name_taken() from None
            raise
        log.info("share_created", extra={"actor_id": actor_id, "share_id": share_id})
        self._audit.maybe_prune()
        return self.get(share_id)

    def rename(self, actor_id: str, share_id: str, raw_name: str) -> ShareRecord:
        name = normalize_share_name(raw_name)
        try:
            with self._db.transaction() as conn:
                self._require_share(conn, share_id)
                self._require_name_free(conn, name, share_id)
                conn.execute("UPDATE shares SET name = ? WHERE id = ?", (name, share_id))
                self._audit.record(conn, actor_id, "share_renamed", "share", share_id)
        except sqlite3.IntegrityError:
            raise _name_taken() from None
        log.info("share_renamed", extra={"actor_id": actor_id, "share_id": share_id})
        self._audit.maybe_prune()
        return self.get(share_id)

    # ---- delete ------------------------------------------------------------------------

    def delete(self, actor_id: str, share_id: str) -> None:
        """Remove the share, its grants and its unfinished uploads. Files are never deleted:
        a share whose folder holds anything (hidden or unlistable names included) is refused with
        409 `not_empty` and nothing changes.

        The emptiness check runs inside the same transaction as the delete. That transaction
        holds the database lock, so no authorization can be decided between the check and the
        commit: nobody can start a write into the share in that window. (A write that passed its
        own authorization a moment earlier can still land; its folder is then left behind, see
        below, and no file is lost.)"""
        with self._db.transaction() as conn:
            self._require_share(conn, share_id)
            (grants,) = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE share_id = ?", (share_id,)
            ).fetchone()
            conn.execute("DELETE FROM shares WHERE id = ?", (share_id,))  # grants cascade
            thumb_scope = share_scope(share_id)
            thumb_keys = self._thumbnails.take_scope(conn, thumb_scope)  # bytes go after the commit
            self._photo_index.take_scope(conn, thumb_scope)
            self._audit.record(
                conn, actor_id, "share_deleted", "share", share_id, {"count": int(grants)}
            )
            try:
                empty = self._perms.shares.is_empty(share_id)
            except StorageError as exc:
                log.error("share_dir_check_failed", extra=error_fields(exc))
                raise AppError(500, "internal_error", "Internal Server Error") from None
            if not empty:
                raise AppError(409, "not_empty", "Share is not empty")  # rolls everything back
        self._thumbnails.unlink_unreferenced(thumb_scope, thumb_keys)
        self._photo_index.forget_scope(thumb_scope)  # its job stops between two files
        dropped = self._uploads.discard_for_space(share_space_id(share_id))
        log.info(
            "share_deleted",
            extra={"actor_id": actor_id, "share_id": share_id, "uploads_dropped": dropped},
        )
        # Never a recursive delete: rmdir succeeds only on an empty folder. If it cannot go
        # (something was written in the last moment, or a plain error) the folder stays, nothing
        # refers to it any more, and the id is never reused.
        self._remove_dir_quietly(share_id)
        self._audit.maybe_prune()

    # ---- grants ------------------------------------------------------------------------

    def set_grant(self, actor_id: str, share_id: str, user_id: str, level: Level) -> GrantRecord:
        """Give `user_id` the level on the share, replacing any earlier level (upsert). A
        disabled user may hold a grant: it takes effect when the account is enabled again."""
        with self._db.transaction() as conn:
            self._require_share(conn, share_id)
            self._require_user(conn, user_id)
            conn.execute(
                "INSERT INTO grants (share_id, user_id, level, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (share_id, user_id) DO UPDATE SET level = excluded.level",
                (share_id, user_id, level, int(self._clock())),
            )
            self._audit.record(
                conn, actor_id, "grant_set", "grant", f"{share_id}:{user_id}", {"level": level}
            )
        log.info(
            "grant_set", extra={"actor_id": actor_id, "share_id": share_id, "user_id": user_id}
        )
        self._audit.maybe_prune()
        return GrantRecord(user_id, level)

    def remove_grant(self, actor_id: str, share_id: str, user_id: str) -> None:
        """Take the access away. Idempotent: no grant is a success (and no audit row)."""
        with self._db.transaction() as conn:
            self._require_share(conn, share_id)
            self._require_user(conn, user_id)
            removed = conn.execute(
                "DELETE FROM grants WHERE share_id = ? AND user_id = ?", (share_id, user_id)
            ).rowcount
            if removed:
                self._audit.record(
                    conn, actor_id, "grant_removed", "grant", f"{share_id}:{user_id}"
                )
        if removed:
            log.info(
                "grant_removed",
                extra={"actor_id": actor_id, "share_id": share_id, "user_id": user_id},
            )
            self._audit.maybe_prune()

    # ---- helpers -----------------------------------------------------------------------

    @staticmethod
    def _require_name_free(conn: sqlite3.Connection, name: str, except_id: str | None) -> None:
        """409 if another share already has this name, ignoring case in every script (the
        column's NOCASE only folds ASCII, so "Café" and "CAFÉ" are caught here). The table is
        tiny and this runs inside the write transaction, so two requests cannot both pass."""
        wanted = name.casefold()
        for row in conn.execute("SELECT id, name FROM shares"):
            if row["id"] != except_id and str(row["name"]).casefold() == wanted:
                raise _name_taken()

    @staticmethod
    def _require_share(conn: sqlite3.Connection, share_id: str) -> None:
        if conn.execute("SELECT 1 FROM shares WHERE id = ?", (share_id,)).fetchone() is None:
            raise _not_found()

    @staticmethod
    def _require_user(conn: sqlite3.Connection, user_id: str) -> None:
        if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
            raise _not_found()

    def _remove_dir_quietly(self, share_id: str) -> None:
        try:
            self._perms.shares.remove_if_empty(share_id)
        except Exception as exc:
            log.warning("share_dir_orphaned", extra={"share_id": share_id, **error_fields(exc)})
