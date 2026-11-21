"""Audit log: who changed what in the administration and in shared spaces.

Only admin and account changes and file events inside shared spaces are recorded; private `home`
activity and unauthenticated events (failed logins) are not (they stay in the JSON log). A row
holds ids and a few counters, never a name: no user names, share names, file names, paths, tokens
or passwords. `record` enforces that with an allowlist and refuses anything else, so a future
caller cannot start writing personal data by accident. The owner maps ids to names through the
list endpoints.

`record` writes on the caller's connection, so an admin change and its audit row commit or roll
back together (an audit failure means the change is not applied: fail closed).
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from yournas.core.database import Database
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields

log = logging.getLogger("yournas.audit")

# Admin/account changes and share-space file events (docs: Phase 4 spec section 6).
ACTIONS = frozenset(
    {
        "user_created",
        "user_disabled",
        "user_enabled",
        "password_reset",
        "sessions_revoked",
        "share_created",
        "share_renamed",
        "share_deleted",
        "grant_set",
        "grant_removed",
        "password_changed",
        "folder_created",
        "upload_completed",
        "item_deleted",
    }
)
# File events inside shares: the only rows a friend with `write` access can create, and so the
# only rows that can flood the table. They are evicted before anything else. Every other action
# (accounts, sessions, shares, grants, passwords) is a management/security event.
FILE_ACTIONS = frozenset({"folder_created", "upload_completed", "item_deleted"})
MANAGEMENT_ACTIONS = ACTIONS - FILE_ACTIONS
# At most this many file events are evicted by one write (bounded work per request); the daily
# prune removes any rest.
WRITE_TRIM_BATCH = 100
# user: an account. share: a share (also the target of file events inside it). grant: one
# user's access to one share, its target id is "<share_id>:<user_id>".
TARGET_TYPES = frozenset({"user", "share", "grant"})
# detail keys and the value type each one takes. Nothing else may be stored.
DETAIL_KEYS: Mapping[str, type] = {
    "level": str,  # "read" | "write"
    "size": int,  # bytes
    "kind": str,  # "file" | "dir"
    "depth": int,  # number of path components, never the path
    "disabled": bool,
    "count": int,
    "overwrite": bool,
}
MAX_INT = 2**63 - 1  # fits SQLite and JSON consumers
_DETAIL_STRING = re.compile(r"[a-z_]{1,16}")
_ACTOR_ID = re.compile(r"[A-Za-z0-9_]{1,64}")
_TARGET_ID = re.compile(r"[A-Za-z0-9_:]{1,80}")

MAX_LIMIT = 500
DEFAULT_LIMIT = 100
DAY_SECONDS = 86400
DEFAULT_MAX_AGE_DAYS = 365
DEFAULT_MAX_ROWS = 100_000

DetailValue = int | bool | str


class AuditError(ValueError):
    """An audit entry was refused (programming error or malformed cursor). The message never
    contains the offending value, because that value may be what must not be stored."""


@dataclass(frozen=True)
class AuditEvent:
    id: int
    at: int
    actor_id: str
    action: str
    target_type: str
    target_id: str
    detail: dict[str, DetailValue] | None


@dataclass(frozen=True)
class AuditFilter:
    action: str | None = None
    actor_id: str | None = None
    target_id: str | None = None


@dataclass(frozen=True)
class AuditPage:
    events: tuple[AuditEvent, ...]
    next_cursor: str | None


def _check_detail(detail: Mapping[str, object]) -> str:
    for key, value in detail.items():
        expected = DETAIL_KEYS.get(key) if isinstance(key, str) else None
        if expected is None:
            raise AuditError("audit detail key is not allowed")
        if expected is bool:
            ok = isinstance(value, bool)
        elif expected is int:
            ok = isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_INT
        else:
            ok = isinstance(value, str) and _DETAIL_STRING.fullmatch(value) is not None
        if not ok:
            raise AuditError("audit detail value is not allowed")
    return json.dumps(dict(detail), sort_keys=True, separators=(",", ":"))


def record(
    conn: sqlite3.Connection,
    actor_id: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: Mapping[str, object] | None = None,
    *,
    now: int | None = None,
) -> int:
    """Insert one audit row on `conn` (inside the caller's transaction) and return its id.

    Raises AuditError for an unknown action or target type, an id that is not a plain identifier
    (a name or a path would not fit), a detail key outside DETAIL_KEYS, or a detail value of the
    wrong type (strings: lowercase letters and underscore, 16 characters at most).
    """
    if action not in ACTIONS:
        raise AuditError("unknown audit action")
    if target_type not in TARGET_TYPES:
        raise AuditError("unknown audit target type")
    if not isinstance(actor_id, str) or _ACTOR_ID.fullmatch(actor_id) is None:
        raise AuditError("audit actor id is not an identifier")
    if not isinstance(target_id, str) or _TARGET_ID.fullmatch(target_id) is None:
        raise AuditError("audit target id is not an identifier")
    encoded = None if not detail else _check_detail(detail)
    at = int(time.time()) if now is None else now
    cur = conn.execute(
        "INSERT INTO audit_log (at, actor_id, action, target_type, target_id, detail) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (at, actor_id, action, target_type, target_id, encoded),
    )
    row_id = cur.lastrowid
    assert row_id is not None
    return row_id


# ---- cursor ------------------------------------------------------------------------------


def encode_cursor(last_id: int) -> str:
    """Opaque cursor naming the last row of a page."""
    return base64.urlsafe_b64encode(f"a1:{last_id}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> int:
    """The row id a cursor stands for. AuditError for anything this module did not produce."""
    try:
        if not isinstance(cursor, str) or not cursor or len(cursor) > 64:
            raise ValueError
        padded = cursor + "=" * (-len(cursor) % 4)
        text = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True).decode()
        prefix, _, number = text.partition(":")
        if prefix != "a1" or not number.isascii() or not number.isdigit():
            raise ValueError
        value = int(number)
        if value > MAX_INT:
            raise ValueError
    except (ValueError, binascii.Error, UnicodeError):
        raise AuditError("invalid audit cursor") from None
    return value


# ---- reading -----------------------------------------------------------------------------


def _parse_detail(raw: object) -> dict[str, DetailValue] | None:
    if not isinstance(raw, str):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return {k: v for k, v in data.items() if k in DETAIL_KEYS and isinstance(v, int | bool | str)}


def list_events(
    db: Database,
    limit: int = DEFAULT_LIMIT,
    after_id: int | None = None,
    filters: AuditFilter | None = None,
) -> AuditPage:
    """Newest first. `after_id` is the id of the last row already seen (see decode_cursor); only
    older rows are returned. `limit` is clamped to 1..MAX_LIMIT."""
    limit = min(max(int(limit), 1), MAX_LIMIT)
    where: list[str] = []
    params: list[object] = []
    if after_id is not None:
        where.append("id < ?")
        params.append(after_id)
    f = filters or AuditFilter()
    for column, value in (
        ("action", f.action),
        ("actor_id", f.actor_id),
        ("target_id", f.target_id),
    ):
        if value is not None:
            where.append(f"{column} = ?")  # column names come from the tuple above
            params.append(value)
    sql = "SELECT * FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit + 1)
    with db.read() as conn:
        rows = conn.execute(sql, params).fetchall()
    page = rows[:limit]
    events = tuple(
        AuditEvent(
            id=int(r["id"]),
            at=int(r["at"]),
            actor_id=str(r["actor_id"]),
            action=str(r["action"]),
            target_type=str(r["target_type"]),
            target_id=str(r["target_id"]),
            detail=_parse_detail(r["detail"]),
        )
        for r in page
    )
    more = len(rows) > limit
    return AuditPage(events, encode_cursor(events[-1].id) if more and events else None)


# ---- retention ---------------------------------------------------------------------------


def prune(
    db: Database,
    now: int,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> int:
    """Delete rows older than `max_age_days`, then bring the table down to `max_rows` in one
    transaction: the oldest FILE events go first, and a management/security event is deleted
    only when no file event is left to give up. Returns how many rows were deleted."""
    if max_age_days < 1 or max_rows < 1:
        raise ValueError("retention limits must be positive")
    with db.transaction() as conn:
        deleted = conn.execute(
            "DELETE FROM audit_log WHERE at < ?", (now - max_age_days * DAY_SECONDS,)
        ).rowcount
        excess = _row_count(conn) - max_rows
        if excess > 0:
            deleted += _delete_oldest(conn, excess, FILE_ACTIONS)
            excess = _row_count(conn) - max_rows
        if excess > 0:
            deleted += _delete_oldest(conn, excess, ACTIONS)
    return int(deleted)


def _row_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])


def _delete_oldest(
    conn: sqlite3.Connection,
    limit: int,
    actions: frozenset[str],
    *,
    keep_id: int | None = None,
) -> int:
    """Delete up to `limit` of the oldest rows whose action is in `actions` (never `keep_id`)."""
    names = sorted(actions)
    marks = ", ".join("?" for _ in names)  # placeholders only, the values are bound
    sql = (
        f"DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log "
        f"WHERE action IN ({marks}) AND id != ? ORDER BY id LIMIT ?)"
    )
    return int(conn.execute(sql, (*names, -1 if keep_id is None else keep_id, limit)).rowcount)


class AuditLog:
    """The audit log of one app: `record` on a transaction connection, reading, and retention
    that runs at most once a day."""

    def __init__(
        self,
        db: Database,
        clock: Callable[[], float] = time.time,
        *,
        max_age_days: int = DEFAULT_MAX_AGE_DAYS,
        max_rows: int = DEFAULT_MAX_ROWS,
    ) -> None:
        self._db = db
        self._clock = clock
        self._max_age_days = max_age_days
        self._max_rows = max_rows
        self._lock = threading.Lock()
        self._last_prune: float | None = None

    def record(
        self,
        conn: sqlite3.Connection,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        detail: Mapping[str, object] | None = None,
    ) -> int:
        return record(
            conn, actor_id, action, target_type, target_id, detail, now=int(self._clock())
        )

    def record_committed(
        self,
        actor_id: str,
        action: str,
        target_type: str,
        target_id: str,
        detail: Mapping[str, object] | None = None,
    ) -> int:
        """`record` in its own transaction, committed before this returns. For events that are
        not part of a bigger change (file events in a share). Retention runs after the commit.

        A file event also keeps the table under its row cap right here, in the same transaction:
        a friend with `write` access can create these rows as fast as they can send requests, so
        waiting for the daily prune would let them grow without bound. The oldest FILE events are
        evicted (at most WRITE_TRIM_BATCH per write, never the row just written); management
        events are never touched here."""
        with self._db.transaction() as conn:
            row_id = self.record(conn, actor_id, action, target_type, target_id, detail)
            if action in FILE_ACTIONS:
                excess = _row_count(conn) - self._max_rows
                if excess > 0:
                    _delete_oldest(
                        conn, min(excess, WRITE_TRIM_BATCH), FILE_ACTIONS, keep_id=row_id
                    )
        self.maybe_prune()
        return row_id

    def share_file_event(
        self,
        actor_id: str,
        share_id: str | None,
        action: str,
        detail: Mapping[str, object] | None = None,
        *,
        strict: bool,
    ) -> None:
        """Audit a file event inside a share; nothing for a private space (`share_id` None).

        strict=True is for destructive events, written BEFORE the action: a failure raises a
        generic 500 and the caller must not act. strict=False is for events written after the
        action succeeded: a failure is logged and the response is not turned into an error."""
        if share_id is None:
            return
        try:
            self.record_committed(actor_id, action, "share", share_id, detail)
        except Exception as exc:  # fail closed when strict, whatever went wrong
            log.error("audit_write_failed", extra=error_fields(exc))
            if strict:
                raise AppError(500, "internal_error", "Internal Server Error") from None

    def list_events(
        self,
        limit: int = DEFAULT_LIMIT,
        after_id: int | None = None,
        filters: AuditFilter | None = None,
    ) -> AuditPage:
        return list_events(self._db, limit, after_id, filters)

    def maybe_prune(self) -> int | None:
        """Prune unless it already ran in the last 24 hours (the first call always runs).
        Call it at startup and after a write transaction has committed, never inside one.
        Returns the number of rows deleted, or None when it did not run or failed. A failure is
        logged and never raised: retention must not break the request that triggered it."""
        now = self._clock()
        with self._lock:
            if self._last_prune is not None and now - self._last_prune < DAY_SECONDS:
                return None
            self._last_prune = now
        try:
            deleted = prune(self._db, int(now), self._max_age_days, self._max_rows)
        except sqlite3.Error as exc:
            log.warning("audit_prune_failed", extra=error_fields(exc))
            return None
        if deleted:
            log.info("audit_pruned", extra={"deleted_rows": deleted})
        return deleted
