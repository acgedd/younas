"""SQLite access: one connection, serialized by a lock, explicit transactions, versioned schema."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

SCHEMA_VERSION = 6
DB_FILE_NAME = "yournas.db"

_SCHEMA_V1 = """
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('owner', 'user')),
    disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at          INTEGER NOT NULL,
    password_changed_at INTEGER NOT NULL
);
-- At most one owner. Phase 2 has no way to create a second one.
CREATE UNIQUE INDEX users_single_owner ON users (role) WHERE role = 'owner';

-- Only the SHA-256 of the token is stored. The token itself is shown once at login.
CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Login throttling. `key` is "acct:<username>" (exists or not) or "ip:<address>".
-- Persisted so a restart does not reset the counters.
CREATE TABLE login_throttle (
    key          TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);
"""


# Resumable uploads (Phase 3). The bytes live in the staging file, whose size is the offset, so
# the row stores no offset that could drift. updated_at is the last time a chunk arrived.
_SCHEMA_V2 = """
CREATE TABLE uploads (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    space      TEXT NOT NULL,
    rel_path   TEXT NOT NULL,
    size       INTEGER NOT NULL CHECK (size >= 0),
    overwrite  INTEGER NOT NULL DEFAULT 0 CHECK (overwrite IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX uploads_user ON uploads (user_id);
CREATE INDEX uploads_updated ON uploads (updated_at);
"""

# Shares, grants, audit log and the forced password change (Phase 4). A share id is "s_" plus 16
# hex digits and is never reused. Share names are display-only and unique ignoring case. grants has
# no row for "no access". audit_log has no foreign keys on purpose, so its rows outlive the users
# and shares they mention. No semicolons inside the comments or strings of this script (it is
# split on them).
_SCHEMA_V3 = """
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0
    CHECK (must_change_password IN (0, 1));

CREATE TABLE shares (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE grants (
    share_id   TEXT NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    level      TEXT NOT NULL CHECK (level IN ('read', 'write')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (share_id, user_id)
);
CREATE INDEX grants_user ON grants (user_id);

CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX audit_at ON audit_log (at);
"""

# Photo thumbnails (Phase B step 1, docs/THUMBNAILS-SPEC.md). The bytes are files under
# <data_dir>/thumbs, never in this database. scope comes from the authorization decision, path_key
# is the real path inside the space as spelled on disk (not casefolded: NTFS keeps names apart that
# casefold() merges), and the file_ columns are the version of the source file the thumbnail was
# made from. No foreign keys, like audit_log: a row says nothing about access, which is decided
# per request.
_SCHEMA_V4 = """
CREATE TABLE thumbnails (
    scope         TEXT NOT NULL,
    path_key      TEXT NOT NULL,
    file_ino      TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    file_mtime_ns INTEGER NOT NULL,
    byte_len      INTEGER NOT NULL CHECK (byte_len > 0),
    set_by        TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (scope, path_key)
) WITHOUT ROWID;
"""

# Photos by month (Phase B step 2, docs/MONTHS-SPEC.md). One row per photo-named file of a space
# that the background job looked at. kind 'other' is a file whose content is not a photo, kept so it
# is not opened again. sort_at is wall-clock seconds (the recorded date taken, or the file time in
# the configured offset) and month is its 'YYYY-MM'. Only numbers derived on the server are stored,
# never a string read from a file. Same scope and path_key as thumbnails, so the two join. Rollback
# in place (roll back v6 first): DROP TABLE photo_index, then PRAGMA user_version = 4.
# photo_index_month covers what GET .../photos/months reads (GROUP BY month with COUNT and
# SUM(file_size), and the version columns the cover matches against thumbnails) without a table
# row, and is in the order of the month pages and the cover lookup (sort_at newest first, then
# path_key), so neither sorts the month.
_SCHEMA_V5 = """
CREATE TABLE photo_index (
    scope         TEXT NOT NULL,
    path_key      TEXT NOT NULL,
    file_size     INTEGER NOT NULL,
    file_mtime_ns INTEGER NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('photo', 'other')),
    source        TEXT CHECK (source IN ('exif', 'mtime')),
    month         TEXT,
    sort_at       INTEGER,
    parser        INTEGER NOT NULL,
    indexed_at    INTEGER NOT NULL,
    CHECK ((kind = 'photo') = (source IS NOT NULL AND month IS NOT NULL AND sort_at IS NOT NULL)),
    PRIMARY KEY (scope, path_key)
) WITHOUT ROWID;
CREATE INDEX photo_index_month
    ON photo_index (scope, month, sort_at DESC, path_key, file_size, file_mtime_ns);
"""

# Month covers (Phase B step 2b, docs/COVERS-SPEC.md). The cover a space chose for a month: one
# row per (scope, month). scope comes from the authorization decision, never from the space
# parameter, and path_key is copied from the photo_index row it was matched to (exact key). No user
# id and no timestamp. A row is only a choice: GET .../photos/months uses it only while photo_index
# still has a photo of that scope, key and month with a current thumbnail. Rollback in place (a
# destructive migration, confirmed by the owner as a separate step): DROP TABLE month_covers, then
# PRAGMA user_version = 5.
_SCHEMA_V6 = """
CREATE TABLE month_covers (
    scope    TEXT NOT NULL,
    month    TEXT NOT NULL,
    path_key TEXT NOT NULL,
    PRIMARY KEY (scope, month)
) WITHOUT ROWID;
"""

# Forward migrations: _MIGRATIONS[n] takes a database at version n-1 to version n. A new database
# runs all of them in order, so there is exactly one path to the current schema.
_MIGRATIONS: dict[int, str] = {
    1: _SCHEMA_V1,
    2: _SCHEMA_V2,
    3: _SCHEMA_V3,
    4: _SCHEMA_V4,
    5: _SCHEMA_V5,
    6: _SCHEMA_V6,
}
assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))


class DatabaseError(Exception):
    """The database cannot be opened or has an unsupported schema."""


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(
                self.path,
                isolation_level=None,  # autocommit; transactions are explicit
                check_same_thread=False,
                timeout=10,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            # FULL: a power loss must not bring back a revoked session or an old password.
            self._conn.execute("PRAGMA synchronous = FULL")
            self._migrate()
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database: {exc}") from None

    def _migrate(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise DatabaseError(
                f"database schema {version} is newer than this server supports ({SCHEMA_VERSION})"
            )
        for target in range(version + 1, SCHEMA_VERSION + 1):
            # executescript would commit implicitly; run the statements in one transaction, so a
            # failed step leaves the previous version intact.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in _MIGRATIONS[target].split(";"):
                    if statement.strip():
                        self._conn.execute(statement)
                self._conn.execute(f"PRAGMA user_version = {target}")
                self._conn.execute("COMMIT")
            except sqlite3.Error:
                self._conn.execute("ROLLBACK")
                raise

    @property
    def schema_version(self) -> int:
        with self.read() as conn:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            yield self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Write transaction. Commits on success, rolls back on any exception."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                try:
                    self._conn.execute("COMMIT")
                except BaseException:
                    # A failed COMMIT leaves the transaction open; without this every later
                    # BEGIN would fail and the server would stay broken until restart.
                    with suppress(sqlite3.Error):
                        self._conn.execute("ROLLBACK")
                    raise

    def check(self) -> bool:
        try:
            with self.read() as conn:
                return bool(conn.execute("PRAGMA quick_check").fetchone()[0] == "ok")
        except sqlite3.Error:
            return False

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def open_database(data_dir: Path) -> Database:
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DatabaseError(f"cannot create data directory: {exc.strerror}") from None
    return Database(data_dir / DB_FILE_NAME)
