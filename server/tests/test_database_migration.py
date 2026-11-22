"""Forward migrations, tested against a database file that really has the old schema."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from yournas.core.database import DB_FILE_NAME, SCHEMA_VERSION, Database, DatabaseError

# A frozen copy of what Phase 2 created (schema version 1). Deliberately not imported from the
# code: if someone edits the shipped v1 script, this test still starts from the real old shape.
V1_SCHEMA = """
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN ('owner', 'user')),
    disabled            INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at          INTEGER NOT NULL,
    password_changed_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_single_owner ON users (role) WHERE role = 'owner';
CREATE TABLE sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE TABLE login_throttle (
    key          TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL,
    locked_until INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL
);
"""


def make_v1(path: Path) -> None:
    raw = sqlite3.connect(path)
    for statement in V1_SCHEMA.split(";"):
        if statement.strip():
            raw.execute(statement)
    raw.execute(
        "INSERT INTO users (id, username, password_hash, role, created_at, password_changed_at) "
        "VALUES ('u_1', 'alice', 'hash', 'owner', 1, 1)"
    )
    raw.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) "
        "VALUES ('t', 'u_1', 1, 1, 99)"
    )
    raw.execute("INSERT INTO login_throttle (key, failures, updated_at) VALUES ('acct:x', 2, 1)")
    raw.execute("PRAGMA user_version = 1")
    raw.commit()
    raw.close()


def tables(db: Database) -> set[str]:
    with db.read() as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {r["name"] for r in rows}


def test_current_schema_version_is_six() -> None:
    assert SCHEMA_VERSION == 6


def test_v1_database_is_migrated_and_keeps_its_data(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE_NAME
    make_v1(path)
    db = Database(path)
    assert db.schema_version == SCHEMA_VERSION
    assert "uploads" in tables(db)
    with db.read() as conn:
        assert conn.execute("SELECT username FROM users").fetchone()[0] == "alice"
        assert conn.execute("SELECT user_id FROM sessions").fetchone()[0] == "u_1"
        assert conn.execute("SELECT failures FROM login_throttle").fetchone()[0] == 2
    db.close()


def test_migrated_uploads_table_enforces_its_rules(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE_NAME
    make_v1(path)
    db = Database(path)
    insert = (
        "INSERT INTO uploads (id, user_id, space, rel_path, size, overwrite, created_at, "
        "updated_at) VALUES (?, ?, 'home', 'a.txt', ?, ?, 1, 1)"
    )
    with db.transaction() as conn:
        conn.execute(insert, ("a" * 32, "u_1", 10, 0))
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute(insert, ("b" * 32, "u_missing", 10, 0))  # unknown user
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute(insert, ("c" * 32, "u_1", -1, 0))  # negative size
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        conn.execute(insert, ("d" * 32, "u_1", 1, 2))  # overwrite is 0 or 1
    with db.transaction() as conn:
        conn.execute("DELETE FROM users WHERE id = 'u_1'")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM uploads").fetchone()[0] == 0  # cascade
    db.close()


def test_migration_is_idempotent_on_reopen(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE_NAME
    make_v1(path)
    Database(path).close()
    again = Database(path)
    assert again.schema_version == SCHEMA_VERSION
    with again.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    again.close()


def test_new_database_has_the_same_shape_as_a_migrated_one(tmp_path: Path) -> None:
    make_v1(tmp_path / "old.db")
    migrated = Database(tmp_path / "old.db")
    fresh = Database(tmp_path / "new.db")

    def shape(db: Database) -> list[tuple[str, str, str]]:
        with db.read() as conn:
            rows = conn.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY 1, 2"
            )
            # Whitespace differs between the original script and a migration; the DDL must not.
            return [(r["type"], r["name"], " ".join(str(r["sql"]).split())) for r in rows]

    assert shape(migrated) == shape(fresh)
    migrated.close()
    fresh.close()


def test_failed_migration_step_leaves_the_old_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yournas.core import database

    path = tmp_path / DB_FILE_NAME
    make_v1(path)
    monkeypatch.setitem(
        database._MIGRATIONS, 2, "CREATE TABLE uploads (id TEXT); CREATE TABLE uploads (id TEXT)"
    )
    with pytest.raises(DatabaseError):
        Database(path)
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 1
    assert (
        raw.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'uploads'").fetchone()[0] == 0
    )
    raw.close()


@pytest.mark.parametrize("version", [SCHEMA_VERSION + 1, 99])
def test_database_newer_than_the_server_is_still_refused(tmp_path: Path, version: int) -> None:
    path = tmp_path / DB_FILE_NAME
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {version}")
    raw.close()
    with pytest.raises(DatabaseError, match="newer"):
        Database(path)
