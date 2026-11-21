from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from yournas.core.database import (
    DB_FILE_NAME,
    SCHEMA_VERSION,
    Database,
    DatabaseError,
    open_database,
)


def _insert_user(conn: sqlite3.Connection, user_id: str, name: str, role: str = "user") -> None:
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role, created_at, password_changed_at) "
        "VALUES (?, ?, 'h', ?, 1, 1)",
        (user_id, name, role),
    )


def test_open_creates_schema_and_is_idempotent(tmp_path: Path) -> None:
    db = open_database(tmp_path / "d")
    assert db.schema_version == SCHEMA_VERSION
    assert db.check()
    db.close()
    again = open_database(tmp_path / "d")  # reopening must not try to recreate tables
    assert again.schema_version == SCHEMA_VERSION
    again.close()


def test_wal_and_foreign_keys_are_on(tmp_path: Path) -> None:
    db = open_database(tmp_path)
    with db.read() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    db.close()


def test_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE_NAME
    raw = sqlite3.connect(path)
    raw.execute("PRAGMA user_version = 99")
    raw.close()
    with pytest.raises(DatabaseError, match="newer"):
        Database(path)


def test_unwritable_data_dir_is_a_database_error(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(DatabaseError):
        open_database(blocker / "sub")


def test_corrupt_file_is_a_database_error(tmp_path: Path) -> None:
    (tmp_path / DB_FILE_NAME).write_bytes(b"this is not a sqlite database" * 20)
    with pytest.raises(DatabaseError):
        Database(tmp_path / DB_FILE_NAME)


def test_transaction_rolls_back_on_error(tmp_path: Path) -> None:
    db = open_database(tmp_path)
    with pytest.raises(RuntimeError), db.transaction() as conn:
        _insert_user(conn, "u_1", "alice")
        raise RuntimeError("boom")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    db.close()


def test_only_one_owner_is_possible(tmp_path: Path) -> None:
    db = open_database(tmp_path)
    with db.transaction() as conn:
        _insert_user(conn, "u_1", "alice", "owner")
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        _insert_user(conn, "u_2", "bob", "owner")
    with db.transaction() as conn:
        _insert_user(conn, "u_3", "carol", "user")
        _insert_user(conn, "u_4", "dave", "user")
    db.close()


def test_usernames_are_unique_and_role_is_constrained(tmp_path: Path) -> None:
    db = open_database(tmp_path)
    with db.transaction() as conn:
        _insert_user(conn, "u_1", "alice")
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        _insert_user(conn, "u_2", "alice")
    with pytest.raises(sqlite3.IntegrityError), db.transaction() as conn:
        _insert_user(conn, "u_3", "eve", "admin")
    db.close()


def test_sessions_are_deleted_with_their_user(tmp_path: Path) -> None:
    db = open_database(tmp_path)
    with db.transaction() as conn:
        _insert_user(conn, "u_1", "alice")
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) "
            "VALUES ('t', 'u_1', 1, 1, 2)"
        )
        conn.execute("DELETE FROM users WHERE id = 'u_1'")
    with db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    db.close()
