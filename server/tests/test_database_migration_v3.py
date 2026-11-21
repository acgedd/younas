"""Schema v3 (shares, grants, audit log, forced password change), tested against a database file
that really has the v2 shape."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from yournas.core.database import DB_FILE_NAME, SCHEMA_VERSION, Database, DatabaseError

# A frozen copy of what Phase 3 created (schema version 2). Deliberately not imported from the
# code: if someone edits the shipped scripts, this test still starts from the real old shape.
V2_SCHEMA = """
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

SHARE_A = "s_" + "a" * 16
SHARE_B = "s_" + "b" * 16


def make_v2(path: Path) -> None:
    raw = sqlite3.connect(path)
    for statement in V2_SCHEMA.split(";"):
        if statement.strip():
            raw.execute(statement)
    raw.execute(
        "INSERT INTO users (id, username, password_hash, role, disabled, created_at, "
        "password_changed_at) VALUES ('u_owner', 'owner', 'h1', 'owner', 0, 1, 1)"
    )
    raw.execute(
        "INSERT INTO users (id, username, password_hash, role, disabled, created_at, "
        "password_changed_at) VALUES ('u_friend', 'friend', 'h2', 'user', 1, 2, 3)"
    )
    raw.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) "
        "VALUES ('tok', 'u_friend', 1, 1, 99)"
    )
    raw.execute("INSERT INTO login_throttle (key, failures, updated_at) VALUES ('acct:x', 2, 1)")
    raw.execute(
        "INSERT INTO uploads (id, user_id, space, rel_path, size, overwrite, created_at, "
        "updated_at) VALUES ('u1', 'u_friend', 'home', 'a/b.txt', 42, 1, 5, 6)"
    )
    raw.execute("PRAGMA user_version = 2")
    raw.commit()
    raw.close()


@pytest.fixture
def migrated(tmp_path: Path) -> Database:
    path = tmp_path / DB_FILE_NAME
    make_v2(path)
    db = Database(path)
    assert db.schema_version == 3
    return db


def test_v2_database_is_migrated_and_keeps_all_its_data(migrated: Database) -> None:
    with migrated.read() as conn:
        users = {r["id"]: r for r in conn.execute("SELECT * FROM users")}
        assert set(users) == {"u_owner", "u_friend"}
        assert users["u_friend"]["username"] == "friend"
        assert users["u_friend"]["password_hash"] == "h2"
        assert users["u_friend"]["role"] == "user"
        assert users["u_friend"]["disabled"] == 1
        assert users["u_friend"]["created_at"] == 2
        assert users["u_friend"]["password_changed_at"] == 3
        assert users["u_owner"]["role"] == "owner"
        # the new column defaults to "no forced change" for every existing account
        assert [r["must_change_password"] for r in users.values()] == [0, 0]
        session = conn.execute("SELECT * FROM sessions").fetchone()
        assert (session["token_hash"], session["user_id"], session["expires_at"]) == (
            "tok",
            "u_friend",
            99,
        )
        assert conn.execute("SELECT failures FROM login_throttle").fetchone()[0] == 2
        upload = conn.execute("SELECT * FROM uploads").fetchone()
        assert (upload["id"], upload["user_id"], upload["space"], upload["rel_path"]) == (
            "u1",
            "u_friend",
            "home",
            "a/b.txt",
        )
        assert (upload["size"], upload["overwrite"], upload["created_at"]) == (42, 1, 5)
        assert conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 0
    migrated.close()


def test_reopening_a_migrated_database_changes_nothing(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE_NAME
    make_v2(path)
    Database(path).close()
    again = Database(path)
    assert again.schema_version == SCHEMA_VERSION
    with again.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM uploads").fetchone()[0] == 1
    again.close()


def test_a_failed_v3_step_leaves_a_v2_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yournas.core import database

    path = tmp_path / DB_FILE_NAME
    make_v2(path)
    # The first statement succeeds, the second fails: nothing of the step may remain.
    monkeypatch.setitem(
        database._MIGRATIONS,
        3,
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0; "
        "CREATE TABLE shares (id TEXT); CREATE TABLE shares (id TEXT)",
    )
    with pytest.raises(DatabaseError):
        Database(path)
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 2
    columns = {r[1] for r in raw.execute("PRAGMA table_info(users)")}
    assert "must_change_password" not in columns
    assert (
        raw.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = 'shares'").fetchone()[0] == 0
    )
    assert raw.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    raw.close()
    # and the next start with the real script works
    monkeypatch.undo()
    assert Database(path).schema_version == 3


@pytest.mark.parametrize("version", [SCHEMA_VERSION + 1, 99])
def test_a_newer_database_is_still_refused(tmp_path: Path, version: int) -> None:
    path = tmp_path / DB_FILE_NAME
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {version}")
    raw.close()
    with pytest.raises(DatabaseError, match="newer"):
        Database(path)


def _add_share(db: Database, share_id: str, name: str) -> None:
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO shares (id, name, created_at, created_by) VALUES (?, ?, 1, 'u_owner')",
            (share_id, name),
        )


def _grant(db: Database, share_id: str, user_id: str, level: str) -> None:
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO grants (share_id, user_id, level, created_at) VALUES (?, ?, ?, 1)",
            (share_id, user_id, level),
        )


def _count(db: Database, table: str) -> int:
    with db.read() as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_deleting_a_share_removes_its_grants_only(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    _add_share(migrated, SHARE_B, "Docs")
    _grant(migrated, SHARE_A, "u_friend", "read")
    _grant(migrated, SHARE_B, "u_friend", "write")
    with migrated.transaction() as conn:
        conn.execute("DELETE FROM shares WHERE id = ?", (SHARE_A,))
    with migrated.read() as conn:
        rows = conn.execute("SELECT share_id, user_id FROM grants").fetchall()
    assert [(r["share_id"], r["user_id"]) for r in rows] == [(SHARE_B, "u_friend")]
    assert _count(migrated, "users") == 2
    migrated.close()


def test_deleting_a_user_removes_their_grants_only(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    _grant(migrated, SHARE_A, "u_friend", "read")
    _grant(migrated, SHARE_A, "u_owner", "write")
    with migrated.transaction() as conn:
        conn.execute("DELETE FROM users WHERE id = 'u_friend'")
    with migrated.read() as conn:
        rows = conn.execute("SELECT user_id FROM grants").fetchall()
    assert [r["user_id"] for r in rows] == ["u_owner"]
    assert _count(migrated, "shares") == 1
    migrated.close()


def test_a_grant_needs_an_existing_share_and_user(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    with pytest.raises(sqlite3.IntegrityError):
        _grant(migrated, SHARE_B, "u_friend", "read")  # unknown share
    with pytest.raises(sqlite3.IntegrityError):
        _grant(migrated, SHARE_A, "u_nobody", "read")  # unknown user
    migrated.close()


def test_share_names_are_unique_ignoring_case(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    with pytest.raises(sqlite3.IntegrityError):
        _add_share(migrated, SHARE_B, "pHOTOS")
    with pytest.raises(sqlite3.IntegrityError):
        _add_share(migrated, SHARE_A, "Other")  # duplicate id
    _add_share(migrated, SHARE_B, "Photos 2")
    assert _count(migrated, "shares") == 2
    migrated.close()


@pytest.mark.parametrize("level", ["none", "admin", "READ", "", "owner"])
def test_grant_level_is_read_or_write(migrated: Database, level: str) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    with pytest.raises(sqlite3.IntegrityError):
        _grant(migrated, SHARE_A, "u_friend", level)
    _grant(migrated, SHARE_A, "u_friend", "read")
    migrated.close()


def test_a_user_has_one_grant_per_share(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    _grant(migrated, SHARE_A, "u_friend", "read")
    with pytest.raises(sqlite3.IntegrityError):
        _grant(migrated, SHARE_A, "u_friend", "write")
    migrated.close()


def test_must_change_password_is_a_flag(migrated: Database) -> None:
    with migrated.transaction() as conn:
        conn.execute("UPDATE users SET must_change_password = 1 WHERE id = 'u_friend'")
    with pytest.raises(sqlite3.IntegrityError), migrated.transaction() as conn:
        conn.execute("UPDATE users SET must_change_password = 2 WHERE id = 'u_friend'")
    migrated.close()


def test_audit_rows_outlive_the_users_and_shares_they_mention(migrated: Database) -> None:
    _add_share(migrated, SHARE_A, "Photos")
    with migrated.transaction() as conn:
        conn.execute(
            "INSERT INTO audit_log (at, actor_id, action, target_type, target_id) "
            "VALUES (1, 'u_ghost', 'share_created', 'share', ?)",
            (SHARE_A,),  # no foreign keys: the actor need not exist
        )
        conn.execute("DELETE FROM shares WHERE id = ?", (SHARE_A,))
        conn.execute("DELETE FROM users WHERE id = 'u_friend'")
    assert _count(migrated, "audit_log") == 1
    with migrated.read() as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM audit_log")]
    assert ids == [1]
    migrated.close()


def test_new_database_has_the_same_shape_as_a_migrated_v2_one(tmp_path: Path) -> None:
    make_v2(tmp_path / "old.db")
    migrated = Database(tmp_path / "old.db")
    fresh = Database(tmp_path / "new.db")

    def shape(db: Database) -> list[tuple[str, str, str]]:
        with db.read() as conn:
            rows = conn.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY 1, 2"
            )
            return [(r["type"], r["name"], " ".join(str(r["sql"]).split())) for r in rows]

    assert shape(migrated) == shape(fresh)
    names = {name for _type, name, _sql in shape(fresh)}
    assert {"shares", "grants", "audit_log", "grants_user", "audit_at"} <= names
    migrated.close()
    fresh.close()
