"""Regression tests for the Phase 2 security/code review findings."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from argon2 import PasswordHasher
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv
from pydantic import ValidationError

from yournas.auth import throttle as throttle_module
from yournas.auth.passwords import (
    MAX_CONCURRENT_HASHES,
    PasswordPolicyError,
    PasswordService,
    validate_new_password,
)
from yournas.auth.service import AuthService
from yournas.auth.throttle import MAX_LOCK_SECONDS, LoginThrottle, Throttled
from yournas.core.config import Settings
from yournas.core.database import open_database
from yournas.core.errors import AppError
from yournas.main import JSON_BODY_LIMIT_BYTES


class _FailingCommitConnection:
    """Delegates to a real connection but fails the next COMMIT."""

    def __init__(self, real: sqlite3.Connection) -> None:
        self._real = real
        self.fail_commit = False

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if sql == "COMMIT" and self.fail_commit:
            self.fail_commit = False
            raise sqlite3.OperationalError("database or disk is full")
        return self._real.execute(sql, *args)

    def close(self) -> None:
        self._real.close()


def test_failed_commit_does_not_wedge_the_database(tmp_path: Path) -> None:
    db = open_database(tmp_path / "d")
    proxy = _FailingCommitConnection(db._conn)
    db._conn = proxy  # type: ignore[assignment]
    proxy.fail_commit = True
    with pytest.raises(sqlite3.OperationalError), db.transaction() as conn:
        conn.execute("INSERT INTO login_throttle (key, failures, updated_at) VALUES ('a', 1, 1)")
    # The next transaction must start (no "cannot start a transaction within a transaction").
    with db.transaction() as conn:
        conn.execute("INSERT INTO login_throttle (key, failures, updated_at) VALUES ('b', 1, 1)")
    with db.read() as conn:
        keys = [r["key"] for r in conn.execute("SELECT key FROM login_throttle")]
    assert keys == ["b"]  # the failed transaction left nothing behind


def test_database_uses_full_synchronous(tmp_path: Path) -> None:
    db = open_database(tmp_path / "d")
    with db.read() as conn:
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


# ---- request body limit --------------------------------------------------------------------


def test_oversized_declared_body_is_rejected_before_auth(auth_env: AuthEnv) -> None:
    r = auth_env.client().post(
        "/api/v1/auth/password",
        content=b"x" * (JSON_BODY_LIMIT_BYTES + 1),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "payload_too_large"
    assert r.headers["x-request-id"]


def test_oversized_chunked_body_is_rejected(auth_env: AuthEnv) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(8):
            yield b"x" * (JSON_BODY_LIMIT_BYTES // 2)

    r = auth_env.client().post(
        "/api/v1/auth/login", content=chunks(), headers={"content-type": "application/json"}
    )
    assert r.status_code == 413


def test_normal_login_still_works_under_the_limit(auth_env: AuthEnv) -> None:
    assert auth_env.login()


def test_health_is_not_body_limited(auth_env: AuthEnv) -> None:
    assert auth_env.client().get("/health").status_code != 413


# ---- throttle table cap and clock clamp ----------------------------------------------------


def test_throttle_table_is_capped(auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(throttle_module, "MAX_THROTTLE_ROWS", 20)
    throttle = LoginThrottle(auth_env.db, auth_env.clock)
    for i in range(50):
        throttle.begin(f"acct:fake{i}", None)
        auth_env.clock.advance(1)
    auth_env.clock.advance(120)  # let the periodic purge run
    throttle.begin("acct:trigger", None)
    with auth_env.db.read() as conn:
        count = conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0]
    assert count <= 21


def test_lock_after_clock_jump_is_clamped(auth_env: AuthEnv) -> None:
    throttle = LoginThrottle(auth_env.db, auth_env.clock)
    now = int(auth_env.clock())
    with auth_env.db.transaction() as conn:
        conn.execute(
            "INSERT INTO login_throttle (key, failures, locked_until, updated_at) "
            "VALUES ('acct:victim', 9, ?, ?)",
            (now + 10 * 24 * 3600, now),
        )
    with pytest.raises(Throttled) as excinfo:
        throttle.begin("acct:victim", None)
    assert excinfo.value.retry_after <= MAX_LOCK_SECONDS


# ---- hashing concurrency -------------------------------------------------------------------


class _CountingHasher:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    def hash(self, password: str) -> str:
        return "h"

    def verify(self, stored: str, password: str) -> bool:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.05)
        with self._lock:
            self.active -= 1
        return True


def test_concurrent_hashing_is_bounded() -> None:
    hasher = _CountingHasher()
    service = PasswordService(hasher)  # type: ignore[arg-type]
    threads = [threading.Thread(target=service.verify, args=("h", "p")) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert 1 <= hasher.peak <= MAX_CONCURRENT_HASHES


# ---- X-Forwarded-For -----------------------------------------------------------------------


def test_forwarded_for_uses_proxy_entry_of_last_header_line(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    r = env.client("127.0.0.1").post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "wrong-password-1"},
        headers=[
            ("x-forwarded-for", "9.9.9.9"),  # client-supplied line
            ("x-forwarded-for", "10.0.0.7"),  # line appended by the proxy
        ],
    )
    assert r.status_code == 401
    with env.db.read() as conn:
        keys = {row["key"] for row in conn.execute("SELECT key FROM login_throttle")}
    assert "ip:10.0.0.7" in keys
    assert "ip:9.9.9.9" not in keys


# ---- data_dir validation -------------------------------------------------------------------


def test_data_dir_must_be_absolute(storage_root: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(storage_root=storage_root, data_dir=Path("relative/dir"))


@pytest.mark.parametrize("exposed", ["users", "shared"])
def test_data_dir_must_not_be_inside_an_exposed_directory(storage_root: Path, exposed: str) -> None:
    with pytest.raises(ValidationError):
        Settings(storage_root=storage_root, data_dir=storage_root / exposed / "x")


def test_data_dir_outside_storage_root_is_allowed(storage_root: Path, tmp_path: Path) -> None:
    Settings(storage_root=storage_root, data_dir=tmp_path / "elsewhere")


# ---- rehash race and lockout counter -------------------------------------------------------


class _RehashRacePasswords(PasswordService):
    """Always wants a rehash, and swaps the stored hash while the new one is computed."""

    def __init__(self, db: Any, username: str) -> None:
        super().__init__(PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))
        self._db = db
        self._username = username
        self.race_armed = False

    def needs_rehash(self, stored_hash: str) -> bool:
        return True

    def hash(self, password: str) -> str:
        if self.race_armed:
            self.race_armed = False
            with self._db.transaction() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    ("concurrently-changed", self._username),
                )
        return super().hash(password)


def test_rehash_does_not_overwrite_a_concurrent_password_change(auth_env: AuthEnv) -> None:
    passwords = _RehashRacePasswords(auth_env.db, OWNER_NAME)
    with auth_env.db.transaction() as conn:  # a hash this PasswordService can verify
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (passwords.hash(OWNER_PASSWORD), OWNER_NAME),
        )
    service = AuthService(
        auth_env.db, passwords, idle_seconds=3600, lifetime_seconds=7200, clock=auth_env.clock
    )
    passwords.race_armed = True
    # The password changed while this login was hashing, so the login is refused (Phase 4 review).
    with pytest.raises(AppError) as excinfo:
        service.login(OWNER_NAME, OWNER_PASSWORD, None)
    assert excinfo.value.status_code == 401
    with auth_env.db.read() as conn:
        stored = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (OWNER_NAME,)
        ).fetchone()[0]
    assert stored == "concurrently-changed"


def test_failed_policy_check_does_not_clear_the_lockout_counter(auth_env: AuthEnv) -> None:
    auth = {"authorization": f"Bearer {auth_env.login()}"}
    client = auth_env.client()
    wrong = client.post(
        "/api/v1/auth/password",
        json={"current": "not-the-password", "new": "a-new-long-password"},
        headers=auth,
    )
    assert wrong.status_code == 403
    weak = client.post(
        "/api/v1/auth/password",
        json={"current": OWNER_PASSWORD, "new": "short"},
        headers=auth,
    )
    assert weak.status_code == 400
    with auth_env.db.read() as conn:
        row = conn.execute(
            "SELECT failures FROM login_throttle WHERE key = ?", ("acct:" + OWNER_NAME,)
        ).fetchone()
    assert row is not None and row[0] >= 1


@pytest.mark.parametrize(
    "weak", ["123456789012", "aaaaaaaaaaaa", "ababababab12", "PasswordPassword", "QWERTYUIOPAS"]
)
def test_easy_to_guess_passwords_are_rejected(weak: str) -> None:
    with pytest.raises(PasswordPolicyError):
        validate_new_password(weak)


def test_ordinary_passphrase_is_accepted() -> None:
    validate_new_password("correct horse battery")
