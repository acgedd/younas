"""Regression tests for the Phase 4 step 5 security and reviewer findings."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import FRIEND_NAME, FRIEND_PASSWORD, AuthEnv, Session
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_admin_api import count
from test_file_authz import start_upload

from yournas.auth import throttle as throttle_module
from yournas.auth.throttle import LoginThrottle, Throttled
from yournas.core.errors import AppError
from yournas.core.logging_setup import (
    LOG_FILE_NAME,
    REDACTED,
    configure_logging,
    redact_text,
    shutdown_logging,
)

LOGIN = "/api/v1/auth/login"


# ---- log redaction must stay linear on a hostile URL path ------------------------------------


@pytest.mark.parametrize(
    "text",
    ["token-" * 10_000, "pwd" * 20_000, "pass-" * 12_000, "secret." * 9_000],
    ids=["token-dash", "pwd", "pass-dash", "secret-dot"],
)
def test_redaction_is_fast_on_one_long_word_full_of_keywords(text: str) -> None:
    start = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - start < 1.0  # was several seconds (quadratic backtracking)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("x" * 200 + "password=LONGKEYSECRET", "LONGKEYSECRET"),
        ("user_password=PLAINSECRET", "PLAINSECRET"),
        ("passwordHash=HASHSECRET", "HASHSECRET"),
        ('{"api_key": "KEYSECRET"}', "KEYSECRET"),
    ],
    ids=["long-key-prefix", "prefixed-key", "camel-case-key", "json-key"],
)
def test_redaction_still_hides_values_of_sensitive_keys(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out and REDACTED in out


# ---- a login in flight must not survive a change made while it verified ----------------------


def _after_verify(env: AuthEnv, monkeypatch: pytest.MonkeyPatch, action: Callable[[], Any]) -> None:
    """Run `action` once, right after the next password check (the unlocked window of login)."""
    passwords = env.service._passwords
    real_verify = passwords.verify
    fired: list[bool] = []

    def verify(stored: str, password: str) -> bool:
        ok = real_verify(stored, password)
        if not fired:
            fired.append(True)
            action()
        return ok

    monkeypatch.setattr(passwords, "verify", verify)


def _live_sessions(env: AuthEnv, user_id: str) -> int:
    with env.db.read() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL", (user_id,)
        ).fetchone()
    return int(row[0])


def _owner_id(env: AuthEnv) -> str:
    with env.db.read() as conn:
        return str(conn.execute("SELECT id FROM users WHERE role = 'owner'").fetchone()[0])


def test_a_login_in_flight_during_disable_gets_no_session(
    auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = auth_env.add_user(FRIEND_NAME, FRIEND_PASSWORD)
    owner_id = _owner_id(auth_env)
    _after_verify(auth_env, monkeypatch, lambda: auth_env.service.set_disabled(owner_id, uid, True))
    with pytest.raises(AppError) as excinfo:
        auth_env.service.login(FRIEND_NAME, FRIEND_PASSWORD, None)
    assert excinfo.value.status_code == 401
    assert _live_sessions(auth_env, uid) == 0


def test_a_login_in_flight_during_password_reset_gets_no_session(
    auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = auth_env.add_user(FRIEND_NAME, FRIEND_PASSWORD)
    owner_id = _owner_id(auth_env)
    _after_verify(auth_env, monkeypatch, lambda: auth_env.service.reset_password(owner_id, uid))
    with pytest.raises(AppError) as excinfo:
        auth_env.service.login(FRIEND_NAME, FRIEND_PASSWORD, None)
    assert excinfo.value.status_code == 401
    assert _live_sessions(auth_env, uid) == 0


def test_a_login_in_flight_during_password_change_gets_no_session(
    auth_env: AuthEnv, friend: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = auth_env.service.authenticate(friend.token)
    assert ctx is not None
    new_password = "a different long passphrase 7"  # noqa: S105 - test credential
    _after_verify(
        auth_env,
        monkeypatch,
        lambda: auth_env.service.change_password(ctx, FRIEND_PASSWORD, new_password),
    )
    with pytest.raises(AppError) as excinfo:
        auth_env.service.login(FRIEND_NAME, FRIEND_PASSWORD, None)  # the OLD password
    assert excinfo.value.status_code == 401
    assert _live_sessions(auth_env, friend.user_id) == 1  # only the session that changed it


def test_a_normal_login_still_works_after_the_check(auth_env: AuthEnv) -> None:
    uid = auth_env.add_user(FRIEND_NAME, FRIEND_PASSWORD)
    result = auth_env.service.login(FRIEND_NAME, FRIEND_PASSWORD, None)
    assert result.token and _live_sessions(auth_env, uid) == 1


# ---- the throttle row cap must not evict a locked account ------------------------------------


def test_throttle_cap_evicts_unlocked_rows_before_a_locked_account(
    auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(throttle_module, "MAX_THROTTLE_ROWS", 20)
    throttle = LoginThrottle(auth_env.db, auth_env.clock)
    now = int(auth_env.clock())
    with auth_env.db.transaction() as conn:  # the oldest row, and locked for 15 minutes
        conn.execute(
            "INSERT INTO login_throttle (key, failures, locked_until, updated_at) "
            "VALUES ('acct:victim', 9, ?, ?)",
            (now + 900, now),
        )
    for i in range(50):  # attacker-chosen unknown usernames
        auth_env.clock.advance(1)
        throttle.begin(f"acct:fake{i}", None)
    auth_env.clock.advance(120)  # let the periodic purge run
    throttle.begin("acct:trigger", None)
    with pytest.raises(Throttled):  # the lock survived the purge
        throttle.begin("acct:victim", None)
    with auth_env.db.read() as conn:
        rows = conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0]
    assert rows <= 22


# ---- an upload whose destination can never be written is refused at creation -----------------


def test_upload_with_a_too_long_destination_is_refused_when_created(friend: Session) -> None:
    home = str(friend.home.resolve())
    name_length = 245 - len(home)  # the resolved path reaches MAX_REAL_PATH (240)
    if not 1 <= name_length <= 200:
        pytest.skip("temporary directory depth does not allow this scenario")
    r = start_upload(friend, "home", "n" * name_length, 10)
    assert r.status_code == 400, r.text
    assert r.json()["error"]["code"] == "invalid_path"
    assert count(friend.env, "uploads") == 0
    assert not list((friend.env.storage_root / ".yournas-tmp").iterdir())


# ---- IPv4-mapped IPv6 forwarded addresses share the bucket of the plain IPv4 address ---------


def test_ipv4_mapped_forwarded_address_uses_the_ipv4_bucket(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    r = env.client("127.0.0.1", **{"X-Forwarded-For": "::ffff:203.0.113.9"}).post(
        LOGIN, json={"username": "nobody", "password": "wrong-password-1"}
    )
    assert r.status_code == 401
    with env.db.read() as conn:
        keys = {row["key"] for row in conn.execute("SELECT key FROM login_throttle")}
    assert "ip:203.0.113.9" in keys
    assert not any("ffff" in k for k in keys)


# ---- the log of an unexpected error carries no exception message -----------------------------


def test_unhandled_error_log_has_no_exception_message_or_path(
    make_app: Callable[..., FastAPI], tmp_path: Path
) -> None:
    app = make_app()
    message = r"cannot open C:\StorageRoot\users\u_1\private-diary.txt"  # not in the raise line

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError(message)

    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/boom")
    shutdown_logging()
    assert response.status_code == 500
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "private-diary" not in text and "StorageRoot" not in text
    records = [json.loads(line) for line in text.splitlines()]
    entry = next(r for r in records if r["message"] == "unhandled_error")
    assert entry["error_type"] == "RuntimeError"
    assert "boom" in entry["frames"]  # the stack stays useful for debugging
