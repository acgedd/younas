"""A temporary password works for 7 days after it was issued, then it is dead.

The issue time is `users.password_changed_at` (set together with `must_change_password = 1` by
create_user and reset_password), so no schema change is needed. A permanent password never expires.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv, bearer

from yournas.core.database import SCHEMA_VERSION
from yournas.core.errors import AppError

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
PASSWORD = "/api/v1/auth/password"
NEW_PASSWORD = "a brand new passphrase 77"  # noqa: S105 - test credential
DAY = 86400
WEEK = 7 * DAY


def login(env: AuthEnv, name: str, password: str) -> httpx.Response:
    r: httpx.Response = env.client().post(LOGIN, json={"username": name, "password": password})
    return r


def code(r: httpx.Response) -> str:
    return str(r.json()["error"]["code"])


def owner_id(env: AuthEnv) -> str:
    with env.db.read() as conn:
        return str(conn.execute("SELECT id FROM users WHERE role = 'owner'").fetchone()[0])


def issue(env: AuthEnv, name: str = "alice") -> tuple[str, str]:
    """Create a user with a temporary password. Returns (user id, temporary password)."""
    user, temp = env.service.create_user(owner_id(env), name)
    return user.id, temp


def sessions_of(env: AuthEnv, user_id: str) -> int:
    with env.db.read() as conn:
        row = conn.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (user_id,))
        return int(row.fetchone()[0])


def hash_of(env: AuthEnv, user_id: str) -> str:
    with env.db.read() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        return str(row.fetchone()[0])


def change(env: AuthEnv, token: str, current: str, new: str) -> httpx.Response:
    r: httpx.Response = env.client(**bearer(token)).post(
        PASSWORD, json={"current": current, "new": new}
    )
    return r


# ---- the 7 day window ------------------------------------------------------------------------


def test_a_temporary_password_works_until_the_seven_day_mark(auth_env: AuthEnv) -> None:
    _, temp = issue(auth_env)
    auth_env.clock.advance(WEEK - 1)
    r = login(auth_env, "alice", temp)
    assert r.status_code == 200 and r.json()["must_change_password"] is True


def test_an_expired_temporary_password_gets_no_session(auth_env: AuthEnv) -> None:
    user_id, temp = issue(auth_env)
    before = hash_of(auth_env, user_id)
    auth_env.clock.advance(WEEK)  # exactly 7 days: dead, like a session at its expires_at
    r = login(auth_env, "alice", temp)
    assert r.status_code == 401 and code(r) == "temporary_password_expired"
    assert "token" not in r.json() and temp not in r.text
    assert "set-cookie" not in r.headers
    assert sessions_of(auth_env, user_id) == 0
    assert hash_of(auth_env, user_id) == before  # no rehash, nothing written


def test_an_expired_account_does_not_reveal_itself_to_a_wrong_password(
    auth_env: AuthEnv,
) -> None:
    issue(auth_env)
    auth_env.clock.advance(WEEK + DAY)
    wrong = login(auth_env, "alice", "not the password at all 1")
    unknown = login(auth_env, "nobody", "not the password at all 1")
    assert wrong.status_code == unknown.status_code == 401
    assert code(wrong) == code(unknown) == "invalid_credentials"


def test_the_expired_attempt_is_logged_without_the_password(
    auth_env: AuthEnv, caplog: pytest.LogCaptureFixture
) -> None:
    _, temp = issue(auth_env)
    auth_env.clock.advance(WEEK)
    caplog.set_level(logging.INFO)
    login(auth_env, "alice", temp)
    assert any(r.getMessage() == "login_failed" for r in caplog.records)
    assert temp not in caplog.text


def test_an_expired_account_still_counts_against_the_login_throttle(auth_env: AuthEnv) -> None:
    _, temp = issue(auth_env)
    auth_env.clock.advance(WEEK)
    codes = {login(auth_env, "alice", temp).status_code for _ in range(12)}
    assert codes == {401, 429}  # the lock still applies: expiry is not a free retry


# ---- sessions opened before the deadline -----------------------------------------------------


def test_a_pending_session_dies_with_its_temporary_password(auth_env: AuthEnv) -> None:
    _, temp = issue(auth_env)
    token = login(auth_env, "alice", temp).json()["token"]
    client = auth_env.client(**bearer(token))
    assert client.get(ME).status_code == 200
    auth_env.clock.advance(WEEK)
    assert client.get(ME).status_code == 401
    assert change(auth_env, token, temp, NEW_PASSWORD).status_code == 401


def test_change_password_itself_refuses_an_expired_temporary_password(auth_env: AuthEnv) -> None:
    """The service-level check, for a session the request layer had already accepted."""
    user_id, temp = issue(auth_env)
    token = login(auth_env, "alice", temp).json()["token"]
    ctx = auth_env.service.authenticate(token)
    assert ctx is not None
    before = hash_of(auth_env, user_id)
    auth_env.clock.advance(WEEK)
    with pytest.raises(AppError) as info:
        auth_env.service.change_password(ctx, temp, NEW_PASSWORD)
    assert info.value.status_code == 401
    assert hash_of(auth_env, user_id) == before


# ---- first-login change and permanent passwords ----------------------------------------------


def test_first_login_change_inside_the_window_makes_the_password_permanent(
    auth_env: AuthEnv,
) -> None:
    _, temp = issue(auth_env)
    auth_env.clock.advance(WEEK - DAY)  # day 6
    token = login(auth_env, "alice", temp).json()["token"]
    assert change(auth_env, token, temp, NEW_PASSWORD).status_code == 204
    auth_env.clock.advance(400 * DAY)
    again = login(auth_env, "alice", NEW_PASSWORD)
    assert again.status_code == 200 and again.json()["must_change_password"] is False


def test_ordinary_permanent_passwords_never_expire(auth_env: AuthEnv) -> None:
    auth_env.clock.advance(1000 * DAY)
    assert login(auth_env, OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_the_old_temporary_password_is_dead_after_the_change(auth_env: AuthEnv) -> None:
    _, temp = issue(auth_env)
    token = login(auth_env, "alice", temp).json()["token"]
    assert change(auth_env, token, temp, NEW_PASSWORD).status_code == 204
    r = login(auth_env, "alice", temp)
    assert r.status_code == 401 and code(r) == "invalid_credentials"


# ---- reset -----------------------------------------------------------------------------------


def test_a_reset_gives_an_expired_account_a_fresh_seven_days(auth_env: AuthEnv) -> None:
    user_id, old = issue(auth_env)
    auth_env.clock.advance(WEEK + DAY)
    assert code(login(auth_env, "alice", old)) == "temporary_password_expired"
    fresh = auth_env.service.reset_password(owner_id(auth_env), user_id)
    assert login(auth_env, "alice", fresh).status_code == 200
    assert code(login(auth_env, "alice", old)) == "invalid_credentials"  # the old one is gone
    auth_env.clock.advance(WEEK)  # and the new one expires on its own schedule
    assert code(login(auth_env, "alice", fresh)) == "temporary_password_expired"


def test_a_reset_of_an_account_with_a_permanent_password_starts_a_new_window(
    auth_env: AuthEnv,
) -> None:
    user_id, temp = issue(auth_env)
    token = login(auth_env, "alice", temp).json()["token"]
    assert change(auth_env, token, temp, NEW_PASSWORD).status_code == 204
    auth_env.clock.advance(300 * DAY)  # the permanent password is old; only the new one counts
    fresh = auth_env.service.reset_password(owner_id(auth_env), user_id)
    assert login(auth_env, "alice", fresh).status_code == 200
    auth_env.clock.advance(WEEK)
    assert code(login(auth_env, "alice", fresh)) == "temporary_password_expired"


def test_accounts_that_already_hold_an_old_temporary_password_are_expired_not_migrated(
    auth_env: AuthEnv,
) -> None:
    """No schema change: an account whose temporary password was issued more than 7 days ago
    (password_changed_at is that time) is simply expired at the first login after the upgrade;
    the owner resets it. Nothing is rewritten or guessed."""
    user_id, temp = issue(auth_env)
    with auth_env.db.transaction() as conn:
        conn.execute(
            "UPDATE users SET password_changed_at = ? WHERE id = ?",
            (int(auth_env.clock()) - 30 * DAY, user_id),
        )
    assert code(login(auth_env, "alice", temp)) == "temporary_password_expired"
    assert auth_env.db.schema_version == SCHEMA_VERSION
