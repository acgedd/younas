from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime

import httpx
import pytest
from argon2 import PasswordHasher
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv, routes_of

from yournas.auth.passwords import PasswordService
from yournas.auth.service import MAX_SESSIONS_PER_USER, AuthService

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
LOGOUT = "/api/v1/auth/logout"
PASSWORD = "/api/v1/auth/password"
STATUS = "/api/v1/admin/status"
PUBLIC = {("GET", "/health"), ("POST", LOGIN)}
FRIEND = "friend"
FRIEND_PASSWORD = "friendly passphrase 42"  # noqa: S105 - test credential
CHEAP = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def error_code(response: httpx.Response) -> str:
    return str(response.json()["error"]["code"])


def error_without_request_id(response: httpx.Response) -> dict[str, str]:
    error: dict[str, str] = dict(response.json()["error"])
    error.pop("request_id")
    return error


# ---- login ---------------------------------------------------------------------------------


def test_login_success_returns_token_user_and_expiry(auth_env: AuthEnv) -> None:
    r = auth_env.client().post(LOGIN, json={"username": OWNER_NAME, "password": OWNER_PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert len(body["token"]) >= 43  # 256 bits, base64url
    assert body["user"]["username"] == OWNER_NAME and body["user"]["role"] == "owner"
    assert set(body["user"]) == {"id", "username", "role"}
    assert body["user"]["id"].startswith("u_")
    expires = datetime.fromisoformat(body["expires_at"])
    assert expires.tzinfo is not None
    assert expires == datetime.fromtimestamp(auth_env.clock() + 30 * 86400, UTC)
    assert r.headers["cache-control"] == "no-store"


def test_username_is_case_insensitive(auth_env: AuthEnv) -> None:
    r = auth_env.client().post(LOGIN, json={"username": "OWNER", "password": OWNER_PASSWORD})
    assert r.status_code == 200


def test_token_is_stored_only_as_a_hash(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    with auth_env.db.read() as conn:
        sessions = conn.execute("SELECT * FROM sessions").fetchall()
        users = conn.execute("SELECT * FROM users").fetchall()
    assert len(sessions) == 1
    assert sessions[0]["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    for row in [*sessions, *users]:
        values = [str(v) for v in tuple(row)]
        assert token not in values and OWNER_PASSWORD not in values
    assert users[0]["password_hash"].startswith("$argon2id$")


def test_wrong_password_and_unknown_user_look_identical(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    wrong = client.post(LOGIN, json={"username": OWNER_NAME, "password": "wrong wrong wrong"})
    unknown = client.post(LOGIN, json={"username": "nobody", "password": "wrong wrong wrong"})
    assert wrong.status_code == unknown.status_code == 401
    assert error_without_request_id(wrong) == error_without_request_id(unknown)
    assert error_code(wrong) == "invalid_credentials"
    assert "token" not in wrong.text


def test_disabled_user_cannot_log_in_with_the_right_password(auth_env: AuthEnv) -> None:
    auth_env.add_user(FRIEND, FRIEND_PASSWORD, disabled=True)
    r = auth_env.client().post(LOGIN, json={"username": FRIEND, "password": FRIEND_PASSWORD})
    assert r.status_code == 401 and error_code(r) == "invalid_credentials"


def test_unknown_user_still_costs_a_password_verification(
    auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(auth_env.service._passwords, "verify_dummy", calls.append)
    auth_env.client().post(LOGIN, json={"username": "nobody", "password": "whatever it is"})
    assert calls == ["whatever it is"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"username": OWNER_NAME},
        {"password": OWNER_PASSWORD},
        {"username": "", "password": "x"},
        {"username": OWNER_NAME, "password": ""},
        {"username": "u" * 65, "password": "x"},
        {"username": OWNER_NAME, "password": "p" * 129},
        {"username": OWNER_NAME, "password": OWNER_PASSWORD, "role": "owner"},
        {"username": 1, "password": OWNER_PASSWORD},
        {"username": ["owner"], "password": OWNER_PASSWORD},
    ],
    ids=[
        "empty",
        "no-password",
        "no-username",
        "empty-username",
        "empty-password",
        "long-username",
        "long-password",
        "extra-field",
        "int-username",
        "list-username",
    ],
)
def test_malformed_login_is_a_generic_400(auth_env: AuthEnv, payload: dict[str, object]) -> None:
    r = auth_env.client().post(LOGIN, json=payload)
    assert r.status_code == 400 and error_code(r) == "invalid_request"
    assert OWNER_PASSWORD not in r.text


def test_non_json_login_body_is_400(auth_env: AuthEnv) -> None:
    r = auth_env.client().post(LOGIN, content=b"not json", headers={"content-type": "text/plain"})
    assert r.status_code == 400


def test_login_rehashes_when_parameters_were_raised(auth_env: AuthEnv) -> None:
    stronger_hasher = PasswordHasher(time_cost=2, memory_cost=8, parallelism=1)
    stronger = AuthService(
        auth_env.db,
        PasswordService(stronger_hasher),
        idle_seconds=3600,
        lifetime_seconds=86400,
        clock=auth_env.clock,
    )
    with auth_env.db.read() as conn:
        before = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    stronger.login(OWNER_NAME, OWNER_PASSWORD, None)
    with auth_env.db.read() as conn:
        after = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert "t=1" in before and "t=2" in after
    assert PasswordService(stronger_hasher).verify(after, OWNER_PASSWORD)


# ---- authentication on every route ---------------------------------------------------------


def test_every_route_except_the_public_ones_requires_authentication(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    protected = routes_of(auth_env.app) - PUBLIC
    assert len(protected) >= 4  # logout, me, password, admin status: never vacuous
    for method, path in sorted(protected):
        r = client.request(method, path)
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"
        assert r.headers["www-authenticate"] == "Bearer"


def test_health_stays_public_and_minimal(auth_env: AuthEnv) -> None:
    r = auth_env.client().get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Basic b3duZXI6cGFzcw==",
        "Token abc",
        "abc",
        "Bearer not-a-real-token",
        "Bearer " + "a" * 500,
        "Bearer a b",
    ],
    ids=["empty", "no-token", "blank", "basic", "token-scheme", "bare", "bogus", "huge", "two"],
)
def test_bad_authorization_headers_are_401(auth_env: AuthEnv, header: str) -> None:
    r = auth_env.client().get(ME, headers={"Authorization": header})
    assert r.status_code == 401 and error_code(r) == "unauthorized"


def test_bearer_scheme_is_case_insensitive(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    r = auth_env.client().get(ME, headers={"Authorization": f"bearer {token}"})
    assert r.status_code == 200


def test_me_returns_the_caller_and_no_secrets(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    r = auth_env.client().get(ME, headers=bearer(token))
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == OWNER_NAME and body["role"] == "owner"
    assert body["spaces"] == [{"id": "home", "name": "My files", "access": "write"}]
    assert body["must_change_password"] is False
    # The flag's name contains "password", so look for secrets in the other fields.
    secrets_view = {k: v for k, v in body.items() if k != "must_change_password"}
    assert "password" not in str(secrets_view) and "hash" not in r.text and token not in r.text


def test_a_token_cannot_be_used_as_another_user(auth_env: AuthEnv) -> None:
    auth_env.add_user(FRIEND, FRIEND_PASSWORD)
    friend_token = auth_env.login(FRIEND, FRIEND_PASSWORD)
    owner_token = auth_env.login()
    assert auth_env.client().get(ME, headers=bearer(friend_token)).json()["username"] == FRIEND
    assert auth_env.client().get(ME, headers=bearer(owner_token)).json()["username"] == OWNER_NAME
    # A token with one character changed is a different (unknown) token.
    tampered = friend_token[:-1] + ("A" if friend_token[-1] != "A" else "B")
    assert auth_env.client().get(ME, headers=bearer(tampered)).status_code == 401


# ---- sessions ------------------------------------------------------------------------------


def test_logout_revokes_the_token(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    client = auth_env.client()
    assert client.post(LOGOUT, headers=bearer(token)).status_code == 204
    assert client.get(ME, headers=bearer(token)).status_code == 401
    assert client.post(LOGOUT, headers=bearer(token)).status_code == 401


def test_logout_only_revokes_the_current_session(auth_env: AuthEnv) -> None:
    first, second = auth_env.login(), auth_env.login()
    auth_env.client().post(LOGOUT, headers=bearer(first))
    assert auth_env.client().get(ME, headers=bearer(second)).status_code == 200


def test_idle_timeout_is_sliding(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(session_idle_hours=1)
    token = env.login()
    client = env.client()
    env.clock.advance(50 * 60)
    assert client.get(ME, headers=bearer(token)).status_code == 200
    env.clock.advance(50 * 60)  # 100 minutes after login, 50 after the last use
    assert client.get(ME, headers=bearer(token)).status_code == 200
    env.clock.advance(61 * 60)
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_absolute_lifetime_ends_an_active_session(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(session_lifetime_days=1, session_idle_hours=24)
    token = env.login()
    client = env.client()
    env.clock.advance(12 * 3600)
    assert client.get(ME, headers=bearer(token)).status_code == 200
    env.clock.advance(12 * 3600)  # exactly at the absolute limit, despite recent activity
    assert client.get(ME, headers=bearer(token)).status_code == 401


def test_disabling_a_user_kills_their_sessions(auth_env: AuthEnv) -> None:
    auth_env.add_user(FRIEND, FRIEND_PASSWORD)
    token = auth_env.login(FRIEND, FRIEND_PASSWORD)
    assert auth_env.client().get(ME, headers=bearer(token)).status_code == 200
    with auth_env.db.transaction() as conn:
        conn.execute("UPDATE users SET disabled = 1 WHERE username = ?", (FRIEND,))
    assert auth_env.client().get(ME, headers=bearer(token)).status_code == 401


def test_live_sessions_per_user_are_capped(auth_env: AuthEnv) -> None:
    tokens = []
    for _ in range(MAX_SESSIONS_PER_USER + 2):
        tokens.append(auth_env.login())
        auth_env.clock.advance(1)
    client = auth_env.client()
    statuses = [client.get(ME, headers=bearer(t)).status_code for t in tokens]
    assert statuses[:2] == [401, 401] and statuses[2:] == [200] * MAX_SESSIONS_PER_USER


def test_sessions_survive_a_restart(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    restarted = AuthService(
        auth_env.db,
        PasswordService(CHEAP),
        idle_seconds=3600,
        lifetime_seconds=86400,
        clock=auth_env.clock,
    )
    assert restarted.authenticate(token) is not None


# ---- password change -----------------------------------------------------------------------


def test_password_change_revokes_other_sessions_and_keeps_current(auth_env: AuthEnv) -> None:
    current, other = auth_env.login(), auth_env.login()
    new = "a brand new passphrase"
    r = auth_env.client().post(
        PASSWORD, headers=bearer(current), json={"current": OWNER_PASSWORD, "new": new}
    )
    assert r.status_code == 204
    client = auth_env.client()
    assert client.get(ME, headers=bearer(current)).status_code == 200
    assert client.get(ME, headers=bearer(other)).status_code == 401
    old_login = client.post(LOGIN, json={"username": OWNER_NAME, "password": OWNER_PASSWORD})
    assert old_login.status_code == 401
    assert client.post(LOGIN, json={"username": OWNER_NAME, "password": new}).status_code == 200


def test_password_change_with_wrong_current_changes_nothing(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    r = auth_env.client().post(
        PASSWORD,
        headers=bearer(token),
        json={"current": "not the password", "new": "a brand new passphrase"},
    )
    assert r.status_code == 403 and error_code(r) == "invalid_current_password"
    assert auth_env.login()  # old password still works


@pytest.mark.parametrize("new", ["short", " " * 20], ids=["short", "blank"])
def test_password_change_enforces_the_policy(auth_env: AuthEnv, new: str) -> None:
    token = auth_env.login()
    r = auth_env.client().post(
        PASSWORD, headers=bearer(token), json={"current": OWNER_PASSWORD, "new": new}
    )
    assert r.status_code == 400 and error_code(r) == "weak_password"
    assert auth_env.login()  # old password still works


def test_password_change_requires_authentication_and_both_fields(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    assert client.post(PASSWORD, json={"current": "x", "new": "y"}).status_code == 401
    token = auth_env.login()
    assert client.post(PASSWORD, headers=bearer(token), json={"new": "y" * 20}).status_code == 400


def test_password_change_is_throttled_like_login(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    client = auth_env.client()
    codes = [
        client.post(
            PASSWORD, headers=bearer(token), json={"current": f"guess number {i}", "new": "n" * 20}
        ).status_code
        for i in range(6)
    ]
    assert codes == [403] * 5 + [429]
    # The guessing also locks the account's login: a stolen token cannot dodge the throttle.
    r = client.post(LOGIN, json={"username": OWNER_NAME, "password": OWNER_PASSWORD})
    assert r.status_code == 429


# ---- owner-only status ---------------------------------------------------------------------


def test_admin_status_is_owner_only(auth_env: AuthEnv) -> None:
    auth_env.add_user(FRIEND, FRIEND_PASSWORD)
    owner = auth_env.login()
    friend = auth_env.login(FRIEND, FRIEND_PASSWORD)
    client = auth_env.client()
    assert client.get(STATUS).status_code == 401
    r = client.get(STATUS, headers=bearer(friend))
    assert r.status_code == 403 and error_code(r) == "forbidden"
    ok = client.get(STATUS, headers=bearer(owner))
    assert ok.status_code == 200
    body = ok.json()
    assert body["database"] == {"ok": True, "schema_version": 3}
    assert body["storage"]["free_bytes"] > 0 and body["storage"]["total_bytes"] > 0
    assert body["version"]
    # No server paths or secrets.
    assert str(auth_env.storage_root) not in ok.text
    assert "hash" not in ok.text


def test_admin_status_rejects_a_revoked_owner_token(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    auth_env.client().post(LOGOUT, headers=bearer(token))
    assert auth_env.client().get(STATUS, headers=bearer(token)).status_code == 401


# ---- logging -------------------------------------------------------------------------------


def test_secrets_never_reach_the_logs(auth_env: AuthEnv, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    token = auth_env.login()
    client = auth_env.client()
    client.post(LOGIN, json={"username": OWNER_NAME, "password": "a wrong password!"})
    client.post(LOGIN, json={"username": "nobody-at-all", "password": "another wrong one"})
    client.get(ME, headers=bearer(token))
    new = "a brand new passphrase"
    client.post(PASSWORD, headers=bearer(token), json={"current": OWNER_PASSWORD, "new": new})
    client.post(LOGOUT, headers=bearer(token))
    everything = caplog.text + " ".join(str(r.__dict__) for r in caplog.records)
    for secret in (OWNER_PASSWORD, "a wrong password!", "another wrong one", new, token):
        assert secret not in everything
    # An unknown username is never logged: people sometimes type a password into that field.
    assert "nobody-at-all" not in everything
    events = {r.getMessage() for r in caplog.records}
    assert {"login_success", "login_failed", "logout", "password_changed"} <= events
