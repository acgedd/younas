"""Phase 4 step 2a: a temporary password limits a session to me, password and logout."""

from __future__ import annotations

import re
import secrets

import httpx
import pytest
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv, bearer, routes_of
from fastapi.testclient import TestClient

LOGIN = "/api/v1/auth/login"
ME = "/api/v1/auth/me"
LOGOUT = "/api/v1/auth/logout"
PASSWORD = "/api/v1/auth/password"
PUBLIC = {("GET", "/health"), ("POST", LOGIN)}
SESSION_ONLY = {("GET", ME), ("POST", LOGOUT), ("POST", PASSWORD)}
NEW_PASSWORD = "a brand new passphrase 77"  # noqa: S105 - test credential


def error_code(response: httpx.Response) -> str:
    return str(response.json()["error"]["code"])


def fill(path: str) -> str:
    """A concrete URL for a documented path template."""
    return re.sub(r"\{[^}]+\}", "x", path)


class Pending:
    """A freshly created user: logged in with the temporary password, flag still set."""

    def __init__(self, env: AuthEnv, name: str = "alice") -> None:
        self.env = env
        with env.db.read() as conn:
            self.actor = str(conn.execute("SELECT id FROM users WHERE role='owner'").fetchone()[0])
        user, self.temp = env.service.create_user(self.actor, name)
        self.name = name
        self.user_id = user.id
        self.token = env.login(name, self.temp)

    def client(self) -> TestClient:
        return self.env.client(**bearer(self.token))


@pytest.fixture
def pending(auth_env: AuthEnv) -> Pending:
    return Pending(auth_env)


# ---- the route set ------------------------------------------------------------------------


def test_pending_user_gets_403_on_every_route_except_the_three_session_routes(
    auth_env: AuthEnv, pending: Pending
) -> None:
    routes = routes_of(auth_env.app)
    assert len(routes) >= 15  # files, uploads, admin and auth: never a vacuous loop
    assert routes >= PUBLIC and routes >= SESSION_ONLY
    guarded = routes - PUBLIC - SESSION_ONLY
    assert ("GET", "/api/v1/admin/status") in guarded
    assert ("GET", "/api/v1/spaces") in guarded
    client = pending.client()
    for method, path in sorted(guarded):
        r = client.request(method, fill(path))
        assert r.status_code == 403, f"{method} {path} -> {r.status_code}"
        if method != "HEAD":  # a HEAD response has no body to carry the code
            assert error_code(r) == "password_change_required", f"{method} {path}"


def test_pending_user_gets_403_not_404_for_spaces_that_do_not_exist(pending: Pending) -> None:
    r = pending.client().get("/api/v1/spaces/share:s_0123456789abcdef/items")
    assert r.status_code == 403 and error_code(r) == "password_change_required"


def test_a_pending_owner_is_blocked_from_admin_routes_too(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    with auth_env.db.transaction() as conn:
        conn.execute("UPDATE users SET must_change_password = 1 WHERE role = 'owner'")
    client = auth_env.client(**bearer(token))
    r = client.get("/api/v1/admin/status")
    assert r.status_code == 403 and error_code(r) == "password_change_required"
    assert client.get(ME).json()["must_change_password"] is True


def test_the_three_session_routes_work_for_a_pending_user(pending: Pending) -> None:
    client = pending.client()
    me = client.get(ME)
    assert me.status_code == 200 and me.json()["must_change_password"] is True
    assert client.post(LOGOUT).status_code == 204
    assert client.get(ME).status_code == 401


def test_unauthenticated_requests_stay_401_not_403(auth_env: AuthEnv) -> None:
    r = auth_env.client().get("/api/v1/spaces")
    assert r.status_code == 401 and error_code(r) == "unauthorized"
    r = auth_env.client().get("/api/v1/spaces", headers=bearer(secrets.token_urlsafe(32)))
    assert r.status_code == 401


# ---- changing the password ----------------------------------------------------------------


def test_changing_the_password_clears_the_flag_and_opens_the_other_routes(
    auth_env: AuthEnv, pending: Pending
) -> None:
    client = pending.client()
    assert client.get("/api/v1/spaces").status_code == 403
    r = client.post(PASSWORD, json={"current": pending.temp, "new": NEW_PASSWORD})
    assert r.status_code == 204
    # The same token keeps working, now without the restriction.
    assert client.get("/api/v1/spaces").status_code == 200
    assert client.get("/api/v1/spaces/home/items").status_code == 200
    assert client.get(ME).json()["must_change_password"] is False
    # Logging in again reports no pending change; the temporary password is dead.
    ok = auth_env.client().post(LOGIN, json={"username": pending.name, "password": NEW_PASSWORD})
    assert ok.status_code == 200 and ok.json()["must_change_password"] is False
    old = auth_env.client().post(LOGIN, json={"username": pending.name, "password": pending.temp})
    assert old.status_code == 401


def test_changing_the_password_ends_the_other_sessions(auth_env: AuthEnv, pending: Pending) -> None:
    other = auth_env.login(pending.name, pending.temp)
    client = pending.client()
    assert (
        client.post(PASSWORD, json={"current": pending.temp, "new": NEW_PASSWORD}).status_code
        == 204
    )
    assert auth_env.client().get(ME, headers=bearer(other)).status_code == 401


def test_the_same_password_is_rejected_and_the_flag_stays(
    auth_env: AuthEnv, pending: Pending
) -> None:
    client = pending.client()
    r = client.post(PASSWORD, json={"current": pending.temp, "new": pending.temp})
    assert r.status_code == 400 and error_code(r) == "password_unchanged"
    assert pending.temp not in r.text
    assert client.get(ME).json()["must_change_password"] is True
    assert client.get("/api/v1/spaces").status_code == 403


def test_a_wrong_current_or_weak_new_password_keeps_the_flag(pending: Pending) -> None:
    client = pending.client()
    r = client.post(PASSWORD, json={"current": "not the password", "new": NEW_PASSWORD})
    assert r.status_code == 403 and error_code(r) == "invalid_current_password"
    r = client.post(PASSWORD, json={"current": pending.temp, "new": "aaaaaaaaaaaaaaaa"})
    assert r.status_code == 400 and error_code(r) == "weak_password"
    assert client.get(ME).json()["must_change_password"] is True


def test_a_normal_user_can_change_the_password_later_and_new_equals_current_is_rejected(
    auth_env: AuthEnv,
) -> None:
    auth_env.add_user("friend", "friendly passphrase 42")
    client = auth_env.client(**bearer(auth_env.login("friend", "friendly passphrase 42")))
    same = client.post(
        PASSWORD, json={"current": "friendly passphrase 42", "new": "friendly passphrase 42"}
    )
    assert same.status_code == 400 and error_code(same) == "password_unchanged"
    ok = client.post(PASSWORD, json={"current": "friendly passphrase 42", "new": NEW_PASSWORD})
    assert ok.status_code == 204


# ---- reset and disable at the HTTP level --------------------------------------------------


def test_reset_makes_a_normal_user_pending_again_and_the_old_token_dies(
    auth_env: AuthEnv, pending: Pending
) -> None:
    pending.client().post(PASSWORD, json={"current": pending.temp, "new": NEW_PASSWORD})
    token = auth_env.login(pending.name, NEW_PASSWORD)
    client = auth_env.client(**bearer(token))
    assert client.get("/api/v1/spaces").status_code == 200
    temp = auth_env.service.reset_password(pending.actor, pending.user_id)
    assert client.get(ME).status_code == 401
    again = auth_env.login(pending.name, temp)
    assert auth_env.client(**bearer(again)).get("/api/v1/spaces").status_code == 403


def test_a_disabled_pending_user_is_rejected_on_the_next_request(
    auth_env: AuthEnv, pending: Pending
) -> None:
    auth_env.service.set_disabled(pending.actor, pending.user_id, True)
    r = pending.client().get(ME)
    assert r.status_code == 401 and error_code(r) == "unauthorized"


# ---- login and /auth/me payloads ----------------------------------------------------------


def test_login_and_me_expose_the_flag_and_the_spaces(auth_env: AuthEnv, pending: Pending) -> None:
    login = auth_env.client().post(LOGIN, json={"username": pending.name, "password": pending.temp})
    body = login.json()
    assert login.status_code == 200 and body["must_change_password"] is True
    assert body["spaces"] == [{"id": "home", "name": "My files", "access": "write"}]
    me = auth_env.client(**bearer(body["token"])).get(ME).json()
    assert me["must_change_password"] is True and me["spaces"] == body["spaces"]
    owner = auth_env.client().post(LOGIN, json={"username": OWNER_NAME, "password": OWNER_PASSWORD})
    assert owner.json()["must_change_password"] is False


def test_spaces_come_from_the_permissions_service(auth_env: AuthEnv, pending: Pending) -> None:
    owner_id = pending.actor
    share_id = "s_" + secrets.token_hex(8)
    with auth_env.db.transaction() as conn:
        conn.execute(
            "INSERT INTO shares (id, name, created_at, created_by) VALUES (?, 'Photos', 1, ?)",
            (share_id, owner_id),
        )
        conn.execute(
            "INSERT INTO grants (share_id, user_id, level, created_at) VALUES (?, ?, 'read', 1)",
            (share_id, pending.user_id),
        )
    expected = [
        {"id": "home", "name": "My files", "access": "write"},
        {"id": f"share:{share_id}", "name": "Photos", "access": "read"},
    ]
    assert pending.client().get(ME).json()["spaces"] == expected
    login = auth_env.client().post(LOGIN, json={"username": pending.name, "password": pending.temp})
    assert login.json()["spaces"] == expected
    # The owner holds no grant here, so sees only their own space.
    owner_token = auth_env.login()
    owner_me = auth_env.client(**bearer(owner_token)).get(ME).json()
    assert [s["id"] for s in owner_me["spaces"]] == ["home"]
