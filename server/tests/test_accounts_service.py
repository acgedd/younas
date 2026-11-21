"""Phase 4 step 2a: account administration in AuthService (create, disable, reset, revoke)."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from typing import Any

import pytest
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv

from yournas.audit import AuditLog
from yournas.auth.service import (
    RESERVED_USERNAMES,
    AuthService,
    OwnerProtectedError,
    generate_temporary_password,
)
from yournas.core.errors import AppError

ME = "/api/v1/auth/me"
FRIEND = "friend"
FRIEND_PASSWORD = "friendly passphrase 42"  # noqa: S105 - test credential


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def owner_id(env: AuthEnv) -> str:
    with env.db.read() as conn:
        return str(conn.execute("SELECT id FROM users WHERE role = 'owner'").fetchone()[0])


def user_row(env: AuthEnv, user_id: str) -> Any:
    with env.db.read() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def audit_rows(env: AuthEnv) -> list[Any]:
    with env.db.read() as conn:
        return conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()


def live_sessions(env: AuthEnv, user_id: str) -> int:
    with env.db.read() as conn:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND revoked_at IS NULL",
                (user_id,),
            ).fetchone()[0]
        )


def throttle_keys(env: AuthEnv) -> set[str]:
    with env.db.read() as conn:
        return {r[0] for r in conn.execute("SELECT key FROM login_throttle")}


def dump_database_text(env: AuthEnv) -> str:
    """Everything a stray secret could hide in: the audit log and the users' non-hash columns."""
    with env.db.read() as conn:
        audit = conn.execute("SELECT * FROM audit_log").fetchall()
        users = conn.execute(
            "SELECT id, username, role, disabled, created_at, must_change_password FROM users"
        ).fetchall()
    return repr([tuple(r) for r in audit]) + repr([tuple(r) for r in users])


def api_status(env: AuthEnv, token: str) -> int:
    return int(env.client().get(ME, headers=bearer(token)).status_code)


@pytest.fixture
def actor(auth_env: AuthEnv) -> str:
    return owner_id(auth_env)


# ---- create_user --------------------------------------------------------------------------


def test_create_user_makes_a_pending_user_with_a_usable_temporary_password(
    auth_env: AuthEnv, actor: str
) -> None:
    user, temp = auth_env.service.create_user(actor, "Alice")
    assert user.username == "alice" and user.role == "user" and user.id.startswith("u_")
    row = user_row(auth_env, user.id)
    assert row["role"] == "user" and row["disabled"] == 0 and row["must_change_password"] == 1
    assert temp not in row["password_hash"] and row["password_hash"].startswith("$argon2id$")
    result = auth_env.service.login("alice", temp, None)
    assert result.must_change_password is True and result.user.id == user.id
    ctx = auth_env.service.authenticate(result.token)
    assert ctx is not None and ctx.must_change is True


def test_create_user_audits_with_ids_only(auth_env: AuthEnv, actor: str) -> None:
    user, temp = auth_env.service.create_user(actor, "alice")
    (row,) = audit_rows(auth_env)
    assert (row["actor_id"], row["action"]) == (actor, "user_created")
    assert (row["target_type"], row["target_id"], row["detail"]) == ("user", user.id, None)
    assert temp not in dump_database_text(auth_env)


@pytest.mark.parametrize("name", sorted(RESERVED_USERNAMES) + ["Admin", "ROOT"])
def test_reserved_usernames_are_refused_like_a_taken_name(
    auth_env: AuthEnv, actor: str, name: str
) -> None:
    with pytest.raises(AppError) as exc:
        auth_env.service.create_user(actor, name)
    assert (exc.value.status_code, exc.value.code) == (409, "username_taken")
    assert audit_rows(auth_env) == []


def test_taken_username_is_409_and_does_not_touch_the_existing_account(
    auth_env: AuthEnv, actor: str
) -> None:
    auth_env.add_user(FRIEND, FRIEND_PASSWORD)
    with pytest.raises(AppError) as exc:
        auth_env.service.create_user(actor, "FRIEND")
    assert (exc.value.status_code, exc.value.code) == (409, "username_taken")
    assert auth_env.service.login(FRIEND, FRIEND_PASSWORD, None).must_change_password is False
    assert audit_rows(auth_env) == []


@pytest.mark.parametrize("name", ["", "ab", "has space", "x" * 33, "-lead", "ünï", "a/b"])
def test_invalid_username_is_400(auth_env: AuthEnv, actor: str, name: str) -> None:
    with pytest.raises(AppError) as exc:
        auth_env.service.create_user(actor, name)
    assert (exc.value.status_code, exc.value.code) == (400, "invalid_username")


def test_create_user_never_creates_an_owner(auth_env: AuthEnv, actor: str) -> None:
    user, _ = auth_env.service.create_user(actor, "carol")
    assert user.role == "user"
    with auth_env.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE role = 'owner'").fetchone()[0] == 1


def test_temporary_password_is_regenerated_until_it_passes_the_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = iter(["aaaaaaaaaaaaaaaa", "123456789012", "Xk3-vQ9_mZ7pLw2R"])
    monkeypatch.setattr(secrets, "token_urlsafe", lambda _n: next(candidates))
    assert generate_temporary_password("alice") == "Xk3-vQ9_mZ7pLw2R"


def test_generated_temporary_passwords_are_long_and_different() -> None:
    first, second = generate_temporary_password("alice"), generate_temporary_password("alice")
    assert first != second and len(first) >= 16


def test_temporary_password_never_reaches_logs_or_the_database(
    auth_env: AuthEnv, actor: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    user, created = auth_env.service.create_user(actor, "alice")
    reset = auth_env.service.reset_password(actor, user.id)
    auth_env.service.login("alice", reset, None)
    auth_env.service.revoke_sessions(actor, user.id)
    auth_env.service.set_disabled(actor, user.id, True)
    for secret in (created, reset):
        assert secret not in caplog.text
        assert secret not in dump_database_text(auth_env)
    assert any(r.message == "password_reset" for r in caplog.records)


# ---- list_users ---------------------------------------------------------------------------


def test_list_users_reports_state_without_secrets(auth_env: AuthEnv, actor: str) -> None:
    auth_env.clock.advance(10)
    user, _ = auth_env.service.create_user(actor, "alice")
    auth_env.service.set_disabled(actor, user.id, True)
    users = auth_env.service.list_users()
    assert [u.username for u in users] == [OWNER_NAME, "alice"]
    owner, alice = users
    assert (owner.role, owner.disabled, owner.must_change_password) == ("owner", False, False)
    assert (alice.id, alice.role, alice.disabled, alice.must_change_password) == (
        user.id,
        "user",
        True,
        True,
    )
    assert alice.created_at == int(auth_env.clock())
    assert not any("hash" in f or "token" in f for f in alice.__dataclass_fields__)


# ---- set_disabled -------------------------------------------------------------------------


def make_friend_with_token(env: AuthEnv) -> tuple[str, str]:
    user_id = env.add_user(FRIEND, FRIEND_PASSWORD)
    return user_id, env.login(FRIEND, FRIEND_PASSWORD)


def test_disable_revokes_sessions_and_the_next_request_is_401(
    auth_env: AuthEnv, actor: str
) -> None:
    user_id, token = make_friend_with_token(auth_env)
    assert api_status(auth_env, token) == 200
    auth_env.service.set_disabled(actor, user_id, True)
    assert user_row(auth_env, user_id)["disabled"] == 1
    assert live_sessions(auth_env, user_id) == 0
    assert api_status(auth_env, token) == 401
    r = auth_env.client().post(
        "/api/v1/auth/login", json={"username": FRIEND, "password": FRIEND_PASSWORD}
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_credentials"
    row = audit_rows(auth_env)[-1]
    assert (row["action"], row["target_type"], row["target_id"]) == (
        "user_disabled",
        "user",
        user_id,
    )


def test_enabling_does_not_resurrect_old_sessions(auth_env: AuthEnv, actor: str) -> None:
    user_id, old_token = make_friend_with_token(auth_env)
    auth_env.service.set_disabled(actor, user_id, True)
    auth_env.service.set_disabled(actor, user_id, False)
    assert user_row(auth_env, user_id)["disabled"] == 0
    assert api_status(auth_env, old_token) == 401
    new_token = auth_env.login(FRIEND, FRIEND_PASSWORD)
    assert api_status(auth_env, new_token) == 200 and api_status(auth_env, old_token) == 401
    assert [r["action"] for r in audit_rows(auth_env)] == ["user_disabled", "user_enabled"]


def test_owner_cannot_be_disabled(auth_env: AuthEnv, actor: str) -> None:
    token = auth_env.login()
    with pytest.raises(OwnerProtectedError) as exc:
        auth_env.service.set_disabled(actor, actor, True)
    assert (exc.value.status_code, exc.value.code) == (400, "cannot_modify_owner")
    assert user_row(auth_env, actor)["disabled"] == 0
    assert api_status(auth_env, token) == 200
    assert audit_rows(auth_env) == []


def test_unknown_user_is_404_for_every_mutator(auth_env: AuthEnv, actor: str) -> None:
    for call in (
        lambda: auth_env.service.set_disabled(actor, "u_0000000000000000", True),
        lambda: auth_env.service.reset_password(actor, "u_0000000000000000"),
        lambda: auth_env.service.revoke_sessions(actor, "u_0000000000000000"),
    ):
        with pytest.raises(AppError) as exc:
            call()
        assert (exc.value.status_code, exc.value.code) == (404, "not_found")
    assert audit_rows(auth_env) == []


# ---- reset_password -----------------------------------------------------------------------


def test_reset_password_forces_a_change_and_kills_every_session(
    auth_env: AuthEnv, actor: str
) -> None:
    user_id, token = make_friend_with_token(auth_env)
    second = auth_env.login(FRIEND, FRIEND_PASSWORD)
    before = user_row(auth_env, user_id)
    auth_env.clock.advance(60)
    temp = auth_env.service.reset_password(actor, user_id)
    after = user_row(auth_env, user_id)
    assert after["must_change_password"] == 1
    assert after["password_hash"] != before["password_hash"]
    assert after["password_changed_at"] == int(auth_env.clock())
    assert api_status(auth_env, token) == 401 and api_status(auth_env, second) == 401
    assert live_sessions(auth_env, user_id) == 0
    login = auth_env.client().post(
        "/api/v1/auth/login", json={"username": FRIEND, "password": FRIEND_PASSWORD}
    )
    assert login.status_code == 401
    result = auth_env.service.login(FRIEND, temp, None)
    assert result.must_change_password is True
    row = audit_rows(auth_env)[-1]
    assert (row["action"], row["target_id"], row["detail"]) == (
        "password_reset",
        user_id,
        '{"count":2}',
    )


def test_reset_password_clears_that_accounts_login_lockout(auth_env: AuthEnv, actor: str) -> None:
    user_id, _ = make_friend_with_token(auth_env)
    for _ in range(3):
        r = auth_env.client().post(
            "/api/v1/auth/login", json={"username": FRIEND, "password": "wrong password!"}
        )
        assert r.status_code == 401
    other = auth_env.client().post(
        "/api/v1/auth/login", json={"username": "someone-else", "password": "wrong password!"}
    )
    assert other.status_code == 401
    assert {"acct:" + FRIEND, "acct:someone-else"} <= throttle_keys(auth_env)
    temp = auth_env.service.reset_password(actor, user_id)
    keys = throttle_keys(auth_env)
    assert "acct:" + FRIEND not in keys and "acct:someone-else" in keys
    assert auth_env.service.login(FRIEND, temp, None).user.id == user_id


def test_owner_password_cannot_be_reset(auth_env: AuthEnv, actor: str) -> None:
    token = auth_env.login()
    before = user_row(auth_env, actor)["password_hash"]
    with pytest.raises(OwnerProtectedError) as exc:
        auth_env.service.reset_password(actor, actor)
    assert (exc.value.status_code, exc.value.code) == (400, "cannot_modify_owner")
    after = user_row(auth_env, actor)
    assert after["password_hash"] == before and after["must_change_password"] == 0
    assert api_status(auth_env, token) == 200 and audit_rows(auth_env) == []
    auth_env.service.login(OWNER_NAME, OWNER_PASSWORD, None)


def test_a_disabled_account_can_be_reset_and_stays_disabled(auth_env: AuthEnv, actor: str) -> None:
    user_id, _ = make_friend_with_token(auth_env)
    auth_env.service.set_disabled(actor, user_id, True)
    temp = auth_env.service.reset_password(actor, user_id)
    assert user_row(auth_env, user_id)["disabled"] == 1
    r = auth_env.client().post("/api/v1/auth/login", json={"username": FRIEND, "password": temp})
    assert r.status_code == 401


# ---- revoke_sessions ----------------------------------------------------------------------


def test_revoke_sessions_counts_and_audits(auth_env: AuthEnv, actor: str) -> None:
    user_id, token = make_friend_with_token(auth_env)
    auth_env.login(FRIEND, FRIEND_PASSWORD)
    assert auth_env.service.revoke_sessions(actor, user_id) == 2
    assert api_status(auth_env, token) == 401
    assert auth_env.service.revoke_sessions(actor, user_id) == 0
    rows = audit_rows(auth_env)
    assert [(r["action"], r["detail"]) for r in rows] == [
        ("sessions_revoked", '{"count":2}'),
        ("sessions_revoked", '{"count":0}'),
    ]
    # The account itself still works: only its sessions ended.
    assert api_status(auth_env, auth_env.login(FRIEND, FRIEND_PASSWORD)) == 200


def test_revoke_sessions_leaves_other_users_alone(auth_env: AuthEnv, actor: str) -> None:
    user_id, _ = make_friend_with_token(auth_env)
    owner_token = auth_env.login()
    auth_env.service.revoke_sessions(actor, user_id)
    assert api_status(auth_env, owner_token) == 200


# ---- change_password ----------------------------------------------------------------------


def test_change_password_audits_and_rejects_the_same_password(
    auth_env: AuthEnv, actor: str
) -> None:
    user, temp = auth_env.service.create_user(actor, "alice")
    ctx = auth_env.service.authenticate(auth_env.service.login("alice", temp, None).token)
    assert ctx is not None
    with pytest.raises(AppError) as exc:
        auth_env.service.change_password(ctx, temp, temp)
    assert (exc.value.status_code, exc.value.code) == (400, "password_unchanged")
    assert user_row(auth_env, user.id)["must_change_password"] == 1
    auth_env.service.change_password(ctx, temp, "a brand new passphrase 77")
    assert user_row(auth_env, user.id)["must_change_password"] == 0
    row = audit_rows(auth_env)[-1]
    assert (row["actor_id"], row["action"], row["target_type"], row["target_id"]) == (
        user.id,
        "password_changed",
        "user",
        user.id,
    )
    assert "a brand new passphrase 77" not in dump_database_text(auth_env)


# ---- audit atomicity ----------------------------------------------------------------------


@pytest.fixture
def failing_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AuditLog, "record", _boom)


def test_create_user_is_rolled_back_when_the_audit_row_fails(
    auth_env: AuthEnv, actor: str, failing_audit: None
) -> None:
    with pytest.raises(RuntimeError):
        auth_env.service.create_user(actor, "alice")
    assert [u.username for u in auth_env.service.list_users()] == [OWNER_NAME]


def test_disable_is_rolled_back_when_the_audit_row_fails(
    auth_env: AuthEnv, actor: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, token = make_friend_with_token(auth_env)
    with monkeypatch.context() as m:
        m.setattr(AuditLog, "record", _boom)
        with pytest.raises(RuntimeError):
            auth_env.service.set_disabled(actor, user_id, True)
    assert user_row(auth_env, user_id)["disabled"] == 0
    assert live_sessions(auth_env, user_id) == 1 and api_status(auth_env, token) == 200


def test_reset_is_rolled_back_when_the_audit_row_fails(
    auth_env: AuthEnv, actor: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, token = make_friend_with_token(auth_env)
    for _ in range(2):
        auth_env.client().post(
            "/api/v1/auth/login", json={"username": FRIEND, "password": "wrong password!"}
        )
    before = user_row(auth_env, user_id)
    with monkeypatch.context() as m:
        m.setattr(AuditLog, "record", _boom)
        with pytest.raises(RuntimeError):
            auth_env.service.reset_password(actor, user_id)
    after = user_row(auth_env, user_id)
    assert after["password_hash"] == before["password_hash"]
    assert after["must_change_password"] == 0
    assert api_status(auth_env, token) == 200
    assert "acct:" + FRIEND in throttle_keys(auth_env)
    assert auth_env.service.login(FRIEND, FRIEND_PASSWORD, None).user.id == user_id


def test_revoke_is_rolled_back_when_the_audit_row_fails(
    auth_env: AuthEnv, actor: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    user_id, token = make_friend_with_token(auth_env)
    with monkeypatch.context() as m:
        m.setattr(AuditLog, "record", _boom)
        with pytest.raises(RuntimeError):
            auth_env.service.revoke_sessions(actor, user_id)
    assert api_status(auth_env, token) == 200


def test_change_password_is_rolled_back_when_the_audit_row_fails(
    make_auth_env: Callable[..., AuthEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_auth_env()
    actor = owner_id(env)
    _, temp = env.service.create_user(actor, "alice")
    ctx = env.service.authenticate(env.service.login("alice", temp, None).token)
    assert ctx is not None
    with monkeypatch.context() as m:
        m.setattr(AuditLog, "record", _boom)
        with pytest.raises(RuntimeError):
            env.service.change_password(ctx, temp, "a brand new passphrase 77")
    row = user_row(env, ctx.user.id)
    assert row["must_change_password"] == 1
    # The old (temporary) password still works, the new one does not.
    assert env.service.login("alice", temp, None).must_change_password is True
    with pytest.raises(AppError):
        env.service.login("alice", "a brand new passphrase 77", None)


def _boom(self: AuditLog, *args: object, **kwargs: object) -> int:
    raise RuntimeError("audit insert failed")


def test_a_default_audit_log_is_built_when_none_is_given(auth_env: AuthEnv) -> None:
    service = AuthService(
        auth_env.db,
        auth_env.service._passwords,
        idle_seconds=3600,
        lifetime_seconds=86400,
        clock=auth_env.clock,
    )
    user, _ = service.create_user(owner_id(auth_env), "dave")
    assert audit_rows(auth_env)[-1]["target_id"] == user.id
