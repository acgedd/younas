"""Phase 4 step 3: the owner-only admin routes (users, shares, grants, share delete, audit).

Real HTTP against a real database and storage root. `owner` and `friend` are the logged-in
accounts of conftest; `mk_user` creates further accounts through the admin API itself.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    FRIEND_NAME,
    FRIEND_PASSWORD,
    AuthEnv,
    Session,
    bearer,
    routes_of,
)

from yournas.audit import AuditLog

A = "/api/v1/admin"
ZERO_USER = "u_" + "0" * 16
ZERO_SHARE = "s_" + "0" * 16
OCTET = {"content-type": "application/octet-stream"}


def code(r: Any) -> str:
    return str(r.json()["error"]["code"])


def concrete(path: str) -> str:
    return path.replace("{user_id}", ZERO_USER).replace("{share_id}", ZERO_SHARE)


def mk_share(owner: Session, name: str = "Docs") -> dict[str, Any]:
    r = owner.client.post(f"{A}/shares", json={"name": name})
    assert r.status_code == 201, r.text
    data: dict[str, Any] = r.json()
    return data


def mk_user(owner: Session, name: str) -> tuple[str, str]:
    r = owner.client.post(f"{A}/users", json={"username": name})
    assert r.status_code == 201, r.text
    return str(r.json()["id"]), str(r.json()["temporary_password"])


def share_dir(env: AuthEnv, share_id: str) -> Path:
    return env.storage_root / "shared" / share_id


def space(share_id: str) -> str:
    return f"share:{share_id}"


def grant(owner: Session, share_id: str, user_id: str, level: str = "write") -> None:
    r = owner.client.put(f"{A}/shares/{share_id}/grants/{user_id}", json={"level": level})
    assert r.status_code == 200, r.text


def audit_rows(env: AuthEnv) -> list[dict[str, Any]]:
    with env.db.read() as conn:
        rows = conn.execute(
            "SELECT id, actor_id, action, target_type, target_id, detail FROM audit_log ORDER BY id"
        ).fetchall()
    return [
        {
            "id": r["id"],
            "actor": r["actor_id"],
            "action": r["action"],
            "type": r["target_type"],
            "target": r["target_id"],
            "detail": json.loads(r["detail"]) if r["detail"] else None,
        }
        for r in rows
    ]


def count(env: AuthEnv, table: str) -> int:
    with env.db.read() as conn:
        (n,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()  # noqa: S608
    return int(n)


def shared_children(env: AuthEnv) -> list[str]:
    root = env.storage_root / "shared"
    return sorted(p.name for p in root.iterdir()) if root.exists() else []


def break_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(AuditLog, "record", boom)


# ---- the owner-only boundary ------------------------------------------------------------------


def admin_routes(env: AuthEnv) -> list[tuple[str, str]]:
    found = sorted(r for r in routes_of(env.app) if r[1].startswith(A))
    assert len(found) >= 12  # never a vacuous loop
    return found


def test_every_admin_route_is_401_without_a_token(auth_env: AuthEnv) -> None:
    anon = auth_env.client()
    for method, path in admin_routes(auth_env):
        r = anon.request(method, concrete(path))
        assert r.status_code == 401, (method, path)
        assert r.headers["www-authenticate"] == "Bearer"
    r = auth_env.client(Authorization="Bearer not-a-token").get(f"{A}/users")
    assert r.status_code == 401


def test_every_admin_route_is_403_for_a_friend(auth_env: AuthEnv, friend: Session) -> None:
    for method, path in admin_routes(auth_env):
        r = friend.client.request(method, concrete(path))
        assert r.status_code == 403, (method, path)
        assert code(r) == "forbidden"


def test_forged_identity_or_role_does_not_open_the_admin_routes(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    forged = {
        "X-User-Id": owner.user_id,
        "X-Role": "owner",
        "X-Forwarded-User": owner.user_id,
        "X-Admin": "1",
    }
    users_before = count(auth_env, "users")
    r = friend.client.get(f"{A}/users", headers=forged, params={"user_id": owner.user_id})
    assert r.status_code == 403
    r = friend.client.post(
        f"{A}/users",
        headers=forged,
        json={"username": "sneaky", "role": "owner", "user_id": owner.user_id},
    )
    assert r.status_code == 403
    r = friend.client.patch(
        f"{A}/users/{friend.user_id}", headers=forged, json={"disabled": True, "role": "owner"}
    )
    assert r.status_code == 403
    r = friend.client.post(f"{A}/shares", headers=forged, json={"name": "x", "role": "owner"})
    assert r.status_code == 403
    assert count(auth_env, "users") == users_before and count(auth_env, "shares") == 0
    with auth_env.db.read() as conn:
        role = conn.execute("SELECT role FROM users WHERE id = ?", (friend.user_id,)).fetchone()
    assert role["role"] == "user"


def test_a_friend_cannot_manage_their_own_access(owner: Session, friend: Session) -> None:
    share = mk_share(owner)
    r = friend.client.put(
        f"{A}/shares/{share['id']}/grants/{friend.user_id}", json={"level": "write"}
    )
    assert r.status_code == 403
    assert friend.client.get(f"/api/v1/spaces/{space(share['id'])}/items").status_code == 404


def test_the_owner_account_cannot_be_modified_over_http(owner: Session) -> None:
    r = owner.client.patch(f"{A}/users/{owner.user_id}", json={"disabled": True})
    assert r.status_code == 400 and code(r) == "cannot_modify_owner"
    r = owner.client.post(f"{A}/users/{owner.user_id}/password-reset")
    assert r.status_code == 400 and code(r) == "cannot_modify_owner"
    rows = owner.client.get(f"{A}/users").json()
    assert [u["role"] for u in rows].count("owner") == 1
    assert owner.client.get(f"{A}/status").status_code == 200  # still logged in and enabled


# ---- users ------------------------------------------------------------------------------------


def test_create_user_returns_a_one_time_temporary_password(
    auth_env: AuthEnv, owner: Session
) -> None:
    r = owner.client.post(f"{A}/users", json={"username": "Bob.Smith"})
    assert r.status_code == 201
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == {"id", "username", "role", "temporary_password"}
    assert body["username"] == "bob.smith" and body["role"] == "user"
    temp = body["temporary_password"]
    assert len(temp) >= 12
    # The temporary password works once: the account must change it before anything else.
    token = auth_env.login("bob.smith", temp)
    client = auth_env.client(**bearer(token))
    me = client.get("/api/v1/auth/me").json()
    assert me["must_change_password"] is True and me["role"] == "user"
    assert client.get("/api/v1/spaces").status_code == 403
    changed = client.post(
        "/api/v1/auth/password", json={"current": temp, "new": "a brand new passphrase 9"}
    )
    assert changed.status_code == 204
    assert client.get("/api/v1/spaces").status_code == 200
    # Never shown again, never stored in the clear.
    listing = owner.client.get(f"{A}/users")
    assert temp not in listing.text
    with auth_env.db.read() as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE id = ?", (body["id"],))
        assert temp not in stored.fetchone()["password_hash"]


@pytest.mark.parametrize(
    "name", ["ab", "x" * 33, "has space", "-leading", "ünïcode", "a/b", "..", "a" * 65, "tab\t1"]
)
def test_invalid_usernames_are_refused(owner: Session, auth_env: AuthEnv, name: str) -> None:
    before = count(auth_env, "users")
    r = owner.client.post(f"{A}/users", json={"username": name})
    assert r.status_code == 400
    assert code(r) in ("invalid_username", "invalid_request")
    assert count(auth_env, "users") == before


def test_duplicate_and_reserved_usernames_are_409(owner: Session) -> None:
    mk_user(owner, "carol")
    for name in ("carol", "CAROL", "owner", "Admin", "root", "system"):
        r = owner.client.post(f"{A}/users", json={"username": name})
        assert r.status_code == 409 and code(r) == "username_taken", name


def test_create_user_ignores_attempts_to_choose_role_id_or_password(owner: Session) -> None:
    for extra in ({"role": "owner"}, {"id": "u_" + "1" * 16}, {"password": "chosen password 1"}):
        r = owner.client.post(f"{A}/users", json={"username": "dave", **extra})
        assert r.status_code == 400
        assert "chosen password" not in r.text  # a validation error never echoes input
    assert [u["username"] for u in owner.client.get(f"{A}/users").json()] == ["owner"]


def test_list_users_has_no_secrets(owner: Session, friend: Session) -> None:
    rows = owner.client.get(f"{A}/users").json()
    assert {u["username"] for u in rows} == {"owner", "friend"}
    for u in rows:
        assert set(u) == {
            "id",
            "username",
            "role",
            "disabled",
            "created_at",
            "must_change_password",
        }
    assert "argon2" not in json.dumps(rows)


def test_disable_and_enable_an_account(auth_env: AuthEnv, owner: Session, friend: Session) -> None:
    r = owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": True})
    assert r.status_code == 200 and r.json() == {"id": friend.user_id, "disabled": True}
    assert friend.client.get("/api/v1/auth/me").status_code == 401  # sessions ended
    bad = auth_env.client().post(
        "/api/v1/auth/login", json={"username": FRIEND_NAME, "password": FRIEND_PASSWORD}
    )
    assert bad.status_code == 401
    r = owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": False})
    assert r.status_code == 200 and r.json()["disabled"] is False
    assert friend.client.get("/api/v1/auth/me").status_code == 401  # old token stays dead
    assert auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)  # the account works again


@pytest.mark.parametrize(
    "body",
    [{}, {"disabled": "true"}, {"disabled": 1}, {"disabled": None}, {"disabled": True, "x": 1}],
    ids=["empty", "string", "int", "null", "extra"],
)
def test_disable_body_is_strict(owner: Session, friend: Session, body: dict[str, Any]) -> None:
    r = owner.client.patch(f"{A}/users/{friend.user_id}", json=body)
    assert r.status_code == 400
    assert friend.client.get("/api/v1/auth/me").status_code == 200


def test_unknown_and_malformed_user_ids(owner: Session) -> None:
    for uid in (ZERO_USER, "x", "u_xyz", "U_" + "0" * 16, "owner", "u_" + "0" * 17):
        for method, tail, body in (
            ("PATCH", "", {"disabled": True}),
            ("POST", "/password-reset", None),
            ("DELETE", "/sessions", None),
        ):
            r = owner.client.request(method, f"{A}/users/{uid}{tail}", json=body)
            assert r.status_code == 404, (uid, method)
            assert code(r) == "not_found"


def test_password_reset_gives_a_new_temporary_password(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    r = owner.client.post(f"{A}/users/{friend.user_id}/password-reset")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    temp = r.json()["temporary_password"]
    assert set(r.json()) == {"temporary_password"}
    assert friend.client.get("/api/v1/auth/me").status_code == 401  # sessions ended
    old = auth_env.client().post(
        "/api/v1/auth/login", json={"username": FRIEND_NAME, "password": FRIEND_PASSWORD}
    )
    assert old.status_code == 401
    token = auth_env.login(FRIEND_NAME, temp)
    me = auth_env.client(**bearer(token)).get("/api/v1/auth/me").json()
    assert me["must_change_password"] is True


def test_revoke_sessions_logs_the_account_out_everywhere(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    second = auth_env.client(**bearer(auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)))
    assert second.get("/api/v1/auth/me").status_code == 200
    assert owner.client.delete(f"{A}/users/{friend.user_id}/sessions").status_code == 204
    assert friend.client.get("/api/v1/auth/me").status_code == 401
    assert second.get("/api/v1/auth/me").status_code == 401
    assert auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)  # not a lock: logging in again works
    actions = [(a["action"], a["detail"]) for a in audit_rows(auth_env)]
    assert ("sessions_revoked", {"count": 2}) in actions


def test_user_admin_is_audited_without_secrets(
    auth_env: AuthEnv, owner: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    uid, temp = mk_user(owner, "erin")
    assert owner.client.patch(f"{A}/users/{uid}", json={"disabled": True}).status_code == 200
    assert owner.client.patch(f"{A}/users/{uid}", json={"disabled": False}).status_code == 200
    reset = owner.client.post(f"{A}/users/{uid}/password-reset").json()["temporary_password"]
    assert owner.client.delete(f"{A}/users/{uid}/sessions").status_code == 204
    rows = [a for a in audit_rows(auth_env) if a["target"] == uid]
    assert [(a["action"], a["actor"]) for a in rows] == [
        ("user_created", owner.user_id),
        ("user_disabled", owner.user_id),
        ("user_enabled", owner.user_id),
        ("password_reset", owner.user_id),
        ("sessions_revoked", owner.user_id),
    ]
    logs = "\n".join(
        r.getMessage() + json.dumps({k: str(v) for k, v in r.__dict__.items()})
        for r in caplog.records
        if r.name.startswith("yournas")
    )
    blob = logs + json.dumps(audit_rows(auth_env)) + owner.client.get(f"{A}/audit").text
    for secret in (temp, reset, owner.token, "erin"):
        assert secret not in blob, secret


def test_user_creation_is_atomic_with_its_audit_row(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    break_audit(monkeypatch)
    r = owner.client.post(f"{A}/users", json={"username": "frank"})
    assert r.status_code == 500 and "disk I/O" not in r.text
    assert [u["username"] for u in owner.client.get(f"{A}/users").json()] == ["owner"]


# ---- shares -----------------------------------------------------------------------------------


def test_create_share_makes_its_folder_and_grants_the_owner_write(
    auth_env: AuthEnv, owner: Session
) -> None:
    share = mk_share(owner, "Family photos")
    assert re.fullmatch(r"s_[0-9a-f]{16}", share["id"])
    assert share["name"] == "Family photos"
    assert share["grants"] == [{"user_id": owner.user_id, "level": "write"}]
    assert share_dir(auth_env, share["id"]).is_dir()
    spaces = owner.client.get("/api/v1/spaces").json()
    assert {"id": space(share["id"]), "name": "Family photos", "access": "write"} in spaces
    assert owner.client.get(f"/api/v1/spaces/{space(share['id'])}/items").status_code == 200
    rows = audit_rows(auth_env)
    assert [(a["action"], a["type"], a["target"], a["detail"]) for a in rows] == [
        ("share_created", "share", share["id"], None),
        ("grant_set", "grant", f"{share['id']}:{owner.user_id}", {"level": "write"}),
    ]
    assert all(a["actor"] == owner.user_id for a in rows)


@pytest.mark.parametrize(
    "name",
    ["..", "../..", "C:\\Windows", "\\\\host\\share\\x", "/etc/passwd", "a:b", "CON", "x/../y"],
)
def test_a_share_name_is_display_text_and_never_a_path(
    auth_env: AuthEnv, owner: Session, name: str
) -> None:
    before = {p.relative_to(auth_env.storage_root) for p in auth_env.storage_root.rglob("*")}
    share = mk_share(owner, name)
    after = {p.relative_to(auth_env.storage_root) for p in auth_env.storage_root.rglob("*")}
    assert after - before == {Path("shared") / share["id"]}  # exactly the server-named folder
    assert shared_children(auth_env) == [share["id"]]
    assert not (auth_env.storage_root.parent / "x").exists()


@pytest.mark.parametrize(
    "extra", [{"path": "C:\\Windows"}, {"path": "../x"}, {"root": "D:\\"}, {"id": "s_" + "1" * 16}]
)
def test_the_client_cannot_choose_where_a_share_lives(
    auth_env: AuthEnv, owner: Session, extra: dict[str, str]
) -> None:
    r = owner.client.post(f"{A}/shares", json={"name": "ok", **extra})
    assert r.status_code == 400
    assert shared_children(auth_env) == [] and count(auth_env, "shares") == 0


@pytest.mark.parametrize(
    "name",
    [
        "",
        "   ",
        "a\x00b",
        "line\nbreak",
        "tab\there",
        "rtl\u202eoverride",
        "zero\u200bwidth",
        "x" * 65,
    ],
    ids=["empty", "blank", "nul", "newline", "tab", "bidi", "zero-width", "too-long"],
)
def test_invalid_share_names_are_refused(auth_env: AuthEnv, owner: Session, name: str) -> None:
    r = owner.client.post(f"{A}/shares", json={"name": name})
    assert r.status_code == 400
    assert code(r) in ("invalid_share_name", "invalid_request")
    assert shared_children(auth_env) == [] and count(auth_env, "shares") == 0
    assert audit_rows(auth_env) == []


def test_share_names_are_unique_ignoring_case_and_normalization(
    auth_env: AuthEnv, owner: Session
) -> None:
    mk_share(owner, "Café")
    for name in ("café", "CAFÉ", "Cafe\u0301", "  Café  "):
        r = owner.client.post(f"{A}/shares", json={"name": name})
        assert r.status_code == 409 and code(r) == "share_name_taken", name
    assert len(shared_children(auth_env)) == 1  # the refused ones left no folder behind
    assert count(auth_env, "shares") == 1


def test_rename_share(auth_env: AuthEnv, owner: Session) -> None:
    a, b = mk_share(owner, "Alpha"), mk_share(owner, "Beta")
    patch = owner.client.patch
    r = patch(f"{A}/shares/{a['id']}", json={"name": "Gamma"})
    assert r.status_code == 200 and r.json()["name"] == "Gamma" and r.json()["id"] == a["id"]
    assert share_dir(auth_env, a["id"]).is_dir()  # the folder is named by id, never by name
    assert patch(f"{A}/shares/{a['id']}", json={"name": "beta"}).status_code == 409
    assert patch(f"{A}/shares/{a['id']}", json={"name": "\u202e"}).status_code == 400
    assert patch(f"{A}/shares/{ZERO_SHARE}", json={"name": "x"}).status_code == 404
    assert patch(f"{A}/shares/nope", json={"name": "x"}).status_code == 404
    assert patch(f"{A}/shares/{a['id']}", json={"name": "z", "id": b["id"]}).status_code == 400
    assert patch(f"{A}/shares/{a['id']}", json={"name": "Gamma"}).status_code == 200
    renamed = [r for r in audit_rows(auth_env) if r["action"] == "share_renamed"]
    assert [r["target"] for r in renamed] == [a["id"], a["id"]]


def test_list_shares_shows_grants(owner: Session, friend: Session) -> None:
    s = mk_share(owner, "Docs")
    grant(owner, s["id"], friend.user_id, "read")
    listed = owner.client.get(f"{A}/shares").json()
    assert [x["name"] for x in listed] == ["Docs"]
    assert {(g["user_id"], g["level"]) for g in listed[0]["grants"]} == {
        (owner.user_id, "write"),
        (friend.user_id, "read"),
    }


# ---- grants -----------------------------------------------------------------------------------


def test_grant_and_regrant_and_revoke(auth_env: AuthEnv, owner: Session, friend: Session) -> None:
    s = mk_share(owner)
    sp = f"/api/v1/spaces/{space(s['id'])}"
    assert friend.client.get(f"{sp}/items").status_code == 404  # no grant yet
    r = owner.client.put(f"{A}/shares/{s['id']}/grants/{friend.user_id}", json={"level": "read"})
    assert r.status_code == 200 and r.json() == {"user_id": friend.user_id, "level": "read"}
    assert friend.client.get(f"{sp}/items").status_code == 200
    assert friend.client.post(f"{sp}/folders", json={"path": "n"}).status_code == 403
    grant(owner, s["id"], friend.user_id, "write")  # upsert, not a second row
    assert friend.client.post(f"{sp}/folders", json={"path": "n"}).status_code == 201
    assert count(auth_env, "grants") == 2
    assert owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}").status_code == 204
    assert friend.client.get(f"{sp}/items").status_code == 404
    again = owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}")
    assert again.status_code == 204  # idempotent
    events = [
        (a["action"], a["detail"])
        for a in audit_rows(auth_env)
        if a["target"] == f"{s['id']}:{friend.user_id}"
    ]
    assert events == [
        ("grant_set", {"level": "read"}),
        ("grant_set", {"level": "write"}),
        ("grant_removed", None),  # the second delete changed nothing and left no row
    ]


@pytest.mark.parametrize(
    "body", [{}, {"level": "admin"}, {"level": "WRITE"}, {"level": None}, {"level": "read", "x": 1}]
)
def test_grant_level_is_one_of_read_or_write(owner: Session, friend: Session, body: Any) -> None:
    s = mk_share(owner)
    r = owner.client.put(f"{A}/shares/{s['id']}/grants/{friend.user_id}", json=body)
    assert r.status_code == 400


def test_grants_to_unknown_or_malformed_targets_are_404(owner: Session, friend: Session) -> None:
    s = mk_share(owner)
    for share_id, user_id in (
        (ZERO_SHARE, friend.user_id),
        (s["id"], ZERO_USER),
        ("nope", friend.user_id),
        (s["id"], "nope"),
        (s["id"].upper(), friend.user_id),
    ):
        path = f"{A}/shares/{share_id}/grants/{user_id}"
        assert owner.client.put(path, json={"level": "read"}).status_code == 404, path
        assert owner.client.delete(path).status_code == 404, path


def test_a_disabled_user_can_hold_a_grant_that_works_after_enabling(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner)
    off = owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": True})
    assert off.status_code == 200
    grant(owner, s["id"], friend.user_id, "read")
    assert auth_env.app.state.permissions.spaces_for(friend.user_id) == []  # disabled: nothing
    on = owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": False})
    assert on.status_code == 200
    client = auth_env.client(**bearer(auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)))
    assert client.get(f"/api/v1/spaces/{space(s['id'])}/items").status_code == 200


def test_the_owner_can_revoke_their_own_automatic_grant(owner: Session) -> None:
    s = mk_share(owner)
    sp = f"/api/v1/spaces/{space(s['id'])}"
    assert owner.client.delete(f"{A}/shares/{s['id']}/grants/{owner.user_id}").status_code == 204
    assert owner.client.get(f"{sp}/items").status_code == 404  # the owner role grants nothing
    assert owner.client.get(f"{A}/shares").json()[0]["id"] == s["id"]  # still administrable


def test_revoking_a_grant_stops_an_upload_in_progress(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    sp = f"/api/v1/spaces/{space(s['id'])}"
    uid = friend.client.post(f"{sp}/uploads", json={"path": "f.bin", "size": 4}).json()["upload_id"]
    first = friend.client.patch(
        f"/api/v1/uploads/{uid}", content=b"ab", headers={**OCTET, "Upload-Offset": "0"}
    )
    assert first.status_code == 200
    assert owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}").status_code == 204
    last = friend.client.patch(
        f"/api/v1/uploads/{uid}", content=b"cd", headers={**OCTET, "Upload-Offset": "2"}
    )
    assert last.status_code == 404
    assert not (share_dir(auth_env, s["id"]) / "f.bin").exists()


# ---- deleting a share -------------------------------------------------------------------------


def test_delete_an_empty_share(auth_env: AuthEnv, owner: Session, friend: Session) -> None:
    keep = mk_share(owner, "Keep")
    s = mk_share(owner, "Temp")
    grant(owner, s["id"], friend.user_id, "read")
    (share_dir(auth_env, keep["id"]) / "precious.txt").write_bytes(b"precious")
    r = owner.client.delete(f"{A}/shares/{s['id']}")
    assert r.status_code == 204
    assert not share_dir(auth_env, s["id"]).exists()
    assert [x["id"] for x in owner.client.get(f"{A}/shares").json()] == [keep["id"]]
    assert count(auth_env, "grants") == 1  # only the owner's grant on `keep` is left
    assert friend.client.get(f"/api/v1/spaces/{space(s['id'])}/items").status_code == 404
    assert space(s["id"]) not in [x["id"] for x in friend.client.get("/api/v1/spaces").json()]
    assert (share_dir(auth_env, keep["id"]) / "precious.txt").read_bytes() == b"precious"
    deleted = [a for a in audit_rows(auth_env) if a["action"] == "share_deleted"]
    assert [(a["actor"], a["type"], a["target"], a["detail"]) for a in deleted] == [
        (owner.user_id, "share", s["id"], {"count": 2})  # grants removed with the share
    ]
    assert owner.client.post(f"{A}/shares", json={"name": "Temp"}).json()["id"] != s["id"]
    assert owner.client.delete(f"{A}/shares/{s['id']}").status_code == 404  # gone for good


def _nested(d: Path) -> None:
    (d / "sub").mkdir()
    (d / "sub" / "deep.txt").write_bytes(b"x")


@pytest.mark.parametrize(
    "populate",
    [
        lambda d: (d / "file.txt").write_bytes(b"data"),
        lambda d: (d / "sub").mkdir(),
        _nested,
        lambda d: (d / ".hidden").write_bytes(b"x"),
        lambda d: (d / "e\u0301.txt").write_bytes(b"not nfc, invisible in listings"),
        lambda d: (d / "empty.txt").write_bytes(b""),
    ],
    ids=["file", "empty-folder", "nested", "hidden", "not-nfc", "empty-file"],
)
def test_a_share_with_anything_inside_is_never_deleted(
    auth_env: AuthEnv, owner: Session, friend: Session, populate: Callable[[Path], object]
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    d = share_dir(auth_env, s["id"])
    populate(d)
    tree = sorted(str(p.relative_to(d)) for p in d.rglob("*"))
    audit_before = audit_rows(auth_env)
    r = owner.client.delete(f"{A}/shares/{s['id']}")
    assert r.status_code == 409 and code(r) == "not_empty"
    assert sorted(str(p.relative_to(d)) for p in d.rglob("*")) == tree  # no file touched
    assert count(auth_env, "shares") == 1 and count(auth_env, "grants") == 2  # nothing changed
    assert audit_rows(auth_env) == audit_before  # a refused delete leaves no row
    assert friend.client.get(f"/api/v1/spaces/{space(s['id'])}/items").status_code == 200


def test_delete_works_when_the_folder_is_already_gone(auth_env: AuthEnv, owner: Session) -> None:
    s = mk_share(owner)
    share_dir(auth_env, s["id"]).rmdir()
    assert owner.client.delete(f"{A}/shares/{s['id']}").status_code == 204
    assert count(auth_env, "shares") == 0


def test_delete_drops_unfinished_uploads_into_the_share_only(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s, other = mk_share(owner, "A"), mk_share(owner, "B")
    for sh in (s, other):
        grant(owner, sh["id"], friend.user_id, "write")
    sp, osp = (f"/api/v1/spaces/{space(x['id'])}" for x in (s, other))
    u1 = friend.client.post(f"{sp}/uploads", json={"path": "a.bin", "size": 4}).json()["upload_id"]
    u2 = friend.client.post(f"{osp}/uploads", json={"path": "b.bin", "size": 4}).json()["upload_id"]
    for uid in (u1, u2):
        friend.client.patch(
            f"/api/v1/uploads/{uid}", content=b"ab", headers={**OCTET, "Upload-Offset": "0"}
        )
    assert len(list((auth_env.storage_root / ".yournas-tmp").glob("*.part"))) == 2
    assert owner.client.delete(f"{A}/shares/{s['id']}").status_code == 204
    with auth_env.db.read() as conn:
        left = [r["id"] for r in conn.execute("SELECT id FROM uploads")]
    assert left == [u2]
    assert [p.stem for p in (auth_env.storage_root / ".yournas-tmp").glob("*.part")] == [u2]
    gone = friend.client.patch(
        f"/api/v1/uploads/{u1}", content=b"cd", headers={**OCTET, "Upload-Offset": "2"}
    )
    assert gone.status_code == 404
    still = friend.client.patch(
        f"/api/v1/uploads/{u2}", content=b"cd", headers={**OCTET, "Upload-Offset": "2"}
    )
    assert still.status_code == 200 and still.json()["complete"] is True


def test_delete_never_follows_a_junction(auth_env: AuthEnv, owner: Session, tmp_path: Path) -> None:
    s = mk_share(owner)
    d = share_dir(auth_env, s["id"])
    d.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(d), str(outside)], capture_output=True, text=True
    )
    if made.returncode != 0:
        pytest.skip(f"cannot create junction: {made.stderr.strip()}")
    try:
        r = owner.client.delete(f"{A}/shares/{s['id']}")
        assert r.status_code == 409 and code(r) == "not_empty"
        assert (outside / "keep.txt").read_text() == "keep"
        assert count(auth_env, "shares") == 1
    finally:
        d.rmdir()  # removes the junction only


def test_delete_share_is_atomic_with_its_audit_row(
    auth_env: AuthEnv, owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = mk_share(owner)
    break_audit(monkeypatch)
    r = owner.client.delete(f"{A}/shares/{s['id']}")
    assert r.status_code == 500
    assert count(auth_env, "shares") == 1 and count(auth_env, "grants") == 1
    assert share_dir(auth_env, s["id"]).is_dir()


def test_share_changes_are_atomic_with_their_audit_rows(
    auth_env: AuthEnv, owner: Session, friend: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = mk_share(owner, "Base")
    rows_before = audit_rows(auth_env)
    break_audit(monkeypatch)
    assert owner.client.post(f"{A}/shares", json={"name": "New"}).status_code == 500
    assert shared_children(auth_env) == [s["id"]]  # the folder made first was taken back
    assert [x["name"] for x in owner.client.get(f"{A}/shares").json()] == ["Base"]
    r = owner.client.put(f"{A}/shares/{s['id']}/grants/{friend.user_id}", json={"level": "read"})
    assert r.status_code == 500 and count(auth_env, "grants") == 1
    assert owner.client.patch(f"{A}/shares/{s['id']}", json={"name": "Other"}).status_code == 500
    assert owner.client.get(f"{A}/shares").json()[0]["name"] == "Base"
    assert audit_rows(auth_env) == rows_before


# ---- the audit route --------------------------------------------------------------------------


def test_audit_route_lists_newest_first_with_paging_and_filters(
    owner: Session, friend: Session
) -> None:
    shares = [mk_share(owner, f"Share {i}") for i in range(4)]  # 2 rows each
    grant(owner, shares[0]["id"], friend.user_id, "read")  # +1
    everything = owner.client.get(f"{A}/audit").json()
    assert everything["next_cursor"] is None
    ids = [e["id"] for e in everything["events"]]
    assert ids == sorted(ids, reverse=True) and len(ids) == 9
    first = everything["events"][0]
    assert set(first) == {"id", "at", "actor_id", "action", "target_type", "target_id", "detail"}
    assert first["action"] == "grant_set" and first["detail"] == {"level": "read"}
    seen: list[int] = []
    cursor: str | None = None
    while True:
        params: dict[str, Any] = {"limit": 4}
        if cursor:
            params["cursor"] = cursor
        page = owner.client.get(f"{A}/audit", params=params).json()
        assert len(page["events"]) <= 4
        seen += [e["id"] for e in page["events"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == ids
    created = owner.client.get(f"{A}/audit", params={"action": "share_created"}).json()["events"]
    assert len(created) == 4
    one = owner.client.get(f"{A}/audit", params={"target_id": shares[1]["id"]}).json()["events"]
    assert {e["action"] for e in one} == {"share_created"}
    mine = owner.client.get(f"{A}/audit", params={"actor_id": owner.user_id}).json()["events"]
    assert len(mine) == 9
    none = owner.client.get(f"{A}/audit", params={"actor_id": friend.user_id}).json()["events"]
    assert none == []


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 501},
        {"limit": "x"},
        {"cursor": "!!!"},
        {"cursor": "AAAA"},
        {"action": "drop_table"},
        {"actor_id": "a b"},
        {"target_id": "x'; DROP TABLE audit_log; --"},
        {"action": "x" * 40},
    ],
)
def test_audit_route_rejects_bad_parameters(
    auth_env: AuthEnv, owner: Session, params: dict[str, Any]
) -> None:
    mk_share(owner)
    r = owner.client.get(f"{A}/audit", params=params)
    assert r.status_code == 400, r.text
    assert count(auth_env, "audit_log") == 2  # nothing was written or dropped


def test_audit_rows_never_hold_names_or_secrets(auth_env: AuthEnv, owner: Session) -> None:
    mk_share(owner, "TopSecretShareName")
    uid, temp = mk_user(owner, "hushhush")
    owner.client.put(f"{A}/shares/{ZERO_SHARE}/grants/{uid}", json={"level": "read"})
    text = json.dumps(audit_rows(auth_env)) + owner.client.get(f"{A}/audit").text
    for secret in ("TopSecretShareName", "hushhush", temp, owner.token, str(auth_env.storage_root)):
        assert secret not in text, secret
