"""Phase 4 step 4 (QA): security regression over the whole Phase 4 surface.

Not a feature test: every test here attacks the boundary the earlier steps built (failed-login
abuse, CORS, secret leakage, the role x route matrix, hostile paths and links in shares, the share
lifecycle, upload revocation, audit atomicity, concurrency) and fails if the boundary moves.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import (
    FRIEND_NAME,
    FRIEND_PASSWORD,
    OWNER_NAME,
    OWNER_PASSWORD,
    AuthEnv,
    Session,
    bearer,
    routes_of,
)
from test_admin_api import (
    ZERO_SHARE,
    ZERO_USER,
    A,
    break_audit,
    code,
    count,
    grant,
    mk_share,
    mk_user,
    share_dir,
    space,
)
from test_file_authz import OCTET, UPLOADS, fingerprint, patch, snapshot, start_upload

from yournas.auth.throttle import MAX_THROTTLE_ROWS
from yournas.uploads import UploadService

PUBLIC = {("GET", "/health"), ("POST", "/api/v1/auth/login")}
LOGOUT = ("POST", "/api/v1/auth/logout")
LOGIN = "/api/v1/auth/login"


def fill_ids(path: str) -> str:
    return (
        path.replace("{space}", "home")
        .replace("{upload_id}", "0" * 32)
        .replace("{user_id}", ZERO_USER)
        .replace("{share_id}", ZERO_SHARE)
    )


def all_routes(env: AuthEnv) -> list[tuple[str, str]]:
    found = sorted(routes_of(env.app))
    assert len(found) >= 29  # the pinned surface has 29 routes: never a vacuous loop
    return found


def protected_routes(env: AuthEnv) -> list[tuple[str, str]]:
    return [r for r in all_routes(env) if r not in PUBLIC]


def safe_routes(env: AuthEnv) -> list[tuple[str, str]]:
    """Every route except logout, so one loop can keep using the same session."""
    return [r for r in all_routes(env) if r != LOGOUT]


TABLES = ("users", "sessions", "shares", "grants", "uploads", "audit_log", "login_throttle")


def db_state(env: AuthEnv, tables: tuple[str, ...] = TABLES) -> dict[str, list[tuple[Any, ...]]]:
    out: dict[str, list[tuple[Any, ...]]] = {}
    with env.db.read() as conn:
        for t in tables:
            rows = conn.execute(f"SELECT * FROM {t} ORDER BY 1, 2").fetchall()  # noqa: S608
            out[t] = [tuple(r) for r in rows]
    return out


def audit_trail(env: AuthEnv) -> list[tuple[str, str, Any, str]]:
    with env.db.read() as conn:
        rows = conn.execute(
            "SELECT action, target_type, detail, target_id FROM audit_log ORDER BY id"
        ).fetchall()
    return [
        (
            r["action"],
            r["target_type"],
            json.loads(r["detail"]) if r["detail"] else None,
            r["target_id"],
        )
        for r in rows
    ]


def log_text(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        r.getMessage() + json.dumps({k: str(v) for k, v in r.__dict__.items()})
        for r in caplog.records
        if r.name.startswith("yournas")
    )


# ---- A. failed-login abuse --------------------------------------------------------------------


def attempt(client: Any, user: str, password: str) -> Any:
    return client.post(LOGIN, json={"username": user, "password": password})


def test_1000_failed_logins_against_one_account_are_bounded_and_harmless(
    auth_env: AuthEnv,
) -> None:
    before = db_state(auth_env, ("users", "sessions", "audit_log"))
    client = auth_env.client(host="127.0.0.1")  # loopback peer: only the account is throttled
    statuses = [attempt(client, OWNER_NAME, f"wrong password {i}").status_code for i in range(1000)]
    assert set(statuses) <= {401, 429}  # never a 200, never a 5xx
    assert 1 <= statuses.count(401) <= 10  # a handful of free tries, then the account locks
    assert statuses.count(429) >= 990
    locked = attempt(client, OWNER_NAME, "wrong again")
    assert locked.status_code == 429 and 0 < int(locked.headers["retry-after"]) <= 15 * 60
    assert "wrong again" not in locked.text
    # Nothing else moved: no session, no audit row, no change to the account.
    assert db_state(auth_env, ("users", "sessions", "audit_log")) == before
    assert count(auth_env, "login_throttle") <= 2
    # The lock is temporary and the account is intact: the right password works afterwards.
    auth_env.clock.advance(16 * 60)
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 200


def test_1000_failed_logins_from_one_address_lock_the_address(auth_env: AuthEnv) -> None:
    client = auth_env.client(host="100.64.0.7")  # a tailnet-style, non-loopback address
    statuses = [
        attempt(client, f"nobody{i:04d}", "wrong password").status_code for i in range(1000)
    ]
    assert set(statuses) <= {401, 429}
    assert statuses.count(401) <= 21  # ADDRESS_FREE_FAILURES plus the charge that locks
    assert statuses.count(429) >= 979
    # Even the real owner is refused from that address while it is locked ...
    assert attempt(client, OWNER_NAME, OWNER_PASSWORD).status_code == 429
    # ... but not from another one.
    other = auth_env.client(host="100.64.0.8")
    assert attempt(other, OWNER_NAME, OWNER_PASSWORD).status_code == 200
    assert count(auth_env, "login_throttle") <= 25
    assert count(auth_env, "audit_log") == 0


def test_a_flood_of_distinct_unknown_names_cannot_grow_state_without_bound(
    auth_env: AuthEnv,
) -> None:
    client = auth_env.client(host="127.0.0.1")
    for i in range(1000):
        r = attempt(client, f"ghost{i:04d}", "wrong password")
        assert r.status_code == 401, i
    assert count(auth_env, "login_throttle") <= MAX_THROTTLE_ROWS
    assert count(auth_env, "sessions") == 0 and count(auth_env, "audit_log") == 0
    assert count(auth_env, "users") == 1


def test_failed_logins_do_not_reveal_which_accounts_exist(
    auth_env: AuthEnv, friend: Session
) -> None:
    c = auth_env.client(host="127.0.0.1")
    owner_id = auth_env.service.list_users()[0].id
    auth_env.service.set_disabled(owner_id, friend.user_id, True)
    unknown = fingerprint(attempt(c, "no-such-person", "wrong password 1"))
    wrong = fingerprint(attempt(c, OWNER_NAME, "wrong password 2"))
    disabled = fingerprint(attempt(c, FRIEND_NAME, FRIEND_PASSWORD))  # right password, disabled
    assert unknown == wrong == disabled
    body = json.loads(unknown[1])
    assert body["error"]["code"] == "invalid_credentials"
    text = unknown[1].replace("invalid_credentials", "") + str(unknown[2])
    for leak in ("argon2", "token", "hash", "no-such-person", OWNER_NAME, FRIEND_NAME):
        assert leak not in text, leak


# ---- B. CORS ----------------------------------------------------------------------------------

ORIGINS = ["https://evil.example", "null", "http://localhost:3000", "https://trusted.example"]


def has_cors(headers: Any) -> bool:
    return any(h.lower().startswith("access-control-") for h in headers)


def test_no_cors_middleware_is_installed(auth_env: AuthEnv) -> None:
    names = {getattr(m.cls, "__name__", str(m.cls)) for m in auth_env.app.user_middleware}
    assert names  # the list is real: our own middlewares are in it
    assert not any("cors" in n.lower() for n in names), names


@pytest.mark.parametrize("origin", ORIGINS)
def test_no_route_ever_sends_cors_headers(auth_env: AuthEnv, owner: Session, origin: str) -> None:
    for method, path in safe_routes(auth_env):
        r = owner.client.request(method, fill_ids(path), headers={"Origin": origin})
        assert not has_cors(r.headers), (method, path)
        assert r.status_code < 500, (method, path)
    anon = auth_env.client()
    for method, path in all_routes(auth_env):
        r = anon.request(method, fill_ids(path), headers={"Origin": origin})
        assert not has_cors(r.headers), (method, path)


@pytest.mark.parametrize("origin", ORIGINS)
def test_preflight_requests_are_not_answered_with_permission(
    auth_env: AuthEnv, owner: Session, origin: str
) -> None:
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "DELETE",
        "Access-Control-Request-Headers": "authorization,content-type",
    }
    for _method, path in all_routes(auth_env):
        for who in (owner.client, auth_env.client()):
            r = who.options(fill_ids(path), headers=headers)
            assert r.status_code in (400, 401, 403, 404, 405), (path, r.status_code)
            assert not has_cors(r.headers), path


def test_a_credentialed_cross_origin_request_gets_no_browser_permission(
    owner: Session,
) -> None:
    r = owner.client.get(
        f"{A}/users", headers={"Origin": "https://evil.example", "Cookie": "session=abc"}
    )
    assert r.status_code == 200  # a non-browser client is served ...
    assert not has_cors(r.headers)  # ... but a browser is given no permission to read it


# ---- C. password echo and secret leakage ------------------------------------------------------

MARK = "ZZ-secret-marker-ZZ"


def test_validation_errors_never_echo_what_was_sent(
    auth_env: AuthEnv, owner: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    bad = {
        "password": {"x": MARK},
        "current": [MARK],
        "new": 123,
        "username": [MARK],
        "name": {"a": MARK},
        "level": {"x": MARK},
        "disabled": [MARK],
        "path": [MARK],
        "size": MARK,
        "zz_unknown": MARK,
    }
    writes = [
        r
        for r in safe_routes(auth_env)
        if r[0] in ("POST", "PUT", "PATCH", "DELETE") and not r[1].startswith("/api/v1/uploads/")
    ]
    assert len(writes) >= 12
    for client in (owner.client, auth_env.client()):
        for method, path in writes:
            r = client.request(method, fill_ids(path), json=bad)
            assert r.status_code < 500, (method, path)
            assert MARK not in r.text, (method, path, r.text)
            assert MARK not in json.dumps(dict(r.headers)), (method, path)
    # Real wrong values on the password routes.
    r = attempt(auth_env.client(), OWNER_NAME, MARK)
    assert r.status_code == 401 and MARK not in r.text
    r = owner.client.post("/api/v1/auth/password", json={"current": MARK, "new": MARK + "-new"})
    assert r.status_code in (400, 403) and MARK not in r.text
    r = owner.client.post(
        "/api/v1/auth/password", json={"current": OWNER_PASSWORD, "new": "aaaaaaaaaaaa"}
    )
    assert r.status_code == 400 and "aaaaaaaaaaaa" not in r.text  # weak password, not echoed
    logs = log_text(caplog)
    for secret in (MARK, "aaaaaaaaaaaa", OWNER_PASSWORD, FRIEND_PASSWORD):
        assert secret not in logs


def test_no_response_carries_hashes_tokens_or_credentials(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    _uid, temp = mk_user(owner, "hana")
    s = mk_share(owner, "Docs")
    grant(owner, s["id"], friend.user_id, "read")
    secrets_ = (owner.token, friend.token, temp, OWNER_PASSWORD, FRIEND_PASSWORD, "token_hash")
    gets = [p for m, p in all_routes(auth_env) if m == "GET" and p != "/health"]
    assert len(gets) >= 8
    for client in (owner.client, friend.client):
        for path in gets:
            real = path.replace("{space}", space(s["id"])).replace("{upload_id}", "0" * 32)
            r = client.get(real, params={"path": ""})
            blob = r.text + json.dumps(dict(r.headers))
            assert "password_hash" not in blob and "$argon2" not in blob, path
            for secret in secrets_:
                assert secret not in blob, (path, secret[:6])
    for u in owner.client.get(f"{A}/users").json():
        assert not set(u) & {"password", "password_hash", "temporary_password", "token"}


def test_the_temporary_password_exists_only_in_its_response(
    auth_env: AuthEnv, owner: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    r = owner.client.post(f"{A}/users", json={"username": "ivy"})
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    uid, temp = r.json()["id"], r.json()["temporary_password"]
    reset = owner.client.post(f"{A}/users/{uid}/password-reset")
    assert reset.headers["cache-control"] == "no-store"
    temp2 = reset.json()["temporary_password"]
    assert temp2 != temp
    token = auth_env.login("ivy", temp2)
    ivy = auth_env.client(**bearer(token))
    later = [
        owner.client.get(f"{A}/users"),
        owner.client.get(f"{A}/audit"),
        owner.client.get(f"{A}/shares"),
        ivy.get("/api/v1/auth/me"),
        owner.client.delete(f"{A}/users/{uid}/sessions"),
    ]
    for resp in later:
        assert temp not in resp.text and temp2 not in resp.text
        assert "temporary_password" not in resp.text
    with auth_env.db.read() as conn:
        dump: dict[str, Any] = {}
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            dump[name] = [tuple(row) for row in conn.execute(f"SELECT * FROM {name}")]  # noqa: S608
    flat = json.dumps(dump, default=str)
    for secret in (temp, temp2, token, owner.token):
        assert secret not in flat, "plaintext secret stored in the database"
    assert flat.count("$argon2") == count(auth_env, "users")  # hashes live in users only
    logs = log_text(caplog)
    for secret in (temp, temp2, token, owner.token, OWNER_PASSWORD):
        assert secret not in logs


# ---- D. authorization matrix ------------------------------------------------------------------


def test_disabled_account_is_locked_out_of_every_route(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    sp = f"/api/v1/spaces/{space(s['id'])}"
    assert friend.client.get(f"{sp}/items").status_code == 200
    off = owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": True})
    assert off.status_code == 200
    for method, path in protected_routes(auth_env):
        r = friend.client.request(method, fill_ids(path))
        assert r.status_code == 401, (method, path, r.status_code)
    assert friend.client.get(f"{sp}/items").status_code == 401
    # Re-enabling does not resurrect the old token, and the grant is still there afterwards.
    owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": False})
    assert friend.client.get("/api/v1/auth/me").status_code == 401
    fresh = auth_env.client(**bearer(auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)))
    assert fresh.get(f"{sp}/items").status_code == 200


def test_anonymous_is_401_and_a_friend_403_on_every_admin_route(
    auth_env: AuthEnv, friend: Session
) -> None:
    anon = auth_env.client()
    for method, path in protected_routes(auth_env):
        assert anon.request(method, fill_ids(path)).status_code == 401, (method, path)
    for method, path in safe_routes(auth_env):
        if method == "GET" and path == "/health" or (method, path) in PUBLIC:
            continue
        r = friend.client.request(method, fill_ids(path))
        assert r.status_code < 500, (method, path)
        if path.startswith(A):
            assert r.status_code == 403, (method, path)


def test_forged_identity_on_every_route_changes_nothing(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    mine = friend.client.get("/api/v1/spaces").json()
    forged = {
        "X-User-Id": owner.user_id,
        "X-Role": "owner",
        "X-Forwarded-User": owner.user_id,
        "X-Original-User": OWNER_NAME,
        "X-Auth-User": owner.user_id,
        "Remote-User": OWNER_NAME,
    }
    params = {"user_id": owner.user_id, "role": "owner", "as": OWNER_NAME, "owner": "1"}
    body = {"user_id": owner.user_id, "role": "owner", "actor_id": owner.user_id}
    for method, path in safe_routes(auth_env):
        if (method, path) in PUBLIC:
            continue
        r = friend.client.request(method, fill_ids(path), headers=forged, params=params, json=body)
        assert r.status_code < 500, (method, path)
        if path.startswith(A):
            assert r.status_code == 403, (method, path)
    # Distinct contents in the two homes: a forged header must not make the server read the
    # other user's folder (the names alone would not tell).
    (owner.home / "who.txt").write_bytes(b"owner-home")
    (friend.home / "who.txt").write_bytes(b"friend-home")
    for forged_by in (forged, {"X-User-Id": owner.user_id}, {"Authorization-User": owner.user_id}):
        r = friend.client.get(
            "/api/v1/spaces/home/files", params={"path": "who.txt", **params}, headers=forged_by
        )
        assert r.status_code == 200 and r.content == b"friend-home"
    assert friend.client.get("/api/v1/spaces", headers=forged, params=params).json() == mine
    assert friend.client.get("/api/v1/auth/me", headers=forged).json()["id"] == friend.user_id
    # Nothing was created or changed by any of that.
    assert count(auth_env, "shares") == 0 and count(auth_env, "users") == 2
    assert count(auth_env, "audit_log") == 0


FUZZ = [
    "%00",
    "..%2f..",
    "%2e%2e",
    "a" * 1500,
    "%C3%BC" * 20,
    "%F0%9F%92%A9",
    "u_" + "g" * 16,
    "s_" + "0" * 15,
    "S_" + "0" * 16,
    "%20",
    "null",
    "%7Buser_id%7D",
    "%5C",
    "x%0d%0ay",
    "0" * 33,
    "-1",
]


@pytest.mark.parametrize("who", ["owner", "friend"])
def test_malformed_ids_never_cause_a_5xx_or_a_bypass(
    auth_env: AuthEnv, owner: Session, friend: Session, who: str
) -> None:
    client = (owner if who == "owner" else friend).client
    with_ids = [r for r in protected_routes(auth_env) if "{" in r[1]]
    assert len(with_ids) >= 12
    for method, path in with_ids:
        for value in FUZZ:
            url = re.sub(r"\{[^}]+\}", value, path)
            r = client.request(method, url, json={"level": "read", "disabled": True, "name": "x"})
            assert r.status_code < 500, (method, url[:60], r.status_code)
            if who == "friend" and path.startswith(A):
                assert r.status_code in (403, 404, 405), (method, url[:60], r.status_code)
            if who == "owner" and path.startswith(A):
                assert r.status_code in (400, 404, 405, 413), (method, url[:60], r.status_code)
    assert count(auth_env, "shares") == 0 and count(auth_env, "audit_log") == 0


# ---- E. hostile paths and links inside shares -------------------------------------------------

HOSTILE = [
    "../x",
    "..\\x",
    "C:\\x",
    "C:/x",
    "\\\\h\\s\\x",
    "//h/s/x",
    "/abs",
    "a/../../x",
    "x:y",
    "CON",
    "nul.txt",
    "a/./b",
    "a//b",
    "x\x00y",
    "\u202eevil",
    "a/",
    "trail.",
]


def test_hostile_paths_never_leave_a_share_or_change_anything(
    auth_env: AuthEnv, owner: Session, friend: Session, tmp_path: Path
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("untouched")
    before = snapshot(auth_env)
    audit_before = len(audit_trail(auth_env))
    sp = f"/api/v1/spaces/{space(s['id'])}"
    for path in HOSTILE:
        for client in (friend.client, owner.client):
            probes = [
                client.get(f"{sp}/items", params={"path": path}),
                client.get(f"{sp}/items/meta", params={"path": path}),
                client.get(f"{sp}/files", params={"path": path}),
                client.delete(f"{sp}/items", params={"path": path, "recursive": "true"}),
                client.post(f"{sp}/folders", json={"path": path}),
                client.post(f"{sp}/uploads", json={"path": path, "size": 3}),
            ]
            for r in probes:
                assert r.status_code in (400, 404), (path, r.request.method, r.status_code)
    assert snapshot(auth_env) == before
    assert sentinel.read_text() == "untouched"
    assert count(auth_env, "uploads") == 0
    assert len(audit_trail(auth_env)) == audit_before  # nothing hostile reached an audit row


@pytest.mark.parametrize("kind", ["junction", "symlink"])
def test_a_link_inside_a_share_is_never_followed(
    auth_env: AuthEnv, owner: Session, friend: Session, tmp_path: Path, kind: str
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    d = share_dir(auth_env, s["id"])
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    link = d / "link"
    if kind == "junction":
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, text=True
        )
        if made.returncode != 0:
            pytest.skip(f"cannot create junction: {made.stderr.strip()}")
    else:
        try:
            os.symlink(outside, link, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"cannot create symlink: {exc}")
    sp = f"/api/v1/spaces/{space(s['id'])}"
    try:
        listed = friend.client.get(f"{sp}/items").json()["items"]
        assert [i["name"] for i in listed] == []  # the link is not even listed
        r = friend.client.get(f"{sp}/files", params={"path": "link/secret.txt"})
        assert r.status_code == 404
        assert friend.client.get(f"{sp}/items/meta", params={"path": "link"}).status_code == 404
        assert friend.client.get(f"{sp}/items", params={"path": "link"}).status_code == 404
        assert friend.client.post(f"{sp}/folders", json={"path": "link/new"}).status_code == 404
        r = friend.client.post(f"{sp}/uploads", json={"path": "link/x.bin", "size": 3})
        assert r.status_code == 404
        friend.client.delete(f"{sp}/items", params={"path": "link", "recursive": "true"})
        friend.client.delete(f"{sp}/items", params={"path": "link/secret.txt"})
        assert (outside / "secret.txt").read_text() == "secret"  # nothing outside was touched
        assert sorted(p.name for p in outside.iterdir()) == ["secret.txt"]
        # The share cannot be deleted while something (a link included) sits in its folder.
        if os.path.lexists(link):
            r = owner.client.delete(f"{A}/shares/{s['id']}")
            assert r.status_code == 409 and code(r) == "not_empty"
            assert (outside / "secret.txt").read_text() == "secret"
    finally:
        if os.path.lexists(link):
            os.rmdir(link)  # removes the link only, never what it points to


# ---- F. the whole share lifecycle -------------------------------------------------------------


def test_share_lifecycle_from_creation_to_deletion(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    other = mk_share(owner, "Other")
    (share_dir(auth_env, other["id"]) / "private.txt").write_bytes(b"not for the friend")
    # 1-2: owner creates a share and grants the friend read.
    s = mk_share(owner, "Trip")
    sp = f"/api/v1/spaces/{space(s['id'])}"
    (share_dir(auth_env, s["id"]) / "plan.txt").write_bytes(b"the plan")
    grant(owner, s["id"], friend.user_id, "read")
    # 3-4: the friend reads the share and nothing outside it.
    assert friend.client.get(f"{sp}/files", params={"path": "plan.txt"}).content == b"the plan"
    osp = f"/api/v1/spaces/{space(other['id'])}"
    assert friend.client.get(f"{osp}/items").status_code == 404
    assert friend.client.get(f"{osp}/files", params={"path": "private.txt"}).status_code == 404
    assert friend.client.get(f"{sp}/files", params={"path": "../private.txt"}).status_code == 400
    listed = [x["id"] for x in friend.client.get("/api/v1/spaces").json()]
    assert listed == ["home", space(s["id"])]
    # 5: upgrade and downgrade.
    assert friend.client.post(f"{sp}/folders", json={"path": "new"}).status_code == 403
    grant(owner, s["id"], friend.user_id, "write")
    assert friend.client.post(f"{sp}/folders", json={"path": "new"}).status_code == 201
    grant(owner, s["id"], friend.user_id, "read")
    assert friend.client.post(f"{sp}/folders", json={"path": "new2"}).status_code == 403
    assert friend.client.get(f"{sp}/items").status_code == 200
    # 6-7: revoke.
    assert owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}").status_code == 204
    assert friend.client.get(f"{sp}/items").status_code == 404
    assert space(s["id"]) not in [x["id"] for x in friend.client.get("/api/v1/spaces").json()]
    # 9-10: a non-empty share is refused and nothing is deleted, whatever is inside.
    before = snapshot(auth_env)
    state = db_state(auth_env, ("shares", "grants", "audit_log"))
    r = owner.client.delete(f"{A}/shares/{s['id']}")
    assert r.status_code == 409 and code(r) == "not_empty"
    assert snapshot(auth_env) == before
    assert db_state(auth_env, ("shares", "grants", "audit_log")) == state
    # 8, 11: empty it (the owner removes the files, the server never does), then delete.
    grant(owner, s["id"], friend.user_id, "read")
    d = share_dir(auth_env, s["id"])
    for p in sorted(d.rglob("*"), reverse=True):
        if p.is_dir():
            p.rmdir()
        else:
            p.unlink()
    assert owner.client.delete(f"{A}/shares/{s['id']}").status_code == 204
    assert not d.exists()
    with auth_env.db.read() as conn:
        grants = conn.execute("SELECT COUNT(*) FROM grants WHERE share_id = ?", (s["id"],))
        shares = conn.execute("SELECT COUNT(*) FROM shares WHERE id = ?", (s["id"],))
        assert grants.fetchone()[0] == 0 and shares.fetchone()[0] == 0
    assert friend.client.get(f"{sp}/items").status_code == 404
    # 12: the audit trail of the whole story, ids and counters only.
    mine = [a for a in audit_trail(auth_env) if s["id"] in a[3]]
    assert [a[0] for a in mine] == [
        "share_created",
        "grant_set",  # the creator's automatic grant
        "grant_set",  # friend: read
        "grant_set",  # friend: write
        "folder_created",  # the friend's mkdir while they held write (share events are audited)
        "grant_set",  # friend: read again
        "grant_removed",
        "grant_set",  # friend: read once more
        "share_deleted",
    ]
    assert [a[2] for a in mine if a[0] == "share_deleted"] == [{"count": 2}]
    # The other share and its file are untouched by all of it.
    assert (share_dir(auth_env, other["id"]) / "private.txt").read_bytes() == b"not for the friend"


def test_failed_operations_leave_no_partial_state(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner, "Base")
    mk_share(owner, "Taken")
    grant(owner, s["id"], friend.user_id, "read")
    (share_dir(auth_env, s["id"]) / "f.txt").write_bytes(b"x")
    state, tree = db_state(auth_env), snapshot(auth_env)
    sg = f"{A}/shares/{s['id']}/grants"
    failing = [
        (owner.client.post(f"{A}/shares", json={"name": "taken"}), 409),
        (owner.client.post(f"{A}/shares", json={"name": "\u202e"}), 400),
        (owner.client.patch(f"{A}/shares/{s['id']}", json={"name": "TAKEN"}), 409),
        (owner.client.delete(f"{A}/shares/{s['id']}"), 409),
        (owner.client.put(f"{sg}/{ZERO_USER}", json={"level": "read"}), 404),
        (
            owner.client.put(
                f"{A}/shares/{ZERO_SHARE}/grants/{friend.user_id}", json={"level": "read"}
            ),
            404,
        ),
        (owner.client.put(f"{sg}/{friend.user_id}", json={"level": "root"}), 400),
        (owner.client.delete(f"{A}/shares/{ZERO_SHARE}"), 404),
        (owner.client.post(f"{A}/users", json={"username": "friend"}), 409),
        (owner.client.post(f"{A}/users", json={"username": "admin"}), 409),
        (owner.client.patch(f"{A}/users/{owner.user_id}", json={"disabled": True}), 400),
        (owner.client.post(f"{A}/users/{owner.user_id}/password-reset"), 400),
        (owner.client.patch(f"{A}/users/{ZERO_USER}", json={"disabled": True}), 404),
    ]
    assert [r.status_code for r, _ in failing] == [want for _, want in failing]
    assert db_state(auth_env) == state
    assert snapshot(auth_env) == tree


# ---- G. upload revocation ---------------------------------------------------------------------


def test_the_last_check_before_the_file_appears_holds_even_if_the_earlier_ones_are_skipped(
    auth_env: AuthEnv, owner: Session, friend: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulates the race (access lost between the in-lock check and the final move): the
    earlier re-authorizations are disabled, so only `_complete`'s own check can stop the file."""
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    uid = start_upload(friend, space(s["id"]), "up.bin", 4).json()["upload_id"]
    assert patch(friend, uid, 0, b"ab").status_code == 200
    original = UploadService._find

    def no_access_check(self: UploadService, user_id: str, upload_id: str, **_k: Any) -> Any:
        return original(self, user_id, upload_id, check_access=False)

    monkeypatch.setattr(UploadService, "_find", no_access_check)
    assert owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}").status_code == 204
    r = patch(friend, uid, 2, b"cd")
    assert r.status_code == 404
    assert not (share_dir(auth_env, s["id"]) / "up.bin").exists()


def test_an_upload_row_cannot_be_pointed_at_a_space_the_user_cannot_use(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    mine, theirs = mk_share(owner, "Mine"), mk_share(owner, "Theirs")
    grant(owner, mine["id"], friend.user_id, "write")
    uid = start_upload(friend, space(mine["id"]), "up.bin", 4).json()["upload_id"]
    assert patch(friend, uid, 0, b"ab").status_code == 200
    with auth_env.db.transaction() as conn:  # a tampered row: the user holds no grant on it
        conn.execute("UPDATE uploads SET space = ? WHERE id = ?", (space(theirs["id"]), uid))
    assert patch(friend, uid, 2, b"cd").status_code == 404
    assert friend.client.get(f"{UPLOADS}/{uid}").status_code == 404
    for sh in (mine, theirs):
        assert not (share_dir(auth_env, sh["id"]) / "up.bin").exists()


def test_a_disabled_account_cannot_continue_an_upload_and_can_after_a_fresh_login(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    uid = start_upload(friend, space(s["id"]), "up.bin", 4).json()["upload_id"]
    assert patch(friend, uid, 0, b"ab").status_code == 200
    owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": True})
    assert patch(friend, uid, 2, b"cd").status_code == 401
    assert not (share_dir(auth_env, s["id"]) / "up.bin").exists()
    owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": False})
    assert patch(friend, uid, 2, b"cd").status_code == 401  # the old token stays dead
    fresh = auth_env.client(**bearer(auth_env.login(FRIEND_NAME, FRIEND_PASSWORD)))
    done = fresh.patch(f"{UPLOADS}/{uid}", content=b"cd", headers={**OCTET, "Upload-Offset": "2"})
    assert done.status_code == 200 and done.json()["complete"] is True
    assert (share_dir(auth_env, s["id"]) / "up.bin").read_bytes() == b"abcd"


# ---- H. audit atomicity of every admin mutation -----------------------------------------------

CASES = [
    "create-user",
    "disable-user",
    "reset-password",
    "revoke-sessions",
    "create-share",
    "rename-share",
    "delete-share",
    "set-grant",
    "remove-grant",
]


def case_request(
    name: str, owner: Session, friend: Session, share: str, empty: str
) -> tuple[str, str, Any]:
    return {
        "create-user": ("POST", f"{A}/users", {"username": "gina"}),
        "disable-user": ("PATCH", f"{A}/users/{friend.user_id}", {"disabled": True}),
        "reset-password": ("POST", f"{A}/users/{friend.user_id}/password-reset", None),
        "revoke-sessions": ("DELETE", f"{A}/users/{friend.user_id}/sessions", None),
        "create-share": ("POST", f"{A}/shares", {"name": "Brand new"}),
        "rename-share": ("PATCH", f"{A}/shares/{share}", {"name": "Renamed"}),
        "delete-share": ("DELETE", f"{A}/shares/{empty}", None),
        "set-grant": ("PUT", f"{A}/shares/{share}/grants/{owner.user_id}", {"level": "read"}),
        "remove-grant": ("DELETE", f"{A}/shares/{share}/grants/{friend.user_id}", None),
    }[name]


@pytest.mark.parametrize("name", CASES)
def test_every_admin_mutation_is_all_or_nothing_with_its_audit_row(
    auth_env: AuthEnv,
    owner: Session,
    friend: Session,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    s, empty = mk_share(owner, "Base"), mk_share(owner, "Empty")
    grant(owner, s["id"], friend.user_id, "write")
    method, url, body = case_request(name, owner, friend, s["id"], empty["id"])
    state, tree = db_state(auth_env), snapshot(auth_env)
    with monkeypatch.context() as m:
        break_audit(m)
        r = owner.client.request(method, url, json=body)
        assert r.status_code == 500 and "disk I/O" not in r.text, (name, r.status_code)
    assert db_state(auth_env) == state  # not a row, a hash, a session or a grant changed
    assert snapshot(auth_env) == tree  # not a folder made or removed
    ok = owner.client.request(method, url, json=body)  # the same request works with a sound log
    assert ok.status_code in (200, 201, 204), (name, ok.status_code, ok.text)
    assert len(audit_trail(auth_env)) > len(state["audit_log"])


def test_each_admin_mutation_writes_exactly_its_audit_rows(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    s = mk_share(owner, "Base")
    n0 = len(audit_trail(auth_env))
    assert n0 == 2  # share_created + the creator's grant_set
    owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": True})
    owner.client.patch(f"{A}/users/{friend.user_id}", json={"disabled": False})
    owner.client.post(f"{A}/users/{friend.user_id}/password-reset")
    owner.client.delete(f"{A}/users/{friend.user_id}/sessions")
    mk_user(owner, "jade")
    owner.client.patch(f"{A}/shares/{s['id']}", json={"name": "Renamed"})
    grant(owner, s["id"], friend.user_id, "read")
    owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}")
    owner.client.delete(f"{A}/shares/{s['id']}/grants/{friend.user_id}")  # no-op: no row
    assert [a[0] for a in audit_trail(auth_env)][n0:] == [
        "user_disabled",
        "user_enabled",
        "password_reset",
        "sessions_revoked",
        "user_created",
        "share_renamed",
        "grant_set",
        "grant_removed",
    ]
    text = json.dumps(audit_trail(auth_env))
    for secret in ("jade", "Renamed", "Base", owner.token, OWNER_PASSWORD, FRIEND_PASSWORD):
        assert secret not in text, secret


# ---- I. error semantics -----------------------------------------------------------------------


def test_the_status_code_vocabulary_is_kept_apart(
    auth_env: AuthEnv, owner: Session, friend: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "read")
    sp = f"/api/v1/spaces/{space(s['id'])}"
    (share_dir(auth_env, s["id"]) / "f.txt").write_bytes(b"x")
    anon = auth_env.client()
    cases = [
        (anon.get(f"{A}/users"), 401, "unauthorized"),
        (friend.client.get(f"{A}/users"), 403, "forbidden"),
        (friend.client.post(f"{sp}/folders", json={"path": "n"}), 403, "forbidden"),
        (friend.client.get(f"/api/v1/spaces/{space(ZERO_SHARE)}/items"), 404, "not_found"),
        (owner.client.delete(f"{A}/shares/{ZERO_SHARE}"), 404, "not_found"),
        (owner.client.post(f"{A}/shares", json={"name": "x", "path": "y"}), 400, "invalid_request"),
        (friend.client.get(f"{sp}/files", params={"path": "../x"}), 400, "invalid_path"),
        (owner.client.delete(f"{A}/shares/{s['id']}"), 409, "not_empty"),
        (owner.client.post(f"{A}/users", json={"username": "friend"}), 409, "username_taken"),
    ]
    for r, status, error in cases:
        assert r.status_code == status and code(r) == error, (r.request.url.path, r.text)
    break_audit(monkeypatch)
    r = owner.client.post(f"{A}/shares", json={"name": "z"})
    assert r.status_code == 500 and code(r) == "internal_error"
    assert "Traceback" not in r.text and "sqlite" not in r.text.lower()


# ---- J. concurrency ---------------------------------------------------------------------------


def job(client: Any, method: str, url: str, **kwargs: Any) -> Callable[[], Any]:
    """One request, ready to be started on a thread (arguments bound now, not at call time)."""

    def run() -> Any:
        return client.request(method, url, **kwargs)

    return run


def run_threads(jobs: list[Callable[[], Any]]) -> list[Any]:
    barrier = threading.Barrier(len(jobs))
    results: list[Any] = [None] * len(jobs)

    def wrap(i: int, job: Callable[[], Any]) -> None:
        barrier.wait()
        try:
            results[i] = job()
        except BaseException as exc:  # a test must see it, not lose it in a thread
            results[i] = exc

    threads = [threading.Thread(target=wrap, args=(i, j)) for i, j in enumerate(jobs)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    for r in results:
        assert not isinstance(r, BaseException), r
    return results


def test_concurrent_creation_of_one_share_name_makes_exactly_one_share(
    auth_env: AuthEnv, owner: Session
) -> None:
    clients = [auth_env.client(**bearer(owner.token)) for _ in range(8)]
    out = run_threads([job(c, "POST", f"{A}/shares", json={"name": "Same"}) for c in clients])
    assert sorted(r.status_code for r in out) == [201] + [409] * 7
    assert count(auth_env, "shares") == 1
    assert len(list((auth_env.storage_root / "shared").iterdir())) == 1  # losers left no folder


def test_concurrent_creation_of_one_username_makes_exactly_one_user(
    auth_env: AuthEnv, owner: Session
) -> None:
    clients = [auth_env.client(**bearer(owner.token)) for _ in range(6)]
    out = run_threads([job(c, "POST", f"{A}/users", json={"username": "kim"}) for c in clients])
    assert sorted(r.status_code for r in out) == [201] + [409] * 5
    assert count(auth_env, "users") == 2


def test_share_delete_racing_the_final_chunk_never_loses_a_file(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    """The reported race: a write that passed authorization just before the share delete."""
    seen: dict[str, int] = {}
    for i in range(14):
        s = mk_share(owner, f"Race {i}")
        grant(owner, s["id"], friend.user_id, "write")
        d = share_dir(auth_env, s["id"])
        uid = start_upload(friend, space(s["id"]), "up.bin", 4).json()["upload_id"]
        assert patch(friend, uid, 0, b"ab").status_code == 200
        c_up = auth_env.client(**bearer(friend.token))
        c_del = auth_env.client(**bearer(owner.token))
        up, de = run_threads(
            [
                job(
                    c_up,
                    "PATCH",
                    f"{UPLOADS}/{uid}",
                    content=b"cd",
                    headers={**OCTET, "Upload-Offset": "2"},
                ),
                job(c_del, "DELETE", f"{A}/shares/{s['id']}"),
            ]
        )
        assert up.status_code in (200, 404) and de.status_code in (204, 409), (
            up.status_code,
            de.status_code,
        )
        with auth_env.db.read() as conn:
            row = conn.execute("SELECT 1 FROM shares WHERE id = ?", (s["id"],)).fetchone()
        landed = (d / "up.bin").exists()
        outcome = f"upload={up.status_code} delete={de.status_code} landed={landed}"
        seen[outcome] = seen.get(outcome, 0) + 1
        if up.status_code == 200:
            assert landed and (d / "up.bin").read_bytes() == b"abcd"  # a success never loses data
        else:
            assert not landed  # a refused upload leaves no file
        if de.status_code == 204:
            assert row is None  # the accepted race: with `landed` the folder stays, unreferenced
        else:  # 409: the file was there first, the share stands, nothing was removed
            assert row is not None and landed and up.status_code == 200
        for p in (auth_env.storage_root / ".yournas-tmp").glob("*.part"):
            p.unlink()
    print("race outcomes:", seen)


def test_a_write_landing_after_the_delete_checks_is_kept_in_an_unreferenced_folder(
    auth_env: AuthEnv,
    owner: Session,
    friend: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Forces the accepted race: a write that passed its own authorization just before the
    delete lands after the delete's emptiness check. The file must survive, the share must be
    gone for every user, and the leftover folder is logged by id only."""
    s = mk_share(owner)
    grant(owner, s["id"], friend.user_id, "write")
    d = share_dir(auth_env, s["id"])
    original = UploadService.discard_for_space

    def late_write(self: UploadService, space_id: str) -> int:
        (d / "late.txt").write_bytes(b"landed late")  # the straggler, after the commit
        return original(self, space_id)

    monkeypatch.setattr(UploadService, "discard_for_space", late_write)
    caplog.set_level(logging.DEBUG)
    r = owner.client.delete(f"{A}/shares/{s['id']}")
    assert r.status_code == 204
    assert (d / "late.txt").read_bytes() == b"landed late"  # never removed, never recursive
    with auth_env.db.read() as conn:
        assert conn.execute("SELECT 1 FROM shares WHERE id = ?", (s["id"],)).fetchone() is None
    sp = f"/api/v1/spaces/{space(s['id'])}"
    for client in (friend.client, owner.client):
        assert client.get(f"{sp}/items").status_code == 404  # no access to the stray folder
        assert client.get(f"{sp}/files", params={"path": "late.txt"}).status_code == 404
    orphaned = [r for r in caplog.records if r.getMessage() == "share_dir_orphaned"]
    assert len(orphaned) == 1 and orphaned[0].__dict__["share_id"] == s["id"]
    assert str(auth_env.storage_root) not in log_text(caplog)  # id only, never a path
    assert owner.client.delete(f"{A}/shares/{s['id']}").status_code == 404  # and not reusable


def test_concurrent_grant_changes_and_share_delete_leave_a_consistent_database(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    for i in range(10):
        s = mk_share(owner, f"G {i}")
        sid = s["id"]
        clients = [auth_env.client(**bearer(owner.token)) for _ in range(4)]
        out = run_threads(
            [
                job(
                    clients[0],
                    "PUT",
                    f"{A}/shares/{sid}/grants/{friend.user_id}",
                    json={"level": "write"},
                ),
                job(clients[1], "DELETE", f"{A}/shares/{sid}/grants/{friend.user_id}"),
                job(clients[2], "DELETE", f"{A}/shares/{sid}"),
                job(clients[3], "PATCH", f"{A}/shares/{sid}", json={"name": f"N {i}"}),
            ]
        )
        assert all(r.status_code < 500 for r in out), [r.status_code for r in out]
        with auth_env.db.read() as conn:
            orphans = conn.execute(
                "SELECT COUNT(*) FROM grants WHERE share_id NOT IN (SELECT id FROM shares)"
            ).fetchone()[0]
            assert orphans == 0
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
