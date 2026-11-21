"""Phase 4 step 2b: the file API authorizes every request against the caller's grants.

Real HTTP (TestClient) against real storage. Three accounts and three shares:

    share  name   owner O   friend A   friend B
    S1     Alpha  write     read       -
    S2     Beta   -         write      read
    S3     Gamma  read      -          write

The owner role grants nothing: O reaches S2 only through a grant row, which it does not have.
Every share holds `doc.txt` and a folder `sub`; every account has `mine.txt` in their home.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv, Session, session_for

from yournas.audit import AuditLog

UPLOADS = "/api/v1/uploads"
OCTET = {"content-type": "application/octet-stream"}
DOC = b"share-doc"

ACTORS = ("O", "A", "B")
SHARES = ("S1", "S2", "S3")
NAMES = {"S1": "Alpha", "S2": "Beta", "S3": "Gamma"}
GRANTS = {
    "S1": {"O": "write", "A": "read"},
    "S2": {"A": "write", "B": "read"},
    "S3": {"O": "read", "B": "write"},
}
LEVELS = {"read": 1, "write": 2}
ACTIONS = ("list", "meta", "download", "upload", "mkdir", "delete")
NEED = {"list": 1, "meta": 1, "download": 1, "upload": 2, "mkdir": 2, "delete": 2}
SUCCESS = {"list": 200, "meta": 200, "download": 200, "upload": 201, "mkdir": 201, "delete": 204}
PAIRS = [(a, s) for a in ACTORS for s in SHARES]
PAIR_IDS = [f"{a}-{s}" for a, s in PAIRS]
FILE_EVENTS = ("folder_created", "upload_completed", "item_deleted")


def level_of(actor: str, share: str) -> int:
    return LEVELS.get(GRANTS[share].get(actor, ""), 0)


def expected_status(level: int, action: str) -> int:
    if level == 0:
        return 404
    return SUCCESS[action] if level >= NEED[action] else 403


@dataclass
class World:
    env: AuthEnv
    users: dict[str, Session]
    shares: dict[str, str]

    def space(self, share: str) -> str:
        return f"share:{self.shares[share]}"

    def share_dir(self, share: str) -> Path:
        return self.env.storage_root / "shared" / self.shares[share]

    def set_grant(self, share: str, actor: str, level: str | None) -> None:
        user_id = self.users[actor].user_id
        with self.env.db.transaction() as conn:
            if level is None:
                conn.execute(
                    "DELETE FROM grants WHERE share_id = ? AND user_id = ?",
                    (self.shares[share], user_id),
                )
            else:
                conn.execute(
                    "INSERT OR REPLACE INTO grants (share_id, user_id, level, created_at) "
                    "VALUES (?, ?, ?, 1)",
                    (self.shares[share], user_id, level),
                )


def build_world(env: AuthEnv) -> World:
    env.add_user("alice", "alice passphrase 42")
    env.add_user("bob", "bobs passphrase 4242")
    users = {
        "O": session_for(env, OWNER_NAME, OWNER_PASSWORD),
        "A": session_for(env, "alice", "alice passphrase 42"),
        "B": session_for(env, "bob", "bobs passphrase 4242"),
    }
    for actor, s in users.items():
        (s.home / "mine.txt").write_bytes(f"home-of-{actor}".encode())
    perms = env.app.state.permissions
    shares: dict[str, str] = {}
    for share in SHARES:
        share_id = perms.shares.new_id()
        shares[share] = share_id
        with env.db.transaction() as conn:
            conn.execute(
                "INSERT INTO shares (id, name, created_at, created_by) VALUES (?, ?, 1, ?)",
                (share_id, NAMES[share], users["O"].user_id),
            )
            for actor, level in GRANTS[share].items():
                conn.execute(
                    "INSERT INTO grants (share_id, user_id, level, created_at) VALUES (?, ?, ?, 1)",
                    (share_id, users[actor].user_id, level),
                )
        root = perms.shares.create(share_id)
        (root / "doc.txt").write_bytes(DOC)
        (root / "sub").mkdir()
        (root / "sub" / "inner.txt").write_bytes(b"inner")
    return World(env, users, shares)


@pytest.fixture
def world(auth_env: AuthEnv) -> World:
    return build_world(auth_env)


def url(space: str, tail: str) -> str:
    return f"/api/v1/spaces/{quote(space, safe=':')}/{tail}"


def call(s: Session, action: str, space: str, path: str = "doc.txt") -> httpx.Response:
    c = s.client
    r: httpx.Response
    if action == "list":
        r = c.get(url(space, "items"), params={"path": ""})
    elif action == "meta":
        r = c.get(url(space, "items/meta"), params={"path": path})
    elif action == "download":
        r = c.get(url(space, "files"), params={"path": path})
    elif action == "upload":
        r = c.post(url(space, "uploads"), json={"path": "new.bin", "size": 3})
    elif action == "mkdir":
        r = c.post(url(space, "folders"), json={"path": "newdir"})
    elif action == "delete":
        r = c.delete(url(space, "items"), params={"path": path})
    else:
        raise AssertionError(action)
    return r


def start_upload(
    s: Session, space: str, path: str, size: int, *, overwrite: bool = False
) -> httpx.Response:
    r: httpx.Response = s.client.post(
        url(space, "uploads"), json={"path": path, "size": size, "overwrite": overwrite}
    )
    return r


def patch(s: Session, upload_id: str, offset: int, data: bytes) -> httpx.Response:
    r: httpx.Response = s.client.patch(
        f"{UPLOADS}/{upload_id}", content=data, headers={**OCTET, "Upload-Offset": str(offset)}
    )
    return r


def fingerprint(r: httpx.Response) -> tuple[Any, ...]:
    """Everything a client can observe except the per-request id."""
    body = r.json()
    body["error"].pop("request_id", None)
    headers = tuple(
        sorted(
            (k.lower(), v)
            for k, v in r.headers.items()
            if "request-id" not in k.lower() and k.lower() != "date"
        )
    )
    return (r.status_code, json.dumps(body, sort_keys=True), headers)


def snapshot(env: AuthEnv) -> set[tuple[str, int]]:
    """Every path under the storage root with its size: a denied request must not change it."""
    root = env.storage_root
    return {
        (str(p.relative_to(root)), p.stat().st_size if p.is_file() else -1) for p in root.rglob("*")
    }


def upload_rows(env: AuthEnv) -> list[sqlite3.Row]:
    with env.db.read() as conn:
        return list(conn.execute("SELECT * FROM uploads"))


def staged(env: AuthEnv) -> list[Path]:
    return sorted((env.storage_root / ".yournas-tmp").glob("*.part"))


def file_events(env: AuthEnv) -> list[dict[str, Any]]:
    marks = ",".join("?" for _ in FILE_EVENTS)
    sql = (
        "SELECT actor_id, action, target_type, target_id, detail FROM audit_log "
        f"WHERE action IN ({marks}) ORDER BY id"
    )
    with env.db.read() as conn:
        rows = conn.execute(sql, FILE_EVENTS).fetchall()
    return [
        {
            "actor": r["actor_id"],
            "action": r["action"],
            "type": r["target_type"],
            "target": r["target_id"],
            "detail": json.loads(r["detail"]) if r["detail"] else None,
        }
        for r in rows
    ]


# ---- the matrix: every actor x every share x every action -------------------------------------


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(("actor", "share"), PAIRS, ids=PAIR_IDS)
def test_share_matrix(world: World, actor: str, share: str, action: str) -> None:
    level = level_of(actor, share)
    allowed = level >= NEED[action]
    d = world.share_dir(share)
    r = call(world.users[actor], action, world.space(share))
    assert r.status_code == expected_status(level, action), r.text
    if action == "list" and allowed:
        assert {i["name"] for i in r.json()["items"]} == {"doc.txt", "sub"}
    if action == "download" and allowed:
        assert r.content == DOC
    if action == "delete":
        assert (d / "doc.txt").exists() is (not allowed)
    if action == "mkdir":
        assert (d / "newdir").is_dir() is allowed
    if action == "upload":
        rows = upload_rows(world.env)
        assert len(rows) == (1 if allowed else 0)
        if allowed:
            assert rows[0]["space"] == world.space(share)
            assert rows[0]["user_id"] == world.users[actor].user_id
    if not allowed and action != "upload":
        assert (d / "doc.txt").read_bytes() == DOC
    if level == 0:
        assert r.json()["error"]["code"] == "not_found"
    elif not allowed:
        assert r.json()["error"]["code"] == "forbidden"


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("actor", ACTORS)
def test_own_home_allows_everything(world: World, actor: str, action: str) -> None:
    s = world.users[actor]
    r = call(s, action, "home", "mine.txt")
    assert r.status_code == SUCCESS[action], r.text
    if action == "download":
        assert r.content == f"home-of-{actor}".encode()
    if action == "delete":
        assert not (s.home / "mine.txt").exists()


def test_home_is_never_audited(world: World) -> None:
    s = world.users["A"]
    assert call(s, "mkdir", "home").status_code == 201
    r = start_upload(s, "home", "up.bin", 3)
    assert r.status_code == 201
    assert patch(s, r.json()["upload_id"], 0, b"abc").json()["complete"] is True
    assert call(s, "delete", "home", "mine.txt").status_code == 204
    assert file_events(world.env) == []


def test_spaces_listing_follows_the_grants(world: World) -> None:
    expect = {
        "O": [("home", "write"), ("S1", "write"), ("S3", "read")],
        "A": [("home", "write"), ("S1", "read"), ("S2", "write")],
        "B": [("home", "write"), ("S2", "read"), ("S3", "write")],
    }
    for actor, wanted in expect.items():
        s = world.users[actor]
        r = s.client.get("/api/v1/spaces")
        assert r.status_code == 200
        got = [(i["id"], i["access"]) for i in r.json()]
        want = [("home" if k == "home" else world.space(k), lvl) for k, lvl in wanted]
        assert got == want
        me = s.client.get("/api/v1/auth/me").json()["spaces"]
        assert [(i["id"], i["access"]) for i in me] == want


def test_the_owner_role_grants_no_file_access(world: World) -> None:
    o = world.users["O"]
    assert call(o, "list", world.space("S2")).status_code == 404  # no grant on S2
    # Another user's home is not addressable at all: the owner's `home` is the owner's own.
    assert call(o, "download", "home", "mine.txt").content == b"home-of-O"
    other = f"../{world.users['A'].user_id}/mine.txt"
    assert call(o, "meta", "home", other).status_code == 400


# ---- denied means indistinguishable, and nothing is created ----------------------------------


def hostile_spaces(world: World) -> list[str]:
    ids = [world.users[k].user_id for k in ACTORS]
    return [
        "share:s_" + "0" * 16,  # well formed, never existed
        "share:s_" + "f" * 16,
        "share:",
        "share:s_xyz",
        "share:S_" + "0" * 16,
        "share:../" + ids[0],
        "SHARE:" + world.shares["S2"],  # wrong case of the prefix
        "share:" + world.shares["S2"].upper(),
        " share:" + world.shares["S2"],
        ids[1],  # another user's id used as a space
        f"home:{ids[1]}",
        f"users/{ids[1]}",
        "..",
        "%2e%2e",
        "home ",
        "HOME",
        "x" * 300,
    ]


@pytest.mark.parametrize("action", ACTIONS)
def test_every_denial_is_one_identical_404(world: World, action: str) -> None:
    a = world.users["A"]
    reference = fingerprint(call(a, action, world.space("S3")))  # S3: A holds no grant
    assert reference[0] == 404
    for space in hostile_spaces(world):
        r = call(a, action, space)
        assert fingerprint(r) == reference, space
    # The same for a different actor and a different ungranted share.
    b = world.users["B"]
    assert fingerprint(call(b, action, world.space("S1"))) == reference


@pytest.mark.parametrize(
    "bad_path", ["..", "../x", "a/../../x", "C:\\Windows", "\\\\h\\s\\f", "/etc"]
)
@pytest.mark.parametrize("action", ["meta", "download", "delete", "list"])
def test_invalid_path_in_a_denied_space_is_404_not_400(
    world: World, action: str, bad_path: str
) -> None:
    a = world.users["A"]
    reference = fingerprint(call(a, action, world.space("S3"), "doc.txt"))
    r = call(a, action, world.space("S3"), bad_path)
    assert fingerprint(r) == reference
    assert r.status_code == 404


@pytest.mark.parametrize("bad_path", ["..", "../x", "C:\\Windows", "\\\\h\\s\\f", "/etc", "a\\b"])
def test_invalid_path_in_a_granted_space_is_400(world: World, bad_path: str) -> None:
    a = world.users["A"]  # write on S2, read on S1
    sp = world.space("S2")
    for action in ("meta", "download", "delete"):
        r = call(a, action, sp, bad_path)
        assert r.status_code == 400, (action, r.text)
        assert r.json()["error"]["code"] == "invalid_path"
    assert a.client.post(url(sp, "folders"), json={"path": bad_path}).status_code == 400
    assert start_upload(a, sp, bad_path, 3).status_code == 400
    assert call(a, "meta", world.space("S1"), bad_path).status_code == 400  # read is enough
    assert not (world.env.storage_root / "x").exists()
    assert not (world.env.storage_root / "shared" / "x").exists()


def test_invalid_path_with_only_read_access_to_a_write_action_is_403(world: World) -> None:
    a = world.users["A"]
    r = a.client.post(url(world.space("S1"), "folders"), json={"path": ".."})
    assert r.status_code == 403  # authorization comes first, then the path


def test_denied_requests_create_nothing_on_disk(world: World) -> None:
    before = snapshot(world.env)
    ghost = "share:s_" + "ab" * 8
    for actor in ACTORS:
        s = world.users[actor]
        for share in SHARES:
            if level_of(actor, share) == 0:
                for action in ACTIONS:
                    assert call(s, action, world.space(share)).status_code == 404
            if level_of(actor, share) == 1:
                for action in ("upload", "mkdir", "delete"):
                    assert call(s, action, world.space(share)).status_code == 403
        for action in ACTIONS:
            assert call(s, action, ghost).status_code == 404
            assert call(s, action, "share:bad").status_code == 404
    assert snapshot(world.env) == before
    assert not (world.env.storage_root / "shared" / ("s_" + "ab" * 8)).exists()
    assert upload_rows(world.env) == []


def test_unauthenticated_requests_are_401_everywhere(world: World) -> None:
    anon = world.env.client()
    sp = world.space("S2")
    ghost = "0" * 32
    calls = [
        anon.get("/api/v1/spaces"),
        anon.get(url(sp, "items")),
        anon.get(url(sp, "items/meta"), params={"path": "doc.txt"}),
        anon.get(url(sp, "files"), params={"path": "doc.txt"}),
        anon.post(url(sp, "folders"), json={"path": "n"}),
        anon.delete(url(sp, "items"), params={"path": "doc.txt"}),
        anon.post(url(sp, "uploads"), json={"path": "n", "size": 1}),
        anon.patch(f"{UPLOADS}/{ghost}", content=b"x", headers={**OCTET, "Upload-Offset": "0"}),
        anon.get(f"{UPLOADS}/{ghost}"),
        anon.delete(f"{UPLOADS}/{ghost}"),
    ]
    assert [r.status_code for r in calls] == [401] * len(calls)
    bad = world.env.client(Authorization="Bearer not-a-token")
    assert bad.get(url(sp, "items")).status_code == 401
    assert (world.share_dir("S2") / "doc.txt").read_bytes() == DOC


def test_client_supplied_identity_changes_nothing(world: World) -> None:
    a = world.users["A"]
    b_id = world.users["B"].user_id
    r = a.client.get(
        url("home", "items"),
        params={"path": "", "user_id": b_id, "owner": b_id},
        headers={"X-User-Id": b_id, "X-Forwarded-User": b_id},
    )
    assert [i["name"] for i in r.json()["items"]] == ["mine.txt"]
    assert a.client.get(url("home", "files"), params={"path": "mine.txt"}).content == b"home-of-A"
    # Mass assignment: unknown body fields are refused, not applied.
    r = a.client.post(url(world.space("S2"), "folders"), json={"path": "n", "user_id": b_id})
    assert r.status_code == 400
    r = a.client.post(
        url(world.space("S2"), "uploads"), json={"path": "n", "size": 1, "space": "home"}
    )
    assert r.status_code == 400
    assert not (world.share_dir("S2") / "n").exists()


def test_a_friend_cannot_reach_another_friends_home(world: World) -> None:
    a, b = world.users["A"], world.users["B"]
    for target in (f"../{b.user_id}/mine.txt", f"..\\{b.user_id}\\mine.txt"):
        r = call(a, "download", "home", target)
        assert r.status_code == 400
        assert b"home-of-B" not in r.content
    assert call(a, "download", "home", "mine.txt").content == b"home-of-A"
    assert call(b, "download", "home", "mine.txt").content == b"home-of-B"


# ---- uploads re-authorize on every request ---------------------------------------------------


def test_upload_in_a_share_lands_in_the_share(world: World) -> None:
    a = world.users["A"]
    r = start_upload(a, world.space("S2"), "up.bin", 6)
    assert r.status_code == 201
    uid = r.json()["upload_id"]
    assert patch(a, uid, 0, b"abc").status_code == 200
    done = patch(a, uid, 3, b"def")
    assert done.status_code == 200 and done.json()["complete"] is True
    assert (world.share_dir("S2") / "up.bin").read_bytes() == b"abcdef"
    assert not (a.home / "up.bin").exists()
    b = world.users["B"]  # read-only on S2: sees it, cannot start one of its own
    assert call(b, "download", world.space("S2"), "up.bin").content == b"abcdef"
    assert start_upload(b, world.space("S2"), "b.bin", 1).status_code == 403


@pytest.mark.parametrize("change", ["revoke", "downgrade", "delete_share", "disable_user"])
@pytest.mark.parametrize("when", ["next_chunk", "finalizing_chunk"])
def test_losing_access_mid_upload_stops_it(world: World, change: str, when: str) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    uid = start_upload(a, sp, "up.bin", 6).json()["upload_id"]
    first = patch(a, uid, 0, b"abc" if when == "finalizing_chunk" else b"ab")
    assert first.status_code == 200
    offset = first.json()["offset"]
    if change == "revoke":
        world.set_grant("S2", "A", None)
    elif change == "downgrade":
        world.set_grant("S2", "A", "read")
    elif change == "delete_share":
        with world.env.db.transaction() as conn:
            conn.execute("DELETE FROM shares WHERE id = ?", (world.shares["S2"],))
    else:
        world.env.service.set_disabled(world.users["O"].user_id, a.user_id, True)
    r = patch(a, uid, offset, b"def"[: 6 - offset])
    assert r.status_code == (401 if change == "disable_user" else 404), r.text
    assert not (world.share_dir("S2") / "up.bin").exists()
    if change != "disable_user":
        assert a.client.get(f"{UPLOADS}/{uid}").status_code == 404
        assert a.client.head(f"{UPLOADS}/{uid}").status_code == 404


def test_a_lost_grant_is_enforced_before_the_final_chunk_is_stored(world: World) -> None:
    a = world.users["A"]
    uid = start_upload(a, world.space("S2"), "up.bin", 4).json()["upload_id"]
    assert patch(a, uid, 0, b"ab").status_code == 200
    world.set_grant("S2", "A", "read")
    assert patch(a, uid, 2, b"cd").status_code == 404
    assert [p.stat().st_size for p in staged(world.env)] == [2]  # the chunk was never written


def test_grants_are_never_cached_for_uploads(world: World) -> None:
    a = world.users["A"]
    uid = start_upload(a, world.space("S2"), "up.bin", 4).json()["upload_id"]
    assert patch(a, uid, 0, b"ab").status_code == 200
    world.set_grant("S2", "A", None)
    assert patch(a, uid, 2, b"cd").status_code == 404
    world.set_grant("S2", "A", "write")  # access returns: the upload can go on
    done = patch(a, uid, 2, b"cd")
    assert done.status_code == 200 and done.json()["complete"] is True
    assert (world.share_dir("S2") / "up.bin").read_bytes() == b"abcd"


def test_abort_works_even_after_the_grant_is_gone(world: World) -> None:
    a = world.users["A"]
    uid = start_upload(a, world.space("S2"), "up.bin", 4).json()["upload_id"]
    assert patch(a, uid, 0, b"ab").status_code == 200
    world.set_grant("S2", "A", None)
    assert a.client.delete(f"{UPLOADS}/{uid}").status_code == 204
    assert upload_rows(world.env) == []
    assert staged(world.env) == []


def test_zero_byte_upload_into_a_share(world: World) -> None:
    a = world.users["A"]
    r = start_upload(a, world.space("S2"), "empty.txt", 0)
    assert r.status_code == 201 and r.json()["complete"] is True
    assert (world.share_dir("S2") / "empty.txt").read_bytes() == b""
    assert start_upload(a, world.space("S1"), "empty.txt", 0).status_code == 403  # read only
    assert start_upload(a, world.space("S3"), "empty.txt", 0).status_code == 404  # no grant
    assert not (world.share_dir("S1") / "empty.txt").exists()


@pytest.mark.parametrize("route", ["patch", "get", "head", "delete"])
@pytest.mark.parametrize("thief", ["O", "B"])
def test_another_users_upload_id_is_404_on_every_route(
    world: World, route: str, thief: str
) -> None:
    a = world.users["A"]
    uid = start_upload(a, world.space("S2"), "up.bin", 4).json()["upload_id"]
    patch(a, uid, 0, b"ab")
    t = world.users[thief]
    send: dict[str, Callable[[], httpx.Response]] = {
        "patch": lambda: patch(t, uid, 2, b"cd"),
        "get": lambda: t.client.get(f"{UPLOADS}/{uid}"),
        "head": lambda: t.client.head(f"{UPLOADS}/{uid}"),
        "delete": lambda: t.client.delete(f"{UPLOADS}/{uid}"),
    }
    assert send[route]().status_code == 404
    assert len(upload_rows(world.env)) == 1  # untouched
    assert patch(a, uid, 2, b"cd").json()["complete"] is True


def test_upload_cannot_be_redirected_into_another_space_afterwards(world: World) -> None:
    a = world.users["A"]
    uid = start_upload(a, world.space("S2"), "up.bin", 3).json()["upload_id"]
    # The space of an upload is fixed at creation; no request parameter can change it.
    r = a.client.patch(
        f"{UPLOADS}/{uid}?space=home&path=other.bin",
        content=b"abc",
        headers={**OCTET, "Upload-Offset": "0", "X-Space": "home"},
    )
    assert r.status_code == 200
    assert (world.share_dir("S2") / "up.bin").read_bytes() == b"abc"
    assert not (a.home / "up.bin").exists() and not (a.home / "other.bin").exists()


def test_discard_for_space_drops_rows_and_staging(world: World) -> None:
    a, b = world.users["A"], world.users["B"]
    ids = [start_upload(a, world.space("S2"), f"u{i}.bin", 4).json()["upload_id"] for i in range(2)]
    for uid in ids:
        patch(a, uid, 0, b"ab")
    keep = start_upload(b, world.space("S3"), "keep.bin", 4).json()["upload_id"]
    assert world.env.uploads.discard_for_space(world.space("S2")) == 2
    assert [r["id"] for r in upload_rows(world.env)] == [keep]
    assert {p.stem for p in staged(world.env)} == {keep}
    assert world.env.uploads.discard_for_space(world.space("S2")) == 0


# ---- the in-flight upload quota --------------------------------------------------------------


def test_inflight_upload_quota_per_user(make_auth_env: Callable[..., AuthEnv]) -> None:
    w = build_world(make_auth_env(max_inflight_upload_bytes_per_user=100))
    a, b = w.users["A"], w.users["B"]
    first = start_upload(a, w.space("S2"), "one.bin", 60)
    assert first.status_code == 201
    r = start_upload(a, "home", "two.bin", 60)  # home counts too
    assert r.status_code == 507 and r.json()["error"]["code"] == "upload_quota_exceeded"
    assert start_upload(a, "home", "zero.bin", 0).status_code == 201  # nothing in flight
    assert start_upload(a, "home", "two.bin", 40).status_code == 201  # exactly at the cap
    assert start_upload(a, "home", "three.bin", 1).status_code == 507
    assert start_upload(b, w.space("S2"), "b.bin", 60).status_code == 403  # B: read only
    assert start_upload(b, w.space("S3"), "b.bin", 60).status_code == 201  # per user, not global
    assert a.client.delete(f"{UPLOADS}/{first.json()['upload_id']}").status_code == 204
    assert start_upload(a, "home", "four.bin", 60).status_code == 201  # freed


# ---- audit of share file events --------------------------------------------------------------


def event(actor: str, action: str, target: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {"actor": actor, "action": action, "type": "share", "target": target, "detail": detail}


def test_share_file_events_are_audited(world: World) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    sid = world.shares["S2"]
    assert call(a, "mkdir", sp).status_code == 201
    uid = start_upload(a, sp, "up.bin", 3).json()["upload_id"]
    assert patch(a, uid, 0, b"abc").json()["complete"] is True
    assert start_upload(a, sp, "empty.bin", 0).status_code == 201
    assert call(a, "delete", sp, "doc.txt").status_code == 204
    assert call(a, "delete", sp, "sub").status_code == 409  # folder is not empty
    assert file_events(world.env) == [
        event(a.user_id, "folder_created", sid, {"depth": 1}),
        event(a.user_id, "upload_completed", sid, {"overwrite": False, "size": 3}),
        event(a.user_id, "upload_completed", sid, {"overwrite": False, "size": 0}),
        event(a.user_id, "item_deleted", sid, {"depth": 1, "kind": "file"}),
        # The refused delete of a non-empty folder still has its row: the intent is recorded
        # first (documented: audit-first may over-report a failed delete).
        event(a.user_id, "item_deleted", sid, {"depth": 1, "kind": "dir"}),
    ]


def test_denied_and_failed_requests_leave_no_audit_row(world: World) -> None:
    a = world.users["A"]
    for action in ("mkdir", "delete", "upload"):
        assert call(a, action, world.space("S1")).status_code == 403  # read only
        assert call(a, action, world.space("S3")).status_code == 404  # no grant
    assert call(a, "meta", world.space("S2"), "missing.txt").status_code == 404
    assert call(a, "delete", world.space("S2"), "missing.txt").status_code == 404
    assert call(a, "delete", world.space("S2"), "..").status_code == 400
    assert call(a, "delete", world.space("S2"), "").status_code == 400  # the space root
    assert call(a, "download", world.space("S2"), "").status_code == 400  # a folder
    assert file_events(world.env) == []


def test_overwrite_is_audited_and_replaces_the_file(world: World) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    assert start_upload(a, sp, "doc.txt", 4, overwrite=False).status_code == 409  # exists
    uid = start_upload(a, sp, "doc.txt", 4, overwrite=True).json()["upload_id"]
    assert patch(a, uid, 0, b"new!").json()["complete"] is True
    assert (world.share_dir("S2") / "doc.txt").read_bytes() == b"new!"
    assert file_events(world.env) == [
        event(a.user_id, "upload_completed", world.shares["S2"], {"overwrite": True, "size": 4}),
    ]


def break_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> int:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(AuditLog, "record", boom)


def test_delete_in_a_share_needs_its_audit_row_first(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = world.users["A"]
    break_audit(monkeypatch)
    r = call(a, "delete", world.space("S2"), "doc.txt")
    assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error"
    assert (world.share_dir("S2") / "doc.txt").read_bytes() == DOC  # not deleted
    assert "disk I/O" not in r.text
    # A private home is not audited, so a broken audit log does not block it.
    assert call(a, "delete", "home", "mine.txt").status_code == 204
    assert not (a.home / "mine.txt").exists()


def test_overwrite_in_a_share_needs_its_audit_row_first(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    uid = start_upload(a, sp, "doc.txt", 4, overwrite=True).json()["upload_id"]
    with monkeypatch.context() as m:
        break_audit(m)
        r = patch(a, uid, 0, b"new!")
        assert r.status_code == 500 and r.json()["error"]["code"] == "internal_error"
        assert (world.share_dir("S2") / "doc.txt").read_bytes() == DOC  # not replaced
    # The staged file survives, so the client repeats the last request once the cause is gone.
    done = patch(a, uid, 4, b"")
    assert done.status_code == 200 and done.json()["complete"] is True
    assert (world.share_dir("S2") / "doc.txt").read_bytes() == b"new!"


def test_a_broken_audit_log_does_not_undo_a_harmless_event(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    break_audit(monkeypatch)
    assert call(a, "mkdir", sp).status_code == 201
    assert (world.share_dir("S2") / "newdir").is_dir()
    uid = start_upload(a, sp, "up.bin", 3).json()["upload_id"]
    assert patch(a, uid, 0, b"abc").json()["complete"] is True
    assert (world.share_dir("S2") / "up.bin").read_bytes() == b"abc"


def test_no_names_paths_or_tokens_reach_audit_rows_or_logs(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    a = world.users["A"]
    sp = world.space("S2")
    secret = "very-secret-name"
    caplog.set_level(logging.DEBUG)
    assert a.client.post(url(sp, "folders"), json={"path": secret}).status_code == 201
    uid = start_upload(a, sp, f"{secret}/{secret}.txt", 3).json()["upload_id"]
    assert patch(a, uid, 0, b"abc").json()["complete"] is True
    assert call(a, "delete", sp, f"{secret}/{secret}.txt").status_code == 204
    assert call(a, "download", sp, f"{secret}/gone.txt").status_code == 404
    with world.env.db.read() as conn:
        dump = json.dumps([tuple(r) for r in conn.execute("SELECT * FROM audit_log")])
    seen = [dump]
    server_records = [r for r in caplog.records if r.name.startswith("yournas")]
    assert {r.name for r in server_records} >= {"yournas.request", "yournas.files"}
    for rec in server_records:  # not httpx: that is the test client logging its own URLs
        seen.append(rec.getMessage())
        seen.append(json.dumps({k: str(v) for k, v in rec.__dict__.items()}))
    blob = "\n".join(seen)
    for forbidden in (secret, a.token, str(world.env.storage_root), "alice", NAMES["S2"]):
        assert forbidden not in blob, forbidden
