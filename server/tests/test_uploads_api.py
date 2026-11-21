"""Resumable uploads through the real HTTP layer."""

from __future__ import annotations

import logging
import os
import re
import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest
from conftest import AuthEnv, Session, bearer, routes_of, session_for

from yournas.main import CHUNK_BODY_SLACK_BYTES, JSON_BODY_LIMIT_BYTES
from yournas.storage import files
from yournas.storage.errors import DiskFull

CREATE = "/api/v1/spaces/home/uploads"
UPLOADS = "/api/v1/uploads"
ITEMS = "/api/v1/spaces/home/items"
FILES = "/api/v1/spaces/home/files"
OCTET = {"content-type": "application/octet-stream"}


def code(r: httpx.Response) -> str:
    return str(r.json()["error"]["code"])


def start(
    s: Session, path: str, size: int, *, overwrite: bool = False, expect: int = 201
) -> httpx.Response:
    r: httpx.Response = s.client.post(
        CREATE, json={"path": path, "size": size, "overwrite": overwrite}
    )
    assert r.status_code == expect, r.text
    return r


def send(s: Session, upload_id: str, offset: int, data: bytes | Iterator[bytes]) -> httpx.Response:
    r: httpx.Response = s.client.patch(
        f"{UPLOADS}/{upload_id}", content=data, headers={**OCTET, "Upload-Offset": str(offset)}
    )
    return r


def staging_files(s: Session) -> list[Path]:
    return sorted((s.env.storage_root / ".yournas-tmp").glob("*.part"))


def rows(s: Session) -> list[sqlite3.Row]:
    with s.env.db.read() as conn:
        return list(conn.execute("SELECT * FROM uploads"))


def upload_whole(
    s: Session, path: str, data: bytes, *, chunk: int, overwrite: bool = False
) -> httpx.Response:
    uid = start(s, path, len(data), overwrite=overwrite).json()["upload_id"]
    offset = 0
    last: httpx.Response | None = None
    while offset < len(data) or last is None:
        piece = data[offset : offset + chunk]
        last = send(s, uid, offset, piece)
        assert last.status_code == 200, last.text
        offset = last.json()["offset"]
        if last.json()["complete"]:
            break
    return last


# ---- start ----------------------------------------------------------------------------------


def test_create_upload(owner: Session) -> None:
    r = start(owner, "movie.mp4", 1000)
    body = r.json()
    assert re.fullmatch(r"[0-9a-f]{32}", body["upload_id"])
    assert body["offset"] == 0 and body["size"] == 1000
    assert body["chunk_max_bytes"] == 8 * 1024 * 1024
    assert body["complete"] is False and body.get("item") is None
    assert [p.stat().st_size for p in staging_files(owner)] == [0]
    (row,) = rows(owner)
    assert (row["user_id"], row["space"], row["rel_path"], row["size"], row["overwrite"]) == (
        owner.user_id,
        "home",
        "movie.mp4",
        1000,
        0,
    )
    assert not (owner.home / "movie.mp4").exists()  # nothing visible before completion


def test_upload_ids_are_random_and_unique(owner: Session) -> None:
    ids = {start(owner, f"f{i}", 5).json()["upload_id"] for i in range(5)}
    assert len(ids) == 5


def test_chunk_max_follows_the_setting(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(upload_chunk_max_bytes=4096)
    s = session_for(env, "owner", "correct horse battery")
    assert start(s, "a", 5).json()["chunk_max_bytes"] == 4096


def test_full_upload_in_chunks(owner: Session) -> None:
    data = os.urandom(10_000)
    uid = start(owner, "big.bin", len(data)).json()["upload_id"]
    r1 = send(owner, uid, 0, data[:4000])
    assert r1.status_code == 200
    assert r1.json() == {"offset": 4000, "size": 10_000, "complete": False, "item": None}
    assert r1.headers["upload-offset"] == "4000"
    assert not (owner.home / "big.bin").exists()
    r2 = send(owner, uid, 4000, data[4000:9000])
    assert r2.json()["offset"] == 9000 and r2.json()["complete"] is False
    r3 = send(owner, uid, 9000, data[9000:])
    body = r3.json()
    assert r3.status_code == 200 and body["complete"] is True and body["offset"] == 10_000
    assert body["item"]["name"] == "big.bin" and body["item"]["size"] == 10_000
    assert body["item"]["kind"] == "file"
    assert (owner.home / "big.bin").read_bytes() == data
    assert staging_files(owner) == [] and rows(owner) == []
    assert owner.client.get(f"{UPLOADS}/{uid}").status_code == 404  # finished uploads are gone
    assert owner.client.get(FILES, params={"path": "big.bin"}).content == data


def test_one_chunk_upload_and_subfolder(owner: Session) -> None:
    assert (
        owner.client.post("/api/v1/spaces/home/folders", json={"path": "docs"}).status_code == 201
    )
    r = upload_whole(owner, "docs/a.txt", b"hello", chunk=100)
    assert r.json()["complete"] is True
    assert (owner.home / "docs" / "a.txt").read_bytes() == b"hello"


def test_zero_byte_upload_completes_immediately(owner: Session) -> None:
    r = start(owner, "empty.txt", 0)
    body = r.json()
    assert body["complete"] is True and body["item"]["size"] == 0 and body["size"] == 0
    assert (owner.home / "empty.txt").read_bytes() == b""
    assert staging_files(owner) == [] and rows(owner) == []
    start(owner, "empty.txt", 0, expect=409)  # no overwrite


def test_zero_byte_overwrite(owner: Session) -> None:
    (owner.home / "f.txt").write_bytes(b"old")
    start(owner, "f.txt", 0, overwrite=True)
    assert (owner.home / "f.txt").read_bytes() == b""


@pytest.mark.parametrize(
    "body",
    [
        {"path": "a"},
        {"size": 1},
        {"path": "a", "size": -1},
        {"path": "a", "size": 1.5},
        {"path": "a", "size": "10"},
        {"path": "a", "size": True},
        {"path": "a", "size": None},
        {"path": "a", "size": 1, "overwrite": "maybe"},
        {"path": "a", "size": 1, "extra": 1},
        {"path": 5, "size": 1},
        {"path": "a" * 2000, "size": 1},
        [],
    ],
)
def test_bad_create_bodies_are_a_400(owner: Session, body: object) -> None:
    r = owner.client.post(CREATE, json=body)
    assert r.status_code == 400 and code(r) == "invalid_request"
    assert staging_files(owner) == [] and rows(owner) == []


def test_empty_path_is_refused(owner: Session) -> None:
    r = owner.client.post(CREATE, json={"path": "", "size": 5})
    assert r.status_code == 400 and code(r) == "invalid_path"


def test_size_above_the_maximum_is_413(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(max_upload_bytes=1000)
    s = session_for(env, "owner", "correct horse battery")
    start(s, "ok", 1000)
    r = start(s, "too-big", 1001, expect=413)
    assert code(r) == "payload_too_large"
    assert len(staging_files(s)) == 1 and len(rows(s)) == 1


def test_not_enough_free_space_is_507(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(free_space_floor_bytes=10**18)
    s = session_for(env, "owner", "correct horse battery")
    r = start(s, "a", 1, expect=507)
    assert code(r) == "insufficient_storage"
    assert staging_files(s) == [] and rows(s) == []


def test_free_space_check_counts_the_file_size(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(files, "free_bytes", lambda _path: 5 * 1024**3 + 1000)
    start(owner, "fits", 1000)
    start(owner, "does-not-fit", 1001, expect=507)


def test_parent_must_exist_and_be_a_folder(owner: Session) -> None:
    (owner.home / "file").write_text("x")
    for path in ("missing/a.txt", "file/a.txt"):
        r = start(owner, path, 5, expect=404)
        assert code(r) == "not_found"
    assert rows(owner) == []


def test_destination_conflicts_are_checked_when_starting(owner: Session) -> None:
    (owner.home / "exists.txt").write_text("old")
    (owner.home / "dir").mkdir()
    assert code(start(owner, "exists.txt", 5, expect=409)) == "already_exists"
    assert code(start(owner, "EXISTS.TXT", 5, expect=409)) == "already_exists"
    assert code(start(owner, "dir", 5, expect=409)) == "is_a_directory"
    assert code(start(owner, "dir", 5, overwrite=True, expect=409)) == "is_a_directory"
    assert (owner.home / "exists.txt").read_text() == "old"
    assert rows(owner) == [] and staging_files(owner) == []


def test_overwrite_replaces_only_at_the_end(owner: Session) -> None:
    (owner.home / "doc.txt").write_text("old content")
    uid = start(owner, "doc.txt", 6, overwrite=True).json()["upload_id"]
    send(owner, uid, 0, b"new")
    assert (owner.home / "doc.txt").read_text() == "old content"
    assert send(owner, uid, 3, b"new").json()["complete"] is True
    assert (owner.home / "doc.txt").read_text() == "newnew"


def test_destination_created_meanwhile_is_a_409_at_the_end_and_can_be_retried(
    owner: Session,
) -> None:
    uid = start(owner, "race.txt", 4).json()["upload_id"]
    send(owner, uid, 0, b"ab")
    (owner.home / "race.txt").write_text("someone else")
    r = send(owner, uid, 2, b"cd")
    assert r.status_code == 409 and code(r) == "already_exists"
    assert (owner.home / "race.txt").read_text() == "someone else"
    # The staged bytes are kept: remove the obstacle and repeat the last request (empty body).
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 4
    (owner.home / "race.txt").unlink()
    done = send(owner, uid, 4, b"")
    assert done.status_code == 200 and done.json()["complete"] is True
    assert (owner.home / "race.txt").read_bytes() == b"abcd"


def test_folder_created_meanwhile_does_not_get_replaced(owner: Session) -> None:
    uid = start(owner, "name", 2, overwrite=True).json()["upload_id"]
    (owner.home / "name").mkdir()
    r = send(owner, uid, 0, b"xy")
    assert r.status_code == 409 and code(r) == "is_a_directory"
    assert (owner.home / "name").is_dir()


def test_parent_removed_meanwhile_is_a_404_at_the_end(owner: Session) -> None:
    owner.client.post("/api/v1/spaces/home/folders", json={"path": "d"})
    uid = start(owner, "d/f", 2).json()["upload_id"]
    (owner.home / "d").rmdir()
    assert send(owner, uid, 0, b"xy").status_code == 404


def test_filenames_are_normalized_like_everywhere(owner: Session) -> None:
    upload_whole(owner, "é.txt", b"x", chunk=10)
    assert [p.name for p in owner.home.iterdir()] == ["é.txt"]
    for bad in ("CON", "con.txt", "a:b", "x.", "NUL"):
        r = owner.client.post(CREATE, json={"path": bad, "size": 1})
        assert r.status_code in (400, 404), bad


def test_at_most_n_live_uploads_per_user(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_uploads_per_user=3)
    a = session_for(env, "owner", "correct horse battery")
    env.add_user("friend", "friendly passphrase 42")
    b = session_for(env, "friend", "friendly passphrase 42")
    ids = [start(a, f"f{i}", 10).json()["upload_id"] for i in range(3)]
    r = start(a, "one-too-many", 10, expect=409)
    assert code(r) == "too_many_uploads"
    assert len(staging_files(a)) == 3  # the refused one left no staging file
    start(b, "friend-file", 10)  # the limit is per user
    assert a.client.delete(f"{UPLOADS}/{ids[0]}").status_code == 204
    start(a, "now-it-fits", 10)


def test_default_limit_is_eight_uploads(owner: Session) -> None:
    for i in range(8):
        start(owner, f"f{i}", 1)
    assert code(start(owner, "f9", 1, expect=409)) == "too_many_uploads"


def test_zero_byte_uploads_do_not_count_against_the_limit(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_uploads_per_user=1)
    s = session_for(env, "owner", "correct horse battery")
    start(s, "a", 1)
    start(s, "empty", 0)


# ---- chunks ---------------------------------------------------------------------------------


def test_offset_mismatch_reports_the_real_offset(owner: Session) -> None:
    uid = start(owner, "f", 100).json()["upload_id"]
    send(owner, uid, 0, b"x" * 30)
    for wrong in (0, 10, 31, 99):
        r = send(owner, uid, wrong, b"y")
        assert r.status_code == 409 and code(r) == "offset_mismatch"
        assert r.headers["upload-offset"] == "30"
        assert r.json()["error"]["offset"] == 30
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 30  # nothing was written


def test_resending_an_acknowledged_chunk_is_a_mismatch_not_a_duplicate(owner: Session) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    assert send(owner, uid, 0, b"12345").status_code == 200
    assert send(owner, uid, 0, b"12345").status_code == 409
    assert send(owner, uid, 5, b"67890").json()["complete"] is True
    assert (owner.home / "f").read_bytes() == b"1234567890"


@pytest.mark.parametrize("value", [None, "", "abc", "-1", "1.5", " 5", "5 ", "0x10", "1" * 30])
def test_bad_upload_offset_header_is_a_400(owner: Session, value: str | None) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    headers = dict(OCTET)
    if value is not None:
        headers["Upload-Offset"] = value
    r = owner.client.patch(f"{UPLOADS}/{uid}", content=b"x", headers=headers)
    assert r.status_code == 400 and code(r) == "invalid_request"
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 0


def test_chunk_beyond_the_declared_size_is_413_and_changes_nothing(owner: Session) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    send(owner, uid, 0, b"x" * 8)
    r = send(owner, uid, 8, b"y" * 3)
    assert r.status_code == 413 and code(r) == "payload_too_large"
    assert staging_files(owner)[0].stat().st_size == 8  # truncated back / never written
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 8
    assert send(owner, uid, 8, b"yz").json()["complete"] is True
    assert (owner.home / "f").read_bytes() == b"x" * 8 + b"yz"


def test_chunk_larger_than_the_chunk_limit_is_413(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(upload_chunk_max_bytes=1000)
    s = session_for(env, "owner", "correct horse battery")
    uid = start(s, "f", 100_000).json()["upload_id"]
    send(s, uid, 0, b"a" * 1000)
    # declared via Content-Length
    r = send(s, uid, 1000, b"b" * 1001)
    assert r.status_code == 413 and code(r) == "payload_too_large"
    # without a Content-Length (chunked transfer)
    r = send(s, uid, 1000, iter([b"b" * 600, b"b" * 600]))
    assert r.status_code == 413
    # far above the middleware cap too
    r = send(s, uid, 1000, b"b" * (1000 + CHUNK_BODY_SLACK_BYTES + 1))
    assert r.status_code == 413
    assert s.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 1000
    assert staging_files(s)[0].stat().st_size == 1000
    assert send(s, uid, 1000, b"c" * 1000).status_code == 200  # a chunk at the limit is fine


def test_empty_chunk_is_a_noop_status_check(owner: Session) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    send(owner, uid, 0, b"abc")
    r = send(owner, uid, 3, b"")
    assert r.status_code == 200 and r.json()["offset"] == 3 and r.json()["complete"] is False


def test_disk_full_from_the_storage_layer_maps_to_507(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    send(owner, uid, 0, b"abc")

    def boom(*_a: object, **_k: object) -> int:
        raise DiskFull("disk-full")

    monkeypatch.setattr(files, "append_chunk", boom)
    r = send(owner, uid, 3, b"defg")
    assert r.status_code == 507 and code(r) == "insufficient_storage"
    monkeypatch.undo()
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 3


def test_staging_file_is_the_truth_about_the_offset(owner: Session) -> None:
    uid = start(owner, "f", 200).json()["upload_id"]
    send(owner, uid, 0, b"x" * 100)
    with staging_files(owner)[0].open("r+b") as fh:  # simulate a crash that lost the tail
        fh.truncate(60)
    r = send(owner, uid, 100, b"y")
    assert r.status_code == 409 and r.json()["error"]["offset"] == 60
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 60
    assert send(owner, uid, 60, b"z" * 140).json()["complete"] is True
    assert (owner.home / "f").read_bytes() == b"x" * 60 + b"z" * 140


def test_vanished_staging_file_ends_the_upload(owner: Session) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    staging_files(owner)[0].unlink()
    assert owner.client.get(f"{UPLOADS}/{uid}").status_code == 404
    assert rows(owner) == []  # the dead row is cleaned up
    uid2 = start(owner, "g", 10).json()["upload_id"]
    staging_files(owner)[0].unlink()
    assert send(owner, uid2, 0, b"x").status_code == 404
    assert rows(owner) == []


def test_concurrent_chunks_at_the_same_offset_one_wins(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    # Six requests at once: raise the per-user cap so that the upload lock is what decides.
    owner = session_for(
        make_auth_env(max_concurrent_chunks_per_user=6), "owner", "correct horse battery"
    )
    uid = start(owner, "f", 2_000_000).json()["upload_id"]
    results: list[httpx.Response] = []
    barrier = threading.Barrier(6)

    def worker(fill: bytes) -> None:
        client = owner.env.client(**bearer(owner.token))
        barrier.wait()
        results.append(
            client.patch(
                f"{UPLOADS}/{uid}",
                content=fill * 1_000_000,
                headers={**OCTET, "Upload-Offset": "0"},
            )
        )

    threads = [threading.Thread(target=worker, args=(bytes([65 + i]),)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 409, 409, 409, 409, 409]
    winner = next(r for r in results if r.status_code == 200)
    assert winner.json()["offset"] == 1_000_000
    staged = staging_files(owner)[0].read_bytes()
    assert len(staged) == 1_000_000 and len(set(staged)) == 1  # one writer, no interleaving
    losers = [r for r in results if r.status_code == 409]
    # Either the winner was still writing (busy) or it had already finished (offset mismatch).
    assert {code(r) for r in losers} <= {"upload_busy", "offset_mismatch"}
    assert all(r.headers["upload-offset"] == str(r.json()["error"]["offset"]) for r in losers)
    assert all(
        r.json()["error"]["offset"] == 1_000_000 for r in losers if code(r) == "offset_mismatch"
    )


def test_progress_resumption_after_connection_trouble(owner: Session) -> None:
    """A client that lost the answer asks for the offset and continues from there."""
    data = os.urandom(5000)
    uid = start(owner, "f", len(data)).json()["upload_id"]
    send(owner, uid, 0, data[:2000])  # the answer was "lost"
    offset = owner.client.get(f"{UPLOADS}/{uid}").json()["offset"]
    assert offset == 2000
    assert send(owner, uid, offset, data[offset:]).json()["complete"] is True
    assert (owner.home / "f").read_bytes() == data


# ---- status, head, abort --------------------------------------------------------------------


def test_progress_and_head(owner: Session) -> None:
    uid = start(owner, "docs.txt", 50).json()["upload_id"]
    send(owner, uid, 0, b"x" * 20)
    r = owner.client.get(f"{UPLOADS}/{uid}")
    assert r.status_code == 200
    assert r.json() == {"upload_id": uid, "offset": 20, "size": 50, "path": "docs.txt"}
    assert r.headers["upload-offset"] == "20"
    h = owner.client.head(f"{UPLOADS}/{uid}")
    assert h.status_code == 200 and h.content == b""
    assert h.headers["upload-offset"] == "20" and h.headers["upload-length"] == "50"


def test_abort_discards_staging_and_row(owner: Session) -> None:
    uid = start(owner, "f", 50).json()["upload_id"]
    send(owner, uid, 0, b"x" * 20)
    r = owner.client.delete(f"{UPLOADS}/{uid}")
    assert r.status_code == 204 and r.content == b""
    assert staging_files(owner) == [] and rows(owner) == []
    assert owner.client.get(f"{UPLOADS}/{uid}").status_code == 404
    assert owner.client.delete(f"{UPLOADS}/{uid}").status_code == 404
    assert send(owner, uid, 20, b"x").status_code == 404
    assert not (owner.home / "f").exists()


def test_locks_do_not_pile_up(owner: Session) -> None:
    done = start(owner, "a", 1).json()["upload_id"]
    send(owner, done, 0, b"x")
    aborted = start(owner, "b", 1).json()["upload_id"]
    send(owner, aborted, 0, b"")
    owner.client.delete(f"{UPLOADS}/{aborted}")
    for bad in ("0" * 32, "f" * 32, "nonsense"):
        owner.client.get(f"{UPLOADS}/{bad}")
        send(owner, bad, 0, b"x")
    assert owner.env.uploads._locks == {}


# ---- ownership ------------------------------------------------------------------------------


def test_another_users_upload_is_indistinguishable_from_a_missing_one(
    owner: Session, friend: Session
) -> None:
    uid = start(owner, "mine.bin", 10).json()["upload_id"]
    send(owner, uid, 0, b"12345")
    missing = "0" * 32

    def shape(r: httpx.Response) -> tuple[int, str, str]:
        return r.status_code, code(r), r.json()["error"]["message"]

    for call in (
        lambda s, u: s.client.get(f"{UPLOADS}/{u}"),
        lambda s, u: send(s, u, 0, b"evil"),
        lambda s, u: send(s, u, 5, b"evil!"),
        lambda s, u: s.client.delete(f"{UPLOADS}/{u}"),
    ):
        stranger = call(friend, uid)
        absent = call(friend, missing)
        assert stranger.status_code == 404
        assert shape(stranger) == shape(absent)
    assert friend.client.head(f"{UPLOADS}/{uid}").status_code == 404
    # the owner's upload is untouched and still completes
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 5
    assert send(owner, uid, 5, b"67890").json()["complete"] is True
    assert (owner.home / "mine.bin").read_bytes() == b"1234567890"
    assert not list(friend.home.iterdir())


def test_the_owner_role_does_not_grant_access_to_a_friends_upload(
    owner: Session, friend: Session
) -> None:
    uid = start(friend, "f.bin", 10).json()["upload_id"]
    assert owner.client.get(f"{UPLOADS}/{uid}").status_code == 404
    assert owner.client.delete(f"{UPLOADS}/{uid}").status_code == 404
    assert len(staging_files(friend)) == 1


@pytest.mark.parametrize(
    "bad",
    ["abc", "A" * 32, "g" * 32, "0" * 31, "0" * 33, "..", "%2e%2e", "0" * 32 + ".part", "x/y"],
)
def test_malformed_upload_ids_are_404(owner: Session, bad: str) -> None:
    assert owner.client.get(f"{UPLOADS}/{bad}").status_code == 404
    assert send(owner, bad, 0, b"x").status_code == 404
    assert owner.client.delete(f"{UPLOADS}/{bad}").status_code == 404


def test_upload_cannot_target_another_users_home(owner: Session, friend: Session) -> None:
    r = owner.client.post(CREATE, json={"path": f"../{friend.user_id}/x", "size": 1})
    assert r.status_code == 400
    assert list(friend.home.iterdir()) == []


def test_revoked_session_cannot_continue_an_upload(owner: Session, auth_env: AuthEnv) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    owner.client.post("/api/v1/auth/logout")
    c = auth_env.client()
    r = c.patch(f"{UPLOADS}/{uid}", content=b"x", headers={**OCTET, "Upload-Offset": "0"})
    assert r.status_code == 401
    assert staging_files(owner)[0].stat().st_size == 0
    # a new session of the same user can still continue it
    again = session_for(auth_env, "owner", "correct horse battery")
    assert send(again, uid, 0, b"x" * 10).json()["complete"] is True


def test_deleting_the_user_removes_the_rows(owner: Session, friend: Session) -> None:
    start(friend, "f", 10)
    with friend.env.db.transaction() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (friend.user_id,))
    assert rows(owner) == []


# ---- restart --------------------------------------------------------------------------------


def test_upload_resumes_after_a_restart(auth_env: AuthEnv, owner: Session) -> None:
    data = os.urandom(9000)
    uid = start(owner, "survivor.bin", len(data)).json()["upload_id"]
    assert send(owner, uid, 0, data[:3000]).json()["offset"] == 3000

    env2 = auth_env.restart()  # new app, new database connection, new upload service
    client = env2.client(**bearer(owner.token))  # the same login still works
    progress = client.get(f"{UPLOADS}/{uid}")
    assert progress.status_code == 200 and progress.json()["offset"] == 3000
    r = client.patch(
        f"{UPLOADS}/{uid}", content=data[3000:], headers={**OCTET, "Upload-Offset": "3000"}
    )
    assert r.status_code == 200 and r.json()["complete"] is True
    assert (owner.home / "survivor.bin").read_bytes() == data
    assert staging_files(owner) == []


def test_restart_keeps_young_staging_and_drops_nothing_else(
    auth_env: AuthEnv, owner: Session
) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    send(owner, uid, 0, b"12345")
    env2 = auth_env.restart().restart()
    assert len(staging_files(owner)) == 1
    assert env2.client(**bearer(owner.token)).get(f"{UPLOADS}/{uid}").json()["offset"] == 5


def test_restart_sweeps_staging_older_than_the_stale_limit(
    auth_env: AuthEnv, owner: Session
) -> None:
    uid = start(owner, "f", 10).json()["upload_id"]
    part = staging_files(owner)[0]
    old = part.stat().st_mtime - 73 * 3600
    os.utime(part, (old, old))
    env2 = auth_env.restart()
    assert staging_files(owner) == []
    # The row is still there (it is removed by upload maintenance) but the upload is dead.
    assert env2.client(**bearer(owner.token)).get(f"{UPLOADS}/{uid}").status_code == 404


# ---- log events -----------------------------------------------------------------------------


def test_upload_events_carry_user_and_size_but_no_paths(
    owner: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="yournas")
    upload_whole(owner, "TopSecretName.pdf", b"x" * 10, chunk=4)
    uid = start(owner, "AnotherSecretName.pdf", 10).json()["upload_id"]
    owner.client.delete(f"{UPLOADS}/{uid}")
    events = [r for r in caplog.records if r.getMessage().startswith("upload_")]
    assert [r.getMessage() for r in events] == [
        "upload_created",
        "upload_completed",
        "upload_created",
        "upload_aborted",
    ]
    assert all(r.user_id == owner.user_id for r in events)  # type: ignore[attr-defined]
    assert events[0].size == 10 and events[1].size == 10  # type: ignore[attr-defined]
    everything = " ".join(str(r.__dict__) + r.getMessage() for r in caplog.records)
    assert "SecretName" not in everything
    assert owner.token not in everything


# ---- request body limits and authentication -------------------------------------------------


def concrete(path: str) -> str:
    return path.replace("{space}", "home").replace("{upload_id}", "0" * 32)


def test_every_route_with_a_body_has_a_size_cap_before_authentication(
    auth_env: AuthEnv,
) -> None:
    client = auth_env.client()
    routes = routes_of(auth_env.app)
    assert len(routes) >= 17
    chunk_cap = auth_env.settings.upload_chunk_max_bytes
    for method, path in sorted(routes):
        if method in ("GET", "HEAD", "DELETE"):
            size = JSON_BODY_LIMIT_BYTES + 1
        elif method == "PATCH":
            size = chunk_cap + CHUNK_BODY_SLACK_BYTES + 1
        else:
            size = JSON_BODY_LIMIT_BYTES + 1
        r = client.request(method, concrete(path), content=b"x" * size)
        if method == "HEAD":
            assert r.status_code == 413, (method, path)
            continue
        assert r.status_code == 413, (method, path, r.status_code)
        assert r.json()["error"]["code"] == "payload_too_large"


def test_json_routes_in_spaces_are_capped_at_16_kib(owner: Session) -> None:
    pad = "a" * (JSON_BODY_LIMIT_BYTES)
    r = owner.client.post(CREATE, json={"path": "a", "size": 1, "pad": pad})
    assert r.status_code == 413
    r = owner.client.post("/api/v1/spaces/home/folders", json={"path": pad})
    assert r.status_code == 413


def test_chunk_limit_is_not_the_json_limit(owner: Session) -> None:
    uid = start(owner, "f", 100_000).json()["upload_id"]
    assert send(owner, uid, 0, b"x" * (JSON_BODY_LIMIT_BYTES * 3)).status_code == 200


def test_unauthenticated_requests_never_reach_the_upload_logic(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for method, path in sorted(routes_of(auth_env.app)):
        if "upload" not in path and "/spaces" not in path:
            continue
        r = client.request(method, concrete(path))
        assert r.status_code == 401, (method, path)
        assert r.headers["www-authenticate"] == "Bearer"
    assert staging_files_of(auth_env) == []


def staging_files_of(env: AuthEnv) -> list[Path]:
    return sorted((env.storage_root / ".yournas-tmp").iterdir())


# ---- over a real socket ---------------------------------------------------------------------


def raw_patch(
    live: tuple[str, int], token: str, uid: str, offset: int, body: bytes, *, declare: int | None
) -> socket.socket:
    """Send a PATCH head (declaring `declare` bytes) and `body`, without waiting for an answer."""
    sock = socket.create_connection(live, timeout=10)
    length = len(body) if declare is None else declare
    head = (
        f"PATCH {UPLOADS}/{uid} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n"
        f"Content-Type: application/octet-stream\r\nUpload-Offset: {offset}\r\n"
        f"Content-Length: {length}\r\n\r\n"
    )
    sock.sendall(head.encode() + body)
    return sock


def test_upload_over_a_real_socket(owner: Session, live: tuple[str, int]) -> None:
    import http.client

    data = os.urandom(3_000_000)
    uid = start(owner, "real.bin", len(data)).json()["upload_id"]
    conn = http.client.HTTPConnection(*live, timeout=10)
    for offset in range(0, len(data), 1_000_000):
        conn.request(
            "PATCH",
            f"{UPLOADS}/{uid}",
            body=data[offset : offset + 1_000_000],
            headers={**OCTET, **bearer(owner.token), "Upload-Offset": str(offset)},
        )
        resp = conn.getresponse()
        assert resp.status == 200, resp.read()
        resp.read()
    conn.close()
    assert (owner.home / "real.bin").read_bytes() == data


def test_client_dropping_mid_chunk_changes_nothing_and_logs_no_error(
    owner: Session, live: tuple[str, int], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="yournas")
    uid = start(owner, "f.bin", 100_000).json()["upload_id"]
    assert send(owner, uid, 0, b"a" * 10_000).status_code == 200
    # promise 50 000 bytes, deliver 5 000, hang up
    sock = raw_patch(live, owner.token, uid, 10_000, b"b" * 5_000, declare=50_000)
    sock.close()
    deadline = time.time() + 5
    while time.time() < deadline and not any(
        r.getMessage() == "request" and getattr(r, "method", "") == "PATCH" for r in caplog.records
    ):
        time.sleep(0.05)
    assert staging_files(owner)[0].stat().st_size == 10_000  # the half chunk was never written
    assert owner.client.get(f"{UPLOADS}/{uid}").json()["offset"] == 10_000
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert send(owner, uid, 10_000, b"c" * 90_000).json()["complete"] is True  # resume works
    assert (owner.home / "f.bin").read_bytes() == b"a" * 10_000 + b"c" * 90_000


def test_oversized_declared_chunk_is_refused_before_the_body_is_read(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(upload_chunk_max_bytes=2000)
    s = session_for(env, "owner", "correct horse battery")
    uid = start(s, "f", 1_000_000).json()["upload_id"]
    r = s.client.patch(
        f"{UPLOADS}/{uid}",
        content=b"x" * 10_000_000,
        headers={**OCTET, "Upload-Offset": "0"},
    )
    assert r.status_code == 413
    assert staging_files(s)[0].stat().st_size == 0
