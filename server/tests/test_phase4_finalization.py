"""Phase 4 finalization: upload reservations expire and release their quota and disk space.

An upload reserves its declared size (per-user quota and the server-wide free-space check) from
the moment it is created, before a single byte arrives. These tests pin what bounds that.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from conftest import (
    FRIEND_NAME,
    FRIEND_PASSWORD,
    OWNER_NAME,
    OWNER_PASSWORD,
    AuthEnv,
    Session,
    bearer,
    session_for,
)
from fastapi.testclient import TestClient
from test_file_authz import UPLOADS, patch, start_upload

from yournas.storage import files

HOUR = 3600
DEADLINE = 7 * 24 * HOUR  # the absolute upload lifetime
FLOOR = 5 * 1024**3  # the default free_space_floor_bytes


def two_users(env: AuthEnv) -> tuple[Session, Session]:
    env.add_user(FRIEND_NAME, FRIEND_PASSWORD)
    return (
        session_for(env, OWNER_NAME, OWNER_PASSWORD),
        session_for(env, FRIEND_NAME, FRIEND_PASSWORD),
    )


def staged(env: AuthEnv) -> set[str]:
    return {p.name for p in (env.storage_root / ".yournas-tmp").glob("*.part")}


def test_an_expired_reservation_releases_the_users_quota(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    assert start_upload(friend, "home", "one.bin", 100).status_code == 201
    refused = start_upload(friend, "home", "two.bin", 1)
    assert refused.status_code == 507 and refused.json()["error"]["code"] == "upload_quota_exceeded"
    env.clock.advance(73 * HOUR)  # no byte was ever sent: idle for longer than the 72 h limit
    assert start_upload(friend, "home", "two.bin", 100).status_code == 201  # create ran the sweep
    assert len(staged(env)) == 1  # the expired upload's staging file is gone


def test_an_expired_reservation_releases_server_wide_capacity(
    make_auth_env: Callable[..., AuthEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_auth_env()
    owner, friend = two_users(env)
    monkeypatch.setattr(files, "free_bytes", lambda _path: FLOOR + 1000)
    assert start_upload(friend, "home", "hog.bin", 800).status_code == 201
    blocked = start_upload(owner, "home", "mine.bin", 500)  # 800 reserved + 500 > 1000 of room
    assert blocked.status_code == 507 and blocked.json()["error"]["code"] == "insufficient_storage"
    env.clock.advance(73 * HOUR)
    assert start_upload(owner, "home", "mine.bin", 500).status_code == 201


def test_a_reservation_that_is_still_young_keeps_its_capacity(
    make_auth_env: Callable[..., AuthEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_auth_env()
    owner, friend = two_users(env)
    monkeypatch.setattr(files, "free_bytes", lambda _path: FLOOR + 1000)
    assert start_upload(friend, "home", "hog.bin", 800).status_code == 201
    env.clock.advance(71 * HOUR)
    assert start_upload(owner, "home", "mine.bin", 500).status_code == 507


def test_one_user_cannot_use_up_the_per_user_quota_of_another(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    owner, friend = two_users(env)
    assert start_upload(friend, "home", "hog.bin", 100).status_code == 201
    assert start_upload(owner, "home", "mine.bin", 100).status_code == 201


def test_the_quota_and_the_expiry_survive_a_restart(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    assert start_upload(friend, "home", "one.bin", 100).status_code == 201

    env2 = env.restart()  # rows live in the database: the reservation is still counted
    with TestClient(env2.app, client=("testclient", 1), headers=bearer(friend.token)) as c:
        r = c.post("/api/v1/spaces/home/uploads", json={"path": "two.bin", "size": 1})
        assert r.status_code == 507 and r.json()["error"]["code"] == "upload_quota_exceeded"

    env2.clock.advance(73 * HOUR)
    env3 = env2.restart()  # startup maintenance frees the abandoned reservation
    with TestClient(env3.app, client=("testclient", 1), headers=bearer(friend.token)) as c:
        r = c.post("/api/v1/spaces/home/uploads", json={"path": "two.bin", "size": 100})
        assert r.status_code == 201
    assert len(staged(env3)) == 1  # only the new upload's staging file remains


# ---- the absolute lifetime of an upload ------------------------------------------------------


def test_a_trickle_of_bytes_renews_the_idle_limit_but_not_the_absolute_one(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "slow.bin", 100).json()["upload_id"]
    for offset in range(2):  # t = 60 h and 120 h: inside both limits, each chunk renews idle
        env.clock.advance(60 * HOUR)
        assert patch(friend, uid, offset, b"x").status_code == 200
    assert start_upload(friend, "home", "second.bin", 1).status_code == 507  # still reserved
    env.clock.advance(60 * HOUR)  # t = 180 h: past 7 days although the last chunk is 60 h old
    assert patch(friend, uid, 2, b"x").status_code == 404
    assert friend.client.get(f"{UPLOADS}/{uid}").status_code == 404
    # Nothing renews it; the next create sweeps it and the quota and staging file are released.
    assert start_upload(friend, "home", "second.bin", 100).status_code == 201
    assert len(staged(env)) == 1


def test_the_deadline_boundary_is_exact(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "edge.bin", 10).json()["upload_id"]
    env.clock.advance(DEADLINE)  # exactly 7 days old is still alive
    assert patch(friend, uid, 0, b"a").status_code == 200
    env.clock.advance(1)
    assert patch(friend, uid, 1, b"b").status_code == 404
    assert friend.client.get(f"{UPLOADS}/{uid}").status_code == 404


def test_maintenance_removes_an_upload_only_after_the_deadline_even_when_it_is_not_idle(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "edge.bin", 10).json()["upload_id"]
    env.clock.advance(120 * HOUR)
    assert patch(friend, uid, 0, b"a").status_code == 200  # idle clock restarts here
    env.clock.advance(DEADLINE - 120 * HOUR)  # exactly 7 days old, 48 h idle
    assert env.uploads.run_maintenance().stale_uploads == 0
    assert len(staged(env)) == 1
    env.clock.advance(1)  # 7 days and a second old, still only 48 h idle
    assert env.uploads.run_maintenance().stale_uploads == 1
    assert staged(env) == set()
    with env.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM uploads").fetchone()[0] == 0


def test_expiry_releases_quota_and_leaves_finished_files_alone(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    done = start_upload(friend, "home", "done.bin", 3).json()["upload_id"]
    assert patch(friend, done, 0, b"abc").json()["complete"] is True
    start_upload(friend, "home", "hog.bin", 100)
    assert start_upload(friend, "home", "more.bin", 1).status_code == 507
    env.clock.advance(DEADLINE + 1)
    assert env.uploads.run_maintenance().stale_uploads == 1
    assert (friend.home / "done.bin").read_bytes() == b"abc"  # the finished file stays
    assert start_upload(friend, "home", "more.bin", 100).status_code == 201


def test_a_user_can_still_discard_an_expired_upload_at_once(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "old.bin", 100).json()["upload_id"]
    env.clock.advance(DEADLINE + 1)
    assert friend.client.delete(f"{UPLOADS}/{uid}").status_code == 204
    assert staged(env) == set()
    assert start_upload(friend, "home", "new.bin", 100).status_code == 201


def test_the_deadline_survives_a_restart(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(max_inflight_upload_bytes_per_user=100, session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "slow.bin", 10).json()["upload_id"]
    env.clock.advance(60 * HOUR)
    assert patch(friend, uid, 0, b"x").status_code == 200

    env2 = env.restart()  # created_at is in the database: the age is not reset by a restart
    env2.clock.advance(60 * HOUR)
    r = env2.client(**bearer(friend.token)).patch(
        f"{UPLOADS}/{uid}",
        content=b"y",
        headers={"content-type": "application/octet-stream", "Upload-Offset": "1"},
    )
    assert r.status_code == 200  # 120 h old: alive, and its idle clock is fresh again

    env2.clock.advance(60 * HOUR)  # 180 h old, only 60 h idle: just the absolute limit applies
    env3 = env2.restart()
    with TestClient(env3.app, client=("testclient", 1), headers=bearer(friend.token)) as c:
        assert c.get(f"{UPLOADS}/{uid}").status_code == 404
        # startup maintenance has already released the quota and the staging file
        ok = c.post("/api/v1/spaces/home/uploads", json={"path": "n.bin", "size": 100})
        assert ok.status_code == 201
    assert len(staged(env3)) == 1


def test_a_deadline_passing_during_the_last_chunk_stops_the_move(
    make_auth_env: Callable[..., AuthEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_auth_env()
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "late.bin", 3).json()["upload_id"]
    real = files.append_chunk

    def slow(*args: object, **kwargs: object) -> int:
        result: int = real(*args, **kwargs)  # type: ignore[arg-type]
        env.clock.advance(DEADLINE + 1)  # the write took "forever"
        return result

    monkeypatch.setattr(files, "append_chunk", slow)
    assert patch(friend, uid, 0, b"abc").status_code == 404
    assert not (friend.home / "late.bin").exists()


def test_a_chunk_that_arrives_while_the_sweep_waits_for_the_lock_saves_the_upload(
    make_auth_env: Callable[..., AuthEnv], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep selects an idle upload, then takes its lock and looks again: a chunk that
    arrived in between makes it fresh, and only the absolute limit could still drop it."""
    env = make_auth_env(session_idle_hours=24 * 30)
    _, friend = two_users(env)
    uid = start_upload(friend, "home", "busy.bin", 10).json()["upload_id"]
    env.clock.advance(73 * HOUR)  # idle past the limit, far from the 7 day deadline
    real_lock_for = env.uploads._lock_for

    def lock_after_a_chunk(upload_id: str):  # type: ignore[no-untyped-def]
        with env.db.transaction() as conn:
            conn.execute(
                "UPDATE uploads SET updated_at = ? WHERE id = ?", (int(env.clock()), upload_id)
            )
        return real_lock_for(upload_id)

    monkeypatch.setattr(env.uploads, "_lock_for", lock_after_a_chunk)
    assert env.uploads.run_maintenance().stale_uploads == 0
    with env.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM uploads WHERE id = ?", (uid,)).fetchone()[0] == 1
