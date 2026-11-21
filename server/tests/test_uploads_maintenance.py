"""Stale uploads, orphaned staging files and when maintenance runs."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import OWNER_NAME, OWNER_PASSWORD, AuthEnv, Session, bearer, session_for
from fastapi.testclient import TestClient

from yournas.uploads import MAINTENANCE_INTERVAL_SECONDS, ORPHAN_AGE_SECONDS

CREATE = "/api/v1/spaces/home/uploads"
UPLOADS = "/api/v1/uploads"
HOUR = 3600


def start(s: Session, path: str, size: int = 10) -> str:
    r = s.client.post(CREATE, json={"path": path, "size": size})
    assert r.status_code == 201, r.text
    return str(r.json()["upload_id"])


def chunk(s: Session, uid: str, offset: int, data: bytes) -> int:
    r = s.client.patch(
        f"{UPLOADS}/{uid}",
        content=data,
        headers={"content-type": "application/octet-stream", "Upload-Offset": str(offset)},
    )
    return int(r.status_code)


def tmp_dir(env: AuthEnv) -> Path:
    return env.storage_root / ".yournas-tmp"


def parts(env: AuthEnv) -> set[str]:
    return {p.name for p in tmp_dir(env).glob("*.part")}


def ids(env: AuthEnv) -> set[str]:
    with env.db.read() as conn:
        return {r["id"] for r in conn.execute("SELECT id FROM uploads")}


def set_mtime(path: Path, epoch: float) -> None:
    os.utime(path, (epoch, epoch))


def drop_orphan(env: AuthEnv, name: str, age_seconds: float) -> Path:
    """A staging file with no row, `age_seconds` old by the fake clock."""
    p = tmp_dir(env) / name
    p.write_bytes(b"orphan")
    set_mtime(p, env.clock() - age_seconds)
    return p


# ---- stale uploads --------------------------------------------------------------------------


def test_uploads_idle_for_the_stale_limit_are_removed_with_their_staging(
    auth_env: AuthEnv, owner: Session
) -> None:
    old = start(owner, "old")
    chunk(owner, old, 0, b"abc")
    auth_env.clock.advance(71 * HOUR)
    fresh = start(owner, "fresh")
    auth_env.clock.advance(2 * HOUR)  # old: 73 h idle, fresh: 2 h
    result = auth_env.uploads.run_maintenance()
    assert result.stale_uploads == 1
    assert ids(auth_env) == {fresh}
    assert parts(auth_env) == {f"{fresh}.part"}
    assert owner.client.get(f"{UPLOADS}/{old}").status_code == 404
    assert owner.client.get(f"{UPLOADS}/{fresh}").status_code == 200


def test_a_chunk_resets_the_idle_clock(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "f", 10)
    auth_env.clock.advance(60 * HOUR)
    assert chunk(owner, uid, 0, b"abc") == 200
    auth_env.clock.advance(60 * HOUR)  # 120 h since creation, 60 h since the last chunk
    assert auth_env.uploads.run_maintenance().stale_uploads == 0
    assert chunk(owner, uid, 3, b"defghij") == 200


def test_just_inside_and_just_outside_the_limit(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "f")
    auth_env.clock.advance(72 * HOUR)
    assert auth_env.uploads.run_maintenance().stale_uploads == 0  # exactly 72 h is not yet stale
    auth_env.clock.advance(1)
    assert auth_env.uploads.run_maintenance().stale_uploads == 1
    assert uid not in ids(auth_env)


def test_stale_limit_is_a_setting(make_auth_env: Callable[..., AuthEnv]) -> None:
    env = make_auth_env(upload_stale_hours=1)
    s = session_for(env, OWNER_NAME, OWNER_PASSWORD)
    start(s, "f")
    env.clock.advance(HOUR + 1)
    assert env.uploads.run_maintenance().stale_uploads == 1


def test_staging_file_that_is_in_use_keeps_its_row_for_the_next_run(
    auth_env: AuthEnv, owner: Session
) -> None:
    uid = start(owner, "f")
    auth_env.clock.advance(80 * HOUR)
    part = tmp_dir(auth_env) / f"{uid}.part"
    with part.open("rb"):  # a handle blocks deletion on Windows
        assert auth_env.uploads.run_maintenance().stale_uploads == 0
        assert ids(auth_env) == {uid}
    assert auth_env.uploads.run_maintenance().stale_uploads == 1
    assert ids(auth_env) == set() and parts(auth_env) == set()


def test_stale_cleanup_forgets_the_locks(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "f")
    chunk(owner, uid, 0, b"a")
    auth_env.clock.advance(80 * HOUR)
    auth_env.uploads.run_maintenance()
    assert auth_env.uploads._locks == {}


def test_stale_upload_of_one_user_does_not_touch_another_users(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    a = start(owner, "a")
    auth_env.clock.advance(80 * HOUR)
    b = start(friend, "b")
    auth_env.uploads.run_maintenance()
    assert ids(auth_env) == {b} and parts(auth_env) == {f"{b}.part"}
    assert a not in ids(auth_env)


# ---- orphans --------------------------------------------------------------------------------


def test_orphaned_staging_files_older_than_an_hour_are_removed(
    auth_env: AuthEnv, owner: Session
) -> None:
    live = start(owner, "live")
    old = drop_orphan(auth_env, "a" * 32 + ".part", ORPHAN_AGE_SECONDS + 60)
    young = drop_orphan(auth_env, "b" * 32 + ".part", ORPHAN_AGE_SECONDS - 60)
    result = auth_env.uploads.run_maintenance()
    assert result.orphan_files == 1
    assert not old.exists() and young.exists()
    assert (tmp_dir(auth_env) / f"{live}.part").exists()


def test_a_staging_file_with_a_row_is_never_an_orphan(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "f")
    part = tmp_dir(auth_env) / f"{uid}.part"
    set_mtime(part, auth_env.clock() - 10 * HOUR)  # old file, but its upload is live
    assert auth_env.uploads.run_maintenance().orphan_files == 0
    assert part.exists()


def test_maintenance_ignores_files_that_are_not_staging_files(auth_env: AuthEnv) -> None:
    strangers = [
        drop_orphan(auth_env, "notes.txt", 10 * HOUR),
        drop_orphan(auth_env, "short.part", 10 * HOUR),
        drop_orphan(auth_env, ("A" * 32) + ".part", 10 * HOUR),
        drop_orphan(auth_env, ("c" * 32) + ".part.bak", 10 * HOUR),
    ]
    (tmp_dir(auth_env) / ("d" * 32 + ".part.d")).mkdir()
    assert auth_env.uploads.run_maintenance().orphan_files == 0
    assert all(p.exists() for p in strangers)


def test_orphan_that_is_in_use_is_skipped(auth_env: AuthEnv) -> None:
    p = drop_orphan(auth_env, "e" * 32 + ".part", 5 * HOUR)
    with p.open("rb"):
        assert auth_env.uploads.run_maintenance().orphan_files == 0
    assert auth_env.uploads.run_maintenance().orphan_files == 1


def test_a_junction_in_staging_is_not_followed(auth_env: AuthEnv, tmp_path: Path) -> None:
    import subprocess

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep")
    link = tmp_dir(auth_env) / ("f" * 32 + ".part")
    r = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, text=True
    )
    if r.returncode != 0:
        pytest.skip("cannot create a junction here")
    try:
        auth_env.clock.advance(10 * HOUR)
        auth_env.uploads.run_maintenance()
        assert (outside / "precious.txt").read_text() == "keep"
    finally:
        if link.exists():
            os.rmdir(link)


# ---- when it runs ---------------------------------------------------------------------------


def test_creating_an_upload_runs_maintenance_at_most_every_ten_minutes(
    auth_env: AuthEnv, owner: Session
) -> None:
    orphan = drop_orphan(auth_env, "1" * 32 + ".part", 5 * HOUR)
    start(owner, "a")  # the clock has not moved: too soon since startup
    assert orphan.exists()
    auth_env.clock.advance(MAINTENANCE_INTERVAL_SECONDS + 1)
    start(owner, "b")
    assert not orphan.exists()
    second = drop_orphan(auth_env, "2" * 32 + ".part", 5 * HOUR)
    auth_env.clock.advance(60)
    start(owner, "c")  # ran a minute ago: skipped
    assert second.exists()


def test_a_failing_maintenance_run_does_not_block_new_uploads(
    auth_env: AuthEnv, owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> None:
        raise OSError("disk trouble")

    monkeypatch.setattr(auth_env.uploads, "_drop_orphans", lambda _cutoff: boom())
    auth_env.clock.advance(MAINTENANCE_INTERVAL_SECONDS + 1)
    start(owner, "still-works")


def test_maintenance_runs_at_application_startup(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "f")
    orphan = drop_orphan(auth_env, "3" * 32 + ".part", 5 * HOUR)
    auth_env.clock.advance(80 * HOUR)
    with TestClient(auth_env.app, client=("testclient", 1)) as client:  # runs the lifespan
        assert client.get("/health").status_code == 200
    assert uid not in ids(auth_env)
    assert not orphan.exists()
    assert parts(auth_env) == set()


def test_overlapping_runs_do_not_pile_up(auth_env: AuthEnv) -> None:
    assert auth_env.uploads._maintenance_lock.acquire(blocking=False)
    try:
        result = auth_env.uploads.run_maintenance()  # someone else is running: do nothing
        assert (result.stale_uploads, result.orphan_files) == (0, 0)
    finally:
        auth_env.uploads._maintenance_lock.release()


def test_maintenance_does_not_touch_finished_files(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "done.txt", 3)
    assert chunk(owner, uid, 0, b"abc") == 200
    auth_env.clock.advance(500 * HOUR)
    auth_env.uploads.run_maintenance()
    assert (owner.home / "done.txt").read_bytes() == b"abc"


def test_stale_rows_and_files_survive_when_they_are_not_stale_after_restart(
    auth_env: AuthEnv, owner: Session
) -> None:
    uid = start(owner, "f")
    env2 = auth_env.restart()
    with TestClient(env2.app, client=("testclient", 1), headers=bearer(owner.token)) as client:
        assert client.get(f"{UPLOADS}/{uid}").status_code == 200


def test_database_helper_rows_shape(auth_env: AuthEnv, owner: Session) -> None:
    uid = start(owner, "dir-less.txt", 7)
    with auth_env.db.read() as conn:
        row: sqlite3.Row = conn.execute("SELECT * FROM uploads WHERE id = ?", (uid,)).fetchone()
    assert row["created_at"] == row["updated_at"] == int(auth_env.clock())
