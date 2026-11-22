"""Regression tests for the Phase 3 security/code review findings."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from conftest import AuthEnv, Session, bearer
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from yournas.core.logging_setup import JsonFormatter, error_fields
from yournas.core.middleware import BodyLimitMiddleware, content_length_over
from yournas.storage import files
from yournas.storage.errors import StorageIOError

CREATE = "/api/v1/spaces/home/uploads"
UPLOADS = "/api/v1/uploads"
ITEMS = "/api/v1/spaces/home/items"
OCTET = {"content-type": "application/octet-stream"}
FLOOR = 5 * 1024**3  # the default free_space_floor_bytes
SECRET_PATH = r"C:\secret-dir\TopSecretName.pdf"


def code(r: httpx.Response) -> str:
    return str(r.json()["error"]["code"])


def start(s: Session, path: str, size: int, *, expect: int = 201) -> httpx.Response:
    r: httpx.Response = s.client.post(CREATE, json={"path": path, "size": size})
    assert r.status_code == expect, r.text
    return r


def send(s: Session, upload_id: str, offset: int, data: bytes) -> httpx.Response:
    r: httpx.Response = s.client.patch(
        f"{UPLOADS}/{upload_id}", content=data, headers={**OCTET, "Upload-Offset": str(offset)}
    )
    return r


def rows(s: Session) -> list[sqlite3.Row]:
    with s.env.db.read() as conn:
        return list(conn.execute("SELECT * FROM uploads"))


def staging_files(s: Session) -> list[Path]:
    return sorted((s.env.storage_root / ".yournas-tmp").glob("*.part"))


def offset_of(s: Session, upload_id: str) -> int:
    return int(s.client.get(f"{UPLOADS}/{upload_id}").json()["offset"])


def os_error() -> OSError:
    """An OSError the way Windows words it: path and file name inside the message."""
    return OSError(5, f"Access is denied: {SECRET_PATH}", SECRET_PATH)


def rendered_logs(caplog: pytest.LogCaptureFixture) -> str:
    """Everything the log would show: the JSON lines as written plus pytest's own rendering."""
    fmt = JsonFormatter()
    return "\n".join(fmt.format(r) for r in caplog.records) + "\n" + caplog.text


def assert_no_secrets(text: str) -> None:
    for secret in ("TopSecretName", "secret-dir", "Access is denied"):
        assert secret not in text, secret


# ---- 1. a success must stay a success -------------------------------------------------------


def test_failing_row_delete_after_the_move_still_returns_the_finished_item(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = start(owner, "done.bin", 3).json()["upload_id"]

    def boom(_upload_id: str) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(owner.env.uploads, "_delete_row", boom)
    r = send(owner, uid, 0, b"abc")
    assert r.status_code == 200 and r.json()["complete"] is True
    assert r.json()["item"]["name"] == "done.bin" and r.json()["item"]["size"] == 3
    assert (owner.home / "done.bin").read_bytes() == b"abc"
    assert staging_files(owner) == [] and owner.env.uploads._locks == {}
    assert len(rows(owner)) == 1  # the leftover row; the upload can no longer continue
    monkeypatch.undo()
    assert owner.client.get(f"{UPLOADS}/{uid}").status_code == 404  # and is swept on contact
    assert rows(owner) == []


def test_failing_stat_after_the_move_still_returns_the_finished_item(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    uid = start(owner, "done.bin", 3).json()["upload_id"]

    real = files._lstat

    def flaky(path: Path) -> object:
        if path.name in ("done.bin", "empty.bin"):  # only the look at the new file fails
            raise StorageIOError("errno=5")
        return real(path)

    monkeypatch.setattr(files, "_lstat", flaky)
    r = send(owner, uid, 0, b"abc")
    assert r.status_code == 200 and r.json()["complete"] is True
    assert r.json()["item"]["name"] == "done.bin" and r.json()["item"]["size"] == 3
    assert (owner.home / "done.bin").read_bytes() == b"abc"
    assert rows(owner) == [] and staging_files(owner) == []
    # a zero-byte upload goes through the same last step
    done = owner.client.post(CREATE, json={"path": "empty.bin", "size": 0})
    assert done.status_code == 201 and done.json()["complete"] is True
    assert done.json()["item"]["size"] == 0


# ---- 2. logs never carry paths or file names ------------------------------------------------


def test_error_fields_are_type_and_numbers_only() -> None:
    assert error_fields(os_error()) == {"error_type": "OSError", "errno": 5}
    wrapped = StorageIOError("errno=5")
    wrapped.__cause__ = os_error()
    assert error_fields(wrapped) == {"error_type": "OSError", "errno": 5}
    assert error_fields(sqlite3.OperationalError(SECRET_PATH)) == {"error_type": "OperationalError"}
    assert SECRET_PATH not in str(error_fields(os_error()))


def test_storage_io_error_is_logged_without_path_or_name(
    owner: Session, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="yournas")
    exc = os_error()

    def boom(*_a: object, **_k: object) -> object:
        raise files.translate_os_error(exc) from exc

    monkeypatch.setattr(files, "list_dir", boom)
    r = owner.client.get(ITEMS)
    assert r.status_code == 500 and code(r) == "internal_error"
    (record,) = [r for r in caplog.records if r.getMessage() == "storage_io_error"]
    assert record.levelno == logging.ERROR and record.exc_info is None
    assert (record.error_type, record.errno) == ("OSError", 5)  # type: ignore[attr-defined]
    assert_no_secrets(rendered_logs(caplog))
    assert_no_secrets(r.text)


def test_failed_maintenance_is_logged_without_path_or_name(
    auth_env: AuthEnv,
    owner: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from yournas.uploads import MAINTENANCE_INTERVAL_SECONDS

    caplog.set_level(logging.INFO, logger="yournas")

    def boom(_cutoff: int) -> int:
        raise os_error()

    monkeypatch.setattr(auth_env.uploads, "_drop_orphans", boom)
    auth_env.clock.advance(MAINTENANCE_INTERVAL_SECONDS + 1)
    start(owner, "still-works", 5)
    (record,) = [r for r in caplog.records if r.getMessage() == "upload_maintenance_failed"]
    assert record.exc_info is None and record.errno == 5  # type: ignore[attr-defined]
    assert_no_secrets(rendered_logs(caplog))


# ---- 3a. a second chunk of a busy upload does not wait --------------------------------------


def test_chunk_for_an_upload_that_is_being_written_is_a_409_busy_not_a_wait(
    owner: Session,
) -> None:
    uid = start(owner, "f", 100).json()["upload_id"]
    assert send(owner, uid, 0, b"x" * 10).status_code == 200
    lock = owner.env.uploads._lock_for(uid)  # a chunk of this upload is "in flight"
    assert lock.acquire(blocking=False)
    answers: list[httpx.Response] = []
    client = owner.env.client(**bearer(owner.token))

    def second_chunk() -> None:
        answers.append(
            client.patch(f"{UPLOADS}/{uid}", content=b"y", headers={**OCTET, "Upload-Offset": "10"})
        )

    t = threading.Thread(target=second_chunk)
    t.start()
    t.join(5)
    parked = t.is_alive()  # without the fix the request waits for the lock
    lock.release()
    t.join(5)
    assert not parked, "the request was parked behind the upload lock"
    (r,) = answers
    assert r.status_code == 409 and code(r) == "upload_busy"
    assert r.headers["upload-offset"] == "10" and r.json()["error"]["offset"] == 10
    assert offset_of(owner, uid) == 10  # nothing was written
    assert send(owner, uid, 10, b"z" * 90).json()["complete"] is True


# ---- 3b. a user's chunks in flight are capped -----------------------------------------------


def test_chunk_slots_are_per_user_and_released(make_auth_env: Callable[..., AuthEnv]) -> None:
    uploads = make_auth_env(max_concurrent_chunks_per_user=2).uploads
    assert uploads.try_begin_chunk("a") and uploads.try_begin_chunk("a")
    assert not uploads.try_begin_chunk("a")
    assert uploads.try_begin_chunk("b")  # another user is not affected
    uploads.end_chunk("a")
    assert uploads.try_begin_chunk("a")
    for user in ("a", "a", "b"):
        uploads.end_chunk(user)
    assert uploads._active_chunks == {}  # nothing piles up


def test_too_many_chunks_in_flight_is_a_429_before_the_body_is_read(
    owner: Session, friend: Session, live: tuple[str, int]
) -> None:
    import socket

    limit = owner.env.settings.max_concurrent_chunks_per_user
    assert limit == 4
    slow: list[socket.socket] = []
    for i in range(limit):
        uid = start(owner, f"slow{i}", 100_000).json()["upload_id"]
        sock = socket.create_connection(live, timeout=10)
        head = (
            f"PATCH {UPLOADS}/{uid} HTTP/1.1\r\nHost: localhost\r\n"
            f"Authorization: Bearer {owner.token}\r\n"
            f"Content-Type: application/octet-stream\r\nUpload-Offset: 0\r\n"
            f"Content-Length: 50000\r\n\r\n"
        )
        sock.sendall(head.encode() + b"a" * 100)  # promises 50 000 bytes, sends 100, waits
        slow.append(sock)
    try:
        deadline = time.time() + 5
        while owner.env.uploads._active_chunks.get(owner.user_id) != limit:
            assert time.time() < deadline, "the slow requests never registered"
            time.sleep(0.02)

        uid = start(owner, "one-too-many", 10).json()["upload_id"]
        r = send(owner, uid, 0, b"z")
        assert r.status_code == 429 and code(r) == "too_many_requests"
        assert r.headers["retry-after"] == "1"
        assert offset_of(owner, uid) == 0  # refused, not written

        other = start(friend, "friends-file", 3).json()["upload_id"]
        assert send(friend, other, 0, b"abc").json()["complete"] is True  # per user, not global
    finally:
        for sock in slow:
            sock.close()
    deadline = time.time() + 5
    while owner.env.uploads._active_chunks.get(owner.user_id):
        assert time.time() < deadline, "slots were not released"
        time.sleep(0.02)
    assert send(owner, uid, 0, b"z" * 10).json()["complete"] is True


# ---- 4. housekeeping failures are not fatal -------------------------------------------------


def test_discard_staging_reports_failure_instead_of_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_path: Path) -> object:
        raise StorageIOError("errno=5")

    monkeypatch.setattr(files, "lstat_or_none", boom)
    assert files.discard_staging(tmp_path / ("a" * 32 + ".part")) is False


def test_stale_cleanup_goes_on_after_an_upload_that_cannot_be_removed(
    auth_env: AuthEnv,
    owner: Session,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="yournas")
    first = start(owner, "a", 10).json()["upload_id"]
    second = start(owner, "b", 10).json()["upload_id"]
    auth_env.clock.advance(80 * 3600)
    real = files.discard_staging
    calls: list[str] = []

    def flaky(path: Path) -> bool:
        calls.append(path.name)
        if len(calls) == 1:
            raise os_error()
        return real(path)

    monkeypatch.setattr(files, "discard_staging", flaky)
    result = auth_env.uploads.run_maintenance()
    assert len(calls) == 2  # the failure did not stop the second upload
    assert result.stale_uploads == 1
    assert len(rows(owner)) == 1 and rows(owner)[0]["id"] in (first, second)
    assert_no_secrets(rendered_logs(caplog))
    monkeypatch.undo()
    assert auth_env.uploads.run_maintenance().stale_uploads == 1  # the next run finishes it
    assert rows(owner) == []


@pytest.mark.parametrize(
    "error",
    [os_error(), StorageIOError("errno=5"), sqlite3.OperationalError("database is locked")],
    ids=["oserror", "storage", "sqlite"],
)
def test_failing_startup_maintenance_does_not_stop_the_app_from_booting(
    auth_env: AuthEnv,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    error: Exception,
) -> None:
    caplog.set_level(logging.INFO, logger="yournas")

    def boom() -> None:
        raise error

    monkeypatch.setattr(auth_env.uploads, "run_maintenance", boom)
    with TestClient(auth_env.app, client=("testclient", 1)) as client:  # runs the lifespan
        assert client.get("/health").status_code == 200
    (record,) = [r for r in caplog.records if r.getMessage() == "upload_maintenance_failed"]
    assert record.exc_info is None
    assert_no_secrets(rendered_logs(caplog))


# ---- 5. the free-space floor holds for every chunk and reserves at creation -----------------


def set_free(monkeypatch: pytest.MonkeyPatch, value: Callable[[], int]) -> None:
    monkeypatch.setattr(files, "free_bytes", lambda _path: value())


def test_free_space_floor_is_enforced_for_every_chunk(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    free = [FLOOR + 10_000]
    set_free(monkeypatch, lambda: free[0])
    uid = start(owner, "f", 100).json()["upload_id"]
    assert send(owner, uid, 0, b"x" * 50).status_code == 200
    free[0] = FLOOR + 49  # the disk filled up meanwhile: 50 more bytes would break the floor
    r = send(owner, uid, 50, b"y" * 50)
    assert r.status_code == 507 and code(r) == "insufficient_storage"
    assert offset_of(owner, uid) == 50 and staging_files(owner)[0].stat().st_size == 50
    free[0] = FLOOR + 50  # exactly the floor is allowed
    assert send(owner, uid, 50, b"y" * 50).json()["complete"] is True
    assert (owner.home / "f").read_bytes() == b"x" * 50 + b"y" * 50


def test_an_empty_chunk_needs_no_free_space(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    free = [FLOOR + 10_000]
    set_free(monkeypatch, lambda: free[0])
    uid = start(owner, "f", 10).json()["upload_id"]
    send(owner, uid, 0, b"abc")
    free[0] = 0
    assert send(owner, uid, 3, b"").status_code == 200  # a status check, nothing is written


def test_creating_an_upload_reserves_the_unwritten_rest_of_the_live_uploads(
    owner: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_free(monkeypatch, lambda: FLOOR + 1500)
    a = start(owner, "a", 1000).json()["upload_id"]
    start(owner, "too-big-for-the-rest", 600, expect=507)  # 1000 reserved + 600 > 1500
    start(owner, "b", 500)  # exactly what is left
    start(owner, "nothing-left", 1, expect=507)
    assert send(owner, a, 0, b"x" * 400).status_code == 200  # 400 of "a" are written now
    # The (patched) free space does not shrink, but 400 bytes are no longer owed: 400 are free.
    start(owner, "c-too-big", 401, expect=507)
    start(owner, "c", 400)
    assert len(rows(owner)) == 3


def test_reservation_counts_the_uploads_of_all_users(
    owner: Session, friend: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_free(monkeypatch, lambda: FLOOR + 1500)
    start(owner, "big", 1000)
    start(friend, "friends-big", 600, expect=507)  # not the friend's own uploads, the owner's
    start(friend, "friends-small", 500)


# ---- 6. Content-Length is parsed strictly ---------------------------------------------------


@pytest.mark.parametrize("value", ["²", "٣", "1" * 30, "-1", "+5", " 5", "5 ", "1.5", "0x10", ""])
def test_malformed_content_length_counts_as_too_large(value: str) -> None:
    assert content_length_over(value, 10**9) is True


@pytest.mark.parametrize(
    ("value", "limit", "over"), [("0", 0, False), ("10", 10, False), ("11", 10, True)]
)
def test_content_length_comparison(value: str, limit: int, over: bool) -> None:
    assert content_length_over(value, limit) is over
    assert content_length_over(None, limit) is False


def call_asgi(app: ASGIApp, method: str, path: str, headers: list[tuple[bytes, bytes]]) -> int:
    """Run one request through `app` without a server; return the status."""
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send_(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        # A real request always has a Host; the app refuses one without (Host allowlist).
        "headers": [(b"host", b"localhost"), *headers],
        "client": ("testclient", 1),
        "server": ("testserver", 80),
        "state": {},
    }

    async def run() -> None:
        await app(scope, receive, send_)

    asyncio.run(run())
    return next(int(m["status"]) for m in sent if m["type"] == "http.response.start")


@pytest.mark.parametrize("raw", [b"\xb2", b"1" * 30])  # "²" (str.isdigit() is True), 30 digits
def test_middleware_answers_413_to_an_odd_content_length(raw: bytes) -> None:
    async def never(_scope: Scope, _receive: Receive, _send: Send) -> None:
        raise AssertionError("the request must not reach the app")

    app = BodyLimitMiddleware(never, rules=[(lambda _m, _p: True, 100)])
    assert call_asgi(app, "POST", "/x", [(b"content-length", raw)]) == 413


@pytest.mark.parametrize("raw", [b"\xb2", b"1" * 30])
def test_full_app_answers_413_not_500_to_an_odd_content_length(
    auth_env: AuthEnv, raw: bytes
) -> None:
    uid = "0" * 32
    for method, path in (("PATCH", f"{UPLOADS}/{uid}"), ("POST", "/api/v1/auth/login")):
        headers = [(b"content-length", raw), (b"upload-offset", b"0")]
        assert call_asgi(auth_env.app, method, path, headers) == 413
