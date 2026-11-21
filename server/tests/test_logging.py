from __future__ import annotations

import io
import json
import logging
import shutil
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import suppress
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from yournas.core.logging_setup import (
    LOG_FILE_NAME,
    REDACTED,
    JsonFormatter,
    configure_logging,
    redact_text,
    shutdown_logging,
)


@pytest.fixture(autouse=True)
def _clean_logging() -> Iterator[None]:
    yield
    shutdown_logging()


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abc.def-ghi_123", "abc.def-ghi_123"),
        ("authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("login failed password=hunter2 for bob", "hunter2"),
        ('token: "abc 123 xyz"', "abc 123 xyz"),
        ("api_key=zzzSECRETzzz&x=1", "zzzSECRETzzz"),
        ("Cookie: sessionid=cafe1234", "cafe1234"),
        ("secret = 'p@ss w0rd'", "p@ss w0rd"),
        ('{"password": "hunter2"}', "hunter2"),
        ("{'password': 'hunter2'}", "hunter2"),
        ('{"token":"tok-abc-999"}', "tok-abc-999"),
        ("user_password=x1y2z3", "x1y2z3"),
        ("db_token=tok999", "tok999"),
        ("passwordHash=abc123hash", "abc123hash"),
        ("Cookie: sid=AAA111; other=BBB222", "BBB222"),
        ("Set-Cookie: a=ZZZ999; Path=/; HttpOnly", "ZZZ999"),
        ("Authorization: Digest username=bob response=RESP777", "RESP777"),
        ("Proxy-Authorization: Basic Zm9vOmJhcg==", "Zm9vOmJhcg=="),
        ("connect https://bob:SECRETPW@host.example/db", "SECRETPW"),
        ("login pass=letmein2", "letmein2"),
    ],
)
def test_redact_text_removes_secret(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


def test_redact_text_keeps_harmless_text() -> None:
    assert redact_text("upload finished in 12 ms") == "upload finished in 12 ms"


@pytest.mark.parametrize(
    "text",
    ["Cookie: sid=A; other=B", "password=hunter2", '{"token": "abc"}', "Authorization: Bearer x.y"],
)
def test_redaction_is_idempotent(text: str) -> None:
    once = redact_text(text)
    assert redact_text(once) == once


@pytest.mark.parametrize(
    "text",
    ["a" * 300_000, "word-with.dots_" * 40_000, "token " * 50_000],
    ids=["one-long-word", "dotted-words", "repeated-keyword"],
)
def test_redaction_is_fast_on_long_input(text: str) -> None:
    start = time.perf_counter()
    redact_text(text)
    assert time.perf_counter() - start < 2.0


def test_non_string_extras_are_redacted() -> None:
    logger, buf = _logger_with_buffer()
    logger.info(
        "boom",
        extra={
            "err": ValueError("password=hunter2"),
            "where": Path("C:/x/token=abc999"),
            "nested": [ValueError("secret=s3cr3t")],
            "count": 3,
        },
    )
    line = buf.getvalue()
    for secret in ("hunter2", "abc999", "s3cr3t"):
        assert secret not in line
    assert json.loads(line)["count"] == 3


def _logger_with_buffer() -> tuple[logging.Logger, io.StringIO]:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    # Isolated logger name: the file-handler tests log through "yournas.test".
    logger = logging.getLogger("isolated.buffer")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, buf


def test_json_line_shape_and_extra_redaction() -> None:
    logger, buf = _logger_with_buffer()
    logger.info(
        "login attempt password=hunter2",
        extra={
            "user": "bob",
            "password": "hunter2",
            "headers": {"Authorization": "Bearer abc123", "x-ok": "fine"},
            "token": "t0k3n",
        },
    )
    line = buf.getvalue().strip()
    data = json.loads(line)
    assert data["level"] == "INFO" and data["logger"] == "isolated.buffer"
    assert data["ts"].endswith("+00:00")
    assert data["user"] == "bob"
    assert data["password"] == REDACTED and data["token"] == REDACTED
    assert data["headers"] == {"Authorization": REDACTED, "x-ok": "fine"}
    for secret in ("hunter2", "abc123", "t0k3n"):
        assert secret not in line


def test_exception_traceback_is_redacted() -> None:
    logger, buf = _logger_with_buffer()
    try:
        raise ValueError("bad password=hunter2")
    except ValueError:
        logger.exception("failed")
    out = buf.getvalue()
    assert "ValueError" in out
    assert "hunter2" not in out


def test_file_handler_writes_json_lines_and_releases_file(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    logging.getLogger("yournas.test").info("hello", extra={"k": 1})
    shutdown_logging()
    lines = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["message"] == "hello"
    shutil.rmtree(log_dir)  # fails on Windows if the file is still held open


def test_log_level_is_applied(tmp_path: Path) -> None:
    configure_logging("WARNING", tmp_path / "logs")
    log = logging.getLogger("yournas.test")
    log.info("quiet")
    log.warning("loud")
    shutdown_logging()
    text = (tmp_path / "logs" / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "loud" in text and "quiet" not in text


def test_words_that_merely_contain_pass_are_kept() -> None:
    assert redact_text("passed=3 bypassed=no") == "passed=3 bypassed=no"


def test_extra_cannot_overwrite_core_fields() -> None:
    logger, buf = _logger_with_buffer()
    logger.info("real message", extra={"level": "FORGED", "message_id": 1, "ts": "never"})
    data = json.loads(buf.getvalue())
    assert data["level"] == "INFO" and data["message"] == "real message"
    assert data["extra_level"] == "FORGED" and data["extra_ts"] == "never"


def test_third_party_loggers_are_redacted_too(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    logging.getLogger("asyncio").error(
        "Task failed: Authorization: Token ROOTLEAK password=hunter3"
    )
    shutdown_logging()
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "Task failed" in text
    assert "ROOTLEAK" not in text and "hunter3" not in text


def _read_records(log_dir: Path) -> list[dict[str, object]]:
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines()]


def test_logs_from_handlers_carry_the_request_id(
    make_app: Callable[..., FastAPI], tmp_path: Path
) -> None:
    app = make_app()

    @app.get("/work")
    async def work() -> dict[str, str]:
        logging.getLogger("yournas.route").info("inside handler")
        return {"ok": "yes"}

    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    with TestClient(app) as client:
        response = client.get("/work")
    shutdown_logging()
    inside = next(r for r in _read_records(log_dir) if r["message"] == "inside handler")
    assert inside["request_id"] == response.headers["x-request-id"]


def test_error_after_response_start_is_logged_once_and_marked_aborted(
    make_app: Callable[..., FastAPI], tmp_path: Path
) -> None:
    app = make_app()

    async def chunks() -> AsyncIterator[bytes]:
        yield b"first"
        raise RuntimeError("mid-stream failure")

    @app.get("/stream")
    async def stream() -> StreamingResponse:
        return StreamingResponse(chunks())

    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    with TestClient(app, raise_server_exceptions=False) as client, suppress(Exception):
        client.get("/stream")
    shutdown_logging()
    records = _read_records(log_dir)
    assert len([r for r in records if r["message"] == "unhandled_error"]) == 1
    request = next(r for r in records if r["message"] == "request" and r["path"] == "/stream")
    assert request["aborted"] is True


def test_request_log_has_no_query_string_or_credentials(
    make_app: Callable[..., FastAPI], tmp_path: Path
) -> None:
    log_dir = tmp_path / "logs"
    configure_logging("INFO", log_dir)
    with TestClient(make_app()) as client:
        client.get(
            "/health?token=abc123&path=private-notes.txt",
            headers={"Authorization": "Bearer SUPERSECRETTOKEN", "Cookie": "sid=COOKIEVALUE"},
        )
    shutdown_logging()
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in text.splitlines()]
    request = next(r for r in records if r["message"] == "request")
    assert request["path"] == "/health" and request["status"] == 200
    assert {"startup", "shutdown"} <= {r["message"] for r in records}
    for leaked in ("abc123", "private-notes", "SUPERSECRETTOKEN", "COOKIEVALUE", "Bearer"):
        assert leaked not in text
