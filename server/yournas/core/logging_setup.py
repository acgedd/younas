"""Structured JSON logging with central redaction of secrets."""

from __future__ import annotations

import json
import logging
import re
import sys
import traceback
from contextvars import ContextVar
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

REDACTED = "[REDACTED]"
LOG_FILE_NAME = "yournas.log"
_LOGGER_NAMES = ("yournas", "uvicorn", "uvicorn.error")

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_KEYWORDS = (
    r"password|passwd|pwd|pass(?![a-z])|token|secret|authorization|cookie|api[_-]?key|session[_-]?id"
)
_URL_USERINFO = re.compile(r"(://[^/\s:@]+:)[^@\s/]+@")
_SENSITIVE_KEY = re.compile(_KEYWORDS, re.IGNORECASE)
# Whole-line headers: everything after the colon is secret (cookie lists, digest auth, ...).
_HEADER = re.compile(
    r"\b((?:set-)?cookie|(?:proxy-)?authorization)(\s*:\s*)[^\r\n]*", re.IGNORECASE
)
_BEARER = re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
# key=value, key: value, "key": "value", user_password=x, passwordHash=x.
# The match starts at the keyword (text before it is left untouched) and the rest of the key is
# bounded, so a long word full of keywords (a hostile URL path) cannot cause quadratic backtracking.
_KEY_VALUE = re.compile(
    r"((?:" + _KEYWORDS + r")[\w.-]{0,64})"
    r"""(["']?\s*[=:]\s*)"""
    r"""(?:"[^"]*"|'[^']*'|(?!\[REDACTED\])[^\s,;&"']+)""",
    re.IGNORECASE,
)
_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "taskName"}


def redact_text(text: str) -> str:
    text = _HEADER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    return _KEY_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


def redact_value(key: str, value: Any) -> Any:
    if _SENSITIVE_KEY.search(key):
        return REDACTED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_value(key, v) for v in value]
    # Exceptions, paths, arbitrary objects: json.dumps would stringify them unredacted.
    return redact_text(str(value))


def error_fields(exc: BaseException) -> dict[str, Any]:
    """The only parts of an exception that may be logged: its type and the OS error numbers.

    The message and traceback of an OSError carry server paths and file names, so they are never
    logged. A wrapper (StorageError) is looked through to the OS error it was raised from.
    """
    cause = exc.__cause__ if exc.__cause__ is not None else exc
    fields: dict[str, Any] = {"error_type": type(cause).__name__}
    for name in ("errno", "winerror"):
        value = getattr(cause, name, None)
        if isinstance(value, int):
            fields[name] = value
    return fields


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                # An extra must never overwrite ts/level/logger/message (log forging).
                name = key if key not in payload else f"extra_{key}"
                payload[name] = redact_value(key, value)
        if record.exc_info:
            payload["exc"] = redact_text("".join(traceback.format_exception(*record.exc_info)))
        return json.dumps(payload, default=str)


_handlers: list[logging.Handler] = []


def configure_logging(level: str = "INFO", log_dir: Path | None = None) -> None:
    """Install JSON handlers (stderr plus optional rotating file). Safe to call repeatedly."""
    shutdown_logging()
    formatter = JsonFormatter()
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    _handlers.append(stream)
    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / LOG_FILE_NAME, maxBytes=5_000_000, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        _handlers.append(file_handler)
    for name in _LOGGER_NAMES:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False
        for handler in _handlers:
            logger.addHandler(handler)
    # Third-party loggers (asyncio, multipart, ...) reach the root logger; give it the same
    # redacting handlers so they never fall through to Python's unredacted last-resort output.
    root = logging.getLogger()
    root.setLevel(max(logging.getLevelNamesMapping()[level], logging.WARNING))
    for handler in _handlers:
        root.addHandler(handler)


def shutdown_logging() -> None:
    for logger in [*(logging.getLogger(n) for n in _LOGGER_NAMES), logging.getLogger()]:
        for handler in _handlers:
            logger.removeHandler(handler)
    for handler in _handlers:
        handler.close()
    _handlers.clear()
