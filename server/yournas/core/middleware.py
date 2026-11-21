"""Pure ASGI middleware: request id, security headers, access log, generic 500."""

from __future__ import annotations

import json
import logging
import re
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Sequence

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from yournas.core.errors import error_body
from yournas.core.hosts import LOOPBACK_HOST_NAMES, normalize_host_name, parse_host_header
from yournas.core.logging_setup import error_fields, request_id_var

log = logging.getLogger("yournas.request")


# (method, path) -> does the rule apply
BodyMatcher = Callable[[str, str], bool]
BodyRule = tuple[BodyMatcher, int]


_CONTENT_LENGTH = re.compile(r"[0-9]{1,18}")  # ASCII digits only; str.isdigit() accepts "²"


def content_length_over(raw: str | None, limit: int) -> bool:
    """True if a Content-Length header is malformed or declares more than `limit` bytes."""
    if raw is None:
        return False
    return _CONTENT_LENGTH.fullmatch(raw) is None or int(raw) > limit


def prefix_matcher(*prefixes: str) -> BodyMatcher:
    return lambda _method, path: path.startswith(prefixes)


class BodyLimitMiddleware:
    """Reject oversized request bodies before the framework buffers them.

    FastAPI reads a JSON body before it resolves the auth dependency, so without a cap an
    unauthenticated caller can make the server buffer arbitrarily large bodies. `rules` is an
    ordered list of (matcher, max_bytes); the first matching rule applies. A request that matches
    no rule is not limited, so the caller ends the list with a catch-all rule.
    """

    def __init__(self, app: ASGIApp, *, rules: Sequence[BodyRule]) -> None:
        self.app = app
        self.rules = tuple(rules)

    def _limit(self, method: str, path: str) -> int | None:
        for matches, max_bytes in self.rules:
            if matches(method, path):
                return max_bytes
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope["method"], scope["path"])
        if limit is None:
            await self.app(scope, receive, send)
            return

        if content_length_over(Headers(scope=scope).get("content-length"), limit):
            await self._reject(scope, send)
            return

        received = 0
        started = False
        rejected = False

        async def counting_receive() -> Message:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # The framework turns exceptions raised while reading into a 400, so answer
                    # here and make it see a closed connection.
                    rejected = True
                    if not started:
                        await self._reject(scope, send)
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if rejected:
                return  # the 413 is already sent; drop whatever the app produces afterwards
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, counting_receive, tracking_send)

    async def _reject(self, scope: Scope, send: Send) -> None:
        request_id = str(scope.get("state", {}).get("request_id", "-"))
        body = json.dumps(
            error_body("payload_too_large", "Request body too large", request_id)
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class HostValidationMiddleware:
    """Answer 400 `invalid_host` unless the Host header names a host this app was told about.

    Defence against DNS rebinding: a page on another origin that is rebound to the loopback
    address still sends its own name in Host. Accepted: the loopback names, plus `allowed_hosts`
    (exact names, no wildcard; a port on the header is syntax-checked but not compared). Refused:
    a missing, repeated or malformed Host header (see `parse_host_header`). Only the Host header
    is read, never X-Forwarded-Host or Forwarded. It sits just inside RequestContextMiddleware, so
    the 400 carries the request id and is logged, and it covers every route, /app, /docs, the
    404 and 405 paths and the static files, because it runs before routing. The rejected value is
    never logged or echoed.
    """

    def __init__(self, app: ASGIApp, *, allowed_hosts: Iterable[str] = ()) -> None:
        self.app = app
        names: set[str] = set(LOOPBACK_HOST_NAMES)
        for entry in allowed_hosts:
            name = normalize_host_name(entry)
            if name is None:
                raise ValueError("allowed_hosts entries must be plain host names or IP addresses")
            names.add(name)
        self.allowed = frozenset(names)

    def _refusal(self, scope: Scope) -> str | None:
        hosts = [value for name, value in scope.get("headers", ()) if name == b"host"]
        if not hosts:
            return "missing"
        if len(hosts) > 1:
            return "repeated"
        host = parse_host_header(hosts[0].decode("latin-1"))
        if host is None:
            return "malformed"
        return None if host in self.allowed else "not_allowed"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        reason = self._refusal(scope)
        if reason is None:
            await self.app(scope, receive, send)
            return
        log.warning("host_rejected", extra={"reason": reason})
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        request_id = str(scope.get("state", {}).get("request_id", "-"))
        body = json.dumps(error_body("invalid_host", "Invalid host header", request_id)).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


HSTS_VALUE = "max-age=31536000"  # one year; one host name, so no includeSubDomains


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        id_token = request_id_var.set(request_id)
        started = False
        completed = False
        status = 0  # 0 = no response was started (client gone, or crash before headers)
        t0 = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("Cache-Control", "no-store")
                if self.hsts:
                    headers["Strict-Transport-Security"] = HSTS_VALUE
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            completed = True
        except Exception as exc:
            # Never the exception message: an OSError message holds server paths and file names.
            # The stack frames (no messages) are enough to find the bug.
            log.error(
                "unhandled_error",
                extra={
                    **error_fields(exc),
                    "frames": "".join(traceback.format_tb(exc.__traceback__)),
                },
            )
            if started:
                raise
            body = json.dumps(
                error_body("internal_error", "Internal Server Error", request_id)
            ).encode()
            await send_wrapper(
                {
                    "type": "http.response.start",
                    "status": 500,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            completed = True
        finally:
            # Path only: never the query string or any header. `aborted` marks requests that
            # did not finish cleanly (error after the response started, or client cancelled).
            log.info(
                "request",
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "status": status,
                    "aborted": not completed,
                    "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
                },
            )
            request_id_var.reset(id_token)
