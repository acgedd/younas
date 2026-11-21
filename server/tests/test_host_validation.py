"""Host header allowlist (DNS-rebinding defence), Phase 5.1.1.

The app answers only to the loopback names plus the exact names in `allowed_hosts`. Everything
else, a missing, repeated or malformed Host included, is 400 `invalid_host` before any route,
body, authentication or throttle is touched. Only the Host header counts: X-Forwarded-Host and its
relatives are ignored.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import logging
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from conftest import AuthEnv, Session, routes_of
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from yournas.core.config import ConfigError, Settings, load_settings
from yournas.core.hosts import normalize_host_name, parse_host_header
from yournas.core.middleware import HostValidationMiddleware

EVIL = "evil.example"
TAILNET = "nas.example-tailnet.ts.net"

# What a real local client sends.
LOCAL_HOSTS = [
    "localhost",
    "localhost:8000",
    "LOCALHOST:8000",
    "LocalHost",
    "localhost:1",
    "localhost:65535",
    "127.0.0.1",
    "127.0.0.1:8000",
    "[::1]",
    "[::1]:8000",
    "[0:0:0:0:0:0:0:1]:8000",
]

# Well-formed but not approved.
UNAPPROVED_HOSTS = [
    EVIL,
    f"{EVIL}:8000",
    "EVIL.EXAMPLE",
    "localhost.evil.example",
    "evil.example.localhost",
    "127.0.0.1.evil.example",
    "127.0.0.2",
    "127.0.0.2:8000",
    "0.0.0.0",
    "0.0.0.0:8000",
    "192.168.0.5:8000",
    "100.64.0.1",
    "[::2]",
    "[::ffff:127.0.0.1]",
    "testserver",
    "localhost2",
    TAILNET,  # not approved until it is configured
]

# Not even a valid Host value (what a TestClient can send as text).
MALFORMED_HOSTS = [
    "localhost:",
    "localhost:0",
    "localhost:65536",
    "localhost:999999",
    "localhost:80:80",
    "localhost:http",
    "local host",
    "*",
    "[::1",
    "::1",
    "[::1]x",
    "[::1]:",
    "user@localhost",
    "localhost/",
    "localhost#evil.example",
    "localhost?x=1",
    "http://localhost",
    "localhost.",
    ".localhost",
    "local_host",
    "-localhost",
]


async def never(_scope: Scope, _receive: Receive, _send: Send) -> None:
    raise AssertionError("the request must not reach the app")


def run_asgi(
    app: ASGIApp, headers: list[tuple[bytes, bytes]], scope_type: str = "http"
) -> list[Message]:
    """One request straight into `app` (no server, so the header bytes stay exactly as given)."""
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/health",
        "raw_path": b"/health",
        "query_string": b"",
        "root_path": "",
        "scheme": "http",
        "headers": headers,
        "client": ("testclient", 1),
        "server": ("testserver", 80),
        "state": {},
    }

    async def run() -> None:
        await app(scope, receive, send)

    asyncio.run(run())
    return sent


def assert_invalid_host(response: Any, *, secret: str | None = None) -> None:
    assert response.status_code == 400, response.text
    body = response.json()
    assert body["error"]["code"] == "invalid_host"
    assert body["error"]["message"] == "Invalid host header"
    assert body["error"]["request_id"] == response.headers["x-request-id"]
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "location" not in response.headers
    if secret:
        assert secret.lower() not in response.text.lower()


# ---- the parsing rules ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("localhost", "localhost"),
        ("LOCALHOST:8000", "localhost"),
        ("127.0.0.1:1", "127.0.0.1"),
        ("[::1]:80", "[::1]"),
        ("[0:0:0:0:0:0:0:1]", "[::1]"),
        ("[::FFFF:7F00:1]", "[::ffff:7f00:1]"),
        (TAILNET, TAILNET),
        (f"{TAILNET}:443", TAILNET),
        ("a-b.c1.example", "a-b.c1.example"),
        ("localhost:65535", "localhost"),
    ],
)
def test_parse_host_header_accepts_and_normalizes(raw: str, expected: str) -> None:
    assert parse_host_header(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        *MALFORMED_HOSTS,
        "",
        " ",
        " localhost",
        "localhost ",
        "localhost\t",
        "local\thost",
        "localhost\r\nX-Evil: 1",
        "localhost\x00",
        "localhost\x7f",
        "locälhost",
        "localhost:٨٠",  # Arabic-Indic digits are not a port
        "[::1%25eth0]",
        "[::1%eth0]",
        "a" * 64 + ".example",
        "a" * 300,
        "1.2.3",
        "300.1.1.1",
    ],
)
def test_parse_host_header_rejects(raw: str) -> None:
    assert parse_host_header(raw) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Nas.Example", "nas.example"),
        ("::1", "[::1]"),
        ("[::1]", "[::1]"),
        ("10.0.0.1", "10.0.0.1"),
    ],
)
def test_normalize_host_name(raw: str, expected: str) -> None:
    assert normalize_host_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "*",
        "*.example.com",
        "a.example:80",
        "http://a.example",
        "a.example/",
        "a@example.com",
        "a.example.",
        "a..example",
        "fe80::1%eth0",
        "ünicode.example",
        "256.1.1.1",
        "[::1",
    ],
)
def test_normalize_host_name_rejects(raw: str) -> None:
    assert normalize_host_name(raw) is None


# ---- the whole app: allowed and refused hosts -------------------------------------------------


@pytest.mark.parametrize("host", LOCAL_HOSTS)
def test_local_hosts_reach_the_app(make_app: Callable[..., FastAPI], host: str) -> None:
    client = TestClient(make_app())
    headers = {"Host": host}
    assert client.get("/health", headers=headers).status_code == 200
    page = client.get("/app", headers=headers)
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    # An API route is reached too: it answers 401 for want of a token, not 400 for the host.
    assert client.get("/api/v1/spaces", headers=headers).status_code == 401


@pytest.mark.parametrize("host", [*UNAPPROVED_HOSTS, *MALFORMED_HOSTS])
def test_other_hosts_are_refused_everywhere(make_app: Callable[..., FastAPI], host: str) -> None:
    client = TestClient(make_app())
    for path in ("/health", "/app", "/api/v1/spaces", "/nope"):
        assert_invalid_host(client.get(path, headers={"Host": host}), secret=host)


def test_every_route_is_covered_not_only_the_ones_named_here(
    make_app: Callable[..., FastAPI],
) -> None:
    app = make_app(enable_docs=True)
    client = TestClient(app, follow_redirects=False)
    routes = routes_of(app)
    assert routes  # an empty set would make this test vacuous
    targets = {(method, path.replace("{", "").replace("}", "")) for method, path in routes}
    targets |= {
        ("GET", p)
        for p in (
            "/docs",
            "/openapi.json",
            "/app",
            "/app/",
            "/app/s",
            "/app/s/js/main.js",
            "/app/s/no-such-file",
            "/health/",
            "/nope",
        )
    }
    for method, path in sorted(targets):
        response = client.request(method, path, headers={"Host": EVIL})
        assert response.status_code == 400, (method, path, response.status_code)
        if method != "HEAD":  # a HEAD answer has no body, by definition
            assert response.json()["error"]["code"] == "invalid_host", (method, path)
    # The same routes with a local Host are not refused for their Host.
    for method, path in sorted(targets):
        response = client.request(method, path, headers={"Host": "localhost"})
        assert b"invalid_host" not in response.content, (method, path)


def test_the_refusal_comes_before_the_body_is_read(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    big = b"x" * 100_000  # over the 16 KiB cap: a 413 would show that the body limit ran first
    r = client.post("/api/v1/auth/login", content=big, headers={"Host": EVIL})
    assert_invalid_host(r)


def test_the_refusal_is_logged_without_the_rejected_value(
    make_app: Callable[..., FastAPI], caplog: pytest.LogCaptureFixture
) -> None:
    client = TestClient(make_app())
    with caplog.at_level(logging.INFO, logger="yournas.request"):
        client.get("/health", headers={"Host": "secret-looking.evil.example"})
    refused = [r for r in caplog.records if r.getMessage() == "host_rejected"]
    assert len(refused) == 1
    assert refused[0].__dict__["reason"] == "not_allowed"
    everything = " ".join(str(v) for r in caplog.records for v in r.__dict__.values())
    assert "secret-looking" not in everything
    access = [r for r in caplog.records if r.getMessage() == "request"]
    assert access
    assert access[-1].__dict__["status"] == 400


# ---- configured hosts -------------------------------------------------------------------------


def test_a_configured_host_is_accepted_with_or_without_a_port(
    make_app: Callable[..., FastAPI],
) -> None:
    client = TestClient(make_app(allowed_hosts=(TAILNET.upper(), "[::2]")))
    for host in (TAILNET, f"{TAILNET}:443", TAILNET.upper(), "[::2]:8000", "localhost"):
        assert client.get("/health", headers={"Host": host}).status_code == 200, host


@pytest.mark.parametrize(
    "host",
    [
        f"other.{TAILNET}",  # no suffix matching
        f"{TAILNET}.evil.example",
        f"evil.{TAILNET}",
        f"x{TAILNET}",
        TAILNET.split(".", 1)[1],  # a parent domain
        "[::3]",
        f"{TAILNET}:",
        f"{TAILNET}:0",
    ],
)
def test_configuring_a_host_does_not_open_related_names(
    make_app: Callable[..., FastAPI], host: str
) -> None:
    client = TestClient(make_app(allowed_hosts=(TAILNET,)))
    assert_invalid_host(client.get("/health", headers={"Host": host}))


def test_the_default_is_loopback_only(make_app: Callable[..., FastAPI]) -> None:
    assert Settings(storage_root=Path("C:\\data")).allowed_hosts == ()
    client = TestClient(make_app())
    assert_invalid_host(client.get("/health", headers={"Host": TAILNET}))


def test_a_non_loopback_bind_does_not_approve_its_own_address(
    make_app: Callable[..., FastAPI],
) -> None:
    # Binding to a LAN address (an explicit override) must not make that address a valid Host.
    app = make_app(host="192.168.0.5", allow_non_loopback=True)
    client = TestClient(app)
    assert_invalid_host(client.get("/health", headers={"Host": "192.168.0.5:8000"}))
    app = make_app(host="192.168.0.5", allow_non_loopback=True, allowed_hosts=("192.168.0.5",))
    assert TestClient(app).get("/health", headers={"Host": "192.168.0.5:8000"}).status_code == 200


def test_the_middleware_refuses_a_wildcard_by_itself() -> None:
    for entry in ("*", "*.example.com", "a.example:80"):
        with pytest.raises(ValueError, match="allowed_hosts"):
            HostValidationMiddleware(never, allowed_hosts=[entry])


# ---- configuration parsing --------------------------------------------------------------------

ROOT_ENV = {"YOURNAS_STORAGE_ROOT": "C:\\data"}


def test_allowed_hosts_from_the_environment() -> None:
    value = f" {TAILNET.upper()}, other.example  [::1]\t10.0.0.1,, {TAILNET} "
    s = load_settings({**ROOT_ENV, "YOURNAS_ALLOWED_HOSTS": value})
    assert s.allowed_hosts == (TAILNET, "other.example", "[::1]", "10.0.0.1")


def test_allowed_hosts_from_a_json_file(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"storage_root": "C:\\data", "allowed_hosts": [TAILNET, "::1"]}))
    assert load_settings({"YOURNAS_CONFIG": str(cfg)}).allowed_hosts == (TAILNET, "[::1]")
    cfg.write_text(json.dumps({"storage_root": "C:\\data", "allowed_hosts": TAILNET}))
    assert load_settings({"YOURNAS_CONFIG": str(cfg)}).allowed_hosts == (TAILNET,)


def test_an_empty_variable_means_not_set() -> None:
    assert load_settings({**ROOT_ENV, "YOURNAS_ALLOWED_HOSTS": ""}).allowed_hosts == ()
    assert load_settings({**ROOT_ENV, "YOURNAS_ALLOWED_HOSTS": " , "}).allowed_hosts == ()


@pytest.mark.parametrize(
    "entry",
    [
        "*",
        "*.example.com",
        "evil.example:8000",
        "http://evil.example",
        "evil.example/path",
        "user@evil.example",
        "evil.example.",
        "evil_host.example",
        "-bad.example",
        "bad-.example",
        "a..b",
        "ünicode.example",
        "1.2.3",
        "300.1.1.1",
        "fe80::1%eth0",
        "[::1",
        "a" * 64 + ".example",
    ],
)
def test_bad_allowed_hosts_stop_the_start_without_echoing_the_value(entry: str) -> None:
    with pytest.raises(ConfigError, match="allowed_hosts") as info:
        load_settings({**ROOT_ENV, "YOURNAS_ALLOWED_HOSTS": f"{TAILNET},{entry}"})
    assert entry not in str(info.value)


def test_one_bad_entry_does_not_leave_the_good_ones_active() -> None:
    with pytest.raises(ConfigError):
        load_settings({**ROOT_ENV, "YOURNAS_ALLOWED_HOSTS": f"{TAILNET} *"})


# ---- X-Forwarded-Host and friends are never trusted -------------------------------------------

FORWARDED = [
    ("X-Forwarded-Host", "localhost"),
    ("X-Forwarded-Host", "localhost:8000"),
    ("Forwarded", "host=localhost"),
    ("X-Original-Host", "localhost"),
    ("X-Host", "localhost"),
    ("X-Forwarded-Server", "localhost"),
    ("X-Forwarded-For", "127.0.0.1"),
]


@pytest.mark.parametrize(("name", "value"), FORWARDED)
def test_a_forwarded_header_cannot_make_a_bad_host_good(
    make_app: Callable[..., FastAPI], name: str, value: str
) -> None:
    client = TestClient(make_app())
    assert_invalid_host(client.get("/health", headers={"Host": EVIL, name: value}))


def test_a_forwarded_header_naming_a_bad_host_is_not_followed(
    make_app: Callable[..., FastAPI],
) -> None:
    client = TestClient(make_app())
    r = client.get("/health", headers={"Host": "localhost", "X-Forwarded-Host": EVIL})
    assert r.status_code == 200
    assert EVIL not in r.text


def test_trust_forwarded_for_does_not_relax_the_host_check(
    make_auth_env: Callable[..., AuthEnv],
) -> None:
    env = make_auth_env(trust_forwarded_for=True)
    client = env.client(host="127.0.0.1")  # a loopback peer, as Tailscale Serve would be
    r = client.get("/health", headers={"Host": EVIL, "X-Forwarded-For": "100.64.0.9"})
    assert_invalid_host(r)
    ok = client.get("/health", headers={"Host": "localhost", "X-Forwarded-For": "100.64.0.9"})
    assert ok.status_code == 200


# ---- the middleware on its own: bytes a TestClient cannot send -------------------------------


def status_and_body(sent: list[Message]) -> tuple[int, dict[str, Any]]:
    assert sent[0]["type"] == "http.response.start"
    return int(sent[0]["status"]), json.loads(sent[1]["body"])


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b" ",
        b"localhost\x00",
        b"local\thost",
        b"localhost\r\nX-Evil: 1",
        b"localhost\x7f",
        "locälhost".encode(),  # UTF-8 bytes
        b"\xff\xfe",
        "localhost:٨٠".encode(),
        b"[::1%25eth0]",
        b"a" * 300,
        b"localhost:80:80",
    ],
    ids=[
        "empty",
        "space",
        "nul",
        "tab",
        "crlf",
        "del",
        "utf8",
        "binary",
        "arabic-port",
        "zone-id",
        "too-long",
        "two-ports",
    ],
)
def test_raw_malformed_host_values_never_reach_the_app(raw: bytes) -> None:
    app = HostValidationMiddleware(never)
    status, body = status_and_body(run_asgi(app, [(b"host", raw)]))
    assert status == 400
    assert body["error"]["code"] == "invalid_host"


def test_a_missing_host_is_refused() -> None:
    app = HostValidationMiddleware(never)
    status, body = status_and_body(run_asgi(app, [(b"accept", b"*/*")]))
    assert (status, body["error"]["code"]) == (400, "invalid_host")


def test_a_repeated_host_is_refused_even_if_every_copy_is_good() -> None:
    app = HostValidationMiddleware(never)
    for pair in (
        [(b"host", b"localhost"), (b"host", b"localhost")],
        [(b"host", b"localhost"), (b"host", EVIL.encode())],
        [(b"host", EVIL.encode()), (b"host", b"localhost")],
    ):
        status, body = status_and_body(run_asgi(app, pair))
        assert (status, body["error"]["code"]) == (400, "invalid_host")


def test_a_good_host_is_passed_on_and_lifespan_is_never_filtered() -> None:
    reached: list[str] = []

    async def inner(scope: Scope, _receive: Receive, _send: Send) -> None:
        reached.append(scope["type"])

    app = HostValidationMiddleware(inner)
    run_asgi(app, [(b"host", b"localhost:8000")])
    run_asgi(app, [], scope_type="lifespan")  # no Host header at all
    assert reached == ["http", "lifespan"]


def test_a_websocket_with_a_bad_host_is_closed_before_the_app() -> None:
    app = HostValidationMiddleware(never)
    sent = run_asgi(app, [(b"host", EVIL.encode())], scope_type="websocket")
    assert sent == [{"type": "websocket.close", "code": 1008}]


def test_the_middleware_takes_only_the_host_header() -> None:
    app = HostValidationMiddleware(never)
    headers = [(b"host", EVIL.encode()), (b"x-forwarded-host", b"localhost")]
    assert status_and_body(run_asgi(app, headers))[0] == 400


# ---- authentication and authorization are untouched -------------------------------------------


def test_a_valid_token_does_not_help_with_a_bad_host(owner: Session) -> None:
    assert owner.client.get("/api/v1/auth/me").status_code == 200
    r = owner.client.get("/api/v1/auth/me", headers={"Host": EVIL})
    assert_invalid_host(r)
    assert owner.token not in r.text


def test_a_refused_host_changes_nothing(owner: Session) -> None:
    refused = owner.client.post(
        "/api/v1/spaces/home/folders", json={"path": "made-by-evil"}, headers={"Host": EVIL}
    )
    assert refused.status_code == 400
    assert not (owner.home / "made-by-evil").exists()
    ok = owner.client.post("/api/v1/spaces/home/folders", json={"path": "made-by-owner"})
    assert ok.status_code == 201
    assert (owner.home / "made-by-owner").is_dir()


def test_roles_and_tokens_behave_as_before_on_a_good_host(
    auth_env: AuthEnv, owner: Session, friend: Session
) -> None:
    assert auth_env.client().get("/api/v1/admin/users").status_code == 401
    assert friend.client.get("/api/v1/admin/users").status_code == 403
    assert owner.client.get("/api/v1/admin/users").status_code == 200
    assert auth_env.client().get("/api/v1/auth/me").status_code == 401


def test_bad_host_logins_cannot_lock_an_account_or_fill_the_throttle(auth_env: AuthEnv) -> None:
    client = auth_env.client()
    for _ in range(30):
        r = client.post(
            "/api/v1/auth/login",
            json={"username": "owner", "password": "wrong password here"},
            headers={"Host": EVIL},
        )
        assert r.status_code == 400
    with auth_env.db.read() as conn:
        assert conn.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0] == 0
    # The real owner is not locked out.
    assert auth_env.login()


# ---- over a real socket (uvicorn) -------------------------------------------------------------


def raw_exchange(live: tuple[str, int], request: bytes) -> bytes:
    with socket.create_connection(live, timeout=10) as sock:
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(65536)
            except TimeoutError:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def test_a_real_client_on_loopback_still_works(live: tuple[str, int]) -> None:
    conn = http.client.HTTPConnection(*live, timeout=10)  # sends Host: 127.0.0.1:<port>
    conn.request("GET", "/health")
    assert conn.getresponse().status == 200
    conn.close()


def test_a_real_socket_gets_the_400_and_the_connection_is_closed(live: tuple[str, int]) -> None:
    reply = raw_exchange(live, b"GET /health HTTP/1.1\r\nHost: evil.example\r\n\r\n")
    head, _, body = reply.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 400")
    assert b"connection: close" in head.lower()
    assert json.loads(body)["error"]["code"] == "invalid_host"
    assert b"evil.example" not in body


def test_http_1_0_without_a_host_is_refused(live: tuple[str, int]) -> None:
    reply = raw_exchange(live, b"GET /health HTTP/1.0\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 400"), reply[:80]
    assert b"invalid_host" in reply


def test_two_host_headers_are_refused_on_the_wire(live: tuple[str, int]) -> None:
    request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n"
    reply = raw_exchange(live, request)
    assert reply.startswith(b"HTTP/1.1 400"), reply[:80]  # by the server or by the app


def test_the_target_of_an_absolute_form_request_does_not_stand_in_for_host(
    live: tuple[str, int],
) -> None:
    request = b"GET http://localhost/health HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    assert raw_exchange(live, request).startswith(b"HTTP/1.1 400")
