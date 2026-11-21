from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from yournas.core.errors import AppError


def test_health_ok_with_request_id_and_security_headers(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    r1 = client.get("/health")
    r2 = client.get("/health")
    assert r1.status_code == 200
    assert r1.json() == {"status": "ok"}
    assert len(r1.headers["x-request-id"]) == 32
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]
    assert r1.headers["x-content-type-options"] == "nosniff"
    assert r1.headers["cache-control"] == "no-store"


def test_not_found_uses_generic_envelope(make_app: Callable[..., FastAPI]) -> None:
    r = TestClient(make_app()).get("/does-not-exist")
    assert r.status_code == 404
    assert r.json() == {
        "error": {
            "code": "not_found",
            "message": "Not Found",
            "request_id": r.headers["x-request-id"],
        }
    }


def test_method_not_allowed_envelope_keeps_allow_header(make_app: Callable[..., FastAPI]) -> None:
    r = TestClient(make_app()).post("/health")
    assert r.status_code == 405
    assert r.json()["error"]["code"] == "method_not_allowed"
    assert "GET" in r.headers["allow"]


def test_docs_disabled_by_default(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_docs_enabled_only_by_setting(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app(enable_docs=True))
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_unhandled_error_is_generic_and_leaks_nothing(make_app: Callable[..., FastAPI]) -> None:
    app = make_app()

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("internal detail C:\\secret\\path password=hunter2")

    r = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"
    assert r.json()["error"]["request_id"] == r.headers["x-request-id"]
    assert "secret" not in r.text and "hunter2" not in r.text and "RuntimeError" not in r.text


def test_app_error_uses_its_code_and_message(make_app: Callable[..., FastAPI]) -> None:
    app = make_app()

    @app.get("/taken")
    async def taken() -> None:
        raise AppError(409, "name_taken", "Name already in use")

    @app.get("/slow-down")
    async def slow_down() -> None:
        raise AppError(429, headers={"Retry-After": "30"})

    client = TestClient(app)
    r = client.get("/taken")
    assert r.status_code == 409
    assert r.json()["error"] == {
        "code": "name_taken",
        "message": "Name already in use",
        "request_id": r.headers["x-request-id"],
    }
    r = client.get("/slow-down")
    assert r.status_code == 429 and r.json()["error"]["code"] == "too_many_requests"
    assert r.headers["retry-after"] == "30"


def test_http_exception_detail_is_not_exposed(make_app: Callable[..., FastAPI]) -> None:
    app = make_app()

    @app.get("/nope")
    async def nope() -> None:
        raise HTTPException(status_code=404, detail="no such file C:\\secret\\notes.txt")

    r = TestClient(app).get("/nope")
    assert r.status_code == 404
    assert "secret" not in r.text


def test_no_slash_redirect_built_from_host_header(make_app: Callable[..., FastAPI]) -> None:
    # evil.example is allowed here on purpose: the request must get past the Host check, so this
    # still proves that the router itself never builds a redirect from the Host header.
    r = TestClient(make_app(allowed_hosts=("evil.example",)), follow_redirects=False).get(
        "/health/", headers={"Host": "evil.example"}
    )
    assert r.status_code == 404
    assert "location" not in r.headers


def test_validation_error_does_not_echo_input(make_app: Callable[..., FastAPI]) -> None:
    app = make_app()

    @app.get("/n/{n}")
    async def n(n: int) -> dict[str, int]:
        return {"n": n}

    r = TestClient(app).get("/n/not-a-number-xyz")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_request"
    assert "not-a-number-xyz" not in r.text
