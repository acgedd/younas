"""Uniform, non-leaking error responses."""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

_CODES = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    416: "range_not_satisfiable",
    423: "busy",
    429: "too_many_requests",
    500: "internal_error",
    507: "insufficient_storage",
}


class AppError(Exception):
    """Raise from routes/services for an expected failure with a stable machine code.

    `message` is shown to the client: it must be generic and must never contain paths,
    user input, or internal detail. `extra` is merged into the error object (same rule).
    """

    def __init__(
        self,
        status_code: int,
        code: str | None = None,
        message: str | None = None,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code or str(status_code))
        self.status_code = status_code
        self.code = code or _CODES.get(status_code, "http_error")
        self.message = message or _phrase(status_code)
        self.headers = headers
        # Additional fields for the error object, e.g. the current offset of an upload.
        self.extra = extra


def _phrase(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except ValueError:
        return "Error"


def error_body(code: str, message: str, request_id: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def request_id_of(request: Request) -> str:
    return str(getattr(request.state, "request_id", "-"))


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        body = error_body(exc.code, exc.message, request_id_of(request))
        if exc.extra:
            body["error"].update(exc.extra)
        return JSONResponse(body, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        # exc.detail is deliberately dropped: it can carry internal detail.
        return JSONResponse(
            error_body(
                _CODES.get(exc.status_code, "http_error"),
                _phrase(exc.status_code),
                request_id_of(request),
            ),
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo the submitted input back.
        return JSONResponse(
            error_body("invalid_request", "Invalid request", request_id_of(request)),
            status_code=400,
        )
