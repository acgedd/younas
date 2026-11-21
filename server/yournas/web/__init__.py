"""The web UI: one static page and its assets, served from the same origin as the API.

    GET /app        the page (index.html)
    GET /app/sw.js  the service worker (here, not under /app/s, so its scope can be all of /app/)
    GET /app/s/...  its CSS, JavaScript, fonts and images (read-only static files)

There is no template and no build step, and the only third-party code is one vendored, hash-pinned
animation library (static/vendor). The browser keeps the session token in
localStorage, which is only acceptable because every response under /app carries a strict
Content-Security-Policy: scripts and styles come from this origin only, nothing inline, nothing
framed, no outside connection. These headers apply to /app and never touch the API responses.
"""

from __future__ import annotations

import logging
import mimetypes
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = logging.getLogger("yournas.web")

UI_PREFIX = "/app"
STATIC_PREFIX = "/app/s"

WEB_DIR = Path(__file__).resolve().parent
INDEX_FILE = WEB_DIR / "index.html"
STATIC_DIR = WEB_DIR / "static"
SERVICE_WORKER_FILE = WEB_DIR / "sw.js"

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)

# Revalidate on every load (the files carry an ETag) so an update is picked up at once.
UI_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-cache",
}

# The Windows registry can map .js to text/plain, and a browser refuses a module with that type.
for _suffix, _type in {
    ".js": "text/javascript",
    ".css": "text/css",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".webmanifest": "application/manifest+json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}.items():
    mimetypes.add_type(_type, _suffix)


def is_ui_path(path: str) -> bool:
    return path == UI_PREFIX or path.startswith(UI_PREFIX + "/")


def route_path(scope: Scope) -> str:
    """The path the router sees: `scope["path"]` without `root_path`. A server started with a
    root path (a prefix proxy in front) puts the prefix in `path`; matching `/app` against that
    would silently skip the UI headers."""
    path: str = scope.get("path", "")
    root: str = scope.get("root_path", "")
    if not root or not path.startswith(root):
        return path
    if path == root:
        return ""
    return path[len(root) :] if path[len(root)] == "/" else path


class SafeStaticFiles(StaticFiles):
    """StaticFiles that answers 404 for a name the filesystem refuses (reserved characters,
    stream syntax, over-long). Starlette re-raises those OSErrors, which became an unauthenticated
    500 without the UI headers and an ERROR log line per request."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except (OSError, ValueError):
            raise HTTPException(status_code=404) from None


class UiHeadersMiddleware:
    """Adds the UI security headers to every response under /app, and only to those."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not is_ui_path(route_path(scope)):
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in UI_HEADERS.items():
                    headers[name] = value
            await send(message)

        await self.app(scope, receive, send_wrapper)


def install_web(app: FastAPI) -> None:
    """Serve the UI. Call before RequestContextMiddleware is added, so these headers sit inside it.

    A build that lacks the UI files still boots: the API does not depend on them."""
    app.add_middleware(UiHeadersMiddleware)
    if not INDEX_FILE.is_file() or not STATIC_DIR.is_dir() or not SERVICE_WORKER_FILE.is_file():
        log.warning("web_ui_missing")
        return

    async def index() -> FileResponse:
        return FileResponse(INDEX_FILE, media_type="text/html; charset=utf-8")

    async def service_worker() -> FileResponse:
        return FileResponse(SERVICE_WORKER_FILE, media_type="text/javascript")

    app.add_api_route(UI_PREFIX, index, methods=["GET"], include_in_schema=False)
    app.add_api_route(UI_PREFIX + "/", index, methods=["GET"], include_in_schema=False)
    app.add_api_route(
        UI_PREFIX + "/sw.js", service_worker, methods=["GET"], include_in_schema=False
    )
    app.mount(STATIC_PREFIX, SafeStaticFiles(directory=STATIC_DIR), name="web-static")
