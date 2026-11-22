"""The web UI mount: what is served, with which headers, and that the API is untouched.

The UI is static files (no build step), so these tests also lint the files themselves for the
patterns the Content-Security-Policy relies on (no inline script or style, no outside URLs, no
HTML built from server data) and check that every error code the JavaScript branches on exists in
the backend.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import routes_of
from fastapi import FastAPI
from fastapi.testclient import TestClient

import yournas.web as web

SERVER_DIR = Path(__file__).resolve().parent.parent
JS_DIR = web.STATIC_DIR / "js"
CSS_DIR = web.STATIC_DIR / "css"


def js_files() -> list[Path]:
    return sorted(JS_DIR.rglob("*.js"))


def css_files() -> list[Path]:
    return sorted(CSS_DIR.rglob("*.css"))


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---- serving ----------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/app", "/app/"])
def test_page_is_served_with_the_ui_security_headers(
    make_app: Callable[..., FastAPI], path: str
) -> None:
    r = TestClient(make_app()).get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert '<div id="app"' in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "http:" not in csp and "https:" not in csp and "*" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-cache"
    assert len(r.headers["x-request-id"]) == 32  # still inside the request-context middleware


def test_static_assets_have_the_right_content_types(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    expected = {
        "/app/s/js/main.js": "text/javascript",  # a module with text/plain is refused by browsers
        "/app/s/css/app.css": "text/css",
        "/app/s/fonts/DMMono-Regular.woff2": "font/woff2",
        "/app/s/fonts/Redaction10-Regular.ttf": "font/ttf",
        "/app/s/fonts/EternalBloom.otf": "font/otf",
        "/app/s/img/icon-32.png": "image/png",  # linked as the page icon
        "/app/s/img/noise.svg": "image/svg+xml",
        "/app/s/manifest.webmanifest": "application/manifest+json",  # needed to install the PWA
    }
    for path, content_type in expected.items():
        r = client.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-type"].split(";")[0] == content_type, path
        assert "content-security-policy" in r.headers, path


def test_ui_headers_do_not_leak_onto_the_api(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    for path in ("/health", "/api/v1/spaces", "/does-not-exist"):
        r = client.get(path)
        assert "content-security-policy" not in r.headers, path
        assert "x-frame-options" not in r.headers, path
        assert r.headers["cache-control"] == "no-store", path


def test_api_still_requires_a_token(make_app: Callable[..., FastAPI]) -> None:
    r = TestClient(make_app()).get("/api/v1/spaces")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_static_mount_is_read_only_and_does_not_list_or_escape(
    make_app: Callable[..., FastAPI],
) -> None:
    client = TestClient(make_app())
    assert client.post("/app/s/js/main.js").status_code == 405
    assert client.delete("/app/s/js/main.js").status_code == 405
    for path in (
        "/app/s/js/",  # no directory listing
        "/app/s/js",
        "/app/s/nope.js",
        "/app/s/..%2f..%2fmain.py",
        "/app/s/%2e%2e/%2e%2e/main.py",
        "/app/s/js/..%5c..%5c..%5cmain.py",
    ):
        r = client.get(path)
        assert r.status_code == 404, path
        assert "def create_app" not in r.text, path


def test_names_the_filesystem_refuses_are_a_404_with_the_ui_headers(
    make_app: Callable[..., FastAPI],
) -> None:
    """Starlette re-raises OSError for reserved characters and stream syntax: that was an
    unauthenticated 500 with no CSP and an ERROR log line per request (a log-flood vector)."""
    client = TestClient(make_app())
    for path in (
        "/app/s/x%7Cy",
        "/app/s/x%22y",
        "/app/s/x%3Cy",
        "/app/s/js/main.js::$INDEX_ALLOCATION",
        "/app/s/js/%00main.js",
        "/app/s/" + "a" * 5000,
    ):
        r = client.get(path)
        assert r.status_code == 404, path
        assert "content-security-policy" in r.headers, path


@pytest.mark.parametrize("path", ["/application", "/appx", "/apps/", "/App", "//app"])
def test_the_ui_headers_stop_at_the_app_prefix(make_app: Callable[..., FastAPI], path: str) -> None:
    r = TestClient(make_app()).get(path)
    assert "content-security-policy" not in r.headers, path


def test_route_path_ignores_the_root_path() -> None:
    assert web.route_path({"path": "/nas/app", "root_path": "/nas"}) == "/app"
    assert web.route_path({"path": "/app", "root_path": ""}) == "/app"
    assert web.route_path({"path": "/app", "root_path": "/nas"}) == "/app"
    assert web.route_path({"path": "/nas", "root_path": "/nas"}) == ""
    assert web.route_path({"path": "/nasty/app", "root_path": "/nas"}) == "/nasty/app"


def test_the_ui_headers_still_apply_behind_a_path_prefix(make_app: Callable[..., FastAPI]) -> None:
    """A server started with a root path (a prefix proxy) puts the prefix in scope["path"]."""
    r = TestClient(make_app(), root_path="/nas").get("/nas/app")
    assert "content-security-policy" in r.headers


def test_ui_is_not_part_of_the_api_schema(make_app: Callable[..., FastAPI]) -> None:
    routes = routes_of(make_app(enable_docs=True))
    assert routes
    assert not [path for _, path in routes if path.startswith("/app")]


def test_app_boots_without_the_ui_files(
    make_app: Callable[..., FastAPI], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(web, "INDEX_FILE", tmp_path / "missing.html")
    client = TestClient(make_app())
    assert client.get("/health").status_code == 200
    assert client.get("/app").status_code == 404


def test_ui_files_are_packaged() -> None:
    config = tomllib.loads(read(SERVER_DIR / "pyproject.toml"))
    data = config["tool"]["setuptools"]["package-data"]["yournas.web"]
    assert "index.html" in data and "static/**/*" in data


# ---- the files themselves -----------------------------------------------------------------------


def test_page_has_no_inline_script_style_or_handler() -> None:
    html = read(web.INDEX_FILE)
    scripts = re.findall(r"<script\b[^>]*>", html)
    assert scripts
    for tag in scripts:
        assert 'src="/app/s/' in tag and 'type="module"' in tag, tag
    assert "<style" not in html
    assert not re.search(r"\sstyle\s*=", html)
    assert not re.search(r"\son[a-z]+\s*=", html)
    assert not re.search(r"javascript:", html, re.IGNORECASE)


def test_everything_the_page_references_is_served(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    refs: set[str] = set(re.findall(r'(?:href|src)="(/app/s/[^"]+)"', read(web.INDEX_FILE)))
    for css in css_files():
        refs.update(re.findall(r"url\(\"?(/app/s/[^)\"]+)\"?\)", read(css)))
    for js in js_files():
        text = read(js)
        refs.update(re.findall(r'"(/app/s/[^"]+)"', text))
        for rel in re.findall(r'from "(\.{1,2}/[^"]+)"', text):
            assert (js.parent / rel).resolve().is_file(), f"{js.name} imports missing {rel}"
    assert refs
    for ref in sorted(refs):
        assert client.get(ref).status_code == 200, ref


def test_no_outside_urls_in_the_ui_files() -> None:
    allowed = {"http://www.w3.org/2000/svg"}  # an XML namespace, never fetched
    for path in [web.INDEX_FILE, *js_files(), *css_files()]:
        for url in re.findall(r"https?://[^\s\"')<>]+", read(path)):
            assert url in allowed, f"{path.name}: {url}"
    assert "@import" not in "".join(read(f) for f in css_files())


def test_js_never_builds_html_or_runs_strings() -> None:
    banned = (
        r"\.innerHTML\b",
        r"\.outerHTML\b",
        r"\binsertAdjacentHTML\b",
        r"\bdocument\.write\b",
        r"\beval\s*\(",
        r"\bnew Function\b",
        r"\bsetTimeout\s*\(\s*[\"'`]",
        r"\bsetInterval\s*\(\s*[\"'`]",
        r"\bsessionStorage\b",
        r"\bdocument\.cookie\b",
        r"\.setAttribute\(\s*[\"']style",  # the CSP has no 'unsafe-inline' for styles
        r"\.style\.cssText\b",
        r"[\"'`]//[a-z0-9-]+\.[a-z]",  # a protocol-relative URL is an outside URL
    )
    for path in js_files():
        text = read(path)
        for pattern in banned:
            assert not re.search(pattern, text), f"{path.name}: {pattern}"


def test_token_is_only_touched_by_the_api_module() -> None:
    for path in js_files():
        if path.name != "api.js":
            assert "localStorage" not in read(path), path.name


def backend_error_codes() -> set[str]:
    """Codes the server really sends: `AppError(<status>, "<code>", ...)` and the default code of a
    status in core/errors.py. (A bare string match also hit the unrelated 423 `busy`, which hid a
    client that retried `busy` while the upload route sends `upload_busy`.)"""
    codes: set[str] = set()
    for path in (SERVER_DIR / "yournas").rglob("*.py"):
        if "web" in path.parts:
            continue
        text = read(path)
        codes.update(re.findall(r'AppError\(\s*\d{3}\s*,\s*"([a-z_]+)"', text))
        codes.update(re.findall(r'^\s*\d{3}:\s*"([a-z_]+)"', text, re.MULTILINE))
    return codes


def test_every_error_code_the_js_branches_on_exists_in_the_backend() -> None:
    # made up by the UI itself (file_unreadable: the phone could not read a picked file;
    # stalled: a chunk was refused too many times in a row)
    client_only = {"network", "error", "incomplete", "file_unreadable", "stalled"}
    seen: set[str] = set()
    for path in js_files():
        text = read(path)
        seen.update(re.findall(r'\.code\s*===?\s*"([a-z_]+)"', text))
        seen.update(re.findall(r'case "([a-z_]+)":', text))
        for group in re.findall(r"new Set\(\[([^\]]*)\]\)", text):  # e.g. the retry list
            seen.update(re.findall(r'"([a-z_]+)"', group))
    seen -= client_only
    assert {"invalid_credentials", "offset_mismatch", "upload_busy"} <= seen  # the scan found them
    sent = backend_error_codes()
    assert {"invalid_credentials", "offset_mismatch", "upload_busy", "busy"} <= sent
    for code in sorted(seen):
        assert code in sent, f"the UI uses code {code!r}, the server never sends it"


def test_no_sample_data_ships() -> None:
    """The redesign removed every mock screen: what the UI shows must come from the server, so
    no sample data may creep back in looking like a live reading."""
    assert not (JS_DIR / "mock.js").exists()
    for path in js_files():
        text = read(path)
        assert "mock.js" not in text, f"{path.name} imports sample data"
        assert "mockTag" not in text and "SAMPLE DATA" not in text, path.name


def test_a_folder_row_opens_exactly_once_on_a_double_click() -> None:
    """A dblclick handler next to the click handler opened the folder twice ("a/a" -> 404): the
    click handler already opens an already-selected folder."""
    for path in js_files():
        assert not re.search(r"addEventListener\(\s*[\"']dblclick", read(path)), path.name


def css_rule(selector: str) -> str:
    """The body of the first top-level `selector{...}` rule in the app's stylesheets."""
    for name in ("app.css", "additions.css"):
        css = read(CSS_DIR / name)
        match = re.search(r"(?:^|[}\n])\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", css)
        if match:
            return match.group(1)
    raise AssertionError(f"no rule for {selector}")


def test_long_names_wrap_instead_of_widening_the_screen() -> None:
    """A long file or folder name pushed the delete question and the breadcrumb off the screen."""
    assert "overflow-wrap:anywhere" in css_rule(".fask")  # "Delete <name>?"
    assert "overflow-wrap:anywhere" in css_rule(".crumbs")
    row_name = css_rule(".frow .nm")  # a row keeps one line and cuts the name short instead
    assert "text-overflow:ellipsis" in row_name and "overflow:hidden" in row_name
    library = read(JS_DIR / "views" / "library.js")
    assert '"fask"' in library and "crumbs" in library
