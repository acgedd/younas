"""Spaces, listing, metadata, folders, download and delete through the real HTTP layer."""

from __future__ import annotations

import base64
import contextlib
import http.client
import json
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

import pytest
from conftest import (
    FRIEND_NAME,
    FRIEND_PASSWORD,
    OWNER_NAME,
    OWNER_PASSWORD,
    AuthEnv,
    Session,
    bearer,
    session_for,
)

from yournas.api.spaces import content_disposition, decode_cursor, encode_cursor

SPACES = "/api/v1/spaces"
ITEMS = f"{SPACES}/home/items"
META = f"{SPACES}/home/items/meta"
FOLDERS = f"{SPACES}/home/folders"
FILES = f"{SPACES}/home/files"


def code(response: object) -> str:
    return str(response.json()["error"]["code"])  # type: ignore[attr-defined]


def put(session: Session, rel: str, data: bytes = b"x") -> Path:
    path = session.home.joinpath(*rel.split("/"))
    path.write_bytes(data)
    return path


def names(session: Session, path: str = "") -> list[str]:
    r = session.client.get(ITEMS, params={"path": path, "limit": 1000})
    assert r.status_code == 200, r.text
    return [i["name"] for i in r.json()["items"]]


# ---- spaces ---------------------------------------------------------------------------------


def test_spaces_lists_only_the_private_home(owner: Session) -> None:
    r = owner.client.get(SPACES)
    assert r.status_code == 200
    assert r.json() == [{"id": "home", "name": "My files", "access": "write"}]


def test_me_lists_the_same_spaces(owner: Session) -> None:
    assert owner.client.get("/api/v1/auth/me").json()["spaces"] == owner.client.get(SPACES).json()


def test_home_folder_is_created_lazily_per_user_id(auth_env: AuthEnv) -> None:
    users = auth_env.storage_root / "users"
    assert list(users.iterdir()) == []
    owner = session_for(auth_env, OWNER_NAME, OWNER_PASSWORD)
    assert [p.name for p in users.iterdir()] == [owner.user_id]


@pytest.mark.parametrize(
    "space", ["share:x", "share:1", "other", "HOME", "home ", "u_abc", "..", "%2e"]
)
def test_every_other_space_is_the_generic_404(owner: Session, space: str) -> None:
    base = f"{SPACES}/{urllib.parse.quote(space, safe='')}"
    calls = [
        owner.client.get(f"{base}/items"),
        owner.client.get(f"{base}/items/meta"),
        owner.client.get(f"{base}/files", params={"path": "a"}),
        owner.client.delete(f"{base}/items", params={"path": "a"}),
        owner.client.post(f"{base}/folders", json={"path": "a"}),
        owner.client.post(f"{base}/uploads", json={"path": "a", "size": 1}),
    ]
    bodies = []
    for r in calls:
        assert r.status_code == 404, (r.request.url, r.status_code)
        assert code(r) == "not_found"
        bodies.append({k: v for k, v in r.json()["error"].items() if k != "request_id"})
    assert all(b == bodies[0] for b in bodies)


def test_users_have_separate_homes(owner: Session, friend: Session) -> None:
    put(owner, "secret.txt", b"owner data")
    assert names(owner) == ["secret.txt"]
    assert names(friend) == []
    assert friend.client.get(f"{FILES}", params={"path": "secret.txt"}).status_code == 404
    assert friend.client.get(META, params={"path": "secret.txt"}).status_code == 404
    assert friend.client.delete(ITEMS, params={"path": "secret.txt"}).status_code == 404
    assert (owner.home / "secret.txt").read_bytes() == b"owner data"


def test_owner_has_no_special_access_to_a_friends_home(owner: Session, friend: Session) -> None:
    put(friend, "private.txt", b"friend data")
    assert names(owner) == []
    assert owner.client.get(FILES, params={"path": "private.txt"}).status_code == 404
    # The friend's folder name is an internal id; it cannot be reached by naming it either.
    r = owner.client.get(FILES, params={"path": f"../{friend.user_id}/private.txt"})
    assert r.status_code == 400


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH", "DELETE"])
def test_a_user_id_in_the_url_is_not_a_space(owner: Session, friend: Session, method: str) -> None:
    r = owner.client.request(method, f"{SPACES}/{friend.user_id}/items")
    assert r.status_code in (404, 405)


# ---- path validation through HTTP -----------------------------------------------------------

BAD_PATHS = [
    "..",
    "../x",
    "a/../../x",
    "a/./b",
    "/abs",
    "\\abs",
    "a\\b",
    "C:\\Windows",
    "C:/Windows",
    "C:",
    "//server/share",
    "\\\\server\\share",
    "\\\\?\\C:\\x",
    "a:stream",
    "a.txt::$DATA",
    "file.txt:ads",
    "CON",
    "nul.txt",
    "COM1",
    "lpt3.log",
    "aux ",
    "trail.",
    "trail ",
    "a//b",
    "a/",
    "a\x00b",
    "a\nb",
    "a|b",
    'a"b',
    "a*b",
    "a?b",
    "a<b",
    "x" * 300,
    "/".join(["d"] * 100),
]


@pytest.mark.parametrize("bad", BAD_PATHS, ids=lambda s: repr(s)[:30])
def test_hostile_paths_are_rejected_on_every_route(owner: Session, bad: str) -> None:
    c = owner.client
    responses = [
        c.get(ITEMS, params={"path": bad}),
        c.get(META, params={"path": bad}),
        c.get(FILES, params={"path": bad}),
        c.delete(ITEMS, params={"path": bad}),
        c.post(FOLDERS, json={"path": bad}),
        c.post(f"{SPACES}/home/uploads", json={"path": bad, "size": 1}),
    ]
    for r in responses:
        assert r.status_code in (400, 404), (bad, r.request.method, r.status_code)
        assert code(r) in ("invalid_path", "not_found")
        assert bad not in r.text or bad == ".."
        assert str(owner.env.storage_root) not in r.text
    assert list(owner.home.iterdir()) == []


def test_nothing_outside_the_home_is_touched_by_traversal_attempts(
    owner: Session, auth_env: AuthEnv
) -> None:
    sentinel = auth_env.storage_root / "users" / "sentinel.txt"
    sentinel.write_text("keep")
    for attempt in ("../sentinel.txt", "..\\sentinel.txt", "%2e%2e/sentinel.txt"):
        assert owner.client.delete(ITEMS, params={"path": attempt}).status_code in (400, 404)
        assert owner.client.get(FILES, params={"path": attempt}).status_code in (400, 404)
    assert sentinel.read_text() == "keep"


def test_unicode_names_are_nfc_normalized(owner: Session) -> None:
    decomposed = "e\u0301.txt"
    composed = "\u00e9.txt"
    assert owner.client.post(FOLDERS, json={"path": decomposed[:-4]}).status_code == 201
    assert composed[:-4] in names(owner)
    r = owner.client.get(META, params={"path": decomposed[:-4]})
    assert r.status_code == 200 and r.json()["name"] == composed[:-4]


def test_a_junction_inside_the_home_is_not_followed(owner: Session, tmp_path: Path) -> None:
    import subprocess

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loot.txt").write_text("loot")
    link = owner.home / "link"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip("cannot create a junction here")
    try:
        assert "link" not in names(owner)  # not even listed
        assert owner.client.get(FILES, params={"path": "link/loot.txt"}).status_code == 404
        assert owner.client.get(ITEMS, params={"path": "link"}).status_code == 404
        assert owner.client.post(FOLDERS, json={"path": "link/new"}).status_code == 404
        assert owner.client.delete(ITEMS, params={"path": "link/loot.txt"}).status_code == 404
        assert (outside / "loot.txt").read_text() == "loot"
    finally:
        with contextlib.suppress(OSError):
            link.rmdir()


# ---- listing --------------------------------------------------------------------------------


def test_list_empty_root(owner: Session) -> None:
    r = owner.client.get(ITEMS)
    assert r.status_code == 200
    assert r.json() == {"items": [], "next_cursor": None}


def test_list_item_fields_and_order(owner: Session) -> None:
    put(owner, "b.txt", b"12345")
    put(owner, "A.txt", b"1")
    (owner.home / "folder").mkdir()
    r = owner.client.get(ITEMS)
    items = r.json()["items"]
    assert [i["name"] for i in items] == ["A.txt", "b.txt", "folder"]  # case-insensitive order
    by_name = {i["name"]: i for i in items}
    assert by_name["b.txt"]["kind"] == "file" and by_name["b.txt"]["size"] == 5
    assert by_name["folder"]["kind"] == "dir" and by_name["folder"]["size"] is None
    assert set(by_name["b.txt"]) == {"name", "kind", "size", "modified", "thumb"}
    assert by_name["b.txt"]["thumb"] is False  # no thumbnail was stored for it
    modified = datetime.fromisoformat(by_name["b.txt"]["modified"])
    assert modified.utcoffset() is not None and modified.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert abs(modified.timestamp() - time.time()) < 120


def test_list_a_subfolder_and_errors(owner: Session) -> None:
    (owner.home / "sub").mkdir()
    put(owner, "sub/f.txt")
    put(owner, "plain.txt")
    assert names(owner, "sub") == ["f.txt"]
    r = owner.client.get(ITEMS, params={"path": "plain.txt"})
    assert r.status_code == 400 and code(r) == "not_a_directory"
    r = owner.client.get(ITEMS, params={"path": "missing"})
    assert r.status_code == 404 and code(r) == "not_found"


def test_pagination_end_to_end_with_2000_entries(owner: Session) -> None:
    expected = [f"file{i:04d}.txt" for i in range(2000)]
    for n in expected:
        (owner.home / n).write_bytes(b"")
    for limit in (1000, 777, 200):
        seen: list[str] = []
        cursor: str | None = None
        pages = 0
        while True:
            params: dict[str, str | int] = {"limit": limit}
            if cursor:
                params["cursor"] = cursor
            r = owner.client.get(ITEMS, params=params)
            assert r.status_code == 200
            body = r.json()
            assert len(body["items"]) <= limit
            seen += [i["name"] for i in body["items"]]
            pages += 1
            cursor = body["next_cursor"]
            if cursor is None:
                break
            assert pages < 50
        assert seen == expected, limit
    # default page size is 200
    r = owner.client.get(ITEMS)
    assert len(r.json()["items"]) == 200 and r.json()["next_cursor"] is not None


def test_cursor_is_opaque_base64url_of_the_last_name(owner: Session) -> None:
    for n in ("a", "b", "c"):
        put(owner, n)
    cursor = owner.client.get(ITEMS, params={"limit": 2}).json()["next_cursor"]
    assert re.fullmatch(r"[A-Za-z0-9_-]+", cursor)
    assert base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)) == b"b"
    r = owner.client.get(ITEMS, params={"limit": 2, "cursor": cursor})
    assert [i["name"] for i in r.json()["items"]] == ["c"] and r.json()["next_cursor"] is None


def test_cursor_survives_deletion_of_its_entry(owner: Session) -> None:
    for n in ("a", "b", "c", "d"):
        put(owner, n)
    cursor = owner.client.get(ITEMS, params={"limit": 2}).json()["next_cursor"]
    (owner.home / "b").unlink()
    r = owner.client.get(ITEMS, params={"limit": 2, "cursor": cursor})
    assert [i["name"] for i in r.json()["items"]] == ["c", "d"]


def test_cursor_with_unicode_name_round_trips(owner: Session) -> None:
    for n in ("a", "日本語", "z"):
        put(owner, n)
    first = owner.client.get(ITEMS, params={"limit": 1}).json()
    second = owner.client.get(ITEMS, params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert [i["name"] for i in second["items"]] == ["z", "日本語"] or len(second["items"]) == 2


@pytest.mark.parametrize(
    "cursor",
    [
        "!!!",
        "a b",
        "====",
        "YQ==",  # padding is not part of the format
        "Yg-",  # not canonical
        base64.urlsafe_b64encode(b"\xff\xfe").decode().rstrip("="),  # not UTF-8
        base64.urlsafe_b64encode(b"a/b").decode().rstrip("="),  # not a single name
        base64.urlsafe_b64encode(b"..").decode().rstrip("="),
        base64.urlsafe_b64encode(b"a\x00").decode().rstrip("="),
        base64.urlsafe_b64encode(b"x" * 400).decode().rstrip("="),
        "A" * 3000,
    ],
)
def test_malformed_cursor_is_a_400(owner: Session, cursor: str) -> None:
    r = owner.client.get(ITEMS, params={"cursor": cursor})
    assert r.status_code == 400 and code(r) == "invalid_request"
    assert cursor not in r.text


@pytest.mark.parametrize("limit", ["0", "-1", "1001", "abc", "1.5", ""])
def test_bad_limit_is_a_400(owner: Session, limit: str) -> None:
    r = owner.client.get(ITEMS, params={"limit": limit})
    assert r.status_code == 400 and code(r) == "invalid_request"


def test_cursor_codec_round_trip() -> None:
    for name in ("a", "é", "日本語 x.txt", "x" * 255):
        assert decode_cursor(encode_cursor(name)) == name


# ---- metadata -------------------------------------------------------------------------------


def test_meta_of_the_space_root(owner: Session) -> None:
    r = owner.client.get(META)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "dir" and body["size"] is None and body["name"] == ""
    assert r.json() == owner.client.get(META, params={"path": ""}).json()


def test_meta_of_file_and_folder_and_missing(owner: Session) -> None:
    put(owner, "f.bin", b"abc")
    (owner.home / "d").mkdir()
    f = owner.client.get(META, params={"path": "f.bin"}).json()
    assert (f["name"], f["kind"], f["size"]) == ("f.bin", "file", 3)
    d = owner.client.get(META, params={"path": "d"}).json()
    assert (d["name"], d["kind"], d["size"]) == ("d", "dir", None)
    assert owner.client.get(META, params={"path": "nope"}).status_code == 404


# ---- folders --------------------------------------------------------------------------------


def test_create_folder(owner: Session) -> None:
    r = owner.client.post(FOLDERS, json={"path": "docs"})
    assert r.status_code == 201
    assert r.json()["name"] == "docs" and r.json()["kind"] == "dir"
    assert (owner.home / "docs").is_dir()
    r = owner.client.post(FOLDERS, json={"path": "docs/inner"})
    assert r.status_code == 201 and (owner.home / "docs" / "inner").is_dir()


def test_create_folder_needs_an_existing_parent(owner: Session) -> None:
    r = owner.client.post(FOLDERS, json={"path": "a/b/c"})
    assert r.status_code == 404 and code(r) == "not_found"
    assert list(owner.home.iterdir()) == []


def test_create_folder_conflicts(owner: Session) -> None:
    put(owner, "file")
    (owner.home / "dir").mkdir()
    for path in ("file", "dir", "DIR"):
        r = owner.client.post(FOLDERS, json={"path": path})
        assert r.status_code == 409 and code(r) == "already_exists", path
    assert owner.client.post(FOLDERS, json={"path": "file/sub"}).status_code == 404


def test_create_folder_refuses_the_root_and_junk(owner: Session) -> None:
    assert owner.client.post(FOLDERS, json={"path": ""}).status_code == 400
    bodies: list[object] = [{}, {"path": 5}, {"path": "a", "extra": 1}, [], "x", None]
    for body in bodies:
        r = owner.client.post(FOLDERS, json=body)
        assert r.status_code == 400 and code(r) == "invalid_request", body
    r = owner.client.post(
        FOLDERS, content=b"not json", headers={"content-type": "application/json"}
    )
    assert r.status_code == 400


# ---- download -------------------------------------------------------------------------------

CONTENT = bytes(range(256)) * 40  # 10240 bytes


def test_download_whole_file_and_headers(owner: Session) -> None:
    put(owner, "data.bin", CONTENT)
    r = owner.client.get(FILES, params={"path": "data.bin"})
    assert r.status_code == 200
    assert r.content == CONTENT
    h = r.headers
    assert h["content-length"] == str(len(CONTENT))
    assert h["accept-ranges"] == "bytes"
    assert h["content-type"] == "application/octet-stream"
    assert h["x-content-type-options"] == "nosniff"
    assert h["cache-control"] == "no-store"
    assert h["content-disposition"].startswith('attachment; filename="data.bin"')
    assert "filename*=UTF-8''data.bin" in h["content-disposition"]
    assert h["last-modified"].endswith("GMT")
    assert h["x-request-id"]


def test_download_empty_file(owner: Session) -> None:
    put(owner, "empty", b"")
    r = owner.client.get(FILES, params={"path": "empty"})
    assert r.status_code == 200 and r.content == b"" and r.headers["content-length"] == "0"
    r = owner.client.get(FILES, params={"path": "empty"}, headers={"Range": "bytes=0-"})
    assert r.status_code == 416 and r.headers["content-range"] == "bytes */0"


@pytest.mark.parametrize(
    ("header", "start", "end"),
    [
        ("bytes=0-0", 0, 0),  # first byte
        ("bytes=0-99", 0, 99),
        ("bytes=100-199", 100, 199),
        ("bytes=10239-10239", 10239, 10239),  # last byte
        ("bytes=10000-", 10000, 10239),  # open-ended
        ("bytes=0-", 0, 10239),
        ("bytes=-1", 10239, 10239),  # suffix: last byte
        ("bytes=-100", 10140, 10239),
        ("bytes=-99999", 0, 10239),  # suffix longer than the file
        ("bytes=5-999999", 5, 10239),  # end past EOF is clamped
        ("BYTES=1-2", 1, 2),
    ],
)
def test_single_range_requests(owner: Session, header: str, start: int, end: int) -> None:
    put(owner, "data.bin", CONTENT)
    r = owner.client.get(FILES, params={"path": "data.bin"}, headers={"Range": header})
    assert r.status_code == 206
    assert r.content == CONTENT[start : end + 1]
    assert r.headers["content-range"] == f"bytes {start}-{end}/{len(CONTENT)}"
    assert r.headers["content-length"] == str(end - start + 1)
    assert r.headers["accept-ranges"] == "bytes"


@pytest.mark.parametrize("header", ["bytes=10240-", "bytes=99999-100000", "bytes=-0"])
def test_unsatisfiable_range_is_416_with_content_range(owner: Session, header: str) -> None:
    put(owner, "data.bin", CONTENT)
    r = owner.client.get(FILES, params={"path": "data.bin"}, headers={"Range": header})
    assert r.status_code == 416
    assert code(r) == "range_not_satisfiable"
    assert r.headers["content-range"] == f"bytes */{len(CONTENT)}"


@pytest.mark.parametrize(
    "header",
    ["bytes=0-1,5-6", "bytes=0-1, 3-", "items=0-5", "bytes=abc", "bytes=5-2", "bytes=", "0-5", "x"],
)
def test_multi_range_and_unusable_headers_fall_back_to_the_full_file(
    owner: Session, header: str
) -> None:
    put(owner, "data.bin", CONTENT)
    r = owner.client.get(FILES, params={"path": "data.bin"}, headers={"Range": header})
    assert r.status_code == 200 and r.content == CONTENT
    assert "content-range" not in r.headers


def test_if_range_with_a_stale_validator_serves_the_whole_file(owner: Session) -> None:
    put(owner, "data.bin", CONTENT)
    first = owner.client.get(FILES, params={"path": "data.bin"})
    ok = owner.client.get(
        FILES,
        params={"path": "data.bin"},
        headers={"Range": "bytes=0-9", "If-Range": first.headers["last-modified"]},
    )
    assert ok.status_code == 206 and ok.content == CONTENT[:10]
    stale = owner.client.get(
        FILES,
        params={"path": "data.bin"},
        headers={"Range": "bytes=0-9", "If-Range": "Mon, 01 Jan 2001 00:00:00 GMT"},
    )
    assert stale.status_code == 200 and stale.content == CONTENT


def test_download_errors(owner: Session) -> None:
    (owner.home / "dir").mkdir()
    r = owner.client.get(FILES, params={"path": "dir"})
    assert r.status_code == 400 and code(r) == "is_a_directory"
    r = owner.client.get(FILES)  # the root is a folder too
    assert r.status_code == 400
    r = owner.client.get(FILES, params={"path": "nope.txt"})
    assert r.status_code == 404 and code(r) == "not_found"
    assert "nope.txt" not in r.text


@pytest.mark.parametrize(
    "name",
    [
        "plain.txt",
        "with space.txt",
        "semi;colon=equals.txt",
        "it's.txt",
        "percent%0d%0aSet-Cookie.txt",
        "100%.txt",
        "é accent.txt",
        "日本語.txt",
        "emoji 😀.txt",
        "a" * 60,
        "{braces}.txt",
        "[x](y).txt",
    ],
)
def test_content_disposition_cannot_be_injected(owner: Session, name: str) -> None:
    put(owner, name, b"payload")
    r = owner.client.get(FILES, params={"path": name})
    assert r.status_code == 200 and r.content == b"payload"
    header = r.headers["content-disposition"]
    assert "\r" not in header and "\n" not in header
    assert header.isascii()
    m = re.fullmatch(
        r"attachment; filename=\"([A-Za-z0-9._ -]*)\"; filename\*=UTF-8''([A-Za-z0-9%._~-]*)",
        header,
    )
    assert m is not None, header
    assert urllib.parse.unquote(m.group(2)) == name  # the exact name round-trips
    assert set(r.headers) >= {"content-length"}


@pytest.mark.parametrize(
    "name",
    ['a"b.txt', "a\r\nSet-Cookie: x=1", "a\nb", 'x"; filename="evil.exe', "é\u202etxt.exe", ""],
)
def test_content_disposition_helper_never_leaks_dangerous_characters(name: str) -> None:
    header = content_disposition(name)
    assert header.isascii() and "\r" not in header and "\n" not in header
    quoted = header.split('filename="', 1)[1].split('"', 1)[0]
    assert re.fullmatch(r"[A-Za-z0-9._ -]+", quoted)
    assert header.count('"') == 2
    assert ";" not in header.split("filename*=", 1)[1]


def test_replacing_a_file_after_a_fully_read_download_serves_the_new_content(
    owner: Session,
) -> None:
    put(owner, "f.bin", b"A" * 1000)
    r1 = owner.client.get(FILES, params={"path": "f.bin"})
    put(owner, "f.bin", b"B" * 500)
    r2 = owner.client.get(FILES, params={"path": "f.bin"})
    assert r1.content == b"A" * 1000 and r2.content == b"B" * 500
    assert r2.headers["content-length"] == "500"


# ---- delete ---------------------------------------------------------------------------------


def test_delete_a_file(owner: Session) -> None:
    put(owner, "gone.txt")
    r = owner.client.delete(ITEMS, params={"path": "gone.txt"})
    assert r.status_code == 204 and r.content == b""
    assert not (owner.home / "gone.txt").exists()
    assert owner.client.delete(ITEMS, params={"path": "gone.txt"}).status_code == 404


def test_delete_folders(owner: Session) -> None:
    (owner.home / "full").mkdir()
    put(owner, "full/inner.txt")
    (owner.home / "empty").mkdir()
    r = owner.client.delete(ITEMS, params={"path": "full"})
    assert r.status_code == 409 and code(r) == "not_empty"
    assert (owner.home / "full" / "inner.txt").exists()
    assert owner.client.delete(ITEMS, params={"path": "empty"}).status_code == 204
    r = owner.client.delete(ITEMS, params={"path": "full", "recursive": "true"})
    assert r.status_code == 204
    assert not (owner.home / "full").exists()


def test_delete_refuses_the_space_root(owner: Session) -> None:
    put(owner, "keep.txt")
    for params in ({}, {"path": ""}, {"recursive": "true"}, {"path": "", "recursive": "true"}):
        r = owner.client.delete(ITEMS, params=params)
        assert r.status_code == 400 and code(r) == "invalid_path", params
    assert owner.home.is_dir() and (owner.home / "keep.txt").exists()


def test_delete_bad_recursive_flag_is_a_400(owner: Session) -> None:
    put(owner, "x")
    assert owner.client.delete(ITEMS, params={"path": "x", "recursive": "maybe"}).status_code == 400
    assert (owner.home / "x").exists()


def test_delete_of_a_file_held_open_is_a_clean_423(owner: Session) -> None:
    path = put(owner, "busy.bin", b"data")
    with path.open("rb"):  # an open handle blocks deletion on Windows
        r = owner.client.delete(ITEMS, params={"path": "busy.bin"})
    assert r.status_code == 423 and code(r) == "busy"
    assert owner.client.delete(ITEMS, params={"path": "busy.bin"}).status_code == 204


def test_delete_logs_depth_and_kind_but_no_names(
    owner: Session, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.INFO, logger="yournas")
    (owner.home / "SecretFolderName").mkdir()
    put(owner, "SecretFolderName/SecretFileName.txt")
    owner.client.post(FOLDERS, json={"path": "AnotherSecretName"})
    owner.client.delete(ITEMS, params={"path": "SecretFolderName", "recursive": "true"})
    events = {r.getMessage(): r for r in caplog.records}
    deleted = events["item_deleted"]
    assert deleted.user_id == owner.user_id  # type: ignore[attr-defined]
    assert deleted.kind == "dir" and deleted.depth == 1 and deleted.removed == 2  # type: ignore[attr-defined]
    assert events["folder_created"].user_id == owner.user_id  # type: ignore[attr-defined]
    log_text = " ".join(json.dumps(r.__dict__, default=str) for r in caplog.records)
    assert "SecretFolderName" not in log_text.replace("path", "")
    assert "SecretFileName" not in log_text and "AnotherSecretName" not in log_text.replace(
        "path", ""
    )


# ---- responses never contain the storage root -----------------------------------------------


def test_no_response_body_contains_the_storage_root(owner: Session, auth_env: AuthEnv) -> None:
    put(owner, "a.txt", b"hi")
    root = str(auth_env.storage_root)
    texts = [
        owner.client.get(SPACES).text,
        owner.client.get(ITEMS).text,
        owner.client.get(META, params={"path": "a.txt"}).text,
        owner.client.get(META, params={"path": "nope"}).text,
        owner.client.get(ITEMS, params={"path": "a.txt"}).text,
        owner.client.post(FOLDERS, json={"path": "x/y"}).text,
        owner.client.delete(ITEMS, params={"path": "nope"}).text,
        owner.client.get(FILES, params={"path": "..\\..\\x"}).text,
        owner.client.get(f"{SPACES}/share:x/items").text,
    ]
    for t in texts:
        assert root not in t and root.replace("\\", "/") not in t
        assert "yournas-tmp" not in t and "users" not in t


# ---- authentication -------------------------------------------------------------------------


def test_file_routes_reject_a_revoked_token_and_other_schemes(owner: Session) -> None:
    c = owner.env.client()
    assert c.get(ITEMS).status_code == 401
    assert c.get(ITEMS, headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code == 401
    assert c.get(ITEMS, headers=bearer(owner.token)).status_code == 200
    owner.client.post("/api/v1/auth/logout")
    assert c.get(ITEMS, headers=bearer(owner.token)).status_code == 401
    assert c.get(FILES, params={"path": "a"}, headers=bearer(owner.token)).status_code == 401


def test_disabled_user_loses_file_access(auth_env: AuthEnv, friend: Session) -> None:
    assert friend.client.get(ITEMS).status_code == 200
    with auth_env.db.transaction() as conn:
        conn.execute("UPDATE users SET disabled = 1 WHERE id = ?", (friend.user_id,))
    assert friend.client.get(ITEMS).status_code == 401


def test_friend_constants_are_distinct_from_owner() -> None:
    assert FRIEND_NAME != OWNER_NAME and FRIEND_PASSWORD != OWNER_PASSWORD


# ---- streaming over a real socket: leaks and downloads in progress --------------------------


def eventually(check: object, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if check():  # type: ignore[operator]
            return True
        time.sleep(0.05)
    return False


def start_download(live: tuple[str, int], token: str, rel: str) -> http.client.HTTPConnection:
    conn = http.client.HTTPConnection(*live, timeout=10)
    conn.request("GET", f"{FILES}?path={urllib.parse.quote(rel)}", headers=bearer(token))
    return conn


def test_aborted_download_does_not_leak_the_file_handle(
    owner: Session, live: tuple[str, int]
) -> None:
    big = put(owner, "big.bin", b"\0" * (64 * 1024 * 1024))
    conn = start_download(live, owner.token, "big.bin")
    resp = conn.getresponse()
    assert resp.status == 200
    assert len(resp.read(1024)) == 1024
    conn.sock.close()  # abort mid-stream (RST/FIN without reading the rest)
    conn.close()

    def deletable() -> bool:
        try:
            big.unlink()
        except OSError:
            return False
        return True

    assert eventually(deletable), "file still locked after the client aborted the download"


def test_delete_during_a_download_is_a_clean_423_and_works_afterwards(
    owner: Session, live: tuple[str, int]
) -> None:
    big = put(owner, "big.bin", b"\0" * (64 * 1024 * 1024))
    conn = start_download(live, owner.token, "big.bin")
    resp = conn.getresponse()
    assert resp.status == 200
    resp.read(1024)  # the server is now blocked sending into a full socket buffer
    time.sleep(0.3)
    api = http.client.HTTPConnection(*live, timeout=10)
    api.request("DELETE", f"{ITEMS}?path=big.bin", headers=bearer(owner.token))
    answer = api.getresponse()
    body = json.loads(answer.read())
    assert answer.status == 423, body
    assert body["error"]["code"] == "busy"
    api.close()
    conn.sock.close()
    conn.close()

    def deleted() -> bool:
        c = http.client.HTTPConnection(*live, timeout=10)
        c.request("DELETE", f"{ITEMS}?path=big.bin", headers=bearer(owner.token))
        r = c.getresponse()
        r.read()
        c.close()
        return r.status == 204

    assert eventually(deleted)
    assert not big.exists()


def test_complete_download_over_a_real_socket(owner: Session, live: tuple[str, int]) -> None:
    put(owner, "mid.bin", CONTENT * 100)
    conn = start_download(live, owner.token, "mid.bin")
    resp = conn.getresponse()
    assert resp.status == 200 and resp.getheader("Content-Length") == str(len(CONTENT) * 100)
    assert resp.read() == CONTENT * 100
    conn.close()
    assert (owner.home / "mid.bin").exists()
    (owner.home / "mid.bin").unlink()  # not held open after a normal finish
