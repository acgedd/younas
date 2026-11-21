"""/api/v1/spaces: spaces, listing, metadata, folders, download, delete.

Handlers are sync on purpose: the storage layer blocks, so FastAPI runs them in its thread pool.
Relative paths come in the query string (or the JSON body of mkdir) and only ever pass through
`parse_path`; the space root comes from the authenticated user.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from email.utils import formatdate
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

from yournas.api.common import (
    ItemOut,
    ListedItemOut,
    SpaceOut,
    authorize_space,
    item_out,
    listed_item_out,
    parse_path,
    share_id_of,
    spaces_of,
    storage_errors,
)
from yournas.auth.deps import require_user
from yournas.auth.service import AuthContext
from yournas.core.errors import AppError
from yournas.permissions import Action, SpaceAccess
from yournas.storage import files
from yournas.storage.errors import InvalidPath
from yournas.storage.paths import validate_relative_path

log = logging.getLogger("yournas.files")

router = APIRouter(prefix="/api/v1/spaces")

User = Annotated[AuthContext, Depends(require_user)]
PathQuery = Annotated[str, Query(max_length=1024)]

DEFAULT_LIMIT = 200
MAX_LIMIT = 1000
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,2048}")
_SAFE_FILENAME_CHAR = re.compile(r"[^A-Za-z0-9._ -]")


class ItemsPage(BaseModel):
    items: list[ListedItemOut]
    next_cursor: str | None


class FolderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(max_length=1024)


# ---- cursor ---------------------------------------------------------------------------------


def encode_cursor(after: str) -> str:
    return base64.urlsafe_b64encode(after.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> str:
    """The `after` name behind an opaque cursor; anything that is not one is a 400."""
    bad = AppError(400, "invalid_request", "Invalid cursor")
    if not _CURSOR.fullmatch(cursor):
        raise bad
    try:
        after = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    except (binascii.Error, UnicodeDecodeError):
        raise bad from None
    # A real cursor is the name of a listed entry, so it is a valid single component.
    try:
        if validate_relative_path(after) != (after,):
            raise bad
    except InvalidPath:
        raise bad from None
    if encode_cursor(after) != cursor:  # non-canonical base64 (stray bits)
        raise bad
    return after


# ---- spaces and listing ---------------------------------------------------------------------


@router.get("")
def list_spaces(request: Request, ctx: User) -> list[SpaceOut]:
    return spaces_of(request, ctx)


@router.get("/{space}/items")
def list_items(
    space: str,
    request: Request,
    ctx: User,
    path: PathQuery = "",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(max_length=2048)] = None,
) -> ItemsPage:
    access = authorize_space(request, ctx, space, Action.LIST)
    parts = parse_path(path)
    after = decode_cursor(cursor) if cursor else None
    with storage_errors():
        page = files.list_dir(access.root, parts, limit=limit, after=after)
    with_thumb = request.app.state.thumbnails.present(
        access, parts, [e.name for e in page.entries if e.kind == "file"]
    )
    return ItemsPage(
        items=[listed_item_out(e, thumb=e.name in with_thumb) for e in page.entries],
        next_cursor=encode_cursor(page.next_after) if page.next_after is not None else None,
    )


@router.get("/{space}/items/meta")
def item_meta(space: str, request: Request, ctx: User, path: PathQuery = "") -> ItemOut:
    access = authorize_space(request, ctx, space, Action.LIST)
    parts = parse_path(path)
    with storage_errors():
        return item_out(files.stat_item(access.root, parts))


# ---- folders and delete ---------------------------------------------------------------------


@router.post("/{space}/folders", status_code=201)
def create_folder(space: str, body: FolderRequest, request: Request, ctx: User) -> ItemOut:
    access = authorize_space(request, ctx, space, Action.MKDIR)
    parts = parse_path(body.path)
    with storage_errors():
        entry = files.make_dir(access.root, parts)
    log.info("folder_created", extra={"user_id": ctx.user.id, "depth": len(parts)})
    # Share spaces only; the folder exists already, so an audit failure is logged, not fatal.
    request.app.state.audit.share_file_event(
        ctx.user.id, share_id_of(access), "folder_created", {"depth": len(parts)}, strict=False
    )
    return item_out(entry)


def _purge_derived(
    request: Request,
    access: SpaceAccess,
    key: str | None,
    parts: tuple[str, ...],
    *,
    folder: bool,
) -> None:
    """What the server keeps about a deleted item (its thumbnails and photo index rows, and for a
    folder everything below it), by exact key plus key range, never LIKE. Never fails a delete.
    Without a key (it could not be worked out before the delete) nothing is purged by key, but a
    folder or a photo name still marks the photo index dirty, so its next walk drops the rows."""
    photo_index = request.app.state.photo_index
    if key is None:
        if parts:
            photo_index.mark_changed(access.scope, parts[-1], folder=folder)
        return
    request.app.state.thumbnails.purge(access.scope, key, folder=folder)
    photo_index.purge(access.scope, key, folder=folder)


@router.delete("/{space}/items", status_code=204)
def delete_item(
    space: str, request: Request, ctx: User, path: PathQuery = "", recursive: bool = False
) -> Response:
    access = authorize_space(request, ctx, space, Action.DELETE)
    root = access.root
    parts = parse_path(path)
    with storage_errors():
        # The space root cannot be deleted (storage raises InvalidPath for it).
        kind = files.stat_item(root, parts).kind if parts else "dir"
    if parts:
        # Destructive: in a share the audit row is written and committed BEFORE anything is
        # deleted. If it cannot be written the request fails with a 500 and nothing is touched.
        # The row records the intent: a delete that then fails (e.g. a non-empty folder without
        # `recursive`) still leaves its row.
        request.app.state.audit.share_file_event(
            ctx.user.id,
            share_id_of(access),
            "item_deleted",
            {"kind": kind, "depth": len(parts)},
            strict=True,
        )
    thumbnails = request.app.state.thumbnails
    thumb_key = thumbnails.key_of(access, parts)  # before the delete: it needs the real path
    try:
        with storage_errors():
            removed = files.delete_item(root, parts, recursive=recursive)
    except AppError:
        # A recursive delete that failed midway keeps what it removed. Which files those are is
        # not known here, so no thumbnail of the folder stays; one that is still wanted is made
        # again. Any other failed delete removed nothing and costs nothing.
        if recursive and kind == "dir":
            _purge_derived(request, access, thumb_key, parts, folder=True)
        raise
    _purge_derived(request, access, thumb_key, parts, folder=kind == "dir")
    # No names or paths in the log: depth and kind only.
    log.info(
        "item_deleted",
        extra={"user_id": ctx.user.id, "depth": len(parts), "kind": kind, "removed": removed},
    )
    return Response(status_code=204)


# ---- download -------------------------------------------------------------------------------


def content_disposition(name: str) -> str:
    """`attachment` with an ASCII-only fallback and the exact name as RFC 5987 filename*.

    Nothing but [A-Za-z0-9._ -] reaches the quoted form and filename* is fully percent-encoded,
    so a quote, CR/LF, semicolon or non-ASCII character cannot break out of the header.
    """
    ascii_name = _SAFE_FILENAME_CHAR.sub("_", name)
    if not ascii_name.strip("._ -"):
        ascii_name = "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name, safe='')}"


class _FileResponse(StreamingResponse):
    """Streams an already opened file and closes it however the response ends.

    `iter_range(close=True)` covers a finished or interrupted stream; this covers a response
    that is never started (client gone first), which would otherwise keep the file open and, on
    Windows, undeletable until garbage collection.
    """

    def __init__(
        self,
        opened: files.OpenFile,
        start: int,
        length: int,
        *,
        status_code: int,
        headers: dict[str, str],
    ) -> None:
        self._opened = opened
        super().__init__(
            files.iter_range(opened.fh, start, length, close=True),
            status_code=status_code,
            headers=headers,
            media_type="application/octet-stream",
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._opened.close()


@router.get("/{space}/files")
def download(space: str, request: Request, ctx: User, path: PathQuery = "") -> Response:
    access = authorize_space(request, ctx, space, Action.READ)
    parts = parse_path(path)
    with storage_errors(reading=True):
        opened = files.open_for_read(access.root, parts)
    try:
        last_modified = formatdate(opened.mtime, usegmt=True)
        range_header = request.headers.get("range")
        # If-Range: honour the range only if the client's validator is the current one.
        if_range = request.headers.get("if-range")
        if if_range is not None and if_range != last_modified:
            range_header = None
        with storage_errors(reading=True):
            spec = files.parse_range_header(range_header, opened.size)
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Disposition": content_disposition(parts[-1]),
            "Last-Modified": last_modified,
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        }
        if spec is None:
            start, length, status = 0, opened.size, 200
        else:
            start, length, status = spec.start, spec.length, 206
            headers["Content-Range"] = f"bytes {spec.start}-{spec.end}/{opened.size}"
        headers["Content-Length"] = str(length)
        return _FileResponse(
            opened,
            start,
            length,
            status_code=status,
            headers=headers,
        )
    except BaseException:
        opened.close()
        raise
