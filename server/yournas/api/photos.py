"""Photos by month (docs/MONTHS-SPEC.md).

    GET /api/v1/spaces/{space}/photos/months?year=YYYY
    GET /api/v1/spaces/{space}/photos/months/{YYYY-MM}?limit=&cursor=
    PUT /api/v1/spaces/{space}/photos/months/{YYYY-MM}/cover   {"path": ...} -> 204
    DELETE /api/v1/spaces/{space}/photos/months/{YYYY-MM}/cover               -> 204

Shape checks come first and answer the same 400 `invalid_request` for every space, so a malformed
request says nothing about a space; then `Action.LIST` (read-only members allowed) answers the
generic 404 for no access. Only the first route may start the background index of the space; the
second only reads the database. Responses carry no inode, no mtime_ns, no `set_by` and no server
path: `path` is relative to the space and goes back to the existing routes, which resolve it again.
`no-store` comes from the middleware default. A user has at most 2 photo requests in flight
(both routes together); past that, after the shape and access checks, the answer is 429
`too_many_requests` with `Retry-After: 1`, as for thumbnail uploads.

Month covers (docs/COVERS-SPEC.md): the shape checks (month, and for PUT the JSON body) answer 400
`invalid_request` first, the same for every space; then `Action.COVER_WRITE` (generic 404 for no
access, 403 for read-only); then the request slot (429); then, for PUT, the path (400
`invalid_path`, also for an empty path). The key is the parsed path joined with `/` and must equal
a stored photo_index key exactly: no casefold and no disk access. The service decides access again
inside the write transaction. Both answer 204 with no body.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from yournas.api.common import authorize_space, parse_path
from yournas.auth.deps import require_user
from yournas.auth.service import AuthContext
from yournas.core.errors import AppError
from yournas.permissions import Action
from yournas.photo_index import (
    CURSOR_MAX,
    MONTH_ITEMS_DEFAULT,
    MONTH_ITEMS_MAX,
    PhotoIndexService,
    decode_cursor,
)

router = APIRouter(prefix="/api/v1/spaces")

User = Annotated[AuthContext, Depends(require_user)]

YEAR_MIN = 1900
YEAR_MAX = 2100
_YEAR = re.compile(r"[0-9]{4}")
_MONTH = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])")
_LIMIT = re.compile(r"[0-9]{1,3}")


class YearOut(BaseModel):
    year: int
    count: int


class TotalOut(BaseModel):
    count: int
    bytes: int


class CoverOut(BaseModel):
    path: str
    size: int
    modified: str


class MonthOut(BaseModel):
    month: str
    count: int
    bytes: int
    cover: CoverOut | None
    custom: bool  # the cover is the space's stored choice, not the newest photo


class IndexOut(BaseModel):
    state: Literal["ready", "updating", "waiting"]
    pending: int
    complete: bool
    truncated: bool


class MonthsOut(BaseModel):
    years: list[YearOut]
    year: int | None
    total: TotalOut
    months: list[MonthOut]
    index: IndexOut


class PhotoOut(BaseModel):
    path: str
    name: str
    size: int
    modified: str
    taken: str | None
    thumb: bool


class CoverRequest(BaseModel):
    """The body of PUT .../cover: the same shape for every space."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(max_length=1024)


class MonthPage(BaseModel):
    month: str
    count: int
    bytes: int
    items: list[PhotoOut]
    next_cursor: str | None


def get_photo_index(request: Request) -> PhotoIndexService:
    service: PhotoIndexService = request.app.state.photo_index
    return service


Photos = Annotated[PhotoIndexService, Depends(get_photo_index)]


def _bad() -> AppError:
    return AppError(400, "invalid_request", "Invalid request")


def _year(raw: str | None) -> int | None:
    if raw is None:
        return None
    if not _YEAR.fullmatch(raw) or not YEAR_MIN <= int(raw) <= YEAR_MAX:
        raise _bad()
    return int(raw)


@contextmanager
def _slot(photos: PhotoIndexService, user_id: str) -> Iterator[None]:
    """One of the user's photo request slots for the duration of the work, or 429."""
    if not photos.try_begin_request(user_id):
        raise AppError(
            429,
            "too_many_requests",
            "Too many photo requests in flight, retry shortly",
            {"Retry-After": "1"},
        )
    try:
        yield
    finally:
        photos.end_request(user_id)


def _limit(raw: str | None) -> int:
    if raw is None:
        return MONTH_ITEMS_DEFAULT
    if not _LIMIT.fullmatch(raw) or not 1 <= int(raw) <= MONTH_ITEMS_MAX:
        raise _bad()
    return int(raw)


@router.get("/{space}/photos/months")
def photo_months(
    space: str,
    request: Request,
    ctx: User,
    photos: Photos,
    year: Annotated[str | None, Query(max_length=16)] = None,
) -> MonthsOut:
    wanted = _year(year)
    access = authorize_space(request, ctx, space, Action.LIST)
    with _slot(photos, ctx.user.id):
        return MonthsOut.model_validate(photos.months(ctx.user.id, access, wanted))


@router.get("/{space}/photos/months/{month}")
def photo_month(
    space: str,
    month: str,
    request: Request,
    ctx: User,
    photos: Photos,
    limit: Annotated[str | None, Query(max_length=16)] = None,
    cursor: Annotated[str | None, Query(max_length=CURSOR_MAX + 1)] = None,
) -> MonthPage:
    if not _MONTH.fullmatch(month):
        raise _bad()
    count = _limit(limit)
    after = decode_cursor(cursor) if cursor is not None else None
    access = authorize_space(request, ctx, space, Action.LIST)
    with _slot(photos, ctx.user.id):
        return MonthPage.model_validate(photos.month_items(access, month, count, after))


@router.put("/{space}/photos/months/{month}/cover", status_code=204)
def put_month_cover(
    space: str, month: str, body: CoverRequest, request: Request, ctx: User, photos: Photos
) -> Response:
    if not _MONTH.fullmatch(month):
        raise _bad()
    access = authorize_space(request, ctx, space, Action.COVER_WRITE)
    with _slot(photos, ctx.user.id):
        parts = parse_path(body.path)
        if not parts:
            raise AppError(400, "invalid_path", "Invalid path")  # the space root is not a photo
        photos.set_cover(ctx.user.id, access, month, "/".join(parts))
    return Response(status_code=204)


@router.delete("/{space}/photos/months/{month}/cover", status_code=204)
def delete_month_cover(
    space: str, month: str, request: Request, ctx: User, photos: Photos
) -> Response:
    if not _MONTH.fullmatch(month):
        raise _bad()
    access = authorize_space(request, ctx, space, Action.COVER_WRITE)
    with _slot(photos, ctx.user.id):
        photos.clear_cover(ctx.user.id, access, month)
    return Response(status_code=204)
