"""Photo thumbnails, addressed like every file route: the space in the URL, the path in the query.

    PUT /api/v1/spaces/{space}/thumbnail?path=&size=&modified=   raw JPEG body -> 204
    GET /api/v1/spaces/{space}/thumbnail?path=                   the bytes

Authorization comes first, before the path is parsed, the body is read or the disk is touched.
Nothing on this origin should ever render the GET: see the fixed headers below.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from yournas.api.common import authorize_space, parse_path, storage_errors
from yournas.auth.deps import require_user
from yournas.auth.service import AuthContext
from yournas.core.errors import AppError
from yournas.permissions import Action, SpaceAccess
from yournas.thumbnails import THUMBNAIL_MAX_BYTES, ThumbnailService

router = APIRouter(prefix="/api/v1/spaces")

User = Annotated[AuthContext, Depends(require_user)]
PathQuery = Annotated[str, Query(max_length=1024)]
SizeQuery = Annotated[int, Query(ge=0, le=2**63 - 1)]
ModifiedQuery = Annotated[str, Query(max_length=64)]

_RESPONSE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Content-Disposition": 'attachment; filename="thumbnail.jpg"',
}


def get_thumbnail_service(request: Request) -> ThumbnailService:
    service: ThumbnailService = request.app.state.thumbnails
    return service


Thumbnails = Annotated[ThumbnailService, Depends(get_thumbnail_service)]


async def _read_body(request: Request) -> bytes:
    """The body, at most THUMBNAIL_MAX_BYTES. BodyLimitMiddleware holds the same limit; this keeps
    the route correct without it."""
    data = bytearray()
    try:
        async for part in request.stream():
            data += part
            if len(data) > THUMBNAIL_MAX_BYTES:
                raise AppError(413, "payload_too_large", "Thumbnail is larger than allowed")
    except ClientDisconnect:
        raise AppError(400, "invalid_request", "Request body was interrupted") from None
    return bytes(data)


@router.put("/{space}/thumbnail", status_code=204)
async def put_thumbnail(
    space: str,
    request: Request,
    ctx: User,
    thumbnails: Thumbnails,
    size: SizeQuery,
    modified: ModifiedQuery,
    path: PathQuery = "",
) -> Response:
    def authorized() -> tuple[SpaceAccess, tuple[str, ...]]:
        access = authorize_space(request, ctx, space, Action.THUMBNAIL_WRITE)
        return access, parse_path(path)

    access, parts = await run_in_threadpool(authorized)
    if not parts:
        raise AppError(400, "invalid_path", "Invalid path")  # the space root is not a file
    # The rest wait outside, before their body is read, so a flooding client pins little.
    if not thumbnails.try_begin_put(ctx.user.id):
        raise AppError(
            429,
            "too_many_requests",
            "Too many thumbnails in flight, retry shortly",
            {"Retry-After": "1"},
        )
    try:

        def check() -> None:
            with storage_errors():
                thumbnails.check_source(access, parts, size, modified)

        await run_in_threadpool(check)  # no reason to wait for a body that will be refused
        body = await _read_body(request)

        def store() -> None:
            with storage_errors():
                thumbnails.store(
                    ctx.user.id, access, parts, size, modified, body, session=ctx.token_hash
                )

        await run_in_threadpool(store)
    finally:
        thumbnails.end_put(ctx.user.id)
    return Response(status_code=204)


@router.get("/{space}/thumbnail")
def get_thumbnail(
    space: str, request: Request, ctx: User, thumbnails: Thumbnails, path: PathQuery = ""
) -> Response:
    access = authorize_space(request, ctx, space, Action.READ)
    parts = parse_path(path)
    with storage_errors():
        data = thumbnails.fetch(access, parts)
    # Read whole (128 KiB at most) and sent after the file is closed: on Windows an open handle
    # held by a slow client would block the replace or the delete of this file.
    return Response(data, media_type="application/octet-stream", headers=_RESPONSE_HEADERS)
