"""Resumable uploads.

    POST   /api/v1/spaces/{space}/uploads   start (path, size, overwrite)
    PATCH  /api/v1/uploads/{id}             append one chunk at `Upload-Offset`
    GET    /api/v1/uploads/{id}             progress (HEAD: the same as headers)
    DELETE /api/v1/uploads/{id}             abort

An upload belongs to the user who created it; anyone else gets the same 404 as for an unknown id.
It also belongs to the space it was started in: every request except DELETE re-checks that the
user may still upload there, and a revoked, downgraded or deleted share gives that same 404.
"""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from yournas.api.common import ItemOut, authorize_space, item_out, parse_path, storage_errors
from yournas.auth.deps import require_user
from yournas.auth.service import AuthContext
from yournas.core.errors import AppError
from yournas.core.middleware import content_length_over
from yournas.permissions import Action
from yournas.uploads import UploadService

router = APIRouter(prefix="/api/v1")

User = Annotated[AuthContext, Depends(require_user)]
_OFFSET = re.compile(r"[0-9]{1,18}")


def get_upload_service(request: Request) -> UploadService:
    service: UploadService = request.app.state.uploads
    return service


Uploads = Annotated[UploadService, Depends(get_upload_service)]


class UploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(max_length=1024)
    size: int = Field(ge=0, strict=True)
    overwrite: bool = False


class UploadCreated(BaseModel):
    upload_id: str
    offset: int
    size: int
    chunk_max_bytes: int
    # True only for a zero-byte file, which is complete as soon as it is created.
    complete: bool
    item: ItemOut | None = None


class ChunkResult(BaseModel):
    offset: int
    size: int
    complete: bool
    item: ItemOut | None = None


class UploadProgress(BaseModel):
    upload_id: str
    offset: int
    size: int
    path: str


@router.post("/spaces/{space}/uploads", status_code=201)
def create_upload(
    space: str, body: UploadRequest, request: Request, ctx: User, uploads: Uploads
) -> UploadCreated:
    # Authorize first: no access is a 404 and read-only access a 403, before the path is looked
    # at. The service authorizes again and takes the root from that decision, not from here.
    authorize_space(request, ctx, space, Action.UPLOAD)
    parts = parse_path(body.path)
    with storage_errors():
        created = uploads.create(ctx.user.id, space, parts, body.size, overwrite=body.overwrite)
    return UploadCreated(
        upload_id=created.upload_id,
        offset=0,
        size=created.size,
        chunk_max_bytes=request.app.state.settings.upload_chunk_max_bytes,
        complete=created.item is not None,
        item=item_out(created.item) if created.item else None,
    )


def _parse_offset(request: Request) -> int:
    raw = request.headers.get("upload-offset", "")
    if not _OFFSET.fullmatch(raw):
        raise AppError(400, "invalid_request", "Missing or invalid Upload-Offset header")
    return int(raw)


@router.patch("/uploads/{upload_id}")
async def append_chunk(
    upload_id: str, request: Request, response: Response, ctx: User, uploads: Uploads
) -> ChunkResult:
    limit = request.app.state.settings.upload_chunk_max_bytes
    offset = _parse_offset(request)
    if content_length_over(request.headers.get("content-length"), limit):
        raise AppError(413, "payload_too_large", "Chunk is larger than allowed")
    # Ownership first: a stranger's id is a 404 before any body is read.
    await run_in_threadpool(uploads.lookup, ctx.user.id, upload_id)

    # A user may have only a few chunks in flight; the rest wait outside, before their body is
    # read, so a slow or flooding client cannot pin memory or worker threads.
    if not uploads.try_begin_chunk(ctx.user.id):
        raise AppError(
            429,
            "too_many_requests",
            "Too many chunks in flight, retry shortly",
            {"Retry-After": "1"},
        )
    try:
        # The chunk is buffered (at most `limit` bytes) and written only once it has fully
        # arrived, so a connection that breaks mid-chunk changes nothing and the client resends.
        data = bytearray()
        try:
            async for part in request.stream():
                data += part
                if len(data) > limit:
                    raise AppError(413, "payload_too_large", "Chunk is larger than allowed")
        except ClientDisconnect:
            raise AppError(400, "invalid_request", "Request body was interrupted") from None

        def work() -> ChunkResult:
            with storage_errors():
                done = uploads.append(ctx.user.id, upload_id, offset, bytes(data))
            return ChunkResult(
                offset=done.offset,
                size=done.size,
                complete=done.item is not None,
                item=item_out(done.item) if done.item else None,
            )

        result = await run_in_threadpool(work)
    finally:
        uploads.end_chunk(ctx.user.id)
    response.headers["Upload-Offset"] = str(result.offset)
    return result


@router.get("/uploads/{upload_id}")
def upload_progress(
    upload_id: str, ctx: User, uploads: Uploads, response: Response
) -> UploadProgress:
    with storage_errors():
        status = uploads.status(ctx.user.id, upload_id)
    response.headers["Upload-Offset"] = str(status.offset)
    return UploadProgress(
        upload_id=upload_id,
        offset=status.offset,
        size=status.row.size,
        path="/".join(status.row.parts),
    )


@router.head("/uploads/{upload_id}")
def upload_head(upload_id: str, ctx: User, uploads: Uploads) -> Response:
    with storage_errors():
        status = uploads.status(ctx.user.id, upload_id)
    return Response(
        status_code=200,
        headers={"Upload-Offset": str(status.offset), "Upload-Length": str(status.row.size)},
    )


@router.delete("/uploads/{upload_id}", status_code=204)
def abort_upload(upload_id: str, ctx: User, uploads: Uploads) -> Response:
    with storage_errors():
        uploads.abort(ctx.user.id, upload_id)
    return Response(status_code=204)
