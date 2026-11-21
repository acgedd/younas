"""Shared pieces of the file API: spaces, item output, storage error mapping, path parsing.

Every client path goes through `parse_path` (storage.validate_relative_path) and every space root
is derived from the authenticated user id, never from client input.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Literal

from fastapi import Request
from pydantic import BaseModel

from yournas.auth.service import AuthContext
from yournas.core.errors import AppError
from yournas.core.logging_setup import error_fields
from yournas.permissions import HOME_SPACE, Action, SpaceAccess, parse_share_space
from yournas.storage import files
from yournas.storage.errors import (
    AlreadyExists,
    Busy,
    DiskFull,
    InvalidPath,
    IsADirectoryErr,
    NotADirectoryErr,
    NotEmpty,
    NotFound,
    OffsetMismatch,
    RangeNotSatisfiable,
    StorageError,
    StorageIOError,
    TooLarge,
    UnsafePath,
)
from yournas.storage.paths import validate_relative_path

log = logging.getLogger("yournas.files")

__all__ = ["HOME_SPACE"]  # re-exported: the private space id is defined in permissions


class SpaceOut(BaseModel):
    id: str
    name: str
    access: Literal["read", "write"]


class ItemOut(BaseModel):
    name: str
    kind: Literal["file", "dir"]
    size: int | None
    modified: str


class ListedItemOut(ItemOut):
    """A row of a folder listing. `thumb` is a hint: a stale value only costs one 404 on GET."""

    thumb: bool


def spaces_of(request: Request, ctx: AuthContext) -> list[SpaceOut]:
    """The spaces the caller can open: their `home`, then the shares granted to them."""
    return [
        SpaceOut(id=s.id, name=s.name, access=s.access)
        for s in request.app.state.permissions.spaces_for(ctx.user.id)
    ]


def iso_utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")


def item_out(entry: files.Entry) -> ItemOut:
    return ItemOut(
        name=entry.name, kind=entry.kind, size=entry.size, modified=iso_utc(entry.modified)
    )


def listed_item_out(entry: files.Entry, *, thumb: bool) -> ListedItemOut:
    return ListedItemOut(**item_out(entry).model_dump(), thumb=thumb)


def not_found() -> AppError:
    """The one 404 for anything unknown, invisible or unsafe: identical for every cause."""
    return AppError(404)


def to_app_error(exc: StorageError, *, reading: bool = False) -> AppError:
    """HTTP form of a storage error. Nothing from the exception reaches the client except the
    fixed codes below (and, for an offset mismatch, the number the client needs to resume)."""
    if isinstance(exc, NotFound | UnsafePath):
        return not_found()
    if isinstance(exc, InvalidPath):
        return AppError(400, "invalid_path", "Invalid path")
    if isinstance(exc, NotADirectoryErr):
        return AppError(400, "not_a_directory", "Not a folder")
    if isinstance(exc, IsADirectoryErr):
        if reading:
            return AppError(400, "is_a_directory", "That is a folder")
        return AppError(409, "is_a_directory", "A folder is in the way")
    if isinstance(exc, AlreadyExists):
        return AppError(409, "already_exists", "Already exists")
    if isinstance(exc, NotEmpty):
        return AppError(409, "not_empty", "Folder is not empty")
    if isinstance(exc, Busy):
        return AppError(423, "busy", "Item is in use, try again later")
    if isinstance(exc, OffsetMismatch):
        return AppError(
            409,
            "offset_mismatch",
            "Upload offset does not match the server",
            {"Upload-Offset": str(exc.actual)},
            {"offset": exc.actual},
        )
    if isinstance(exc, RangeNotSatisfiable):
        return AppError(
            416,
            "range_not_satisfiable",
            "Range not satisfiable",
            {"Content-Range": f"bytes */{exc.size}"},
        )
    if isinstance(exc, TooLarge):
        return AppError(413, "payload_too_large", "Upload exceeds its declared size")
    if isinstance(exc, DiskFull):
        return AppError(507, "insufficient_storage", "Not enough free space on the server")
    if isinstance(exc, StorageIOError):
        # Only the error type and numbers reach the log: an OSError message holds server paths.
        log.error("storage_io_error", extra=error_fields(exc))
        return AppError(500, "internal_error", "Internal Server Error")
    log.error("storage_unmapped_error", extra={"error_type": type(exc).__name__})
    return AppError(500, "internal_error", "Internal Server Error")


@contextmanager
def storage_errors(*, reading: bool = False) -> Iterator[None]:
    try:
        yield
    except StorageError as exc:
        raise to_app_error(exc, reading=reading) from None


def parse_path(raw: str) -> tuple[str, ...]:
    """Client path -> validated components. The only way client input reaches the storage layer."""
    with storage_errors():
        return validate_relative_path(raw)


def authorize_space(request: Request, ctx: AuthContext, space: str, action: Action) -> SpaceAccess:
    """Allow `action` for the authenticated user in `space`, or raise: 404 when the user has no
    access at all (identical to an unknown or malformed space), 403 for read-only access to a
    write action. Every file route calls this FIRST, before it parses the client path, so a denied
    request touches nothing on disk and an invalid path in a denied space is still a 404."""
    access: SpaceAccess = request.app.state.permissions.authorize(ctx.user.id, space, action)
    return access


def share_id_of(access: SpaceAccess) -> str | None:
    """The share id behind a granted space, None for a private `home` (which is not audited)."""
    return parse_share_space(access.space)
