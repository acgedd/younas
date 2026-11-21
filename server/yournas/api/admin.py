"""/api/v1/admin: owner-only endpoints (status, users, shares, grants, audit).

The whole router depends on `require_owner`: no token is a 401, any other role a 403, a pending
temporary password a 403 `password_change_required`. The acting user always comes from the
session, never from the request. Request bodies reject unknown fields, ids in the URL that are not
well formed are a 404, and no response carries a password hash, a token or a server path. A
temporary password appears only in the response that creates or resets it, with
`Cache-Control: no-store`.

Handlers are sync on purpose: password hashing and SQLite block, so FastAPI runs them in its
thread pool.
"""

from __future__ import annotations

import re
import shutil
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from yournas import __version__
from yournas.audit import ACTIONS, AuditError, AuditFilter, decode_cursor
from yournas.auth.deps import require_owner
from yournas.auth.service import MAX_LOGIN_USERNAME_LENGTH, AuthContext, AuthService
from yournas.core.errors import AppError
from yournas.shares import ShareRecord, ShareService, is_share_id, is_user_id

router = APIRouter(prefix="/api/v1/admin", dependencies=[Depends(require_owner)])

Owner = Annotated[AuthContext, Depends(require_owner)]
_ACTOR_ID = re.compile(r"[A-Za-z0-9_]{1,64}")
_TARGET_ID = re.compile(r"[A-Za-z0-9_:]{1,80}")


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds")


def _auth(request: Request) -> AuthService:
    service: AuthService = request.app.state.auth
    return service


def _shares(request: Request) -> ShareService:
    service: ShareService = request.app.state.shares
    return service


def _user_id(raw: str) -> str:
    """A well-formed user id, else the generic 404 (nothing says whether it exists)."""
    if not is_user_id(raw):
        raise AppError(404)
    return raw


def _share_id(raw: str) -> str:
    if not is_share_id(raw):
        raise AppError(404)
    return raw


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---- status ---------------------------------------------------------------------------------


class StorageStatus(BaseModel):
    total_bytes: int
    free_bytes: int


class DatabaseStatus(BaseModel):
    ok: bool
    schema_version: int


class StatusResponse(BaseModel):
    version: str
    storage: StorageStatus
    database: DatabaseStatus


@router.get("/status")
def status(request: Request, _owner: Owner) -> StatusResponse:
    usage = shutil.disk_usage(request.app.state.storage.root)
    db = request.app.state.database
    return StatusResponse(
        version=__version__,
        storage=StorageStatus(total_bytes=usage.total, free_bytes=usage.free),
        database=DatabaseStatus(ok=db.check(), schema_version=db.schema_version),
    )


# ---- users ----------------------------------------------------------------------------------


class UserRow(BaseModel):
    id: str
    username: str
    role: str
    disabled: bool
    created_at: str
    must_change_password: bool


class CreateUserRequest(_Body):
    username: str = Field(min_length=1, max_length=MAX_LOGIN_USERNAME_LENGTH)


class CreatedUser(BaseModel):
    id: str
    username: str
    role: str
    temporary_password: str


class DisableRequest(_Body):
    disabled: bool = Field(strict=True)


class DisabledState(BaseModel):
    id: str
    disabled: bool


class TemporaryPassword(BaseModel):
    temporary_password: str


@router.get("/users")
def list_users(request: Request, _owner: Owner) -> list[UserRow]:
    return [
        UserRow(
            id=u.id,
            username=u.username,
            role=u.role,
            disabled=u.disabled,
            created_at=_iso(u.created_at),
            must_change_password=u.must_change_password,
        )
        for u in _auth(request).list_users()
    ]


@router.post("/users", status_code=201)
def create_user(
    body: CreateUserRequest, request: Request, response: Response, owner: Owner
) -> CreatedUser:
    user, temporary_password = _auth(request).create_user(owner.user.id, body.username)
    _no_store(response)
    return CreatedUser(
        id=user.id, username=user.username, role=user.role, temporary_password=temporary_password
    )


@router.patch("/users/{user_id}")
def set_user_disabled(
    user_id: str, body: DisableRequest, request: Request, owner: Owner
) -> DisabledState:
    uid = _user_id(user_id)
    _auth(request).set_disabled(owner.user.id, uid, body.disabled)
    return DisabledState(id=uid, disabled=body.disabled)


@router.post("/users/{user_id}/password-reset")
def reset_user_password(
    user_id: str, request: Request, response: Response, owner: Owner
) -> TemporaryPassword:
    temporary_password = _auth(request).reset_password(owner.user.id, _user_id(user_id))
    _no_store(response)
    return TemporaryPassword(temporary_password=temporary_password)


@router.delete("/users/{user_id}/sessions", status_code=204)
def revoke_user_sessions(user_id: str, request: Request, owner: Owner) -> Response:
    _auth(request).revoke_sessions(owner.user.id, _user_id(user_id))
    return Response(status_code=204)


# ---- shares and grants ----------------------------------------------------------------------


class GrantOut(BaseModel):
    user_id: str
    level: Literal["read", "write"]


class ShareOut(BaseModel):
    id: str
    name: str
    created_at: str
    grants: list[GrantOut]


class ShareNameRequest(_Body):
    name: str = Field(min_length=1, max_length=256)


class GrantRequest(_Body):
    level: Literal["read", "write"]


def _share_out(s: ShareRecord) -> ShareOut:
    return ShareOut(
        id=s.id,
        name=s.name,
        created_at=_iso(s.created_at),
        grants=[GrantOut(user_id=g.user_id, level=g.level) for g in s.grants],
    )


@router.get("/shares")
def list_shares(request: Request, _owner: Owner) -> list[ShareOut]:
    return [_share_out(s) for s in _shares(request).list_shares()]


@router.post("/shares", status_code=201)
def create_share(body: ShareNameRequest, request: Request, owner: Owner) -> ShareOut:
    return _share_out(_shares(request).create(owner.user.id, body.name))


@router.patch("/shares/{share_id}")
def rename_share(share_id: str, body: ShareNameRequest, request: Request, owner: Owner) -> ShareOut:
    return _share_out(_shares(request).rename(owner.user.id, _share_id(share_id), body.name))


@router.delete("/shares/{share_id}", status_code=204)
def delete_share(share_id: str, request: Request, owner: Owner) -> Response:
    _shares(request).delete(owner.user.id, _share_id(share_id))
    return Response(status_code=204)


@router.put("/shares/{share_id}/grants/{user_id}")
def put_grant(
    share_id: str, user_id: str, body: GrantRequest, request: Request, owner: Owner
) -> GrantOut:
    sid, uid = _share_id(share_id), _user_id(user_id)
    grant = _shares(request).set_grant(owner.user.id, sid, uid, body.level)
    return GrantOut(user_id=grant.user_id, level=grant.level)


@router.delete("/shares/{share_id}/grants/{user_id}", status_code=204)
def delete_grant(share_id: str, user_id: str, request: Request, owner: Owner) -> Response:
    sid, uid = _share_id(share_id), _user_id(user_id)
    _shares(request).remove_grant(owner.user.id, sid, uid)
    return Response(status_code=204)


# ---- audit ----------------------------------------------------------------------------------


class AuditEventOut(BaseModel):
    id: int
    at: str
    actor_id: str
    action: str
    target_type: str
    target_id: str
    detail: dict[str, int | bool | str] | None


class AuditPageOut(BaseModel):
    events: list[AuditEventOut]
    next_cursor: str | None


def _bad_filter() -> AppError:
    return AppError(400, "invalid_request", "Invalid filter")


@router.get("/audit")
def audit_events(
    request: Request,
    _owner: Owner,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    cursor: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    actor_id: Annotated[str | None, Query(max_length=64)] = None,
    target_id: Annotated[str | None, Query(max_length=80)] = None,
) -> AuditPageOut:
    """Newest first. `cursor` is the opaque `next_cursor` of the previous page."""
    if action is not None and action not in ACTIONS:
        raise _bad_filter()
    if actor_id is not None and not _ACTOR_ID.fullmatch(actor_id):
        raise _bad_filter()
    if target_id is not None and not _TARGET_ID.fullmatch(target_id):
        raise _bad_filter()
    try:
        after = decode_cursor(cursor) if cursor else None
    except AuditError:
        raise AppError(400, "invalid_request", "Invalid cursor") from None
    page = request.app.state.audit.list_events(
        limit, after, AuditFilter(action=action, actor_id=actor_id, target_id=target_id)
    )
    return AuditPageOut(
        events=[
            AuditEventOut(
                id=e.id,
                at=_iso(e.at),
                actor_id=e.actor_id,
                action=e.action,
                target_type=e.target_type,
                target_id=e.target_id,
                detail=e.detail,
            )
            for e in page.events
        ],
        next_cursor=page.next_cursor,
    )
