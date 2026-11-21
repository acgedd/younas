"""/api/v1/auth: login, logout, current user, password change."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from yournas.auth.deps import client_ip, get_auth_service, require_session
from yournas.auth.passwords import MAX_PASSWORD_LENGTH
from yournas.auth.service import MAX_LOGIN_USERNAME_LENGTH, AuthContext, AuthService

router = APIRouter(prefix="/api/v1/auth")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Body):
    username: str = Field(min_length=1, max_length=MAX_LOGIN_USERNAME_LENGTH)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class PasswordChangeRequest(_Body):
    current: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class UserOut(BaseModel):
    id: str
    username: str
    role: str


class SpaceEntry(BaseModel):
    id: str
    name: str
    access: Literal["read", "write"]


class LoginResponse(BaseModel):
    token: str
    expires_at: str
    user: UserOut
    must_change_password: bool
    spaces: list[SpaceEntry]


class MeResponse(UserOut):
    must_change_password: bool
    spaces: list[SpaceEntry]


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def _spaces(request: Request, user_id: str) -> list[SpaceEntry]:
    return [
        SpaceEntry(id=s.id, name=s.name, access=s.access)
        for s in request.app.state.permissions.spaces_for(user_id)
    ]


# Sync handlers on purpose: password hashing and SQLite block, so FastAPI runs them in its
# thread pool instead of on the event loop.


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    result = service.login(body.username, body.password, client_ip(request))
    return LoginResponse(
        token=result.token,
        expires_at=_iso(result.expires_at),
        user=UserOut(id=result.user.id, username=result.user.username, role=result.user.role),
        must_change_password=result.must_change_password,
        spaces=_spaces(request, result.user.id),
    )


@router.post("/logout", status_code=204)
def logout(
    ctx: Annotated[AuthContext, Depends(require_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    service.logout(ctx)
    return Response(status_code=204)


@router.get("/me")
def me(request: Request, ctx: Annotated[AuthContext, Depends(require_session)]) -> MeResponse:
    return MeResponse(
        id=ctx.user.id,
        username=ctx.user.username,
        role=ctx.user.role,
        must_change_password=ctx.must_change,
        spaces=_spaces(request, ctx.user.id),
    )


@router.post("/password", status_code=204)
def change_password(
    body: PasswordChangeRequest,
    ctx: Annotated[AuthContext, Depends(require_session)],
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    service.change_password(ctx, body.current, body.new)
    return Response(status_code=204)
