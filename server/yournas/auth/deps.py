"""FastAPI dependencies: bearer authentication, forced password change, owner, client address."""

from __future__ import annotations

import ipaddress
from typing import Annotated

from fastapi import Depends, Request

from yournas.auth.service import AuthContext, AuthService
from yournas.core.config import is_loopback_host
from yournas.core.errors import AppError

_BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


def _unauthorized() -> AppError:
    return AppError(401, "unauthorized", "Authentication required", _BEARER_CHALLENGE)


def get_auth_service(request: Request) -> AuthService:
    service: AuthService = request.app.state.auth
    return service


def client_ip(request: Request) -> str | None:
    """Address of the caller, or None when it cannot be told apart from the local proxy.

    A loopback TCP peer is only meaningful behind a trusted proxy: with `trust_forwarded_for`
    the last X-Forwarded-For entry (the one the proxy itself appended) is used; otherwise None,
    and the caller gets no per-address throttle. A non-loopback peer is used as is, and the
    header is ignored, so a remote client cannot pick its own address.
    """
    peer = request.client.host if request.client else None
    if peer is None:
        return None
    if not is_loopback_host(peer):
        return peer
    if request.app.state.settings.trust_forwarded_for:
        # The proxy's own entry is the last one, whether it joined values or added a header line.
        lines = request.headers.getlist("x-forwarded-for")
        last = lines[-1].rsplit(",", 1)[-1].strip() if lines else ""
        try:
            address = ipaddress.ip_address(last)
        except ValueError:
            return None
        # ::ffff:1.2.3.4 and 1.2.3.4 are the same host: one throttle bucket for both.
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return str(address)
    return None


def require_session(
    request: Request, service: Annotated[AuthService, Depends(get_auth_service)]
) -> AuthContext:
    """A live bearer session, even for an account that must still change its password.

    Only /auth/me, /auth/password and /auth/logout use this. Everything else uses `require_user`.
    Fail closed: anything but a well-formed bearer token for a live session is a 401.
    """
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized()
    ctx = service.authenticate(token.strip())
    if ctx is None:
        raise _unauthorized()
    return ctx


def require_user(ctx: Annotated[AuthContext, Depends(require_session)]) -> AuthContext:
    """A live session whose password is not a temporary one (403 password_change_required)."""
    if ctx.must_change:
        raise AppError(
            403,
            "password_change_required",
            "You must change your temporary password first",
        )
    return ctx


def require_owner(ctx: Annotated[AuthContext, Depends(require_user)]) -> AuthContext:
    if ctx.user.role != "owner":
        raise AppError(403, "forbidden", "Forbidden")
    return ctx
