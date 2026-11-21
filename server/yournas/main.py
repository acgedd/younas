"""Application factory."""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from yournas import __version__
from yournas.api.admin import router as admin_router
from yournas.api.auth import router as auth_router
from yournas.api.health import router as health_router
from yournas.api.photos import router as photos_router
from yournas.api.spaces import router as spaces_router
from yournas.api.thumbnails import router as thumbnails_router
from yournas.api.uploads import router as uploads_router
from yournas.audit import AuditLog
from yournas.auth.passwords import PasswordService
from yournas.auth.service import AuthService
from yournas.core.config import Settings
from yournas.core.database import Database, open_database
from yournas.core.errors import install_error_handlers
from yournas.core.logging_setup import error_fields
from yournas.core.middleware import (
    BodyLimitMiddleware,
    BodyRule,
    HostValidationMiddleware,
    RequestContextMiddleware,
)
from yournas.permissions import Permissions
from yournas.photo_index import PhotoIndexService
from yournas.shares import ShareService
from yournas.storage.errors import StorageError
from yournas.storage.root import StorageRoot
from yournas.storage.thumbs import THUMBS_DIR_NAME
from yournas.thumbnails import THUMBNAIL_MAX_BYTES, ThumbnailService
from yournas.uploads import UploadService
from yournas.web import install_web

log = logging.getLogger("yournas.app")

# Every JSON body in this API (login, password, mkdir, start of an upload) is tiny; anything
# bigger is refused unread. The exceptions are a chunk of an upload and a thumbnail, below.
JSON_BODY_LIMIT_BYTES = 16 * 1024
# Slack on top of upload_chunk_max_bytes; the route enforces the exact chunk limit itself.
CHUNK_BODY_SLACK_BYTES = 1024
_CHUNK_PATH = re.compile(r"/api/v1/uploads/[^/]+")
_THUMBNAIL_PATH = re.compile(r"/api/v1/spaces/[^/]+/thumbnail")


def body_limit_rules(settings: Settings) -> list[BodyRule]:
    """Ordered rules for BodyLimitMiddleware. The last one is a catch-all, so no route can
    receive an unbounded body."""
    return [
        (
            lambda method, path: method == "PATCH" and _CHUNK_PATH.fullmatch(path) is not None,
            settings.upload_chunk_max_bytes + CHUNK_BODY_SLACK_BYTES,
        ),
        (
            lambda method, path: method == "PUT" and _THUMBNAIL_PATH.fullmatch(path) is not None,
            THUMBNAIL_MAX_BYTES,
        ),
        (lambda _method, _path: True, JSON_BODY_LIMIT_BYTES),
    ]


DEFAULT_DATA_DIR_NAME = ".yournas-data"


def default_data_dir(settings: Settings, storage: StorageRoot) -> Path:
    return settings.data_dir or storage.root / DEFAULT_DATA_DIR_NAME


def create_app(
    settings: Settings,
    storage: StorageRoot,
    *,
    database: Database | None = None,
    auth: AuthService | None = None,
    uploads: UploadService | None = None,
    permissions: Permissions | None = None,
    audit: AuditLog | None = None,
) -> FastAPI:
    """Build the app. `storage` must already have passed validation.

    `database` and `auth` are injectable for the entry point and for tests; by default the
    database is opened in the data directory and the auth service is built from the settings.
    `permissions` (space authorization) and `audit` (audit log) are built from the database and
    the storage root unless given; they live on `app.state.permissions` / `app.state.audit`.
    """
    owns_database = database is None
    if database is None:
        database = open_database(default_data_dir(settings, storage))
    if audit is None:
        audit = AuditLog(database)
    if auth is None:
        auth = AuthService(
            database,
            PasswordService(),
            idle_seconds=settings.session_idle_hours * 3600,
            lifetime_seconds=settings.session_lifetime_days * 86400,
            audit=audit,
        )
    if permissions is None:
        permissions = Permissions(database, storage)
    if uploads is None:
        uploads = UploadService(database, storage, settings, permissions=permissions, audit=audit)
    # Next to the database: the data directory is never inside a space.
    thumbnails = ThumbnailService(
        database, permissions, settings, database.path.parent / THUMBS_DIR_NAME
    )
    # Never started here: only GET .../photos/months starts the one background job.
    photo_index = PhotoIndexService(database, permissions, settings)
    uploads.add_completion_listener(photo_index.mark_uploaded)
    share_service = ShareService(database, permissions, uploads, audit, thumbnails, photo_index)
    db = database
    auth_service = auth
    upload_service = uploads
    audit_log = audit

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.info(
            "startup",
            extra={
                "version": __version__,
                "host": settings.host,
                "port": settings.port,
                "allowed_hosts": list(settings.allowed_hosts),
                "storage_root": str(storage.root),
                "swept_tmp_entries": storage.swept_tmp_entries,
                "skipped_tmp_entries": storage.skipped_tmp_entries,
                "database_schema": db.schema_version,
            },
        )
        # Staged chunks survive a restart (the storage sweep is age based); this drops what is
        # stale for good: expired uploads and staging files nothing refers to.
        try:
            await run_in_threadpool(upload_service.run_maintenance)
        except (OSError, StorageError, sqlite3.Error) as exc:
            log.warning("upload_maintenance_failed", extra=error_fields(exc))  # boot anyway
        # Thumbnail temp files a crash left between open and os.replace; never blocks boot.
        try:
            swept = await run_in_threadpool(thumbnails.sweep_temp_files)
            if swept:
                log.info("thumbnail_temp_swept", extra={"count": swept})
        except (OSError, StorageError) as exc:
            log.warning("thumbnail_sweep_failed", extra=error_fields(exc))
        # Audit retention (a year, 100k rows); a failure is logged and never blocks boot.
        try:
            await run_in_threadpool(audit_log.maybe_prune)
        except (OSError, sqlite3.Error) as exc:
            log.warning("audit_prune_failed", extra=error_fields(exc))
        if not auth_service.owner_exists():
            log.warning("no_owner", extra={"hint": "run: python -m yournas create-owner"})
        yield
        log.info("shutdown")
        # The photo index job stops between two files; the database closes only after it.
        await run_in_threadpool(photo_index.close)
        if owns_database:
            db.close()

    app = FastAPI(
        title="YourNAS",
        version=__version__,
        lifespan=lifespan,
        # A slash redirect builds its Location from the client-controlled Host header.
        redirect_slashes=False,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.storage = storage
    app.state.database = database
    app.state.auth = auth
    app.state.uploads = uploads
    app.state.permissions = permissions
    app.state.audit = audit
    app.state.shares = share_service
    app.state.thumbnails = thumbnails
    app.state.photo_index = photo_index
    install_error_handlers(app)
    # Added first = inner: it runs inside RequestContextMiddleware, so a 413 is logged and
    # carries the request id and security headers.
    app.add_middleware(BodyLimitMiddleware, rules=body_limit_rules(settings))
    # The web UI under /app (and its own security headers); inside RequestContextMiddleware.
    install_web(app)
    # Host header allowlist (DNS rebinding). Inside RequestContextMiddleware, so a 400 is logged
    # and carries the request id; outside everything else, so no route or body is reached first.
    app.add_middleware(HostValidationMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(RequestContextMiddleware, hsts=settings.enable_hsts)
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(spaces_router)
    app.include_router(thumbnails_router)
    app.include_router(photos_router)
    app.include_router(uploads_router)
    return app
