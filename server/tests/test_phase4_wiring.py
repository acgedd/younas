"""Phase 4 foundation is wired into the app without changing request behaviour."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import AuthEnv
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yournas.audit import AuditLog
from yournas.core.config import Settings
from yournas.core.database import Database, open_database
from yournas.main import create_app
from yournas.permissions import Action, Level, Permissions
from yournas.storage.root import open_storage
from yournas.uploads import UploadService


def test_the_app_exposes_permissions_and_audit(make_app: Callable[..., FastAPI]) -> None:
    app = make_app()
    assert isinstance(app.state.permissions, Permissions)
    assert isinstance(app.state.audit, AuditLog)
    # the app's permissions sit on the app's own database and storage root
    assert app.state.permissions.level_for("u_" + "0" * 16, "home") is Level.NONE


def test_injected_permissions_and_audit_are_used(tmp_path: Path, storage_root: Path) -> None:
    db = open_database(tmp_path / "d")
    storage = open_storage(storage_root)
    perms = Permissions(db, storage)
    audit = AuditLog(db)
    app = create_app(
        Settings(storage_root=storage_root), storage, database=db, permissions=perms, audit=audit
    )
    assert app.state.permissions is perms and app.state.audit is audit
    assert app.state.uploads._permissions is perms
    db.close()


def test_upload_service_has_a_safe_default(tmp_path: Path, storage_root: Path) -> None:
    db = Database(tmp_path / "x.db")
    storage = open_storage(storage_root)
    service = UploadService(db, storage, Settings(storage_root=storage_root))
    assert isinstance(service._permissions, Permissions)
    with pytest.raises(Exception, match=r"404|Not Found|not_found") as exc:
        service._permissions.authorize("u_" + "1" * 16, "home", Action.LIST)
    assert getattr(exc.value, "status_code", None) == 404
    db.close()


def test_startup_prunes_old_audit_rows(auth_env: AuthEnv) -> None:
    now = int(time.time())  # the app's audit log runs on the real clock
    with auth_env.db.transaction() as conn:
        conn.execute(
            "INSERT INTO audit_log (at, actor_id, action, target_type, target_id) "
            "VALUES (?, 'u_x', 'share_created', 'share', 's_1')",
            (now - 400 * 86400,),
        )
        conn.execute(
            "INSERT INTO audit_log (at, actor_id, action, target_type, target_id) "
            "VALUES (?, 'u_x', 'share_created', 'share', 's_2')",
            (now,),
        )
    with TestClient(auth_env.app):  # runs the lifespan: startup maintenance
        pass
    with auth_env.db.read() as conn:
        ids = [r["target_id"] for r in conn.execute("SELECT target_id FROM audit_log")]
    assert ids == ["s_2"]


def test_a_failing_audit_prune_does_not_stop_the_server(
    auth_env: AuthEnv, caplog: pytest.LogCaptureFixture
) -> None:
    with auth_env.db.transaction() as conn:
        conn.execute("DROP TABLE audit_log")
    with caplog.at_level(logging.WARNING), TestClient(auth_env.app) as client:
        assert client.get("/health").status_code == 200


def test_a_prune_that_raises_is_logged_and_boot_continues(
    auth_env: AuthEnv, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import sqlite3

    def boom() -> int | None:
        raise sqlite3.OperationalError("disk I/O error at C:\\secret\\path")

    monkeypatch.setattr(auth_env.app.state.audit, "maybe_prune", boom)
    with caplog.at_level(logging.WARNING, logger="yournas.app"), TestClient(auth_env.app) as client:
        assert client.get("/health").status_code == 200
    messages = [r.message for r in caplog.records]
    assert "audit_prune_failed" in messages
    assert "secret" not in repr([r.__dict__ for r in caplog.records])


def test_request_behaviour_is_unchanged_home_only(auth_env: AuthEnv) -> None:
    token = auth_env.login()
    client = auth_env.client(Authorization=f"Bearer {token}")
    spaces = client.get("/api/v1/spaces")
    assert spaces.status_code == 200
    assert [s["id"] for s in spaces.json()] == ["home"]
    assert client.get("/api/v1/spaces/share:s_0123456789abcdef/items").status_code == 404
