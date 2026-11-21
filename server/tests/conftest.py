from __future__ import annotations

import os
import secrets
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from argon2 import PasswordHasher
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yournas.audit import AuditLog
from yournas.auth.passwords import PasswordService
from yournas.auth.service import AuthService
from yournas.core.config import Settings
from yournas.core.database import Database, open_database
from yournas.main import create_app
from yournas.storage.root import open_storage
from yournas.uploads import UploadService


@pytest.fixture(autouse=True)
def _hermetic_env(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No stray config.local.json in cwd and no YOURNAS_* variables from the real environment."""
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
    for key in [k for k in os.environ if k.startswith("YOURNAS_")]:
        monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def _loopback_host_for_test_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    """Starlette's TestClient sends `Host: testserver`, which the app refuses (Host allowlist).
    Default every client to `localhost`, as a real local client would; a test that needs another
    Host passes `base_url` or a `Host` header itself."""
    original = TestClient.__init__

    def init(self: TestClient, app: Any, *args: Any, **kwargs: Any) -> None:
        if not args:
            kwargs.setdefault("base_url", "http://localhost")
        original(self, app, *args, **kwargs)

    monkeypatch.setattr(TestClient, "__init__", init)


@pytest.fixture
def storage_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir()
    return root


@pytest.fixture
def make_app(storage_root: Path) -> Callable[..., FastAPI]:
    def _make(**overrides: Any) -> FastAPI:
        settings = Settings(storage_root=storage_root, **overrides)
        return create_app(settings, open_storage(storage_root))

    return _make


def routes_of(app: FastAPI) -> set[tuple[str, str]]:
    """(METHOD, path) of every documented route, via the public OpenAPI schema.

    Walking `app.routes` is not reliable: newer FastAPI wraps included routers in private
    objects. Callers must still assert the set is non-empty, so a silent change cannot make a
    guard test vacuous.
    """
    paths = app.openapi()["paths"]
    return {(method.upper(), path) for path, operations in paths.items() for method in operations}


OWNER_NAME = "owner"
OWNER_PASSWORD = "correct horse battery"  # noqa: S105 - test credential


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


CHEAP_HASHER = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def build_app(
    settings: Settings, data_dir: Path, clock: FakeClock
) -> tuple[FastAPI, AuthService, UploadService, Database]:
    """An app on `data_dir` (database) and the settings' storage root, as after a (re)start."""
    db = open_database(data_dir)
    audit = AuditLog(db, clock)
    service = AuthService(
        db,
        PasswordService(CHEAP_HASHER),
        idle_seconds=settings.session_idle_hours * 3600,
        lifetime_seconds=settings.session_lifetime_days * 86400,
        clock=clock,
        audit=audit,
    )
    storage = open_storage(
        settings.storage_root, tmp_max_age_seconds=settings.upload_stale_hours * 3600
    )
    uploads = UploadService(db, storage, settings, clock=clock)
    app = create_app(settings, storage, database=db, auth=service, uploads=uploads, audit=audit)
    return app, service, uploads, db


@dataclass
class AuthEnv:
    app: FastAPI
    service: AuthService
    db: Database
    clock: FakeClock
    storage_root: Path
    uploads: UploadService
    settings: Settings
    data_dir: Path

    def restart(self) -> AuthEnv:
        """A new app instance on the same data directory and storage root (simulated restart).
        Sessions and unfinished uploads are expected to survive."""
        self.db.close()
        app, service, uploads, db = build_app(self.settings, self.data_dir, self.clock)
        return AuthEnv(
            app, service, db, self.clock, self.storage_root, uploads, self.settings, self.data_dir
        )

    def client(self, host: str = "testclient", **headers: str) -> TestClient:
        return TestClient(self.app, client=(host, 50000), headers=headers)

    def add_user(
        self, username: str, password: str, *, role: str = "user", disabled: bool = False
    ) -> str:
        """Insert an account directly. Phase 2 has no HTTP or CLI way to add non-owner users."""
        user_id = "u_" + secrets.token_hex(8)
        now = int(self.clock())
        password_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(password)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, disabled, created_at, "
                "password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, username, password_hash, role, int(disabled), now, now),
            )
        return user_id

    def login(self, username: str = OWNER_NAME, password: str = OWNER_PASSWORD) -> str:
        r = self.client().post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert r.status_code == 200, r.text
        return str(r.json()["token"])


@pytest.fixture
def make_auth_env(tmp_path: Path, storage_root: Path) -> Callable[..., AuthEnv]:
    """App with a cheap password hasher, a fake clock and an owner account."""

    def _make(**overrides: Any) -> AuthEnv:
        clock = FakeClock()
        data_dir = tmp_path / "appdata"
        settings = Settings(storage_root=storage_root, **overrides)
        app, service, uploads, db = build_app(settings, data_dir, clock)
        service.create_owner(OWNER_NAME, OWNER_PASSWORD)
        return AuthEnv(app, service, db, clock, storage_root, uploads, settings, data_dir)

    return _make


@pytest.fixture
def auth_env(make_auth_env: Callable[..., AuthEnv]) -> AuthEnv:
    return make_auth_env()


FRIEND_NAME = "friend"
FRIEND_PASSWORD = "friendly passphrase 42"  # noqa: S105 - test credential


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Session:
    """A logged-in user of an AuthEnv: a client that carries the bearer token."""

    env: AuthEnv
    user_id: str
    token: str
    client: TestClient

    @property
    def home(self) -> Path:
        """This user's private folder on disk."""
        return self.env.storage_root / "users" / self.user_id


def session_for(env: AuthEnv, username: str, password: str) -> Session:
    token = env.login(username, password)
    client = env.client(**bearer(token))
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200, me.text
    # The private folder is created lazily by the first file request.
    assert client.get("/api/v1/spaces/home/items").status_code == 200
    return Session(env, str(me.json()["id"]), token, client)


@pytest.fixture
def owner(auth_env: AuthEnv) -> Session:
    return session_for(auth_env, OWNER_NAME, OWNER_PASSWORD)


@pytest.fixture
def friend(auth_env: AuthEnv) -> Session:
    auth_env.add_user(FRIEND_NAME, FRIEND_PASSWORD)
    return session_for(auth_env, FRIEND_NAME, FRIEND_PASSWORD)


@pytest.fixture
def live(auth_env: AuthEnv) -> Iterator[tuple[str, int]]:
    """The app on a real loopback socket (TestClient buffers whole responses)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(auth_env.app, host="127.0.0.1", port=port, log_config=None, access_log=False)
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    assert server.started
    yield "127.0.0.1", port
    server.should_exit = True
    thread.join(10)
