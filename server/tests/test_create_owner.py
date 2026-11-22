from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from conftest import routes_of
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yournas.__main__ import cli, create_owner
from yournas.core.config import Settings
from yournas.core.database import Database, open_database
from yournas.core.logging_setup import shutdown_logging
from yournas.main import DEFAULT_DATA_DIR_NAME, create_app
from yournas.storage.root import open_storage

PASSWORD = "an owner passphrase"  # noqa: S105 - test credential


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    yield
    shutdown_logging()


@pytest.fixture
def configured(storage_root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("YOURNAS_STORAGE_ROOT", str(storage_root))
    return storage_root


def answers(*values: str) -> Callable[[str], str]:
    queue = iter(values)

    def _ask(_prompt: str) -> str:
        return next(queue)

    return _ask


def never(_prompt: str) -> str:
    raise AssertionError("must not prompt")


def open_db(root: Path) -> Database:
    return open_database(root / DEFAULT_DATA_DIR_NAME)


def owner_rows(root: Path) -> list[tuple[str, str, str]]:
    db = open_db(root)
    try:
        with db.read() as conn:
            rows = conn.execute("SELECT username, role, password_hash FROM users").fetchall()
            return [(r[0], r[1], r[2]) for r in rows]
    finally:
        db.close()


def test_create_owner_stores_an_argon2_hash_and_never_the_password(
    configured: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = create_owner(
        ["--username", "Alice"], prompt_username=never, prompt_password=answers(PASSWORD, PASSWORD)
    )
    assert rc == 0
    [(username, role, password_hash)] = owner_rows(configured)
    assert (username, role) == ("alice", "owner")
    assert password_hash.startswith("$argon2id$")
    out = capsys.readouterr()
    assert "alice" in out.out and PASSWORD not in out.out + out.err
    for path in (configured / DEFAULT_DATA_DIR_NAME).iterdir():
        assert PASSWORD.encode() not in path.read_bytes()


def test_username_is_prompted_when_not_given(configured: Path) -> None:
    rc = create_owner(
        [], prompt_username=answers("bob.the.owner"), prompt_password=answers(PASSWORD, PASSWORD)
    )
    assert rc == 0 and owner_rows(configured)[0][0] == "bob.the.owner"


def test_a_second_owner_is_refused_before_any_prompt(configured: Path) -> None:
    create_owner(
        ["--username", "alice"], prompt_username=never, prompt_password=answers(PASSWORD, PASSWORD)
    )
    rc = create_owner(["--username", "bob"], prompt_username=never, prompt_password=never)
    assert rc == 1
    assert [row[0] for row in owner_rows(configured)] == ["alice"]


def test_mismatched_passwords_create_nothing(
    configured: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = create_owner(
        ["--username", "alice"],
        prompt_username=never,
        prompt_password=answers(PASSWORD, PASSWORD + "x"),
    )
    assert rc == 1 and owner_rows(configured) == []
    assert "do not match" in capsys.readouterr().err


def test_weak_password_is_refused(configured: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = create_owner(
        ["--username", "alice"], prompt_username=never, prompt_password=answers("short", "short")
    )
    assert rc == 1 and owner_rows(configured) == []
    assert "at least" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["", "ab", "Bad Name!", "-leading-dash", "x" * 33, "a/b"])
def test_invalid_username_is_refused(configured: Path, name: str) -> None:
    # "--username=NAME": a value starting with "-" would otherwise be read as an option.
    rc = create_owner([f"--username={name}"], prompt_username=answers(name), prompt_password=never)
    assert rc == 1 and owner_rows(configured) == []


def test_the_password_cannot_be_given_as_an_argument(configured: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        create_owner(["--username", "alice", "--password", PASSWORD])
    assert exc.value.code == 2


def test_missing_storage_root_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("YOURNAS_STORAGE_ROOT", str(tmp_path / "nope"))
    rc = create_owner(["--username", "alice"], prompt_username=never, prompt_password=never)
    assert rc == 2 and "storage root rejected" in capsys.readouterr().err
    assert not (tmp_path / "nope").exists()


def test_cli_rejects_unknown_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli(["register"]) == 2
    assert "usage" in capsys.readouterr().err


def test_owner_created_on_the_console_can_use_the_api(configured: Path) -> None:
    create_owner(
        ["--username", "alice"], prompt_username=never, prompt_password=answers(PASSWORD, PASSWORD)
    )
    app = create_app(Settings(storage_root=configured), open_storage(configured))
    client = TestClient(app)
    login = client.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    status = client.get("/api/v1/admin/status", headers=headers)
    assert status.status_code == 200 and status.json()["database"]["ok"] is True


def test_the_http_surface_is_pinned(make_app: Callable[..., FastAPI]) -> None:
    """Pin the API surface: new routes must be added here on purpose. Accounts can be created
    over HTTP only through the owner-only /admin/users routes (see test_admin_api.py)."""
    assert routes_of(make_app()) == {
        ("GET", "/health"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/logout"),
        ("GET", "/api/v1/auth/me"),
        ("POST", "/api/v1/auth/password"),
        ("GET", "/api/v1/admin/status"),
        ("GET", "/api/v1/admin/users"),
        ("POST", "/api/v1/admin/users"),
        ("PATCH", "/api/v1/admin/users/{user_id}"),
        ("POST", "/api/v1/admin/users/{user_id}/password-reset"),
        ("DELETE", "/api/v1/admin/users/{user_id}/sessions"),
        ("GET", "/api/v1/admin/shares"),
        ("POST", "/api/v1/admin/shares"),
        ("PATCH", "/api/v1/admin/shares/{share_id}"),
        ("DELETE", "/api/v1/admin/shares/{share_id}"),
        ("PUT", "/api/v1/admin/shares/{share_id}/grants/{user_id}"),
        ("DELETE", "/api/v1/admin/shares/{share_id}/grants/{user_id}"),
        ("GET", "/api/v1/admin/audit"),
        ("GET", "/api/v1/spaces"),
        ("GET", "/api/v1/spaces/{space}/items"),
        ("DELETE", "/api/v1/spaces/{space}/items"),
        ("GET", "/api/v1/spaces/{space}/items/meta"),
        ("POST", "/api/v1/spaces/{space}/folders"),
        ("GET", "/api/v1/spaces/{space}/files"),
        ("POST", "/api/v1/spaces/{space}/uploads"),
        ("PATCH", "/api/v1/uploads/{upload_id}"),
        ("GET", "/api/v1/uploads/{upload_id}"),
        ("HEAD", "/api/v1/uploads/{upload_id}"),
        ("DELETE", "/api/v1/uploads/{upload_id}"),
        ("GET", "/api/v1/spaces/{space}/thumbnail"),
        ("PUT", "/api/v1/spaces/{space}/thumbnail"),
        ("GET", "/api/v1/spaces/{space}/photos/months"),
        ("GET", "/api/v1/spaces/{space}/photos/months/{month}"),
        ("PUT", "/api/v1/spaces/{space}/photos/months/{month}/cover"),
        ("DELETE", "/api/v1/spaces/{space}/photos/months/{month}/cover"),
    }


def test_default_database_lives_in_a_hidden_data_dir_outside_every_space(
    make_app: Callable[..., FastAPI], storage_root: Path
) -> None:
    make_app()
    assert (storage_root / DEFAULT_DATA_DIR_NAME / "yournas.db").is_file()
    assert not (storage_root / "users" / "yournas.db").exists()


def test_data_dir_can_be_moved(make_app: Callable[..., FastAPI], tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    make_app(data_dir=elsewhere)
    assert (elsewhere / "yournas.db").is_file()


def test_startup_warns_when_there_is_no_owner(
    make_app: Callable[..., FastAPI], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    with TestClient(make_app()):
        pass
    assert "no_owner" in {r.getMessage() for r in caplog.records}
