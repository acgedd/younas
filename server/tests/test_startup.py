from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import uvicorn

from yournas.__main__ import main
from yournas.core.logging_setup import LOG_FILE_NAME, shutdown_logging


def run_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("YOURNAS_")}
    env.update(extra)
    return env


def run_cli(tmp_path: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "yournas"],
        cwd=tmp_path,
        env=run_env(**extra),
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_missing_storage_root_setting_fails_closed(tmp_path: Path) -> None:
    r = run_cli(tmp_path)
    assert r.returncode == 2
    assert "configuration error" in r.stderr and "storage_root" in r.stderr
    assert "Traceback" not in r.stderr


def test_nonexistent_storage_root_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    r = run_cli(tmp_path, YOURNAS_STORAGE_ROOT=str(missing))
    assert r.returncode == 2
    assert "storage root rejected" in r.stderr and "does not exist" in r.stderr
    assert "Traceback" not in r.stderr
    assert not missing.exists()


def test_unc_storage_root_fails_closed(tmp_path: Path) -> None:
    r = run_cli(tmp_path, YOURNAS_STORAGE_ROOT="\\\\server\\share\\nas")
    assert r.returncode == 2
    assert "UNC" in r.stderr


def test_public_bind_refused_without_override(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    r = run_cli(tmp_path, YOURNAS_STORAGE_ROOT=str(root), YOURNAS_HOST="0.0.0.0")
    assert r.returncode == 2
    assert "loopback" in r.stderr
    assert list(root.iterdir()) == []


def test_rejected_storage_root_leaves_no_log_directory(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"
    r = run_cli(
        tmp_path, YOURNAS_STORAGE_ROOT=str(tmp_path / "nope"), YOURNAS_LOG_DIR=str(log_dir)
    )
    assert r.returncode == 2
    assert not log_dir.exists()


def test_nul_byte_in_storage_root_exits_cleanly(tmp_path: Path) -> None:
    # Environment values cannot hold NUL on Windows, but a JSON config file can ("\u0000").
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"storage_root": str(tmp_path) + "\x00x"}))
    r = run_cli(tmp_path, YOURNAS_CONFIG=str(cfg))
    assert r.returncode == 2
    assert "invalid character" in r.stderr
    assert "Traceback" not in r.stderr


def test_host_and_hardening_flags_reach_uvicorn_and_override_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    log_dir = tmp_path / "logs"
    monkeypatch.setenv("YOURNAS_STORAGE_ROOT", str(root))
    monkeypatch.setenv("YOURNAS_HOST", "100.64.0.1")
    monkeypatch.setenv("YOURNAS_ALLOW_NON_LOOPBACK", "true")
    monkeypatch.setenv("YOURNAS_LOG_DIR", str(log_dir))
    seen: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    try:
        assert main() == 0
    finally:
        shutdown_logging()
    assert seen["host"] == "100.64.0.1"
    assert seen["server_header"] is False and seen["proxy_headers"] is False
    assert seen["access_log"] is False
    text = (log_dir / LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "non_loopback_bind_override" in text


def test_loopback_default_is_what_uvicorn_gets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("YOURNAS_STORAGE_ROOT", str(root))
    seen: dict[str, object] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: seen.update(kwargs))
    try:
        assert main() == 0
    finally:
        shutdown_logging()
    assert seen["host"] == "127.0.0.1"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_server_starts_serves_health_and_prepares_storage(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    port = free_port()
    stderr_file = tmp_path / "server.stderr"
    with stderr_file.open("wb") as err:
        proc = subprocess.Popen(
            [sys.executable, "-m", "yournas"],
            cwd=tmp_path,
            env=run_env(
                YOURNAS_STORAGE_ROOT=str(root),
                YOURNAS_PORT=str(port),
                YOURNAS_LOG_DIR=str(tmp_path / "logs"),
            ),
            stdout=subprocess.DEVNULL,
            stderr=err,
        )
    try:
        body: dict[str, str] | None = None
        headers = None
        deadline = time.time() + 20
        while time.time() < deadline and body is None:
            if proc.poll() is not None:
                pytest.fail(
                    f"server exited early with code {proc.returncode}: "
                    f"{stderr_file.read_text(errors='replace')}"
                )
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
                    body = json.loads(resp.read())
                    headers = resp.headers
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                time.sleep(0.3)
        assert body == {"status": "ok"}
        assert headers is not None and headers.get("server") is None
        # .yournas-data holds the SQLite database; no space (users/, shared/) can reach it.
        assert {p.name for p in root.iterdir()} == {
            "users",
            "shared",
            ".yournas-tmp",
            ".yournas-data",
        }
    finally:
        proc.terminate()
        proc.wait(timeout=10)
