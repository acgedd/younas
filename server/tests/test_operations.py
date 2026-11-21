"""Running the server for real: one instance per data directory, HSTS switch, config template and
the start script."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_startup import free_port, run_env

from yournas.core.config import load_settings
from yournas.core.instance_lock import InstanceLockError, acquire_instance_lock

SERVER_DIR = Path(__file__).resolve().parent.parent
TEMPLATE = SERVER_DIR / "config.example.json"
START_SCRIPT = SERVER_DIR / "scripts" / "start-yournas.ps1"


# ---- single instance --------------------------------------------------------------------------


def test_the_lock_is_exclusive_and_released(tmp_path: Path) -> None:
    first = acquire_instance_lock(tmp_path)
    with pytest.raises(InstanceLockError, match="already running"):
        acquire_instance_lock(tmp_path)
    first.release()
    first.release()  # twice is harmless
    acquire_instance_lock(tmp_path).release()


def start_server(root: Path, port: int, err: Path) -> subprocess.Popen[bytes]:
    with err.open("wb") as handle:
        return subprocess.Popen(
            [sys.executable, "-m", "yournas"],
            cwd=root.parent,
            env=run_env(YOURNAS_STORAGE_ROOT=str(root), YOURNAS_PORT=str(port)),
            stdout=subprocess.DEVNULL,
            stderr=handle,
        )


def wait_healthy(proc: subprocess.Popen[bytes], port: int, err: Path) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            pytest.fail(
                f"server exited early ({proc.returncode}): {err.read_text(errors='replace')}"
            )
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2):
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(0.3)
    pytest.fail("server never answered /health")


def test_a_second_server_on_the_same_data_refuses_to_start(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    port = free_port()
    proc = start_server(root, port, tmp_path / "first.stderr")
    try:
        wait_healthy(proc, port, tmp_path / "first.stderr")
        second = subprocess.run(
            [sys.executable, "-m", "yournas"],
            cwd=tmp_path,
            env=run_env(YOURNAS_STORAGE_ROOT=str(root), YOURNAS_PORT=str(free_port())),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert second.returncode == 3, second.stderr
        assert "already running" in second.stderr
        assert "Traceback" not in second.stderr
        # The first server is unharmed.
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            assert resp.status == 200
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    # A killed server leaves no lock behind: the OS drops it with the process. On Windows the venv
    # python.exe is a launcher whose child (the real server) ends a moment after it, so wait a bit.
    deadline = time.time() + 10
    while True:
        try:
            acquire_instance_lock(root / ".yournas-data").release()
            break
        except InstanceLockError:
            assert time.time() < deadline, "the lock outlived the killed server"
            time.sleep(0.2)


# ---- HSTS -------------------------------------------------------------------------------------


def test_hsts_is_off_by_default(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app())
    for path in ("/health", "/app", "/nope"):
        assert "strict-transport-security" not in client.get(path).headers


def test_hsts_on_every_response_when_enabled(make_app: Callable[..., FastAPI]) -> None:
    client = TestClient(make_app(enable_hsts=True))
    responses = [
        client.get("/health"),
        client.get("/app"),
        client.get("/nope"),
        client.get("/api/v1/spaces"),
        client.get("/health", headers={"Host": "evil.example"}),
    ]
    assert [r.status_code for r in responses] == [200, 200, 404, 401, 400]
    for r in responses:
        assert r.headers["strict-transport-security"] == "max-age=31536000"


# ---- config template --------------------------------------------------------------------------


def test_the_config_template_loads_with_safe_values() -> None:
    s = load_settings({"YOURNAS_CONFIG": str(TEMPLATE)})
    assert s.storage_root == Path("C:\\NAS")
    assert s.host == "127.0.0.1"
    assert s.allow_non_loopback is False
    assert s.allowed_hosts == ()
    assert s.trust_forwarded_for is False
    assert s.enable_hsts is False
    assert s.enable_docs is False
    assert s.log_dir is not None
    assert s.log_dir.parent != s.storage_root


# ---- start script -----------------------------------------------------------------------------

POWERSHELL = shutil.which("powershell")
needs_powershell = pytest.mark.skipif(
    sys.platform != "win32" or POWERSHELL is None, reason="Windows PowerShell only"
)


def run_script(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(START_SCRIPT), *args],
        env=run_env(**env),
        capture_output=True,
        text=True,
        timeout=60,
    )


@needs_powershell
def test_the_start_script_stops_on_a_missing_config(tmp_path: Path) -> None:
    r = run_script("-Config", str(tmp_path / "nope.json"))
    assert r.returncode == 2
    assert "config file not found" in r.stderr


@needs_powershell
def test_the_start_script_uses_only_the_config_file(tmp_path: Path) -> None:
    from_file = tmp_path / "from-file-root"
    from_env = tmp_path / "from-env-root"
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"storage_root": str(from_file)}), encoding="utf-8")
    # A YOURNAS_* variable would normally override the file; the script must drop it.
    r = run_script("-Config", str(cfg), YOURNAS_STORAGE_ROOT=str(from_env))
    assert r.returncode == 2, r.stderr
    assert "storage root rejected" in r.stderr
    assert "from-file-root" in r.stderr
    assert "from-env-root" not in r.stderr


@needs_powershell
def test_keep_running_does_not_retry_a_configuration_error(tmp_path: Path) -> None:
    cfg = tmp_path / "c.json"
    logs = tmp_path / "logs"
    cfg.write_text(
        json.dumps({"storage_root": str(tmp_path / "missing"), "log_dir": str(logs)}),
        encoding="utf-8",
    )
    r = run_script("-Config", str(cfg), "-KeepRunning", "-RestartDelaySeconds", "1")
    assert r.returncode == 2, r.stderr
    assert "restart" not in r.stderr
    assert not (logs / "supervisor.log").exists()


@needs_powershell
def test_keep_running_restarts_a_crashed_server_and_logs_it(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    logs = tmp_path / "logs"
    port = free_port()
    cfg = tmp_path / "c.json"
    cfg.write_text(
        json.dumps({"storage_root": str(root), "port": port, "log_dir": str(logs)}),
        encoding="utf-8",
    )
    # The port is taken, so every start fails after the storage checks (uvicorn exits 1).
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", port))
        blocker.listen()
        r = run_script(
            "-Config", str(cfg), "-KeepRunning", "-RestartDelaySeconds", "1", "-MaxRestarts", "2"
        )
    assert r.returncode == 1, r.stderr
    lines = (logs / "supervisor.log").read_text(encoding="utf-8-sig").splitlines()
    assert len(lines) == 3
    assert "restart 1 in 1 s" in lines[0]
    assert "restart 2 in 1 s" in lines[1]
    assert "restart limit 2 reached" in lines[2]


# ---- host scripts (install / stop / uninstall) ------------------------------------------------

SCRIPTS = sorted((SERVER_DIR / "scripts").glob("*.ps1"))


def test_the_host_scripts_are_plain_ascii() -> None:
    # Windows PowerShell 5.1 reads a script without a BOM in the ANSI code page.
    assert {p.name for p in SCRIPTS} >= {
        "host-common.ps1",
        "install-yournas.ps1",
        "start-yournas.ps1",
        "stop-yournas.ps1",
        "uninstall-yournas.ps1",
    }
    for path in SCRIPTS:
        path.read_bytes().decode("ascii")


def scratch_install(tmp_path: Path, config: dict[str, object]) -> Path:
    """A copy of the scripts in a fake code folder, so a dry run reads no real config."""
    server = tmp_path / "code" / "server"
    shutil.copytree(SERVER_DIR / "scripts", server / "scripts")
    shutil.copy(TEMPLATE, server / "config.example.json")
    (server / "config.local.json").write_text(json.dumps(config), encoding="utf-8")
    return server


def dry_run(server: Path) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(server / "scripts" / "install-yournas.ps1"),
            "-DryRun",
        ],
        env=run_env(),
        capture_output=True,
        text=True,
        timeout=120,
    )


@needs_powershell
def test_the_installer_dry_run_shows_every_step_and_changes_nothing(tmp_path: Path) -> None:
    root = tmp_path / "nas"
    root.mkdir()
    logs = tmp_path / "code" / "logs"
    server = scratch_install(tmp_path, {"storage_root": str(root), "log_dir": str(logs)})
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    r = dry_run(server)
    assert r.returncode == 0, r.stdout + r.stderr
    for step in range(1, 9):
        assert f"== {step}." in r.stdout
    assert r.stdout.count("[dry run] nothing changed") == 8
    assert "storage root" in r.stdout and str(root) in r.stdout
    assert "Create it yourself" not in r.stdout
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*")) == before


@needs_powershell
def test_the_installer_refuses_a_missing_root_and_a_public_bind(tmp_path: Path) -> None:
    server = scratch_install(
        tmp_path, {"storage_root": str(tmp_path / "missing"), "host": "0.0.0.0"}
    )
    r = dry_run(server)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "does not exist. Create it yourself" in r.stdout
    assert "it must be loopback" in r.stdout
    assert not (tmp_path / "missing").exists()


@needs_powershell
def test_the_host_scripts_find_a_running_server(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    port = free_port()
    proc = start_server(root, port, tmp_path / "err")
    try:
        wait_healthy(proc, port, tmp_path / "err")
        assert POWERSHELL is not None
        common = SERVER_DIR / "scripts" / "host-common.ps1"
        r = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f". '{common}'; Get-YourNASProcesses | ForEach-Object {{ $_.ProcessId }}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        found = {int(x) for x in r.stdout.split()}
        assert proc.pid in found, r.stdout + r.stderr
    finally:
        proc.terminate()
        proc.wait(timeout=10)
