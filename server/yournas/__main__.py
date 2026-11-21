"""Entry point: python -m yournas [create-owner]"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from collections.abc import Callable, Sequence

import uvicorn
from fastapi import FastAPI

from yournas.auth.passwords import PasswordPolicyError, PasswordService
from yournas.auth.service import AuthService, UsernameError, normalize_username
from yournas.core.config import ConfigError, Settings, is_loopback_host, load_settings
from yournas.core.database import Database, DatabaseError, open_database
from yournas.core.instance_lock import InstanceLock, InstanceLockError, acquire_instance_lock
from yournas.core.logging_setup import configure_logging
from yournas.main import create_app, default_data_dir
from yournas.storage.root import StorageRoot, StorageRootError, open_storage

EXIT_FAILURE = 1
EXIT_CONFIG = 2
EXIT_ALREADY_RUNNING = 3


def _prepare(
    *, hold_lock: bool = False
) -> tuple[Settings, StorageRoot, Database, InstanceLock | None] | int:
    """Settings, validated storage root, database and (for the server) the instance lock, or an
    exit code after printing why. The lock is taken before the database is opened, so a second
    server never touches the database or migrates it under a running one."""
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"yournas: configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # Console-only logging first: a rejected storage root must not leave a log directory behind.
    configure_logging(settings.log_level, None)
    log = logging.getLogger("yournas")

    try:
        storage = open_storage(
            settings.storage_root, tmp_max_age_seconds=settings.upload_stale_hours * 3600
        )
    except StorageRootError as exc:
        log.error("storage_root_invalid", extra={"reason": str(exc)})
        print(f"yournas: storage root rejected: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        configure_logging(settings.log_level, settings.log_dir)
    except OSError as exc:
        print(f"yournas: cannot set up logging: {exc.strerror}", file=sys.stderr)
        return EXIT_CONFIG

    data_dir = default_data_dir(settings, storage)
    lock: InstanceLock | None = None
    if hold_lock:
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            lock = acquire_instance_lock(data_dir)
        except InstanceLockError as exc:
            log.error("already_running")
            print(f"yournas: {exc}", file=sys.stderr)
            return EXIT_ALREADY_RUNNING
        except OSError as exc:
            print(f"yournas: cannot lock the data directory: {exc.strerror}", file=sys.stderr)
            return EXIT_CONFIG

    try:
        database = open_database(data_dir)
    except DatabaseError as exc:
        if lock is not None:
            lock.release()
        log.error("database_unusable", extra={"reason": str(exc)})
        print(f"yournas: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    return settings, storage, database, lock


def main() -> int:
    """Run the server."""
    prepared = _prepare(hold_lock=True)
    if isinstance(prepared, int):
        return prepared
    settings, storage, database, lock = prepared
    log = logging.getLogger("yournas")

    if not is_loopback_host(settings.host):
        log.warning("non_loopback_bind_override", extra={"host": settings.host})

    app = create_app(settings, storage, database=database)
    try:
        _serve(app, settings)
    except SystemExit as exc:
        # uvicorn exits with 3 when it cannot start (port taken). 3 means "already running" here,
        # and the start script does not retry it, so report a plain failure instead.
        if exc.code in (None, 0):
            raise
        log.error("server_start_failed", extra={"uvicorn_exit": exc.code})
        return EXIT_FAILURE
    finally:
        database.close()
        if lock is not None:
            lock.release()
    return 0


def _serve(app: FastAPI, settings: Settings) -> None:
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
        # Never let uvicorn rewrite the peer address from X-Forwarded-*. The app reads the header
        # itself, and only when `trust_forwarded_for` is set and the TCP peer is loopback.
        proxy_headers=False,
    )


def create_owner(
    argv: Sequence[str] = (),
    *,
    prompt_username: Callable[[str], str] = input,
    prompt_password: Callable[[str], str] = getpass.getpass,
) -> int:
    """Create the one owner account from the local console. There is no HTTP equivalent."""
    parser = argparse.ArgumentParser(prog="python -m yournas create-owner")
    parser.add_argument("--username", help="owner username (asked if omitted)")
    args = parser.parse_args(list(argv))

    prepared = _prepare()
    if isinstance(prepared, int):
        return prepared
    settings, _storage, database, _lock = prepared
    service = AuthService(
        database,
        PasswordService(),
        idle_seconds=settings.session_idle_hours * 3600,
        lifetime_seconds=settings.session_lifetime_days * 86400,
    )
    try:
        if service.owner_exists():
            print("yournas: an owner account already exists", file=sys.stderr)
            return EXIT_FAILURE
        username = args.username or prompt_username("Owner username: ")
        try:
            normalize_username(username)
        except UsernameError as exc:
            print(f"yournas: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        # Passwords are only ever read from the console, never from arguments or environment.
        password = prompt_password("Password: ")
        if password != prompt_password("Repeat password: "):
            print("yournas: passwords do not match", file=sys.stderr)
            return EXIT_FAILURE
        try:
            user = service.create_owner(username, password)
        except (UsernameError, PasswordPolicyError) as exc:
            print(f"yournas: {exc}", file=sys.stderr)
            return EXIT_FAILURE
        print(f"Owner '{user.username}' created.")
        return 0
    finally:
        database.close()


def cli(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return main()
    if args[0] == "create-owner":
        return create_owner(args[1:])
    print("usage: python -m yournas [create-owner [--username NAME]]", file=sys.stderr)
    return EXIT_CONFIG


if __name__ == "__main__":
    raise SystemExit(cli())
