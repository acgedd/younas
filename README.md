# YourNAS

A small, self-hosted private file server for a few trusted users, running on an existing Windows machine and reached remotely over Tailscale.

Status: Phases 1 and 2 implemented (server foundation, authentication). The server starts, validates its storage root, logs with redaction, and has login, sessions and an owner-only status endpoint. There is no file API yet, so do not expose it to anything but localhost. See `docs/ROADMAP.md` for the plan, `docs/ARCHITECTURE.md` and `docs/SECURITY.md` for the design.

**Backup warning:** YourNAS is not a backup system. If a file exists only on the server's disk, a disk failure can permanently destroy it.

## Run the server (development)

Requires Windows and Python 3.12.

```powershell
cd server
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"

# The storage root must be an existing folder on a local NTFS drive (not a system folder).
$env:YOURNAS_STORAGE_ROOT = "C:\YourNAS-Data"
# Create the one owner account (password typed at a hidden prompt; there is no HTTP signup):
.\.venv\Scripts\python -m yournas create-owner --username alice

.\.venv\Scripts\python -m yournas        # listens on 127.0.0.1:8000
```

The database (users, sessions, login throttling) is created in `<storage root>\.yournas-data`; set `YOURNAS_DATA_DIR` to put it elsewhere.

Settings come from `YOURNAS_*` environment variables, optionally a JSON file named by `YOURNAS_CONFIG`. See `server/.env.example`. The server refuses to start (exit code 2) if the configuration or the storage root is unsafe.

## Test

```powershell
cd server
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m mypy
```
