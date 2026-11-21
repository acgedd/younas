# YourNAS — Roadmap (revision 2, decisions recorded)

Based on the PRD, the findings in ARCHITECTURE.md, and the owner's answers on 2026-10-03. Changes from the PRD are marked **changed**. Each phase ends with passing tests, updated docs, and a git commit. One phase at a time; each needs owner go-ahead.

## Decisions

| # | Decision | Status |
|---|---|---|
| 1 | Server = the owner's old laptop. Owner's Settings > About screenshot (2026-10-03): Surface Laptop, Intel Core i5-7200U 2.50 GHz, 8 GB RAM, 238 GB Toshiba THNSN0256GTYA SSD (61 GB used), Intel HD 620, 64-bit; the Settings layout looks like Windows 10 (edition and build not shown). Still **to be inspected in full** (OS build, NTFS free space, NICs, firewall, ports) before Phase 5/8 [inspected read-only 2026-10-12: Windows 10 Pro 22H2, `C:` NTFS; see `docs/HANDOFF.md`]. Phase 1-4 are developed and tested on the dev desktop with temp storage; code must be machine-independent. | decided |
| 2 | Client = Web/PWA first, optimized for speed on iPhone. Native iOS deferred until a Mac and the USD 99/year developer program exist. | decided |
| 3 | Python 3.12 pinned. | default, assumed accepted |
| 4 | Owner cannot read friends' private spaces through the API by default. | default, assumed accepted |
| 5 | Friends join through Tailscale device sharing (each installs the Tailscale app). Plan limits to be verified in Phase 5. Alternatives considered and rejected for MVP: Cloudflare Tunnel (public exposure, domain cost, ~100 MB upload cap), router port forwarding (public, CGNAT). | decided, verify in Phase 5 |
| 6 | Windows Defender stays on. If it measurably slows uploads, add exclusions for the staging directory and the server process only; never disable it. | decided |

## Known bottlenecks to design and measure for

1. Home upload bandwidth (~43.9 Mbps, ~5.5 MB/s) caps remote downloads. Not fixable in software.
2. Tailscale relay (DERP) instead of a direct connection can cut speed to 1-2 MB/s. Verify direct connection in Phase 5; use Ethernet on the server.
3. iOS suspends a PWA seconds after the screen locks or the app is backgrounded, killing in-flight uploads. Mitigation: chunked resumable uploads (Phase 3), Wake Lock and clear "keep screen on" UI (Phase 6). Downloads are unaffected (Safari download manager). Only a native app fixes background upload fully.
4. Defender real-time scanning on every upload (decision 6).
5. Wi-Fi latency on the server; use Ethernet, disable adapter power saving, no sleep.

## Phase 0 — Discovery and architecture (done)

ARCHITECTURE, SECURITY, API, ROADMAP drafted; repo and 10 subagents configured. Environment table in ARCHITECTURE §1 describes the **dev desktop**; the laptop is inspected later (before Phase 5; storage root chosen at deployment). [2026-10-12: the laptop was inspected read-only as Phase 5.1.0, see the Phase 5 section and `docs/HANDOFF.md`; the storage root chosen is `C:\NAS`.]

## Phase 1 — Server foundation (done 2026-10-03)

Implemented under `server/yournas/` (the package is `yournas`, not `app`; it matches `python -m yournas` in SECURITY.md). Reviewed by an independent code review and security review; valid findings were fixed, the rest are in the carry-forward list below.

Scope (nothing else):

- `server/pyproject.toml` (Python >=3.12, minimal deps: fastapi, uvicorn, pydantic; dev: pytest, httpx, ruff, mypy).
- `server/yournas/core/config.py`: settings from environment variables and an optional git-ignored JSON file named by `YOURNAS_CONFIG` (no implicit lookup in the working directory); validated at startup; `.env.example` committed.
- `server/yournas/core/logging_setup.py`: structured JSON logging, rotation, central redaction of `password`, `token`, `Authorization`, cookies, URL credentials; applied to the app, uvicorn, and the root logger.
- `server/yournas/storage/root.py`: `validate_storage_root()` checks the root exists, is a directory, is writable, is on NTFS (FAT32 rejected), is local (not UNC/network drive), is not a reparse point, and is not inside the Windows or Program Files directories. Creates `users/`, `shared/`, `.yournas-tmp/` only after validation passes. Startup sweep of `.yournas-tmp/`.
- `server/yournas/main.py`: `create_app()`, lifespan startup/shutdown logging, refuses to bind a non-loopback host without an explicit logged override, docs/OpenAPI disabled by default.
- `GET /health`: liveness only. (Storage free space etc. arrives with the owner-only status endpoint in Phase 2.)
- Request-ID middleware and generic error handler (no stack traces or server paths to clients).
- Tests: config validation, each storage-root rejection case, startup failure messages, health endpoint, log redaction, non-loopback bind refusal.

Acceptance: server starts reliably; `/health` returns ok; a bad or missing storage root, a FAT32 volume, a UNC path, a junction root, and a system directory each fail closed with a clear error and no directories created; redaction test proves secrets do not reach logs; ruff, mypy, pytest all pass.

Agent pipeline: yournas-backend (app, config, logging) and yournas-storage (root validation) with disjoint files -> yournas-qa -> yournas-security -> yournas-reviewer -> yournas-docs -> commit.

Out of scope: authentication, users, database, file operations, Tailscale, any client.

### Carry-forward from the Phase 1 reviews

- **Phase 2 (done):** client addresses for per-IP login throttling are decided (see SECURITY.md §3: TCP peer, loopback treated as unknown, optional trusted last `X-Forwarded-For`). Expected failures use `AppError`; log lines carry the request ID.
- **Phase 3:** the startup sweep currently deletes everything in `.yournas-tmp/` (best effort: locked or busy entries are skipped and counted). Resumable uploads need staged chunks to survive a restart, so change the policy then (for example sweep only entries older than N hours). `validate -> prepare` is not atomic (local-attacker TOCTOU, documented).
- **Phase 5:** add a Host-header allowlist once the tailnet hostname is known (DNS-rebinding defense for the loopback port) [DONE in Phase 5.1.1, 2026-10-13: setting `allowed_hosts`, loopback names always accepted; the MagicDNS name is still to be added once it is known]; slash redirects are already disabled. Decide on CSP/frame headers for the PWA, and re-check client-address headers behind Tailscale Serve.
- **Phase 8:** run the service with `YOURNAS_CONFIG` or environment variables, never relying on the working directory; pin or lock dependency versions (Starlette already warns that `httpx` is deprecated for its TestClient).
- **Known gaps, accepted for now:** natural-language secrets ("the password is X") are not redacted; junction tests skip if `mklink /J` is unavailable.

## Phase 2 — Authentication and users (done 2026-10-03, awaiting independent review and commit)

Implemented: SQLite schema v1 (`users`, `sessions`, `login_throttle`, WAL, versioned with `PRAGMA user_version`) in `core/database.py`; Argon2id and the password policy in `auth/passwords.py`; persistent login throttling in `auth/throttle.py`; users, login, sessions and password change in `auth/service.py`; bearer dependencies `require_user` / `require_owner` and client-address handling in `auth/deps.py`; `/api/v1/auth/{login,logout,me,password}` and owner-only `/api/v1/admin/status`; `python -m yournas create-owner` (console only). New settings: `data_dir`, `session_idle_hours`, `session_lifetime_days`, `trust_forwarded_for` (all with safe defaults).

Decisions taken (flag if you disagree): password policy 12–128 characters; sliding idle timeout 7 days plus absolute lifetime 30 days; 10 live sessions per user; throttle 5 failures per account / 20 per address, 15 s doubling to 15 min; loopback peers get no per-address throttle until Phase 5; the database lives in `<storage_root>/.yournas-data`; no audit table (JSON log events instead); exactly one owner (partial unique index), no HTTP route creates accounts; no owner password-reset command yet.

Verification: 263 tests, ruff and mypy strict clean. A scratch-copy mutation run broke 14 security rules one at a time (owner check, revoked/disabled/idle/absolute expiry, throttle, forwarded-header trust, raw token storage, dummy verify, session revocation on password change, current-password check, unauthenticated route); every one made the suite fail.

Not done in this phase (by design): user creation endpoints, shares, audit endpoint (Phase 4), spaces in `/auth/me` (Phase 3), Tailscale-aware client address (Phase 5).

### Carry-forward from Phase 2

- **Phase 3:** create `users/<id>/` for the private space lazily; add HTTP request-size limits together with uploads; fill `spaces` in `/auth/me`.
- **Phase 4:** admin user endpoints (create, disable, reset password, revoke sessions), audit table and endpoint, device/session list.
- **Phase 5:** confirm what Tailscale Serve sends, then set `trust_forwarded_for=true`; Host-header allowlist [done in Phase 5.1.1]; consider an owner password-reset console command.
- **Phase 8:** back up `.yournas-data`; the Argon2 default (64 MiB per hash) is fine for 8 GB RAM but concurrent logins are bounded only by the thread pool, so re-measure on the laptop.

## Phase 3 — File API (done 2026-10-03; independently security- and code-reviewed, no Critical/High, valid findings fixed)

`storage.resolve`, list (paginated, no file index), mkdir, download (streamed, Range), delete, metadata, size and free-space limits, and **chunked resumable upload** (**changed**: replaces the single-request PUT in API.md so iOS interruptions resume; API.md updated in this phase).
Acceptance: traversal, absolute, UNC, ADS, device-name and junction escapes all fail; interrupted upload resumes; large and malformed requests handled; per-user isolation holds. Measure LAN throughput and listing latency.

Status of the HTTP and database layer (on top of the storage package `storage/{paths,files,errors}.py`): `GET /spaces`, listing with opaque cursors, metadata, mkdir, streamed download with single Range, delete, and the resumable upload protocol (`POST /spaces/{space}/uploads`, `PATCH|GET|HEAD|DELETE /uploads/{id}`) are in place; `/auth/me` returns the same `spaces` list; schema v2 adds the `uploads` table through a forward migration (a new database creates v1, then migrates to v2); request-size rules are per route (16 KiB, the chunk limit for `PATCH`); the startup sweep of `.yournas-tmp` is age based and an upload-maintenance step removes stale uploads and orphaned staging files. New settings: `max_upload_bytes` (20 GiB), `free_space_floor_bytes` (5 GiB), `upload_chunk_max_bytes` (8 MiB), `upload_stale_hours` (72), `max_uploads_per_user` (8). Only the `home` space exists; `share:<id>` is 404 until Phase 4. Not yet done: LAN throughput and listing-latency measurements, independent security and code review.

## Phase 4 — Sharing and permissions

Shares, grants, owner administration endpoints, full boundary matrix as automated tests (decision 4).

## Phase 5 — Tailscale remote access

Inspect the real laptop first (hardware, SSD, NICs, firewall, ports, WARP/other VPN software). Tailscale install (user action), Serve to the loopback backend, ACLs for friends, SMB exposure verification from LAN and tailnet, direct-vs-relay check, restart recovery.

Added 2026-10-07 (the external-drive parts are SUPERSEDED on 2026-10-12, see the status paragraph below): the host is a Surface Laptop 1 with data on an external drive (the dev PC is not the server). Phase 5 must also deliver: `tailscale serve` over HTTPS (tailnet only, never Funnel, backend on 127.0.0.1); NTFS ACLs so only the service account writes the storage root, staging and data dirs (closes the junction race); always-on host setup and restart recovery including an unplugged or slow external drive; the friend access plan (Tailscale node sharing + ACLs). The tray app "NAS Manager" (single on/off switch for service + tailscale serve + firewall rules, state restored after reboot, devices/uploads/disk+SMART/logs/backup/audit views) is built AFTER Phase 5; see ARCHITECTURE section 14.

Phase 5.1.0 status (2026-10-12): the read-only inventory of the Surface is DONE (owner-run scripts, output read by Claude; details and the INVENTORY / OWNER-REPORTED / UNVERIFIED split are in `docs/HANDOFF.md`, "Deployment Surface inventory"). Baseline: Windows 10 Pro 22H2, one NTFS drive `C:` with about 169 GB free, Tailscale 1.102.4 running with no Serve or Funnel config, firewall on with inbound blocked by default, nothing listening on 8000, SMB 139/445 listening, lid close = sleep. Owner decisions: Python 3.12 via `py -3.12` (3.12.10 reported), storage root `C:\NAS` (created, ACL and startup validation untested), 24/7 operation, no external drive. CURRENT PLAN (owner decision 2026-10-12): the storage root is `C:\NAS` on the Surface's internal NTFS drive and no external drive is planned; this supersedes the external-drive parts of the "Added 2026-10-07" paragraph above (kept as history). So the Phase 5 deliverables read: NTFS ACLs on `C:\NAS`, `.yournas-tmp` and `.yournas-data` (only the service account writes), always-on setup with lid close = do nothing, restart recovery, and no handling of a missing or slow external drive. What stays from that requirement is an invariant, not a preference: the server never creates the storage root and fails closed when it is missing (`storage/root.py`, read from the code, not run on the Surface). If an external drive is ever added, the owner must confirm the storage-root change first (`CLAUDE.md`). Still UNVERIFIED on the Surface: lid setting applied, WARP off, interface scope of the "Tailscale-In" rules, SMB reachability from the tailnet, ACLs on `C:\NAS`, running the app under Python 3.12.10, remote access, reboot recovery. Phase 5.1.1 (Host header allowlist) is IMPLEMENTED on the dev desktop on 2026-10-13, uncommitted: `HostValidationMiddleware` + the `allowed_hosts` setting, 185 new tests, 1807 passed / 4 skipped in the full suite there; see `docs/SECURITY.md` §11 and `docs/HANDOFF.md`. It has not been run on the Surface (no code is there), and what `Host` Tailscale Serve sends to the backend is UNVERIFIED. Phase 5.1.2 and later have not started.

## Phase 6 — Web client / PWA **changed**

Static SPA served by the backend: login, browse, upload (resumable, Wake Lock), download, delete, mkdir, usage. Installable on iPhone via Add to Home Screen.

Started early (2026-10-10, owner request): the four-screen UI (Status, Files, Transfer, System) from the Claude Desktop design is in `server/yournas/web/`, served at `/app` (plain HTML/CSS/ES modules, no build step; design tokens in `static/css/tokens.css`). Real: login, forced password change, session end, browse/mkdir/delete/download, resumable chunked upload, browser-measured speeds, owner disk status. Mock and tagged `MOCK`: tunnel/DNS/TLS, CPU/memory/temperature, drive health, device list, share links. Still open for Phase 6: PWA manifest and service worker, Wake Lock. Known limitations: downloads are buffered in browser memory and refused above 512 MiB (a bearer token rules out a plain link; real streaming needs a one-time download ticket from the server, a backend decision for later). Known limitation, deliberately deferred: the Transfer list and upload queue live in the page only, so a reload or closed tab drops them and an unfinished upload is not resumed (the server keeps its partial data until the stale-upload window expires; the upload API itself is unchanged and already supports resume by `upload_id` and offset).

## Phase 7 — Native iOS client (deferred, conditional)

Only with a Mac and the developer-program decision. Same API.

## Phase 8 — Reliability and operations

Run under `yournas-svc` at boot, sleep/lid/power settings, monitoring, config validation, backup and recovery docs, restart/crash/interrupted-upload tests, Defender exclusion measurement.

## Phase 9 — Security audit

Per SECURITY.md §12; dependency audit; port scans; documented residual risk.
