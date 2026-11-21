# YourNAS — Architecture (Phase 0)

Status: proposed, awaiting owner approval. No application code exists yet.

## 1. Discovery results (read-only inspection, 2026-10-02)

The machine inspected is the **dev desktop**, not the server laptop described in the PRD. The laptop (owner reports Intel i5-class, SSD) had not been inspected when this was written; ROADMAP Phase 5 requires inspecting it before deployment. See section 2. UPDATE 2026-10-12: the Surface laptop was inventoried read-only (Phase 5.1.0); the results are in `docs/HANDOFF.md`, "Deployment Surface inventory". The table below stays the dev-desktop snapshot of 2026-10-02 and says nothing about the Surface.

| Item | Observed | PRD assumption |
|---|---|---|
| Machine | MSI MS-7D77 desktop | Old laptop |
| OS | Windows 11 Home 10.0.26200, 64-bit | "Windows", version unknown |
| CPU | AMD Ryzen 5 9500F, 6C/12T | Intel i5-7200U |
| RAM | 15.6 GB (8.2 GB free) | 8 GB |
| Disks | C: NTFS 930 GB (175 GB free); H: **FAT32** 930 GB (166 GB free); G: FAT32 15 GB (removable) | ~150 GB free |
| Physical disk | ADATA LEGEND 860 SSD, Healthy | SSD |
| NICs | Ethernet 1 Gbps (192.168.0.160, Public profile); Wi-Fi 6E (disconnected); Cloudflare WARP tunnel (up) | Wi-Fi, Ethernet preferred |
| Firewall | Domain / Private / Public all **enabled**, defaults NotConfigured | must stay enabled |
| SMB | LanmanServer running; port 445 listening on all interfaces; only default shares (ADMIN$, C$, IPC$); **no enabled inbound allow rule for 445** | never public |
| Tailscale | **Not installed** (no service, no binary) | installed |
| Python | 3.14.7 (default) and 3.12; FastAPI/uvicorn/pydantic/argon2-cffi/python-multipart resolve as binary wheels on both | — |
| Other tools | Node, npm, git 2.55, winget present; **no Swift, no Xcode, no Docker** | — |
| Power | High performance plan; S3 sleep available | server must not sleep |
| Repo | none existed; created `C:\Users\acgeddzzz\YourNAS` | — |

Nothing was changed on the system: no firewall, network, service, or share modification.

## 2. Flags that need an owner decision before Phase 1

1. **Which machine is the server?** This is a Ryzen desktop with 16 GB RAM, not the i5-7200U laptop. Phase 1 needs the real target (storage path, disk, NIC). Nothing in this design depends on the CPU, but throughput and idle-power numbers will.
2. **H: is FAT32.** FAT32 has a 4 GB per-file limit and no NTFS ACLs. The storage root must be on NTFS. C: is NTFS. Recommend `C:\YourNAS-Data` or a dedicated NTFS volume. Storage root is configured, never hardcoded.
3. **iOS build is impossible from Windows.** Swift/SwiftUI needs macOS + Xcode. Running on a real iPhone needs an Apple ID; free signing expires every 7 days, and TestFlight/App Store need the USD 99/year developer program. This conflicts with "zero recurring cost" and with Claude Code running on this Windows box. See section 9 for the recommended re-ordering (web client / PWA first).
4. **Cloudflare WARP is running.** WARP and Tailscale can conflict (routing, DNS, overlapping CGNAT-style ranges). Verify in Phase 5 before relying on Tailscale on this host.
5. **Friend access via Tailscale.** Friends are other people, usually with their own Tailscale accounts. This normally means Tailscale device sharing plus ACLs limiting friends to the NAS HTTPS port only. Verify current Personal-plan limits and sharing rules before Phase 5 (the PRD already says to).
6. **Owner access to friends' private files.** PRD section 15 gives the owner "everything authorized"; section 6.2 says friends never see the owner's files but is silent on the reverse. Recommendation: the owner role manages users, shares and quotas but does **not** read friends' private spaces through the API by default. Needs a decision before Phase 4.

## 3. Components

```
 client (browser/PWA, later iOS)
        │ HTTPS (tailnet only)
 Tailscale Serve  :443  ──►  127.0.0.1:8000
                              │
                    FastAPI app (single process)
   ┌────────────┬─────────────┼──────────────┬───────────┐
 auth/sessions  users     permissions     files API    health
        │         │            │              │
        └─────── SQLite ───────┘        storage layer (only code that touches the FS)
                                              │
                                    NTFS storage root
```

- One Python process. No queue, no containers, no extra services.
- The backend listens on **127.0.0.1 only**. Tailscale Serve terminates TLS (a real certificate for the MagicDNS name) and forwards to loopback. Result: nothing listens on LAN or public interfaces, and iOS App Transport Security is satisfied without custom certificate handling. Note: Tailscale-issued certificates appear in public Certificate Transparency logs, which exposes the tailnet hostname (not the data). Document this in DEPLOYMENT.md.
- LAN-only fallback (no Tailscale) for development: bind 127.0.0.1 and use plain HTTP on localhost.

## 4. Technology choices

| Concern | Choice | Reason |
|---|---|---|
| Runtime | Python 3.12 (pinned; 3.14 also resolves wheels but 3.12 has the widest ecosystem support) | stable, already installed |
| Web framework | FastAPI + uvicorn | PRD preference; streaming uploads/downloads |
| DB | SQLite (WAL mode), stdlib `sqlite3` behind a thin repository layer | single host, no server process; users, grants, sessions, audit |
| Password hashing | Argon2id via `argon2-cffi` | current best practice |
| Sessions | Opaque random 256-bit tokens, only SHA-256 hash stored, server-side expiry and revocation, `Authorization: Bearer` | simple, revocable; JWT adds nothing here |
| Tests | pytest + httpx/TestClient, `tmp_path` storage roots | |
| Lint/type | ruff + mypy (strict on `storage/` and `permissions/`) | those modules are the security boundary |

Dependencies are kept to: fastapi, uvicorn, pydantic, argon2-cffi, python-multipart (or streaming body handling), pytest, httpx, ruff, mypy.

## 5. Storage model

```
<STORAGE_ROOT>\            (configured; must exist, be NTFS, be writable)
  users\<user_id>\         private space, one per user
  shared\<share_id>\       shared spaces
  .yournas-tmp\            upload staging, same volume so os.replace is atomic
```

- Directory names use immutable internal IDs (e.g. `u_7f3a…`), not display names, so renames never move data and names cannot be used for traversal.
- The database holds users, shares, grants, sessions and an audit log. **The filesystem is the source of truth for files.** There is no file-ID index to drift out of sync when something is edited directly on disk.

### Deviation from the PRD example API

The PRD sketches `GET /api/files/{id}`. A DB-backed file ID requires a scanner/index and breaks when files change outside the app. Instead, clients address an item as **(space, relative path)**:

- `space` is an opaque identifier: `home` (the caller's private space) or `share:<share_id>`.
- `path` is a relative POSIX-style path inside that space, validated server-side.

Clients never send an absolute or server-side path. This still satisfies the PRD requirement ("logical storage identifiers or safely normalized paths").

## 6. Authorization model

- Roles: `owner`, `user`.
- Every file operation goes through `permissions.authorize(user, space, action)` and then `storage.resolve(space, path)`. Handlers never call `open`/`os` directly.
- Private space: only its owner user has access (see decision 6 for the admin question).
- Shared space: explicit grant per user, level `read` or `write`. `write` includes create-folder, upload, delete.
- Default deny. Unknown space, missing grant, disabled user, expired session, or any internal error → 403/404 (fail closed). Return 404 for spaces the caller cannot see, so existence is not leaked.
- Enforced server-side only; clients are untrusted.

## 7. Path safety (the core security module)

`storage.resolve(space_root, rel_path)` must:

1. Reject empty-component tricks, absolute paths, drive letters (`C:`), UNC (`\\`, `//`), leading `/` or `\`, `..` components, NUL bytes, control characters, backslashes (normalize only `/` from clients), alternate data streams (`:`), trailing dots/spaces, and Windows reserved device names (`CON`, `NUL`, `COM1`, …) in any component.
2. Join onto the space root and verify containment using resolved paths (`os.path.realpath` + `commonpath`), case-insensitively on NTFS.
3. Reject any component that is a reparse point (symlink or junction) using `lstat` file attributes, so a junction inside a space cannot escape it.
4. Limit path length and component length.
5. Be the only function that turns client input into a filesystem path. Property/fuzz tests target it directly.

Known residual risk: time-of-check/time-of-use races if something with local access swaps a directory for a junction between check and use. Mitigation: the service account is the only writer to the storage root (NTFS ACLs), documented in SECURITY.md.

## 8. File operations

- **Upload:** streamed to `.yournas-tmp`, running byte counter enforces the max size (also checked against `Content-Length`), `fsync`, then atomic `os.replace` into place. A dropped connection leaves only a temp file, which a startup sweep removes. No overwrite unless explicitly requested.
- **Download:** streamed, `Content-Disposition` with a sanitized name, `X-Content-Type-Options: nosniff`, HTTP Range supported later.
- **Delete:** requires `write` level and writes an audit log entry. MVP deletes permanently; a per-space trash is deferred.
- Never exposes server-side absolute paths in responses or errors.

## 9. Clients (recommended re-ordering)

PRD order is Phase 6 iOS native, Phase 7 web. Given decision 3, recommend:

1. **Phase 6 → web client served by the backend** (static SPA, installable as a PWA on iPhone through Safari "Add to Home Screen"). Zero recurring cost, works on Windows, iPhone, Android, Mac. Node is already installed for building it.
2. Native SwiftUI iOS app becomes a later phase, gated on access to a Mac and the owner accepting the developer-program fee.

The API is platform-neutral either way. If the owner does have a Mac, the PRD order can stand.

## 10. Process and deployment (summary; detail in Phase 8)

- Run as a dedicated low-privilege local account (`yournas-svc`) with NTFS write access only to the storage root and the app data directory.
- Start at boot via Task Scheduler (no extra dependencies) or NSSM; choose in Phase 8 after testing restart behavior.
- Configuration through environment variables or `config.local.json`, both git-ignored; `.env.example` committed.
- The server must not sleep: set the power plan to never sleep on AC; on a laptop also set lid-close action to "Do nothing".
- No firewall rule is needed for the backend because it listens on loopback only. Tailscale handles the inbound path.

## 11. Network reality

Upload bandwidth is about 43.9 Mbps ≈ 5.5 MB/s theoretical, so remote downloads from the NAS are capped near that. LAN and remote throughput are measured separately (Phase 3/8). No gigabit claims.

## 12. Backup

YourNAS is not a backup. One disk failing means permanent data loss. Documented prominently in README and DEPLOYMENT.md; backup is a post-MVP phase.

## 13. Testing strategy

- Unit: path validation (table-driven plus fuzz), permission matrix, password hashing, session lifecycle.
- Integration: full API against a temp storage root, including the Friend A / Friend B / Owner boundary matrix from Phase 4.
- Security tests: traversal, absolute/UNC paths, junction escape (created in the test temp dir), oversized uploads, malformed multipart, token reuse after logout, log redaction check (no passwords/tokens in captured logs).
- Manual: restart recovery, interrupted upload, remote access over Tailscale, SMB not reachable from the tailnet or LAN-public side.
- Every phase runs the existing suite first (no regressions) and ends with a commit.

## 14. Deployment target and NAS Manager (recorded 2026-10-07, not built)

- **Target host:** Microsoft Surface Laptop 1 (Windows; Intel i5-7200U class, 8 GB RAM, small internal SSD; user data on an external drive). The development desktop is not the server. Consequences: one process, bounded thread pool, no periodic scans, Argon2 concurrency already capped at 2; the storage root on the external NTFS drive must be handled when the drive is missing or slow (fail closed at startup with a clear error, never create the root on the internal disk by accident). [HISTORICAL as recorded 2026-10-07; the external-drive parts are SUPERSEDED by the next bullet.]
- **Current deployment decision (owner, 2026-10-12):** the server is the Surface Laptop 1 and the intended storage root is `C:\NAS` on its internal NTFS drive (its only drive; about 169 GB free at the inventory). No external drive is planned; the system is meant to run 24/7. The code must live outside `C:\NAS`. The external-drive handling of the previous bullet is not needed now. Its invariant is kept and applies to `C:\NAS`: the server never creates the storage root and fails closed at startup when it is missing; it also refuses a root that is not a local fixed NTFS disk, is a drive root, or is inside a system folder (read from `storage/root.py`; the validation was NOT run on the Surface). Consequences of sharing the system drive with Windows: the free-space floor (`free_space_floor_bytes`, default 5 GiB) is measured on `C:`, and the Phase 5 NTFS ACLs must cover `C:\NAS`, `.yournas-tmp` and `.yournas-data`; their current state is UNVERIFIED. Adding an external drive later is a storage-root change and needs the owner's confirmation first (`CLAUDE.md`). Facts about the Surface: INVENTORY, OWNER-REPORTED and UNVERIFIED items are listed in `docs/HANDOFF.md`.
- **NAS Manager (after Phase 5):** a Windows tray application on the Surface. One ON/OFF switch controls, as one unit, the hyNAS service, `tailscale serve` (HTTPS, tailnet only, never Funnel) and any firewall rules; OFF means no network entry point at all. It persists the desired state and restores it after reboot. It shows: connected devices, active uploads, disk space and SMART status of the data drive, service logs, backup status, audit log (read through the owner-only admin API). It must not weaken any server control and must use the same admin API (no direct database access except read-only health checks).
- **Phase 5 scope:** Tailscale Serve to 127.0.0.1 only, never Funnel; NTFS ACLs (the service account is the only writer to the storage root, `.yournas-tmp`, `.yournas-data`) to close the junction race; always-on host setup (power plan, lid, restart recovery, service/Task Scheduler); friend access plan (Tailscale node sharing, ACLs restricting friends to the NAS HTTPS port).
