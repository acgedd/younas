# YourNAS — API

Status: versioned under `/api/v1`. Auth (Phase 2) and spaces, files and resumable uploads (Phase 3) are implemented. The owner-only admin endpoints (users, shares, grants, audit) are implemented (Phase 4 step 3). JSON everywhere except upload/download bodies.

## Conventions

- Auth: `Authorization: Bearer <token>` on everything except `/health` and `/api/v1/auth/login`.
- A `space` is `home` or `share:<share_id>` (a share is usable once the owner has created it and granted the caller access through the admin routes). A `path` is a relative POSIX path inside the space (`""` is the space root). Clients never send server filesystem paths.
- Errors: `{"error": {"code": "<machine_code>", "message": "<generic text>", "request_id": "<id>"}}`. Spaces the caller cannot see return 404.
- Every response carries `X-Request-ID`.
- Pagination: `limit` (default 200, max 1000) and an opaque `cursor` (see Spaces and files).

## Public

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | liveness only: `{"status":"ok"}` |

## Auth (Phase 2, implemented)

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/v1/auth/login` | `{username, password}` | 200 `{token, expires_at, user:{id, username, role}}` |
| POST | `/api/v1/auth/logout` | — | 204, token revoked |
| GET | `/api/v1/auth/me` | — | `{id, username, role, spaces:[{id, name, access}]}` (the same list as `GET /api/v1/spaces`) |
| POST | `/api/v1/auth/password` | `{current, new}` | 204, all other sessions revoked, the calling session stays valid |

Details:

- Usernames are matched case-insensitively and stored lowercase. Bodies reject unknown fields. Username max 64 characters, password max 128 (login input is bounded so it cannot be used to burn CPU).
- The token is 256 random bits, shown once in the login response. `expires_at` (ISO 8601, UTC) is the absolute end of the session. Independently, a session ends after `session_idle_hours` (default 168) without use; every use slides the idle window, never the absolute one (`session_lifetime_days`, default 30). At most 10 live sessions per user; the oldest are dropped.
- Failure codes: `invalid_credentials` (401, identical for unknown user, wrong password and disabled account), `temporary_password_expired` (401, only after the temporary password was verified: it is older than 7 days; no session is created, see below), `unauthorized` (401, missing/invalid/expired/revoked token, with `WWW-Authenticate: Bearer`), `invalid_current_password` (403), `weak_password` (400, message states the rule), `too_many_attempts` (429 with `Retry-After` seconds), `invalid_request` (400), `payload_too_large` (413, body over 16 KiB on any JSON route), `conflict` (409, password changed concurrently).
- Password policy: 12–128 characters, not only whitespace, not equal to the username.
- Throttling: 5 failed attempts per account (known or unknown username, case-insensitive) lock that account's login and password change for 15 s, doubling per further failure up to 15 min. Per client address: 20 failures, same schedule. A correct login clears the account counter and refunds one address failure. Counters decay after 24 h without failure and survive a restart. Password change shares the account counter, so a stolen token cannot be used to guess the current password.
- The owner is created on the server console with `python -m yournas create-owner`. Every other account is created by the owner through `POST /api/v1/admin/users` (see Admin below); no public endpoint creates users.

Phase 4 (2a): login also returns `must_change_password` and `spaces`. An account created or reset by the owner has a temporary password and `must_change_password=true`; until it is changed, every route except `/auth/me`, `/auth/password` and `/auth/logout` answers 403 `password_change_required`. `/auth/password` rejects a new password equal to the current one (400 `password_unchanged`). A temporary password is valid for 7 days from the moment it was issued (account creation or password reset), measured with the server clock: from the 7 day mark on, login with it answers 401 `temporary_password_expired` (the owner resets the account), a session that was opened with it before then answers 401 on every route including `/auth/password`, and the attempt still counts against the login throttle. Changing it in time makes the new password permanent; permanent passwords never expire.

## Spaces and files (Phase 3, implemented; shares in Phase 4)

All routes need a bearer token (401 otherwise). A space is `home` (the caller's private folder, `users/<user_id>/`, created on first use) or `share:<share_id>` (a shared folder, `shared/<share_id>/`, created when the share is created and never on access). The root of a space is never taken from the request: it comes from the authorization decision (`permissions.py`), which reads the caller's grants from the database on every request (nothing is cached). A client can never name another user's folder, and the owner role gives no access to anyone else's `home` or to a share without a grant.

Authorization (Phase 4 step 2b, implemented): every route below decides FIRST, before the path is looked at, whether the caller may do the action in the space. Levels: `read` allows list, meta and download; `write` also allows folder creation, upload and delete; `home` is always `write` for its owner.

| Caller's access to the space | Answer |
|---|---|
| none: not granted, share unknown or deleted, space id malformed, another user's folder | 404 `not_found`, byte for byte the same body and headers (except `request_id`) as for a space that does not exist, whatever the path (an invalid path in such a space is 404, never 400). A disabled account never gets this far: its token is refused with 401. The request shape (JSON body, query parameters, a path over 1024 characters) is checked before the access decision with 400 `invalid_request`, identically for every space, so it reveals nothing about a space. |
| `read`, but the action needs `write` | 403 `forbidden` |
| enough | the action; only now is the path validated (400 `invalid_path`) |

A denied request creates nothing on disk.

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/spaces` | `[{"id":"home","name":"My files","access":"write"}, {"id":"share:s_<16 hex>","name":"...","access":"read"\|"write"}]`: `home` first, then the granted shares by name (the same list as `/auth/me`; no usage figures) |
| GET | `/api/v1/spaces/{space}/items?path=&limit=&cursor=` | `{items:[{name, kind, size, modified}], next_cursor}` |
| GET | `/api/v1/spaces/{space}/items/meta?path=` | one item; `path=""` is the space root (`kind:"dir"`, `name:""`) |
| POST | `/api/v1/spaces/{space}/folders` | body `{path}` -> 201 item. The parent must exist (no `mkdir -p`) |
| GET | `/api/v1/spaces/{space}/files?path=` | streamed download, single `Range` supported |
| DELETE | `/api/v1/spaces/{space}/items?path=&recursive=false` | 204. The space root cannot be deleted (400) |
| POST | `/api/v1/spaces/{space}/uploads` | start a resumable upload -> 201 |
| PATCH | `/api/v1/uploads/{upload_id}` | append one chunk at `Upload-Offset` |
| GET / HEAD | `/api/v1/uploads/{upload_id}` | progress (HEAD: `Upload-Offset` and `Upload-Length` headers only) |
| DELETE | `/api/v1/uploads/{upload_id}` | abort -> 204 |

Relative paths go in the query string (not the URL path) so slashes and encoded characters are handled by one validator; folder creation and upload start take `path` in the JSON body.

Paths: each one is validated by the storage layer. It is NFC-normalized, and these are refused with 400 `invalid_path`: `..`, `.`, empty components, absolute paths, drive letters, UNC and `\\?\` forms, backslashes, `:` (alternate data streams), trailing dots or spaces, control characters, `<>:"|?*`, Windows device names (`CON`, `NUL`, `COM1`...) and over-long names or paths. A path that is well-formed but fails on the disk (missing, a junction or symlink on the way, anything unsafe) is 404 `not_found` with the same body for every cause, so nothing says which. `item.kind` is `file` or `dir`; `size` is bytes (`null` for a folder); `modified` is ISO 8601 UTC (`+00:00`).

Listing: sorted by name, case-insensitive. `limit` defaults to 200, maximum 1000 (400 outside 1..1000). `next_cursor` is `null` on the last page; otherwise pass it back as `cursor`. A cursor is opaque (base64url of the last name returned); a malformed one is 400 `invalid_request`. It stays valid if that entry is deleted meanwhile. Links (symlinks, junctions) and names that cannot be addressed again are not listed.

Download: `200` or `206` with `Content-Length`, `Accept-Ranges: bytes`, `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="<ASCII fallback>"; filename*=UTF-8''<percent-encoded name>`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and `Last-Modified`. One range (`bytes=a-b`, `a-`, `-n`) gives `206` with `Content-Range`; an unsatisfiable range gives `416` with `Content-Range: bytes */<size>`; several ranges, another unit or a malformed header are ignored and the whole file is sent. `If-Range` is honoured only when it equals the current `Last-Modified`. A folder is 400 `is_a_directory`.

Delete: a non-empty folder needs `recursive=true`, otherwise 409 `not_empty`. A file that is open elsewhere (for example while it is being downloaded) is 423 `busy`; retry later. Names created outside the app that are not in NFC (for example NFD) or are otherwise invalid are invisible in listings, but they still count as content: deleting a folder that holds one without `recursive=true` is 409 `not_empty` although the listing looks empty.

### Resumable upload protocol

Replaces the single-request `PUT` of the first draft, so an interrupted phone upload resumes instead of restarting. Bytes are staged on the same volume and moved into place atomically only when the last byte has arrived; nothing is visible at the destination before that.

1. `POST /api/v1/spaces/{space}/uploads` (`home` or a share where the caller has `write`: 403 with `read`, 404 without access) with `{"path": "photos/a.jpg", "size": 1234567, "overwrite": false}` -> `201 {upload_id, offset: 0, size, chunk_max_bytes, complete: false}`. The path is validated now: the parent folder must exist (404 otherwise), a destination whose resolved path would be too long is 400 `invalid_path`, and an existing file is 409 `already_exists` unless `overwrite` is true; an existing folder is always 409 `is_a_directory`. These checks run again when the upload completes. `size` must be an integer from 0 to `max_upload_bytes` (413 above) and the server must keep `free_space_floor_bytes` free after it and after the unwritten rest of every other unfinished upload (507 otherwise). Each user may have `max_uploads_per_user` (default 8) unfinished uploads: 409 `too_many_uploads`; and at most `max_inflight_upload_bytes_per_user` (default 50 GiB) declared bytes across them (any space): 507 `upload_quota_exceeded`. A `size` of 0 completes immediately: the response has `complete: true` and `item`, and there is no upload to continue.
2. `PATCH /api/v1/uploads/{upload_id}` with header `Upload-Offset: N` and the raw chunk as the body (`Content-Type: application/octet-stream`; at most `chunk_max_bytes`, default 8 MiB). `N` must equal the bytes the server already holds. The answer is `200 {offset, size, complete: false}` with the new offset (also in the `Upload-Offset` response header). The chunk that brings the total to `size` completes the upload: the file is flushed and moved into place, and the answer is `200 {offset, size, complete: true, item}`. A chunk is written only after it has arrived completely, so a broken connection changes nothing.
3. After any doubt (timeout, app suspended, server restarted) ask `GET /api/v1/uploads/{upload_id}` -> `{upload_id, offset, size, path}` and continue from `offset`. The offset is the real size of the staged file. An upload with no chunk for `upload_stale_hours` (default 72) is discarded, and no upload lives longer than 7 days from its creation however often chunks arrive (sending a byte now and then does not renew this limit); asking for a discarded upload gives 404, and a chunk sent after the 7 days is refused with 404 even before the cleanup has run. Discarding frees its quota and staging file; a finished file is never touched.
4. `DELETE /api/v1/uploads/{upload_id}` discards the staged bytes.

Upload errors: wrong offset -> 409 `offset_mismatch`, with the server's offset in the `Upload-Offset` header and as `error.offset`; missing or malformed `Upload-Offset` -> 400; a chunk bigger than `chunk_max_bytes`, or one that would pass the declared size -> 413 `payload_too_large` (nothing is written); less than `free_space_floor_bytes` would stay free after the chunk, or disk full -> 507 `insufficient_storage` (offset unchanged; retry later). Another chunk of the same upload is still being written -> 409 `upload_busy` with the current offset in `Upload-Offset` and `error.offset`: wait a moment, ask `GET` for the offset and continue (a client that sends one chunk at a time never sees it). More than `max_concurrent_chunks_per_user` (default 4) chunk requests of one user at once -> 429 `too_many_requests` with `Retry-After: 1`, answered before the body is read. If the destination changed while the upload ran, the last chunk gets 409 `already_exists` / `is_a_directory` or 404 and the staged bytes are kept: fix the cause and repeat the last request (an empty body at `Upload-Offset: <size>` is enough) to finish. When the last chunk replaces (`overwrite`) a file that is open for download, the answer is 423 `busy`, the staging file is kept, and the same request can be retried. If the answer to the last chunk is lost, the file may already be in place: a 404 on the last chunk or on any later upload request after a possible success means the upload is over, so check `GET /api/v1/spaces/home/items/meta?path=` before sending the file again. An upload belongs to the user who created it and to the space it was started in: for anyone else, and for unknown or malformed ids, every upload route answers the same 404. Every request on an upload except `DELETE` re-checks that its user may still upload into that space (at lookup, before the chunk is written and again before the file is moved into place). If the grant was removed or lowered to `read`, the share deleted or the account disabled meanwhile, the answer is 404 (401 for a disabled account), nothing more is written and the file never appears; the user can still `DELETE` the upload. If access comes back, the upload can continue.

Audit (shares only, never `home`): `folder_created`, `upload_completed` (`size`, `overwrite`) and `item_deleted` (`kind`, `depth`) are written to the audit log with the user id and the share id, never a name or a path. A delete, and an upload that replaces a file (`overwrite: true`), write and commit their row BEFORE the action; if that fails the answer is 500 `internal_error` and nothing is deleted or replaced (for an upload the staged file is kept, so repeating the last request finishes it once the cause is gone). The row records the intent, so a delete that then fails (for example a non-empty folder without `recursive=true`) still leaves its row. Folder creation and a plain upload write their row after the action; if that fails it is logged and the answer stays a success.

Request body limits: every route is capped at 16 KiB (login, password, folders, starting an upload) except `PATCH /api/v1/uploads/{id}`, which accepts `chunk_max_bytes`. Oversized bodies get 413 before authentication or parsing.

## Admin (owner only, implemented: status Phase 2, the rest Phase 4 step 3)

The whole `/api/v1/admin` router is owner-only: no token 401, a friend 403 `forbidden`, a pending temporary password 403 `password_change_required`. The acting user is the one of the session; no header, query parameter or body field can name another actor or role. Request bodies reject unknown fields (400). A user or share id in the URL that is not well formed, or does not exist, is 404 `not_found`. No response carries a password hash, a session token or a server path. There is no user delete, no role change and no second owner over HTTP.

| Method | Path | Result |
|---|---|---|
| GET | `/api/v1/admin/status` | `{version, storage:{total_bytes, free_bytes}, database:{ok, schema_version}}`. No server paths. Tailscale state is added in Phase 5. |
| GET | `/api/v1/admin/users` | `[{id, username, role, disabled, created_at, must_change_password}]` |
| POST | `/api/v1/admin/users` | body `{username}` -> 201 `{id, username, role:"user", temporary_password}` with `Cache-Control: no-store`. The username is lower-cased (3-32 characters of `a-z 0-9 . _ -`): 400 `invalid_username`; a name over 64 characters is refused earlier as 400 `invalid_request`; taken or reserved (`owner`, `admin`, `system`, `root`): 409 `username_taken`. The server generates the password, shows it once and the account must change it at first login. |
| PATCH | `/api/v1/admin/users/{user_id}` | body `{disabled: true\|false}` (strict boolean, the only field) -> 200 `{id, disabled}`. Disabling also ends all its sessions; enabling does not bring them back. The owner: 400 `cannot_modify_owner`. |
| POST | `/api/v1/admin/users/{user_id}/password-reset` | -> 200 `{temporary_password}` (`no-store`), ends all its sessions, forces a change at next login. The owner: 400 `cannot_modify_owner`. |
| DELETE | `/api/v1/admin/users/{user_id}/sessions` | -> 204, ends every live session of the account |
| GET | `/api/v1/admin/shares` | `[{id, name, created_at, grants:[{user_id, level}]}]` ordered by name |
| POST | `/api/v1/admin/shares` | body `{name}` -> 201 share. The server creates the folder `shared/<id>` and gives the creator a revocable `write` grant. The client never sends a path: the name is display text only (NFC, trimmed, 1-64 characters, no control, bidi or zero-width characters: 400 `invalid_share_name`), and unique ignoring case in every script (409 `share_name_taken`). |
| PATCH | `/api/v1/admin/shares/{share_id}` | body `{name}` -> 200 share. Only the name changes; the folder is named by id. |
| DELETE | `/api/v1/admin/shares/{share_id}` | -> 204. See "Deleting a share". |
| PUT | `/api/v1/admin/shares/{share_id}/grants/{user_id}` | body `{level: "read"\|"write"}` -> 200 `{user_id, level}`. An upsert: it replaces an earlier level. A disabled user may be granted; it works once the account is enabled. Unknown share or user: 404. |
| DELETE | `/api/v1/admin/shares/{share_id}/grants/{user_id}` | -> 204, idempotent (no grant is also 204). Unknown share or user: 404. Takes effect on the user's next request; an unfinished upload of theirs stops. |
| GET | `/api/v1/admin/audit?limit=&cursor=&action=&actor_id=&target_id=` | `{events:[{id, at, actor_id, action, target_type, target_id, detail}], next_cursor}`, newest first. `limit` 1-500 (default 100). `cursor` is the opaque `next_cursor` of the previous page. Filters are matched exactly; an unknown `action`, a malformed id or cursor, or a `limit` outside 1..500 is 400. |

### Deleting a share

`DELETE /api/v1/admin/shares/{share_id}` removes only the logical share. It never deletes a file:

- The share folder must be empty. Anything inside, including hidden names, names that no listing shows (not NFC, invalid) and a link or junction in the folder's place, is 409 `not_empty` and NOTHING changes (no row, no grant, no audit row). The owner has to deal with the files first.
- An empty (or already missing) folder: in ONE transaction the share row, its grants (cascade) and the `share_deleted` audit row (`detail.count` = grants removed) go. The emptiness check runs inside that transaction, which holds the database lock, so no request can be authorized between the check and the commit.
- After the commit the unfinished uploads into the share (rows and staging files) are dropped, so their next request is 404, and the empty folder is removed with a plain `rmdir` (never a recursive delete). If it cannot be removed (something was written in the last instant) it stays, nothing refers to it, the id is never reused, and a `share_dir_orphaned` log line names the id only.
- Share ids are random and never reused.

Audit: every admin change writes its row in the same transaction as the change (if the row cannot be written the change is not made and the answer is 500). Events: `user_created`, `user_disabled`, `user_enabled`, `password_reset`, `sessions_revoked`, `share_created` (plus `grant_set` for the creator's grant), `share_renamed`, `share_deleted`, `grant_set` (`detail.level`), `grant_removed`. Rows hold ids and counters only: never a username, a share name, a path, a token or a password.

## Status codes

200/201/204 success; 206 partial download; 400 a Host header the server does not accept (`invalid_host`, on every route, before authentication: missing, repeated, malformed, or not loopback and not in `allowed_hosts`), invalid path (`invalid_path`), cursor, offset header or body (`invalid_request`), or an operation on the wrong kind of item (`not_a_directory`, `is_a_directory`); 401 missing/invalid/expired token, a disabled account, or an expired temporary password (`temporary_password_expired`); 403 authenticated but forbidden (only where existence is already known; also `password_change_required` for an account that still has a temporary password, on every route except `/auth/me`, `/auth/password` and `/auth/logout`); 404 unknown or invisible space, item or upload (`not_found`, one body for every cause); 409 conflicts (`already_exists`, `not_empty`, `is_a_directory`, `offset_mismatch`, `upload_busy`, `too_many_uploads`, `username_taken`, `share_name_taken`); 400 also `cannot_modify_owner` and `invalid_username`; 413 too large (`payload_too_large`); 416 range not satisfiable (with `Content-Range: bytes */size`); 423 item in use (`busy`); 429 login throttled, or too many chunk requests at once (`too_many_requests`, `Retry-After: 1`); 507 not enough free space (`insufficient_storage`) or too many declared bytes in unfinished uploads (`upload_quota_exceeded`).
