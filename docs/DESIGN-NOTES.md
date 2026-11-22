# YourNAS — Design notes

How the photo features and the web client work, and why. The HTTP contract is in [API.md](API.md) and the threat model in [SECURITY.md](SECURITY.md). This file explains the decisions behind them. Where the two disagree, the code is the reference.

- [Thumbnails](#thumbnails)
- [Photos by month](#photos-by-month)
- [Month covers](#month-covers)
- [iOS Safari notes](#ios-safari-notes)

## Thumbnails

Code: `yournas/thumbnails.py`, `yournas/api/thumbnails.py`, `yournas/jpeg_markers.py`, `web/static/js/thumbs.js`.

**Made on the phone, checked on the server.** The browser decodes a photo, draws it at 320 px on a canvas and uploads a JPEG of at most 128 KiB. The server never decodes pixels. This keeps image libraries, a large attack surface, out of the server, and costs the old laptop no CPU.

```
PUT /api/v1/spaces/{space}/thumbnail?path=&size=&modified=   raw JPEG body -> 204
GET /api/v1/spaces/{space}/thumbnail?path=                   the bytes
```

- **Access:** writing needs `write` access to the space, reading needs `read`. Access is checked first, before the path is parsed, the body is read or the disk is touched.
- **Versioned:** `size` and `modified` must match the file on disk, otherwise `409 item_changed`. A thumbnail belongs to one version of a file. A thumbnail for an old version is never shown for a newer file at the same path.
- **Strict JPEG check:** a thumbnail is shown on other people's phones without a tap, so a crafted image must not reach them. `jpeg_markers.py` walks the marker structure only. It accepts exactly one 8-bit baseline frame (SOF0) with both sides from 1 to 512 px, and nothing after EOI. Progressive, arithmetic, 12-bit and lossless files, a second image and unknown markers are all refused.
- **Metadata stripped:** every APPn segment (EXIF, location, JFIF) and every comment is removed before storing. The server does not rely on the client to strip location data.
- **Limits:** 128 KiB per thumbnail (enforced before authentication, see [SECURITY.md](SECURITY.md)), 2 GiB for all thumbnails, and at most 2 uploads in flight per user (then `429` with `Retry-After: 1`). The server's free-space floor also applies (`507 insufficient_storage`).
- **Safe consistency:** bytes are moved into place before their database row is committed, and removed only when no row refers to them. A crash can leave a row without bytes (one 404, then it is cleaned up), never a row showing another version's bytes.
- **Never rendered by the server origin:** the GET answers `application/octet-stream` with `nosniff`, `no-store` and `Content-Disposition: attachment`. The client reads the bytes and paints them on a canvas.
- **Client safety:** before decoding a thumbnail from the server, the client reads its size from the JPEG header and refuses anything larger than 512 px. Originals are decoded only after their header says how many pixels they hold. On a phone, photos are decoded one at a time, only while no upload is active and the page is visible, because running out of memory would kill an upload in progress.
- **Logs and audit:** log lines carry a user id, a size and fixed reason codes, never a name, path or key. Thumbnails write no audit rows, because a backfill would push real events out of the audit trail. The database records who wrote each thumbnail (`set_by`).

## Photos by month

Code: `yournas/photo_index.py`, `yournas/photo_dates.py`, `yournas/storage/photo_scan.py`, `yournas/api/photos.py`, `web/static/js/views/photos.js`.

```
GET /api/v1/spaces/{space}/photos/months?year=YYYY
GET /api/v1/spaces/{space}/photos/months/{YYYY-MM}?limit=&cursor=
```

Photos are grouped by the month they were taken, otherwise by the file's modified time. Photo files are `jpg jpeg png gif webp heic heif`.

**Reading the date (owner decision: read the date, nothing else).** This is the second narrow exception to "the server never interprets file contents". Only the EXIF date taken (`DateTimeOriginal`) is read, from JPEG, HEIC/HEIF, PNG (`eXIf`) and WebP. Place, camera, names and XMP are never looked at or kept. The parser does no I/O of its own. It reads through a reader capped at 256 KiB and 32 reads per file, checks every declared size against fixed limits, and caps every loop. Anything malformed simply means "no date".

**The index job (owner decision: once started, it finishes in the background).**

- **When it runs:** only `GET .../photos/months` starts it, and only when the space has no index yet, changed (an upload finished or an item was deleted), or was last walked more than 10 minutes ago. It never runs at startup or on a timer.
- **One job for the whole server:** a request for another space while it runs gets `state: "waiting"` from the database, and that space is queued, oldest first. A space indexed less than 60 s ago is not walked again, so one user cannot hold the slot by uploading in a loop.
- **Gentle on the laptop:** it works in slices of at most 200 files with short sleeps, pauses every 2,000 entries, and stops on shutdown, when its share is deleted, or when the user loses access.
- **Safe walk:** it uses an explicit stack, skips junctions, symlinks and special files, and runs the same name checks as the file listing. Depth (32), entries (200,000) and unlisted folders (1,000) are capped.
- **Not seen is not deleted:** rows are removed only for files the walk could see were gone. A folder that could not be listed keeps its rows.
- **Index caps:** 100,000 photos per space and 1,000,000 in total. Past either cap the index is marked `truncated`.

**Responses.** The months list returns `years`, `total`, `months` (each with `count`, `bytes` and a `cover`) and `index: {state: "ready"|"updating"|"waiting", pending, complete, truncated}`. A month page returns `items` (`path`, `name`, `size`, `modified`, `taken`, `thumb`) with a cursor. There is no server path, inode or `set_by` in any response. Each `path` is relative to the space and goes back through the normal file routes, which check access again.

**Checks and limits.**
- A malformed year, month or cursor gets the same `400 invalid_request` in every space, so a bad request reveals nothing about a space.
- Then access is checked: `read` is enough, and no access gets the generic 404.
- A user may have at most 2 photo requests in flight, otherwise `429`.
- Logs carry counts and durations only, never a name, path, month or date.

## Month covers

Code: `yournas/photo_index.py` (`set_cover`, `clear_cover`), `yournas/api/photos.py`, `web/static/js/views/photos.js`.

```
PUT    /api/v1/spaces/{space}/photos/months/{YYYY-MM}/cover   {"path": "..."} -> 204
DELETE /api/v1/spaces/{space}/photos/months/{YYYY-MM}/cover                   -> 204
```

By default a month shows its newest photo. A user with `write` access to the space can choose another photo from that month as the cover (`cover_write` needs `write`: `403` for read-only members, the generic 404 for no access).

- **Order of checks:** request shape (400), access (404/403), request slot (429), then the path (`400 invalid_path`). The path must equal a key already in the photo index exactly: no case folding and no disk access.
- **One row per space and month:** the choice is stored in `month_covers`. It is used only while that photo is still indexed for that month and has a thumbnail of its current version. Otherwise the month falls back to its newest photo, and the response says `custom: false`.
- **No stale covers:** every cleanup of photo index rows (a delete, a share delete, the walk) removes the matching cover rows in the same transaction. An old choice can never attach to a new file that later appears at the same path.
- **Logs:** one line per cover set or cleared, with the user id and the space type. No audit rows.

## iOS Safari notes

The web client is designed mobile-first for iPhone Safari and the home-screen PWA. The rules below were learned the hard way on iPhone Safari. Keep them when changing the UI (`web/static/js/shell.js`, `web/static/css/app.css`, `additions.css`).

**Backgrounding and uploads**
- iOS suspends the page as soon as it is hidden or the screen locks, and a web page cannot upload in the background. A lost connection is therefore not an error: the upload pauses, and when the page is visible and online again it asks the server for its offset and continues (`transfers.js`).
- iOS may kill the page entirely. Each unfinished upload id is kept in IndexedDB on the device (`store.js`), so the queue comes back with those rows as "unfinished". The file handle is lost, so the user picks the file again and the upload resumes from the server's offset.
- "Keep screen on" uses the Wake Lock API while something uploads, and takes the lock again whenever the page comes back, because the browser drops it when the page is hidden (`wakelock.js`).
- A file picker opens only from inside a user gesture, so it is triggered directly in the tap handler.

**Rendering**
- Transformed or animated layers escape `overflow: hidden` + `border-radius` on iOS. Clip with `clip-path: inset(0 round …)` on the element itself instead.
- The glowing buttons get a painted ripple (a radial gradient) on press, not a transform.
- The wheel menu has an opaque backdrop, and the page track is hidden while the wheel is open.
- Animation loops run only on the visible page.
- Press feedback starts only after a 90 ms hold.
- iOS paints a cover `<canvas>` in its own GPU layer, above siblings that are not layers. Text drawn over a cover gets its own layer, so `z-index` works again.
- iOS limits the total memory of all canvases on a page. At most 300 thumbnail canvases are kept for one open folder.
- Images stored in IndexedDB are kept as `ArrayBuffer`, which is more reliable on iOS than a stored `Blob`.

**Forms and the Content-Security-Policy**
- No `<select>`: WebKit styles its own `<select>` with an inline style, which the Content-Security-Policy refuses. The app uses a button that opens a short list instead.
- Do not close that list on `focusout`: Safari fires it on a tap inside the list.

**Known limits**
- In-app downloads are buffered in memory and limited to 512 MiB.
- Only a native app could upload in the background.
