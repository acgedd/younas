// Client-side transfer queue. Uploads use the resumable chunk API; downloads stream into a Blob.
//
// iOS can suspend the page at any moment and cannot upload in the background, so a lost link is not a
// failure: the upload waits (state "paused") until the page is visible and the network is back, then
// asks the server for its offset and continues. Each upload id is also kept on this device, because
// the server has no list of a user's uploads: after iOS kills the page the queue comes back with
// those rows as "unfinished". The file handle is gone by then, so the user picks the file again.
//
// States: queued | active | paused | unfinished | done | error | cancelled.

import { ApiError, api, errorTag } from "./api.js";
import { forgetUpload, rememberUpload, uploadsOf } from "./store.js";

const listeners = new Set();
const doneListeners = new Set();
const SAMPLE_WINDOW_MS = 4000;
const KEEP_FINISHED = 30;
const MAX_RETRIES = 5;
const LINK_RETRY_MS = 15000;
const CHUNK_TIMEOUT_MS = 180000; // a black-holed request must not hold the queue for ever
const FINGERPRINT_BYTES = 1024 * 1024;

export const transfers = { items: [] };

let currentUser = null;
let generation = 0; // bumped whenever the queue is detached, so older async work can tell

export function setTransferUser(id) {
  if (id !== currentUser) detachAll(); // the next account must not see the previous one's file names
  currentUser = id;
}

// Stop everything without telling the server, and keep the ids on this device: for when the session
// ended or another tab changed account, so the uploads can be found again after signing in.
export function detachAll() {
  generation += 1;
  for (const ctrl of controllers.values()) ctrl.abort();
  transfers.items = [];
  emit();
}

// Changes whenever the account may have: work that outlives a request checks it before sending.
export const generationNow = () => generation;

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Called with each upload that reached the server, whichever screen started it.
export function subscribeDone(fn) {
  doneListeners.add(fn);
  return () => doneListeners.delete(fn);
}

function emit() {
  for (const fn of listeners) fn();
}

let counter = 0;
let running = false;
const controllers = new Map();

function create(kind, name, size, extra) {
  const t = {
    id: ++counter,
    kind, // "up" | "down"
    name,
    size,
    loaded: 0,
    state: "queued",
    tag: "",
    samples: [],
    startedAt: 0,
    ...extra,
  };
  transfers.items.unshift(t);
  trimFinished();
  emit();
  return t;
}

const isFinished = (t) => ["done", "error", "cancelled"].includes(t.state);

function trimFinished() {
  const finished = transfers.items.filter(isFinished);
  for (const t of finished.slice(KEEP_FINISHED)) {
    transfers.items.splice(transfers.items.indexOf(t), 1);
  }
}

function progress(t, loaded) {
  t.loaded = loaded;
  const now = performance.now();
  t.samples.push({ at: now, loaded });
  while (t.samples.length > 2 && now - t.samples[0].at > SAMPLE_WINDOW_MS) t.samples.shift();
  emit();
}

export function speedOf(t) {
  if (t.state !== "active" || t.samples.length < 2) return 0;
  const a = t.samples[0];
  const b = t.samples[t.samples.length - 1];
  const dt = (b.at - a.at) / 1000;
  return dt > 0 ? (b.loaded - a.loaded) / dt : 0;
}

export function speeds() {
  let up = 0;
  let down = 0;
  for (const t of transfers.items) {
    if (t.state !== "active") continue;
    if (t.kind === "up") up += speedOf(t);
    else down += speedOf(t);
  }
  return { up, down };
}

export function activeCount(kind) {
  return transfers.items.filter((t) => ["queued", "active", "paused"].includes(t.state) && (!kind || t.kind === kind))
    .length;
}

// Bytes are moving right now (not waiting for a link): what the screen stays on for.
export function uploadingNow() {
  return transfers.items.some((t) => t.kind === "up" && t.state === "active");
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ---- waiting out a lost link --------------------------------------------------------------------

const pageHidden = () => typeof document !== "undefined" && document.visibilityState === "hidden";
const linkLooksUp = () => !pageHidden() && !(typeof navigator !== "undefined" && navigator.onLine === false);
const isNetwork = (err) => err instanceof ApiError && err.code === "network";

// Resolves after `ms`, or as soon as the page comes back or the network returns. Rejects on cancel.
function wake(signal, ms) {
  return new Promise((resolve, reject) => {
    const finish = (fn, arg) => {
      clearTimeout(timer);
      if (typeof window !== "undefined") window.removeEventListener("online", onEvent);
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onEvent);
      signal.removeEventListener("abort", onAbort);
      fn(arg);
    };
    const onEvent = () => {
      if (!pageHidden()) finish(resolve);
    };
    const onAbort = () => finish(reject, new DOMException("cancelled", "AbortError"));
    const timer = setTimeout(() => finish(resolve), ms);
    if (typeof window !== "undefined") window.addEventListener("online", onEvent);
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", onEvent);
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort);
  });
}

// The first failure with the page in view gets a quick retry; anything longer shows as waiting.
async function waitForLink(t, signal, failures) {
  if (failures > 1 || !linkLooksUp()) {
    t.state = "paused";
    t.tag = "Waiting for connection";
    emit();
  }
  await wake(signal, linkLooksUp() ? Math.min(1000 * failures, LINK_RETRY_MS) : LINK_RETRY_MS);
  while (pageHidden()) await wake(signal, LINK_RETRY_MS); // no point in trying while suspended
  t.state = "active";
  t.tag = "";
  t.samples = [{ at: performance.now(), loaded: t.loaded }];
  emit();
}

// Repeats a request across link losses. Only cancelling, or a real answer, ends it.
async function withLink(t, signal, call) {
  let failures = 0;
  for (;;) {
    try {
      return await call();
    } catch (err) {
      if (!isNetwork(err)) throw err;
      failures += 1;
      await waitForLink(t, signal, failures);
    }
  }
}

// ---- uploads ------------------------------------------------------------------------------------

export function enqueueUploads(files, space, dir, onDone) {
  for (const file of files) {
    create("up", file.name, file.size, { file, space, dir: [...dir], onDone });
  }
  pump();
}

async function pump() {
  if (running) return;
  running = true;
  try {
    for (;;) {
      const next = [...transfers.items].reverse().find((t) => t.kind === "up" && t.state === "queued");
      if (!next) break;
      await runUpload(next);
    }
  } finally {
    running = false;
  }
}

// Worth another try after a pause. `busy` is a locked item (423); `upload_busy` is a second chunk
// of the same upload still being written (409). 507 (disk full) will not fix itself in seconds.
const TRANSIENT_CODES = new Set(["busy", "upload_busy", "too_many_requests"]);

function isTransient(err) {
  return err instanceof ApiError && (TRANSIENT_CODES.has(err.code) || (err.status >= 500 && err.status !== 507));
}

// Is the finished file in place with the size we sent?
async function stored(t, signal) {
  try {
    const item = await api.meta(t.space, [...t.dir, t.name].join("/"), signal);
    return item.kind === "file" && item.size === t.size;
  } catch (err) {
    if (err instanceof ApiError && err.code === "not_found") return false;
    throw err;
  }
}

// SHA-256 of the start of a file, to recognise it when it is picked again. Null where the browser
// has no crypto.subtle (a plain http page): the name and size checks still apply.
async function fingerprintOf(file) {
  if (typeof crypto === "undefined" || !crypto.subtle) return null;
  const head = await file.slice(0, FINGERPRINT_BYTES).arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", head);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readable(file, offset) {
  try {
    await file.slice(offset, offset + 1).arrayBuffer();
    return true;
  } catch {
    return false;
  }
}

// A new upload: create it on the server and note its id on this device.
async function begin(t, signal) {
  const path = [...t.dir, t.name].join("/");
  t.fingerprint = await fingerprintOf(t.file).catch(() => null);
  // Not aborted by a cancel: the reply carries the id that the cancel needs to drop the reservation.
  const created = await withLink(t, signal, () => api.createUpload(t.space, path, t.size));
  t.uploadId = created.upload_id;
  t.chunkMax = created.chunk_max_bytes;
  if (signal.aborted) {
    // Cancelled while the create request was in flight: the server holds a reservation now.
    api.abortUpload(t.uploadId).catch(() => {});
    throw new DOMException("cancelled", "AbortError");
  }
  if (!created.complete) {
    await rememberUpload({
      uploadId: t.uploadId,
      user: currentUser,
      space: t.space,
      dir: t.dir,
      name: t.name,
      size: t.size,
      chunkMax: t.chunkMax,
      fingerprint: t.fingerprint,
      createdAt: Date.now(),
    });
  }
  return { offset: created.offset, complete: created.complete === true };
}

// An upload the server already holds: ask how far it got.
async function resume(t, signal) {
  try {
    const status = await withLink(t, signal, () => api.uploadStatus(t.uploadId, signal));
    let complete = false;
    if (status.offset >= t.size) {
      // Every byte is staged but the file was never moved into place: repeat the final step.
      const last = await withLink(t, signal, () => api.uploadChunk(t.uploadId, t.size, new Blob([]), signal));
      complete = last.complete === true;
    }
    return { offset: status.offset, complete };
  } catch (err) {
    // The record can be gone because the file was already filed; that is a success.
    if (err instanceof ApiError && err.code === "not_found" && (await withLink(t, signal, () => stored(t, signal)))) {
      return { offset: t.size, complete: true };
    }
    throw err;
  }
}

// One chunk, with a limit on how long it may hang. A timeout counts as a lost link.
async function sendChunk(t, offset, end, signal) {
  const watchdog = new AbortController();
  const onCancel = () => watchdog.abort();
  signal.addEventListener("abort", onCancel);
  const timer = setTimeout(() => watchdog.abort(), CHUNK_TIMEOUT_MS);
  try {
    return await api.uploadChunk(t.uploadId, offset, t.file.slice(offset, end), watchdog.signal);
  } catch (err) {
    if (err && err.name === "AbortError" && !signal.aborted) throw new ApiError(0, "network", "The chunk timed out");
    throw err;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onCancel);
  }
}

async function runUpload(t) {
  const ctrl = new AbortController();
  const signal = ctrl.signal;
  controllers.set(t.id, ctrl);
  t.state = "active";
  t.tag = "";
  t.startedAt = performance.now();
  t.samples = [{ at: t.startedAt, loaded: t.loaded }];
  emit();
  try {
    let { offset, complete } = t.uploadId ? await resume(t, signal) : await begin(t, signal);
    progress(t, offset);
    let retries = 0;
    let linkFailures = 0;
    let refused = 0; // the server answers, yet the chunk never gets through
    while (!complete && offset < t.size) {
      const end = Math.min(offset + t.chunkMax, t.size);
      try {
        const result = await sendChunk(t, offset, end, signal);
        offset = result.offset;
        retries = 0;
        linkFailures = 0;
        refused = 0;
        progress(t, offset);
        if (result.complete) complete = true;
      } catch (err) {
        if (err instanceof ApiError && err.code === "offset_mismatch" && err.offset != null && retries < MAX_RETRIES) {
          retries += 1;
          offset = err.offset; // the server knows the truth
          continue;
        }
        // The reply to the LAST chunk was lost and a repeat of it finds the upload gone: the same
        // case as the 404 from the status request below.
        if (err instanceof ApiError && err.code === "not_found" && end >= t.size && (await withLink(t, signal, () => stored(t, signal)))) {
          complete = true;
          continue;
        }
        const lostLink = isNetwork(err);
        if (lostLink) {
          linkFailures += 1;
          // A fetch also rejects when the browser cannot read the file (changed on disk, handle gone
          // after a suspension). No link will fix that, but picking the file again will.
          if (!(await readable(t.file, offset))) throw new ApiError(0, "file_unreadable", "The file cannot be read");
          await waitForLink(t, signal, linkFailures);
        } else if (isTransient(err) && retries < MAX_RETRIES) {
          retries += 1;
          await sleep(Math.min(1000 * retries, 5000));
        } else {
          throw err;
        }
        try {
          const status = await api.uploadStatus(t.uploadId, signal); // resume from the server
          if (lostLink && status.offset === offset) {
            refused += 1;
            if (refused > MAX_RETRIES) throw new ApiError(0, "stalled", "Chunks do not get through");
          }
          offset = status.offset;
        } catch (statusErr) {
          if (isNetwork(statusErr)) continue;
          // The reply to the LAST chunk can be lost after the server filed the file: the upload
          // record is then gone (404). That is a success only if the file really is there.
          if (
            statusErr instanceof ApiError &&
            statusErr.code === "not_found" &&
            end >= t.size &&
            (await withLink(t, signal, () => stored(t, signal)))
          ) {
            complete = true;
          } else {
            throw statusErr;
          }
        }
      }
    }
    // "Every byte sent" is not "done": only the server's complete flag, or the file being in place,
    // is. (A failed final step leaves the bytes staged with the offset at the full size.)
    if (!complete && !(await withLink(t, signal, () => stored(t, signal)))) {
      throw new ApiError(409, "incomplete", "The server did not finish the upload");
    }
    progress(t, t.size);
    t.state = "done";
    t.tag = "";
    if (t.uploadId) await forgetUpload(t.uploadId);
  } catch (err) {
    if (err && err.name === "AbortError") {
      t.state = "cancelled";
      t.tag = "Cancelled";
    } else if (err instanceof ApiError && err.code === "file_unreadable") {
      t.state = "unfinished";
      t.tag = "";
      t.file = null;
    } else {
      t.state = "error";
      t.tag = errorTag(err);
      if (err instanceof ApiError && err.code === "not_found" && t.uploadId) {
        await forgetUpload(t.uploadId); // nothing left on the server to go back to
        t.uploadId = null;
      }
    }
  } finally {
    controllers.delete(t.id);
    emit();
    if (t.state === "done") {
      if (t.onDone) t.onDone(t);
      for (const fn of doneListeners) fn(t);
    }
  }
}

// Bring back the uploads this device remembers for this account. A record the server has dropped
// (finished, stale or refused) is forgotten without a row.
export async function loadUnfinished(user) {
  const started = generation;
  for (const record of await uploadsOf(user)) {
    if (started !== generation) return; // signed out or switched account meanwhile
    if (transfers.items.some((t) => t.uploadId === record.uploadId)) continue;
    let offset = 0;
    try {
      offset = (await api.uploadStatus(record.uploadId)).offset;
      if (started !== generation) return;
    } catch (err) {
      if (started !== generation) return; // that answer was for another account's token
      if (err instanceof ApiError && err.code === "not_found") {
        await forgetUpload(record.uploadId);
        continue;
      }
      if (!isNetwork(err)) continue; // not answerable now; the record stays for the next launch
    }
    const t = create("up", record.name, record.size, {
      uploadId: record.uploadId,
      chunkMax: record.chunkMax,
      fingerprint: record.fingerprint,
      space: record.space,
      dir: record.dir,
      loaded: offset,
    });
    t.state = "unfinished";
    emit();
  }
}

// Continue an unfinished upload with the file picked again. The server cannot compare contents, so a
// file that differs in name, size or first megabyte is refused: appending to the wrong bytes would
// corrupt it. (A file edited later on, keeping its size, is not caught.)
export async function resumeWith(id, file) {
  const t = transfers.items.find((x) => x.id === id);
  if (!t || t.state !== "unfinished") return false;
  if (file.name !== t.name || file.size !== t.size) return false;
  if (t.fingerprint) {
    const same = await fingerprintOf(file).then((f) => f === t.fingerprint, () => false);
    if (!same || t.state !== "unfinished") return false;
  }
  t.file = file;
  t.state = "queued";
  t.tag = "";
  emit();
  pump();
  return true;
}

// Try a failed upload again from where the server stopped.
export function retry(id) {
  const t = transfers.items.find((x) => x.id === id);
  if (!t || t.state !== "error" || t.kind !== "up" || !t.file) return;
  t.state = "queued";
  t.tag = "";
  emit();
  pump();
}

// ---- downloads ---------------------------------------------------------------------------------

// A browser cannot stream a bearer-authenticated download to disk, so the file is held in memory
// (twice, briefly, while the Blob is built). Past this size a phone tab is likely to be killed.
export const MAX_BROWSER_DOWNLOAD_BYTES = 512 * 1024 * 1024;

export async function startDownload(space, parts, name, size) {
  const t = create("down", name, size, {});
  if (size > MAX_BROWSER_DOWNLOAD_BYTES) {
    t.state = "error";
    t.tag = "Too large";
    emit();
    return;
  }
  const ctrl = new AbortController();
  controllers.set(t.id, ctrl);
  t.state = "active";
  t.startedAt = performance.now();
  t.samples = [{ at: t.startedAt, loaded: 0 }];
  emit();
  try {
    const res = await api.download(space, parts.join("/"), ctrl.signal);
    const total = Number.parseInt(res.headers.get("Content-Length") || "", 10);
    if (Number.isFinite(total)) t.size = total;
    const pieces = [];
    if (res.body) {
      const reader = res.body.getReader();
      let loaded = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        pieces.push(value);
        loaded += value.length;
        progress(t, loaded);
      }
    } else {
      pieces.push(await res.blob());
    }
    // Never a type a browser would render: a shared file must not run on this origin.
    const url = URL.createObjectURL(new Blob(pieces, { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    progress(t, t.size);
    t.state = "done";
    t.tag = "";
  } catch (err) {
    if (err && err.name === "AbortError") {
      t.state = "cancelled";
      t.tag = "Cancelled";
    } else {
      t.state = "error";
      t.tag = errorTag(err);
    }
  } finally {
    controllers.delete(t.id);
    emit();
  }
}

// ---- control ------------------------------------------------------------------------------------

function dropOnServer(t) {
  if (t.kind !== "up" || !t.uploadId) return Promise.resolve();
  const id = t.uploadId;
  t.uploadId = null;
  // The id is forgotten only once the server has let go: otherwise a cancel during an outage would
  // leave a slot held with nothing left to free it. The record shows up again on the next launch.
  return api.abortUpload(id).then(
    () => forgetUpload(id),
    (err) => (err instanceof ApiError && err.code === "not_found" ? forgetUpload(id) : undefined),
  );
}

// Returns a promise that settles when the server has been told to drop the staged upload (so a
// caller that is about to sign out can wait for it while the token still works).
export function cancel(id) {
  const t = transfers.items.find((x) => x.id === id);
  if (!t) return Promise.resolve();
  const ctrl = controllers.get(id);
  if (ctrl) {
    ctrl.abort();
  } else if (t.state === "done" || t.state === "cancelled") {
    return Promise.resolve();
  } else {
    t.state = "cancelled";
    t.tag = "Cancelled";
    emit();
  }
  return dropOnServer(t);
}

// Everything that still holds a slot on the server, for sign-out.
export function cancelAll() {
  return transfers.items.filter((t) => t.state !== "done" && t.state !== "cancelled").map((t) => cancel(t.id));
}

export function clearFinished() {
  for (const t of transfers.items) {
    if (t.state === "error") dropOnServer(t);
  }
  transfers.items = transfers.items.filter((t) => !isFinished(t));
  emit();
}
