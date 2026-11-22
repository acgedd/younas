// Photo thumbnails, made here in the browser: the server stores them and decodes no pixels. See
// docs/DESIGN-NOTES.md#thumbnails.
//
// Decoding a photo takes a lot of memory on a phone, and a memory kill would take an upload in flight
// with it, so a photo is only decoded when no upload is active and the page is in view, and only one
// at a time. Nothing here may ever fail an upload: a photo without a thumbnail just keeps its badge.
//
// A thumbnail from the server was made by whoever could write there, and it is decoded without a tap.
// So its size is read from its header first, and anything larger than a thumbnail is never decoded.
// An original is only decoded after its header said how many pixels it holds (see preview.js).

import { ApiError, api } from "./api.js";
import { coverFit, paint, toBlob } from "./covers.js";
import { MAX_PREVIEW_BYTES, decodable, isPhoto, jpegSize, readCapped, typeOf } from "./preview.js";
import { kvGet, kvSet } from "./store.js";
import { activeCount, generationNow, subscribeDone } from "./transfers.js";

const THUMB_SIDE = 320;
const MAX_THUMB_SIDE = 512; // what the server accepts; anything above it did not come from a real client
const MAX_THUMB_BYTES = 128 * 1024;
const QUALITIES = [0.7, 0.5, 0.35];
const ROW_SIDE = 88; // a row's badge is 44 px, twice that for a sharp screen
const MAX_LOADS = 4;
const MAX_PAINTED = 300; // canvases kept for one open folder; iOS limits the memory of all canvases
const MAX_JOURNAL = 200;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const hidden = () => document.visibilityState === "hidden";

// ---- making one ---------------------------------------------------------------------------------

// The JPEG for a photo. Through the canvas, so it carries none of the photo's metadata.
async function makeThumb(source) {
  const bitmap = await createImageBitmap(source);
  const canvas = document.createElement("canvas");
  try {
    const size = coverFit(bitmap.width, bitmap.height, THUMB_SIDE);
    canvas.width = size.width;
    canvas.height = size.height;
    canvas.getContext("2d").drawImage(bitmap, 0, 0, size.width, size.height);
  } finally {
    bitmap.close();
  }
  try {
    for (const quality of QUALITIES) {
      const blob = await toBlob(canvas, quality);
      if (blob.size <= MAX_THUMB_BYTES) return blob;
    }
    throw new Error("thumbnail too large");
  } finally {
    canvas.width = 0;
    canvas.height = 0;
  }
}

// True once no upload runs and the page is in view; false if the work was called off meanwhile.
async function quiet(signal, generation) {
  const off = () => (signal && signal.aborted) || generation !== generationNow();
  while (!off() && (hidden() || activeCount("up") > 0)) await sleep(1000);
  return !off();
}

// One decode at a time in this whole page: the queue after an upload and the button share it.
let decoding = Promise.resolve();
function oneAtATime(work) {
  const run = decoding.then(work, work);
  decoding = run.catch(() => {});
  return run;
}

// The thumbnail of `source`, or null when it was called off. `mark(true)` runs right before the
// decode and `mark(false)` right after it, so a page killed by the decode is noticed next time.
function decodeQuietly(source, signal, generation, mark) {
  return oneAtATime(async () => {
    if (!(await quiet(signal, generation))) return null;
    if (mark) await mark(true);
    try {
      return await makeThumb(source);
    } finally {
      if (mark) await mark(false);
    }
  });
}

// ---- after an upload ----------------------------------------------------------------------------

const thumbListeners = new Set();

// Called with { space, dir, name } when a photo gained a thumbnail on this device.
export function subscribeThumb(fn) {
  thumbListeners.add(fn);
  return () => thumbListeners.delete(fn);
}

function announce(space, dir, name) {
  for (const fn of thumbListeners) {
    try {
      fn({ space, dir, name });
    } catch {
      /* a screen that went away */
    }
  }
}

let queue = [];
let draining = false;

async function afterUpload(job) {
  const path = [...job.dir, job.name].join("/");
  if ((await decodable(job.file)) !== "ok") return;
  const item = await api.meta(job.space, path);
  // Replaced by someone else since: this thumbnail would show the wrong picture.
  if (job.generation !== generationNow() || item.size !== job.file.size) return;
  const thumb = await decodeQuietly(job.file, null, job.generation);
  if (!thumb || thumb.size > item.size || job.generation !== generationNow()) return;
  await api.putThumbnail(job.space, path, item.size, item.modified, thumb);
  announce(job.space, job.dir, job.name);
}

async function drain() {
  if (draining) return;
  draining = true;
  try {
    for (;;) {
      queue = queue.filter((job) => job.generation === generationNow());
      const job = queue.shift();
      if (!job) return;
      try {
        await afterUpload(job);
      } catch {
        /* no thumbnail for this one: the button can still make it later */
      }
    }
  } finally {
    draining = false;
  }
}

// A throw here would stop the upload queue, so this only takes note.
subscribeDone((t) => {
  try {
    if (!t.file || t.file.size > MAX_PREVIEW_BYTES || !isPhoto({ kind: "file", name: t.name })) return;
    queue.push({ space: t.space, dir: [...t.dir], name: t.name, file: t.file, generation: generationNow() });
    drain().catch(() => {});
  } catch {
    /* no thumbnail, and the upload is not affected */
  }
});

// ---- photos already on the server ---------------------------------------------------------------
//
// One button makes them for a folder and everything below it, at the top of a space for all of it.
// The run belongs to the page, not to the folder on screen: it goes on while the user looks elsewhere,
// and stops on sign-out, on Stop, or when the page closes. Pressing again later skips what is done.

const journalKey = (user) => `thumbjournal:${user}`;
const MAX_DEPTH = 32;

let job = null; // { space, dir, finding, found, done, failed, total, ctrl }
const jobListeners = new Set();
const gaveUp = new Set(); // `${generation}|${space}|${path}`: could not be made, not offered again here

const snapshot = () => job && { space: job.space, dir: job.dir, finding: job.finding, found: job.found, done: job.done, failed: job.failed, total: job.total };

// Called with the run's progress, or null when none runs.
export function subscribeThumbJob(fn) {
  jobListeners.add(fn);
  return () => jobListeners.delete(fn);
}

export const thumbJobNow = snapshot;

function tell() {
  const now = snapshot();
  for (const fn of jobListeners) {
    try {
      fn(now);
    } catch {
      /* a screen that went away */
    }
  }
}

// True when this photo already failed during this sign-in, so the button need not offer it.
export const thumbGaveUp = (space, path) => gaveUp.has(`${generationNow()}|${space}|${path}`);

export function stopThumbJob() {
  if (job) job.ctrl.abort();
}

// Every photo without a thumbnail in `dir` and below: [{ dir, photo }].
async function photosBelow(space, dir, signal, generation) {
  const found = [];
  const folders = [{ dir, depth: 0 }];
  while (folders.length) {
    const { dir: here, depth } = folders.shift();
    let cursor;
    do {
      if (signal.aborted || generation !== generationNow()) return null;
      const page = await api.list(space, here.join("/"), cursor);
      for (const item of page.items) {
        if (item.kind === "dir" && depth < MAX_DEPTH) folders.push({ dir: [...here, item.name], depth: depth + 1 });
        else if (isPhoto(item) && !item.thumb && !thumbGaveUp(space, [...here, item.name].join("/"))) found.push({ dir: here, photo: item });
      }
      cursor = page.next_cursor;
      job.found = found.length;
      tell();
    } while (cursor);
  }
  return found;
}

// Makes what it can, one photo at a time, downloading each original. The journal notes the photo
// being decoded: if it kills the page, it is still noted next time, and that photo is skipped from then on.
async function makeAll({ user, space, photos, signal, generation, onItem }) {
  const current = () => !signal.aborted && generation === generationNow();
  const journal = await kvGet(journalKey(user), { doing: null, skip: [] });
  // Never written back once signed out: sign-out removed it, and it holds file names.
  const save = async () => {
    if (generation === generationNow()) await kvSet(journalKey(user), journal);
  };
  if (journal.doing) journal.skip = [...journal.skip, journal.doing].slice(-MAX_JOURNAL);
  journal.doing = null;
  await save();
  const skip = async (key) => {
    journal.skip = [...journal.skip, key].slice(-MAX_JOURNAL);
    await save();
  };

  for (const { dir, photo } of photos) {
    if (!(await quiet(signal, generation))) return;
    const path = [...dir, photo.name].join("/");
    const key = `${space}|${path}|${photo.size}`;
    let made = false;
    try {
      if (journal.skip.includes(key) || photo.size > MAX_PREVIEW_BYTES) throw new Error("skipped");
      // The version first: if the file changes during the download, the server refuses the thumbnail.
      const item = await api.meta(space, path, signal);
      if (item.size > MAX_PREVIEW_BYTES) throw new Error("too large");
      const res = await api.download(space, path, signal);
      const blob = await readCapped(res, MAX_PREVIEW_BYTES, typeOf(photo.name));
      if ((await decodable(blob)) !== "ok") {
        await skip(key);
        throw new Error("not safe to decode");
      }
      const thumb = await decodeQuietly(blob, signal, generation, async (starting) => {
        journal.doing = starting ? key : null;
        await save();
      });
      if (!thumb || !current()) return;
      if (thumb.size > item.size) {
        await skip(key); // the server keeps no thumbnail larger than its photo
        throw new Error("thumbnail larger than the photo");
      }
      await api.putThumbnail(space, path, item.size, item.modified, thumb, signal);
      made = true;
    } catch (err) {
      if ((err && err.name === "AbortError") || !current()) return;
    }
    if (made) announce(space, dir, photo.name);
    else gaveUp.add(`${generation}|${space}|${path}`);
    onItem(made);
  }
}

// Starts the run for `dir` and below, unless one runs. Resolves with { done, failed, stopped }.
export function startThumbJob({ user, space, dir }) {
  if (job) return null;
  const ctrl = new AbortController();
  const generation = generationNow();
  job = { space, dir: [...dir], finding: true, found: 0, done: 0, failed: 0, total: 0, ctrl };
  const mine = job;
  tell();
  return (async () => {
    try {
      const photos = await photosBelow(space, mine.dir, ctrl.signal, generation);
      if (photos) {
        mine.finding = false;
        mine.total = photos.length;
        tell();
        await makeAll({
          user,
          space,
          photos,
          signal: ctrl.signal,
          generation,
          onItem(made) {
            if (made) mine.done += 1;
            else mine.failed += 1;
            tell();
          },
        });
      }
    } catch {
      mine.failed += 1; // a listing that failed: what was made stays made
    }
    if (job === mine) job = null;
    tell();
    return { done: mine.done, failed: mine.failed, stopped: ctrl.signal.aborted || generation !== generationNow() };
  })();
}

// ---- showing them -------------------------------------------------------------------------------

// A server thumbnail as a bitmap, or null when it is missing or not what a thumbnail can be. Its size is
// read from its header first: anything larger than a thumbnail is never decoded. Throws ApiError and
// AbortError as they come, so a caller can tell a lost link from a missing thumbnail.
export async function fetchThumb(spaceId, path, signal) {
  const res = await api.thumbnail(spaceId, path, signal);
  const blob = await readCapped(res, MAX_THUMB_BYTES, "image/jpeg");
  const size = await jpegSize(new Uint8Array(await blob.arrayBuffer()));
  if (!size || size.width > MAX_THUMB_SIDE || size.height > MAX_THUMB_SIDE) return null;
  return createImageBitmap(blob);
}

// The whole thumbnail on a canvas, for a cover (the page crops it with CSS). Null when there is none.
export async function thumbCanvas(spaceId, path, signal) {
  let bitmap = null;
  try {
    bitmap = await fetchThumb(spaceId, path, signal);
    if (!bitmap || signal.aborted) return null;
    const canvas = document.createElement("canvas");
    paint(canvas, bitmap, THUMB_SIDE);
    return canvas;
  } catch {
    return null;
  } finally {
    if (bitmap) bitmap.close();
  }
}

// The middle square of the picture, for a square badge or tile. The stored thumbnail keeps the whole picture.
function squareOf(bitmap, most) {
  const side = Math.min(bitmap.width, bitmap.height);
  const canvas = document.createElement("canvas");
  canvas.width = Math.min(most, side);
  canvas.height = canvas.width;
  const sx = Math.floor((bitmap.width - side) / 2);
  const sy = Math.floor((bitmap.height - side) / 2);
  canvas.getContext("2d").drawImage(bitmap, sx, sy, side, side, 0, 0, canvas.width, canvas.height);
  return canvas;
}

// Thumbnails for the rows or tiles on screen: fetched when one comes into view, and kept only as small
// canvases in memory while the view is open. An item is found by `path` when it has one (a month spans
// folders), else by its name in the open folder.
//
// `release`: for a long grid. A tile's canvas is let go as soon as the tile is far out of view and made
// again when it comes back, so a month of thousands of photos never holds more than a screenful or two
// of canvases (iOS limits the memory of all canvases on a page).
export function createThumbLoader(spaceId, getRoot, { side = ROW_SIDE, release = false } = {}) {
  let dir = [];
  let ctrl = new AbortController();
  let observer = null;
  const painted = new Map(); // id -> { key, canvas }, oldest first
  const missing = new Set();
  const inflight = new Set(); // ids being fetched: a redraw must not fetch them again
  const slots = new Map(); // id -> the badge on screen now
  let waiting = [];
  let loading = 0;

  const keyOf = (item) => `${item.size}|${item.modified}`;
  const idOf = (item) => item.path || item.name;
  const pathOf = (item) => item.path || [...dir, item.name].join("/");

  function keep(id, entry) {
    painted.delete(id);
    painted.set(id, entry);
    // Dropped, not emptied: an old canvas may still be on screen, and it goes with its row.
    while (painted.size > MAX_PAINTED) painted.delete(painted.keys().next().value);
  }

  function show(slot, canvas) {
    slot.replaceChildren(canvas);
    slot.classList.add("ld");
  }

  // No thumbnail to come: stop the loading shimmer.
  function none(id) {
    const slot = slots.get(id);
    if (slot) slot.classList.add("ld", "nothumb");
  }

  function free(id) {
    const have = painted.get(id);
    if (!have) return;
    painted.delete(id);
    have.canvas.remove();
    have.canvas.width = 0;
    have.canvas.height = 0;
    const slot = slots.get(id);
    if (slot) slot.classList.remove("ld");
  }

  async function loadOne(item) {
    const { signal } = ctrl;
    const key = keyOf(item);
    const id = idOf(item);
    inflight.add(id);
    let bitmap = null;
    try {
      bitmap = await fetchThumb(spaceId, pathOf(item), signal);
      if (signal.aborted) return;
      if (!bitmap) {
        missing.add(key + id);
        none(id);
        return;
      }
      const slot = slots.get(id);
      if (release && !(slot && slot._near)) return; // scrolled away while it loaded
      const canvas = squareOf(bitmap, side);
      keep(id, { key, canvas });
      if (slot) show(slot, canvas);
    } catch (err) {
      // A link that came back can try again on the next draw; nothing else will change by itself.
      if (!(err instanceof ApiError && err.code === "network") && !(err && err.name === "AbortError")) {
        missing.add(key + id);
        none(id);
      }
    } finally {
      if (bitmap) bitmap.close();
      if (!signal.aborted) inflight.delete(id);
    }
  }

  function pump() {
    while (loading < MAX_LOADS && waiting.length) {
      const item = waiting.shift();
      if (inflight.has(idOf(item))) continue;
      loading += 1;
      loadOne(item).finally(() => {
        loading -= 1;
        pump();
      });
    }
  }

  function watcher() {
    if (observer || !("IntersectionObserver" in window)) return observer;
    observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          const item = e.target._thumbItem;
          e.target._near = e.isIntersecting;
          if (!e.isIntersecting) {
            if (release && item) free(idOf(item));
            continue;
          }
          if (!release) observer.unobserve(e.target);
          if (!item) continue;
          const id = idOf(item);
          const have = painted.get(id);
          if (have && have.key === keyOf(item)) show(e.target, have.canvas);
          else if (!missing.has(keyOf(item) + id)) waiting.push(item);
        }
        pump();
      },
      { root: getRoot(), rootMargin: release ? "600px 0px" : "200px 0px" },
    );
    return observer;
  }

  return {
    // The rows are about to be drawn again.
    reset() {
      if (observer) observer.disconnect();
      slots.clear();
      waiting = [];
    },
    // Show this item's thumbnail in its slot, now or when it comes into view.
    attach(slot, item) {
      const id = idOf(item);
      slots.set(id, slot);
      const have = painted.get(id);
      const key = keyOf(item);
      if (have && have.key === key && !release) return show(slot, have.canvas);
      if (missing.has(key + id)) return none(id);
      if (inflight.has(id) && !release) return undefined; // a fetch running places it here
      const seen = watcher();
      if (seen) {
        slot._thumbItem = item;
        seen.observe(slot);
      } else {
        waiting.push(item);
        pump();
      }
      return undefined;
    },
    // Another folder, or the same one closing: drop everything of the old one.
    open(next) {
      this.reset();
      ctrl.abort();
      ctrl = new AbortController();
      dir = [...next];
      for (const { canvas } of painted.values()) {
        canvas.width = 0;
        canvas.height = 0;
      }
      painted.clear();
      missing.clear();
      inflight.clear();
    },
    close() {
      this.open([]);
      observer = null;
    },
  };
}
