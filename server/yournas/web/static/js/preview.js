// Full-screen view of one photo in a folder, through the normal download route with the user's token.
//
// The Content-Security-Policy allows same-origin images only (no blob:, no data:), so the bytes are
// decoded with createImageBitmap and drawn on a <canvas>, like the Home cover. Nothing is written to
// the device: the bytes stay in memory while they are decoded, and the canvas is emptied on close.
// SVG is left out on purpose: it is a document that can carry script, not a photo.

import { ApiError, api, errorTag } from "./api.js";
import { paint } from "./covers.js";
import { h, icon } from "./dom.js";
import { bytes } from "./format.js";
import { fx } from "./motion.js";

const TYPES = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
  webp: "image/webp",
  heic: "image/heic",
  heif: "image/heif",
};

export const MAX_PREVIEW_BYTES = 40 * 1000 * 1000;
const MAX_SIDE = 2400;
const SWIPE_PX = 50;

export function typeOf(name) {
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return null;
  return TYPES[name.slice(dot + 1).toLowerCase()] || null;
}

export function isPhoto(item) {
  return item.kind === "file" && typeOf(item.name) !== null;
}

export class TooLarge extends Error {}

// ---- what a file really is, read from its header without decoding it ------------------------------
//
// The browser decodes by content, not by name, and a small file can unpack to billions of pixels
// (a "pixel bomb") that kills the tab. So the size is read from the header first, whatever the name.

export const MAX_PIXELS = 50 * 1000 * 1000; // a 48 MP iPhone photo fits
const MAX_HEIC_BYTES = 20 * 1000 * 1000; // HEIC sizes cannot be read cheaply: a byte cap has to do
const MAX_JPEG_SEGMENTS = 4096;
const HEIC_BRANDS = ["heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1", "heif"];

const ascii = (b, at, n) => String.fromCharCode(...b.subarray(at, at + n));
const isFrame = (m) => m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc;

// `read(start, length)` gives those bytes (fewer at the end). Walks the segment headers only, so a
// frame header after a large EXIF or XMP block is still found.
async function walkJpeg(read) {
  let at = 2;
  for (let n = 0; n < MAX_JPEG_SEGMENTS; n += 1) {
    const head = await read(at, 4);
    if (head.length < 2 || head[0] !== 0xff) return null;
    const marker = head[1];
    if (marker === 0xff) {
      at += 1; // fill byte
      continue;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      at += 2; // no length
      continue;
    }
    if (marker === 0xd9 || marker === 0xda || head.length < 4) return null; // the image data before any frame
    const length = (head[2] << 8) | head[3];
    if (length < 2) return null;
    if (isFrame(marker)) {
      const f = await read(at + 5, 4);
      if (f.length < 4) return null;
      const size = { height: (f[0] << 8) | f[1], width: (f[2] << 8) | f[3] };
      return size.width && size.height ? size : null;
    }
    at += 2 + length;
  }
  return null;
}

// { width, height } of a JPEG held in memory, or null.
export function jpegSize(bytes) {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return Promise.resolve(null);
  return walkJpeg(async (start, length) => bytes.subarray(start, start + length));
}

// { kind, width, height } for JPEG, PNG, GIF and WebP; { kind: "heic" } for HEIC/HEIF; null for
// anything else, which is then not decoded at all.
export async function imageInfo(blob) {
  const read = async (start, length) => new Uint8Array(await blob.slice(start, start + length).arrayBuffer());
  const b = await read(0, 32);
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    const size = await walkJpeg(read);
    return size && { kind: "jpeg", ...size };
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (b.length >= 24 && ascii(b, 1, 3) === "PNG" && b[0] === 0x89 && ascii(b, 12, 4) === "IHDR") {
    return { kind: "png", width: view.getUint32(16), height: view.getUint32(20) };
  }
  if (b.length >= 10 && (ascii(b, 0, 6) === "GIF87a" || ascii(b, 0, 6) === "GIF89a")) {
    return { kind: "gif", width: view.getUint16(6, true), height: view.getUint16(8, true) };
  }
  if (b.length >= 30 && ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WEBP") {
    const chunk = ascii(b, 12, 4);
    if (chunk === "VP8X") {
      return { kind: "webp", width: 1 + (b[24] | (b[25] << 8) | (b[26] << 16)), height: 1 + (b[27] | (b[28] << 8) | (b[29] << 16)) };
    }
    if (chunk === "VP8L" && b[20] === 0x2f) {
      return { kind: "webp", width: 1 + (((b[22] & 0x3f) << 8) | b[21]), height: 1 + (((b[24] & 0x0f) << 10) | (b[23] << 2) | ((b[22] & 0xc0) >> 6)) };
    }
    if (chunk === "VP8 " && b[23] === 0x9d && b[24] === 0x01 && b[25] === 0x2a) {
      return { kind: "webp", width: view.getUint16(26, true) & 0x3fff, height: view.getUint16(28, true) & 0x3fff };
    }
    return null;
  }
  if (b.length >= 12 && ascii(b, 4, 4) === "ftyp" && HEIC_BRANDS.includes(ascii(b, 8, 4))) return { kind: "heic" };
  return null;
}

// "ok", "large" (safe to say it is too big) or "unknown" (not a picture this page decodes).
export async function decodable(blob, maxPixels = MAX_PIXELS) {
  const info = await imageInfo(blob);
  if (!info) return "unknown";
  if (info.kind === "heic") return blob.size <= MAX_HEIC_BYTES ? "ok" : "large";
  if (!info.width || !info.height) return "unknown";
  return info.width * info.height <= maxPixels ? "ok" : "large";
}

// The whole body as a Blob, refused as soon as it passes `max`: the listing's size can be out of date.
export async function readCapped(res, max, type, onProgress) {
  const declared = Number.parseInt(res.headers.get("Content-Length") || "", 10);
  if (declared > max) throw new TooLarge();
  const pieces = [];
  if (res.body) {
    const reader = res.body.getReader();
    let loaded = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      loaded += value.length;
      if (loaded > max) {
        await reader.cancel().catch(() => {});
        throw new TooLarge();
      }
      pieces.push(value);
      if (onProgress && declared > 0) onProgress(loaded / declared);
    }
  } else {
    const whole = await res.blob();
    if (whole.size > max) throw new TooLarge();
    pieces.push(whole);
  }
  return new Blob(pieces, { type });
}

// Opens over `host`. `photos` is the list to step through. Returns the function that closes it.
export function openPreview(host, { spaceId, dir, photos, start, onDownload }) {
  const opener = document.activeElement;
  const listeners = new AbortController();
  const { signal } = listeners;
  let index = start;
  let seq = 0;
  let loading = null;
  let closed = false;

  const canvas = h("canvas", { class: "pvc", role: "img" });
  const name = h("div", { class: "pvname" });
  const count = h("div", { class: "pvcount" });
  const message = h("p", { class: "pvmsg", role: "status" });
  const retry = h("button", { class: "ghost", type: "button", text: "Try again", hidden: true, onclick: () => show() });
  const save = h("button", { class: "ghost", type: "button", text: "Download", onclick: () => onDownload(photos[index]) });
  const shut = h("button", { class: "pvx glass", type: "button", "aria-label": "Close" }, icon("x"));
  const prev = h("button", { class: "pvstep pvprev glass", type: "button", "aria-label": "Previous photo", onclick: () => step(-1) }, icon("chev"));
  const next = h("button", { class: "pvstep pvnext glass", type: "button", "aria-label": "Next photo", onclick: () => step(1) }, icon("chev"));
  const view = h(
    "div",
    { class: "pv", role: "dialog", "aria-modal": "true", "aria-label": "Photo" },
    canvas,
    message,
    h("div", { class: "pvtop" }, shut, h("div", { class: "pvtitle" }, name, count)),
    prev,
    next,
    h("div", { class: "pvbar" }, retry, save),
  );

  function empty() {
    canvas.width = 0;
    canvas.height = 0;
  }

  function fail(text, canRetry) {
    message.textContent = text;
    retry.hidden = !canRetry;
  }

  async function show() {
    seq += 1;
    const mine = seq;
    if (loading) loading.abort();
    const ctrl = new AbortController();
    loading = ctrl;
    const photo = photos[index];
    empty();
    name.textContent = photo.name;
    count.textContent = `${index + 1} / ${photos.length}`;
    canvas.setAttribute("aria-label", photo.name);
    prev.hidden = index === 0;
    next.hidden = index === photos.length - 1;
    retry.hidden = true;
    const tooLarge = `Too large to preview, ${bytes(MAX_PREVIEW_BYTES)} at most`;
    if (photo.size > MAX_PREVIEW_BYTES) return fail(tooLarge, false);
    message.textContent = "Loading";
    let bitmap = null;
    try {
      const res = await api.download(spaceId, photo.path || [...dir, photo.name].join("/"), ctrl.signal);
      const blob = await readCapped(res, MAX_PREVIEW_BYTES, typeOf(photo.name), (part) => {
        if (mine === seq) message.textContent = `Loading ${Math.round(part * 100)}%`;
      });
      const verdict = await decodable(blob);
      if (mine !== seq) return;
      if (verdict === "large") return fail(`Too large to preview, ${MAX_PIXELS / 1e6} megapixels at most`, false);
      if (verdict !== "ok") return fail("This device cannot show this file", false);
      bitmap = await createImageBitmap(blob);
      if (mine !== seq) return;
      paint(canvas, bitmap, Math.min(MAX_SIDE, Math.ceil(Math.max(innerWidth, innerHeight) * (devicePixelRatio || 1))));
      message.textContent = "";
    } catch (err) {
      if (mine !== seq || (err && err.name === "AbortError")) return;
      if (err instanceof TooLarge) fail(tooLarge, false);
      else if (err instanceof ApiError) fail(`Could not load this photo: ${errorTag(err)}`, true);
      else fail("This device cannot show this file", false);
    } finally {
      if (bitmap) bitmap.close();
    }
  }

  function step(by) {
    const target = index + by;
    if (target < 0 || target >= photos.length) return;
    index = target;
    show();
  }

  function close() {
    if (closed) return;
    closed = true;
    seq += 1;
    if (loading) loading.abort();
    listeners.abort();
    empty();
    view.remove();
    if (opener && opener.isConnected) opener.focus({ preventScroll: true });
  }

  shut.addEventListener("click", close);

  // Swipe sideways to step, down to close.
  let press = null;
  view.addEventListener("pointerdown", (e) => {
    press = e.target.closest("button") ? null : { x: e.clientX, y: e.clientY };
  });
  view.addEventListener("pointerup", (e) => {
    if (!press) return;
    const dx = e.clientX - press.x;
    const dy = e.clientY - press.y;
    press = null;
    if (Math.abs(dx) > Math.abs(dy)) {
      if (Math.abs(dx) > SWIPE_PX) step(dx < 0 ? 1 : -1);
    } else if (dy > SWIPE_PX * 2) {
      close();
    }
  });
  view.addEventListener("pointercancel", () => {
    press = null;
  });

  // Before the shell's own Escape, which would close the whole folder underneath.
  window.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Escape") {
        e.stopImmediatePropagation();
        close();
      } else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        step(e.key === "ArrowLeft" ? -1 : 1);
      } else if (e.key === "Tab") {
        // Keep the keyboard inside the dialog: the folder behind it is still in the page.
        const stops = [...view.querySelectorAll("button")].filter((b) => !b.hidden);
        const at = stops.indexOf(document.activeElement);
        e.preventDefault();
        stops[(at + (e.shiftKey ? -1 : 1) + stops.length) % stops.length].focus();
      }
    },
    { capture: true, signal },
  );

  host.append(view);
  shut.focus({ preventScroll: true });
  fx(view, { opacity: [0, 1] }, { duration: 0.18, ease: "linear" });
  show();
  return close;
}
