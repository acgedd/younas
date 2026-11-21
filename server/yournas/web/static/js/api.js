// The only module that talks to the server. Same origin, bearer token, no cookies.
//
// The token lives in localStorage so a phone stays signed in. That is safe only because the page is
// served with a strict Content-Security-Policy (no inline script, nothing from another origin); see
// docs/SECURITY.md. A 401 from the server clears it and fires the "unauthorized" event.

const API = "/api/v1";
const TOKEN_KEY = "yournas.token";

export const events = new EventTarget();

// Another tab signed in, out or changed account: localStorage is shared, so this tab would keep
// showing its own user while sending the other tab's token. Tell the app to start over.
if (typeof window !== "undefined" && window.addEventListener) {
  window.addEventListener("storage", (e) => {
    if (e.key !== TOKEN_KEY && e.key !== null) return;
    memoryToken = null; // the stored value is the truth now; a stale in-memory copy would hide a sign-out
    events.dispatchEvent(new Event("tokenchanged"));
  });
}

let memoryToken = null;

export const token = {
  get() {
    try {
      return localStorage.getItem(TOKEN_KEY) || memoryToken;
    } catch {
      return memoryToken;
    }
  },
  set(value) {
    memoryToken = value;
    try {
      localStorage.setItem(TOKEN_KEY, value);
    } catch {
      /* private mode: the token lives in memory only */
    }
  },
  clear() {
    memoryToken = null;
    try {
      localStorage.removeItem(TOKEN_KEY);
    } catch {
      /* nothing to do */
    }
  },
};

export class ApiError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = extra.retryAfter ?? null;
    this.offset = extra.offset ?? null;
  }
}

async function toError(res) {
  let code = "error";
  let message = res.statusText || "Request failed";
  let offset = null;
  try {
    const body = await res.json();
    if (body && body.error) {
      code = body.error.code || code;
      message = body.error.message || message;
      offset = typeof body.error.offset === "number" ? body.error.offset : null;
    }
  } catch {
    /* not JSON */
  }
  const retry = Number.parseInt(res.headers.get("Retry-After") || "", 10);
  return new ApiError(res.status, code, message, {
    retryAfter: Number.isFinite(retry) ? retry : null,
    offset,
  });
}

export async function request(method, path, options = {}) {
  const { query, json, headers, body, signal, raw } = options;
  const url = new URL(path.startsWith("/health") ? path : API + path, location.origin);
  for (const [k, v] of Object.entries(query || {})) {
    if (v != null) url.searchParams.set(k, String(v));
  }
  const sent = { ...(headers || {}) };
  const t = token.get();
  if (t) sent.Authorization = `Bearer ${t}`;
  let payload = body;
  if (json !== undefined) {
    sent["Content-Type"] = "application/json";
    payload = JSON.stringify(json);
  }
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: sent,
      body: payload,
      signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
  } catch (e) {
    if (e && e.name === "AbortError") throw e;
    throw new ApiError(0, "network", "Server unreachable");
  }
  if (!res.ok) {
    const err = await toError(res);
    if (err.status === 401 && err.code === "unauthorized") events.dispatchEvent(new Event("unauthorized"));
    throw err;
  }
  if (raw) return res;
  if (res.status === 204) return null;
  return res.json();
}

const space = (id) => encodeURIComponent(id);

export const api = {
  health: () => request("GET", "/health"),
  login: (username, password) => request("POST", "/auth/login", { json: { username, password } }),
  logout: () => request("POST", "/auth/logout"),
  me: () => request("GET", "/auth/me"),
  changePassword: (current, next) => request("POST", "/auth/password", { json: { current, new: next } }),
  adminStatus: () => request("GET", "/admin/status"),

  list: (spaceId, path, cursor) =>
    request("GET", `/spaces/${space(spaceId)}/items`, { query: { path, limit: 200, cursor } }),
  mkdir: (spaceId, path) => request("POST", `/spaces/${space(spaceId)}/folders`, { json: { path } }),
  meta: (spaceId, path, signal) =>
    request("GET", `/spaces/${space(spaceId)}/items/meta`, { query: { path }, signal }),
  remove: (spaceId, path) => request("DELETE", `/spaces/${space(spaceId)}/items`, { query: { path } }),
  download: (spaceId, path, signal) =>
    request("GET", `/spaces/${space(spaceId)}/files`, { query: { path }, signal, raw: true }),
  thumbnail: (spaceId, path, signal) =>
    request("GET", `/spaces/${space(spaceId)}/thumbnail`, { query: { path }, signal, raw: true }),
  putThumbnail: (spaceId, path, size, modified, blob, signal) =>
    request("PUT", `/spaces/${space(spaceId)}/thumbnail`, {
      query: { path, size, modified },
      body: blob,
      signal,
      headers: { "Content-Type": "application/octet-stream" },
    }),

  months: (spaceId, year, signal) =>
    request("GET", `/spaces/${space(spaceId)}/photos/months`, { query: { year }, signal }),
  monthPhotos: (spaceId, month, cursor, signal) =>
    request("GET", `/spaces/${space(spaceId)}/photos/months/${encodeURIComponent(month)}`, { query: { limit: 60, cursor }, signal }),
  setMonthCover: (spaceId, month, path, signal) =>
    request("PUT", `/spaces/${space(spaceId)}/photos/months/${encodeURIComponent(month)}/cover`, { json: { path }, signal }),
  clearMonthCover: (spaceId, month, signal) =>
    request("DELETE", `/spaces/${space(spaceId)}/photos/months/${encodeURIComponent(month)}/cover`, { signal }),

  createUpload: (spaceId, path, size, signal) =>
    request("POST", `/spaces/${space(spaceId)}/uploads`, { json: { path, size, overwrite: false }, signal }),
  uploadStatus: (id, signal) => request("GET", `/uploads/${id}`, { signal }),
  uploadChunk: (id, offset, blob, signal) =>
    request("PATCH", `/uploads/${id}`, {
      body: blob,
      signal,
      headers: { "Content-Type": "application/octet-stream", "Upload-Offset": String(offset) },
    }),
  abortUpload: (id) => request("DELETE", `/uploads/${id}`),
};

// A short, human label for an error.
export function errorTag(err) {
  if (!(err instanceof ApiError)) return "Error";
  switch (err.code) {
    case "network":
      return "Link lost";
    case "already_exists":
      return "Already exists";
    case "payload_too_large":
      return "Too large";
    case "insufficient_storage":
      return "No space";
    case "upload_quota_exceeded":
      return "Over quota";
    case "too_many_uploads":
      return "Too many unfinished";
    case "forbidden":
      return "Read only";
    case "not_found":
      return "Not found";
    case "not_empty":
      return "Not empty";
    case "stalled":
      return "Stalled";
    case "busy":
      return "In use";
    case "invalid_path":
      return "Bad name";
    case "too_many_attempts":
    case "too_many_requests":
      return "Slow down";
    case "password_change_required":
      return "Change password first";
    default:
      return err.status ? `Error ${err.status}` : "Error";
  }
}
