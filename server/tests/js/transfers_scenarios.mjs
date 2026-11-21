// Behaviour checks for the browser upload queue (static/js/transfers.js), run by
// tests/test_web_ui_transfers.py under Node. The real api.js and transfers.js run unchanged against
// an in-memory fake of the upload API; only fetch and the retry delays are replaced. Prints one JSON
// array with an object per scenario: { name, state, tag, patches, deletes, metas }.

import { cancel, clearFinished, enqueueUploads, startDownload, transfers } from "../../yournas/web/static/js/transfers.js";

globalThis.location = { origin: "http://test" };
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, _ms, ...args) => realSetTimeout(fn, 0, ...args); // no real backoff waits

const CHUNK = 4;
const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const error = (status, code, extra = {}) => json(status, { error: { code, message: code, ...extra } });

// A fake server for one upload. `patch(call, state)` may return "lose" (the server does the work
// but the reply never arrives), a Response (the server refuses), or nothing (normal).
function fakeServer({ size, patch = () => undefined, onCreate = () => undefined, stageFull = false }) {
  const s = { offset: 0, upload: false, stored: false, patches: 0, deletes: 0, metas: 0, creates: 0 };
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    const m = init.method || "GET";
    const p = u.pathname;
    if (m === "POST" && p.endsWith("/uploads")) {
      s.creates += 1;
      s.upload = true;
      onCreate(s);
      return json(201, { upload_id: "u1", offset: 0, size, chunk_max_bytes: CHUNK, complete: size === 0, item: null });
    }
    if (p === "/api/v1/uploads/u1") {
      if (m === "PATCH") {
        s.patches += 1;
        const len = init.body.size;
        const call = { n: s.patches, offset: Number(init.headers["Upload-Offset"]), len };
        const verdict = patch(call, s);
        if (verdict instanceof Response) return verdict;
        s.offset += len;
        const done = s.offset >= size;
        if (done && !stageFull) {
          s.stored = true;
          s.upload = false;
        }
        if (verdict === "lose") throw new TypeError("fetch failed");
        return json(200, { upload_id: "u1", offset: s.offset, size, complete: done && !stageFull, item: null });
      }
      if (m === "GET") return s.upload ? json(200, { upload_id: "u1", offset: s.offset, size, complete: false }) : error(404, "not_found");
      if (m === "DELETE") {
        s.deletes += 1;
        return new Response(null, { status: 204 });
      }
    }
    if (m === "GET" && p.endsWith("/items/meta")) {
      s.metas += 1;
      return s.stored ? json(200, { name: "x.bin", kind: "file", size, modified: "2026-01-01T00:00:00Z" }) : error(404, "not_found");
    }
    return error(500, "unexpected_request");
  };
  return s;
}

async function settled(t) {
  while (t.state === "queued" || t.state === "active") await new Promise((r) => setTimeout(r, 1));
}

async function upload(name, size, server) {
  const file = new File([new Uint8Array(size)], "x.bin");
  enqueueUploads([file], "home", [], () => {});
  const t = transfers.items[0];
  await settled(t);
  const out = { name, state: t.state, tag: t.tag, patches: server.patches, deletes: server.deletes, metas: server.metas };
  clearFinished();
  return out;
}

const results = [];

// Normal upload, several chunks.
results.push(await upload("normal", 10, fakeServer({ size: 10 })));

// The reply to the LAST chunk is lost after the server filed the file: the upload record is gone
// (404) but the file is in place. Must end as done, not as NOT FOUND.
results.push(
  await upload("lost-final-reply", 10, fakeServer({ size: 10, patch: (c) => (c.offset + c.len >= 10 ? "lose" : undefined) })),
);

// A second chunk arrives while the first is still being written: 409 upload_busy, retry works.
results.push(
  await upload("upload-busy", 10, fakeServer({ size: 10, patch: (c) => (c.n === 2 ? error(409, "upload_busy", { offset: 4 }) : undefined) })),
);

// Disk full is not retried.
results.push(await upload("disk-full", 10, fakeServer({ size: 10, patch: () => error(507, "insufficient_storage") })));

// Every byte arrived but the server never finished the file (final step failed): the reply is
// lost, the status shows the full size and the file is not there. Must not be reported as done.
results.push(
  await upload("staged-not-finished", 10, fakeServer({ size: 10, stageFull: true, patch: (c) => (c.offset + c.len >= 10 ? "lose" : undefined) })),
);

// A server that keeps answering offset_mismatch must not loop for ever.
results.push(await upload("mismatch-loop", 10, fakeServer({ size: 10, patch: () => error(409, "offset_mismatch", { offset: 0 }) })));

// Cancel while the create request is in flight: the staged upload must be dropped on the server.
results.push(await upload("cancel-during-create", 10, fakeServer({ size: 10, onCreate: () => cancel(transfers.items[0].id) })));

// An oversized download is refused before any request.
{
  let called = 0;
  globalThis.fetch = async () => {
    called += 1;
    return error(500, "unexpected_request");
  };
  await startDownload("home", ["big.bin"], "big.bin", 600 * 1024 * 1024);
  const t = transfers.items[0];
  results.push({ name: "download-too-large", state: t.state, tag: t.tag, requests: called });
  clearFinished();
}

console.log(JSON.stringify(results));
