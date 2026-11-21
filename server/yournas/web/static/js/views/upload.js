// Upload page. REAL: the queue, speed and graph all come from the transfers actually running in this
// browser. The prototype's link test (latency, jitter, packet loss, path) needs a server probe
// (Phase B), so it is not shown.

import { ApiError, api } from "../api.js";
import { clear, h, icon, nf, s } from "../dom.js";
import { bytes, rate } from "../format.js";
import { tween } from "../motion.js";
import { kvGet, kvSet } from "../store.js";
import { activeCount, cancel, clearFinished, resumeWith, retry, speeds, subscribe, transfers, uploadingNow } from "../transfers.js";
import { createWakeLock, wakeLockSupported } from "../wakelock.js";

const GRAPH_POINTS = 40;
const W = 320;
const HEIGHT = 96;

export function mount(page, ui) {
  const { spaces, user } = ui.session;
  const awakeKey = `awake:${user.id}`;

  // ---- speed graph -------------------------------------------------------------------------------
  const samples = new Array(GRAPH_POINTS).fill(0);
  const speedEl = h("div", { class: "big", text: "0.0" });
  const fillPath = s("path", { fill: "url(#gf)" });
  const linePath = s("path", { fill: "none", stroke: "#a9cbf6", "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round", "vector-effect": "non-scaling-stroke" });
  const graphCap = h("span", { class: "eyebrow", text: "Idle" });
  const graph = s(
    "svg",
    { viewBox: `0 0 ${W} ${HEIGHT}`, width: "100%", height: HEIGHT, preserveAspectRatio: "none", "aria-label": "Upload speed history" },
    s(
      "defs",
      {},
      s(
        "linearGradient",
        { id: "gf", x1: 0, y1: 0, x2: 0, y2: 1 },
        s("stop", { offset: 0, "stop-color": "#a9cbf6", "stop-opacity": ".35" }),
        s("stop", { offset: 1, "stop-color": "#a9cbf6", "stop-opacity": 0 }),
      ),
    ),
    [0.5, 1].map((f) => s("line", { x1: 0, x2: W, y1: HEIGHT - 6 - f * (HEIGHT - 14), y2: HEIGHT - 6 - f * (HEIGHT - 14), stroke: "rgba(255,255,255,.07)", "stroke-dasharray": "3 5" })),
    fillPath,
    linePath,
  );

  function drawGraph() {
    const peak = Math.max(1, ...samples);
    const points = samples.map((v, i) => [(i / (samples.length - 1)) * W, HEIGHT - 6 - (v / peak) * (HEIGHT - 14)]);
    const line = points.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join("");
    linePath.setAttribute("d", line);
    fillPath.setAttribute("d", `${line}L${W} ${HEIGHT}L0 ${HEIGHT}Z`);
  }

  // ---- stats -------------------------------------------------------------------------------------
  const statQueue = h("span", { text: "0" });
  const statLeft = h("span", { text: "0 B" });
  const statDone = h("span", { text: "0" });
  const statFailed = h("span", { text: "0" });
  const stat = (label, value) => h("div", { class: "stat" }, h("div", { class: "k", text: label }), h("div", { class: "v" }, value));

  // ---- destination -------------------------------------------------------------------------------
  const destText = h("span", { class: "nm" });
  const destRow = h(
    "button",
    { class: "frow destrow", type: "button", onclick: openDestination },
    h("span", { class: "ext" }, icon("folder")),
    h("span", { class: "ftext" }, h("div", { class: "sub", text: "Upload to" }), destText),
    icon("chev", "i chev"),
  );

  const spaceName = (id) => (spaces.find((x) => x.id === id) || { name: id }).name;

  function drawDest() {
    const dest = ui.getDest();
    destRow.hidden = !dest;
    if (dest) destText.textContent = `${spaceName(dest.space)} / ${dest.dir.join(" / ")}`.replace(/ \/ $/, "");
  }
  ui.onDest(drawDest);

  function openDestination() {
    const writable = spaces.filter((x) => x.access === "write");
    const current = ui.getDest();
    const st = { space: current.space, dir: [...current.dir] };
    const list = h("div", { class: "slist" });
    const here = h("span", { class: "eyebrow crumbs" });
    const useThis = h("button", {
      class: "sdone",
      type: "button",
      text: "Use this folder",
      disabled: true,
      onclick: () => {
        ui.setDest({ space: st.space, dir: [...st.dir] });
        ui.closeSheet();
      },
    });
    const spaceRow = h("div", { class: "acts" });
    let seq = 0;

    async function load() {
      seq += 1;
      const mine = seq;
      useThis.disabled = true; // only a folder that was just listed can be chosen
      here.textContent = `/ ${[spaceName(st.space), ...st.dir].join(" / ")} /`;
      clear(spaceRow);
      if (writable.length > 1) {
        spaceRow.append(
          ...writable.map((x) =>
            h("button", {
              class: `ghost${x.id === st.space ? " sel" : ""}`,
              type: "button",
              text: x.name,
              onclick: () => {
                st.space = x.id;
                st.dir = [];
                load();
              },
            }),
          ),
        );
      }
      clear(list);
      if (st.dir.length) {
        list.append(
          h("button", {
            class: "ghost",
            type: "button",
            text: "Up",
            onclick: () => {
              st.dir = st.dir.slice(0, -1);
              load();
            },
          }),
        );
      }
      try {
        // Files and folders are sorted together, so a page can hold no folder at all.
        const folders = [];
        let cursor;
        do {
          const result = await api.list(st.space, st.dir.join("/"), cursor);
          if (mine !== seq) return;
          folders.push(...result.items.filter((item) => item.kind === "dir"));
          cursor = result.next_cursor;
        } while (cursor);
        useThis.disabled = false;
        if (!folders.length) list.append(h("p", { class: "hint", text: "No folders here" }));
        list.append(
          ...folders.map((item) =>
            h(
              "button",
              {
                class: "frow",
                type: "button",
                onclick: () => {
                  st.dir = [...st.dir, item.name];
                  load();
                },
              },
              h("span", { class: "ext" }, icon("folder")),
              h("span", { class: "ftext" }, h("div", { class: "nm", text: item.name })),
            ),
          ),
        );
      } catch (err) {
        if (mine !== seq) return;
        // The saved folder was deleted: step up to one that exists.
        if (err instanceof ApiError && err.code === "not_found" && st.dir.length) {
          st.dir = st.dir.slice(0, -1);
          return load();
        }
        list.append(h("p", { class: "hint", text: "Could not load folders" }));
      }
    }

    ui.openSheet(
      "Upload to",
      h("div", { class: "stitle", text: "Upload to" }),
      spaceRow,
      here,
      list,
      useThis,
    );
    load();
  }

  // ---- queue -------------------------------------------------------------------------------------
  const queue = h("div", { class: "list" });
  const emptyQueue = h("p", { class: "hint", text: "Nothing in the queue" });
  const clearBtn = h("button", { class: "ghost", type: "button", text: "Clear finished", hidden: true, onclick: () => clearFinished() });
  const resumeInput = h("input", { type: "file", hidden: true });
  let resumeId = null;

  resumeInput.addEventListener("change", async () => {
    const file = resumeInput.files && resumeInput.files[0];
    resumeInput.value = "";
    const id = resumeId;
    resumeId = null;
    if (!file || id == null) return;
    if (!(await resumeWith(id, file))) ui.toast("Not the same file. Discard it to start over.");
  });

  const rows = new Map(); // transfer id -> row parts

  function statusText(t) {
    const percent = t.size ? Math.round((t.loaded / t.size) * 100) : 100;
    const kind = t.kind === "down" ? "Download, " : "";
    const text = {
      queued: `${kind}${bytes(t.size)}, Queued`,
      active: `${kind}${bytes(t.loaded)} / ${bytes(t.size)}, ${percent}%`,
      paused: `${bytes(t.loaded)} / ${bytes(t.size)}, ${t.tag}`,
      unfinished: `${percent}% sent. Choose the file again to continue.`,
      done: `${kind}${bytes(t.size)}, Done`,
      cancelled: `${kind}Cancelled`,
      error: `${kind}${bytes(t.size)}, ${t.tag}`,
    };
    return text[t.state];
  }

  function buttonsFor(t) {
    const out = [];
    if (t.state === "unfinished") {
      out.push(
        h("button", {
          class: "ghost",
          type: "button",
          text: "Continue",
          onclick: () => {
            resumeId = t.id;
            resumeInput.click();
          },
        }),
        h("button", { class: "ghost", type: "button", text: "Discard", onclick: () => cancel(t.id) }),
      );
    } else if (t.state === "error" && t.kind === "up" && t.file) {
      out.push(h("button", { class: "ghost", type: "button", text: "Retry", onclick: () => retry(t.id) }));
    } else if (["queued", "active", "paused"].includes(t.state)) {
      out.push(h("button", { class: "qx", type: "button", "aria-label": `Cancel ${t.name}`, onclick: () => cancel(t.id) }, icon("x", "i i18")));
    }
    return out;
  }

  function drawRow(t) {
    let row = rows.get(t.id);
    if (!row) {
      const status = h("div", { class: "s" });
      const bar = h("i");
      const controls = h("div", { class: "qc" });
      const el = h("div", { class: "q" }, h("div", { class: "t" }, h("div", { class: "n", text: t.name }), status, h("div", { class: "p" }, bar)), controls);
      row = { el, status, bar, controls, state: null };
      rows.set(t.id, row);
    }
    row.status.textContent = statusText(t);
    row.bar.style.width = `${t.size ? Math.min(100, (t.loaded / t.size) * 100) : 100}%`;
    row.el.classList.toggle("fail", t.state === "error");
    // Rebuilt only when the state changes, so a button is never replaced under a finger.
    if (row.state !== t.state) {
      row.state = t.state;
      clear(row.controls);
      row.controls.append(...buttonsFor(t));
    }
    return row.el;
  }

  // ---- screen on ---------------------------------------------------------------------------------
  const wakeLock = createWakeLock();
  let keepAwake = true;
  const awakeToggle = h("button", {
    class: "tgl",
    type: "button",
    role: "switch",
    "aria-label": "Keep screen on while uploading",
    "aria-checked": "true",
    onclick: () => {
      keepAwake = !keepAwake;
      kvSet(awakeKey, keepAwake);
      awakeToggle.setAttribute("aria-checked", String(keepAwake));
      syncWake();
    },
  });
  // Only while bytes move: a dead link must not keep a phone unlocked.
  const syncWake = () => wakeLock.set(keepAwake && uploadingNow());
  kvGet(awakeKey, true).then((saved) => {
    keepAwake = saved;
    awakeToggle.setAttribute("aria-checked", String(keepAwake));
    syncWake();
  });

  // ---- page --------------------------------------------------------------------------------------
  page.append(
    h(
      "div",
      { class: "pad" },
      h("div", { class: "row", "data-in": "" }, h("h1", { class: "h1", text: "Upload" }), clearBtn),
      h(
        "div",
        { "data-in": "" },
        h("div", { class: "eyebrow", text: "Upload speed" }),
        h("div", { class: "row endrow12" }, speedEl, h("span", { class: "mono unit", text: "MB/s" })),
      ),
      h("div", { class: "card graphcard", "data-in": "" }, graph, h("div", { class: "row graphfoot" }, graphCap, h("span", { class: "eyebrow", text: `${GRAPH_POINTS} s` }))),
      h("div", { class: "stats", "data-in": "" }, stat("In queue", statQueue), stat("Left to send", statLeft), stat("Done", statDone), stat("Failed", statFailed)),
      h("div", { "data-in": "" }, destRow),
      wakeLockSupported()
        ? h("div", { class: "trow", "data-in": "" }, h("span", {}, h("b", { text: "Keep screen on" }), h("small", { text: "While something is uploading" })), awakeToggle)
        : null,
      h("div", { class: "eyebrow mt6", "data-in": "", text: "Queue" }),
      emptyQueue,
      queue,
      h("p", { class: "hint", text: "If you leave the app, uploads wait and continue when you come back." }),
      h(
        "div",
        { class: "cta" },
        h("span", { class: "halo chalo", "aria-hidden": "true" }),
        h("button", { class: "gb", type: "button", onclick: () => ui.pick() }, h("span", { class: "gbr" }), icon("upload"), "Upload files"),
      ),
      resumeInput,
    ),
  );

  // ---- updates -----------------------------------------------------------------------------------
  let shownSpeed = 0;
  const setSpeed = (v) => {
    shownSpeed = v;
    nf(speedEl, rate(v));
  };

  let frame = 0;
  function draw() {
    frame = 0;
    const items = transfers.items;
    for (const id of [...rows.keys()]) {
      if (!items.some((t) => t.id === id)) {
        rows.get(id).el.remove();
        rows.delete(id);
      }
    }
    items.forEach((t, i) => {
      const el = drawRow(t);
      if (queue.children[i] !== el) queue.insertBefore(el, queue.children[i] || null);
    });
    emptyQueue.hidden = items.length > 0;
    const waiting = items.filter((t) => t.kind === "up" && ["queued", "active", "paused", "unfinished"].includes(t.state));
    statQueue.textContent = String(waiting.length);
    statLeft.textContent = bytes(waiting.reduce((sum, t) => sum + Math.max(0, t.size - t.loaded), 0));
    statDone.textContent = String(items.filter((t) => t.state === "done").length);
    statFailed.textContent = String(items.filter((t) => t.state === "error").length);
    clearBtn.hidden = !items.some((t) => ["done", "error", "cancelled"].includes(t.state));
    syncWake();
    syncTicker();
  }

  // One graph sample a second, only while something is moving.
  let ticker = 0;
  function tick() {
    const now = speeds().up;
    samples.push(now);
    samples.shift();
    drawGraph();
    setSpeed(now);
    if (activeCount("up") === 0) {
      clearInterval(ticker);
      ticker = 0;
      graphCap.textContent = "Idle";
      tween(shownSpeed, 0, { duration: 0.8, onUpdate: setSpeed });
    }
  }
  function syncTicker() {
    if (ticker || activeCount("up") === 0) return;
    graphCap.textContent = "Live";
    ticker = setInterval(tick, 1000);
  }

  const stopListening = subscribe(() => {
    if (!frame) frame = requestAnimationFrame(draw);
  });

  drawDest();
  drawGraph();
  setSpeed(0);
  draw();

  return {
    destroy() {
      stopListening();
      cancelAnimationFrame(frame);
      clearInterval(ticker);
      wakeLock.destroy();
    },
  };
}
