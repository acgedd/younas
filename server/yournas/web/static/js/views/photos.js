// Library, "Photos": one space's photos grouped by the month they were taken (docs/MONTHS-SPEC.md).
// The server keeps the index and sorts old photos in the background; this page only shows it, and asks
// again every few seconds while the sorting runs and the page is in view. Nothing is asked before the
// Library page is first opened.
//
// Layout from the approved prototype (the owner's reference image): a year header with a chevron, then
// one large card per month. A month opens like a space does, with its photos in a three-column grid.
// The grid shows server thumbnails only; an original is fetched only when a photo is tapped.

import { ApiError, api, errorTag } from "../api.js";
import { chars, clear, h, icon } from "../dom.js";
import { bytes } from "../format.js";
import { openPreview } from "../preview.js";
import { createThumbLoader, thumbCanvas } from "../thumbs.js";
import { MAX_BROWSER_DOWNLOAD_BYTES, startDownload, subscribeDone } from "../transfers.js";

const MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const POLL_MS = 3000;
const TILE_SIDE = 200; // a tile is about a third of a phone's width

const photosText = (n) => `${n} ${n === 1 ? "photo" : "photos"}`;

// "2026-11" -> { year: 2026, index: 10 }, or null for anything else.
function parseMonth(text) {
  const m = /^(\d{4})-(\d{2})$/.exec(String(text));
  if (!m) return null;
  const index = Number(m[2]) - 1;
  return index >= 0 && index < 12 ? { year: Number(m[1]), index } : null;
}

function emptyCanvas(canvas) {
  if (!canvas) return;
  canvas.remove();
  canvas.width = 0;
  canvas.height = 0;
}

// A button that opens a short list to pick from. Not a <select>: WebKit styles its own <select> with an
// inline style, which the Content-Security-Policy refuses.
function picker(cls, label) {
  const text = h("span", { class: "pkt" });
  const button = h("button", { class: "pk", type: "button", "aria-expanded": "false" }, text, icon("chev", "i pkc"));
  const list = h("div", { class: "pkm", hidden: true });
  const wrap = h("div", { class: `pkw ${cls}` }, button, list);
  let signature = "";
  const isOpen = () => !list.hidden;
  function close() {
    list.hidden = true;
    button.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", outside, true);
  }
  function outside(e) {
    if (!wrap.contains(e.target)) close();
  }
  button.addEventListener("click", () => {
    if (isOpen()) return close();
    if (list.children.length < 2) return undefined;
    list.hidden = false;
    button.setAttribute("aria-expanded", "true");
    document.addEventListener("pointerdown", outside, true);
    const on = list.querySelector("[aria-current]") || list.firstElementChild;
    if (on) on.focus();
    return undefined;
  });
  wrap.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && isOpen()) {
      e.stopPropagation();
      close();
      button.focus();
    } else if ((e.key === "ArrowDown" || e.key === "ArrowUp") && isOpen()) {
      e.preventDefault();
      const items = [...list.children];
      const at = items.indexOf(document.activeElement);
      const next = items[(at + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length];
      if (next) next.focus();
    } else if (e.key === "Tab" && isOpen()) {
      close(); // the keyboard leaves; not on focusout, which Safari fires on a tap inside the list
    }
  });
  return {
    el: wrap,
    isOpen,
    // options: [{ value, text }]. Left alone while open, and when nothing changed.
    set(shown, options, current, onPick) {
      const next = JSON.stringify([shown, current, options]);
      if (isOpen() || next === signature) return;
      signature = next;
      text.textContent = shown;
      button.setAttribute("aria-label", `${label}: ${shown}`);
      clear(list);
      for (const o of options) {
        list.append(
          h("button", {
            type: "button",
            "aria-current": o.value === current ? "true" : null,
            "data-v": o.value,
            text: o.text,
            onclick: () => {
              close();
              button.focus();
              onPick(o.value);
            },
          }),
        );
      }
      const single = options.length < 2;
      wrap.classList.toggle("single", single);
      if (single) button.setAttribute("aria-disabled", "true");
      else button.removeAttribute("aria-disabled");
    },
    close,
  };
}

// `track(card, nameEl)` lets the Library page fit and reveal the card's name like its other cards; it
// returns the function that lets go of the card.
export function createPhotos({ ui, spaces, page, track }) {
  let spaceIndex = Math.max(0, spaces.findIndex((s) => s.id === "home"));
  let year = null; // null: the newest year with photos
  let seq = 0;
  let timer = 0;
  let alive = true;
  let started = false;
  let data = null;
  let closeMonth = null;
  let loading = null; // the AbortController of the request in flight
  let covers = new AbortController(); // cover fetches of what is on screen now
  const cards = new Map(); // month -> { el, chip, coverPath, cover, data, untrack }

  const yearPick = picker("yrp", "Year");
  const spacePick = picker("spk", "Space");
  const state = h("span", { role: "status" }); // only "sorting", "waiting" and the like: no counter in here
  const count = h("span");
  const status = h("p", { class: "hint" }, state, count);
  const list = h("div", { class: "cards" });
  const el = h(
    "div",
    { class: "photos" },
    h("div", { class: "row sec", id: "sec-photos", "data-in": "" }, yearPick.el, h("span", { class: "eyebrow", text: "By month" })),
    spaces.length > 1 ? h("div", { class: "spkrow", "data-in": "" }, spacePick.el) : null,
    status,
    list,
  );

  const space = () => spaces[spaceIndex];
  const tone = () => `tone${spaceIndex % 5}`;
  const visible = () => document.visibilityState === "visible" && page.classList.contains("act");

  function drawSpaces() {
    const options = spaces.map((s, i) => ({ value: String(i), text: s.name }));
    spacePick.set(spaces[spaceIndex].name, options, String(spaceIndex), (v) => {
      spaceIndex = Number(v);
      year = null;
      drawSpaces();
      reset();
      load();
    });
  }
  drawSpaces();
  yearPick.set("Photos", [], null, () => {});

  function setState(text) {
    if (state.textContent !== text) state.textContent = text;
  }

  function drop(entry) {
    entry.untrack();
    entry.el.remove();
    emptyCanvas(entry.cover);
  }

  function reset() {
    clearTimeout(timer);
    if (loading) loading.abort();
    covers.abort();
    covers = new AbortController();
    for (const c of cards.values()) drop(c);
    cards.clear();
    data = null;
  }

  // Ask again later while the sorting runs; never while the page is out of view.
  function schedule() {
    clearTimeout(timer);
    if (alive && visible()) timer = setTimeout(() => alive && visible() && load(), POLL_MS);
  }

  async function load() {
    started = true;
    seq += 1;
    const mine = seq;
    if (loading) loading.abort();
    const ctrl = new AbortController();
    loading = ctrl;
    try {
      const answer = await api.months(space().id, year ?? undefined, ctrl.signal);
      if (mine !== seq || !alive) return;
      data = answer;
      draw();
      if (answer.index && answer.index.state !== "ready") schedule();
    } catch (err) {
      if (mine !== seq || !alive || (err && err.name === "AbortError")) return;
      setState(`Could not load photos: ${errorTag(err)}`);
      count.textContent = "";
      if (!(err instanceof ApiError) || err.code === "network" || err.code === "too_many_requests") schedule();
    }
  }

  function drawYears() {
    const years = (data.years || []).filter((y) => Number.isInteger(y.year) && Number.isInteger(y.count));
    const shown = Number.isInteger(data.year) ? data.year : null;
    const options = years.map((y) => ({ value: String(y.year), text: `${y.year}, ${photosText(y.count)}` }));
    yearPick.set(shown === null ? "Photos" : String(shown), options, shown === null ? null : String(shown), (v) => {
      year = Number(v);
      reset();
      load();
    });
  }

  function drawStatus() {
    const index = data.index || {};
    const months = data.months || [];
    count.textContent = "";
    if (index.state && index.state !== "ready") {
      setState(index.state === "waiting" ? "Waiting to sort photos" : "Sorting photos");
      if (Number.isInteger(index.pending) && index.pending > 0) count.textContent = `, ${index.pending} left`;
    } else if (!months.length) {
      setState((data.years || []).length && Number.isInteger(data.year) ? `No photos in ${data.year}` : "No photos in this space yet");
    } else {
      setState(index.truncated ? "Too many files: only part of this space is sorted" : "");
    }
  }

  function card(month) {
    const when = parseMonth(month.month);
    const name = h("span", { class: "mname", "aria-hidden": "true" }, chars(MONTH_NAMES[when.index]));
    const chip = h("span", { class: "chip glass" });
    const elCard = h(
      "button",
      { class: `mcard ld ${tone()}`, type: "button", "data-in": "" },
      h("div", { class: "shade" }),
      chip,
      h("span", { class: "dots glass" }, icon("dots")),
      name,
    );
    const entry = { el: elCard, chip, coverPath: null, cover: null, data: month, untrack: () => {} };
    elCard.addEventListener("click", () => openMonth(entry));
    entry.untrack = track(elCard, name) || (() => {});
    return entry;
  }

  async function setCover(entry, cover) {
    const path = cover && typeof cover.path === "string" ? cover.path : null;
    if (path === entry.coverPath) return;
    entry.coverPath = path;
    emptyCanvas(entry.cover);
    entry.cover = null;
    if (!path) return;
    const { signal } = covers;
    const canvas = await thumbCanvas(space().id, path, signal);
    if (!alive || signal.aborted || entry.coverPath !== path) return emptyCanvas(canvas);
    if (!canvas) {
      entry.coverPath = null; // a lost link: try again on the next answer
      return undefined;
    }
    canvas.className = "cvr";
    entry.cover = canvas;
    entry.el.prepend(canvas);
    return undefined;
  }

  function drawCards() {
    const months = (data.months || []).filter((m) => parseMonth(m.month) && Number.isInteger(m.count));
    const keep = new Set(months.map((m) => m.month));
    for (const [key, c] of cards) {
      if (!keep.has(key)) {
        drop(c);
        cards.delete(key);
      }
    }
    const order = [];
    for (const m of months) {
      let entry = cards.get(m.month);
      if (!entry) {
        entry = card(m);
        cards.set(m.month, entry);
      }
      entry.data = m;
      const label = photosText(m.count);
      if (entry.chip.textContent !== label) entry.chip.textContent = label;
      entry.el.setAttribute("aria-label", `${MONTH_NAMES[parseMonth(m.month).index]}, ${label}`);
      order.push(entry.el);
      setCover(entry, m.cover);
    }
    // Moved only when the order changed: moving a card loses the keyboard focus on it.
    const now = [...list.children];
    if (now.length !== order.length || order.some((e, i) => now[i] !== e)) list.append(...order);
  }

  function draw() {
    drawYears();
    drawStatus();
    drawCards();
  }

  // ---- one month, opened ---------------------------------------------------------------------------
  function openMonth(entry) {
    if (closeMonth) closeMonth();
    const s = space();
    const m = entry.data;
    const when = parseMonth(m.month);
    const st = { items: [], seen: new Set(), cursor: null, loading: false, done: false };
    let open = true;
    let closePreview = null;
    const ctrl = new AbortController();
    const grid = h("div", { class: "grid3" });
    const more = h("div", { class: "gmore" });
    const note = h("p", { class: "hint", role: "status" });
    const hero = h(
      "div",
      { class: `hero ${tone()}` },
      h("button", { class: "back glass", type: "button", "aria-label": "Back", onclick: () => ui.closeDetail() }, icon("chev")),
      h("div", { class: "htitle" }, chars(MONTH_NAMES[when.index])),
    );
    let big = null;
    if (entry.cover) {
      big = document.createElement("canvas");
      big.width = entry.cover.width;
      big.height = entry.cover.height;
      big.getContext("2d").drawImage(entry.cover, 0, 0);
      big.className = "cvr";
      hero.prepend(big);
    }
    // Cover choice (docs/COVERS-SPEC.md): writers only; the server checks again. In pick mode a tap
    // on a tile sends that item's own path, never one rebuilt from its name.
    const writable = s.access === "write";
    const tools = h("div", { class: "acts" });
    const pickNote = h("p", { class: "hint", role: "status" });
    let picking = false;
    let busy = false;

    // A tile without a thumbnail cannot be the cover: say so to assistive tech, not only by its look.
    function markTiles(tiles) {
      for (const b of tiles) {
        if (!b.classList.contains("nothumb")) continue;
        if (picking) b.setAttribute("aria-disabled", "true");
        else b.removeAttribute("aria-disabled");
      }
    }

    function drawTools() {
      clear(tools);
      grid.classList.toggle("picking", picking);
      markTiles(grid.children);
      pickNote.textContent = picking ? "Tap a photo for the cover" : "";
      if (!writable) return;
      if (!picking) {
        tools.append(h("button", { class: "ghost", type: "button", text: "Choose cover", onclick: () => setPicking(true) }));
        return;
      }
      if (m.custom === true) tools.append(h("button", { class: "ghost", type: "button", text: "Use newest photo", onclick: () => chooseCover(null) }));
      tools.append(h("button", { class: "ghost", type: "button", text: "Cancel", onclick: () => setPicking(false) }));
    }

    function setPicking(on) {
      if (busy) return;
      picking = on;
      drawTools();
    }

    // item: a month-page item to use, or null for "newest photo". On success the overlay closes and
    // the months are asked again, so the card shows the new cover.
    async function chooseCover(item) {
      if (busy || !open) return;
      busy = true;
      pickNote.textContent = "Saving";
      try {
        if (item) await api.setMonthCover(s.id, m.month, item.path, ctrl.signal);
        else await api.clearMonthCover(s.id, m.month, ctrl.signal);
        if (!open) return;
        ui.toast(item ? "Cover set" : "Cover back to the newest photo");
        ui.closeDetail();
        if (alive && visible()) load();
      } catch (err) {
        if (!open || (err && err.name === "AbortError")) return;
        pickNote.textContent = `Could not change the cover: ${errorTag(err)}`;
      } finally {
        busy = false;
      }
    }

    const content = h(
      "div",
      { class: "sc" },
      hero,
      h(
        "div",
        { class: "body" },
        h("div", { class: "row", "data-d": "" }, h("span", { class: "eyebrow", text: `${photosText(m.count)}, ${bytes(m.bytes || 0)}` }), h("span", { class: "pill", text: String(when.year) })),
        tools,
        pickNote,
        grid,
        note,
        more,
      ),
    );
    drawTools();
    const thumbs = createThumbLoader(s.id, () => content, { side: TILE_SIDE, release: true });

    function download(item) {
      if (item.size > MAX_BROWSER_DOWNLOAD_BYTES) return ui.toast(`Too large for a browser, ${bytes(MAX_BROWSER_DOWNLOAD_BYTES)} at most`);
      startDownload(s.id, item.path.split("/"), item.name, item.size);
      ui.toast(`Downloading ${item.name}`);
      return undefined;
    }

    function tile(item, i) {
      const b = h("button", { type: "button", "aria-label": item.name, "data-d": "" });
      if (item.thumb) thumbs.attach(b, item);
      else b.classList.add("ld", "nothumb");
      b.addEventListener("click", () => {
        if (picking) {
          if (item.thumb) chooseCover(item); // a cover needs a thumbnail: the server refuses one without
          return;
        }
        if (closePreview) closePreview();
        const close = openPreview(content, { spaceId: s.id, dir: [], photos: st.items, start: i, onDownload: download });
        closePreview = () => {
          closePreview = null;
          close();
        };
      });
      return b;
    }

    // The next page when the end of the grid comes near.
    let moreObserver = null;
    function watchMore() {
      if (!("IntersectionObserver" in window)) return next();
      if (!moreObserver) {
        moreObserver = new IntersectionObserver(
          (entries) => {
            if (entries.some((e) => e.isIntersecting)) next();
          },
          { root: content, rootMargin: "400px 0px" },
        );
      }
      moreObserver.unobserve(more);
      moreObserver.observe(more);
      return undefined;
    }

    async function next() {
      if (st.loading || st.done || !open) return;
      st.loading = true;
      note.textContent = st.items.length ? "" : "Loading";
      try {
        const answer = await api.monthPhotos(s.id, m.month, st.cursor ?? undefined, ctrl.signal);
        if (!open) return;
        // The index may move while it is read: a photo already shown is not shown twice.
        const items = (answer.items || []).filter((i) => typeof i.path === "string" && typeof i.name === "string" && !st.seen.has(i.path));
        const start = st.items.length;
        for (const i of items) st.seen.add(i.path);
        st.items.push(...items);
        const added = items.map((item, k) => tile(item, start + k));
        grid.append(...added);
        markTiles(added);
        st.cursor = answer.next_cursor || null;
        st.done = !st.cursor;
        note.textContent = st.items.length ? "" : "No photos in this month any more";
      } catch (err) {
        if (!open || (err && err.name === "AbortError")) return;
        note.textContent = `Could not load this month: ${errorTag(err)}`;
        // A lost link can try again when the end of the grid comes near again; anything else cannot.
        if (!(err instanceof ApiError && err.code === "network")) st.done = true;
      } finally {
        st.loading = false;
      }
      if (open && !st.done) watchMore();
    }

    closeMonth = () => {
      open = false;
      // A cover request cut off here may still have been stored: ask for the months again.
      if (busy && alive && visible()) setTimeout(() => alive && visible() && load(), 300);
      ctrl.abort();
      if (closePreview) closePreview();
      if (moreObserver) moreObserver.disconnect();
      thumbs.close();
      emptyCanvas(big);
      closeMonth = null;
    };

    ui.openDetail(entry.el, content, () => closeMonth && closeMonth());
    next();
  }

  // A "ready" answer is only true until the next upload or delete, so the page asks again each
  // time it comes back into view: the server walks the space again once it is marked changed
  // (after its cool-down), and the answer is one indexed query when nothing changed.
  function onVisibility() {
    if (alive && started && visible()) load();
  }
  document.addEventListener("visibilitychange", onVisibility);

  // An upload into the space shown, finished while the Library is in view (a space opened over
  // it): ask again, so "Waiting to sort photos" and then the new month show up without leaving.
  let doneTimer = 0;
  const stopDone = subscribeDone((t) => {
    if (!alive || !started || t.space !== space().id) return;
    clearTimeout(doneTimer);
    doneTimer = setTimeout(() => alive && visible() && load(), 300);
  });

  return {
    el,
    // The Library page came into view: the first ask, or the space may have changed since.
    enter() {
      if (!alive) return;
      load();
    },
    destroy() {
      alive = false;
      clearTimeout(timer);
      clearTimeout(doneTimer);
      stopDone();
      document.removeEventListener("visibilitychange", onVisibility);
      yearPick.close();
      spacePick.close();
      reset();
      if (closeMonth) closeMonth();
    },
  };
}
