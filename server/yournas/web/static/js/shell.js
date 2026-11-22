// The app frame from the approved prototype: five pages on a vertical track, the wheel menu, the
// card-to-detail overlay, the bottom sheet, the toast and the file picker. Pages live in views/ and
// get this frame as `ui`.
//
// iOS Safari lessons kept from the prototype (see docs/DESIGN-NOTES.md#ios-safari-notes): opaque wheel backdrop and hidden
// track once the wheel is open; loops run only on the visible page; press feedback only after a
// 90 ms hold; the glowing buttons get a painted ripple, not a transform.

import { $, $$, clamp, clear, h, icon, s } from "./dom.js";
import { ApiError, api, errorTag } from "./api.js";
import { kvGet, kvSet } from "./store.js";
import { canAnimate, done, fx, reduced, stag, tween } from "./motion.js";
import { enqueueUploads } from "./transfers.js";
import * as home from "./views/home.js";
import * as library from "./views/library.js";
import * as status from "./views/status.js";
import * as storage from "./views/storage.js";
import * as upload from "./views/upload.js";

const PAGES = [
  { id: "status", label: "Status", icon: "status", view: status },
  { id: "library", label: "Library", icon: "gallery", view: library },
  { id: "home", label: "Home", icon: "home", view: home },
  { id: "upload", label: "Upload", icon: "upload", view: upload },
  { id: "storage", label: "Storage", icon: "storage", view: storage },
];
const HOME = 2;
const UPLOAD = 3;
const ROW = 64;
const RAD = 420;
const EASE = [0.22, 1, 0.36, 1];

export function createShell(root, session, { onLogout }) {
  const aborter = new AbortController();
  const { signal } = aborter;
  const app = root;
  const loops = [];
  let cur = HOME;
  let wheelOpen = false;
  let sheetOpen = false;
  let timers = [];

  const track = h("div", { class: "track now" });
  const handle = h("button", { class: "handle", type: "button", "aria-label": "Open menu" });
  const ov = h("div", { class: "ov", hidden: true });
  const toastEl = h("div", { class: "toast", role: "status" });
  const picker = h("input", { type: "file", multiple: true, hidden: true });

  // ---- wheel markup ------------------------------------------------------------------------------
  const arc = s("svg", { class: "arc", "aria-hidden": "true" });
  const wlist = h("div", { class: "wlist" });
  const wx = h("button", { class: "wx", type: "button", "aria-label": "Close menu" }, icon("x"));
  const wgo = h("button", { class: "wgo", type: "button", text: "Open" });
  const wbd = h("div", { class: "bd" });
  const wheel = h("div", { class: "wheel", hidden: true, role: "dialog", "aria-label": "Menu" }, wbd, h("div", { class: "wglow" }), arc, wlist, wx, wgo);
  const witems = PAGES.map((p, i) => {
    const item = h(
      "button",
      { class: "wi", type: "button", "aria-label": p.label, "data-i": i },
      h("span", { class: "in" }, h("span", { class: "lb", text: p.label }), h("span", { class: "ic" }, icon(p.icon))),
    );
    wlist.append(item);
    return item;
  });

  // ---- sheet markup ------------------------------------------------------------------------------
  const sbd = h("div", { class: "sbd" });
  const spanel = h("div", { class: "spanel", role: "dialog" });
  const sheet = h("div", { class: "sheet", hidden: true }, sbd, spanel);

  app.append(track, handle, ov, wheel, sheet, toastEl, picker);

  const pages = PAGES.map((p, i) => {
    const section = h("section", { class: "page", "aria-label": p.label, style: { top: `${i * 100}%` } });
    track.append(section);
    return section;
  });

  // ---- toast -------------------------------------------------------------------------------------
  function toast(text) {
    toastEl.textContent = text;
    if (canAnimate()) {
      fx(toastEl, { opacity: [0, 1, 1, 0], y: [14, 0, 0, -8] }, { duration: 2.6, times: [0, 0.12, 0.85, 1] });
    } else {
      toastEl.style.opacity = "1";
      timers.push(setTimeout(() => (toastEl.style.opacity = "0"), 2000));
    }
  }

  // ---- track -------------------------------------------------------------------------------------
  const H = () => app.clientHeight;
  const setY = (y) => {
    track.style.transform = `translate3d(0,${y}px,0)`;
  };

  let views = [];

  function syncLoops() {
    const live = (k) => k === cur && !wheelOpen;
    for (const { pg, a } of loops) {
      try {
        if (live(pg)) a.play();
        else a.pause();
      } catch {
        /* a finished animation has nothing to toggle */
      }
    }
    app.classList.toggle("still", wheelOpen || (cur !== HOME && cur !== UPLOAD));
    app.classList.toggle("wopen", wheelOpen);
    pages.forEach((p, k) => p.classList.toggle("act", k === cur));
    views.forEach((v, k) => v.setActive && v.setActive(live(k)));
  }

  function splitTitle(title) {
    if (title.dataset.split) return;
    title.dataset.split = "1";
    for (const node of [...title.childNodes]) {
      if (node.nodeType !== Node.TEXT_NODE) continue;
      const words = node.textContent.split(/(\s+)/).filter(Boolean);
      node.replaceWith(...words.map((w) => (/^\s+$/.test(w) ? " " : h("span", { class: "w", text: w }))));
    }
  }

  function enter(i) {
    const p = pages[i];
    if (canAnimate()) {
      for (const title of $$(".h1", p)) {
        splitTitle(title);
        fx($$(".w", title), { opacity: [0, 1], y: [34, 0], rotate: [3, 0] }, { duration: 0.8, delay: stag(0.09, { startDelay: 0.12 }), ease: EASE });
      }
    }
    fx($$("[data-in]", p), { opacity: [0, 1], y: [22, 0] }, { duration: 0.6, delay: stag(0.045), ease: EASE });
    if (views[i] && views[i].enter) views[i].enter();
  }

  function goTo(index, instant) {
    const i = clamp(index, 0, PAGES.length - 1);
    track.classList.toggle("now", Boolean(instant || reduced));
    setY(-i * H());
    const changed = i !== cur;
    cur = i;
    syncPageAccess();
    if (changed) enter(i);
    syncLoops();
  }

  function syncPageAccess() {
    pages.forEach((p, k) => p.setAttribute("aria-hidden", k === cur ? "false" : "true"));
  }
  // Focus moving to a page out of view makes the browser scroll this clipped frame to reach it. (Not
  // `inert`: Chromium stops hit-testing a page's animated rows after it comes back from inert.)
  app.addEventListener("scroll", () => {
    app.scrollTop = 0;
    app.scrollLeft = 0;
  }, { signal });

  window.addEventListener(
    "resize",
    () => {
      track.classList.add("now");
      setY(-cur * H());
      views.forEach((v) => v.resize && v.resize());
    },
    { signal },
  );

  // ---- gestures: a left swipe opens the wheel ----------------------------------------------------
  let gesture = null;
  app.addEventListener(
    "touchstart",
    (e) => {
      if (wheelOpen || sheetOpen || !ov.hidden) {
        gesture = null;
        return;
      }
      const t = e.touches[0];
      gesture = { x: t.clientX, y: t.clientY, mode: null, dx: 0, dy: 0 };
    },
    { passive: true, signal },
  );
  app.addEventListener(
    "touchmove",
    (e) => {
      if (!gesture) return;
      const t = e.touches[0];
      gesture.dx = t.clientX - gesture.x;
      gesture.dy = t.clientY - gesture.y;
      if (!gesture.mode) {
        if (Math.abs(gesture.dx) < 9 && Math.abs(gesture.dy) < 9) return;
        gesture.mode = Math.abs(gesture.dx) > Math.abs(gesture.dy) * 1.2 ? "h" : "n";
      }
    },
    { passive: true, signal },
  );
  app.addEventListener(
    "touchend",
    () => {
      if (gesture && gesture.mode === "h" && gesture.dx < -50) openWheel();
      gesture = null;
    },
    { signal },
  );
  app.addEventListener(
    "touchcancel",
    () => {
      gesture = null;
    },
    { signal },
  );

  // ---- wheel -------------------------------------------------------------------------------------
  let sel = cur;
  let selR = -1;
  let wAnim = null;
  let wClose = null;
  let wFullT = 0;
  let wd = null;
  let wPend = null;
  let wRaf = 0;

  function drawArc() {
    const w = app.clientWidth;
    const height = app.clientHeight;
    const cx = height / 2;
    const ic0 = $(".ic", witems[0]);
    const x0 = w - parseFloat(getComputedStyle(witems[0]).right) - ic0.offsetWidth / 2;
    let d = "";
    for (let dy = -height / 2; dy <= height / 2; dy += 8) {
      d += `${d ? "L" : "M"}${(x0 + (dy * dy) / (2 * RAD)).toFixed(1)} ${(cx + dy).toFixed(1)}`;
    }
    clear(arc);
    arc.append(s("path", { d, fill: "none", stroke: "rgba(160,200,255,.6)", "stroke-width": 1 }));
  }

  function layout(k) {
    sel = k;
    const r = Math.round(k);
    witems.forEach((item, i) => {
      const d = i - k;
      const dy = d * ROW;
      const x = (dy * dy) / (2 * RAD);
      item.style.transform = `translate3d(${x.toFixed(2)}px,${dy.toFixed(2)}px,0)`;
      item.style.opacity = clamp(1 - Math.abs(d) * 0.2, 0.12, 1).toFixed(3);
    });
    if (r !== selR) {
      selR = r;
      witems.forEach((item, i) => item.classList.toggle("sel", i === r));
      wgo.textContent = `Open ${PAGES[r].label}`;
    }
  }

  const queueLayout = (k) => {
    wPend = k;
    if (!wRaf) {
      wRaf = requestAnimationFrame(() => {
        wRaf = 0;
        if (wPend !== null) {
          layout(wPend);
          wPend = null;
        }
      });
    }
  };

  function openWheel() {
    if (wheelOpen) return;
    wheelOpen = true;
    if (wClose && wClose.stop) wClose.stop();
    wClose = null;
    wheel.hidden = false;
    if (canAnimate()) fx(wheel, { opacity: 1 }, { duration: 0.12 });
    else wheel.style.opacity = "";
    drawArc();
    if (wAnim && wAnim.stop) wAnim.stop();
    wd = null;
    layout(cur);
    syncLoops();
    handle.hidden = true;
    fx(wbd, { opacity: [0, 1] }, { duration: 0.3 });
    clearTimeout(wFullT);
    wFullT = setTimeout(() => {
      if (wheelOpen) app.classList.add("wfull");
    }, 320);
    witems.forEach((item, i) => fx($(".in", item), { opacity: [0, 1], x: [90, 0] }, { duration: 0.55, delay: 0.04 * i, ease: EASE }));
    fx(wgo, { opacity: [0, 1], y: [24, 0] }, { duration: 0.45, delay: 0.15, ease: EASE });
    fx(arc, { opacity: [0, 1] }, { duration: 0.5 });
    const path = $("path", arc);
    if (path && canAnimate()) {
      path.setAttribute("pathLength", "1");
      path.setAttribute("stroke-dasharray", "1 1");
      tween(1, 0, { duration: 0.9, ease: EASE, onUpdate: (v) => path.setAttribute("stroke-dashoffset", v) });
    }
    wgo.focus({ preventScroll: true });
  }

  function closeWheel(then) {
    if (!wheelOpen) return;
    wheelOpen = false;
    wd = null;
    clearTimeout(wFullT);
    app.classList.remove("wfull");
    const finish = () => {
      if (wheelOpen) return;
      wheel.hidden = true;
      wheel.style.opacity = "";
      handle.hidden = false;
      syncLoops();
      if (then) then();
    };
    if (!canAnimate()) return finish();
    const a = fx(wheel, { opacity: [1, 0] }, { duration: 0.22 });
    wClose = a;
    done(a).then(() => {
      if (wClose === a) wClose = null;
      finish();
    });
  }

  function snapTo(target) {
    if (wAnim && wAnim.stop) wAnim.stop();
    wAnim = tween(sel, target, { duration: 0.36, ease: EASE, onUpdate: layout });
  }

  function go(i) {
    closeWheel(() => goTo(i));
    goTo(i);
  }

  wheel.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".wx,.wgo")) return;
    wd = { y: e.clientY, s: sel, moved: false, target: e.target };
    wheel.setPointerCapture(e.pointerId);
    if (wAnim && wAnim.stop) wAnim.stop();
  });
  wheel.addEventListener("pointermove", (e) => {
    if (!wd) return;
    const dy = e.clientY - wd.y;
    if (Math.abs(dy) > 6) wd.moved = true;
    if (wd.moved) queueLayout(clamp(wd.s - dy / ROW, 0, PAGES.length - 1));
  });
  wheel.addEventListener("pointerup", () => {
    if (!wd) return;
    const d = wd;
    wd = null;
    if (wPend !== null) {
      layout(wPend);
      wPend = null;
    }
    if (d.moved) return snapTo(Math.round(sel));
    const item = d.target.closest && d.target.closest(".wi");
    if (!item) return closeWheel();
    const i = Number(item.dataset.i);
    if (i === Math.round(sel)) go(i);
    else snapTo(i);
  });
  for (const name of ["pointercancel", "lostpointercapture"]) {
    wheel.addEventListener(name, () => {
      if (!wd) return;
      wd = null;
      snapTo(Math.round(clamp(sel, 0, PAGES.length - 1)));
    });
  }
  // A keyboard press on a row has no pointer behind it (detail 0).
  wlist.addEventListener("click", (e) => {
    const item = e.target.closest(".wi");
    if (item && e.detail === 0) go(Number(item.dataset.i));
  });
  wgo.addEventListener("click", () => go(Math.round(sel)));
  wx.addEventListener("click", () => closeWheel());
  handle.addEventListener("click", () => openWheel());
  fx(handle, { scaleY: [1, 1.6, 1], opacity: [0.6, 1, 0.75] }, { duration: 1.4, repeat: 2, delay: 1.2 });

  // ---- detail overlay ----------------------------------------------------------------------------
  let ovFrom = null;
  let ovTok = 0;
  let ovAnims = [];
  let ovOnClose = null;

  const ovStop = () => {
    for (const a of ovAnims) {
      try {
        if (a && a.stop) a.stop();
      } catch {
        /* already finished */
      }
    }
    ovAnims = [];
  };

  const rectIn = (el) => {
    const r = el.getBoundingClientRect();
    const a = app.getBoundingClientRect();
    return `inset(${Math.max(0, r.top - a.top)}px ${Math.max(0, a.right - r.right)}px ${Math.max(0, a.bottom - r.bottom)}px ${Math.max(0, r.left - a.left)}px round 28px)`;
  };

  function openDetail(card, content, onClose) {
    ovTok += 1;
    ovStop();
    ov.style.opacity = "";
    ov.style.clipPath = "";
    ovFrom = card;
    ovOnClose = onClose || null;
    clear(ov);
    ov.append(content);
    ov.hidden = false;
    handle.hidden = true;
    card.style.transform = ""; // measure the card unpressed
    fx(ov, { clipPath: [rectIn(card), "inset(0px 0px 0px 0px round 0px)"] }, { duration: 0.6, ease: EASE });
    fx(ov, { opacity: [0, 1] }, { duration: 0.22, ease: "linear" });
    fx($$(".htitle", ov), { opacity: [0, 1], y: [24, 0] }, { duration: 0.6, delay: 0.2, ease: EASE });
  }

  function closeDetail() {
    if (ov.hidden) return;
    ovTok += 1;
    const tok = ovTok;
    ovStop();
    const a = fx(ov, { clipPath: ["inset(0px 0px 0px 0px round 0px)", ovFrom ? rectIn(ovFrom) : "inset(50% 50% 50% 50% round 28px)"] }, { duration: 0.42, ease: [0.4, 0, 0.2, 1] });
    // Hand off to the real card underneath: fade while the clip lands, so the hero never snaps.
    ovAnims = [a, fx(ov, { opacity: [1, 1, 0] }, { duration: 0.42, times: [0, 0.45, 1], ease: "linear" })];
    const finish = () => {
      if (tok !== ovTok) return;
      ovAnims = [];
      ov.hidden = true;
      clear(ov);
      ov.style.clipPath = "";
      ov.style.opacity = "";
      if (!wheelOpen && !sheetOpen) handle.hidden = false;
      if (ovOnClose) ovOnClose();
      ovOnClose = null;
    };
    if (canAnimate()) done(a).then(finish);
    else finish();
  }

  // ---- bottom sheet ------------------------------------------------------------------------------
  let sheetTok = 0;

  function openSheet(label, ...content) {
    if (sheetOpen || wheelOpen) return;
    sheetOpen = true;
    sheetTok += 1;
    clear(spanel);
    spanel.setAttribute("aria-label", label);
    spanel.append(h("div", { class: "sgrab" }), ...content);
    sheet.hidden = false;
    handle.hidden = true;
    spanel.style.transform = "";
    sbd.style.opacity = "";
    fx(sbd, { opacity: [0, 1] }, { duration: 0.3 });
    fx(spanel, { y: [spanel.offsetHeight, 0] }, { duration: 0.5, ease: EASE });
  }

  function closeSheet(from = 0) {
    if (!sheetOpen) return;
    sheetOpen = false;
    sheetTok += 1;
    const tok = sheetTok;
    const a = fx(spanel, { y: [from, spanel.offsetHeight + 20] }, { duration: 0.35, ease: [0.4, 0, 0.2, 1] });
    fx(sbd, { opacity: [Number(getComputedStyle(sbd).opacity), 0] }, { duration: 0.3 });
    const finish = () => {
      if (tok !== sheetTok) return; // another sheet opened while this one was closing
      sheet.hidden = true;
      spanel.style.transform = "";
      clear(spanel);
      if (!wheelOpen && ov.hidden) handle.hidden = false;
    };
    if (canAnimate()) done(a).then(finish);
    else finish();
  }

  sbd.addEventListener("click", () => closeSheet());
  // Drag down to dismiss.
  let sd = null;
  spanel.addEventListener("pointerdown", (e) => {
    if (e.target.closest(".thumbs,.slist,button,input,label")) return;
    sd = { y: e.clientY, t: performance.now(), dy: 0 };
    try {
      spanel.setPointerCapture(e.pointerId);
    } catch {
      /* the pointer is already gone */
    }
  });
  spanel.addEventListener("pointermove", (e) => {
    if (!sd) return;
    const raw = e.clientY - sd.y;
    sd.dy = raw > 0 ? raw : raw * 0.2;
    spanel.style.transform = `translateY(${sd.dy}px)`;
    sbd.style.opacity = String(clamp(1 - sd.dy / 420, 0, 1));
  });
  const sheetEnd = () => {
    if (!sd) return;
    const { dy, t } = sd;
    sd = null;
    const v = dy / Math.max(1, performance.now() - t);
    if (dy > 110 || v > 0.6) return closeSheet(dy);
    fx(spanel, { y: [dy, 0] }, { duration: 0.4, ease: EASE });
    fx(sbd, { opacity: [Number(sbd.style.opacity) || 1, 1] }, { duration: 0.3 });
  };
  spanel.addEventListener("pointerup", sheetEnd);
  spanel.addEventListener("pointercancel", sheetEnd);

  window.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Escape") {
        if (sheetOpen) closeSheet();
        else if (wheelOpen) closeWheel();
        else if (!ov.hidden) closeDetail();
      } else if (wheelOpen && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
        e.preventDefault();
        snapTo(clamp(Math.round(sel) + (e.key === "ArrowUp" ? -1 : 1), 0, PAGES.length - 1));
      }
    },
    { signal },
  );

  // ---- press feedback ----------------------------------------------------------------------------
  if (canAnimate()) {
    const PRESS = ".mcard,.seg button,.ghost,.frow";
    let pressed = null;
    let pressTimer = 0;
    let pressX = 0;
    let pressY = 0;
    let pressOn = false;
    const release = () => {
      clearTimeout(pressTimer);
      if (!pressed) return;
      const t = pressed;
      pressed = null;
      if (pressOn) fx(t, { scale: 1 }, { duration: 0.3, ease: EASE });
      pressOn = false;
    };
    document.addEventListener(
      "pointerdown",
      (e) => {
        const t = e.target.closest(PRESS);
        if (!t || t.closest(".wheel")) return;
        pressed = t;
        pressOn = false;
        pressX = e.clientX;
        pressY = e.clientY;
        clearTimeout(pressTimer);
        pressTimer = setTimeout(() => {
          if (pressed === t) {
            pressOn = true;
            fx(t, { scale: 0.97 }, { duration: 0.14, ease: "easeOut" });
          }
        }, 90);
      },
      { passive: true, signal },
    );
    document.addEventListener(
      "pointermove",
      (e) => {
        if (pressed && Math.hypot(e.clientX - pressX, e.clientY - pressY) > 8) release();
      },
      { passive: true, signal },
    );
    for (const name of ["pointerup", "pointercancel"]) document.addEventListener(name, release, { passive: true, signal });
  }

  // ---- glowing buttons: painted ripple, no transforms (see .gb in the CSS) ----------------------
  document.addEventListener(
    "pointerdown",
    (e) => {
      const btn = e.target.closest(".gb");
      if (!btn) return;
      let z = $(".ripz", btn);
      if (!z) {
        z = h("span", { class: "ripz" });
        btn.append(z);
      }
      const r = btn.getBoundingClientRect();
      const x = e.clientX - r.left;
      const y = e.clientY - r.top;
      const R = Math.hypot(Math.max(x, r.width - x), Math.max(y, r.height - y));
      if (btn._ripple && btn._ripple.stop) btn._ripple.stop();
      const paint = (v, k = 1) => {
        const rad = 12 + (R - 12) * v;
        const a = (0.34 * (1 - v) + 0.06) * k;
        z.style.background = `radial-gradient(circle at ${x}px ${y}px, rgba(190,220,255,${a.toFixed(3)}) 0, rgba(190,220,255,${(a * 0.5).toFixed(3)}) ${(rad * 0.6).toFixed(1)}px, rgba(190,220,255,0) ${rad.toFixed(1)}px)`;
      };
      if (!canAnimate()) {
        paint(0.4);
        timers.push(setTimeout(() => (z.style.background = ""), 160));
        return;
      }
      const grow = tween(0, 1, { duration: 0.7, ease: EASE, onUpdate: paint });
      btn._ripple = grow;
      done(grow).then(() => {
        if (btn._ripple !== grow) return;
        const fade = tween(1, 0, { duration: 0.35, onUpdate: (k) => paint(1, k) });
        btn._ripple = fade;
        done(fade).then(() => {
          if (btn._ripple === fade) z.style.background = "";
        });
      });
    },
    { passive: true, signal },
  );

  // ---- where uploads go --------------------------------------------------------------------------
  // The default is a "Photos" folder in My files (the owner's choice, 2026-11-08). The app makes
  // that folder when it is the destination, so it is there before the first upload. A folder the
  // person chose wins. A choice saved before this default (no `v`) is ignored once, so every
  // account starts in Photos.
  const destKey = `dest:${session.user.id}`;
  const writable = session.spaces.filter((space) => space.access === "write");
  const PHOTOS = "Photos";
  const defaultDest = writable.some((space) => space.id === "home")
    ? { space: "home", dir: [PHOTOS] }
    : writable.length
      ? { space: writable[0].id, dir: [] }
      : null;
  let dest = defaultDest;
  const destListeners = new Set();
  let pending = null;

  function setDest(next, save = true) {
    dest = next;
    if (save) kvSet(destKey, { space: next.space, dir: next.dir, v: 2 });
    for (const fn of destListeners) fn(next);
  }

  const isPhotos = (where) => where.space === "home" && where.dir.length === 1 && where.dir[0] === PHOTOS;

  // Already there is fine: an existing folder (in any casing, on NTFS) answers 409.
  async function ensurePhotos(where) {
    if (!isPhotos(where)) return;
    try {
      await api.mkdir(where.space, PHOTOS);
    } catch (err) {
      if (!(err instanceof ApiError && err.code === "already_exists")) throw err;
    }
  }

  kvGet(destKey).then((saved) => {
    if (saved && saved.v === 2 && Array.isArray(saved.dir) && writable.some((space) => space.id === saved.space)) {
      setDest({ space: saved.space, dir: saved.dir }, false);
    }
    if (dest && isPhotos(dest)) ensurePhotos(dest).catch(() => {}); // tried again before an upload
  });

  // Must run inside the tap: iOS opens a file picker only from a user gesture.
  function pick(target) {
    const where = target || dest;
    if (!where) return toast("You have no folder you can upload to");
    pending = where;
    picker.click();
  }

  picker.addEventListener("change", () => {
    const chosen = Array.from(picker.files || []);
    picker.value = "";
    if (!chosen.length || !pending) return;
    const where = pending;
    // The Photos folder may have been deleted since the app opened: an upload needs its folder.
    ensurePhotos(where).then(
      () => {
        enqueueUploads(chosen, where.space, where.dir);
        if (ov.hidden) goTo(UPLOAD);
        toast(`${chosen.length} ${chosen.length === 1 ? "file" : "files"} added to the queue`);
      },
      (err) => toast(`Could not make the Photos folder: ${errorTag(err)}`),
    );
  });

  // ---- pages -------------------------------------------------------------------------------------
  const ui = {
    session,
    signal,
    toast,
    goTo,
    current: () => cur,
    busy: () => wheelOpen || sheetOpen || !ov.hidden,
    loop(pg, a) {
      if (a) loops.push({ pg, a });
      return a;
    },
    openDetail,
    closeDetail,
    openSheet,
    closeSheet,
    pick,
    getDest: () => dest,
    setDest,
    onDest(fn) {
      destListeners.add(fn);
    },
    logout: onLogout,
  };

  views = PAGES.map((p, i) => p.view.mount(pages[i], ui) || {});
  setY(-cur * H());
  syncPageAccess();
  syncLoops();

  return {
    // Called once the launch skeleton has gone.
    reveal() {
      enter(cur);
      syncLoops();
    },
    destroy() {
      aborter.abort();
      for (const t of timers) clearTimeout(t);
      timers = [];
      clearTimeout(wFullT);
      for (const { a } of loops) {
        try {
          if (a.stop) a.stop();
        } catch {
          /* already finished */
        }
      }
      for (const v of views) if (v.destroy) v.destroy();
      for (const el of [track, handle, ov, wheel, sheet, toastEl, picker]) el.remove();
      app.classList.remove("still", "wopen", "wfull");
    },
  };
}
