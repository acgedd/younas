// Home page: the greeting, the big Upload button and the cover. Press and hold to customize.
//
// The default cover is the Sky. There are no bundled photos: Photo and Random use only what this
// user picked from their own device, kept on this device (see covers.js and store.js).

import { MAX_COVERS, decodeCover, encodeCover, paint } from "../covers.js";
import { $, $$, clear, h, icon, placeIndicator } from "../dom.js";
import { canAnimate, fx, stag } from "../motion.js";
import { coversOf, deleteCover, kvGet, kvSet, saveCover } from "../store.js";

const GREET = {
  morning: ["Good morning", "Morning, sunshine", "Rise and shine"],
  day: ["Good afternoon", "Hello there", "Nice to see you"],
  dusk: ["Good evening", "Welcome home", "Evening, friend"],
  night: ["Good night", "Sweet dreams", "Time for bed", "Rest well"],
};
const EASE = [0.22, 1, 0.36, 1];
const THUMB_SIDE = 256;
const BLUR_SIDE = 360;
const slotOf = (hour) => (hour >= 5 && hour < 11 ? "morning" : hour < 17 ? "day" : hour < 20 ? "dusk" : "night");

const newId = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`);

export function mount(page, ui) {
  const userId = ui.session.user.id;
  const cfgKey = `cover:${userId}`;
  const hintKey = `hint:${userId}`;
  page.classList.add("home");

  const cfg = { mode: "sky", pick: null, tint: true };
  let photos = []; // this user's cover records
  let randomId = null;
  let shownId = null;
  let applyTok = 0;
  let slot = slotOf(new Date().getHours());

  const hb = h("canvas", { class: "hb" });
  const hs = h("canvas", { class: "hs" });
  const cov = h("div", { class: "hcov" }, hb, hs);
  const blobs = ["b1", "b2", "b3", "b4", "b5"].map((b) => h("i", { class: `b ${b}` }));
  const greet = h("h1", { class: "greet" });
  const upBtn = h(
    "button",
    { class: "ubtn gb", type: "button", "aria-label": "Upload files", onclick: () => ui.pick() },
    h("span", { class: "gbr" }),
    h("span", { class: "ushw" }),
    h("span", { class: "uic" }, icon("upload")),
    h("span", { class: "ulb", text: "Upload" }),
  );
  const glow = h("div", { class: "uglow" });

  page.append(
    h("div", { class: "hbg", "aria-hidden": "true" }, blobs, cov, h("div", { class: "htint" }), h("div", { class: "hscrim" }), h("div", { class: "fade" })),
    h(
      "div",
      { class: "pad padrel" },
      h("div", { class: "greetwrap", "data-in": "" }, greet),
      h("div", { class: "homefoot", "data-in": "" }, h("span", { class: "halo uhalo", "aria-hidden": "true" }), upBtn, glow),
    ),
  );

  // ---- loops -------------------------------------------------------------------------------------
  blobs.forEach((el, k) => {
    ui.loop(2, fx(el, { x: [0, k % 2 ? -28 : 28, 0], y: [0, k % 2 ? 22 : -18, 0] }, { duration: 9 + k * 1.7, repeat: Infinity, ease: "easeInOut" }));
  });
  if (canAnimate()) {
    ui.loop(2, fx($(".uic", upBtn), { y: [0, -7, 0] }, { duration: 3.2, repeat: Infinity, ease: "easeInOut" }));
    ui.loop(2, fx(glow, { opacity: [0.65, 1, 0.65], scaleX: [0.88, 1.12, 0.88] }, { duration: 3.2, repeat: Infinity, ease: "easeInOut" }));
  }

  // ---- greeting ----------------------------------------------------------------------------------
  function fitGreet() {
    greet.style.fontSize = "84px";
    const width = greet.clientWidth;
    const needed = greet.scrollWidth;
    if (width && needed > width) greet.style.fontSize = `${Math.floor((84 * width) / needed)}px`;
  }

  function setGreeting() {
    const list = GREET[slot];
    const words = list[Math.floor(Math.random() * list.length)].split(" ");
    const half = Math.ceil(words.length / 2);
    const lines = words.length > 1 ? [words.slice(0, half), words.slice(half)] : [words];
    clear(greet);
    lines.forEach((line, i) => {
      if (i) greet.append(h("br"));
      line.forEach((word, j) => {
        if (j) greet.append(" ");
        greet.append(h("span", { class: "gw", text: word }));
      });
    });
    fitGreet();
  }

  function greetIn() {
    fx($$(".gw", greet), { opacity: [0, 1], filter: ["blur(14px)", "blur(0px)"], y: [12, 0] }, { duration: 0.9, delay: stag(0.12, { startDelay: 0.25 }), ease: EASE });
  }

  // ---- cover -------------------------------------------------------------------------------------
  function chosenPhoto() {
    if (cfg.mode === "pick") return photos.find((p) => p.id === cfg.pick) || null;
    if (cfg.mode === "random") return photos.find((p) => p.id === randomId) || photos[0] || null;
    return null;
  }

  let covAnims = [];
  function stopCover() {
    for (const a of covAnims) a.stop();
    covAnims = [];
  }

  function coverIn(isPhoto) {
    stopCover();
    if (!isPhoto) {
      // Through Motion once it has touched the element: it renders its own last value over a style
      // written by hand, which would bring the photo back on the Sky.
      if (canAnimate()) covAnims = [fx(cov, { opacity: 0 }, { duration: 0.25, ease: "easeOut" })];
      else cov.style.opacity = "0";
      return;
    }
    if (!canAnimate()) {
      cov.style.opacity = "1";
      hs.style.opacity = "1";
      return;
    }
    covAnims = [
      fx(cov, { opacity: [0, 1] }, { duration: 0.6, ease: "easeOut" }),
      fx(hs, { opacity: [0, 1] }, { duration: 1.6, delay: 0.3, ease: [0.4, 0, 0.2, 1] }),
      fx(hs, { scale: [1, 1.07] }, { duration: 14, ease: [0.2, 0, 0.1, 1] }),
      fx(hb, { scale: [1.15, 1.2] }, { duration: 14, ease: [0.2, 0, 0.1, 1] }),
    ];
  }

  async function applyCover(fade) {
    applyTok += 1;
    const tok = applyTok;
    let record = chosenPhoto();
    if (record && record.id !== shownId) {
      try {
        const bitmap = await decodeCover(record);
        if (tok !== applyTok) return bitmap.close();
        paint(hs, bitmap);
        paint(hb, bitmap, BLUR_SIDE);
        bitmap.close();
        shownId = record.id;
      } catch {
        record = null; // an unreadable photo falls back to the Sky
      }
    }
    if (tok !== applyTok) return;
    const isPhoto = Boolean(record);
    page.classList.toggle("photo", isPhoto);
    page.classList.toggle("tint", Boolean(cfg.tint));
    for (const t of ["morning", "day", "dusk", "night"]) page.classList.toggle(`t-${t}`, t === slot);
    page.classList.toggle("dark", !isPhoto && cfg.tint && slot === "night");
    if (fade) {
      coverIn(isPhoto);
    } else if (!covAnims.length) {
      cov.style.opacity = isPhoto ? "1" : "0";
    }
    if (!fade && isPhoto) hs.style.opacity = "1";
  }

  // ---- customize sheet ---------------------------------------------------------------------------
  const coverInput = h("input", { type: "file", accept: "image/*", hidden: true });
  page.append(coverInput);

  let sheetParts = null;
  const save = () => kvSet(cfgKey, { ...cfg });

  function syncSheet() {
    if (!sheetParts) return;
    const { source, thumbs, tintToggle, remove } = sheetParts;
    for (const b of $$("button", source)) b.classList.toggle("on", b.dataset.v === cfg.mode);
    placeIndicator(source);
    thumbs.classList.toggle("off", cfg.mode === "sky");
    for (const b of $$("button", thumbs)) b.classList.toggle("on", cfg.mode === "pick" && cfg.pick === b.dataset.k);
    tintToggle.setAttribute("aria-checked", String(Boolean(cfg.tint)));
    remove.hidden = !(cfg.mode === "pick" && photos.some((p) => p.id === cfg.pick));
  }

  async function renderThumbs() {
    if (!sheetParts) return;
    const { thumbs } = sheetParts;
    clear(thumbs);
    for (const photo of photos) {
      const canvas = h("canvas");
      const button = h("button", { type: "button", "data-k": photo.id, "aria-label": "Your photo" }, canvas);
      thumbs.append(button);
      decodeCover(photo)
        .then((bitmap) => {
          paint(canvas, bitmap, THUMB_SIDE);
          bitmap.close();
        })
        .catch(() => {});
    }
    if (photos.length < MAX_COVERS) {
      thumbs.append(h("button", { class: "dev", type: "button", "data-k": "add", "aria-label": "Choose from device" }, icon("upload", "i i22"), h("span", { text: "From device" })));
    }
    syncSheet();
  }

  function setMode(mode) {
    if (mode !== "sky" && !photos.length) return coverInput.click(); // nothing to show yet: go and pick one
    cfg.mode = mode;
    if (mode === "pick" && !photos.some((p) => p.id === cfg.pick)) cfg.pick = photos[0].id;
    if (mode === "random") randomId = photos[Math.floor(Math.random() * photos.length)].id;
    save();
    syncSheet();
    applyCover(true);
  }

  function openCustomize() {
    const source = h(
      "div",
      { class: "sgm", role: "group", "aria-label": "Cover source" },
      h("span", { class: "ind" }),
      [
        ["random", "Random"],
        ["pick", "Photo"],
        ["sky", "Sky"],
      ].map(([v, label]) => h("button", { type: "button", "data-v": v, text: label, onclick: () => setMode(v) })),
    );
    const thumbs = h("div", {
      class: "thumbs",
      onclick: (e) => {
        const b = e.target.closest("button");
        if (!b) return;
        if (b.dataset.k === "add") return coverInput.click();
        cfg.mode = "pick";
        cfg.pick = b.dataset.k;
        save();
        syncSheet();
        applyCover(true);
      },
    });
    const tintToggle = h("button", {
      class: "tgl",
      type: "button",
      role: "switch",
      "aria-label": "Time of day tint",
      onclick: () => {
        cfg.tint = !cfg.tint;
        save();
        syncSheet();
        applyCover(false);
      },
    });
    const remove = h("button", {
      class: "ghost",
      type: "button",
      text: "Remove this photo",
      onclick: async () => {
        const id = cfg.pick;
        photos = photos.filter((p) => p.id !== id);
        await deleteCover(id);
        cfg.mode = photos.length ? "pick" : "sky";
        cfg.pick = photos.length ? photos[0].id : null;
        shownId = null;
        save();
        await renderThumbs();
        applyCover(true);
      },
    });
    sheetParts = { source, thumbs, tintToggle, remove };
    ui.openSheet(
      "Customize Home",
      h("div", { class: "stitle", text: "Home cover" }),
      source,
      thumbs,
      remove,
      h("div", { class: "trow" }, h("span", {}, h("b", { text: "Time of day tint" }), h("small", { text: "Warmer mornings, deeper nights" })), tintToggle),
      h("button", { class: "sdone", type: "button", text: "Done", onclick: () => ui.closeSheet() }),
    );
    renderThumbs();
    requestAnimationFrame(() => placeIndicator(source));
  }

  coverInput.addEventListener("change", async () => {
    const file = coverInput.files && coverInput.files[0];
    coverInput.value = "";
    if (!file) return;
    if (photos.length >= MAX_COVERS) return ui.toast(`You can keep ${MAX_COVERS} photos. Remove one first.`);
    try {
      const encoded = await encodeCover(file);
      const record = { id: newId(), user: userId, ...encoded };
      await saveCover(record);
      photos = [...photos, record];
      cfg.mode = "pick";
      cfg.pick = record.id;
      save();
      await renderThumbs();
      await applyCover(true);
    } catch {
      ui.toast("Could not open that photo");
    }
  });

  // Press and hold Home to customize.
  let hold = null;
  const stopHold = () => {
    if (hold) clearTimeout(hold.id);
    hold = null;
  };
  page.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button")) return;
    const { clientX: x, clientY: y } = e;
    hold = {
      x,
      y,
      id: setTimeout(() => {
        hold = null;
        fx(page, { scale: [1, 0.985, 1] }, { duration: 0.35, ease: "easeOut" });
        openCustomize();
      }, 520),
    };
  });
  page.addEventListener("pointermove", (e) => {
    if (hold && Math.hypot(e.clientX - hold.x, e.clientY - hold.y) > 10) stopHold();
  });
  for (const name of ["pointerup", "pointercancel", "pointerleave"]) page.addEventListener(name, stopHold);
  page.addEventListener("contextmenu", (e) => e.preventDefault());

  // ---- start -------------------------------------------------------------------------------------
  setGreeting();
  applyCover(false);
  if (document.fonts) document.fonts.ready.then(fitGreet);

  const ready = (async () => {
    const [savedCfg, records] = await Promise.all([kvGet(cfgKey), coversOf(userId)]);
    if (savedCfg) Object.assign(cfg, savedCfg);
    photos = records;
    if (photos.length) randomId = photos[Math.floor(Math.random() * photos.length)].id;
    await applyCover(false);
  })();

  const clock = setInterval(() => {
    const next = slotOf(new Date().getHours());
    if (next === slot) return;
    slot = next;
    applyCover(false);
    setGreeting();
  }, 60000);

  let hintTimer = 0;
  let gone = false;
  async function firstRunHint() {
    if (await kvGet(hintKey)) return;
    if (gone) return;
    clearTimeout(hintTimer);
    hintTimer = setTimeout(() => {
      if (ui.current() !== 2 || ui.busy()) return;
      ui.toast("Press and hold to change the cover");
      kvSet(hintKey, true);
    }, 2600);
  }

  return {
    enter() {
      fx(blobs, { opacity: [0, 1] }, { duration: 1.2, delay: stag(0.08) });
      ready.then(() => coverIn(Boolean(chosenPhoto())));
      greetIn();
      firstRunHint();
    },
    resize: fitGreet,
    destroy() {
      gone = true;
      stopCover();
      clearInterval(clock);
      clearTimeout(hintTimer);
      stopHold();
      applyTok += 1;
    },
  };
}
