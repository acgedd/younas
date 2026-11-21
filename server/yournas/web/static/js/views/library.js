// Library page. REAL: photos by month (views/photos.js, from the server's index), spaces from /auth/me,
// listing, new folder, delete, upload, download and a photo preview through the API.
//
// Differences from the prototype that follow from the real API: the server has no search, so the box
// filters what is already loaded; a folder has no item count; delete never recurses, so a non-empty
// folder is refused by the server. Cards have no photo: the prototype's images were placeholders.

import { ApiError, api, errorTag } from "../api.js";
import { $$, chars, clear, h, icon, placeIndicator } from "../dom.js";
import { bytes, extOf, when } from "../format.js";
import { fx, stag } from "../motion.js";
import { isPhoto, openPreview } from "../preview.js";
import { createThumbLoader, startThumbJob, stopThumbJob, subscribeThumb, subscribeThumbJob, thumbGaveUp, thumbJobNow } from "../thumbs.js";
import { MAX_BROWSER_DOWNLOAD_BYTES, startDownload, subscribeDone } from "../transfers.js";
import { createPhotos } from "./photos.js";

const EASE = [0.22, 1, 0.36, 1];
const SEARCH_FROM = 4; // a search box over a couple of cards is only clutter

// Survives closing the overlay, so a space reopens where the user left it.
const remembered = { user: null, dirs: new Map() };

export function mount(page, ui) {
  const { spaces, user } = ui.session;
  if (remembered.user !== user.id) {
    // A different account signed in: never start in the previous user's folder.
    remembered.user = user.id;
    remembered.dirs = new Map();
  }

  // ---- cards -------------------------------------------------------------------------------------
  const nameEls = [];

  function fitNames() {
    for (const el of nameEls) {
      const width = el.parentElement.clientWidth;
      if (!width) continue;
      el.style.fontSize = "100px";
      const natural = el.getBoundingClientRect().width;
      if (natural) el.style.fontSize = `${Math.min(150, Math.floor((100 * (width * 0.94)) / natural))}px`;
    }
  }

  function card(space, i) {
    const access = space.access === "write" ? "Read and write" : "Read only";
    const name = h("span", { class: "mname", "aria-hidden": "true" }, chars(space.name));
    nameEls.push(name);
    const el = h(
      "button",
      { class: `mcard ld tone${i % 5}`, type: "button", "data-in": "", "aria-label": `${space.name}, ${access}` },
      h("div", { class: "shade" }),
      h("span", { class: "chip glass", text: access }),
      h("span", { class: "dots glass" }, icon("dots")),
      name,
    );
    el.addEventListener("click", () => openSpace(el, space));
    return el;
  }

  const cards = spaces.map((space, i) => ({ space, el: card(space, i) }));
  const search = h("input", { type: "search", placeholder: "Search spaces", "aria-label": "Search spaces", autocomplete: "off" });
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    for (const { space, el } of cards) el.hidden = Boolean(q) && !space.name.toLowerCase().includes(q);
  });

  let seenObserver = null;
  if ("IntersectionObserver" in window) {
    seenObserver = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.intersectionRatio >= 0.4) e.target.classList.add("seen");
          else if (!e.isIntersecting) e.target.classList.remove("seen");
        }
      },
      { root: page, threshold: [0, 0.4] },
    );
  }
  // Fit and reveal a card's name like the space cards. Returns the function that lets go of it.
  const track = (el, nameEl) => {
    if (nameEl) nameEls.push(nameEl);
    if (seenObserver) seenObserver.observe(el);
    else el.classList.add("seen");
    requestAnimationFrame(fitNames);
    return () => {
      const at = nameEls.indexOf(nameEl);
      if (at >= 0) nameEls.splice(at, 1);
      if (seenObserver) seenObserver.unobserve(el);
    };
  };

  const photos = createPhotos({ ui, spaces, user, page, track });

  // Photos / Files: jumps to its half of the page, like the prototype.
  const seg = h("div", { class: "seg", role: "group", "aria-label": "Jump to", "data-in": "" }, h("span", { class: "ind" }));
  const filesHead = h(
    "div",
    { class: "row sec", id: "sec-files" },
    h("h2", { class: "h2", text: "Files" }),
    h("span", { class: "pill", text: `${spaces.length} ${spaces.length === 1 ? "space" : "spaces"}` }),
  );
  for (const [label, target] of [
    ["Photos", photos.el],
    ["Files", filesHead],
  ]) {
    seg.append(
      h("button", {
        type: "button",
        text: label,
        class: label === "Photos" ? "on" : "",
        "aria-current": label === "Photos" ? "true" : null,
        onclick: (e) => {
          for (const b of $$("button", seg)) {
            b.classList.toggle("on", b === e.currentTarget);
            if (b === e.currentTarget) b.setAttribute("aria-current", "true");
            else b.removeAttribute("aria-current");
          }
          placeIndicator(seg);
          target.scrollIntoView({ behavior: "smooth", block: "start" });
        },
      }),
    );
  }

  page.append(
    h(
      "div",
      { class: "pad" },
      h("div", { class: "row", "data-in": "" }, h("h1", { class: "h1", text: "Library" })),
      seg,
      photos.el,
      filesHead,
      spaces.length >= SEARCH_FROM ? h("label", { class: "search", "data-in": "" }, icon("search", "i i18"), search) : null,
      cards.length ? h("div", { class: "cards" }, cards.map((c) => c.el)) : h("p", { class: "hint", text: "This account has no spaces yet. Ask the owner to share one." }),
    ),
  );
  for (const c of cards) track(c.el, null);
  requestAnimationFrame(() => placeIndicator(seg));

  if (document.fonts) document.fonts.ready.then(fitNames);

  // ---- a space, opened: the detail overlay -------------------------------------------------------
  let closeFolder = null;

  function openSpace(cardEl, space) {
    if (closeFolder) closeFolder(); // tapped while the previous one was still closing
    const writable = space.access === "write";
    const st = { dir: remembered.dirs.get(space.id) || [], items: [], cursor: null, loading: false, error: null, selected: null, confirming: false, creating: false, filter: "" };
    let seq = 0;
    let alive = true;
    let reloadTimer = 0;
    let firstDraw = true;
    let closePreview = null;
    const thumbs = createThumbLoader(space.id, () => content);
    thumbs.open(st.dir);

    const title = h("div", { class: "htitle" });
    const crumbs = h("span", { class: "eyebrow crumbs" });
    const list = h("div", { class: "flist" });
    const tools = h("div", { class: "acts" });
    const formSlot = h("div");
    const filter = h("input", { type: "search", placeholder: "Filter this folder", "aria-label": "Filter this folder", autocomplete: "off" });

    const path = (name) => [...st.dir, name].join("/");

    function setTitle() {
      const text = st.dir.length ? st.dir[st.dir.length - 1] : space.name;
      clear(title);
      title.append(...chars(text));
      title.style.fontSize = "";
      requestAnimationFrame(() => {
        const width = title.clientWidth;
        if (width && title.scrollWidth > width) title.style.fontSize = `${Math.max(22, Math.floor((54 * width) / title.scrollWidth))}px`;
      });
    }

    // `quiet` keeps what is on screen until the answer arrives (a refresh after an upload).
    async function load({ more = false, quiet = false } = {}) {
      seq += 1;
      const mine = seq;
      st.loading = true;
      st.error = null;
      if (!more && !quiet) {
        st.items = [];
        st.cursor = null;
        st.selected = null;
        st.confirming = false;
      }
      draw();
      try {
        const result = await api.list(space.id, st.dir.join("/"), more ? st.cursor : undefined);
        if (mine !== seq || !alive) return;
        st.items = more ? st.items.concat(result.items) : result.items;
        st.cursor = result.next_cursor;
        if (st.selected && !st.items.some((i) => i.name === st.selected)) {
          st.selected = null;
          st.confirming = false;
        }
      } catch (err) {
        if (mine !== seq || !alive) return;
        st.error = err;
      }
      st.loading = false;
      draw();
    }

    function go(dir) {
      thumbs.open(dir);
      st.dir = dir;
      remembered.dirs.set(space.id, dir);
      st.creating = false;
      st.filter = "";
      filter.value = "";
      firstDraw = true;
      drawForm();
      setTitle();
      load();
    }

    async function remove(item) {
      st.confirming = false;
      try {
        await api.remove(space.id, path(item.name));
        ui.toast(`Deleted ${item.name}`);
        load();
      } catch (err) {
        ui.toast(`Could not delete: ${errorTag(err)}`);
        draw();
      }
    }

    function download(item) {
      if (item.size > MAX_BROWSER_DOWNLOAD_BYTES) return ui.toast(`Too large for a browser, ${bytes(MAX_BROWSER_DOWNLOAD_BYTES)} at most`);
      startDownload(space.id, [...st.dir, item.name], item.name, item.size);
      ui.toast(`Downloading ${item.name}`);
    }

    function visibleItems() {
      const q = st.filter.trim().toLowerCase();
      return q ? st.items.filter((i) => i.name.toLowerCase().includes(q)) : st.items;
    }

    function preview(item) {
      if (closePreview) closePreview();
      const photos = visibleItems().filter(isPhoto);
      const close = openPreview(content, {
        spaceId: space.id,
        dir: [...st.dir],
        photos,
        start: Math.max(0, photos.indexOf(item)),
        onDownload: download,
      });
      closePreview = () => {
        closePreview = null;
        close();
      };
    }

    const lacking = () => st.items.filter((i) => isPhoto(i) && !i.thumb && !thumbGaveUp(space.id, path(i.name)));

    // This folder and everything below it; at the top of the space, all of it.
    async function makeThumbs() {
      const run = startThumbJob({ user: user.id, space: space.id, dir: [...st.dir] });
      if (!run) return;
      const result = await run;
      if (result.stopped) return;
      if (result.failed) ui.toast(`${result.done} made. Some photos could not get a thumbnail`);
      else ui.toast(result.done ? `${result.done} thumbnails made` : "Every photo has a thumbnail");
      if (alive) draw();
    }

    function actionsFor(item) {
      if (st.confirming) {
        return h(
          "div",
          { class: "acts fact" },
          h("span", { class: "fask", text: `Delete ${item.name}?` }),
          h("button", { class: "ghost warn", type: "button", text: "Delete", onclick: () => remove(item) }),
          h("button", {
            class: "ghost",
            type: "button",
            text: "Keep",
            onclick: () => {
              st.confirming = false;
              draw();
            },
          }),
        );
      }
      return h(
        "div",
        { class: "acts fact" },
        item.kind === "file" ? h("button", { class: "ghost", type: "button", text: "Download", onclick: () => download(item) }) : null,
        writable
          ? h("button", {
              class: "ghost",
              type: "button",
              text: "Delete",
              onclick: () => {
                st.confirming = true;
                draw();
              },
            })
          : null,
      );
    }

    function select(item) {
      st.selected = st.selected === item.name ? null : item.name;
      st.confirming = false;
      draw();
    }

    function row(item) {
      const on = item.name === st.selected;
      const isDir = item.kind === "dir";
      const photo = isPhoto(item);
      const hasMore = photo || (isDir && writable); // a tap on these rows opens them, so their actions need a button
      const meta = isDir ? `Folder, ${when(item.modified)}` : `${bytes(item.size)}, ${when(item.modified)}`;
      const badge = h("span", { class: "ext" }, isDir ? icon("folder") : extOf(item));
      if (photo && item.thumb) thumbs.attach(badge, item);
      return h(
        "div",
        { class: "frw" },
        h(
          "button",
          {
            class: `frow${on ? " on" : ""}${hasMore ? " more" : ""}`,
            type: "button",
            "data-d": "",
            onclick: () => {
              if (isDir) go([...st.dir, item.name]);
              else if (photo) preview(item);
              else select(item);
            },
          },
          badge,
          h("span", { class: "ftext" }, h("div", { class: "nm", text: item.name }), h("div", { class: "sub", text: meta })),
        ),
        hasMore ? h("button", { class: "fmore", type: "button", "aria-label": `Options for ${item.name}`, onclick: () => select(item) }, icon("dots")) : null,
        on ? actionsFor(item) : null,
      );
    }

    function drawTools() {
      clear(tools);
      if (st.dir.length) tools.append(h("button", { class: "ghost", type: "button", text: "Up", onclick: () => go(st.dir.slice(0, -1)) }));
      if (writable) {
        tools.append(
          h("button", {
            class: "ghost",
            type: "button",
            text: "New folder",
            onclick: () => {
              st.creating = !st.creating;
              drawForm();
            },
          }),
          h("button", {
            class: "ghost",
            type: "button",
            text: "Upload here",
            onclick: () => {
              const target = { space: space.id, dir: [...st.dir] };
              ui.setDest(target);
              ui.pick(target);
            },
          }),
        );
        const run = thumbJobNow();
        if (run && run.space === space.id) {
          const text = run.finding ? `Finding photos, ${run.found}` : `Making ${run.done + run.failed} / ${run.total}`;
          tools.append(
            h("button", { class: "ghost", type: "button", disabled: true, text }),
            h("button", { class: "ghost", type: "button", text: "Stop", onclick: () => stopThumbJob() }),
          );
        } else if (!run && (lacking().length || (!st.dir.length && st.items.length))) {
          const text = st.dir.length ? "Make thumbnails" : "Make all thumbnails";
          tools.append(h("button", { class: "ghost", type: "button", text, onclick: () => makeThumbs() }));
        }
      }
    }

    function drawForm() {
      clear(formSlot);
      if (!st.creating) return;
      const name = h("input", { type: "text", placeholder: "Folder name", "aria-label": "Folder name", maxlength: 255, autocomplete: "off" });
      const form = h("form", { class: "search fform" }, name, h("button", { class: "ghost", type: "submit", text: "Create" }));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const value = name.value.trim();
        if (!value) return;
        if (value.includes("/") || value.includes("\\")) return ui.toast("A name cannot contain / or \\");
        try {
          await api.mkdir(space.id, path(value));
          st.creating = false;
          drawForm();
          ui.toast(`Created ${value}`);
          load();
        } catch (err) {
          ui.toast(`Could not create: ${errorTag(err)}`);
        }
      });
      formSlot.append(form);
      name.focus();
    }

    function drawList() {
      clear(list);
      thumbs.reset();
      if (st.error) {
        const gone = st.error instanceof ApiError && st.error.code === "not_found" && st.dir.length;
        list.append(
          h("p", { class: "hint", text: `Could not load this folder: ${errorTag(st.error)}` }),
          h(
            "div",
            { class: "acts center" },
            h("button", { class: "ghost", type: "button", text: "Try again", onclick: () => load() }),
            gone ? h("button", { class: "ghost", type: "button", text: "Up one level", onclick: () => go(st.dir.slice(0, -1)) }) : null,
          ),
        );
        return;
      }
      if (st.loading && !st.items.length) {
        list.append(h("div", { class: "sk skrow" }), h("div", { class: "sk skrow" }), h("div", { class: "sk skrow" }));
        return;
      }
      const items = visibleItems();
      if (!items.length) list.append(h("p", { class: "hint", text: st.items.length ? "Nothing matches" : "This folder is empty" }));
      list.append(...items.map(row));
      if (st.cursor) {
        list.append(h("button", { class: "ghost wide", type: "button", disabled: st.loading, text: st.loading ? "Loading" : "Load more", onclick: () => load({ more: true }) }));
      }
      if (firstDraw && items.length) {
        firstDraw = false;
        fx($$("[data-d]", list), { opacity: [0, 1], y: [20, 0] }, { duration: 0.5, delay: stag(0.04), ease: EASE });
      }
    }

    function draw() {
      if (!alive) return;
      crumbs.textContent = `/ ${[space.name, ...st.dir].join(" / ")} /`;
      drawTools();
      drawList();
    }

    filter.addEventListener("input", () => {
      st.filter = filter.value;
      drawList();
    });

    const stopDone = subscribeDone((t) => {
      if (t.space !== space.id || t.dir.join("/") !== st.dir.join("/")) return;
      clearTimeout(reloadTimer);
      reloadTimer = setTimeout(() => alive && load({ quiet: true }), 300);
    });

    const stopThumb = subscribeThumb((made) => {
      if (made.space !== space.id || made.dir.join("/") !== st.dir.join("/")) return;
      const item = st.items.find((i) => i.name === made.name);
      if (!item) return;
      item.thumb = true;
      draw();
    });

    const stopJob = subscribeThumbJob(() => {
      if (alive) drawTools();
    });

    closeFolder = () => {
      alive = false;
      if (closePreview) closePreview();
      thumbs.close();
      clearTimeout(reloadTimer);
      stopDone();
      stopThumb();
      stopJob();
      closeFolder = null;
    };

    const content = h(
      "div",
      { class: "sc" },
      h(
        "div",
        { class: `hero tone${spaces.indexOf(space) % 5}` },
        h("button", { class: "back glass", type: "button", "aria-label": "Back", onclick: () => ui.closeDetail() }, icon("chev")),
        title,
      ),
      h(
        "div",
        { class: "body" },
        h("div", { class: "row frowhead" }, crumbs),
        tools,
        formSlot,
        h("label", { class: "search fsearch" }, icon("search", "i i18"), filter),
        list,
      ),
    );

    setTitle();
    draw();
    ui.openDetail(cardEl, content, () => closeFolder && closeFolder());
    load();
  }

  return {
    enter() {
      fitNames();
      placeIndicator(seg);
      photos.enter();
    },
    resize() {
      fitNames();
      placeIndicator(seg);
    },
    destroy() {
      photos.destroy();
      if (closeFolder) closeFolder();
      if (seenObserver) seenObserver.disconnect();
    },
  };
}
