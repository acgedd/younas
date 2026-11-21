// Tiny DOM helpers. Everything is built with createElement and textContent: nothing from the server
// (file names, user names, error messages) is ever parsed as HTML.
//
// The Content-Security-Policy refuses a style attribute, so `style` takes an object and goes through
// the CSSOM, which the policy allows.

function assign(el, props) {
  for (const [key, value] of Object.entries(props || {})) {
    if (value == null || value === false) continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key === "text") el.textContent = value;
    else if (key === "style") {
      if (typeof value !== "object") throw new TypeError("style must be an object");
      for (const [name, v] of Object.entries(value)) el.style.setProperty(name, String(v));
    } else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  return el;
}

function fill(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

export function h(tag, props, ...kids) {
  return fill(assign(document.createElement(tag), props), kids);
}

export function s(tag, props, ...kids) {
  return fill(assign(document.createElementNS("http://www.w3.org/2000/svg", tag), props), kids);
}

// Constant strings of this file (never server data), parsed once as SVG.
const ICONS = {
  status: '<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',
  gallery: '<rect x="3.5" y="4.5" width="17" height="15" rx="3.5"/><circle cx="9" cy="10" r="1.6"/><path d="M4 17l5-4.5 4 3.5 3-2.5 4 3.5"/>',
  home: '<path d="M4 11l8-7 8 7v8.5a1 1 0 01-1 1h-4.5v-5.5h-5v5.5H5a1 1 0 01-1-1z"/>',
  upload: '<path d="M12 16V5M7.5 9.5L12 5l4.5 4.5"/><path d="M4.5 15.5v2a2 2 0 002 2h11a2 2 0 002-2v-2"/>',
  storage: '<ellipse cx="12" cy="6.5" rx="7.5" ry="3"/><path d="M4.5 6.5v5.5c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6.5"/><path d="M4.5 12v5.5c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V12"/>',
  folder: '<path d="M3.5 7a2 2 0 012-2H10l2 2.5h6.5a2 2 0 012 2V17.5a2 2 0 01-2 2h-13a2 2 0 01-2-2z"/>',
  chev: '<path d="M15 5l-7 7 7 7"/>',
  dots: '<circle cx="6" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="18" cy="12" r="1.2"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
};

export function icon(name, cls = "i") {
  const doc = new DOMParser().parseFromString(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true" class="${cls}">${ICONS[name]}</svg>`,
    "image/svg+xml",
  );
  return document.importNode(doc.documentElement, true);
}

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
export const clamp = (v, low, high) => Math.min(high, Math.max(low, v));

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

// Text split into letters for the big names; each letter rises on its own delay.
export function chars(text) {
  return [...text].map((c, i) => h("span", { class: "ch", text: c, style: { "--i": i } }));
}

const isDigit = (c) => c >= "0" && c <= "9";

// Rolling digits.
export function nf(el, value) {
  const str = String(value);
  const old = el._nf;
  if (!old || old.length !== str.length || [...str].some((c, i) => isDigit(c) !== isDigit(old[i]))) {
    let k = 0;
    clear(el);
    for (const c of str) {
      if (isDigit(c)) {
        const roll = h(
          "span",
          { class: "ns", style: { "transition-delay": `${k * 30}ms` } },
          [..."0123456789"].map((d) => h("i", { text: d })),
        );
        k += 1;
        el.append(h("span", { class: "nd" }, roll));
      } else {
        el.append(h("span", { text: c }));
      }
    }
    el.classList.add("nf");
    const from = [...(old && old.length === str.length ? old : str)].filter(isDigit);
    $$(".ns", el).forEach((c, i) => {
      c.style.transition = "none";
      c.style.transform = `translateY(${-(Number(from[i]) || 0)}em)`;
    });
    void el.offsetWidth;
    for (const c of $$(".ns", el)) c.style.transition = "";
  }
  el._nf = str;
  const digits = [...str].filter(isDigit);
  $$(".ns", el).forEach((c, i) => {
    c.style.transform = `translateY(${-Number(digits[i])}em)`;
  });
}

// Roll up from zeros to a number.
export function countTo(el, text) {
  el._nf = null;
  nf(el, text.replace(/[0-9]/g, "0"));
  requestAnimationFrame(() => requestAnimationFrame(() => nf(el, text)));
}

// The sliding pill behind a segmented control.
export function placeIndicator(segment) {
  const on = $("button.on", segment);
  const ind = $(".ind", segment);
  if (!on || !ind) return;
  ind.style.width = `${on.offsetWidth}px`;
  ind.style.transform = `translateX(${on.offsetLeft}px)`;
}
