// Status page. REAL: reachability and latency measured from this device (GET /health) and, for the
// owner, the server version and database state (GET /api/v1/admin/status). The 60-day uptime history
// of the prototype needs server-side heartbeats, so it is not shown: the bars here are this device's
// own checks since the app opened, and they say so.

import { api } from "../api.js";
import { $, h, icon, nf } from "../dom.js";
import { fx, reduced, tween } from "../motion.js";

const BARS = 60;
const CHECK_MS = 10000;
const WARN_MS = 1500;
const history = []; // survives leaving the page, not a reload: { ok, ms }

export function mount(page, ui) {
  const { isOwner } = ui.session;
  const pillText = h("span", { text: "Checking" });
  const dot = h("span", { class: "dot" });
  const latency = h("span", { class: "nfv", text: "-" });
  const bars = h("div", { class: "bars", "aria-hidden": "true" }, Array.from({ length: BARS }, () => h("i", { class: "nodata" })));
  const countLabel = h("span", { text: "0 checks" });

  const fileMeta = h("div", { class: "meta", text: isOwner ? "YourNAS" : "Reachable from this device" });
  const fileState = h("span", { text: "Checking" });
  const statLatency = h("b", { text: "-" });
  const statOk = h("b", { text: "-" });
  const statFailed = h("b", { text: "-" });

  const dbMeta = h("div", { class: "meta", text: "Checking" });
  const dbState = h("span", { text: "Checking" });

  function service(name, metaEl, stateEl, more) {
    const body = more ? h("div", { class: "more" }, h("div", { class: "more-in" }, more)) : null;
    const button = h(
      more ? "button" : "div",
      { class: "svc", ...(more ? { type: "button", "aria-expanded": "false" } : {}) },
      h(
        "div",
        { class: "row" },
        h("div", {}, h("div", { class: "name", text: name }), metaEl),
        h("div", { class: "st" }, h("i"), stateEl, more ? icon("chev", "i chev") : null),
      ),
      body,
    );
    if (more) {
      button.addEventListener("click", () => {
        const open = button.getAttribute("aria-expanded") === "true";
        button.setAttribute("aria-expanded", String(!open));
        const inner = $(".more-in", button);
        tween(body.offsetHeight, open ? 0 : inner.offsetHeight, {
          duration: 0.35,
          ease: [0.22, 1, 0.36, 1],
          onUpdate: (v) => {
            body.style.height = `${v}px`;
          },
        });
      });
    }
    return h("div", { class: "svc-row" }, button);
  }

  const cell = (label, value) => h("div", {}, h("span", { class: "eyebrow", text: label }), value);

  page.append(
    h(
      "div",
      { class: "pad" },
      h("div", { class: "row", "data-in": "" }, h("h1", { class: "h1", text: "Status" }), h("span", { class: "pill" }, dot, pillText)),
      h(
        "div",
        { class: "card ovw", "data-in": "" },
        h("div", { class: "row" }, h("span", { class: "ovt", text: "Connection" }), h("span", { class: "eyebrow", text: "This device" })),
        h(
          "div",
          { class: "row endrow" },
          h("div", { class: "mono bignum" }, latency, h("small", { text: "ms" })),
          h("span", { class: "eyebrow endnote", text: "Checks since you opened the app" }),
        ),
        bars,
        h("div", { class: "foot" }, countLabel, h("span", { text: "Now" })),
      ),
      h("div", { class: "eyebrow mt6", "data-in": "", text: "Services" }),
      h(
        "div",
        { class: "list", "data-in": "" },
        service("File service", fileMeta, fileState, h("div", { class: "sgrid" }, cell("Latency", statLatency), cell("Passed", statOk), cell("Failed", statFailed))),
        isOwner ? service("Database", dbMeta, dbState, null) : null,
      ),
    ),
  );

  const dotLoop = fx(dot, { scale: [1, 1.5, 1] }, { duration: 2.4, repeat: Infinity, ease: "easeInOut" });
  ui.loop(0, dotLoop);

  function draw() {
    const shown = history.slice(-BARS);
    const offset = BARS - shown.length;
    [...bars.children].forEach((bar, i) => {
      const check = shown[i - offset];
      let cls = "nodata";
      if (check) cls = !check.ok ? "bad" : check.ms > WARN_MS ? "warn" : "";
      bar.className = cls;
    });
    const last = history[history.length - 1];
    const failed = history.filter((c) => !c.ok).length;
    countLabel.textContent = `${history.length} ${history.length === 1 ? "check" : "checks"}`;
    statOk.textContent = String(history.length - failed);
    statFailed.textContent = String(failed);
    if (!last) return;
    const text = last.ok ? "Online" : "Offline";
    pillText.textContent = text;
    fileState.textContent = last.ok ? "Operational" : "Unreachable";
    dot.classList.toggle("off", !last.ok);
    fileState.previousElementSibling.classList.toggle("off", !last.ok);
    if (last.ok) {
      nf(latency, String(last.ms));
      statLatency.textContent = `${last.ms} ms`;
    } else {
      latency.textContent = "-";
      latency._nf = null;
      statLatency.textContent = "-";
    }
  }

  async function check() {
    const started = performance.now();
    let ok = true;
    try {
      await api.health();
    } catch {
      ok = false;
    }
    history.push({ ok, ms: Math.round(performance.now() - started) });
    if (history.length > BARS * 4) history.splice(0, history.length - BARS);
    draw();
  }

  async function loadOwner() {
    if (!isOwner) return;
    try {
      const status = await api.adminStatus();
      fileMeta.textContent = `YourNAS ${status.version}`;
      dbMeta.textContent = `Schema ${status.database.schema_version}`;
      dbState.textContent = status.database.ok ? "Operational" : "Problem";
      dbState.previousElementSibling.classList.toggle("off", !status.database.ok);
    } catch {
      dbMeta.textContent = "Not available";
      dbState.textContent = "Unknown";
    }
  }

  let timer = 0;
  let active = false;
  const start = () => {
    clearInterval(timer);
    timer = 0;
    if (!active || document.visibilityState !== "visible") return;
    check();
    timer = setInterval(check, CHECK_MS);
  };
  document.addEventListener("visibilitychange", start, { signal: ui.signal });

  draw();

  return {
    enter() {
      if (!reduced) {
        page.classList.remove("grow");
        void page.offsetWidth;
        page.classList.add("grow");
      }
      loadOwner();
    },
    setActive(value) {
      if (value === active) return;
      active = value;
      start();
    },
    destroy() {
      clearInterval(timer);
    },
  };
}
