// Storage page. REAL: disk size and free space for the owner (GET /api/v1/admin/status); the account,
// its spaces, password change and sign-out for everyone. A friend sees no disk numbers: the server
// shows them to the owner only. The prototype's breakdown by category needs a server index (Phase B),
// so the ring shows used and free only.

import { api } from "../api.js";
import { clear, countTo, h, s } from "../dom.js";
import { bytes } from "../format.js";
import { tween } from "../motion.js";
import { MIN_PASSWORD, changeMessage, field, message } from "./gate.js";

const R = 86;
const C = 2 * Math.PI * R;

const kv = (label, value, mono = false) => h("div", { class: "kv" }, h("span", { text: label }), h("span", { class: mono ? "mono" : null, text: value }));

function gigabytes(n) {
  return Math.round(n / 1e9);
}

export function mount(page, ui) {
  const { user, spaces, isOwner } = ui.session;

  const arc = s("circle", { cx: 108, cy: 108, r: R, fill: "none", stroke: "#b7d3f7", "stroke-width": 18, "stroke-dasharray": `0 ${C}` });
  const freeValue = h("div", { class: "mono ringnum", text: "-" });
  const freeLabel = h("div", { class: "ringsub", text: "Checking" });
  const legend = h("div", { class: "list plain", "data-in": "" });
  const about = h("div", { class: "list plain", "data-in": "" });

  const disk = isOwner
    ? h(
        "div",
        { class: "ring", "data-in": "" },
        s("svg", { viewBox: "0 0 216 216", "aria-hidden": "true" }, s("circle", { cx: 108, cy: 108, r: R, fill: "none", stroke: "#121b33", "stroke-width": 18 }), arc),
        h("div", { class: "mid" }, freeValue, freeLabel),
      )
    : null;

  let usedLength = 0;
  let freeText = "";

  function drawAbout(version, database) {
    clear(about);
    const rows = [
      kv("Signed in as", user.username),
      kv("Role", user.role === "owner" ? "Owner" : "Friend"),
      version ? kv("YourNAS", version, true) : null,
      database ? kv("Database", database) : null,
      ...spaces.map((space) => kv(space.name, space.access === "write" ? "Read and write" : "Read only")),
    ];
    about.append(...rows.filter(Boolean));
  }

  function changePassword() {
    const msg = message();
    const submit = h("button", { class: "sdone", type: "submit", text: "Change password" });
    const form = h(
      "form",
      { novalidate: true, class: "gform" },
      field("cp-current", "Current password", { type: "password", autocomplete: "current-password", maxlength: 128 }),
      field("cp-new", `New password, ${MIN_PASSWORD}+ characters`, { type: "password", autocomplete: "new-password", maxlength: 128 }),
      field("cp-again", "Repeat new password", { type: "password", autocomplete: "new-password", maxlength: 128 }),
      msg,
      submit,
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const current = form.querySelector("#cp-current").value;
      const next = form.querySelector("#cp-new").value;
      if (!current || !next) return msg.say("Fill in all fields", true);
      if (next !== form.querySelector("#cp-again").value) return msg.say("New passwords do not match", true);
      submit.disabled = true;
      msg.say("Saving...");
      try {
        await api.changePassword(current, next);
        ui.closeSheet();
        ui.toast("Password changed. Other devices are signed out.");
      } catch (err) {
        msg.say(changeMessage(err), true);
        submit.disabled = false;
      }
    });
    ui.openSheet("Change password", h("div", { class: "stitle", text: "Change password" }), form);
  }

  page.append(
    h(
      "div",
      { class: "pad" },
      h("div", { class: "row", "data-in": "" }, h("h1", { class: "h1", text: isOwner ? "Storage" : "Account" })),
      disk,
      isOwner ? legend : null,
      h("div", { class: "eyebrow mt6", "data-in": "", text: "About" }),
      about,
      h(
        "div",
        { class: "acts", "data-in": "" },
        h("button", { class: "ghost", type: "button", text: "Change password", onclick: changePassword }),
        h("button", { class: "ghost", type: "button", text: "Sign out", onclick: () => ui.logout() }),
      ),
    ),
  );

  drawAbout();

  function growRing() {
    arc.setAttribute("stroke-dasharray", `0 ${C}`);
    if (freeText) countTo(freeValue, freeText);
    tween(0, usedLength, {
      duration: 0.8,
      delay: 0.12,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => arc.setAttribute("stroke-dasharray", `${v} ${C - v}`),
    });
  }

  async function load() {
    if (!isOwner) return;
    try {
      const status = await api.adminStatus();
      const { total_bytes: total, free_bytes: free } = status.storage;
      const used = Math.max(0, total - free);
      usedLength = total > 0 ? (used / total) * C : 0;
      freeText = String(gigabytes(free));
      freeLabel.textContent = `GB free of ${bytes(total)}`;
      clear(legend);
      legend.append(
        h("div", { class: "leg" }, h("i", { class: "lused" }), h("span", { text: "Used" }), h("span", { class: "mono legv", text: bytes(used) })),
        h("div", { class: "leg" }, h("i", { class: "lfree" }), h("span", { text: "Free" }), h("span", { class: "mono legv", text: bytes(free) })),
      );
      drawAbout(status.version, status.database.ok ? "Operational" : "Problem");
      growRing();
    } catch {
      freeValue.textContent = "-";
      freeLabel.textContent = "Not available";
    }
  }

  return { enter: load };
}
