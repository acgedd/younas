// Entry point: decides what to show (sign in, forced password change, or the app) and owns sign-out.

import { ApiError, api, events, token } from "./api.js";
import { createShell } from "./shell.js";
import { forgetUser } from "./store.js";
import { cancelAll, detachAll, loadUnfinished, setTransferUser } from "./transfers.js";
import { renderLogin, renderPasswordChange, renderProblem } from "./views/gate.js";

const root = document.getElementById("app");
const bootEl = document.getElementById("boot");
const SIGN_OUT_WAIT_MS = 2000;

// The service worker's scope is /app/, and /app without the slash is outside it.
if (location.pathname === "/app") history.replaceState(null, "", "/app/");
const BOOT_WAIT_MS = 1800;

let shell = null;
let session = null;
let userId = null; // whose data this device holds, also on the forced password screen
let bootSeq = 0;
let signingOut = false;
let bootGone = null;

function clearScreen() {
  if (shell) shell.destroy();
  shell = null;
  session = null;
  for (const child of [...root.children]) {
    if (child !== bootEl) child.remove();
  }
}

// The launch skeleton stays until the fonts are in, so the first paint is the real design.
function hideBoot() {
  if (bootGone) return bootGone;
  bootGone = Promise.race([
    document.fonts ? document.fonts.ready : Promise.resolve(),
    new Promise((resolve) => setTimeout(resolve, BOOT_WAIT_MS)),
  ]).then(() => {
    bootEl.classList.add("gone");
    setTimeout(() => bootEl.remove(), 400);
  });
  return bootGone;
}

function showLogin(notice = "") {
  clearScreen();
  renderLogin(root, { notice, onLoggedIn: afterLogin });
  hideBoot();
}

function showPasswordChange() {
  clearScreen();
  renderPasswordChange(root, { onDone: boot, onLogout: logout });
  hideBoot();
}

function showProblem(text) {
  clearScreen();
  renderProblem(root, { text, onRetry: boot });
  hideBoot();
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function logout() {
  if (signingOut) return;
  signingOut = true;
  try {
    const who = userId;
    const mine = token.get();
    // Drop the staged uploads while the token still works (each one holds server space and one of
    // the user's upload slots). Bounded, so a dead link cannot hold the sign-out hostage.
    await Promise.race([Promise.allSettled(cancelAll()), wait(SIGN_OUT_WAIT_MS)]);
    if (token.get() !== mine) return boot(); // another tab changed account: not ours to end
    // If the server cannot be told, the session lives until it expires; this device still lets go.
    await Promise.race([api.logout().catch(() => {}), wait(SIGN_OUT_WAIT_MS)]);
    token.clear();
    userId = null;
    detachAll();
    clearScreen(); // nothing on screen may write a setting after the wipe
    let notice = "";
    if (who !== null) {
      try {
        await forgetUser(who);
      } catch {
        notice = "Signed out, but saved data on this device could not be cleared.";
      }
    }
    showLogin(notice);
  } finally {
    signingOut = false;
  }
}

function afterLogin(result) {
  userId = result.user.id;
  if (result.must_change_password) return showPasswordChange();
  showApp({ ...result.user, spaces: result.spaces });
}

function showApp(me) {
  clearScreen();
  session = {
    user: { id: me.id, username: me.username, role: me.role },
    spaces: me.spaces,
    isOwner: me.role === "owner",
  };
  setTransferUser(me.id);
  const current = createShell(root, session, { onLogout: logout });
  shell = current;
  hideBoot().then(() => {
    if (shell === current) current.reveal();
  });
  loadUnfinished(me.id);
}

async function boot() {
  bootSeq += 1;
  const seq = bootSeq;
  if (!token.get()) return showLogin();
  try {
    const me = await api.me();
    if (seq !== bootSeq) return; // a later start has taken over; this answer may be another account
    userId = me.id;
    if (me.must_change_password) return showPasswordChange();
    showApp(me);
  } catch (err) {
    if (seq !== bootSeq) return;
    if (err instanceof ApiError && err.status === 401) {
      token.clear();
      return showLogin();
    }
    if (err instanceof ApiError && err.code === "network") return showProblem("Server unreachable. Is Tailscale on?");
    showProblem(`Could not start${err instanceof ApiError && err.status ? ` (${err.status})` : ""}`);
  }
}

events.addEventListener("unauthorized", () => {
  if (!token.get()) return; // already signed out (e.g. a 401 from cancelling an upload)
  token.clear();
  detachAll();
  showLogin("Your session ended. Sign in again.");
});

// Another tab signed in, out or switched account (tabs share one stored token, see api.js):
// forget this tab's transfers and start over as whoever the token now belongs to.
events.addEventListener("tokenchanged", () => {
  detachAll();
  boot();
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/app/sw.js", { scope: "/app/" })
    .then((registration) => {
      // An installed app can stay suspended for days: look for a new version whenever it comes back.
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") registration.update().catch(() => {});
      });
    })
    .catch(() => {
      /* the app works without it; it just cannot open offline */
    });
}

boot();
