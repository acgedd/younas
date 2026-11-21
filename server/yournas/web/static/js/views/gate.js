// The two screens shown before the app: sign in, and the forced change of a temporary password.
// Both use the real auth API. Nothing is stored here except the token (in api.js).

import { ApiError, api, token } from "../api.js";
import { h } from "../dom.js";

export const MIN_PASSWORD = 12; // mirrors yournas.auth.passwords.MIN_PASSWORD_LENGTH; the server decides

function loginMessage(err) {
  if (!(err instanceof ApiError)) return "Something went wrong";
  switch (err.code) {
    case "invalid_credentials":
      return "Wrong username or password";
    case "too_many_attempts":
      return err.retryAfter ? `Too many tries. Wait ${err.retryAfter} seconds.` : "Too many tries. Wait a moment.";
    case "temporary_password_expired":
      return "Temporary password expired. Ask the owner for a new one.";
    case "network":
      return "Server unreachable";
    default:
      return `Error ${err.status || ""}`.trim();
  }
}

export function changeMessage(err) {
  if (!(err instanceof ApiError)) return "Something went wrong";
  switch (err.code) {
    case "invalid_current_password":
      return "Current password is wrong";
    case "weak_password":
      return err.message; // fixed text from the server's password policy
    case "password_unchanged":
      return "New password must be different";
    case "temporary_password_expired":
      return "Temporary password expired. Ask the owner for a new one.";
    case "too_many_attempts":
      return err.retryAfter ? `Too many tries. Wait ${err.retryAfter} seconds.` : "Too many tries. Wait a moment.";
    case "network":
      return "Server unreachable";
    default:
      return `Error ${err.status || ""}`.trim();
  }
}

export function field(id, label, props) {
  return h(
    "div",
    { class: "gfield" },
    h("label", { class: "eyebrow", for: id, text: label }),
    h("input", { class: "fld", id, required: true, ...props }),
  );
}

export function message() {
  const el = h("p", { class: "gmsg", role: "alert" });
  el.say = (text, isError = false) => {
    el.textContent = text;
    el.classList.toggle("err", isError);
  };
  return el;
}

// The sky from Home behind every gate screen.
function sky() {
  return h(
    "div",
    { class: "hbg", "aria-hidden": "true" },
    ["b1", "b2", "b3", "b4", "b5"].map((b) => h("i", { class: `b ${b}` })),
    h("div", { class: "fade" }),
  );
}

export function gatePage(title, sub, ...body) {
  return h(
    "section",
    { class: "page gate home" },
    sky(),
    h(
      "div",
      { class: "pad padrel" },
      h("h1", { class: "greet gtitle", text: title }),
      sub ? h("p", { class: "gsub", text: sub }) : null,
      h("div", { class: "card gcard" }, body),
    ),
  );
}

export function renderLogin(root, { notice = "", onLoggedIn }) {
  const msg = message();
  if (notice) msg.say(notice, true);
  const submit = h("button", { class: "sdone", type: "submit", text: "Sign in" });
  const form = h(
    "form",
    { novalidate: true, class: "gform" },
    field("login-user", "Username", { type: "text", autocomplete: "username", autocapitalize: "none", spellcheck: "false", maxlength: 64 }),
    field("login-pass", "Password", { type: "password", autocomplete: "current-password", maxlength: 128 }),
    submit,
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = form.querySelector("#login-user").value.trim();
    const password = form.querySelector("#login-pass").value;
    if (!username || !password) return msg.say("Enter your username and password", true);
    submit.disabled = true;
    msg.say("Signing in...");
    try {
      const result = await api.login(username, password);
      token.set(result.token);
      form.querySelector("#login-pass").value = "";
      onLoggedIn(result);
    } catch (err) {
      msg.say(loginMessage(err), true);
      submit.disabled = false;
    }
  });

  root.append(gatePage("YourNAS", "Sign in to continue", form, msg));
  form.querySelector("#login-user").focus();
}

export function renderPasswordChange(root, { onDone, onLogout }) {
  const msg = message();
  const submit = h("button", { class: "sdone", type: "submit", text: "Change password" });
  const form = h(
    "form",
    { novalidate: true, class: "gform" },
    field("pw-current", "Current (temporary) password", { type: "password", autocomplete: "current-password", maxlength: 128 }),
    field("pw-new", `New password, ${MIN_PASSWORD}+ characters`, { type: "password", autocomplete: "new-password", maxlength: 128 }),
    field("pw-again", "Repeat new password", { type: "password", autocomplete: "new-password", maxlength: 128 }),
    submit,
  );

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const current = form.querySelector("#pw-current").value;
    const next = form.querySelector("#pw-new").value;
    const again = form.querySelector("#pw-again").value;
    if (!current || !next) return msg.say("Fill in all fields", true);
    if (next !== again) return msg.say("New passwords do not match", true);
    submit.disabled = true;
    msg.say("Saving...");
    try {
      await api.changePassword(current, next);
      onDone();
    } catch (err) {
      msg.say(changeMessage(err), true);
      submit.disabled = false;
    }
  });

  root.append(
    gatePage(
      "New password",
      "Your password is temporary. Choose a new one.",
      form,
      msg,
      h("button", { class: "ghost gout", type: "button", text: "Sign out", onclick: onLogout }),
    ),
  );
  form.querySelector("#pw-current").focus();
}

export function renderProblem(root, { text, onRetry }) {
  const msg = message();
  msg.say(text, true);
  root.append(gatePage("YourNAS", null, msg, h("button", { class: "sdone", type: "button", text: "Try again", onclick: onRetry })));
}
