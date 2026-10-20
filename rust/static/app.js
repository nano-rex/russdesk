"use strict";

/* RussDesk web console. Plain DOM, no framework or build step. Pages follow
   RustDesk Server Pro's console; what a user sees depends on ME.perms. */

const root = document.getElementById("app");
let ME = null;
let LOOKUP = { users: [], user_groups: [], device_groups: [], strategies: [], admin_roles: [] };

// -- helpers ----------------------------------------------------------------------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "selected" || k === "disabled") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, kids);
  return el;
}

function append(el, ...kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") {
    opts.headers["X-Russdesk"] = "1";
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body || {});
  }
  const resp = await fetch("/api/admin" + path, opts);
  let data = null;
  try { data = await resp.json(); } catch (e) { data = null; }
  if (resp.status === 401 && !path.startsWith("/login") && !path.startsWith("/invite")) {
    ME = null;
    renderLogin();
    throw new ApiError(401, "Session expired");
  }
  if (!resp.ok) throw new ApiError(resp.status, (data && data.error) || "HTTP " + resp.status);
  return data;
}

function toast(message, isError) {
  const el = h("div", { class: "toast" + (isError ? " error" : "") }, message);
  document.getElementById("toasts").append(el);
  setTimeout(() => el.remove(), isError ? 6000 : 3000);
}

function fail(err) { if (!(err instanceof ApiError && err.status === 401)) toast(err.message, true); }

const can = (perm) => !!ME && (ME.is_admin || ME.perms.includes(perm));

const pad = (n) => String(n).padStart(2, "0");
function dt(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  if (s < 86400 * 30) return Math.floor(s / 86400) + " d ago";
  return dt(ts).slice(0, 10);
}
function dur(s) {
  if (s === null || s === undefined) return "—";
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
}
function bytes(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}
const argbToCss = (c) => "#" + ((c >>> 0) & 0xffffff).toString(16).padStart(6, "0");
const cssToArgb = (s) => (0xff000000 | parseInt(s.slice(1), 16)) >>> 0;

function nameOf(list, id) { const x = list.find((i) => i.id === id); return x ? x.name : ""; }

function select(options, value, attrs) {
  return h("select", attrs || {}, options.map(([v, label]) =>
    h("option", { value: v === null ? "" : v, selected: String(v === null ? "" : v) === String(value === null || value === undefined ? "" : value) }, label)));
}
const optList = (list, none) => [["", none || "— none —"]].concat(list.map((i) => [i.id, i.name]));
const intOrNull = (v) => (v === "" || v === null ? null : parseInt(v, 10));

function field(label, control, hint) {
  return h("div", { class: "field" }, h("label", {}, h("span", {}, label), control), hint ? h("div", { class: "hint" }, hint) : null);
}

function checkbox(label, checked, hint) {
  const box = h("input", { type: "checkbox", checked });
  const el = h("div", { class: "field" }, h("label", { class: "check" }, box, label), hint ? h("div", { class: "hint" }, hint) : null);
  el.box = box;
  return el;
}

function copyButton(textFn) {
  return h("button", {
    class: "small", type: "button", onclick: async () => {
      try { await navigator.clipboard.writeText(textFn()); toast("Copied"); }
      catch (e) { toast("Copy failed; select the text instead", true); }
    },
  }, "Copy");
}

function modal({ title, body, actions, wide }) {
  const errorEl = h("div", { class: "error" });
  const overlay = h("div", { class: "overlay" });
  const close = () => { overlay.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  const buttons = (actions || [{ label: "Close" }]).filter(Boolean).map((a) => {
    const b = h("button", { class: (a.primary ? "primary" : "") + (a.danger ? " danger" : ""), type: "button" }, a.label);
    b.addEventListener("click", async () => {
      if (!a.onClick) return close();
      errorEl.textContent = "";
      b.disabled = true;
      try { if ((await a.onClick()) !== false) close(); }
      catch (err) { errorEl.textContent = err.message; }
      finally { b.disabled = false; }
    });
    return b;
  });
  const m = h("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
    h("header", {}, h("span", {}, title), h("button", { class: "small", type: "button", onclick: close, "aria-label": "Close" }, "✕")),
    h("div", { class: "body" }, body),
    h("footer", {}, errorEl, buttons));
  overlay.append(m);
  overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(overlay);
  const first = m.querySelector(".body input:not([type=checkbox]), .body select, .body textarea");
  if (first) first.focus();
  return { close };
}

function confirmDialog(title, message, label, run) {
  modal({
    title, body: h("p", {}, message),
    actions: [{ label: "Cancel" }, { label: label || "Delete", danger: true, onClick: run }],
  });
}

function table(columns, rows, opts) {
  opts = opts || {};
  columns = columns.filter(Boolean);
  if (!rows.length) return h("div", { class: "table-wrap" }, h("div", { class: "empty" }, opts.empty || "Nothing here yet."));
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, columns.map((c) => h("th", {}, c.label)))),
    h("tbody", {}, rows.map((r) => h("tr", {
      class: opts.onRow ? "clickable" : "",
      onclick: opts.onRow ? (e) => { if (!e.target.closest("button, input, a, select, label")) opts.onRow(r); } : null,
    }, columns.map((c) => h("td", { class: c.cls || "" }, c.render ? c.render(r) : (r[c.key] ?? "")))))),
  ));
}

function pager(total, page, size, go) {
  const pages = Math.max(1, Math.ceil(total / size));
  return h("div", { class: "pager" },
    `${total} total · page ${page} of ${pages}`,
    h("button", { class: "small", disabled: page <= 1, onclick: () => go(page - 1) }, "‹ Prev"),
    h("button", { class: "small", disabled: page >= pages, onclick: () => go(page + 1) }, "Next ›"));
}

function qrImage(text) {
  if (typeof qrcode !== "function") return h("div", { class: "muted" }, "(QR code library missing)");
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  return h("div", { class: "qr" }, h("img", { src: qr.createDataURL(4, 2), alt: "QR code" }));
}

const onlineDot = (on) => h("span", { class: "dot" + (on ? " on" : ""), title: on ? "Online" : "Offline" });
const badge = (text, kind) => h("span", { class: "badge" + (kind ? " " + kind : "") }, text);
const muted = (text) => h("span", { class: "muted" }, text);

/* A list of checkboxes; el.values() returns the checked ids. */
function checklist(items, chosen, opts) {
  opts = opts || {};
  const boxes = items.map((i) => ({ id: i.id, box: h("input", { type: "checkbox", checked: chosen.includes(i.id) }), item: i }));
  const search = items.length > 8 ? h("input", { type: "search", placeholder: "Filter…", "aria-label": "Filter list" }) : null;
  const list = h("div", { class: "checklist" }, boxes.length
    ? boxes.map((b) => { b.row = h("label", {}, b.box, opts.render ? opts.render(b.item) : b.item.name); return b.row; })
    : muted(opts.empty || "None defined"));
  if (search) search.addEventListener("input", () => {
    const q = search.value.toLowerCase();
    for (const b of boxes) b.row.hidden = q && !b.row.textContent.toLowerCase().includes(q);
  });
  const el = h("div", { class: "checklist-wrap" }, search, list);
  el.values = () => boxes.filter((b) => b.box.checked).map((b) => b.id);
  return el;
}

/* A small popup menu of actions (Pro's per-row "More" menu). */
function menuButton(label, items) {
  const wrap = h("span", { class: "menu-wrap" });
  const panel = h("div", { class: "menu", role: "menu" });
  panel.hidden = true;
  const close = () => { panel.hidden = true; document.removeEventListener("mousedown", outside); };
  const outside = (e) => { if (!wrap.contains(e.target)) close(); };
  for (const it of items.filter(Boolean)) {
    panel.append(h("button", { type: "button", role: "menuitem", class: it.danger ? "danger" : "", onclick: () => { close(); it.onClick(); } }, it.label));
  }
  const btn = h("button", { class: "small", type: "button", "aria-haspopup": "menu", onclick: () => {
    panel.hidden = !panel.hidden;
    if (!panel.hidden) document.addEventListener("mousedown", outside);
  } }, label);
  wrap.append(btn, panel);
  return wrap;
}

function tabs(items, active) {
  return h("div", { class: "tabs", role: "tablist" }, items.map(([href, label]) =>
    h("a", { href, class: href === active ? "active" : "", role: "tab", "aria-selected": href === active ? "true" : "false" }, label)));
}

// -- shell and routing -------------------------------------------------------------

const NAV = [
  { href: "#/dashboard", label: "Dashboard" },
  { href: "#/devices", label: "Devices", perm: "devices.view" },
  { href: "#/address-books", label: "Address Books" },
  { section: "Management" },
  { href: "#/users", label: "Users", perm: "users.view" },
  { href: "#/groups", label: "Groups", perm: ["user_groups.view", "device_groups.view"] },
  { href: "#/strategies", label: "Strategies", perm: "strategies.view" },
  { href: "#/admin-roles", label: "Admin Roles", admin: true },
  { section: "Audit" },
  { href: "#/logs/connections", label: "Logs", perm: "audits.view", match: "#/logs" },
  { href: "#/recordings", label: "Recordings", admin: true },
  { section: "Server" },
  { href: "#/settings", label: "Settings", admin: true, match: "#/settings" },
];

function navVisible(n) {
  if (n.admin) return ME.is_admin;
  if (!n.perm) return true;
  return [].concat(n.perm).some(can);
}

const ROUTES = {
  dashboard: pageDashboard,
  devices: pageDevices,
  users: pageUsers,
  groups: pageGroups,
  strategies: pageStrategies,
  "address-books": pageAddressBooks,
  "admin-roles": pageAdminRoles,
  logs: pageLogs,
  recordings: pageRecordings,
  settings: pageSettings,
  account: pageAccount,
};

let mainEl, sideEl, titleEl, actionsEl, refreshTimer;
let navSeq = 0;

function renderShell() {
  clear(root).className = "";
  titleEl = h("h1", {});
  actionsEl = h("div", { class: "split" });
  mainEl = h("div", {});
  // Drop section headings that have no visible links under them.
  const items = NAV.filter((n) => n.section || navVisible(n));
  const visible = items.filter((n, i) => !n.section || (items[i + 1] && !items[i + 1].section));
  sideEl = h("nav", { class: "side", "aria-label": "Main" },
    h("div", { class: "brand" }, h("img", { src: "/favicon.svg", alt: "" }), "RussDesk"),
    ME.must_setup_2fa ? null : visible.map((n) => n.section
      ? h("div", { class: "section" }, n.section)
      : h("a", { class: "nav", href: n.href, "data-match": n.match || n.href, onclick: () => sideEl.classList.remove("open") }, n.label)),
    h("div", { class: "spacer" }),
    h("div", { class: "who" },
      h("div", {}, h("strong", {}, ME.display_name || ME.name), " ", ME.is_admin ? badge("admin", "accent") : null),
      h("div", { class: "split" },
        h("a", { href: "#/account", onclick: () => sideEl.classList.remove("open") }, "Account"),
        h("span", {}, "·"),
        h("button", { class: "link", onclick: logout }, "Sign out"))));
  root.append(h("div", { class: "shell" }, sideEl, h("main", { class: "main" },
    h("div", { class: "topbar" },
      h("button", { class: "menu-btn", onclick: () => sideEl.classList.toggle("open"), "aria-label": "Menu" }, "☰"),
      titleEl, actionsEl),
    mainEl)));
}

function setPage(title, ...actions) {
  titleEl.textContent = title;
  document.title = title + " · RussDesk";
  append(clear(actionsEl), actions);
}

async function route() {
  const hash = location.hash || "#/dashboard";
  const parts = hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (parts[0] === "invite") return renderInvite(parts[1]);
  if (!ME) return;
  clearInterval(refreshTimer);
  if (ME.must_setup_2fa && parts[0] !== "account") {
    location.hash = "#/account";
    return;
  }
  const page = ROUTES[parts[0]] || pageDashboard;
  navSeq += 1;
  // Pages render into a fresh container; a late reload from a page the user
  // already left then draws into a detached element and is never shown.
  const fresh = h("div", {});
  mainEl.replaceWith(fresh);
  mainEl = fresh;
  for (const a of sideEl.querySelectorAll("a.nav")) {
    a.classList.toggle("active", hash.startsWith(a.dataset.match));
  }
  clear(mainEl).append(muted("Loading…"));
  try {
    await page(parts.slice(1), fresh);
  } catch (err) {
    fail(err);
    clear(fresh).append(h("div", { class: "panel" }, err.message));
  }
}

async function refreshLookup() {
  LOOKUP = await api("GET", "/lookup");
}

async function logout() {
  await api("POST", "/logout").catch(() => {});
  ME = null;
  renderLogin();
}

function loginCard(...kids) {
  clear(root).className = "";
  root.append(h("div", { class: "login" }, h("div", { class: "card" },
    h("h1", {}, h("img", { src: "/favicon.svg", alt: "" }), "RussDesk"), kids)));
}

function renderLogin() {
  clearInterval(refreshTimer);
  document.title = "Sign in · RussDesk";
  const user = h("input", { autocomplete: "username", required: true });
  const pass = h("input", { type: "password", autocomplete: "current-password", required: true });
  const err = h("div", { class: "error", role: "alert" });
  const btn = h("button", { class: "primary", type: "submit" }, "Sign in");
  const form = h("form", { class: "form" }, field("Username", user), field("Password", pass), err, btn);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    btn.disabled = true;
    try {
      const res = await api("POST", "/login", { username: user.value, password: pass.value });
      if (res.need_code) return renderCodeStep(res);
      await start();
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      btn.disabled = false;
    }
  });
  loginCard(h("p", {}, "Sign in to the console"), form);
  user.focus();
}

function renderCodeStep(challenge) {
  const email = challenge.need_code === "email";
  const code = h("input", { inputmode: email ? "numeric" : "text", autocomplete: "one-time-code", maxlength: 9, placeholder: email ? "123456" : "123456 or backup code" });
  const err = h("div", { class: "error", role: "alert" });
  const btn = h("button", { class: "primary", type: "submit" }, "Verify");
  const form = h("form", { class: "form" },
    field(email ? "Code from the email we just sent" : "Verification code", code,
      email ? "It expires in 10 minutes." : "From your authenticator app, or one of your backup codes."),
    err, btn, h("button", { class: "link", type: "button", onclick: renderLogin }, "‹ Back"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    btn.disabled = true;
    try {
      await api("POST", "/login/verify", { secret: challenge.secret, code: code.value.trim() });
      await start();
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      btn.disabled = false;
    }
  });
  loginCard(h("p", {}, "Two-step verification"), form);
  code.focus();
}

async function renderInvite(token) {
  document.title = "Accept invitation · RussDesk";
  let info;
  try { info = await api("GET", "/invite/" + encodeURIComponent(token)); }
  catch (e) { return loginCard(h("p", { class: "error" }, e.message), h("a", { href: "#/" , onclick: () => { location.hash = ""; start(); } }, "Go to sign in")); }
  const pass = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const err = h("div", { class: "error", role: "alert" });
  const form = h("form", { class: "form" }, field("Choose a password", pass, "At least 8 characters"), field("Repeat it", again), err,
    h("button", { class: "primary", type: "submit" }, "Activate account"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (pass.value !== again.value) { err.textContent = "The passwords differ"; return; }
    try {
      await api("POST", "/invite/" + encodeURIComponent(token), { password: pass.value });
      location.hash = "";
      toast("Account activated; sign in now");
      renderLogin();
    } catch (ex) { err.textContent = ex.message; }
  });
  loginCard(h("p", {}, `Welcome, ${info.name}. Set a password to activate your account.`), form);
}

async function start() {
  if ((location.hash || "").startsWith("#/invite/")) return route();
  try {
    ME = await api("GET", "/me");
  } catch (e) {
    if (!ME) renderLogin();
    return;
  }
  await refreshLookup().catch(() => {});
  renderShell();
  route();
}

window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", start);

// -- dashboard ---------------------------------------------------------------------

async function pageDashboard(_params, mainEl) {
  setPage("Dashboard");
  const draw = async () => {
    const [d, cfg] = await Promise.all([api("GET", "/dashboard"), api("GET", "/client-config")]);
    const stats = [["Devices online", h("span", {}, d.devices_online, h("small", {}, " / " + d.devices_total))]];
    if (d.connections_24h !== undefined) {
      stats.push(["Active sessions", d.active_sessions.length], ["Connections (24 h)", d.connections_24h], ["Alarms (24 h)", d.alarms_24h]);
    }
    if (d.users_total !== undefined) stats.push(["Users", d.users_total]);
    const parts = [h("div", { class: "grid stats" }, stats.map(([l, v]) =>
      h("div", { class: "stat" }, h("div", { class: "label" }, l), h("div", { class: "value" }, v))))];

    if (d.connections_24h !== undefined) {
      parts.push(h("div", { class: "panel" }, h("h2", {}, "Active sessions"),
        table([
          { label: "Controlled device", render: (r) => h("span", {}, r.device_id, " ", muted(r.device_name)) },
          { label: "Controlling side", render: (r) => r.peer_id ? h("span", {}, r.controller ? h("strong", {}, r.controller + " ") : null, r.peer_id, " ", muted(r.peer_name)) : muted("connecting…") },
          { label: "Type", key: "type" },
          { label: "IP", key: "ip" },
          { label: "Duration", render: (r) => dur(r.duration) },
          can("audits.edit") ? { label: "", cls: "actions", render: (r) => h("button", { class: "small danger", onclick: () => disconnectLog(r.id, draw) }, "Disconnect") } : null,
        ], d.active_sessions, { empty: "No one is connected right now." })));
    }

    const lower = [];
    if (d.connections_by_day) {
      const max = Math.max(1, ...d.connections_by_day.map((x) => x.count));
      const bars = h("div", { class: "bars" }, d.connections_by_day.map((x) => {
        const bar = h("i", { title: `${dt(x.day).slice(0, 10)}: ${x.count}` });
        bar.style.height = (x.count / max) * 100 + "%";
        return h("div", { class: "bar" }, bar, h("span", {}, new Date(x.day * 1000).getDate()));
      }));
      lower.push(h("div", { class: "panel" }, h("h2", {}, "Connections", h("span", { class: "sub" }, "last 14 days")), bars));
    }
    lower.push(h("div", { class: "panel" }, h("h2", {}, "Platforms"),
      Object.keys(d.platforms).length
        ? h("dl", { class: "kv" }, Object.entries(d.platforms).sort((a, b) => b[1] - a[1]).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]))
        : muted("No devices have reported yet.")));
    if ((d.recent_alarms || []).length) {
      lower.push(h("div", { class: "panel" }, h("h2", {}, "Recent alarms"),
        d.recent_alarms.map((a) => h("div", { class: "alarm-line" }, badge(a.type, "danger"), " ",
          a.target, " ", muted(`from ${a.from || a.ip} · ${ago(a.created_at)}`)))));
    }
    lower.push(clientConfigPanel(cfg));
    parts.push(h("div", { class: "grid two" }, lower));
    append(clear(mainEl), parts);
  };
  await draw();
  refreshTimer = setInterval(() => draw().catch(() => {}), 15000);
}

function clientConfigPanel(cfg) {
  const row = (label, value, note) => [h("dt", {}, label), h("dd", {}, value ? h("code", {}, value) : muted(note || "not set"))];
  return h("div", { class: "panel" },
    h("h2", {}, "Connect a RustDesk client"),
    h("p", { class: "muted" }, "In RustDesk: Settings → Network → ID/Relay server. Enter the ID server (with its port) and the key, and leave the API server empty. Or copy the config string and use the clipboard import button."),
    h("dl", { class: "kv spaced" }, row("ID server", cfg.host), row("Relay server", cfg.relay, "leave empty (hbbs tells clients)"),
      row("API server", cfg.api, "leave empty (the client uses " + (cfg.api_default || "the ID server port minus 2") + ")"),
      row("Key", cfg.key)),
    h("div", { class: "copy-box" }, h("code", {}, cfg.config_string), copyButton(() => cfg.config_string)),
    h("details", { class: "spaced-top" }, h("summary", {}, "Windows EXE"),
      h("p", { class: "muted" }, "Rename rustdesk.exe to this name and the Windows client configures itself (no settings to type):"),
      h("div", { class: "copy-box" }, h("code", {}, cfg.windows_exe), copyButton(() => cfg.windows_exe))),
    !cfg.key ? h("p", { class: "hint muted" }, "The key is empty: set it in Settings or point RUSSDESK_HBBS_KEY_FILE at hbbs' id_ed25519.pub.") : null);
}

async function disconnectLog(logId, after) {
  confirmDialog("Disconnect session", "End this session? The device drops it within a few seconds and the controlling side is told it was disconnected from the console.", "Disconnect", async () => {
    await api("POST", `/logs/connections/${logId}/disconnect`);
    toast("Disconnect sent");
    if (after) setTimeout(() => after().catch(() => {}), 4000);
  });
}

// -- devices -----------------------------------------------------------------------

async function pageDevices(params, mainEl) {
  const state = { q: "", status: "", group: "", user_group: "", user: "", strategy: "", offline_days: "", page: 1 };
  const selected = new Set();
  const listEl = h("div", {});
  setPage("Devices");

  const search = h("input", { type: "search", placeholder: "Search ID, name, user, IP, note…", "aria-label": "Search devices" });
  let timer;
  search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.q = search.value; state.page = 1; load(); }, 250); });
  const filter = (key, options, label) => select(options, "", { "aria-label": label, onchange: (e) => { state[key] = e.target.value; state.page = 1; load(); } });
  const filters = [
    filter("status", [["", "All statuses"], ["online", "Online"], ["offline", "Offline"], ["enabled", "Enabled"], ["disabled", "Disabled"]], "Status"),
    filter("group", [["", "All device groups"], ["none", "No device group"]].concat(LOOKUP.device_groups.map((g) => [g.id, g.name])), "Device group"),
    filter("user_group", [["", "All user groups"]].concat(LOOKUP.user_groups.map((g) => [g.id, g.name])), "User group"),
    filter("offline_days", [["", "Any last online"], ["7", "Offline 7+ days"], ["30", "Offline 30+ days"], ["90", "Offline 90+ days"]], "Offline for"),
  ];
  const bulk = h("div", { class: "split" });
  const bulkable = can("devices.enable_disable") || can("devices.delete") || can("devices.assign_to_user") || can("devices.change_group") || can("devices.change_strategy");

  async function load() {
    const qs = new URLSearchParams(Object.assign({}, state, { size: 50 }));
    const data = await api("GET", "/devices?" + qs);
    const cols = [
      bulkable ? {
        label: "", render: (r) => h("input", {
          type: "checkbox", checked: selected.has(r.id), "aria-label": "Select " + r.id,
          onchange: (e) => { e.target.checked ? selected.add(r.id) : selected.delete(r.id); drawBulk(); },
        }),
      } : null,
      { label: "", render: (r) => onlineDot(r.online) },
      { label: "ID", render: (r) => h("strong", { class: "mono" }, r.id) },
      { label: "Device name", render: (r) => h("span", {}, r.hostname || muted("—"), r.username ? h("div", { class: "muted" }, r.username) : null) },
      { label: "Platform", render: (r) => h("span", { title: r.os }, r.platform || "—", r.version ? h("div", { class: "muted" }, "v" + r.version) : null) },
      { label: "User", render: (r) => r.user_name ? h("span", {}, r.user_name, r.group_name ? h("div", { class: "muted" }, r.group_name) : null) : muted("—") },
      { label: "Device group", render: (r) => r.device_group_name || muted("—") },
      { label: "Strategy", render: (r) => r.strategy_name || muted("—") },
      { label: "IP", render: (r) => h("span", { class: "mono" }, r.ip) },
      { label: "Status", render: (r) => r.disabled ? badge("Disabled", "danger") : r.online ? badge(r.conns.length ? `${r.conns.length} session${r.conns.length > 1 ? "s" : ""}` : "Online", "ok") : muted(ago(r.last_seen_at)) },
      { label: "Note", cls: "wrap", render: (r) => muted(r.note) },
    ];
    append(clear(listEl), table(cols, data.items, {
      onRow: (r) => deviceDialog(r.id, load),
      empty: state.q || state.status || state.group ? "No devices match." : "No devices yet. Point a RustDesk client at this server and it appears here within a few seconds.",
    }), pager(data.total, state.page, 50, (p) => { state.page = p; load(); }));
  }

  function drawBulk() {
    clear(bulk);
    if (!selected.size) return;
    const ids = () => [...selected];
    const done = () => { selected.clear(); drawBulk(); load(); };
    append(bulk, muted(`${selected.size} selected`),
      menuButton("Batch actions ▾", [
        (can("devices.assign_to_user") || can("devices.change_group") || can("devices.change_strategy")) && { label: "Assign…", onClick: () => bulkAssign(ids(), done) },
        can("devices.enable_disable") && { label: "Enable", onClick: () => api("POST", "/devices/bulk", { action: "enable", ids: ids() }).then(done, fail) },
        can("devices.enable_disable") && { label: "Disable", onClick: () => confirmDialog("Disable devices", `Disable ${selected.size} devices? Nobody can connect to them until they are enabled again.`, "Disable", async () => { await api("POST", "/devices/bulk", { action: "disable", ids: ids() }); done(); }) },
        can("devices.delete") && { label: "Delete", danger: true, onClick: () => confirmDialog("Delete devices", `Delete ${selected.size} devices? Only disabled devices can be deleted. They reappear if they check in again.`, "Delete", async () => { await api("POST", "/devices/bulk", { action: "delete", ids: ids() }); done(); }) },
      ]));
  }

  append(clear(mainEl), h("div", { class: "toolbar" }, search, filters, h("div", { class: "grow" }), bulk), listEl);
  await load();
  refreshTimer = setInterval(() => { if (!document.querySelector(".overlay")) load().catch(() => {}); }, 15000);
  if (params[0]) deviceDialog(params[0], load);
}

function bulkAssign(ids, done) {
  const keep = "__keep";
  const fields = [];
  const owner = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.users)), keep);
  const group = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.device_groups)), keep);
  const strategy = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.strategies, "— none —")), keep);
  if (can("devices.assign_to_user")) fields.push(field("User", owner));
  if (can("devices.change_group")) fields.push(field("Device group", group));
  if (can("devices.change_strategy")) fields.push(field("Strategy", strategy));
  modal({
    title: `Assign ${ids.length} devices`,
    body: h("div", { class: "form" }, fields),
    actions: [{ label: "Cancel" }, {
      label: "Apply", primary: true, onClick: async () => {
        const body = { action: "assign", ids };
        if (owner.value !== keep) body.user_id = intOrNull(owner.value);
        if (group.value !== keep) body.device_group_id = intOrNull(group.value);
        if (strategy.value !== keep) body.strategy_id = intOrNull(strategy.value);
        await api("POST", "/devices/bulk", body);
        toast("Devices updated");
        done();
      },
    }],
  });
}

async function deviceDialog(id, reload) {
  let d;
  try { d = await api("GET", "/devices/" + encodeURIComponent(id)); } catch (e) { return fail(e); }
  const c = d.can;
  const source = { device: "set on the device", user: "from its user", device_group: "from its device group", default: "the default strategy" }[d.effective_strategy_source];
  const info = h("dl", { class: "kv" },
    [["Status", h("span", {}, onlineDot(d.online), d.online ? "Online" : "Last online " + ago(d.last_seen_at), d.disabled ? h("span", {}, " ", badge("Disabled", "danger")) : null)],
     ["Device name", d.reported_hostname], ["OS user", d.reported_username], ["OS", d.os], ["CPU", d.cpu], ["Memory", d.memory],
     ["Version", d.version], ["IP", d.ip], ["First seen", dt(d.created_at)],
     ["Strategy in effect", d.effective_strategy ? `${d.effective_strategy} (${source})` : muted("none")],
     d.blocked && !d.disabled ? ["Blocked", "its user is disabled"] : null]
      .filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v || "—")]));
  const parts = [info];
  const inputs = {};
  const form = [];
  if (c["devices.edit_info"]) {
    inputs.name_override = h("input", { value: d.name_override, placeholder: d.reported_hostname });
    inputs.username_override = h("input", { value: d.username_override, placeholder: d.reported_username });
    inputs.note = h("textarea", {}, d.note);
    form.push(h("div", { class: "row" }, field("Device name", inputs.name_override, "Shown instead of the reported name"), field("Device username", inputs.username_override)));
  }
  const row = [];
  if (c["devices.assign_to_user"]) { inputs.user_id = select(optList(LOOKUP.users), d.user_id); row.push(field("User", inputs.user_id, "Set automatically when someone logs in on the device.")); }
  if (c["devices.change_group"]) { inputs.device_group_id = select(optList(LOOKUP.device_groups), d.device_group_id); row.push(field("Device group", inputs.device_group_id)); }
  if (row.length) form.push(h("div", { class: "row" }, row));
  if (c["devices.change_strategy"]) { inputs.strategy_id = select(optList(LOOKUP.strategies, "— none (use user / group) —"), d.strategy_id); form.push(field("Strategy", inputs.strategy_id)); }
  if (inputs.note) form.push(field("Note", inputs.note));
  if (form.length) parts.push(h("hr", {}), h("div", { class: "form" }, form));
  else if (d.note) parts.push(h("p", {}, d.note));
  if (d.recent_connections.length) {
    parts.push(h("h3", {}, "Recent connections"), table([
      { label: "When", render: (r) => dt(r.started_at) },
      { label: "Direction", render: (r) => r.device_id === d.id ? "Incoming" : "Outgoing" },
      { label: "Other side", render: (r) => r.device_id === d.id ? `${r.controller ? r.controller + " · " : ""}${r.peer_id} ${r.peer_name}` : r.device_id },
      { label: "Type", key: "type" },
      { label: "Duration", render: (r) => r.ended_at ? dur(r.duration) : badge("ongoing", "ok") },
    ], d.recent_connections));
  }
  if (Object.keys(d.sysinfo || {}).length) {
    parts.push(h("details", {}, h("summary", { class: "muted" }, "Raw system info"), h("pre", { class: "mono" }, JSON.stringify(d.sysinfo, null, 2))));
  }
  const actions = [];
  if (c["devices.delete"] && d.disabled) actions.push({ label: "Delete", danger: true, onClick: () => { confirmDialog("Delete device", `Delete ${d.id}? It reappears if it checks in again, without its note or assignments.`, "Delete", async () => { await api("DELETE", "/devices/" + encodeURIComponent(d.id)); toast("Device deleted"); reload(); }); } });
  if (c["devices.enable_disable"]) {
    actions.push(d.disabled
      ? { label: "Enable", onClick: async () => { await api("POST", `/devices/${encodeURIComponent(d.id)}/enable`); toast("Device enabled"); reload(); } }
      : { label: "Disable", danger: true, onClick: () => { confirmDialog("Disable device", `Disable ${d.id}? Nobody can connect to it until it is enabled again (RussDesk pushes a blocking IP whitelist to it).`, "Disable", async () => { await api("POST", `/devices/${encodeURIComponent(d.id)}/disable`); toast("Device disabled"); reload(); }); } });
  }
  if (c.disconnect && d.conns.length) actions.push({ label: "Disconnect all", danger: true, onClick: () => { confirmDialog("Disconnect", `End all ${d.conns.length} sessions on ${d.id}?`, "Disconnect", async () => { await api("POST", `/devices/${encodeURIComponent(d.id)}/disconnect`, {}); toast("Disconnect sent"); }); } });
  if (c["devices.edit_info"]) actions.push({ label: "Refresh info", onClick: async () => { await api("POST", `/devices/${encodeURIComponent(d.id)}/refresh`); toast("The device re-sends its system info on its next heartbeat"); } });
  actions.push({ label: "Close" });
  if (Object.keys(inputs).length) {
    actions.push({
      label: "Save", primary: true, onClick: async () => {
        const body = {};
        for (const [k, el] of Object.entries(inputs)) body[k] = k.endsWith("_id") ? intOrNull(el.value) : el.value;
        await api("PATCH", "/devices/" + encodeURIComponent(d.id), body);
        toast("Saved");
        reload();
      },
    });
  }
  modal({ title: `${d.id}${d.hostname ? " · " + d.hostname : ""}`, body: h("div", {}, parts), actions, wide: true });
}

// -- users -------------------------------------------------------------------------

function userStatusBadge(u) {
  if (u.status === 1) return badge("Normal", "ok");
  if (u.status === -1) return badge("Unverified", "warn");
  return badge("Disabled", "danger");
}

function tfaBadge(u) {
  if (u.totp_enabled) return h("span", {}, badge(u.totp_expired ? "Expired" : "On", u.totp_expired ? "warn" : "ok"), u.force_2fa ? muted(" enforced") : null);
  if (u.force_2fa) return badge("Enforced, not set up", "warn");
  return u.email_verification ? badge("Email code", "accent") : muted("Off");
}

async function pageUsers(_params, mainEl) {
  setPage("Users",
    ME.smtp_ready && can("users.invite") ? h("button", { onclick: () => inviteDialog(load) }, "Invite") : null,
    can("users.create") ? h("button", { class: "primary", onclick: () => userDialog(null, load) }, "New user") : null);
  const listEl = h("div", {});
  const search = h("input", { type: "search", placeholder: "Search users…", "aria-label": "Search users" });
  const group = select([["", "All groups"], ["none", "No group"]].concat(LOOKUP.user_groups.map((g) => [g.id, g.name])), "", { "aria-label": "Group" });
  const status = select([["", "All statuses"], ["1", "Normal"], ["0", "Disabled"], ["-1", "Unverified"]], "", { "aria-label": "Status" });
  for (const el of [search, group, status]) el.addEventListener("input", () => load().catch(fail));
  async function load() {
    const qs = new URLSearchParams({ q: search.value, group: group.value, status: status.value });
    const data = await api("GET", "/users?" + qs);
    append(clear(listEl), table([
      { label: "Username", render: (u) => h("strong", {}, u.name) },
      { label: "Name", render: (u) => h("span", {}, u.display_name, u.email ? h("div", { class: "muted" }, u.email) : null) },
      { label: "Group", render: (u) => u.group_name || muted("—") },
      { label: "Role", render: (u) => u.is_admin ? badge("Administrator", "accent") : (u.admin_role_ids.length ? u.admin_role_ids.map((id) => nameOf(LOOKUP.admin_roles, id)).join(", ") : "User") },
      { label: "Status", render: userStatusBadge },
      { label: "2FA", render: tfaBadge },
      { label: "Devices", key: "devices" },
      { label: "Last login", render: (u) => ago(u.last_login_at) },
    ], data.items, { onRow: (u) => userDialog(u, load) }));
  }
  append(clear(mainEl), h("div", { class: "toolbar" }, search, group, status), listEl);
  await load();
}

function inviteDialog(reload) {
  const name = h("input", { autocomplete: "off" });
  const email = h("input", { type: "email" });
  const group = select(optList(LOOKUP.user_groups), "");
  const note = h("input", {});
  modal({
    title: "Invite a user",
    body: h("div", { class: "form" }, h("p", { class: "muted" }, "They get an email with a link to set their password (valid 7 days)."),
      h("div", { class: "row" }, field("Username", name), field("Email", email)), h("div", { class: "row" }, field("User group", group), field("Note", note))),
    actions: [{ label: "Cancel" }, { label: "Send invitation", primary: true, onClick: async () => {
      await api("POST", "/users/invite", { name: name.value, email: email.value, group_id: intOrNull(group.value), note: note.value });
      toast("Invitation sent");
      await refreshLookup(); reload();
    } }],
  });
}

function userDialog(u, reload) {
  const creating = !u;
  u = u || { name: "", display_name: "", email: "", note: "", is_admin: false, status: 1, group_id: null, strategy_id: null, admin_role_ids: [], force_2fa: false, email_verification: false };
  const editable = (perm) => creating ? true : can(perm);
  const name = h("input", { value: u.name, autocomplete: "off", disabled: !creating });
  const display = h("input", { value: u.display_name, disabled: !editable("users.edit_display_name") });
  const email = h("input", { type: "email", value: u.email, disabled: !editable("users.edit_email") });
  const note = h("textarea", { disabled: !editable("users.edit_note") }, u.note);
  const group = select(optList(LOOKUP.user_groups), u.group_id, { disabled: !editable("users.change_group") });
  const strategy = select(optList(LOOKUP.strategies, "— none —"), u.strategy_id, { disabled: !can("users.change_strategy") });
  const password = h("input", { type: "password", autocomplete: "new-password", placeholder: creating ? "At least 8 characters" : "Leave empty to keep", disabled: !editable("users.edit_password") });
  const admin = checkbox("Administrator (full console access)", u.is_admin);
  const force2fa = checkbox("Require two-factor authentication", u.force_2fa, "The user must set up an authenticator app before using the console or logging in from the client.");
  const emailVer = checkbox("Email login verification", u.email_verification, "Send a code by email at each login (needs SMTP). TOTP replaces it when set up.");
  const roles = checklist(LOOKUP.admin_roles, u.admin_role_ids, { render: (r) => `${r.name} (${r.type})`, empty: "No admin roles defined" });
  const sessionsEl = h("div", {});
  const fields = [
    h("div", { class: "row" }, field("Username", name, "Used to log in from the RustDesk client"), field("Display name", display)),
    h("div", { class: "row" }, field("Email", email), field(creating ? "Password" : "New password", password)),
    h("div", { class: "row" }, field("User group", group), field("Strategy for this user's devices", strategy)),
  ];
  if (ME.is_admin) fields.push(admin);
  if (!creating && can("users.manage_2fa")) fields.push(h("div", { class: "row" }, force2fa, emailVer));
  if (ME.is_admin) fields.push(field("Admin roles", roles, "Delegate part of the console to a non-administrator. The permissions of all roles add up."));
  fields.push(field("Note", note), sessionsEl);
  const actions = [{ label: "Cancel" }];
  if (!creating) {
    const more = [];
    if (can("users.enable_disable")) more.push(u.status === 1
      ? { label: "Disable", danger: true, onClick: async () => { await api("POST", `/users/${u.id}/disable`); toast("User disabled; their devices are blocked"); reload(); } }
      : { label: "Enable", onClick: async () => { await api("POST", `/users/${u.id}/enable`); toast("User enabled"); reload(); } });
    if (can("users.delete") && u.status !== 1) more.push({ label: "Delete", danger: true, onClick: () => { confirmDialog("Delete user", `Delete ${u.name}? Their personal address book and the shared books they own are deleted, and their devices become unassigned.`, "Delete", async () => { await api("DELETE", "/users/" + u.id); toast("User deleted"); await refreshLookup(); reload(); }); } });
    if (can("users.manage_2fa") && u.totp_enabled) more.push({ label: "Reset 2FA", onClick: async () => { await api("POST", `/users/${u.id}/reset-2fa`); toast("Two-factor login removed"); reload(); } });
    if (can("users.force_logout")) more.push({ label: "Force logout", onClick: async () => { await api("POST", `/users/${u.id}/logout-all`); toast("All sessions revoked"); } });
    if (can("devices.assign_to_user")) more.push({ label: "Assign devices", onClick: () => assignDevicesDialog(u, reload) });
    actions.unshift(...more);
    api("GET", `/users/${u.id}/sessions`).then((s) => {
      if (!s.items.length) return;
      append(sessionsEl, h("details", {}, h("summary", { class: "muted" }, `${s.items.length} signed-in session(s)`),
        table([
          { label: "Where", render: (t) => t.kind === "console" ? "Web console" : `Client ${t.device_id} ${t.device_info.name || ""}` },
          { label: "IP", key: "ip" },
          { label: "Last used", render: (t) => ago(t.last_seen_at) },
        ], s.items)));
    }).catch(() => {});
  }
  actions.push({
    label: creating ? "Create" : "Save", primary: true, onClick: async () => {
      const data = {};
      if (creating) Object.assign(data, { name: name.value, display_name: display.value, email: email.value, note: note.value, group_id: intOrNull(group.value) });
      else {
        if (can("users.edit_display_name")) data.display_name = display.value;
        if (can("users.edit_email")) data.email = email.value;
        if (can("users.edit_note")) data.note = note.value;
        if (can("users.change_group")) data.group_id = intOrNull(group.value);
        if (can("users.manage_2fa")) { data.force_2fa = force2fa.box.checked; data.email_verification = emailVer.box.checked; }
      }
      if (can("users.change_strategy")) data.strategy_id = intOrNull(strategy.value);
      if (ME.is_admin) { data.is_admin = admin.box.checked; data.admin_role_ids = roles.values(); }
      if (password.value) data.password = password.value;
      if (creating) await api("POST", "/users", data); else await api("PATCH", "/users/" + u.id, data);
      toast(creating ? "User created" : "Saved");
      await refreshLookup();
      reload();
    },
  });
  modal({ title: creating ? "New user" : "Edit " + u.name, body: h("div", { class: "form" }, fields), actions, wide: true });
}

async function assignDevicesDialog(u, reload) {
  const data = await api("GET", "/devices?size=500");
  const list = checklist(data.items.map((d) => ({ id: d.id, name: `${d.id} ${d.hostname || ""}`, user: d.user_name })),
    data.items.filter((d) => d.user_id === u.id).map((d) => d.id),
    { render: (d) => h("span", {}, h("span", { class: "mono" }, d.name), d.user && d.user !== u.name ? muted(` (now ${d.user})`) : null) });
  modal({
    title: `Assign devices to ${u.name}`, body: h("div", {}, h("p", { class: "muted" }, "Ticked devices are assigned to this user."), list),
    actions: [{ label: "Cancel" }, { label: "Assign", primary: true, onClick: async () => {
      await api("POST", `/users/${u.id}/assign-devices`, { device_ids: list.values() });
      toast("Devices assigned"); reload();
    } }],
  });
}

// -- groups ------------------------------------------------------------------------

async function pageGroups(params, mainEl) {
  const kind = params[0] === "devices" ? "devices" : "users";
  const canUG = can("user_groups.view"), canDG = can("device_groups.view");
  const active = kind === "devices" || !canUG ? "devices" : "users";
  let data;
  setPage("Groups",
    active === "users" && can("user_groups.edit") ? h("button", { class: "primary", onclick: () => userGroupDialog(null) }, "New user group") : null,
    active === "devices" && can("device_groups.edit") ? h("button", { class: "primary", onclick: () => deviceGroupDialog(null) }, "New device group") : null);
  const rulesText = (items) => items.length ? items.map((i) => `${i.name}${i.type === 2 ? " (user)" : ""}`).join(", ") : muted("—");

  async function load() {
    data = await api("GET", "/groups");
    const header = tabs([canUG ? ["#/groups/users", "User groups"] : null, canDG ? ["#/groups/devices", "Device groups"] : null].filter(Boolean),
      active === "users" ? "#/groups/users" : "#/groups/devices");
    if (active === "users") {
      append(clear(mainEl), header,
        h("p", { class: "muted" }, "Members of a group can connect to each other's devices. \"Can access to\" lets the group also reach other groups' users and device groups; \"Can be accessed from\" is the same setting seen from the other side."),
        table([
          { label: "Name", render: (g) => h("strong", {}, g.name) },
          { label: "Members", render: (g) => h("button", { class: "link", onclick: () => membersDialog("user_group", g) }, String(g.members)) },
          { label: "Can access to", cls: "wrap", render: (g) => rulesText(g.allowed_outgoings) },
          { label: "Can be accessed from", cls: "wrap", render: (g) => rulesText(g.allowed_incomings) },
          { label: "Note", cls: "wrap", key: "note" },
        ], data.user_groups, { onRow: can("user_groups.edit") ? userGroupDialog : null, empty: "No user groups. Users without a group only reach their own devices." }));
    } else {
      append(clear(mainEl), header,
        h("p", { class: "muted" }, "A device belongs to at most one device group. Access granted here adds to the access users have through their user group."),
        table([
          { label: "Name", render: (g) => h("strong", {}, g.name) },
          { label: "Devices", render: (g) => h("button", { class: "link", onclick: () => membersDialog("device_group", g) }, String(g.devices)) },
          { label: "Can be accessed from", cls: "wrap", render: (g) => rulesText(g.allowed_incomings) },
          { label: "Strategy", render: (g) => g.strategy_name || muted("—") },
          { label: "Note", cls: "wrap", key: "note" },
        ], data.device_groups, { onRow: can("device_groups.edit") || can("device_groups.change_strategy") ? deviceGroupDialog : null, empty: "No device groups yet." }));
    }
  }

  const incomingLists = (rules) => {
    const ug = checklist(data.user_groups.map((g) => ({ id: "0:" + g.id, name: g.name })), rules.filter((r) => r.type === 0).map((r) => "0:" + r.id));
    const users = checklist(LOOKUP.users.map((u) => ({ id: "2:" + u.id, name: u.name })), rules.filter((r) => r.type === 2).map((r) => "2:" + r.id));
    return { ug, users, values: () => ug.values().concat(users.values()).map((v) => ({ type: parseInt(v, 10), id: parseInt(v.split(":")[1], 10) })) };
  };

  function userGroupDialog(g) {
    const creating = !g;
    g = g || { name: "", note: "", allowed_incomings: [], allowed_outgoings: [] };
    const name = h("input", { value: g.name });
    const note = h("input", { value: g.note });
    const out = checklist(
      data.user_groups.filter((x) => x.id !== g.id).map((x) => ({ id: "0:" + x.id, name: "User group: " + x.name }))
        .concat(data.device_groups.map((x) => ({ id: "1:" + x.id, name: "Device group: " + x.name }))),
      g.allowed_outgoings.map((r) => `${r.type}:${r.id}`));
    const inc = incomingLists(g.allowed_incomings.filter((r) => !(r.type === 0 && r.id === g.id)));
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Create" : "Save", primary: true, onClick: async () => {
        const body = { name: name.value, note: note.value,
          allowed_outgoings: out.values().map((v) => ({ type: parseInt(v, 10), id: parseInt(v.split(":")[1], 10) })),
          allowed_incomings: inc.values() };
        if (creating) await api("POST", "/user-groups", body); else await api("PATCH", "/user-groups/" + g.id, body);
        await refreshLookup(); load();
      },
    }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete group", `Delete ${g.name}? Its members stay, without a group.`, "Delete", async () => { await api("DELETE", "/user-groups/" + g.id); await refreshLookup(); load(); }) });
    modal({
      title: creating ? "New user group" : "Edit " + g.name, actions, wide: true,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name), field("Note", note)),
        field("Can access to", out, "Members can connect to devices of these user groups and these device groups."),
        h("div", { class: "row" }, field("Can be accessed from: user groups", inc.ug), field("Can be accessed from: users", inc.users))),
    });
  }

  function deviceGroupDialog(g) {
    const creating = !g;
    g = g || { name: "", note: "", strategy_id: null, allowed_incomings: [] };
    const editable = can("device_groups.edit");
    const name = h("input", { value: g.name, disabled: !editable });
    const note = h("input", { value: g.note, disabled: !editable });
    const strategy = select(optList(LOOKUP.strategies), g.strategy_id, { disabled: !(creating || can("device_groups.change_strategy")) });
    const inc = incomingLists(g.allowed_incomings);
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Create" : "Save", primary: true, onClick: async () => {
        const body = {};
        if (editable) Object.assign(body, { name: name.value, note: note.value, allowed_incomings: inc.values() });
        if (creating || can("device_groups.change_strategy")) body.strategy_id = intOrNull(strategy.value);
        if (creating) await api("POST", "/device-groups", body); else await api("PATCH", "/device-groups/" + g.id, body);
        await refreshLookup(); load();
      },
    }];
    if (!creating && editable) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete group", `Delete ${g.name}? Its devices stay, without a group.`, "Delete", async () => { await api("DELETE", "/device-groups/" + g.id); await refreshLookup(); load(); }) });
    modal({
      title: creating ? "New device group" : "Edit " + g.name, actions, wide: true,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name, "Custom clients can join it with preset-device-group-name."), field("Note", note)),
        field("Strategy", strategy, "Applies to devices in the group that have no device or user strategy."),
        editable ? h("div", { class: "row" }, field("Can be accessed from: user groups", inc.ug), field("Can be accessed from: users", inc.users)) : null),
    });
  }

  async function membersDialog(kind, g) {
    const isUsers = kind === "user_group";
    const editPerm = isUsers ? "users.change_group" : "devices.change_group";
    let items;
    if (isUsers) items = can("users.view") ? (await api("GET", "/users")).items.map((u) => ({ id: u.id, name: u.name, current: u.group_id, other: u.group_name })) : [];
    else items = (await api("GET", "/devices?size=500")).items.map((d) => ({ id: d.id, name: `${d.id} ${d.hostname || ""}`, current: d.device_group_id, other: d.device_group_name }));
    const chosen = items.filter((i) => i.current === g.id).map((i) => i.id);
    const list = checklist(items, chosen, { render: (i) => h("span", {}, i.name, i.other && i.current !== g.id ? muted(` (in ${i.other})`) : null) });
    if (!can(editPerm)) for (const b of list.querySelectorAll("input[type=checkbox]")) b.disabled = true;
    modal({
      title: `${isUsers ? "Members" : "Devices"} of ${g.name}`, body: list,
      actions: [{ label: "Close" }, can(editPerm) ? { label: "Save", primary: true, onClick: async () => {
        const now = list.values();
        const add = now.filter((x) => !chosen.includes(x)), remove = chosen.filter((x) => !now.includes(x));
        await api("POST", `/${isUsers ? "user-groups" : "device-groups"}/${g.id}/members`, { add, remove });
        toast("Saved"); load();
      } } : null],
    });
  }

  await load();
}

// -- strategies --------------------------------------------------------------------

async function pageStrategies(_params, mainEl) {
  const editable = can("strategies.edit");
  setPage("Strategies", editable ? h("button", { class: "primary", onclick: () => editor(null) }, "New strategy") : null);
  let data;
  async function load() {
    data = await api("GET", "/strategies");
    append(clear(mainEl),
      h("p", { class: "muted" }, "A strategy is a set of client settings pushed to devices within about 15 seconds. Priority: the device's own strategy, then its user's, then its device group's (then the default, if one is set). If the strategy that applies is disabled, the device is not managed by any strategy. When a strategy stops applying, the settings it set go back to the client's defaults."),
      table([
        { label: "Name", render: (s) => h("span", {}, h("strong", {}, s.name), s.is_default ? h("span", {}, " ", badge("default", "accent")) : null) },
        { label: "Status", render: (s) => s.enabled ? badge("Enabled", "ok") : badge("Disabled") },
        { label: "Applied to", render: (s) => h("span", { title: "Devices actually managed by this strategy, after priority" }, `${s.applied} device${s.applied === 1 ? "" : "s"}`) },
        { label: "Assigned", render: (s) => muted(`${s.devices} devices · ${s.users} users · ${s.device_groups} device groups`) },
        { label: "Settings", render: (s) => Object.keys(s.options).length },
        { label: "Changed", render: (s) => ago(s.modified_at) },
        { label: "", cls: "actions", render: (s) => menuButton("More ▾", [
          editable && { label: "Edit", onClick: () => editor(s) },
          editable && { label: s.enabled ? "Disable" : "Enable", onClick: () => api("PATCH", "/strategies/" + s.id, { enabled: !s.enabled }).then(load, fail) },
          editable && { label: "Duplicate", onClick: () => api("POST", `/strategies/${s.id}/duplicate`).then(async () => { await refreshLookup(); load(); }, fail) },
          can("devices.change_strategy") && { label: "Edit devices", onClick: () => targetsDialog(s, "devices") },
          can("users.change_strategy") && { label: "Edit users", onClick: () => targetsDialog(s, "users") },
          can("device_groups.change_strategy") && { label: "Edit device groups", onClick: () => targetsDialog(s, "device_groups") },
          editable && { label: "Delete", danger: true, onClick: () => confirmDialog("Delete strategy", `Delete ${s.name}? Devices using it fall back to the next strategy in line.`, "Delete", async () => { await api("DELETE", "/strategies/" + s.id); await refreshLookup(); load(); }) },
        ]) },
      ], data.items, { onRow: editable ? editor : null, empty: "No strategies yet." }));
  }

  async function targetsDialog(s, kind) {
    const label = { devices: "devices", users: "users", device_groups: "device groups" }[kind];
    const res = await api("GET", `/strategies/${s.id}/targets?kind=${kind}`);
    const chosen = res.items.filter((i) => i.selected).map((i) => i.id);
    const list = checklist(res.items, chosen, { render: (i) => h("span", {}, h("span", { class: kind === "devices" ? "mono" : "" }, kind === "devices" ? `${i.id} ${i.name || ""}` : i.name),
      muted("  " + i.strategies.join(" / "))) });
    modal({
      title: `${s.name}: ${label}`, wide: true,
      body: h("div", {}, h("p", { class: "muted" }, kind === "devices" ? "Ticked devices get this strategy. Grey text: device strategy / user strategy / device group strategy (\"-\" = none)." : `Ticked ${label} get this strategy. Grey text: their current strategy.`), list),
      actions: [{ label: "Cancel" }, { label: "Save", primary: true, onClick: async () => {
        const now = list.values();
        await api("POST", `/strategies/${s.id}/targets`, { kind, add: now.filter((x) => !chosen.includes(x)), remove: chosen.filter((x) => !now.includes(x)) });
        toast("Saved; devices pick it up within about 15 seconds"); load();
      } }],
    });
  }

  function editor(s) {
    const creating = !s;
    s = s || { name: "", note: "", options: {}, is_default: false, enabled: true };
    const name = h("input", { value: s.name });
    const note = h("input", { value: s.note });
    const isDefault = checkbox("Default strategy for devices that have no other strategy", s.is_default);
    const enabled = checkbox("Enabled", s.enabled);
    const controls = [];
    const sections = {};
    for (const o of data.catalog) {
      const on = Object.prototype.hasOwnProperty.call(s.options, o.key);
      const value = on ? s.options[o.key] : o.default;
      let ctl;
      if (o.type === "bool") ctl = select([["Y", "Yes"], ["N", "No"]], value);
      else if (o.type === "choice") ctl = select(o.choices, value);
      else ctl = h("input", { type: "text", value });
      ctl.setAttribute("aria-label", o.label);
      const box = h("input", { type: "checkbox", checked: on, "aria-label": "Set " + o.label });
      const row = h("div", { class: "opt" + (on ? "" : " off") }, box, h("div", {}, o.label, h("div", { class: "key mono" }, o.key)), h("div", { class: "ctl" }, ctl));
      box.addEventListener("change", () => row.classList.toggle("off", !box.checked));
      ctl.addEventListener("input", () => { box.checked = true; row.classList.remove("off"); });
      controls.push({ key: o.key, box, ctl });
      (sections[o.section] = sections[o.section] || []).push(row);
    }
    const known = new Set(data.catalog.map((o) => o.key));
    const custom = h("textarea", { class: "mono", placeholder: "key=value, one per line", "aria-label": "Other client options" },
      Object.entries(s.options).filter(([k]) => !known.has(k)).map(([k, v]) => `${k}=${v}`).join("\n"));
    const body = h("div", {},
      h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name, "Custom clients can pick it with preset-strategy-name."), field("Note", note)),
        h("div", { class: "row" }, enabled, isDefault)),
      h("p", { class: "muted" }, "Tick a setting to enforce it; unticked settings are left to the device."),
      Object.entries(sections).map(([title, rows]) => h("div", { class: "opt-section" }, h("h3", {}, title), rows)),
      h("div", { class: "opt-section" }, h("h3", {}, "Other client options"), custom,
        h("div", { class: "hint muted" }, "Any option key from the RustDesk client's settings, for example enable-directx-capture=N.")));
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Create" : "Save", primary: true, onClick: async () => {
        const options = {};
        for (const c of controls) if (c.box.checked) options[c.key] = c.ctl.value;
        for (const line of custom.value.split("\n")) {
          const m = line.trim().match(/^([A-Za-z0-9_-]+)\s*=(.*)$/);
          if (m) options[m[1]] = m[2].trim();
          else if (line.trim()) throw new Error("Cannot read custom option: " + line.trim());
        }
        let id = s.id;
        if (creating) id = (await api("POST", "/strategies", { name: name.value, note: note.value, options })).id;
        await api("PATCH", "/strategies/" + id, Object.assign({ enabled: enabled.box.checked }, creating ? {} : { name: name.value, note: note.value, options }));
        if (isDefault.box.checked !== s.is_default) await api("PATCH", "/settings", { default_strategy_id: isDefault.box.checked ? id : null });
        toast("Saved; devices pick it up within about 15 seconds");
        await refreshLookup(); load();
      },
    }];
    modal({ title: creating ? "New strategy" : "Edit " + s.name, body, actions, wide: true });
  }
  await load();
}

// -- address books -----------------------------------------------------------------

const RULES = [[1, "Read-only"], [2, "Read/Write"], [3, "Full Control"]];
const ruleName = (r) => (RULES.find((x) => x[0] === r) || [0, "None"])[1];

async function pageAddressBooks(params, mainEl) {
  if (params[0]) return pageAddressBook(params[0], params[1], mainEl);
  setPage("Address Books", h("button", { class: "primary", onclick: create }, "New shared address book"));
  const data = await api("GET", "/address-books");
  const personal = data.items.filter((b) => b.personal);
  const shared = data.items.filter((b) => !b.personal);
  const cols = [
    { label: "Name", render: (b) => h("a", { href: "#/address-books/" + b.guid }, b.name) },
    { label: "Owner", key: "owner" },
    { label: "Devices", key: "peers" },
    { label: "Your permission", render: (b) => ruleName(b.rule) },
    { label: "Shared password", render: (b) => b.password_set ? badge("Set") : muted("—") },
    { label: "Note", cls: "wrap", key: "note" },
  ];
  append(clear(mainEl),
    h("p", { class: "muted" }, "Address books appear in the RustDesk client's Address Book tab after signing in. My address book is private; shared books can be given to users, user groups or everyone."),
    h("div", { class: "panel" }, h("h2", {}, "My address book"),
      personal.map((b) => h("p", {}, h("a", { href: "#/address-books/" + b.guid }, "Open my address book"), muted(` · ${b.peers} devices`)))),
    h("div", { class: "panel" }, h("h2", {}, "Shared"),
      table(cols, shared, { onRow: (b) => { location.hash = "#/address-books/" + b.guid; }, empty: "No shared address books you can see." })));
  function create() {
    const name = h("input", {});
    const note = h("input", {});
    const password = h("input", { type: "password", autocomplete: "new-password" });
    const owner = ME.is_admin ? select(LOOKUP.users.map((u) => [u.id, u.name]), ME.id) : null;
    modal({
      title: "New shared address book",
      body: h("div", { class: "form" }, field("Name", name, "Custom clients can add themselves with preset-address-book-name."), field("Note", note),
        field("Default shared password", password, "Used when a device entry has no password of its own."), owner ? field("Owner", owner) : null),
      actions: [{ label: "Cancel" }, {
        label: "Create", primary: true, onClick: async () => {
          const res = await api("POST", "/address-books", { name: name.value, note: note.value, password: password.value, owner_id: owner ? intOrNull(owner.value) : undefined });
          location.hash = "#/address-books/" + res.guid;
        },
      }],
    });
  }
}

async function pageAddressBook(guid, view, mainEl) {
  const b = await api("GET", "/address-books/" + guid);
  if (!mainEl.isConnected) return;  // the user navigated away meanwhile
  const canWrite = b.rule >= 2;
  const full = b.rule >= 3;
  // Re-render whatever the user is looking at now: an action can finish
  // after they switched tabs, and this view may already be gone.
  const reload = () => route();
  const tagColor = Object.fromEntries(b.tags.map((t) => [t.name, t.color]));
  setPage(b.name,
    h("a", { class: "btn", href: "#/address-books" }, "‹ All books"),
    canWrite ? h("button", { onclick: importDialog }, "Import") : null,
    canWrite ? h("button", { class: "primary", onclick: () => peerDialog(null) }, "Add") : null);

  const tagChip = (name) => h("span", { class: "tag" }, (() => { const i = h("i", {}); i.style.background = argbToCss(tagColor[name] || 0); return i; })(), name);
  const base = "#/address-books/" + guid;
  const header = tabs([[base, "Devices"], [base + "/tags", "Tags"], !b.personal && full ? [base + "/share", "Sharing"] : null,
    full && !b.personal ? [base + "/settings", "Settings"] : null, [base + "/recycle", `Recycle bin (${b.recycled})`]].filter(Boolean),
    view ? `${base}/${view}` : base);
  const info = h("p", { class: "muted" }, `${b.personal ? "Personal" : "Shared"} address book of ${b.owner} · your permission: ${ruleName(b.rule)}`, b.password_set ? " · default shared password set" : "");

  function peerDialog(p) {
    const creating = !p;
    p = p || { id: "", alias: "", tags: [], note: "", password_set: false };
    const id = h("input", { value: p.id, disabled: !creating, class: "mono" });
    const alias = h("input", { value: p.alias });
    const note = h("input", { value: p.note });
    const password = b.personal ? null : h("input", { type: "password", autocomplete: "new-password", placeholder: p.password_set ? "Set; leave empty to keep" : "Optional" });
    const tags = checklist(b.tags.map((t) => ({ id: t.name, name: t.name })), p.tags, { empty: "No tags in this book" });
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Add" : "Save", primary: true, onClick: async () => {
        const body = { alias: alias.value, note: note.value, tags: tags.values() };
        if (password && password.value) body.password = password.value;
        if (creating) await api("POST", `/address-books/${guid}/peers`, Object.assign(body, { id: id.value.trim() }));
        else await api("PATCH", `/address-books/${guid}/peers/${encodeURIComponent(p.id)}`, body);
        reload();
      },
    }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: async () => { await api("DELETE", `/address-books/${guid}/peers/${encodeURIComponent(p.id)}`); toast("Moved to the recycle bin"); reload(); } });
    modal({
      title: creating ? "Add device" : "Edit " + p.id, actions,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("RustDesk ID (or IP for direct access)", id), field("Alias", alias)),
        field("Note", note), password ? field("Device password", password, "Members connect with it from this book; without one, the book's default shared password is used.") : null,
        field("Tags", tags)),
    });
  }

  async function importDialog() {
    const res = await api("GET", `/address-books/${guid}/importable`);
    const list = checklist(res.items.map((d) => ({ id: d.id, name: `${d.id}  ${d.hostname || ""}`, d })), [],
      { render: (i) => h("span", {}, onlineDot(i.d.online), h("span", { class: "mono" }, i.name), i.d.user_name ? muted(" · " + i.d.user_name) : null), empty: "All your devices are already in this book." });
    modal({
      title: "Import devices", body: h("div", {}, h("p", { class: "muted" }, "Pick devices from the device list."), list),
      actions: [{ label: "Cancel" }, { label: "Save", primary: true, onClick: async () => {
        await api("POST", `/address-books/${guid}/import`, { ids: list.values() });
        reload();
      } }],
    });
  }

  if (!view) {
    // Tag filter: Pro's tag panel with Untagged and "filter by intersection".
    const chosen = new Set();
    let intersect = false;
    const tableEl = h("div", {});
    const drawPeers = () => {
      const visible = b.peers.filter((p) => {
        if (!chosen.size) return true;
        const wants = [...chosen];
        const has = (t) => t === "__untagged" ? !p.tags.length : p.tags.includes(t);
        return intersect ? wants.every(has) : wants.some(has);
      });
      append(clear(tableEl), table([
        { label: "", render: (p) => onlineDot(p.online) },
        { label: "ID", render: (p) => h("strong", { class: "mono" }, p.id) },
        { label: "Alias", key: "alias" },
        { label: "Device", render: (p) => h("span", {}, p.hostname, p.username ? h("div", { class: "muted" }, p.username) : null) },
        { label: "Platform", key: "platform" },
        { label: "Tags", cls: "wrap", render: (p) => p.tags.map(tagChip) },
        !b.personal ? { label: "Password", render: (p) => p.password_set ? badge("Set") : muted("—") } : null,
        { label: "Note", cls: "wrap", key: "note" },
      ], visible, { onRow: canWrite ? peerDialog : null, empty: chosen.size ? "No devices match the selected tags." : "No devices. Add or import them, or add them from the RustDesk client." }));
    };
    const chips = h("div", { class: "inline-list tag-filter" },
      [["__untagged", "Untagged"]].concat(b.tags.map((t) => [t.name, t.name])).map(([value, label]) => {
        const btn = h("button", { class: "small chip", type: "button", "aria-pressed": "false", onclick: () => {
          chosen.has(value) ? chosen.delete(value) : chosen.add(value);
          btn.setAttribute("aria-pressed", chosen.has(value) ? "true" : "false");
          drawPeers();
        } }, value === "__untagged" ? label : tagChip(label));
        return btn;
      }));
    const inter = checkbox("Filter by intersection", false);
    inter.box.addEventListener("change", () => { intersect = inter.box.checked; drawPeers(); });
    drawPeers();
    append(clear(mainEl), header, info, b.tags.length ? h("div", { class: "toolbar" }, chips, inter) : null, tableEl);
    return;
  }

  if (view === "tags") {
    const newTag = h("input", { placeholder: "New tag", "aria-label": "New tag" });
    const newColor = h("input", { type: "color", value: "#2196f3", "aria-label": "Tag colour" });
    append(clear(mainEl), header, info, h("div", { class: "panel" },
      b.tags.length ? table([
        { label: "Tag", render: (t) => tagChip(t.name) },
        { label: "Devices", render: (t) => b.peers.filter((p) => p.tags.includes(t.name)).length },
        canWrite ? { label: "", cls: "actions", render: (t) => h("span", { class: "split" },
          h("button", { class: "small", onclick: () => {
            const n = h("input", { value: t.name });
            const c = h("input", { type: "color", value: argbToCss(t.color) });
            modal({ title: "Edit tag", body: h("div", { class: "form" }, field("Name", n), field("Colour", c)),
              actions: [{ label: "Cancel" }, { label: "Save", primary: true, onClick: async () => { await api("PATCH", `/address-books/${guid}/tags/${encodeURIComponent(t.name)}`, { name: n.value.trim(), color: cssToArgb(c.value) }); reload(); } }] });
          } }, "Edit"),
          h("button", { class: "small danger", onclick: () => confirmDialog("Delete tag", `Delete tag ${t.name}? Devices keep their other tags.`, "Delete", async () => { await api("DELETE", `/address-books/${guid}/tags/${encodeURIComponent(t.name)}`); reload(); }) }, "Delete")) } : null,
      ], b.tags) : muted("No tags yet."),
      canWrite ? h("form", { class: "toolbar", onsubmit: async (e) => { e.preventDefault(); if (!newTag.value.trim()) return; try { await api("POST", `/address-books/${guid}/tags`, { name: newTag.value.trim(), color: cssToArgb(newColor.value) }); reload(); } catch (err) { fail(err); } } },
        newTag, newColor, h("button", { type: "submit" }, "Add tag")) : null));
    return;
  }

  if (view === "share") {
    const rules = b.rules.map((r) => ({ ...r }));
    const rulesEl = h("div", {});
    const drawRules = () => append(clear(rulesEl), rules.length ? table([
      { label: "Shared with", render: (r) => r.everyone ? h("strong", {}, "Everyone") : r.user_id ? h("span", {}, "User ", h("strong", {}, r.name)) : h("span", {}, "Group ", h("strong", {}, r.name)) },
      { label: "Permission", render: (r) => select(RULES, r.rule, { "aria-label": "Permission for " + r.name, onchange: (e) => { r.rule = parseInt(e.target.value, 10); } }) },
      { label: "", cls: "actions", render: (r) => h("button", { class: "small danger", onclick: () => { rules.splice(rules.indexOf(r), 1); drawRules(); } }, "Remove") },
    ], rules) : h("p", { class: "muted" }, "Not shared: only the owner and administrators can see this book."));
    drawRules();
    const who = select([["", "Share with…"], ["e", "Everyone"]].concat(
      LOOKUP.users.filter((u) => u.id !== b.owner_id).map((u) => ["u" + u.id, "User: " + u.name]),
      LOOKUP.user_groups.map((g) => ["g" + g.id, "Group: " + g.name])), "", { "aria-label": "Share with" });
    who.addEventListener("change", () => {
      const v = who.value;
      if (!v) return;
      const id = parseInt(v.slice(1), 10);
      const exists = rules.find((r) => (v === "e" ? r.everyone : v[0] === "u" ? r.user_id === id : r.user_group_id === id));
      if (!exists) rules.push(v === "e" ? { everyone: true, rule: 1, name: "Everyone" } : v[0] === "u" ? { user_id: id, rule: 1, name: nameOf(LOOKUP.users, id) } : { user_group_id: id, rule: 1, name: nameOf(LOOKUP.user_groups, id) });
      who.value = "";
      drawRules();
    });
    append(clear(mainEl), header, info, h("div", { class: "panel" },
      h("p", { class: "muted" }, "Read-only: view and use passwords. Read/Write: edit devices and tags. Full Control: also re-share, rename or delete the book. A user rule wins over a group rule, which wins over Everyone."),
      rulesEl,
      h("div", { class: "toolbar" }, who, h("div", { class: "grow" }),
        h("button", { class: "primary", onclick: async () => {
          try { await api("PATCH", "/address-books/" + guid, { rules: rules.map((r) => ({ user_id: r.user_id || null, user_group_id: r.user_group_id || null, everyone: !!r.everyone, rule: r.rule })) }); toast("Sharing saved"); reload(); } catch (e) { fail(e); }
        } }, "Save sharing"))));
    return;
  }

  if (view === "settings") {
    const n = h("input", { value: b.name });
    const note = h("input", { value: b.note });
    const pw = h("input", { type: "password", autocomplete: "new-password", placeholder: b.password_set ? "Set; leave empty to keep" : "Not set" });
    const clearPw = checkbox("Remove the default shared password", false);
    const owner = ME.is_admin ? select(LOOKUP.users.map((u) => [u.id, u.name]), b.owner_id) : null;
    append(clear(mainEl), header, info, h("div", { class: "panel" }, h("div", { class: "form" },
      h("div", { class: "row" }, field("Name", n), field("Note", note)),
      field("Default shared password", pw, "Used when a device entry has no password of its own."),
      b.password_set ? clearPw : null, owner ? field("Owner", owner) : null,
      h("div", { class: "split" },
        h("button", { class: "primary", onclick: async () => {
          const body = { name: n.value, note: note.value };
          if (pw.value) body.password = pw.value; else if (clearPw.box.checked) body.password = "";
          if (owner) body.owner_id = intOrNull(owner.value);
          try { await api("PATCH", "/address-books/" + guid, body); toast("Saved"); reload(); } catch (e) { fail(e); }
        } }, "Save"),
        h("button", { class: "danger", onclick: () => confirmDialog("Delete address book", `Delete ${b.name} and its ${b.peers.length} devices for everyone?`, "Delete", async () => { await api("DELETE", "/address-books/" + guid); location.hash = "#/address-books"; }) }, "Delete address book")))));
    return;
  }

  if (view === "recycle") {
    const res = await api("GET", `/address-books/${guid}/recycle`);
    append(clear(mainEl), header, info,
      canWrite && res.items.length ? h("div", { class: "toolbar" }, h("div", { class: "grow" }),
        h("button", { class: "danger", onclick: () => confirmDialog("Empty recycle bin", `Delete ${res.items.length} entries for good?`, "Empty", async () => { await api("POST", `/address-books/${guid}/recycle/delete`, { all: true }); reload(); }) }, "Empty recycle bin")) : null,
      table([
        { label: "ID", render: (p) => h("strong", { class: "mono" }, p.id) },
        { label: "Alias", key: "alias" },
        { label: "Deleted", render: (p) => dt(p.deleted_at) },
        canWrite ? { label: "", cls: "actions", render: (p) => h("span", { class: "split" },
          h("button", { class: "small", onclick: async () => { await api("POST", `/address-books/${guid}/recycle/restore`, { ids: [p.id] }); reload(); } }, "Restore"),
          h("button", { class: "small danger", onclick: async () => { await api("POST", `/address-books/${guid}/recycle/delete`, { ids: [p.id] }); reload(); } }, "Delete")) } : null,
      ], res.items, { empty: "The recycle bin is empty. Devices removed from this book land here." }));
  }
}

// -- admin roles -------------------------------------------------------------------

async function pageAdminRoles(_params, mainEl) {
  setPage("Admin Roles", h("button", { class: "primary", onclick: () => roleDialog(null) }, "New role"));
  let data;
  const TYPES = [["global", "Global: all users and devices"], ["group", "Group scoped: selected groups"], ["individual", "Individual: the user's own devices and logs"]];
  async function load() {
    data = await api("GET", "/admin-roles");
    append(clear(mainEl),
      h("p", { class: "muted" }, "Admin roles delegate part of the console to users who are not administrators. A user can hold several roles; their permissions add up. Edit permissions include view."),
      table([
        { label: "Name", render: (r) => h("strong", {}, r.name) },
        { label: "Type", render: (r) => r.type },
        { label: "Permissions", render: (r) => r.perms.length },
        { label: "Scope", cls: "wrap", render: (r) => r.type !== "group" ? muted("—") :
          [r.user_groups.map((id) => nameOf(LOOKUP.user_groups, id)), r.device_groups.map((id) => nameOf(LOOKUP.device_groups, id)), r.unassigned ? ["unassigned devices"] : []].flat().join(", ") || muted("nothing") },
        { label: "Users", render: (r) => r.users.map((id) => nameOf(LOOKUP.users, id)).join(", ") || muted("—") },
        { label: "Note", cls: "wrap", key: "note" },
      ], data.items, { onRow: roleDialog, empty: "No admin roles yet." }));
  }
  function roleDialog(r) {
    const creating = !r;
    r = r || { name: "", type: "global", note: "", perms: [], user_groups: [], device_groups: [], unassigned: false, users: [] };
    const name = h("input", { value: r.name });
    const note = h("input", { value: r.note });
    const type = select(TYPES, r.type, { disabled: !creating });
    const permsEl = h("div", {});
    const scopeEl = h("div", {});
    let perms = checklist([], []);
    const ug = checklist(LOOKUP.user_groups, r.user_groups);
    const dg = checklist(LOOKUP.device_groups, r.device_groups);
    const unassigned = checkbox("Unassigned devices", r.unassigned);
    const users = checklist(LOOKUP.users, r.users);
    const drawPerms = () => {
      const valid = data.permissions.filter((p) => p.types.includes(type.value));
      perms = checklist(valid.map((p) => ({ id: p.name, name: p.label })), r.perms.filter((p) => valid.some((v) => v.name === p)));
      append(clear(permsEl), field("Permissions", perms));
      clear(scopeEl);
      if (type.value === "group") append(scopeEl, h("div", { class: "row" }, field("User groups", ug, "Their users, and devices assigned to them"), field("Device groups", dg)), unassigned);
    };
    type.addEventListener("change", drawPerms);
    drawPerms();
    const actions = [{ label: "Cancel" }, { label: creating ? "Create" : "Save", primary: true, onClick: async () => {
      const body = { name: name.value, note: note.value, perms: perms.values(), user_groups: ug.values(), device_groups: dg.values(), unassigned: unassigned.box.checked, users: users.values() };
      if (creating) await api("POST", "/admin-roles", Object.assign(body, { type: type.value })); else await api("PATCH", "/admin-roles/" + r.id, body);
      await refreshLookup(); load();
    } }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete role", `Delete ${r.name}? Its users lose these permissions.`, "Delete", async () => { await api("DELETE", "/admin-roles/" + r.id); await refreshLookup(); load(); }) });
    modal({ title: creating ? "New admin role" : "Edit " + r.name, wide: true, actions,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name), field("Type", type, creating ? "Cannot be changed later" : null)), field("Note", note), permsEl, scopeEl, field("Users with this role", users)) });
  }
  await load();
}

// -- logs --------------------------------------------------------------------------

const LOG_KINDS = [["connections", "Connection"], ["files", "File"], ["alarms", "Alarm"], ["console", "Console"]];

function sideCell(id, name, extra) {
  return h("span", {}, extra ? h("strong", {}, extra + " ") : null, h("span", { class: "mono" }, id || "—"), name ? h("div", { class: "muted" }, name) : null);
}

async function pageLogs(params, mainEl) {
  const kind = LOG_KINDS.find((k) => k[0] === params[0]) ? params[0] : "connections";
  const state = { page: 1 };
  const listEl = h("div", {});
  const q = h("input", { type: "search", placeholder: "Search…", "aria-label": "Search logs" });
  const device = kind === "console" ? null : h("input", { placeholder: "Device ID", class: "mono", "aria-label": "Device ID" });
  const connType = kind === "connections" ? select([["", "All types"], ["0", "Remote Desktop"], ["1", "File Transfer"], ["2", "Port Transfer"], ["3", "View Camera"], ["4", "Terminal"]], "", { "aria-label": "Type" }) : null;
  const active = kind === "connections" ? checkbox("Ongoing only", false) : null;
  const from = h("input", { type: "date", "aria-label": "From" });
  const to = h("input", { type: "date", "aria-label": "To" });
  const csv = h("a", { class: "btn" }, "Export as CSV");
  setPage("Logs", csv);
  const query = (extra) => {
    const p = { q: q.value, page: state.page, size: 50 };
    if (device) p.device = device.value;
    if (connType && connType.value) p.conn_type = connType.value;
    if (active && active.box.checked) p.active = "1";
    if (from.value) p.from = Math.floor(new Date(from.value + "T00:00").getTime() / 1000);
    if (to.value) p.to = Math.floor(new Date(to.value + "T00:00").getTime() / 1000) + 86400;
    return new URLSearchParams(Object.assign(p, extra || {}));
  };
  async function load() {
    csv.href = `/api/admin/logs/${kind}?` + query({ format: "csv" });
    const data = await api("GET", `/logs/${kind}?` + query());
    const editNote = (r) => {
      const input = h("textarea", {}, r.note);
      modal({ title: "Connection note", body: field("Note", input), actions: [{ label: "Cancel" }, { label: "Save", primary: true, onClick: async () => { await api("PATCH", `/logs/connections/${r.id}`, { note: input.value }); load(); } }] });
    };
    const columns = {
      connections: [
        { label: "Type", render: (r) => r.type === "Not Logged In" ? badge("Not Logged In", "warn") : r.type },
        { label: "Controlled device", render: (r) => sideCell(r.device_id, r.device_name) },
        { label: "Controlling side", render: (r) => sideCell(r.peer_id, [r.peer_name, r.ip].filter(Boolean).join(" · "), r.controller) },
        { label: "Start", render: (r) => dt(r.started_at) },
        { label: "End", render: (r) => r.ended_at ? dt(r.ended_at) : badge("ongoing", "ok") },
        { label: "Duration", render: (r) => dur(r.duration) },
        { label: "Authentication", render: (r) => h("span", {}, r.auth || "—", r.two_factor ? h("div", { class: "muted" }, "+ " + r.two_factor) : null) },
        { label: "Note", cls: "wrap", render: (r) => h("span", {}, r.note, " ", h("button", { class: "link small", onclick: () => editNote(r), "aria-label": "Edit note" }, "✎")) },
        data.can_edit ? { label: "Action", render: (r) => !r.ended_at ? h("button", { class: "small danger", onclick: () => disconnectLog(r.id, load) }, "Disconnect") : null } : null,
      ],
      files: [
        { label: "Controlled device", render: (r) => sideCell(r.device_id, r.device_name) },
        { label: "Controlling side", render: (r) => sideCell(r.peer_id, [r.peer_name, r.ip].filter(Boolean).join(" · ")) },
        { label: "Time", render: (r) => dt(r.created_at) },
        { label: "Direction", key: "direction" },
        { label: "File", cls: "wrap", render: (r) => h("span", { class: "mono" }, r.path) },
        { label: "Detail", render: (r) => r.is_file && r.size !== null ? bytes(r.size) : h("button", { class: "link", onclick: () => modal({
          title: `${r.count} files`, body: h("div", {}, r.count > (r.files || []).length ? h("p", { class: "muted" }, `The ${(r.files || []).length} largest files:`) : null,
            table([{ label: "File", cls: "wrap", render: (f) => h("span", { class: "mono" }, f[0]) }, { label: "Size", render: (f) => bytes(f[1]) }], r.files || [])),
        }) }, `${r.count} files`) },
      ],
      alarms: [
        { label: "Type", render: (r) => badge(r.type, "danger") },
        { label: "From", render: (r) => h("span", { class: "mono" }, r.from || r.ip || "—") },
        { label: "Target", render: (r) => h("span", { class: "mono" }, r.target || "—") },
        { label: "Event time", render: (r) => dt(r.created_at) },
        { label: "Detail", cls: "wrap", render: (r) => h("span", { class: "mono muted" }, JSON.stringify(r.detail)) },
      ],
      console: [
        { label: "Type", key: "type" },
        { label: "User", key: "user_name" },
        { label: "Operation", render: (r) => r.operation },
        { label: "Time", render: (r) => dt(r.created_at) },
        { label: "Detail", cls: "wrap", render: (r) => h("span", {}, r.target, r.detail ? h("div", { class: "mono muted" }, r.detail) : null) },
      ],
    }[kind];
    append(clear(listEl), table(columns, data.items, { empty: "No entries." }),
      pager(data.total, state.page, 50, (p) => { state.page = p; load(); }));
  }
  let timer;
  for (const el of [q, device, connType, from, to, active && active.box].filter(Boolean)) {
    el.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.page = 1; load().catch(fail); }, 300); });
    el.addEventListener("change", () => { state.page = 1; load().catch(fail); });
  }
  append(clear(mainEl),
    tabs(LOG_KINDS.map(([k, label]) => ["#/logs/" + k, label]), "#/logs/" + kind),
    h("div", { class: "toolbar" }, q, device, connType, active, muted("from"), from, muted("to"), to),
    listEl);
  await load();
}

// -- recordings --------------------------------------------------------------------

async function pageRecordings(_params, mainEl) {
  setPage("Recordings");
  const [data, settings] = await Promise.all([api("GET", "/recordings"), api("GET", "/settings")]);
  const notice = settings.accept_recordings
    ? h("p", { class: "muted" }, "Clients upload a session recording while it is recorded. Turn recording on for devices with a strategy (Automatically record incoming sessions).")
    : h("div", { class: "panel" }, "Recording upload is turned off. ", h("a", { href: "#/settings/others" }, "Enable it in Settings"), " to receive recordings from clients.");
  append(clear(mainEl), notice, table([
    { label: "File", render: (r) => h("span", { class: "mono" }, r.filename) },
    { label: "Size", render: (r) => bytes(r.size) },
    { label: "Started", render: (r) => dt(r.created_at) },
    { label: "Status", render: (r) => r.completed_at ? badge("complete", "ok") : badge("in progress", "warn") },
    { label: "", cls: "actions", render: (r) => h("span", { class: "split" },
      h("a", { class: "btn", href: `/api/admin/recordings/${r.id}/download` }, "Download"),
      h("button", { class: "small danger", onclick: () => confirmDialog("Delete recording", `Delete ${r.filename}?`, "Delete", async () => { await api("DELETE", "/recordings/" + r.id); pageRecordings(null, mainEl); }) }, "Delete")) },
  ], data.items, { empty: "No recordings." }));
}

// -- settings ----------------------------------------------------------------------

async function pageSettings(params, mainEl) {
  const sub = ["general", "smtp", "tokens", "others"].includes(params[0]) ? params[0] : "general";
  setPage("Settings");
  const header = tabs([["#/settings/general", "General"], ["#/settings/smtp", "SMTP"], ["#/settings/tokens", "Tokens"], ["#/settings/others", "Others"]], "#/settings/" + sub);
  const s = await api("GET", "/settings");
  const save = async (body) => { try { await api("PATCH", "/settings", body); toast("Settings saved"); pageSettings(params, mainEl); } catch (e) { fail(e); } };
  const text = (k, ph, attrs) => h("input", Object.assign({ value: s[k], placeholder: ph || "" }, attrs || {}));
  const num = (k) => h("input", { type: "number", min: 0, value: s[k] });

  if (sub === "general") {
    const cfg = await api("GET", "/client-config");
    const f = {
      id_server: text("id_server", "taken from the address you opened this page with"),
      relay_server: text("relay_server", "optional; hbbs already tells clients its relay"),
      api_server: text("api_server", "empty: clients use the ID server's port minus 2 (31114)"),
      server_key: text("server_key", s.detected_key ? "read from " + s.hbbs_key_file : "contents of id_ed25519.pub"),
    };
    append(clear(mainEl), header, h("div", { class: "grid two" },
      h("div", {}, h("div", { class: "panel" }, h("h2", {}, "Server addresses", h("span", { class: "sub" }, "what clients are told to use")),
        h("div", { class: "form" },
          field("ID server (hbbs)", f.id_server, "Host and port of hbbs, e.g. rd.example.com:31116. Without a port clients use 21116."),
          field("Relay server (hbbr)", f.relay_server),
          field("API server (this console)", f.api_server, "Leave empty when RussDesk runs on the ID server's host two ports below hbbs (31114 with hbbs on 31116). Set it only for HTTPS or another host/port, e.g. https://rd.example.com."),
          field("Server public key", f.server_key, s.detected_key ? "Leave empty to use the key read from hbbs: " + s.detected_key : "Paste the content of hbbs' id_ed25519.pub."),
          h("div", {}, h("button", { class: "primary", onclick: () => save(Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]))) }, "Save"))))),
      h("div", {}, clientConfigPanel(cfg),
        h("div", { class: "panel" }, h("h2", {}, "Scan on a phone"), h("p", { class: "muted" }, "RustDesk for Android: Settings → ID/Relay server → scan the QR code."), qrImage("config=" + cfg.config_string)),
        h("div", { class: "panel" }, h("h2", {}, "Custom client presets"),
          h("p", { class: "muted" }, "Clients built with these options are sorted automatically when they first check in (Pro's deployment presets; `rustdesk --assign` with an API token does the same afterwards):"),
          h("dl", { class: "kv" },
            [["preset-user-name", "assigns the device to this user"], ["preset-device-group-name", "puts it in this device group"], ["preset-strategy-name", "gives it this strategy"],
             ["preset-address-book-name", "adds it to this shared book (with -tag, -alias, -password, -note)"], ["preset-note", "sets the device note"]]
              .map(([k, v]) => [h("dt", {}, h("code", {}, k)), h("dd", {}, v)]))))));
    return;
  }

  if (sub === "smtp") {
    const f = {
      smtp_host: text("smtp_host", "smtp.example.com"),
      smtp_port: num("smtp_port"),
      smtp_security: select([["starttls", "STARTTLS (usually port 587)"], ["ssl", "SSL/TLS (usually port 465)"], ["none", "None"]], s.smtp_security),
      smtp_user: text("smtp_user", "", { autocomplete: "off" }),
      smtp_password: h("input", { type: "password", autocomplete: "new-password", placeholder: s.smtp_password_set ? "Set; leave empty to keep" : "" }),
      smtp_from: text("smtp_from", "rustdesk@example.com"),
    };
    const testTo = h("input", { type: "email", placeholder: ME.email || "you@example.com", "aria-label": "Test recipient" });
    append(clear(mainEl), header, h("div", { class: "panel" }, h("h2", {}, "Outgoing email", h("span", { class: "sub" }, "invitations and login verification codes")),
      h("div", { class: "form" },
        h("div", { class: "row" }, field("SMTP server", f.smtp_host), field("Port", f.smtp_port)),
        h("div", { class: "row" }, field("Security", f.smtp_security), field("From address", f.smtp_from)),
        h("div", { class: "row" }, field("Account", f.smtp_user, "Leave empty if the server needs no login"), field("Password", f.smtp_password, "Gmail and Microsoft 365 need an app password")),
        h("div", { class: "split" }, h("button", { class: "primary", onclick: () => {
          const body = {};
          for (const [k, el] of Object.entries(f)) {
            if (k === "smtp_password" && !el.value) continue;
            body[k] = k === "smtp_port" ? parseInt(el.value || "0", 10) : el.value;
          }
          save(body);
        } }, "Save")),
        h("hr", {}),
        h("div", { class: "split" }, testTo, h("button", { onclick: async () => {
          try { await api("POST", "/settings/smtp-test", { to: testTo.value }); toast("Test email sent"); } catch (e) { fail(e); }
        } }, "Send test email")))));
    return;
  }

  if (sub === "tokens") {
    const data = await api("GET", "/tokens");
    const LEVELS = [[0, "None"], [1, "Read"], [2, "Read/Write"]];
    const RES = [["device", "Device"], ["audit", "Audit log"], ["user", "User"], ["group", "Group"], ["strategy", "Strategy"], ["ab", "Address book"]];
    const create = () => {
      const name = h("input", {});
      const expiry = select([["", "Never"], ["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]], "");
      const levels = Object.fromEntries(RES.map(([k]) => [k, select(LEVELS, 0, { "aria-label": k })]));
      modal({ title: "Create API token", wide: true,
        body: h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name), field("Expires", expiry)),
          h("div", { class: "row" }, RES.map(([k, label]) => field(label, levels[k]))),
          h("p", { class: "muted" }, "Use the token with `rustdesk --assign --token …` on a device (needs Device read/write) or with RustDesk Server Pro's Python scripts (users.py, devices.py, ab.py, …).")),
        actions: [{ label: "Cancel" }, { label: "Create", primary: true, onClick: async () => {
          const perms = Object.fromEntries(Object.entries(levels).map(([k, el]) => [k, parseInt(el.value, 10)]));
          const res = await api("POST", "/tokens", { name: name.value, perms, expires_days: expiry.value ? parseInt(expiry.value, 10) : null });
          modal({ title: "Token created", body: h("div", {}, h("p", {}, "Copy it now; it is not shown again."), h("div", { class: "copy-box" }, h("code", {}, res.token), copyButton(() => res.token))) });
          pageSettings(params, mainEl);
        } }] });
    };
    append(clear(mainEl), header, h("div", { class: "toolbar" }, h("div", { class: "grow" }), h("button", { class: "primary", onclick: create }, "Create token")),
      table([
        { label: "Name", render: (t) => h("strong", {}, t.name) },
        { label: "Permissions", cls: "wrap", render: (t) => RES.filter(([k]) => t.perms[k]).map(([k, label]) => `${label}: ${t.perms[k] === 2 ? "rw" : "r"}`).join(", ") || muted("none") },
        { label: "Created by", key: "creator" },
        { label: "Expires", render: (t) => t.expires_at ? dt(t.expires_at) : "Never" },
        { label: "Last used", render: (t) => ago(t.last_used_at) },
        { label: "", cls: "actions", render: (t) => h("button", { class: "small danger", onclick: () => confirmDialog("Delete token", `Delete ${t.name}? Scripts using it stop working.`, "Delete", async () => { await api("DELETE", "/tokens/" + t.id); pageSettings(params, mainEl); }) }, "Delete") },
      ], data.items, { empty: "No API tokens." }));
    return;
  }

  // Others
  const f = {
    log_retention_days: num("log_retention_days"),
    client_token_days: num("client_token_days"),
    console_session_hours: num("console_session_hours"),
    max_peers_per_ab: num("max_peers_per_ab"),
    recordings_max_mb: num("recordings_max_mb"),
    console_url: text("console_url", "e.g. https://rd.example.com (used in invitation links)"),
  };
  const flags = {
    only_admin_logs: checkbox("Only admin can access logs", s.only_admin_logs, "Normal users then cannot see even their own logs (admin roles with Audit Logs - View still can)."),
    allow_non_admin_share: checkbox("Allow non-admin to share address books to other groups", s.allow_non_admin_share, "Otherwise non-admins share only within their own user group, never with everyone."),
    disable_accessible_devices: checkbox("Disable retrieving accessible devices", s.disable_accessible_devices, "Hides the Accessible devices tab content in clients."),
    accept_recordings: checkbox("Accept session recordings uploaded by clients", s.accept_recordings, "Clients upload without logging in, so anyone who can reach this server could send files. Cap the storage below."),
  };
  append(clear(mainEl), header, h("div", { class: "panel" }, h("div", { class: "form" },
    h("div", { class: "row" }, field("Log retention (days, 0 = keep forever)", f.log_retention_days), field("Console URL", f.console_url)),
    h("div", { class: "row" }, field("Client login lifetime (days, 0 = never expires)", f.client_token_days, "With 0, a client stays logged in until it logs out or is signed out from the console."), field("Console session (hours)", f.console_session_hours)),
    h("div", { class: "row" }, field("Devices per address book (0 = unlimited)", f.max_peers_per_ab), field("Recording storage cap (MB)", f.recordings_max_mb)),
    Object.values(flags),
    h("div", {}, h("button", { class: "primary", onclick: () => {
      const body = {};
      for (const [k, el] of Object.entries(f)) body[k] = el.type === "number" ? parseInt(el.value || "0", 10) : el.value;
      for (const [k, el] of Object.entries(flags)) body[k] = el.box.checked;
      save(body);
    } }, "Save")))));
}

// -- account -----------------------------------------------------------------------

async function pageAccount(_params, mainEl) {
  setPage("Account");
  ME = await api("GET", "/me");
  const display = h("input", { value: ME.display_name });
  const email = h("input", { type: "email", value: ME.email });
  const emailVer = checkbox("Email login verification", ME.email_verification, ME.smtp_ready ? "Send me a code by email at each login. Not used once TOTP is on." : "Needs SMTP to be set up by an administrator.");
  if (!ME.smtp_ready && !ME.email_verification) emailVer.box.disabled = true;
  const profile = h("div", { class: "panel" }, h("h2", {}, "Profile"),
    h("dl", { class: "kv spaced" }, h("dt", {}, "Username"), h("dd", {}, ME.name), h("dt", {}, "Role"), h("dd", {}, ME.is_admin ? "Administrator" : (ME.admin_roles.length ? ME.admin_roles.join(", ") : "User"))),
    h("div", { class: "form" }, h("div", { class: "row" }, field("Display name", display), field("Email", email)), emailVer,
      h("div", {}, h("button", { class: "primary", onclick: async () => {
        try { await api("PATCH", "/account", { display_name: display.value, email: email.value, email_verification: emailVer.box.checked }); toast("Saved"); } catch (e) { fail(e); }
      } }, "Save"))));

  const current = h("input", { type: "password", autocomplete: "current-password" });
  const next = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const code = ME.totp_enabled ? h("input", { inputmode: "numeric", autocomplete: "one-time-code", placeholder: "123456" }) : null;
  const pwPanel = h("div", { class: "panel" }, h("h2", {}, "Change password"),
    h("form", {
      class: "form", onsubmit: async (e) => {
        e.preventDefault();
        if (next.value !== again.value) return toast("The new passwords differ", true);
        try { await api("POST", "/account/password", { current: current.value, new: next.value, code: code ? code.value : "" }); toast("Password changed; other sessions were signed out"); current.value = next.value = again.value = ""; } catch (err) { fail(err); }
      },
    }, field("Current password", current), field("New password", next, "At least 8 characters"), field("Repeat new password", again),
      code ? field("Two-factor code", code) : null,
      h("div", {}, h("button", { class: "primary", type: "submit" }, "Change password"))));

  const showCodes = (codes) => modal({ title: "Backup codes",
    body: h("div", {}, h("p", {}, "Each code works once, in place of a code from your app. Store them somewhere safe; they are not shown again."),
      h("pre", { class: "mono backup-codes" }, codes.join("\n")), copyButton(() => codes.join("\n"))) });
  const tfaPanel = h("div", { class: "panel" }, h("h2", {}, "Two-factor authentication (TOTP)"));
  if (ME.must_setup_2fa) tfaPanel.append(h("p", { class: "notice" }, "Your administrator requires two-factor authentication. Set it up to continue."));
  if (ME.totp_enabled) {
    const pw = h("input", { type: "password", autocomplete: "current-password" });
    const regen = h("input", { inputmode: "numeric", placeholder: "123456", "aria-label": "Code for new backup codes" });
    append(tfaPanel,
      h("p", {}, ME.totp_expired ? badge("Expired", "warn") : badge("Enabled", "ok"), " Logins from the console and the RustDesk client ask for a code from your authenticator app.",
        ME.totp_expired ? " It still works, but was set up more than 180 days ago; turn it off and on again to renew the secret." : ""),
      h("p", { class: "muted" }, `${ME.backup_codes_left} backup code${ME.backup_codes_left === 1 ? "" : "s"} left.`),
      h("div", { class: "split" }, regen, h("button", { onclick: async () => { try { showCodes((await api("POST", "/account/2fa/backup-codes", { code: regen.value })).backup_codes); pageAccount(null, mainEl); } catch (e) { fail(e); } } }, "New backup codes")),
      h("hr", {}),
      h("div", { class: "form" }, field("Password, to turn it off", pw),
        h("div", {}, h("button", { class: "danger", onclick: async () => { try { await api("POST", "/account/2fa/disable", { password: pw.value }); toast("Two-factor authentication turned off"); pageAccount(null, mainEl); } catch (e) { fail(e); } } }, "Turn off"))));
  } else {
    append(tfaPanel, h("p", { class: "muted" }, "Ask for a code from an authenticator app (Aegis, Google or Microsoft Authenticator, Authy, 1Password…) at each login, in the console and in the RustDesk client."),
      h("button", {
        class: "primary", onclick: async () => {
          const setup = await api("POST", "/account/2fa/setup");
          const c = h("input", { inputmode: "numeric", maxlength: 6, placeholder: "123456" });
          modal({
            title: "Enable 2FA",
            body: h("div", { class: "form" }, h("p", {}, "Scan this with your authenticator app, then enter the 6-digit code it shows."), qrImage(setup.uri),
              h("div", { class: "hint" }, "Or enter the key by hand: ", h("code", {}, setup.secret)), field("Code", c)),
            actions: [{ label: "Cancel" }, { label: "Enable", primary: true, onClick: async () => {
              const res = await api("POST", "/account/2fa/enable", { secret: setup.secret, code: c.value });
              toast("Two-factor authentication is on");
              if (ME.must_setup_2fa) { await start(); } else { pageAccount(null, mainEl); }
              showCodes(res.backup_codes);
            } }],
          });
        },
      }, "Enable 2FA"));
  }
  append(clear(mainEl), h("div", { class: "grid two" }, ME.must_setup_2fa ? tfaPanel : [profile, tfaPanel, pwPanel]));
}
