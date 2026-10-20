"use strict";

/* RussDesk web console. Plain DOM, no framework or build step. */

const root = document.getElementById("app");
let ME = null;
let LOOKUP = { users: [], user_groups: [], device_groups: [], strategies: [] };

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
  if (resp.status === 401 && path !== "/login") {
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
  const buttons = (actions || [{ label: "Close" }]).map((a) => {
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
  const m = h("div", { class: "modal" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true" },
    h("header", {}, h("span", {}, title), h("button", { class: "small", type: "button", onclick: close, "aria-label": "Close" }, "✕")),
    h("div", { class: "body" }, body),
    h("footer", {}, errorEl, buttons));
  overlay.append(m);
  overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(overlay);
  const first = m.querySelector(".body input, .body select, .body textarea");
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
  if (!rows.length) return h("div", { class: "table-wrap" }, h("div", { class: "empty" }, opts.empty || "Nothing here yet."));
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, columns.map((c) => h("th", {}, c.label)))),
    h("tbody", {}, rows.map((r) => h("tr", {
      class: opts.onRow ? "clickable" : "",
      onclick: opts.onRow ? (e) => { if (!e.target.closest("button, input, a, select")) opts.onRow(r); } : null,
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

// -- shell and routing -------------------------------------------------------------

const NAV = [
  { href: "#/dashboard", label: "Dashboard" },
  { href: "#/devices", label: "Devices" },
  { href: "#/address-books", label: "Address books" },
  { section: "Management", admin: true },
  { href: "#/users", label: "Users", admin: true },
  { href: "#/groups", label: "Groups", admin: true },
  { href: "#/strategies", label: "Strategies", admin: true },
  { section: "Audit", admin: true },
  { href: "#/logs/connections", label: "Logs", admin: true, match: "#/logs" },
  { href: "#/recordings", label: "Recordings", admin: true },
  { section: "Server", admin: true },
  { href: "#/settings", label: "Settings", admin: true },
];

const ROUTES = {
  dashboard: pageDashboard,
  devices: pageDevices,
  users: pageUsers,
  groups: pageGroups,
  strategies: pageStrategies,
  "address-books": pageAddressBooks,
  logs: pageLogs,
  recordings: pageRecordings,
  settings: pageSettings,
  account: pageAccount,
};

let mainEl, sideEl, titleEl, actionsEl, refreshTimer;

function renderShell() {
  clear(root).className = "";
  titleEl = h("h1", {});
  actionsEl = h("div", { class: "split" });
  mainEl = h("div", {});
  sideEl = h("nav", { class: "side" },
    h("div", { class: "brand" }, h("img", { src: "/favicon.svg", alt: "" }), "RussDesk"),
    NAV.filter((n) => !n.admin || ME.is_admin).map((n) => n.section
      ? h("div", { class: "section" }, n.section)
      : h("a", { class: "nav", href: n.href, "data-match": n.match || n.href, onclick: () => sideEl.classList.remove("open") }, n.label)),
    h("div", { class: "spacer" }),
    h("div", { class: "who" },
      h("div", {}, h("strong", {}, ME.display_name || ME.name), " ", ME.is_admin ? h("span", { class: "badge accent" }, "admin") : null),
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
  if (!ME) return;
  clearInterval(refreshTimer);
  const hash = location.hash || "#/dashboard";
  const parts = hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  const page = ROUTES[parts[0]] || pageDashboard;
  for (const a of sideEl.querySelectorAll("a.nav")) {
    a.classList.toggle("active", hash.startsWith(a.dataset.match));
  }
  clear(mainEl).append(h("div", { class: "muted" }, "Loading…"));
  try {
    await page(parts.slice(1));
  } catch (err) {
    fail(err);
    clear(mainEl).append(h("div", { class: "panel" }, err.message));
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

function renderLogin() {
  clearInterval(refreshTimer);
  document.title = "Sign in · RussDesk";
  const user = h("input", { autocomplete: "username", required: true });
  const pass = h("input", { type: "password", autocomplete: "current-password", required: true });
  const code = h("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, placeholder: "123456" });
  const codeField = field("Verification code", code, "From your authenticator app");
  codeField.hidden = true;
  const err = h("div", { class: "error" });
  const btn = h("button", { class: "primary", type: "submit" }, "Sign in");
  const form = h("form", { class: "form" }, field("Username", user), field("Password", pass), codeField, err, btn);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    btn.disabled = true;
    try {
      const res = await api("POST", "/login", { username: user.value, password: pass.value, code: code.value });
      if (res.need_code) {
        codeField.hidden = false;
        code.focus();
        return;
      }
      await start();
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      btn.disabled = false;
    }
  });
  clear(root).className = "";
  root.append(h("div", { class: "login" }, h("div", { class: "card" },
    h("h1", {}, h("img", { src: "/favicon.svg", alt: "" }), "RussDesk"),
    h("p", {}, "Sign in to the console"), form)));
  user.focus();
}

async function start() {
  try {
    ME = await api("GET", "/me");
  } catch (e) {
    if (!ME) renderLogin();
    return;
  }
  await refreshLookup();
  renderShell();
  route();
}

window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", start);

// -- dashboard ---------------------------------------------------------------------

async function pageDashboard() {
  setPage("Dashboard");
  const draw = async () => {
    const [d, cfg] = await Promise.all([api("GET", "/dashboard"), api("GET", "/client-config")]);
    const stats = [
      ["Devices online", h("span", {}, d.devices_online, h("small", {}, " / " + d.devices_total))],
      ["Active sessions", d.active_sessions.length],
    ];
    if (ME.is_admin) {
      stats.push(["Connections (24 h)", d.connections_24h], ["Alarms (24 h)", d.alarms_24h], ["Users", d.users_total]);
    }
    const parts = [h("div", { class: "grid stats" }, stats.map(([l, v]) =>
      h("div", { class: "stat" }, h("div", { class: "label" }, l), h("div", { class: "value" }, v))))];

    parts.push(h("div", { class: "panel" }, h("h2", {}, "Active sessions"),
      table([
        { label: "Device", render: (r) => h("span", {}, r.device_id, " ", h("span", { class: "muted" }, r.device_name)) },
        { label: "From", render: (r) => r.peer_id ? h("span", {}, r.peer_id, " ", h("span", { class: "muted" }, r.peer_name)) : h("span", { class: "muted" }, "connecting…") },
        { label: "Type", key: "type" },
        { label: "IP", key: "ip" },
        { label: "Duration", render: (r) => dur(r.duration) },
        ME.is_admin ? { label: "", cls: "actions", render: (r) => h("button", { class: "small danger", onclick: () => disconnect(r.device_id, [r.conn_id], draw) }, "Disconnect") } : null,
      ].filter(Boolean), d.active_sessions, { empty: "No one is connected right now." })));

    const lower = [];
    if (ME.is_admin) {
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
        : h("div", { class: "muted" }, "No devices have reported yet.")));
    if (ME.is_admin && d.recent_alarms.length) {
      lower.push(h("div", { class: "panel" }, h("h2", {}, "Recent alarms"),
        d.recent_alarms.map((a) => h("div", {}, h("span", { class: "badge danger" }, a.type), " ",
          a.device_id, " ", h("span", { class: "muted" }, `${a.ip} · ${ago(a.created_at)}`)))));
    }
    lower.push(clientConfigPanel(cfg));
    parts.push(h("div", { class: "grid two" }, lower));
    append(clear(mainEl), parts);
  };
  await draw();
  refreshTimer = setInterval(() => draw().catch(() => {}), 15000);
}

function clientConfigPanel(cfg) {
  const row = (label, value) => [h("dt", {}, label), h("dd", {}, value ? h("code", {}, value) : h("span", { class: "muted" }, "not set"))];
  return h("div", { class: "panel" },
    h("h2", {}, "Connect a RustDesk client"),
    h("p", { class: "muted" }, "In RustDesk: Settings → Network → ID/Relay server. Fill in the ID server and key; leave the API server empty. Or copy the config string and use the clipboard import button."),
    h("dl", { class: "kv spaced" }, row("ID server", cfg.host), row("Relay server", cfg.relay),
      h("dt", {}, "API server"), h("dd", {}, cfg.api ? h("code", {}, cfg.api) : h("span", { class: "muted" }, "leave empty (the client uses " + (cfg.api_default || "the ID server port minus 2") + ")")),
      row("Key", cfg.key)),
    h("div", { class: "copy-box" }, h("code", {}, cfg.config_string), copyButton(() => cfg.config_string)),
    !cfg.key ? h("p", { class: "hint muted" }, "The key is empty: set it in Settings or point RUSSDESK_HBBS_KEY_FILE at hbbs' id_ed25519.pub.") : null);
}

async function disconnect(deviceId, connIds, after) {
  confirmDialog("Disconnect session", `End ${connIds ? "this session" : "all sessions"} on ${deviceId}? The device drops it within a few seconds.`, "Disconnect", async () => {
    await api("POST", `/devices/${encodeURIComponent(deviceId)}/disconnect`, connIds ? { conn_ids: connIds } : {});
    toast("Disconnect sent");
    if (after) setTimeout(() => after().catch(() => {}), 4000);
  });
}

// -- devices -----------------------------------------------------------------------

async function pageDevices(params) {
  const state = { q: "", status: "", group: "", user: "", page: 1 };
  const selected = new Set();
  const listEl = h("div", {});
  setPage("Devices");

  const search = h("input", { type: "search", placeholder: "Search ID, host, user, IP, note…" });
  let timer;
  search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.q = search.value; state.page = 1; load(); }, 250); });
  const status = select([["", "All"], ["online", "Online"], ["offline", "Offline"]], "", { onchange: (e) => { state.status = e.target.value; state.page = 1; load(); } });
  const group = select([["", "All groups"], ["none", "No group"]].concat(LOOKUP.device_groups.map((g) => [g.id, g.name])), "", { onchange: (e) => { state.group = e.target.value; state.page = 1; load(); } });
  const bulk = h("div", { class: "split" });

  async function load() {
    const qs = new URLSearchParams({ q: state.q, status: state.status, group: state.group, user: state.user, page: state.page, size: 50 });
    const data = await api("GET", "/devices?" + qs);
    const cols = [
      { label: "", render: (r) => onlineDot(r.online) },
      { label: "ID", render: (r) => h("strong", { class: "mono" }, r.id) },
      { label: "Device", render: (r) => h("span", {}, r.hostname || h("span", { class: "muted" }, "—"), r.username ? h("div", { class: "muted" }, r.username) : null) },
      { label: "Platform", render: (r) => h("span", { title: r.os }, r.platform || "—", r.version ? h("div", { class: "muted" }, "v" + r.version) : null) },
      { label: "User", render: (r) => r.user_name || h("span", { class: "muted" }, "—") },
      { label: "Group", render: (r) => r.device_group_name || h("span", { class: "muted" }, "—") },
      { label: "IP", render: (r) => h("span", { class: "mono" }, r.ip) },
      { label: "Last seen", render: (r) => r.online ? h("span", { class: "badge ok" }, r.conns.length ? `${r.conns.length} session${r.conns.length > 1 ? "s" : ""}` : "online") : ago(r.last_seen_at) },
      { label: "Note", cls: "wrap", render: (r) => h("span", { class: "muted" }, r.note) },
    ];
    if (ME.is_admin) {
      cols.unshift({
        label: "", render: (r) => h("input", {
          type: "checkbox", checked: selected.has(r.id), "aria-label": "Select " + r.id,
          onchange: (e) => { e.target.checked ? selected.add(r.id) : selected.delete(r.id); drawBulk(); },
        }),
      });
    }
    append(clear(listEl), table(cols, data.items, {
      onRow: (r) => deviceDialog(r.id, load),
      empty: state.q || state.status || state.group ? "No devices match." : "No devices yet. Point a RustDesk client's API server at this console and it appears here within a few seconds.",
    }), pager(data.total, state.page, 50, (p) => { state.page = p; load(); }));
  }

  function drawBulk() {
    clear(bulk);
    if (!selected.size) return;
    append(bulk,
      h("span", { class: "muted" }, `${selected.size} selected`),
      h("button", { class: "small", onclick: () => bulkAssign([...selected], () => { selected.clear(); drawBulk(); load(); }) }, "Assign…"),
      h("button", { class: "small danger", onclick: () => confirmDialog("Delete devices", `Remove ${selected.size} devices from the console? They reappear when they next check in.`, "Delete", async () => {
        await api("POST", "/devices/bulk", { action: "delete", ids: [...selected] });
        selected.clear(); drawBulk(); load();
      }) }, "Delete"));
  }

  append(clear(mainEl), h("div", { class: "toolbar" }, search, status, group, h("div", { class: "grow" }), bulk), listEl);
  await load();
  refreshTimer = setInterval(() => { if (!document.querySelector(".overlay")) load().catch(() => {}); }, 15000);
  if (params[0]) deviceDialog(params[0], load);
}

function bulkAssign(ids, done) {
  const keep = "__keep";
  const owner = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.users)), keep);
  const group = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.device_groups)), keep);
  const strategy = select([[keep, "(unchanged)"]].concat(optList(LOOKUP.strategies, "— inherit —")), keep);
  modal({
    title: `Assign ${ids.length} devices`,
    body: h("div", { class: "form" }, field("User", owner), field("Device group", group), field("Strategy", strategy)),
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
  const si = d.sysinfo || {};
  const info = h("dl", { class: "kv" },
    [["Status", h("span", {}, onlineDot(d.online), d.online ? "Online" : "Last seen " + ago(d.last_seen_at))],
     ["Hostname", d.hostname], ["OS user", d.username], ["OS", d.os], ["CPU", d.cpu], ["Memory", d.memory],
     ["Version", d.version], ["IP", d.ip], ["First seen", dt(d.created_at)],
     ["Effective strategy", d.effective_strategy || h("span", { class: "muted" }, "none")]]
      .map(([k, v]) => [h("dt", {}, k), h("dd", {}, v || "—")]));
  const parts = [info];
  let note, owner, group, strategy;
  if (ME.is_admin) {
    note = h("textarea", {}, d.note);
    owner = select(optList(LOOKUP.users), d.user_id);
    group = select(optList(LOOKUP.device_groups), d.device_group_id);
    strategy = select(optList(LOOKUP.strategies, "— inherit from user / group —"), d.strategy_id);
    parts.push(h("hr", {}), h("div", { class: "form" },
      h("div", { class: "row" }, field("User", owner, "Set automatically when someone logs in on the device."), field("Device group", group)),
      field("Strategy", strategy), field("Note", note)));
  } else if (d.note) {
    parts.push(h("p", {}, d.note));
  }
  if (d.recent_connections.length) {
    parts.push(h("h3", {}, "Recent connections"), table([
      { label: "When", render: (r) => dt(r.started_at) },
      { label: "Direction", render: (r) => r.device_id === d.id ? "Incoming" : "Outgoing" },
      { label: "Peer", render: (r) => r.device_id === d.id ? `${r.peer_id} ${r.peer_name}` : r.device_id },
      { label: "Type", key: "type" },
      { label: "Duration", render: (r) => dur(r.duration) },
    ], d.recent_connections));
  }
  if (Object.keys(si).length) {
    parts.push(h("details", {}, h("summary", { class: "muted" }, "Raw system info"), h("pre", { class: "mono" }, JSON.stringify(si, null, 2))));
  }
  const actions = [{ label: "Close" }];
  if (ME.is_admin) {
    actions.unshift(
      { label: "Delete", danger: true, onClick: () => { confirmDialog("Delete device", `Remove ${d.id} from the console? It reappears when it next checks in, without its note or assignments.`, "Delete", async () => { await api("DELETE", "/devices/" + encodeURIComponent(d.id)); toast("Device deleted"); reload(); }); } },
      { label: "Refresh info", onClick: async () => { await api("POST", `/devices/${encodeURIComponent(d.id)}/refresh`); toast("The device re-sends its system info on its next heartbeat"); } });
    if (d.conns.length) actions.unshift({ label: "Disconnect all", danger: true, onClick: () => disconnect(d.id, null, reload) });
    actions.push({
      label: "Save", primary: true, onClick: async () => {
        await api("PATCH", "/devices/" + encodeURIComponent(d.id), {
          note: note.value, user_id: intOrNull(owner.value), device_group_id: intOrNull(group.value), strategy_id: intOrNull(strategy.value),
        });
        toast("Saved");
        reload();
      },
    });
  }
  modal({ title: `${d.id}${d.hostname ? " · " + d.hostname : ""}`, body: h("div", {}, parts), actions, wide: true });
}

// -- users -------------------------------------------------------------------------

async function pageUsers() {
  setPage("Users", h("button", { class: "primary", onclick: () => userDialog(null, load) }, "New user"));
  const listEl = h("div", {});
  const search = h("input", { type: "search", placeholder: "Search users…" });
  search.addEventListener("input", () => load());
  async function load() {
    const data = await api("GET", "/users?q=" + encodeURIComponent(search.value));
    append(clear(listEl), table([
      { label: "Username", render: (u) => h("strong", {}, u.name) },
      { label: "Name", render: (u) => h("span", {}, u.display_name, u.email ? h("div", { class: "muted" }, u.email) : null) },
      { label: "Group", render: (u) => u.group_name || h("span", { class: "muted" }, "—") },
      { label: "Role", render: (u) => u.is_admin ? h("span", { class: "badge accent" }, "Admin") : "User" },
      { label: "Status", render: (u) => u.status === 1 ? h("span", { class: "badge ok" }, "Active") : h("span", { class: "badge danger" }, "Disabled") },
      { label: "2FA", render: (u) => u.totp_enabled ? h("span", { class: "badge ok" }, "On") : h("span", { class: "muted" }, "Off") },
      { label: "Devices", key: "devices" },
      { label: "Last login", render: (u) => ago(u.last_login_at) },
    ], data.items, { onRow: (u) => userDialog(u, load) }));
  }
  append(clear(mainEl), h("div", { class: "toolbar" }, search), listEl);
  await load();
}

function userDialog(u, reload) {
  const creating = !u;
  u = u || { name: "", display_name: "", email: "", note: "", is_admin: false, status: 1, group_id: null, strategy_id: null };
  const name = h("input", { value: u.name, autocomplete: "off" });
  const display = h("input", { value: u.display_name });
  const email = h("input", { type: "email", value: u.email });
  const note = h("textarea", {}, u.note);
  const group = select(optList(LOOKUP.user_groups), u.group_id);
  const strategy = select(optList(LOOKUP.strategies, "— none —"), u.strategy_id);
  const admin = h("input", { type: "checkbox", checked: u.is_admin });
  const active = h("input", { type: "checkbox", checked: u.status === 1 });
  const password = h("input", { type: "password", autocomplete: "new-password", placeholder: creating ? "At least 8 characters" : "Leave empty to keep" });
  const sessionsEl = h("div", {});
  const body = h("div", { class: "form" },
    h("div", { class: "row" }, field("Username", name, "Used to log in from the RustDesk client"), field("Display name", display)),
    h("div", { class: "row" }, field("Email", email), field(creating ? "Password" : "New password", password)),
    h("div", { class: "row" }, field("User group", group), field("Strategy for this user's devices", strategy)),
    h("label", { class: "check" }, admin, "Administrator (full console access)"),
    h("label", { class: "check" }, active, "Active (can log in)"),
    field("Note", note), sessionsEl);
  const actions = [{ label: "Cancel" }];
  if (!creating) {
    actions.unshift({ label: "Delete", danger: true, onClick: () => { confirmDialog("Delete user", `Delete ${u.name}? Their personal address book is deleted, shared books they own are deleted too, and their devices become unassigned.`, "Delete", async () => { await api("DELETE", "/users/" + u.id); toast("User deleted"); await refreshLookup(); reload(); }); } });
    if (u.totp_enabled) actions.unshift({ label: "Reset 2FA", onClick: async () => { await api("POST", `/users/${u.id}/reset-2fa`); toast("Two-factor login removed"); reload(); } });
    actions.unshift({ label: "Sign out everywhere", onClick: async () => { await api("POST", `/users/${u.id}/logout-all`); toast("All sessions revoked"); } });
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
      const data = {
        name: name.value, display_name: display.value, email: email.value, note: note.value,
        group_id: intOrNull(group.value), strategy_id: intOrNull(strategy.value), is_admin: admin.checked, status: active.checked ? 1 : 0,
      };
      if (password.value) data.password = password.value;
      if (creating) await api("POST", "/users", data); else await api("PATCH", "/users/" + u.id, data);
      toast(creating ? "User created" : "Saved");
      await refreshLookup();
      reload();
    },
  });
  modal({ title: creating ? "New user" : "Edit " + u.name, body, actions, wide: true });
}

// -- groups ------------------------------------------------------------------------

function checklist(items, chosen) {
  const boxes = items.map((i) => ({ id: i.id, box: h("input", { type: "checkbox", checked: chosen.includes(i.id) }), name: i.name }));
  const el = h("div", { class: "checklist" }, boxes.length ? boxes.map((b) => h("label", {}, b.box, b.name)) : h("span", { class: "muted" }, "None defined"));
  el.values = () => boxes.filter((b) => b.box.checked).map((b) => b.id);
  return el;
}

async function pageGroups() {
  setPage("Groups",
    h("button", { onclick: () => userGroupDialog(null) }, "New user group"),
    h("button", { class: "primary", onclick: () => deviceGroupDialog(null) }, "New device group"));
  let data;
  async function load() {
    data = await api("GET", "/groups");
    const ugName = (id) => nameOf(data.user_groups, id);
    const dgName = (id) => nameOf(data.device_groups, id);
    append(clear(mainEl),
      h("div", { class: "panel" }, h("h2", {}, "User groups", h("span", { class: "sub" }, "members see each other's devices; grant more access per group")),
        table([
          { label: "Name", render: (g) => h("strong", {}, g.name) },
          { label: "Members", key: "members" },
          { label: "Also sees users of", cls: "wrap", render: (g) => g.access_user_groups.map(ugName).join(", ") || h("span", { class: "muted" }, "—") },
          { label: "Also sees device groups", cls: "wrap", render: (g) => g.access_device_groups.map(dgName).join(", ") || h("span", { class: "muted" }, "—") },
          { label: "Note", cls: "wrap", key: "note" },
        ], data.user_groups, { onRow: userGroupDialog, empty: "No user groups. Users without a group only see their own devices." })),
      h("div", { class: "panel" }, h("h2", {}, "Device groups", h("span", { class: "sub" }, "organise devices and give them a strategy")),
        table([
          { label: "Name", render: (g) => h("strong", {}, g.name) },
          { label: "Devices", key: "devices" },
          { label: "Strategy", render: (g) => nameOf(LOOKUP.strategies, g.strategy_id) || h("span", { class: "muted" }, "—") },
          { label: "Note", cls: "wrap", key: "note" },
        ], data.device_groups, { onRow: deviceGroupDialog, empty: "No device groups yet." })));
  }
  function userGroupDialog(g) {
    const creating = !g;
    g = g || { name: "", note: "", access_user_groups: [], access_device_groups: [] };
    const name = h("input", { value: g.name });
    const note = h("input", { value: g.note });
    const ug = checklist(data.user_groups.filter((x) => x.id !== g.id), g.access_user_groups);
    const dg = checklist(data.device_groups, g.access_device_groups);
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Create" : "Save", primary: true, onClick: async () => {
        const body = { name: name.value, note: note.value, access_user_groups: ug.values(), access_device_groups: dg.values() };
        if (creating) await api("POST", "/user-groups", body); else await api("PATCH", "/user-groups/" + g.id, body);
        await refreshLookup(); load();
      },
    }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete group", `Delete ${g.name}? Its members stay, without a group.`, "Delete", async () => { await api("DELETE", "/user-groups/" + g.id); await refreshLookup(); load(); }) });
    modal({
      title: creating ? "New user group" : "Edit " + g.name, actions,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name), field("Note", note)),
        h("div", { class: "row" }, field("Members can also see users and devices of", ug), field("Members can also see devices in", dg))),
    });
  }
  function deviceGroupDialog(g) {
    const creating = !g;
    g = g || { name: "", note: "", strategy_id: null };
    const name = h("input", { value: g.name });
    const note = h("input", { value: g.note });
    const strategy = select(optList(LOOKUP.strategies), g.strategy_id);
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Create" : "Save", primary: true, onClick: async () => {
        const body = { name: name.value, note: note.value, strategy_id: intOrNull(strategy.value) };
        if (creating) await api("POST", "/device-groups", body); else await api("PATCH", "/device-groups/" + g.id, body);
        await refreshLookup(); load();
      },
    }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete group", `Delete ${g.name}? Its devices stay, without a group.`, "Delete", async () => { await api("DELETE", "/device-groups/" + g.id); await refreshLookup(); load(); }) });
    modal({
      title: creating ? "New device group" : "Edit " + g.name, actions,
      body: h("div", { class: "form" }, field("Name", name, "Custom clients can join a group automatically with preset-device-group-name."),
        field("Strategy", strategy, "Applies to devices in the group unless the device or its user has one."), field("Note", note)),
    });
  }
  await load();
}

// -- strategies --------------------------------------------------------------------

async function pageStrategies() {
  setPage("Strategies", h("button", { class: "primary", onclick: () => editor(null) }, "New strategy"));
  let data;
  async function load() {
    data = await api("GET", "/strategies");
    append(clear(mainEl),
      h("p", { class: "muted" }, "A strategy is a set of client settings pushed to devices on their next heartbeat. A device uses its own strategy, else its user's, else its device group's, else the default. When a strategy stops applying, the settings it set return to the client's defaults."),
      table([
        { label: "Name", render: (s) => h("span", {}, h("strong", {}, s.name), s.is_default ? h("span", { class: "badge accent" }, " default") : null) },
        { label: "Settings", render: (s) => Object.keys(s.options).length },
        { label: "Assigned", render: (s) => `${s.devices} devices · ${s.users} users · ${s.device_groups} groups` },
        { label: "Changed", render: (s) => ago(s.modified_at) },
        { label: "Note", cls: "wrap", key: "note" },
      ], data.items, { onRow: editor, empty: "No strategies yet." }));
  }
  function editor(s) {
    const creating = !s;
    s = s || { name: "", note: "", options: {}, is_default: false };
    const name = h("input", { value: s.name });
    const note = h("input", { value: s.note });
    const isDefault = h("input", { type: "checkbox", checked: s.is_default });
    const controls = [];
    const sections = {};
    for (const o of data.catalog) {
      const on = Object.prototype.hasOwnProperty.call(s.options, o.key);
      const value = on ? s.options[o.key] : o.default;
      let ctl;
      if (o.type === "bool") ctl = select([["Y", "Yes"], ["N", "No"]], value);
      else if (o.type === "choice") ctl = select(o.choices, value);
      else ctl = h("input", { type: "text", value });
      const box = h("input", { type: "checkbox", checked: on, "aria-label": "Set " + o.label });
      const row = h("div", { class: "opt" + (on ? "" : " off") }, box, h("div", {}, o.label, h("div", { class: "key mono" }, o.key)), h("div", { class: "ctl" }, ctl));
      box.addEventListener("change", () => row.classList.toggle("off", !box.checked));
      ctl.addEventListener("input", () => { box.checked = true; row.classList.remove("off"); });
      controls.push({ key: o.key, box, ctl });
      (sections[o.section] = sections[o.section] || []).push(row);
    }
    const known = new Set(data.catalog.map((o) => o.key));
    const custom = h("textarea", { class: "mono", placeholder: "key=value, one per line" },
      Object.entries(s.options).filter(([k]) => !known.has(k)).map(([k, v]) => `${k}=${v}`).join("\n"));
    const body = h("div", {},
      h("div", { class: "form" }, h("div", { class: "row" }, field("Name", name, "Custom clients can pick it with preset-strategy-name."), field("Note", note)),
        h("label", { class: "check" }, isDefault, "Default strategy for devices with no other strategy")),
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
        else await api("PATCH", "/strategies/" + s.id, { name: name.value, note: note.value, options });
        if (isDefault.checked !== s.is_default) await api("PATCH", "/settings", { default_strategy_id: isDefault.checked ? id : null });
        toast("Saved; devices pick it up within about 15 seconds");
        await refreshLookup(); load();
      },
    }];
    if (!creating) actions.unshift({ label: "Delete", danger: true, onClick: () => confirmDialog("Delete strategy", `Delete ${s.name}? Devices using it fall back to the next strategy in line.`, "Delete", async () => { await api("DELETE", "/strategies/" + s.id); await refreshLookup(); load(); }) });
    modal({ title: creating ? "New strategy" : "Edit " + s.name, body, actions, wide: true });
  }
  await load();
}

// -- address books -----------------------------------------------------------------

const RULES = [[1, "Read only"], [2, "Read/write"], [3, "Full control"]];
const ruleName = (r) => (RULES.find((x) => x[0] === r) || [0, "None"])[1];

async function pageAddressBooks(params) {
  if (params[0]) return pageAddressBook(params[0]);
  setPage("Address books", h("button", { class: "primary", onclick: create }, "New shared book"));
  const data = await api("GET", "/address-books");
  append(clear(mainEl),
    h("p", { class: "muted" }, "Address books appear in the RustDesk client's Address Book tab. Each user has a personal book; shared books can be given to users and groups."),
    table([
      { label: "Name", render: (b) => h("a", { href: "#/address-books/" + b.guid }, b.name) },
      { label: "Type", render: (b) => b.personal ? h("span", { class: "badge" }, "Personal") : h("span", { class: "badge accent" }, "Shared") },
      { label: "Owner", key: "owner" },
      { label: "Peers", key: "peers" },
      { label: "Your access", render: (b) => ruleName(b.rule) },
      { label: "Note", cls: "wrap", key: "note" },
    ], data.items, { onRow: (b) => { location.hash = "#/address-books/" + b.guid; } }));
  function create() {
    const name = h("input", {});
    const note = h("input", {});
    const owner = ME.is_admin ? select(LOOKUP.users.map((u) => [u.id, u.name]), ME.id) : null;
    modal({
      title: "New shared address book",
      body: h("div", { class: "form" }, field("Name", name, "Custom clients can add themselves with preset-address-book-name."), field("Note", note), owner ? field("Owner", owner) : null),
      actions: [{ label: "Cancel" }, {
        label: "Create", primary: true, onClick: async () => {
          const res = await api("POST", "/address-books", { name: name.value, note: note.value, owner_id: owner ? intOrNull(owner.value) : undefined });
          location.hash = "#/address-books/" + res.guid;
        },
      }],
    });
  }
}

async function pageAddressBook(guid) {
  const b = await api("GET", "/address-books/" + guid);
  const canWrite = b.rule >= 2;
  const full = b.rule >= 3;
  const reload = () => pageAddressBook(guid).catch(fail);
  const tagColor = Object.fromEntries(b.tags.map((t) => [t.name, t.color]));
  setPage(b.name,
    h("a", { class: "btn", href: "#/address-books" }, "‹ All books"),
    canWrite ? h("button", { class: "primary", onclick: () => peerDialog(null) }, "Add peer") : null);

  const tagChip = (name) => h("span", { class: "tag" }, (() => { const i = h("i", {}); i.style.background = argbToCss(tagColor[name] || 0); return i; })(), name);

  function peerDialog(p) {
    const creating = !p;
    p = p || { id: "", alias: "", tags: [], note: "", password: "" };
    const id = h("input", { value: p.id, disabled: !creating, class: "mono" });
    const alias = h("input", { value: p.alias });
    const note = h("input", { value: p.note });
    const password = b.personal ? null : h("input", { type: "password", autocomplete: "new-password", placeholder: full ? "Saved for everyone with access" : "Leave empty to keep" });
    const tags = checklist(b.tags.map((t) => ({ id: t.name, name: t.name })), p.tags);
    const actions = [{ label: "Cancel" }, {
      label: creating ? "Add" : "Save", primary: true, onClick: async () => {
        const body = { alias: alias.value, note: note.value, tags: tags.values() };
        if (password && password.value) body.password = password.value;
        if (creating) await api("POST", `/address-books/${guid}/peers`, Object.assign(body, { id: id.value.trim() }));
        else await api("PATCH", `/address-books/${guid}/peers/${encodeURIComponent(p.id)}`, body);
        reload();
      },
    }];
    if (!creating) actions.unshift({ label: "Remove", danger: true, onClick: async () => { await api("DELETE", `/address-books/${guid}/peers/${encodeURIComponent(p.id)}`); reload(); } });
    modal({
      title: creating ? "Add peer" : "Edit " + p.id, actions,
      body: h("div", { class: "form" }, h("div", { class: "row" }, field("RustDesk ID", id), field("Alias", alias)),
        field("Note", note), password ? field("Password", password, "Shared books store the password so members can connect without typing it.") : null,
        field("Tags", tags)),
    });
  }

  const peersPanel = h("div", { class: "panel" }, h("h2", {}, "Peers", h("span", { class: "sub" }, `${b.peers.length} · ${b.personal ? "personal" : "shared"} book of ${b.owner} · your access: ${ruleName(b.rule)}`)),
    table([
      { label: "", render: (p) => onlineDot(p.online) },
      { label: "ID", render: (p) => h("strong", { class: "mono" }, p.id) },
      { label: "Alias", key: "alias" },
      { label: "Host", render: (p) => h("span", {}, p.hostname, p.username ? h("div", { class: "muted" }, p.username) : null) },
      { label: "Platform", key: "platform" },
      { label: "Tags", cls: "wrap", render: (p) => p.tags.map(tagChip) },
      { label: "Note", cls: "wrap", key: "note" },
    ], b.peers, { onRow: canWrite ? peerDialog : null, empty: "No peers. Add them here or from the RustDesk client." }));

  const newTag = h("input", { placeholder: "New tag" });
  const newColor = h("input", { type: "color", value: "#2196f3", "aria-label": "Tag colour" });
  const tagsPanel = h("div", { class: "panel" }, h("h2", {}, "Tags"),
    h("div", { class: "inline-list" }, b.tags.length ? b.tags.map((t) => h("span", { class: "split" }, tagChip(t.name),
      canWrite ? h("button", { class: "small link danger", onclick: async () => { await api("DELETE", `/address-books/${guid}/tags/${encodeURIComponent(t.name)}`); reload(); }, "aria-label": "Delete tag " + t.name }, "✕") : null)) : h("span", { class: "muted" }, "No tags")),
    canWrite ? h("form", { class: "toolbar", onsubmit: async (e) => { e.preventDefault(); if (!newTag.value.trim()) return; try { await api("POST", `/address-books/${guid}/tags`, { name: newTag.value.trim(), color: cssToArgb(newColor.value) }); reload(); } catch (err) { fail(err); } } },
      newTag, newColor, h("button", { type: "submit" }, "Add tag")) : null);

  const panels = [peersPanel, tagsPanel];
  if (!b.personal && full) {
    const rules = b.rules.map((r) => ({ ...r }));
    const rulesEl = h("div", {});
    const drawRules = () => append(clear(rulesEl), rules.length ? table([
      { label: "Who", render: (r) => r.user_id ? h("span", {}, "User ", h("strong", {}, r.name)) : h("span", {}, "Group ", h("strong", {}, r.name)) },
      { label: "Access", render: (r) => select(RULES, r.rule, { onchange: (e) => { r.rule = parseInt(e.target.value, 10); } }) },
      { label: "", cls: "actions", render: (r) => h("button", { class: "small danger", onclick: () => { rules.splice(rules.indexOf(r), 1); drawRules(); } }, "Remove") },
    ], rules) : h("p", { class: "muted" }, "Only the owner and administrators can see this book."));
    drawRules();
    const who = select([["", "Add user or group…"]].concat(
      LOOKUP.users.filter((u) => u.id !== b.owner_id).map((u) => ["u" + u.id, "User: " + u.name]),
      LOOKUP.user_groups.map((g) => ["g" + g.id, "Group: " + g.name])), "");
    who.addEventListener("change", () => {
      const v = who.value;
      if (!v) return;
      const id = parseInt(v.slice(1), 10);
      const exists = rules.find((r) => (v[0] === "u" ? r.user_id === id : r.user_group_id === id));
      if (!exists) rules.push(v[0] === "u" ? { user_id: id, rule: 1, name: nameOf(LOOKUP.users, id) } : { user_group_id: id, rule: 1, name: nameOf(LOOKUP.user_groups, id) });
      who.value = "";
      drawRules();
    });
    panels.push(h("div", { class: "panel" }, h("h2", {}, "Sharing"), rulesEl,
      h("div", { class: "toolbar" }, who, h("div", { class: "grow" }),
        h("button", { class: "primary", onclick: async () => { try { await api("PATCH", "/address-books/" + guid, { rules: rules.map((r) => ({ user_id: r.user_id || null, user_group_id: r.user_group_id || null, rule: r.rule })) }); toast("Sharing saved"); reload(); } catch (e) { fail(e); } } }, "Save sharing")),
      h("hr", {}),
      h("div", { class: "toolbar" },
        h("button", { onclick: () => { const n = h("input", { value: b.name }); const note = h("input", { value: b.note }); modal({ title: "Rename", body: h("div", { class: "form" }, field("Name", n), field("Note", note)), actions: [{ label: "Cancel" }, { label: "Save", primary: true, onClick: async () => { await api("PATCH", "/address-books/" + guid, { name: n.value, note: note.value }); reload(); } }] }); } }, "Rename"),
        h("button", { class: "danger", onclick: () => confirmDialog("Delete address book", `Delete ${b.name} and its ${b.peers.length} peers for everyone?`, "Delete", async () => { await api("DELETE", "/address-books/" + guid); location.hash = "#/address-books"; }) }, "Delete book"))));
  }
  append(clear(mainEl), panels);
}

// -- logs --------------------------------------------------------------------------

const LOG_KINDS = [["connections", "Connections"], ["files", "File transfers"], ["alarms", "Alarms"], ["console", "Console activity"]];

const LOG_COLUMNS = {
  connections: [
    { label: "Started", render: (r) => dt(r.started_at) },
    { label: "Device", render: (r) => h("span", {}, h("span", { class: "mono" }, r.device_id), r.device_name ? h("div", { class: "muted" }, r.device_name) : null) },
    { label: "From", render: (r) => h("span", {}, h("span", { class: "mono" }, r.peer_id || "—"), r.peer_name ? h("div", { class: "muted" }, r.peer_name) : null) },
    { label: "IP", render: (r) => h("span", { class: "mono" }, r.ip) },
    { label: "Type", render: (r) => r.type || h("span", { class: "muted" }, r.authorized_at ? "—" : "Not authorized") },
    { label: "Auth", render: (r) => h("span", {}, r.auth, r.two_factor ? h("div", { class: "muted" }, "+ " + r.two_factor) : null) },
    { label: "Duration", render: (r) => r.ended_at ? dur(r.duration) : h("span", { class: "badge ok" }, "ongoing") },
  ],
  files: [
    { label: "Time", render: (r) => dt(r.created_at) },
    { label: "Device", render: (r) => h("span", {}, h("span", { class: "mono" }, r.device_id), r.device_name ? h("div", { class: "muted" }, r.device_name) : null) },
    { label: "By", render: (r) => h("span", {}, h("span", { class: "mono" }, r.peer_id), r.peer_name ? h("div", { class: "muted" }, r.peer_name) : null) },
    { label: "Direction", key: "direction" },
    { label: "Path", cls: "wrap", render: (r) => h("span", { class: "mono" }, r.path) },
    { label: "Files", cls: "wrap", render: (r) => h("span", { title: (r.files || []).map((f) => f[0]).join("\n") }, `${r.count} item${r.count === 1 ? "" : "s"}`, (r.files || []).length ? h("div", { class: "muted" }, (r.files || []).slice(0, 3).map((f) => `${f[0]} (${bytes(f[1])})`).join(", ")) : null) },
  ],
  alarms: [
    { label: "Time", render: (r) => dt(r.created_at) },
    { label: "Device", render: (r) => h("span", {}, h("span", { class: "mono" }, r.device_id), r.device_name ? h("div", { class: "muted" }, r.device_name) : null) },
    { label: "Alarm", render: (r) => h("span", { class: "badge danger" }, r.type) },
    { label: "IP", render: (r) => h("span", { class: "mono" }, r.ip) },
    { label: "Peer", render: (r) => `${r.peer_id} ${r.peer_name}` },
    { label: "Detail", cls: "wrap", render: (r) => h("span", { class: "mono muted" }, JSON.stringify(r.detail)) },
  ],
  console: [
    { label: "Time", render: (r) => dt(r.created_at) },
    { label: "User", key: "user_name" },
    { label: "Action", render: (r) => h("code", {}, r.action) },
    { label: "Target", key: "target" },
    { label: "IP", render: (r) => h("span", { class: "mono" }, r.ip) },
    { label: "Detail", cls: "wrap", render: (r) => h("span", { class: "mono muted" }, r.detail) },
  ],
};

async function pageLogs(params) {
  const kind = LOG_KINDS.find((k) => k[0] === params[0]) ? params[0] : "connections";
  const state = { q: "", device: "", from: "", to: "", page: 1 };
  const listEl = h("div", {});
  const q = h("input", { type: "search", placeholder: "Search…" });
  const device = kind === "console" ? null : h("input", { placeholder: "Device ID", class: "mono" });
  const from = h("input", { type: "date", "aria-label": "From" });
  const to = h("input", { type: "date", "aria-label": "To" });
  const csv = h("a", { class: "btn" }, "Export CSV");
  setPage("Logs", csv);
  const query = (extra) => {
    const p = { q: q.value, device: device ? device.value : "", page: state.page, size: 50 };
    if (from.value) p.from = Math.floor(new Date(from.value + "T00:00").getTime() / 1000);
    if (to.value) p.to = Math.floor(new Date(to.value + "T00:00").getTime() / 1000) + 86400;
    return new URLSearchParams(Object.assign(p, extra || {}));
  };
  async function load() {
    csv.href = `/api/admin/logs/${kind}?` + query({ format: "csv" });
    const data = await api("GET", `/logs/${kind}?` + query());
    append(clear(listEl), table(LOG_COLUMNS[kind], data.items, { empty: "No entries." }),
      pager(data.total, state.page, 50, (p) => { state.page = p; load(); }));
  }
  let timer;
  for (const el of [q, device, from, to].filter(Boolean)) {
    el.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { state.page = 1; load().catch(fail); }, 300); });
  }
  append(clear(mainEl),
    h("div", { class: "tabs" }, LOG_KINDS.map(([k, label]) => h("a", { href: "#/logs/" + k, class: k === kind ? "active" : "" }, label))),
    h("div", { class: "toolbar" }, q, device, h("span", { class: "muted" }, "from"), from, h("span", { class: "muted" }, "to"), to),
    listEl);
  await load();
}

// -- recordings --------------------------------------------------------------------

async function pageRecordings() {
  setPage("Recordings");
  const [data, settings] = await Promise.all([api("GET", "/recordings"), api("GET", "/settings")]);
  const notice = settings.accept_recordings
    ? h("p", { class: "muted" }, "Clients upload a session recording while it is recorded. Turn on recording on devices with a strategy (Automatically record incoming sessions).")
    : h("div", { class: "panel" }, "Recording upload is turned off. ", h("a", { href: "#/settings" }, "Enable it in Settings"), " to receive recordings from clients.");
  append(clear(mainEl), notice, table([
    { label: "File", render: (r) => h("span", { class: "mono" }, r.filename) },
    { label: "Size", render: (r) => bytes(r.size) },
    { label: "Started", render: (r) => dt(r.created_at) },
    { label: "Status", render: (r) => r.completed_at ? h("span", { class: "badge ok" }, "complete") : h("span", { class: "badge warn" }, "in progress") },
    { label: "", cls: "actions", render: (r) => h("span", { class: "split" },
      h("a", { class: "btn", href: `/api/admin/recordings/${r.id}/download` }, "Download"),
      h("button", { class: "small danger", onclick: () => confirmDialog("Delete recording", `Delete ${r.filename}?`, "Delete", async () => { await api("DELETE", "/recordings/" + r.id); pageRecordings(); }) }, "Delete")) },
  ], data.items, { empty: "No recordings." }));
}

// -- settings ----------------------------------------------------------------------

async function pageSettings() {
  setPage("Settings");
  const [s, cfg] = await Promise.all([api("GET", "/settings"), api("GET", "/client-config")]);
  const text = (k, ph) => h("input", { value: s[k], placeholder: ph || "" });
  const num = (k) => h("input", { type: "number", min: 0, value: s[k] });
  const f = {
    id_server: text("id_server", "taken from the address you opened this page with"),
    relay_server: text("relay_server", "optional; hbbs tells clients its relay"),
    api_server: text("api_server", "empty: clients use the ID server's port minus 2 (31114)"),
    server_key: text("server_key", s.detected_key ? "read from " + s.hbbs_key_file : "contents of id_ed25519.pub"),
    client_token_days: num("client_token_days"),
    console_session_hours: num("console_session_hours"),
    log_retention_days: num("log_retention_days"),
    max_peers_per_ab: num("max_peers_per_ab"),
    recordings_max_mb: num("recordings_max_mb"),
  };
  const recordings = h("input", { type: "checkbox", checked: s.accept_recordings });
  const save = h("button", {
    class: "primary", onclick: async () => {
      const body = { accept_recordings: recordings.checked };
      for (const [k, el] of Object.entries(f)) body[k] = el.type === "number" ? parseInt(el.value || "0", 10) : el.value;
      try { await api("PATCH", "/settings", body); toast("Settings saved"); pageSettings(); } catch (e) { fail(e); }
    },
  }, "Save settings");
  append(clear(mainEl), h("div", { class: "grid two" },
    h("div", {},
      h("div", { class: "panel" }, h("h2", {}, "Server addresses", h("span", { class: "sub" }, "what clients are told to use")),
        h("div", { class: "form" },
          field("ID server (hbbs)", f.id_server, "Host and port of hbbs, e.g. rd.example.com:31116. Without a port clients use 21116."),
          field("Relay server (hbbr)", f.relay_server),
          field("API server (this console)", f.api_server, "Leave empty when RussDesk runs on the ID server's host two ports below hbbs (31114 with hbbs on 31116): clients find it on their own. Set it only for HTTPS or another host/port, e.g. https://rd.example.com."),
          field("Server public key", f.server_key, s.detected_key ? "Leave empty to use the key read from hbbs: " + s.detected_key : "Paste the content of hbbs' id_ed25519.pub."))),
      h("div", { class: "panel" }, h("h2", {}, "Sessions and limits"),
        h("div", { class: "form" },
          h("div", { class: "row" }, field("Client login lifetime (days, 0 = never expires)", f.client_token_days, "With 0, a client stays logged in until it logs out or you revoke it."), field("Console session (hours)", f.console_session_hours)),
          h("div", { class: "row" }, field("Keep logs (days, 0 = forever)", f.log_retention_days), field("Peers per address book (0 = unlimited)", f.max_peers_per_ab)))),
      h("div", { class: "panel" }, h("h2", {}, "Session recordings"),
        h("div", { class: "form" },
          h("label", { class: "check" }, recordings, "Accept recordings uploaded by clients"),
          h("div", { class: "hint" }, "The client uploads without logging in, so anyone who can reach this server could send files. Leave this off unless you need it, and cap the storage."),
          field("Storage cap (MB)", f.recordings_max_mb))),
      save),
    h("div", {}, clientConfigPanel(cfg),
      h("div", { class: "panel" }, h("h2", {}, "Scan on a phone"), h("p", { class: "muted" }, "RustDesk for Android: Settings → ID/Relay server → scan the QR code."), qrImage("config=" + cfg.config_string)),
      h("div", { class: "panel" }, h("h2", {}, "Custom client presets"),
        h("p", { class: "muted" }, "Clients built with these options are sorted automatically when they first check in:"),
        h("dl", { class: "kv" },
          [["preset-user-name", "assigns the device to this user"], ["preset-device-group-name", "puts it in this device group"], ["preset-strategy-name", "gives it this strategy"],
           ["preset-address-book-name", "adds it to this shared book (with -tag, -alias, -password, -note)"], ["preset-note", "sets the device note"]]
            .map(([k, v]) => [h("dt", {}, h("code", {}, k)), h("dd", {}, v)]))))));
}

// -- account -----------------------------------------------------------------------

async function pageAccount() {
  setPage("Account");
  ME = await api("GET", "/me");
  const current = h("input", { type: "password", autocomplete: "current-password" });
  const next = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const pwPanel = h("div", { class: "panel" }, h("h2", {}, "Change password"),
    h("form", {
      class: "form", onsubmit: async (e) => {
        e.preventDefault();
        if (next.value !== again.value) return toast("The new passwords differ", true);
        try { await api("POST", "/account/password", { current: current.value, new: next.value }); toast("Password changed; other sessions were signed out"); current.value = next.value = again.value = ""; } catch (err) { fail(err); }
      },
    }, field("Current password", current), field("New password", next, "At least 8 characters"), field("Repeat new password", again),
      h("div", {}, h("button", { class: "primary", type: "submit" }, "Change password"))));

  const tfaPanel = h("div", { class: "panel" }, h("h2", {}, "Two-factor login"));
  if (ME.totp_enabled) {
    const pw = h("input", { type: "password", autocomplete: "current-password" });
    append(tfaPanel, h("p", {}, h("span", { class: "badge ok" }, "On"), " Logins from the console and the RustDesk client ask for a code from your authenticator app."),
      h("div", { class: "form" }, field("Password, to turn it off", pw),
        h("div", {}, h("button", { class: "danger", onclick: async () => { try { await api("POST", "/account/2fa/disable", { password: pw.value }); toast("Two-factor login turned off"); pageAccount(); } catch (e) { fail(e); } } }, "Turn off"))));
  } else {
    append(tfaPanel, h("p", { class: "muted" }, "Ask for a code from an authenticator app (Aegis, Google Authenticator, 1Password…) when you log in, in the console and in the RustDesk client."),
      h("button", {
        class: "primary", onclick: async () => {
          const setup = await api("POST", "/account/2fa/setup");
          const code = h("input", { inputmode: "numeric", maxlength: 6, placeholder: "123456" });
          modal({
            title: "Set up two-factor login",
            body: h("div", { class: "form" }, h("p", {}, "Scan this with your authenticator app, then enter the 6-digit code it shows."), qrImage(setup.uri),
              h("div", { class: "hint" }, "Or enter the key by hand: ", h("code", {}, setup.secret)), field("Code", code)),
            actions: [{ label: "Cancel" }, { label: "Turn on", primary: true, onClick: async () => { await api("POST", "/account/2fa/enable", { secret: setup.secret, code: code.value }); toast("Two-factor login is on"); pageAccount(); } }],
          });
        },
      }, "Set up"));
  }
  append(clear(mainEl), h("div", { class: "grid two" }, h("div", { class: "panel" }, h("h2", {}, "Profile"),
    h("dl", { class: "kv" }, h("dt", {}, "Username"), h("dd", {}, ME.name), h("dt", {}, "Name"), h("dd", {}, ME.display_name || "—"),
      h("dt", {}, "Email"), h("dd", {}, ME.email || "—"), h("dt", {}, "Role"), h("dd", {}, ME.is_admin ? "Administrator" : "User"))),
  pwPanel, tfaPanel));
}
