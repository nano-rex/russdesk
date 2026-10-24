"use strict";
(async function () {
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const id = params.get("id");
  const setStatus = (s) => { $("status").textContent = s; };
  const fail = (m) => { $("otitle").textContent = "Cannot connect"; $("err").textContent = m; $("overlay").hidden = false; };
  if (!id) return fail("No device id");
  $("dev").textContent = "Device " + id;

  let info;
  try {
    const r = await fetch("/api/admin/devices/" + encodeURIComponent(id) + "/viewer-info", { credentials: "same-origin" });
    info = await r.json();
    if (!r.ok) throw new Error(info.error || ("HTTP " + r.status));
  } catch (e) { return fail(e.message + " — are you signed in to the console?"); }

  if (!("VideoDecoder" in window)) return fail("This browser has no WebCodecs video support. Use a recent Chrome, Edge or Chromium.");
  if (!window.isSecureContext && location.hostname !== "localhost" && !/^\d+\.\d+\.\d+\.\d+$/.test(location.hostname)) {
    // WebCodecs needs a secure context except on localhost / plain IP over http.
  }

  async function run(password) {
    $("err").textContent = "";
    $("omsg").textContent = "Connecting to " + info.host + "…";
    $("pwbox").hidden = true;
    $("otitle").textContent = "Connecting…";
    $("overlay").hidden = false;
    const viewer = new window.RussDeskViewer(Object.assign({}, info, { password }), $("screen"),
      (s) => { setStatus(s); if (s === "connected" || s.startsWith("connected")) $("overlay").hidden = true; });
    window._viewer = viewer;
    try {
      await viewer.start();
    } catch (e) {
      viewer.close();
      if (/login refused|wrong|password/i.test(e.message)) { askPassword(e.message); }
      else fail(e.message);
    }
  }

  function askPassword(msg) {
    $("otitle").textContent = "Password needed";
    $("omsg").textContent = "Enter the device's permanent password.";
    $("err").textContent = msg && /refused|wrong/i.test(msg) ? "Wrong password, try again." : "";
    $("pwbox").hidden = false;
    $("overlay").hidden = false;
    $("pw").focus();
    $("go").onclick = () => run($("pw").value);
    $("pw").onkeydown = (e) => { if (e.key === "Enter") run($("pw").value); };
  }

  $("cad").onclick = () => { if (window._viewer) window._viewer.sendCtrlAltDel && window._viewer.sendCtrlAltDel(); };
  $("full").onclick = () => { const s = $("screen"); (s.requestFullscreen || s.webkitRequestFullscreen).call(s); };

  if (info.password) run(info.password); else askPassword();
})();
