"use strict";

/* RussDesk in-browser viewer: connects to a device through hbbs/hbbr over
   WebSocket, speaks the real RustDesk peer protocol (libsodium + WebCodecs),
   draws the screen to a canvas and sends mouse/keyboard back.

   Ported from tools/rdproto.py, which validated the same wire format against a
   real RustDesk device. */

// -- protobuf (varint + length-delimited + fixed) --------------------------------

function uvarint(n) {
  const out = [];
  if (n < 0) n = n >>> 0;
  n = BigInt(n);
  const mask = 0x7Fn;
  while (true) {
    let b = Number(n & mask);
    n >>= 7n;
    if (n) out.push(b | 0x80); else { out.push(b); return out; }
  }
}

function pbFields(fields) {
  // fields: [[num, value], ...]; value: number|bigint -> varint, Uint8Array/str -> bytes, true/false bool
  const out = [];
  for (const [num, value] of fields) {
    if (value === null || value === undefined) continue;
    if (value === false) continue;
    if (value === true) { out.push(...uvarint(num << 3), ...uvarint(1)); continue; }
    if (typeof value === "number" || typeof value === "bigint") {
      if (value === 0 || value === 0n) continue;
      out.push(...uvarint(num << 3), ...uvarint(value));
    } else {
      const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
      out.push(...uvarint((num << 3) | 2), ...uvarint(data.length), ...data);
    }
  }
  return new Uint8Array(out);
}

function wrap(num, inner) {
  return new Uint8Array([...uvarint((num << 3) | 2), ...uvarint(inner.length), ...inner]);
}

function unpb(buf) {
  const fields = {};
  let i = 0;
  while (i < buf.length) {
    let [key, ni] = readVarint(buf, i); i = ni;
    const num = key >> 3, wt = key & 7;
    let v;
    if (wt === 0) { [v, i] = readVarint(buf, i); }
    else if (wt === 2) { let [n, j] = readVarint(buf, i); v = buf.subarray(j, j + n); i = j + n; }
    else if (wt === 5) { v = buf.subarray(i, i + 4); i += 4; }
    else if (wt === 1) { v = buf.subarray(i, i + 8); i += 8; }
    else throw new Error("wire type " + wt);
    (fields[num] = fields[num] || []).push(v);
  }
  return fields;
}

function readVarint(buf, i) {
  let shift = 0, result = 0;
  while (true) {
    const b = buf[i++];
    result += (b & 0x7F) * Math.pow(2, shift);  // avoid 32-bit overflow
    if (!(b & 0x80)) return [result, i];
    shift += 7;
  }
}

const first = (f, num) => (f[num] ? f[num][0] : undefined);
const asText = (f, num) => { const v = first(f, num); return v ? new TextDecoder().decode(v) : ""; };
const asInt = (f, num) => { const v = first(f, num); return typeof v === "number" ? v : 0; };
const zigzag = (n) => (n >>> 1) ^ -(n & 1);

// -- transport: WebSocket, one binary message per RustDesk message ----------------

class Ws {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.ws.binaryType = "arraybuffer";
    this.queue = [];
    this.waiters = [];
    this.error = null;
    this.ready = new Promise((res, rej) => {
      this.ws.onopen = () => res();
      this.ws.onerror = () => rej(new Error("WebSocket to " + url + " failed"));
    });
    this.ws.onmessage = (e) => {
      const data = new Uint8Array(e.data);
      if (this.waiters.length) this.waiters.shift()(data);
      else this.queue.push(data);
    };
    this.ws.onclose = () => {
      this.error = this.error || new Error("connection closed");
      while (this.waiters.length) this.waiters.shift()(null);
    };
  }
  send(bytes) { this.ws.send(bytes); }
  recv() {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((res) => this.waiters.push((d) => d ? res(d) : res(Promise.reject(this.error))));
  }
  close() { try { this.ws.close(); } catch (e) {} }
}

// -- crypto helpers ---------------------------------------------------------------

async function sha256(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

function nonce(seq) {
  const n = new Uint8Array(24);
  let s = BigInt(seq);
  for (let i = 0; i < 8; i++) { n[i] = Number(s & 0xFFn); s >>= 8n; }
  return n;
}

function subkey(sodium, key, direction, advertised, picked, initiatorPk, responderPk) {
  const le32 = (v) => new Uint8Array([v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >> 24) & 255]);
  const parts = [new TextEncoder().encode("rdkx-spl"), new Uint8Array([direction]),
                 le32(advertised), le32(picked), initiatorPk, responderPk];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const data = new Uint8Array(total);
  let o = 0; for (const p of parts) { data.set(p, o); o += p.length; }
  return sodium.crypto_generichash(32, data, key);
}

// -- message field numbers --------------------------------------------------------

const M = { signed_id: 3, public_key: 4, test_delay: 5, video_frame: 6, login_request: 7,
            login_response: 8, hash: 9, mouse_event: 10, key_event: 15, misc: 19 };

// -- the viewer -------------------------------------------------------------------

class Viewer {
  constructor(cfg, canvas, onStatus) {
    this.cfg = cfg;            // {host, id_port, relay_port, scheme, key, device_id, password, name}
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.onStatus = onStatus || (() => {});
    this.sendSeq = 0;
    this.recvSeq = 0;
    this.display = { width: 0, height: 0 };
    this.stop = false;
    this.lastButtons = 0;
  }

  status(s) { this.onStatus(s); }

  async start() {
    this.sodium = window.sodium;
    await this.sodium.ready;
    this.serverPk = this.sodium.from_base64(this.cfg.key, this.sodium.base64_variants.ORIGINAL);
    const secure = this.cfg.scheme === "https";
    const wsScheme = secure ? "wss" : "ws";
    // Over HTTPS the browser blocks plain ws:// (mixed content) and the hbbs/hbbr
    // ws ports have no TLS, so route through the console origin, which a TLS proxy
    // forwards to hbbs (/ws/id) and hbbr (/ws/relay). Plain HTTP keeps talking to
    // the ID/relay host directly on port+2.
    const hostFor = (p) => secure
      ? `${wsScheme}://${location.host}/ws/${p === this.cfg.relay_port ? "relay" : "id"}`
      : `${wsScheme}://${this.cfg.host}:${p + 2}`;

    this.status("contacting ID server…");
    const uuid = await this._pair(hostFor(this.cfg.id_port));
    this.status("relaying through hbbr…");
    this.relay = new Ws(hostFor(this.cfg.relay_port));
    await this.relay.ready;
    // request_relay{ id=1, uuid=2, licence_key=6 }
    this.relay.send(wrap(18, pbFields([[1, this.cfg.device_id], [2, uuid], [6, this.cfg.key]])));

    await this._handshake();
    this.status("authenticating…");
    await this._login();
    this.status("connected");
    this._setupInput();
    await this._videoLoop();
  }

  async _pair(url) {
    const ws = new Ws(url);
    await ws.ready;
    // punch_hole_request{ id=1, nat_type=2(SYMMETRIC), licence_key=3, conn_type=4, version=6, force_relay=8 }
    ws.send(wrap(8, pbFields([[1, this.cfg.device_id], [2, 2], [3, this.cfg.key],
                              [4, 0], [6, "1.4.2"], [8, true]])));
    while (true) {
      const f = unpb(await ws.recv());
      if (11 in f) {  // punch_hole_response
        const r = unpb(first(f, 11));
        const fail = asInt(r, 3);
        ws.close();
        throw new Error("ID server refused the device (" + (PUNCH[fail] || fail) + ")");
      }
      if (19 in f) {  // relay_response
        const r = unpb(first(f, 19));
        const uuid = asText(r, 2);
        const signedIdPk = first(r, 5);
        if (!signedIdPk) { ws.close(); throw new Error("no device key in relay response"); }
        const idpk0 = unpb(this.sodium.crypto_sign_open(signedIdPk, this.serverPk));
        if (asText(idpk0, 1) !== this.cfg.device_id) { ws.close(); throw new Error("server-signed id mismatch"); }
        this.deviceSignPk = first(idpk0, 2);
        ws.close();
        return uuid;
      }
    }
  }

  async _handshake() {
    const m = unpb(await this.relay.recv());
    const signed = first(m, M.signed_id);
    if (!signed) throw new Error("no SignedId from device");
    const blob = first(unpb(signed), 1);
    const idpk = unpb(this.sodium.crypto_sign_open(blob, this.deviceSignPk));
    if (asText(idpk, 1) !== this.cfg.device_id) throw new Error("device id mismatch");
    const devBox = first(idpk, 2);
    const kxAdv = asInt(idpk, 4);
    const kp = this.sodium.crypto_box_keypair();
    const sessionKey = this.sodium.randombytes_buf(32);
    const sealed = this.sodium.crypto_box_easy(sessionKey, new Uint8Array(24), devBox, kp.privateKey);
    const picked = Math.min(kxAdv, 1);
    this.relay.send(wrap(M.public_key, pbFields([[1, kp.publicKey], [2, sealed], [3, picked]])));
    if (picked >= 1) {
      this.encKey = subkey(this.sodium, sessionKey, 1, kxAdv, picked, kp.publicKey, devBox);
      this.decKey = subkey(this.sodium, sessionKey, 2, kxAdv, picked, kp.publicKey, devBox);
    } else {
      this.encKey = this.decKey = sessionKey;
    }
  }

  _send(body) {
    this.sendSeq += 1;
    this.relay.send(this.sodium.crypto_secretbox_easy(body, nonce(this.sendSeq), this.encKey));
  }

  async _recv() {
    const cipher = await this.relay.recv();
    if (cipher.length <= 1) return {};
    this.recvSeq += 1;
    return unpb(this.sodium.crypto_secretbox_open_easy(cipher, nonce(this.recvSeq), this.decKey));
  }

  async _login() {
    let salt, challenge;
    while (true) {
      const m = await this._recv();
      if (M.hash in m) { const h = unpb(first(m, M.hash)); salt = asText(h, 1); challenge = asText(h, 2); break; }
    }
    const pw = new TextEncoder().encode(this.cfg.password);
    const h1 = await sha256(pw, new TextEncoder().encode(salt));
    const h2 = await sha256(h1, new TextEncoder().encode(challenge));
    // OptionMessage{ supported_decoding=10{ ability_vp9=1, ability_h264=2, prefer=4:H264(2),
    // ability_vp8=5 } }. H264 is preferred, but a device can only encode it with hardware
    // support, so VP9/VP8 (which every browser's WebCodecs decodes) keep other devices working.
    const option = pbFields([[10, pbFields([[1, 1], [2, 1], [4, 2], [5, 1]])]]);
    const lr = pbFields([[1, this.cfg.device_id], [2, h2], [4, randId()], [5, this.cfg.name || "RussDesk"],
                         [6, option], [9, true], [10, randId()], [11, "1.4.2"], [13, "Linux"]]);
    this._send(wrap(M.login_request, lr));
    while (true) {
      const m = await this._recv();
      if (M.login_response in m) {
        const resp = unpb(first(m, M.login_response));
        if (1 in resp) throw new Error("login refused: " + asText(resp, 1));
        const pi = unpb(first(resp, 2) || new Uint8Array());
        const d = pi[4] ? unpb(pi[4][0]) : {};
        this.display = { width: asInt(d, 3) || 1920, height: asInt(d, 4) || 1080 };
        this.canvas.width = this.display.width;
        this.canvas.height = this.display.height;
        return;
      }
    }
  }

  _configureDecoder(kind, keyframe) {
    let codec = kind === "vp9" ? "vp09.00.10.08" : kind === "vp8" ? "vp8" : "avc1.42E01E";
    if (kind === "h264") {
      // Build the H264 codec string from the SPS in the keyframe (Annex B).
      for (let i = 0; i + 4 < keyframe.length; i++) {
        if (keyframe[i] === 0 && keyframe[i + 1] === 0 && keyframe[i + 2] === 1 && (keyframe[i + 3] & 0x1F) === 7) {
          const p = keyframe[i + 4], c = keyframe[i + 5], l = keyframe[i + 6];
          codec = "avc1." + [p, c, l].map((x) => x.toString(16).padStart(2, "0")).join("");
          break;
        }
      }
    }
    if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    this.codecKind = kind;
    this.decoder = new VideoDecoder({
      output: (frame) => { try { this.ctx.drawImage(frame, 0, 0, this.canvas.width, this.canvas.height); } finally { frame.close(); } },
      error: (e) => this.status("decoder error: " + e.message),
    });
    this.decoder.configure({ codec, optimizeForLatency: true, hardwareAcceleration: "prefer-software" });
    this.status("connected (" + codec + ")");
  }

  async _videoLoop() {
    let ts = 0;
    while (!this.stop) {
      let m;
      try { m = await this._recv(); } catch (e) { if (!this.stop) this.status("disconnected: " + e.message); return; }
      const vf = first(m, M.video_frame);
      if (!vf) continue;
      const frames = unpb(vf);
      // VideoFrame oneof: vp9s=6, h264s=10, vp8s=12. The device may switch codec mid-session
      // (e.g. when another viewer connects), so (re)configure on the first keyframe of each.
      for (const [field, kind] of [[10, "h264"], [6, "vp9"], [12, "vp8"]]) {
        for (const evs of (frames[field] || [])) {
          for (const ev of (unpb(evs)[1] || [])) {
            const e = unpb(ev);
            const data = first(e, 1);
            const key = asInt(e, 2) ? true : asBool(e, 2);
            if (this.codecKind !== kind) {
              if (!key) continue;  // wait for a keyframe
              this._configureDecoder(kind, data);
            }
            this.decoder.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp: ts, data }));
            ts += 1000000 / 30;
          }
        }
      }
    }
  }

  // -- input --------------------------------------------------------------------

  _remoteXY(ev) {
    const r = this.canvas.getBoundingClientRect();
    const x = Math.round((ev.clientX - r.left) / r.width * this.display.width);
    const y = Math.round((ev.clientY - r.top) / r.height * this.display.height);
    return [Math.max(0, Math.min(this.display.width - 1, x)), Math.max(0, Math.min(this.display.height - 1, y))];
  }

  _mouse(mask, x, y, ev) {
    const mods = [];
    if (ev && ev.altKey) mods.push(1);      // ControlKey.Alt
    if (ev && ev.ctrlKey) mods.push(4);     // ControlKey.Control
    if (ev && ev.shiftKey) mods.push(29);   // ControlKey.Shift
    const body = [[1, mask], [2, zz(x)], [3, zz(y)]];
    for (const mk of mods) body.push([4, mk]);  // repeated modifiers
    this._send(wrap(M.mouse_event, pbFields(body)));
  }

  _setupInput() {
    const c = this.canvas;
    c.tabIndex = 0;
    const BTN = { 0: 1, 1: 4, 2: 2 };  // browser button -> RustDesk button (left/middle/right)
    c.addEventListener("mousemove", (e) => { const [x, y] = this._remoteXY(e); this._mouse(0, x, y, e); });
    c.addEventListener("mousedown", (e) => { e.preventDefault(); c.focus(); const [x, y] = this._remoteXY(e); this._mouse(((BTN[e.button] || 1) << 3) | 1, x, y, e); });
    c.addEventListener("mouseup", (e) => { e.preventDefault(); const [x, y] = this._remoteXY(e); this._mouse(((BTN[e.button] || 1) << 3) | 2, x, y, e); });
    c.addEventListener("contextmenu", (e) => e.preventDefault());
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const dx = Math.sign(-e.deltaX) * 1, dy = Math.sign(-e.deltaY) * 1;  // RustDesk: +up/+left
      this._send(wrap(M.mouse_event, pbFields([[1, 3], [2, zz(dx)], [3, zz(dy)]])));  // type 3 = wheel
    }, { passive: false });
    c.addEventListener("keydown", (e) => { e.preventDefault(); this._key(e, true); });
    c.addEventListener("keyup", (e) => { e.preventDefault(); this._key(e, false); });
  }

  _key(e, down) {
    const ck = CONTROL_KEYS[e.code];
    const mods = [];
    if (e.altKey) mods.push(1);
    if (e.ctrlKey) mods.push(4);
    if (e.shiftKey) mods.push(29);
    if (e.metaKey) mods.push(23);  // Meta
    let fields;
    if (ck !== undefined) {
      fields = [[1, down], [3, ck]];  // control_key
    } else if (e.key && e.key.length === 1) {
      fields = [[1, down], [5, e.key.codePointAt(0)]];  // unicode
    } else {
      return;
    }
    for (const mk of mods) fields.push([8, mk]);
    fields.push([9, 2]);  // KeyboardMode.Translate
    this._send(wrap(M.key_event, pbFields(fields)));
  }

  sendCtrlAltDel() {
    // ControlKey.CtrlAltDel = 100 (message.proto)
    this._send(wrap(M.key_event, pbFields([[1, true], [3, 100], [9, 2]])));
    this._send(wrap(M.key_event, pbFields([[1, false], [3, 100], [9, 2]])));
  }

  close() { this.stop = true; if (this.decoder) try { this.decoder.close(); } catch (e) {} if (this.relay) this.relay.close(); }
}

// -- small helpers ----------------------------------------------------------------

const PUNCH = { 0: "not registered", 2: "offline", 3: "wrong key" };
function enc(s) { return new TextEncoder().encode(s); }
function randId() { return Math.floor(100000000 + Math.random() * 899999999); }
function zz(n) { return (n << 1) ^ (n >> 31); }  // sint32 zigzag encode (for varint)
function asBool(f, num) { const v = first(f, num); return v === 1 || v === true; }

// Browser KeyboardEvent.code -> RustDesk ControlKey enum value (message.proto).
const CONTROL_KEYS = {
  Backspace: 2, CapsLock: 3, Delete: 5, ArrowDown: 6, End: 7, Escape: 8,
  F1: 9, F2: 13, F3: 14, F4: 15, F5: 16, F6: 17, F7: 18, F8: 19, F9: 20, F10: 10, F11: 11, F12: 12,
  Home: 21, ArrowLeft: 22, PageDown: 25, PageUp: 26, Enter: 27, ArrowRight: 28, ArrowUp: 32,
  Tab: 31, Insert: 58, NumpadEnter: 72, NumLock: 63, ScrollLock: 62, Pause: 46, PrintScreen: 57,
  ContextMenu: 65, AltLeft: 1, AltRight: 75, ControlLeft: 4, ControlRight: 74,
  ShiftLeft: 29, ShiftRight: 73, MetaLeft: 23, MetaRight: 23,
  Numpad0: 33, Numpad1: 34, Numpad2: 35, Numpad3: 36, Numpad4: 37,
  Numpad5: 38, Numpad6: 39, Numpad7: 40, Numpad8: 41, Numpad9: 42,
};

window.RussDeskViewer = Viewer;
