#!/usr/bin/env python3
"""rdclient: a terminal RustDesk test client for RussDesk servers.

It speaks the same network protocols as the official client, without the
screen-sharing part:

  * hbbs (rendezvous, UDP/TCP protobuf): ID registration, keep-alive, punch-hole
    and relay requests
  * hbbr (relay): pairing two sides by UUID and passing data through
  * RussDesk's HTTP API: login, heartbeat, sysinfo, strategies, remote
    disconnect, connection audit, notes, accessible devices, address books

Commands:
  device    act as a controlled device until stopped
  connect   act as the controlling side: reach a device through hbbs/hbbr
  login     log in to the API and remember the token
  peers     list accessible devices (needs login)
  ab        list address books and their devices (needs login)
  selftest  run a device and a controller against a server and check every
            step through the web console (needs an admin account)

Needs only Python 3.6+. Example:
  rdclient.py device --server rd.example.com:31116 --key KEY
  rdclient.py connect 123456789 --server rd.example.com:31116 --key KEY
"""

import argparse
import base64
import http.cookiejar
import json
import os
import random
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.4.2"  # reported like a client version
REG_INTERVAL = 12  # seconds between registrations (client: REG_INTERVAL)
HEARTBEAT_IDLE = 15
HEARTBEAT_BUSY = 3
STATE_DIR = os.path.expanduser("~/.rdclient")


# -- minimal protobuf -------------------------------------------------------------

def _varint(n):
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb(*fields):
    """Encode (number, value) pairs: int/bool -> varint, str/bytes -> bytes.
    None values are skipped, like proto3 defaults."""
    out = bytearray()
    for num, value in fields:
        if value is None or value is False or value == "" or value == b"":
            continue
        if isinstance(value, bool) or isinstance(value, int):
            out += _varint(num << 3) + _varint(int(value))
        else:
            data = value.encode() if isinstance(value, str) else bytes(value)
            out += _varint((num << 3) | 2) + _varint(len(data)) + data
    return bytes(out)


def unpb(buf):
    """Decode into {number: [values]} (varints as int, the rest as bytes)."""
    fields, i = {}, 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            value, i = _read_varint(buf, i)
        elif wt == 2:
            n, i = _read_varint(buf, i)
            value, i = buf[i:i + n], i + n
        elif wt == 5:
            value, i = buf[i:i + 4], i + 4
        elif wt == 1:
            value, i = buf[i:i + 8], i + 8
        else:
            raise ValueError("unsupported wire type %d" % wt)
        fields.setdefault(num, []).append(value)
    return fields


def _read_varint(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def first(fields, num, default=None):
    return fields.get(num, [default])[0]


def text(fields, num):
    v = first(fields, num, b"")
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


# RendezvousMessage oneof field numbers (hbb_common protos/rendezvous.proto)
RV = {"register_peer": 6, "register_peer_response": 7, "punch_hole_request": 8, "punch_hole": 9,
      "punch_hole_response": 11, "fetch_local_addr": 12, "configure_update": 14, "register_pk": 15,
      "register_pk_response": 16, "request_relay": 18, "relay_response": 19}
RV_NAMES = {v: k for k, v in RV.items()}
PUNCH_FAILURES = {0: "ID_NOT_EXIST", 2: "OFFLINE", 3: "LICENSE_MISMATCH (wrong key)", 4: "LICENSE_OVERUSE"}
REGISTER_PK_RESULTS = {0: "OK", 2: "UUID_MISMATCH", 3: "ID_EXISTS", 4: "TOO_FREQUENT",
                       5: "INVALID_ID_FORMAT", 6: "NOT_SUPPORT", 7: "SERVER_ERROR", 8: "NOT_DEPLOYED"}


def rv(name, inner):
    return pb((RV[name], inner))


def parse_rv(buf):
    fields = unpb(buf)
    for num, values in fields.items():
        if num in RV_NAMES:
            return RV_NAMES[num], unpb(values[0])
    return None, {}


# -- TCP framing (hbb_common BytesCodec) ---------------------------------------------

def frame(data):
    n = len(data)
    if n <= 0x3F:
        head = struct.pack("<B", n << 2)
    elif n <= 0x3FFF:
        head = struct.pack("<H", (n << 2) | 1)
    elif n <= 0x3FFFFF:
        h = (n << 2) | 2
        head = struct.pack("<HB", h & 0xFFFF, h >> 16)
    else:
        head = struct.pack("<I", (n << 2) | 3)
    return head + data


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def read_frame(sock):
    first_byte = _recv_exact(sock, 1)
    head_len = (first_byte[0] & 3) + 1
    head = first_byte + (_recv_exact(sock, head_len - 1) if head_len > 1 else b"")
    n = int.from_bytes(head, "little") >> 2
    return _recv_exact(sock, n)


def decode_addr(data):
    """hbb_common AddrMangle::decode, for display."""
    if not data:
        return ""
    if len(data) > 16:
        return "[%s]:%d" % (socket.inet_ntop(socket.AF_INET6, data[:16]), int.from_bytes(data[16:18], "little"))
    number = int.from_bytes(data + b"\0" * (16 - len(data)), "little")
    tm = (number >> 17) & 0xFFFFFFFF
    ip = ((number >> 49) - tm) & 0xFFFFFFFF
    port = ((number & 0xFFFFFF) - (tm & 0xFFFF)) & 0xFFFF
    return "%s:%d" % (socket.inet_ntoa(ip.to_bytes(4, "little")), port)


def split_host(server, default_port):
    if server.startswith("["):
        host, _, port = server[1:].partition("]:")
    elif server.count(":") == 1:
        host, _, port = server.partition(":")
    else:
        host, port = server, ""
    return host, int(port) if port.isdigit() else default_port


# -- HTTP API --------------------------------------------------------------------------

class Api:
    def __init__(self, base, token=None):
        self.base = base.rstrip("/")
        self.token = token
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, body=None, console=False, timeout=15):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if self.token and not console:
            req.add_header("Authorization", "Bearer " + self.token)
        if console:
            req.add_header("X-Russdesk", "1")
            req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as err:
            raw, status = err.read(), err.code
        try:
            return status, json.loads(raw.decode() or "null")
        except ValueError:
            return status, raw.decode("utf-8", "replace")


def api_for(server, explicit):
    """The API URL a client derives: ID server port minus 2 (common.rs)."""
    if explicit:
        return explicit
    host, port = split_host(server, 21116)
    host = "[%s]" % host if ":" in host else host
    return "http://%s:%d" % (host, port - 2)


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def log(who, msg):
    print("%s [%s] %s" % (time.strftime("%H:%M:%S"), who, msg), flush=True)


# -- controlled device -------------------------------------------------------------------

class Device:
    """A controlled RustDesk peer: registers, heartbeats, accepts relayed sessions."""

    def __init__(self, server, key, api, device_id=None, hostname=None, state_path=None, quiet=False):
        self.server = server
        self.key = key
        self.api = Api(api)
        self.host, self.port = split_host(server, 21116)
        self.state_path = state_path or os.path.join(STATE_DIR, "device.json")
        state = load_state(self.state_path)
        self.id = device_id or state.get("id") or str(random.randint(100000000, 999999999))
        self.uuid = bytes.fromhex(state["uuid"]) if state.get("uuid") else uuid.uuid4().bytes
        self.pk = bytes.fromhex(state["pk"]) if state.get("pk") else os.urandom(32)
        self.strategy_stamp = state.get("strategy_stamp", 0)
        self.options = state.get("options", {})
        self.hostname = hostname or socket.gethostname()
        self.quiet = quiet
        self.stop = threading.Event()
        self.sessions = {}  # conn_id -> socket
        self.conn_seq = 0
        self.lock = threading.Lock()
        self.registered = threading.Event()
        self.sysinfo_sent = False
        self.events = []  # (time, kind, detail) for selftest
        self._persist()

    def say(self, msg):
        if not self.quiet:
            log("device " + self.id, msg)

    def event(self, kind, detail=""):
        self.events.append((time.time(), kind, detail))
        self.say(("%s %s" % (kind, detail)).strip())

    def _persist(self):
        save_state(self.state_path, {"id": self.id, "uuid": self.uuid.hex(), "pk": self.pk.hex(),
                                     "strategy_stamp": self.strategy_stamp, "options": self.options})

    @property
    def uuid64(self):
        return base64.b64encode(self.uuid).decode()

    # rendezvous over UDP
    def run(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(1.0)
        addr = (socket.gethostbyname(self.host), self.port)
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        last = 0
        self.say("registering with hbbs %s:%d as ID %s" % (self.host, self.port, self.id))
        while not self.stop.is_set():
            if time.time() - last >= REG_INTERVAL:
                self.udp.sendto(rv("register_peer", pb((1, self.id), (2, 0))), addr)
                last = time.time()
            try:
                data, _ = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    break
                raise
            name, msg = parse_rv(data)
            if name == "register_peer_response":
                self.registered.set()
                if first(msg, 2, 0):  # request_pk
                    self.udp.sendto(rv("register_pk", pb((1, self.id), (2, self.uuid), (3, self.pk))), addr)
            elif name == "register_pk_response":
                result = first(msg, 1, 0)
                self.event("register_pk", REGISTER_PK_RESULTS.get(result, result))
                if result == 0:
                    self.registered.set()
            elif name in ("punch_hole", "fetch_local_addr"):
                socket_addr, relay = first(msg, 1, b""), text(msg, 2)
                threading.Thread(target=self._serve_relay, args=(socket_addr, relay, None),
                                 daemon=True).start()
            elif name == "request_relay":
                threading.Thread(target=self._serve_relay,
                                 args=(first(msg, 3, b""), text(msg, 4), text(msg, 2)), daemon=True).start()
            elif name == "configure_update":
                pass
        self.udp.close()

    def _serve_relay(self, socket_addr, relay_server, given_uuid):
        """Answer a punch-hole the way the client's create_relay() does: tell
        hbbs our relay UUID, then meet the controller at hbbr."""
        peer = decode_addr(socket_addr)
        relay_uuid = given_uuid or str(uuid.uuid4())
        with self.lock:
            self.conn_seq += 1
            conn_id = self.conn_seq
        session_id = 0
        self.event("incoming", "from %s via relay %s" % (peer, relay_server))
        self.audit({"action": "new", "ip": peer.rsplit(":", 1)[0]}, conn_id, session_id)
        try:
            with socket.create_connection((self.host, self.port), timeout=10) as s:
                rr = pb((1, socket_addr), (2, None if given_uuid else relay_uuid),
                        (3, None if given_uuid else relay_server), (4, None if given_uuid else self.id),
                        (7, VERSION))
                s.sendall(frame(rv("relay_response", rr)))
            rhost, rport = split_host(relay_server or self.host, self.port + 1)
            relay = socket.create_connection((rhost, rport), timeout=10)
            relay.sendall(frame(rv("request_relay", pb((1, self.id), (2, relay_uuid), (6, self.key)))))
            relay.settimeout(30)
            hello = json.loads(read_frame(relay).decode())
            session_id = hello.get("session_id", 0)
            with self.lock:
                self.sessions[conn_id] = relay
            self.audit({"peer": [hello.get("from", ""), hello.get("name", "")], "type": 0, "primary_auth": 3},
                       conn_id, session_id)
            relay.sendall(frame(json.dumps({"t": "welcome", "id": self.id, "hostname": self.hostname,
                                            "options": self.options}).encode()))
            self.event("session", "authorized %s (%s), conn %d" % (hello.get("from"), hello.get("name"), conn_id))
            relay.settimeout(None)
            while not self.stop.is_set():
                msg = json.loads(read_frame(relay).decode())
                if msg.get("t") == "ping":
                    relay.sendall(frame(json.dumps({"t": "pong", "n": msg.get("n")}).encode()))
                elif msg.get("t") == "bye":
                    break
        except (OSError, ConnectionError, ValueError) as exc:
            self.event("session_end", "conn %d: %s" % (conn_id, exc))
        finally:
            with self.lock:
                sock = self.sessions.pop(conn_id, None)
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
            self.audit({"action": "close"}, conn_id, session_id)
            self.event("closed", "conn %d" % conn_id)

    # HTTP side
    def audit(self, body, conn_id, session_id):
        body = dict(body, id=self.id, uuid=self.uuid64, conn_id=conn_id, session_id=session_id,
                    nonce=str(uuid.uuid4()))
        try:
            self.api.call("POST", "/api/audit/conn", body)
        except OSError as exc:
            self.say("audit failed: %s" % exc)

    def send_sysinfo(self):
        body = {"id": self.id, "uuid": self.uuid64, "hostname": self.hostname, "username": os.environ.get("USER", ""),
                "os": "linux / rdclient test device", "cpu": "%d cores" % (os.cpu_count() or 1),
                "memory": "", "version": VERSION}
        status, reply = self.api.call("POST", "/api/sysinfo", body)
        self.sysinfo_sent = status == 200 and reply == "SYSINFO_UPDATED"
        self.event("sysinfo", "ok" if self.sysinfo_sent else "HTTP %s %s" % (status, reply))

    def _heartbeat_loop(self):
        while not self.stop.is_set():
            with self.lock:
                conns = sorted(self.sessions)
            body = {"id": self.id, "uuid": self.uuid64, "ver": 1004002, "modified_at": self.strategy_stamp}
            if conns:
                body["conns"] = conns
            try:
                status, reply = self.api.call("POST", "/api/heartbeat", body)
            except OSError as exc:
                self.say("heartbeat failed: %s" % exc)
                status, reply = 0, None
            if status == 200 and isinstance(reply, dict):
                if "sysinfo" in reply:
                    self.send_sysinfo()
                for conn_id in reply.get("disconnect", []):
                    self.event("disconnect_request", "conn %s from the console" % conn_id)
                    with self.lock:
                        sock = self.sessions.get(conn_id)
                    if sock:
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                if "strategy" in reply:
                    options = reply["strategy"].get("config_options", {})
                    for k, v in options.items():
                        if v == "":
                            self.options.pop(k, None)
                        else:
                            self.options[k] = v
                    self.event("strategy", json.dumps(options, sort_keys=True))
                if "modified_at" in reply:
                    self.strategy_stamp = reply["modified_at"]
                    self._persist()
            elif status:
                self.say("heartbeat HTTP %s %s" % (status, reply))
            self.stop.wait(HEARTBEAT_BUSY if conns else HEARTBEAT_IDLE)


# -- controlling side --------------------------------------------------------------------

class Controller:
    def __init__(self, server, key, my_id=None, name=None, quiet=False):
        self.server, self.key = server, key
        self.host, self.port = split_host(server, 21116)
        self.my_id = my_id or str(random.randint(100000000, 999999999))
        self.name = name or (os.environ.get("USER", "") + "@" + socket.gethostname())
        self.quiet = quiet
        self.session_id = random.randint(1, 2 ** 53)

    def say(self, msg):
        if not self.quiet:
            log("connect", msg)

    def connect(self, target, timeout=20):
        """Return (relay socket, welcome message) or raise RuntimeError."""
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        req = pb((1, target), (2, 2), (3, self.key), (4, 0), (6, VERSION), (8, True))  # SYMMETRIC + force relay
        s.sendall(frame(rv("punch_hole_request", req)))
        self.say("asked hbbs %s:%d for %s" % (self.host, self.port, target))
        t0 = time.time()
        while True:
            name, msg = parse_rv(read_frame(s))
            if name == "punch_hole_response":
                if first(msg, 1) or first(msg, 2):
                    raise RuntimeError("peer offered a direct connection; this client only relays")
                failure = first(msg, 3, 0)
                raise RuntimeError("hbbs refused: %s %s" % (PUNCH_FAILURES.get(failure, failure), text(msg, 7)))
            if name == "relay_response":
                if text(msg, 6):
                    raise RuntimeError("refused: " + text(msg, 6))
                relay_uuid, relay_server = text(msg, 2), text(msg, 3)
                pk = first(msg, 5, b"")
                break
        s.close()
        self.say("hbbs answered in %.0f ms: relay %s, uuid %s, device key %s" % (
            (time.time() - t0) * 1000, relay_server, relay_uuid, "received" if pk else "missing"))
        rhost, rport = split_host(relay_server or self.host, self.port + 1)
        relay = socket.create_connection((rhost, rport), timeout=timeout)
        relay.sendall(frame(rv("request_relay", pb((1, target), (2, relay_uuid), (6, self.key)))))
        relay.settimeout(timeout)
        relay.sendall(frame(json.dumps({"t": "hello", "from": self.my_id, "name": self.name,
                                        "session_id": self.session_id}).encode()))
        welcome = json.loads(read_frame(relay).decode())
        self.say("relayed session up with %s (%s) through hbbr %s:%d" % (
            welcome.get("id"), welcome.get("hostname"), rhost, rport))
        return relay, welcome

    def ping(self, relay, count=5):
        rtts = []
        for n in range(count):
            t0 = time.time()
            relay.sendall(frame(json.dumps({"t": "ping", "n": n}).encode()))
            reply = json.loads(read_frame(relay).decode())
            if reply.get("t") == "pong" and reply.get("n") == n:
                rtts.append((time.time() - t0) * 1000)
        return rtts

    def hold(self, relay, seconds):
        """Keep the session open; return True if the device closed it."""
        relay.settimeout(1.0)
        end = time.time() + seconds
        while time.time() < end:
            try:
                data = relay.recv(4096)
                if not data:
                    return True
            except socket.timeout:
                continue
            except OSError:
                return True
        return False


# -- commands ---------------------------------------------------------------------------

def token_state():
    return load_state(os.path.join(STATE_DIR, "login.json"))


def cmd_device(args):
    dev = Device(args.server, args.key, api_for(args.server, args.api), args.id, args.name,
                 os.path.join(STATE_DIR, "device-%s.json" % args.id) if args.id else None)
    print("Device ID %s  (API %s)  Ctrl+C to stop" % (dev.id, dev.api.base), flush=True)
    try:
        dev.run()
    except KeyboardInterrupt:
        dev.stop.set()


def cmd_connect(args):
    ctl = Controller(args.server, args.key, args.my_id)
    try:
        relay, welcome = ctl.connect(args.target)
    except (OSError, RuntimeError, ConnectionError) as exc:
        sys.exit("connect failed: %s" % exc)
    rtts = ctl.ping(relay, args.pings)
    if rtts:
        print("round trip through hbbr: min %.1f / avg %.1f / max %.1f ms" % (min(rtts), sum(rtts) / len(rtts), max(rtts)))
    if welcome.get("options"):
        print("device's pushed options:", json.dumps(welcome["options"], sort_keys=True))
    if args.note:
        st = token_state()
        api = Api(api_for(args.server, args.api), st.get("token"))
        status, reply = api.call("POST", "/api/audit/conn", {"id": args.target, "session_id": ctl.session_id,
                                                              "note": args.note})
        print("note:", "saved" if status == 200 else "HTTP %s %s" % (status, reply))
    if args.hold:
        print("holding the session %ds (disconnect it from the console to test)…" % args.hold, flush=True)
        if ctl.hold(relay, args.hold):
            print("the device closed the session")
    try:
        relay.sendall(frame(json.dumps({"t": "bye"}).encode()))
    except OSError:
        pass
    relay.close()


def cmd_login(args):
    api = Api(api_for(args.server, args.api))
    password = args.password or os.environ.get("RDCLIENT_PASSWORD") or __import__("getpass").getpass()
    my_id = args.my_id or str(random.randint(100000000, 999999999))
    body = {"username": args.user, "password": password, "id": my_id, "uuid": base64.b64encode(uuid.uuid4().bytes).decode(),
            "type": "account", "autoLogin": True, "deviceInfo": {"os": "linux", "type": "client", "name": "rdclient"}}
    status, reply = api.call("POST", "/api/login", body)
    if isinstance(reply, dict) and reply.get("type") == "email_check":
        code = input("Code (%s): " % ("authenticator" if reply.get("tfa_type") else "email"))
        body.update(type="email_code", verificationCode=code, tfaCode=code, secret=reply["secret"])
        status, reply = api.call("POST", "/api/login", body)
    if not isinstance(reply, dict) or reply.get("type") != "access_token":
        sys.exit("login failed: %s" % (reply.get("error") if isinstance(reply, dict) else reply))
    save_state(os.path.join(STATE_DIR, "login.json"), {"api": api.base, "token": reply["access_token"], "id": my_id})
    print("logged in as %s (admin: %s)" % (reply["user"]["name"], reply["user"]["is_admin"]))


def _logged_in_api(args):
    st = token_state()
    if not st.get("token"):
        sys.exit("log in first: rdclient.py login USER --server ...")
    return Api(args.api or st["api"], st["token"])


def cmd_peers(args):
    api = _logged_in_api(args)
    status, reply = api.call("GET", "/api/peers?current=1&pageSize=100&accessible=&status=1")
    if status != 200:
        sys.exit("HTTP %s %s" % (status, reply))
    for p in reply["data"]:
        print("%-12s %-20s %-10s %s" % (p["id"], p["info"].get("device_name", ""), p.get("user_name", ""),
                                       p.get("device_group_name", "")))
    print("%d accessible devices" % reply["total"])


def cmd_ab(args):
    api = _logged_in_api(args)
    _, personal = api.call("POST", "/api/ab/personal")
    _, shared = api.call("POST", "/api/ab/shared/profiles?current=1&pageSize=100")
    books = [("My address book", personal["guid"], 3)] + [(b["name"], b["guid"], b["rule"]) for b in shared.get("data", [])]
    for name, guid, rule in books:
        _, peers = api.call("POST", "/api/ab/peers?current=1&pageSize=100&ab=" + guid)
        print("%s (rule %s): %d devices" % (name, rule, peers.get("total", 0)))
        for p in peers.get("data", []):
            print("   %-12s %-16s %s" % (p["id"], p.get("alias", ""), ",".join(p.get("tags", []))))


# -- selftest ---------------------------------------------------------------------------

class Checks:
    def __init__(self):
        self.results = []

    def check(self, label, ok, detail=""):
        self.results.append((label, bool(ok)))
        print("%s  %s%s" % ("PASS" if ok else "FAIL", label, ("  (%s)" % detail) if detail else ""), flush=True)
        return ok


def wait_for(fn, timeout, interval=1.0):
    end = time.time() + timeout
    while time.time() < end:
        value = fn()
        if value:
            return value
        time.sleep(interval)
    return None


def cmd_selftest(args):
    api_url = api_for(args.server, args.api)
    password = args.password or os.environ.get("RDCLIENT_PASSWORD") or __import__("getpass").getpass("Admin password: ")
    c = Checks()
    console = Api(api_url)
    status, reply = console.call("POST", "/api/admin/login", {"username": args.user, "password": password}, console=True)
    if not c.check("console login as %s" % args.user, status == 200 and isinstance(reply, dict) and reply.get("ok"), reply):
        sys.exit(1)
    status, cfg = console.call("GET", "/api/admin/client-config", console=True)
    key = args.key or cfg.get("key", "")
    c.check("server key known", key, key[:12] + "…" if key else "set it in Settings")

    tmp_state = os.path.join(STATE_DIR, "selftest-device-%d.json" % os.getpid())
    dev = Device(args.server, key, api_url, hostname="rdclient-selftest", state_path=tmp_state, quiet=not args.verbose)
    threading.Thread(target=dev.run, daemon=True).start()
    c.check("device registered with hbbs (UDP)", dev.registered.wait(15), "ID %s" % dev.id)
    def listed():
        status, reply = console.call("GET", "/api/admin/devices?q=" + dev.id, console=True)
        items = reply.get("items", []) if status == 200 and isinstance(reply, dict) else []
        return items[0] if items and items[0]["hostname"] == "rdclient-selftest" else None
    found = wait_for(listed, 40)
    c.check("device listed in the console via heartbeat + sysinfo", found and found["online"])

    # Client login from the controlling side, as the official client does.
    ctl = Controller(args.server, key, name="rdclient selftest")
    client = Api(api_url)
    status, reply = client.call("POST", "/api/login", {"username": args.user, "password": password, "id": ctl.my_id,
                                                       "uuid": base64.b64encode(uuid.uuid4().bytes).decode(),
                                                       "type": "account", "deviceInfo": {"name": "rdclient"}})
    logged = isinstance(reply, dict) and reply.get("type") == "access_token"
    c.check("client API login", logged, "" if logged else reply)
    client.token = reply.get("access_token") if logged else None

    try:
        relay, welcome = ctl.connect(dev.id)
        connected = welcome.get("id") == dev.id
    except (OSError, RuntimeError, ConnectionError) as exc:
        relay, connected = None, False
        c.check("connection brokered by hbbs and relayed by hbbr", False, exc)
    if connected:
        c.check("connection brokered by hbbs and relayed by hbbr", True)
        rtts = ctl.ping(relay, 5)
        c.check("data passes through the relay", len(rtts) == 5, "avg %.1f ms" % (sum(rtts) / max(1, len(rtts))))
        session = wait_for(lambda: next((s for s in console.call("GET", "/api/admin/dashboard", console=True)[1]
                                         .get("active_sessions", []) if s["device_id"] == dev.id and s["peer_id"]), None), 20)
        c.check("console shows the active session with the controlling user",
                session and session["controller"] == args.user, session and session["controller"])
        if client.token:
            status, _ = client.call("POST", "/api/audit/conn", {"id": dev.id, "session_id": ctl.session_id,
                                                                 "note": "rdclient selftest note"})
        if session:
            status, _ = console.call("POST", "/api/admin/logs/connections/%d/disconnect" % session["id"], {}, console=True)
            c.check("console Disconnect accepted", status == 200)
            closed = ctl.hold(relay, 25)
            c.check("device dropped the session on the console's request", closed)
            def ended_entry():  # the device posts "close" just after dropping the session
                logs = console.call("GET", "/api/admin/logs/connections?device=" + dev.id, console=True)[1]
                entry = next((i for i in logs.get("items", []) if i["id"] == session["id"]), None)
                return entry if entry and entry.get("ended_at") else None
            entry = wait_for(ended_entry, 15) or {}
            c.check("connection log: type, authentication, end time", entry.get("type") == "Remote Desktop"
                    and entry.get("auth") == "Permanent Password" and entry.get("ended_at"))
            c.check("connection note from the controlling side", entry.get("note") == "rdclient selftest note")
        try:
            relay.close()
        except OSError:
            pass

    # Strategy push and reset.
    status, created = console.call("POST", "/api/admin/strategies", {
        "name": "rdclient-selftest-%d" % os.getpid(), "options": {"enable-file-transfer": "N"}}, console=True)
    sid = created.get("id") if isinstance(created, dict) else None
    if sid:
        console.call("POST", "/api/admin/strategies/%d/targets" % sid, {"kind": "devices", "add": [dev.id]}, console=True)
        got = wait_for(lambda: dev.options.get("enable-file-transfer") == "N", 25)
        c.check("strategy pushed to the device on its heartbeat", got)
        console.call("DELETE", "/api/admin/strategies/%d" % sid, console=True)
        reset = wait_for(lambda: "enable-file-transfer" not in dev.options, 25)
        c.check("deleting the strategy resets the option", reset)

    # Disable: the device gets a blocking whitelist.
    console.call("POST", "/api/admin/devices/%s/disable" % dev.id, {}, console=True)
    blocked = wait_for(lambda: dev.options.get("whitelist") == "255.255.255.255/32", 25)
    c.check("disabling the device pushes a blocking IP whitelist", blocked)
    console.call("POST", "/api/admin/devices/%s/enable" % dev.id, {}, console=True)
    c.check("enabling it lifts the block", wait_for(lambda: "whitelist" not in dev.options, 25))

    if client.token:
        status, peers = client.call("GET", "/api/peers?current=1&pageSize=200&accessible=&status=1")
        c.check("accessible devices list for the logged-in user",
                status == 200 and any(p["id"] == dev.id for p in peers.get("data", [])))
        status, personal = client.call("POST", "/api/ab/personal")
        guid = personal.get("guid") if isinstance(personal, dict) else None
        if guid:
            client.call("POST", "/api/ab/peer/add/" + guid, {"id": dev.id, "alias": "selftest"})
            _, listing = client.call("POST", "/api/ab/peers?current=1&pageSize=100&ab=" + guid)
            c.check("personal address book round trip", any(p["id"] == dev.id for p in listing.get("data", [])))
            client.call("DELETE", "/api/ab/peer/" + guid, [dev.id])
        client.call("POST", "/api/logout", {"id": ctl.my_id})

    # Clean up the test device.
    dev.stop.set()
    if not args.keep:
        console.call("POST", "/api/admin/devices/%s/disable" % dev.id, {}, console=True)
        console.call("DELETE", "/api/admin/devices/%s" % dev.id, console=True)
    try:
        os.remove(tmp_state)
    except OSError:
        pass
    failed = [label for label, ok in c.results if not ok]
    print("\n%d/%d checks passed against %s" % (len(c.results) - len(failed), len(c.results), args.server))
    sys.exit(1 if failed else 0)


def main(argv=None):
    p = argparse.ArgumentParser(prog="rdclient.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    def common(sp, key=True):
        sp.add_argument("--server", required=True, help="ID server, host:port (e.g. rd.example.com:31116)")
        if key:
            sp.add_argument("--key", default="", help="server public key (hbbs id_ed25519.pub)")
        sp.add_argument("--api", help="API URL (default: ID server port minus 2, like the client)")

    sp = sub.add_parser("device", help="act as a controlled device")
    common(sp)
    sp.add_argument("--id", help="device ID (default: random, remembered in ~/.rdclient)")
    sp.add_argument("--name", help="hostname to report")
    sp.set_defaults(fn=cmd_device)

    sp = sub.add_parser("connect", help="connect to a device through hbbs/hbbr")
    sp.add_argument("target")
    common(sp)
    sp.add_argument("--my-id", help="this side's ID (default: random)")
    sp.add_argument("--pings", type=int, default=5)
    sp.add_argument("--hold", type=int, default=0, help="keep the session open N seconds")
    sp.add_argument("--note", help="post a session note (needs login)")
    sp.set_defaults(fn=cmd_connect)

    sp = sub.add_parser("login", help="log in to the API")
    sp.add_argument("user")
    common(sp, key=False)
    sp.add_argument("--password", help="or RDCLIENT_PASSWORD, or prompt")
    sp.add_argument("--my-id")
    sp.set_defaults(fn=cmd_login)

    for name, fn in (("peers", cmd_peers), ("ab", cmd_ab)):
        sp = sub.add_parser(name, help="list accessible devices" if name == "peers" else "list address books")
        sp.add_argument("--api")
        sp.set_defaults(fn=fn)

    sp = sub.add_parser("selftest", help="end-to-end test of a server")
    common(sp)
    sp.add_argument("--user", default="admin", help="administrator account")
    sp.add_argument("--password", help="or RDCLIENT_PASSWORD, or prompt")
    sp.add_argument("--keep", action="store_true", help="keep the test device afterwards")
    sp.add_argument("--verbose", action="store_true")
    sp.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
