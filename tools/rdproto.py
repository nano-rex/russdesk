#!/usr/bin/env python3
"""rdproto: the real RustDesk peer protocol, in Python, for the browser viewer.

Unlike rdclient.py (which fakes the session with its own JSON), this speaks the
actual encrypted RustDesk peer protocol to a genuine device: the ed25519-signed
handshake, the curve25519 key seal, the secretbox stream (with kx-version-1
split keys), the password/challenge login, and the encoded video frames.

It is the reference implementation that the browser viewer (JS + libsodium.js +
WebCodecs) is ported from, and a way to validate the protocol end to end:

    rdproto.py shot <device_id> --server host:31116 --key KEY --password PW [--out shot.png]

connects, logs in, grabs the first H264 keyframe and decodes it to a PNG with
ffmpeg. Needs PyNaCl; `shot` needs ffmpeg on PATH.
"""

import argparse
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

try:
    import nacl.bindings as sodium
except ImportError:
    sys.exit("PyNaCl is required: pip install pynacl")

NONCE = b"\x00" * 24
VERSION = "1.4.2"


# -- protobuf (varint + length-delimited + fixed; enough for these messages) ------

def _uv(n):
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def pb(*fields):
    out = bytearray()
    for num, value in fields:
        if value is None:
            continue
        if isinstance(value, bool):
            if not value:
                continue
            out += _uv(num << 3) + _uv(1)
        elif isinstance(value, int):
            if value == 0:
                continue
            out += _uv(num << 3) + _uv(value)
        else:
            data = value.encode() if isinstance(value, str) else bytes(value)
            out += _uv((num << 3) | 2) + _uv(len(data)) + data
    return bytes(out)


def msg(num, inner):
    """Wrap a sub-message as field `num` of the enclosing message."""
    return _uv((num << 3) | 2) + _uv(len(inner)) + inner


def unpb(buf):
    fields, i = {}, 0
    while i < len(buf):
        key, i = _rv(buf, i)
        num, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _rv(buf, i)
        elif wt == 2:
            n, i = _rv(buf, i)
            v, i = bytes(buf[i:i + n]), i + n
        elif wt == 5:
            v, i = bytes(buf[i:i + 4]), i + 4
        elif wt == 1:
            v, i = bytes(buf[i:i + 8]), i + 8
        else:
            raise ValueError("wire type %d" % wt)
        fields.setdefault(num, []).append(v)
    return fields


def _rv(buf, i):
    shift = result = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def one(fields, num, default=None):
    return fields.get(num, [default])[0]


def txt(fields, num):
    v = one(fields, num, b"")
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)


# -- framing (hbb_common BytesCodec) ---------------------------------------------

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


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def read_frame(sock):
    first = recv_exact(sock, 1)
    head_len = (first[0] & 3) + 1
    head = first + (recv_exact(sock, head_len - 1) if head_len > 1 else b"")
    n = int.from_bytes(head, "little") >> 2
    return recv_exact(sock, n)


# -- rendezvous (same as rdclient, minimal) --------------------------------------

RV = {"punch_hole_request": 8, "punch_hole": 9, "punch_hole_response": 11,
      "relay_response": 19, "request_relay": 18}


def split_host(server, default_port):
    if server.startswith("["):
        host, _, port = server[1:].partition("]:")
    elif server.count(":") == 1:
        host, _, port = server.partition(":")
    else:
        host, port = server, ""
    return host, int(port) if port.isdigit() else default_port


def log(msg):
    print("%s %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# -- transports: raw TCP (BytesCodec) or WebSocket (binary messages) -------------
# The browser can only do WebSocket, so the viewer uses the ws path; proving it
# here keeps the Python reference and the browser port on the same wire format.

class TcpTransport:
    def __init__(self, host, port, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)

    def send(self, payload):
        self.sock.sendall(frame(payload))

    def recv(self):
        return read_frame(self.sock)

    def settimeout(self, t):
        self.sock.settimeout(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class WsTransport:
    """Minimal RFC 6455 client: each RustDesk message is one binary frame."""

    def __init__(self, host, port, timeout, path="/"):
        import base64
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key))
        self.sock.sendall(req.encode())
        while b"\r\n\r\n" not in self.buf:
            self.buf += self.sock.recv(4096)
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        if b"101" not in head.split(b"\r\n", 1)[0]:
            raise RuntimeError("websocket upgrade failed: %r" % head[:80])

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, payload):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        n = len(payload)
        if n < 126:
            hdr = struct.pack("!BB", 0x82, 0x80 | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", 0x82, 0x80 | 126, n)
        else:
            hdr = struct.pack("!BBQ", 0x82, 0x80 | 127, n)
        self.sock.sendall(hdr + mask + masked)

    def recv(self):
        while True:
            b0, b1 = self._read(2)
            opcode, length = b0 & 0x0F, b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if b1 & 0x80 else b""
            data = self._read(length)
            if mask:
                data = bytes(d ^ mask[i & 3] for i, d in enumerate(data))
            if opcode in (0x1, 0x2):   # text/binary
                return data
            if opcode == 0x9:          # ping -> pong
                self.sock.sendall(struct.pack("!BB", 0x8A, 0x80 | len(data)) + os.urandom(4) + data)
            elif opcode == 0x8:        # close
                raise ConnectionError("websocket closed by peer")

    def settimeout(self, t):
        self.sock.settimeout(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def ws_port(port):
    """hbbs 21116 -> 21118, hbbr 21117 -> 21119 (hbb_common check_ws)."""
    return port + 2


# -- the session -----------------------------------------------------------------

class Session:
    def __init__(self, server, key, my_id=None, name="rdproto", verbose=True):
        self.host, self.port = split_host(server, 21116)
        self.key_str = key or ""  # server key as base64, sent as licence_key
        self.server_pk = _b64(key) if key else None  # ed25519 public key (32 bytes)
        self.my_id = my_id or str(_rand_id())
        self.name = name
        self.verbose = verbose
        self.device_sign_pk = None
        self.ws = False
        self.relay = None
        self.enc_key = self.dec_key = None
        self.send_seq = 0
        self.recv_seq = 0
        self.peer_info = {}

    def say(self, m):
        if self.verbose:
            log(m)

    def _transport(self, host, port, timeout):
        return WsTransport(host, ws_port(port), timeout) if self.ws else TcpTransport(host, port, timeout)

    # rendezvous + relay pairing
    def _pair(self, target, timeout):
        s = self._transport(self.host, self.port, timeout)
        # SYMMETRIC nat + force_relay so the device always goes through hbbr.
        s.send(pb((RV["punch_hole_request"],
                   pb((1, target), (2, 2), (3, self.key_str), (4, 0), (6, VERSION), (8, True)))))
        relay_uuid = relay_server = ""
        while True:
            name, body = _rv_msg(s.recv())
            if name == "punch_hole_response":
                fail = one(body, 3, 0)
                raise RuntimeError("hbbs refused: %s" % _PUNCH.get(fail, fail))
            if name == "relay_response":
                relay_uuid, relay_server = txt(body, 2), txt(body, 3)
                # field 5 (pk) = IdPk{id, device SIGN key} signed by the server key;
                # it's how we learn the device's sign key to verify its SignedId.
                signed_id_pk = one(body, 5, b"")
                if not signed_id_pk:
                    raise RuntimeError("relay response carried no device key")
                idpk0 = unpb(sodium.crypto_sign_open(signed_id_pk, self.server_pk))
                if txt(idpk0, 1) != target:
                    raise RuntimeError("server-signed id mismatch (wrong key?)")
                self.device_sign_pk = one(idpk0, 2, b"")
                if len(self.device_sign_pk) != 32:
                    raise RuntimeError("bad device sign key length")
                break
        s.close()
        rhost, rport = split_host(relay_server or self.host, self.port + 1)
        self.say("hbbs paired us: relay %s:%d uuid %s%s" % (rhost, rport, relay_uuid, " (ws)" if self.ws else ""))
        relay = self._transport(rhost, rport, timeout)
        relay.send(pb((RV["request_relay"], pb((1, target), (2, relay_uuid), (6, self.key_str)))))
        relay.settimeout(timeout)
        self.relay = relay

    # secure handshake with the device
    def _handshake(self, target):
        m = unpb(self.relay.recv())
        signed = one(m, 3)  # Message.signed_id (field 3) -> SignedId{ id=1 bytes }
        if signed is None:
            raise RuntimeError("expected SignedId, got fields %s" % list(m))
        blob = one(unpb(signed), 1, b"")
        # The peer's SignedId is signed by the DEVICE's sign key (learned above).
        idpk = unpb(sodium.crypto_sign_open(blob, self.device_sign_pk))
        dev_id, dev_pk = txt(idpk, 1), one(idpk, 2, b"")
        kx_adv = _varint_val(idpk, 4)
        if dev_id != target:
            raise RuntimeError("id mismatch: signed %r, wanted %r (wrong key?)" % (dev_id, target))
        if len(dev_pk) != 32:
            raise RuntimeError("bad device public key length")
        self.say("device identity verified by server key (kx v%d)" % kx_adv)

        our_pk, our_sk = sodium.crypto_box_keypair()
        session_key = os.urandom(32)
        sealed = sodium.crypto_box(session_key, NONCE, dev_pk, our_sk)
        picked = min(kx_adv, 1)
        self.relay.send(msg(4, pb((1, our_pk), (2, sealed), (3, picked))))  # PublicKey
        if picked >= 1:
            self.enc_key = _subkey(session_key, 1, kx_adv, picked, our_pk, dev_pk)  # we are initiator
            self.dec_key = _subkey(session_key, 2, kx_adv, picked, our_pk, dev_pk)
        else:
            self.enc_key = self.dec_key = session_key
        self.say("encrypted channel up")

    # encrypted send/recv
    def send(self, body):
        self.send_seq += 1
        cipher = sodium.crypto_secretbox(body, _nonce(self.send_seq), self.enc_key)
        self.relay.send(cipher)

    def recv(self):
        cipher = self.relay.recv()
        if len(cipher) <= 1:
            return {}
        self.recv_seq += 1
        plain = sodium.crypto_secretbox_open(cipher, _nonce(self.recv_seq), self.dec_key)
        return unpb(plain)

    def login(self, target, password, timeout=20):
        deadline = time.time() + timeout
        salt = challenge = None
        while time.time() < deadline:
            m = self.recv()
            if 9 in m:  # Message.hash
                h = unpb(one(m, 9))
                salt, challenge = txt(h, 1), txt(h, 2)
                break
        if salt is None:
            raise RuntimeError("no Hash from device")
        h1 = hashlib.sha256(password.encode() + salt.encode()).digest()
        h2 = hashlib.sha256(h1 + challenge.encode()).digest()
        # OptionMessage: ask for H264 only (ability_h264=1, prefer=H264=2)
        option = pb((10, pb((2, 1), (4, 2))))
        lr = pb((1, target), (2, h2), (4, self.my_id), (5, self.name),
                (6, option), (9, True), (10, _rand_id()), (11, VERSION), (13, "Linux"))
        self.send(msg(7, lr))  # Message.login_request
        self.say("sent login (H264 requested)")
        while time.time() < deadline:
            m = self.recv()
            if 8 in m:  # Message.login_response
                resp = unpb(one(m, 8))
                if 1 in resp:
                    raise RuntimeError("login refused: %s" % txt(resp, 1))
                pi = unpb(one(resp, 2, b""))
                self.peer_info = {"hostname": txt(pi, 2), "platform": txt(pi, 3),
                                  "displays": [_display(unpb(d)) for d in pi.get(4, [])]}
                self.say("logged in: %s (%s), displays %s" % (
                    self.peer_info["hostname"], self.peer_info["platform"],
                    [(d["width"], d["height"]) for d in self.peer_info["displays"]]))
                return self.peer_info
        raise RuntimeError("no LoginResponse (wrong password?)")

    def frames(self, timeout=20):
        """Yield (codec, key, data) for each encoded video frame."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.relay.settimeout(max(0.1, deadline - time.time()))
            try:
                m = self.recv()
            except socket.timeout:
                break
            vf = one(m, 6)  # Message.video_frame
            if vf is None:
                continue
            frames = unpb(vf)
            for field, codec in ((10, "h264"), (11, "h265"), (6, "vp9"), (12, "vp8"), (13, "av1")):
                for evs in frames.get(field, []):
                    for ev in unpb(evs).get(1, []):
                        e = unpb(ev)
                        yield codec, bool(_varint_val(e, 2)), one(e, 1, b"")

    def connect(self, target, password, timeout=20):
        self._pair(target, timeout)
        self._handshake(target)
        return self.login(target, password, timeout)

    def close(self):
        if self.relay:
            try:
                self.relay.close()
            except OSError:
                pass


# -- helpers ---------------------------------------------------------------------

_PUNCH = {0: "ID_NOT_EXIST (device not registered)", 2: "OFFLINE", 3: "LICENSE_MISMATCH (wrong key)"}


def _rv_msg(buf):
    f = unpb(buf)
    for num, names in {9: "punch_hole", 11: "punch_hole_response", 19: "relay_response"}.items():
        if num in f:
            return names, unpb(one(f, num))
    return None, {}


def _b64(s):
    import base64
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _b64_str(b):
    import base64
    return base64.b64encode(b).decode()


def _rand_id():
    import random
    return random.randint(100000000, 999999999)


def _nonce(seq):
    return struct.pack("<Q", seq) + b"\x00" * 16


def _varint_val(fields, num):
    v = fields.get(num, [0])[0]
    return v if isinstance(v, int) else 0


def _display(d):
    return {"x": _zz(_varint_val(d, 1)), "y": _zz(_varint_val(d, 2)),
            "width": _varint_val(d, 3), "height": _varint_val(d, 4), "name": txt(d, 5)}


def _zz(n):  # sint32 zigzag
    return (n >> 1) ^ -(n & 1)


def _subkey(key, direction, advertised, picked, initiator_pk, responder_pk):
    data = (b"rdkx-spl" + bytes([direction]) + struct.pack("<I", advertised) +
            struct.pack("<I", picked) + initiator_pk + responder_pk)
    return sodium.crypto_generichash_blake2b_salt_personal(data, digest_size=32, key=key)


# -- commands --------------------------------------------------------------------

def cmd_shot(args):
    s = Session(args.server, args.key, name=args.name)
    s.ws = args.ws
    try:
        s.connect(args.target, args.password)
    except (OSError, RuntimeError, ConnectionError) as exc:
        sys.exit("connect/login failed: %s" % exc)
    log("receiving video…")
    chunks, codec = [], None
    got_key = False
    for c, key, data in s.frames(timeout=args.timeout):
        if codec is None:
            codec = c
            log("codec: %s" % c)
        if not got_key and not key:
            continue  # wait for a keyframe to start a decodable stream
        got_key = True
        chunks.append(data)
        if len(chunks) >= args.frames:
            break
    s.close()
    if not chunks:
        sys.exit("no %s keyframe received (is a screen being shared?)" % (codec or "video"))
    raw = b"".join(chunks)
    log("got %d %s frame(s), %d bytes; decoding with ffmpeg" % (len(chunks), codec, len(raw)))
    proc = subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-f", codec, "-i", "pipe:0", "-frames:v", "1", "-y", args.out],
        input=raw, capture_output=True)
    if proc.returncode != 0 or not os.path.exists(args.out):
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.exit("ffmpeg could not decode the frame")
    d = s.peer_info["displays"][0] if s.peer_info.get("displays") else {}
    log("saved %s (%s, screen %sx%s)" % (args.out, codec, d.get("width", "?"), d.get("height", "?")))


def cmd_info(args):
    s = Session(args.server, args.key, name=args.name)
    s.ws = args.ws
    try:
        info = s.connect(args.target, args.password)
    except (OSError, RuntimeError, ConnectionError) as exc:
        sys.exit("failed: %s" % exc)
    print(info)
    s.close()


def main(argv=None):
    p = argparse.ArgumentParser(prog="rdproto.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd")
    sub.required = True
    for name, fn, extra in (("shot", cmd_shot, True), ("info", cmd_info, False)):
        sp = sub.add_parser(name, help="decode a frame to PNG" if extra else "log in and print peer info")
        sp.add_argument("target", help="device RustDesk ID")
        sp.add_argument("--server", required=True, help="ID server host:port")
        sp.add_argument("--key", default="", help="server public key")
        sp.add_argument("--password", required=True, help="device permanent password")
        sp.add_argument("--name", default="rdproto", help="controlling side name")
        sp.add_argument("--ws", action="store_true", help="use WebSocket transport (:port+2), as the browser does")
        if extra:
            sp.add_argument("--out", default="shot.png")
            sp.add_argument("--frames", type=int, default=1)
            sp.add_argument("--timeout", type=int, default=20)
        sp.set_defaults(fn=fn)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
