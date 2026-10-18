"""The HTTP API that RustDesk clients call (the "API server" setting).

Endpoints and payloads follow what the open-source RustDesk client sends and
expects; see docs/client-protocol.md for the reference."""

import json
import os
import re
import secrets
import threading
import time

from . import models
from .db import now
from .models import RULE_READ_WRITE, loads
from .security import (DUMMY_HASH, RateLimiter, new_token, token_hash,
                       verify_password, verify_totp)
from .web import HTTPError, Response, Router, json_response

router = Router()

login_failures = RateLimiter(limit=10, window=300)
_pending_2fa = {}  # secret -> (user_id, expires, attempts)
_pending_lock = threading.Lock()

RECORDING_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,199}\.(webm|mkv|mp4)$")


def ok_empty():
    return Response(b"", 200, "text/plain; charset=utf-8")


def text(body):
    return Response(body, 200, "text/plain; charset=utf-8")


def error(message, status=200):
    return json_response({"error": message}, status)


def page_args(req):
    try:
        current = max(1, int(req.query.get("current") or 1))
        size = min(1000, max(1, int(req.query.get("pageSize") or 100)))
    except ValueError:
        raise HTTPError(400, "Invalid pagination")
    return current, size


def device_id_of(data):
    device_id = data.get("id")
    if not isinstance(device_id, str) or not device_id or len(device_id) > 64:
        raise HTTPError(400, "Invalid device ID")
    device_uuid = data.get("uuid") if isinstance(data.get("uuid"), str) else ""
    return device_id, device_uuid[:128]


# -- authentication --------------------------------------------------------------

def client_user(app, req):
    token = req.bearer()
    if not token:
        raise HTTPError(401, "Not logged in")
    db = app.db
    row = db.one(
        "SELECT t.token_hash, t.last_seen_at, u.* FROM tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND t.kind = 'client' AND t.expires_at > ?",
        (token_hash(token), now()),
    )
    if row is None or row["status"] != 1:
        raise HTTPError(401, "Invalid or expired token")
    if now() - row["last_seen_at"] > 60:
        db.run("UPDATE tokens SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?",
               (now(), client_expiry(db), row["token_hash"]))
    req.user = row
    return row


NEVER = 253402300799  # 9999-12-31


def client_expiry(db):
    """Client logins last until logout or revocation unless a lifetime is set."""
    days = db.setting("client_token_days")
    return now() + days * 86400 if days else NEVER


def _issue_client_token(app, req, user, data):
    db = app.db
    token = new_token()
    device_id = data.get("id") if isinstance(data.get("id"), str) else ""
    device_uuid = data.get("uuid") if isinstance(data.get("uuid"), str) else ""
    info = data.get("deviceInfo") if isinstance(data.get("deviceInfo"), dict) else {}
    expires = client_expiry(db)
    with db.tx() as c:
        c.execute(
            "INSERT INTO tokens(token_hash, user_id, kind, device_id, device_uuid, device_info, ip, "
            "created_at, last_seen_at, expires_at) VALUES (?, ?, 'client', ?, ?, ?, ?, ?, ?, ?)",
            (token_hash(token), user["id"], device_id[:64], device_uuid[:128],
             json.dumps(info)[:2048], req.ip, now(), now(), expires),
        )
        c.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
        if device_id and len(device_id) <= 64:
            # Logging in on a device makes the account its user, as in Pro.
            models.ensure_device(c, device_id, device_uuid[:128], req.ip)
            c.execute("UPDATE devices SET user_id = ? WHERE id = ?", (user["id"], device_id))
    models.personal_book(db, user["id"])
    return json_response({
        "access_token": token,
        "type": "access_token",
        "user": models.user_payload(user),
    })


@router.route("POST", "/api/login")
def login(app, req):
    data = req.json_object()
    kind = data.get("type") or "account"
    username = str(data.get("username") or "").strip()
    keys = ("ip:" + req.ip, "user:" + username.lower())
    if any(login_failures.blocked(k) for k in keys):
        return error("Too many failed attempts, try again later")

    if kind == "account":
        password = str(data.get("password") or "")
        user = app.db.one("SELECT * FROM users WHERE name = ?", (username,))
        if user is None:
            verify_password(password, DUMMY_HASH)
        if user is None or not verify_password(password, user["password_hash"]):
            for k in keys:
                login_failures.hit(k)
            return error("Wrong username or password")
        if user["status"] != 1:
            return error("User is disabled")
        if user["totp_secret"]:
            secret = secrets.token_urlsafe(24)
            with _pending_lock:
                _pending_2fa[secret] = (user["id"], time.time() + 300, 0)
            return json_response({
                "type": "email_check",
                "tfa_type": "tfa_check",
                "secret": secret,
                "user": models.user_payload(user),
            })
        login_failures.reset("user:" + username.lower())
        return _issue_client_token(app, req, user, data)

    if kind in ("email_code", "tfa_code"):
        secret = str(data.get("secret") or "")
        code = str(data.get("tfaCode") or data.get("verificationCode") or "")
        with _pending_lock:
            pending = _pending_2fa.get(secret)
            if pending is None or pending[1] < time.time():
                _pending_2fa.pop(secret, None)
                return error("Verification expired, log in again")
            user_id, expires, attempts = pending
            _pending_2fa[secret] = (user_id, expires, attempts + 1)
            if attempts >= 5:
                _pending_2fa.pop(secret, None)
                return error("Too many wrong codes, log in again")
        user = app.db.one("SELECT * FROM users WHERE id = ?", (user_id,))
        if user is None or user["status"] != 1:
            return error("User is disabled")
        if not verify_totp(user["totp_secret"], code):
            for k in keys:
                login_failures.hit(k)
            return error("Wrong verification code")
        with _pending_lock:
            _pending_2fa.pop(secret, None)
        return _issue_client_token(app, req, user, data)

    return error("Unsupported login type")


@router.route("GET", "/api/login-options")
def login_options(app, req):
    return json_response([])


@router.route("POST", "/api/logout")
def logout(app, req):
    token = req.bearer()
    if token:
        app.db.run("DELETE FROM tokens WHERE token_hash = ? AND kind = 'client'", (token_hash(token),))
    return ok_empty()


@router.route("POST", "/api/currentUser")
def current_user(app, req):
    user = client_user(app, req)
    return json_response(models.user_payload(user))


# -- device sync -----------------------------------------------------------------

@router.route("POST", "/api/heartbeat")
def heartbeat(app, req):
    data = req.json_object()
    device_id, device_uuid = device_id_of(data)
    conns = [c for c in data.get("conns") or [] if isinstance(c, int)][:256]
    try:
        client_stamp = int(data.get("modified_at") or 0)
    except (TypeError, ValueError):
        client_stamp = 0
    db = app.db
    resp = {}
    with db.tx() as c:
        device = models.ensure_device(c, device_id, device_uuid, req.ip)
        c.execute("UPDATE devices SET last_seen_at = ?, ip = ?, conns = ?, uuid = ? WHERE id = ?",
                  (now(), req.ip, json.dumps(conns), device_uuid or device["uuid"], device_id))
        if device["sysinfo_at"] is None:
            resp["sysinfo"] = 1
        pending = [r["conn_id"] for r in c.execute(
            "SELECT conn_id FROM pending_disconnects WHERE device_id = ?", (device_id,))]
        if pending:
            resp["disconnect"] = pending
            c.execute("DELETE FROM pending_disconnects WHERE device_id = ?", (device_id,))
        # Sessions the client no longer reports have ended (a close audit
        # can be lost when the device goes offline mid-session).
        open_rows = c.execute(
            "SELECT id, conn_id FROM conn_logs WHERE device_id = ? AND ended_at IS NULL "
            "AND started_at < ?", (device_id, now() - 60)).fetchall()
        for row in open_rows:
            if row["conn_id"] not in conns:
                c.execute("UPDATE conn_logs SET ended_at = ? WHERE id = ?", (now(), row["id"]))

    device = db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    strategy = models.effective_strategy(db, device)
    stamp = models.strategy_stamp(strategy)
    if stamp != client_stamp:
        options = loads(strategy["options"], {}) if strategy else {}
        options = {str(k): str(v) for k, v in options.items()}
        config = dict(options)
        for key in loads(device["applied_keys"], []):
            if key not in config:
                config[key] = ""  # falls back to the client's built-in default
        if config or client_stamp:
            resp["strategy"] = {"config_options": config}
        resp["modified_at"] = stamp
        db.run("UPDATE devices SET applied_keys = ? WHERE id = ?",
               (json.dumps(sorted(options)), device_id))
    return json_response(resp)


@router.route("POST", "/api/sysinfo")
def sysinfo(app, req):
    data = req.json_object()
    device_id, device_uuid = device_id_of(data)

    def field(name, limit=256):
        value = data.get(name)
        return str(value)[:limit] if value is not None else ""

    db = app.db
    with db.tx() as c:
        device = models.ensure_device(c, device_id, device_uuid, req.ip)
        c.execute(
            "UPDATE devices SET hostname=?, username=?, os=?, cpu=?, memory=?, version=?, "
            "sysinfo=?, ip=?, uuid=?, sysinfo_at=?, last_seen_at=? WHERE id=?",
            (field("hostname"), field("username"), field("os"), field("cpu"), field("memory"),
             field("version", 32), json.dumps(data)[:16384], req.ip,
             device_uuid or device["uuid"], now(), now(), device_id),
        )
        _apply_presets(c, device, data)
    return text("SYSINFO_UPDATED")


def _apply_presets(c, device, data):
    """Honour preset-* values baked into a custom client, without overriding
    what an admin already set in the console."""
    device_id = device["id"]
    name = data.get("preset-user-name")
    if isinstance(name, str) and name and not device["user_id"]:
        u = c.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchone()
        if u:
            c.execute("UPDATE devices SET user_id = ? WHERE id = ?", (u["id"], device_id))
    name = data.get("preset-device-group-name")
    if isinstance(name, str) and name and not device["device_group_id"]:
        g = c.execute("SELECT id FROM device_groups WHERE name = ?", (name,)).fetchone()
        if g:
            c.execute("UPDATE devices SET device_group_id = ? WHERE id = ?", (g["id"], device_id))
    name = data.get("preset-strategy-name")
    if isinstance(name, str) and name and not device["strategy_id"]:
        s = c.execute("SELECT id FROM strategies WHERE name = ?", (name,)).fetchone()
        if s:
            c.execute("UPDATE devices SET strategy_id = ? WHERE id = ?", (s["id"], device_id))
    note = data.get("preset-note")
    if isinstance(note, str) and note and not device["note"]:
        c.execute("UPDATE devices SET note = ? WHERE id = ?", (note[:1024], device_id))
    name = data.get("preset-address-book-name")
    if isinstance(name, str) and name:
        book = c.execute("SELECT guid FROM address_books WHERE name = ? AND personal = 0 "
                         "ORDER BY created_at LIMIT 1", (name,)).fetchone()
        if book and not c.execute("SELECT 1 FROM ab_peers WHERE guid = ? AND peer_id = ?",
                                  (book["guid"], device_id)).fetchone():
            peer = {"id": device_id}
            tag = data.get("preset-address-book-tag")
            if isinstance(tag, str) and tag:
                c.execute("INSERT OR IGNORE INTO ab_tags(guid, name, color) VALUES (?, ?, ?)",
                          (book["guid"], tag[:64], 0xFF2196F3))
                peer["tags"] = [tag[:64]]
            for key, target in (("preset-address-book-alias", "alias"),
                                ("preset-address-book-password", "password"),
                                ("preset-address-book-note", "note")):
                if isinstance(data.get(key), str) and data[key]:
                    peer[target] = data[key]
            models.upsert_peer(c, book["guid"], peer, personal=False)


@router.route("POST", "/api/sysinfo_ver")
def sysinfo_ver(app, req):
    return text(app.db.meta("instance_id"))


# -- audit ---------------------------------------------------------------------

def _claim_nonce(c, data):
    """False when this nonce was already stored (a client retry)."""
    nonce = data.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return True
    try:
        c.execute("INSERT INTO nonces(nonce, created_at) VALUES (?, ?)", (nonce[:64], now()))
    except Exception as exc:  # sqlite3.IntegrityError
        if "UNIQUE" in str(exc):
            return False
        raise
    return True


def _int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


@router.route("POST", "/api/audit/conn")
def audit_conn(app, req):
    data = req.json_object()
    device_id, _ = device_id_of(data)
    conn_id = _int(data.get("conn_id"))
    if conn_id is None:
        raise HTTPError(400, "Missing conn_id")
    session_id = str(data.get("session_id") or "")[:64]
    action = data.get("action")
    with app.db.tx() as c:
        if not _claim_nonce(c, data):
            return ok_empty()
        open_row = c.execute(
            "SELECT id FROM conn_logs WHERE device_id = ? AND conn_id = ? AND ended_at IS NULL "
            "ORDER BY id DESC LIMIT 1", (device_id, conn_id)).fetchone()
        if action == "new":
            c.execute("INSERT INTO conn_logs(device_id, conn_id, session_id, ip, started_at) "
                      "VALUES (?, ?, ?, ?, ?)",
                      (device_id, conn_id, session_id, str(data.get("ip") or "")[:64], now()))
        elif action == "close":
            if open_row:
                c.execute("UPDATE conn_logs SET ended_at = ? WHERE id = ?", (now(), open_row["id"]))
        else:
            peer = data.get("peer") if isinstance(data.get("peer"), list) else []
            peer_id = str(peer[0])[:64] if len(peer) > 0 else ""
            peer_name = str(peer[1])[:256] if len(peer) > 1 else ""
            values = (peer_id, peer_name, _int(data.get("type")), _int(data.get("primary_auth")),
                      _int(data.get("two_factor")), now())
            if open_row:
                c.execute("UPDATE conn_logs SET peer_id=?, peer_name=?, type=?, primary_auth=?, "
                          "two_factor=?, authorized_at=?, session_id = COALESCE(NULLIF(?, ''), session_id) "
                          "WHERE id = ?", values + (session_id, open_row["id"]))
            else:
                c.execute("INSERT INTO conn_logs(peer_id, peer_name, type, primary_auth, two_factor, "
                          "authorized_at, device_id, conn_id, session_id, started_at) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?)",
                          values + (device_id, conn_id, session_id, now()))
    return ok_empty()


@router.route("POST", "/api/audit/file")
def audit_file(app, req):
    data = req.json_object()
    device_id, _ = device_id_of(data)
    info = data.get("info")
    info = loads(info, {}) if isinstance(info, str) else (info if isinstance(info, dict) else {})
    with app.db.tx() as c:
        if not _claim_nonce(c, data):
            return ok_empty()
        c.execute(
            "INSERT INTO file_logs(device_id, peer_id, conn_id, type, path, is_file, info, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (device_id, str(data.get("peer_id") or "")[:64], _int(data.get("conn_id")),
             _int(data.get("type")) or 0, str(data.get("path") or "")[:4096],
             1 if data.get("is_file") else 0, json.dumps(info)[:16384], now()),
        )
    return ok_empty()


@router.route("POST", "/api/audit/alarm")
def audit_alarm(app, req):
    data = req.json_object()
    device_id, _ = device_id_of(data)
    info = data.get("info")
    info = loads(info, {}) if isinstance(info, str) else (info if isinstance(info, dict) else {})
    typ = _int(data.get("typ"))
    with app.db.tx() as c:
        if not _claim_nonce(c, data):
            return ok_empty()
        c.execute(
            "INSERT INTO alarm_logs(device_id, typ, info, conn_id, ip, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, typ if typ is not None else -1, json.dumps(info)[:16384],
             _int(data.get("conn_id")), str(info.get("ip") or "")[:64], now()),
        )
    return ok_empty()


# -- accessible users, devices and groups (the client's "Accessible devices" tab)

@router.route("GET", "/api/users")
def users(app, req):
    user = client_user(app, req)
    current, size = page_args(req)
    scope = models.access_scope(app.db, user)
    where, params = "1", ()
    if scope is not None:
        ids = scope[0]
        where = f"id IN ({','.join('?' * len(ids))})"
        params = tuple(ids)
    if req.query.get("status") == "1":
        where += " AND status = 1"
    total = app.db.one(f"SELECT COUNT(*) AS n FROM users WHERE {where}", params)["n"]
    rows = app.db.all(f"SELECT * FROM users WHERE {where} ORDER BY name COLLATE NOCASE "
                      "LIMIT ? OFFSET ?", params + (size, (current - 1) * size))
    return json_response({"total": total, "data": [models.user_payload(r) for r in rows]})


@router.route("GET", "/api/peers")
def peers(app, req):
    user = client_user(app, req)
    current, size = page_args(req)
    cond, params = models.scope_sql(models.access_scope(app.db, user))
    total = app.db.one(f"SELECT COUNT(*) AS n FROM devices d WHERE {cond}", params)["n"]
    rows = app.db.all(
        f"SELECT d.*, u.name AS owner, g.name AS group_name FROM devices d "
        f"LEFT JOIN users u ON u.id = d.user_id LEFT JOIN device_groups g ON g.id = d.device_group_id "
        f"WHERE {cond} ORDER BY d.id LIMIT ? OFFSET ?", params + (size, (current - 1) * size))
    data = [{
        "id": r["id"],
        "info": {"device_name": r["hostname"], "os": r["os"], "username": r["username"]},
        "status": 1,
        "user": r["owner"] or "",
        "user_name": r["owner"] or "",
        "device_group_name": r["group_name"] or "",
        "note": r["note"],
    } for r in rows]
    return json_response({"total": total, "data": data})


@router.route("GET", "/api/device-group/accessible")
def device_groups(app, req):
    user = client_user(app, req)
    current, size = page_args(req)
    scope = models.access_scope(app.db, user)
    if scope is None:
        rows = app.db.all("SELECT name FROM device_groups ORDER BY name COLLATE NOCASE")
    else:
        ids = scope[1]
        rows = app.db.all(f"SELECT name FROM device_groups WHERE id IN ({','.join('?' * len(ids))}) "
                          "ORDER BY name COLLATE NOCASE", tuple(ids)) if ids else []
    page = rows[(current - 1) * size:current * size]
    return json_response({"total": len(rows), "data": [{"name": r["name"]} for r in page]})


# -- address books -------------------------------------------------------------

def _book(app, req, guid, need):
    user = client_user(app, req)
    rule = models.book_rule(app.db, user, guid)
    if rule < need:
        raise HTTPError(403, "No permission for this address book")
    personal = app.db.one("SELECT personal FROM address_books WHERE guid = ?", (guid,))["personal"]
    return user, bool(personal)


def action_result(err):
    return error(err) if err else ok_empty()


@router.route("POST", "/api/ab/settings")
def ab_settings(app, req):
    client_user(app, req)
    return json_response({"max_peer_one_ab": app.db.setting("max_peers_per_ab")})


@router.route("POST", "/api/ab/personal")
def ab_personal(app, req):
    user = client_user(app, req)
    return json_response({"guid": models.personal_book(app.db, user["id"])})


@router.route("POST", "/api/ab/shared/profiles")
def ab_shared_profiles(app, req):
    user = client_user(app, req)
    current, size = page_args(req)
    books = models.shared_books_for(app.db, user)
    page = books[(current - 1) * size:current * size]
    data = [{"guid": b["guid"], "name": b["name"], "owner": b["owner"], "note": b["note"],
             "rule": b["rule"]} for b in page]
    return json_response({"total": len(books), "data": data})


@router.route("POST", "/api/ab/peers")
def ab_peers(app, req):
    guid = req.query.get("ab") or ""
    _, personal = _book(app, req, guid, 1)
    current, size = page_args(req)
    total = app.db.one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?", (guid,))["n"]
    rows = app.db.all("SELECT * FROM ab_peers WHERE guid = ? ORDER BY created_at, peer_id "
                      "LIMIT ? OFFSET ?", (guid, size, (current - 1) * size))
    return json_response({"total": total,
                          "data": [models.peer_payload(app.db, r, personal) for r in rows]})


@router.route("POST", "/api/ab/tags/<guid>")
def ab_tags(app, req, guid):
    _book(app, req, guid, 1)
    rows = app.db.all("SELECT name, color FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))
    return json_response([{"name": r["name"], "color": r["color"]} for r in rows])


@router.route("POST", "/api/ab/peer/add/<guid>")
def ab_peer_add(app, req, guid):
    _, personal = _book(app, req, guid, RULE_READ_WRITE)
    peer = req.json_object()
    limit = app.db.setting("max_peers_per_ab")
    with app.db.tx() as c:
        if limit and c.execute("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?",
                               (guid,)).fetchone()["n"] >= limit:
            return error("exceed_max_devices")
        return action_result(models.upsert_peer(c, guid, peer, personal))


@router.route("PUT", "/api/ab/peer/update/<guid>")
def ab_peer_update(app, req, guid):
    _, personal = _book(app, req, guid, RULE_READ_WRITE)
    peer = req.json_object()
    with app.db.tx() as c:
        return action_result(models.upsert_peer(c, guid, peer, personal, update_only=True))


@router.route("DELETE", "/api/ab/peer/<guid>")
def ab_peer_delete(app, req, guid):
    _book(app, req, guid, RULE_READ_WRITE)
    ids = req.json([])
    if not isinstance(ids, list):
        raise HTTPError(400, "Expected a list of IDs")
    with app.db.tx() as c:
        for peer_id in ids:
            c.execute("DELETE FROM ab_peers WHERE guid = ? AND peer_id = ?", (guid, str(peer_id)))
    return ok_empty()


def _tag_body(req):
    data = req.json_object()
    name = data.get("name")
    if not isinstance(name, str) or not name or len(name) > 64:
        raise HTTPError(400, "Invalid tag name")
    color = data.get("color")
    return name, color if isinstance(color, int) else 0


@router.route("POST", "/api/ab/tag/add/<guid>")
def ab_tag_add(app, req, guid):
    _book(app, req, guid, RULE_READ_WRITE)
    name, color = _tag_body(req)
    app.db.run("INSERT INTO ab_tags(guid, name, color) VALUES (?, ?, ?) "
               "ON CONFLICT(guid, name) DO UPDATE SET color = excluded.color", (guid, name, color))
    return ok_empty()


@router.route("PUT", "/api/ab/tag/rename/<guid>")
def ab_tag_rename(app, req, guid):
    _book(app, req, guid, RULE_READ_WRITE)
    data = req.json_object()
    old, new = data.get("old"), data.get("new")
    if not all(isinstance(v, str) and v and len(v) <= 64 for v in (old, new)):
        raise HTTPError(400, "Invalid tag name")
    with app.db.tx() as c:
        if c.execute("SELECT 1 FROM ab_tags WHERE guid = ? AND name = ?", (guid, new)).fetchone():
            return error(f"Tag {new} already exists")
        models.rename_tag(c, guid, old, new)
    return ok_empty()


@router.route("PUT", "/api/ab/tag/update/<guid>")
def ab_tag_update(app, req, guid):
    _book(app, req, guid, RULE_READ_WRITE)
    name, color = _tag_body(req)
    app.db.run("UPDATE ab_tags SET color = ? WHERE guid = ? AND name = ?", (color, guid, name))
    return ok_empty()


@router.route("DELETE", "/api/ab/tag/<guid>")
def ab_tag_delete(app, req, guid):
    _book(app, req, guid, RULE_READ_WRITE)
    names = req.json([])
    if not isinstance(names, list):
        raise HTTPError(400, "Expected a list of tags")
    with app.db.tx() as c:
        models.delete_tags(c, guid, [str(n) for n in names])
    return ok_empty()


# Legacy single address book (clients older than 1.2.4 / servers without
# /api/ab/personal). Mapped onto the user's personal book.

@router.route("GET", "/api/ab")
def ab_legacy_get(app, req):
    user = client_user(app, req)
    guid = models.personal_book(app.db, user["id"])
    tags = app.db.all("SELECT name, color FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))
    peers_ = [models.peer_payload(app.db, r, True)
              for r in app.db.all("SELECT * FROM ab_peers WHERE guid = ? ORDER BY created_at", (guid,))]
    for p in peers_:
        p.pop("same_server", None)
        p.pop("device_group_name", None)
    data = {
        "tags": [t["name"] for t in tags],
        "peers": peers_,
        "tag_colors": json.dumps({t["name"]: t["color"] for t in tags}),
    }
    return json_response({"data": json.dumps(data), "licensed_devices": 0})


@router.route("POST", "/api/ab")
def ab_legacy_post(app, req):
    user = client_user(app, req)
    guid = models.personal_book(app.db, user["id"])
    body = req.json_object()
    data = loads(body.get("data"), None) if isinstance(body.get("data"), str) else None
    if not isinstance(data, dict):
        raise HTTPError(400, "Invalid address book data")
    colors = loads(data.get("tag_colors"), {}) if isinstance(data.get("tag_colors"), str) else {}
    with app.db.tx() as c:
        c.execute("DELETE FROM ab_tags WHERE guid = ?", (guid,))
        for name in models.clean_tags(data.get("tags")):
            color = colors.get(name)
            c.execute("INSERT INTO ab_tags(guid, name, color) VALUES (?, ?, ?)",
                      (guid, name, color if isinstance(color, int) else 0))
        c.execute("DELETE FROM ab_peers WHERE guid = ?", (guid,))
        for peer in data.get("peers") or []:
            if isinstance(peer, dict):
                models.upsert_peer(c, guid, peer, personal=True)
    return ok_empty()


# -- session recordings ----------------------------------------------------------

@router.route("POST", "/api/record")
def record(app, req):
    settings = app.db.settings()
    if not settings["accept_recordings"]:
        raise HTTPError(403, "Recording upload is disabled on this server")
    kind = req.query.get("type")
    name = req.query.get("file") or ""
    if not RECORDING_NAME.match(name):
        raise HTTPError(400, "Invalid file name")
    path = os.path.join(app.cfg.recordings_dir, name)
    db = app.db
    if kind == "new":
        used = db.one("SELECT COALESCE(SUM(size), 0) AS n FROM recordings")["n"]
        if used > settings["recordings_max_mb"] * 1024 * 1024:
            raise HTTPError(507, "Recording storage is full")
        os.makedirs(app.cfg.recordings_dir, exist_ok=True)
        open(path, "wb").close()
        db.run("INSERT INTO recordings(filename, size, ip, created_at) VALUES (?, 0, ?, ?) "
               "ON CONFLICT(filename) DO UPDATE SET size = 0, completed_at = NULL, "
               "created_at = excluded.created_at", (name, req.ip, now()))
        return json_response({})
    row = db.one("SELECT * FROM recordings WHERE filename = ?", (name,))
    if row is None or not os.path.exists(path):
        raise HTTPError(404, "Unknown recording")
    if kind == "remove":
        os.remove(path)
        db.run("DELETE FROM recordings WHERE id = ?", (row["id"],))
        return json_response({})
    if kind not in ("part", "tail"):
        raise HTTPError(400, "Invalid upload type")
    try:
        offset = int(req.query.get("offset") or 0)
    except ValueError:
        raise HTTPError(400, "Invalid offset")
    if offset < 0 or offset > row["size"]:
        raise HTTPError(400, "Offset out of range")
    if kind == "part":
        used = db.one("SELECT COALESCE(SUM(size), 0) AS n FROM recordings")["n"]
        if used + len(req.body) > settings["recordings_max_mb"] * 1024 * 1024:
            raise HTTPError(507, "Recording storage is full")
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(req.body)
    size = os.path.getsize(path)
    db.run("UPDATE recordings SET size = ?, completed_at = ? WHERE id = ?",
           (size, now() if kind == "tail" else None, row["id"]))
    return json_response({})
