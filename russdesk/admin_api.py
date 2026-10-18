"""JSON API behind the web console (/api/admin/...)."""

import base64
import csv
import io
import json
import os
import re
import uuid

from . import models
from .client_api import login_failures
from .db import DEFAULT_SETTINGS, now
from .models import ONLINE_SECONDS, RULE_FULL, RULE_READ, RULE_READ_WRITE, loads
from .security import (DUMMY_HASH, hash_password, new_token, new_totp_secret,
                       token_hash, totp_uri, verify_password, verify_totp)
from .strategy_options import STRATEGY_OPTIONS
from .web import HTTPError, Response, Router, json_response

router = Router()

COOKIE = "russdesk_session"
CSRF_HEADER = "X-Russdesk"
NAME_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,64}$")


# -- auth helpers ------------------------------------------------------------------

def console_user(app, req):
    token = req.cookie(COOKIE)
    if not token:
        raise HTTPError(401, "Not logged in")
    db = app.db
    row = db.one(
        "SELECT t.token_hash, t.last_seen_at, u.* FROM tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = ? AND t.kind = 'console' AND t.expires_at > ?",
        (token_hash(token), now()),
    )
    if row is None or row["status"] != 1:
        raise HTTPError(401, "Session expired, log in again")
    if req.method not in ("GET", "HEAD") and req.headers.get(CSRF_HEADER) != "1":
        raise HTTPError(403, "Missing CSRF header")
    if now() - row["last_seen_at"] > 60:
        db.run("UPDATE tokens SET last_seen_at = ? WHERE token_hash = ?", (now(), row["token_hash"]))
    req.user = row
    req.token = row["token_hash"]
    return row


def admin_user(app, req):
    user = console_user(app, req)
    if not user["is_admin"]:
        raise HTTPError(403, "Administrator access required")
    return user


def log(app, req, action, target="", detail=""):
    models.console_log(app.db, req, action, target, detail)


def body(req):
    return req.json_object()


def page_args(req, default=50):
    try:
        page = max(1, int(req.query.get("page") or 1))
        size = min(500, max(1, int(req.query.get("size") or default)))
    except ValueError:
        raise HTTPError(400, "Invalid pagination")
    return page, size, (page - 1) * size


def opt_id(value, table, db, label):
    """Validate an optional foreign key from console input."""
    if value in (None, "", 0):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise HTTPError(400, f"Invalid {label}")
    if db.one(f"SELECT 1 FROM {table} WHERE id = ?", (value,)) is None:
        raise HTTPError(400, f"Unknown {label}")
    return value


def text_field(data, key, limit=1024):
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPError(400, f"Invalid {key}")
    return value.strip()[:limit]


def require_name(value, label="name"):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 64:
        raise HTTPError(400, f"Invalid {label}")
    return value.strip()


def unique_error(exc, label):
    if "UNIQUE" in str(exc):
        raise HTTPError(409, f"{label} already exists")
    raise exc


# -- session -----------------------------------------------------------------------

@router.route("POST", "/api/admin/login")
def login(app, req):
    data = body(req)
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    keys = ("ip:" + req.ip, "user:" + username.lower())
    if any(login_failures.blocked(k) for k in keys):
        raise HTTPError(429, "Too many failed attempts, try again in a few minutes")
    user = app.db.one("SELECT * FROM users WHERE name = ?", (username,))
    if user is None:
        verify_password(password, DUMMY_HASH)
    if user is None or not verify_password(password, user["password_hash"]):
        for k in keys:
            login_failures.hit(k)
        raise HTTPError(401, "Wrong username or password")
    if user["status"] != 1:
        raise HTTPError(403, "This account is disabled")
    if user["totp_secret"]:
        code = str(data.get("code") or "")
        if not code:
            return json_response({"need_code": True})
        if not verify_totp(user["totp_secret"], code):
            for k in keys:
                login_failures.hit(k)
            raise HTTPError(401, "Wrong verification code")
    login_failures.reset("user:" + username.lower())
    token = new_token()
    hours = app.db.setting("console_session_hours")
    app.db.run(
        "INSERT INTO tokens(token_hash, user_id, kind, ip, created_at, last_seen_at, expires_at) "
        "VALUES (?, ?, 'console', ?, ?, ?, ?)",
        (token_hash(token), user["id"], req.ip, now(), now(), now() + hours * 3600),
    )
    app.db.run("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
    req.user = user
    log(app, req, "login")
    secure = "; Secure" if req.scheme == "https" else ""
    cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={hours * 3600}{secure}"
    return json_response({"ok": True}, headers=[("Set-Cookie", cookie)])


@router.route("POST", "/api/admin/logout")
def logout(app, req):
    try:
        console_user(app, req)
        app.db.run("DELETE FROM tokens WHERE token_hash = ?", (req.token,))
    except HTTPError:
        pass
    return json_response({"ok": True},
                         headers=[("Set-Cookie", f"{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")])


@router.route("GET", "/api/admin/me")
def me(app, req):
    user = console_user(app, req)
    return json_response({
        "id": user["id"], "name": user["name"], "display_name": user["display_name"],
        "email": user["email"], "is_admin": bool(user["is_admin"]),
        "totp_enabled": bool(user["totp_secret"]),
    })


# -- dashboard ---------------------------------------------------------------------

@router.route("GET", "/api/admin/dashboard")
def dashboard(app, req):
    user = console_user(app, req)
    db = app.db
    cond, params = models.scope_sql(models.access_scope(db, user))
    cutoff = now() - ONLINE_SECONDS
    devices = db.one(f"SELECT COUNT(*) AS total, SUM(last_seen_at >= ?) AS online "
                     f"FROM devices d WHERE {cond}", (cutoff,) + params)
    platforms = {}
    for row in db.all(f"SELECT os FROM devices d WHERE {cond}", params):
        name = models.platform_of(row["os"]) or "Unknown"
        platforms[name] = platforms.get(name, 0) + 1
    day = now() - 86400
    sessions = db.all(
        f"SELECT l.* FROM conn_logs l JOIN devices d ON d.id = l.device_id "
        f"WHERE l.ended_at IS NULL AND d.last_seen_at >= ? AND {cond} ORDER BY l.started_at DESC",
        (cutoff,) + params)
    data = {
        "devices_total": devices["total"] or 0,
        "devices_online": devices["online"] or 0,
        "platforms": platforms,
        "active_sessions": [conn_row(db, r) for r in sessions],
    }
    if user["is_admin"]:
        data["users_total"] = db.one("SELECT COUNT(*) AS n FROM users")["n"]
        data["connections_24h"] = db.one("SELECT COUNT(*) AS n FROM conn_logs WHERE started_at >= ?",
                                         (day,))["n"]
        data["alarms_24h"] = db.one("SELECT COUNT(*) AS n FROM alarm_logs WHERE created_at >= ?",
                                    (day,))["n"]
        start = (now() // 86400 - 13) * 86400
        per_day = {r["d"]: r["n"] for r in db.all(
            "SELECT started_at / 86400 AS d, COUNT(*) AS n FROM conn_logs WHERE started_at >= ? "
            "GROUP BY d", (start,))}
        data["connections_by_day"] = [
            {"day": (start // 86400 + i) * 86400, "count": per_day.get(start // 86400 + i, 0)}
            for i in range(14)]
        data["recent_alarms"] = [alarm_row(db, r) for r in db.all(
            "SELECT * FROM alarm_logs ORDER BY id DESC LIMIT 5")]
    return json_response(data)


# -- devices -----------------------------------------------------------------------

def _names(db, table):
    return {r["id"]: r["name"] for r in db.all(f"SELECT id, name FROM {table}")}


@router.route("GET", "/api/admin/devices")
def devices(app, req):
    user = console_user(app, req)
    db = app.db
    page, size, offset = page_args(req)
    cond, params = models.scope_sql(models.access_scope(db, user))
    where, args = [cond], list(params)
    q = (req.query.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        where.append("(d.id LIKE ? OR d.hostname LIKE ? OR d.username LIKE ? OR d.note LIKE ? "
                     "OR d.ip LIKE ? OR d.os LIKE ? OR u.name LIKE ?)")
        args += [like] * 7
    status = req.query.get("status")
    if status == "online":
        where.append("d.last_seen_at >= ?")
        args.append(now() - ONLINE_SECONDS)
    elif status == "offline":
        where.append("(d.last_seen_at IS NULL OR d.last_seen_at < ?)")
        args.append(now() - ONLINE_SECONDS)
    for key, column in (("group", "d.device_group_id"), ("user", "d.user_id"),
                        ("strategy", "d.strategy_id")):
        value = req.query.get(key)
        if value == "none":
            where.append(f"{column} IS NULL")
        elif value:
            where.append(f"{column} = ?")
            args.append(int(value) if value.isdigit() else -1)
    sql = " AND ".join(where)
    joins = "FROM devices d LEFT JOIN users u ON u.id = d.user_id"
    total = db.one(f"SELECT COUNT(*) AS n {joins} WHERE {sql}", args)["n"]
    rows = db.all(f"SELECT d.* {joins} WHERE {sql} "
                  "ORDER BY (d.last_seen_at >= ?) DESC, d.last_seen_at DESC, d.id LIMIT ? OFFSET ?",
                  args + [now() - ONLINE_SECONDS, size, offset])
    users, groups = _names(db, "users"), _names(db, "device_groups")
    return json_response({"total": total, "items": [
        models.device_payload(db, r, users, groups) for r in rows]})


def _device(app, req, device_id, admin=True):
    user = admin_user(app, req) if admin else console_user(app, req)
    if not admin and not models.can_access_device(app.db, user, device_id):
        raise HTTPError(404, "Device not found")
    row = app.db.one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if row is None:
        raise HTTPError(404, "Device not found")
    return row


@router.route("GET", "/api/admin/devices/<device_id>")
def device_detail(app, req, device_id):
    row = _device(app, req, device_id, admin=False)
    db = app.db
    data = models.device_payload(db, row, full=True)
    strategy = models.effective_strategy(db, row)
    data["effective_strategy"] = strategy["name"] if strategy else None
    data["recent_connections"] = [conn_row(db, r) for r in db.all(
        "SELECT * FROM conn_logs WHERE device_id = ? OR peer_id = ? ORDER BY id DESC LIMIT 20",
        (device_id, device_id))]
    return json_response(data)


@router.route("PATCH", "/api/admin/devices/<device_id>")
def device_update(app, req, device_id):
    _device(app, req, device_id)
    data = body(req)
    db = app.db
    sets, args = [], []
    note = text_field(data, "note")
    if note is not None:
        sets.append("note = ?")
        args.append(note)
    for key, table in (("user_id", "users"), ("device_group_id", "device_groups"),
                       ("strategy_id", "strategies")):
        if key in data:
            sets.append(f"{key} = ?")
            args.append(opt_id(data[key], table, db, key.replace("_id", "")))
    if sets:
        db.run(f"UPDATE devices SET {', '.join(sets)} WHERE id = ?", args + [device_id])
        log(app, req, "device.update", device_id, json.dumps(data))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/devices/<device_id>")
def device_delete(app, req, device_id):
    _device(app, req, device_id)
    app.db.run("DELETE FROM devices WHERE id = ?", (device_id,))
    app.db.run("DELETE FROM pending_disconnects WHERE device_id = ?", (device_id,))
    log(app, req, "device.delete", device_id)
    return json_response({"ok": True})


@router.route("POST", "/api/admin/devices/<device_id>/disconnect")
def device_disconnect(app, req, device_id):
    row = _device(app, req, device_id)
    data = body(req)
    conn_ids = data.get("conn_ids")
    if conn_ids is None:
        conn_ids = loads(row["conns"], [])
    conn_ids = [c for c in conn_ids if isinstance(c, int)]
    with app.db.tx() as c:
        for conn_id in conn_ids:
            c.execute("INSERT OR IGNORE INTO pending_disconnects(device_id, conn_id, created_at) "
                      "VALUES (?, ?, ?)", (device_id, conn_id, now()))
    log(app, req, "device.disconnect", device_id, json.dumps(conn_ids))
    return json_response({"ok": True, "queued": conn_ids})


@router.route("POST", "/api/admin/devices/<device_id>/refresh")
def device_refresh(app, req, device_id):
    _device(app, req, device_id)
    app.db.run("UPDATE devices SET sysinfo_at = NULL WHERE id = ?", (device_id,))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/devices/bulk")
def devices_bulk(app, req):
    admin_user(app, req)
    data = body(req)
    ids = [i for i in data.get("ids") or [] if isinstance(i, str)]
    db = app.db
    action = data.get("action")
    if action == "delete":
        with db.tx() as c:
            for device_id in ids:
                c.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    elif action == "assign":
        sets, args = [], []
        for key, table in (("user_id", "users"), ("device_group_id", "device_groups"),
                           ("strategy_id", "strategies")):
            if key in data:
                sets.append(f"{key} = ?")
                args.append(opt_id(data[key], table, db, key.replace("_id", "")))
        if not sets:
            raise HTTPError(400, "Nothing to assign")
        with db.tx() as c:
            for device_id in ids:
                c.execute(f"UPDATE devices SET {', '.join(sets)} WHERE id = ?", args + [device_id])
    else:
        raise HTTPError(400, "Unknown action")
    log(app, req, f"device.bulk_{action}", ",".join(ids)[:256], json.dumps(data))
    return json_response({"ok": True})


# -- users ------------------------------------------------------------------------

def user_row(db, r, groups=None):
    return {
        "id": r["id"], "name": r["name"], "display_name": r["display_name"], "email": r["email"],
        "note": r["note"], "is_admin": bool(r["is_admin"]), "status": r["status"],
        "group_id": r["group_id"], "group_name": (groups or {}).get(r["group_id"]),
        "strategy_id": r["strategy_id"], "totp_enabled": bool(r["totp_secret"]),
        "created_at": r["created_at"], "last_login_at": r["last_login_at"],
        "devices": db.one("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?", (r["id"],))["n"],
    }


def check_password(password):
    if not isinstance(password, str) or len(password) < 8:
        raise HTTPError(400, "Password must be at least 8 characters")
    if len(password) > 256:
        raise HTTPError(400, "Password is too long")
    return password


@router.route("GET", "/api/admin/users")
def users(app, req):
    admin_user(app, req)
    db = app.db
    groups = _names(db, "user_groups")
    q = (req.query.get("q") or "").strip()
    rows = db.all("SELECT * FROM users WHERE name LIKE ? OR display_name LIKE ? OR email LIKE ? "
                  "ORDER BY name COLLATE NOCASE", (f"%{q}%",) * 3)
    return json_response({"items": [user_row(db, r, groups) for r in rows]})


def _user_fields(db, data, creating):
    fields = {}
    if creating or "name" in data:
        name = data.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name.strip()):
            raise HTTPError(400, "Username may use letters, digits and _ . @ - (up to 64)")
        fields["name"] = name.strip()
    for key in ("display_name", "email", "note"):
        value = text_field(data, key, 256)
        if value is not None:
            fields[key] = value
    if "is_admin" in data:
        fields["is_admin"] = 1 if data["is_admin"] else 0
    if "status" in data:
        fields["status"] = 1 if data["status"] in (1, True, "1") else 0
    if "group_id" in data:
        fields["group_id"] = opt_id(data["group_id"], "user_groups", db, "user group")
    if "strategy_id" in data:
        fields["strategy_id"] = opt_id(data["strategy_id"], "strategies", db, "strategy")
    return fields


def _other_admins(db, user_id):
    return db.one("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND status = 1 AND id != ?",
                  (user_id,))["n"]


@router.route("POST", "/api/admin/users")
def user_create(app, req):
    admin_user(app, req)
    data = body(req)
    db = app.db
    fields = _user_fields(db, data, True)
    fields["password_hash"] = hash_password(check_password(data.get("password")))
    fields["created_at"] = now()
    cols = ", ".join(fields)
    try:
        cur = db.run(f"INSERT INTO users({cols}) VALUES ({','.join('?' * len(fields))})",
                     tuple(fields.values()))
    except Exception as exc:
        unique_error(exc, "User")
    models.personal_book(db, cur.lastrowid)
    log(app, req, "user.create", fields["name"])
    return json_response({"id": cur.lastrowid}, 201)


@router.route("PATCH", "/api/admin/users/<user_id>")
def user_update(app, req, user_id):
    me_ = admin_user(app, req)
    db = app.db
    target = db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if target is None:
        raise HTTPError(404, "User not found")
    data = body(req)
    fields = _user_fields(db, data, False)
    demoting = fields.get("is_admin") == 0 or fields.get("status") == 0
    if demoting and target["is_admin"] and not _other_admins(db, target["id"]):
        raise HTTPError(400, "Keep at least one active administrator")
    if target["id"] == me_["id"] and fields.get("status") == 0:
        raise HTTPError(400, "You cannot disable your own account")
    if fields:
        try:
            db.run(f"UPDATE users SET {', '.join(k + ' = ?' for k in fields)} WHERE id = ?",
                   tuple(fields.values()) + (target["id"],))
        except Exception as exc:
            unique_error(exc, "User")
        if fields.get("status") == 0:
            db.run("DELETE FROM tokens WHERE user_id = ?", (target["id"],))
    if data.get("password"):
        db.run("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(check_password(data["password"])), target["id"]))
        if target["id"] != me_["id"]:
            db.run("DELETE FROM tokens WHERE user_id = ?", (target["id"],))
        fields["password"] = "(changed)"
    log(app, req, "user.update", target["name"], json.dumps(fields))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/users/<user_id>")
def user_delete(app, req, user_id):
    me_ = admin_user(app, req)
    db = app.db
    target = db.one("SELECT * FROM users WHERE id = ?", (user_id,))
    if target is None:
        raise HTTPError(404, "User not found")
    if target["id"] == me_["id"]:
        raise HTTPError(400, "You cannot delete your own account")
    if target["is_admin"] and not _other_admins(db, target["id"]):
        raise HTTPError(400, "Keep at least one active administrator")
    db.run("DELETE FROM users WHERE id = ?", (target["id"],))
    log(app, req, "user.delete", target["name"])
    return json_response({"ok": True})


@router.route("POST", "/api/admin/users/<user_id>/reset-2fa")
def user_reset_2fa(app, req, user_id):
    admin_user(app, req)
    target = app.db.one("SELECT name FROM users WHERE id = ?", (user_id,))
    if target is None:
        raise HTTPError(404, "User not found")
    app.db.run("UPDATE users SET totp_secret = '' WHERE id = ?", (user_id,))
    log(app, req, "user.reset_2fa", target["name"])
    return json_response({"ok": True})


@router.route("GET", "/api/admin/users/<user_id>/sessions")
def user_sessions(app, req, user_id):
    admin_user(app, req)
    rows = app.db.all("SELECT * FROM tokens WHERE user_id = ? AND expires_at > ? "
                      "ORDER BY last_seen_at DESC", (user_id, now()))
    return json_response({"items": [{
        "kind": r["kind"], "device_id": r["device_id"], "device_info": loads(r["device_info"], {}),
        "ip": r["ip"], "created_at": r["created_at"], "last_seen_at": r["last_seen_at"],
    } for r in rows]})


@router.route("POST", "/api/admin/users/<user_id>/logout-all")
def user_logout_all(app, req, user_id):
    admin_user(app, req)
    target = app.db.one("SELECT name FROM users WHERE id = ?", (user_id,))
    if target is None:
        raise HTTPError(404, "User not found")
    app.db.run("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?", (user_id, req.token))
    log(app, req, "user.logout_all", target["name"])
    return json_response({"ok": True})


# -- groups ------------------------------------------------------------------------

@router.route("GET", "/api/admin/groups")
def groups(app, req):
    admin_user(app, req)
    db = app.db
    access = {}
    for r in db.all("SELECT * FROM group_access"):
        entry = access.setdefault(r["user_group_id"], {"user_group": [], "device_group": []})
        entry[r["target_type"]].append(r["target_id"])
    user_groups = [{
        "id": r["id"], "name": r["name"], "note": r["note"],
        "members": db.one("SELECT COUNT(*) AS n FROM users WHERE group_id = ?", (r["id"],))["n"],
        "access_user_groups": access.get(r["id"], {}).get("user_group", []),
        "access_device_groups": access.get(r["id"], {}).get("device_group", []),
    } for r in db.all("SELECT * FROM user_groups ORDER BY name COLLATE NOCASE")]
    device_groups = [{
        "id": r["id"], "name": r["name"], "note": r["note"], "strategy_id": r["strategy_id"],
        "devices": db.one("SELECT COUNT(*) AS n FROM devices WHERE device_group_id = ?", (r["id"],))["n"],
    } for r in db.all("SELECT * FROM device_groups ORDER BY name COLLATE NOCASE")]
    return json_response({"user_groups": user_groups, "device_groups": device_groups})


def _set_access(c, group_id, data):
    for key, kind, table in (("access_user_groups", "user_group", "user_groups"),
                             ("access_device_groups", "device_group", "device_groups")):
        if key not in data:
            continue
        ids = data[key] or []
        if not isinstance(ids, list):
            raise HTTPError(400, f"Invalid {key}")
        c.execute("DELETE FROM group_access WHERE user_group_id = ? AND target_type = ?", (group_id, kind))
        for target in ids:
            if not isinstance(target, int) or not c.execute(
                    f"SELECT 1 FROM {table} WHERE id = ?", (target,)).fetchone():
                raise HTTPError(400, f"Unknown group in {key}")
            if kind == "user_group" and target == group_id:
                continue
            c.execute("INSERT OR IGNORE INTO group_access(user_group_id, target_type, target_id) "
                      "VALUES (?, ?, ?)", (group_id, kind, target))


@router.route("POST", "/api/admin/user-groups")
def user_group_create(app, req):
    admin_user(app, req)
    data = body(req)
    name = require_name(data.get("name"))
    try:
        with app.db.tx() as c:
            cur = c.execute("INSERT INTO user_groups(name, note, created_at) VALUES (?, ?, ?)",
                            (name, text_field(data, "note") or "", now()))
            _set_access(c, cur.lastrowid, data)
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Group")
    log(app, req, "user_group.create", name)
    return json_response({"id": cur.lastrowid}, 201)


@router.route("PATCH", "/api/admin/user-groups/<group_id>")
def user_group_update(app, req, group_id):
    admin_user(app, req)
    data = body(req)
    gid = int(group_id) if group_id.isdigit() else -1
    if app.db.one("SELECT 1 FROM user_groups WHERE id = ?", (gid,)) is None:
        raise HTTPError(404, "Group not found")
    try:
        with app.db.tx() as c:
            if "name" in data:
                c.execute("UPDATE user_groups SET name = ? WHERE id = ?", (require_name(data["name"]), gid))
            if "note" in data:
                c.execute("UPDATE user_groups SET note = ? WHERE id = ?", (text_field(data, "note") or "", gid))
            _set_access(c, gid, data)
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Group")
    log(app, req, "user_group.update", group_id, json.dumps(data))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/user-groups/<group_id>")
def user_group_delete(app, req, group_id):
    admin_user(app, req)
    with app.db.tx() as c:
        c.execute("DELETE FROM group_access WHERE target_type = 'user_group' AND target_id = ?", (group_id,))
        c.execute("DELETE FROM user_groups WHERE id = ?", (group_id,))
    log(app, req, "user_group.delete", group_id)
    return json_response({"ok": True})


@router.route("POST", "/api/admin/device-groups")
def device_group_create(app, req):
    admin_user(app, req)
    data = body(req)
    name = require_name(data.get("name"))
    try:
        cur = app.db.run("INSERT INTO device_groups(name, note, strategy_id, created_at) VALUES (?, ?, ?, ?)",
                         (name, text_field(data, "note") or "",
                          opt_id(data.get("strategy_id"), "strategies", app.db, "strategy"), now()))
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Group")
    log(app, req, "device_group.create", name)
    return json_response({"id": cur.lastrowid}, 201)


@router.route("PATCH", "/api/admin/device-groups/<group_id>")
def device_group_update(app, req, group_id):
    admin_user(app, req)
    data = body(req)
    db = app.db
    if db.one("SELECT 1 FROM device_groups WHERE id = ?", (group_id,)) is None:
        raise HTTPError(404, "Group not found")
    try:
        if "name" in data:
            db.run("UPDATE device_groups SET name = ? WHERE id = ?", (require_name(data["name"]), group_id))
        if "note" in data:
            db.run("UPDATE device_groups SET note = ? WHERE id = ?", (text_field(data, "note") or "", group_id))
        if "strategy_id" in data:
            db.run("UPDATE device_groups SET strategy_id = ? WHERE id = ?",
                   (opt_id(data["strategy_id"], "strategies", db, "strategy"), group_id))
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Group")
    log(app, req, "device_group.update", group_id, json.dumps(data))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/device-groups/<group_id>")
def device_group_delete(app, req, group_id):
    admin_user(app, req)
    with app.db.tx() as c:
        c.execute("DELETE FROM group_access WHERE target_type = 'device_group' AND target_id = ?", (group_id,))
        c.execute("DELETE FROM device_groups WHERE id = ?", (group_id,))
    log(app, req, "device_group.delete", group_id)
    return json_response({"ok": True})


# -- strategies --------------------------------------------------------------------

@router.route("GET", "/api/admin/strategies")
def strategies(app, req):
    admin_user(app, req)
    db = app.db
    default_id = db.setting("default_strategy_id")
    items = [{
        "id": r["id"], "name": r["name"], "note": r["note"], "options": loads(r["options"], {}),
        "modified_at": r["modified_at"], "is_default": r["id"] == default_id,
        "devices": db.one("SELECT COUNT(*) AS n FROM devices WHERE strategy_id = ?", (r["id"],))["n"],
        "users": db.one("SELECT COUNT(*) AS n FROM users WHERE strategy_id = ?", (r["id"],))["n"],
        "device_groups": db.one("SELECT COUNT(*) AS n FROM device_groups WHERE strategy_id = ?",
                                (r["id"],))["n"],
    } for r in db.all("SELECT * FROM strategies ORDER BY name COLLATE NOCASE")]
    return json_response({"items": items, "catalog": STRATEGY_OPTIONS})


def _options(data):
    options = data.get("options", {})
    if not isinstance(options, dict):
        raise HTTPError(400, "Invalid options")
    clean = {}
    for key, value in options.items():
        if not isinstance(key, str) or not re.match(r"^[A-Za-z0-9_\-]{1,64}$", key):
            raise HTTPError(400, f"Invalid option key: {key}")
        if not isinstance(value, (str, int, bool)):
            raise HTTPError(400, f"Invalid value for {key}")
        if isinstance(value, bool):
            value = "Y" if value else "N"
        clean[key] = str(value)[:1024]
    return clean


@router.route("POST", "/api/admin/strategies")
def strategy_create(app, req):
    admin_user(app, req)
    data = body(req)
    name = require_name(data.get("name"))
    try:
        cur = app.db.run("INSERT INTO strategies(name, note, options, modified_at) VALUES (?, ?, ?, ?)",
                         (name, text_field(data, "note") or "", json.dumps(_options(data)), now()))
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Strategy")
    log(app, req, "strategy.create", name)
    return json_response({"id": cur.lastrowid}, 201)


@router.route("PATCH", "/api/admin/strategies/<sid>")
def strategy_update(app, req, sid):
    admin_user(app, req)
    data = body(req)
    db = app.db
    row = db.one("SELECT * FROM strategies WHERE id = ?", (sid,))
    if row is None:
        raise HTTPError(404, "Strategy not found")
    name = require_name(data["name"]) if "name" in data else row["name"]
    note = text_field(data, "note") if "note" in data else row["note"]
    options = json.dumps(_options(data)) if "options" in data else row["options"]
    # modified_at changes the stamp devices compare, so bump it only when
    # the options change and keep it strictly increasing.
    modified = max(now(), row["modified_at"] + 1) if options != row["options"] else row["modified_at"]
    try:
        db.run("UPDATE strategies SET name = ?, note = ?, options = ?, modified_at = ? WHERE id = ?",
               (name, note or "", options, modified, row["id"]))
    except Exception as exc:
        unique_error(exc, "Strategy")
    log(app, req, "strategy.update", name, options)
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/strategies/<sid>")
def strategy_delete(app, req, sid):
    admin_user(app, req)
    db = app.db
    row = db.one("SELECT name FROM strategies WHERE id = ?", (sid,))
    if row is None:
        raise HTTPError(404, "Strategy not found")
    db.run("DELETE FROM strategies WHERE id = ?", (sid,))
    if db.setting("default_strategy_id") == int(sid):
        db.set_settings({"default_strategy_id": None})
    log(app, req, "strategy.delete", row["name"])
    return json_response({"ok": True})


# -- address books -----------------------------------------------------------------

def _book_for(app, req, guid, need):
    user = console_user(app, req)
    rule = models.book_rule(app.db, user, guid, as_admin=True)
    if rule == 0:
        raise HTTPError(404, "Address book not found")
    if rule < need:
        raise HTTPError(403, "You do not have permission to change this address book")
    return user, rule, app.db.one("SELECT * FROM address_books WHERE guid = ?", (guid,))


@router.route("GET", "/api/admin/address-books")
def books(app, req):
    user = console_user(app, req)
    db = app.db
    models.personal_book(db, user["id"])
    rows = db.all("SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id "
                  "ORDER BY b.personal DESC, b.name COLLATE NOCASE")
    items = []
    for r in rows:
        rule = models.book_rule(db, user, r["guid"], as_admin=True)
        if not rule:
            continue
        items.append({
            "guid": r["guid"], "name": r["name"], "note": r["note"], "owner": r["owner"],
            "owner_id": r["owner_id"], "personal": bool(r["personal"]), "rule": rule,
            "mine": r["owner_id"] == user["id"],
            "peers": db.one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?", (r["guid"],))["n"],
        })
    if not user["is_admin"]:
        items = [i for i in items if not i["personal"] or i["mine"]]
    return json_response({"items": items})


@router.route("POST", "/api/admin/address-books")
def book_create(app, req):
    user = console_user(app, req)
    data = body(req)
    owner = user["id"]
    if user["is_admin"] and data.get("owner_id"):
        owner = opt_id(data["owner_id"], "users", app.db, "owner")
    guid = str(uuid.uuid4())
    app.db.run("INSERT INTO address_books(guid, name, owner_id, personal, note, created_at) "
               "VALUES (?, ?, ?, 0, ?, ?)",
               (guid, require_name(data.get("name")), owner, text_field(data, "note") or "", now()))
    log(app, req, "address_book.create", data.get("name"))
    return json_response({"guid": guid}, 201)


@router.route("GET", "/api/admin/address-books/<guid>")
def book_detail(app, req, guid):
    _, rule, book = _book_for(app, req, guid, RULE_READ)
    db = app.db
    peers = [models.peer_payload(db, r, bool(book["personal"])) for r in db.all(
        "SELECT * FROM ab_peers WHERE guid = ? ORDER BY created_at, peer_id", (guid,))]
    cutoff = now() - ONLINE_SECONDS
    for p in peers:
        seen = db.one("SELECT last_seen_at FROM devices WHERE id = ?", (p["id"],))
        p["online"] = bool(seen and seen["last_seen_at"] and seen["last_seen_at"] >= cutoff)
        if rule < RULE_FULL:
            p.pop("password", None)
        p.pop("hash", None)  # the personal hash only matters to the client
    tags = [{"name": r["name"], "color": r["color"]}
            for r in db.all("SELECT * FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))]
    rules = [{
        "user_id": r["user_id"], "user_group_id": r["user_group_id"], "rule": r["rule"],
        "name": r["uname"] or r["gname"],
    } for r in db.all(
        "SELECT r.*, u.name AS uname, g.name AS gname FROM ab_rules r "
        "LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.user_group_id "
        "WHERE r.guid = ?", (guid,))]
    owner = db.one("SELECT name FROM users WHERE id = ?", (book["owner_id"],))
    return json_response({
        "guid": guid, "name": book["name"], "note": book["note"], "personal": bool(book["personal"]),
        "owner": owner["name"] if owner else "", "owner_id": book["owner_id"], "rule": rule,
        "peers": peers, "tags": tags, "rules": rules,
    })


@router.route("PATCH", "/api/admin/address-books/<guid>")
def book_update(app, req, guid):
    user, _, book = _book_for(app, req, guid, RULE_FULL)
    data = body(req)
    db = app.db
    if "name" in data and not book["personal"]:
        db.run("UPDATE address_books SET name = ? WHERE guid = ?", (require_name(data["name"]), guid))
    if "note" in data:
        db.run("UPDATE address_books SET note = ? WHERE guid = ?", (text_field(data, "note") or "", guid))
    if "owner_id" in data and user["is_admin"] and not book["personal"]:
        db.run("UPDATE address_books SET owner_id = ? WHERE guid = ?",
               (opt_id(data["owner_id"], "users", db, "owner") or book["owner_id"], guid))
    if "rules" in data and not book["personal"]:
        rules = data["rules"]
        if not isinstance(rules, list):
            raise HTTPError(400, "Invalid rules")
        with db.tx() as c:
            c.execute("DELETE FROM ab_rules WHERE guid = ?", (guid,))
            for r in rules:
                if not isinstance(r, dict) or r.get("rule") not in (1, 2, 3):
                    raise HTTPError(400, "Invalid rule")
                uid = r.get("user_id")
                gid = r.get("user_group_id")
                if bool(uid) == bool(gid):
                    raise HTTPError(400, "A rule targets either a user or a group")
                if uid and not c.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
                    raise HTTPError(400, "Unknown user in rules")
                if gid and not c.execute("SELECT 1 FROM user_groups WHERE id = ?", (gid,)).fetchone():
                    raise HTTPError(400, "Unknown group in rules")
                c.execute("INSERT OR REPLACE INTO ab_rules(guid, user_id, user_group_id, rule) "
                          "VALUES (?, ?, ?, ?)", (guid, uid or None, gid or None, r["rule"]))
    log(app, req, "address_book.update", book["name"], json.dumps(data))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/address-books/<guid>")
def book_delete(app, req, guid):
    _, _, book = _book_for(app, req, guid, RULE_FULL)
    if book["personal"]:
        raise HTTPError(400, "A personal address book cannot be deleted")
    app.db.run("DELETE FROM address_books WHERE guid = ?", (guid,))
    log(app, req, "address_book.delete", book["name"])
    return json_response({"ok": True})


@router.route("POST", "/api/admin/address-books/<guid>/peers")
def book_peer_add(app, req, guid):
    _, _, book = _book_for(app, req, guid, RULE_READ_WRITE)
    data = body(req)
    with app.db.tx() as c:
        if c.execute("SELECT 1 FROM ab_peers WHERE guid = ? AND peer_id = ?",
                     (guid, str(data.get("id") or "").strip())).fetchone():
            raise HTTPError(409, "This ID is already in the address book")
        limit = app.db.setting("max_peers_per_ab")
        if limit and c.execute("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?",
                               (guid,)).fetchone()["n"] >= limit:
            raise HTTPError(400, "The address book is full")
        err = models.upsert_peer(c, guid, data, bool(book["personal"]))
    if err:
        raise HTTPError(400, err)
    return json_response({"ok": True}, 201)


@router.route("PATCH", "/api/admin/address-books/<guid>/peers/<peer_id>")
def book_peer_update(app, req, guid, peer_id):
    _, _, book = _book_for(app, req, guid, RULE_READ_WRITE)
    data = body(req)
    data["id"] = peer_id
    with app.db.tx() as c:
        err = models.upsert_peer(c, guid, data, bool(book["personal"]), update_only=True)
    if err:
        raise HTTPError(400, err)
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/address-books/<guid>/peers/<peer_id>")
def book_peer_delete(app, req, guid, peer_id):
    _book_for(app, req, guid, RULE_READ_WRITE)
    app.db.run("DELETE FROM ab_peers WHERE guid = ? AND peer_id = ?", (guid, peer_id))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/address-books/<guid>/tags")
def book_tag_add(app, req, guid):
    _book_for(app, req, guid, RULE_READ_WRITE)
    data = body(req)
    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 64:
        raise HTTPError(400, "Invalid tag name")
    color = data.get("color") if isinstance(data.get("color"), int) else 0xFF2196F3
    app.db.run("INSERT INTO ab_tags(guid, name, color) VALUES (?, ?, ?) "
               "ON CONFLICT(guid, name) DO UPDATE SET color = excluded.color", (guid, name.strip(), color))
    return json_response({"ok": True}, 201)


@router.route("PATCH", "/api/admin/address-books/<guid>/tags/<name>")
def book_tag_update(app, req, guid, name):
    _book_for(app, req, guid, RULE_READ_WRITE)
    from urllib.parse import unquote
    name = unquote(name)
    data = body(req)
    with app.db.tx() as c:
        if isinstance(data.get("color"), int):
            c.execute("UPDATE ab_tags SET color = ? WHERE guid = ? AND name = ?", (data["color"], guid, name))
        new = data.get("name")
        if isinstance(new, str) and new.strip() and new.strip() != name:
            if c.execute("SELECT 1 FROM ab_tags WHERE guid = ? AND name = ?", (guid, new.strip())).fetchone():
                raise HTTPError(409, "Tag already exists")
            models.rename_tag(c, guid, name, new.strip()[:64])
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/address-books/<guid>/tags/<name>")
def book_tag_delete(app, req, guid, name):
    _book_for(app, req, guid, RULE_READ_WRITE)
    from urllib.parse import unquote
    with app.db.tx() as c:
        models.delete_tags(c, guid, [unquote(name)])
    return json_response({"ok": True})


# -- logs --------------------------------------------------------------------------

def _hostname(db, device_id):
    row = db.one("SELECT hostname FROM devices WHERE id = ?", (device_id,))
    return row["hostname"] if row else ""


def conn_row(db, r):
    end = r["ended_at"]
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "conn_id": r["conn_id"], "peer_id": r["peer_id"], "peer_name": r["peer_name"], "ip": r["ip"],
        "type": models.CONN_TYPES.get(r["type"], "" if r["type"] is None else str(r["type"])),
        "auth": models.PRIMARY_AUTH.get(r["primary_auth"], ""),
        "two_factor": models.TWO_FACTOR.get(r["two_factor"], ""),
        "started_at": r["started_at"], "authorized_at": r["authorized_at"], "ended_at": end,
        "duration": (end or now()) - r["started_at"],
    }


def file_row(db, r):
    info = loads(r["info"], {})
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "peer_id": r["peer_id"], "peer_name": info.get("name", ""), "ip": info.get("ip", ""),
        "direction": models.FILE_TYPES.get(r["type"], str(r["type"])), "path": r["path"],
        "is_file": bool(r["is_file"]), "count": info.get("num", 0),
        "files": info.get("files", []), "created_at": r["created_at"],
    }


def alarm_row(db, r):
    info = loads(r["info"], {})
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "type": models.ALARM_TYPES.get(r["typ"], f"Alarm {r['typ']}"), "ip": r["ip"] or info.get("ip", ""),
        "peer_id": info.get("id", ""), "peer_name": info.get("name", ""),
        "detail": info, "created_at": r["created_at"],
    }


def console_row(db, r):
    return {k: r[k] for k in ("id", "user_name", "action", "target", "detail", "ip", "created_at")}


LOGS = {
    "connections": ("conn_logs", "started_at", conn_row,
                    ["device_id", "peer_id", "peer_name", "ip"]),
    "files": ("file_logs", "created_at", file_row, ["device_id", "peer_id", "path", "info"]),
    "alarms": ("alarm_logs", "created_at", alarm_row, ["device_id", "ip", "info"]),
    "console": ("console_logs", "created_at", console_row, ["user_name", "action", "target", "ip"]),
}

CSV_COLUMNS = {
    "connections": ["started_at", "ended_at", "duration", "device_id", "device_name", "peer_id",
                    "peer_name", "ip", "type", "auth", "two_factor"],
    "files": ["created_at", "device_id", "device_name", "peer_id", "peer_name", "ip", "direction",
              "path", "count"],
    "alarms": ["created_at", "device_id", "device_name", "type", "ip", "peer_id", "peer_name"],
    "console": ["created_at", "user_name", "action", "target", "detail", "ip"],
}


@router.route("GET", "/api/admin/logs/<kind>")
def logs(app, req, kind):
    admin_user(app, req)
    if kind not in LOGS:
        raise HTTPError(404, "Unknown log")
    table, time_col, render, search_cols = LOGS[kind]
    db = app.db
    where, args = ["1"], []
    q = (req.query.get("q") or "").strip()
    if q:
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in search_cols) + ")")
        args += [f"%{q}%"] * len(search_cols)
    device = (req.query.get("device") or "").strip()
    if device and kind != "console":
        if kind == "connections":
            where.append("(device_id = ? OR peer_id = ?)")
            args += [device, device]
        else:
            where.append("device_id = ?")
            args.append(device)
    for key, op in (("from", ">="), ("to", "<")):
        if (req.query.get(key) or "").isdigit():
            where.append(f"{time_col} {op} ?")
            args.append(int(req.query[key]))
    sql = " AND ".join(where)
    if req.query.get("format") == "csv":
        rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT 100000", args)
        out = io.StringIO()
        writer = csv.writer(out)
        cols = CSV_COLUMNS[kind]
        writer.writerow(cols)
        for r in rows:
            item = render(db, r)
            writer.writerow([_csv_safe(item.get(c)) for c in cols])
        return Response(out.getvalue(), 200, "text/csv; charset=utf-8",
                        headers=[("Content-Disposition", f'attachment; filename="{kind}.csv"')])
    page, size, offset = page_args(req)
    total = db.one(f"SELECT COUNT(*) AS n FROM {table} WHERE {sql}", args)["n"]
    rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                  args + [size, offset])
    return json_response({"total": total, "items": [render(db, r) for r in rows]})


def _csv_safe(value):
    """Stop spreadsheet apps from treating a cell as a formula."""
    if value is None:
        return ""
    text_ = str(value)
    if text_[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text_
    return text_


# -- recordings --------------------------------------------------------------------

@router.route("GET", "/api/admin/recordings")
def recordings(app, req):
    admin_user(app, req)
    rows = app.db.all("SELECT * FROM recordings ORDER BY created_at DESC")
    return json_response({"items": [dict(r) for r in rows]})


@router.route("GET", "/api/admin/recordings/<rid>/download")
def recording_download(app, req, rid):
    admin_user(app, req)
    row = app.db.one("SELECT * FROM recordings WHERE id = ?", (rid,))
    path = os.path.join(app.cfg.recordings_dir, row["filename"]) if row else None
    if row is None or not os.path.exists(path):
        raise HTTPError(404, "Recording not found")
    resp = Response(b"", 200, "video/webm" if path.endswith(".webm") else "application/octet-stream",
                    headers=[("Content-Disposition", f'attachment; filename="{row["filename"]}"')])
    resp.stream = open(path, "rb")
    resp.stream_length = os.path.getsize(path)
    log(app, req, "recording.download", row["filename"])
    return resp


@router.route("DELETE", "/api/admin/recordings/<rid>")
def recording_delete(app, req, rid):
    admin_user(app, req)
    row = app.db.one("SELECT * FROM recordings WHERE id = ?", (rid,))
    if row is None:
        raise HTTPError(404, "Recording not found")
    path = os.path.join(app.cfg.recordings_dir, row["filename"])
    if os.path.exists(path):
        os.remove(path)
    app.db.run("DELETE FROM recordings WHERE id = ?", (rid,))
    log(app, req, "recording.delete", row["filename"])
    return json_response({"ok": True})


# -- settings and client configuration ---------------------------------------------

def hbbs_key(app):
    key = app.db.setting("server_key")
    if key:
        return key
    path = app.cfg.hbbs_key_file
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    return ""


def client_config(app, req):
    s = app.db.settings()
    host_header = (req.headers.get("Host") or "").strip()
    hostname = host_header.rsplit(":", 1)[0] if not host_header.startswith("[") else \
        host_header.split("]")[0] + "]"
    host = s["id_server"] or app.cfg.id_server or hostname
    # Left empty, the client derives http://<ID server>:21114 by itself, which
    # is where this server listens by default.
    relay = s["relay_server"] or app.cfg.relay_server
    config = {"host": host, "relay": relay, "api": s["api_server"], "key": hbbs_key(app)}
    encoded = base64.urlsafe_b64encode(
        json.dumps(config, separators=(",", ":")).encode()).decode()[::-1]
    host_only = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return dict(config, config_string=encoded, api_default=f"http://{host_only}:21114" if host_only else "")


@router.route("GET", "/api/admin/client-config")
def get_client_config(app, req):
    console_user(app, req)
    return json_response(client_config(app, req))


SETTING_TYPES = {
    "id_server": str, "relay_server": str, "api_server": str, "server_key": str,
    "client_token_days": int, "console_session_hours": int, "log_retention_days": int,
    "accept_recordings": bool, "recordings_max_mb": int, "max_peers_per_ab": int,
    "default_strategy_id": "strategy",
}


@router.route("GET", "/api/admin/settings")
def get_settings(app, req):
    admin_user(app, req)
    data = app.db.settings()
    data["hbbs_key_file"] = app.cfg.hbbs_key_file
    data["detected_key"] = hbbs_key(app) if not data["server_key"] else ""
    return json_response(data)


@router.route("PATCH", "/api/admin/settings")
def patch_settings(app, req):
    admin_user(app, req)
    data = body(req)
    values = {}
    for key, value in data.items():
        kind = SETTING_TYPES.get(key)
        if kind is None:
            raise HTTPError(400, f"Unknown setting: {key}")
        if kind is str:
            if not isinstance(value, str):
                raise HTTPError(400, f"Invalid {key}")
            value = value.strip()[:512]
        elif kind is int:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise HTTPError(400, f"Invalid {key}")
            if key == "console_session_hours" and value < 1:
                raise HTTPError(400, f"{key} must be at least 1")
        elif kind is bool:
            value = bool(value)
        else:
            value = opt_id(value, "strategies", app.db, "strategy")
        values[key] = value
    assert set(values) <= set(DEFAULT_SETTINGS)
    app.db.set_settings(values)
    log(app, req, "settings.update", "", json.dumps(values))
    return json_response({"ok": True})


@router.route("GET", "/api/admin/lookup")
def lookup(app, req):
    """Names for select boxes."""
    console_user(app, req)
    db = app.db
    return json_response({
        "users": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM users ORDER BY name COLLATE NOCASE")],
        "user_groups": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM user_groups ORDER BY name COLLATE NOCASE")],
        "device_groups": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM device_groups ORDER BY name COLLATE NOCASE")],
        "strategies": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM strategies ORDER BY name COLLATE NOCASE")],
    })


# -- own account -------------------------------------------------------------------

@router.route("POST", "/api/admin/account/password")
def change_password(app, req):
    user = console_user(app, req)
    data = body(req)
    if not verify_password(str(data.get("current") or ""), user["password_hash"]):
        raise HTTPError(400, "Current password is wrong")
    app.db.run("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(check_password(data.get("new"))), user["id"]))
    app.db.run("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?", (user["id"], req.token))
    log(app, req, "account.password")
    return json_response({"ok": True})


@router.route("POST", "/api/admin/account/2fa/setup")
def totp_setup(app, req):
    user = console_user(app, req)
    secret = new_totp_secret()
    return json_response({"secret": secret, "uri": totp_uri(secret, user["name"])})


@router.route("POST", "/api/admin/account/2fa/enable")
def totp_enable(app, req):
    user = console_user(app, req)
    data = body(req)
    secret = str(data.get("secret") or "")
    if not re.match(r"^[A-Z2-7]{16,64}$", secret):
        raise HTTPError(400, "Invalid secret")
    if not verify_totp(secret, str(data.get("code") or "")):
        raise HTTPError(400, "The code does not match; check the time on your phone and try again")
    app.db.run("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
    log(app, req, "account.2fa_enable")
    return json_response({"ok": True})


@router.route("POST", "/api/admin/account/2fa/disable")
def totp_disable(app, req):
    user = console_user(app, req)
    data = body(req)
    if not verify_password(str(data.get("password") or ""), user["password_hash"]):
        raise HTTPError(400, "Password is wrong")
    app.db.run("UPDATE users SET totp_secret = '' WHERE id = ?", (user["id"],))
    log(app, req, "account.2fa_disable")
    return json_response({"ok": True})

