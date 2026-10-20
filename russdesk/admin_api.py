"""JSON API behind the web console (/api/admin/...).

Every endpoint goes through authz: administrators can do everything, other
users get what their admin roles grant (Pro's Admin Role), plus their own
devices and logs."""

import base64
import csv
import io
import json
import os
import re

from . import auth, mail, models, rest_api
from .auth import LoginError
from .authz import PERMISSIONS, Actor
from .db import DEFAULT_SETTINGS, now
from .models import ONLINE_SECONDS, RULE_FULL, RULE_READ, RULE_READ_WRITE, loads
from .security import (hash_password, new_backup_codes, new_token, new_totp_secret, token_hash,
                       totp_uri, verify_password, verify_totp)
from .strategy_options import STRATEGY_OPTIONS
from .web import HTTPError, Response, Router, json_response

router = Router()

COOKIE = "russdesk_session"
CSRF_HEADER = "X-Russdesk"
TOTP_EXPIRE_DAYS = 180  # Pro marks 2FA "expired" after this long without renewal
# Endpoints a user who must set up 2FA first may still call.
SETUP_ALLOWED = ("/api/admin/me", "/api/admin/logout", "/api/admin/account/2fa/")


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
    if auth.needs_2fa_setup(row) and not req.path.startswith(SETUP_ALLOWED):
        raise HTTPError(403, "Set up two-factor authentication first (Account page)")
    if now() - row["last_seen_at"] > 60:
        db.run("UPDATE tokens SET last_seen_at = ? WHERE token_hash = ?", (now(), row["token_hash"]))
    req.user = row
    req.token = row["token_hash"]
    req.actor = Actor(user=row)
    return req.actor


def admin_only(app, req):
    actor = console_user(app, req)
    if not actor.is_admin:
        raise HTTPError(403, "Administrator access required")
    return actor


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


def as_int(value, label="id"):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPError(400, f"Invalid {label}")


def opt_id(value, table, db, label):
    """Validate an optional foreign key from console input."""
    if value in (None, "", 0):
        return None
    value = as_int(value, label)
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


def names(db, table):
    return {r["id"]: r["name"] for r in db.all(f"SELECT id, name FROM {table}")}


# -- session -----------------------------------------------------------------------

def _start_session(app, req, user):
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


@router.route("POST", "/api/admin/login")
def login(app, req):
    data = body(req)
    try:
        user = auth.check_password(app, req, data.get("username"), data.get("password"))
    except LoginError as exc:
        raise HTTPError(401, str(exc))
    method = auth.second_factor(user)
    if method is None:
        return _start_session(app, req, user)
    secret = auth.start_challenge(app, user, method)
    return json_response({"need_code": method, "secret": secret})


@router.route("POST", "/api/admin/login/verify")
def login_verify(app, req):
    data = body(req)
    try:
        user = auth.finish_challenge(app, req, str(data.get("secret") or ""), str(data.get("code") or ""))
    except LoginError as exc:
        raise HTTPError(401, str(exc))
    return _start_session(app, req, user)


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
    actor = console_user(app, req)
    user = actor.user
    db = app.db
    set_at = user["totp_set_at"] or 0
    return json_response({
        "id": user["id"], "name": user["name"], "display_name": user["display_name"],
        "email": user["email"], "is_admin": bool(user["is_admin"]),
        "perms": actor.capabilities(db),
        "totp_enabled": bool(user["totp_secret"]),
        "totp_expired": bool(user["totp_secret"]) and now() - set_at > TOTP_EXPIRE_DAYS * 86400,
        "backup_codes_left": len(loads(user["totp_backup"], [])),
        "must_setup_2fa": auth.needs_2fa_setup(user),
        "email_verification": bool(user["email_verification"]),
        "smtp_ready": mail.configured(db.settings()),
        "admin_roles": [r["name"] for r in actor.roles(db)],
    })


@router.route("GET", "/api/admin/invite/<token>")
def invite_info(app, req, token):
    row = app.db.one("SELECT name, email FROM users WHERE invite_hash = ? AND status = -1 AND invite_expires > ?",
                     (token_hash(token), now()))
    if row is None:
        raise HTTPError(404, "This invitation is invalid or has expired")
    return json_response({"name": row["name"], "email": row["email"]})


@router.route("POST", "/api/admin/invite/<token>")
def invite_accept(app, req, token):
    data = body(req)
    row = app.db.one("SELECT * FROM users WHERE invite_hash = ? AND status = -1 AND invite_expires > ?",
                     (token_hash(token), now()))
    if row is None:
        raise HTTPError(404, "This invitation is invalid or has expired")
    app.db.run("UPDATE users SET password_hash = ?, status = 1, invite_hash = '', invite_expires = NULL "
               "WHERE id = ?", (hash_password(check_password(data.get("password"))), row["id"]))
    return json_response({"ok": True, "name": row["name"]})


# -- dashboard ---------------------------------------------------------------------

@router.route("GET", "/api/admin/dashboard")
def dashboard(app, req):
    actor = console_user(app, req)
    db = app.db
    cond, params = actor.scope(db, "devices.view").device_sql()
    cutoff = now() - ONLINE_SECONDS
    devices = db.one(f"SELECT COUNT(*) AS total, SUM(last_seen_at >= ?) AS online, SUM(disabled) AS disabled "
                     f"FROM devices d WHERE {cond}", (cutoff,) + params)
    platforms = {}
    for row in db.all(f"SELECT os FROM devices d WHERE {cond}", params):
        name = models.platform_of(row["os"]) or "Unknown"
        platforms[name] = platforms.get(name, 0) + 1
    data = {
        "devices_total": devices["total"] or 0,
        "devices_online": devices["online"] or 0,
        "devices_disabled": devices["disabled"] or 0,
        "platforms": platforms,
        "active_sessions": [],
    }
    if actor.can(db, "audits.view"):
        table, sql, aparams = rest_api.audit_rows(app, actor, "conn", {})
        data["active_sessions"] = [conn_row(db, r) for r in db.all(
            f"SELECT l.* FROM conn_logs l JOIN devices dd ON dd.id = l.device_id WHERE l.ended_at IS NULL "
            f"AND dd.last_seen_at >= ? AND l.id IN (SELECT id FROM {table} WHERE {sql}) "
            "ORDER BY l.started_at DESC", [cutoff] + aparams)]
        day = now() - 86400
        data["connections_24h"] = db.one(f"SELECT COUNT(*) AS n FROM conn_logs WHERE {sql} AND started_at >= ?",
                                         aparams + [day])["n"]
        atable, asql, alparams = rest_api.audit_rows(app, actor, "alarm", {})
        data["alarms_24h"] = db.one(f"SELECT COUNT(*) AS n FROM alarm_logs WHERE {asql} AND created_at >= ?",
                                    alparams + [day])["n"]
        start = (now() // 86400 - 13) * 86400
        per_day = {r["d"]: r["n"] for r in db.all(
            f"SELECT started_at / 86400 AS d, COUNT(*) AS n FROM conn_logs WHERE {sql} AND started_at >= ? "
            "GROUP BY d", aparams + [start])}
        data["connections_by_day"] = [
            {"day": (start // 86400 + i) * 86400, "count": per_day.get(start // 86400 + i, 0)}
            for i in range(14)]
        data["recent_alarms"] = [alarm_row(db, r) for r in db.all(
            f"SELECT * FROM alarm_logs WHERE {asql} ORDER BY id DESC LIMIT 5", alparams)]
    if actor.can(db, "users.view"):
        data["users_total"] = db.one("SELECT COUNT(*) AS n FROM users")["n"]
    return json_response(data)


# -- devices -----------------------------------------------------------------------

@router.route("GET", "/api/admin/devices")
def devices(app, req):
    actor = console_user(app, req)
    db = app.db
    page, size, offset = page_args(req)
    cond, params = actor.scope(db, "devices.view").device_sql()
    where, args = [cond], list(params)
    q = (req.query.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        where.append("(d.id LIKE ? OR d.hostname LIKE ? OR d.name_override LIKE ? OR d.username LIKE ? "
                     "OR d.note LIKE ? OR d.ip LIKE ? OR d.os LIKE ? OR u.name LIKE ?)")
        args += [like] * 8
    status = req.query.get("status")
    cutoff = now() - ONLINE_SECONDS
    if status == "online":
        where.append("d.last_seen_at >= ?")
        args.append(cutoff)
    elif status == "offline":
        where.append("(d.last_seen_at IS NULL OR d.last_seen_at < ?)")
        args.append(cutoff)
    elif status == "disabled":
        where.append("d.disabled = 1")
    elif status == "enabled":
        where.append("d.disabled = 0")
    for key, column in (("group", "d.device_group_id"), ("user", "d.user_id"),
                        ("strategy", "d.strategy_id"), ("user_group", "u.group_id")):
        value = req.query.get(key)
        if value == "none":
            where.append(f"{column} IS NULL")
        elif value:
            where.append(f"{column} = ?")
            args.append(as_int(value, key))
    if (req.query.get("offline_days") or "").isdigit():
        where.append("COALESCE(d.last_seen_at, d.created_at) < ?")
        args.append(now() - int(req.query["offline_days"]) * 86400)
    sql = " AND ".join(where)
    joins = "FROM devices d LEFT JOIN users u ON u.id = d.user_id"
    total = db.one(f"SELECT COUNT(*) AS n {joins} WHERE {sql}", args)["n"]
    rows = db.all(f"SELECT d.* {joins} WHERE {sql} "
                  "ORDER BY (d.last_seen_at >= ?) DESC, d.last_seen_at DESC, d.id LIMIT ? OFFSET ?",
                  args + [cutoff, size, offset])
    cache = {}
    return json_response({"total": total, "items": [models.device_payload(db, r, cache) for r in rows]})


def _device(app, actor, device_id, perm):
    db = app.db
    scope = actor.require(db, perm)
    cond, params = scope.device_sql()
    row = db.one(f"SELECT * FROM devices d WHERE d.id = ? AND {cond}", (device_id,) + params)
    if row is None:
        raise HTTPError(404, "Device not found")
    return row


@router.route("GET", "/api/admin/devices/<device_id>")
def device_detail(app, req, device_id):
    actor = console_user(app, req)
    db = app.db
    row = _device(app, actor, device_id, "devices.view")
    data = models.device_payload(db, row, full=True)
    strategy, source = models.effective_strategy(db, row)
    data["effective_strategy"] = strategy["name"] if strategy else None
    data["effective_strategy_source"] = source
    data["blocked"] = models.is_blocked(db, row)
    data["can"] = {p: actor.can(db, p) for p in PERMISSIONS if p.startswith("devices.")}
    data["can"]["disconnect"] = actor.can(db, "audits.edit")
    if actor.can(db, "audits.view"):
        table, sql, params = rest_api.audit_rows(app, actor, "conn", {})
        data["recent_connections"] = [conn_row(db, r) for r in db.all(
            f"SELECT * FROM conn_logs WHERE {sql} AND (device_id = ? OR peer_id = ?) ORDER BY id DESC LIMIT 20",
            params + [device_id, device_id])]
    else:
        data["recent_connections"] = []
    return json_response(data)


DEVICE_FIELDS = {  # console field -> (column, permission, foreign table)
    "note": ("note", "devices.edit_info", None),
    "name_override": ("name_override", "devices.edit_info", None),
    "username_override": ("username_override", "devices.edit_info", None),
    "user_id": ("user_id", "devices.assign_to_user", "users"),
    "device_group_id": ("device_group_id", "devices.change_group", "device_groups"),
    "strategy_id": ("strategy_id", "devices.change_strategy", "strategies"),
}


def update_device(app, actor, row, data):
    db = app.db
    sets, args = [], []
    for key, (column, perm, table) in DEVICE_FIELDS.items():
        if key not in data:
            continue
        _device(app, actor, row["id"], perm)
        if table:
            args.append(opt_id(data[key], table, db, key.replace("_id", "")))
        else:
            args.append(text_field(data, key) or "")
        sets.append(f"{column} = ?")
    if sets:
        db.run(f"UPDATE devices SET {', '.join(sets)} WHERE id = ?", args + [row["id"]])


@router.route("PATCH", "/api/admin/devices/<device_id>")
def device_update(app, req, device_id):
    actor = console_user(app, req)
    row = _device(app, actor, device_id, "devices.view")
    data = body(req)
    update_device(app, actor, row, data)
    log(app, req, "device.update", device_id, json.dumps(data))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/devices/<device_id>/enable")
def device_enable(app, req, device_id):
    actor = console_user(app, req)
    rest_api.set_device_disabled(app, req, _device(app, actor, device_id, "devices.enable_disable"), False)
    return json_response({"ok": True})


@router.route("POST", "/api/admin/devices/<device_id>/disable")
def device_disable(app, req, device_id):
    actor = console_user(app, req)
    rest_api.set_device_disabled(app, req, _device(app, actor, device_id, "devices.enable_disable"), True)
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/devices/<device_id>")
def device_delete(app, req, device_id):
    actor = console_user(app, req)
    rest_api.delete_device(app, req, _device(app, actor, device_id, "devices.delete"))
    return json_response({"ok": True})


def queue_disconnect(app, req, device_id, conn_ids):
    with app.db.tx() as c:
        for conn_id in conn_ids:
            c.execute("INSERT OR IGNORE INTO pending_disconnects(device_id, conn_id, created_at) "
                      "VALUES (?, ?, ?)", (device_id, conn_id, now()))
    log(app, req, "device.disconnect", device_id, json.dumps(conn_ids))


@router.route("POST", "/api/admin/devices/<device_id>/disconnect")
def device_disconnect(app, req, device_id):
    actor = console_user(app, req)
    actor.require(app.db, "audits.edit")
    row = _device(app, actor, device_id, "devices.view")
    conn_ids = body(req).get("conn_ids")
    if conn_ids is None:
        conn_ids = loads(row["conns"], [])
    conn_ids = [c for c in conn_ids if isinstance(c, int)]
    queue_disconnect(app, req, device_id, conn_ids)
    return json_response({"ok": True, "queued": conn_ids})


@router.route("POST", "/api/admin/devices/<device_id>/refresh")
def device_refresh(app, req, device_id):
    actor = console_user(app, req)
    _device(app, actor, device_id, "devices.edit_info")
    app.db.run("UPDATE devices SET sysinfo_at = NULL WHERE id = ?", (device_id,))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/devices/bulk")
def devices_bulk(app, req):
    actor = console_user(app, req)
    data = body(req)
    ids = [i for i in data.get("ids") or [] if isinstance(i, str)]
    action = data.get("action")
    perm = {"enable": "devices.enable_disable", "disable": "devices.enable_disable",
            "delete": "devices.delete", "assign": "devices.view"}.get(action)
    if perm is None:
        raise HTTPError(400, "Unknown action")
    rows = [_device(app, actor, device_id, perm) for device_id in ids]
    if action == "delete" and any(not r["disabled"] for r in rows):
        raise HTTPError(400, "Disable devices before deleting them")
    for row in rows:
        if action == "enable":
            rest_api.set_device_disabled(app, req, row, False)
        elif action == "disable":
            rest_api.set_device_disabled(app, req, row, True)
        elif action == "delete":
            rest_api.delete_device(app, req, row)
        else:
            update_device(app, actor, row, {k: data[k] for k in ("user_id", "device_group_id", "strategy_id")
                                            if k in data})
    if action == "assign":
        log(app, req, "device.update", ",".join(ids)[:256], json.dumps(data))
    return json_response({"ok": True})


# -- users ------------------------------------------------------------------------

def user_row(db, r, groups, strategies, roles):
    set_at = r["totp_set_at"] or 0
    return {
        "id": r["id"], "guid": r["guid"], "name": r["name"], "display_name": r["display_name"],
        "email": r["email"], "note": r["note"], "is_admin": bool(r["is_admin"]), "status": r["status"],
        "group_id": r["group_id"], "group_name": groups.get(r["group_id"]),
        "strategy_id": r["strategy_id"], "strategy_name": strategies.get(r["strategy_id"]),
        "totp_enabled": bool(r["totp_secret"]),
        "totp_expired": bool(r["totp_secret"]) and now() - set_at > TOTP_EXPIRE_DAYS * 86400,
        "force_2fa": bool(r["force_2fa"]), "email_verification": bool(r["email_verification"]),
        "admin_role_ids": roles.get(r["id"], []),
        "created_at": r["created_at"], "last_login_at": r["last_login_at"],
        "devices": db.one("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?", (r["id"],))["n"],
    }


def check_password(password):
    if not isinstance(password, str) or len(password) < 8:
        raise HTTPError(400, "Password must be at least 8 characters")
    if len(password) > 256:
        raise HTTPError(400, "Password is too long")
    return password


def _user(app, actor, user_id, perm):
    db = app.db
    scope = actor.require(db, perm)
    row = db.one("SELECT * FROM users WHERE id = ?", (as_int(user_id),))
    if row is None:
        raise HTTPError(404, "User not found")
    if not actor.is_admin:
        if row["is_admin"]:
            raise HTTPError(403, "Only administrators can change administrator accounts")
        cond, params = scope.user_sql()
        if not scope.everything and db.one(f"SELECT 1 FROM users u WHERE u.id = ? AND {cond}",
                                           (row["id"],) + params) is None:
            raise HTTPError(403, "This user is outside your role's groups")
    return row


@router.route("GET", "/api/admin/users")
def users(app, req):
    actor = console_user(app, req)
    db = app.db
    scope = actor.require(db, "users.view")
    where, params = ["(u.name LIKE ? OR u.display_name LIKE ? OR u.email LIKE ?)"], \
        [f"%{(req.query.get('q') or '').strip()}%"] * 3
    if not scope.everything:
        cond, sparams = scope.user_sql()
        where.append(cond)
        params += list(sparams)
    for key, column in (("group", "u.group_id"), ("status", "u.status")):
        value = req.query.get(key)
        if value == "none":
            where.append(f"{column} IS NULL")
        elif value not in (None, ""):
            where.append(f"{column} = ?")
            params.append(as_int(value, key))
    rows = db.all(f"SELECT u.* FROM users u WHERE {' AND '.join(where)} ORDER BY u.name COLLATE NOCASE", params)
    roles = {}
    for r in db.all("SELECT * FROM user_admin_roles"):
        roles.setdefault(r["user_id"], []).append(r["role_id"])
    groups, strategies = names(db, "user_groups"), names(db, "strategies")
    return json_response({"items": [user_row(db, r, groups, strategies, roles) for r in rows]})


@router.route("POST", "/api/admin/users")
def user_create(app, req):
    actor = console_user(app, req)
    data = body(req)
    if data.get("group_id") is not None:
        data["group_id"] = opt_id(data.get("group_id"), "user_groups", app.db, "user group")
    uid = rest_api.create_user(app, req, actor, data)
    if data.get("strategy_id") and actor.can(app.db, "users.change_strategy"):
        app.db.run("UPDATE users SET strategy_id = ? WHERE id = ?",
                   (opt_id(data["strategy_id"], "strategies", app.db, "strategy"), uid))
    if actor.is_admin and isinstance(data.get("admin_role_ids"), list):
        _set_roles(app.db, uid, data["admin_role_ids"])
    return json_response({"id": uid}, 201)


@router.route("POST", "/api/admin/users/invite")
def user_invite(app, req):
    actor = console_user(app, req)
    data = body(req)
    if data.get("group_id") is not None:
        data["group_id"] = opt_id(data.get("group_id"), "user_groups", app.db, "user group")
    uid = rest_api.create_user(app, req, actor, data, invite=True)
    return json_response({"id": uid}, 201)


USER_FIELDS = {  # field -> permission
    "display_name": "users.edit_display_name", "email": "users.edit_email", "note": "users.edit_note",
    "group_id": "users.change_group", "strategy_id": "users.change_strategy",
    "force_2fa": "users.manage_2fa", "email_verification": "users.manage_2fa",
}


def _set_roles(db, user_id, role_ids):
    with db.tx() as c:
        c.execute("DELETE FROM user_admin_roles WHERE user_id = ?", (user_id,))
        for rid in role_ids:
            if not c.execute("SELECT 1 FROM admin_roles WHERE id = ?", (as_int(rid),)).fetchone():
                raise HTTPError(400, "Unknown admin role")
            c.execute("INSERT OR IGNORE INTO user_admin_roles(user_id, role_id) VALUES (?, ?)", (user_id, int(rid)))


@router.route("PATCH", "/api/admin/users/<user_id>")
def user_update(app, req, user_id):
    actor = console_user(app, req)
    db = app.db
    target = _user(app, actor, user_id, "users.view")
    data = body(req)
    sets, args, changed = [], [], {}
    for key, perm in USER_FIELDS.items():
        if key not in data:
            continue
        _user(app, actor, user_id, perm)
        if key == "group_id":
            value = opt_id(data[key], "user_groups", db, "user group")
        elif key == "strategy_id":
            value = opt_id(data[key], "strategies", db, "strategy")
        elif key in ("force_2fa", "email_verification"):
            value = 1 if data[key] else 0
            if key == "email_verification" and value and not (data.get("email") or target["email"]):
                raise HTTPError(400, "Email login verification needs an email address")
        else:
            value = text_field(data, key, 256) or ""
        sets.append(f"{key} = ?")
        args.append(value)
        changed[key] = value
    if "is_admin" in data:
        if not actor.is_admin:
            raise HTTPError(403, "Only administrators can grant administrator access")
        if not data["is_admin"] and target["is_admin"] and not rest_api.other_admins(db, target["id"]):
            raise HTTPError(400, "Keep at least one active administrator")
        sets.append("is_admin = ?")
        args.append(1 if data["is_admin"] else 0)
        changed["is_admin"] = bool(data["is_admin"])
    if sets:
        db.run(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", args + [target["id"]])
    if data.get("password"):
        _user(app, actor, user_id, "users.edit_password")
        db.run("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(check_password(data["password"])), target["id"]))
        if target["id"] != actor.user["id"]:
            db.run("DELETE FROM tokens WHERE user_id = ?", (target["id"],))
        changed["password"] = "(changed)"
    if "admin_role_ids" in data:
        if not actor.is_admin:
            raise HTTPError(403, "Only administrators can assign admin roles")
        _set_roles(db, target["id"], data["admin_role_ids"] or [])
        changed["admin_roles"] = data["admin_role_ids"]
    log(app, req, "user.update", target["name"], json.dumps(changed))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/users/<user_id>/enable")
def user_enable(app, req, user_id):
    actor = console_user(app, req)
    rest_api.set_user_status(app, req, _user(app, actor, user_id, "users.enable_disable"), 1)
    return json_response({"ok": True})


@router.route("POST", "/api/admin/users/<user_id>/disable")
def user_disable(app, req, user_id):
    actor = console_user(app, req)
    target = _user(app, actor, user_id, "users.enable_disable")
    if target["id"] == actor.user["id"]:
        raise HTTPError(400, "You cannot disable your own account")
    rest_api.set_user_status(app, req, target, 0)
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/users/<user_id>")
def user_delete(app, req, user_id):
    actor = console_user(app, req)
    target = _user(app, actor, user_id, "users.delete")
    if target["id"] == actor.user["id"]:
        raise HTTPError(400, "You cannot delete your own account")
    rest_api.delete_user(app, req, target)
    return json_response({"ok": True})


@router.route("POST", "/api/admin/users/<user_id>/reset-2fa")
def user_reset_2fa(app, req, user_id):
    actor = console_user(app, req)
    target = _user(app, actor, user_id, "users.manage_2fa")
    app.db.run("UPDATE users SET totp_secret = '', totp_backup = '[]', totp_set_at = NULL WHERE id = ?",
               (target["id"],))
    log(app, req, "user.update", target["name"], "2FA reset")
    return json_response({"ok": True})


@router.route("GET", "/api/admin/users/<user_id>/sessions")
def user_sessions(app, req, user_id):
    actor = console_user(app, req)
    _user(app, actor, user_id, "users.view")
    rows = app.db.all("SELECT * FROM tokens WHERE user_id = ? AND expires_at > ? "
                      "ORDER BY last_seen_at DESC", (as_int(user_id), now()))
    return json_response({"items": [{
        "kind": r["kind"], "device_id": r["device_id"], "device_info": loads(r["device_info"], {}),
        "ip": r["ip"], "created_at": r["created_at"], "last_seen_at": r["last_seen_at"],
    } for r in rows]})


@router.route("POST", "/api/admin/users/<user_id>/logout-all")
def user_logout_all(app, req, user_id):
    actor = console_user(app, req)
    target = _user(app, actor, user_id, "users.force_logout")
    app.db.run("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?", (target["id"], req.token))
    log(app, req, "user.update", target["name"], "forced logout")
    return json_response({"ok": True})


@router.route("POST", "/api/admin/users/<user_id>/assign-devices")
def user_assign_devices(app, req, user_id):
    """Pro: Users > More > Assign Devices."""
    actor = console_user(app, req)
    target = _user(app, actor, user_id, "users.view")
    ids = body(req).get("device_ids")
    if not isinstance(ids, list):
        raise HTTPError(400, "device_ids must be a list")
    for device_id in ids:
        row = _device(app, actor, str(device_id), "devices.assign_to_user")
        app.db.run("UPDATE devices SET user_id = ? WHERE id = ?", (target["id"], row["id"]))
    log(app, req, "device.update", ",".join(map(str, ids))[:256], f"assigned to {target['name']}")
    return json_response({"ok": True})


# -- groups ------------------------------------------------------------------------

@router.route("GET", "/api/admin/groups")
def groups(app, req):
    actor = console_user(app, req)
    db = app.db
    data = {"user_groups": [], "device_groups": []}
    if actor.can(db, "user_groups.view"):
        for r in db.all("SELECT * FROM user_groups ORDER BY name COLLATE NOCASE"):
            incomings, outgoings = rest_api.access_lists(db, "user_group", r["id"])
            data["user_groups"].append({
                "id": r["id"], "guid": r["guid"], "name": r["name"], "note": r["note"],
                "members": db.one("SELECT COUNT(*) AS n FROM users WHERE group_id = ?", (r["id"],))["n"],
                "allowed_incomings": incomings, "allowed_outgoings": outgoings})
    if actor.can(db, "device_groups.view"):
        strategies = names(db, "strategies")
        for r in db.all("SELECT * FROM device_groups ORDER BY name COLLATE NOCASE"):
            incomings, _ = rest_api.access_lists(db, "device_group", r["id"])
            data["device_groups"].append({
                "id": r["id"], "guid": r["guid"], "name": r["name"], "note": r["note"],
                "strategy_id": r["strategy_id"], "strategy_name": strategies.get(r["strategy_id"]),
                "devices": db.one("SELECT COUNT(*) AS n FROM devices WHERE device_group_id = ?", (r["id"],))["n"],
                "allowed_incomings": incomings})
    return json_response(data)


def _group(app, actor, kind, group_id, perm):
    actor.require(app.db, perm)
    row = app.db.one(f"SELECT * FROM {kind}s WHERE id = ?", (as_int(group_id),))
    if row is None:
        raise HTTPError(404, "Group not found")
    return row


def _save_group(app, req, kind, row, data):
    db = app.db
    try:
        with db.tx() as c:
            if row is None:
                cur = c.execute(f"INSERT INTO {kind}s(guid, name, note, created_at) VALUES (?, ?, ?, ?)",
                                (models.new_guid(), require_name(data.get("name")),
                                 text_field(data, "note") or "", now()))
                gid = cur.lastrowid
            else:
                gid = row["id"]
                if "name" in data:
                    c.execute(f"UPDATE {kind}s SET name = ? WHERE id = ?", (require_name(data["name"]), gid))
                if "note" in data:
                    c.execute(f"UPDATE {kind}s SET note = ? WHERE id = ?", (text_field(data, "note") or "", gid))
            rest_api.set_access(c, db, kind, gid, data)
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Group")
    log(app, req, f"{kind}.{'create' if row is None else 'update'}", data.get("name") or row["name"],
        json.dumps(data))
    return gid


@router.route("POST", "/api/admin/user-groups")
def user_group_create(app, req):
    actor = console_user(app, req)
    actor.require(app.db, "user_groups.edit")
    return json_response({"id": _save_group(app, req, "user_group", None, body(req))}, 201)


@router.route("PATCH", "/api/admin/user-groups/<group_id>")
def user_group_update(app, req, group_id):
    actor = console_user(app, req)
    _save_group(app, req, "user_group", _group(app, actor, "user_group", group_id, "user_groups.edit"), body(req))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/user-groups/<group_id>")
def user_group_delete(app, req, group_id):
    actor = console_user(app, req)
    rest_api.delete_group(app, req, "user_group", _group(app, actor, "user_group", group_id, "user_groups.edit"))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/user-groups/<group_id>/members")
def user_group_members(app, req, group_id):
    """{"add": [user ids], "remove": [user ids]}"""
    actor = console_user(app, req)
    group = _group(app, actor, "user_group", group_id, "user_groups.view")
    data = body(req)
    for uid in data.get("add") or []:
        _user(app, actor, uid, "users.change_group")
        app.db.run("UPDATE users SET group_id = ? WHERE id = ?", (group["id"], as_int(uid)))
    for uid in data.get("remove") or []:
        _user(app, actor, uid, "users.change_group")
        app.db.run("UPDATE users SET group_id = NULL WHERE id = ? AND group_id = ?", (as_int(uid), group["id"]))
    log(app, req, "user_group.update", group["name"], json.dumps(data))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/device-groups")
def device_group_create(app, req):
    actor = console_user(app, req)
    db = app.db
    actor.require(db, "device_groups.edit")
    data = body(req)
    gid = _save_group(app, req, "device_group", None, data)
    if data.get("strategy_id"):
        db.run("UPDATE device_groups SET strategy_id = ? WHERE id = ?",
               (opt_id(data["strategy_id"], "strategies", db, "strategy"), gid))
    return json_response({"id": gid}, 201)


@router.route("PATCH", "/api/admin/device-groups/<group_id>")
def device_group_update(app, req, group_id):
    actor = console_user(app, req)
    db = app.db
    data = body(req)
    edit_keys = {"name", "note", "allowed_incomings"} & set(data)
    if edit_keys:
        row = _group(app, actor, "device_group", group_id, "device_groups.edit")
        _save_group(app, req, "device_group", row, {k: data[k] for k in edit_keys})
    if "strategy_id" in data:
        row = _group(app, actor, "device_group", group_id, "device_groups.change_strategy")
        db.run("UPDATE device_groups SET strategy_id = ? WHERE id = ?",
               (opt_id(data["strategy_id"], "strategies", db, "strategy"), row["id"]))
        log(app, req, "device_group.update", row["name"], json.dumps({"strategy_id": data["strategy_id"]}))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/device-groups/<group_id>")
def device_group_delete(app, req, group_id):
    actor = console_user(app, req)
    rest_api.delete_group(app, req, "device_group",
                          _group(app, actor, "device_group", group_id, "device_groups.edit"))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/device-groups/<group_id>/members")
def device_group_members(app, req, group_id):
    """{"add": [device ids], "remove": [device ids]}"""
    actor = console_user(app, req)
    group = _group(app, actor, "device_group", group_id, "device_groups.view")
    data = body(req)
    for device_id in data.get("add") or []:
        row = _device(app, actor, str(device_id), "devices.change_group")
        app.db.run("UPDATE devices SET device_group_id = ? WHERE id = ?", (group["id"], row["id"]))
    for device_id in data.get("remove") or []:
        row = _device(app, actor, str(device_id), "devices.change_group")
        app.db.run("UPDATE devices SET device_group_id = NULL WHERE id = ? AND device_group_id = ?",
                   (row["id"], group["id"]))
    log(app, req, "device_group.update", group["name"], json.dumps(data))
    return json_response({"ok": True})


# -- strategies --------------------------------------------------------------------

@router.route("GET", "/api/admin/strategies")
def strategies(app, req):
    actor = console_user(app, req)
    db = app.db
    actor.require(db, "strategies.view")
    default_id = db.setting("default_strategy_id")
    applied = {}
    for d in db.all("SELECT * FROM devices"):
        strategy, _ = models.effective_strategy(db, d)
        if strategy:
            applied[strategy["id"]] = applied.get(strategy["id"], 0) + 1
    items = [{
        "id": r["id"], "guid": r["guid"], "name": r["name"], "note": r["note"],
        "options": loads(r["options"], {}), "enabled": bool(r["enabled"]),
        "modified_at": r["modified_at"], "is_default": r["id"] == default_id,
        "applied": applied.get(r["id"], 0),
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


def _strategy(app, actor, sid, perm="strategies.edit"):
    actor.require(app.db, perm)
    row = app.db.one("SELECT * FROM strategies WHERE id = ?", (as_int(sid),))
    if row is None:
        raise HTTPError(404, "Strategy not found")
    return row


@router.route("POST", "/api/admin/strategies")
def strategy_create(app, req):
    actor = console_user(app, req)
    actor.require(app.db, "strategies.edit")
    data = body(req)
    name = require_name(data.get("name"))
    try:
        cur = app.db.run("INSERT INTO strategies(guid, name, note, options, modified_at) VALUES (?, ?, ?, ?, ?)",
                         (models.new_guid(), name, text_field(data, "note") or "",
                          json.dumps(_options(data)), now()))
    except HTTPError:
        raise
    except Exception as exc:
        unique_error(exc, "Strategy")
    log(app, req, "strategy.create", name)
    return json_response({"id": cur.lastrowid}, 201)


@router.route("PATCH", "/api/admin/strategies/<sid>")
def strategy_update(app, req, sid):
    actor = console_user(app, req)
    row = _strategy(app, actor, sid)
    data = body(req)
    db = app.db
    name = require_name(data["name"]) if "name" in data else row["name"]
    note = text_field(data, "note") if "note" in data else row["note"]
    options = json.dumps(_options(data)) if "options" in data else row["options"]
    enabled = (1 if data["enabled"] else 0) if "enabled" in data else row["enabled"]
    # modified_at changes the stamp devices compare, so bump it only when
    # the options change and keep it strictly increasing.
    modified = max(now(), row["modified_at"] + 1) if options != row["options"] else row["modified_at"]
    try:
        db.run("UPDATE strategies SET name = ?, note = ?, options = ?, modified_at = ?, enabled = ? WHERE id = ?",
               (name, note or "", options, modified, enabled, row["id"]))
    except Exception as exc:
        unique_error(exc, "Strategy")
    log(app, req, "strategy.update", name, json.dumps({k: data[k] for k in data if k != "options"}) +
        (" options changed" if options != row["options"] else ""))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/strategies/<sid>/duplicate")
def strategy_duplicate(app, req, sid):
    actor = console_user(app, req)
    row = _strategy(app, actor, sid)
    db = app.db
    base = f"{row['name']} (copy)"
    name, n = base, 2
    while db.one("SELECT 1 FROM strategies WHERE name = ?", (name,)):
        name, n = f"{base} {n}", n + 1
    cur = db.run("INSERT INTO strategies(guid, name, note, options, modified_at, enabled) VALUES (?, ?, ?, ?, ?, ?)",
                 (models.new_guid(), name[:64], row["note"], row["options"], now(), row["enabled"]))
    log(app, req, "strategy.create", name, f"duplicate of {row['name']}")
    return json_response({"id": cur.lastrowid}, 201)


@router.route("DELETE", "/api/admin/strategies/<sid>")
def strategy_delete(app, req, sid):
    actor = console_user(app, req)
    row = _strategy(app, actor, sid)
    db = app.db
    db.run("DELETE FROM strategies WHERE id = ?", (row["id"],))
    if db.setting("default_strategy_id") == row["id"]:
        db.set_settings({"default_strategy_id": None})
    log(app, req, "strategy.delete", row["name"])
    return json_response({"ok": True})


TARGETS = {"devices": ("devices", "devices.change_strategy", "devices.view"),
           "users": ("users", "users.change_strategy", "users.view"),
           "device_groups": ("device_groups", "device_groups.change_strategy", "device_groups.view")}


@router.route("GET", "/api/admin/strategies/<sid>/targets")
def strategy_targets(app, req, sid):
    """Pro's Edit Devices / Edit Users / Edit Device Groups dialog."""
    actor = console_user(app, req)
    row = _strategy(app, actor, sid, "strategies.view")
    kind = req.query.get("kind")
    if kind not in TARGETS:
        raise HTTPError(400, "kind must be devices, users or device_groups")
    table, _, view = TARGETS[kind]
    db = app.db
    scope = actor.require(db, view)
    strategies_ = names(db, "strategies")
    items = []
    if kind == "devices":
        cond, params = scope.device_sql()
        for d in db.all(f"SELECT d.* FROM devices d WHERE {cond} ORDER BY d.id", params):
            user_s = db.one("SELECT strategy_id FROM users WHERE id = ?", (d["user_id"],)) if d["user_id"] else None
            group_s = db.one("SELECT strategy_id FROM device_groups WHERE id = ?", (d["device_group_id"],)) \
                if d["device_group_id"] else None
            items.append({"id": d["id"], "name": d["name_override"] or d["hostname"],
                          "selected": d["strategy_id"] == row["id"],
                          # Pro: "device strategy/user strategy/device group strategy"
                          "strategies": [strategies_.get(d["strategy_id"]) or "-",
                                         (strategies_.get(user_s["strategy_id"]) if user_s else None) or "-",
                                         (strategies_.get(group_s["strategy_id"]) if group_s else None) or "-"]})
    else:
        if kind == "users" and not scope.everything:
            cond, params = scope.user_sql()
            rows = db.all(f"SELECT u.* FROM users u WHERE {cond} ORDER BY u.name COLLATE NOCASE", params)
        else:
            rows = db.all(f"SELECT * FROM {table} ORDER BY name COLLATE NOCASE")
        for r in rows:
            items.append({"id": r["id"], "name": r["name"], "selected": r["strategy_id"] == row["id"],
                          "strategies": [strategies_.get(r["strategy_id"]) or "-"]})
    return json_response({"items": items})


@router.route("POST", "/api/admin/strategies/<sid>/targets")
def strategy_set_targets(app, req, sid):
    """{"kind", "add": [...], "remove": [...]}: devices by RustDesk ID, users
    and device groups by numeric id."""
    actor = console_user(app, req)
    row = _strategy(app, actor, sid, "strategies.view")
    data = body(req)
    kind = data.get("kind")
    if kind not in TARGETS:
        raise HTTPError(400, "kind must be devices, users or device_groups")
    table, perm, _ = TARGETS[kind]
    db = app.db
    actor.require(db, perm)
    for value, ids in ((row["id"], data.get("add") or []), (None, data.get("remove") or [])):
        for target in ids:
            if kind == "devices":
                _device(app, actor, str(target), perm)
            elif kind == "users":
                _user(app, actor, target, perm)
            if value is None:
                db.run(f"UPDATE {table} SET strategy_id = NULL WHERE id = ? AND strategy_id = ?",
                       (target, row["id"]))
            else:
                db.run(f"UPDATE {table} SET strategy_id = ? WHERE id = ?", (value, target))
    log(app, req, "strategy.assign", row["name"], json.dumps(data))
    return json_response({"ok": True})


# -- address books -----------------------------------------------------------------

def _book_for(app, req, guid, need):
    actor = console_user(app, req)
    rule = models.book_rule(app.db, actor.user, guid, as_admin=True)
    if rule == 0:
        raise HTTPError(404, "Address book not found")
    if rule < need:
        raise HTTPError(403, "You do not have permission to change this address book")
    return actor, rule, app.db.one("SELECT * FROM address_books WHERE guid = ?", (guid,))


@router.route("GET", "/api/admin/address-books")
def books(app, req):
    actor = console_user(app, req)
    user = actor.user
    db = app.db
    models.personal_book(db, user["id"])
    rows = db.all("SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id "
                  "ORDER BY b.personal DESC, b.name COLLATE NOCASE")
    items = []
    for r in rows:
        mine = r["owner_id"] == user["id"]
        if r["personal"] and not mine:
            continue  # other people's personal books are private, as in Pro
        rule = models.book_rule(db, user, r["guid"], as_admin=True)
        if not rule:
            continue
        items.append({
            "guid": r["guid"], "name": r["name"], "note": r["note"], "owner": r["owner"],
            "owner_id": r["owner_id"], "personal": bool(r["personal"]), "rule": rule, "mine": mine,
            "password_set": bool(r["password"]),
            "peers": db.one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ? AND deleted_at IS NULL",
                            (r["guid"],))["n"],
        })
    return json_response({"items": items})


@router.route("POST", "/api/admin/address-books")
def book_create(app, req):
    actor = console_user(app, req)
    data = body(req)
    owner = actor.user["id"]
    if actor.is_admin and data.get("owner_id"):
        owner = opt_id(data["owner_id"], "users", app.db, "owner")
    guid = models.new_guid()
    name = require_name(data.get("name"))
    app.db.run("INSERT INTO address_books(guid, name, owner_id, personal, note, password, created_at) "
               "VALUES (?, ?, ?, 0, ?, ?, ?)",
               (guid, name, owner, text_field(data, "note") or "", str(data.get("password") or "")[:1024], now()))
    log(app, req, "address_book.create", name)
    return json_response({"guid": guid}, 201)


@router.route("GET", "/api/admin/address-books/<guid>")
def book_detail(app, req, guid):
    _, rule, book = _book_for(app, req, guid, RULE_READ)
    db = app.db
    peers = []
    cutoff = now() - ONLINE_SECONDS
    for r in db.all("SELECT * FROM ab_peers WHERE guid = ? AND deleted_at IS NULL "
                    "ORDER BY created_at, peer_id", (guid,)):
        p = models.peer_payload(db, r, bool(book["personal"]))
        seen = db.one("SELECT last_seen_at FROM devices WHERE id = ?", (p["id"],))
        p["online"] = bool(seen and seen["last_seen_at"] and seen["last_seen_at"] >= cutoff)
        # Pro shows only whether a password is set, never the value.
        p["password_set"] = bool(p.pop("password", "") or p.pop("hash", ""))
        p.pop("hash", None)
        peers.append(p)
    tags = [{"name": r["name"], "color": r["color"]}
            for r in db.all("SELECT * FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))]
    rules = [{
        "guid": r["rule_guid"], "user_id": r["user_id"], "user_group_id": r["user_group_id"],
        "everyone": bool(r["everyone"]), "rule": r["rule"], "name": r["uname"] or r["gname"] or "Everyone",
    } for r in db.all(
        "SELECT r.*, u.name AS uname, g.name AS gname FROM ab_rules r "
        "LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.user_group_id "
        "WHERE r.guid = ? ORDER BY r.everyone, r.user_group_id IS NULL, r.id", (guid,))]
    owner = db.one("SELECT name FROM users WHERE id = ?", (book["owner_id"],))
    return json_response({
        "guid": guid, "name": book["name"], "note": book["note"], "personal": bool(book["personal"]),
        "owner": owner["name"] if owner else "", "owner_id": book["owner_id"], "rule": rule,
        "password_set": bool(book["password"]), "peers": peers, "tags": tags, "rules": rules,
        "recycled": db.one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ? AND deleted_at IS NOT NULL",
                           (guid,))["n"],
    })


@router.route("PATCH", "/api/admin/address-books/<guid>")
def book_update(app, req, guid):
    actor, _, book = _book_for(app, req, guid, RULE_FULL)
    data = body(req)
    db = app.db
    if "name" in data and not book["personal"]:
        db.run("UPDATE address_books SET name = ? WHERE guid = ?", (require_name(data["name"]), guid))
        log(app, req, "address_book.rename", data["name"])
    if "note" in data:
        db.run("UPDATE address_books SET note = ? WHERE guid = ?", (text_field(data, "note") or "", guid))
    if "password" in data and not book["personal"]:
        db.run("UPDATE address_books SET password = ? WHERE guid = ?", (str(data["password"] or "")[:1024], guid))
    if "owner_id" in data and actor.is_admin and not book["personal"]:
        db.run("UPDATE address_books SET owner_id = ? WHERE guid = ?",
               (opt_id(data["owner_id"], "users", db, "owner") or book["owner_id"], guid))
    if "rules" in data and not book["personal"]:
        _replace_rules(app, req, actor, guid, data["rules"])
    return json_response({"ok": True})


def _replace_rules(app, req, actor, guid, rules):
    """Replace a book's sharing rules: [{user_id | user_group_id | everyone, rule}]."""
    from .client_api import check_share_target
    if not isinstance(rules, list):
        raise HTTPError(400, "Invalid rules")
    db = app.db
    old = {(r["user_id"], r["user_group_id"], r["everyone"]): r["rule"]
           for r in db.all("SELECT * FROM ab_rules WHERE guid = ?", (guid,))}
    new = {}
    for r in rules:
        if not isinstance(r, dict) or r.get("rule") not in (1, 2, 3):
            raise HTTPError(400, "Invalid rule")
        uid, gid, everyone = r.get("user_id") or None, r.get("user_group_id") or None, bool(r.get("everyone"))
        if sum(map(bool, (uid, gid, everyone))) != 1:
            raise HTTPError(400, "A rule targets one user, one group, or everyone")
        if uid and not db.one("SELECT 1 FROM users WHERE id = ?", (uid,)):
            raise HTTPError(400, "Unknown user in rules")
        if gid and not db.one("SELECT 1 FROM user_groups WHERE id = ?", (gid,)):
            raise HTTPError(400, "Unknown group in rules")
        key = (uid, gid, int(everyone))
        if key not in old or old[key] != r["rule"]:
            check_share_target(app, actor, uid, gid, everyone)
        new[key] = r["rule"]
    with db.tx() as c:
        c.execute("DELETE FROM ab_rules WHERE guid = ?", (guid,))
        for (uid, gid, everyone), rule in new.items():
            c.execute("INSERT INTO ab_rules(rule_guid, guid, user_id, user_group_id, everyone, rule) "
                      "VALUES (?, ?, ?, ?, ?, ?)", (models.new_guid(), guid, uid, gid, everyone, rule))
    for key in set(old) | set(new):
        if key not in new:
            log(app, req, "address_book.rule_delete", guid, json.dumps(key))
        elif key not in old:
            log(app, req, "address_book.rule_add", guid, json.dumps([*key, new[key]]))
        elif old[key] != new[key]:
            log(app, req, "address_book.rule_update", guid, json.dumps([*key, new[key]]))


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
        existing = c.execute("SELECT deleted_at FROM ab_peers WHERE guid = ? AND peer_id = ?",
                             (guid, str(data.get("id") or "").strip())).fetchone()
        if existing and not existing["deleted_at"]:
            raise HTTPError(409, "This ID is already in the address book")
        limit = app.db.setting("max_peers_per_ab")
        if limit and c.execute("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ? AND deleted_at IS NULL",
                               (guid,)).fetchone()["n"] >= limit:
            raise HTTPError(400, "The address book is full")
        err = models.upsert_peer(c, guid, data, bool(book["personal"]))
    if err:
        raise HTTPError(400, err)
    return json_response({"ok": True}, 201)


@router.route("GET", "/api/admin/address-books/<guid>/importable")
def book_importable(app, req, guid):
    """Devices the user can see that are not in the book yet (Pro: Import)."""
    actor, _, _ = _book_for(app, req, guid, RULE_READ_WRITE)
    db = app.db
    cond, params = actor.scope(db, "devices.view").device_sql()
    rows = db.all(f"SELECT d.* FROM devices d WHERE {cond} AND d.id NOT IN "
                  "(SELECT peer_id FROM ab_peers WHERE guid = ? AND deleted_at IS NULL) ORDER BY d.id",
                  params + (guid,))
    cache = {}
    return json_response({"items": [models.device_payload(db, r, cache) for r in rows]})


@router.route("POST", "/api/admin/address-books/<guid>/import")
def book_import(app, req, guid):
    actor, _, book = _book_for(app, req, guid, RULE_READ_WRITE)
    ids = body(req).get("ids")
    if not isinstance(ids, list):
        raise HTTPError(400, "ids must be a list")
    db = app.db
    cond, params = actor.scope(db, "devices.view").device_sql()
    with db.tx() as c:
        for device_id in ids:
            if c.execute(f"SELECT 1 FROM devices d WHERE d.id = ? AND {cond}", (str(device_id),) + params).fetchone():
                models.upsert_peer(c, guid, {"id": str(device_id)}, bool(book["personal"]))
    return json_response({"ok": True})


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
    with app.db.tx() as c:
        models.recycle_peers(c, guid, [peer_id])
    return json_response({"ok": True})


@router.route("GET", "/api/admin/address-books/<guid>/recycle")
def book_recycle(app, req, guid):
    _, _, book = _book_for(app, req, guid, RULE_READ)
    rows = app.db.all("SELECT * FROM ab_peers WHERE guid = ? AND deleted_at IS NOT NULL "
                      "ORDER BY deleted_at DESC", (guid,))
    items = []
    for r in rows:
        p = models.peer_payload(app.db, r, bool(book["personal"]))
        p.pop("password", None)
        p.pop("hash", None)
        p["deleted_at"] = r["deleted_at"]
        items.append(p)
    return json_response({"items": items})


@router.route("POST", "/api/admin/address-books/<guid>/recycle/restore")
def book_recycle_restore(app, req, guid):
    _book_for(app, req, guid, RULE_READ_WRITE)
    ids = body(req).get("ids") or []
    with app.db.tx() as c:
        for peer_id in ids:
            c.execute("UPDATE ab_peers SET deleted_at = NULL WHERE guid = ? AND peer_id = ?", (guid, str(peer_id)))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/address-books/<guid>/recycle/delete")
def book_recycle_delete(app, req, guid):
    """{"ids": [...]} deletes those for good; {"all": true} empties the bin."""
    _, _, book = _book_for(app, req, guid, RULE_READ_WRITE)
    data = body(req)
    with app.db.tx() as c:
        if data.get("all"):
            c.execute("DELETE FROM ab_peers WHERE guid = ? AND deleted_at IS NOT NULL", (guid,))
        else:
            for peer_id in data.get("ids") or []:
                c.execute("DELETE FROM ab_peers WHERE guid = ? AND peer_id = ? AND deleted_at IS NOT NULL",
                          (guid, str(peer_id)))
    log(app, req, "address_book.recycle_empty" if data.get("all") else "address_book.recycle_delete",
        book["name"], json.dumps(data))
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
    from urllib.parse import unquote
    _book_for(app, req, guid, RULE_READ_WRITE)
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
    from urllib.parse import unquote
    _book_for(app, req, guid, RULE_READ_WRITE)
    with app.db.tx() as c:
        models.delete_tags(c, guid, [unquote(name)])
    return json_response({"ok": True})


# -- logs --------------------------------------------------------------------------

def _hostname(db, device_id):
    row = db.one("SELECT hostname, name_override FROM devices WHERE id = ?", (device_id,))
    return (row["name_override"] or row["hostname"]) if row else ""


def conn_row(db, r):
    end = r["ended_at"]
    authorized = r["authorized_at"] is not None
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "conn_id": r["conn_id"], "peer_id": r["peer_id"], "peer_name": r["peer_name"], "ip": r["ip"],
        "controller": r["controller"], "note": r["note"],
        "type": models.CONN_TYPES.get(r["type"], "") if authorized else "Not Logged In",
        "auth": models.PRIMARY_AUTH.get(r["primary_auth"], ""),
        "two_factor": models.TWO_FACTOR.get(r["two_factor"], ""),
        "started_at": r["started_at"], "authorized_at": r["authorized_at"], "ended_at": end,
        "duration": (end or now()) - r["started_at"],
    }


def file_row(db, r):
    info = loads(r["info"], {})
    files = info.get("files", [])
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "peer_id": r["peer_id"], "peer_name": info.get("name", ""), "ip": info.get("ip", ""),
        "direction": models.FILE_TYPES.get(r["type"], str(r["type"])), "path": r["path"],
        "is_file": bool(r["is_file"]), "count": info.get("num", 0),
        "size": files[0][1] if len(files) == 1 and isinstance(files[0], list) else None,
        "files": files, "created_at": r["created_at"],
    }


def alarm_row(db, r):
    info = loads(r["info"], {})
    login_alarm = r["typ"] in models.LOGIN_ALARMS
    return {
        "id": r["id"], "device_id": r["device_id"], "device_name": _hostname(db, r["device_id"]),
        "type": models.ALARM_TYPES.get(r["typ"], f"Alarm {r['typ']}"), "ip": r["ip"] or info.get("ip", ""),
        # Pro: From is the login device / controlling side; Target is the
        # login account / controlled device.
        "from": (info.get("id") or r["ip"]) if login_alarm else (info.get("id") or info.get("ip", "")),
        "target": info.get("name", "") if login_alarm else r["device_id"],
        "peer_id": info.get("id", ""), "peer_name": info.get("name", ""),
        "detail": info, "created_at": r["created_at"],
    }


def console_row(db, r):
    data = {k: r[k] for k in ("id", "user_name", "action", "target", "detail", "ip", "created_at")}
    data["type"] = models.CONSOLE_TYPES.get(r["typ"], "")
    data["operation"] = models.CONSOLE_OP_NAMES.get(r["iop"], r["action"])
    return data


LOGS = {  # console name -> (REST kind, renderer, free-text columns)
    "connections": ("conn", conn_row, ["device_id", "peer_id", "peer_name", "ip", "controller", "note"]),
    "files": ("file", file_row, ["device_id", "peer_id", "path", "info"]),
    "alarms": ("alarm", alarm_row, ["device_id", "ip", "info"]),
    "console": ("console", console_row, ["user_name", "action", "target", "detail", "ip"]),
}

CSV_COLUMNS = {
    "connections": ["started_at", "ended_at", "duration", "type", "device_id", "device_name", "controller",
                    "peer_id", "peer_name", "ip", "auth", "two_factor", "note"],
    "files": ["created_at", "device_id", "device_name", "peer_id", "peer_name", "ip", "direction",
              "path", "count"],
    "alarms": ["created_at", "type", "from", "target", "device_id", "ip"],
    "console": ["created_at", "type", "user_name", "operation", "target", "detail", "ip"],
}


@router.route("GET", "/api/admin/logs/<kind>")
def logs(app, req, kind):
    actor = console_user(app, req)
    if kind not in LOGS:
        raise HTTPError(404, "Unknown log")
    rest_kind, render, search_cols = LOGS[kind]
    db = app.db
    query = dict(req.query)
    device = (query.pop("device", "") or "").strip()
    table, sql, params = rest_api.audit_rows(app, actor, rest_kind, query)
    where = [sql]
    q = (req.query.get("q") or "").strip()
    if q:
        where.append("(" + " OR ".join(f"{c} LIKE ?" for c in search_cols) + ")")
        params += [f"%{q}%"] * len(search_cols)
    if device and kind != "console":
        if kind in ("connections", "files"):
            where.append("(device_id = ? OR peer_id = ?)")
            params += [device, device]
        else:
            where.append("device_id = ?")
            params.append(device)
    if kind == "connections" and req.query.get("active") == "1":
        where.append("ended_at IS NULL")
    sql = " AND ".join(where)
    if req.query.get("format") == "csv":
        # Pro exports up to 1000 rows per file, following the page filters.
        rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT 1000", params)
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
    total = db.one(f"SELECT COUNT(*) AS n FROM {table} WHERE {sql}", params)["n"]
    rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                  params + [size, offset])
    return json_response({"total": total, "items": [render(db, r) for r in rows],
                          "can_edit": actor.can(db, "audits.edit")})


def _conn_log(app, actor, log_id):
    table, sql, params = rest_api.audit_rows(app, actor, "conn", {})
    row = app.db.one(f"SELECT * FROM conn_logs WHERE id = ? AND {sql}", [as_int(log_id)] + params)
    if row is None:
        raise HTTPError(404, "Log entry not found")
    return row


@router.route("PATCH", "/api/admin/logs/connections/<log_id>")
def conn_note(app, req, log_id):
    """Anyone who can see a connection record can edit its note (Pro)."""
    actor = console_user(app, req)
    row = _conn_log(app, actor, log_id)
    app.db.run("UPDATE conn_logs SET note = ? WHERE id = ?", (text_field(body(req), "note") or "", row["id"]))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/logs/connections/<log_id>/disconnect")
def conn_disconnect(app, req, log_id):
    actor = console_user(app, req)
    actor.require(app.db, "audits.edit")
    row = _conn_log(app, actor, log_id)
    if row["ended_at"]:
        raise HTTPError(400, "This connection has already ended")
    queue_disconnect(app, req, row["device_id"], [row["conn_id"]])
    return json_response({"ok": True})


def _csv_safe(value):
    """Stop spreadsheet apps from treating a cell as a formula."""
    if value is None:
        return ""
    text_ = str(value)
    if text_[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text_
    return text_


# -- admin roles -------------------------------------------------------------------

def role_payload(db, r):
    return {
        "id": r["id"], "guid": r["guid"], "name": r["name"], "type": r["type"], "note": r["note"],
        "perms": loads(r["perms"], []), "user_groups": loads(r["user_groups"], []),
        "device_groups": loads(r["device_groups"], []), "unassigned": bool(r["unassigned"]),
        "users": [u["user_id"] for u in db.all("SELECT user_id FROM user_admin_roles WHERE role_id = ?", (r["id"],))],
    }


@router.route("GET", "/api/admin/admin-roles")
def admin_roles(app, req):
    admin_only(app, req)
    db = app.db
    return json_response({
        "items": [role_payload(db, r) for r in db.all("SELECT * FROM admin_roles ORDER BY name COLLATE NOCASE")],
        "permissions": [{"name": k, "label": v[0], "types": list(v[1])} for k, v in PERMISSIONS.items()],
    })


def _role_fields(db, data, role_type):
    perms = data.get("perms") or []
    if not isinstance(perms, list) or any(p not in PERMISSIONS for p in perms):
        raise HTTPError(400, "Unknown permission")
    bad = [p for p in perms if role_type not in PERMISSIONS[p][1]]
    if bad:
        raise HTTPError(400, f"Not valid for a {role_type} role: {', '.join(bad)}")
    ugs = [as_int(i) for i in data.get("user_groups") or []]
    dgs = [as_int(i) for i in data.get("device_groups") or []]
    for ids, table in ((ugs, "user_groups"), (dgs, "device_groups")):
        for i in ids:
            if not db.one(f"SELECT 1 FROM {table} WHERE id = ?", (i,)):
                raise HTTPError(400, "Unknown group in scope")
    if role_type != "group":
        ugs, dgs = [], []
    return json.dumps(sorted(set(perms))), json.dumps(ugs), json.dumps(dgs), \
        1 if (data.get("unassigned") and role_type == "group") else 0


@router.route("POST", "/api/admin/admin-roles")
def admin_role_create(app, req):
    admin_only(app, req)
    data = body(req)
    role_type = data.get("type")
    if role_type not in ("global", "individual", "group"):
        raise HTTPError(400, "type must be global, individual or group")
    perms, ugs, dgs, unassigned = _role_fields(app.db, data, role_type)
    name = require_name(data.get("name"))
    try:
        cur = app.db.run("INSERT INTO admin_roles(guid, name, type, perms, user_groups, device_groups, unassigned, "
                         "note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (models.new_guid(), name, role_type, perms, ugs, dgs, unassigned,
                          text_field(data, "note") or "", now()))
    except Exception as exc:
        unique_error(exc, "Role")
    if isinstance(data.get("users"), list):
        _set_role_users(app.db, cur.lastrowid, data["users"])
    log(app, req, "admin_role.create", name, perms)
    return json_response({"id": cur.lastrowid}, 201)


def _set_role_users(db, role_id, user_ids):
    with db.tx() as c:
        c.execute("DELETE FROM user_admin_roles WHERE role_id = ?", (role_id,))
        for uid in user_ids:
            if c.execute("SELECT 1 FROM users WHERE id = ?", (as_int(uid),)).fetchone():
                c.execute("INSERT OR IGNORE INTO user_admin_roles VALUES (?, ?)", (int(uid), role_id))


@router.route("PATCH", "/api/admin/admin-roles/<role_id>")
def admin_role_update(app, req, role_id):
    admin_only(app, req)
    db = app.db
    row = db.one("SELECT * FROM admin_roles WHERE id = ?", (as_int(role_id),))
    if row is None:
        raise HTTPError(404, "Role not found")
    data = body(req)
    merged = {"perms": loads(row["perms"], []), "user_groups": loads(row["user_groups"], []),
              "device_groups": loads(row["device_groups"], []), "unassigned": row["unassigned"]}
    merged.update({k: data[k] for k in merged if k in data})
    perms, ugs, dgs, unassigned = _role_fields(db, merged, row["type"])  # the type is fixed, as in Pro
    name = require_name(data["name"]) if "name" in data else row["name"]
    note = text_field(data, "note") if "note" in data else row["note"]
    try:
        db.run("UPDATE admin_roles SET name = ?, note = ?, perms = ?, user_groups = ?, device_groups = ?, "
               "unassigned = ? WHERE id = ?", (name, note or "", perms, ugs, dgs, unassigned, row["id"]))
    except Exception as exc:
        unique_error(exc, "Role")
    if isinstance(data.get("users"), list):
        _set_role_users(db, row["id"], data["users"])
    log(app, req, "admin_role.update", name, json.dumps(data))
    return json_response({"ok": True})


@router.route("DELETE", "/api/admin/admin-roles/<role_id>")
def admin_role_delete(app, req, role_id):
    admin_only(app, req)
    row = app.db.one("SELECT name FROM admin_roles WHERE id = ?", (as_int(role_id),))
    if row is None:
        raise HTTPError(404, "Role not found")
    app.db.run("DELETE FROM admin_roles WHERE id = ?", (as_int(role_id),))
    log(app, req, "admin_role.delete", row["name"])
    return json_response({"ok": True})


# -- API tokens --------------------------------------------------------------------

TOKEN_KEYS = ("device", "audit", "user", "group", "strategy", "ab")


@router.route("GET", "/api/admin/tokens")
def tokens(app, req):
    admin_only(app, req)
    rows = app.db.all("SELECT t.*, u.name AS creator FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id "
                      "ORDER BY t.created_at DESC")
    return json_response({"items": [{
        "id": r["id"], "guid": r["guid"], "name": r["name"], "perms": loads(r["perms"], {}),
        "creator": r["creator"], "created_at": r["created_at"], "expires_at": r["expires_at"],
        "last_used_at": r["last_used_at"],
    } for r in rows]})


@router.route("POST", "/api/admin/tokens")
def token_create(app, req):
    actor = admin_only(app, req)
    data = body(req)
    name = require_name(data.get("name"))
    perms = data.get("perms") or {}
    if not isinstance(perms, dict):
        raise HTTPError(400, "Invalid permissions")
    clean = {k: perms.get(k, 0) for k in TOKEN_KEYS}
    if any(v not in (0, 1, 2) for v in clean.values()):
        raise HTTPError(400, "Permission levels are 0 (none), 1 (read) or 2 (read/write)")
    days = data.get("expires_days")
    expires = now() + as_int(days, "expiry") * 86400 if days else None
    token = new_token()
    app.db.run("INSERT INTO api_tokens(guid, name, token_hash, user_id, perms, created_at, expires_at) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)",
               (models.new_guid(), name, token_hash(token), actor.user["id"], json.dumps(clean), now(), expires))
    log(app, req, "settings.token_create", name, json.dumps(clean))
    return json_response({"token": token}, 201)


@router.route("DELETE", "/api/admin/tokens/<token_id>")
def token_delete(app, req, token_id):
    admin_only(app, req)
    row = app.db.one("SELECT name FROM api_tokens WHERE id = ?", (as_int(token_id),))
    if row is None:
        raise HTTPError(404, "Token not found")
    app.db.run("DELETE FROM api_tokens WHERE id = ?", (as_int(token_id),))
    log(app, req, "settings.token_delete", row["name"])
    return json_response({"ok": True})


# -- recordings --------------------------------------------------------------------

@router.route("GET", "/api/admin/recordings")
def recordings(app, req):
    admin_only(app, req)
    rows = app.db.all("SELECT * FROM recordings ORDER BY created_at DESC")
    return json_response({"items": [dict(r) for r in rows]})


@router.route("GET", "/api/admin/recordings/<rid>/download")
def recording_download(app, req, rid):
    admin_only(app, req)
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
    admin_only(app, req)
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
    if not s["id_server"] and not app.cfg.id_server and hostname:
        # By convention hbbs listens two ports above this server (31116 for 31114).
        port = app.server.server_address[1] if getattr(app, "server", None) else app.cfg.port
        hostname = f"{hostname}:{port + 2}"
    host = s["id_server"] or app.cfg.id_server or hostname
    relay = s["relay_server"] or app.cfg.relay_server
    config = {"host": host, "relay": relay, "api": s["api_server"], "key": hbbs_key(app)}
    encoded = base64.urlsafe_b64encode(
        json.dumps(config, separators=(",", ":")).encode()).decode()[::-1]
    return dict(config, config_string=encoded, api_default=derived_api(host),
                # Pro's "Windows EXE": renaming rustdesk.exe to this configures
                # the client (custom_server.rs get_custom_server_from_string).
                windows_exe=f"rustdesk-licensed-{encoded}.exe")


def derived_api(host):
    """The API URL a client derives when its API server field is empty: the ID
    server's port minus 2, or 21114 when no port is given (common.rs
    get_api_server)."""
    if not host:
        return ""
    if host.startswith("["):
        name, _, port = host.partition("]:")
        name += "]"
    elif host.count(":") == 1:
        name, _, port = host.partition(":")
    else:
        name, port = host, ""
    return f"http://{name}:{int(port) - 2 if port.isdigit() else 21114}"


@router.route("GET", "/api/admin/client-config")
def get_client_config(app, req):
    console_user(app, req)
    return json_response(client_config(app, req))


SETTING_TYPES = {
    "id_server": str, "relay_server": str, "api_server": str, "server_key": str, "console_url": str,
    "client_token_days": int, "console_session_hours": int, "log_retention_days": int,
    "accept_recordings": bool, "recordings_max_mb": int, "max_peers_per_ab": int,
    "default_strategy_id": "strategy", "only_admin_logs": bool, "allow_non_admin_share": bool,
    "disable_accessible_devices": bool, "smtp_host": str, "smtp_port": int, "smtp_security": str,
    "smtp_user": str, "smtp_password": str, "smtp_from": str,
}


@router.route("GET", "/api/admin/settings")
def get_settings(app, req):
    admin_only(app, req)
    data = app.db.settings()
    data["smtp_password_set"] = bool(data.pop("smtp_password"))
    data["hbbs_key_file"] = app.cfg.hbbs_key_file
    data["detected_key"] = hbbs_key(app) if not data["server_key"] else ""
    return json_response(data)


@router.route("PATCH", "/api/admin/settings")
def patch_settings(app, req):
    actor = console_user(app, req)
    data = body(req)
    # Choosing the default strategy belongs to strategy editors too.
    if set(data) == {"default_strategy_id"}:
        actor.require(app.db, "strategies.edit")
    elif not actor.is_admin:
        raise HTTPError(403, "Administrator access required")
    values = {}
    for key, value in data.items():
        kind = SETTING_TYPES.get(key)
        if kind is None:
            raise HTTPError(400, f"Unknown setting: {key}")
        if kind is str:
            if not isinstance(value, str):
                raise HTTPError(400, f"Invalid {key}")
            value = value.strip()[:512]
            if key == "smtp_security" and value not in ("starttls", "ssl", "none"):
                raise HTTPError(400, "smtp_security must be starttls, ssl or none")
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
    shown = {k: ("(hidden)" if k == "smtp_password" else v) for k, v in values.items()}
    log(app, req, "settings.update", "", json.dumps(shown))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/settings/smtp-test")
def smtp_test(app, req):
    actor = admin_only(app, req)
    to = str(body(req).get("to") or actor.user["email"] or "").strip()
    if "@" not in to:
        raise HTTPError(400, "Enter an address to send the test email to")
    mail.send(app.db.settings(), to, "RussDesk test email", "Email from RussDesk works.")
    return json_response({"ok": True})


@router.route("GET", "/api/admin/lookup")
def lookup(app, req):
    """Names for select boxes."""
    console_user(app, req)
    db = app.db
    return json_response({
        "users": [{"id": r["id"], "name": r["name"], "group_id": r["group_id"]} for r in db.all(
            "SELECT id, name, group_id FROM users ORDER BY name COLLATE NOCASE")],
        "user_groups": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM user_groups ORDER BY name COLLATE NOCASE")],
        "device_groups": [{"id": r["id"], "name": r["name"]} for r in db.all(
            "SELECT id, name FROM device_groups ORDER BY name COLLATE NOCASE")],
        "strategies": [{"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"])} for r in db.all(
            "SELECT id, name, enabled FROM strategies ORDER BY name COLLATE NOCASE")],
        "admin_roles": [{"id": r["id"], "name": r["name"], "type": r["type"]} for r in db.all(
            "SELECT id, name, type FROM admin_roles ORDER BY name COLLATE NOCASE")],
    })


# -- own account -------------------------------------------------------------------

@router.route("PATCH", "/api/admin/account")
def account_update(app, req):
    """Display name, email and email login verification (Pro: Settings)."""
    actor = console_user(app, req)
    data = body(req)
    user = actor.user
    db = app.db
    email = text_field(data, "email", 256) if "email" in data else user["email"]
    if "display_name" in data:
        db.run("UPDATE users SET display_name = ? WHERE id = ?", (text_field(data, "display_name", 256) or "",
                                                                  user["id"]))
    if "email" in data:
        db.run("UPDATE users SET email = ? WHERE id = ?", (email or "", user["id"]))
    if "email_verification" in data:
        if data["email_verification"] and not (email and mail.configured(db.settings())):
            raise HTTPError(400, "Email login verification needs an email address and SMTP settings")
        db.run("UPDATE users SET email_verification = ? WHERE id = ?",
               (1 if data["email_verification"] else 0, user["id"]))
    log(app, req, "account.update", user["name"], json.dumps(data))
    return json_response({"ok": True})


@router.route("POST", "/api/admin/account/password")
def change_password(app, req):
    actor = console_user(app, req)
    user = actor.user
    data = body(req)
    if not verify_password(str(data.get("current") or ""), user["password_hash"]):
        raise HTTPError(400, "Current password is wrong")
    if user["totp_secret"] and not auth.verify_code(app.db, user, str(data.get("code") or "")):
        raise HTTPError(400, "Enter a valid two-factor code to change your password")
    app.db.run("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(check_password(data.get("new"))), user["id"]))
    app.db.run("DELETE FROM tokens WHERE user_id = ? AND token_hash != ?", (user["id"], req.token))
    log(app, req, "account.password")
    return json_response({"ok": True})


@router.route("POST", "/api/admin/account/2fa/setup")
def totp_setup(app, req):
    actor = console_user(app, req)
    secret = new_totp_secret()
    return json_response({"secret": secret, "uri": totp_uri(secret, actor.user["name"])})


@router.route("POST", "/api/admin/account/2fa/enable")
def totp_enable(app, req):
    actor = console_user(app, req)
    data = body(req)
    secret = str(data.get("secret") or "")
    if not re.match(r"^[A-Z2-7]{16,64}$", secret):
        raise HTTPError(400, "Invalid secret")
    if not verify_totp(secret, str(data.get("code") or "")):
        raise HTTPError(400, "The code does not match; check the time on your phone and try again")
    codes, hashes = new_backup_codes()
    app.db.run("UPDATE users SET totp_secret = ?, totp_backup = ?, totp_set_at = ? WHERE id = ?",
               (secret, json.dumps(hashes), now(), actor.user["id"]))
    log(app, req, "account.2fa_enable")
    return json_response({"ok": True, "backup_codes": codes})


@router.route("POST", "/api/admin/account/2fa/backup-codes")
def totp_backup_codes(app, req):
    actor = console_user(app, req)
    user = actor.user
    if not user["totp_secret"]:
        raise HTTPError(400, "Two-factor login is off")
    if not verify_totp(user["totp_secret"], str(body(req).get("code") or "")):
        raise HTTPError(400, "Enter a current code from your authenticator app")
    codes, hashes = new_backup_codes()
    app.db.run("UPDATE users SET totp_backup = ? WHERE id = ?", (json.dumps(hashes), user["id"]))
    log(app, req, "account.2fa_backup_codes")
    return json_response({"backup_codes": codes})


@router.route("POST", "/api/admin/account/2fa/disable")
def totp_disable(app, req):
    actor = console_user(app, req)
    user = actor.user
    if user["force_2fa"]:
        raise HTTPError(400, "Two-factor login is required for your account")
    if not verify_password(str(body(req).get("password") or ""), user["password_hash"]):
        raise HTTPError(400, "Password is wrong")
    app.db.run("UPDATE users SET totp_secret = '', totp_backup = '[]', totp_set_at = NULL WHERE id = ?",
               (user["id"],))
    log(app, req, "account.2fa_disable")
    return json_response({"ok": True})
