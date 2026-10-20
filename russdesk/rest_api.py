"""Token REST API compatible with RustDesk Server Pro's management scripts
(rustdesk/rustdesk res/devices.py, users.py, user-groups.py, device-groups.py,
strategies.py, audits.py; ab.py lives in client_api). Callers authenticate with
an API token from Settings > Tokens."""

import datetime
import json

from . import mail, models
from .client_api import api_token, apply_assignments, console_url, ok_empty, page_args
from .authz import Actor
from .db import now
from .security import new_token, token_hash
from .web import HTTPError, Router, json_response

router = Router()


def token_actor(app, req):
    token = api_token(app, req)
    if token is None:
        raise HTTPError(401, "A valid API token is required")
    creator = app.db.one("SELECT * FROM users WHERE id = ?", (token["user_id"],)) if token["user_id"] else None
    req.user = creator
    req.actor = Actor(user=creator, token=token)
    return req.actor


def page(rows, req):
    current, size = page_args(req)
    return json_response({"total": len(rows), "data": rows[(current - 1) * size:current * size]})


def filters(req, mapping):
    where, params = [], []
    for key, column in mapping.items():
        value = req.query.get(key)
        if value:
            where.append(f"{column} LIKE ?")
            params.append(models.like(value))
    return where, params


def log(app, req, action, target="", detail=""):
    models.console_log(app.db, req, action, target, detail)


# -- devices -------------------------------------------------------------------

@router.route("GET", "/api/devices")
def devices(app, req):
    actor = token_actor(app, req)
    db = app.db
    scope = actor.require(db, "devices.view")
    cond, params = scope.device_sql()
    where, extra = filters(req, {
        "id": "d.id", "device_name": "COALESCE(NULLIF(d.name_override, ''), d.hostname)",
        "user_name": "u.name", "group_name": "g.name", "device_group_name": "dg.name",
        "device_username": "COALESCE(NULLIF(d.username_override, ''), d.username)",
    })
    sql = " AND ".join([cond] + where)
    rows = db.all("SELECT d.* FROM devices d LEFT JOIN users u ON u.id = d.user_id "
                  "LEFT JOIN user_groups g ON g.id = u.group_id "
                  f"LEFT JOIN device_groups dg ON dg.id = d.device_group_id WHERE {sql} ORDER BY d.id",
                  tuple(params) + tuple(extra))
    names = {}
    return page([models.device_payload(db, r, names) for r in rows], req)


def _device_by_guid(app, actor, guid, perm):
    db = app.db
    scope = actor.require(db, perm)
    cond, params = scope.device_sql()
    row = db.one(f"SELECT * FROM devices d WHERE d.guid = ? AND {cond}", (guid,) + params)
    if row is None:
        raise HTTPError(404, "Device not found")
    return row


def set_device_disabled(app, req, row, disabled):
    app.db.run("UPDATE devices SET disabled = ? WHERE id = ?", (1 if disabled else 0, row["id"]))
    log(app, req, "device.disable" if disabled else "device.enable", row["id"])


@router.route("POST", "/api/devices/<guid>/enable")
def device_enable(app, req, guid):
    actor = token_actor(app, req)
    set_device_disabled(app, req, _device_by_guid(app, actor, guid, "devices.enable_disable"), False)
    return ok_empty()


@router.route("POST", "/api/devices/<guid>/disable")
def device_disable(app, req, guid):
    actor = token_actor(app, req)
    set_device_disabled(app, req, _device_by_guid(app, actor, guid, "devices.enable_disable"), True)
    return ok_empty()


def delete_device(app, req, row):
    """Pro only deletes disabled devices."""
    if not row["disabled"]:
        raise HTTPError(400, "Disable the device before deleting it")
    app.db.run("DELETE FROM devices WHERE id = ?", (row["id"],))
    app.db.run("DELETE FROM pending_disconnects WHERE device_id = ?", (row["id"],))
    log(app, req, "device.delete", row["id"])


@router.route("DELETE", "/api/devices/<guid>")
def device_delete(app, req, guid):
    actor = token_actor(app, req)
    delete_device(app, req, _device_by_guid(app, actor, guid, "devices.delete"))
    return ok_empty()


ASSIGN_PERMS = {"user_name": "devices.assign_to_user", "device_group_name": "devices.change_group",
                "strategy_name": "devices.change_strategy", "note": "devices.edit_info",
                "device_username": "devices.edit_info", "device_name": "devices.edit_info",
                "ab": "devices.edit_info"}


@router.route("POST", "/api/devices/<guid>/assign")
def device_assign(app, req, guid):
    actor = token_actor(app, req)
    data = req.json_object()
    kind, value = data.get("type"), data.get("value")
    if kind not in ASSIGN_PERMS or not isinstance(value, str):
        raise HTTPError(400, "Invalid assignment")
    row = _device_by_guid(app, actor, guid, ASSIGN_PERMS[kind])
    if kind == "ab":
        parts = (value.split(",") + [""] * 5)[:5]
        values = dict(zip(("address_book_name", "address_book_tag", "address_book_alias",
                           "address_book_password", "address_book_note"), parts))
    else:
        values = {kind: value}
    with app.db.tx() as c:
        errors = apply_assignments(c, row, values, keep_existing=False)
    if errors:
        raise HTTPError(400, "; ".join(errors))
    log(app, req, "device.update", row["id"], json.dumps(data))
    return ok_empty()


# -- users -----------------------------------------------------------------------
# GET /api/users is served by client_api (clients and tokens share the path).

def _user_by_guid(app, actor, guid, perm):
    db = app.db
    scope = actor.require(db, perm)
    row = db.one("SELECT * FROM users WHERE guid = ?", (guid,))
    if row is None:
        raise HTTPError(404, "User not found")
    if not scope.everything:
        cond, params = scope.user_sql()
        if db.one(f"SELECT 1 FROM users u WHERE u.id = ? AND {cond}", (row["id"],) + params) is None:
            raise HTTPError(403, "You do not have permission for this user")
    if row["is_admin"] and not actor.is_admin and actor.token is None:
        raise HTTPError(403, "Only administrators can change administrator accounts")
    return row


def set_user_status(app, req, row, status):
    db = app.db
    if status == 0 and row["is_admin"] and not other_admins(db, row["id"]):
        raise HTTPError(400, "Keep at least one active administrator")
    db.run("UPDATE users SET status = ? WHERE id = ?", (status, row["id"]))
    if status == 0:
        db.run("DELETE FROM tokens WHERE user_id = ?", (row["id"],))
    log(app, req, "user.disable" if status == 0 else "user.enable", row["name"])


def other_admins(db, user_id):
    return db.one("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND status = 1 AND id != ?",
                  (user_id,))["n"]


@router.route("POST", "/api/users/<guid>/enable")
def user_enable(app, req, guid):
    actor = token_actor(app, req)
    set_user_status(app, req, _user_by_guid(app, actor, guid, "users.enable_disable"), 1)
    return ok_empty()


@router.route("POST", "/api/users/<guid>/disable")
def user_disable(app, req, guid):
    actor = token_actor(app, req)
    set_user_status(app, req, _user_by_guid(app, actor, guid, "users.enable_disable"), 0)
    return ok_empty()


def delete_user(app, req, row):
    """Pro only deletes disabled users."""
    if row["status"] == 1:
        raise HTTPError(400, "Disable the user before deleting it")
    app.db.run("DELETE FROM access_rules WHERE subject_type = 'user' AND subject_id = ?", (row["id"],))
    app.db.run("DELETE FROM users WHERE id = ?", (row["id"],))
    log(app, req, "user.delete", row["name"])


@router.route("DELETE", "/api/users/<guid>")
def user_delete(app, req, guid):
    actor = token_actor(app, req)
    delete_user(app, req, _user_by_guid(app, actor, guid, "users.delete"))
    return ok_empty()


def _group_id_by_name(db, name):
    if not name:
        return None
    row = db.one("SELECT id FROM user_groups WHERE name = ?", (name,))
    if row is None:
        raise HTTPError(400, f"User group '{name}' not found")
    return row["id"]


def create_user(app, req, actor, data, invite=False):
    """Shared by the REST API and the console. Returns the new user's id."""
    import re
    from .security import hash_password
    db = app.db
    actor.require(db, "users.invite" if invite else "users.create")
    name = str(data.get("name") or "").strip()
    if not re.match(r"^[A-Za-z0-9_.@\-]{1,64}$", name):
        raise HTTPError(400, "Username may use letters, digits and _ . @ - (up to 64)")
    group_id = data.get("group_id")
    if group_id is None and data.get("group_name"):
        group_id = _group_id_by_name(db, data.get("group_name"))
    scope = actor.scope(db, "users.invite" if invite else "users.create")
    if not scope.everything and group_id not in scope.user_groups:
        raise HTTPError(403, "You can only create users in the groups your role covers")
    is_admin = 1 if data.get("is_admin") and actor.is_admin else 0
    email = str(data.get("email") or "").strip()[:256]
    fields = {
        "guid": models.new_guid(), "name": name, "email": email,
        "note": str(data.get("note") or "")[:1024],
        "display_name": str(data.get("display_name") or "")[:256],
        "group_id": group_id, "is_admin": is_admin, "created_at": now(),
    }
    invite_token = None
    if invite:
        if "@" not in email:
            raise HTTPError(400, "An invitation needs an email address")
        invite_token = new_token()
        fields.update(status=-1, password_hash="!", invite_hash=token_hash(invite_token),
                      invite_expires=now() + 7 * 86400)
    else:
        password = data.get("password")
        if not isinstance(password, str) or len(password) < 8:
            raise HTTPError(400, "Password must be at least 8 characters")
        fields.update(status=1, password_hash=hash_password(password))
    cols = ", ".join(fields)
    try:
        cur = db.run(f"INSERT INTO users({cols}) VALUES ({','.join('?' * len(fields))})",
                     tuple(fields.values()))
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPError(409, "User already exists")
        raise
    models.personal_book(db, cur.lastrowid)
    if invite:
        link = f"{console_url(app, req)}/#/invite/{invite_token}"
        try:
            mail.send(db.settings(), email, "You are invited to RussDesk",
                      f"Hello {name},\n\nYou have been invited to RussDesk. Set your password here "
                      f"(the link is valid for 7 days):\n\n{link}\n")
        except HTTPError:
            db.run("DELETE FROM users WHERE id = ?", (cur.lastrowid,))
            raise
    log(app, req, "user.invite" if invite else "user.create", name)
    return cur.lastrowid


@router.route("POST", "/api/users")
def user_create(app, req):
    actor = token_actor(app, req)
    create_user(app, req, actor, req.json_object())
    return ok_empty()


@router.route("POST", "/api/users/invite")
def user_invite(app, req):
    actor = token_actor(app, req)
    create_user(app, req, actor, req.json_object(), invite=True)
    return ok_empty()


def _user_guids(app, actor, data, perm):
    guids = data.get("user_guids")
    if not isinstance(guids, list):
        raise HTTPError(400, "user_guids must be a list")
    return [_user_by_guid(app, actor, str(g), perm) for g in guids]


@router.route("PUT", "/api/users/tfa/totp/enforce")
def users_enforce_2fa(app, req):
    actor = token_actor(app, req)
    data = req.json_object()
    for row in _user_guids(app, actor, data, "users.manage_2fa"):
        app.db.run("UPDATE users SET force_2fa = ? WHERE id = ?", (1 if data.get("enforce") else 0, row["id"]))
        log(app, req, "user.update", row["name"], f"2FA enforcement {'on' if data.get('enforce') else 'off'}")
    return ok_empty()


@router.route("PUT", "/api/users/disable_login_verification")
def users_disable_verification(app, req):
    actor = token_actor(app, req)
    data = req.json_object()
    column = {"email": "email_verification = 0", "2fa": "totp_secret = '', totp_backup = '[]'"}.get(data.get("type"))
    if column is None:
        raise HTTPError(400, "type must be email or 2fa")
    for row in _user_guids(app, actor, data, "users.manage_2fa"):
        app.db.run(f"UPDATE users SET {column} WHERE id = ?", (row["id"],))
        log(app, req, "user.update", row["name"], f"{data['type']} login verification turned off")
    return ok_empty()


@router.route("POST", "/api/users/force-logout")
def users_force_logout(app, req):
    actor = token_actor(app, req)
    for row in _user_guids(app, actor, req.json_object(), "users.force_logout"):
        app.db.run("DELETE FROM tokens WHERE user_id = ?", (row["id"],))
        log(app, req, "user.update", row["name"], "forced logout")
    return ok_empty()


# -- groups ----------------------------------------------------------------------
# allowed_incomings: [{"type": 0 user group | 2 user, "name"}]
# allowed_outgoings: [{"type": 0 user group | 1 device group, "name"}]

def access_lists(db, target_type, target_id):
    incomings = [{"type": 0 if r["subject_type"] == "user_group" else 2, "name": r["name"],
                  "id": r["subject_id"]} for r in db.all(
        "SELECT a.subject_type, a.subject_id, COALESCE(g.name, u.name) AS name FROM access_rules a "
        "LEFT JOIN user_groups g ON a.subject_type = 'user_group' AND g.id = a.subject_id "
        "LEFT JOIN users u ON a.subject_type = 'user' AND u.id = a.subject_id "
        "WHERE a.target_type = ? AND a.target_id = ?", (target_type, target_id))]
    outgoings = []
    if target_type == "user_group":
        outgoings = [{"type": 0 if r["target_type"] == "user_group" else 1, "name": r["name"],
                      "id": r["target_id"]} for r in db.all(
            "SELECT a.target_type, a.target_id, COALESCE(g.name, d.name) AS name FROM access_rules a "
            "LEFT JOIN user_groups g ON a.target_type = 'user_group' AND g.id = a.target_id "
            "LEFT JOIN device_groups d ON a.target_type = 'device_group' AND d.id = a.target_id "
            "WHERE a.subject_type = 'user_group' AND a.subject_id = ?", (target_id,))]
    return incomings, outgoings


def _resolve(db, item, kinds):
    """{"type", "name"} (or "id") -> (kind, id)."""
    if not isinstance(item, dict):
        raise HTTPError(400, "Access rules must be objects with type and name")
    kind = kinds.get(item.get("type"))
    if kind is None:
        raise HTTPError(400, f"Invalid access rule type {item.get('type')!r}")
    table = {"user_group": "user_groups", "device_group": "device_groups", "user": "users"}[kind]
    if isinstance(item.get("id"), int):
        row = db.one(f"SELECT id FROM {table} WHERE id = ?", (item["id"],))
    else:
        row = db.one(f"SELECT id FROM {table} WHERE name = ?", (str(item.get("name") or ""),))
    if row is None:
        raise HTTPError(400, f"{kind.replace('_', ' ').capitalize()} '{item.get('name')}' not found")
    return kind, row["id"]


def set_access(c, db, target_type, target_id, data):
    """Apply allowed_incomings / allowed_outgoings from REST or console input."""
    if "allowed_incomings" in data:
        c.execute("DELETE FROM access_rules WHERE target_type = ? AND target_id = ?", (target_type, target_id))
        for item in data["allowed_incomings"] or []:
            kind, sid = _resolve(db, item, {0: "user_group", 2: "user"})
            if not (kind == "user_group" and target_type == "user_group" and sid == target_id):
                c.execute("INSERT OR IGNORE INTO access_rules VALUES (?, ?, ?, ?)",
                          (kind, sid, target_type, target_id))
    if "allowed_outgoings" in data and target_type == "user_group":
        c.execute("DELETE FROM access_rules WHERE subject_type = 'user_group' AND subject_id = ?", (target_id,))
        for item in data["allowed_outgoings"] or []:
            kind, tid = _resolve(db, item, {0: "user_group", 1: "device_group"})
            if not (kind == "user_group" and tid == target_id):
                c.execute("INSERT OR IGNORE INTO access_rules VALUES ('user_group', ?, ?, ?)",
                          (target_id, kind, tid))


def group_payload(db, row, kind):
    incomings, outgoings = access_lists(db, kind, row["id"])
    data = {"guid": row["guid"], "name": row["name"], "note": row["note"],
            "allowed_incomings": incomings}
    if kind == "user_group":
        data["allowed_outgoings"] = outgoings
    return data


def _groups(app, req, kind):
    actor = token_actor(app, req)
    db = app.db
    actor.require(db, f"{kind}s.view")
    table = kind + "s"
    where, params = filters(req, {"name": "name"})
    sql = " AND ".join(["1"] + where)
    rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY name COLLATE NOCASE", params)
    return page([group_payload(db, r, kind) for r in rows], req)


def _create_group(app, req, kind):
    actor = token_actor(app, req)
    db = app.db
    actor.require(db, f"{kind}s.edit")
    data = req.json_object()
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 64:
        raise HTTPError(400, "Invalid name")
    try:
        with db.tx() as c:
            cur = c.execute(f"INSERT INTO {kind}s(guid, name, note, created_at) VALUES (?, ?, ?, ?)",
                            (models.new_guid(), name, str(data.get("note") or "")[:1024], now()))
            set_access(c, db, kind, cur.lastrowid, data)
    except HTTPError:
        raise
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPError(409, "Group already exists")
        raise
    log(app, req, f"{kind}.create", name)
    return ok_empty()


def _group_by_guid(app, actor, kind, guid, perm):
    actor.require(app.db, perm)
    row = app.db.one(f"SELECT * FROM {kind}s WHERE guid = ?", (guid,))
    if row is None:
        raise HTTPError(404, "Group not found")
    return row


def _update_group(app, req, kind, guid):
    actor = token_actor(app, req)
    row = _group_by_guid(app, actor, kind, guid, f"{kind}s.edit")
    data = req.json_object()
    db = app.db
    try:
        with db.tx() as c:
            if isinstance(data.get("name"), str) and data["name"].strip():
                c.execute(f"UPDATE {kind}s SET name = ? WHERE id = ?", (data["name"].strip()[:64], row["id"]))
            if "note" in data:
                c.execute(f"UPDATE {kind}s SET note = ? WHERE id = ?", (str(data["note"] or "")[:1024], row["id"]))
            set_access(c, db, kind, row["id"], data)
    except HTTPError:
        raise
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPError(409, "Group already exists")
        raise
    log(app, req, f"{kind}.update", row["name"], json.dumps(data))
    return ok_empty()


def delete_group(app, req, kind, row):
    with app.db.tx() as c:
        c.execute("DELETE FROM access_rules WHERE (target_type = ? AND target_id = ?) OR "
                  "(subject_type = ? AND subject_id = ?)", (kind, row["id"], kind, row["id"]))
        c.execute(f"DELETE FROM {kind}s WHERE id = ?", (row["id"],))
    log(app, req, f"{kind}.delete", row["name"])


@router.route("GET", "/api/user-groups")
def user_groups(app, req):
    return _groups(app, req, "user_group")


@router.route("POST", "/api/user-groups")
def user_group_create(app, req):
    return _create_group(app, req, "user_group")


@router.route("PATCH", "/api/user-groups/<guid>")
def user_group_update(app, req, guid):
    return _update_group(app, req, "user_group", guid)


@router.route("DELETE", "/api/user-groups/<guid>")
def user_group_delete(app, req, guid):
    actor = token_actor(app, req)
    delete_group(app, req, "user_group", _group_by_guid(app, actor, "user_group", guid, "user_groups.edit"))
    return ok_empty()


@router.route("POST", "/api/user-groups/<guid>")
def user_group_add_users(app, req, guid):
    actor = token_actor(app, req)
    group = _group_by_guid(app, actor, "user_group", guid, "users.change_group")
    guids = req.json([])
    if not isinstance(guids, list):
        raise HTTPError(400, "Expected a list of user GUIDs")
    for user_guid in guids:
        row = _user_by_guid(app, actor, str(user_guid), "users.change_group")
        app.db.run("UPDATE users SET group_id = ? WHERE id = ?", (group["id"], row["id"]))
    log(app, req, "user_group.update", group["name"], f"added {len(guids)} users")
    return ok_empty()


@router.route("GET", "/api/device-groups")
def device_groups(app, req):
    return _groups(app, req, "device_group")


@router.route("POST", "/api/device-groups")
def device_group_create(app, req):
    return _create_group(app, req, "device_group")


@router.route("PATCH", "/api/device-groups/<guid>")
def device_group_update(app, req, guid):
    return _update_group(app, req, "device_group", guid)


@router.route("DELETE", "/api/device-groups/<guid>")
def device_group_delete(app, req, guid):
    actor = token_actor(app, req)
    delete_group(app, req, "device_group", _group_by_guid(app, actor, "device_group", guid, "device_groups.edit"))
    return ok_empty()


def _device_ids(req):
    ids = req.json([])
    if not isinstance(ids, list):
        raise HTTPError(400, "Expected a list of device IDs")
    return [str(i) for i in ids]


@router.route("POST", "/api/device-groups/<guid>")
def device_group_add_devices(app, req, guid):
    actor = token_actor(app, req)
    group = _group_by_guid(app, actor, "device_group", guid, "devices.change_group")
    ids = _device_ids(req)
    missing = [i for i in ids if not app.db.one("SELECT 1 FROM devices WHERE id = ?", (i,))]
    if missing:
        raise HTTPError(400, "Devices not found: " + ", ".join(missing))
    for device_id in ids:
        app.db.run("UPDATE devices SET device_group_id = ? WHERE id = ?", (group["id"], device_id))
    log(app, req, "device_group.update", group["name"], "added " + ",".join(ids))
    return ok_empty()


@router.route("DELETE", "/api/device-groups/<guid>/devices")
def device_group_remove_devices(app, req, guid):
    actor = token_actor(app, req)
    group = _group_by_guid(app, actor, "device_group", guid, "devices.change_group")
    for device_id in _device_ids(req):
        app.db.run("UPDATE devices SET device_group_id = NULL WHERE id = ? AND device_group_id = ?",
                   (device_id, group["id"]))
    log(app, req, "device_group.update", group["name"], "removed devices")
    return ok_empty()


# -- strategies ----------------------------------------------------------------

def strategy_payload(db, row, full=False):
    data = {"guid": row["guid"], "name": row["name"], "note": row["note"],
            "enabled": bool(row["enabled"]), "modified_at": row["modified_at"]}
    if full:
        data["options"] = json.loads(row["options"] or "{}")
        data["peers"] = [r["id"] for r in db.all("SELECT id FROM devices WHERE strategy_id = ?", (row["id"],))]
        data["users"] = [r["name"] for r in db.all("SELECT name FROM users WHERE strategy_id = ?", (row["id"],))]
        data["groups"] = [r["name"] for r in db.all(
            "SELECT name FROM device_groups WHERE strategy_id = ?", (row["id"],))]
    return data


@router.route("GET", "/api/strategies")
def strategies(app, req):
    actor = token_actor(app, req)
    actor.require(app.db, "strategies.view")
    return json_response([strategy_payload(app.db, r) for r in app.db.all(
        "SELECT * FROM strategies ORDER BY name COLLATE NOCASE")])


@router.route("GET", "/api/strategies/<guid>")
def strategy(app, req, guid):
    actor = token_actor(app, req)
    actor.require(app.db, "strategies.view")
    row = app.db.one("SELECT * FROM strategies WHERE guid = ?", (guid,))
    if row is None:
        raise HTTPError(404, "Strategy not found")
    return json_response(strategy_payload(app.db, row, full=True))


@router.route("PUT", "/api/strategies/<guid>/status")
def strategy_status(app, req, guid):
    actor = token_actor(app, req)
    actor.require(app.db, "strategies.edit")
    enabled = req.json(None)
    if not isinstance(enabled, bool):
        raise HTTPError(400, "Body must be true or false")
    row = app.db.one("SELECT * FROM strategies WHERE guid = ?", (guid,))
    if row is None:
        raise HTTPError(404, "Strategy not found")
    app.db.run("UPDATE strategies SET enabled = ? WHERE id = ?", (int(enabled), row["id"]))
    log(app, req, "strategy.update", row["name"], "enabled" if enabled else "disabled")
    return ok_empty()


def assign_strategy(app, req, actor, strategy_id, peers=(), users=(), groups=()):
    """Set (or clear, with None) the strategy of devices, users and device groups,
    all given by GUID. Each target needs its own update permission."""
    db = app.db
    for table, guids, perm in (("devices", peers, "devices.change_strategy"),
                               ("users", users, "users.change_strategy"),
                               ("device_groups", groups, "device_groups.change_strategy")):
        if not guids:
            continue
        actor.require(db, perm)
        for guid in guids:
            if db.run(f"UPDATE {table} SET strategy_id = ? WHERE guid = ?", (strategy_id, str(guid))).rowcount == 0:
                raise HTTPError(400, f"Unknown GUID {guid}")
    log(app, req, "strategy.assign", strategy_id or "-", json.dumps(
        {"peers": list(peers), "users": list(users), "groups": list(groups)}))


@router.route("POST", "/api/strategies/assign")
def strategies_assign(app, req):
    actor = token_actor(app, req)
    data = req.json_object()
    strategy_id = None
    if data.get("strategy"):
        row = app.db.one("SELECT id FROM strategies WHERE guid = ?", (str(data["strategy"]),))
        if row is None:
            raise HTTPError(404, "Strategy not found")
        strategy_id = row["id"]
    assign_strategy(app, req, actor, strategy_id, data.get("peers") or [], data.get("users") or [],
                    data.get("groups") or [])
    return ok_empty()


# -- audits ----------------------------------------------------------------------

def _since(value):
    """Pro's created_at filter: a UTC "YYYY-MM-DD HH:MM:SS[.fff]" lower bound."""
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.datetime.strptime(value, fmt).replace(tzinfo=datetime.timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise HTTPError(400, "created_at must look like 2025-09-16 14:15:57")


def audit_rows(app, actor, kind, query):
    """Shared by the REST API (Pro field names) and the console."""
    db = app.db
    scope = actor.require(db, "audits.view")
    table, time_col = {"conn": ("conn_logs", "started_at"), "file": ("file_logs", "created_at"),
                       "alarm": ("alarm_logs", "created_at"), "console": ("console_logs", "created_at")}[kind]
    where, params = ["1"], []
    if not scope.everything:
        if kind == "console":
            where.append("user_id IN (%s)" % ",".join("?" * len(scope.own_users or {0})))
            params += sorted(scope.own_users or {0})
        else:
            # Personal logs (Pro): records whose device on either side is in
            # scope, and connections the user made while logged in.
            cond, cparams = scope.device_sql("d")
            sides = "device_id" if kind == "alarm" else "device_id, peer_id"
            mine = f"EXISTS (SELECT 1 FROM devices d WHERE d.id IN ({sides}) AND {cond})"
            params += list(cparams)
            if kind == "conn" and actor.user is not None:
                mine = f"({mine} OR controller = ?)"
                params.append(actor.user["name"])
            where.append(mine)
    if query.get("created_at"):
        where.append(f"{time_col} >= ?")
        params.append(_since(query["created_at"]))
    for key, op in (("from", ">="), ("to", "<")):
        if str(query.get(key) or "").isdigit():
            where.append(f"{time_col} {op} ?")
            params.append(int(query[key]))
    remote = query.get("remote")
    if remote and kind in ("conn", "file"):
        where.append("peer_id LIKE ?")
        params.append(models.like(remote))
    if kind == "conn" and str(query.get("conn_type") or "").isdigit():
        where.append("type = ?")
        params.append(int(query["conn_type"]))
    if query.get("device") and kind != "console":
        where.append("device_id LIKE ?")
        params.append(models.like(query["device"]))
    if query.get("operator") and kind == "console":
        where.append("user_name LIKE ?")
        params.append(models.like(query["operator"]))
    return table, " AND ".join(where), params


def rest_audit(db, kind, r):
    if kind == "conn":
        data = {"id": r["device_id"], "guid": str(r["id"]), "remote": r["peer_id"], "peer_name": r["peer_name"],
                "ip": r["ip"], "user": r["controller"], "note": r["note"], "created_at": r["started_at"],
                "end_time": r["ended_at"], "primary_auth": r["primary_auth"], "two_factor": r["two_factor"]}
        if r["type"] is not None and r["authorized_at"]:
            data["conn_type"] = r["type"]
        return data
    if kind == "file":
        return {"id": r["device_id"], "remote": r["peer_id"], "type": r["type"], "path": r["path"],
                "is_file": bool(r["is_file"]), "info": json.loads(r["info"] or "{}"), "created_at": r["created_at"]}
    if kind == "alarm":
        return {"device": r["device_id"], "typ": r["typ"], "info": json.loads(r["info"] or "{}"),
                "ip": r["ip"], "created_at": r["created_at"]}
    data = {"operator": r["user_name"], "action": r["action"], "target": r["target"], "detail": r["detail"],
            "ip": r["ip"], "created_at": r["created_at"]}
    if r["typ"] is not None:
        data["typ"] = r["typ"]
    if r["iop"] is not None:
        data["iop"] = r["iop"]
    return data


@router.route("GET", "/api/audits/<kind>")
def audits(app, req, kind):
    if kind not in ("conn", "file", "alarm", "console"):
        raise HTTPError(404, "Unknown audit log")
    actor = token_actor(app, req)
    current, size = page_args(req)
    table, sql, params = audit_rows(app, actor, kind, req.query)
    db = app.db
    total = db.one(f"SELECT COUNT(*) AS n FROM {table} WHERE {sql}", params)["n"]
    rows = db.all(f"SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                  params + [size, (current - 1) * size])
    return json_response({"total": total, "data": [rest_audit(db, kind, r) for r in rows]})

