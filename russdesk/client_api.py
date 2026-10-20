"""The HTTP API that RustDesk clients call (the "API server" setting).

Endpoints and payloads follow what the open-source RustDesk client sends and
expects; see docs/client-protocol.md. The address book endpoints also accept
API tokens and the GET forms used by RustDesk Server Pro's `ab.py` script."""

import json
import os
import re

from . import auth, models
from .auth import LoginError
from .authz import Actor
from .db import now
from .models import RULE_FULL, RULE_READ, RULE_READ_WRITE, loads
from .security import new_token, token_hash
from .web import HTTPError, Response, Router, json_response

router = Router()

# Kept for callers (tests, app maintenance) that reset or inspect the limiter.
login_failures = auth.login_failures

RECORDING_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,199}\.(webm|mkv|mp4)$")
NEVER = 253402300799  # 9999-12-31


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

def client_expiry(db):
    """Client logins last until logout or revocation unless a lifetime is set."""
    days = db.setting("client_token_days")
    return now() + days * 86400 if days else NEVER


def client_user(app, req):
    """The user behind a client login token."""
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
    req.actor = Actor(user=row)
    return row


def api_token(app, req):
    """The API token (Settings > Tokens) in the Authorization header, or None."""
    token = req.bearer()
    if not token:
        return None
    row = app.db.one("SELECT * FROM api_tokens WHERE token_hash = ?", (token_hash(token),))
    if row is None:
        return None
    if row["expires_at"] and row["expires_at"] < now():
        raise HTTPError(401, "API token expired")
    if not row["last_used_at"] or now() - row["last_used_at"] > 60:
        app.db.run("UPDATE api_tokens SET last_used_at = ? WHERE id = ?", (now(), row["id"]))
    return row


def bearer_actor(app, req):
    """An API token or a client login, for endpoints both may call."""
    token = api_token(app, req)
    if token is not None:
        creator = app.db.one("SELECT * FROM users WHERE id = ?", (token["user_id"],)) \
            if token["user_id"] else None
        req.user = creator
        req.actor = Actor(user=creator, token=token)
        return req.actor
    client_user(app, req)
    return req.actor


def _issue_client_token(app, req, user, data):
    db = app.db
    token = new_token()
    device_id = data.get("id") if isinstance(data.get("id"), str) else ""
    device_uuid = data.get("uuid") if isinstance(data.get("uuid"), str) else ""
    info = data.get("deviceInfo") if isinstance(data.get("deviceInfo"), dict) else {}
    with db.tx() as c:
        c.execute(
            "INSERT INTO tokens(token_hash, user_id, kind, device_id, device_uuid, device_info, ip, "
            "created_at, last_seen_at, expires_at) VALUES (?, ?, 'client', ?, ?, ?, ?, ?, ?, ?)",
            (token_hash(token), user["id"], device_id[:64], device_uuid[:128],
             json.dumps(info)[:2048], req.ip, now(), now(), client_expiry(db)),
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


def console_url(app, req):
    url = app.db.setting("console_url")
    if url:
        return url.rstrip("/")
    host = req.headers.get("Host") or ""
    return f"{req.scheme}://{host}" if host else ""


@router.route("POST", "/api/login")
def login(app, req):
    data = req.json_object()
    kind = data.get("type") or "account"
    try:
        if kind == "account":
            user = auth.check_password(app, req, data.get("username"), data.get("password"),
                                       data.get("id") if isinstance(data.get("id"), str) else "")
            if auth.needs_2fa_setup(user):
                return error("Two-factor authentication is required for this account. Set it up in "
                             f"the web console first: {console_url(app, req)}")
            method = auth.second_factor(user)
            if method is None:
                return _issue_client_token(app, req, user, data)
            secret = auth.start_challenge(app, user, method)
            resp = {"type": "email_check", "secret": secret, "user": models.user_payload(user)}
            if method == "totp":
                resp["tfa_type"] = "tfa_check"
            return json_response(resp)
        if kind in ("email_code", "tfa_code"):
            code = str(data.get("tfaCode") or data.get("verificationCode") or "")
            user = auth.finish_challenge(app, req, str(data.get("secret") or ""), code)
            return _issue_client_token(app, req, user, data)
    except LoginError as exc:
        return error(str(exc))
    except HTTPError as exc:  # e.g. the login email could not be sent
        return error(exc.message)
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
    options, stamp = models.desired_config(db, device)
    if stamp != client_stamp:
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
        apply_assignments(c, device, {
            "user_name": data.get("preset-user-name"),
            "device_group_name": data.get("preset-device-group-name"),
            "strategy_name": data.get("preset-strategy-name"),
            "address_book_name": data.get("preset-address-book-name"),
            "address_book_tag": data.get("preset-address-book-tag"),
            "address_book_alias": data.get("preset-address-book-alias"),
            "address_book_password": data.get("preset-address-book-password"),
            "address_book_note": data.get("preset-address-book-note"),
            "note": data.get("preset-note"),
        }, keep_existing=True)
    return text("SYSINFO_UPDATED")


def apply_assignments(c, device, values, keep_existing):
    """Assign a device to a user, group, strategy and address book by name:
    preset-* options in custom clients (keep_existing: never override the
    console) and `rustdesk --assign` (override). Returns a list of errors."""
    errors = []
    device_id = device["id"]

    def given(key):
        v = values.get(key)
        return v.strip() if isinstance(v, str) and v.strip() else None

    for key, table, column in (("user_name", "users", "user_id"),
                               ("device_group_name", "device_groups", "device_group_id"),
                               ("strategy_name", "strategies", "strategy_id")):
        name = given(key)
        if name is None or (keep_existing and device[column]):
            continue
        row = c.execute(f"SELECT id FROM {table} WHERE name = ?", (name,)).fetchone()
        if row is None:
            errors.append(f"{key.replace('_name', '').replace('_', ' ')} '{name}' not found")
        else:
            c.execute(f"UPDATE devices SET {column} = ? WHERE id = ?", (row["id"], device_id))
    for key, column in (("note", "note"), ("device_username", "username_override"),
                        ("device_name", "name_override")):
        value = given(key)
        if value is not None and not (keep_existing and device[column]):
            c.execute(f"UPDATE devices SET {column} = ? WHERE id = ?", (value[:1024], device_id))
    name = given("address_book_name")
    if name:
        book = c.execute("SELECT guid FROM address_books WHERE name = ? AND personal = 0 "
                         "ORDER BY created_at LIMIT 1", (name,)).fetchone()
        if book is None:
            errors.append(f"address book '{name}' not found")
        else:
            existing = c.execute("SELECT deleted_at FROM ab_peers WHERE guid = ? AND peer_id = ?",
                                 (book["guid"], device_id)).fetchone()
            if existing is None or existing["deleted_at"] or not keep_existing:
                peer = {"id": device_id}
                tag = given("address_book_tag")
                if tag:
                    c.execute("INSERT OR IGNORE INTO ab_tags(guid, name, color) VALUES (?, ?, ?)",
                              (book["guid"], tag[:64], 0xFF2196F3))
                    peer["tags"] = [tag[:64]]
                for key, target in (("address_book_alias", "alias"),
                                    ("address_book_password", "password"),
                                    ("address_book_note", "note")):
                    if given(key):
                        peer[target] = given(key)
                models.upsert_peer(c, book["guid"], peer, personal=False)
    return errors


@router.route("POST", "/api/sysinfo_ver")
def sysinfo_ver(app, req):
    return text(app.db.meta("instance_id"))


@router.route("POST", "/api/devices/cli")
def devices_cli(app, req):
    """`rustdesk --assign --token <API token> ...` (Pro's command-line assign).
    The client prints the body: empty means "Done!"."""
    token = api_token(app, req)
    if token is None:
        return text("Invalid token")
    req.actor = Actor(token=token)
    if not req.actor.can(app.db, "devices.edit_info"):
        return text("The token needs Device read/write permission")
    data = req.json_object()
    device_id, device_uuid = device_id_of(data)
    with app.db.tx() as c:
        device = models.ensure_device(c, device_id, device_uuid, req.ip)
        errors = apply_assignments(c, device, data, keep_existing=False)
    req.user = None
    models.console_log(app.db, req, "device.update", device_id, "assigned from the command line")
    return text("; ".join(errors))


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
    session_id = str(data.get("session_id") or "")[:64]
    conn_id = _int(data.get("conn_id"))
    if conn_id is None:
        # The controlling side's session note: {"id": <controlled device>,
        # "session_id", "note"} (ui_session_interface.rs send_note).
        if "note" in data:
            app.db.run("UPDATE conn_logs SET note = ? WHERE id = (SELECT id FROM conn_logs "
                       "WHERE device_id = ? AND session_id = ? ORDER BY id DESC LIMIT 1)",
                       (str(data.get("note") or "")[:1024], device_id, session_id))
            return ok_empty()
        raise HTTPError(400, "Missing conn_id")
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
                      _int(data.get("two_factor")), now(), models.controller_of(app.db, peer_id))
            if open_row:
                c.execute("UPDATE conn_logs SET peer_id=?, peer_name=?, type=?, primary_auth=?, "
                          "two_factor=?, authorized_at=?, controller=?, "
                          "session_id = COALESCE(NULLIF(?, ''), session_id) WHERE id = ?",
                          values + (session_id, open_row["id"]))
            else:
                c.execute("INSERT INTO conn_logs(peer_id, peer_name, type, primary_auth, two_factor, "
                          "authorized_at, controller, device_id, conn_id, session_id, started_at) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
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


# -- accessible users, devices and groups (the client's group tab) ------------

@router.route("GET", "/api/users")
def users(app, req):
    """Client: accessible users. API token: Pro's user list (users.py)."""
    actor = bearer_actor(app, req)
    db = app.db
    current, size = page_args(req)
    where, params = ["1"], []
    if actor.token is not None:
        actor.require(db, "users.view")
    elif db.setting("disable_accessible_devices"):
        return json_response({"total": 0, "data": []})
    else:
        ids = models.accessible_users(db, actor.user)
        if ids is not None:
            where.append(f"u.id IN ({','.join('?' * len(ids))})")
            params += sorted(ids)
    if req.query.get("status") == "1":
        where.append("u.status = 1")
    for key, column in (("name", "u.name"), ("group_name", "g.name")):
        if req.query.get(key):
            where.append(f"{column} LIKE ?")
            params.append(models.like(req.query[key]))
    sql = " AND ".join(where)
    joins = "FROM users u LEFT JOIN user_groups g ON g.id = u.group_id"
    total = db.one(f"SELECT COUNT(*) AS n {joins} WHERE {sql}", params)["n"]
    rows = db.all(f"SELECT u.*, g.name AS gname {joins} WHERE {sql} ORDER BY u.name COLLATE NOCASE "
                  "LIMIT ? OFFSET ?", params + [size, (current - 1) * size])
    return json_response({"total": total,
                          "data": [models.user_payload(r, r["gname"] or "") for r in rows]})


@router.route("GET", "/api/peers")
def peers(app, req):
    user = client_user(app, req)
    db = app.db
    current, size = page_args(req)
    if db.setting("disable_accessible_devices"):
        return json_response({"total": 0, "data": []})
    cond, params = models.accessible_sql(models.accessible_scope(db, user))
    total = db.one(f"SELECT COUNT(*) AS n FROM devices d WHERE {cond}", params)["n"]
    rows = db.all(
        f"SELECT d.*, u.name AS owner, g.name AS group_name FROM devices d "
        f"LEFT JOIN users u ON u.id = d.user_id LEFT JOIN device_groups g ON g.id = d.device_group_id "
        f"WHERE {cond} ORDER BY d.id LIMIT ? OFFSET ?", params + (size, (current - 1) * size))
    data = [{
        "id": r["id"],
        "info": {"device_name": r["name_override"] or r["hostname"], "os": r["os"],
                 "username": r["username_override"] or r["username"]},
        "status": 1,
        "user": r["owner"] or "",
        "user_name": r["owner"] or "",
        "device_group_name": r["group_name"] or "",
        "note": r["note"],
    } for r in rows]
    return json_response({"total": total, "data": data})


@router.route("GET", "/api/device-group/accessible")
def device_groups_accessible(app, req):
    user = client_user(app, req)
    db = app.db
    current, size = page_args(req)
    if db.setting("disable_accessible_devices"):
        return json_response({"total": 0, "data": []})
    scope = models.accessible_scope(db, user)
    if scope is None:
        rows = db.all("SELECT name FROM device_groups ORDER BY name COLLATE NOCASE")
    else:
        ids = scope[1]
        rows = db.all(f"SELECT name FROM device_groups WHERE id IN ({','.join('?' * len(ids))}) "
                      "ORDER BY name COLLATE NOCASE", tuple(sorted(ids))) if ids else []
    page = rows[(current - 1) * size:current * size]
    return json_response({"total": len(rows), "data": [{"name": r["name"]} for r in page]})


# -- address books -------------------------------------------------------------

def _rule(app, actor, guid):
    """The actor's rule on a book; API tokens get their Address Book level."""
    if actor.token is not None:
        book = app.db.one("SELECT personal, owner_id FROM address_books WHERE guid = ?", (guid,))
        if book is None:
            return 0
        if book["personal"] and book["owner_id"] != (actor.user["id"] if actor.user else None):
            return 0
        return {0: 0, 1: RULE_READ}.get(actor.ab_level(), RULE_FULL)
    return models.book_rule(app.db, actor.user, guid)


def _book(app, req, guid, need):
    actor = bearer_actor(app, req)
    rule = _rule(app, actor, guid)
    if rule < need:
        raise HTTPError(403, "No permission for this address book")
    book = app.db.one("SELECT * FROM address_books WHERE guid = ?", (guid,))
    return actor, book, bool(book["personal"])


def action_result(err):
    return error(err) if err else ok_empty()


@router.route("POST", "/api/ab/settings")
def ab_settings(app, req):
    bearer_actor(app, req)
    return json_response({"max_peer_one_ab": app.db.setting("max_peers_per_ab")})


def ab_personal(app, req):
    actor = bearer_actor(app, req)
    if actor.user is None:
        raise HTTPError(400, "This token has no user, so it has no personal address book")
    return json_response({"guid": models.personal_book(app.db, actor.user["id"])})


router.add("POST", "/api/ab/personal", ab_personal)
router.add("GET", "/api/ab/personal", ab_personal)


def ab_shared_profiles(app, req):
    actor = bearer_actor(app, req)
    current, size = page_args(req)
    db = app.db
    if actor.token is not None:
        if not actor.ab_level():
            raise HTTPError(403, "The token has no Address Book permission")
        rule = RULE_FULL if actor.ab_level() >= 2 else RULE_READ
        books = [dict(r, rule=rule) for r in db.all(
            "SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id "
            "WHERE b.personal = 0 ORDER BY b.name COLLATE NOCASE")]
    else:
        books = models.shared_books_for(db, actor.user)
    name = req.query.get("name")
    if name:
        pattern = re.compile("^" + ".*".join(map(re.escape, name.split("%"))) + "$", re.I)
        books = [b for b in books if pattern.match(b["name"])]
    page = books[(current - 1) * size:current * size]
    return json_response({"total": len(books), "data": [models.profile_payload(b, b["rule"]) for b in page]})


router.add("POST", "/api/ab/shared/profiles", ab_shared_profiles)
router.add("GET", "/api/ab/shared/profiles", ab_shared_profiles)


def ab_peers(app, req):
    guid = req.query.get("ab") or ""
    _, _, personal = _book(app, req, guid, RULE_READ)
    current, size = page_args(req)
    where, params = ["guid = ?", "deleted_at IS NULL"], [guid]
    for key, column in (("id", "peer_id"), ("alias", "alias")):
        if req.query.get(key):
            where.append(f"{column} LIKE ?")
            params.append(models.like(req.query[key]))
    sql = " AND ".join(where)
    total = app.db.one(f"SELECT COUNT(*) AS n FROM ab_peers WHERE {sql}", params)["n"]
    rows = app.db.all(f"SELECT * FROM ab_peers WHERE {sql} ORDER BY created_at, peer_id "
                      "LIMIT ? OFFSET ?", params + [size, (current - 1) * size])
    return json_response({"total": total,
                          "data": [models.peer_payload(app.db, r, personal) for r in rows]})


router.add("POST", "/api/ab/peers", ab_peers)
router.add("GET", "/api/ab/peers", ab_peers)


def ab_tags(app, req, guid):
    _book(app, req, guid, RULE_READ)
    rows = app.db.all("SELECT name, color FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))
    return json_response([{"name": r["name"], "color": r["color"]} for r in rows])


router.add("POST", "/api/ab/tags/<guid>", ab_tags)
router.add("GET", "/api/ab/tags/<guid>", ab_tags)


@router.route("POST", "/api/ab/peer/add/<guid>")
def ab_peer_add(app, req, guid):
    _, _, personal = _book(app, req, guid, RULE_READ_WRITE)
    peer = req.json_object()
    limit = app.db.setting("max_peers_per_ab")
    with app.db.tx() as c:
        if limit and c.execute("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ? AND deleted_at IS NULL",
                               (guid,)).fetchone()["n"] >= limit:
            return error("exceed_max_devices")
        return action_result(models.upsert_peer(c, guid, peer, personal))


@router.route("PUT", "/api/ab/peer/update/<guid>")
def ab_peer_update(app, req, guid):
    _, _, personal = _book(app, req, guid, RULE_READ_WRITE)
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
        models.recycle_peers(c, guid, ids)
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


# Shared book management (Pro's ab.py: add-ab, update-ab, delete-ab, rules)

def _info_password(data):
    info = data.get("info")
    if isinstance(info, dict) and "password" in info:
        return str(info.get("password") or "")[:1024]
    return None


@router.route("POST", "/api/ab/shared/add")
def ab_shared_add(app, req):
    actor = bearer_actor(app, req)
    if actor.token is not None and actor.ab_level() < 2:
        raise HTTPError(403, "The token needs Address Book read/write permission")
    if actor.user is None:
        raise HTTPError(400, "This token has no owner user")
    data = req.json_object()
    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 64:
        raise HTTPError(400, "Invalid name")
    guid = models.new_guid()
    app.db.run("INSERT INTO address_books(guid, name, owner_id, personal, note, password, created_at) "
               "VALUES (?, ?, ?, 0, ?, ?, ?)",
               (guid, name.strip(), actor.user["id"], str(data.get("note") or "")[:1024],
                _info_password(data) or "", now()))
    models.console_log(app.db, req, "address_book.create", name)
    return json_response({"guid": guid})


@router.route("PUT", "/api/ab/shared/update/profile")
def ab_shared_update(app, req):
    data = req.json_object()
    guid = str(data.get("guid") or "")
    actor, book, personal = _book(app, req, guid, RULE_FULL)
    if personal:
        raise HTTPError(400, "A personal address book cannot be changed here")
    db = app.db
    if isinstance(data.get("name"), str) and data["name"].strip():
        db.run("UPDATE address_books SET name = ? WHERE guid = ?", (data["name"].strip()[:64], guid))
        models.console_log(db, req, "address_book.rename", data["name"])
    if "note" in data:
        db.run("UPDATE address_books SET note = ? WHERE guid = ?", (str(data["note"] or "")[:1024], guid))
    if _info_password(data) is not None:
        db.run("UPDATE address_books SET password = ? WHERE guid = ?", (_info_password(data), guid))
    if isinstance(data.get("owner"), str) and data["owner"]:
        owner = db.one("SELECT id FROM users WHERE name = ?", (data["owner"],))
        if owner is None:
            raise HTTPError(400, "Owner not found")
        db.run("UPDATE address_books SET owner_id = ? WHERE guid = ?", (owner["id"], guid))
    return ok_empty()


@router.route("DELETE", "/api/ab/shared")
def ab_shared_delete(app, req):
    guids = req.json([])
    if not isinstance(guids, list):
        raise HTTPError(400, "Expected a list of address book GUIDs")
    for guid in guids:
        _, book, personal = _book(app, req, str(guid), RULE_FULL)
        if not personal:
            app.db.run("DELETE FROM address_books WHERE guid = ?", (guid,))
            models.console_log(app.db, req, "address_book.delete", book["name"])
    return ok_empty()


def rule_payload(r):
    return {"guid": r["rule_guid"], "user": r["uname"], "group": r["gname"],
            "everyone": bool(r["everyone"]), "rule": r["rule"]}


RULES_SQL = ("SELECT r.*, u.name AS uname, g.name AS gname FROM ab_rules r "
             "LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.user_group_id ")


@router.route("GET", "/api/ab/rules")
def ab_rules(app, req):
    guid = req.query.get("ab") or ""
    _book(app, req, guid, RULE_FULL)
    current, size = page_args(req)
    rows = app.db.all(RULES_SQL + "WHERE r.guid = ? ORDER BY r.id", (guid,))
    page = rows[(current - 1) * size:current * size]
    return json_response({"total": len(rows), "data": [rule_payload(r) for r in page]})


@router.route("POST", "/api/ab/rule")
def ab_rule_add(app, req):
    data = req.json_object()
    guid = str(data.get("guid") or "")
    actor, _, personal = _book(app, req, guid, RULE_FULL)
    if personal:
        raise HTTPError(400, "A personal address book cannot be shared")
    rule = data.get("rule")
    if rule not in (1, 2, 3):
        raise HTTPError(400, "Invalid rule")
    db = app.db
    user_id = group_id = None
    if data.get("user"):
        row = db.one("SELECT id FROM users WHERE name = ?", (str(data["user"]),))
        if row is None:
            raise HTTPError(400, "User not found")
        user_id = row["id"]
    elif data.get("group"):
        row = db.one("SELECT id FROM user_groups WHERE name = ?", (str(data["group"]),))
        if row is None:
            raise HTTPError(400, "Group not found")
        group_id = row["id"]
    check_share_target(app, actor, user_id, group_id, everyone=not (user_id or group_id))
    try:
        db.run("INSERT INTO ab_rules(rule_guid, guid, user_id, user_group_id, everyone, rule) "
               "VALUES (?, ?, ?, ?, ?, ?)",
               (models.new_guid(), guid, user_id, group_id, 0 if (user_id or group_id) else 1, rule))
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPError(409, "A rule for this target already exists")
        raise
    models.console_log(db, req, "address_book.rule_add", guid, json.dumps(data))
    return ok_empty()


def check_share_target(app, actor, user_id, group_id, everyone):
    """Settings > Others: unless allowed, non-admins share only inside their
    own group (Pro: Allow non-admin to share address books to other groups)."""
    if actor.token is not None or actor.is_admin or app.db.setting("allow_non_admin_share"):
        return
    own = actor.user["group_id"]
    if everyone:
        raise HTTPError(403, "Only administrators can share an address book with everyone")
    if group_id and group_id != own:
        raise HTTPError(403, "You can only share with your own group")
    if user_id:
        row = app.db.one("SELECT group_id FROM users WHERE id = ?", (user_id,))
        if row is None or row["group_id"] != own:
            raise HTTPError(403, "You can only share with users in your own group")


@router.route("PATCH", "/api/ab/rule")
def ab_rule_update(app, req):
    data = req.json_object()
    row = app.db.one("SELECT * FROM ab_rules WHERE rule_guid = ?", (str(data.get("guid") or ""),))
    if row is None:
        raise HTTPError(404, "Rule not found")
    _book(app, req, row["guid"], RULE_FULL)
    if data.get("rule") not in (1, 2, 3):
        raise HTTPError(400, "Invalid rule")
    app.db.run("UPDATE ab_rules SET rule = ? WHERE id = ?", (data["rule"], row["id"]))
    models.console_log(app.db, req, "address_book.rule_update", row["guid"], json.dumps(data))
    return ok_empty()


@router.route("DELETE", "/api/ab/rules")
def ab_rules_delete(app, req):
    guids = req.json([])
    if not isinstance(guids, list):
        raise HTTPError(400, "Expected a list of rule GUIDs")
    for rule_guid in guids:
        row = app.db.one("SELECT * FROM ab_rules WHERE rule_guid = ?", (str(rule_guid),))
        if row is None:
            continue
        _book(app, req, row["guid"], RULE_FULL)
        app.db.run("DELETE FROM ab_rules WHERE id = ?", (row["id"],))
        models.console_log(app.db, req, "address_book.rule_delete", row["guid"])
    return ok_empty()


# Legacy single address book (clients older than 1.2.4 / servers without
# /api/ab/personal). Mapped onto the user's personal book.

@router.route("GET", "/api/ab")
def ab_legacy_get(app, req):
    user = client_user(app, req)
    guid = models.personal_book(app.db, user["id"])
    tags = app.db.all("SELECT name, color FROM ab_tags WHERE guid = ? ORDER BY rowid", (guid,))
    peers_ = [models.peer_payload(app.db, r, True) for r in app.db.all(
        "SELECT * FROM ab_peers WHERE guid = ? AND deleted_at IS NULL ORDER BY created_at", (guid,))]
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
    cap = settings["recordings_max_mb"] * 1024 * 1024
    if kind == "new":
        used = db.one("SELECT COALESCE(SUM(size), 0) AS n FROM recordings")["n"]
        if used > cap:
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
        if used + len(req.body) > cap:
            raise HTTPError(507, "Recording storage is full")
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(req.body)
    size = os.path.getsize(path)
    db.run("UPDATE recordings SET size = ?, completed_at = ? WHERE id = ?",
           (size, now() if kind == "tail" else None, row["id"]))
    return json_response({})
