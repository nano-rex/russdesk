"""Domain logic shared by the client API, the console API and the REST API."""

import hashlib
import json
import uuid

from .db import now

ONLINE_SECONDS = 45  # clients heartbeat every 15 s when idle

RULE_READ, RULE_READ_WRITE, RULE_FULL = 1, 2, 3

# Pro's names, as shown in its console and printed by audits.py
CONN_TYPES = {0: "Remote Desktop", 1: "File Transfer", 2: "Port Transfer",
              3: "View Camera", 4: "Terminal"}
PRIMARY_AUTH = {1: "Click Confirmation", 2: "One-time Password",
                3: "Permanent Password", 4: "Switch Sides"}
TWO_FACTOR = {1: "2FA Code", 2: "Trusted Device"}
FILE_TYPES = {0: "Controlling Side -> Controlled Device", 1: "Controlled Device -> Controlling Side"}
ALARM_TYPES = {
    0: "Access attempt outside the IP whitelist",
    1: "Over 30 consecutive access attempts",
    2: "Multiple access attempts within one minute",
    3: "Over 30 consecutive login attempts",
    4: "Multiple login attempts within one minute",
    5: "Multiple login attempts within one hour",
    6: "Too many consecutive access attempts from a single IPv6 prefix",
    7: "Multiple failed Terminal (Run as administrator) login attempts",
    8: "Multiple simultaneous Terminal (Run as administrator) login attempts",
    9: "Session scope violation",
    10: "Access attempt outside the ID whitelist",
}
LOGIN_ALARMS = (3, 4, 5)

# Console audit categories and operations, numbered like Pro (audits.py).
CONSOLE_TYPES = {0: "Group Management", 1: "User Management", 2: "Device Management",
                 3: "Address Book Management", 4: "Admin Role Management", 5: "Settings"}
CONSOLE_OPS = {
    "login": (1, 0), "user_group.create": (0, 1), "device_group.create": (0, 1),
    "user.create": (1, 2), "user.invite": (1, 2), "user_group.delete": (0, 4),
    "device_group.delete": (0, 4), "device.disconnect": (2, 5), "user.enable": (1, 6),
    "user.disable": (1, 7), "device.enable": (2, 8), "device.disable": (2, 9),
    "user_group.update": (0, 10), "device_group.update": (0, 10), "user.update": (1, 11),
    "device.update": (2, 12), "user.delete": (1, 13), "device.delete": (2, 14),
    "address_book.create": (3, 15), "address_book.delete": (3, 16),
    "address_book.rename": (3, 17), "address_book.recycle_delete": (3, 18),
    "address_book.recycle_empty": (3, 19), "address_book.rule_add": (3, 20),
    "address_book.rule_delete": (3, 21), "address_book.rule_update": (3, 22),
}
CONSOLE_OP_NAMES = {
    0: "User Login", 1: "Add Group", 2: "Add User", 3: "Add Device", 4: "Delete Groups",
    5: "Disconnect Device", 6: "Enable Users", 7: "Disable Users", 8: "Enable Devices",
    9: "Disable Devices", 10: "Update Group", 11: "Update User", 12: "Update Device",
    13: "Delete User", 14: "Delete Device", 15: "Add Address Book", 16: "Delete Address Book",
    17: "Change Address Book Name", 18: "Delete Devices in the Address Book Recycle Bin",
    19: "Empty Address Book Recycle Bin", 20: "Add Address Book Permission",
    21: "Delete Address Book Permission", 22: "Update Address Book Permission",
}

# Pushed as the device's IP whitelist while it is disabled: no address
# matches it, so the client refuses every incoming connection.
BLOCK_WHITELIST = "255.255.255.255/32"


def loads(text, default=None):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def new_guid():
    return str(uuid.uuid4())


def is_online(device_row, at=None):
    seen = device_row["last_seen_at"]
    return bool(seen) and (at or now()) - seen <= ONLINE_SECONDS


def platform_of(os_text):
    """Map sysinfo's "os" field to the platform names the client uses."""
    first = (os_text or "").split(" / ")[0].lower()
    if first == "windows":
        return "Windows"
    if first == "macos":
        return "Mac OS"
    if first == "android":
        return "Android"
    if first == "linux" or "linux" in (os_text or "").lower():
        return "Linux"
    return ""


def like(value):
    """Pro's REST filters: '%' wildcards pass through; '-' means empty."""
    if value == "-":
        return ""
    return value


# -- users ---------------------------------------------------------------------

def user_status(row):
    """1 normal, 0 disabled, -1 unverified (invited, no password yet)."""
    return row["status"]


def user_payload(row, group_name=None):
    """The user object the RustDesk client expects (UserPayload), plus the
    fields Pro's REST API returns."""
    data = {
        "guid": row["guid"],
        "name": row["name"],
        "display_name": row["display_name"],
        "email": row["email"],
        "note": row["note"],
        "status": row["status"],
        "is_admin": bool(row["is_admin"]),
        "info": {},
    }
    if group_name is not None:
        data["group_name"] = group_name
    return data


def rules_for(db, user):
    """Access targets granted to a user directly or through their group."""
    rows = db.all(
        "SELECT target_type, target_id FROM access_rules WHERE "
        "(subject_type = 'user' AND subject_id = ?) OR (subject_type = 'user_group' AND subject_id = ?)",
        (user["id"], user["group_id"] or -1))
    user_groups = {r["target_id"] for r in rows if r["target_type"] == "user_group"}
    device_groups = {r["target_id"] for r in rows if r["target_type"] == "device_group"}
    return user_groups, device_groups


def accessible_scope(db, user):
    """(user_ids, device_group_ids) whose devices the user may connect to, or
    None for everything (administrators). This is Pro's Access Control."""
    if user["is_admin"]:
        return None
    user_groups, device_groups = rules_for(db, user)
    if user["group_id"]:
        user_groups.add(user["group_id"])
    user_ids = {user["id"]}
    if user_groups:
        marks = ",".join("?" * len(user_groups))
        user_ids |= {r["id"] for r in db.all(f"SELECT id FROM users WHERE group_id IN ({marks})",
                                             tuple(user_groups))}
    return user_ids, device_groups


def accessible_sql(scope, alias="d"):
    """Devices in an access scope that are not disabled (nor their user)."""
    blocked = (f"{alias}.disabled = 0 AND NOT EXISTS (SELECT 1 FROM users bu "
               f"WHERE bu.id = {alias}.user_id AND bu.status = 0)")
    if scope is None:
        return blocked, ()
    user_ids, device_groups = scope
    parts, params = [], []
    if user_ids:
        parts.append(f"{alias}.user_id IN ({','.join('?' * len(user_ids))})")
        params.extend(sorted(user_ids))
    if device_groups:
        parts.append(f"{alias}.device_group_id IN ({','.join('?' * len(device_groups))})")
        params.extend(sorted(device_groups))
    return "(" + (" OR ".join(parts) or "0") + f") AND {blocked}", tuple(params)


def accessible_users(db, user):
    """Users shown in the client's group tab."""
    if user["is_admin"]:
        return None
    return accessible_scope(db, user)[0]


# -- strategies ----------------------------------------------------------------

def effective_strategy(db, device):
    """(strategy row or None, source). Pro's priority: the device's own
    strategy, then its user's, then its device group's. If the strategy that
    applies is disabled the device is not managed by any strategy."""
    sid, source = device["strategy_id"], "device"
    if not sid and device["user_id"]:
        row = db.one("SELECT strategy_id FROM users WHERE id = ?", (device["user_id"],))
        sid, source = (row["strategy_id"] if row else None), "user"
    if not sid and device["device_group_id"]:
        row = db.one("SELECT strategy_id FROM device_groups WHERE id = ?", (device["device_group_id"],))
        sid, source = (row["strategy_id"] if row else None), "device_group"
    if not sid:
        sid, source = db.setting("default_strategy_id"), "default"
    if not sid:
        return None, None
    row = db.one("SELECT * FROM strategies WHERE id = ?", (sid,))
    if row is None or not row["enabled"]:
        return None, None
    return row, source


def is_blocked(db, device):
    if device["disabled"]:
        return True
    if device["user_id"]:
        row = db.one("SELECT status FROM users WHERE id = ?", (device["user_id"],))
        return bool(row) and row["status"] == 0
    return False


def desired_config(db, device):
    """(options to push, stamp) for a device. The client echoes the stamp back
    as modified_at, so any change to it makes the server re-send."""
    strategy, _ = effective_strategy(db, device)
    options = loads(strategy["options"], {}) if strategy else {}
    options = {str(k): str(v) for k, v in options.items()}
    blocked = is_blocked(db, device)
    if blocked:
        options["whitelist"] = BLOCK_WHITELIST
    if strategy is None and not blocked:
        return options, 0
    key = f"{strategy['id']}:{strategy['modified_at']}" if strategy else "-"
    digest = hashlib.sha256(f"{key}:{int(blocked)}".encode()).hexdigest()
    return options, int(digest[:12], 16) or 1


# -- devices -------------------------------------------------------------------

def ensure_device(c, device_id, device_uuid, ip):
    """Find or create the device row; follow a device whose ID changed."""
    row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None and device_uuid:
        moved = c.execute("SELECT * FROM devices WHERE uuid = ?", (device_uuid,)).fetchone()
        if moved is not None:
            c.execute("UPDATE devices SET id = ? WHERE id = ?", (device_id, moved["id"]))
            row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        c.execute("INSERT INTO devices(id, guid, uuid, ip, created_at) VALUES (?, ?, ?, ?, ?)",
                  (device_id, new_guid(), device_uuid or "", ip, now()))
        row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return row


def device_payload(db, row, names=None, full=False):
    """Console/REST view of a device. `names` caches id->name lookups."""
    names = names if names is not None else {}

    def name_of(table, key):
        if not key:
            return None
        cache = names.setdefault(table, {})
        if key not in cache:
            r = db.one(f"SELECT name FROM {table} WHERE id = ?", (key,))
            cache[key] = r["name"] if r else None
        return cache[key]

    owner = name_of("users", row["user_id"])
    user_group = None
    if row["user_id"]:
        g = db.one("SELECT g.name FROM users u JOIN user_groups g ON g.id = u.group_id WHERE u.id = ?",
                   (row["user_id"],))
        user_group = g["name"] if g else None
    hostname = row["name_override"] or row["hostname"]
    username = row["username_override"] or row["username"]
    data = {
        "guid": row["guid"],
        "id": row["id"],
        "hostname": hostname,
        "device_name": hostname,
        "username": username,
        "os": row["os"],
        "platform": platform_of(row["os"]),
        "cpu": row["cpu"],
        "memory": row["memory"],
        "version": row["version"],
        "ip": row["ip"],
        "note": row["note"],
        "user_id": row["user_id"],
        "user_name": owner,
        "group_name": user_group,
        "device_group_id": row["device_group_id"],
        "device_group_name": name_of("device_groups", row["device_group_id"]),
        "strategy_id": row["strategy_id"],
        "strategy_name": name_of("strategies", row["strategy_id"]),
        "status": 0 if row["disabled"] else 1,
        "disabled": bool(row["disabled"]),
        "online": is_online(row),
        "conns": loads(row["conns"], []),
        "created_at": row["created_at"],
        "last_seen_at": row["last_seen_at"],
        "last_online": _iso(row["last_seen_at"] or row["created_at"]),
    }
    if full:
        data["sysinfo"] = loads(row["sysinfo"], {})
        data["uuid"] = row["uuid"]
        data["reported_hostname"] = row["hostname"]
        data["reported_username"] = row["username"]
        data["name_override"] = row["name_override"]
        data["username_override"] = row["username_override"]
    return data


def _iso(ts):
    import datetime
    return datetime.datetime.utcfromtimestamp(ts or 0).strftime("%Y-%m-%dT%H:%M:%S")


def controller_of(db, peer_id):
    """The account logged in on a controlling device, if any."""
    if not peer_id:
        return ""
    row = db.one("SELECT u.name FROM tokens t JOIN users u ON u.id = t.user_id "
                 "WHERE t.kind = 'client' AND t.device_id = ? ORDER BY t.last_seen_at DESC LIMIT 1",
                 (peer_id,))
    return row["name"] if row else ""


# -- address books -------------------------------------------------------------

def personal_book(db, user_id):
    row = db.one("SELECT guid FROM address_books WHERE owner_id = ? AND personal = 1", (user_id,))
    if row:
        return row["guid"]
    db.run("INSERT OR IGNORE INTO address_books(guid, name, owner_id, personal, created_at) "
           "VALUES (?, 'My address book', ?, 1, ?)", (new_guid(), user_id, now()))
    row = db.one("SELECT guid FROM address_books WHERE owner_id = ? AND personal = 1", (user_id,))
    return row["guid"]


def book_rule(db, user, guid, as_admin=False):
    """Permission on a book: 0 none, 1 read, 2 read/write, 3 full control.
    As in Pro, a user rule beats a group rule, which beats Everyone."""
    book = db.one("SELECT owner_id, personal FROM address_books WHERE guid = ?", (guid,))
    if book is None:
        return 0
    if book["owner_id"] == user["id"]:
        return RULE_FULL
    if as_admin and user["is_admin"]:
        return RULE_FULL
    if book["personal"]:
        return 0
    for cond, params in (("user_id = ?", (user["id"],)),
                         ("user_group_id = ?", (user["group_id"] or -1,)),
                         ("everyone = 1", ())):
        row = db.one(f"SELECT rule FROM ab_rules WHERE guid = ? AND {cond}", (guid,) + params)
        if row:
            return row["rule"]
    return 0


def shared_books_for(db, user):
    """Shared books the user owns or has a rule on, with the user's rule."""
    rows = db.all("SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id "
                  "WHERE b.personal = 0 ORDER BY b.name COLLATE NOCASE")
    books = []
    for r in rows:
        rule = book_rule(db, user, r["guid"])
        if rule:
            books.append(dict(r, rule=rule))
    return books


def profile_payload(book, rule):
    """A shared book as the client's AbProfile; info.password is the book's
    default shared password."""
    return {
        "guid": book["guid"], "name": book["name"], "owner": book["owner"], "note": book["note"],
        "rule": rule, "info": {"password": book["password"]} if book["password"] else {},
    }


PEER_TEXT_FIELDS = ("alias", "hash", "password", "username", "hostname", "platform", "note")
PEER_EXTRA_FIELDS = ("forceAlwaysRelay", "rdpPort", "rdpUsername")


def peer_payload(db, row, personal):
    extra = loads(row["extra"], {})
    data = {
        "id": row["peer_id"],
        "alias": row["alias"],
        "tags": loads(row["tags"], []),
        "username": row["username"],
        "hostname": row["hostname"],
        "platform": row["platform"],
        "note": row["note"],
    }
    if personal:
        data["hash"] = row["hash"]
    else:
        data["password"] = row["password"]
    for key in PEER_EXTRA_FIELDS:
        if key in extra:
            data[key] = extra[key]
    device = db.one("SELECT * FROM devices WHERE id = ?", (row["peer_id"],))
    if device is not None:
        data["same_server"] = True
        data["hostname"] = device["name_override"] or device["hostname"] or data["hostname"]
        data["username"] = device["username_override"] or device["username"] or data["username"]
        data["platform"] = platform_of(device["os"]) or data["platform"]
        if device["device_group_id"]:
            g = db.one("SELECT name FROM device_groups WHERE id = ?", (device["device_group_id"],))
            if g:
                data["device_group_name"] = g["name"]
    return data


def clean_tags(value):
    if not isinstance(value, list):
        return []
    out = []
    for tag in value:
        if isinstance(tag, str) and tag and tag not in out:
            out.append(tag[:64])
    return out


def upsert_peer(c, guid, peer, personal, update_only=False):
    """Insert or update a peer from client/console JSON. Returns error or None.
    Adding a peer that is in the recycle bin restores it."""
    peer_id = str(peer.get("id") or "").strip()
    if not peer_id or len(peer_id) > 64:
        return "Invalid peer ID"
    existing = c.execute("SELECT * FROM ab_peers WHERE guid = ? AND peer_id = ?",
                         (guid, peer_id)).fetchone()
    if existing is not None and existing["deleted_at"] and update_only:
        return "Peer not found"
    if existing is None and update_only:
        return "Peer not found"
    if existing is None or existing["deleted_at"]:
        values = {k: "" for k in PEER_TEXT_FIELDS}
        values["tags"] = "[]"
        values["extra"] = "{}"
    else:
        values = {k: existing[k] for k in PEER_TEXT_FIELDS + ("tags", "extra")}
    for key in PEER_TEXT_FIELDS:
        if key in peer and peer[key] is not None:
            values[key] = str(peer[key])[:1024]
    if personal:
        values["password"] = ""
    else:
        values["hash"] = ""
    if "tags" in peer:
        tags = clean_tags(peer["tags"])
        known = {r["name"] for r in c.execute("SELECT name FROM ab_tags WHERE guid = ?", (guid,))}
        values["tags"] = json.dumps([t for t in tags if t in known])
    extra = loads(values["extra"], {})
    for key in PEER_EXTRA_FIELDS:
        if key in peer:
            extra[key] = str(peer[key])[:256]
    values["extra"] = json.dumps(extra)
    if existing is None:
        c.execute(
            "INSERT INTO ab_peers(guid, peer_id, alias, hash, password, username, hostname, "
            "platform, note, tags, extra, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (guid, peer_id, values["alias"], values["hash"], values["password"],
             values["username"], values["hostname"], values["platform"], values["note"],
             values["tags"], values["extra"], now()),
        )
    else:
        c.execute(
            "UPDATE ab_peers SET alias=?, hash=?, password=?, username=?, hostname=?, platform=?, "
            "note=?, tags=?, extra=?, deleted_at = NULL WHERE guid = ? AND peer_id = ?",
            (values["alias"], values["hash"], values["password"], values["username"],
             values["hostname"], values["platform"], values["note"], values["tags"],
             values["extra"], guid, peer_id),
        )
    return None


def recycle_peers(c, guid, peer_ids):
    """Deleting from a book moves entries to its recycle bin, as in Pro."""
    for peer_id in peer_ids:
        c.execute("UPDATE ab_peers SET deleted_at = ? WHERE guid = ? AND peer_id = ? AND deleted_at IS NULL",
                  (now(), guid, str(peer_id)))


def rename_tag(c, guid, old, new):
    c.execute("UPDATE ab_tags SET name = ? WHERE guid = ? AND name = ?", (new, guid, old))
    for row in c.execute("SELECT peer_id, tags FROM ab_peers WHERE guid = ?", (guid,)).fetchall():
        tags = loads(row["tags"], [])
        if old in tags:
            tags = [new if t == old else t for t in tags]
            c.execute("UPDATE ab_peers SET tags = ? WHERE guid = ? AND peer_id = ?",
                      (json.dumps(clean_tags(tags)), guid, row["peer_id"]))


def delete_tags(c, guid, names):
    for name in names:
        c.execute("DELETE FROM ab_tags WHERE guid = ? AND name = ?", (guid, name))
    for row in c.execute("SELECT peer_id, tags FROM ab_peers WHERE guid = ?", (guid,)).fetchall():
        tags = loads(row["tags"], [])
        kept = [t for t in tags if t not in names]
        if kept != tags:
            c.execute("UPDATE ab_peers SET tags = ? WHERE guid = ? AND peer_id = ?",
                      (json.dumps(kept), guid, row["peer_id"]))


# -- console audit -------------------------------------------------------------

def console_log(db, req, action, target="", detail=""):
    actor = getattr(req, "actor", None)
    user = req.user
    name = actor.name if actor is not None else (user["name"] if user else "")
    typ, iop = CONSOLE_OPS.get(action, (_type_of(action), None))
    db.run(
        "INSERT INTO console_logs(user_id, user_name, action, target, detail, ip, created_at, typ, iop) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user["id"] if user else None, name, action, str(target)[:256], str(detail)[:2048],
         req.ip, now(), typ, iop),
    )


def _type_of(action):
    area = action.split(".")[0]
    return {"user": 1, "account": 1, "device": 2, "address_book": 3, "user_group": 0,
            "device_group": 0, "admin_role": 4}.get(area, 5)
