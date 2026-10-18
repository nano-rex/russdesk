"""Domain logic shared by the client API and the console API."""

import hashlib
import json
import uuid

from .db import now

ONLINE_SECONDS = 45  # clients heartbeat every 15 s when idle

RULE_READ, RULE_READ_WRITE, RULE_FULL = 1, 2, 3

CONN_TYPES = {0: "Remote desktop", 1: "File transfer", 2: "Port forward",
              3: "View camera", 4: "Terminal"}
PRIMARY_AUTH = {1: "Click to accept", 2: "Temporary password",
                3: "Permanent password", 4: "Switch sides"}
TWO_FACTOR = {1: "TOTP", 2: "Trusted device"}
FILE_TYPES = {0: "Send to remote", 1: "Receive from remote"}
ALARM_TYPES = {
    0: "IP not in whitelist",
    1: "Over 30 failed attempts",
    2: "6 failed attempts within a minute",
    6: "Too many attempts from an IPv6 prefix",
    7: "Terminal OS login backoff",
    8: "Terminal OS login concurrency",
    9: "Session scope violation",
    10: "ID not in whitelist",
}


def loads(text, default=None):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


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


# -- users ---------------------------------------------------------------------

def user_payload(row):
    """The user object the RustDesk client expects (UserPayload)."""
    return {
        "name": row["name"],
        "display_name": row["display_name"],
        "email": row["email"],
        "note": row["note"],
        "status": 1 if row["status"] == 1 else 0,
        "is_admin": bool(row["is_admin"]),
        "info": {},
    }


def access_scope(db, user):
    """Return (user_ids, device_group_ids) the user may see, or None for all."""
    if user["is_admin"]:
        return None
    user_ids = {user["id"]}
    device_groups = set()
    group_id = user["group_id"]
    if group_id:
        user_groups = {group_id}
        for row in db.all("SELECT target_type, target_id FROM group_access WHERE user_group_id = ?",
                          (group_id,)):
            if row["target_type"] == "user_group":
                user_groups.add(row["target_id"])
            else:
                device_groups.add(row["target_id"])
        marks = ",".join("?" * len(user_groups))
        for row in db.all(f"SELECT id FROM users WHERE group_id IN ({marks})", tuple(user_groups)):
            user_ids.add(row["id"])
    return user_ids, device_groups


def scope_sql(scope, device_alias="d"):
    """SQL condition (and params) restricting devices to an access scope."""
    if scope is None:
        return "1", ()
    user_ids, device_groups = scope
    parts, params = [], []
    if user_ids:
        parts.append(f"{device_alias}.user_id IN ({','.join('?' * len(user_ids))})")
        params.extend(user_ids)
    if device_groups:
        parts.append(f"{device_alias}.device_group_id IN ({','.join('?' * len(device_groups))})")
        params.extend(device_groups)
    return "(" + (" OR ".join(parts) or "0") + ")", tuple(params)


def can_access_device(db, user, device_id):
    cond, params = scope_sql(access_scope(db, user))
    return db.one(f"SELECT 1 FROM devices d WHERE d.id = ? AND {cond}", (device_id,) + params) is not None


# -- strategies ----------------------------------------------------------------

def effective_strategy(db, device):
    """Device strategy, else its owner's, else its group's, else the default."""
    candidates = [device["strategy_id"]]
    if device["user_id"]:
        row = db.one("SELECT strategy_id FROM users WHERE id = ?", (device["user_id"],))
        candidates.append(row["strategy_id"] if row else None)
    if device["device_group_id"]:
        row = db.one("SELECT strategy_id FROM device_groups WHERE id = ?", (device["device_group_id"],))
        candidates.append(row["strategy_id"] if row else None)
    candidates.append(db.setting("default_strategy_id"))
    for sid in candidates:
        if sid:
            row = db.one("SELECT * FROM strategies WHERE id = ?", (sid,))
            if row:
                return row
    return None


def strategy_stamp(strategy):
    """The client echoes this back as modified_at; any change re-sends."""
    if strategy is None:
        return 0
    digest = hashlib.sha256(f"{strategy['id']}:{strategy['modified_at']}".encode()).hexdigest()
    return int(digest[:12], 16) or 1


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
        c.execute("INSERT INTO devices(id, uuid, ip, created_at) VALUES (?, ?, ?, ?)",
                  (device_id, device_uuid or "", ip, now()))
        row = c.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return row


def device_payload(db, row, owner_names=None, group_names=None, full=False):
    owner = None
    if row["user_id"]:
        if owner_names is not None:
            owner = owner_names.get(row["user_id"])
        else:
            u = db.one("SELECT name FROM users WHERE id = ?", (row["user_id"],))
            owner = u["name"] if u else None
    group = None
    if row["device_group_id"]:
        if group_names is not None:
            group = group_names.get(row["device_group_id"])
        else:
            g = db.one("SELECT name FROM device_groups WHERE id = ?", (row["device_group_id"],))
            group = g["name"] if g else None
    data = {
        "id": row["id"],
        "hostname": row["hostname"],
        "username": row["username"],
        "os": row["os"],
        "platform": platform_of(row["os"]),
        "cpu": row["cpu"],
        "memory": row["memory"],
        "version": row["version"],
        "ip": row["ip"],
        "note": row["note"],
        "user_id": row["user_id"],
        "user_name": owner,
        "device_group_id": row["device_group_id"],
        "device_group_name": group,
        "strategy_id": row["strategy_id"],
        "online": is_online(row),
        "conns": loads(row["conns"], []),
        "created_at": row["created_at"],
        "last_seen_at": row["last_seen_at"],
    }
    if full:
        data["sysinfo"] = loads(row["sysinfo"], {})
        data["uuid"] = row["uuid"]
    return data


# -- address books -------------------------------------------------------------

def personal_book(db, user_id):
    row = db.one("SELECT guid FROM address_books WHERE owner_id = ? AND personal = 1", (user_id,))
    if row:
        return row["guid"]
    guid = str(uuid.uuid4())
    db.run("INSERT OR IGNORE INTO address_books(guid, name, owner_id, personal, created_at) "
           "VALUES (?, 'My address book', ?, 1, ?)", (guid, user_id, now()))
    row = db.one("SELECT guid FROM address_books WHERE owner_id = ? AND personal = 1", (user_id,))
    return row["guid"]


def book_rule(db, user, guid, as_admin=False):
    """Permission of user on a book: 0 none, 1 read, 2 read/write, 3 full."""
    book = db.one("SELECT owner_id, personal FROM address_books WHERE guid = ?", (guid,))
    if book is None:
        return 0
    if book["owner_id"] == user["id"]:
        return RULE_FULL
    if as_admin and user["is_admin"]:
        return RULE_FULL
    if book["personal"]:
        return 0
    row = db.one(
        "SELECT MAX(rule) AS r FROM ab_rules WHERE guid = ? AND (user_id = ? OR user_group_id = ?)",
        (guid, user["id"], user["group_id"] or -1),
    )
    return row["r"] or 0


def shared_books_for(db, user):
    """Shared books the user owns or has a rule on, with the user's rule."""
    rows = db.all(
        """
        SELECT b.guid, b.name, b.note, u.name AS owner,
               CASE WHEN b.owner_id = ? THEN 3 ELSE
                 (SELECT MAX(r.rule) FROM ab_rules r WHERE r.guid = b.guid
                    AND (r.user_id = ? OR r.user_group_id = ?)) END AS rule
        FROM address_books b JOIN users u ON u.id = b.owner_id
        WHERE b.personal = 0
        ORDER BY b.name COLLATE NOCASE
        """,
        (user["id"], user["id"], user["group_id"] or -1),
    )
    return [dict(r) for r in rows if r["rule"]]


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
    device = db.one("SELECT hostname, username, os, device_group_id FROM devices WHERE id = ?",
                    (row["peer_id"],))
    if device is not None:
        data["same_server"] = True
        data["hostname"] = device["hostname"] or data["hostname"]
        data["username"] = device["username"] or data["username"]
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
    """Insert or update a peer from client/console JSON. Returns error or None."""
    peer_id = str(peer.get("id") or "").strip()
    if not peer_id or len(peer_id) > 64:
        return "Invalid peer ID"
    existing = c.execute("SELECT * FROM ab_peers WHERE guid = ? AND peer_id = ?",
                         (guid, peer_id)).fetchone()
    if existing is None and not update_only:
        values = {k: "" for k in PEER_TEXT_FIELDS}
        values["tags"] = "[]"
        values["extra"] = "{}"
    elif existing is None:
        return "Peer not found"
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
            "note=?, tags=?, extra=? WHERE guid = ? AND peer_id = ?",
            (values["alias"], values["hash"], values["password"], values["username"],
             values["hostname"], values["platform"], values["note"], values["tags"],
             values["extra"], guid, peer_id),
        )
    return None


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
    user = req.user
    db.run(
        "INSERT INTO console_logs(user_id, user_name, action, target, detail, ip, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user["id"] if user else None, user["name"] if user else "", action,
         str(target)[:256], str(detail)[:2048], req.ip, now()),
    )
