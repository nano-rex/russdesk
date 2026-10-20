//! Domain logic shared by the client, console and REST APIs. Port of models.py.
//!
//! Rows are read as JSON objects (`db::Row`) to mirror the Python dict style.
//! Functions that mutate (ensure_device, upsert_peer, …) run on `&Database`
//! directly here; the API layer (M4/M5) will call them inside request
//! transactions.

use std::collections::{BTreeMap, BTreeSet};

use crate::json::Value;

use crate::db::{int, now, opt_int, text, Database, Row};

pub const ONLINE_SECONDS: i64 = 45;
pub const RULE_READ: i64 = 1;
pub const RULE_READ_WRITE: i64 = 2;
pub const RULE_FULL: i64 = 3;

pub const LOGIN_ALARMS: &[i64] = &[3, 4, 5];

/// Pushed as a device's IP whitelist while it is disabled: no address matches.
pub const BLOCK_WHITELIST: &str = "255.255.255.255/32";

pub const PEER_TEXT_FIELDS: &[&str] =
    &["alias", "hash", "password", "username", "hostname", "platform", "note"];
pub const PEER_EXTRA_FIELDS: &[&str] = &["forceAlwaysRelay", "rdpPort", "rdpUsername"];

pub fn conn_type_name(t: i64) -> &'static str {
    match t {
        0 => "Remote Desktop",
        1 => "File Transfer",
        2 => "Port Transfer",
        3 => "View Camera",
        4 => "Terminal",
        _ => "",
    }
}

pub fn primary_auth_name(t: i64) -> &'static str {
    match t {
        1 => "Click Confirmation",
        2 => "One-time Password",
        3 => "Permanent Password",
        4 => "Switch Sides",
        _ => "",
    }
}

pub fn alarm_type_name(t: i64) -> &'static str {
    match t {
        0 => "Access attempt outside the IP whitelist",
        1 => "Over 30 consecutive access attempts",
        2 => "Multiple access attempts within one minute",
        3 => "Over 30 consecutive login attempts",
        4 => "Multiple login attempts within one minute",
        5 => "Multiple login attempts within one hour",
        6 => "Too many consecutive access attempts from a single IPv6 prefix",
        7 => "Multiple failed Terminal (Run as administrator) login attempts",
        8 => "Multiple simultaneous Terminal (Run as administrator) login attempts",
        9 => "Session scope violation",
        10 => "Access attempt outside the ID whitelist",
        _ => "",
    }
}

/// Console audit category + operation for an action (models.py CONSOLE_OPS).
pub fn console_op(action: &str) -> Option<(i64, i64)> {
    Some(match action {
        "login" => (1, 0),
        "user_group.create" | "device_group.create" => (0, 1),
        "user.create" | "user.invite" => (1, 2),
        "user_group.delete" | "device_group.delete" => (0, 4),
        "device.disconnect" => (2, 5),
        "user.enable" => (1, 6),
        "user.disable" => (1, 7),
        "device.enable" => (2, 8),
        "device.disable" => (2, 9),
        "user_group.update" | "device_group.update" => (0, 10),
        "user.update" => (1, 11),
        "device.update" => (2, 12),
        "user.delete" => (1, 13),
        "device.delete" => (2, 14),
        "address_book.create" => (3, 15),
        "address_book.delete" => (3, 16),
        "address_book.rename" => (3, 17),
        "address_book.recycle_delete" => (3, 18),
        "address_book.recycle_empty" => (3, 19),
        "address_book.rule_add" => (3, 20),
        "address_book.rule_delete" => (3, 21),
        "address_book.rule_update" => (3, 22),
        _ => return None,
    })
}

fn type_of(action: &str) -> i64 {
    let area = action.split('.').next().unwrap_or("");
    match area {
        "user" | "account" => 1,
        "device" => 2,
        "address_book" => 3,
        "user_group" | "device_group" => 0,
        "admin_role" => 4,
        _ => 5,
    }
}

// -- row field helpers --------------------------------------------------------

pub fn rstr(row: &Row, key: &str) -> String {
    row.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
pub fn rint(row: &Row, key: &str) -> i64 {
    row.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}
pub fn ropt_int(row: &Row, key: &str) -> Option<i64> {
    row.get(key).and_then(|v| v.as_i64())
}
pub fn rbool(row: &Row, key: &str) -> bool {
    rint(row, key) != 0
}
fn rval(row: &Row, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

// -- generic helpers ----------------------------------------------------------

/// Parse a JSON string, or return `default` on empty/invalid (models.py loads).
pub fn loads_or(s: &str, default: Value) -> Value {
    if s.is_empty() {
        return default;
    }
    crate::json::from_str(s).unwrap_or(default)
}

/// A random RFC 4122 v4 GUID string.
pub fn new_guid() -> String {
    let mut b = [0u8; 16];
    crate::rand::fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

pub fn is_online(device: &Row, at: Option<i64>) -> bool {
    match ropt_int(device, "last_seen_at") {
        Some(seen) if seen > 0 => at.unwrap_or_else(now) - seen <= ONLINE_SECONDS,
        _ => false,
    }
}

/// Map sysinfo's "os" field to the platform names the client uses.
pub fn platform_of(os_text: &str) -> String {
    let first = os_text.split(" / ").next().unwrap_or("").to_lowercase();
    match first.as_str() {
        "windows" => "Windows",
        "macos" => "Mac OS",
        "android" => "Android",
        "linux" => "Linux",
        _ if os_text.to_lowercase().contains("linux") => "Linux",
        _ => "",
    }
    .to_string()
}

/// Pro's REST filters: '%' wildcards pass through; '-' means empty.
pub fn like(value: &str) -> &str {
    if value == "-" {
        ""
    } else {
        value
    }
}

fn iso(ts: i64) -> String {
    // UTC civil date from epoch seconds (Howard Hinnant's algorithm).
    let ts = ts.max(0);
    let days = ts / 86400;
    let secs = ts % 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        y, m, d, secs / 3600, (secs % 3600) / 60, secs % 60
    )
}

// -- users --------------------------------------------------------------------

pub fn user_payload(row: &Row, group_name: Option<&str>) -> Value {
    let mut data = json!({
        "guid": rstr(row, "guid"),
        "name": rstr(row, "name"),
        "display_name": rstr(row, "display_name"),
        "email": rstr(row, "email"),
        "note": rstr(row, "note"),
        "status": rint(row, "status"),
        "is_admin": rbool(row, "is_admin"),
        "info": {},
    });
    if let Some(g) = group_name {
        data["group_name"] = json!(g);
    }
    data
}

/// Access targets granted to a user directly or through their group.
pub fn rules_for(db: &Database, user: &Row) -> (BTreeSet<i64>, BTreeSet<i64>) {
    let uid = rint(user, "id");
    let gid = ropt_int(user, "group_id").unwrap_or(-1);
    let rows = db
        .query(
            "SELECT target_type, target_id FROM access_rules WHERE \
             (subject_type = 'user' AND subject_id = ?1) OR \
             (subject_type = 'user_group' AND subject_id = ?2)",
            &[int(uid), int(gid)],
        )
        .unwrap_or_default();
    let mut user_groups = BTreeSet::new();
    let mut device_groups = BTreeSet::new();
    for r in &rows {
        let tid = rint(r, "target_id");
        match rstr(r, "target_type").as_str() {
            "user_group" => {
                user_groups.insert(tid);
            }
            "device_group" => {
                device_groups.insert(tid);
            }
            _ => {}
        }
    }
    (user_groups, device_groups)
}

/// (user_ids, device_group_ids) whose devices the user may connect to, or None
/// for everything (administrators). Pro's Access Control.
pub fn accessible_scope(db: &Database, user: &Row) -> Option<(BTreeSet<i64>, BTreeSet<i64>)> {
    if rbool(user, "is_admin") {
        return None;
    }
    let (mut user_groups, device_groups) = rules_for(db, user);
    if let Some(gid) = ropt_int(user, "group_id") {
        user_groups.insert(gid);
    }
    let mut user_ids = BTreeSet::new();
    user_ids.insert(rint(user, "id"));
    if !user_groups.is_empty() {
        let marks = vec!["?"; user_groups.len()].join(",");
        let params: Vec<_> = user_groups.iter().map(|g| int(*g)).collect();
        if let Ok(rows) = db.query(
            &format!("SELECT id FROM users WHERE group_id IN ({marks})"),
            &params,
        ) {
            for r in &rows {
                user_ids.insert(rint(r, "id"));
            }
        }
    }
    Some((user_ids, device_groups))
}

/// Devices in an access scope that are not disabled (nor their user).
pub fn accessible_sql(
    scope: &Option<(BTreeSet<i64>, BTreeSet<i64>)>,
    alias: &str,
) -> (String, Vec<crate::db::SqlValue>) {
    let blocked = format!(
        "{alias}.disabled = 0 AND NOT EXISTS (SELECT 1 FROM users bu \
         WHERE bu.id = {alias}.user_id AND bu.status = 0)"
    );
    let Some((user_ids, device_groups)) = scope else {
        return (blocked, vec![]);
    };
    let mut parts = Vec::new();
    let mut params = Vec::new();
    if !user_ids.is_empty() {
        parts.push(format!(
            "{alias}.user_id IN ({})",
            vec!["?"; user_ids.len()].join(",")
        ));
        params.extend(user_ids.iter().map(|x| int(*x)));
    }
    if !device_groups.is_empty() {
        parts.push(format!(
            "{alias}.device_group_id IN ({})",
            vec!["?"; device_groups.len()].join(",")
        ));
        params.extend(device_groups.iter().map(|x| int(*x)));
    }
    let cond = if parts.is_empty() {
        "0".to_string()
    } else {
        parts.join(" OR ")
    };
    (format!("({cond}) AND {blocked}"), params)
}

pub fn accessible_users(db: &Database, user: &Row) -> Option<BTreeSet<i64>> {
    if rbool(user, "is_admin") {
        return None;
    }
    accessible_scope(db, user).map(|(u, _)| u)
}

// -- strategies ---------------------------------------------------------------

/// (strategy row or None, source). Pro's priority: the device's own strategy,
/// then its user's, then its device group's, then the default. A disabled
/// strategy means no strategy applies.
pub fn effective_strategy(db: &Database, device: &Row) -> (Option<Row>, Option<&'static str>) {
    let mut sid = ropt_int(device, "strategy_id");
    let mut source: &'static str = "device";
    if sid.is_none() {
        if let Some(uid) = ropt_int(device, "user_id") {
            let r = db
                .query_one("SELECT strategy_id FROM users WHERE id = ?1", &[int(uid)])
                .ok()
                .flatten();
            sid = r.as_ref().and_then(|r| ropt_int(r, "strategy_id"));
            source = "user";
        }
    }
    if sid.is_none() {
        if let Some(dg) = ropt_int(device, "device_group_id") {
            let r = db
                .query_one("SELECT strategy_id FROM device_groups WHERE id = ?1", &[int(dg)])
                .ok()
                .flatten();
            sid = r.as_ref().and_then(|r| ropt_int(r, "strategy_id"));
            source = "device_group";
        }
    }
    if sid.is_none() {
        sid = db.settings().default_strategy_id;
        source = "default";
    }
    let Some(sid) = sid else {
        return (None, None);
    };
    let row = db
        .query_one("SELECT * FROM strategies WHERE id = ?1", &[int(sid)])
        .ok()
        .flatten();
    match row {
        Some(r) if rbool(&r, "enabled") => (Some(r), Some(source)),
        _ => (None, None),
    }
}

pub fn is_blocked(db: &Database, device: &Row) -> bool {
    if rbool(device, "disabled") {
        return true;
    }
    if let Some(uid) = ropt_int(device, "user_id") {
        if let Ok(Some(r)) = db.query_one("SELECT status FROM users WHERE id = ?1", &[int(uid)]) {
            return rint(&r, "status") == 0;
        }
    }
    false
}

/// (options to push, stamp). The client echoes the stamp back as modified_at,
/// so any change makes the server re-send.
pub fn desired_config(db: &Database, device: &Row) -> (BTreeMap<String, String>, i64) {
    let (strategy, _) = effective_strategy(db, device);
    let mut options: BTreeMap<String, String> = BTreeMap::new();
    if let Some(s) = &strategy {
        if let Value::Object(map) = loads_or(&rstr(s, "options"), json!({})) {
            for (k, v) in map {
                let val = match v {
                    Value::Str(s) => s,
                    other => other.to_string(),
                };
                options.insert(k, val);
            }
        }
    }
    let blocked = is_blocked(db, device);
    if blocked {
        options.insert("whitelist".to_string(), BLOCK_WHITELIST.to_string());
    }
    if strategy.is_none() && !blocked {
        return (options, 0);
    }
    let key = match &strategy {
        Some(s) => format!("{}:{}", rint(s, "id"), rint(s, "modified_at")),
        None => "-".to_string(),
    };
    let digest = hex12(&format!("{key}:{}", blocked as i64));
    (options, if digest == 0 { 1 } else { digest })
}

fn hex12(input: &str) -> i64 {
    let d = crate::crypto::sha256(input.as_bytes());
    let hex: String = d.iter().take(6).map(|b| format!("{:02x}", b)).collect();
    i64::from_str_radix(&hex, 16).unwrap_or(0)
}

// -- devices ------------------------------------------------------------------

/// Find or create the device row; follow a device whose ID changed.
pub fn ensure_device(db: &Database, device_id: &str, device_uuid: &str, ip: &str) -> Option<Row> {
    let existing = db
        .query_one("SELECT * FROM devices WHERE id = ?1", &[text(device_id)])
        .ok()
        .flatten();
    if existing.is_none() && !device_uuid.is_empty() {
        if let Ok(Some(moved)) =
            db.query_one("SELECT * FROM devices WHERE uuid = ?1", &[text(device_uuid)])
        {
            let _ = db.execute(
                "UPDATE devices SET id = ?1 WHERE id = ?2",
                &[text(device_id), text(rstr(&moved, "id"))],
            );
            return db
                .query_one("SELECT * FROM devices WHERE id = ?1", &[text(device_id)])
                .ok()
                .flatten();
        }
    }
    if existing.is_none() {
        let _ = db.execute(
            "INSERT INTO devices(id, guid, uuid, ip, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                text(device_id),
                text(new_guid()),
                text(device_uuid),
                text(ip),
                int(now()),
            ],
        );
        return db
            .query_one("SELECT * FROM devices WHERE id = ?1", &[text(device_id)])
            .ok()
            .flatten();
    }
    existing
}

fn name_of(db: &Database, table: &str, id: Option<i64>) -> Option<String> {
    let id = id?;
    db.query_one(&format!("SELECT name FROM {table} WHERE id = ?1"), &[int(id)])
        .ok()
        .flatten()
        .map(|r| rstr(&r, "name"))
}

/// Console/REST view of a device.
pub fn device_payload(db: &Database, row: &Row, full: bool) -> Value {
    let user_id = ropt_int(row, "user_id");
    let owner = name_of(db, "users", user_id);
    let user_group = user_id.and_then(|uid| {
        db.query_one(
            "SELECT g.name FROM users u JOIN user_groups g ON g.id = u.group_id WHERE u.id = ?1",
            &[int(uid)],
        )
        .ok()
        .flatten()
        .map(|r| rstr(&r, "name"))
    });
    let name_override = rstr(row, "name_override");
    let hostname = if name_override.is_empty() {
        rstr(row, "hostname")
    } else {
        name_override
    };
    let username_override = rstr(row, "username_override");
    let username = if username_override.is_empty() {
        rstr(row, "username")
    } else {
        username_override
    };
    let last_seen = ropt_int(row, "last_seen_at");
    let mut data = json!({
        "guid": rstr(row, "guid"),
        "id": rstr(row, "id"),
        "hostname": hostname.clone(),
        "device_name": hostname,
        "username": username,
        "os": rstr(row, "os"),
        "platform": platform_of(&rstr(row, "os")),
        "cpu": rstr(row, "cpu"),
        "memory": rstr(row, "memory"),
        "version": rstr(row, "version"),
        "ip": rstr(row, "ip"),
        "note": rstr(row, "note"),
        "user_id": user_id,
        "user_name": owner,
        "group_name": user_group,
        "device_group_id": ropt_int(row, "device_group_id"),
        "device_group_name": name_of(db, "device_groups", ropt_int(row, "device_group_id")),
        "strategy_id": ropt_int(row, "strategy_id"),
        "strategy_name": name_of(db, "strategies", ropt_int(row, "strategy_id")),
        "status": if rbool(row, "disabled") { 0 } else { 1 },
        "disabled": rbool(row, "disabled"),
        "online": is_online(row, None),
        "conns": loads_or(&rstr(row, "conns"), json!([])),
        "created_at": rint(row, "created_at"),
        "last_seen_at": last_seen,
        "last_online": iso(last_seen.unwrap_or_else(|| rint(row, "created_at"))),
    });
    if full {
        data["sysinfo"] = loads_or(&rstr(row, "sysinfo"), json!({}));
        data["uuid"] = json!(rstr(row, "uuid"));
        data["reported_hostname"] = json!(rstr(row, "hostname"));
        data["reported_username"] = json!(rstr(row, "username"));
        data["name_override"] = json!(rstr(row, "name_override"));
        data["username_override"] = json!(rstr(row, "username_override"));
    }
    data
}

/// The account logged in on a controlling device, if any.
pub fn controller_of(db: &Database, peer_id: &str) -> String {
    if peer_id.is_empty() {
        return String::new();
    }
    db.query_one(
        "SELECT u.name FROM tokens t JOIN users u ON u.id = t.user_id \
         WHERE t.kind = 'client' AND t.device_id = ?1 ORDER BY t.last_seen_at DESC LIMIT 1",
        &[text(peer_id)],
    )
    .ok()
    .flatten()
    .map(|r| rstr(&r, "name"))
    .unwrap_or_default()
}

// -- address books ------------------------------------------------------------

pub fn personal_book(db: &Database, user_id: i64) -> String {
    if let Ok(Some(r)) = db.query_one(
        "SELECT guid FROM address_books WHERE owner_id = ?1 AND personal = 1",
        &[int(user_id)],
    ) {
        return rstr(&r, "guid");
    }
    let _ = db.execute(
        "INSERT OR IGNORE INTO address_books(guid, name, owner_id, personal, created_at) \
         VALUES (?1, 'My address book', ?2, 1, ?3)",
        &[text(new_guid()), int(user_id), int(now())],
    );
    db.query_one(
        "SELECT guid FROM address_books WHERE owner_id = ?1 AND personal = 1",
        &[int(user_id)],
    )
    .ok()
    .flatten()
    .map(|r| rstr(&r, "guid"))
    .unwrap_or_default()
}

/// Permission on a book: 0 none, 1 read, 2 read/write, 3 full control. A user
/// rule beats a group rule, which beats Everyone.
pub fn book_rule(db: &Database, user: &Row, guid: &str, as_admin: bool) -> i64 {
    let Ok(Some(book)) = db.query_one(
        "SELECT owner_id, personal FROM address_books WHERE guid = ?1",
        &[text(guid)],
    ) else {
        return 0;
    };
    if ropt_int(&book, "owner_id") == ropt_int(user, "id") {
        return RULE_FULL;
    }
    if as_admin && rbool(user, "is_admin") {
        return RULE_FULL;
    }
    if rbool(&book, "personal") {
        return 0;
    }
    let uid = rint(user, "id");
    let gid = ropt_int(user, "group_id").unwrap_or(-1);
    let checks: [(&str, Vec<crate::db::SqlValue>); 3] = [
        ("user_id = ?2", vec![text(guid), int(uid)]),
        ("user_group_id = ?2", vec![text(guid), int(gid)]),
        ("everyone = 1", vec![text(guid)]),
    ];
    for (cond, params) in checks {
        if let Ok(Some(r)) = db.query_one(
            &format!("SELECT rule FROM ab_rules WHERE guid = ?1 AND {cond}"),
            &params,
        ) {
            return rint(&r, "rule");
        }
    }
    0
}

/// Shared books the user owns or has a rule on, each with the user's rule.
pub fn shared_books_for(db: &Database, user: &Row) -> Vec<Row> {
    let rows = db
        .query(
            "SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id \
             WHERE b.personal = 0 ORDER BY b.name COLLATE NOCASE",
            &[],
        )
        .unwrap_or_default();
    let mut books = Vec::new();
    for mut r in rows {
        let rule = book_rule(db, user, &rstr(&r, "guid"), false);
        if rule != 0 {
            r.insert("rule".to_string(), json!(rule));
            books.push(r);
        }
    }
    books
}

/// A shared book as the client's AbProfile.
pub fn profile_payload(book: &Row, rule: i64) -> Value {
    let password = rstr(book, "password");
    json!({
        "guid": rstr(book, "guid"),
        "name": rstr(book, "name"),
        "owner": rstr(book, "owner"),
        "note": rstr(book, "note"),
        "rule": rule,
        "info": if password.is_empty() { json!({}) } else { json!({ "password": password }) },
    })
}

pub fn clean_tags(value: &Value) -> Vec<String> {
    let Some(arr) = value.as_array() else {
        return vec![];
    };
    let mut out: Vec<String> = Vec::new();
    for tag in arr {
        if let Some(t) = tag.as_str() {
            if !t.is_empty() && !out.iter().any(|x| x == t) {
                out.push(t.chars().take(64).collect());
            }
        }
    }
    out
}

pub fn peer_payload(db: &Database, row: &Row, personal: bool) -> Value {
    let extra = loads_or(&rstr(row, "extra"), json!({}));
    let mut data = json!({
        "id": rstr(row, "peer_id"),
        "alias": rstr(row, "alias"),
        "tags": loads_or(&rstr(row, "tags"), json!([])),
        "username": rstr(row, "username"),
        "hostname": rstr(row, "hostname"),
        "platform": rstr(row, "platform"),
        "note": rstr(row, "note"),
    });
    if personal {
        data["hash"] = json!(rstr(row, "hash"));
    } else {
        data["password"] = json!(rstr(row, "password"));
    }
    if let Value::Object(map) = &extra {
        for key in PEER_EXTRA_FIELDS {
            if let Some(v) = map.get(*key) {
                data[*key] = v.clone();
            }
        }
    }
    if let Ok(Some(device)) =
        db.query_one("SELECT * FROM devices WHERE id = ?1", &[text(rstr(row, "peer_id"))])
    {
        data["same_server"] = json!(true);
        let n = rstr(&device, "name_override");
        let n = if n.is_empty() { rstr(&device, "hostname") } else { n };
        if !n.is_empty() {
            data["hostname"] = json!(n);
        }
        let u = rstr(&device, "username_override");
        let u = if u.is_empty() { rstr(&device, "username") } else { u };
        if !u.is_empty() {
            data["username"] = json!(u);
        }
        let p = platform_of(&rstr(&device, "os"));
        if !p.is_empty() {
            data["platform"] = json!(p);
        }
        if let Some(dg) = ropt_int(&device, "device_group_id") {
            if let Some(name) = name_of(db, "device_groups", Some(dg)) {
                data["device_group_name"] = json!(name);
            }
        }
    }
    data
}

/// Insert or update a peer from client/console JSON. Returns an error string or
/// None. Adding a peer that is in the recycle bin restores it.
pub fn upsert_peer(
    db: &Database,
    guid: &str,
    peer: &crate::json::Object,
    personal: bool,
    update_only: bool,
) -> Option<String> {
    let peer_id = peer
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if peer_id.is_empty() || peer_id.len() > 64 {
        return Some("Invalid peer ID".to_string());
    }
    let existing = db
        .query_one(
            "SELECT * FROM ab_peers WHERE guid = ?1 AND peer_id = ?2",
            &[text(guid), text(&peer_id)],
        )
        .ok()
        .flatten();
    let is_deleted = existing
        .as_ref()
        .map(|e| ropt_int(e, "deleted_at").is_some())
        .unwrap_or(false);
    if existing.is_none() && update_only {
        return Some("Peer not found".to_string());
    }
    if is_deleted && update_only {
        return Some("Peer not found".to_string());
    }

    let fresh = existing.is_none() || is_deleted;
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for f in PEER_TEXT_FIELDS {
        values.insert(
            (*f).to_string(),
            if fresh {
                String::new()
            } else {
                rstr(existing.as_ref().unwrap(), f)
            },
        );
    }
    let mut tags = if fresh {
        "[]".to_string()
    } else {
        rstr(existing.as_ref().unwrap(), "tags")
    };
    let mut extra = if fresh {
        "{}".to_string()
    } else {
        rstr(existing.as_ref().unwrap(), "extra")
    };

    for key in PEER_TEXT_FIELDS {
        if let Some(v) = peer.get(*key) {
            if !v.is_null() {
                let s = match v {
                    Value::Str(s) => s.clone(),
                    other => other.to_string(),
                };
                values.insert((*key).to_string(), s.chars().take(1024).collect());
            }
        }
    }
    if personal {
        values.insert("password".to_string(), String::new());
    } else {
        values.insert("hash".to_string(), String::new());
    }
    if let Some(t) = peer.get("tags") {
        let wanted = clean_tags(t);
        let known: BTreeSet<String> = db
            .query("SELECT name FROM ab_tags WHERE guid = ?1", &[text(guid)])
            .unwrap_or_default()
            .iter()
            .map(|r| rstr(r, "name"))
            .collect();
        let kept: Vec<String> = wanted.into_iter().filter(|t| known.contains(t)).collect();
        tags = crate::json::to_string(&Value::from(kept));
    }
    let mut extra_val = loads_or(&extra, json!({}));
    if let Value::Object(map) = &mut extra_val {
        for key in PEER_EXTRA_FIELDS {
            if let Some(v) = peer.get(*key) {
                let s = match v {
                    Value::Str(s) => s.clone(),
                    other => other.to_string(),
                };
                map.insert((*key).to_string(), json!(s.chars().take(256).collect::<String>()));
            }
        }
    }
    extra = extra_val.to_string();

    let get = |k: &str| values.get(k).cloned().unwrap_or_default();
    if existing.is_none() {
        let _ = db.execute(
            "INSERT INTO ab_peers(guid, peer_id, alias, hash, password, username, hostname, \
             platform, note, tags, extra, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            &[
                text(guid), text(&peer_id), text(get("alias")), text(get("hash")),
                text(get("password")), text(get("username")), text(get("hostname")),
                text(get("platform")), text(get("note")), text(tags), text(extra), int(now()),
            ],
        );
    } else {
        let _ = db.execute(
            "UPDATE ab_peers SET alias=?3, hash=?4, password=?5, username=?6, hostname=?7, \
             platform=?8, note=?9, tags=?10, extra=?11, deleted_at = NULL WHERE guid = ?1 AND peer_id = ?2",
            &[
                text(guid), text(&peer_id), text(get("alias")), text(get("hash")),
                text(get("password")), text(get("username")), text(get("hostname")),
                text(get("platform")), text(get("note")), text(tags), text(extra),
            ],
        );
    }
    None
}

/// Deleting from a book moves entries to its recycle bin.
pub fn recycle_peers(db: &Database, guid: &str, peer_ids: &[String]) {
    for peer_id in peer_ids {
        let _ = db.execute(
            "UPDATE ab_peers SET deleted_at = ?1 WHERE guid = ?2 AND peer_id = ?3 AND deleted_at IS NULL",
            &[int(now()), text(guid), text(peer_id)],
        );
    }
}

pub fn rename_tag(db: &Database, guid: &str, old: &str, new: &str) {
    let _ = db.execute(
        "UPDATE ab_tags SET name = ?1 WHERE guid = ?2 AND name = ?3",
        &[text(new), text(guid), text(old)],
    );
    let rows = db
        .query("SELECT peer_id, tags FROM ab_peers WHERE guid = ?1", &[text(guid)])
        .unwrap_or_default();
    for r in &rows {
        let tags = loads_or(&rstr(r, "tags"), json!([]));
        if let Some(arr) = tags.as_array() {
            if arr.iter().any(|t| t.as_str() == Some(old)) {
                let renamed: Vec<Value> = arr
                    .iter()
                    .map(|t| if t.as_str() == Some(old) { json!(new) } else { t.clone() })
                    .collect();
                let cleaned = clean_tags(&Value::Array(renamed));
                let _ = db.execute(
                    "UPDATE ab_peers SET tags = ?1 WHERE guid = ?2 AND peer_id = ?3",
                    &[
                        text(crate::json::to_string(&Value::from(cleaned))),
                        text(guid),
                        text(rstr(r, "peer_id")),
                    ],
                );
            }
        }
    }
}

pub fn delete_tags(db: &Database, guid: &str, names: &[String]) {
    for name in names {
        let _ = db.execute(
            "DELETE FROM ab_tags WHERE guid = ?1 AND name = ?2",
            &[text(guid), text(name)],
        );
    }
    let rows = db
        .query("SELECT peer_id, tags FROM ab_peers WHERE guid = ?1", &[text(guid)])
        .unwrap_or_default();
    for r in &rows {
        let tags = loads_or(&rstr(r, "tags"), json!([]));
        if let Some(arr) = tags.as_array() {
            let kept: Vec<Value> = arr
                .iter()
                .filter(|t| !t.as_str().map(|s| names.iter().any(|n| n == s)).unwrap_or(false))
                .cloned()
                .collect();
            if kept.len() != arr.len() {
                let _ = db.execute(
                    "UPDATE ab_peers SET tags = ?1 WHERE guid = ?2 AND peer_id = ?3",
                    &[
                        text(crate::json::to_string(&Value::from(kept))),
                        text(guid),
                        text(rstr(r, "peer_id")),
                    ],
                );
            }
        }
    }
}

// -- console audit ------------------------------------------------------------

/// Record a console action in the audit log.
pub fn console_log(
    db: &Database,
    user_id: Option<i64>,
    user_name: &str,
    ip: &str,
    action: &str,
    target: &str,
    detail: &str,
) {
    let (typ, iop) = match console_op(action) {
        Some((t, o)) => (Some(t), Some(o)),
        None => (Some(type_of(action)), None),
    };
    let _ = db.execute(
        "INSERT INTO console_logs(user_id, user_name, action, target, detail, ip, created_at, typ, iop) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        &[
            opt_int(user_id),
            text(user_name),
            text(action),
            text(target.chars().take(256).collect::<String>()),
            text(detail.chars().take(2048).collect::<String>()),
            text(ip),
            int(now()),
            opt_int(typ),
            opt_int(iop),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_mapping() {
        assert_eq!(platform_of("windows / 10"), "Windows");
        assert_eq!(platform_of("macos / 14"), "Mac OS");
        assert_eq!(platform_of("android"), "Android");
        assert_eq!(platform_of("Linux / Ubuntu"), "Linux");
        assert_eq!(platform_of("freebsd"), "");
    }

    #[test]
    fn like_filter() {
        assert_eq!(like("-"), "");
        assert_eq!(like("abc%"), "abc%");
    }

    #[test]
    fn guid_format() {
        let g = new_guid();
        assert_eq!(g.len(), 36);
        assert_eq!(g.as_bytes()[14], b'4'); // version nibble
        assert_eq!(g.matches('-').count(), 4);
    }

    #[test]
    fn iso_epoch() {
        assert_eq!(iso(0), "1970-01-01T00:00:00");
        assert_eq!(iso(1_700_000_000), "2023-11-14T22:13:20");
    }

    #[test]
    fn online_window() {
        let mut row = Row::new();
        row.insert("last_seen_at".into(), json!(now() - 10));
        assert!(is_online(&row, None));
        row.insert("last_seen_at".into(), json!(now() - 100));
        assert!(!is_online(&row, None));
        row.insert("last_seen_at".into(), Value::Null);
        assert!(!is_online(&row, None));
    }

    #[test]
    fn clean_tags_dedups_and_limits() {
        let v = json!(["a", "a", "", "b", 5]);
        assert_eq!(clean_tags(&v), vec!["a".to_string(), "b".to_string()]);
        assert_eq!(clean_tags(&json!("notarray")), Vec::<String>::new());
    }

    fn tmp_db() -> (std::path::PathBuf, Database) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "russdesk-models-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let db = Database::open(&dir.join("t.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn device_strategy_and_payload() {
        let (dir, db) = tmp_db();
        // A user, a strategy and a device wired to that strategy.
        let uid = db
            .insert(
                "INSERT INTO users(name, password_hash, created_at, guid) VALUES ('alice','x',?1,?2)",
                &[int(now()), text(new_guid())],
            )
            .unwrap();
        let sid = db
            .insert(
                "INSERT INTO strategies(name, options, modified_at, guid, enabled) \
                 VALUES ('s1', ?1, ?2, ?3, 1)",
                &[text(r#"{"enable-audio":"N"}"#), int(now()), text(new_guid())],
            )
            .unwrap();
        db.execute(
            "INSERT INTO devices(id, guid, user_id, strategy_id, os, created_at, last_seen_at) \
             VALUES ('123456789', ?1, ?2, ?3, 'windows / 11', ?4, ?5)",
            &[text(new_guid()), int(uid), int(sid), int(now()), int(now() - 5)],
        )
        .unwrap();

        let device = db
            .query_one("SELECT * FROM devices WHERE id = '123456789'", &[])
            .unwrap()
            .unwrap();

        // effective_strategy picks the device's own, enabled strategy.
        let (strat, source) = effective_strategy(&db, &device);
        assert!(strat.is_some());
        assert_eq!(source, Some("device"));

        // desired_config carries the strategy option and a non-zero stamp.
        let (opts, stamp) = desired_config(&db, &device);
        assert_eq!(opts.get("enable-audio").map(|s| s.as_str()), Some("N"));
        assert_ne!(stamp, 0);

        // device_payload renders names, platform and online state.
        let p = device_payload(&db, &device, true);
        assert_eq!(p["platform"], json!("Windows"));
        assert_eq!(p["user_name"], json!("alice"));
        assert_eq!(p["strategy_name"], json!("s1"));
        assert_eq!(p["online"], json!(true));
        assert_eq!(p["status"], json!(1));

        // Disabling the device blocks it: whitelist is pushed, status flips.
        db.execute("UPDATE devices SET disabled = 1 WHERE id = '123456789'", &[])
            .unwrap();
        let device = db
            .query_one("SELECT * FROM devices WHERE id = '123456789'", &[])
            .unwrap()
            .unwrap();
        assert!(is_blocked(&db, &device));
        let (opts, _) = desired_config(&db, &device);
        assert_eq!(opts.get("whitelist").map(|s| s.as_str()), Some(BLOCK_WHITELIST));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_device_and_personal_book() {
        let (dir, db) = tmp_db();
        let d1 = ensure_device(&db, "999000111", "uuid-a", "1.2.3.4").unwrap();
        assert_eq!(rstr(&d1, "id"), "999000111");
        // Same id again returns the same row (no duplicate).
        let d2 = ensure_device(&db, "999000111", "uuid-a", "1.2.3.4").unwrap();
        assert_eq!(rstr(&d2, "guid"), rstr(&d1, "guid"));
        // A new id but the same uuid follows the device (id change).
        let d3 = ensure_device(&db, "999000222", "uuid-a", "1.2.3.4").unwrap();
        assert_eq!(rstr(&d3, "guid"), rstr(&d1, "guid"));
        let rows = db.query("SELECT count(*) AS c FROM devices", &[]).unwrap();
        assert_eq!(rows[0].get("c").unwrap().as_i64(), Some(1));

        let uid = db
            .insert(
                "INSERT INTO users(name, password_hash, created_at, guid) VALUES ('bob','x',?1,?2)",
                &[int(now()), text(new_guid())],
            )
            .unwrap();
        let g1 = personal_book(&db, uid);
        let g2 = personal_book(&db, uid);
        assert!(!g1.is_empty());
        assert_eq!(g1, g2); // idempotent
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn console_ops_match() {
        assert_eq!(console_op("login"), Some((1, 0)));
        assert_eq!(console_op("device.delete"), Some((2, 14)));
        assert_eq!(console_op("unknown.thing"), None);
        assert_eq!(type_of("address_book.whatever"), 3);
        assert_eq!(type_of("mystery"), 5);
    }
}
