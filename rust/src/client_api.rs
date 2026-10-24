//! The HTTP API that RustDesk clients call (the "API server" setting). Port of
//! client_api.py. Endpoints and payloads follow the open-source client and the
//! GET forms used by RustDesk Server Pro's `ab.py`.

use crate::json::{Object, Value};

use crate::app::App;
use crate::authz::Actor;
use crate::db::{int, now, opt_int, text, Database, Row};
use crate::models::{self, ropt_int, rstr, RULE_FULL, RULE_READ, RULE_READ_WRITE};
use crate::security::{new_token, token_hash};
use crate::web::{json_response, HttpError, HttpResult, Params, Request, Response, Router};
use crate::auth;

const NEVER: i64 = 253402300799; // 9999-12-31

pub fn register(r: &mut Router<App>) {
    r.add("POST", "/api/login", login);
    r.add("GET", "/api/login-options", |_a, _r, _p| {
        Ok(json_response(&json!([]), 200))
    });
    r.add("POST", "/api/logout", logout);
    r.add("POST", "/api/currentUser", current_user);
    r.add("POST", "/api/heartbeat", heartbeat);
    r.add("POST", "/api/sysinfo", sysinfo);
    r.add("POST", "/api/sysinfo_ver", |a, _r, _p| {
        Ok(reply_text(&a.db.meta("instance_id").unwrap_or_default()))
    });
    r.add("POST", "/api/devices/cli", devices_cli);
    r.add("POST", "/api/audit/conn", audit_conn);
    r.add("POST", "/api/audit/file", audit_file);
    r.add("POST", "/api/audit/alarm", audit_alarm);
    r.add("GET", "/api/users", users);
    r.add("GET", "/api/peers", peers);
    r.add(
        "GET",
        "/api/device-group/accessible",
        device_groups_accessible,
    );
    r.add("POST", "/api/ab/settings", |a, req, _p| {
        bearer_actor(a, req)?;
        Ok(json_response(
            &json!({ "max_peer_one_ab": a.db.settings().max_peers_per_ab }),
            200,
        ))
    });
    r.add("POST", "/api/ab/personal", ab_personal);
    r.add("GET", "/api/ab/personal", ab_personal);
    r.add("POST", "/api/ab/shared/profiles", ab_shared_profiles);
    r.add("GET", "/api/ab/shared/profiles", ab_shared_profiles);
    r.add("POST", "/api/ab/peers", ab_peers);
    r.add("GET", "/api/ab/peers", ab_peers);
    r.add("POST", "/api/ab/tags/<guid>", ab_tags);
    r.add("GET", "/api/ab/tags/<guid>", ab_tags);
    r.add("POST", "/api/ab/peer/add/<guid>", ab_peer_add);
    r.add("PUT", "/api/ab/peer/update/<guid>", ab_peer_update);
    r.add("DELETE", "/api/ab/peer/<guid>", ab_peer_delete);
    r.add("POST", "/api/ab/tag/add/<guid>", ab_tag_add);
    r.add("PUT", "/api/ab/tag/rename/<guid>", ab_tag_rename);
    r.add("PUT", "/api/ab/tag/update/<guid>", ab_tag_update);
    r.add("DELETE", "/api/ab/tag/<guid>", ab_tag_delete);
    r.add("POST", "/api/ab/shared/add", ab_shared_add);
    r.add("PUT", "/api/ab/shared/update/profile", ab_shared_update);
    r.add("DELETE", "/api/ab/shared", ab_shared_delete);
    r.add("GET", "/api/ab/rules", ab_rules);
    r.add("POST", "/api/ab/rule", ab_rule_add);
    r.add("PATCH", "/api/ab/rule", ab_rule_update);
    r.add("DELETE", "/api/ab/rules", ab_rules_delete);
    r.add("GET", "/api/ab", ab_legacy_get);
    r.add("POST", "/api/ab", ab_legacy_post);
    r.add("POST", "/api/record", record);
}

// -- small helpers ------------------------------------------------------------

pub fn ok_empty() -> Response {
    Response::new(Vec::new(), 200, "text/plain; charset=utf-8")
}
fn reply_text(body: &str) -> Response {
    Response::new(body.as_bytes().to_vec(), 200, "text/plain; charset=utf-8")
}
fn error(message: &str) -> Response {
    json_response(&json!({ "error": message }), 200)
}

fn jstr(m: &Object, k: &str) -> String {
    m.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn jint(m: &Object, k: &str) -> Option<i64> {
    match m.get(k) {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    }
}

pub fn page_args(req: &Request) -> HttpResult<(i64, i64)> {
    let current = req
        .query
        .get("current")
        .map(|s| s.parse::<i64>())
        .transpose()
        .map_err(|_| HttpError::new(400, "Invalid pagination"))?
        .unwrap_or(1)
        .max(1);
    let size = req
        .query
        .get("pageSize")
        .map(|s| s.parse::<i64>())
        .transpose()
        .map_err(|_| HttpError::new(400, "Invalid pagination"))?
        .unwrap_or(100)
        .clamp(1, 1000);
    Ok((current, size))
}

fn device_id_of(data: &Object) -> HttpResult<(String, String)> {
    let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if id.is_empty() || id.len() > 64 {
        return Err(HttpError::new(400, "Invalid device ID"));
    }
    let uuid: String = data
        .get("uuid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(128)
        .collect();
    Ok((id.to_string(), uuid))
}

// -- authentication -----------------------------------------------------------

fn client_expiry(db: &Database) -> i64 {
    let days = db.settings().client_token_days;
    if days > 0 {
        now() + days * 86400
    } else {
        NEVER
    }
}

fn actor_from_user(u: &Row) -> Actor {
    Actor {
        user_id: ropt_int(u, "id"),
        group_id: ropt_int(u, "group_id"),
        user_is_admin: u.get("is_admin").and_then(|v| v.as_i64()).unwrap_or(0) != 0,
        user_name: rstr(u, "name"),
        token_name: None,
        token_perms: None,
    }
}

pub fn actor_from_token(token: &Row, creator: Option<&Row>) -> Actor {
    Actor {
        user_id: creator.and_then(|u| ropt_int(u, "id")),
        group_id: creator.and_then(|u| ropt_int(u, "group_id")),
        user_is_admin: false,
        user_name: creator.map(|u| rstr(u, "name")).unwrap_or_default(),
        token_name: Some(rstr(token, "name")),
        token_perms: Some(rstr(token, "perms")),
    }
}

/// The user behind a client login token.
pub fn client_user(app: &App, req: &Request) -> HttpResult<Row> {
    let token = req
        .bearer()
        .ok_or_else(|| HttpError::new(401, "Not logged in"))?;
    let db = &app.db;
    let row = db
        .query_one(
            "SELECT t.token_hash, t.last_seen_at, u.* FROM tokens t JOIN users u ON u.id = t.user_id \
             WHERE t.token_hash = ?1 AND t.kind = 'client' AND t.expires_at > ?2",
            &[text(token_hash(&token)), int(now())],
        )
        .ok()
        .flatten();
    let row = match row {
        Some(r) if r.get("status").and_then(|v| v.as_i64()) == Some(1) => r,
        _ => return Err(HttpError::new(401, "Invalid or expired token")),
    };
    if now() - models::rint(&row, "last_seen_at") > 60 {
        let _ = db.execute(
            "UPDATE tokens SET last_seen_at = ?1, expires_at = ?2 WHERE token_hash = ?3",
            &[
                int(now()),
                int(client_expiry(db)),
                text(rstr(&row, "token_hash")),
            ],
        );
    }
    Ok(row)
}

/// The API token (Settings > Tokens) in the Authorization header, or None.
pub fn api_token(app: &App, req: &Request) -> HttpResult<Option<Row>> {
    let Some(token) = req.bearer() else {
        return Ok(None);
    };
    let row = app
        .db
        .query_one(
            "SELECT * FROM api_tokens WHERE token_hash = ?1",
            &[text(token_hash(&token))],
        )
        .ok()
        .flatten();
    let Some(row) = row else { return Ok(None) };
    if let Some(exp) = ropt_int(&row, "expires_at") {
        if exp < now() {
            return Err(HttpError::new(401, "API token expired"));
        }
    }
    let last = ropt_int(&row, "last_used_at");
    if last.is_none() || now() - last.unwrap() > 60 {
        let _ = app.db.execute(
            "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
            &[int(now()), int(models::rint(&row, "id"))],
        );
    }
    Ok(Some(row))
}

/// An API token or a client login, for endpoints both may call. Returns the
/// actor and the backing user row (the token's creator, if any).
pub fn bearer_actor(app: &App, req: &Request) -> HttpResult<(Actor, Option<Row>)> {
    if let Some(token) = api_token(app, req)? {
        let creator = ropt_int(&token, "user_id").and_then(|uid| {
            app.db
                .query_one("SELECT * FROM users WHERE id = ?1", &[int(uid)])
                .ok()
                .flatten()
        });
        let actor = actor_from_token(&token, creator.as_ref());
        return Ok((actor, creator));
    }
    let user = client_user(app, req)?;
    let actor = actor_from_user(&user);
    Ok((actor, Some(user)))
}

pub fn console_url(app: &App, req: &Request) -> String {
    let url = app.db.settings().console_url;
    if !url.is_empty() {
        return url.trim_end_matches('/').to_string();
    }
    match req.header("host") {
        Some(host) if !host.is_empty() => format!("{}://{}", req.scheme, host),
        _ => String::new(),
    }
}

/// The server key, from the `server_key` setting or the hbbs key file.
pub fn hbbs_key(app: &App) -> String {
    let key = app.db.settings().server_key;
    if !key.is_empty() {
        return key;
    }
    let path = &app.cfg.hbbs_key_file;
    if !path.is_empty() {
        if let Ok(data) = std::fs::read_to_string(path) {
            return data.trim().to_string();
        }
    }
    String::new()
}

/// The API URL a client derives when its API server field is empty: the ID
/// server's port minus 2, or 21114 when no port is given.
pub fn derived_api(host: &str) -> String {
    if host.is_empty() {
        return String::new();
    }
    let (name, port) = if host.starts_with('[') {
        match host.split_once("]:") {
            Some((h, p)) => (format!("{h}]"), p.to_string()),
            None => (host.to_string(), String::new()),
        }
    } else if host.matches(':').count() == 1 {
        let (h, p) = host.split_once(':').unwrap();
        (h.to_string(), p.to_string())
    } else {
        (host.to_string(), String::new())
    };
    let api_port = port.parse::<i64>().map(|p| p - 2).unwrap_or(21114);
    format!("http://{name}:{api_port}")
}

/// The client configuration shown in the console (host, relay, key and the
/// encoded strings RustDesk accepts). Port of admin_api.client_config.
pub fn client_config(app: &App, req: &Request) -> Object {
    let s = app.db.settings();
    let host_header = req.header("host").unwrap_or("").trim().to_string();
    let mut hostname = if host_header.starts_with('[') {
        host_header
            .split_once(']')
            .map(|(h, _)| format!("{h}]"))
            .unwrap_or_else(|| host_header.clone())
    } else {
        host_header.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(host_header.clone())
    };
    if s.id_server.is_empty() && app.cfg.id_server.is_empty() && !hostname.is_empty() {
        // By convention hbbs listens two ports above this server.
        hostname = format!("{hostname}:{}", app.cfg.port as i64 + 2);
    }
    let host = first_non_empty(&[&s.id_server, &app.cfg.id_server, &hostname]);
    let relay = first_non_empty(&[&s.relay_server, &app.cfg.relay_server]);
    let key = hbbs_key(app);
    let mut config = Object::new();
    config.insert("host".into(), Value::Str(host.clone()));
    config.insert("relay".into(), Value::Str(relay));
    config.insert("api".into(), Value::Str(s.api_server.clone()));
    config.insert("key".into(), Value::Str(key));
    let compact = crate::json::to_string(&Value::Object(config.clone()));
    let encoded: String = crate::encoding::base64url_encode(compact.as_bytes())
        .chars()
        .rev()
        .collect();
    config.insert("config_string".into(), Value::Str(encoded.clone()));
    config.insert("api_default".into(), Value::Str(derived_api(&host)));
    config.insert("windows_exe".into(), Value::Str(format!("rustdesk-licensed-{encoded}.exe")));
    config
}

fn first_non_empty(values: &[&str]) -> String {
    values.iter().find(|v| !v.is_empty()).map(|v| v.to_string()).unwrap_or_default()
}

fn issue_client_token(app: &App, req: &Request, user: &Row, data: &Object) -> Response {
    let db = &app.db;
    let token = new_token();
    let device_id: String = jstr(data, "id").chars().take(64).collect();
    let device_uuid: String = jstr(data, "uuid").chars().take(128).collect();
    let info = match data.get("deviceInfo") {
        Some(Value::Object(m)) => Value::Object(m.clone()).to_string(),
        _ => "{}".to_string(),
    };
    let uid = models::rint(user, "id");
    let _ = db.execute(
        "INSERT INTO tokens(token_hash, user_id, kind, device_id, device_uuid, device_info, ip, \
         created_at, last_seen_at, expires_at) VALUES (?1,?2,'client',?3,?4,?5,?6,?7,?7,?8)",
        &[
            text(token_hash(&token)),
            int(uid),
            text(&device_id),
            text(&device_uuid),
            text(info.chars().take(2048).collect::<String>()),
            text(&req.ip),
            int(now()),
            int(client_expiry(db)),
        ],
    );
    let _ = db.execute(
        "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
        &[int(now()), int(uid)],
    );
    if !device_id.is_empty() && device_id.len() <= 64 {
        models::ensure_device(db, &device_id, &device_uuid, &req.ip);
        let _ = db.execute(
            "UPDATE devices SET user_id = ?1 WHERE id = ?2",
            &[int(uid), text(&device_id)],
        );
    }
    models::personal_book(db, uid);
    json_response(
        &json!({
            "access_token": token,
            "type": "access_token",
            "user": models::user_payload(user, None),
        }),
        200,
    )
}

fn login(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let kind = {
        let k = jstr(&data, "type");
        if k.is_empty() {
            "account".to_string()
        } else {
            k
        }
    };
    if kind == "account" {
        let device_id = jstr(&data, "id");
        match auth::check_password(
            &app.db,
            &req.ip,
            &jstr(&data, "username"),
            &jstr(&data, "password"),
            &device_id,
        ) {
            Err(e) => Ok(error(&e.0)),
            Ok(user) => {
                if auth::needs_2fa_setup(&user) {
                    return Ok(error(&format!(
                        "Two-factor authentication is required for this account. Set it up in \
                         the web console first: {}",
                        console_url(app, req)
                    )));
                }
                match auth::second_factor(&user) {
                    None => Ok(issue_client_token(app, req, &user, &data)),
                    Some(method) => match auth::start_challenge(&app.db, &user, method) {
                        Err(e) => Ok(error(&e.message)),
                        Ok(secret) => {
                            let mut resp = json!({
                                "type": "email_check",
                                "secret": secret,
                                "user": models::user_payload(&user, None),
                            });
                            if method == "totp" {
                                resp["tfa_type"] = json!("tfa_check");
                            }
                            Ok(json_response(&resp, 200))
                        }
                    },
                }
            }
        }
    } else if kind == "email_code" || kind == "tfa_code" {
        let code = {
            let c = jstr(&data, "tfaCode");
            if c.is_empty() {
                jstr(&data, "verificationCode")
            } else {
                c
            }
        };
        match auth::finish_challenge(&app.db, &jstr(&data, "secret"), &code) {
            Err(e) => Ok(error(&e.0)),
            Ok(user) => Ok(issue_client_token(app, req, &user, &data)),
        }
    } else {
        Ok(error("Unsupported login type"))
    }
}

fn logout(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    if let Some(token) = req.bearer() {
        let _ = app.db.execute(
            "DELETE FROM tokens WHERE token_hash = ?1 AND kind = 'client'",
            &[text(token_hash(&token))],
        );
    }
    Ok(ok_empty())
}

fn current_user(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let user = client_user(app, req)?;
    Ok(json_response(&models::user_payload(&user, None), 200))
}

// -- device sync --------------------------------------------------------------

fn heartbeat(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let (device_id, device_uuid) = device_id_of(&data)?;
    let conns: Vec<i64> = data
        .get("conns")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).take(256).collect())
        .unwrap_or_default();
    let client_stamp = jint(&data, "modified_at").unwrap_or(0);
    let db = &app.db;
    let mut resp = Object::new();

    let device = models::ensure_device(db, &device_id, &device_uuid, &req.ip)
        .ok_or_else(|| HttpError::new(500, "device error"))?;
    let conns_json = crate::json::to_string(&Value::from(conns.clone()));
    let uuid_final = if device_uuid.is_empty() {
        rstr(&device, "uuid")
    } else {
        device_uuid.clone()
    };
    let _ = db.execute(
        "UPDATE devices SET last_seen_at = ?1, ip = ?2, conns = ?3, uuid = ?4 WHERE id = ?5",
        &[
            int(now()),
            text(&req.ip),
            text(&conns_json),
            text(&uuid_final),
            text(&device_id),
        ],
    );
    if ropt_int(&device, "sysinfo_at").is_none() {
        resp.insert("sysinfo".into(), json!(1));
    }
    let pending: Vec<i64> = db
        .query(
            "SELECT conn_id FROM pending_disconnects WHERE device_id = ?1",
            &[text(&device_id)],
        )
        .unwrap_or_default()
        .iter()
        .map(|r| models::rint(r, "conn_id"))
        .collect();
    if !pending.is_empty() {
        resp.insert("disconnect".into(), json!(pending));
        let _ = db.execute(
            "DELETE FROM pending_disconnects WHERE device_id = ?1",
            &[text(&device_id)],
        );
    }
    let open_rows = db
        .query(
            "SELECT id, conn_id FROM conn_logs WHERE device_id = ?1 AND ended_at IS NULL \
             AND started_at < ?2",
            &[text(&device_id), int(now() - 60)],
        )
        .unwrap_or_default();
    for row in &open_rows {
        if !conns.contains(&models::rint(row, "conn_id")) {
            let _ = db.execute(
                "UPDATE conn_logs SET ended_at = ?1 WHERE id = ?2",
                &[int(now()), int(models::rint(row, "id"))],
            );
        }
    }

    let device = db
        .query_one("SELECT * FROM devices WHERE id = ?1", &[text(&device_id)])
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(500, "device error"))?;
    let (options, stamp) = models::desired_config(db, &device);
    if stamp != client_stamp {
        let mut config: Object = Object::new();
        for (k, v) in &options {
            config.insert(k.clone(), json!(v));
        }
        if let Value::Array(applied) = models::loads_or(&rstr(&device, "applied_keys"), json!([])) {
            for key in applied {
                if let Some(k) = key.as_str() {
                    if !config.contains_key(k) {
                        config.insert(k.to_string(), json!(""));
                    }
                }
            }
        }
        if !config.is_empty() || client_stamp != 0 {
            resp.insert("strategy".into(), json!({ "config_options": config }));
        }
        resp.insert("modified_at".into(), json!(stamp));
        let keys: Vec<&String> = options.keys().collect();
        let _ = db.execute(
            "UPDATE devices SET applied_keys = ?1 WHERE id = ?2",
            &[
                text(crate::json::to_string(&Value::from(keys))),
                text(&device_id),
            ],
        );
    }
    Ok(json_response(&Value::Object(resp), 200))
}

fn sysinfo(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let (device_id, device_uuid) = device_id_of(&data)?;
    let field = |name: &str, limit: usize| -> String {
        match data.get(name) {
            Some(Value::Null) | None => String::new(),
            Some(Value::Str(s)) => s.chars().take(limit).collect(),
            Some(other) => other.to_string().chars().take(limit).collect(),
        }
    };
    let db = &app.db;
    let device = models::ensure_device(db, &device_id, &device_uuid, &req.ip)
        .ok_or_else(|| HttpError::new(500, "device error"))?;
    let uuid_final = if device_uuid.is_empty() {
        rstr(&device, "uuid")
    } else {
        device_uuid.clone()
    };
    let _ = db.execute(
        "UPDATE devices SET hostname=?1, username=?2, os=?3, cpu=?4, memory=?5, version=?6, \
         sysinfo=?7, ip=?8, uuid=?9, sysinfo_at=?10, last_seen_at=?10 WHERE id=?11",
        &[
            text(field("hostname", 256)),
            text(field("username", 256)),
            text(field("os", 256)),
            text(field("cpu", 256)),
            text(field("memory", 256)),
            text(field("version", 32)),
            text(
                Value::Object(data.clone())
                    .to_string()
                    .chars()
                    .take(16384)
                    .collect::<String>(),
            ),
            text(&req.ip),
            text(&uuid_final),
            int(now()),
            text(&device_id),
        ],
    );
    let mut assign = Object::new();
    for (src, dst) in [
        ("preset-user-name", "user_name"),
        ("preset-device-group-name", "device_group_name"),
        ("preset-strategy-name", "strategy_name"),
        ("preset-address-book-name", "address_book_name"),
        ("preset-address-book-tag", "address_book_tag"),
        ("preset-address-book-alias", "address_book_alias"),
        ("preset-address-book-password", "address_book_password"),
        ("preset-address-book-note", "address_book_note"),
        ("preset-note", "note"),
    ] {
        if let Some(v) = data.get(src) {
            assign.insert(dst.to_string(), v.clone());
        }
    }
    apply_assignments(db, &device, &assign, true);
    Ok(reply_text("SYSINFO_UPDATED"))
}

/// Assign a device to a user, group, strategy and address book by name.
pub fn apply_assignments(
    db: &Database,
    device: &Row,
    values: &Object,
    keep_existing: bool,
) -> Vec<String> {
    let mut errors = Vec::new();
    let device_id = rstr(device, "id");
    let given = |key: &str| -> Option<String> {
        values
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    for (key, table, column) in [
        ("user_name", "users", "user_id"),
        ("device_group_name", "device_groups", "device_group_id"),
        ("strategy_name", "strategies", "strategy_id"),
    ] {
        let Some(name) = given(key) else { continue };
        if keep_existing && ropt_int(device, column).is_some() {
            continue;
        }
        let row = db
            .query_one(
                &format!("SELECT id FROM {table} WHERE name = ?1"),
                &[text(&name)],
            )
            .ok()
            .flatten();
        match row {
            None => errors.push(format!(
                "{} '{}' not found",
                key.replace("_name", "").replace('_', " "),
                name
            )),
            Some(r) => {
                let _ = db.execute(
                    &format!("UPDATE devices SET {column} = ?1 WHERE id = ?2"),
                    &[int(models::rint(&r, "id")), text(&device_id)],
                );
            }
        }
    }
    for (key, column) in [
        ("note", "note"),
        ("device_username", "username_override"),
        ("device_name", "name_override"),
    ] {
        if let Some(value) = given(key) {
            if !(keep_existing && !rstr(device, column).is_empty()) {
                let _ = db.execute(
                    &format!("UPDATE devices SET {column} = ?1 WHERE id = ?2"),
                    &[
                        text(value.chars().take(1024).collect::<String>()),
                        text(&device_id),
                    ],
                );
            }
        }
    }
    if let Some(name) = given("address_book_name") {
        let book = db
            .query_one(
                "SELECT guid FROM address_books WHERE name = ?1 AND personal = 0 \
                 ORDER BY created_at LIMIT 1",
                &[text(&name)],
            )
            .ok()
            .flatten();
        match book {
            None => errors.push(format!("address book '{name}' not found")),
            Some(book) => {
                let guid = rstr(&book, "guid");
                let existing = db
                    .query_one(
                        "SELECT deleted_at FROM ab_peers WHERE guid = ?1 AND peer_id = ?2",
                        &[text(&guid), text(&device_id)],
                    )
                    .ok()
                    .flatten();
                let gone = existing
                    .as_ref()
                    .map(|e| ropt_int(e, "deleted_at").is_some())
                    .unwrap_or(true);
                if existing.is_none() || gone || !keep_existing {
                    let mut peer = Object::new();
                    peer.insert("id".into(), json!(device_id));
                    if let Some(tag) = given("address_book_tag") {
                        let tag: String = tag.chars().take(64).collect();
                        let _ = db.execute(
                            "INSERT OR IGNORE INTO ab_tags(guid, name, color) VALUES (?1,?2,?3)",
                            &[text(&guid), text(&tag), int(0xFF2196F3)],
                        );
                        peer.insert("tags".into(), json!([tag]));
                    }
                    for (key, target) in [
                        ("address_book_alias", "alias"),
                        ("address_book_password", "password"),
                        ("address_book_note", "note"),
                    ] {
                        if let Some(v) = given(key) {
                            peer.insert(target.into(), json!(v));
                        }
                    }
                    models::upsert_peer(db, &guid, &peer, false, false);
                }
            }
        }
    }
    errors
}

fn devices_cli(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let token = match api_token(app, req)? {
        Some(t) => t,
        None => return Ok(reply_text("Invalid token")),
    };
    let actor = actor_from_token(&token, None);
    if !actor.can(&app.db, "devices.edit_info") {
        return Ok(reply_text("The token needs Device read/write permission"));
    }
    let data = req.json_object()?;
    let (device_id, device_uuid) = device_id_of(&data)?;
    let device = models::ensure_device(&app.db, &device_id, &device_uuid, &req.ip)
        .ok_or_else(|| HttpError::new(500, "device error"))?;
    let errors = apply_assignments(&app.db, &device, &data, false);
    models::console_log(
        &app.db,
        None,
        &actor.name(),
        &req.ip,
        "device.update",
        &device_id,
        "assigned from the command line",
    );
    Ok(reply_text(&errors.join("; ")))
}

// -- audit --------------------------------------------------------------------

fn claim_nonce(db: &Database, data: &Object) -> bool {
    let nonce = jstr(data, "nonce");
    if nonce.is_empty() {
        return true;
    }
    let affected = db
        .execute(
            "INSERT OR IGNORE INTO nonces(nonce, created_at) VALUES (?1, ?2)",
            &[text(nonce.chars().take(64).collect::<String>()), int(now())],
        )
        .unwrap_or(0);
    affected > 0
}

fn audit_conn(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let (device_id, _) = device_id_of(&data)?;
    let session_id: String = jstr(&data, "session_id").chars().take(64).collect();
    let conn_id = jint(&data, "conn_id");
    let db = &app.db;
    let Some(conn_id) = conn_id else {
        if data.contains_key("note") {
            let _ = db.execute(
                "UPDATE conn_logs SET note = ?1 WHERE id = (SELECT id FROM conn_logs \
                 WHERE device_id = ?2 AND session_id = ?3 ORDER BY id DESC LIMIT 1)",
                &[
                    text(jstr(&data, "note").chars().take(1024).collect::<String>()),
                    text(&device_id),
                    text(&session_id),
                ],
            );
            return Ok(ok_empty());
        }
        return Err(HttpError::new(400, "Missing conn_id"));
    };
    let action = jstr(&data, "action");
    if !claim_nonce(db, &data) {
        return Ok(ok_empty());
    }
    let open_row = db
        .query_one(
            "SELECT id FROM conn_logs WHERE device_id = ?1 AND conn_id = ?2 AND ended_at IS NULL \
             ORDER BY id DESC LIMIT 1",
            &[text(&device_id), int(conn_id)],
        )
        .ok()
        .flatten();
    if action == "new" {
        let _ = db.execute(
            "INSERT INTO conn_logs(device_id, conn_id, session_id, ip, started_at) \
             VALUES (?1,?2,?3,?4,?5)",
            &[
                text(&device_id),
                int(conn_id),
                text(&session_id),
                text(jstr(&data, "ip").chars().take(64).collect::<String>()),
                int(now()),
            ],
        );
    } else if action == "close" {
        if let Some(row) = &open_row {
            let _ = db.execute(
                "UPDATE conn_logs SET ended_at = ?1 WHERE id = ?2",
                &[int(now()), int(models::rint(row, "id"))],
            );
        }
    } else {
        let peer = data.get("peer").and_then(|v| v.as_array());
        let peer_id: String = peer
            .and_then(|p| p.first())
            .map(value_to_string)
            .unwrap_or_default()
            .chars()
            .take(64)
            .collect();
        let peer_name: String = peer
            .and_then(|p| p.get(1))
            .map(value_to_string)
            .unwrap_or_default()
            .chars()
            .take(256)
            .collect();
        let controller = models::controller_of(db, &peer_id);
        if let Some(row) = &open_row {
            let _ = db.execute(
                "UPDATE conn_logs SET peer_id=?1, peer_name=?2, type=?3, primary_auth=?4, \
                 two_factor=?5, authorized_at=?6, controller=?7, \
                 session_id = COALESCE(NULLIF(?8, ''), session_id) WHERE id = ?9",
                &[
                    text(&peer_id),
                    text(&peer_name),
                    opt_int(jint(&data, "type")),
                    opt_int(jint(&data, "primary_auth")),
                    opt_int(jint(&data, "two_factor")),
                    int(now()),
                    text(&controller),
                    text(&session_id),
                    int(models::rint(row, "id")),
                ],
            );
        } else {
            let _ = db.execute(
                "INSERT INTO conn_logs(peer_id, peer_name, type, primary_auth, two_factor, \
                 authorized_at, controller, device_id, conn_id, session_id, started_at) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                &[
                    text(&peer_id),
                    text(&peer_name),
                    opt_int(jint(&data, "type")),
                    opt_int(jint(&data, "primary_auth")),
                    opt_int(jint(&data, "two_factor")),
                    int(now()),
                    text(&controller),
                    text(&device_id),
                    int(conn_id),
                    text(&session_id),
                    int(now()),
                ],
            );
        }
    }
    Ok(ok_empty())
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => other.to_string(),
    }
}

fn info_json(data: &Object) -> String {
    match data.get("info") {
        Some(Value::Str(s)) => {
            // a JSON string; re-encode the parsed object, else {}
            crate::json::from_str(s).unwrap_or(json!({})).to_string()
        }
        Some(Value::Object(m)) => Value::Object(m.clone()).to_string(),
        _ => "{}".to_string(),
    }
}

fn audit_file(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let (device_id, _) = device_id_of(&data)?;
    let db = &app.db;
    if !claim_nonce(db, &data) {
        return Ok(ok_empty());
    }
    let _ = db.execute(
        "INSERT INTO file_logs(device_id, peer_id, conn_id, type, path, is_file, info, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        &[
            text(&device_id),
            text(jstr(&data, "peer_id").chars().take(64).collect::<String>()),
            opt_int(jint(&data, "conn_id")),
            int(jint(&data, "type").unwrap_or(0)),
            text(jstr(&data, "path").chars().take(4096).collect::<String>()),
            int(if data.get("is_file").and_then(|v| v.as_bool()).unwrap_or(false) { 1 } else { 0 }),
            text(info_json(&data).chars().take(16384).collect::<String>()),
            int(now()),
        ],
    );
    Ok(ok_empty())
}

fn audit_alarm(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let (device_id, _) = device_id_of(&data)?;
    let db = &app.db;
    if !claim_nonce(db, &data) {
        return Ok(ok_empty());
    }
    let info_val: Value = match data.get("info") {
        Some(Value::Str(s)) => crate::json::from_str(s).unwrap_or(json!({})),
        Some(Value::Object(m)) => Value::Object(m.clone()),
        _ => json!({}),
    };
    let ip = info_val.get("ip").and_then(|v| v.as_str()).unwrap_or("");
    let _ = db.execute(
        "INSERT INTO alarm_logs(device_id, typ, info, conn_id, ip, created_at) \
         VALUES (?1,?2,?3,?4,?5,?6)",
        &[
            text(&device_id),
            int(jint(&data, "typ").unwrap_or(-1)),
            text(info_val.to_string().chars().take(16384).collect::<String>()),
            opt_int(jint(&data, "conn_id")),
            text(ip.chars().take(64).collect::<String>()),
            int(now()),
        ],
    );
    Ok(ok_empty())
}

// -- accessible users, devices and groups -------------------------------------

fn users(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = bearer_actor(app, req)?;
    let db = &app.db;
    let (current, size) = page_args(req)?;
    let mut where_ = vec!["1".to_string()];
    let mut params: Vec<crate::db::SqlValue> = Vec::new();
    if actor.token_name.is_some() {
        actor.require(db, "users.view")?;
    } else if db.settings().disable_accessible_devices {
        return Ok(json_response(&json!({ "total": 0, "data": [] }), 200));
    } else if let Some(u) = &user {
        if let Some(ids) = models::accessible_users(db, u) {
            where_.push(format!("u.id IN ({})", vec!["?"; ids.len()].join(",")));
            params.extend(ids.iter().map(|x| int(*x)));
        }
    }
    if req.query.get("status").map(|s| s.as_str()) == Some("1") {
        where_.push("u.status = 1".into());
    }
    for (key, column) in [("name", "u.name"), ("group_name", "g.name")] {
        if let Some(v) = req.query.get(key) {
            where_.push(format!("{column} LIKE ?"));
            params.push(text(models::like(v)));
        }
    }
    let sql = where_.join(" AND ");
    let joins = "FROM users u LEFT JOIN user_groups g ON g.id = u.group_id";
    let total = db
        .query_one(
            &format!("SELECT COUNT(*) AS n {joins} WHERE {sql}"),
            &params,
        )
        .ok()
        .flatten()
        .map(|r| models::rint(&r, "n"))
        .unwrap_or(0);
    let mut page_params = params.clone();
    page_params.push(int(size));
    page_params.push(int((current - 1) * size));
    let rows = db
        .query(
            &format!(
                "SELECT u.*, g.name AS gname {joins} WHERE {sql} \
                 ORDER BY u.name COLLATE NOCASE LIMIT ? OFFSET ?"
            ),
            &page_params,
        )
        .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            let g = rstr(r, "gname");
            models::user_payload(r, Some(&g))
        })
        .collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

fn peers(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let user = client_user(app, req)?;
    let db = &app.db;
    let (current, size) = page_args(req)?;
    if db.settings().disable_accessible_devices {
        return Ok(json_response(&json!({ "total": 0, "data": [] }), 200));
    }
    let scope = models::accessible_scope(db, &user);
    let (cond, mut params) = models::accessible_sql(&scope, "d");
    let total = db
        .query_one(
            &format!("SELECT COUNT(*) AS n FROM devices d WHERE {cond}"),
            &params,
        )
        .ok()
        .flatten()
        .map(|r| models::rint(&r, "n"))
        .unwrap_or(0);
    params.push(int(size));
    params.push(int((current - 1) * size));
    let rows = db
        .query(
            &format!(
                "SELECT d.*, u.name AS owner, g.name AS group_name FROM devices d \
                 LEFT JOIN users u ON u.id = d.user_id \
                 LEFT JOIN device_groups g ON g.id = d.device_group_id \
                 WHERE {cond} ORDER BY d.id LIMIT ? OFFSET ?"
            ),
            &params,
        )
        .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            let name_o = rstr(r, "name_override");
            let host = if name_o.is_empty() {
                rstr(r, "hostname")
            } else {
                name_o
            };
            let user_o = rstr(r, "username_override");
            let uname = if user_o.is_empty() {
                rstr(r, "username")
            } else {
                user_o
            };
            json!({
                "id": rstr(r, "id"),
                "info": { "device_name": host, "os": rstr(r, "os"), "username": uname },
                "status": 1,
                "user": rstr(r, "owner"),
                "user_name": rstr(r, "owner"),
                "device_group_name": rstr(r, "group_name"),
                "note": rstr(r, "note"),
            })
        })
        .collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

fn device_groups_accessible(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let user = client_user(app, req)?;
    let db = &app.db;
    let (current, size) = page_args(req)?;
    if db.settings().disable_accessible_devices {
        return Ok(json_response(&json!({ "total": 0, "data": [] }), 200));
    }
    let scope = models::accessible_scope(db, &user);
    let rows = match &scope {
        None => db
            .query(
                "SELECT name FROM device_groups ORDER BY name COLLATE NOCASE",
                &[],
            )
            .unwrap_or_default(),
        Some((_, ids)) if !ids.is_empty() => {
            let marks = vec!["?"; ids.len()].join(",");
            let params: Vec<_> = ids.iter().map(|x| int(*x)).collect();
            db.query(
                &format!(
                    "SELECT name FROM device_groups WHERE id IN ({marks}) ORDER BY name COLLATE NOCASE"
                ),
                &params,
            )
            .unwrap_or_default()
        }
        _ => vec![],
    };
    let total = rows.len() as i64;
    let start = ((current - 1) * size).max(0) as usize;
    let page: Vec<Value> = rows
        .iter()
        .skip(start)
        .take(size as usize)
        .map(|r| json!({ "name": rstr(r, "name") }))
        .collect();
    Ok(json_response(&json!({ "total": total, "data": page }), 200))
}

// -- address books ------------------------------------------------------------

fn rule_of(app: &App, actor: &Actor, guid: &str) -> i64 {
    if actor.token_name.is_some() {
        let book = app
            .db
            .query_one(
                "SELECT personal, owner_id FROM address_books WHERE guid = ?1",
                &[text(guid)],
            )
            .ok()
            .flatten();
        let Some(book) = book else { return 0 };
        if models::rbool(&book, "personal") && ropt_int(&book, "owner_id") != actor.user_id {
            return 0;
        }
        return match actor.ab_level() {
            0 => 0,
            1 => RULE_READ,
            _ => RULE_FULL,
        };
    }
    // Build a minimal user row for book_rule.
    let user = user_row_for(actor);
    models::book_rule(&app.db, &user, guid, false)
}

fn user_row_for(actor: &Actor) -> Row {
    let mut m = Row::new();
    m.insert("id".into(), json!(actor.user_id));
    m.insert("group_id".into(), json!(actor.group_id));
    m.insert("is_admin".into(), json!(actor.user_is_admin as i64));
    m
}

/// (actor, book row, personal) after checking the rule meets `need`.
fn book_access(app: &App, req: &Request, guid: &str, need: i64) -> HttpResult<(Actor, Row, bool)> {
    let (actor, _) = bearer_actor(app, req)?;
    let rule = rule_of(app, &actor, guid);
    if rule < need {
        return Err(HttpError::new(403, "No permission for this address book"));
    }
    let book = app
        .db
        .query_one("SELECT * FROM address_books WHERE guid = ?1", &[text(guid)])
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Address book not found"))?;
    let personal = models::rbool(&book, "personal");
    Ok((actor, book, personal))
}

fn action_result(err: Option<String>) -> Response {
    match err {
        Some(e) => error(&e),
        None => ok_empty(),
    }
}

fn ab_personal(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = bearer_actor(app, req)?;
    let uid = actor.user_id.ok_or_else(|| {
        HttpError::new(
            400,
            "This token has no user, so it has no personal address book",
        )
    })?;
    Ok(json_response(
        &json!({ "guid": models::personal_book(&app.db, uid) }),
        200,
    ))
}

fn name_matches(pattern: &str, name: &str) -> bool {
    // '%' is a wildcard, as in SQL LIKE; anchored.
    let parts: Vec<&str> = pattern.split('%').collect();
    let lname = name.to_lowercase();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        let lpart = part.to_lowercase();
        if i == 0 {
            if !lname[pos..].starts_with(&lpart) {
                return false;
            }
            pos += lpart.len();
        } else if i == parts.len() - 1 {
            return lname[pos..].ends_with(&lpart);
        } else if let Some(idx) = lname[pos..].find(&lpart) {
            pos += idx + lpart.len();
        } else {
            return false;
        }
    }
    true
}

fn ab_shared_profiles(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = bearer_actor(app, req)?;
    let (current, size) = page_args(req)?;
    let db = &app.db;
    let mut books: Vec<Row> = if actor.token_name.is_some() {
        if actor.ab_level() == 0 {
            return Err(HttpError::new(
                403,
                "The token has no Address Book permission",
            ));
        }
        let rule = if actor.ab_level() >= 2 {
            RULE_FULL
        } else {
            RULE_READ
        };
        db.query(
            "SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id \
             WHERE b.personal = 0 ORDER BY b.name COLLATE NOCASE",
            &[],
        )
        .unwrap_or_default()
        .into_iter()
        .map(|mut r| {
            r.insert("rule".into(), json!(rule));
            r
        })
        .collect()
    } else {
        models::shared_books_for(db, user.as_ref().unwrap())
    };
    if let Some(name) = req.query.get("name") {
        books.retain(|b| name_matches(name, &rstr(b, "name")));
    }
    let total = books.len() as i64;
    let start = ((current - 1) * size).max(0) as usize;
    let data: Vec<Value> = books
        .iter()
        .skip(start)
        .take(size as usize)
        .map(|b| models::profile_payload(b, models::rint(b, "rule")))
        .collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

fn ab_peers(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let guid = req.query.get("ab").cloned().unwrap_or_default();
    let (_, _, personal) = book_access(app, req, &guid, RULE_READ)?;
    let (current, size) = page_args(req)?;
    let mut where_ = vec!["guid = ?".to_string(), "deleted_at IS NULL".to_string()];
    let mut params: Vec<crate::db::SqlValue> = vec![text(&guid)];
    for (key, column) in [("id", "peer_id"), ("alias", "alias")] {
        if let Some(v) = req.query.get(key) {
            where_.push(format!("{column} LIKE ?"));
            params.push(text(models::like(v)));
        }
    }
    let sql = where_.join(" AND ");
    let total = app
        .db
        .query_one(
            &format!("SELECT COUNT(*) AS n FROM ab_peers WHERE {sql}"),
            &params,
        )
        .ok()
        .flatten()
        .map(|r| models::rint(&r, "n"))
        .unwrap_or(0);
    params.push(int(size));
    params.push(int((current - 1) * size));
    let rows = app
        .db
        .query(
            &format!(
                "SELECT * FROM ab_peers WHERE {sql} ORDER BY created_at, peer_id LIMIT ? OFFSET ?"
            ),
            &params,
        )
        .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|r| models::peer_payload(&app.db, r, personal))
        .collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

fn ab_tags(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ)?;
    let rows = app
        .db
        .query(
            "SELECT name, color FROM ab_tags WHERE guid = ?1 ORDER BY rowid",
            &[text(&guid)],
        )
        .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|r| json!({ "name": rstr(r, "name"), "color": models::rint(r, "color") }))
        .collect();
    Ok(json_response(&Value::Array(data), 200))
}

fn ab_peer_add(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (_, _, personal) = book_access(app, req, &guid, RULE_READ_WRITE)?;
    let peer = req.json_object()?;
    let limit = app.db.settings().max_peers_per_ab;
    if limit > 0 {
        let count = app
            .db
            .query_one(
                "SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?1 AND deleted_at IS NULL",
                &[text(&guid)],
            )
            .ok()
            .flatten()
            .map(|r| models::rint(&r, "n"))
            .unwrap_or(0);
        if count >= limit {
            return Ok(error("exceed_max_devices"));
        }
    }
    Ok(action_result(models::upsert_peer(
        &app.db, &guid, &peer, personal, false,
    )))
}

fn ab_peer_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (_, _, personal) = book_access(app, req, &guid, RULE_READ_WRITE)?;
    let peer = req.json_object()?;
    Ok(action_result(models::upsert_peer(
        &app.db, &guid, &peer, personal, true,
    )))
}

fn ab_peer_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ_WRITE)?;
    let ids = req.json()?;
    let ids = ids
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list of IDs"))?;
    let ids: Vec<String> = ids.iter().map(value_to_string).collect();
    models::recycle_peers(&app.db, &guid, &ids);
    Ok(ok_empty())
}

fn tag_body(req: &Request) -> HttpResult<(String, i64)> {
    let data = req.json_object()?;
    let name = jstr(&data, "name");
    if name.is_empty() || name.len() > 64 {
        return Err(HttpError::new(400, "Invalid tag name"));
    }
    let color = jint(&data, "color").unwrap_or(0);
    Ok((name, color))
}

fn ab_tag_add(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ_WRITE)?;
    let (name, color) = tag_body(req)?;
    let _ = app.db.execute(
        "INSERT INTO ab_tags(guid, name, color) VALUES (?1,?2,?3) \
         ON CONFLICT(guid, name) DO UPDATE SET color = excluded.color",
        &[text(&guid), text(&name), int(color)],
    );
    Ok(ok_empty())
}

fn ab_tag_rename(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ_WRITE)?;
    let data = req.json_object()?;
    let old = jstr(&data, "old");
    let new = jstr(&data, "new");
    if old.is_empty() || new.is_empty() || old.len() > 64 || new.len() > 64 {
        return Err(HttpError::new(400, "Invalid tag name"));
    }
    if app
        .db
        .query_one(
            "SELECT 1 AS n FROM ab_tags WHERE guid = ?1 AND name = ?2",
            &[text(&guid), text(&new)],
        )
        .ok()
        .flatten()
        .is_some()
    {
        return Ok(error(&format!("Tag {new} already exists")));
    }
    models::rename_tag(&app.db, &guid, &old, &new);
    Ok(ok_empty())
}

fn ab_tag_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ_WRITE)?;
    let (name, color) = tag_body(req)?;
    let _ = app.db.execute(
        "UPDATE ab_tags SET color = ?1 WHERE guid = ?2 AND name = ?3",
        &[int(color), text(&guid), text(&name)],
    );
    Ok(ok_empty())
}

fn ab_tag_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_READ_WRITE)?;
    let names = req.json()?;
    let names = names
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list of tags"))?;
    let names: Vec<String> = names.iter().map(value_to_string).collect();
    models::delete_tags(&app.db, &guid, &names);
    Ok(ok_empty())
}

fn info_password(data: &Object) -> Option<String> {
    match data.get("info") {
        Some(Value::Object(info)) if info.contains_key("password") => Some(
            info.get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .chars()
                .take(1024)
                .collect(),
        ),
        _ => None,
    }
}

fn ab_shared_add(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = bearer_actor(app, req)?;
    if actor.token_name.is_some() && actor.ab_level() < 2 {
        return Err(HttpError::new(
            403,
            "The token needs Address Book read/write permission",
        ));
    }
    let uid = actor
        .user_id
        .ok_or_else(|| HttpError::new(400, "This token has no owner user"))?;
    let data = req.json_object()?;
    let name = jstr(&data, "name");
    if name.trim().is_empty() || name.len() > 64 {
        return Err(HttpError::new(400, "Invalid name"));
    }
    let guid = models::new_guid();
    let _ = app.db.execute(
        "INSERT INTO address_books(guid, name, owner_id, personal, note, password, created_at) \
         VALUES (?1,?2,?3,0,?4,?5,?6)",
        &[
            text(&guid),
            text(name.trim()),
            int(uid),
            text(jstr(&data, "note").chars().take(1024).collect::<String>()),
            text(info_password(&data).unwrap_or_default()),
            int(now()),
        ],
    );
    models::console_log(
        &app.db,
        actor.user_id,
        &actor.name(),
        &req.ip,
        "address_book.create",
        &name,
        "",
    );
    Ok(json_response(&json!({ "guid": guid }), 200))
}

fn ab_shared_update(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let guid = jstr(&data, "guid");
    let (actor, _, personal) = book_access(app, req, &guid, RULE_FULL)?;
    if personal {
        return Err(HttpError::new(
            400,
            "A personal address book cannot be changed here",
        ));
    }
    let db = &app.db;
    let name = jstr(&data, "name");
    if !name.trim().is_empty() {
        let _ = db.execute(
            "UPDATE address_books SET name = ?1 WHERE guid = ?2",
            &[
                text(name.trim().chars().take(64).collect::<String>()),
                text(&guid),
            ],
        );
        models::console_log(
            db,
            actor.user_id,
            &actor.name(),
            &req.ip,
            "address_book.rename",
            &name,
            "",
        );
    }
    if data.contains_key("note") {
        let _ = db.execute(
            "UPDATE address_books SET note = ?1 WHERE guid = ?2",
            &[
                text(jstr(&data, "note").chars().take(1024).collect::<String>()),
                text(&guid),
            ],
        );
    }
    if let Some(pw) = info_password(&data) {
        let _ = db.execute(
            "UPDATE address_books SET password = ?1 WHERE guid = ?2",
            &[text(pw), text(&guid)],
        );
    }
    let owner = jstr(&data, "owner");
    if !owner.is_empty() {
        let row = db
            .query_one("SELECT id FROM users WHERE name = ?1", &[text(&owner)])
            .ok()
            .flatten()
            .ok_or_else(|| HttpError::new(400, "Owner not found"))?;
        let _ = db.execute(
            "UPDATE address_books SET owner_id = ?1 WHERE guid = ?2",
            &[int(models::rint(&row, "id")), text(&guid)],
        );
    }
    Ok(ok_empty())
}

fn ab_shared_delete(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let guids = req.json()?;
    let guids = guids
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list of address book GUIDs"))?;
    for g in guids {
        let guid = value_to_string(g);
        let (actor, book, personal) = book_access(app, req, &guid, RULE_FULL)?;
        if !personal {
            let _ = app
                .db
                .execute("DELETE FROM address_books WHERE guid = ?1", &[text(&guid)]);
            models::console_log(
                &app.db,
                actor.user_id,
                &actor.name(),
                &req.ip,
                "address_book.delete",
                &rstr(&book, "name"),
                "",
            );
        }
    }
    Ok(ok_empty())
}

fn rule_payload(r: &Row) -> Value {
    json!({
        "guid": rstr(r, "rule_guid"),
        "user": r.get("uname").cloned().unwrap_or(Value::Null),
        "group": r.get("gname").cloned().unwrap_or(Value::Null),
        "everyone": models::rbool(r, "everyone"),
        "rule": models::rint(r, "rule"),
    })
}

const RULES_SQL: &str = "SELECT r.*, u.name AS uname, g.name AS gname FROM ab_rules r \
     LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.user_group_id ";

fn ab_rules(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let guid = req.query.get("ab").cloned().unwrap_or_default();
    book_access(app, req, &guid, RULE_FULL)?;
    let (current, size) = page_args(req)?;
    let rows = app
        .db
        .query(
            &format!("{RULES_SQL} WHERE r.guid = ?1 ORDER BY r.id"),
            &[text(&guid)],
        )
        .unwrap_or_default();
    let total = rows.len() as i64;
    let start = ((current - 1) * size).max(0) as usize;
    let data: Vec<Value> = rows
        .iter()
        .skip(start)
        .take(size as usize)
        .map(rule_payload)
        .collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

pub(crate) fn check_share_target(
    app: &App,
    actor: &Actor,
    user_id: Option<i64>,
    group_id: Option<i64>,
    everyone: bool,
) -> HttpResult<()> {
    if actor.token_name.is_some() || actor.is_admin() || app.db.settings().allow_non_admin_share {
        return Ok(());
    }
    let own = actor.group_id;
    if everyone {
        return Err(HttpError::new(
            403,
            "Only administrators can share an address book with everyone",
        ));
    }
    if group_id.is_some() && group_id != own {
        return Err(HttpError::new(
            403,
            "You can only share with your own group",
        ));
    }
    if let Some(uid) = user_id {
        let row = app
            .db
            .query_one("SELECT group_id FROM users WHERE id = ?1", &[int(uid)])
            .ok()
            .flatten();
        let ok = row
            .as_ref()
            .map(|r| ropt_int(r, "group_id") == own)
            .unwrap_or(false);
        if !ok {
            return Err(HttpError::new(
                403,
                "You can only share with users in your own group",
            ));
        }
    }
    Ok(())
}

fn ab_rule_add(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let guid = jstr(&data, "guid");
    let (actor, _, personal) = book_access(app, req, &guid, RULE_FULL)?;
    if personal {
        return Err(HttpError::new(
            400,
            "A personal address book cannot be shared",
        ));
    }
    let rule = jint(&data, "rule").unwrap_or(0);
    if !(1..=3).contains(&rule) {
        return Err(HttpError::new(400, "Invalid rule"));
    }
    let db = &app.db;
    let mut user_id = None;
    let mut group_id = None;
    if !jstr(&data, "user").is_empty() {
        let row = db
            .query_one(
                "SELECT id FROM users WHERE name = ?1",
                &[text(jstr(&data, "user"))],
            )
            .ok()
            .flatten()
            .ok_or_else(|| HttpError::new(400, "User not found"))?;
        user_id = Some(models::rint(&row, "id"));
    } else if !jstr(&data, "group").is_empty() {
        let row = db
            .query_one(
                "SELECT id FROM user_groups WHERE name = ?1",
                &[text(jstr(&data, "group"))],
            )
            .ok()
            .flatten()
            .ok_or_else(|| HttpError::new(400, "Group not found"))?;
        group_id = Some(models::rint(&row, "id"));
    }
    let everyone = user_id.is_none() && group_id.is_none();
    check_share_target(app, &actor, user_id, group_id, everyone)?;
    let res = db.execute(
        "INSERT INTO ab_rules(rule_guid, guid, user_id, user_group_id, everyone, rule) \
         VALUES (?1,?2,?3,?4,?5,?6)",
        &[
            text(models::new_guid()),
            text(&guid),
            opt_int(user_id),
            opt_int(group_id),
            int(if everyone { 1 } else { 0 }),
            int(rule),
        ],
    );
    if let Err(e) = res {
        if e.to_string().contains("UNIQUE") {
            return Err(HttpError::new(409, "A rule for this target already exists"));
        }
    }
    models::console_log(
        db,
        actor.user_id,
        &actor.name(),
        &req.ip,
        "address_book.rule_add",
        &guid,
        &Value::Object(data).to_string(),
    );
    Ok(ok_empty())
}

fn ab_rule_update(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let data = req.json_object()?;
    let row = app
        .db
        .query_one(
            "SELECT * FROM ab_rules WHERE rule_guid = ?1",
            &[text(jstr(&data, "guid"))],
        )
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Rule not found"))?;
    let (actor, _, _) = book_access(app, req, &rstr(&row, "guid"), RULE_FULL)?;
    let rule = jint(&data, "rule").unwrap_or(0);
    if !(1..=3).contains(&rule) {
        return Err(HttpError::new(400, "Invalid rule"));
    }
    let _ = app.db.execute(
        "UPDATE ab_rules SET rule = ?1 WHERE id = ?2",
        &[int(rule), int(models::rint(&row, "id"))],
    );
    models::console_log(
        &app.db,
        actor.user_id,
        &actor.name(),
        &req.ip,
        "address_book.rule_update",
        &rstr(&row, "guid"),
        &Value::Object(data).to_string(),
    );
    Ok(ok_empty())
}

fn ab_rules_delete(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let guids = req.json()?;
    let guids = guids
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list of rule GUIDs"))?;
    for rg in guids {
        let rule_guid = value_to_string(rg);
        let row = app
            .db
            .query_one(
                "SELECT * FROM ab_rules WHERE rule_guid = ?1",
                &[text(&rule_guid)],
            )
            .ok()
            .flatten();
        let Some(row) = row else { continue };
        let (actor, _, _) = book_access(app, req, &rstr(&row, "guid"), RULE_FULL)?;
        let _ = app.db.execute(
            "DELETE FROM ab_rules WHERE id = ?1",
            &[int(models::rint(&row, "id"))],
        );
        models::console_log(
            &app.db,
            actor.user_id,
            &actor.name(),
            &req.ip,
            "address_book.rule_delete",
            &rstr(&row, "guid"),
            "",
        );
    }
    Ok(ok_empty())
}

fn ab_legacy_get(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let user = client_user(app, req)?;
    let guid = models::personal_book(&app.db, models::rint(&user, "id"));
    let tags = app
        .db
        .query(
            "SELECT name, color FROM ab_tags WHERE guid = ?1 ORDER BY rowid",
            &[text(&guid)],
        )
        .unwrap_or_default();
    let peer_rows = app
        .db
        .query(
            "SELECT * FROM ab_peers WHERE guid = ?1 AND deleted_at IS NULL ORDER BY created_at",
            &[text(&guid)],
        )
        .unwrap_or_default();
    let peers_: Vec<Value> = peer_rows
        .iter()
        .map(|r| {
            let mut p = models::peer_payload(&app.db, r, true);
            if let Value::Object(m) = &mut p {
                m.remove("same_server");
                m.remove("device_group_name");
            }
            p
        })
        .collect();
    let tag_colors: Object = tags
        .iter()
        .map(|t| (rstr(t, "name"), json!(models::rint(t, "color"))))
        .collect();
    let data = json!({
        "tags": tags.iter().map(|t| json!(rstr(t, "name"))).collect::<Vec<_>>(),
        "peers": peers_,
        "tag_colors": Value::Object(tag_colors).to_string(),
    });
    Ok(json_response(
        &json!({ "data": data.to_string(), "licensed_devices": 0 }),
        200,
    ))
}

fn ab_legacy_post(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let user = client_user(app, req)?;
    let guid = models::personal_book(&app.db, models::rint(&user, "id"));
    let body = req.json_object()?;
    let data = match body.get("data") {
        Some(Value::Str(s)) => models::loads_or(s, Value::Null),
        _ => Value::Null,
    };
    let data = data
        .as_object()
        .ok_or_else(|| HttpError::new(400, "Invalid address book data"))?;
    let colors = match data.get("tag_colors") {
        Some(Value::Str(s)) => models::loads_or(s, json!({})),
        _ => json!({}),
    };
    let _ = app
        .db
        .execute("DELETE FROM ab_tags WHERE guid = ?1", &[text(&guid)]);
    for name in models::clean_tags(data.get("tags").unwrap_or(&Value::Null)) {
        let color = colors.get(&name).and_then(|v| v.as_i64()).unwrap_or(0);
        let _ = app.db.execute(
            "INSERT INTO ab_tags(guid, name, color) VALUES (?1,?2,?3)",
            &[text(&guid), text(&name), int(color)],
        );
    }
    let _ = app
        .db
        .execute("DELETE FROM ab_peers WHERE guid = ?1", &[text(&guid)]);
    if let Some(peers_arr) = data.get("peers").and_then(|v| v.as_array()) {
        for peer in peers_arr {
            if let Value::Object(m) = peer {
                models::upsert_peer(&app.db, &guid, m, true, false);
            }
        }
    }
    Ok(ok_empty())
}

// -- session recordings -------------------------------------------------------

fn valid_recording_name(name: &str) -> bool {
    let (stem, ext) = match name.rsplit_once('.') {
        Some(x) => x,
        None => return false,
    };
    if !matches!(ext, "webm" | "mkv" | "mp4") {
        return false;
    }
    if stem.is_empty() || stem.len() > 200 {
        return false;
    }
    let bytes = stem.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    stem.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

fn record(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let settings = app.db.settings();
    if !settings.accept_recordings {
        return Err(HttpError::new(
            403,
            "Recording upload is disabled on this server",
        ));
    }
    let kind = req.query.get("type").cloned().unwrap_or_default();
    let name = req.query.get("file").cloned().unwrap_or_default();
    if !valid_recording_name(&name) {
        return Err(HttpError::new(400, "Invalid file name"));
    }
    let dir = app.cfg.recordings_dir();
    let path = dir.join(&name);
    let db = &app.db;
    let cap = settings.recordings_max_mb * 1024 * 1024;

    let used = || {
        db.query_one("SELECT COALESCE(SUM(size), 0) AS n FROM recordings", &[])
            .ok()
            .flatten()
            .map(|r| models::rint(&r, "n"))
            .unwrap_or(0)
    };

    if kind == "new" {
        if used() > cap {
            return Err(HttpError::new(507, "Recording storage is full"));
        }
        std::fs::create_dir_all(&dir).ok();
        std::fs::File::create(&path).map_err(|_| HttpError::new(500, "cannot create file"))?;
        let _ = db.execute(
            "INSERT INTO recordings(filename, size, ip, created_at) VALUES (?1, 0, ?2, ?3) \
             ON CONFLICT(filename) DO UPDATE SET size = 0, completed_at = NULL, created_at = excluded.created_at",
            &[text(&name), text(&req.ip), int(now())],
        );
        return Ok(json_response(&json!({}), 200));
    }

    let row = db
        .query_one(
            "SELECT * FROM recordings WHERE filename = ?1",
            &[text(&name)],
        )
        .ok()
        .flatten();
    let row = match row {
        Some(r) if path.exists() => r,
        _ => return Err(HttpError::new(404, "Unknown recording")),
    };
    if kind == "remove" {
        let _ = std::fs::remove_file(&path);
        let _ = db.execute(
            "DELETE FROM recordings WHERE id = ?1",
            &[int(models::rint(&row, "id"))],
        );
        return Ok(json_response(&json!({}), 200));
    }
    if kind != "part" && kind != "tail" {
        return Err(HttpError::new(400, "Invalid upload type"));
    }
    let offset: i64 = req
        .query
        .get("offset")
        .map(|s| s.parse())
        .transpose()
        .map_err(|_| HttpError::new(400, "Invalid offset"))?
        .unwrap_or(0);
    if offset < 0 || offset > models::rint(&row, "size") {
        return Err(HttpError::new(400, "Offset out of range"));
    }
    if kind == "part" && used() + req.body.len() as i64 > cap {
        return Err(HttpError::new(507, "Recording storage is full"));
    }
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| HttpError::new(500, "cannot open file"))?;
    f.seek(SeekFrom::Start(offset as u64)).ok();
    f.write_all(&req.body)
        .map_err(|_| HttpError::new(500, "write failed"))?;
    let size = std::fs::metadata(&path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let _ = db.execute(
        "UPDATE recordings SET size = ?1, completed_at = ?2 WHERE id = ?3",
        &[
            int(size),
            if kind == "tail" {
                int(now())
            } else {
                crate::db::SqlValue::Null
            },
            int(models::rint(&row, "id")),
        ],
    );
    Ok(json_response(&json!({}), 200))
}
