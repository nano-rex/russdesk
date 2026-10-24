//! Core Rust web-console API. The remaining console sections are ported in
//! separate modules as they reach parity with the Python implementation.
use crate::app::App;
use crate::auth;
use crate::authz::Actor;
use crate::client_api::console_url;
use crate::db::{int, now, text, Database, Row, SqlValue};
use crate::json::{self, Object, Value};
use crate::models::{
    self, rbool, rint, ropt_int, rstr, ONLINE_SECONDS, RULE_FULL, RULE_READ, RULE_READ_WRITE,
};
use crate::security::{
    hash_password, new_backup_codes, new_token, new_totp_secret, token_hash, totp_uri,
    verify_password, verify_totp,
};
use crate::mail;
use crate::web::{json_response, HttpError, HttpResult, Params, Request, Response, Router};
use crate::{client_api, rest_api};
use std::collections::HashMap;

const COOKIE: &str = "russdesk_session";
const TOTP_EXPIRE_DAYS: i64 = 180;

pub fn register(r: &mut Router<App>) {
    r.add("POST", "/api/admin/login", login);
    r.add("POST", "/api/admin/login/verify", login_verify);
    r.add("POST", "/api/admin/logout", logout);
    r.add("GET", "/api/admin/me", me);
    r.add("GET", "/api/admin/dashboard", dashboard);
    r.add("GET", "/api/admin/devices", devices);
    r.add("GET", "/api/admin/devices/<device_id>", device_detail);
    r.add("PATCH", "/api/admin/devices/<device_id>", device_update);
    r.add(
        "POST",
        "/api/admin/devices/<device_id>/enable",
        device_enable,
    );
    r.add(
        "POST",
        "/api/admin/devices/<device_id>/disable",
        device_disable,
    );
    r.add("DELETE", "/api/admin/devices/<device_id>", device_delete);
    r.add("POST", "/api/admin/devices/<device_id>/disconnect", device_disconnect);
    r.add("POST", "/api/admin/devices/<device_id>/refresh", device_refresh);
    r.add("POST", "/api/admin/devices/bulk", devices_bulk);
    r.add("GET", "/api/admin/devices/<device_id>/viewer-info", viewer_info);
    r.add("GET", "/api/admin/users", users);
    r.add("POST", "/api/admin/users", user_create);
    r.add("POST", "/api/admin/users/invite", user_invite);
    r.add("PATCH", "/api/admin/users/<user_id>", user_update);
    r.add("POST", "/api/admin/users/<user_id>/enable", user_enable);
    r.add("POST", "/api/admin/users/<user_id>/disable", user_disable);
    r.add("DELETE", "/api/admin/users/<user_id>", user_delete);
    r.add("POST", "/api/admin/users/<user_id>/reset-2fa", user_reset_2fa);
    r.add("GET", "/api/admin/users/<user_id>/sessions", user_sessions);
    r.add("POST", "/api/admin/users/<user_id>/logout-all", user_logout_all);
    r.add("POST", "/api/admin/users/<user_id>/assign-devices", user_assign_devices);
    // groups
    r.add("GET", "/api/admin/groups", groups);
    r.add("POST", "/api/admin/user-groups", user_group_create);
    r.add("PATCH", "/api/admin/user-groups/<group_id>", user_group_update);
    r.add("DELETE", "/api/admin/user-groups/<group_id>", user_group_delete);
    r.add("POST", "/api/admin/user-groups/<group_id>/members", user_group_members);
    r.add("POST", "/api/admin/device-groups", device_group_create);
    r.add("PATCH", "/api/admin/device-groups/<group_id>", device_group_update);
    r.add("DELETE", "/api/admin/device-groups/<group_id>", device_group_delete);
    r.add("POST", "/api/admin/device-groups/<group_id>/members", device_group_members);
    // strategies
    r.add("GET", "/api/admin/strategies", strategies);
    r.add("POST", "/api/admin/strategies", strategy_create);
    r.add("PATCH", "/api/admin/strategies/<sid>", strategy_update);
    r.add("POST", "/api/admin/strategies/<sid>/duplicate", strategy_duplicate);
    r.add("DELETE", "/api/admin/strategies/<sid>", strategy_delete);
    r.add("GET", "/api/admin/strategies/<sid>/targets", strategy_targets);
    r.add("POST", "/api/admin/strategies/<sid>/targets", strategy_set_targets);
    // address books
    r.add("GET", "/api/admin/address-books", books);
    r.add("POST", "/api/admin/address-books", book_create);
    r.add("GET", "/api/admin/address-books/<guid>", book_detail);
    r.add("PATCH", "/api/admin/address-books/<guid>", book_update);
    r.add("DELETE", "/api/admin/address-books/<guid>", book_delete);
    r.add("POST", "/api/admin/address-books/<guid>/peers", book_peer_add);
    r.add("GET", "/api/admin/address-books/<guid>/importable", book_importable);
    r.add("POST", "/api/admin/address-books/<guid>/import", book_import);
    r.add("PATCH", "/api/admin/address-books/<guid>/peers/<peer_id>", book_peer_update);
    r.add("DELETE", "/api/admin/address-books/<guid>/peers/<peer_id>", book_peer_delete);
    r.add("GET", "/api/admin/address-books/<guid>/recycle", book_recycle);
    r.add("POST", "/api/admin/address-books/<guid>/recycle/restore", book_recycle_restore);
    r.add("POST", "/api/admin/address-books/<guid>/recycle/delete", book_recycle_delete);
    r.add("POST", "/api/admin/address-books/<guid>/tags", book_tag_add);
    r.add("PATCH", "/api/admin/address-books/<guid>/tags/<name>", book_tag_update);
    r.add("DELETE", "/api/admin/address-books/<guid>/tags/<name>", book_tag_delete);
    // logs
    r.add("GET", "/api/admin/logs/<kind>", logs);
    r.add("PATCH", "/api/admin/logs/connections/<log_id>", conn_note);
    r.add("POST", "/api/admin/logs/connections/<log_id>/disconnect", conn_disconnect);
    // admin roles
    r.add("GET", "/api/admin/admin-roles", admin_roles);
    r.add("POST", "/api/admin/admin-roles", admin_role_create);
    r.add("PATCH", "/api/admin/admin-roles/<role_id>", admin_role_update);
    r.add("DELETE", "/api/admin/admin-roles/<role_id>", admin_role_delete);
    // API tokens
    r.add("GET", "/api/admin/tokens", tokens);
    r.add("POST", "/api/admin/tokens", token_create);
    r.add("DELETE", "/api/admin/tokens/<token_id>", token_delete);
    // recordings
    r.add("GET", "/api/admin/recordings", recordings);
    r.add("GET", "/api/admin/recordings/<rid>/download", recording_download);
    r.add("DELETE", "/api/admin/recordings/<rid>", recording_delete);
    // invitations
    r.add("GET", "/api/admin/invite/<token>", invite_info);
    r.add("POST", "/api/admin/invite/<token>", invite_accept);
    // settings, client config, lookup
    r.add("GET", "/api/admin/client-config", get_client_config);
    r.add("GET", "/api/admin/settings", get_settings);
    r.add("PATCH", "/api/admin/settings", patch_settings);
    r.add("POST", "/api/admin/settings/smtp-test", smtp_test);
    r.add("GET", "/api/admin/lookup", lookup);
    // own account
    r.add("PATCH", "/api/admin/account", account_update);
    r.add("POST", "/api/admin/account/password", change_password);
    r.add("POST", "/api/admin/account/2fa/setup", totp_setup);
    r.add("POST", "/api/admin/account/2fa/enable", totp_enable);
    r.add("POST", "/api/admin/account/2fa/backup-codes", totp_backup_codes);
    r.add("POST", "/api/admin/account/2fa/disable", totp_disable);
}

fn console_user(app: &App, req: &Request) -> HttpResult<(Actor, Row)> {
    let raw = req
        .cookie(COOKIE)
        .ok_or_else(|| HttpError::new(401, "Not logged in"))?;
    let hash = token_hash(&raw);
    let user = app.db.query_one(
        "SELECT t.token_hash, t.last_seen_at, u.* FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?1 AND t.kind = 'console' AND t.expires_at > ?2",
        &[text(&hash), int(now())],
    )?.ok_or_else(|| HttpError::new(401, "Session expired, log in again"))?;
    if rint(&user, "status") != 1 {
        return Err(HttpError::new(401, "Session expired, log in again"));
    }
    if req.method != "GET" && req.method != "HEAD" && req.header("x-russdesk") != Some("1") {
        return Err(HttpError::new(403, "Missing CSRF header"));
    }
    if auth::needs_2fa_setup(&user) && !req.path.starts_with("/api/admin/me") {
        return Err(HttpError::new(
            403,
            "Set up two-factor authentication first",
        ));
    }
    if now() - rint(&user, "last_seen_at") > 60 {
        let _ = app.db.execute(
            "UPDATE tokens SET last_seen_at = ?1 WHERE token_hash = ?2",
            &[int(now()), text(&hash)],
        );
    }
    let actor = Actor {
        user_id: ropt_int(&user, "id"),
        group_id: ropt_int(&user, "group_id"),
        user_is_admin: rbool(&user, "is_admin"),
        user_name: rstr(&user, "name"),
        token_name: None,
        token_perms: None,
    };
    Ok((actor, user))
}

fn login(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let body = req.json_object()?;
    let user = auth::check_password(
        &app.db,
        &req.ip,
        body.get("username").and_then(Value::as_str).unwrap_or(""),
        body.get("password").and_then(Value::as_str).unwrap_or(""),
        "",
    )
    .map_err(|e| HttpError::new(401, e.0))?;
    if let Some(method) = auth::second_factor(&user) {
        let secret = auth::start_challenge(&app.db, &user, method)?;
        return Ok(json_response(
            &json!({"need_code": method, "secret": secret}),
            200,
        ));
    }
    start_session(app, req, &user)
}

fn login_verify(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let body = req.json_object()?;
    let user = auth::finish_challenge(
        &app.db,
        body.get("secret").and_then(Value::as_str).unwrap_or(""),
        body.get("code")
            .and_then(Value::as_str)
            .or_else(|| body.get("verificationCode").and_then(Value::as_str))
            .unwrap_or(""),
    )
    .map_err(|e| HttpError::new(401, e.0))?;
    start_session(app, req, &user)
}

fn start_session(app: &App, req: &Request, user: &Row) -> HttpResult<Response> {
    let raw = new_token();
    let hash = token_hash(&raw);
    let expires = now() + app.db.settings().console_session_hours * 3600;
    app.db.execute("INSERT INTO tokens(token_hash,user_id,kind,ip,created_at,last_seen_at,expires_at) VALUES (?1,?2,'console',?3,?4,?4,?5)", &[text(&hash), int(rint(user,"id")), text(&req.ip), int(now()), int(expires)])?;
    app.db.execute(
        "UPDATE users SET last_login_at = ?1 WHERE id = ?2",
        &[int(now()), int(rint(user, "id"))],
    )?;
    let secure = if req.scheme == "https" {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{COOKIE}={raw}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        expires - now(),
        secure
    );
    Ok(json_response(&json!({"ok": true}), 200).with_header("Set-Cookie", &cookie))
}

fn logout(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    if let Some(raw) = req.cookie(COOKIE) {
        let _ = app.db.execute(
            "DELETE FROM tokens WHERE token_hash = ?1",
            &[text(token_hash(&raw))],
        );
    }
    Ok(json_response(&json!({"ok": true}), 200).with_header(
        "Set-Cookie",
        &format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"),
    ))
}

fn me(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let secret = rstr(&user, "totp_secret");
    let set_at = ropt_int(&user, "totp_set_at").unwrap_or(0);
    let backup_count = match models::loads_or(&rstr(&user, "totp_backup"), json!([])) {
        Value::Array(v) => v.len(),
        _ => 0,
    };
    Ok(json_response(
        &json!({"id":rint(&user,"id"),"name":rstr(&user,"name"),"display_name":rstr(&user,"display_name"),"email":rstr(&user,"email"),"is_admin":rbool(&user,"is_admin"),"perms":actor.capabilities(&app.db),"totp_enabled":!secret.is_empty(),"totp_expired":!secret.is_empty() && now()-set_at > 180*86400,"backup_codes_left":backup_count,"must_setup_2fa":auth::needs_2fa_setup(&user),"console_url":console_url(app,req)}),
        200,
    ))
}

fn dashboard(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let scope = actor.require(&app.db, "devices.view")?;
    let (cond, params) = scope.device_sql("d");
    let cutoff = now() - ONLINE_SECONDS;
    let mut args: Vec<SqlValue> = params.into_iter().map(SqlValue::Int).collect();
    args.push(SqlValue::Int(cutoff));
    let row = app.db.query_one(&format!("SELECT COUNT(*) AS total, SUM(d.last_seen_at >= ?{}) AS online, SUM(d.disabled = 1) AS disabled FROM devices d WHERE {cond}", args.len()), &args)?.unwrap_or_default();
    Ok(json_response(
        &json!({"devices_total":rint(&row,"total"),"devices_online":rint(&row,"online"),"devices_disabled":rint(&row,"disabled")}),
        200,
    ))
}

fn device_where(app: &App, actor: &Actor, id: &str, perm: &str) -> HttpResult<Row> {
    let scope = actor.require(&app.db, perm)?;
    let (cond, params) = scope.device_sql("d");
    let mut args = vec![text(id)];
    args.extend(params.into_iter().map(SqlValue::Int));
    app.db
        .query_one(
            &format!("SELECT d.* FROM devices d WHERE d.id = ?1 AND {cond}"),
            &args,
        )?
        .ok_or_else(|| HttpError::new(404, "Device not found"))
}

fn devices(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let scope = actor.require(&app.db, "devices.view")?;
    let (cond, params) = scope.device_sql("d");
    let args: Vec<SqlValue> = params.into_iter().map(SqlValue::Int).collect();
    let rows = app.db.query(
        &format!("SELECT d.* FROM devices d WHERE {cond} ORDER BY d.id"),
        &args,
    )?;
    let items = rows
        .iter()
        .map(|row| models::device_payload(&app.db, row, false))
        .collect::<Vec<_>>();
    Ok(json_response(
        &json!({"total":items.len(),"items":items}),
        200,
    ))
}

fn device_detail(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = device_where(
        app,
        &actor,
        p.get("device_id").map(String::as_str).unwrap_or(""),
        "devices.view",
    )?;
    Ok(json_response(
        &models::device_payload(&app.db, &row, true),
        200,
    ))
}

fn device_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let id = p.get("device_id").map(String::as_str).unwrap_or("");
    let row = device_where(app, &actor, id, "devices.edit_info")?;
    let data = req.json_object()?;
    let mut sets = Vec::new();
    let mut args = Vec::new();
    for (key, column) in [
        ("note", "note"),
        ("name_override", "name_override"),
        ("username_override", "username_override"),
    ] {
        if let Some(value) = data.get(key).and_then(Value::as_str) {
            sets.push(format!("{column} = ?{}", args.len() + 1));
            args.push(text(value.chars().take(1024).collect::<String>()));
        }
    }
    if !sets.is_empty() {
        args.push(text(rstr(&row, "id")));
        app.db.execute(
            &format!(
                "UPDATE devices SET {} WHERE id = ?{}",
                sets.join(", "),
                args.len()
            ),
            &args,
        )?;
    }
    Ok(json_response(&json!({"ok":true}), 200))
}

fn device_set(app: &App, req: &Request, p: &Params, disabled: bool) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = device_where(
        app,
        &actor,
        p.get("device_id").map(String::as_str).unwrap_or(""),
        "devices.enable_disable",
    )?;
    app.db.execute(
        "UPDATE devices SET disabled = ?1 WHERE id = ?2",
        &[int(disabled as i64), text(rstr(&row, "id"))],
    )?;
    Ok(json_response(&json!({"ok":true}), 200))
}
fn device_enable(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    device_set(app, req, p, false)
}
fn device_disable(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    device_set(app, req, p, true)
}
fn device_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = device_where(
        app,
        &actor,
        p.get("device_id").map(String::as_str).unwrap_or(""),
        "devices.delete",
    )?;
    if !rbool(&row, "disabled") {
        return Err(HttpError::new(400, "Disable devices before deleting them"));
    }
    app.db.execute(
        "DELETE FROM devices WHERE id = ?1",
        &[text(rstr(&row, "id"))],
    )?;
    Ok(json_response(&json!({"ok":true}), 200))
}

// ---- shared console helpers ----

fn body(req: &Request) -> HttpResult<Object> {
    req.json_object()
}

fn log(app: &App, actor: &Actor, req: &Request, action: &str, target: &str, detail: &str) {
    models::console_log(
        &app.db,
        actor.user_id,
        &actor.name(),
        &req.ip,
        action,
        target,
        &detail.chars().take(2048).collect::<String>(),
    );
}

fn pint(s: &str) -> HttpResult<i64> {
    s.parse::<i64>().map_err(|_| HttpError::new(400, "Invalid id"))
}

fn vbool(data: &Object, key: &str) -> bool {
    matches!(data.get(key), Some(Value::Bool(true)))
        || matches!(data.get(key), Some(Value::Int(n)) if *n != 0)
}

fn jstr(data: &Object, key: &str) -> Option<String> {
    data.get(key).and_then(Value::as_str).map(|s| s.to_string())
}

fn text_field(data: &Object, key: &str, limit: usize) -> Option<String> {
    data.get(key)
        .and_then(Value::as_str)
        .map(|s| s.trim().chars().take(limit).collect())
}

fn require_name(data: &Object, key: &str) -> HttpResult<String> {
    match data.get(key).and_then(Value::as_str).map(str::trim) {
        Some(s) if !s.is_empty() && s.chars().count() <= 64 => Ok(s.to_string()),
        _ => Err(HttpError::new(400, "Invalid name")),
    }
}

fn opt_id(app: &App, data: &Object, key: &str, table: &str, label: &str) -> HttpResult<Option<i64>> {
    let id = match data.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Int(n)) if *n != 0 => *n,
        Some(Value::Str(s)) if !s.is_empty() => s
            .parse::<i64>()
            .map_err(|_| HttpError::new(400, format!("Invalid {label}")))?,
        _ => return Ok(None),
    };
    if app
        .db
        .query_one(&format!("SELECT 1 FROM {table} WHERE id = ?1"), &[int(id)])?
        .is_none()
    {
        return Err(HttpError::new(400, format!("Unknown {label}")));
    }
    Ok(Some(id))
}

fn names(db: &Database, table: &str) -> HashMap<i64, String> {
    db.query(&format!("SELECT id, name FROM {table}"), &[])
        .unwrap_or_default()
        .iter()
        .map(|r| (rint(r, "id"), rstr(r, "name")))
        .collect()
}

fn name_value(map: &HashMap<i64, String>, id: Option<i64>) -> Value {
    match id.and_then(|i| map.get(&i)) {
        Some(n) => Value::Str(n.clone()),
        None => Value::Null,
    }
}

fn admin_only(app: &App, req: &Request) -> HttpResult<(Actor, Row)> {
    let pair = console_user(app, req)?;
    if !pair.0.is_admin() {
        return Err(HttpError::new(403, "Administrator access required"));
    }
    Ok(pair)
}

fn session_token_hash(req: &Request) -> String {
    token_hash(&req.cookie(COOKIE).unwrap_or_default())
}

fn check_password(data: &Object) -> HttpResult<String> {
    match data.get("password").and_then(Value::as_str) {
        Some(p) if p.len() >= 8 && p.len() <= 256 => Ok(p.to_string()),
        Some(p) if p.len() > 256 => Err(HttpError::new(400, "Password is too long")),
        _ => Err(HttpError::new(400, "Password must be at least 8 characters")),
    }
}

// ---- users ----

fn user_scope_ok(app: &App, actor: &Actor, scope: &crate::authz::Scope, row: &Row) -> HttpResult<()> {
    if actor.is_admin() {
        return Ok(());
    }
    if rbool(row, "is_admin") {
        return Err(HttpError::new(403, "Only administrators can change administrator accounts"));
    }
    if !scope.everything {
        let (cond, params) = scope.user_sql("u");
        let cond = shift_placeholders(&cond, 1);
        let mut args = vec![int(rint(row, "id"))];
        args.extend(params.into_iter().map(SqlValue::Int));
        if app
            .db
            .query_one(&format!("SELECT 1 FROM users u WHERE u.id = ?1 AND {cond}"), &args)?
            .is_none()
        {
            return Err(HttpError::new(403, "This user is outside your role's groups"));
        }
    }
    Ok(())
}

fn user_row_for(app: &App, actor: &Actor, user_id: &str, perm: &str) -> HttpResult<Row> {
    let scope = actor.require(&app.db, perm)?;
    let row = app
        .db
        .query_one("SELECT * FROM users WHERE id = ?1", &[int(pint(user_id)?)])?
        .ok_or_else(|| HttpError::new(404, "User not found"))?;
    user_scope_ok(app, actor, &scope, &row)?;
    Ok(row)
}

fn user_row_json(
    db: &Database,
    r: &Row,
    groups: &HashMap<i64, String>,
    strategies: &HashMap<i64, String>,
    roles: &HashMap<i64, Vec<i64>>,
) -> Value {
    let set_at = ropt_int(r, "totp_set_at").unwrap_or(0);
    let has_totp = !rstr(r, "totp_secret").is_empty();
    let role_ids = roles
        .get(&rint(r, "id"))
        .map(|v| Value::Array(v.iter().map(|&i| Value::Int(i)).collect()))
        .unwrap_or_else(|| Value::Array(vec![]));
    let devices = db
        .query_one("SELECT COUNT(*) AS n FROM devices WHERE user_id = ?1", &[int(rint(r, "id"))])
        .ok()
        .flatten()
        .map(|x| rint(&x, "n"))
        .unwrap_or(0);
    json!({
        "id": rint(r, "id"), "guid": rstr(r, "guid"), "name": rstr(r, "name"),
        "display_name": rstr(r, "display_name"), "email": rstr(r, "email"), "note": rstr(r, "note"),
        "is_admin": rbool(r, "is_admin"), "status": rint(r, "status"),
        "group_id": ropt_int(r, "group_id"), "group_name": name_value(groups, ropt_int(r, "group_id")),
        "strategy_id": ropt_int(r, "strategy_id"), "strategy_name": name_value(strategies, ropt_int(r, "strategy_id")),
        "totp_enabled": has_totp, "totp_expired": has_totp && now() - set_at > TOTP_EXPIRE_DAYS * 86400,
        "force_2fa": rbool(r, "force_2fa"), "email_verification": rbool(r, "email_verification"),
        "admin_role_ids": role_ids, "created_at": rint(r, "created_at"),
        "last_login_at": ropt_int(r, "last_login_at"), "devices": devices,
    })
}

fn set_roles(app: &App, user_id: i64, role_ids: &[Value]) -> HttpResult<()> {
    app.db.execute("DELETE FROM user_admin_roles WHERE user_id = ?1", &[int(user_id)])?;
    for rid in role_ids {
        let id = rid.as_i64().ok_or_else(|| HttpError::new(400, "Unknown admin role"))?;
        if app
            .db
            .query_one("SELECT 1 FROM admin_roles WHERE id = ?1", &[int(id)])?
            .is_none()
        {
            return Err(HttpError::new(400, "Unknown admin role"));
        }
        app.db.execute(
            "INSERT OR IGNORE INTO user_admin_roles(user_id, role_id) VALUES (?1, ?2)",
            &[int(user_id), int(id)],
        )?;
    }
    Ok(())
}

fn users(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let scope = actor.require(&app.db, "users.view")?;
    let q = req.query.get("q").map(String::as_str).unwrap_or("").trim();
    let mut where_ = vec!["(u.name LIKE ?1 OR u.display_name LIKE ?1 OR u.email LIKE ?1)".to_string()];
    let mut args: Vec<SqlValue> = vec![text(format!("%{q}%"))];
    if !scope.everything {
        let (cond, params) = scope.user_sql("u");
        // shift the scope params after ?1
        let shifted = shift_placeholders(&cond, args.len());
        where_.push(shifted);
        args.extend(params.into_iter().map(SqlValue::Int));
    }
    for (key, column) in [("group", "u.group_id"), ("status", "u.status")] {
        match req.query.get(key).map(String::as_str) {
            Some("none") => where_.push(format!("{column} IS NULL")),
            Some(v) if !v.is_empty() => {
                args.push(int(pint(v)?));
                where_.push(format!("{column} = ?{}", args.len()));
            }
            _ => {}
        }
    }
    let rows = app.db.query(
        &format!("SELECT u.* FROM users u WHERE {} ORDER BY u.name COLLATE NOCASE", where_.join(" AND ")),
        &args,
    )?;
    let mut roles: HashMap<i64, Vec<i64>> = HashMap::new();
    for r in app.db.query("SELECT * FROM user_admin_roles", &[])? {
        roles.entry(rint(&r, "user_id")).or_default().push(rint(&r, "role_id"));
    }
    let groups = names(&app.db, "user_groups");
    let strategies = names(&app.db, "strategies");
    let items: Vec<Value> = rows
        .iter()
        .map(|r| user_row_json(&app.db, r, &groups, &strategies, &roles))
        .collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

/// Re-number the `?N` placeholders in a scope condition so they start after
/// `offset` existing params (scope SQL numbers its own params from 1).
fn shift_placeholders(cond: &str, offset: usize) -> String {
    let mut out = String::new();
    let mut chars = cond.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let mut num = String::new();
            while let Some(d) = chars.peek() {
                if d.is_ascii_digit() {
                    num.push(*d);
                    chars.next();
                } else {
                    break;
                }
            }
            if let Ok(n) = num.parse::<usize>() {
                out.push('?');
                out.push_str(&(n + offset).to_string());
            } else {
                out.push('?');
                out.push_str(&num);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn user_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let mut data = body(req)?;
    if let Some(gid) = opt_id(app, &data, "group_id", "user_groups", "user group")? {
        data.insert("group_id".into(), Value::Int(gid));
    } else {
        data.remove("group_id");
    }
    let uid = rest_api::create_user(app, req, &actor, &data, false)?;
    if data.get("strategy_id").is_some() && actor.can(&app.db, "users.change_strategy") {
        let sid = opt_id(app, &data, "strategy_id", "strategies", "strategy")?;
        app.db.execute(
            "UPDATE users SET strategy_id = ?1 WHERE id = ?2",
            &[sid.map(SqlValue::Int).unwrap_or(SqlValue::Null), int(uid)],
        )?;
    }
    if actor.is_admin() {
        if let Some(Value::Array(ids)) = data.get("admin_role_ids") {
            set_roles(app, uid, ids)?;
        }
    }
    Ok(json_response(&json!({ "id": uid }), 201))
}

fn user_invite(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let mut data = body(req)?;
    if let Some(gid) = opt_id(app, &data, "group_id", "user_groups", "user group")? {
        data.insert("group_id".into(), Value::Int(gid));
    } else {
        data.remove("group_id");
    }
    let uid = rest_api::create_user(app, req, &actor, &data, true)?;
    Ok(json_response(&json!({ "id": uid }), 201))
}

fn user_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, me_row) = console_user(app, req)?;
    let user_id = p.get("user_id").map(String::as_str).unwrap_or("");
    let target = user_row_for(app, &actor, user_id, "users.view")?;
    let data = body(req)?;
    let fields: [(&str, &str); 7] = [
        ("display_name", "users.edit_display_name"),
        ("email", "users.edit_email"),
        ("note", "users.edit_note"),
        ("group_id", "users.change_group"),
        ("strategy_id", "users.change_strategy"),
        ("force_2fa", "users.manage_2fa"),
        ("email_verification", "users.manage_2fa"),
    ];
    let mut sets: Vec<String> = Vec::new();
    let mut args: Vec<SqlValue> = Vec::new();
    let mut changed = Object::new();
    for (key, perm) in fields {
        if data.get(key).is_none() {
            continue;
        }
        user_row_for(app, &actor, user_id, perm)?;
        let value = match key {
            "group_id" => opt_id(app, &data, key, "user_groups", "user group")?
                .map(SqlValue::Int)
                .unwrap_or(SqlValue::Null),
            "strategy_id" => opt_id(app, &data, key, "strategies", "strategy")?
                .map(SqlValue::Int)
                .unwrap_or(SqlValue::Null),
            "force_2fa" | "email_verification" => {
                let v = vbool(&data, key);
                if key == "email_verification"
                    && v
                    && jstr(&data, "email").unwrap_or_default().is_empty()
                    && rstr(&target, "email").is_empty()
                {
                    return Err(HttpError::new(400, "Email login verification needs an email address"));
                }
                int(v as i64)
            }
            _ => text(text_field(&data, key, 256).unwrap_or_default()),
        };
        args.push(value);
        sets.push(format!("{key} = ?{}", args.len()));
        changed.insert(key.into(), data.get(key).cloned().unwrap_or(Value::Null));
    }
    if let Some(v) = data.get("is_admin") {
        if !actor.is_admin() {
            return Err(HttpError::new(403, "Only administrators can grant administrator access"));
        }
        let make_admin = matches!(v, Value::Bool(true));
        if !make_admin && rbool(&target, "is_admin") && rest_api::other_admins(&app.db, rint(&target, "id")) == 0 {
            return Err(HttpError::new(400, "Keep at least one active administrator"));
        }
        args.push(int(make_admin as i64));
        sets.push(format!("is_admin = ?{}", args.len()));
        changed.insert("is_admin".into(), Value::Bool(make_admin));
    }
    if !sets.is_empty() {
        args.push(int(rint(&target, "id")));
        app.db.execute(
            &format!("UPDATE users SET {} WHERE id = ?{}", sets.join(", "), args.len()),
            &args,
        )?;
    }
    if let Some(pw) = data.get("password").and_then(Value::as_str) {
        if !pw.is_empty() {
            user_row_for(app, &actor, user_id, "users.edit_password")?;
            app.db.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                &[text(hash_password(&check_password(&data)?)), int(rint(&target, "id"))],
            )?;
            if rint(&target, "id") != rint(&me_row, "id") {
                app.db.execute("DELETE FROM tokens WHERE user_id = ?1", &[int(rint(&target, "id"))])?;
            }
            changed.insert("password".into(), Value::Str("(changed)".into()));
        }
    }
    if let Some(ids) = data.get("admin_role_ids") {
        if !actor.is_admin() {
            return Err(HttpError::new(403, "Only administrators can assign admin roles"));
        }
        let list = ids.as_array().cloned().unwrap_or_default();
        set_roles(app, rint(&target, "id"), &list)?;
        changed.insert("admin_roles".into(), ids.clone());
    }
    log(app, &actor, req, "user.update", &rstr(&target, "name"), &json::to_string(&Value::Object(changed)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_status_change(app: &App, req: &Request, actor: &Actor, target: &Row, status: i64) -> HttpResult<()> {
    if status == 0 && rbool(target, "is_admin") && rest_api::other_admins(&app.db, rint(target, "id")) == 0 {
        return Err(HttpError::new(400, "Keep at least one active administrator"));
    }
    app.db.execute(
        "UPDATE users SET status = ?1 WHERE id = ?2",
        &[int(status), int(rint(target, "id"))],
    )?;
    if status == 0 {
        app.db.execute("DELETE FROM tokens WHERE user_id = ?1", &[int(rint(target, "id"))])?;
    }
    log(
        app,
        actor,
        req,
        if status == 0 { "user.disable" } else { "user.enable" },
        &rstr(target, "name"),
        "",
    );
    Ok(())
}

fn user_enable(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.enable_disable")?;
    user_status_change(app, req, &actor, &target, 1)?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_disable(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, me_row) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.enable_disable")?;
    if rint(&target, "id") == rint(&me_row, "id") {
        return Err(HttpError::new(400, "You cannot disable your own account"));
    }
    user_status_change(app, req, &actor, &target, 0)?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, me_row) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.delete")?;
    if rint(&target, "id") == rint(&me_row, "id") {
        return Err(HttpError::new(400, "You cannot delete your own account"));
    }
    if rint(&target, "status") == 1 {
        return Err(HttpError::new(400, "Disable the user before deleting it"));
    }
    let id = rint(&target, "id");
    app.db.execute("DELETE FROM access_rules WHERE subject_type = 'user' AND subject_id = ?1", &[int(id)])?;
    app.db.execute("DELETE FROM users WHERE id = ?1", &[int(id)])?;
    log(app, &actor, req, "user.delete", &rstr(&target, "name"), "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_reset_2fa(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.manage_2fa")?;
    app.db.execute(
        "UPDATE users SET totp_secret = '', totp_backup = '[]', totp_set_at = NULL WHERE id = ?1",
        &[int(rint(&target, "id"))],
    )?;
    log(app, &actor, req, "user.update", &rstr(&target, "name"), "2FA reset");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_sessions(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let user_id = pint(p.get("user_id").map(String::as_str).unwrap_or(""))?;
    user_row_for(app, &actor, &user_id.to_string(), "users.view")?;
    let rows = app.db.query(
        "SELECT * FROM tokens WHERE user_id = ?1 AND expires_at > ?2 ORDER BY last_seen_at DESC",
        &[int(user_id), int(now())],
    )?;
    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "kind": rstr(r, "kind"), "device_id": rstr(r, "device_id"),
                "device_info": models::loads_or(&rstr(r, "device_info"), json!({})),
                "ip": rstr(r, "ip"), "created_at": rint(r, "created_at"), "last_seen_at": rint(r, "last_seen_at"),
            })
        })
        .collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

fn user_logout_all(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.force_logout")?;
    app.db.execute(
        "DELETE FROM tokens WHERE user_id = ?1 AND token_hash != ?2",
        &[int(rint(&target, "id")), text(session_token_hash(req))],
    )?;
    log(app, &actor, req, "user.update", &rstr(&target, "name"), "forced logout");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn user_assign_devices(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let target = user_row_for(app, &actor, p.get("user_id").map(String::as_str).unwrap_or(""), "users.view")?;
    let data = body(req)?;
    let ids = data
        .get("device_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| HttpError::new(400, "device_ids must be a list"))?;
    for did in ids {
        let id = match did {
            Value::Str(s) => s.clone(),
            Value::Int(n) => n.to_string(),
            _ => continue,
        };
        let row = device_where(app, &actor, &id, "devices.assign_to_user")?;
        app.db.execute(
            "UPDATE devices SET user_id = ?1 WHERE id = ?2",
            &[int(rint(&target, "id")), text(rstr(&row, "id"))],
        )?;
    }
    log(app, &actor, req, "device.update", "", &format!("assigned to {}", rstr(&target, "name")));
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ---- device extras ----

fn device_disconnect(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "audits.edit")?;
    let row = device_where(app, &actor, p.get("device_id").map(String::as_str).unwrap_or(""), "devices.view")?;
    let data = body(req)?;
    let conn_ids: Vec<i64> = match data.get("conn_ids").and_then(Value::as_array) {
        Some(a) => a.iter().filter_map(Value::as_i64).collect(),
        None => match models::loads_or(&rstr(&row, "conns"), json!([])) {
            Value::Array(v) => v.iter().filter_map(Value::as_i64).collect(),
            _ => vec![],
        },
    };
    for cid in &conn_ids {
        app.db.execute(
            "INSERT OR IGNORE INTO pending_disconnects(device_id, conn_id, created_at) VALUES (?1, ?2, ?3)",
            &[text(rstr(&row, "id")), int(*cid), int(now())],
        )?;
    }
    log(app, &actor, req, "device.disconnect", &rstr(&row, "id"),
        &json::to_string(&Value::Array(conn_ids.iter().map(|&c| Value::Int(c)).collect())));
    let queued = Value::Array(conn_ids.iter().map(|&c| Value::Int(c)).collect());
    Ok(json_response(&json!({ "ok": true, "queued": queued }), 200))
}

fn device_refresh(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = device_where(app, &actor, p.get("device_id").map(String::as_str).unwrap_or(""), "devices.edit_info")?;
    app.db.execute("UPDATE devices SET sysinfo_at = NULL WHERE id = ?1", &[text(rstr(&row, "id"))])?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn devices_bulk(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let data = body(req)?;
    let ids: Vec<String> = data
        .get("ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let action = data.get("action").and_then(Value::as_str).unwrap_or("");
    let perm = match action {
        "enable" | "disable" => "devices.enable_disable",
        "delete" => "devices.delete",
        "assign" => "devices.view",
        _ => return Err(HttpError::new(400, "Unknown action")),
    };
    let rows: Vec<Row> = ids.iter().map(|id| device_where(app, &actor, id, perm)).collect::<HttpResult<_>>()?;
    if action == "delete" && rows.iter().any(|r| !rbool(r, "disabled")) {
        return Err(HttpError::new(400, "Disable devices before deleting them"));
    }
    for row in &rows {
        match action {
            "enable" | "disable" => {
                app.db.execute(
                    "UPDATE devices SET disabled = ?1 WHERE id = ?2",
                    &[int((action == "disable") as i64), text(rstr(row, "id"))],
                )?;
                log(app, &actor, req, if action == "disable" { "device.disable" } else { "device.enable" }, &rstr(row, "id"), "");
            }
            "delete" => {
                app.db.execute("DELETE FROM devices WHERE id = ?1", &[text(rstr(row, "id"))])?;
                log(app, &actor, req, "device.delete", &rstr(row, "id"), "");
            }
            _ => {
                let mut sets = Vec::new();
                let mut args = Vec::new();
                for (key, table, perm2) in [
                    ("user_id", "users", "devices.assign_to_user"),
                    ("device_group_id", "device_groups", "devices.change_group"),
                    ("strategy_id", "strategies", "devices.change_strategy"),
                ] {
                    if data.get(key).is_some() {
                        device_where(app, &actor, &rstr(row, "id"), perm2)?;
                        let v = opt_id(app, &data, key, table, key)?;
                        args.push(v.map(SqlValue::Int).unwrap_or(SqlValue::Null));
                        sets.push(format!("{key} = ?{}", args.len()));
                    }
                }
                if !sets.is_empty() {
                    args.push(text(rstr(row, "id")));
                    app.db.execute(
                        &format!("UPDATE devices SET {} WHERE id = ?{}", sets.join(", "), args.len()),
                        &args,
                    )?;
                }
            }
        }
    }
    if action == "assign" {
        log(app, &actor, req, "device.update", &ids.join(","), &json::to_string(&Value::Object(data)));
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn saved_device_password(app: &App, user: &Row, device_id: &str) -> Option<String> {
    let rows = app
        .db
        .query(
            "SELECT p.password, p.guid FROM ab_peers p JOIN address_books b ON b.guid = p.guid \
             WHERE p.peer_id = ?1 AND b.personal = 0 AND p.password != '' AND p.deleted_at IS NULL",
            &[text(device_id)],
        )
        .unwrap_or_default();
    for r in &rows {
        if models::book_rule(&app.db, user, &rstr(r, "guid"), false) >= 1 {
            return Some(rstr(r, "password"));
        }
    }
    None
}

fn viewer_info(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let device_id = p.get("device_id").map(String::as_str).unwrap_or("");
    device_where(app, &actor, device_id, "devices.view")?;
    let cfg = client_api::client_config(app, req);
    let host = cfg.get("host").and_then(Value::as_str).unwrap_or("").to_string();
    let (hostname, id_port) = if host.starts_with('[') && host.contains("]:") {
        let (h, port) = host[1..].split_once("]:").unwrap();
        (h.to_string(), port.parse::<i64>().unwrap_or(31116))
    } else if host.matches(':').count() == 1 {
        let (h, port) = host.split_once(':').unwrap();
        (h.to_string(), port.parse::<i64>().unwrap_or(31116))
    } else {
        (host.clone(), 31116)
    };
    let pw = saved_device_password(app, &user, device_id);
    let dn = rstr(&user, "display_name");
    let name = if dn.is_empty() { rstr(&user, "name") } else { dn };
    let key = cfg.get("key").cloned().unwrap_or(Value::Str(String::new()));
    Ok(json_response(
        &json!({
            "host": hostname, "id_port": id_port, "relay_port": id_port + 1,
            "scheme": req.scheme.clone(), "key": key,
            "device_id": device_id, "name": name,
            "password": pw.map(Value::Str).unwrap_or(Value::Null),
        }),
        200,
    ))
}

// ============================ groups ============================

fn group_row_for(app: &App, actor: &Actor, kind: &str, group_id: &str, perm: &str) -> HttpResult<Row> {
    actor.require(&app.db, perm)?;
    app.db
        .query_one(&format!("SELECT * FROM {kind}s WHERE id = ?1"), &[int(pint(group_id)?)])?
        .ok_or_else(|| HttpError::new(404, "Group not found"))
}

fn unique_group(e: String) -> HttpError {
    if e.contains("UNIQUE") {
        HttpError::new(409, "Group already exists")
    } else {
        HttpError::new(500, e)
    }
}

/// Insert or update a user/device group and its access rules. Returns the id.
fn save_group(app: &App, req: &Request, actor: &Actor, kind: &str, row: Option<&Row>, data: &Object) -> HttpResult<i64> {
    let db = &app.db;
    let gid = match row {
        None => {
            let name = require_name(data, "name")?;
            let note = text_field(data, "note", 1024).unwrap_or_default();
            db.execute(
                &format!("INSERT INTO {kind}s(guid, name, note, created_at) VALUES (?1,?2,?3,?4)"),
                &[text(models::new_guid()), text(&name), text(&note), int(now())],
            )
            .map_err(unique_group)?;
            db.query_one(&format!("SELECT id FROM {kind}s WHERE name = ?1"), &[text(&name)])?
                .map(|r| rint(&r, "id"))
                .unwrap_or(0)
        }
        Some(r) => {
            let gid = rint(r, "id");
            if data.get("name").is_some() {
                db.execute(
                    &format!("UPDATE {kind}s SET name = ?1 WHERE id = ?2"),
                    &[text(require_name(data, "name")?), int(gid)],
                )
                .map_err(unique_group)?;
            }
            if data.get("note").is_some() {
                db.execute(
                    &format!("UPDATE {kind}s SET note = ?1 WHERE id = ?2"),
                    &[text(text_field(data, "note", 1024).unwrap_or_default()), int(gid)],
                )?;
            }
            gid
        }
    };
    rest_api::set_access(db, kind, gid, data)?;
    let name = data
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| row.map(|r| rstr(r, "name")))
        .unwrap_or_default();
    log(app, actor, req, &format!("{kind}.{}", if row.is_none() { "create" } else { "update" }), &name, &json::to_string(&Value::Object(data.clone())));
    Ok(gid)
}

fn groups(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let db = &app.db;
    let mut user_groups = Vec::new();
    let mut device_groups = Vec::new();
    if actor.can(db, "user_groups.view") {
        for r in db.query("SELECT * FROM user_groups ORDER BY name COLLATE NOCASE", &[])? {
            let (incomings, outgoings) = rest_api::access_lists(db, "user_group", rint(&r, "id"));
            let members = db
                .query_one("SELECT COUNT(*) AS n FROM users WHERE group_id = ?1", &[int(rint(&r, "id"))])?
                .map(|x| rint(&x, "n"))
                .unwrap_or(0);
            user_groups.push(json!({
                "id": rint(&r, "id"), "guid": rstr(&r, "guid"), "name": rstr(&r, "name"), "note": rstr(&r, "note"),
                "members": members, "allowed_incomings": incomings, "allowed_outgoings": outgoings,
            }));
        }
    }
    if actor.can(db, "device_groups.view") {
        let strategies = names(db, "strategies");
        for r in db.query("SELECT * FROM device_groups ORDER BY name COLLATE NOCASE", &[])? {
            let (incomings, _) = rest_api::access_lists(db, "device_group", rint(&r, "id"));
            let devices = db
                .query_one("SELECT COUNT(*) AS n FROM devices WHERE device_group_id = ?1", &[int(rint(&r, "id"))])?
                .map(|x| rint(&x, "n"))
                .unwrap_or(0);
            device_groups.push(json!({
                "id": rint(&r, "id"), "guid": rstr(&r, "guid"), "name": rstr(&r, "name"), "note": rstr(&r, "note"),
                "strategy_id": ropt_int(&r, "strategy_id"), "strategy_name": name_value(&strategies, ropt_int(&r, "strategy_id")),
                "devices": devices, "allowed_incomings": incomings,
            }));
        }
    }
    Ok(json_response(&json!({ "user_groups": user_groups, "device_groups": device_groups }), 200))
}

fn user_group_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "user_groups.edit")?;
    let id = save_group(app, req, &actor, "user_group", None, &body(req)?)?;
    Ok(json_response(&json!({ "id": id }), 201))
}

fn user_group_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = group_row_for(app, &actor, "user_group", p.get("group_id").map(String::as_str).unwrap_or(""), "user_groups.edit")?;
    save_group(app, req, &actor, "user_group", Some(&row), &body(req)?)?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn delete_group_row(app: &App, req: &Request, actor: &Actor, kind: &str, row: &Row) -> HttpResult<()> {
    let id = rint(row, "id");
    app.db.execute(
        "DELETE FROM access_rules WHERE (target_type = ?1 AND target_id = ?2) OR (subject_type = ?1 AND subject_id = ?2)",
        &[text(kind), int(id)],
    )?;
    if kind == "user_group" {
        app.db.execute("UPDATE users SET group_id = NULL WHERE group_id = ?1", &[int(id)])?;
    } else {
        app.db.execute("UPDATE devices SET device_group_id = NULL WHERE device_group_id = ?1", &[int(id)])?;
    }
    app.db.execute(&format!("DELETE FROM {kind}s WHERE id = ?1"), &[int(id)])?;
    log(app, actor, req, &format!("{kind}.delete"), &rstr(row, "name"), "");
    Ok(())
}

fn user_group_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = group_row_for(app, &actor, "user_group", p.get("group_id").map(String::as_str).unwrap_or(""), "user_groups.edit")?;
    delete_group_row(app, req, &actor, "user_group", &row)?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn id_list(data: &Object, key: &str) -> Vec<i64> {
    data.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect())
        .unwrap_or_default()
}

fn user_group_members(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let group = group_row_for(app, &actor, "user_group", p.get("group_id").map(String::as_str).unwrap_or(""), "user_groups.view")?;
    let data = body(req)?;
    for uid in id_list(&data, "add") {
        user_row_for(app, &actor, &uid.to_string(), "users.change_group")?;
        app.db.execute("UPDATE users SET group_id = ?1 WHERE id = ?2", &[int(rint(&group, "id")), int(uid)])?;
    }
    for uid in id_list(&data, "remove") {
        user_row_for(app, &actor, &uid.to_string(), "users.change_group")?;
        app.db.execute("UPDATE users SET group_id = NULL WHERE id = ?1 AND group_id = ?2", &[int(uid), int(rint(&group, "id"))])?;
    }
    log(app, &actor, req, "user_group.update", &rstr(&group, "name"), &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn device_group_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "device_groups.edit")?;
    let data = body(req)?;
    let gid = save_group(app, req, &actor, "device_group", None, &data)?;
    if data.get("strategy_id").is_some() {
        let sid = opt_id(app, &data, "strategy_id", "strategies", "strategy")?;
        app.db.execute(
            "UPDATE device_groups SET strategy_id = ?1 WHERE id = ?2",
            &[sid.map(SqlValue::Int).unwrap_or(SqlValue::Null), int(gid)],
        )?;
    }
    Ok(json_response(&json!({ "id": gid }), 201))
}

fn device_group_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let gidp = p.get("group_id").map(String::as_str).unwrap_or("");
    let data = body(req)?;
    let edit: Object = ["name", "note", "allowed_incomings"]
        .iter()
        .filter_map(|k| data.get(*k).map(|v| (k.to_string(), v.clone())))
        .collect();
    if !edit.is_empty() {
        let row = group_row_for(app, &actor, "device_group", gidp, "device_groups.edit")?;
        save_group(app, req, &actor, "device_group", Some(&row), &edit)?;
    }
    if data.get("strategy_id").is_some() {
        let row = group_row_for(app, &actor, "device_group", gidp, "device_groups.change_strategy")?;
        let sid = opt_id(app, &data, "strategy_id", "strategies", "strategy")?;
        app.db.execute(
            "UPDATE device_groups SET strategy_id = ?1 WHERE id = ?2",
            &[sid.map(SqlValue::Int).unwrap_or(SqlValue::Null), int(rint(&row, "id"))],
        )?;
        log(app, &actor, req, "device_group.update", &rstr(&row, "name"), &json::to_string(&json!({"strategy_id": data.get("strategy_id").cloned().unwrap_or(Value::Null)})));
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn device_group_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = group_row_for(app, &actor, "device_group", p.get("group_id").map(String::as_str).unwrap_or(""), "device_groups.edit")?;
    delete_group_row(app, req, &actor, "device_group", &row)?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn device_group_members(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let group = group_row_for(app, &actor, "device_group", p.get("group_id").map(String::as_str).unwrap_or(""), "device_groups.view")?;
    let data = body(req)?;
    let str_ids = |key: &str| -> Vec<String> {
        data.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| match v {
                Value::Str(s) => Some(s.clone()),
                Value::Int(n) => Some(n.to_string()),
                _ => None,
            }).collect())
            .unwrap_or_default()
    };
    for device_id in str_ids("add") {
        let row = device_where(app, &actor, &device_id, "devices.change_group")?;
        app.db.execute("UPDATE devices SET device_group_id = ?1 WHERE id = ?2", &[int(rint(&group, "id")), text(rstr(&row, "id"))])?;
    }
    for device_id in str_ids("remove") {
        let row = device_where(app, &actor, &device_id, "devices.change_group")?;
        app.db.execute("UPDATE devices SET device_group_id = NULL WHERE id = ?1 AND device_group_id = ?2", &[text(rstr(&row, "id")), int(rint(&group, "id"))])?;
    }
    log(app, &actor, req, "device_group.update", &rstr(&group, "name"), &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ strategies ============================

fn strategy_row_for(app: &App, actor: &Actor, sid: &str, perm: &str) -> HttpResult<Row> {
    actor.require(&app.db, perm)?;
    app.db
        .query_one("SELECT * FROM strategies WHERE id = ?1", &[int(pint(sid)?)])?
        .ok_or_else(|| HttpError::new(404, "Strategy not found"))
}

fn unique_strategy(e: String) -> HttpError {
    if e.contains("UNIQUE") {
        HttpError::new(409, "Strategy already exists")
    } else {
        HttpError::new(500, e)
    }
}

/// Validate and normalise a strategy `options` map to a JSON string.
fn clean_options(data: &Object) -> HttpResult<String> {
    let options = match data.get("options") {
        None | Some(Value::Null) => return Ok("{}".to_string()),
        Some(Value::Object(m)) => m,
        _ => return Err(HttpError::new(400, "Invalid options")),
    };
    let mut clean = Object::new();
    for (key, value) in options.iter() {
        let ok_key = !key.is_empty()
            && key.chars().count() <= 64
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !ok_key {
            return Err(HttpError::new(400, format!("Invalid option key: {key}")));
        }
        let s = match value {
            Value::Bool(b) => if *b { "Y".to_string() } else { "N".to_string() },
            Value::Int(n) => n.to_string(),
            Value::Str(s) => s.chars().take(1024).collect(),
            _ => return Err(HttpError::new(400, format!("Invalid value for {key}"))),
        };
        clean.insert(key.clone(), Value::Str(s));
    }
    Ok(json::to_string(&Value::Object(clean)))
}

fn strategies(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let db = &app.db;
    actor.require(db, "strategies.view")?;
    let default_id = db.settings().default_strategy_id;
    let mut applied: HashMap<i64, i64> = HashMap::new();
    for d in db.query("SELECT * FROM devices", &[])? {
        if let (Some(s), _) = models::effective_strategy(db, &d) {
            *applied.entry(rint(&s, "id")).or_insert(0) += 1;
        }
    }
    let items: Vec<Value> = db
        .query("SELECT * FROM strategies ORDER BY name COLLATE NOCASE", &[])?
        .iter()
        .map(|r| {
            let id = rint(r, "id");
            let count = |sql: &str| db.query_one(sql, &[int(id)]).ok().flatten().map(|x| rint(&x, "n")).unwrap_or(0);
            json!({
                "id": id, "guid": rstr(r, "guid"), "name": rstr(r, "name"), "note": rstr(r, "note"),
                "options": models::loads_or(&rstr(r, "options"), json!({})), "enabled": rbool(r, "enabled"),
                "modified_at": rint(r, "modified_at"), "is_default": Some(id) == default_id,
                "applied": applied.get(&id).copied().unwrap_or(0),
                "devices": count("SELECT COUNT(*) AS n FROM devices WHERE strategy_id = ?1"),
                "users": count("SELECT COUNT(*) AS n FROM users WHERE strategy_id = ?1"),
                "device_groups": count("SELECT COUNT(*) AS n FROM device_groups WHERE strategy_id = ?1"),
            })
        })
        .collect();
    Ok(json_response(&json!({ "items": items, "catalog": crate::strategy_options::catalogue_value() }), 200))
}

fn strategy_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "strategies.edit")?;
    let data = body(req)?;
    let name = require_name(&data, "name")?;
    let options = clean_options(&data)?;
    app.db
        .execute(
            "INSERT INTO strategies(guid, name, note, options, modified_at) VALUES (?1,?2,?3,?4,?5)",
            &[text(models::new_guid()), text(&name), text(text_field(&data, "note", 1024).unwrap_or_default()), text(options), int(now())],
        )
        .map_err(unique_strategy)?;
    let id = app.db.query_one("SELECT id FROM strategies WHERE name = ?1", &[text(&name)])?.map(|r| rint(&r, "id")).unwrap_or(0);
    log(app, &actor, req, "strategy.create", &name, "");
    Ok(json_response(&json!({ "id": id }), 201))
}

fn strategy_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = strategy_row_for(app, &actor, p.get("sid").map(String::as_str).unwrap_or(""), "strategies.edit")?;
    let data = body(req)?;
    let name = if data.get("name").is_some() { require_name(&data, "name")? } else { rstr(&row, "name") };
    let note = if data.get("note").is_some() { text_field(&data, "note", 1024).unwrap_or_default() } else { rstr(&row, "note") };
    let old_options = rstr(&row, "options");
    let options = if data.get("options").is_some() { clean_options(&data)? } else { old_options.clone() };
    let enabled = if let Some(v) = data.get("enabled") { vbool(&data_single("enabled", v), "enabled") as i64 } else { rint(&row, "enabled") };
    let modified = if options != old_options { std::cmp::max(now(), rint(&row, "modified_at") + 1) } else { rint(&row, "modified_at") };
    app.db
        .execute(
            "UPDATE strategies SET name = ?1, note = ?2, options = ?3, modified_at = ?4, enabled = ?5 WHERE id = ?6",
            &[text(&name), text(&note), text(&options), int(modified), int(enabled), int(rint(&row, "id"))],
        )
        .map_err(unique_strategy)?;
    let mut detail: Object = data.iter().filter(|(k, _)| k.as_str() != "options").map(|(k, v)| (k.clone(), v.clone())).collect();
    if options != old_options {
        detail.insert("options".into(), Value::Str("changed".into()));
    }
    log(app, &actor, req, "strategy.update", &name, &json::to_string(&Value::Object(detail)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn data_single(key: &str, v: &Value) -> Object {
    let mut o = Object::new();
    o.insert(key.to_string(), v.clone());
    o
}

fn strategy_duplicate(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = strategy_row_for(app, &actor, p.get("sid").map(String::as_str).unwrap_or(""), "strategies.edit")?;
    let base = format!("{} (copy)", rstr(&row, "name"));
    let mut name = base.clone();
    let mut n = 2;
    while app.db.query_one("SELECT 1 FROM strategies WHERE name = ?1", &[text(&name)])?.is_some() {
        name = format!("{base} {n}");
        n += 1;
    }
    let name: String = name.chars().take(64).collect();
    app.db.execute(
        "INSERT INTO strategies(guid, name, note, options, modified_at, enabled) VALUES (?1,?2,?3,?4,?5,?6)",
        &[text(models::new_guid()), text(&name), text(rstr(&row, "note")), text(rstr(&row, "options")), int(now()), int(rint(&row, "enabled"))],
    )?;
    let id = app.db.query_one("SELECT id FROM strategies WHERE name = ?1", &[text(&name)])?.map(|r| rint(&r, "id")).unwrap_or(0);
    log(app, &actor, req, "strategy.create", &name, &format!("duplicate of {}", rstr(&row, "name")));
    Ok(json_response(&json!({ "id": id }), 201))
}

fn strategy_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = strategy_row_for(app, &actor, p.get("sid").map(String::as_str).unwrap_or(""), "strategies.edit")?;
    let id = rint(&row, "id");
    app.db.execute("DELETE FROM strategies WHERE id = ?1", &[int(id)])?;
    if app.db.settings().default_strategy_id == Some(id) {
        let _ = app.db.set_settings(&[("default_strategy_id", Value::Null)]);
    }
    log(app, &actor, req, "strategy.delete", &rstr(&row, "name"), "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn strategy_target_info(kind: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match kind {
        "devices" => Some(("devices", "devices.change_strategy", "devices.view")),
        "users" => Some(("users", "users.change_strategy", "users.view")),
        "device_groups" => Some(("device_groups", "device_groups.change_strategy", "device_groups.view")),
        _ => None,
    }
}

fn strategy_targets(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = strategy_row_for(app, &actor, p.get("sid").map(String::as_str).unwrap_or(""), "strategies.view")?;
    let kind = req.query.get("kind").map(String::as_str).unwrap_or("");
    let (table, _, view) = strategy_target_info(kind)
        .ok_or_else(|| HttpError::new(400, "kind must be devices, users or device_groups"))?;
    let db = &app.db;
    let scope = actor.require(db, view)?;
    let strategies = names(db, "strategies");
    let sel = rint(&row, "id");
    let mut items = Vec::new();
    if kind == "devices" {
        let (cond, params) = scope.device_sql("d");
        let args: Vec<SqlValue> = params.into_iter().map(SqlValue::Int).collect();
        for d in db.query(&format!("SELECT d.* FROM devices d WHERE {cond} ORDER BY d.id"), &args)? {
            let user_s = ropt_int(&d, "user_id").and_then(|uid| db.query_one("SELECT strategy_id FROM users WHERE id = ?1", &[int(uid)]).ok().flatten());
            let group_s = ropt_int(&d, "device_group_id").and_then(|g| db.query_one("SELECT strategy_id FROM device_groups WHERE id = ?1", &[int(g)]).ok().flatten());
            let name = { let o = rstr(&d, "name_override"); if o.is_empty() { rstr(&d, "hostname") } else { o } };
            let sname = |id: Option<i64>| strategies.get(&id.unwrap_or(-1)).cloned().unwrap_or_else(|| "-".to_string());
            items.push(json!({
                "id": rstr(&d, "id"), "name": name, "selected": ropt_int(&d, "strategy_id") == Some(sel),
                "strategies": [
                    sname(ropt_int(&d, "strategy_id")),
                    sname(user_s.as_ref().and_then(|r| ropt_int(r, "strategy_id"))),
                    sname(group_s.as_ref().and_then(|r| ropt_int(r, "strategy_id"))),
                ],
            }));
        }
    } else {
        let rows = if kind == "users" && !scope.everything {
            let (cond, params) = scope.user_sql("u");
            let args: Vec<SqlValue> = params.into_iter().map(SqlValue::Int).collect();
            db.query(&format!("SELECT u.* FROM users u WHERE {cond} ORDER BY u.name COLLATE NOCASE"), &args)?
        } else {
            db.query(&format!("SELECT * FROM {table} ORDER BY name COLLATE NOCASE"), &[])?
        };
        for r in &rows {
            let sname = strategies.get(&ropt_int(r, "strategy_id").unwrap_or(-1)).cloned().unwrap_or_else(|| "-".to_string());
            items.push(json!({
                "id": rint(r, "id"), "name": rstr(r, "name"),
                "selected": ropt_int(r, "strategy_id") == Some(sel), "strategies": [sname],
            }));
        }
    }
    Ok(json_response(&json!({ "items": items }), 200))
}

fn strategy_set_targets(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = strategy_row_for(app, &actor, p.get("sid").map(String::as_str).unwrap_or(""), "strategies.view")?;
    let data = body(req)?;
    let kind = data.get("kind").and_then(Value::as_str).unwrap_or("");
    let (table, perm, _) = strategy_target_info(kind)
        .ok_or_else(|| HttpError::new(400, "kind must be devices, users or device_groups"))?;
    let db = &app.db;
    actor.require(db, perm)?;
    let sel = rint(&row, "id");
    let targets = |key: &str| -> Vec<Value> { data.get(key).and_then(Value::as_array).cloned().unwrap_or_default() };
    for (value, items) in [(Some(sel), targets("add")), (None, targets("remove"))] {
        for target in items {
            // Validate access; devices are addressed by RustDesk ID, others by numeric id.
            let id_str = match &target {
                Value::Str(s) => s.clone(),
                Value::Int(n) => n.to_string(),
                _ => continue,
            };
            if kind == "devices" {
                device_where(app, &actor, &id_str, perm)?;
            } else if kind == "users" {
                user_row_for(app, &actor, &id_str, perm)?;
            }
            match value {
                None => {
                    if kind == "devices" {
                        db.execute(&format!("UPDATE {table} SET strategy_id = NULL WHERE id = ?1 AND strategy_id = ?2"), &[text(&id_str), int(sel)])?;
                    } else {
                        db.execute(&format!("UPDATE {table} SET strategy_id = NULL WHERE id = ?1 AND strategy_id = ?2"), &[int(pint(&id_str)?), int(sel)])?;
                    }
                }
                Some(v) => {
                    if kind == "devices" {
                        db.execute(&format!("UPDATE {table} SET strategy_id = ?1 WHERE id = ?2"), &[int(v), text(&id_str)])?;
                    } else {
                        db.execute(&format!("UPDATE {table} SET strategy_id = ?1 WHERE id = ?2"), &[int(v), int(pint(&id_str)?)])?;
                    }
                }
            }
        }
    }
    log(app, &actor, req, "strategy.assign", &rstr(&row, "name"), &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ address books ============================

fn as_obj(v: Value) -> Object {
    match v {
        Value::Object(m) => m,
        _ => Object::new(),
    }
}

fn pw_string(data: &Object, key: &str) -> String {
    match data.get(key) {
        Some(Value::Str(s)) => s.chars().take(1024).collect(),
        Some(Value::Int(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Resolve the book for `guid`, enforcing the caller's rule (as admin) meets `need`.
fn book_for(app: &App, req: &Request, guid: &str, need: i64) -> HttpResult<(Actor, Row, i64)> {
    let (actor, user) = console_user(app, req)?;
    let rule = models::book_rule(&app.db, &user, guid, true);
    if rule == 0 {
        return Err(HttpError::new(404, "Address book not found"));
    }
    if rule < need {
        return Err(HttpError::new(403, "You do not have permission to change this address book"));
    }
    let book = app
        .db
        .query_one("SELECT * FROM address_books WHERE guid = ?1", &[text(guid)])?
        .ok_or_else(|| HttpError::new(404, "Address book not found"))?;
    Ok((actor, book, rule))
}

fn books(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (_actor, user) = console_user(app, req)?;
    let db = &app.db;
    models::personal_book(db, rint(&user, "id"));
    let rows = db.query(
        "SELECT b.*, u.name AS owner FROM address_books b JOIN users u ON u.id = b.owner_id \
         ORDER BY b.personal DESC, b.name COLLATE NOCASE",
        &[],
    )?;
    let mut items = Vec::new();
    for r in &rows {
        let mine = ropt_int(r, "owner_id") == ropt_int(&user, "id");
        if rbool(r, "personal") && !mine {
            continue;
        }
        let rule = models::book_rule(db, &user, &rstr(r, "guid"), true);
        if rule == 0 {
            continue;
        }
        let peers = db
            .query_one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?1 AND deleted_at IS NULL", &[text(rstr(r, "guid"))])?
            .map(|x| rint(&x, "n"))
            .unwrap_or(0);
        items.push(json!({
            "guid": rstr(r, "guid"), "name": rstr(r, "name"), "note": rstr(r, "note"), "owner": rstr(r, "owner"),
            "owner_id": ropt_int(r, "owner_id"), "personal": rbool(r, "personal"), "rule": rule, "mine": mine,
            "password_set": !rstr(r, "password").is_empty(), "peers": peers,
        }));
    }
    Ok(json_response(&json!({ "items": items }), 200))
}

fn book_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let data = body(req)?;
    let mut owner = rint(&user, "id");
    if actor.is_admin() && data.get("owner_id").is_some() {
        if let Some(o) = opt_id(app, &data, "owner_id", "users", "owner")? {
            owner = o;
        }
    }
    let guid = models::new_guid();
    let name = require_name(&data, "name")?;
    app.db.execute(
        "INSERT INTO address_books(guid, name, owner_id, personal, note, password, created_at) VALUES (?1,?2,?3,0,?4,?5,?6)",
        &[text(&guid), text(&name), int(owner), text(text_field(&data, "note", 1024).unwrap_or_default()), text(pw_string(&data, "password")), int(now())],
    )?;
    log(app, &actor, req, "address_book.create", &name, "");
    Ok(json_response(&json!({ "guid": guid }), 201))
}

fn book_detail(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (_actor, book, rule) = book_for(app, req, &guid, RULE_READ)?;
    let db = &app.db;
    let personal = rbool(&book, "personal");
    let cutoff = now() - ONLINE_SECONDS;
    let mut peers = Vec::new();
    for r in db.query("SELECT * FROM ab_peers WHERE guid = ?1 AND deleted_at IS NULL ORDER BY created_at, peer_id", &[text(&guid)])? {
        let mut pobj = as_obj(models::peer_payload(db, &r, personal));
        let id = pobj.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let online = db
            .query_one("SELECT last_seen_at FROM devices WHERE id = ?1", &[text(&id)])?
            .map(|s| ropt_int(&s, "last_seen_at").map(|t| t >= cutoff).unwrap_or(false))
            .unwrap_or(false);
        let has_pw = !pobj.get("password").and_then(Value::as_str).unwrap_or("").is_empty()
            || !pobj.get("hash").and_then(Value::as_str).unwrap_or("").is_empty();
        pobj.remove("password");
        pobj.remove("hash");
        pobj.insert("online".into(), Value::Bool(online));
        pobj.insert("password_set".into(), Value::Bool(has_pw));
        peers.push(Value::Object(pobj));
    }
    let tags: Vec<Value> = db
        .query("SELECT * FROM ab_tags WHERE guid = ?1 ORDER BY rowid", &[text(&guid)])?
        .iter()
        .map(|r| json!({ "name": rstr(r, "name"), "color": rint(r, "color") }))
        .collect();
    let rules: Vec<Value> = db
        .query(
            "SELECT r.*, u.name AS uname, g.name AS gname FROM ab_rules r \
             LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.user_group_id \
             WHERE r.guid = ?1 ORDER BY r.everyone, r.user_group_id IS NULL, r.id",
            &[text(&guid)],
        )?
        .iter()
        .map(|r| {
            let name = {
                let u = rstr(r, "uname");
                let g = rstr(r, "gname");
                if !u.is_empty() { u } else if !g.is_empty() { g } else { "Everyone".to_string() }
            };
            json!({
                "guid": rstr(r, "rule_guid"), "user_id": ropt_int(r, "user_id"), "user_group_id": ropt_int(r, "user_group_id"),
                "everyone": rbool(r, "everyone"), "rule": rint(r, "rule"), "name": name,
            })
        })
        .collect();
    let owner = db.query_one("SELECT name FROM users WHERE id = ?1", &[int(ropt_int(&book, "owner_id").unwrap_or(0))])?;
    let recycled = db
        .query_one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?1 AND deleted_at IS NOT NULL", &[text(&guid)])?
        .map(|x| rint(&x, "n"))
        .unwrap_or(0);
    Ok(json_response(
        &json!({
            "guid": guid, "name": rstr(&book, "name"), "note": rstr(&book, "note"), "personal": personal,
            "owner": owner.map(|r| rstr(&r, "name")).unwrap_or_default(), "owner_id": ropt_int(&book, "owner_id"), "rule": rule,
            "password_set": !rstr(&book, "password").is_empty(), "peers": peers, "tags": tags, "rules": rules, "recycled": recycled,
        }),
        200,
    ))
}

fn book_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (actor, book, _) = book_for(app, req, &guid, RULE_FULL)?;
    let data = body(req)?;
    let db = &app.db;
    let personal = rbool(&book, "personal");
    if data.get("name").is_some() && !personal {
        let name = require_name(&data, "name")?;
        db.execute("UPDATE address_books SET name = ?1 WHERE guid = ?2", &[text(&name), text(&guid)])?;
        log(app, &actor, req, "address_book.rename", &name, "");
    }
    if data.get("note").is_some() {
        db.execute("UPDATE address_books SET note = ?1 WHERE guid = ?2", &[text(text_field(&data, "note", 1024).unwrap_or_default()), text(&guid)])?;
    }
    if data.get("password").is_some() && !personal {
        db.execute("UPDATE address_books SET password = ?1 WHERE guid = ?2", &[text(pw_string(&data, "password")), text(&guid)])?;
    }
    if data.get("owner_id").is_some() && actor.is_admin() && !personal {
        let owner = opt_id(app, &data, "owner_id", "users", "owner")?.unwrap_or(ropt_int(&book, "owner_id").unwrap_or(0));
        db.execute("UPDATE address_books SET owner_id = ?1 WHERE guid = ?2", &[int(owner), text(&guid)])?;
    }
    if let Some(rules) = data.get("rules") {
        if !personal {
            replace_rules(app, req, &actor, &guid, rules)?;
        }
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn replace_rules(app: &App, req: &Request, actor: &Actor, guid: &str, rules: &Value) -> HttpResult<()> {
    let list = rules.as_array().ok_or_else(|| HttpError::new(400, "Invalid rules"))?;
    let db = &app.db;
    // key = (user_id, user_group_id, everyone) -> rule
    let key_of = |uid: Option<i64>, gid: Option<i64>, ev: bool| (uid.unwrap_or(0), gid.unwrap_or(0), ev as i64);
    let mut old: HashMap<(i64, i64, i64), i64> = HashMap::new();
    for r in db.query("SELECT * FROM ab_rules WHERE guid = ?1", &[text(guid)])? {
        old.insert((ropt_int(&r, "user_id").unwrap_or(0), ropt_int(&r, "user_group_id").unwrap_or(0), rint(&r, "everyone")), rint(&r, "rule"));
    }
    let mut new: Vec<((i64, i64, i64), Option<i64>, Option<i64>, bool, i64)> = Vec::new();
    let mut seen: HashMap<(i64, i64, i64), i64> = HashMap::new();
    for item in list {
        let o = item.as_object().ok_or_else(|| HttpError::new(400, "Invalid rule"))?;
        let rule = o.get("rule").and_then(Value::as_i64).unwrap_or(0);
        if !(1..=3).contains(&rule) {
            return Err(HttpError::new(400, "Invalid rule"));
        }
        let uid = o.get("user_id").and_then(Value::as_i64).filter(|n| *n != 0);
        let gid = o.get("user_group_id").and_then(Value::as_i64).filter(|n| *n != 0);
        let everyone = vbool(o, "everyone");
        if [uid.is_some(), gid.is_some(), everyone].iter().filter(|b| **b).count() != 1 {
            return Err(HttpError::new(400, "A rule targets one user, one group, or everyone"));
        }
        if let Some(u) = uid {
            if db.query_one("SELECT 1 FROM users WHERE id = ?1", &[int(u)])?.is_none() {
                return Err(HttpError::new(400, "Unknown user in rules"));
            }
        }
        if let Some(g) = gid {
            if db.query_one("SELECT 1 FROM user_groups WHERE id = ?1", &[int(g)])?.is_none() {
                return Err(HttpError::new(400, "Unknown group in rules"));
            }
        }
        let key = key_of(uid, gid, everyone);
        if old.get(&key) != Some(&rule) {
            client_api::check_share_target(app, actor, uid, gid, everyone)?;
        }
        seen.insert(key, rule);
        new.push((key, uid, gid, everyone, rule));
    }
    db.execute("DELETE FROM ab_rules WHERE guid = ?1", &[text(guid)])?;
    for (_key, uid, gid, everyone, rule) in &new {
        db.execute(
            "INSERT INTO ab_rules(rule_guid, guid, user_id, user_group_id, everyone, rule) VALUES (?1,?2,?3,?4,?5,?6)",
            &[text(models::new_guid()), text(guid), opt_int_val(*uid), opt_int_val(*gid), int(*everyone as i64), int(*rule)],
        )?;
    }
    let mut keys: std::collections::HashSet<(i64, i64, i64)> = old.keys().copied().collect();
    keys.extend(seen.keys().copied());
    for key in keys {
        let detail = json::to_string(&json!([key.0, key.1, key.2]));
        if !seen.contains_key(&key) {
            log(app, actor, req, "address_book.rule_delete", guid, &detail);
        } else if !old.contains_key(&key) {
            log(app, actor, req, "address_book.rule_add", guid, &json::to_string(&json!([key.0, key.1, key.2, seen[&key]])));
        } else if old[&key] != seen[&key] {
            log(app, actor, req, "address_book.rule_update", guid, &json::to_string(&json!([key.0, key.1, key.2, seen[&key]])));
        }
    }
    Ok(())
}

fn opt_int_val(n: Option<i64>) -> SqlValue {
    n.map(SqlValue::Int).unwrap_or(SqlValue::Null)
}

fn book_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (actor, book, _) = book_for(app, req, &guid, RULE_FULL)?;
    if rbool(&book, "personal") {
        return Err(HttpError::new(400, "A personal address book cannot be deleted"));
    }
    app.db.execute("DELETE FROM address_books WHERE guid = ?1", &[text(&guid)])?;
    log(app, &actor, req, "address_book.delete", &rstr(&book, "name"), "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_peer_add(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (_actor, book, _) = book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    let peer_id = data.get("id").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let existing = app.db.query_one("SELECT deleted_at FROM ab_peers WHERE guid = ?1 AND peer_id = ?2", &[text(&guid), text(&peer_id)])?;
    if let Some(r) = &existing {
        if ropt_int(r, "deleted_at").is_none() {
            return Err(HttpError::new(409, "This ID is already in the address book"));
        }
    }
    let limit = app.db.settings().max_peers_per_ab;
    if limit > 0 {
        let count = app.db.query_one("SELECT COUNT(*) AS n FROM ab_peers WHERE guid = ?1 AND deleted_at IS NULL", &[text(&guid)])?.map(|x| rint(&x, "n")).unwrap_or(0);
        if count >= limit {
            return Err(HttpError::new(400, "The address book is full"));
        }
    }
    if let Some(err) = models::upsert_peer(&app.db, &guid, &data, rbool(&book, "personal"), false) {
        return Err(HttpError::new(400, err));
    }
    Ok(json_response(&json!({ "ok": true }), 201))
}

fn book_importable(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (actor, _book, _) = book_for(app, req, &guid, RULE_READ_WRITE)?;
    let db = &app.db;
    let (cond, params) = actor.scope(db, "devices.view").device_sql("d");
    let mut args: Vec<SqlValue> = params.into_iter().map(SqlValue::Int).collect();
    args.push(text(&guid));
    let rows = db.query(
        &format!("SELECT d.* FROM devices d WHERE {cond} AND d.id NOT IN (SELECT peer_id FROM ab_peers WHERE guid = ? AND deleted_at IS NULL) ORDER BY d.id"),
        &args,
    )?;
    let items: Vec<Value> = rows.iter().map(|r| models::device_payload(db, r, false)).collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

fn book_import(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (actor, book, _) = book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    let ids = data.get("ids").and_then(Value::as_array).ok_or_else(|| HttpError::new(400, "ids must be a list"))?;
    let db = &app.db;
    let (cond, params) = actor.scope(db, "devices.view").device_sql("d");
    for item in ids {
        let device_id = match item {
            Value::Str(s) => s.clone(),
            Value::Int(n) => n.to_string(),
            _ => continue,
        };
        let mut args: Vec<SqlValue> = vec![text(&device_id)];
        args.extend(params.iter().copied().map(SqlValue::Int));
        if db.query_one(&format!("SELECT 1 FROM devices d WHERE d.id = ? AND {cond}"), &args)?.is_some() {
            let mut one = Object::new();
            one.insert("id".into(), Value::Str(device_id));
            models::upsert_peer(db, &guid, &one, rbool(&book, "personal"), false);
        }
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_peer_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let peer_id = p.get("peer_id").cloned().unwrap_or_default();
    let (_actor, book, _) = book_for(app, req, &guid, RULE_READ_WRITE)?;
    let mut data = body(req)?;
    data.insert("id".into(), Value::Str(peer_id));
    if let Some(err) = models::upsert_peer(&app.db, &guid, &data, rbool(&book, "personal"), true) {
        return Err(HttpError::new(400, err));
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_peer_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let peer_id = p.get("peer_id").cloned().unwrap_or_default();
    book_for(app, req, &guid, RULE_READ_WRITE)?;
    models::recycle_peers(&app.db, &guid, &[peer_id]);
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_recycle(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (_actor, book, _) = book_for(app, req, &guid, RULE_READ)?;
    let personal = rbool(&book, "personal");
    let items: Vec<Value> = app
        .db
        .query("SELECT * FROM ab_peers WHERE guid = ?1 AND deleted_at IS NOT NULL ORDER BY deleted_at DESC", &[text(&guid)])?
        .iter()
        .map(|r| {
            let mut pobj = as_obj(models::peer_payload(&app.db, r, personal));
            pobj.remove("password");
            pobj.remove("hash");
            pobj.insert("deleted_at".into(), ropt_int(r, "deleted_at").map(Value::Int).unwrap_or(Value::Null));
            Value::Object(pobj)
        })
        .collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

fn book_recycle_restore(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    for item in data.get("ids").and_then(Value::as_array).cloned().unwrap_or_default() {
        let id = match item {
            Value::Str(s) => s,
            Value::Int(n) => n.to_string(),
            _ => continue,
        };
        app.db.execute("UPDATE ab_peers SET deleted_at = NULL WHERE guid = ?1 AND peer_id = ?2", &[text(&guid), text(&id)])?;
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_recycle_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let (actor, book, _) = book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    if vbool(&data, "all") {
        app.db.execute("DELETE FROM ab_peers WHERE guid = ?1 AND deleted_at IS NOT NULL", &[text(&guid)])?;
    } else {
        for item in data.get("ids").and_then(Value::as_array).cloned().unwrap_or_default() {
            let id = match item {
                Value::Str(s) => s,
                Value::Int(n) => n.to_string(),
                _ => continue,
            };
            app.db.execute("DELETE FROM ab_peers WHERE guid = ?1 AND peer_id = ?2 AND deleted_at IS NOT NULL", &[text(&guid), text(&id)])?;
        }
    }
    let action = if vbool(&data, "all") { "address_book.recycle_empty" } else { "address_book.recycle_delete" };
    log(app, &actor, req, action, &rstr(&book, "name"), &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_tag_add(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    let name = data.get("name").and_then(Value::as_str).map(str::trim).unwrap_or("");
    if name.is_empty() || name.chars().count() > 64 {
        return Err(HttpError::new(400, "Invalid tag name"));
    }
    let color = data.get("color").and_then(Value::as_i64).unwrap_or(0xFF2196F3);
    app.db.execute(
        "INSERT INTO ab_tags(guid, name, color) VALUES (?1,?2,?3) ON CONFLICT(guid, name) DO UPDATE SET color = excluded.color",
        &[text(&guid), text(name), int(color)],
    )?;
    Ok(json_response(&json!({ "ok": true }), 201))
}

fn book_tag_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let name = p.get("name").cloned().unwrap_or_default();
    book_for(app, req, &guid, RULE_READ_WRITE)?;
    let data = body(req)?;
    if let Some(color) = data.get("color").and_then(Value::as_i64) {
        app.db.execute("UPDATE ab_tags SET color = ?1 WHERE guid = ?2 AND name = ?3", &[int(color), text(&guid), text(&name)])?;
    }
    if let Some(new) = data.get("name").and_then(Value::as_str).map(str::trim) {
        if !new.is_empty() && new != name {
            if app.db.query_one("SELECT 1 FROM ab_tags WHERE guid = ?1 AND name = ?2", &[text(&guid), text(new)])?.is_some() {
                return Err(HttpError::new(409, "Tag already exists"));
            }
            models::rename_tag(&app.db, &guid, &name, &new.chars().take(64).collect::<String>());
        }
    }
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn book_tag_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let guid = p.get("guid").cloned().unwrap_or_default();
    let name = p.get("name").cloned().unwrap_or_default();
    book_for(app, req, &guid, RULE_READ_WRITE)?;
    models::delete_tags(&app.db, &guid, &[name]);
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ logs ============================

fn admin_page(req: &Request) -> HttpResult<(i64, i64, i64)> {
    let page = req.query.get("page").map(|s| s.parse::<i64>()).transpose()
        .map_err(|_| HttpError::new(400, "Invalid pagination"))?.unwrap_or(1).max(1);
    let size = req.query.get("size").map(|s| s.parse::<i64>()).transpose()
        .map_err(|_| HttpError::new(400, "Invalid pagination"))?.unwrap_or(50).clamp(1, 500);
    Ok((page, size, (page - 1) * size))
}

/// A copy of `req` with the console-only query keys removed, so audit_rows sees
/// only the filters it understands.
fn audit_request(req: &Request) -> Request {
    let mut query = req.query.clone();
    for k in ["device", "q", "active", "format", "page", "size"] {
        query.remove(k);
    }
    Request {
        method: req.method.clone(),
        path: req.path.clone(),
        query,
        headers: req.headers.clone(),
        body: Vec::new(),
        ip: req.ip.clone(),
        scheme: req.scheme.clone(),
    }
}

fn hostname_of(db: &Database, device_id: &str) -> String {
    match db.query_one("SELECT hostname, name_override FROM devices WHERE id = ?1", &[text(device_id)]).ok().flatten() {
        Some(r) => {
            let o = rstr(&r, "name_override");
            if o.is_empty() { rstr(&r, "hostname") } else { o }
        }
        None => String::new(),
    }
}

fn conn_log_row(db: &Database, r: &Row) -> Value {
    let end = ropt_int(r, "ended_at");
    let authorized = ropt_int(r, "authorized_at").is_some();
    json!({
        "id": rint(r, "id"), "device_id": rstr(r, "device_id"), "device_name": hostname_of(db, &rstr(r, "device_id")),
        "conn_id": rint(r, "conn_id"), "peer_id": rstr(r, "peer_id"), "peer_name": rstr(r, "peer_name"), "ip": rstr(r, "ip"),
        "controller": rstr(r, "controller"), "note": rstr(r, "note"),
        "type": if authorized { models::conn_type_name(rint(r, "type")) } else { "Not Logged In" },
        "auth": models::primary_auth_name(rint(r, "primary_auth")),
        "two_factor": models::two_factor_name(rint(r, "two_factor")),
        "started_at": rint(r, "started_at"), "authorized_at": ropt_int(r, "authorized_at"), "ended_at": end,
        "duration": end.unwrap_or_else(now) - rint(r, "started_at"),
    })
}

fn file_log_row(db: &Database, r: &Row) -> Value {
    let info = models::loads_or(&rstr(r, "info"), json!({}));
    let files = info.get("files").cloned().unwrap_or(Value::Array(vec![]));
    let files_arr = files.as_array().cloned().unwrap_or_default();
    let size = if files_arr.len() == 1 {
        files_arr[0].as_array().and_then(|f| f.get(1)).cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    json!({
        "id": rint(r, "id"), "device_id": rstr(r, "device_id"), "device_name": hostname_of(db, &rstr(r, "device_id")),
        "peer_id": rstr(r, "peer_id"), "peer_name": info.get("name").cloned().unwrap_or(Value::Str(String::new())),
        "ip": info.get("ip").cloned().unwrap_or(Value::Str(String::new())),
        "direction": models::file_type_name(rint(r, "type")), "path": rstr(r, "path"),
        "is_file": rbool(r, "is_file"), "count": info.get("num").cloned().unwrap_or(Value::Int(0)),
        "size": size, "files": files, "created_at": rint(r, "created_at"),
    })
}

fn alarm_log_row(db: &Database, r: &Row) -> Value {
    let info = models::loads_or(&rstr(r, "info"), json!({}));
    let typ = rint(r, "typ");
    let login = models::LOGIN_ALARMS.contains(&typ);
    let info_s = |k: &str| info.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let type_name = {
        let n = models::alarm_type_name(typ);
        if n.is_empty() { format!("Alarm {typ}") } else { n.to_string() }
    };
    let ip = { let i = rstr(r, "ip"); if i.is_empty() { info_s("ip") } else { i } };
    let from = if login {
        let id = info_s("id");
        if id.is_empty() { rstr(r, "ip") } else { id }
    } else {
        let id = info_s("id");
        if id.is_empty() { info_s("ip") } else { id }
    };
    let target = if login { info_s("name") } else { rstr(r, "device_id") };
    json!({
        "id": rint(r, "id"), "device_id": rstr(r, "device_id"), "device_name": hostname_of(db, &rstr(r, "device_id")),
        "type": type_name, "ip": ip, "from": from, "target": target,
        "peer_id": info_s("id"), "peer_name": info_s("name"), "detail": info, "created_at": rint(r, "created_at"),
    })
}

fn console_log_row(_db: &Database, r: &Row) -> Value {
    let action = rstr(r, "action");
    let op = models::console_op_name(rint(r, "iop"));
    json!({
        "id": rint(r, "id"), "user_name": rstr(r, "user_name"), "action": action.clone(),
        "target": rstr(r, "target"), "detail": rstr(r, "detail"), "ip": rstr(r, "ip"), "created_at": rint(r, "created_at"),
        "type": models::console_type_name(rint(r, "typ")),
        "operation": if op.is_empty() { action } else { op.to_string() },
    })
}

fn log_kind(kind: &str) -> Option<(&'static str, &'static [&'static str])> {
    match kind {
        "connections" => Some(("conn", &["device_id", "peer_id", "peer_name", "ip", "controller", "note"])),
        "files" => Some(("file", &["device_id", "peer_id", "path", "info"])),
        "alarms" => Some(("alarm", &["device_id", "ip", "info"])),
        "console" => Some(("console", &["user_name", "action", "target", "detail", "ip"])),
        _ => None,
    }
}

fn render_log(db: &Database, kind: &str, r: &Row) -> Value {
    match kind {
        "connections" => conn_log_row(db, r),
        "files" => file_log_row(db, r),
        "alarms" => alarm_log_row(db, r),
        _ => console_log_row(db, r),
    }
}

fn csv_cols(kind: &str) -> &'static [&'static str] {
    match kind {
        "connections" => &["started_at", "ended_at", "duration", "type", "device_id", "device_name", "controller", "peer_id", "peer_name", "ip", "auth", "two_factor", "note"],
        "files" => &["created_at", "device_id", "device_name", "peer_id", "peer_name", "ip", "direction", "path", "count"],
        "alarms" => &["created_at", "type", "from", "target", "device_id", "ip"],
        _ => &["created_at", "type", "user_name", "operation", "target", "detail", "ip"],
    }
}

fn csv_safe(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::Str(s) => s.clone(),
        Value::Int(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => json::to_string(other),
    };
    let needs = s.chars().next().map(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r')).unwrap_or(false);
    let s = if needs { format!("'{s}") } else { s };
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

fn logs(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let kind = p.get("kind").map(String::as_str).unwrap_or("");
    let (rest_kind, search_cols) = log_kind(kind).ok_or_else(|| HttpError::new(404, "Unknown log"))?;
    let db = &app.db;
    let sub = audit_request(req);
    let (table, base_sql, mut params) = rest_api::audit_rows(app, &actor, rest_kind, &sub)?;
    let mut where_ = vec![base_sql];
    let q = req.query.get("q").map(|s| s.trim()).unwrap_or("");
    if !q.is_empty() {
        let clause = search_cols.iter().map(|c| format!("{c} LIKE ?")).collect::<Vec<_>>().join(" OR ");
        where_.push(format!("({clause})"));
        for _ in search_cols {
            params.push(text(format!("%{q}%")));
        }
    }
    let device = req.query.get("device").map(|s| s.trim()).unwrap_or("");
    if !device.is_empty() && kind != "console" {
        if kind == "connections" || kind == "files" {
            where_.push("(device_id = ? OR peer_id = ?)".into());
            params.push(text(device));
            params.push(text(device));
        } else {
            where_.push("device_id = ?".into());
            params.push(text(device));
        }
    }
    if kind == "connections" && req.query.get("active").map(String::as_str) == Some("1") {
        where_.push("ended_at IS NULL".into());
    }
    let sql = where_.join(" AND ");
    if req.query.get("format").map(String::as_str) == Some("csv") {
        let rows = db.query(&format!("SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT 1000"), &params)?;
        let cols = csv_cols(kind);
        let mut out = String::new();
        out.push_str(&cols.join(","));
        out.push_str("\r\n");
        for r in &rows {
            let item = render_log(db, kind, r);
            let obj = item.as_object().cloned().unwrap_or_default();
            let line: Vec<String> = cols.iter().map(|c| csv_safe(obj.get(*c).unwrap_or(&Value::Null))).collect();
            out.push_str(&line.join(","));
            out.push_str("\r\n");
        }
        return Ok(Response::new(out.into_bytes(), 200, "text/csv; charset=utf-8")
            .with_header("Content-Disposition", &format!("attachment; filename=\"{kind}.csv\"")));
    }
    let (_page, size, offset) = admin_page(req)?;
    let total = db.query_one(&format!("SELECT COUNT(*) AS n FROM {table} WHERE {sql}"), &params)?.map(|x| rint(&x, "n")).unwrap_or(0);
    let mut paged = params.clone();
    paged.push(int(size));
    paged.push(int(offset));
    let rows = db.query(&format!("SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT ? OFFSET ?"), &paged)?;
    let items: Vec<Value> = rows.iter().map(|r| render_log(db, kind, r)).collect();
    Ok(json_response(&json!({ "total": total, "items": items, "can_edit": actor.can(db, "audits.edit") }), 200))
}

fn conn_log_for(app: &App, req: &Request, actor: &Actor, log_id: &str) -> HttpResult<Row> {
    let sub = audit_request(req);
    let (_table, sql, mut params) = rest_api::audit_rows(app, actor, "conn", &sub)?;
    let mut args = vec![int(pint(log_id)?)];
    args.append(&mut params);
    app.db
        .query_one(&format!("SELECT * FROM conn_logs WHERE id = ? AND {sql}"), &args)?
        .ok_or_else(|| HttpError::new(404, "Log entry not found"))
}

fn conn_note(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let row = conn_log_for(app, req, &actor, p.get("log_id").map(String::as_str).unwrap_or(""))?;
    app.db.execute("UPDATE conn_logs SET note = ?1 WHERE id = ?2", &[text(text_field(&body(req)?, "note", 1024).unwrap_or_default()), int(rint(&row, "id"))])?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn conn_disconnect(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "audits.edit")?;
    let row = conn_log_for(app, req, &actor, p.get("log_id").map(String::as_str).unwrap_or(""))?;
    if ropt_int(&row, "ended_at").is_some() {
        return Err(HttpError::new(400, "This connection has already ended"));
    }
    app.db.execute(
        "INSERT OR IGNORE INTO pending_disconnects(device_id, conn_id, created_at) VALUES (?1, ?2, ?3)",
        &[text(rstr(&row, "device_id")), int(rint(&row, "conn_id")), int(now())],
    )?;
    log(app, &actor, req, "device.disconnect", &rstr(&row, "device_id"), &json::to_string(&json!([rint(&row, "conn_id")])));
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ admin roles ============================

fn role_payload(db: &Database, r: &Row) -> Value {
    let users: Vec<Value> = db
        .query("SELECT user_id FROM user_admin_roles WHERE role_id = ?1", &[int(rint(r, "id"))])
        .unwrap_or_default()
        .iter()
        .map(|u| Value::Int(rint(u, "user_id")))
        .collect();
    json!({
        "id": rint(r, "id"), "guid": rstr(r, "guid"), "name": rstr(r, "name"), "type": rstr(r, "type"), "note": rstr(r, "note"),
        "perms": models::loads_or(&rstr(r, "perms"), json!([])), "user_groups": models::loads_or(&rstr(r, "user_groups"), json!([])),
        "device_groups": models::loads_or(&rstr(r, "device_groups"), json!([])), "unassigned": rbool(r, "unassigned"), "users": users,
    })
}

fn perm_types(name: &str) -> Option<&'static [&'static str]> {
    crate::authz::PERMISSIONS.iter().find(|(n, _, _)| *n == name).map(|(_, _, t)| *t)
}

fn admin_roles(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    admin_only(app, req)?;
    let db = &app.db;
    let items: Vec<Value> = db
        .query("SELECT * FROM admin_roles ORDER BY name COLLATE NOCASE", &[])?
        .iter()
        .map(|r| role_payload(db, r))
        .collect();
    let permissions: Vec<Value> = crate::authz::PERMISSIONS
        .iter()
        .map(|(name, label, types)| json!({ "name": *name, "label": *label, "types": types.iter().map(|t| Value::Str(t.to_string())).collect::<Vec<_>>() }))
        .collect();
    Ok(json_response(&json!({ "items": items, "permissions": permissions }), 200))
}

/// Validate role fields. Returns (perms_json, user_groups_json, device_groups_json, unassigned).
fn role_fields(db: &Database, data: &Object, role_type: &str) -> HttpResult<(String, String, String, i64)> {
    let perms_in = data.get("perms").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut perms: Vec<String> = Vec::new();
    for p in &perms_in {
        let name = p.as_str().ok_or_else(|| HttpError::new(400, "Unknown permission"))?;
        let types = perm_types(name).ok_or_else(|| HttpError::new(400, "Unknown permission"))?;
        if !types.contains(&role_type) {
            return Err(HttpError::new(400, format!("Not valid for a {role_type} role: {name}")));
        }
        perms.push(name.to_string());
    }
    perms.sort();
    perms.dedup();
    let group_ids = |key: &str| -> HttpResult<Vec<i64>> {
        let mut out = Vec::new();
        for v in data.get(key).and_then(Value::as_array).cloned().unwrap_or_default() {
            out.push(v.as_i64().ok_or_else(|| HttpError::new(400, "Unknown group in scope"))?);
        }
        Ok(out)
    };
    let mut ugs = group_ids("user_groups")?;
    let mut dgs = group_ids("device_groups")?;
    for (ids, table) in [(&ugs, "user_groups"), (&dgs, "device_groups")] {
        for i in ids {
            if db.query_one(&format!("SELECT 1 FROM {table} WHERE id = ?1"), &[int(*i)])?.is_none() {
                return Err(HttpError::new(400, "Unknown group in scope"));
            }
        }
    }
    if role_type != "group" {
        ugs.clear();
        dgs.clear();
    }
    let unassigned = if vbool(data, "unassigned") && role_type == "group" { 1 } else { 0 };
    let to_json = |v: &[i64]| json::to_string(&Value::Array(v.iter().map(|&i| Value::Int(i)).collect()));
    Ok((json::to_string(&Value::Array(perms.iter().map(|s| Value::Str(s.clone())).collect())), to_json(&ugs), to_json(&dgs), unassigned))
}

fn set_role_users(db: &Database, role_id: i64, user_ids: &[Value]) -> HttpResult<()> {
    db.execute("DELETE FROM user_admin_roles WHERE role_id = ?1", &[int(role_id)])?;
    for v in user_ids {
        if let Some(uid) = v.as_i64() {
            if db.query_one("SELECT 1 FROM users WHERE id = ?1", &[int(uid)])?.is_some() {
                db.execute("INSERT OR IGNORE INTO user_admin_roles(user_id, role_id) VALUES (?1, ?2)", &[int(uid), int(role_id)])?;
            }
        }
    }
    Ok(())
}

fn unique_role(e: String) -> HttpError {
    if e.contains("UNIQUE") { HttpError::new(409, "Role already exists") } else { HttpError::new(500, e) }
}

fn admin_role_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let data = body(req)?;
    let role_type = data.get("type").and_then(Value::as_str).unwrap_or("");
    if !["global", "individual", "group"].contains(&role_type) {
        return Err(HttpError::new(400, "type must be global, individual or group"));
    }
    let (perms, ugs, dgs, unassigned) = role_fields(&app.db, &data, role_type)?;
    let name = require_name(&data, "name")?;
    app.db
        .execute(
            "INSERT INTO admin_roles(guid, name, type, perms, user_groups, device_groups, unassigned, note, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            &[text(models::new_guid()), text(&name), text(role_type), text(&perms), text(&ugs), text(&dgs), int(unassigned), text(text_field(&data, "note", 1024).unwrap_or_default()), int(now())],
        )
        .map_err(unique_role)?;
    let id = app.db.query_one("SELECT id FROM admin_roles WHERE name = ?1", &[text(&name)])?.map(|r| rint(&r, "id")).unwrap_or(0);
    if let Some(users) = data.get("users").and_then(Value::as_array) {
        set_role_users(&app.db, id, users)?;
    }
    log(app, &actor, req, "admin_role.create", &name, &perms);
    Ok(json_response(&json!({ "id": id }), 201))
}

fn admin_role_update(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let db = &app.db;
    let row = db
        .query_one("SELECT * FROM admin_roles WHERE id = ?1", &[int(pint(p.get("role_id").map(String::as_str).unwrap_or(""))?)])?
        .ok_or_else(|| HttpError::new(404, "Role not found"))?;
    let data = body(req)?;
    let mut merged = Object::new();
    merged.insert("perms".into(), models::loads_or(&rstr(&row, "perms"), json!([])));
    merged.insert("user_groups".into(), models::loads_or(&rstr(&row, "user_groups"), json!([])));
    merged.insert("device_groups".into(), models::loads_or(&rstr(&row, "device_groups"), json!([])));
    merged.insert("unassigned".into(), Value::Int(rint(&row, "unassigned")));
    for k in ["perms", "user_groups", "device_groups", "unassigned"] {
        if let Some(v) = data.get(k) {
            merged.insert(k.into(), v.clone());
        }
    }
    let role_type = rstr(&row, "type");
    let (perms, ugs, dgs, unassigned) = role_fields(db, &merged, &role_type)?;
    let name = if data.get("name").is_some() { require_name(&data, "name")? } else { rstr(&row, "name") };
    let note = if data.get("note").is_some() { text_field(&data, "note", 1024).unwrap_or_default() } else { rstr(&row, "note") };
    db.execute(
        "UPDATE admin_roles SET name = ?1, note = ?2, perms = ?3, user_groups = ?4, device_groups = ?5, unassigned = ?6 WHERE id = ?7",
        &[text(&name), text(&note), text(&perms), text(&ugs), text(&dgs), int(unassigned), int(rint(&row, "id"))],
    ).map_err(unique_role)?;
    if let Some(users) = data.get("users").and_then(Value::as_array) {
        set_role_users(db, rint(&row, "id"), users)?;
    }
    log(app, &actor, req, "admin_role.update", &name, &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn admin_role_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let row = app.db
        .query_one("SELECT * FROM admin_roles WHERE id = ?1", &[int(pint(p.get("role_id").map(String::as_str).unwrap_or(""))?)])?
        .ok_or_else(|| HttpError::new(404, "Role not found"))?;
    app.db.execute("DELETE FROM admin_roles WHERE id = ?1", &[int(rint(&row, "id"))])?;
    log(app, &actor, req, "admin_role.delete", &rstr(&row, "name"), "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ API tokens ============================

const TOKEN_KEYS: [&str; 6] = ["device", "audit", "user", "group", "strategy", "ab"];

fn tokens(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    admin_only(app, req)?;
    let items: Vec<Value> = app.db
        .query("SELECT t.*, u.name AS creator FROM api_tokens t LEFT JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC", &[])?
        .iter()
        .map(|r| json!({
            "id": rint(r, "id"), "guid": rstr(r, "guid"), "name": rstr(r, "name"), "perms": models::loads_or(&rstr(r, "perms"), json!({})),
            "creator": rstr(r, "creator"), "created_at": rint(r, "created_at"), "expires_at": ropt_int(r, "expires_at"), "last_used_at": ropt_int(r, "last_used_at"),
        }))
        .collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

fn token_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, me) = admin_only(app, req)?;
    let data = body(req)?;
    let name = require_name(&data, "name")?;
    let perms_in = match data.get("perms") {
        None | Some(Value::Null) => Object::new(),
        Some(Value::Object(m)) => m.clone(),
        _ => return Err(HttpError::new(400, "Invalid permissions")),
    };
    let mut clean = Object::new();
    for k in TOKEN_KEYS {
        let v = perms_in.get(k).and_then(Value::as_i64).unwrap_or(0);
        if !(0..=2).contains(&v) {
            return Err(HttpError::new(400, "Permission levels are 0 (none), 1 (read) or 2 (read/write)"));
        }
        clean.insert(k.to_string(), Value::Int(v));
    }
    let expires = match data.get("expires_days").and_then(Value::as_i64) {
        Some(d) if d > 0 => SqlValue::Int(now() + d * 86400),
        _ => SqlValue::Null,
    };
    let token = new_token();
    let perms_json = json::to_string(&Value::Object(clean.clone()));
    app.db.execute(
        "INSERT INTO api_tokens(guid, name, token_hash, user_id, perms, created_at, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        &[text(models::new_guid()), text(&name), text(token_hash(&token)), int(rint(&me, "id")), text(&perms_json), int(now()), expires],
    )?;
    log(app, &actor, req, "settings.token_create", &name, &perms_json);
    Ok(json_response(&json!({ "token": token }), 201))
}

fn token_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let row = app.db
        .query_one("SELECT * FROM api_tokens WHERE id = ?1", &[int(pint(p.get("token_id").map(String::as_str).unwrap_or(""))?)])?
        .ok_or_else(|| HttpError::new(404, "Token not found"))?;
    app.db.execute("DELETE FROM api_tokens WHERE id = ?1", &[int(rint(&row, "id"))])?;
    log(app, &actor, req, "settings.token_delete", &rstr(&row, "name"), "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ recordings ============================

fn recordings(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    admin_only(app, req)?;
    let items: Vec<Value> = app.db
        .query("SELECT * FROM recordings ORDER BY created_at DESC", &[])?
        .iter()
        .map(|r| {
            let mut o = Object::new();
            for k in ["id", "filename", "device_id", "peer_id", "conn_id", "size", "created_at"] {
                if let Some(v) = r.get(k) {
                    o.insert(k.to_string(), v.clone());
                }
            }
            Value::Object(o)
        })
        .collect();
    Ok(json_response(&json!({ "items": items }), 200))
}

fn recording_download(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let rid = p.get("rid").map(String::as_str).unwrap_or("");
    let row = app.db
        .query_one("SELECT * FROM recordings WHERE id = ?1", &[int(pint(rid)?)])?
        .ok_or_else(|| HttpError::new(404, "Recording not found"))?;
    let filename = rstr(&row, "filename");
    let path = app.cfg.recordings_dir().join(&filename);
    let data = std::fs::read(&path).map_err(|_| HttpError::new(404, "Recording not found"))?;
    let ctype = if filename.ends_with(".webm") { "video/webm" } else { "application/octet-stream" };
    log(app, &actor, req, "recording.download", &filename, "");
    Ok(Response::new(data, 200, ctype).with_header("Content-Disposition", &format!("attachment; filename=\"{filename}\"")))
}

fn recording_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let (actor, _) = admin_only(app, req)?;
    let row = app.db
        .query_one("SELECT * FROM recordings WHERE id = ?1", &[int(pint(p.get("rid").map(String::as_str).unwrap_or(""))?)])?
        .ok_or_else(|| HttpError::new(404, "Recording not found"))?;
    let filename = rstr(&row, "filename");
    let path = app.cfg.recordings_dir().join(&filename);
    let _ = std::fs::remove_file(&path);
    app.db.execute("DELETE FROM recordings WHERE id = ?1", &[int(rint(&row, "id"))])?;
    log(app, &actor, req, "recording.delete", &filename, "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

// ============================ invitations ============================

fn invite_info(app: &App, _req: &Request, p: &Params) -> HttpResult<Response> {
    let token = p.get("token").cloned().unwrap_or_default();
    let row = app.db
        .query_one(
            "SELECT name, email FROM users WHERE invite_hash = ?1 AND status = -1 AND invite_expires > ?2",
            &[text(token_hash(&token)), int(now())],
        )?
        .ok_or_else(|| HttpError::new(404, "This invitation is invalid or has expired"))?;
    Ok(json_response(&json!({ "name": rstr(&row, "name"), "email": rstr(&row, "email") }), 200))
}

fn invite_accept(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let token = p.get("token").cloned().unwrap_or_default();
    let data = body(req)?;
    let row = app.db
        .query_one(
            "SELECT * FROM users WHERE invite_hash = ?1 AND status = -1 AND invite_expires > ?2",
            &[text(token_hash(&token)), int(now())],
        )?
        .ok_or_else(|| HttpError::new(404, "This invitation is invalid or has expired"))?;
    app.db.execute(
        "UPDATE users SET password_hash = ?1, status = 1, invite_hash = '', invite_expires = NULL WHERE id = ?2",
        &[text(hash_password(&check_password(&data)?)), int(rint(&row, "id"))],
    )?;
    Ok(json_response(&json!({ "ok": true, "name": rstr(&row, "name") }), 200))
}

// ============================ settings ============================

fn get_client_config(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    console_user(app, req)?;
    Ok(json_response(&Value::Object(client_api::client_config(app, req)), 200))
}

fn get_settings(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    admin_only(app, req)?;
    let s = app.db.settings();
    let mut data = as_obj(s.to_value());
    let pw_set = !data.get("smtp_password").and_then(Value::as_str).unwrap_or("").is_empty();
    data.remove("smtp_password");
    data.insert("smtp_password_set".into(), Value::Bool(pw_set));
    data.insert("hbbs_key_file".into(), Value::Str(app.cfg.hbbs_key_file.clone()));
    let detected = if s.server_key.is_empty() { client_api::hbbs_key(app) } else { String::new() };
    data.insert("detected_key".into(), Value::Str(detected));
    Ok(json_response(&Value::Object(data), 200))
}

enum SettingKind {
    Str,
    Int,
    Bool,
    Strategy,
}

fn setting_kind(key: &str) -> Option<SettingKind> {
    Some(match key {
        "id_server" | "relay_server" | "api_server" | "server_key" | "console_url" | "smtp_host"
        | "smtp_security" | "smtp_user" | "smtp_password" | "smtp_from" => SettingKind::Str,
        "client_token_days" | "console_session_hours" | "log_retention_days" | "recordings_max_mb"
        | "max_peers_per_ab" | "smtp_port" => SettingKind::Int,
        "accept_recordings" | "only_admin_logs" | "allow_non_admin_share"
        | "disable_accessible_devices" => SettingKind::Bool,
        "default_strategy_id" => SettingKind::Strategy,
        _ => return None,
    })
}

fn patch_settings(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    let data = body(req)?;
    if data.len() == 1 && data.contains_key("default_strategy_id") {
        actor.require(&app.db, "strategies.edit")?;
    } else if !actor.is_admin() {
        return Err(HttpError::new(403, "Administrator access required"));
    }
    let mut values: Vec<(String, Value)> = Vec::new();
    for (key, value) in data.iter() {
        let kind = setting_kind(key).ok_or_else(|| HttpError::new(400, format!("Unknown setting: {key}")))?;
        let clean = match kind {
            SettingKind::Str => {
                let s = value.as_str().ok_or_else(|| HttpError::new(400, format!("Invalid {key}")))?;
                let s: String = s.trim().chars().take(512).collect();
                if key == "smtp_security" && !["starttls", "ssl", "none"].contains(&s.as_str()) {
                    return Err(HttpError::new(400, "smtp_security must be starttls, ssl or none"));
                }
                Value::Str(s)
            }
            SettingKind::Int => {
                let n = match value {
                    Value::Int(n) => *n,
                    _ => return Err(HttpError::new(400, format!("Invalid {key}"))),
                };
                if n < 0 {
                    return Err(HttpError::new(400, format!("Invalid {key}")));
                }
                if key == "console_session_hours" && n < 1 {
                    return Err(HttpError::new(400, format!("{key} must be at least 1")));
                }
                Value::Int(n)
            }
            SettingKind::Bool => Value::Bool(vbool(&data, key)),
            SettingKind::Strategy => match opt_id(app, &data, key, "strategies", "strategy")? {
                Some(id) => Value::Int(id),
                None => Value::Null,
            },
        };
        values.push((key.clone(), clean));
    }
    let refs: Vec<(&str, Value)> = values.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
    app.db.set_settings(&refs).map_err(|e| HttpError::new(400, e))?;
    let shown: Object = values
        .iter()
        .map(|(k, v)| (k.clone(), if k == "smtp_password" { Value::Str("(hidden)".into()) } else { v.clone() }))
        .collect();
    log(app, &actor, req, "settings.update", "", &json::to_string(&Value::Object(shown)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn smtp_test(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (_actor, me) = admin_only(app, req)?;
    let to = body(req)?
        .get("to")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| rstr(&me, "email"));
    let to = to.trim().to_string();
    if !to.contains('@') {
        return Err(HttpError::new(400, "Enter an address to send the test email to"));
    }
    mail::send(&app.db.settings(), &to, "RussDesk test email", "Email from RussDesk works.")?;
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn lookup(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    console_user(app, req)?;
    let db = &app.db;
    let users: Vec<Value> = db
        .query("SELECT id, name, group_id FROM users ORDER BY name COLLATE NOCASE", &[])?
        .iter()
        .map(|r| json!({ "id": rint(r, "id"), "name": rstr(r, "name"), "group_id": ropt_int(r, "group_id") }))
        .collect();
    let simple = |table: &str| -> HttpResult<Vec<Value>> {
        Ok(db
            .query(&format!("SELECT id, name FROM {table} ORDER BY name COLLATE NOCASE"), &[])?
            .iter()
            .map(|r| json!({ "id": rint(r, "id"), "name": rstr(r, "name") }))
            .collect())
    };
    let strategies: Vec<Value> = db
        .query("SELECT id, name, enabled FROM strategies ORDER BY name COLLATE NOCASE", &[])?
        .iter()
        .map(|r| json!({ "id": rint(r, "id"), "name": rstr(r, "name"), "enabled": rbool(r, "enabled") }))
        .collect();
    let admin_roles: Vec<Value> = db
        .query("SELECT id, name, type FROM admin_roles ORDER BY name COLLATE NOCASE", &[])?
        .iter()
        .map(|r| json!({ "id": rint(r, "id"), "name": rstr(r, "name"), "type": rstr(r, "type") }))
        .collect();
    Ok(json_response(
        &json!({
            "users": users, "user_groups": simple("user_groups")?, "device_groups": simple("device_groups")?,
            "strategies": strategies, "admin_roles": admin_roles,
        }),
        200,
    ))
}

// ============================ own account ============================

fn account_update(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let data = body(req)?;
    let db = &app.db;
    let uid = rint(&user, "id");
    let email = if data.get("email").is_some() {
        text_field(&data, "email", 256).unwrap_or_default()
    } else {
        rstr(&user, "email")
    };
    if data.get("display_name").is_some() {
        db.execute("UPDATE users SET display_name = ?1 WHERE id = ?2", &[text(text_field(&data, "display_name", 256).unwrap_or_default()), int(uid)])?;
    }
    if data.get("email").is_some() {
        db.execute("UPDATE users SET email = ?1 WHERE id = ?2", &[text(&email), int(uid)])?;
    }
    if data.get("email_verification").is_some() {
        if vbool(&data, "email_verification") && !(!email.is_empty() && mail::configured(&db.settings())) {
            return Err(HttpError::new(400, "Email login verification needs an email address and SMTP settings"));
        }
        db.execute("UPDATE users SET email_verification = ?1 WHERE id = ?2", &[int(vbool(&data, "email_verification") as i64), int(uid)])?;
    }
    log(app, &actor, req, "account.update", &rstr(&user, "name"), &json::to_string(&Value::Object(data)));
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn change_password(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let data = body(req)?;
    let current = data.get("current").and_then(Value::as_str).unwrap_or("");
    if !verify_password(current, &rstr(&user, "password_hash")) {
        return Err(HttpError::new(400, "Current password is wrong"));
    }
    if !rstr(&user, "totp_secret").is_empty() {
        let code = data.get("code").and_then(Value::as_str).unwrap_or("");
        if !auth::verify_code(&app.db, &user, code) {
            return Err(HttpError::new(400, "Enter a valid two-factor code to change your password"));
        }
    }
    let new = check_password_field(&data, "new")?;
    app.db.execute("UPDATE users SET password_hash = ?1 WHERE id = ?2", &[text(hash_password(&new)), int(rint(&user, "id"))])?;
    app.db.execute("DELETE FROM tokens WHERE user_id = ?1 AND token_hash != ?2", &[int(rint(&user, "id")), text(session_token_hash(req))])?;
    log(app, &actor, req, "account.password", "", "");
    Ok(json_response(&json!({ "ok": true }), 200))
}

fn check_password_field(data: &Object, key: &str) -> HttpResult<String> {
    match data.get(key).and_then(Value::as_str) {
        Some(p) if p.len() >= 8 && p.len() <= 256 => Ok(p.to_string()),
        Some(p) if p.len() > 256 => Err(HttpError::new(400, "Password is too long")),
        _ => Err(HttpError::new(400, "Password must be at least 8 characters")),
    }
}

fn totp_setup(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (_actor, user) = console_user(app, req)?;
    let secret = new_totp_secret();
    let uri = totp_uri(&secret, &rstr(&user, "name"), "RussDesk");
    Ok(json_response(&json!({ "secret": secret, "uri": uri }), 200))
}

fn valid_totp_secret(s: &str) -> bool {
    (16..=64).contains(&s.len()) && s.chars().all(|c| ('A'..='Z').contains(&c) || ('2'..='7').contains(&c))
}

fn totp_enable(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    let data = body(req)?;
    let secret = data.get("secret").and_then(Value::as_str).unwrap_or("");
    if !valid_totp_secret(secret) {
        return Err(HttpError::new(400, "Invalid secret"));
    }
    let code = data.get("code").and_then(Value::as_str).unwrap_or("");
    if !verify_totp(secret, code) {
        return Err(HttpError::new(400, "The code does not match; check the time on your phone and try again"));
    }
    let (codes, hashes) = new_backup_codes(10);
    app.db.execute(
        "UPDATE users SET totp_secret = ?1, totp_backup = ?2, totp_set_at = ?3 WHERE id = ?4",
        &[text(secret), text(json::to_string(&Value::Array(hashes.into_iter().map(Value::Str).collect()))), int(now()), int(rint(&user, "id"))],
    )?;
    log(app, &actor, req, "account.2fa_enable", "", "");
    Ok(json_response(&json!({ "ok": true, "backup_codes": codes }), 200))
}

fn totp_backup_codes(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    if rstr(&user, "totp_secret").is_empty() {
        return Err(HttpError::new(400, "Two-factor login is off"));
    }
    let code = body(req)?.get("code").and_then(Value::as_str).unwrap_or("").to_string();
    if !verify_totp(&rstr(&user, "totp_secret"), &code) {
        return Err(HttpError::new(400, "Enter a current code from your authenticator app"));
    }
    let (codes, hashes) = new_backup_codes(10);
    app.db.execute(
        "UPDATE users SET totp_backup = ?1 WHERE id = ?2",
        &[text(json::to_string(&Value::Array(hashes.into_iter().map(Value::Str).collect()))), int(rint(&user, "id"))],
    )?;
    log(app, &actor, req, "account.2fa_backup_codes", "", "");
    Ok(json_response(&json!({ "backup_codes": codes }), 200))
}

fn totp_disable(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, user) = console_user(app, req)?;
    if rbool(&user, "force_2fa") {
        return Err(HttpError::new(400, "Two-factor login is required for your account"));
    }
    let password = body(req)?.get("password").and_then(Value::as_str).unwrap_or("").to_string();
    if !verify_password(&password, &rstr(&user, "password_hash")) {
        return Err(HttpError::new(400, "Password is wrong"));
    }
    app.db.execute(
        "UPDATE users SET totp_secret = '', totp_backup = '[]', totp_set_at = NULL WHERE id = ?1",
        &[int(rint(&user, "id"))],
    )?;
    log(app, &actor, req, "account.2fa_disable", "", "");
    Ok(json_response(&json!({ "ok": true }), 200))
}
