//! Core Rust web-console API. The remaining console sections are ported in
//! separate modules as they reach parity with the Python implementation.
use crate::app::App;
use crate::auth;
use crate::authz::Actor;
use crate::client_api::console_url;
use crate::db::{int, now, text, Row, SqlValue};
use crate::json::Value;
use crate::models::{self, rbool, rint, ropt_int, rstr, ONLINE_SECONDS};
use crate::security::{new_token, token_hash};
use crate::web::{json_response, HttpError, HttpResult, Params, Request, Response, Router};

const COOKIE: &str = "russdesk_session";

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
    r.add("GET", "/api/admin/users", users);
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

fn users(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let (actor, _) = console_user(app, req)?;
    actor.require(&app.db, "users.view")?;
    let rows = app
        .db
        .query("SELECT * FROM users ORDER BY name COLLATE NOCASE", &[])?;
    let items=rows.iter().map(|r|json!({"id":rint(r,"id"),"guid":rstr(r,"guid"),"name":rstr(r,"name"),"display_name":rstr(r,"display_name"),"email":rstr(r,"email"),"status":rint(r,"status"),"is_admin":rbool(r,"is_admin"),"group_id":ropt_int(r,"group_id"),"strategy_id":ropt_int(r,"strategy_id"),"totp_enabled":!rstr(r,"totp_secret").is_empty()})).collect::<Vec<_>>();
    Ok(json_response(&json!({"items":items}), 200))
}
