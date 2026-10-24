//! Token REST API compatible with RustDesk Server Pro's management scripts
//! (devices.py, users.py, user-groups.py, device-groups.py, strategies.py,
//! audits.py; ab.py lives in client_api). Callers authenticate with an API token
//! from Settings > Tokens. Port of rest_api.py.

use crate::app::App;
use crate::authz::Actor;
use crate::client_api::{
    actor_from_token, api_token, apply_assignments, console_url, ok_empty, page_args,
};
use crate::db::{int, now, opt_int, text, Database, Row, SqlValue};
use crate::mail;
use crate::models::{self, rbool, rint, ropt_int, rstr};
use crate::security::{hash_password, new_token, token_hash};
use crate::web::{json_response, HttpError, HttpResult, Params, Request, Response, Router};

use crate::json::Value;

pub fn register(r: &mut Router<App>) {
    r.add("GET", "/api/devices", devices);
    r.add("POST", "/api/devices/<guid>/enable", |a, q, p| {
        device_set(a, q, p, false, true)
    });
    r.add("POST", "/api/devices/<guid>/disable", |a, q, p| {
        device_set(a, q, p, true, true)
    });
    r.add("DELETE", "/api/devices/<guid>", device_delete);
    r.add("POST", "/api/devices/<guid>/assign", device_assign);
    r.add("POST", "/api/users/<guid>/enable", |a, q, p| {
        user_set(a, q, p, 1)
    });
    r.add("POST", "/api/users/<guid>/disable", |a, q, p| {
        user_set(a, q, p, 0)
    });
    r.add("DELETE", "/api/users/<guid>", user_delete);
    r.add("POST", "/api/users", user_create);
    r.add("POST", "/api/users/invite", user_invite);
    r.add("PUT", "/api/users/tfa/totp/enforce", users_enforce_2fa);
    r.add(
        "PUT",
        "/api/users/disable_login_verification",
        users_disable_verification,
    );
    r.add("POST", "/api/users/force-logout", users_force_logout);
    r.add("GET", "/api/user-groups", |a, q, p| {
        groups(a, q, p, "user_group")
    });
    r.add("POST", "/api/user-groups", |a, q, p| {
        create_group(a, q, p, "user_group")
    });
    r.add("PATCH", "/api/user-groups/<guid>", |a, q, p| {
        update_group(a, q, p, "user_group")
    });
    r.add("DELETE", "/api/user-groups/<guid>", |a, q, p| {
        group_delete(a, q, p, "user_group")
    });
    r.add("POST", "/api/user-groups/<guid>", user_group_add_users);
    r.add("GET", "/api/device-groups", |a, q, p| {
        groups(a, q, p, "device_group")
    });
    r.add("POST", "/api/device-groups", |a, q, p| {
        create_group(a, q, p, "device_group")
    });
    r.add("PATCH", "/api/device-groups/<guid>", |a, q, p| {
        update_group(a, q, p, "device_group")
    });
    r.add("DELETE", "/api/device-groups/<guid>", |a, q, p| {
        group_delete(a, q, p, "device_group")
    });
    r.add(
        "POST",
        "/api/device-groups/<guid>",
        device_group_add_devices,
    );
    r.add(
        "DELETE",
        "/api/device-groups/<guid>/devices",
        device_group_remove_devices,
    );
    r.add("GET", "/api/strategies", strategies);
    r.add("GET", "/api/strategies/<guid>", strategy);
    r.add("PUT", "/api/strategies/<guid>/status", strategy_status);
    r.add("POST", "/api/strategies/assign", strategies_assign);
    r.add("GET", "/api/audits/<kind>", audits);
}

// -- helpers ------------------------------------------------------------------

fn token_actor(app: &App, req: &Request) -> HttpResult<Actor> {
    let token =
        api_token(app, req)?.ok_or_else(|| HttpError::new(401, "A valid API token is required"))?;
    let creator = ropt_int(&token, "user_id").and_then(|uid| {
        app.db
            .query_one("SELECT * FROM users WHERE id = ?1", &[int(uid)])
            .ok()
            .flatten()
    });
    Ok(actor_from_token(&token, creator.as_ref()))
}

fn log(app: &App, actor: &Actor, req: &Request, action: &str, target: &str, detail: &str) {
    models::console_log(
        &app.db,
        actor.user_id,
        &actor.name(),
        &req.ip,
        action,
        target,
        detail,
    );
}

fn page(rows: Vec<Value>, req: &Request) -> HttpResult<Response> {
    let (current, size) = page_args(req)?;
    let total = rows.len() as i64;
    let start = ((current - 1) * size).max(0) as usize;
    let data: Vec<Value> = rows.into_iter().skip(start).take(size as usize).collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

fn guid_param(p: &Params) -> String {
    p.get("guid").cloned().unwrap_or_default()
}

/// Collect LIKE filters from the query string.
fn filters(req: &Request, mapping: &[(&str, &str)]) -> (Vec<String>, Vec<SqlValue>) {
    let mut where_ = Vec::new();
    let mut params = Vec::new();
    for (key, column) in mapping {
        if let Some(v) = req.query.get(*key) {
            if !v.is_empty() {
                where_.push(format!("{column} LIKE ?"));
                params.push(text(models::like(v)));
            }
        }
    }
    (where_, params)
}

// -- devices ------------------------------------------------------------------

fn devices(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let db = &app.db;
    let scope = actor.require(db, "devices.view")?;
    let (cond, mut params) = scope.device_sql("d");
    let (where_, extra) = filters(
        req,
        &[
            ("id", "d.id"),
            (
                "device_name",
                "COALESCE(NULLIF(d.name_override, ''), d.hostname)",
            ),
            ("user_name", "u.name"),
            ("group_name", "g.name"),
            ("device_group_name", "dg.name"),
            (
                "device_username",
                "COALESCE(NULLIF(d.username_override, ''), d.username)",
            ),
        ],
    );
    let mut args: Vec<SqlValue> = params.drain(..).map(SqlValue::Int).collect();
    args.extend(extra);
    let sql = std::iter::once(cond)
        .chain(where_)
        .collect::<Vec<_>>()
        .join(" AND ");
    let rows = db
        .query(
            &format!(
                "SELECT d.* FROM devices d LEFT JOIN users u ON u.id = d.user_id \
                 LEFT JOIN user_groups g ON g.id = u.group_id \
                 LEFT JOIN device_groups dg ON dg.id = d.device_group_id WHERE {sql} ORDER BY d.id"
            ),
            &args,
        )
        .unwrap_or_default();
    page(
        rows.iter()
            .map(|r| models::device_payload(db, r, false))
            .collect(),
        req,
    )
}

fn device_by_guid(app: &App, actor: &Actor, guid: &str, perm: &str) -> HttpResult<Row> {
    let scope = actor.require(&app.db, perm)?;
    let (cond, params) = scope.device_sql("d");
    let mut args: Vec<SqlValue> = vec![text(guid)];
    args.extend(params.into_iter().map(SqlValue::Int));
    app.db
        .query_one(
            &format!("SELECT * FROM devices d WHERE d.guid = ? AND {cond}"),
            &args,
        )
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Device not found"))
}

pub(crate) fn device_set(
    app: &App,
    req: &Request,
    p: &Params,
    disabled: bool,
    _perm: bool,
) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = device_by_guid(app, &actor, &guid_param(p), "devices.enable_disable")?;
    app.db.execute(
        "UPDATE devices SET disabled = ?1 WHERE id = ?2",
        &[int(disabled as i64), text(rstr(&row, "id"))],
    )?;
    log(
        app,
        &actor,
        req,
        if disabled {
            "device.disable"
        } else {
            "device.enable"
        },
        &rstr(&row, "id"),
        "",
    );
    Ok(ok_empty())
}

fn device_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = device_by_guid(app, &actor, &guid_param(p), "devices.delete")?;
    if !rbool(&row, "disabled") {
        return Err(HttpError::new(400, "Disable the device before deleting it"));
    }
    let id = rstr(&row, "id");
    app.db
        .execute("DELETE FROM devices WHERE id = ?1", &[text(&id)])?;
    app.db.execute(
        "DELETE FROM pending_disconnects WHERE device_id = ?1",
        &[text(&id)],
    )?;
    log(app, &actor, req, "device.delete", &id, "");
    Ok(ok_empty())
}

fn assign_perm(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "user_name" => "devices.assign_to_user",
        "device_group_name" => "devices.change_group",
        "strategy_name" => "devices.change_strategy",
        "note" | "device_username" | "device_name" | "ab" => "devices.edit_info",
        _ => return None,
    })
}

fn device_assign(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let data = req.json_object()?;
    let kind = data.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let value = match data.get("value").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return Err(HttpError::new(400, "Invalid assignment")),
    };
    let perm = assign_perm(kind).ok_or_else(|| HttpError::new(400, "Invalid assignment"))?;
    let row = device_by_guid(app, &actor, &guid_param(p), perm)?;
    let mut values = crate::json::Object::new();
    if kind == "ab" {
        let mut parts: Vec<&str> = value.split(',').collect();
        while parts.len() < 5 {
            parts.push("");
        }
        for (k, v) in [
            ("address_book_name", parts[0]),
            ("address_book_tag", parts[1]),
            ("address_book_alias", parts[2]),
            ("address_book_password", parts[3]),
            ("address_book_note", parts[4]),
        ] {
            values.insert(k.to_string(), json!(v));
        }
    } else {
        values.insert(kind.to_string(), json!(value));
    }
    let errors = apply_assignments(&app.db, &row, &values, false);
    if !errors.is_empty() {
        return Err(HttpError::new(400, errors.join("; ")));
    }
    log(
        app,
        &actor,
        req,
        "device.update",
        &rstr(&row, "id"),
        &Value::Object(data).to_string(),
    );
    Ok(ok_empty())
}

// -- users --------------------------------------------------------------------

pub(crate) fn other_admins(db: &Database, user_id: i64) -> i64 {
    db.query_one(
        "SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND status = 1 AND id != ?1",
        &[int(user_id)],
    )
    .ok()
    .flatten()
    .map(|r| rint(&r, "n"))
    .unwrap_or(0)
}

fn user_by_guid(app: &App, actor: &Actor, guid: &str, perm: &str) -> HttpResult<Row> {
    let scope = actor.require(&app.db, perm)?;
    let row = app
        .db
        .query_one("SELECT * FROM users WHERE guid = ?1", &[text(guid)])
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "User not found"))?;
    if !scope.everything && !crate::authz::user_in_scope(&app.db, &scope, rint(&row, "id")) {
        return Err(HttpError::new(
            403,
            "You do not have permission for this user",
        ));
    }
    if rbool(&row, "is_admin") && !actor.is_admin() && actor.token_name.is_none() {
        return Err(HttpError::new(
            403,
            "Only administrators can change administrator accounts",
        ));
    }
    Ok(row)
}

pub(crate) fn user_set(app: &App, req: &Request, p: &Params, status: i64) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = user_by_guid(app, &actor, &guid_param(p), "users.enable_disable")?;
    if status == 0 && rbool(&row, "is_admin") && other_admins(&app.db, rint(&row, "id")) == 0 {
        return Err(HttpError::new(
            400,
            "Keep at least one active administrator",
        ));
    }
    app.db.execute(
        "UPDATE users SET status = ?1 WHERE id = ?2",
        &[int(status), int(rint(&row, "id"))],
    )?;
    if status == 0 {
        app.db.execute(
            "DELETE FROM tokens WHERE user_id = ?1",
            &[int(rint(&row, "id"))],
        )?;
    }
    log(
        app,
        &actor,
        req,
        if status == 0 {
            "user.disable"
        } else {
            "user.enable"
        },
        &rstr(&row, "name"),
        "",
    );
    Ok(ok_empty())
}

fn user_delete(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = user_by_guid(app, &actor, &guid_param(p), "users.delete")?;
    if rint(&row, "status") == 1 {
        return Err(HttpError::new(400, "Disable the user before deleting it"));
    }
    let id = rint(&row, "id");
    app.db.execute(
        "DELETE FROM access_rules WHERE subject_type = 'user' AND subject_id = ?1",
        &[int(id)],
    )?;
    app.db
        .execute("DELETE FROM users WHERE id = ?1", &[int(id)])?;
    log(app, &actor, req, "user.delete", &rstr(&row, "name"), "");
    Ok(ok_empty())
}

pub(crate) fn group_id_by_name(db: &Database, name: &str) -> HttpResult<Option<i64>> {
    if name.is_empty() {
        return Ok(None);
    }
    db.query_one("SELECT id FROM user_groups WHERE name = ?1", &[text(name)])
        .ok()
        .flatten()
        .map(|r| Some(rint(&r, "id")))
        .ok_or_else(|| HttpError::new(400, format!("User group '{name}' not found")))
}

pub(crate) fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.@-".contains(c))
}

/// Create a user (shared by REST and the console). Returns the new user's id.
pub fn create_user(
    app: &App,
    req: &Request,
    actor: &Actor,
    data: &crate::json::Object,
    invite: bool,
) -> HttpResult<i64> {
    let db = &app.db;
    let perm = if invite {
        "users.invite"
    } else {
        "users.create"
    };
    actor.require(db, perm)?;
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !valid_username(&name) {
        return Err(HttpError::new(
            400,
            "Username may use letters, digits and _ . @ - (up to 64)",
        ));
    }
    let mut group_id = data.get("group_id").and_then(|v| v.as_i64());
    if group_id.is_none() {
        if let Some(gn) = data.get("group_name").and_then(|v| v.as_str()) {
            group_id = group_id_by_name(db, gn)?;
        }
    }
    let scope = actor.scope(db, perm);
    if !scope.everything
        && !group_id
            .map(|g| scope.user_groups.contains(&g))
            .unwrap_or(false)
    {
        return Err(HttpError::new(
            403,
            "You can only create users in the groups your role covers",
        ));
    }
    let is_admin = if data
        .get("is_admin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && actor.is_admin()
    {
        1
    } else {
        0
    };
    let email = data
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(256)
        .collect::<String>();
    let note: String = data
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(1024)
        .collect();
    let display: String = data
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(256)
        .collect();
    let guid = models::new_guid();

    let mut invite_token = None;
    let result = if invite {
        if !email.contains('@') {
            return Err(HttpError::new(400, "An invitation needs an email address"));
        }
        let tok = new_token();
        let r = db.execute(
            "INSERT INTO users(guid,name,email,note,display_name,group_id,is_admin,created_at,\
             status,password_hash,invite_hash,invite_expires) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,-1,'!',?9,?10)",
            &[
                text(&guid),
                text(&name),
                text(&email),
                text(&note),
                text(&display),
                opt_int(group_id),
                int(is_admin),
                int(now()),
                text(token_hash(&tok)),
                int(now() + 7 * 86400),
            ],
        );
        invite_token = Some(tok);
        r
    } else {
        let password = data.get("password").and_then(|v| v.as_str()).unwrap_or("");
        if password.len() < 8 {
            return Err(HttpError::new(
                400,
                "Password must be at least 8 characters",
            ));
        }
        db.execute(
            "INSERT INTO users(guid,name,email,note,display_name,group_id,is_admin,created_at,\
             status,password_hash) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,?9)",
            &[
                text(&guid),
                text(&name),
                text(&email),
                text(&note),
                text(&display),
                opt_int(group_id),
                int(is_admin),
                int(now()),
                text(hash_password(password)),
            ],
        )
    };
    if let Err(e) = result {
        if e.contains("UNIQUE") {
            return Err(HttpError::new(409, "User already exists"));
        }
        return Err(HttpError::new(500, e));
    }
    let uid = db
        .query_one("SELECT id FROM users WHERE guid = ?1", &[text(&guid)])
        .ok()
        .flatten()
        .map(|r| rint(&r, "id"))
        .unwrap_or(0);
    models::personal_book(db, uid);
    if invite {
        let link = format!(
            "{}/#/invite/{}",
            console_url(app, req),
            invite_token.unwrap()
        );
        if let Err(e) = mail::send(
            &db.settings(),
            &email,
            "You are invited to RussDesk",
            &format!(
                "Hello {name},\n\nYou have been invited to RussDesk. Set your password here \
                 (the link is valid for 7 days):\n\n{link}\n"
            ),
        ) {
            db.execute("DELETE FROM users WHERE id = ?1", &[int(uid)])
                .ok();
            return Err(e);
        }
    }
    log(
        app,
        actor,
        req,
        if invite { "user.invite" } else { "user.create" },
        &name,
        "",
    );
    Ok(uid)
}

fn user_create(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    create_user(app, req, &actor, &req.json_object()?, false)?;
    Ok(ok_empty())
}

fn user_invite(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    create_user(app, req, &actor, &req.json_object()?, true)?;
    Ok(ok_empty())
}

fn user_guids(
    app: &App,
    actor: &Actor,
    data: &crate::json::Object,
    perm: &str,
) -> HttpResult<Vec<Row>> {
    let guids = data
        .get("user_guids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| HttpError::new(400, "user_guids must be a list"))?;
    guids
        .iter()
        .map(|g| user_by_guid(app, actor, g.as_str().unwrap_or(""), perm))
        .collect()
}

fn users_enforce_2fa(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let data = req.json_object()?;
    let on = data
        .get("enforce")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    for row in user_guids(app, &actor, &data, "users.manage_2fa")? {
        app.db.execute(
            "UPDATE users SET force_2fa = ?1 WHERE id = ?2",
            &[int(on as i64), int(rint(&row, "id"))],
        )?;
        log(
            app,
            &actor,
            req,
            "user.update",
            &rstr(&row, "name"),
            if on {
                "2FA enforcement on"
            } else {
                "2FA enforcement off"
            },
        );
    }
    Ok(ok_empty())
}

fn users_disable_verification(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let data = req.json_object()?;
    let kind = data.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let set = match kind {
        "email" => "email_verification = 0",
        "2fa" => "totp_secret = '', totp_backup = '[]'",
        _ => return Err(HttpError::new(400, "type must be email or 2fa")),
    };
    for row in user_guids(app, &actor, &data, "users.manage_2fa")? {
        app.db.execute(
            &format!("UPDATE users SET {set} WHERE id = ?1"),
            &[int(rint(&row, "id"))],
        )?;
        log(
            app,
            &actor,
            req,
            "user.update",
            &rstr(&row, "name"),
            &format!("{kind} login verification turned off"),
        );
    }
    Ok(ok_empty())
}

fn users_force_logout(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    for row in user_guids(app, &actor, &req.json_object()?, "users.force_logout")? {
        app.db.execute(
            "DELETE FROM tokens WHERE user_id = ?1",
            &[int(rint(&row, "id"))],
        )?;
        log(
            app,
            &actor,
            req,
            "user.update",
            &rstr(&row, "name"),
            "forced logout",
        );
    }
    Ok(ok_empty())
}

// -- groups -------------------------------------------------------------------

pub(crate) fn access_lists(db: &Database, target_type: &str, target_id: i64) -> (Vec<Value>, Vec<Value>) {
    let in_rows = db
        .query(
            "SELECT a.subject_type, a.subject_id, COALESCE(g.name, u.name) AS name FROM access_rules a \
             LEFT JOIN user_groups g ON a.subject_type = 'user_group' AND g.id = a.subject_id \
             LEFT JOIN users u ON a.subject_type = 'user' AND u.id = a.subject_id \
             WHERE a.target_type = ?1 AND a.target_id = ?2",
            &[text(target_type), int(target_id)],
        )
        .unwrap_or_default();
    let incomings = in_rows
        .iter()
        .map(|r| {
            json!({
                "type": if rstr(r, "subject_type") == "user_group" { 0 } else { 2 },
                "name": rstr(r, "name"),
                "id": ropt_int(r, "subject_id"),
            })
        })
        .collect();
    let mut outgoings = Vec::new();
    if target_type == "user_group" {
        let out_rows = db
            .query(
                "SELECT a.target_type, a.target_id, COALESCE(g.name, d.name) AS name FROM access_rules a \
                 LEFT JOIN user_groups g ON a.target_type = 'user_group' AND g.id = a.target_id \
                 LEFT JOIN device_groups d ON a.target_type = 'device_group' AND d.id = a.target_id \
                 WHERE a.subject_type = 'user_group' AND a.subject_id = ?1",
                &[int(target_id)],
            )
            .unwrap_or_default();
        outgoings = out_rows
            .iter()
            .map(|r| {
                json!({
                    "type": if rstr(r, "target_type") == "user_group" { 0 } else { 1 },
                    "name": rstr(r, "name"),
                    "id": ropt_int(r, "target_id"),
                })
            })
            .collect();
    }
    (incomings, outgoings)
}

fn resolve(db: &Database, item: &Value, kinds: &[(i64, &str)]) -> HttpResult<(String, i64)> {
    let obj = item
        .as_object()
        .ok_or_else(|| HttpError::new(400, "Access rules must be objects with type and name"))?;
    let t = obj.get("type").and_then(|v| v.as_i64());
    let kind = kinds
        .iter()
        .find(|(n, _)| Some(*n) == t)
        .map(|(_, k)| *k)
        .ok_or_else(|| HttpError::new(400, "Invalid access rule type"))?;
    let table = match kind {
        "user_group" => "user_groups",
        "device_group" => "device_groups",
        _ => "users",
    };
    let row = if let Some(id) = obj.get("id").and_then(|v| v.as_i64()) {
        db.query_one(&format!("SELECT id FROM {table} WHERE id = ?1"), &[int(id)])
            .ok()
            .flatten()
    } else {
        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
        db.query_one(
            &format!("SELECT id FROM {table} WHERE name = ?1"),
            &[text(name)],
        )
        .ok()
        .flatten()
    };
    let row = row.ok_or_else(|| HttpError::new(400, format!("{kind} not found")))?;
    Ok((kind.to_string(), rint(&row, "id")))
}

pub(crate) fn set_access(
    db: &Database,
    target_type: &str,
    target_id: i64,
    data: &crate::json::Object,
) -> HttpResult<()> {
    if let Some(items) = data.get("allowed_incomings") {
        db.execute(
            "DELETE FROM access_rules WHERE target_type = ?1 AND target_id = ?2",
            &[text(target_type), int(target_id)],
        )?;
        for item in items.as_array().cloned().unwrap_or_default() {
            let (kind, sid) = resolve(db, &item, &[(0, "user_group"), (2, "user")])?;
            if !(kind == "user_group" && target_type == "user_group" && sid == target_id) {
                db.execute(
                    "INSERT OR IGNORE INTO access_rules VALUES (?1, ?2, ?3, ?4)",
                    &[text(&kind), int(sid), text(target_type), int(target_id)],
                )?;
            }
        }
    }
    if data.get("allowed_outgoings").is_some() && target_type == "user_group" {
        db.execute(
            "DELETE FROM access_rules WHERE subject_type = 'user_group' AND subject_id = ?1",
            &[int(target_id)],
        )?;
        for item in data
            .get("allowed_outgoings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let (kind, tid) = resolve(db, &item, &[(0, "user_group"), (1, "device_group")])?;
            if !(kind == "user_group" && tid == target_id) {
                db.execute(
                    "INSERT OR IGNORE INTO access_rules VALUES ('user_group', ?1, ?2, ?3)",
                    &[int(target_id), text(&kind), int(tid)],
                )?;
            }
        }
    }
    Ok(())
}

pub(crate) fn group_payload(db: &Database, row: &Row, kind: &str) -> Value {
    let (incomings, outgoings) = access_lists(db, kind, rint(row, "id"));
    let mut data = json!({
        "guid": rstr(row, "guid"),
        "name": rstr(row, "name"),
        "note": rstr(row, "note"),
        "allowed_incomings": incomings,
    });
    if kind == "user_group" {
        data["allowed_outgoings"] = Value::Array(outgoings);
    }
    data
}

fn groups(app: &App, req: &Request, _p: &Params, kind: &str) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let db = &app.db;
    actor.require(db, &format!("{kind}s.view"))?;
    let table = format!("{kind}s");
    let (where_, params) = filters(req, &[("name", "name")]);
    let sql = std::iter::once("1".to_string())
        .chain(where_)
        .collect::<Vec<_>>()
        .join(" AND ");
    let rows = db
        .query(
            &format!("SELECT * FROM {table} WHERE {sql} ORDER BY name COLLATE NOCASE"),
            &params,
        )
        .unwrap_or_default();
    page(
        rows.iter().map(|r| group_payload(db, r, kind)).collect(),
        req,
    )
}

fn create_group(app: &App, req: &Request, _p: &Params, kind: &str) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let db = &app.db;
    actor.require(db, &format!("{kind}s.edit"))?;
    let data = req.json_object()?;
    let name = data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(HttpError::new(400, "Invalid name"));
    }
    let note: String = data
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(1024)
        .collect();
    let res = db.execute(
        &format!("INSERT INTO {kind}s(guid, name, note, created_at) VALUES (?1,?2,?3,?4)"),
        &[
            text(models::new_guid()),
            text(&name),
            text(&note),
            int(now()),
        ],
    );
    match res {
        Err(e) if e.contains("UNIQUE") => return Err(HttpError::new(409, "Group already exists")),
        Err(e) => return Err(HttpError::new(500, e)),
        Ok(_) => {}
    }
    let id = db
        .query_one(
            &format!("SELECT id FROM {kind}s WHERE name = ?1"),
            &[text(&name)],
        )
        .ok()
        .flatten()
        .map(|r| rint(&r, "id"))
        .unwrap_or(0);
    set_access(db, kind, id, &data)?;
    log(app, &actor, req, &format!("{kind}.create"), &name, "");
    Ok(ok_empty())
}

fn group_by_guid(app: &App, actor: &Actor, kind: &str, guid: &str, perm: &str) -> HttpResult<Row> {
    actor.require(&app.db, perm)?;
    app.db
        .query_one(
            &format!("SELECT * FROM {kind}s WHERE guid = ?1"),
            &[text(guid)],
        )
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Group not found"))
}

fn update_group(app: &App, req: &Request, p: &Params, kind: &str) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = group_by_guid(app, &actor, kind, &guid_param(p), &format!("{kind}s.edit"))?;
    let data = req.json_object()?;
    let db = &app.db;
    let id = rint(&row, "id");
    if let Some(name) = data.get("name").and_then(|v| v.as_str()) {
        if !name.trim().is_empty() {
            db.execute(
                &format!("UPDATE {kind}s SET name = ?1 WHERE id = ?2"),
                &[
                    text(name.trim().chars().take(64).collect::<String>()),
                    int(id),
                ],
            )?;
        }
    }
    if data.get("note").is_some() {
        let note: String = data
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(1024)
            .collect();
        db.execute(
            &format!("UPDATE {kind}s SET note = ?1 WHERE id = ?2"),
            &[text(note), int(id)],
        )?;
    }
    set_access(db, kind, id, &data)?;
    log(
        app,
        &actor,
        req,
        &format!("{kind}.update"),
        &rstr(&row, "name"),
        &Value::Object(data).to_string(),
    );
    Ok(ok_empty())
}

fn group_delete(app: &App, req: &Request, p: &Params, kind: &str) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let row = group_by_guid(app, &actor, kind, &guid_param(p), &format!("{kind}s.edit"))?;
    let id = rint(&row, "id");
    app.db.execute(
        "DELETE FROM access_rules WHERE (target_type = ?1 AND target_id = ?2) OR \
         (subject_type = ?1 AND subject_id = ?2)",
        &[text(kind), int(id)],
    )?;
    app.db
        .execute(&format!("DELETE FROM {kind}s WHERE id = ?1"), &[int(id)])?;
    log(
        app,
        &actor,
        req,
        &format!("{kind}.delete"),
        &rstr(&row, "name"),
        "",
    );
    Ok(ok_empty())
}

fn json_guids(req: &Request) -> HttpResult<Vec<String>> {
    let v = req.json()?;
    let arr = v
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list"))?;
    Ok(arr
        .iter()
        .map(|x| x.as_str().unwrap_or("").to_string())
        .collect())
}

fn user_group_add_users(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let group = group_by_guid(
        app,
        &actor,
        "user_group",
        &guid_param(p),
        "users.change_group",
    )?;
    let guids = json_guids(req)?;
    for ug in &guids {
        let row = user_by_guid(app, &actor, ug, "users.change_group")?;
        app.db.execute(
            "UPDATE users SET group_id = ?1 WHERE id = ?2",
            &[int(rint(&group, "id")), int(rint(&row, "id"))],
        )?;
    }
    log(
        app,
        &actor,
        req,
        "user_group.update",
        &rstr(&group, "name"),
        &format!("added {} users", guids.len()),
    );
    Ok(ok_empty())
}

fn device_ids(req: &Request) -> HttpResult<Vec<String>> {
    let v = req.json()?;
    let arr = v
        .as_array()
        .ok_or_else(|| HttpError::new(400, "Expected a list of device IDs"))?;
    Ok(arr
        .iter()
        .map(|x| {
            x.as_str()
                .map(|s| s.to_string())
                .unwrap_or_else(|| x.to_string())
        })
        .collect())
}

fn device_group_add_devices(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let group = group_by_guid(
        app,
        &actor,
        "device_group",
        &guid_param(p),
        "devices.change_group",
    )?;
    let ids = device_ids(req)?;
    let missing: Vec<String> = ids
        .iter()
        .filter(|i| {
            app.db
                .query_one("SELECT 1 AS n FROM devices WHERE id = ?1", &[text(*i)])
                .ok()
                .flatten()
                .is_none()
        })
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(HttpError::new(
            400,
            format!("Devices not found: {}", missing.join(", ")),
        ));
    }
    for id in &ids {
        app.db.execute(
            "UPDATE devices SET device_group_id = ?1 WHERE id = ?2",
            &[int(rint(&group, "id")), text(id)],
        )?;
    }
    log(
        app,
        &actor,
        req,
        "device_group.update",
        &rstr(&group, "name"),
        &format!("added {}", ids.join(",")),
    );
    Ok(ok_empty())
}

fn device_group_remove_devices(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let group = group_by_guid(
        app,
        &actor,
        "device_group",
        &guid_param(p),
        "devices.change_group",
    )?;
    for id in device_ids(req)? {
        app.db.execute(
            "UPDATE devices SET device_group_id = NULL WHERE id = ?1 AND device_group_id = ?2",
            &[text(&id), int(rint(&group, "id"))],
        )?;
    }
    log(
        app,
        &actor,
        req,
        "device_group.update",
        &rstr(&group, "name"),
        "removed devices",
    );
    Ok(ok_empty())
}

// -- strategies ---------------------------------------------------------------

pub(crate) fn strategy_payload(db: &Database, row: &Row, full: bool) -> Value {
    let mut data = json!({
        "guid": rstr(row, "guid"),
        "name": rstr(row, "name"),
        "note": rstr(row, "note"),
        "enabled": rbool(row, "enabled"),
        "modified_at": rint(row, "modified_at"),
    });
    if full {
        data["options"] = models::loads_or(&rstr(row, "options"), json!({}));
        let id = rint(row, "id");
        let peers: Vec<Value> = db
            .query("SELECT id FROM devices WHERE strategy_id = ?1", &[int(id)])
            .unwrap_or_default()
            .iter()
            .map(|r| json!(rstr(r, "id")))
            .collect();
        let users: Vec<Value> = db
            .query("SELECT name FROM users WHERE strategy_id = ?1", &[int(id)])
            .unwrap_or_default()
            .iter()
            .map(|r| json!(rstr(r, "name")))
            .collect();
        let groups: Vec<Value> = db
            .query(
                "SELECT name FROM device_groups WHERE strategy_id = ?1",
                &[int(id)],
            )
            .unwrap_or_default()
            .iter()
            .map(|r| json!(rstr(r, "name")))
            .collect();
        data["peers"] = Value::Array(peers);
        data["users"] = Value::Array(users);
        data["groups"] = Value::Array(groups);
    }
    data
}

fn strategies(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    actor.require(&app.db, "strategies.view")?;
    let rows = app
        .db
        .query("SELECT * FROM strategies ORDER BY name COLLATE NOCASE", &[])
        .unwrap_or_default();
    let data: Vec<Value> = rows
        .iter()
        .map(|r| strategy_payload(&app.db, r, false))
        .collect();
    Ok(json_response(&Value::Array(data), 200))
}

fn strategy(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    actor.require(&app.db, "strategies.view")?;
    let row = app
        .db
        .query_one(
            "SELECT * FROM strategies WHERE guid = ?1",
            &[text(guid_param(p))],
        )
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Strategy not found"))?;
    Ok(json_response(&strategy_payload(&app.db, &row, true), 200))
}

fn strategy_status(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    actor.require(&app.db, "strategies.edit")?;
    let enabled = req
        .json()?
        .as_bool()
        .ok_or_else(|| HttpError::new(400, "Body must be true or false"))?;
    let row = app
        .db
        .query_one(
            "SELECT * FROM strategies WHERE guid = ?1",
            &[text(guid_param(p))],
        )
        .ok()
        .flatten()
        .ok_or_else(|| HttpError::new(404, "Strategy not found"))?;
    app.db.execute(
        "UPDATE strategies SET enabled = ?1 WHERE id = ?2",
        &[int(enabled as i64), int(rint(&row, "id"))],
    )?;
    log(
        app,
        &actor,
        req,
        "strategy.update",
        &rstr(&row, "name"),
        if enabled { "enabled" } else { "disabled" },
    );
    Ok(ok_empty())
}

fn strategies_assign(app: &App, req: &Request, _p: &Params) -> HttpResult<Response> {
    let actor = token_actor(app, req)?;
    let data = req.json_object()?;
    let mut strategy_id = None;
    if let Some(sg) = data.get("strategy").and_then(|v| v.as_str()) {
        if !sg.is_empty() {
            let row = app
                .db
                .query_one("SELECT id FROM strategies WHERE guid = ?1", &[text(sg)])
                .ok()
                .flatten()
                .ok_or_else(|| HttpError::new(404, "Strategy not found"))?;
            strategy_id = Some(rint(&row, "id"));
        }
    }
    let list = |key: &str| -> Vec<String> {
        data.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .map(|x| x.as_str().unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    assign_strategy(
        app,
        req,
        &actor,
        strategy_id,
        &list("peers"),
        &list("users"),
        &list("groups"),
    )?;
    Ok(ok_empty())
}

pub(crate) fn assign_strategy(
    app: &App,
    req: &Request,
    actor: &Actor,
    strategy_id: Option<i64>,
    peers: &[String],
    users: &[String],
    groups: &[String],
) -> HttpResult<()> {
    let db = &app.db;
    for (table, guids, perm) in [
        ("devices", peers, "devices.change_strategy"),
        ("users", users, "users.change_strategy"),
        ("device_groups", groups, "device_groups.change_strategy"),
    ] {
        if guids.is_empty() {
            continue;
        }
        actor.require(db, perm)?;
        for guid in guids {
            let n = db.execute(
                &format!("UPDATE {table} SET strategy_id = ?1 WHERE guid = ?2"),
                &[opt_int(strategy_id), text(guid)],
            )?;
            if n == 0 {
                return Err(HttpError::new(400, format!("Unknown GUID {guid}")));
            }
        }
    }
    log(
        app,
        actor,
        req,
        "strategy.assign",
        &strategy_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into()),
        &json!({ "peers": peers.to_vec(), "users": users.to_vec(), "groups": groups.to_vec() })
            .to_string(),
    );
    Ok(())
}

// -- audits -------------------------------------------------------------------

fn since(value: &str) -> HttpResult<i64> {
    // "YYYY-MM-DD HH:MM:SS[.fff]" (UTC) -> epoch seconds.
    let base = value.split('.').next().unwrap_or(value);
    let (date, time) = base.split_once(' ').ok_or_else(|| bad_since())?;
    let d: Vec<i64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<i64> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    if d.len() != 3 || t.len() != 3 {
        return Err(bad_since());
    }
    Ok(days_from_civil(d[0], d[1], d[2]) * 86400 + t[0] * 3600 + t[1] * 60 + t[2])
}

fn bad_since() -> HttpError {
    HttpError::new(400, "created_at must look like 2025-09-16 14:15:57")
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub(crate) fn audit_rows(
    app: &App,
    actor: &Actor,
    kind: &str,
    req: &Request,
) -> HttpResult<(String, String, Vec<SqlValue>)> {
    let db = &app.db;
    let scope = actor.require(db, "audits.view")?;
    let (table, time_col) = match kind {
        "conn" => ("conn_logs", "started_at"),
        "file" => ("file_logs", "created_at"),
        "alarm" => ("alarm_logs", "created_at"),
        "console" => ("console_logs", "created_at"),
        _ => return Err(HttpError::new(404, "Unknown audit log")),
    };
    let mut where_ = vec!["1".to_string()];
    let mut params: Vec<SqlValue> = Vec::new();
    if !scope.everything {
        if kind == "console" {
            let ids: Vec<i64> = if scope.own_users.is_empty() {
                vec![0]
            } else {
                scope.own_users.iter().copied().collect()
            };
            where_.push(format!("user_id IN ({})", vec!["?"; ids.len()].join(",")));
            params.extend(ids.into_iter().map(SqlValue::Int));
        } else {
            let (cond, cparams) = scope.device_sql("d");
            let sides = if kind == "alarm" {
                "device_id"
            } else {
                "device_id, peer_id"
            };
            let mut mine =
                format!("EXISTS (SELECT 1 FROM devices d WHERE d.id IN ({sides}) AND {cond})");
            params.extend(cparams.into_iter().map(SqlValue::Int));
            if kind == "conn" && actor.user_id.is_some() {
                mine = format!("({mine} OR controller = ?)");
                params.push(text(&actor.user_name));
            }
            where_.push(mine);
        }
    }
    if let Some(ca) = req.query.get("created_at") {
        where_.push(format!("{time_col} >= ?"));
        params.push(int(since(ca)?));
    }
    for (key, op) in [("from", ">="), ("to", "<")] {
        if let Some(v) = req.query.get(key) {
            if let Ok(n) = v.parse::<i64>() {
                where_.push(format!("{time_col} {op} ?"));
                params.push(int(n));
            }
        }
    }
    if let Some(remote) = req.query.get("remote") {
        if (kind == "conn" || kind == "file") && !remote.is_empty() {
            where_.push("peer_id LIKE ?".into());
            params.push(text(models::like(remote)));
        }
    }
    if kind == "conn" {
        if let Some(ct) = req
            .query
            .get("conn_type")
            .and_then(|v| v.parse::<i64>().ok())
        {
            where_.push("type = ?".into());
            params.push(int(ct));
        }
    }
    if kind != "console" {
        if let Some(dev) = req.query.get("device") {
            if !dev.is_empty() {
                where_.push("device_id LIKE ?".into());
                params.push(text(models::like(dev)));
            }
        }
    }
    if kind == "console" {
        if let Some(op) = req.query.get("operator") {
            if !op.is_empty() {
                where_.push("user_name LIKE ?".into());
                params.push(text(models::like(op)));
            }
        }
    }
    Ok((table.to_string(), where_.join(" AND "), params))
}

fn rest_audit(kind: &str, r: &Row) -> Value {
    match kind {
        "conn" => {
            let mut d = json!({
                "id": rstr(r, "device_id"),
                "guid": rint(r, "id").to_string(),
                "remote": rstr(r, "peer_id"),
                "peer_name": rstr(r, "peer_name"),
                "ip": rstr(r, "ip"),
                "user": rstr(r, "controller"),
                "note": rstr(r, "note"),
                "created_at": rint(r, "started_at"),
                "end_time": ropt_int(r, "ended_at"),
                "primary_auth": ropt_int(r, "primary_auth"),
                "two_factor": ropt_int(r, "two_factor"),
            });
            if ropt_int(r, "type").is_some() && ropt_int(r, "authorized_at").is_some() {
                d["conn_type"] = json!(ropt_int(r, "type"));
            }
            d
        }
        "file" => json!({
            "id": rstr(r, "device_id"),
            "remote": rstr(r, "peer_id"),
            "type": rint(r, "type"),
            "path": rstr(r, "path"),
            "is_file": rbool(r, "is_file"),
            "info": models::loads_or(&rstr(r, "info"), json!({})),
            "created_at": rint(r, "created_at"),
        }),
        "alarm" => json!({
            "device": rstr(r, "device_id"),
            "typ": rint(r, "typ"),
            "info": models::loads_or(&rstr(r, "info"), json!({})),
            "ip": rstr(r, "ip"),
            "created_at": rint(r, "created_at"),
        }),
        _ => {
            let mut d = json!({
                "operator": rstr(r, "user_name"),
                "action": rstr(r, "action"),
                "target": rstr(r, "target"),
                "detail": rstr(r, "detail"),
                "ip": rstr(r, "ip"),
                "created_at": rint(r, "created_at"),
            });
            if ropt_int(r, "typ").is_some() {
                d["typ"] = json!(ropt_int(r, "typ"));
            }
            if ropt_int(r, "iop").is_some() {
                d["iop"] = json!(ropt_int(r, "iop"));
            }
            d
        }
    }
}

fn audits(app: &App, req: &Request, p: &Params) -> HttpResult<Response> {
    let kind = p.get("kind").cloned().unwrap_or_default();
    if !["conn", "file", "alarm", "console"].contains(&kind.as_str()) {
        return Err(HttpError::new(404, "Unknown audit log"));
    }
    let actor = token_actor(app, req)?;
    let (current, size) = page_args(req)?;
    let (table, sql, mut params) = audit_rows(app, &actor, &kind, req)?;
    let db = &app.db;
    let total = db
        .query_one(
            &format!("SELECT COUNT(*) AS n FROM {table} WHERE {sql}"),
            &params,
        )
        .ok()
        .flatten()
        .map(|r| rint(&r, "n"))
        .unwrap_or(0);
    params.push(int(size));
    params.push(int((current - 1) * size));
    let rows = db
        .query(
            &format!("SELECT * FROM {table} WHERE {sql} ORDER BY id DESC LIMIT ? OFFSET ?"),
            &params,
        )
        .unwrap_or_default();
    let data: Vec<Value> = rows.iter().map(|r| rest_audit(&kind, r)).collect();
    Ok(json_response(&json!({ "total": total, "data": data }), 200))
}

#[allow(unused_imports)]
use crate::authz::Scope as _Scope; // keep Scope in scope for type inference docs
