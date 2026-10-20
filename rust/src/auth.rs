//! Account login shared by the client and the console: password checks, rate
//! limits, login alarms, and the second factor (TOTP, backup code or emailed
//! code). Port of auth.py.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::db::{int, now, text, Database, Row};
use crate::mail;
use crate::models::rstr;
use crate::security::{
    dummy_hash, new_email_code, token_hash, verify_password, verify_totp, RateLimiter,
};

/// Raised when login fails; the API turns it into a user-facing message.
#[derive(Debug)]
pub struct LoginError(pub String);

impl LoginError {
    fn new(msg: &str) -> Self {
        LoginError(msg.to_string())
    }
}

pub fn login_failures() -> &'static RateLimiter {
    static RL: OnceLock<RateLimiter> = OnceLock::new();
    RL.get_or_init(|| RateLimiter::new(10, 300.0))
}

struct Pending {
    user_id: i64,
    method: String,
    code_hash: String,
    expires: f64,
    attempts: u32,
}

fn pending() -> &'static Mutex<HashMap<String, Pending>> {
    static P: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Default)]
struct AlarmState {
    consecutive: u32,
    times: Vec<f64>,
}

fn alarm_state() -> &'static Mutex<HashMap<String, AlarmState>> {
    static A: OnceLock<Mutex<HashMap<String, AlarmState>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(HashMap::new()))
}

fn wall_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn rand_secret(n: usize) -> String {
    crate::encoding::base64url_encode_nopad(&crate::rand::bytes(n))
}

/// Return the user row for valid credentials, else a LoginError.
pub fn check_password(
    db: &Database,
    ip: &str,
    username: &str,
    password: &str,
    device_id: &str,
) -> Result<Row, LoginError> {
    let username = username.trim();
    let keys = [
        format!("ip:{ip}"),
        format!("user:{}", username.to_lowercase()),
    ];
    if keys.iter().any(|k| login_failures().blocked(k)) {
        return Err(LoginError::new(
            "Too many failed attempts, try again in a few minutes",
        ));
    }
    let user = db
        .query_one("SELECT * FROM users WHERE name = ?1", &[text(username)])
        .ok()
        .flatten();
    let ok = match &user {
        None => {
            // Spend the same time as a real verify so a missing account cannot
            // be told apart from a wrong password.
            verify_password(password, dummy_hash());
            false
        }
        Some(u) => verify_password(password, &rstr(u, "password_hash")),
    };
    if !ok {
        for k in &keys {
            login_failures().hit(k);
        }
        record_failure(db, ip, username, device_id);
        return Err(LoginError::new("Wrong username or password"));
    }
    let user = user.unwrap();
    match rint_status(&user) {
        -1 => Err(LoginError::new(
            "This account has not been activated; use the link in the invitation email",
        )),
        1 => {
            login_failures().reset(&format!("user:{}", username.to_lowercase()));
            alarm_state()
                .lock()
                .unwrap()
                .remove(&username.to_lowercase());
            Ok(user)
        }
        _ => Err(LoginError::new("User is disabled")),
    }
}

fn rint_status(user: &Row) -> i64 {
    user.get("status").and_then(|v| v.as_i64()).unwrap_or(0)
}

/// Raise Pro's login-account alarms (types 3, 4 and 5).
fn record_failure(db: &Database, ip: &str, username: &str, device_id: &str) {
    if username.is_empty() {
        return;
    }
    let t = wall_secs();
    let mut alarms: Vec<i64> = Vec::new();
    {
        let mut map = alarm_state().lock().unwrap();
        let state = map.entry(username.to_lowercase()).or_default();
        state.consecutive += 1;
        state.times.retain(|x| t - x < 3600.0);
        state.times.push(t);
        let minute = state.times.iter().filter(|x| t - *x < 60.0).count();
        if state.consecutive == 30 {
            alarms.push(3);
        }
        if minute == 5 {
            alarms.push(4);
        }
        if state.times.len() == 15 {
            alarms.push(5);
        }
    }
    for typ in alarms {
        let info = json!({ "name": username, "ip": ip, "id": device_id }).to_string();
        let _ = db.execute(
            "INSERT INTO alarm_logs(device_id, typ, info, ip, created_at) VALUES (?1,?2,?3,?4,?5)",
            &[text(device_id), int(typ), text(info), text(ip), int(now())],
        );
    }
}

/// "totp", "email" or None. TOTP replaces email verification, as in Pro.
pub fn second_factor(user: &Row) -> Option<&'static str> {
    if !rstr(user, "totp_secret").is_empty() {
        return Some("totp");
    }
    if user
        .get("email_verification")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        != 0
        && !rstr(user, "email").is_empty()
    {
        return Some("email");
    }
    None
}

pub fn needs_2fa_setup(user: &Row) -> bool {
    user.get("force_2fa").and_then(|v| v.as_i64()).unwrap_or(0) != 0
        && rstr(user, "totp_secret").is_empty()
}

/// Create a pending second-factor check; email the code if needed.
pub fn start_challenge(
    db: &Database,
    user: &Row,
    method: &str,
) -> Result<String, crate::web::HttpError> {
    let mut code_hash = String::new();
    if method == "email" {
        let code = new_email_code();
        code_hash = token_hash(&code);
        mail::send(
            &db.settings(),
            &rstr(user, "email"),
            "RussDesk login code",
            &format!(
                "Your RussDesk login code is {code}\n\nIt expires in 10 minutes. \
                 If you did not try to log in, change your password."
            ),
        )?;
    }
    let secret = rand_secret(24);
    pending().lock().unwrap().insert(
        secret.clone(),
        Pending {
            user_id: rint_id(user),
            method: method.to_string(),
            code_hash,
            expires: wall_secs() + 600.0,
            attempts: 0,
        },
    );
    Ok(secret)
}

fn rint_id(user: &Row) -> i64 {
    user.get("id").and_then(|v| v.as_i64()).unwrap_or(0)
}

/// Verify a second-factor code for a pending login; return the user.
pub fn finish_challenge(db: &Database, secret: &str, code: &str) -> Result<Row, LoginError> {
    let (user_id, method, code_hash) = {
        let mut map = pending().lock().unwrap();
        let Some(p) = map.get_mut(secret) else {
            return Err(LoginError::new("Verification expired, log in again"));
        };
        if p.expires < wall_secs() {
            map.remove(secret);
            return Err(LoginError::new("Verification expired, log in again"));
        }
        p.attempts += 1;
        if p.attempts > 5 {
            map.remove(secret);
            return Err(LoginError::new("Too many wrong codes, log in again"));
        }
        (p.user_id, p.method.clone(), p.code_hash.clone())
    };
    let user = db
        .query_one("SELECT * FROM users WHERE id = ?1", &[int(user_id)])
        .ok()
        .flatten();
    let Some(user) = user else {
        return Err(LoginError::new("User is disabled"));
    };
    if rint_status(&user) != 1 {
        return Err(LoginError::new("User is disabled"));
    }
    let ok = if method == "email" {
        !code.is_empty()
            && crate::crypto::ct_eq(token_hash(code.trim()).as_bytes(), code_hash.as_bytes())
    } else {
        verify_code(db, &user, code)
    };
    if !ok {
        login_failures().hit(&format!("user:{}", rstr(&user, "name").to_lowercase()));
        return Err(LoginError::new("Wrong verification code"));
    }
    pending().lock().unwrap().remove(secret);
    Ok(user)
}

/// A TOTP code, or one of the user's unused backup codes (consumed).
pub fn verify_code(db: &Database, user: &Row, code: &str) -> bool {
    if verify_totp(&rstr(user, "totp_secret"), code) {
        return true;
    }
    let mut hashes: Vec<String> = string_array(&rstr(user, "totp_backup"));
    let Some(i) = crate::security::match_backup_code(&hashes, code) else {
        return false;
    };
    hashes.remove(i);
    let _ = db.execute(
        "UPDATE users SET totp_backup = ?1 WHERE id = ?2",
        &[
            text(crate::json::to_string(&crate::json::Value::from(hashes))),
            int(rint_id(user)),
        ],
    );
    true
}

/// Parse a JSON array of strings (the stored backup-code hashes).
fn string_array(s: &str) -> Vec<String> {
    match crate::json::from_str(s) {
        Ok(crate::json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(|x| x.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn expire_pending() {
    let t = wall_secs();
    pending().lock().unwrap().retain(|_, p| p.expires >= t);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::security::hash_password;

    fn tmp_db() -> (std::path::PathBuf, Database) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "russdesk-auth-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let db = Database::open(&dir.join("t.db")).unwrap();
        (dir, db)
    }

    fn add_user(db: &Database, name: &str, password: &str, status: i64) -> i64 {
        db.insert(
            "INSERT INTO users(name, password_hash, status, created_at, guid) VALUES (?1,?2,?3,?4,?5)",
            &[
                text(name),
                text(hash_password(password)),
                int(status),
                int(now()),
                text(crate::models::new_guid()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn password_login() {
        let (dir, db) = tmp_db();
        add_user(&db, "alice", "secret123", 1);
        let u = check_password(&db, "1.1.1.1", "alice", "secret123", "").unwrap();
        assert_eq!(rstr(&u, "name"), "alice");
        assert!(check_password(&db, "1.1.1.1", "alice", "wrong", "").is_err());
        assert!(check_password(&db, "1.1.1.1", "ghost", "whatever", "").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_and_unverified() {
        let (dir, db) = tmp_db();
        add_user(&db, "dis", "secret123", 0);
        add_user(&db, "inv", "secret123", -1);
        let e = check_password(&db, "2.2.2.2", "dis", "secret123", "").unwrap_err();
        assert!(e.0.contains("disabled"));
        let e = check_password(&db, "2.2.2.2", "inv", "secret123", "").unwrap_err();
        assert!(e.0.contains("activated"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn email_challenge_flow() {
        let (dir, db) = tmp_db();
        let uid = add_user(&db, "bob", "secret123", 1);
        // Drive the pending store directly (no SMTP in tests).
        let code = "123456";
        pending().lock().unwrap().insert(
            "sek".into(),
            Pending {
                user_id: uid,
                method: "email".into(),
                code_hash: token_hash(code),
                expires: wall_secs() + 600.0,
                attempts: 0,
            },
        );
        assert!(finish_challenge(&db, "sek", "000000").is_err());
        // reinsert (first wrong attempt counted, still valid)
        let u = finish_challenge(&db, "sek", code);
        assert!(u.is_ok());
        // consumed
        assert!(finish_challenge(&db, "sek", code).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn totp_backup_consumed() {
        let (dir, db) = tmp_db();
        let (codes, hashes) = crate::security::new_backup_codes(3);
        let uid = add_user(&db, "carol", "secret123", 1);
        db.execute(
            "UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP', totp_backup = ?1 WHERE id = ?2",
            &[
                text(crate::json::to_string(&crate::json::Value::from(
                    hashes.clone(),
                ))),
                int(uid),
            ],
        )
        .unwrap();
        let user = db
            .query_one("SELECT * FROM users WHERE id = ?1", &[int(uid)])
            .unwrap()
            .unwrap();
        assert!(verify_code(&db, &user, &codes[0]));
        // reload: one backup code should now be gone
        let user = db
            .query_one("SELECT * FROM users WHERE id = ?1", &[int(uid)])
            .unwrap()
            .unwrap();
        let left: Vec<String> = string_array(&rstr(&user, "totp_backup"));
        assert_eq!(left.len(), 2);
        assert!(!verify_code(&db, &user, &codes[0])); // already used
        let _ = std::fs::remove_dir_all(&dir);
    }
}
