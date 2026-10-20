//! SQLite access: schema, settings and small query helpers. Built on our own
//! sqlite FFI wrapper and json module (no third-party crates).

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::{self, Value};
use crate::rand;
use crate::sqlite::Connection;
pub use crate::sqlite::SqlValue;

/// A database row as a JSON object, mirroring Python's dict-style rows.
pub type Row = json::Object;

/// Seconds since the epoch, as stored in every timestamp column.
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// Parameter constructors.
pub fn int(n: i64) -> SqlValue {
    SqlValue::Int(n)
}
pub fn text(s: impl Into<String>) -> SqlValue {
    SqlValue::Text(s.into())
}
pub fn opt_int(n: Option<i64>) -> SqlValue {
    n.map(SqlValue::Int).unwrap_or(SqlValue::Null)
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS user_groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    guid TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS user_groups_guid ON user_groups(guid);

CREATE TABLE IF NOT EXISTS strategies (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note TEXT NOT NULL DEFAULT '',
    options TEXT NOT NULL DEFAULT '{}',
    modified_at INTEGER NOT NULL,
    guid TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS strategies_guid ON strategies(guid);

CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note TEXT NOT NULL DEFAULT '',
    strategy_id INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    guid TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS device_groups_guid ON device_groups(guid);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1,
    group_id INTEGER REFERENCES user_groups(id) ON DELETE SET NULL,
    strategy_id INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    totp_secret TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_login_at INTEGER,
    guid TEXT NOT NULL DEFAULT '',
    email_verification INTEGER NOT NULL DEFAULT 0,
    force_2fa INTEGER NOT NULL DEFAULT 0,
    totp_backup TEXT NOT NULL DEFAULT '[]',
    totp_set_at INTEGER,
    invite_hash TEXT NOT NULL DEFAULT '',
    invite_expires INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS users_guid ON users(guid);

CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('client', 'console')),
    device_id TEXT NOT NULL DEFAULT '',
    device_uuid TEXT NOT NULL DEFAULT '',
    device_info TEXT NOT NULL DEFAULT '{}',
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_user ON tokens(user_id);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    uuid TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    cpu TEXT NOT NULL DEFAULT '',
    memory TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    sysinfo TEXT NOT NULL DEFAULT '{}',
    ip TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    device_group_id INTEGER REFERENCES device_groups(id) ON DELETE SET NULL,
    strategy_id INTEGER REFERENCES strategies(id) ON DELETE SET NULL,
    applied_keys TEXT NOT NULL DEFAULT '[]',
    conns TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    sysinfo_at INTEGER,
    guid TEXT NOT NULL DEFAULT '',
    disabled INTEGER NOT NULL DEFAULT 0,
    name_override TEXT NOT NULL DEFAULT '',
    username_override TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_guid ON devices(guid);

CREATE TABLE IF NOT EXISTS pending_disconnects (
    device_id TEXT NOT NULL,
    conn_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, conn_id)
);

CREATE TABLE IF NOT EXISTS address_books (
    guid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    personal INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    password TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ab_personal ON address_books(owner_id) WHERE personal = 1;

CREATE TABLE IF NOT EXISTS ab_peers (
    guid TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    peer_id TEXT NOT NULL,
    alias TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    hash TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    extra TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    deleted_at INTEGER,
    PRIMARY KEY (guid, peer_id)
);

CREATE TABLE IF NOT EXISTS ab_tags (
    guid TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (guid, name)
);

CREATE TABLE IF NOT EXISTS ab_rules (
    id INTEGER PRIMARY KEY,
    rule_guid TEXT NOT NULL UNIQUE,
    guid TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_group_id INTEGER REFERENCES user_groups(id) ON DELETE CASCADE,
    everyone INTEGER NOT NULL DEFAULT 0,
    rule INTEGER NOT NULL CHECK (rule IN (1, 2, 3))
);
CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_user ON ab_rules(guid, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_group ON ab_rules(guid, user_group_id) WHERE user_group_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ab_rules_everyone ON ab_rules(guid) WHERE everyone = 1;

CREATE TABLE IF NOT EXISTS conn_logs (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    conn_id INTEGER NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    peer_id TEXT NOT NULL DEFAULT '',
    peer_name TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    type INTEGER,
    primary_auth INTEGER,
    two_factor INTEGER,
    started_at INTEGER NOT NULL,
    authorized_at INTEGER,
    ended_at INTEGER,
    note TEXT NOT NULL DEFAULT '',
    controller TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS conn_logs_open ON conn_logs(device_id, conn_id, ended_at);
CREATE INDEX IF NOT EXISTS conn_logs_started ON conn_logs(started_at);

CREATE TABLE IF NOT EXISTS file_logs (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    peer_id TEXT NOT NULL DEFAULT '',
    conn_id INTEGER,
    type INTEGER NOT NULL DEFAULT 0,
    path TEXT NOT NULL DEFAULT '',
    is_file INTEGER NOT NULL DEFAULT 0,
    info TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS file_logs_created ON file_logs(created_at);

CREATE TABLE IF NOT EXISTS alarm_logs (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL,
    typ INTEGER NOT NULL,
    info TEXT NOT NULL DEFAULT '{}',
    conn_id INTEGER,
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS alarm_logs_created ON alarm_logs(created_at);

CREATE TABLE IF NOT EXISTS console_logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    user_name TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    typ INTEGER,
    iop INTEGER
);
CREATE INDEX IF NOT EXISTS console_logs_created ON console_logs(created_at);

CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, created_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS recordings (
    id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL DEFAULT 0,
    ip TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS access_rules (
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'user_group')),
    subject_id INTEGER NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('user_group', 'device_group')),
    target_id INTEGER NOT NULL,
    PRIMARY KEY (subject_type, subject_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS access_rules_target ON access_rules(target_type, target_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY,
    guid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    perms TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS admin_roles (
    id INTEGER PRIMARY KEY,
    guid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    type TEXT NOT NULL CHECK (type IN ('global', 'individual', 'group')),
    perms TEXT NOT NULL DEFAULT '[]',
    user_groups TEXT NOT NULL DEFAULT '[]',
    device_groups TEXT NOT NULL DEFAULT '[]',
    unassigned INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_admin_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES admin_roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
"#;

/// Console-editable settings and their defaults (db.py DEFAULT_SETTINGS).
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub id_server: String,
    pub relay_server: String,
    pub api_server: String,
    pub server_key: String,
    pub client_token_days: i64,
    pub console_session_hours: i64,
    pub log_retention_days: i64,
    pub accept_recordings: bool,
    pub recordings_max_mb: i64,
    pub max_peers_per_ab: i64,
    pub default_strategy_id: Option<i64>,
    pub only_admin_logs: bool,
    pub allow_non_admin_share: bool,
    pub disable_accessible_devices: bool,
    pub console_url: String,
    pub smtp_host: String,
    pub smtp_port: i64,
    pub smtp_security: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_from: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            id_server: String::new(),
            relay_server: String::new(),
            api_server: String::new(),
            server_key: String::new(),
            client_token_days: 0,
            console_session_hours: 12,
            log_retention_days: 180,
            accept_recordings: false,
            recordings_max_mb: 10240,
            max_peers_per_ab: 0,
            default_strategy_id: None,
            only_admin_logs: false,
            allow_non_admin_share: false,
            disable_accessible_devices: false,
            console_url: String::new(),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_security: "starttls".to_string(),
            smtp_user: String::new(),
            smtp_password: String::new(),
            smtp_from: String::new(),
        }
    }
}

pub const SETTING_KEYS: &[&str] = &[
    "id_server", "relay_server", "api_server", "server_key", "client_token_days",
    "console_session_hours", "log_retention_days", "accept_recordings", "recordings_max_mb",
    "max_peers_per_ab", "default_strategy_id", "only_admin_logs", "allow_non_admin_share",
    "disable_accessible_devices", "console_url", "smtp_host", "smtp_port", "smtp_security",
    "smtp_user", "smtp_password", "smtp_from",
];

impl Settings {
    fn apply(&mut self, key: &str, v: &Value) {
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let i = |v: &Value| v.as_i64().unwrap_or(0);
        let b = |v: &Value| v.as_bool().unwrap_or(false);
        match key {
            "id_server" => self.id_server = s(v),
            "relay_server" => self.relay_server = s(v),
            "api_server" => self.api_server = s(v),
            "server_key" => self.server_key = s(v),
            "client_token_days" => self.client_token_days = i(v),
            "console_session_hours" => self.console_session_hours = i(v),
            "log_retention_days" => self.log_retention_days = i(v),
            "accept_recordings" => self.accept_recordings = b(v),
            "recordings_max_mb" => self.recordings_max_mb = i(v),
            "max_peers_per_ab" => self.max_peers_per_ab = i(v),
            "default_strategy_id" => self.default_strategy_id = v.as_i64(),
            "only_admin_logs" => self.only_admin_logs = b(v),
            "allow_non_admin_share" => self.allow_non_admin_share = b(v),
            "disable_accessible_devices" => self.disable_accessible_devices = b(v),
            "console_url" => self.console_url = s(v),
            "smtp_host" => self.smtp_host = s(v),
            "smtp_port" => self.smtp_port = i(v),
            "smtp_security" => self.smtp_security = s(v),
            "smtp_user" => self.smtp_user = s(v),
            "smtp_password" => self.smtp_password = s(v),
            "smtp_from" => self.smtp_from = s(v),
            _ => {}
        }
    }

    /// The settings as a JSON object (for the console API).
    pub fn to_value(&self) -> Value {
        json!({
            "id_server": self.id_server.clone(),
            "relay_server": self.relay_server.clone(),
            "api_server": self.api_server.clone(),
            "server_key": self.server_key.clone(),
            "client_token_days": self.client_token_days,
            "console_session_hours": self.console_session_hours,
            "log_retention_days": self.log_retention_days,
            "accept_recordings": self.accept_recordings,
            "recordings_max_mb": self.recordings_max_mb,
            "max_peers_per_ab": self.max_peers_per_ab,
            "default_strategy_id": self.default_strategy_id,
            "only_admin_logs": self.only_admin_logs,
            "allow_non_admin_share": self.allow_non_admin_share,
            "disable_accessible_devices": self.disable_accessible_devices,
            "console_url": self.console_url.clone(),
            "smtp_host": self.smtp_host.clone(),
            "smtp_port": self.smtp_port,
            "smtp_security": self.smtp_security.clone(),
            "smtp_user": self.smtp_user.clone(),
            "smtp_password": self.smtp_password.clone(),
            "smtp_from": self.smtp_from.clone(),
        })
    }
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.exec(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; \
             PRAGMA foreign_keys=ON; PRAGMA busy_timeout=30000;",
        )?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.exec(SCHEMA)?;
        let has = conn
            .query("SELECT value FROM meta WHERE key = 'schema_version'", &[])?
            .into_iter()
            .next()
            .is_some();
        if !has {
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', '2'), ('instance_id', ?1)",
                &[text(uuid_hex())],
            )?;
        }
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        self.query_one("SELECT value FROM meta WHERE key = ?1", &[text(key)])
            .ok()
            .flatten()
            .and_then(|r| r.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()))
    }

    pub fn settings(&self) -> Settings {
        let mut s = Settings::default();
        let rows = self.query("SELECT key, value FROM settings", &[]).unwrap_or_default();
        for row in &rows {
            let key = row.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let raw = row.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if let Ok(v) = json::from_str(raw) {
                s.apply(&key, &v);
            }
        }
        s
    }

    /// Store settings; each value is JSON-encoded. Unknown keys error.
    pub fn set_settings(&self, values: &[(&str, Value)]) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.exec("BEGIN IMMEDIATE")?;
        for (key, value) in values {
            if !SETTING_KEYS.contains(key) {
                let _ = conn.exec("ROLLBACK");
                return Err(format!("unknown setting: {key}"));
            }
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?1, ?2) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                &[text(*key), text(json::to_string(value))],
            )?;
        }
        conn.exec("COMMIT")
    }

    pub fn query(&self, sql: &str, args: &[SqlValue]) -> Result<Vec<Row>, String> {
        self.conn.lock().unwrap().query(sql, args)
    }

    pub fn query_one(&self, sql: &str, args: &[SqlValue]) -> Result<Option<Row>, String> {
        Ok(self.query(sql, args)?.into_iter().next())
    }

    pub fn execute(&self, sql: &str, args: &[SqlValue]) -> Result<usize, String> {
        self.conn.lock().unwrap().execute(sql, args)
    }

    pub fn insert(&self, sql: &str, args: &[SqlValue]) -> Result<i64, String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(sql, args)?;
        Ok(conn.last_insert_rowid())
    }
}

pub fn uuid_hex() -> String {
    crate::encoding::hex(&rand::bytes(16))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> (std::path::PathBuf, Database) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "russdesk-db-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let db = Database::open(&dir.join("t.db")).unwrap();
        (dir, db)
    }

    #[test]
    fn schema_and_defaults() {
        let (dir, db) = tmp_db();
        assert_eq!(db.settings(), Settings::default());
        assert_eq!(db.meta("schema_version").as_deref(), Some("2"));
        assert!(db.meta("instance_id").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_typed_round_trip() {
        let (dir, db) = tmp_db();
        db.set_settings(&[
            ("id_server", json!("rd.example.com:21116")),
            ("console_session_hours", json!(24)),
            ("accept_recordings", json!(true)),
            ("default_strategy_id", json!(5)),
        ])
        .unwrap();
        let s = db.settings();
        assert_eq!(s.id_server, "rd.example.com:21116");
        assert_eq!(s.console_session_hours, 24);
        assert!(s.accept_recordings);
        assert_eq!(s.default_strategy_id, Some(5));
        assert!(db.set_settings(&[("bogus", json!(1))]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn core_tables_exist() {
        let (dir, db) = tmp_db();
        let n = db
            .query("SELECT count(*) AS c FROM sqlite_master WHERE type='table'", &[])
            .unwrap();
        assert!(n[0].get("c").unwrap().as_i64().unwrap() >= 20);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
