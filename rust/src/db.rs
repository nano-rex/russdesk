//! SQLite access: schema, settings and small query helpers. Port of db.py.
//!
//! The Rust rewrite uses a fresh database, so rather than replay db.py's v1->v2
//! migration path this emits the consolidated final schema directly.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::types::{Value, ValueRef};
use rusqlite::Connection;
use serde::Serialize;

/// A database row as a JSON object, mirroring Python's sqlite3.Row/dict usage.
pub type Row = serde_json::Map<String, serde_json::Value>;

/// Build a parameter list for the query helpers.
pub fn params(items: Vec<Value>) -> Vec<Value> {
    items
}

fn row_to_json(row: &rusqlite::Row, names: &[String]) -> Row {
    let mut map = serde_json::Map::new();
    for (i, name) in names.iter().enumerate() {
        let val = match row.get_ref(i).unwrap_or(ValueRef::Null) {
            ValueRef::Null => serde_json::Value::Null,
            ValueRef::Integer(n) => serde_json::Value::from(n),
            ValueRef::Real(f) => serde_json::Value::from(f),
            ValueRef::Text(t) => serde_json::Value::from(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(b) => serde_json::Value::from(String::from_utf8_lossy(b).into_owned()),
        };
        map.insert(name.clone(), val);
    }
    map
}

/// Seconds since the epoch, as stored in every timestamp column.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY, created_at INTEGER NOT NULL
);

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
#[derive(Clone, Debug, Serialize, PartialEq)]
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

/// The set of valid setting keys (db.py DEFAULT_SETTINGS keys).
pub const SETTING_KEYS: &[&str] = &[
    "id_server", "relay_server", "api_server", "server_key", "client_token_days",
    "console_session_hours", "log_retention_days", "accept_recordings", "recordings_max_mb",
    "max_peers_per_ab", "default_strategy_id", "only_admin_logs", "allow_non_admin_share",
    "disable_accessible_devices", "console_url", "smtp_host", "smtp_port", "smtp_security",
    "smtp_user", "smtp_password", "smtp_from",
];

impl Settings {
    fn apply(&mut self, key: &str, v: &serde_json::Value) {
        let s = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
        let i = |v: &serde_json::Value| v.as_i64().unwrap_or(0);
        let b = |v: &serde_json::Value| v.as_bool().unwrap_or(false);
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
}

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=30000;",
        )?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA)?;
        let has_meta: bool = conn
            .query_row("SELECT 1 FROM meta WHERE key = 'schema_version'", [], |_| Ok(true))
            .unwrap_or(false);
        if !has_meta {
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('schema_version', '2'), ('instance_id', ?1)",
                [uuid_hex()],
            )?;
        }
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .ok()
    }

    pub fn settings(&self) -> Settings {
        let mut s = Settings::default();
        let conn = self.conn.lock().unwrap();
        let mut stmt = match conn.prepare("SELECT key, value FROM settings") {
            Ok(st) => st,
            Err(_) => return s,
        };
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
            .unwrap_or_default();
        for (key, raw) in rows {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                s.apply(&key, &v);
            }
        }
        s
    }

    /// Store settings; each value is JSON-encoded like db.py. Unknown keys error.
    pub fn set_settings(&self, values: &[(&str, serde_json::Value)]) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        for (key, value) in values {
            if !SETTING_KEYS.contains(key) {
                return Err(rusqlite::Error::InvalidParameterName((*key).to_string()));
            }
            tx.execute(
                "INSERT INTO settings(key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value.to_string()],
            )?;
        }
        tx.commit()
    }

    /// Run a closure with the locked connection. The porting layer uses this
    /// for queries not yet wrapped in a typed helper.
    pub fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    /// All matching rows as JSON objects (db.py `all`).
    pub fn query(&self, sql: &str, args: &[Value]) -> rusqlite::Result<Vec<Row>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
        let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let rows = stmt
            .query_map(rusqlite::params_from_iter(args.iter()), |row| {
                Ok(row_to_json(row, &names))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// The first matching row as a JSON object, if any (db.py `one`).
    pub fn query_one(&self, sql: &str, args: &[Value]) -> rusqlite::Result<Option<Row>> {
        Ok(self.query(sql, args)?.into_iter().next())
    }

    /// Execute a statement, returning the number of affected rows (db.py `run`).
    pub fn execute(&self, sql: &str, args: &[Value]) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(sql, rusqlite::params_from_iter(args.iter()))
    }

    /// The id of the last inserted row after an INSERT via `execute`.
    pub fn insert(&self, sql: &str, args: &[Value]) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(sql, rusqlite::params_from_iter(args.iter()))?;
        Ok(conn.last_insert_rowid())
    }
}

/// Convenience constructors for SQL parameter values.
pub fn int(n: i64) -> Value {
    Value::Integer(n)
}
pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}
pub fn opt_int(n: Option<i64>) -> Value {
    n.map(Value::Integer).unwrap_or(Value::Null)
}

pub fn uuid_hex() -> String {
    let b = {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).expect("getrandom");
        buf
    };
    b.iter().map(|x| format!("{:02x}", x)).collect()
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
        let path = dir.join("t.db");
        let db = Database::open(&path).unwrap();
        (dir, db)
    }

    #[test]
    fn schema_and_defaults() {
        let (dir, db) = tmp_db();
        let s = db.settings();
        assert_eq!(s, Settings::default());
        assert_eq!(s.console_session_hours, 12);
        assert_eq!(s.smtp_security, "starttls");
        assert_eq!(db.meta("schema_version").as_deref(), Some("2"));
        assert!(db.meta("instance_id").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_typed_round_trip() {
        let (dir, db) = tmp_db();
        db.set_settings(&[
            ("id_server", serde_json::json!("rd.example.com:21116")),
            ("console_session_hours", serde_json::json!(24)),
            ("accept_recordings", serde_json::json!(true)),
            ("default_strategy_id", serde_json::json!(5)),
        ])
        .unwrap();
        let s = db.settings();
        assert_eq!(s.id_server, "rd.example.com:21116");
        assert_eq!(s.console_session_hours, 24);
        assert!(s.accept_recordings);
        assert_eq!(s.default_strategy_id, Some(5));
        assert!(db.set_settings(&[("bogus", serde_json::json!(1))]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn core_tables_exist() {
        let (dir, db) = tmp_db();
        let count: i64 = db
            .with_conn(|c| {
                c.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(count >= 20, "expected the full schema, got {count} tables");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
