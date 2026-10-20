//! SQLite access. Port of db.py's foundation (connection, pragmas, epoch clock
//! and the settings key/value store). The full schema and model helpers are
//! ported in a later milestone (see MIGRATION.md).

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

/// Seconds since the epoch, as stored in every timestamp column.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
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
             PRAGMA busy_timeout=5000;",
        )?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Minimal M1 schema. The full console schema lands in M2.
    fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
             );",
        )
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        )
        .ok()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    /// Run a closure with the locked connection, for code not yet wrapped in a
    /// typed helper during the port.
    pub fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip() {
        let dir = std::env::temp_dir().join(format!("russdesk-db-{}", std::process::id()));
        let path = dir.join("t.db");
        let db = Database::open(&path).unwrap();
        assert_eq!(db.get_setting("id_server"), None);
        db.set_setting("id_server", "rd.example.com:21116").unwrap();
        assert_eq!(db.get_setting("id_server").as_deref(), Some("rd.example.com:21116"));
        db.set_setting("id_server", "other:21116").unwrap();
        assert_eq!(db.get_setting("id_server").as_deref(), Some("other:21116"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn now_is_reasonable() {
        assert!(now() > 1_700_000_000);
    }
}
