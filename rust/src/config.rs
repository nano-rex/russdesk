//! Runtime configuration, read once from environment variables. Port of config.py.

use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub host: String,
    pub port: u16,
    /// Path to hbbs' public key (id_ed25519.pub), shown in the console.
    pub hbbs_key_file: String,
    /// Defaults for the addresses shown to clients; console settings win.
    pub id_server: String,
    pub relay_server: String,
    /// Trust X-Forwarded-For / X-Forwarded-Proto from a reverse proxy.
    pub trust_proxy: bool,
    /// Initial admin account, created only when the user table is empty.
    pub admin_user: String,
    pub admin_password: String,
    pub static_dir: PathBuf,
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => matches!(
            v.trim().to_lowercase().as_str(),
            "1" | "y" | "yes" | "true" | "on"
        ),
        _ => default,
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Default for Config {
    fn default() -> Self {
        Config {
            data_dir: PathBuf::from("./data"),
            host: "0.0.0.0".to_string(),
            port: 31114,
            hbbs_key_file: String::new(),
            id_server: String::new(),
            relay_server: String::new(),
            trust_proxy: false,
            admin_user: "admin".to_string(),
            admin_password: String::new(),
            static_dir: default_static_dir(),
        }
    }
}

fn default_static_dir() -> PathBuf {
    // static/ next to the crate at build time; overridable via RUSSDESK_STATIC_DIR.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
}

impl Config {
    pub fn from_env() -> Self {
        let d = Config::default();
        let mut cfg = Config {
            data_dir: PathBuf::from(env_or("RUSSDESK_DATA_DIR", &d.data_dir.to_string_lossy())),
            host: env_or("RUSSDESK_HOST", &d.host),
            port: env_or("RUSSDESK_PORT", &d.port.to_string())
                .parse()
                .unwrap_or(d.port),
            hbbs_key_file: env_or("RUSSDESK_HBBS_KEY_FILE", &d.hbbs_key_file),
            id_server: env_or("RUSSDESK_ID_SERVER", &d.id_server),
            relay_server: env_or("RUSSDESK_RELAY_SERVER", &d.relay_server),
            trust_proxy: env_bool("RUSSDESK_TRUST_PROXY", d.trust_proxy),
            admin_user: env_or("RUSSDESK_ADMIN_USER", &d.admin_user),
            admin_password: env_or("RUSSDESK_ADMIN_PASSWORD", &d.admin_password),
            static_dir: d.static_dir,
        };
        if let Ok(s) = std::env::var("RUSSDESK_STATIC_DIR") {
            if !s.is_empty() {
                cfg.static_dir = PathBuf::from(s);
            }
        }
        cfg
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("russdesk.db")
    }

    pub fn recordings_dir(&self) -> PathBuf {
        self.data_dir.join("recordings")
    }

    pub fn static_dir(&self) -> &Path {
        &self.static_dir
    }
}
