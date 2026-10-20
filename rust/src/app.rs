//! Application wiring: config, database, request handling and static files.
//! Port of app.py's App (routing for the API modules lands per MIGRATION.md).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Config;
use crate::db::Database;
use crate::web::{error_response, json_response, Request, Response};

const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub struct App {
    pub cfg: Config,
    pub db: Arc<Database>,
}

impl App {
    pub fn new(cfg: Config) -> Self {
        let db = Database::open(&cfg.db_path()).expect("failed to open database");
        App {
            cfg,
            db: Arc::new(db),
        }
    }

    pub fn handle(&self, req: &Request) -> Response {
        if req.path.starts_with("/api/") {
            return self.route(req);
        }
        if req.method != "GET" && req.method != "HEAD" {
            return error_response(405, "Method not allowed");
        }
        self.static_file(&req.path)
    }

    fn route(&self, req: &Request) -> Response {
        // M1: only the health endpoint; the API routers are ported in M2+.
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/health") => {
                json_response(&serde_json::json!({ "ok": true, "service": "russdesk" }), 200)
            }
            _ => error_response(404, "Not found"),
        }
    }

    fn static_file(&self, path: &str) -> Response {
        let root = match std::fs::canonicalize(self.cfg.static_dir()) {
            Ok(r) => r,
            Err(_) => return error_response(500, "static directory missing"),
        };
        let rel = path.trim_start_matches('/');
        let rel = if rel.is_empty() { "index.html" } else { rel };

        let candidate = root.join(rel);
        let full = match std::fs::canonicalize(&candidate) {
            Ok(f) if f.starts_with(&root) && f.is_file() => f,
            // Single-page app: unknown paths get the shell.
            _ => root.join("index.html"),
        };

        let data = match std::fs::read(&full) {
            Ok(d) => d,
            Err(_) => return error_response(404, "Not found"),
        };
        let ctype = content_type(&full);
        let mut resp = Response::new(data, 200, &ctype).with_header("Cache-Control", "no-cache");
        if full.extension().and_then(|e| e.to_str()) == Some("html") {
            resp = resp
                .with_header("Content-Security-Policy", CSP)
                .with_header("X-Frame-Options", "DENY");
        }
        resp
    }
}

fn content_type(path: &Path) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let base = match ext {
        "html" => "text/html",
        "js" => "application/javascript",
        "css" => "text/css",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    if base.starts_with("text/") || base == "application/javascript" {
        format!("{base}; charset=utf-8")
    } else {
        base.to_string()
    }
}

/// Body limit per path, mirroring app.py (large for recordings).
pub fn body_limit(path: &str) -> usize {
    if path.starts_with("/api/record") {
        256 * 1024 * 1024
    } else {
        2 * 1024 * 1024
    }
}

/// The static directory as an absolute path (for logging/diagnostics).
pub fn static_dir_abs(cfg: &Config) -> PathBuf {
    std::fs::canonicalize(cfg.static_dir()).unwrap_or_else(|_| cfg.static_dir().to_path_buf())
}
