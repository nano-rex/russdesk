//! Application wiring: config, database, routing, static files, bootstrap and
//! maintenance. Port of app.py.

use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::db::{int, now, text, Database};
use crate::models::{new_guid, personal_book};
use crate::security::hash_password;
use crate::web::{error_response, json_response, Match, Request, Response, Router};
use crate::{admin_api, client_api, rest_api};

const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

// The viewer runs WebAssembly (libsodium) and opens WebSockets to the hbbs/hbbr
// ports on the server's host, which are not same-origin (app.py VIEWER_CSP).
const VIEWER_CSP: &str = "default-src 'self'; img-src 'self' data: blob:; style-src 'self'; \
script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' ws: wss:; frame-ancestors 'none'; \
base-uri 'none'";

pub struct App {
    pub cfg: Config,
    pub db: Arc<Database>,
    router: Router<App>,
}

impl App {
    pub fn new(cfg: Config) -> Self {
        let db = Database::open(&cfg.db_path()).expect("failed to open database");
        let mut router = Router::new();
        router.add("GET", "/api/health", |_app, _req, _p| {
            Ok(json_response(
                &json!({ "ok": true, "service": "russdesk" }),
                200,
            ))
        });
        client_api::register(&mut router);
        rest_api::register(&mut router);
        admin_api::register(&mut router);
        let app = App {
            cfg,
            db: Arc::new(db),
            router,
        };
        app.bootstrap_admin();
        app
    }

    fn bootstrap_admin(&self) {
        let exists = self
            .db
            .query_one("SELECT 1 AS n FROM users LIMIT 1", &[])
            .ok()
            .flatten()
            .is_some();
        if exists {
            return;
        }
        let generated = self.cfg.admin_password.is_empty();
        let password = if generated {
            crate::encoding::base64url_encode_nopad(&crate::rand::bytes(9))
        } else {
            self.cfg.admin_password.clone()
        };
        let id = self
            .db
            .insert(
                "INSERT INTO users(guid, name, password_hash, is_admin, status, created_at) \
                 VALUES (?1, ?2, ?3, 1, 1, ?4)",
                &[
                    text(new_guid()),
                    text(&self.cfg.admin_user),
                    text(hash_password(&password)),
                    int(now()),
                ],
            )
            .expect("failed to create admin");
        personal_book(&self.db, id);
        if generated {
            eprintln!(
                "Created administrator {:?} with password: {}",
                self.cfg.admin_user, password
            );
        } else {
            eprintln!(
                "Created administrator {:?} from RUSSDESK_ADMIN_PASSWORD",
                self.cfg.admin_user
            );
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
        match self.router.match_route(&req.method, &req.path) {
            Match::Found(handler, params) => {
                let mut resp = handler(self, req, &params).unwrap_or_else(|e| e.into());
                resp.headers
                    .push(("Cache-Control".into(), "no-store".into()));
                resp
            }
            Match::MethodNotAllowed => error_response(405, "Method not allowed"),
            Match::NotFound => error_response(404, "Not found"),
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
                .with_header("Content-Security-Policy", csp_for(&full))
                .with_header("X-Frame-Options", "DENY");
        }
        resp
    }

    /// Periodic cleanup (app.py maintenance).
    pub fn maintenance(&self) {
        let db = &self.db;
        let _ = db.execute(
            "DELETE FROM nonces WHERE created_at < ?1",
            &[int(now() - 600)],
        );
        let _ = db.execute("DELETE FROM tokens WHERE expires_at < ?1", &[int(now())]);
        let _ = db.execute(
            "DELETE FROM pending_disconnects WHERE created_at < ?1",
            &[int(now() - 300)],
        );
        let days = db.settings().log_retention_days;
        if days > 0 {
            let cutoff = now() - days * 86400;
            for (table, col) in [
                ("conn_logs", "started_at"),
                ("file_logs", "created_at"),
                ("alarm_logs", "created_at"),
                ("console_logs", "created_at"),
            ] {
                let _ = db.execute(
                    &format!("DELETE FROM {table} WHERE {col} < ?1"),
                    &[int(cutoff)],
                );
            }
        }
        let _ = db.execute(
            "UPDATE users SET invite_hash = '' WHERE status = -1 AND invite_expires < ?1",
            &[int(now())],
        );
        crate::auth::expire_pending();
    }
}

/// Which Content-Security-Policy applies to an HTML file. The viewer gets a
/// wider one (WebAssembly + WebSocket to the hbbs/hbbr ports), like app.py.
fn csp_for(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with("viewer.html") {
        VIEWER_CSP
    } else {
        CSP
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
        "wasm" => "application/wasm",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_html_gets_the_wider_csp() {
        assert_eq!(csp_for(Path::new("/srv/static/viewer.html")), VIEWER_CSP);
        assert!(VIEWER_CSP.contains("'wasm-unsafe-eval'"));
        assert!(VIEWER_CSP.contains("connect-src 'self' ws: wss:"));
    }

    #[test]
    fn other_html_gets_the_console_csp() {
        assert_eq!(csp_for(Path::new("/srv/static/index.html")), CSP);
        assert!(!CSP.contains("wasm-unsafe-eval"));
    }

    #[test]
    fn viewer_assets_have_the_right_content_types() {
        assert_eq!(
            content_type(Path::new("viewer.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("viewer.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("viewer.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("vendor/sodium.wasm")),
            "application/wasm"
        );
        assert_eq!(
            content_type(Path::new("vendor/sodium.js")),
            "application/javascript; charset=utf-8"
        );
    }
}
