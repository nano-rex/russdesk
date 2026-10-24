//! RussDesk API server and web console — Rust rewrite.
//!
//! Rust server entry point. Every Python server module is ported (client and
//! token REST APIs, the admin console and the browser viewer's assets). See
//! MIGRATION.md.

#[macro_use]
mod json;
mod admin_api;
mod app;
mod auth;
mod authz;
mod client_api;
mod config;
mod crypto;
mod db;
mod encoding;
mod mail;
mod models;
mod rand;
mod rest_api;
mod security;
mod smtp;
mod sqlite;
mod strategy_options;
mod web;

use std::sync::Arc;

use app::{body_limit, App};
use config::Config;
use web::{Request, Response, ServerConfig};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = Config::from_env();
    let mut reset_user: Option<String> = None;
    let mut healthcheck = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" => {
                println!("russdesk {VERSION}");
                return;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            "--host" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    cfg.host = v.clone();
                }
            }
            "--port" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| s.parse().ok()) {
                    cfg.port = v;
                }
            }
            "--data-dir" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    cfg.data_dir = v.into();
                }
            }
            "--reset-password" => {
                i += 1;
                match args.get(i) {
                    Some(v) => reset_user = Some(v.clone()),
                    None => {
                        eprintln!("--reset-password needs a user name");
                        std::process::exit(2);
                    }
                }
            }
            "--healthcheck" => healthcheck = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if healthcheck {
        std::process::exit(if healthcheck_ok(cfg.port) { 0 } else { 1 });
    }
    if let Some(user) = reset_user {
        if let Err(e) = reset_password(&cfg, &user) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return;
    }

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let app = Arc::new(App::new(cfg));

    let server_cfg = ServerConfig {
        trust_proxy: app.cfg.trust_proxy,
        body_limit,
        common_headers: vec![
            ("X-Content-Type-Options".into(), "nosniff".into()),
            ("Referrer-Policy".into(), "no-referrer".into()),
        ],
    };

    // Periodic maintenance (expired tokens, log retention, pending logins).
    {
        let app = app.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(300));
            app.maintenance();
        });
    }

    let handler = {
        let app = app.clone();
        move |req: Request| -> Response { app.handle(&req) }
    };

    if let Err(e) = web::serve(&addr, server_cfg, handler) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "russdesk {VERSION} — RussDesk API server and web console\n\n\
         Usage: russdesk [--host ADDR] [--port N] [--data-dir DIR]\n\
         \x20      russdesk --reset-password USER   (new password on stdin)\n\
         \x20      russdesk --healthcheck          (exit 0 when the API answers)\n\n\
         Environment: RUSSDESK_HOST, RUSSDESK_PORT, RUSSDESK_DATA_DIR,\n\
         RUSSDESK_ID_SERVER, RUSSDESK_RELAY_SERVER, RUSSDESK_HBBS_KEY_FILE,\n\
         RUSSDESK_TRUST_PROXY, RUSSDESK_ADMIN_USER, RUSSDESK_ADMIN_PASSWORD,\n\
         RUSSDESK_STATIC_DIR"
    );
}

/// Set a user's password from stdin and turn its two-factor login off.
fn reset_password(cfg: &Config, user: &str) -> Result<(), String> {
    use std::io::Read;
    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .map_err(|e| format!("cannot read the new password: {e}"))?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.len() < 8 {
        return Err("Password must be at least 8 characters".into());
    }
    let db = db::Database::open(&cfg.db_path())?;
    let changed = db.execute(
        "UPDATE users SET password_hash = ?1, totp_secret = '', status = 1 WHERE name = ?2",
        &[db::text(security::hash_password(password)), db::text(user)],
    )?;
    if changed == 0 {
        return Err(format!("No user named {user}"));
    }
    db.execute(
        "DELETE FROM tokens WHERE user_id = (SELECT id FROM users WHERE name = ?1)",
        &[db::text(user)],
    )?;
    println!("Password reset for {user}; two-factor login was turned off.");
    Ok(())
}

/// GET /api/health on localhost; used by the Docker and systemd health checks.
fn healthcheck_ok(port: u16) -> bool {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    if stream
        .write_all(b"GET /api/health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut body = String::new();
    if stream.read_to_string(&mut body).is_err() {
        return false;
    }
    body.starts_with("HTTP/1.1 200") || body.starts_with("HTTP/1.0 200")
}
