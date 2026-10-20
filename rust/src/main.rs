//! RussDesk API server and web console — Rust rewrite.
//!
//! Milestone 1: configuration, the HTTP/web layer, SQLite foundation, security
//! primitives, and a running server (health endpoint + static console shell).
//! The API routers (client/admin/rest), models and the viewer are ported in
//! later milestones; see MIGRATION.md.

mod app;
mod auth;
mod authz;
mod config;
mod db;
mod mail;
mod models;
mod security;
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
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
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
         Usage: russdesk [--host ADDR] [--port N] [--data-dir DIR]\n\n\
         Environment: RUSSDESK_HOST, RUSSDESK_PORT, RUSSDESK_DATA_DIR,\n\
         RUSSDESK_ID_SERVER, RUSSDESK_RELAY_SERVER, RUSSDESK_HBBS_KEY_FILE,\n\
         RUSSDESK_TRUST_PROXY, RUSSDESK_ADMIN_USER, RUSSDESK_ADMIN_PASSWORD,\n\
         RUSSDESK_STATIC_DIR"
    );
}
