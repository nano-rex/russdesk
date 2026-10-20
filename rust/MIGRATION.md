# Python → Rust rewrite

The RussDesk server is being rewritten from Python into Rust to match the
client's language. The rewrite lives here in `rust/` and is landed in compiling,
tested milestones. The Python server at the repo root stays the working server
until the Rust port reaches feature + test parity, so `main` is always
deployable and testable (including on the VPS) during the migration.

Stack: std-only threaded HTTP (mirroring the Python `ThreadingHTTPServer`
design) + `rusqlite` (bundled SQLite) + RustCrypto (`scrypt`, `sha2`, `sha1`,
`hmac`) + `serde_json`. No async runtime, few dependencies — the same "lean,
no framework" spirit as the Python version. The viewer milestone will reuse the
vendored `hbb_common` crate for the RustDesk peer protocol.

## Status

| Python module | Lines | Rust | State |
| --- | --- | --- | --- |
| `config.py` | 54 | `src/config.rs` | ✅ ported |
| `web.py` | 179 | `src/web.rs` | ✅ ported (server, router, request/response) |
| `security.py` | 143 | `src/security.rs` | ✅ ported (scrypt hash format kept, TOTP, rate limiter, backup codes) |
| `app.py` | 150 | `src/app.rs` | ◻ partial (static files, health; API routing stubbed) |
| `__main__.py` | 55 | `src/main.rs` | ◻ partial (serve, args; `--reset-password` pending DB) |
| `db.py` | 475 | `src/db.rs` | ◻ foundation only (connection, pragmas, `now`, settings kv) |
| `models.py` | 515 | — | ⬜ M2 |
| `authz.py` | 210 | — | ⬜ M2 |
| `mail.py` | 40 | — | ⬜ M2 |
| `strategy_options.py` | 85 | — | ⬜ M2 |
| `auth.py` | 144 | — | ⬜ M3 |
| `client_api.py` | 976 | — | ⬜ M4 (the client-facing HTTP API) |
| `rest_api.py` | 725 | — | ⬜ M4 |
| `admin_api.py` | 1913 | — | ⬜ M5 (the console API) |
| `tools/rdproto.py` | — | — | ⬜ M6 (browser viewer, reusing `hbb_common`) |

## Milestones

- **M1 (done):** foundation — config, HTTP/web layer, security primitives,
  SQLite open + settings, a running server (health + static console shell).
  `cargo test` green; server verified serving `/api/health` and the SPA shell.
- **M2:** full DB schema + `models.rs`, `authz`, `mail`, `strategy_options`.
- **M3:** `auth` (login, 2FA challenges, login alarms).
- **M4:** `client_api` + `rest_api`, run the Pro management scripts against them.
- **M5:** `admin_api` (the console) — the largest module.
- **M6:** the browser viewer (peer protocol via `hbb_common`).

Parity is tracked against the existing Python test suite (`tests/`): each
milestone ports the relevant tests to Rust (`cargo test`) and/or keeps the
Python integration tests passing against the equivalent endpoints. The Python
tree is removed only once M1–M5 reach parity.

## Build & run

```sh
cd rust
cargo test
cargo run -- --host 127.0.0.1 --port 31114
```

The static console assets in `rust/static/` are the same SPA as the Python
server's and are shared between the two during the migration.
