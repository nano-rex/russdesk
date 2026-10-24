# Python → Rust rewrite

The RussDesk server was rewritten from Python into Rust to match the client's
language. The rewrite lives in `rust/` and is the only server: the Python
package, tests and tooling are gone, and the installer, Dockerfile and systemd
unit run the `russdesk` binary. The table below maps the old modules to their
Rust replacements and records the parity work.

**Zero third-party crates.** Per project policy the Rust server uses the
standard library only. SQLite is the official single-file amalgamation vendored
under `vendor/sqlite` and compiled by `build.rs` with the system C compiler;
everything else is implemented and reviewable in-tree:

| Concern | In-house module |
| --- | --- |
| JSON value/parser/serializer + `json!` | `src/json.rs` |
| SHA-1, SHA-256, HMAC, PBKDF2, scrypt, constant-time eq | `src/crypto.rs` |
| base64 / base32 / hex | `src/encoding.rs` |
| OS randomness (`/dev/urandom`) | `src/rand.rs` |
| SQLite FFI over the vendored amalgamation | `src/sqlite.rs` + `build.rs` |
| Plaintext SMTP (TLS via a local relay) | `src/smtp.rs` |
| Threaded HTTP/1.1 server + router | `src/web.rs` |

## Status

| Python module | Lines | Rust | State |
| --- | --- | --- | --- |
| `config.py` | 54 | `src/config.rs` | ✅ ported |
| `web.py` | 179 | `src/web.rs` | ✅ ported (threaded server, router, request/response) |
| `security.py` | 143 | `src/security.rs` | ✅ ported (scrypt hash format kept, TOTP, rate limiter, backup codes) |
| `db.py` | 475 | `src/db.rs` | ✅ ported (schema, typed settings, JSON-row helpers over the FFI) |
| `models.py` | 515 | `src/models.rs` | ✅ ported |
| `authz.py` | 210 | `src/authz.rs` | ✅ ported |
| `mail.py` | 40 | `src/mail.rs` | ✅ ported (own SMTP client) |
| `strategy_options.py` | 85 | `src/strategy_options.rs` | ✅ ported |
| `auth.py` | 144 | `src/auth.rs` | ✅ ported |
| `app.py` | 150 | `src/app.rs` | ✅ ported (routing, bootstrap, static, maintenance) |
| `__main__.py` | 55 | `src/main.rs` | ✅ ported |
| `client_api.py` | 976 | `src/client_api.rs` | ✅ ported (all 33 client/ab/record endpoints) |
| `rest_api.py` | 725 | `src/rest_api.rs` | ✅ ported (token REST management API) |
| `admin_api.py` | 1913 | `src/admin_api.rs` | ✅ ported (all 84 console routes) |
| `static/*` | — | `static/*` | ✅ ported (console + browser viewer, served with the viewer's wider CSP) |

## Cutover

- `russdesk --reset-password USER` reads the new password from stdin, clears
  the user's 2FA secret and signs its tokens out (the old `python -m russdesk
  --reset-password` behavior).
- `russdesk --healthcheck` asks `GET /api/health` on the configured port; the
  Docker `HEALTHCHECK` and the installer's post-start check use it.
- The static folder defaults to `static/` next to the executable, then the
  crate's `static/` at build time; `RUSSDESK_STATIC_DIR` overrides it.
- `.github/workflows/release.yml` builds Linux x86-64/ARM64 archives
  (`russdesk` + `static/`) that `russdesk.sh` downloads when it is not run
  from a checkout.

## Milestones

- **M1 (done):** foundation — config, HTTP/web layer, security primitives,
  SQLite open + settings, running server.
- **M2 (done):** full DB schema + typed settings, models, authz, mail,
  strategy_options.
- **M3 (done):** auth — login, rate limiting, login alarms, 2FA challenges.
- **M3.5 (done):** removed all third-party crates — in-house JSON, crypto,
  encodings, RNG, SQLite FFI and SMTP; the crate now builds with std only.
- **M4 (done):** `client_api` and `rest_api` ported (login/heartbeat/sysinfo/audit/
  accessible lists/address books/recordings and token REST management endpoints), verified by the Rust test suite.
- **M5 (done):** `admin_api` — the console: users, device extras, groups,
  strategies, address books, logs/CSV, admin roles, API tokens, recordings,
  settings, client-config, lookup, invitations and own-account/2FA (84 routes).
- **M6 (done):** the browser viewer — `viewer.html/css/js`, `viewer-boot.js` and
  the vendored libsodium are served next to the console, `/viewer-info` supplies
  the connection parameters, and the console offers *Connect in browser*.
  The viewer itself runs in the browser (WebSocket + WebCodecs), so the same
  assets serve the console and the viewer.

## Build & run

```sh
cd rust
cargo test                 # 54 tests, std only
cargo run --release -- --host 127.0.0.1 --port 31114
```

Use `--release`: the pure-Rust scrypt is intentionally expensive, so debug
builds are slow to hash passwords.
