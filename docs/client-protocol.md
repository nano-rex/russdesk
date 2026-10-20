# RustDesk client ↔ API server protocol

RussDesk implements the HTTP API that the open-source RustDesk client calls
when an "API server" is configured. Everything here was read from the client
source (rustdesk/rustdesk `master`, October 2026). If a client update changes
these calls, this file and `russdesk/client_api.py` need re-checking.

| Client source | What it calls |
| --- | --- |
| `src/common.rs` `get_api_server` | API base URL: the `api-server` option, else `http://<custom-rendezvous-server host>:21114` (ID port − 2). Disabled for `*.rustdesk.com`. |
| `src/hbbs_http/sync.rs` | `POST /api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver` |
| `src/server/connection.rs` | `POST /api/audit/conn`, `/api/audit/file`, `/api/audit/alarm` |
| `src/hbbs_http/record_upload.rs` | `POST /api/record?type=new|part|tail|remove&file=…` |
| `flutter/lib/models/user_model.dart` | `POST /api/login`, `/api/currentUser`, `/api/logout`, `GET /api/login-options` |
| `flutter/lib/models/group_model.dart` | `GET /api/users`, `/api/peers`, `/api/device-group/accessible` |
| `flutter/lib/models/ab_model.dart` | `/api/ab/*` (shared address books) and legacy `GET/POST /api/ab` |

## No API server setting needed

If the client's API server field is empty it derives `http://<ID server
host>:<ID port − 2>`, or port 21114 when the ID server has no port. RussDesk
runs hbbs on 31116 and itself on 31114, so clients only need the ID server
(`host:31116`) and key. Set an explicit API server only
for HTTPS (reverse proxy) or another host/port. `https://…:21114` is rewritten
by the client to `https://…` unless the `allow-https-21114` option is set.

## Device sync (no authentication)

* **Heartbeat** every 15 s when idle, every 3 s while a session is open:
  `{"id", "uuid", "ver", "conns": [conn ids], "modified_at"}`.
  Response keys the client acts on:
  * `"sysinfo"` present → re-upload system info.
  * `"disconnect": [conn ids]` → close those sessions.
  * `"modified_at"` → stored and echoed back next time.
  * `"strategy": {"config_options": {key: value}}` → written into the client's
    options; an empty value removes the option (back to the default).
* **Sysinfo**: `{"cpu", "memory", "os", "hostname", "username", "version", "id",
  "uuid", preset-*}`. Reply with the text `SYSINFO_UPDATED`; `ID_NOT_FOUND`
  makes the client retry next heartbeat.
* **sysinfo_ver**: empty POST, reply with any text; the client skips the upload
  when the text and its cached sysinfo hash are unchanged. RussDesk returns its
  database instance id, so a fresh database gets everything re-uploaded.

## Audit

Success is HTTP 200 with an **empty body**; the client retries 5xx, 408, 429
and 200 bodies containing `{"error": …}`. Each record carries a `nonce` for
de-duplication of retries (kept 10 minutes).

* `conn`: `{"action": "new", "ip"}` when a peer connects;
  `{"peer": [id, name], "type", "primary_auth", "two_factor"}` once authorized
  (type 0 remote, 1 file transfer, 2 port forward, 3 camera, 4 terminal);
  `{"action": "close"}` at the end. All carry `id`, `uuid`, `conn_id`,
  `session_id`.
* `file`: `{"peer_id", "conn_id", "type" (0 send, 1 receive), "path", "is_file",
  "info": "<json string with ip, name, num, files>"}`.
* `alarm`: `{"typ", "info": "<json string>", "conn_id"}`; types 0 IP whitelist,
  1 >30 attempts, 2 6 attempts/min, 6 IPv6 prefix, 7–8 terminal login,
  9 scope violation, 10 ID whitelist.

## Accounts

* `POST /api/login` (body sent as JSON without a Content-Type):
  `{"username", "password", "id", "uuid", "autoLogin", "type": "account",
  "deviceInfo": {"os", "type", "name"}}` →
  `{"access_token", "type": "access_token", "user": {"name", "display_name",
  "email", "note", "status", "is_admin"}}` or `{"error"}`.
* Two-factor: reply `{"type": "email_check", "tfa_type": "tfa_check",
  "secret", "user"}`; the client then posts `{"type": "email_code",
  "verificationCode", "tfaCode", "secret", "username", …}`.
* Authenticated calls send `Authorization: Bearer <token>`; HTTP 401 makes the
  client forget the login.

## Address books

`POST /api/ab/personal` → `{"guid"}` switches the client to the shared
address-book API (a 404 keeps it on the legacy single book).
`POST /api/ab/shared/profiles` → `{"total", "data": [{"guid", "name", "owner",
"note", "rule"}]}` with rule 1 read, 2 read/write, 3 full control. Peers and
tags: `POST /api/ab/peers?ab=<guid>`, `POST /api/ab/tags/<guid>`,
`POST /api/ab/peer/add/<guid>`, `PUT /api/ab/peer/update/<guid>`,
`DELETE /api/ab/peer/<guid>` (body: ID list), `POST /api/ab/tag/add/<guid>`,
`PUT /api/ab/tag/rename/<guid>`, `PUT /api/ab/tag/update/<guid>`,
`DELETE /api/ab/tag/<guid>`. Personal books store the password `hash`;
shared books store a plain `password` for members.

List endpoints page with `current` and `pageSize` and return
`{"total", "data"}`.

## Config string

Settings → Network → import from clipboard accepts
`reverse(base64url(json({"host", "relay", "api", "key"})))`
(`ServerConfig.encode` in `flutter/lib/common.dart`).
