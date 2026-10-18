# RussDesk

An open-source web console and API server for self-hosted [RustDesk](https://github.com/rustdesk/rustdesk),
covering the main features of RustDesk Server Pro's console. It runs next to the free
`hbbs`/`hbbr` servers and speaks the HTTP API the stock RustDesk client already uses, so
you don't need a custom client.

RussDesk is an independent project. It is not affiliated with or endorsed by the RustDesk
project, and it contains no code from RustDesk Server Pro. The client protocol was
worked out from the open-source client; see [docs/client-protocol.md](docs/client-protocol.md).

## What you get

| | |
| --- | --- |
| **Devices** | Every client that checks in: online status, hostname, OS user, platform, version, CPU/RAM, IP, user, group, note. Search, filters, bulk assign/delete. |
| **Live sessions** | Who is connected to what right now, with a **Disconnect** button. |
| **Users and login** | Accounts for logging in from the RustDesk client, admin and normal roles, disable, sign-out everywhere, TOTP two-factor login (console and client). |
| **Groups** | User groups and device groups. Members of a group see each other's devices in the client's *Accessible devices* tab; grant extra groups per group. |
| **Address books** | A personal book per user plus shared books with read / read-write / full-control rules per user or group, used directly by the client's Address Book tab. Legacy single-book clients also work. |
| **Strategies** | Push client settings (permissions, approve mode, password type, whitelists, recording, network…) to devices, by device, user, device group, or as the default. Changes reach devices within ~15 s. |
| **Audit logs** | Connection log (who, from where, type, auth method, duration), file transfer log, security alarms, and a log of console actions. Filters and CSV export. |
| **Recordings** | Optional upload of session recordings from clients (off by default). |
| **Custom client presets** | `preset-user-name`, `preset-device-group-name`, `preset-strategy-name`, `preset-address-book-*`, `preset-note` are honoured on first check-in. |
| **Client setup** | ID server, key and a one-click config string / QR code for clients. |

Not included: OIDC/LDAP login, email verification codes, the web client, the custom client
generator, and the Pro relay/ID server features (those live in Pro's `hbbs`, not in the console).

## Quick start (Docker)

```sh
git clone https://github.com/nano-rex/russdesk.git
cd russdesk
docker compose up -d
docker compose logs russdesk | grep password   # first admin password
```

This starts `hbbs`, `hbbr` (the official open-source images) and RussDesk. Open
`http://<server>:21114`, sign in as `admin`, and change the password under **Account**.

Open TCP 21114–21119 and UDP 21116 on the firewall, as for a normal RustDesk server.

### Pointing clients at it

In RustDesk go to **Settings → Network → ID/Relay server** and enter:

* **ID server**: your server's address
* **Key**: the content of `hbbs-data/id_ed25519.pub` (also shown on the console dashboard)
* **API server**: leave it **empty**

With the API server empty the client uses `http://<ID server>:21114` by itself, which is
where RussDesk listens. Or copy the config string from the dashboard and use the
clipboard-import button on that settings page.

Then **log in** from the client's account menu with a RussDesk user. Devices also show up
without anyone logging in, as soon as they send a heartbeat.

Fill in the API server only if RussDesk sits behind HTTPS or on another host or port, for
example `https://rd.example.com`, and set the same address under **Settings → API server**
so the config string includes it.

### Logins don't expire

A client stays logged in until the user logs out, an admin disables the account, or an admin
uses **Sign out everywhere**. To force re-login after some time instead, set
**Settings → Client login lifetime** to a number of days. Console sessions last 12 hours
by default. The hbbs key never expires; it only changes if you delete
`hbbs-data/id_ed25519*`.

## Without Docker

Python 3.10+ with nothing else to install:

```sh
RUSSDESK_HBBS_KEY_FILE=/path/to/id_ed25519.pub python3 -m russdesk --data-dir ./data
```

| Variable | Default | |
| --- | --- | --- |
| `RUSSDESK_PORT` | `21114` | Listen port. Keep 21114 so clients find it without an API server setting. |
| `RUSSDESK_HOST` | `0.0.0.0` | Listen address. |
| `RUSSDESK_DATA_DIR` | `./data` | SQLite database (`russdesk.db`) and recordings. |
| `RUSSDESK_HBBS_KEY_FILE` | — | hbbs' `id_ed25519.pub`, shown to clients. |
| `RUSSDESK_ADMIN_USER` / `RUSSDESK_ADMIN_PASSWORD` | `admin` / random | First admin, created only on an empty database. |
| `RUSSDESK_TRUST_PROXY` | off | Trust `X-Forwarded-For`/`-Proto` from a reverse proxy. |

Forgot the admin password:

```sh
echo 'new-password-here' | python3 -m russdesk --data-dir ./data --reset-password admin
```

## Behind a reverse proxy (HTTPS)

Proxy everything to `127.0.0.1:21114`, set `RUSSDESK_TRUST_PROXY=1`, set **Settings → API
server** to `https://your.host`, and give clients that API server. Console cookies get the
`Secure` flag when the proxy reports `X-Forwarded-Proto: https`.

## Security notes

* Device endpoints (`/api/heartbeat`, `/api/sysinfo`, `/api/audit/*`, `/api/record`) are
  unauthenticated, as in the client protocol. Anyone who can reach port 21114 can add
  device entries or log lines. Restrict the port to your clients' networks if that matters.
* Passwords are hashed with scrypt; tokens are stored as SHA-256 hashes; logins are
  rate-limited per IP and per username.
* The console uses an HttpOnly, SameSite=Strict cookie plus a custom header on every
  change, and a strict Content-Security-Policy.
* Shared address books store connection passwords in the database as plain text (the client
  needs them back). Protect the data directory.

## How strategies apply

A device uses the first strategy found in this order: its own, its user's, its device group's,
the default. On each heartbeat the client reports the strategy stamp it has; when it differs,
RussDesk sends the full option set. Options a previous strategy set but the new one doesn't
are sent empty, which returns them to the client's default.

## Development

```sh
python3 -m unittest discover -s tests            # API tests (no dependencies)
python3 tests/test_ui.py                         # browser test, needs Playwright + Chromium
```

The tests replay the request shapes of the RustDesk client. No real RustDesk client was
used during development. If a client release changes a payload, check
`docs/client-protocol.md` against the client source.

Layout: `russdesk/client_api.py` (what clients call), `russdesk/admin_api.py` (console API),
`russdesk/models.py` (access rules, strategies, address books), `russdesk/static/` (the
console: plain HTML/CSS/JS, no build step).

## License

AGPL-3.0, the same licence as RustDesk's open-source server. Bundled:
[qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 (MIT).
