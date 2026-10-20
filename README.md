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

## Works with the official RustDesk apps

No custom build is needed: the stock apps from rustdesk.com, the app stores and GitHub talk to
the official open-source `hbbs`/`hbbr` for connections, and to RussDesk for everything else.
Checked against the client source (rustdesk/rustdesk `master`, October 2026):

| | Windows | macOS | Linux | Android | iOS |
| --- | :-: | :-: | :-: | :-: | :-: |
| Remote control through your server (hbbs/hbbr) | ✓ | ✓ | ✓ | ✓ | ✓ controller only |
| Log in with a RussDesk account, address books, *Accessible devices* tab | ✓ | ✓ | ✓ | ✓ | ✓ |
| Listed under Devices (heartbeat, system info), online status | ✓ | ✓ | ✓ | ✓ | — |
| Connection, file-transfer and alarm logs for sessions *into* the device | ✓ | ✓ | ✓ | ✓ | — |
| Strategies (pushed settings) and remote **Disconnect** | ✓ | ✓ | ✓ | ✓ | — |
| Import settings by config string / QR code | ✓ | ✓ | ✓ | ✓ (QR) | ✓ |

iOS can't be controlled remotely (an Apple restriction that applies to RustDesk Pro too), so the
iOS client never reports itself as a device; it can log in, use address books and connect out,
and its outgoing sessions appear in the target device's connection log.

Plain `http://<server>:31114` works on phones too: the apps send API requests through their own
Rust HTTP stack, so Android's cleartext rule and iOS App Transport Security don't apply.

When RussDesk answers the client's system-info upload the client treats the server as "Pro".
That changes only two small things in the client: an admin can let a device hide its
connection window (option `allow-hide-cm`, permanent-password-only mode), and a Windows
connection-manager error popup is suppressed.

## Ports

RussDesk keeps RustDesk's port layout but moved to 3111X, so it can sit next to an
existing RustDesk server on the same machine:

| Port | | Service |
| --- | --- | --- |
| 31114 | TCP | RussDesk web console and API |
| 31115 | TCP | hbbs NAT type test |
| 31116 | TCP + UDP | hbbs ID/rendezvous (what clients enter as *ID server*) |
| 31117 | TCP | hbbr relay |
| 31118 | TCP | hbbs WebSocket |
| 31119 | TCP | hbbr WebSocket |

Clients must therefore include the port in the ID server field (`host:31116`); without it
they assume RustDesk's default 21116.

## Install on a bare-metal Linux server

Needs a systemd distribution (Debian/Ubuntu, RHEL/Rocky/Alma, Fedora, Arch…) with Python 3.10+.
Nothing else is installed: no Docker, pip packages or database server.

```sh
git clone https://github.com/nano-rex/russdesk.git
cd russdesk
sudo ./deploy/install.sh --host rd.example.com      # your public DNS name or IP
```

The script:

* downloads the official open-source `hbbs`/`hbbr` release for your CPU (x86-64, ARM64,
  ARMv7, i386) into `/usr/local/bin`
* installs RussDesk to `/opt/russdesk`
* creates a `rustdesk` system user and three systemd services: `rustdesk-hbbs`,
  `rustdesk-hbbr`, `russdesk` (sandboxed, restart on failure, start at boot)
* writes `/etc/russdesk.env` and opens the ports in ufw or firewalld if one is active
* prints the console address, the first admin password and the key for clients

| Path | |
| --- | --- |
| `/var/lib/rustdesk-server/` | hbbs data and the **server key** (`id_ed25519`, `id_ed25519.pub`). Back it up; losing it means re-keying every client. |
| `/var/lib/russdesk/russdesk.db` | Console database (users, devices, logs, address books). |
| `/etc/russdesk.env` | RussDesk settings (see the table under *Without Docker*). |

Day-to-day:

```sh
systemctl status russdesk rustdesk-hbbs rustdesk-hbbr
journalctl -u russdesk -u rustdesk-hbbs -u rustdesk-hbbr -f
git pull && sudo ./deploy/install.sh --host rd.example.com    # upgrade; data and password are kept
sudo ./deploy/install.sh --uninstall                           # remove services, keep data
```

Other options: `--admin-password PW`, `--rustdesk-version 1.1.16` (pin hbbs/hbbr),
`--skip-rustdesk` (hbbs/hbbr already installed; set `RUSSDESK_HBBS_KEY_FILE` in
`/etc/russdesk.env` to its `id_ed25519.pub`), `--no-firewall`.

If the server sits behind a cloud firewall or router, open TCP 31114–31119 and UDP 31116
there too.

## Quick start (Docker)

```sh
git clone https://github.com/nano-rex/russdesk.git
cd russdesk
RUSSDESK_HOST=rd.example.com docker compose up -d   # your public name or IP
docker compose logs russdesk | grep password        # first admin password
```

This starts `hbbs`, `hbbr` (the official open-source images) and RussDesk. Open
`http://<server>:31114`, sign in as `admin`, and change the password under **Account**.

Open TCP 31114–31119 and UDP 31116 on the firewall.

### Pointing clients at it

In RustDesk go to **Settings → Network → ID/Relay server** and enter:

* **ID server**: your server's address **with port 31116**, e.g. `rd.example.com:31116`
* **Key**: the content of `id_ed25519.pub` (also shown on the console dashboard)
* **Relay server**: leave empty (hbbs tells clients to use port 31117)
* **API server**: leave it **empty**

With the API server empty the client uses the ID server's port minus 2, here
`http://rd.example.com:31114`, which is where RussDesk listens. Or copy the config string
from the dashboard and use the clipboard-import button on that settings page.

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
| `RUSSDESK_PORT` | `31114` | Listen port. Keep it two below hbbs' port so clients find it without an API server setting. |
| `RUSSDESK_HOST` | `0.0.0.0` | Listen address. |
| `RUSSDESK_DATA_DIR` | `./data` | SQLite database (`russdesk.db`) and recordings. |
| `RUSSDESK_HBBS_KEY_FILE` | — | hbbs' `id_ed25519.pub`, shown to clients. |
| `RUSSDESK_ID_SERVER` / `RUSSDESK_RELAY_SERVER` | — | Addresses shown to clients when not set in the console's Settings. |
| `RUSSDESK_ADMIN_USER` / `RUSSDESK_ADMIN_PASSWORD` | `admin` / random | First admin, created only on an empty database. |
| `RUSSDESK_TRUST_PROXY` | off | Trust `X-Forwarded-For`/`-Proto` from a reverse proxy. |

Forgot the admin password:

```sh
echo 'new-password-here' | python3 -m russdesk --data-dir ./data --reset-password admin
```

## Behind a reverse proxy (HTTPS)

Proxy everything to `127.0.0.1:31114`, set `RUSSDESK_TRUST_PROXY=1`, set **Settings → API
server** to `https://your.host`, and give clients that API server. Console cookies get the
`Secure` flag when the proxy reports `X-Forwarded-Proto: https`.

## Security notes

* Device endpoints (`/api/heartbeat`, `/api/sysinfo`, `/api/audit/*`, `/api/record`) are
  unauthenticated, as in the client protocol. Anyone who can reach port 31114 can add
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
python3 tests/ui_test.py                         # browser test, needs Playwright + Chromium
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
