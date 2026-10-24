# RussDesk

An open-source web console and API server for self-hosted [RustDesk](https://github.com/rustdesk/rustdesk),
covering the main features of RustDesk Server Pro's console. It runs next to the free
`hbbs`/`hbbr` servers and speaks the HTTP API the stock RustDesk client already uses, so
you don't need a custom client.

RussDesk is an independent project. It is not affiliated with or endorsed by the RustDesk
project, and it contains no code from RustDesk Server Pro. The client protocol was
worked out from the open-source client; see [docs/client-protocol.md](docs/client-protocol.md).

## What you get

Modelled on RustDesk Server Pro's web console (pages, permissions, and behaviour from its
public documentation):

| | |
| --- | --- |
| **Devices** | Online status, device name, OS user, platform, version, user, user group, device group, strategy, IP, note. Filters (status, groups, offline days), batch actions, edit name/username/note, **enable / disable** (disabled devices refuse all incoming connections), delete (disabled devices only, as in Pro). |
| **Users** | Create or **invite by email**, display name, email, note, user group, strategy, enable/disable, delete (disabled only), force logout, **assign devices**, reset 2FA, **enforce 2FA**, email login verification. |
| **Groups** | User groups with *Can access to* / *Can be accessed from* (user groups, device groups, individual users) and member lists; device groups with access rules, members and a strategy. |
| **Admin roles** | Delegate parts of the console with Pro's permission set: *global*, *group scoped* (selected user groups, device groups, unassigned devices) or *individual*. |
| **Strategies** | Push client settings. Enable/disable, duplicate, Edit Devices / Users / Device Groups, devices actually applied. Priority device > user > device group, as in Pro. |
| **Address books** | My address book and shared books; share with users, groups or **everyone** (read-only / read-write / full control; user beats group beats everyone); default shared password; tags with *Untagged* and *Filter by intersection*; **import** from the device list; **recycle bin**. |
| **Logs** | Connection (type incl. *Not Logged In*, controlled device, controlling user/device/IP, start/end/duration, authentication, editable **note**, **Disconnect**), File, Alarm (incl. login-account alarms), Console; filters and CSV export (1000 rows, following the filters). Normal users see their own logs unless *Only admin can access logs* is on. |
| **Security** | TOTP 2FA with **6 backup codes**, email login codes, login rate limits and alarms, console audit trail. |
| **Settings** | Server addresses and key, config string / QR / **Windows EXE name**, **SMTP** (with test mail), **API tokens**, Others (log retention, sharing policy, *Disable retrieving accessible devices*, login lifetime, recordings). |
| **Automation** | `rustdesk --assign --token …` works, and RustDesk Server Pro's own scripts (`users.py`, `devices.py`, `user-groups.py`, `device-groups.py`, `strategies.py`, `ab.py`, `audits.py` from the RustDesk repo) run unmodified against RussDesk. The Rust tests replay their request shapes. |
| **Custom client presets** | `preset-user-name`, `preset-device-group-name`, `preset-strategy-name`, `preset-address-book-*`, `preset-note` are honoured on first check-in. |
| **Custom client build** | The RustDesk client is vendored under `client/vendor`; a script and a GitHub Actions workflow bake your ID server, relay server and key in at compile time, producing an `.exe` / `.apk` that connects to your server with no manual setup. See [docs/custom-client.md](docs/custom-client.md). |

### Not available, and why

* **Control roles** (what an operator may do inside a session): the client receives these
  in rendezvous messages from Pro's closed-source hbbs, which the open-source hbbs and any
  web console cannot send.
* **Device disabling is approximated**: Pro's hbbs refuses connections to a disabled
  device; RussDesk pushes an IP whitelist that matches nothing, so the device itself
  refuses them. A user with access to the device's settings could undo that locally.
* **web client**, **OIDC/LDAP**, licences and multiple relay servers with geo settings
  (those belong to Pro's hbbs/hbbr or RustDesk's build service). A **custom client
  generator** is now included — see *Custom client build* above.

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

## Install on a Linux server (one script)

Needs a systemd distribution (Debian/Ubuntu, RHEL/Rocky/Alma, Fedora, Arch, openSUSE…). No
Docker, no clone, nothing else to set up:

```sh
curl -fsSL https://raw.githubusercontent.com/nano-rex/russdesk/main/russdesk.sh | sudo sh
```

It detects the server's public address (or asks), installs and starts everything, opens the
ports in ufw or firewalld, and prints the console address, the first admin password and the key
for clients. The same script manages it afterwards:

| Command | |
| --- | --- |
| `sudo sh russdesk.sh` | Install, or **upgrade** an existing install (data, key and settings are kept) |
| `sudo sh russdesk.sh status` | Services, client settings, key |
| `sudo sh russdesk.sh reset-password [USER]` | New console password (also turns off that user's 2FA) |
| `sudo sh russdesk.sh uninstall` | Remove RussDesk, keep its data and key for a later reinstall |
| `sudo sh russdesk.sh uninstall --purge` | Remove everything RussDesk created, including data and key |

Get the script with `curl -fsSLO https://raw.githubusercontent.com/nano-rex/russdesk/main/russdesk.sh`
to run the other commands. Install options: `--host ADDR` (skip detection), `--lan CIDR|off`,
`--admin-password PW`, `--rustdesk-version V`, `--ref BRANCH_OR_TAG`, `--no-firewall`, `--yes`.

What it installs:

* the official open-source `hbbs`/`hbbr` release for your CPU (x86-64, ARM64, ARMv7, i386)
  in `/usr/local/lib/russdesk/bin`, and the RussDesk server in `/opt/russdesk`
* a `russdesk` system user and three sandboxed systemd services, started at boot:
  `russdesk` (31114), `russdesk-hbbs` (31115/31116/31118), `russdesk-hbbr` (31117/31119)

RussDesk is a Rust program with no runtime dependencies. The installer uses a checkout it is
run from (built with `cargo`) or downloads the matching release binary; Python is not needed.

All names, paths and ports are RussDesk's own, so it can run on the same machine as RustDesk
Server Pro or the official `rustdesk-server` packages without touching them; uninstalling never
touches them either.

| Path | |
| --- | --- |
| `/var/lib/russdesk-hbbs/` | hbbs data and the **server key** (`id_ed25519`, `id_ed25519.pub`). Back it up; losing it means re-keying every client. |
| `/var/lib/russdesk/russdesk.db` | Console database (users, devices, logs, address books). |
| `/etc/russdesk.env` | RussDesk settings (see the table under *Without Docker*). |

**Servers behind a router (LAN mode).** When the machine has a private address and clients reach
it through a public one, the script sets up hbbs so devices on the same LAN get the relay's LAN
address (many routers don't loop public traffic back into the LAN). Devices on that LAN should
use the LAN address as ID server (`status` shows both). Forward TCP 31114–31119 and UDP 31116 on
the router to the server.

If a cloud firewall sits in front of the server, open TCP 31114–31119 and UDP 31116 there too.

## Checking a server from a terminal

The API is plain HTTP, so `curl` is enough:

```sh
curl -s http://rd.example.com:31114/api/login-options          # console settings for clients
curl -s -X POST -d '{"id":"1","uuid":"u","modified_at":0}' \
     http://rd.example.com:31114/api/heartbeat                 # what a device sends
curl -s -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…"}' \
     http://rd.example.com:31114/api/admin/login                # console session
```

`russdesk --healthcheck` exits 0 when a local server answers, which is what the Docker and
systemd checks use.

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

A release binary (or `cargo build --release --manifest-path rust/Cargo.toml`) and nothing else:

```sh
RUSSDESK_HBBS_KEY_FILE=/path/to/id_ed25519.pub ./russdesk --data-dir ./data
# from a checkout:
cargo run --release --manifest-path rust/Cargo.toml -- --data-dir ./data
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
| `RUSSDESK_STATIC_DIR` | next to the binary | Web console files (`static/`). |

Forgot the admin password:

```sh
echo 'new-password-here' | ./russdesk --data-dir ./data --reset-password admin
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
  needs them back). Protect the data directory. The console only shows whether one is set.
* API tokens are shown once at creation and stored hashed; give each the narrowest
  permissions it needs.

## How strategies apply

A device uses the first strategy found in this order: its own, its user's, its device group's,
the default. On each heartbeat the client reports the strategy stamp it has; when it differs,
RussDesk sends the full option set. Options a previous strategy set but the new one doesn't
are sent empty, which returns them to the client's default.

## Development

```sh
cargo test --manifest-path rust/Cargo.toml       # API, protocol, crypto and database tests
cargo build --release --manifest-path rust/Cargo.toml
```

Databases from v0.1 are upgraded automatically on start.

The tests replay the request shapes of the RustDesk client. No real RustDesk client was
used during development. If a client release changes a payload, check
`docs/client-protocol.md` against the client source.

Layout: `rust/src/client_api.rs` (what clients call), `rust/src/admin_api.rs` (console API),
`rust/src/models.rs` (access rules, strategies, address books), `rust/static/` (the
console: plain HTML/CSS/JS, no build step).

## License

AGPL-3.0, the same licence as RustDesk's open-source server. Bundled:
[qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 (MIT).
