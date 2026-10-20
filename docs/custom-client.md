# Custom client generator

Build a RustDesk client that already knows your self-hosted server, so the
`.exe` / `.apk` you ship connects to your hbbs with no manual *Settings →
Network* step.

The client source is vendored under [`client/vendor`](../client) (RustDesk
`1.5.0`, with the `hbb_common` submodule flattened in). The build bakes three
values into the client at compile time:

| Value | Where it goes | Required |
| --- | --- | --- |
| ID / rendezvous server | `RENDEZVOUS_SERVERS` const in `hbb_common/src/config.rs` | yes |
| Server public key | `RS_PUB_KEY` const in the same file | yes |
| Relay server | seeded into the compile-time `DEFAULT_SETTINGS` (`relay-server`) | no — hbbs advertises one at connect time |
| API server | seeded into `DEFAULT_SETTINGS` (`api-server`) | no — derived from the ID server |

Only the ID server and key are needed for a client that "just works"; the relay
is handed to clients by hbbs during connection setup, so set it only if you want
an explicit default.

> The generated client is an ordinary, unmodified RustDesk client: it shows its
> normal UI and connection indicator and honours the usual accept / permanent-
> password model. Only the default server address and key are pre-filled.

## Where to get the values

Open the RussDesk console → **Settings → General**, or `GET /api/admin/client-config`:
`host` is the ID server, `key` is the public key, `relay` the relay server. They
come from your console settings (or hbbs' `id_ed25519.pub`).

## Build in CI (recommended)

The Rust + Flutter + Android/NDK/vcpkg toolchain is large and cannot run in the
RussDesk server environment, so the shipping path is GitHub Actions:
[`.github/workflows/build-client.yml`](../.github/workflows/build-client.yml).

1. In the repo: **Settings → Secrets and variables → Actions**
   - Variable `RENDEZVOUS_SERVER` = `rd.example.com:21116`
   - Secret `RS_PUB_KEY` = contents of hbbs' `id_ed25519.pub`
   - (optional) Variables `RELAY_SERVER`, `API_SERVER`
2. **Actions → Build custom client → Run workflow**, pick the targets.
3. Download the `rustdesk-android-custom` / `rustdesk-windows-custom` artifacts.

Any value can be overridden per-run with the workflow inputs. Toolchain versions
are pinned to match RustDesk 1.5.0's own CI.

## Build locally

On a machine already set up to build RustDesk (Rust 1.75, Flutter 3.24.5, and —
for Android — the NDK `r28c` with `ANDROID_NDK_HOME` set):

```sh
RENDEZVOUS_SERVER=rd.example.com:21116 RS_PUB_KEY="$(cat id_ed25519.pub)" \
    client/build-client.sh android      # or: windows | linux
```

Artifacts are copied to `client/dist/`. The script re-bakes `config.rs` from a
clean checkout each run, so it is safe to build repeatedly with different values.

## Just the config step

`client/configure_client.py` does the baking on its own and is what both the
script and CI call:

```sh
python3 client/configure_client.py --id-server rd.example.com:21116 \
    --key "$(cat id_ed25519.pub)" --relay rd.example.com:21117 --check
```

`--check` validates and prints the result without writing. Values are validated
before they are written into the Rust source, so a malformed server/key cannot
break (or inject into) `config.rs`.
