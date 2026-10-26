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

## Unattended access (no accept prompt)

By default RustDesk makes the controlled side click **Accept** or read out a
rotating temporary password. To ship a client the console can connect to with no
interaction, pass a shared permanent password:

```sh
python3 client/configure_client.py --id-server rd.example.com:21116 \
    --key "$(cat id_ed25519.pub)" --password 'a-strong-shared-secret'
```

That bakes `approve-mode=password` and `verification-method=use-permanent-password`
into `DEFAULT_SETTINGS`, and the password into `HARD_SETTINGS` as RustDesk's
preset permanent password — **as a SHA256 hash, never the plaintext**, so the
binary (even a public release) does not reveal the password. The console/viewer
connects with that one password; the remote user does nothing. In CI set it as
the `UNATTENDED_PASSWORD` secret or the `password` workflow input.

## Where the Windows build goes

The `windows` job of `build-client.yml` packages a single-file portable `.exe`
and publishes it to the repo's **GitHub Releases** under the `windows-client`
tag (plus a `SHA256SUMS.txt`). The `android` job uploads the `.apk` as a build
artifact.

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

`client/build-client.sh --target …` builds one or more targets (comma-separated); each has to be built on
its own kind of host:

| Target | Output in `client/dist/` | Build host |
| --- | --- | --- |
| `windows` | `russdesk-<host>-windows-x64.exe` (portable, single file) | Windows — `build-client.ps1`, or the `.sh` from Git Bash |
| `android` | `russdesk-<host>-android-arm64-v8a.apk`, `…-armeabi-v7a.apk` | Linux or macOS (Windows via `.ps1` + Git Bash) |
| `macos` | `russdesk-<host>-macos-<arch>.dmg` (unsigned) | macOS |
| `ios` (alias `iphone`) | `russdesk-<host>-ios-unsigned.ipa` | macOS with Xcode |
| `linux` | `russdesk-<host>-linux-<arch>.tar.gz` (Flutter bundle) | Linux |

All targets need Rust 1.75, Flutter 3.24.5, Python 3 and `VCPKG_ROOT` pointing
at a vcpkg checkout (the script installs the vcpkg packages it needs from
`client/vendor/vcpkg.json`). The first build also generates the
flutter_rust_bridge glue, which needs:

```sh
cargo install cargo-expand --version 1.0.95 --locked
cargo install flutter_rust_bridge_codegen --version 1.80.1 --features uuid --locked
```

Per-target extras: Visual Studio 2022 C++ tools + LLVM (windows); Java 17,
NDK `r28c` in `ANDROID_NDK_HOME` and `cargo-ndk` (android); Xcode + CocoaPods
(macos, ios). `--help` lists everything.

```sh
RENDEZVOUS_SERVER=rd.example.com:21116 RS_PUB_KEY="$(cat id_ed25519.pub)" \
    client/build-client.sh --target android,linux
client/build-client.sh --id-server rd.example.com:21116 --key 'KEY=' \
    --password 'a-strong-shared-secret' --target macos,ios   # on a Mac
client/build-client.sh --help
```

On Windows, use the PowerShell script (targets `windows`, `android`). It takes
PowerShell-style `-Target`/`-IdServer`/`-Key`… and also the same `--target`/
`--id-server`/`--key`… flags as the shell script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass   # if scripts are blocked
.\client\build-client.ps1 -Target windows -IdServer rd.example.com:21116 -Key (Get-Content id_ed25519.pub) `
    -Password 'a-strong-shared-secret'
Get-Help .\client\build-client.ps1 -Detailed   # or: .\client\build-client.ps1 -Help
```

Notes:

- macOS and iOS builds are unsigned. On macOS, right-click → Open the first
  time (or `xattr -dr com.apple.quarantine /Applications/RustDesk.app`), and
  grant Screen Recording + Accessibility to be controlled. The `.ipa` has to be
  re-signed (Xcode, AltStore, Sideloadly) before it installs. iOS doesn't allow
  being remote-controlled, so an iPhone client can only control other devices.
- Without `flutter/android/key.properties` the APKs are signed with the debug
  key, as in RustDesk's CI.
- The script re-bakes `config.rs` from a clean checkout each run, so it is safe
  to build repeatedly with different values.

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
