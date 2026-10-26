#!/usr/bin/env bash
#
# build-client.sh — build a RustDesk client with your self-hosted server baked in.
#
# It bakes the ID server, relay server, public key and (optionally) a shared
# unattended password into the vendored client source (via configure_client.py),
# then runs the real RustDesk build for the requested target so the resulting
# .exe / .apk connects to your server with no manual Settings -> Network step.
#
# The heavy toolchain (Rust, Flutter, Android NDK, vcpkg on Windows) is NOT
# installed by this script: it must already be present, exactly as RustDesk's own
# build needs. See docs/custom-client.md and .github/workflows/build-client.yml.
# On Windows, client/build-client.ps1 is the native PowerShell equivalent.
#
# Run `client/build-client.sh --help` for options.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$HERE/vendor"
CONFIG_RS="$VENDOR/libs/hbb_common/src/config.rs"
DIST="$HERE/dist"

usage() {
  cat <<'EOF'
Usage: client/build-client.sh [options] [android|windows|linux]

Bake your RussDesk server settings into the vendored RustDesk client and build it.
Artifacts are copied to client/dist/.

Targets (default: android):
  android    arm64-v8a + armeabi-v7a release APKs   (needs flutter, cargo-ndk, ANDROID_NDK_HOME)
  windows    single-file portable russdesk-<host>-windows-x64.exe + SHA256SUMS.txt
             (needs python, flutter, cargo, VCPKG_ROOT; run from Git Bash/MSYS,
              or use client/build-client.ps1 from PowerShell)
  linux      Flutter Linux bundle in dist/rustdesk-linux   (needs flutter, cargo)

Options (each can also come from the environment variable shown):
  --id-server HOST[:PORT]  ID/rendezvous server, e.g. rd.example.com:31116   [RENDEZVOUS_SERVER]  (required)
  --key KEY                hbbs public key (content of id_ed25519.pub)       [RS_PUB_KEY]         (required)
  --relay HOST[:PORT]      default relay server; hbbs also advertises one    [RELAY_SERVER]
  --api-server URL         default API server; derived from ID server if unset [API_SERVER]
  --password PASS          shared permanent password for unattended access;  [UNATTENDED_PASSWORD]
                           only its SHA256 hash is baked into the binary
  --check                  validate and show the config.rs changes, then exit (no build)
  -h, --help               show this help and exit

Where to get the values: RussDesk console -> Settings -> General,
or GET /api/admin/client-config.

Examples:
  RENDEZVOUS_SERVER=rd.example.com:31116 RS_PUB_KEY="$(cat id_ed25519.pub)" \
      client/build-client.sh android
  client/build-client.sh --id-server rd.example.com:31116 --key 'KEY=' \
      --password 'a-strong-shared-secret' windows
  client/build-client.sh --id-server rd.example.com:31116 --key 'KEY=' --check
EOF
}

ID_SERVER="${RENDEZVOUS_SERVER:-}"
KEY="${RS_PUB_KEY:-}"
RELAY="${RELAY_SERVER:-}"
API="${API_SERVER:-}"
PASSWORD="${UNATTENDED_PASSWORD:-}"
TARGET="android"
CHECK=0

# Options that take a value must be given one.
val() { [ $# -ge 2 ] || { echo "error: $1 needs a value (see --help)" >&2; exit 2; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    --id-server) val "$@"; ID_SERVER="$2"; shift 2 ;;
    --key) val "$@"; KEY="$2"; shift 2 ;;
    --relay) val "$@"; RELAY="$2"; shift 2 ;;
    --api-server) val "$@"; API="$2"; shift 2 ;;
    --password) val "$@"; PASSWORD="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    android|windows|linux) TARGET="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1 (see --help)" >&2; exit 2 ;;
  esac
done

if [ -z "$ID_SERVER" ] || [ -z "$KEY" ]; then
  echo "error: set the ID server and key (--id-server / --key or RENDEZVOUS_SERVER / RS_PUB_KEY); see --help" >&2
  exit 2
fi
if [ ! -f "$CONFIG_RS" ]; then
  echo "error: vendored client not found at $VENDOR (is client/vendor populated?)" >&2
  exit 1
fi

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "error: python3 is required" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
  "$PY" "$HERE/configure_client.py" --config-rs "$CONFIG_RS" --check \
    --id-server "$ID_SERVER" --key "$KEY" --relay "$RELAY" --api-server "$API" \
    --password "$PASSWORD"
  exit 0
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required for target '$TARGET' but was not found" >&2; exit 1; }; }

echo "==> Baking server config into the client source"
# Start from a clean config.rs when this is a git checkout, so each build is
# reproducible regardless of a previous run.
if git -C "$VENDOR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$VENDOR" checkout -- libs/hbb_common/src/config.rs 2>/dev/null || true
fi
"$PY" "$HERE/configure_client.py" --config-rs "$CONFIG_RS" \
  --id-server "$ID_SERVER" --key "$KEY" --relay "$RELAY" --api-server "$API" \
  --password "$PASSWORD"

mkdir -p "$DIST"
cd "$VENDOR"

case "$TARGET" in
  android)
    need flutter; need cargo-ndk
    : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK}"
    echo "==> Building Rust jniLibs + APK (arm64, arm)"
    bash flutter/build_android_deps.sh arm64-v8a armeabi-v7a
    ( cd flutter && flutter pub get && bash build_android.sh )
    find flutter/build/app/outputs -name 'app-*-release.apk' -exec cp {} "$DIST/" \;
    ;;
  windows)
    need flutter; need cargo
    : "${VCPKG_ROOT:?set VCPKG_ROOT to a vcpkg with: vcpkg install --triplet x64-windows-static libvpx libyuv opus aom}"
    echo "==> Building Windows client (flutter + cargo)"
    flutter pub get
    "$PY" build.py --portable --flutter --skip-portable-pack
    echo "==> Packing single-file portable exe"
    rm -rf ./rustdesk
    cp -r ./flutter/build/windows/x64/runner/Release ./rustdesk
    ( cd libs/portable && "$PY" -m pip install -r requirements.txt \
        && "$PY" ./generate.py -f ../../rustdesk/ -o . -e ../../rustdesk/rustdesk.exe )
    host=$(printf '%s' "$ID_SERVER" | sed 's#^[a-z]*://##; s#[:/].*##')
    cp ./target/release/rustdesk-portable-packer.exe "$DIST/russdesk-${host}-windows-x64.exe"
    ( cd "$DIST" && sha256sum "russdesk-${host}-windows-x64.exe" > SHA256SUMS.txt )
    ;;
  linux)
    need cargo; need flutter
    echo "==> Building Linux client (flutter + cargo)"
    cargo build --locked --features flutter --lib --release
    ( cd flutter && flutter pub get && flutter build linux --release )
    rm -rf "$DIST/rustdesk-linux"
    cp -r flutter/build/linux/*/release/bundle "$DIST/rustdesk-linux"
    ;;
esac

echo "==> Done. Artifacts in: $DIST"
ls -la "$DIST"
echo
echo "Baked configuration:"
echo "  ID server : $ID_SERVER"
echo "  Relay     : ${RELAY:-<provided by hbbs at connect time>}"
echo "  API server: ${API:-<derived from ID server>}"
echo "  Key       : ${KEY:0:12}…"
if [ -n "$PASSWORD" ]; then
  echo "  Unattended: yes (shared permanent password, hash only)"
else
  echo "  Unattended: no (remote user must accept)"
fi
