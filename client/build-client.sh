#!/usr/bin/env bash
#
# build-client.sh — build a RustDesk client with your self-hosted server baked in.
#
# It bakes the ID server, relay server and public key into the vendored client
# source (via configure_client.py), then runs the real RustDesk build for the
# requested target so the resulting .exe / .apk connects to your server with no
# manual Settings -> Network step.
#
# The heavy toolchain (Rust, Flutter, Android NDK, vcpkg on Windows) is NOT
# installed by this script: it must already be present, exactly as RustDesk's own
# build needs. Run it on a machine or CI runner set up to build RustDesk; see
# docs/custom-client.md and .github/workflows/build-client.yml for the CI path.
#
# Usage:
#   RENDEZVOUS_SERVER=rd.example.com:21116 RS_PUB_KEY='BASE64KEY=' \
#       client/build-client.sh android
#   client/build-client.sh --id-server rd.example.com:21116 --key 'KEY=' \
#       --relay rd.example.com:21117 windows
#
# Targets: android | windows | linux   (default: android)

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENDOR="$HERE/vendor"
CONFIG_RS="$VENDOR/libs/hbb_common/src/config.rs"
DIST="$HERE/dist"

ID_SERVER="${RENDEZVOUS_SERVER:-}"
KEY="${RS_PUB_KEY:-}"
RELAY="${RELAY_SERVER:-}"
API="${API_SERVER:-}"
TARGET="android"

while [ $# -gt 0 ]; do
  case "$1" in
    --id-server) ID_SERVER="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --relay) RELAY="$2"; shift 2 ;;
    --api-server) API="$2"; shift 2 ;;
    android|windows|linux) TARGET="$1"; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$ID_SERVER" ] || [ -z "$KEY" ]; then
  echo "error: set the ID server and key (--id-server / --key or RENDEZVOUS_SERVER / RS_PUB_KEY)" >&2
  exit 2
fi
if [ ! -f "$CONFIG_RS" ]; then
  echo "error: vendored client not found at $VENDOR (is client/vendor populated?)" >&2
  exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required for target '$TARGET' but was not found" >&2; exit 1; }; }

echo "==> Baking server config into the client source"
# Start from a clean config.rs when this is a git checkout, so each build is
# reproducible regardless of a previous run.
if git -C "$VENDOR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$VENDOR" checkout -- libs/hbb_common/src/config.rs 2>/dev/null || true
elif [ -d "$(git -C "$HERE/.." rev-parse --git-dir 2>/dev/null)" ]; then
  git -C "$HERE/.." checkout -- "client/vendor/libs/hbb_common/src/config.rs" 2>/dev/null || true
fi
python3 "$HERE/configure_client.py" --config-rs "$CONFIG_RS" \
  --id-server "$ID_SERVER" --key "$KEY" --relay "$RELAY" --api-server "$API"

mkdir -p "$DIST"
cd "$VENDOR"

case "$TARGET" in
  android)
    need flutter
    : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK}"
    echo "==> Building Rust jniLibs + APK (arm64, arm)"
    bash flutter/build_android_deps.sh arm64-v8a armeabi-v7a
    ( cd flutter && bash build_android.sh )
    find flutter/build/app/outputs -name 'app-*-release.apk' -exec cp {} "$DIST/" \;
    ;;
  windows)
    need python; need flutter; need cargo
    echo "==> Building Windows client (flutter + cargo)"
    python build.py --flutter
    find build/windows -name 'rustdesk.exe' -path '*Release*' -exec cp {} "$DIST/" \;
    ;;
  linux)
    need cargo; need flutter
    echo "==> Building Linux client (flutter + cargo)"
    cargo build --locked --features flutter --lib --release
    flutter build linux --release
    cp -r build/linux/*/release/bundle "$DIST/rustdesk-linux" 2>/dev/null || true
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
