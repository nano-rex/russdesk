#!/usr/bin/env bash
#
# build-client.sh — build a RustDesk client with your self-hosted server baked in.
#
# It bakes the ID server, relay server, public key and (optionally) a shared
# unattended password into the vendored client source (via configure_client.py),
# then runs the real RustDesk build for each requested target so the resulting
# client connects to your server with no manual Settings -> Network step.
#
# The heavy toolchain (Rust, Flutter, vcpkg, Android NDK, Xcode, ...) is NOT
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

# Pinned to RustDesk 1.5.0's own bridge job (client/vendor/.github/workflows/bridge.yml).
FRB_VERSION="1.80.1"
CARGO_EXPAND_VERSION="1.0.95"

usage() {
  cat <<'EOF'
Usage: client/build-client.sh [options] --target TARGET[,TARGET...]

Bake your RussDesk server settings into the vendored RustDesk client and build it.
Artifacts are copied to client/dist/.

Targets for --target (default: android). Each must be built on the host shown:
  windows   portable russdesk-<host>-windows-x64.exe       Windows (Git Bash/MSYS)
                                                            or use client/build-client.ps1
  android   russdesk-<host>-android-<abi>.apk (arm64-v8a, armeabi-v7a)
                                                            Linux or macOS
  macos     russdesk-<host>-macos-<arch>.dmg (unsigned)     macOS
  ios       russdesk-<host>-ios-unsigned.ipa                macOS with Xcode
            (alias: iphone; must be re-signed to install; iOS clients can
             control other devices but cannot be controlled themselves)
  linux     russdesk-<host>-linux-<arch>.tar.gz             Linux

Options (each can also come from the environment variable shown):
  --id-server HOST[:PORT]  ID/rendezvous server, e.g. rd.example.com:31116   [RENDEZVOUS_SERVER]  (required)
  --key KEY                hbbs public key (content of id_ed25519.pub)       [RS_PUB_KEY]         (required)
  --relay HOST[:PORT]      default relay server; hbbs also advertises one    [RELAY_SERVER]
  --api-server URL         default API server; derived from ID server if unset [API_SERVER]
  --password PASS          shared permanent password for unattended access;  [UNATTENDED_PASSWORD]
                           only its SHA256 hash is baked into the binary
  -t, --target LIST        what to build: comma-separated and/or repeated,
                           e.g. --target macos,ios  or  -t android -t linux
  --regen-bridge           regenerate the flutter_rust_bridge glue even if present
  --check                  validate and show the config.rs changes, then exit (no build)
  -h, --help               show this help and exit

Toolchain (versions match RustDesk 1.5.0's CI):
  all       Rust 1.75, Flutter 3.24.5, Python 3, VCPKG_ROOT pointing at vcpkg,
            and for the first build flutter_rust_bridge_codegen 1.80.1 + cargo-expand
  windows   Visual Studio 2022 C++ build tools, LLVM (libclang)
  android   Java 17, Android NDK r28c in ANDROID_NDK_HOME, cargo-ndk
  macos     Xcode, CocoaPods, nasm
  ios       Xcode, CocoaPods
  linux     clang, cmake, ninja, nasm, pkg-config, libgtk-3-dev and RustDesk's
            other Linux build packages (see client/vendor/README.md)

Where to get the values: RussDesk console -> Settings -> General,
or GET /api/admin/client-config.

Examples:
  RENDEZVOUS_SERVER=rd.example.com:31116 RS_PUB_KEY="$(cat id_ed25519.pub)" \
      client/build-client.sh --target android
  client/build-client.sh --id-server rd.example.com:31116 --key 'KEY=' \
      --password 'a-strong-shared-secret' --target macos,ios
  client/build-client.sh --id-server rd.example.com:31116 --key 'KEY=' --check
EOF
}

ID_SERVER="${RENDEZVOUS_SERVER:-}"
KEY="${RS_PUB_KEY:-}"
RELAY="${RELAY_SERVER:-}"
API="${API_SERVER:-}"
PASSWORD="${UNATTENDED_PASSWORD:-}"
TARGETS=()
CHECK=0
REGEN_BRIDGE=0

# Options that take a value must be given one.
val() { [ $# -ge 2 ] || { echo "error: $1 needs a value (see --help)" >&2; exit 2; }; }

add_target() {
  local IFS=,
  local t
  for t in $1; do add_one_target "$t"; done
}
add_one_target() {
  case "$1" in
    windows|win) TARGETS+=(windows) ;;
    android) TARGETS+=(android) ;;
    macos|mac|osx) TARGETS+=(macos) ;;
    ios|iphone|ipad) TARGETS+=(ios) ;;
    linux) TARGETS+=(linux) ;;
    *) echo "error: unknown target: $1 (windows|android|macos|ios|linux; see --help)" >&2; exit 2 ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --id-server) val "$@"; ID_SERVER="$2"; shift 2 ;;
    --key) val "$@"; KEY="$2"; shift 2 ;;
    --relay) val "$@"; RELAY="$2"; shift 2 ;;
    --api-server) val "$@"; API="$2"; shift 2 ;;
    --password) val "$@"; PASSWORD="$2"; shift 2 ;;
    -t|--target) val "$@"; add_target "$2"; shift 2 ;;
    --regen-bridge) REGEN_BRIDGE=1; shift ;;
    --check) CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "error: unknown option: $1 (see --help)" >&2; exit 2 ;;
    *) echo "error: unexpected argument: $1 (choose targets with --target; see --help)" >&2; exit 2 ;;
  esac
done
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=(android)

if [ -z "$ID_SERVER" ] || [ -z "$KEY" ]; then
  echo "error: set the ID server and key (--id-server / --key or RENDEZVOUS_SERVER / RS_PUB_KEY); see --help" >&2
  exit 2
fi
if [ ! -f "$CONFIG_RS" ]; then
  echo "error: vendored client not found at $VENDOR (is client/vendor populated?)" >&2
  exit 1
fi

# Use the first python that actually runs Python 3: on Windows, python3 is often
# the Microsoft Store placeholder, which exists without Python being installed.
PY=""
for c in python3 python; do
  p="$(command -v "$c" 2>/dev/null)" || continue
  if "$p" -c 'import sys; sys.exit(sys.version_info[0] < 3)' >/dev/null 2>&1; then PY="$p"; break; fi
done
[ -n "$PY" ] || { echo "error: python3 is required" >&2; exit 1; }

if [ "$CHECK" -eq 1 ]; then
  "$PY" "$HERE/configure_client.py" --config-rs "$CONFIG_RS" --check \
    --id-server "$ID_SERVER" --key "$KEY" --relay "$RELAY" --api-server "$API" \
    --password "$PASSWORD"
  exit 0
fi

case "$(uname -s)" in
  Linux) HOST_OS=linux ;;
  Darwin) HOST_OS=macos ;;
  MINGW*|MSYS*|CYGWIN*) HOST_OS=windows ;;
  *) HOST_OS=unknown ;;
esac
case "$(uname -m)" in
  arm64|aarch64) HOST_ARCH=arm64 ;;
  *) HOST_ARCH=x64 ;;
esac
# Short server name for artifact file names, e.g. rd.example.com:31116 -> rd.example.com
SERVER_NAME=$(printf '%s' "$ID_SERVER" | sed 's#^[a-z]*://##; s#[:/].*##')

# Fail before baking or building anything if a target can't be built here.
for t in "${TARGETS[@]}"; do
  case "$t" in
    windows) ok="windows" ;;
    android) ok="linux macos" ;;
    macos|ios) ok="macos" ;;
    linux) ok="linux" ;;
  esac
  case " $ok " in
    *" $HOST_OS "*) ;;
    *) echo "error: target '$t' must be built on: $ok (this host: $HOST_OS)" >&2; exit 1 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required for target '$2' but was not found" >&2; exit 1; }; }

# Files temporarily patched for a build are restored on exit, even on failure.
RESTORE=()
backup() { cp "$1" "$1.russdesk-bak"; RESTORE+=("$1"); }
restore_all() {
  for f in ${RESTORE[@]+"${RESTORE[@]}"}; do
    [ -f "$f.russdesk-bak" ] && mv -f "$f.russdesk-bak" "$f"
  done
  return 0
}
trap restore_all EXIT

# sed -i differs between GNU and BSD (macOS); write through a temp file instead.
subst() { sed "$1" "$2" > "$2.tmp" && mv -f "$2.tmp" "$2"; }

vcpkg_install() {
  : "${VCPKG_ROOT:?set VCPKG_ROOT to your vcpkg checkout (see --help)}"
  echo "==> Installing vcpkg dependencies ($1)"
  "$VCPKG_ROOT/vcpkg" install --triplet "$1" --x-install-root="$VCPKG_ROOT/installed"
}

# The Rust<->Dart glue (src/bridge_generated*.rs, flutter/lib/generated_bridge*.dart)
# is generated, not vendored; every target needs it to compile.
gen_bridge() {
  if [ "$REGEN_BRIDGE" -eq 0 ] && [ -f src/bridge_generated.rs ] && [ -f flutter/lib/generated_bridge.dart ]; then
    return
  fi
  if ! command -v flutter_rust_bridge_codegen >/dev/null 2>&1 || ! command -v cargo-expand >/dev/null 2>&1; then
    cat >&2 <<EOF
error: generating the flutter_rust_bridge glue needs flutter_rust_bridge_codegen and cargo-expand:
  cargo install cargo-expand --version $CARGO_EXPAND_VERSION --locked
  cargo install flutter_rust_bridge_codegen --version $FRB_VERSION --features uuid --locked
EOF
    exit 1
  fi
  need flutter bridge
  echo "==> Generating flutter_rust_bridge glue"
  ( cd flutter && flutter pub get )
  flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart \
    --c-output ./flutter/macos/Runner/bridge_generated.h
  cp ./flutter/macos/Runner/bridge_generated.h ./flutter/ios/Runner/bridge_generated.h
}

# Load the MSVC developer environment (INCLUDE/LIB/LIBPATH) from the Visual
# Studio that actually has the C++ tools. Without it, bindgen's libclang picks the
# newest VS install, which may lack them, and fails on 'stdlib.h' not found.
msvc_env() {
  [ -z "${INCLUDE:-}" ] || return 0
  local vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
  [ -x "$vswhere" ] || { echo "error: Visual Studio Installer (vswhere.exe) not found; install the VS 2022 C++ Build Tools" >&2; exit 1; }
  local vs
  vs=$("$vswhere" -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | tr -d '\r')
  [ -n "$vs" ] || { echo "error: no Visual Studio with the C++ tools (VC.Tools.x86.x64) found; install the VS 2022 C++ Build Tools" >&2; exit 1; }
  echo "==> Using MSVC environment from $vs"
  local bat; bat="$(mktemp -d)/msvc-env.bat"
  printf '@call "%s\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul\r\n@set\r\n' "$vs" > "$bat"
  local k v
  while IFS='=' read -r k v; do
    case "$k" in INCLUDE|LIB|LIBPATH) export "$k=${v%$'\r'}" ;; esac
  done < <(cmd //c "$(cygpath -w "$bat")")
  rm -rf "$(dirname "$bat")"
  [ -n "${INCLUDE:-}" ] || { echo "error: vcvars64.bat from $vs did not set INCLUDE" >&2; exit 1; }
}

build_windows() {
  need flutter windows; need cargo windows
  msvc_env
  vcpkg_install x64-windows-static
  echo "==> Building Windows client (flutter + cargo)"
  ( cd flutter && flutter pub get )
  "$PY" build.py --portable --flutter --skip-portable-pack
  echo "==> Packing single-file portable exe"
  rm -rf ./rustdesk
  cp -r ./flutter/build/windows/x64/runner/Release ./rustdesk
  ( cd libs/portable && "$PY" -m pip install -r requirements.txt \
      && "$PY" ./generate.py -f ../../rustdesk/ -o . -e ../../rustdesk/rustdesk.exe )
  local exe="russdesk-${SERVER_NAME}-windows-x64.exe"
  cp ./target/release/rustdesk-portable-packer.exe "$DIST/$exe"
  ( cd "$DIST" && sha256sum "$exe" > SHA256SUMS-windows.txt )
}

build_android() {
  need flutter android; need cargo android; need cargo-ndk android
  : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your Android NDK (r28c)}"
  : "${VCPKG_ROOT:?set VCPKG_ROOT to your vcpkg checkout (see --help)}"
  local prebuilt="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$([ "$HOST_OS" = macos ] && echo darwin || echo linux)-x86_64/sysroot/usr/lib"
  local abi triple libcxx
  for abi in arm64-v8a armeabi-v7a; do
    case "$abi" in
      arm64-v8a) triple=aarch64-linux-android; libcxx=aarch64-linux-android ;;
      armeabi-v7a) triple=armv7-linux-androideabi; libcxx=arm-linux-androideabi ;;
    esac
    echo "==> Building Android $abi (vcpkg + cargo ndk)"
    bash flutter/build_android_deps.sh "$abi"
    command -v rustup >/dev/null 2>&1 && rustup target add "$triple"
    cargo ndk --platform 21 --target "$triple" build --locked --release --features flutter,hwcodec
    mkdir -p "flutter/android/app/src/main/jniLibs/$abi"
    cp "$prebuilt/$libcxx/libc++_shared.so" "flutter/android/app/src/main/jniLibs/$abi/"
    cp "target/$triple/release/liblibrustdesk.so" "flutter/android/app/src/main/jniLibs/$abi/librustdesk.so"
  done
  # Without a release keystore (flutter/android/key.properties), sign with the
  # debug key like RustDesk's CI does, so the APK still installs.
  if [ ! -f flutter/android/key.properties ]; then
    backup flutter/android/app/build.gradle
    subst 's/signingConfigs.release/signingConfigs.debug/g' flutter/android/app/build.gradle
  fi
  echo "==> Building APKs"
  ( cd flutter && flutter pub get \
      && flutter build apk --release --target-platform android-arm64,android-arm --split-per-abi )
  for abi in arm64-v8a armeabi-v7a; do
    cp "flutter/build/app/outputs/flutter-apk/app-$abi-release.apk" "$DIST/russdesk-${SERVER_NAME}-android-$abi.apk"
  done
}

build_macos() {
  need flutter macos; need cargo macos; need pod macos; need hdiutil macos
  vcpkg_install "$([ "$HOST_ARCH" = arm64 ] && echo arm64-osx || echo x64-osx)"
  echo "==> Building macOS client (flutter + cargo)"
  ( cd flutter && flutter pub get )
  "$PY" build.py --flutter --hwcodec
  local arch; arch="$([ "$HOST_ARCH" = arm64 ] && echo arm64 || echo x86_64)"
  local out="$DIST/russdesk-${SERVER_NAME}-macos-$arch.dmg"
  echo "==> Packing $out"
  hdiutil create -volname RussDesk -srcfolder flutter/build/macos/Build/Products/Release/RustDesk.app \
    -ov -format UDZO "$out"
}

build_ios() {
  need flutter ios; need cargo ios; need pod ios; need xcodebuild ios; need zip ios
  vcpkg_install arm64-ios
  echo "==> Building iOS Rust library"
  command -v rustup >/dev/null 2>&1 && rustup target add aarch64-apple-ios
  cargo build --locked --features flutter,hwcodec --release --target aarch64-apple-ios --lib
  echo "==> Building iOS app (unsigned)"
  ( cd flutter && flutter pub get && flutter build ipa --release --no-codesign )
  local app
  app=$(ls -d flutter/build/ios/archive/Runner.xcarchive/Products/Applications/*.app | head -n 1)
  local tmp; tmp=$(mktemp -d)
  mkdir "$tmp/Payload"
  cp -R "$app" "$tmp/Payload/"
  ( cd "$tmp" && zip -qry "$DIST/russdesk-${SERVER_NAME}-ios-unsigned.ipa" Payload )
  rm -rf "$tmp"
}

build_linux() {
  need flutter linux; need cargo linux
  vcpkg_install "$([ "$HOST_ARCH" = arm64 ] && echo arm64-linux || echo x64-linux)"
  echo "==> Building Linux client (flutter + cargo)"
  cargo build --locked --features flutter --lib --release
  # ffigen workaround RustDesk's own Linux build applies (build.py ffi_bindgen_function_refactor).
  backup flutter/lib/generated_bridge.dart
  subst 's/ffi.NativeFunction<ffi.Bool Function(DartPort/ffi.NativeFunction<ffi.Uint8 Function(DartPort/g' \
    flutter/lib/generated_bridge.dart
  ( cd flutter && flutter pub get && flutter build linux --release )
  local name="russdesk-linux-$HOST_ARCH"
  rm -rf "${DIST:?}/$name"
  cp -r flutter/build/linux/*/release/bundle "$DIST/$name"
  tar -czf "$DIST/russdesk-${SERVER_NAME}-linux-$HOST_ARCH.tar.gz" -C "$DIST" "$name"
  rm -rf "${DIST:?}/$name"
}

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
gen_bridge

for t in "${TARGETS[@]}"; do
  "build_$t"
done

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
