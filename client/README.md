# RustDesk client (vendored)

`vendor/` is the RustDesk client source (release `1.5.0`, with the `hbb_common`
submodule flattened in as plain files) used to build a **custom client** with
your self-hosted server baked in.

- `configure_client.py` — bakes the ID server, relay server and key into
  `vendor/libs/hbb_common/src/config.rs` (compile-time constants).
- `build-client.sh` — bakes the config, then builds the client for any of
  `--target windows,android,macos,ios,linux` on a machine with the RustDesk toolchain.
  Artifacts land in `dist/`. `--help` lists all options.
- `build-client.ps1` — the same for Windows PowerShell (`-Target windows,android`;
  `-Help` for options); builds the single-file portable `.exe` like CI.
- CI: [`.github/workflows/build-client.yml`](../.github/workflows/build-client.yml).

Full guide: [docs/custom-client.md](../docs/custom-client.md).

## Installation requirements

The build scripts don't install the toolchain. Versions are pinned to what
RustDesk 1.5.0's own CI uses; newer Rust or Flutter releases do **not** build
this source (see the notes below).

| Tool | Version | Needed for |
| --- | --- | --- |
| Rust (via rustup) | **1.75**, with the `rustfmt` component | all targets |
| Flutter | **3.24.5** | all targets |
| Python | 3.x | all targets |
| Git | any | all targets |
| vcpkg | commit `9e593bb18ea69cc5095e012465dcd675a822ed0d`, `VCPKG_ROOT` set | all targets |
| LLVM / libclang | any recent (tested with 23) | all targets |
| cargo-expand | 1.0.95 | all targets (bridge generation) |
| flutter_rust_bridge_codegen | 1.80.1, feature `uuid` | all targets (bridge generation) |
| Visual Studio 2022 Build Tools, "Desktop development with C++" | 17.x | windows |
| Java | 17 | android |
| Android NDK + cargo-ndk | r28c, `ANDROID_NDK_HOME` set; cargo-ndk 3.1.2 | android |
| Xcode + CocoaPods | current | macos, ios |

Budget about 25 GB of free disk. The first build compiles the vcpkg libraries
(~12 minutes on a 28-thread machine) and all of RustDesk; later builds reuse
both and are much faster.

Things that look optional but aren't:

- **Rust 1.75, not your default.** RustDesk's locked dependencies don't build
  with much newer compilers. Install 1.75 next to your default and select it
  for the build with `RUSTUP_TOOLCHAIN=1.75` (or `rustup override set 1.75`
  inside `client/vendor`). Include `rustfmt`: the bridge generator needs it.
- **Flutter 3.24.5, not the latest.** The UI code doesn't compile on Flutter
  3.44+. Keep 3.24.5 in its own folder if you also use a newer Flutter, and
  put its `bin` first on `PATH` for the build.
- **vcpkg at the pinned commit**, so the C libraries match what RustDesk expects.

### Windows 10/11

Tested on Windows 11 (October 2026). From an **administrator** PowerShell:

```powershell
winget install --id Git.Git -e
winget install --id Rustlang.Rustup -e
winget install --id LLVM.LLVM -e
winget install --id Python.Python.3.12 -e
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

If Build Tools 2022 is already installed without the C++ workload, add it:

```powershell
& "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe" modify `
  --installPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" `
  --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart
```

Then, in a new PowerShell (so `PATH` picks up the new tools):

```powershell
# Rust 1.75 + rustfmt (your default toolchain stays as it is)
rustup toolchain install 1.75 --component rustfmt

# Bridge generator tools, built with 1.75 like upstream
cargo +1.75 install cargo-expand --version 1.0.95 --locked
cargo +1.75 install flutter_rust_bridge_codegen --version 1.80.1 --features uuid --locked

# Flutter 3.24.5 (unzip to its own folder)
Invoke-WebRequest https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_3.24.5-stable.zip -OutFile flutter-3.24.5.zip
Expand-Archive flutter-3.24.5.zip C:\dev\flutter-3.24.5-tmp
Move-Item C:\dev\flutter-3.24.5-tmp\flutter C:\dev\flutter-3.24.5

# vcpkg at the pinned commit
git clone https://github.com/microsoft/vcpkg C:\dev\vcpkg
git -C C:\dev\vcpkg checkout 9e593bb18ea69cc5095e012465dcd675a822ed0d
C:\dev\vcpkg\bootstrap-vcpkg.bat -disableMetrics

# RustDesk has very deep paths
git config --global core.longpaths true
```

Before each build, in the same shell:

```powershell
$env:Path = "C:\dev\flutter-3.24.5\bin;$env:Path"
$env:RUSTUP_TOOLCHAIN = '1.75'
$env:VCPKG_ROOT = 'C:\dev\vcpkg'
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
```

Windows-specific notes:

- **Running the script.** `build-client.ps1` needs scripts to be allowed
  (`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or
  `powershell -ExecutionPolicy Bypass -File client\build-client.ps1 …`).
  Alternatively run `client/build-client.sh` from Git Bash, which doesn't depend
  on the execution policy (set the same variables with `export`).
- **Symlinks.** Flutter plugins use symlinks: turn on Developer Mode
  (Settings → System → For developers), or build from an elevated shell.
- **Several Visual Studio versions installed.** The scripts load the
  environment of the Visual Studio that actually has the C++ tools, so a newer
  VS without them (e.g. VS 2026 Community) doesn't break the build. If you
  build by hand, use the "x64 Native Tools Command Prompt for VS 2022".
- **python3 / Microsoft Store.** If `python3` opens the Microsoft Store, that's
  the placeholder alias; the scripts skip it and use the real `python`.

### Linux (Ubuntu 22.04)

Not yet tested here; this follows RustDesk's own CI. Packages:

```sh
sudo apt-get install -y clang cmake curl gcc g++ git libayatana-appindicator3-dev \
  libasound2-dev libc6-dev libclang-dev libunwind-dev libgstreamer1.0-dev \
  libgstreamer-plugins-base1.0-dev libgtk-3-dev libpulse-dev libva-dev \
  libxcb-randr0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxdo-dev libxfixes-dev \
  llvm-dev nasm ninja-build pkg-config python3 wget zip unzip
```

Then rustup with `1.75` + `rustfmt`, the two `cargo +1.75 install` commands,
Flutter 3.24.5 (`flutter_linux_3.24.5-stable.tar.xz` from the same storage
URL as above, path `releases/stable/linux/`), and vcpkg at the pinned commit
(`./bootstrap-vcpkg.sh`), as on Windows.

For **Android** (on Linux or macOS) add `openjdk-17-jdk-headless`, the NDK r28c
(`ANDROID_NDK_HOME`), the Rust targets
`rustup +1.75 target add aarch64-linux-android armv7-linux-androideabi`, and
`cargo +1.75 install cargo-ndk --version 3.1.2 --locked`.

### macOS (for the macos and ios targets)

Not yet tested here. Install Xcode from the App Store, then:

```sh
xcode-select --install
brew install cocoapods nasm python git llvm
```

Then rustup with `1.75` + `rustfmt` (plus `rustup +1.75 target add
aarch64-apple-ios` for iOS), the two `cargo +1.75 install` commands, Flutter
3.24.5 for macOS (`releases/stable/macos/`), and vcpkg at the pinned commit.
