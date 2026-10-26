<#
.SYNOPSIS
    Build a RustDesk client with your self-hosted RussDesk server baked in (Windows).

.DESCRIPTION
    PowerShell equivalent of client/build-client.sh. It bakes the ID server,
    relay server, public key and (optionally) a shared unattended password into
    the vendored client source (via configure_client.py), then runs the real
    RustDesk build for each requested target so the result connects to your
    server with no manual Settings -> Network step. Artifacts are copied to
    client\dist\.

    Targets buildable on Windows:
      windows  portable russdesk-<host>-windows-x64.exe + SHA256SUMS-windows.txt
      android  russdesk-<host>-android-<abi>.apk (arm64-v8a, armeabi-v7a)
    macos / ios (iphone) / linux must be built on a Mac / Linux host with
    client/build-client.sh; this script stops with a pointer if you pass them.

    The toolchain is NOT installed by this script; it must already be present,
    as RustDesk's own build needs (versions match RustDesk 1.5.0's CI):
      all      Rust 1.75 (x86_64-pc-windows-msvc), Flutter 3.24.5, Python 3,
               VCPKG_ROOT pointing at vcpkg, and for the first build
               flutter_rust_bridge_codegen 1.80.1 + cargo-expand 1.0.95
      windows  Visual Studio 2022 C++ build tools, LLVM (libclang)
      android  Java 17, Android NDK r28c in ANDROID_NDK_HOME, cargo-ndk,
               Git Bash on PATH (RustDesk's Android dependency script is bash)

    Where to get the values: RussDesk console -> Settings -> General,
    or GET /api/admin/client-config.

.PARAMETER Target
    What to build, comma-separated: -Target windows,android (or --target).
    One or more of: windows (default), android. Also accepts macos, ios,
    iphone, linux only to tell you to use build-client.sh on that host.

.PARAMETER IdServer
    ID/rendezvous server, host or host:port (env RENDEZVOUS_SERVER). Required.

.PARAMETER Key
    hbbs public key, the content of id_ed25519.pub (env RS_PUB_KEY). Required.

.PARAMETER Relay
    Optional default relay server; hbbs also advertises one (env RELAY_SERVER).

.PARAMETER ApiServer
    Optional default API server; derived from the ID server if unset (env API_SERVER).

.PARAMETER Password
    Shared permanent password for unattended access (env UNATTENDED_PASSWORD).
    Only its SHA256 hash is baked into the binary.

.PARAMETER RegenBridge
    Regenerate the flutter_rust_bridge glue even if it is already present.

.PARAMETER Check
    Validate and show the config.rs changes, then exit without building.

.PARAMETER Help
    Show this help and exit.

    The build-client.sh spellings work too: --target, -t, --id-server, --key,
    --relay, --api-server, --password, --regen-bridge, --check, --help.

.EXAMPLE
    .\client\build-client.ps1 -IdServer rd.example.com:31116 -Key (Get-Content id_ed25519.pub)

.EXAMPLE
    .\client\build-client.ps1 -Target windows,android -IdServer rd.example.com:31116 -Key 'KEY=' -Password 'a-strong-shared-secret'

.EXAMPLE
    .\client\build-client.ps1 --target windows --id-server rd.example.com:31116 --key 'KEY='

.EXAMPLE
    $env:RENDEZVOUS_SERVER = 'rd.example.com:31116'; $env:RS_PUB_KEY = 'KEY='
    .\client\build-client.ps1 -Check

.NOTES
    If scripts are blocked, run once per session:
        Set-ExecutionPolicy -Scope Process Bypass
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string[]]$Target = @('windows'),
    [string]$IdServer = $env:RENDEZVOUS_SERVER,
    [string]$Key = $env:RS_PUB_KEY,
    [string]$Relay = $env:RELAY_SERVER,
    [string]$ApiServer = $env:API_SERVER,
    [string]$Password = $env:UNATTENDED_PASSWORD,
    [switch]$RegenBridge,
    [switch]$Check,
    [Alias('h')]
    [switch]$Help,
    # Anything else: build-client.sh-style --flags, parsed below.
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [object[]]$ShArgs
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message, [int]$Code = 1) {
    Write-Host "error: $Message" -ForegroundColor Red
    exit $Code
}

# Accept the same --flags as build-client.sh, so one command line works for both.
# An unquoted list like `--target windows,android` arrives as an array, so values
# are flattened and split on commas.
if ($ShArgs) {
    $shTargets = @()
    $i = 0
    while ($i -lt $ShArgs.Count) {
        $flag = [string]$ShArgs[$i]
        $takesValue = $flag -in '--target', '-t', '--id-server', '--key', '--relay', '--api-server', '--password'
        if ($takesValue) {
            if ($i + 1 -ge $ShArgs.Count) { Fail "$flag needs a value (see -Help)" 2 }
            $value = @($ShArgs[$i + 1])
            $i += 2
        } else {
            $i += 1
        }
        switch ($flag) {
            { $_ -in '--target', '-t' } { $shTargets += @($value | ForEach-Object { "$_" -split ',' } | Where-Object { $_ }) }
            '--id-server' { $IdServer = [string]$value[0] }
            '--key' { $Key = [string]$value[0] }
            '--relay' { $Relay = [string]$value[0] }
            '--api-server' { $ApiServer = [string]$value[0] }
            '--password' { $Password = [string]$value[0] }
            '--regen-bridge' { $RegenBridge = [switch]$true }
            '--check' { $Check = [switch]$true }
            '--help' { $Help = [switch]$true }
            default { Fail "unexpected argument: $flag (choose targets with -Target or --target; see -Help)" 2 }
        }
    }
    if ($shTargets.Count -gt 0) { $Target = $shTargets }
}

if ($Help) {
    Get-Help $PSCommandPath -Detailed
    exit 0
}

$Here = $PSScriptRoot
$Vendor = Join-Path $Here 'vendor'
$ConfigRs = Join-Path $Vendor 'libs\hbb_common\src\config.rs'
$Dist = Join-Path $Here 'dist'

# Pinned to RustDesk 1.5.0's own bridge job (client/vendor/.github/workflows/bridge.yml).
$FrbVersion = '1.80.1'
$CargoExpandVersion = '1.0.95'

function Need([string]$Command, [string]$For) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Fail "'$Command' is required for target '$For' but was not found"
    }
}

# Run a native command and stop on a non-zero exit code ($ErrorActionPreference
# doesn't cover external programs).
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    if (-not $Exe) { Fail "internal: no program to run for arguments '$($Arguments -join ' ')'" }
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "'$Exe $($Arguments -join ' ')' failed (exit $LASTEXITCODE)" $LASTEXITCODE }
}

$Targets = @($Target | ForEach-Object { "$_" -split ',' } | Where-Object { $_ } | ForEach-Object {
    switch ($_.ToLower()) {
        { $_ -in 'windows', 'win' } { 'windows' }
        'android' { 'android' }
        { $_ -in 'macos', 'mac', 'osx' } { 'macos' }
        { $_ -in 'ios', 'iphone', 'ipad' } { 'ios' }
        'linux' { 'linux' }
        default { Fail "unknown target: $_ (windows|android|macos|ios|linux; see -Help)" 2 }
    }
} | Select-Object -Unique)
$notHere = @($Targets | Where-Object { $_ -in 'macos', 'ios', 'linux' })
if ($notHere.Count -gt 0) {
    Fail ("target(s) $($notHere -join ', ') can't be built on Windows: run client/build-client.sh " +
          'on a Mac (macos, ios) or Linux (linux) machine') 2
}

if (-not $IdServer -or -not $Key) {
    Fail 'set the ID server and key (-IdServer / -Key or RENDEZVOUS_SERVER / RS_PUB_KEY); see -Help' 2
}
$Key = $Key.Trim()
if (-not (Test-Path $ConfigRs)) {
    Fail "vendored client not found at $Vendor (is client\vendor populated?)"
}

# "python" / "python3" on Windows; fall back to the py launcher. Only real
# executables count: an alias or function named python has no path, and the
# Microsoft Store stub in WindowsApps exists without Python being installed.
$Py = $null
$PyArgs = @()
$found = Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -and $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
$launcher = Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($found) {
    $Py = $found.Source
} elseif ($launcher) {
    $Py = $launcher.Source; $PyArgs = @('-3')
} else {
    Fail 'Python 3 is required (python or the py launcher)'
}

$ConfigureArgs = $PyArgs + @(
    (Join-Path $Here 'configure_client.py'), '--config-rs', $ConfigRs,
    '--id-server', $IdServer, '--key', $Key)
# Optional values are passed only when set: Windows PowerShell 5.1 drops empty
# string arguments to native programs, which would leave a flag without a value.
if ($Relay) { $ConfigureArgs += @('--relay', $Relay) }
if ($ApiServer) { $ConfigureArgs += @('--api-server', $ApiServer) }
if ($Password) { $ConfigureArgs += @('--password', $Password) }

if ($Check) {
    Invoke-Native $Py ($ConfigureArgs + '--check')
    exit 0
}

# Short server name for artifact file names, e.g. rd.example.com:31116 -> rd.example.com
$ServerName = ($IdServer -replace '^[a-z]*://', '') -replace '[:/].*$', ''

function Install-VcpkgDeps([string]$Triplet) {
    if (-not $env:VCPKG_ROOT) { Fail 'set VCPKG_ROOT to your vcpkg checkout (see -Help)' }
    Write-Host "==> Installing vcpkg dependencies ($Triplet)"
    Invoke-Native (Join-Path $env:VCPKG_ROOT 'vcpkg.exe') @(
        'install', '--triplet', $Triplet, "--x-install-root=$(Join-Path $env:VCPKG_ROOT 'installed')")
}

# The Rust<->Dart glue (src\bridge_generated*.rs, flutter\lib\generated_bridge*.dart)
# is generated, not vendored; every target needs it to compile.
# When libclang can't find the C headers (stdbool.h, stdint.h), ffigen still
# "succeeds" but mistypes bool/int64_t, and the Dart build fails much later. The
# telltale is a generated `typedef bool = ...` shadowing Dart's bool.
function Test-Bridge {
    (Test-Path .\src\bridge_generated.rs) -and (Test-Path .\flutter\lib\generated_bridge.dart) -and
        -not (Select-String -Path .\flutter\lib\generated_bridge.dart -Pattern '^typedef bool ' -Quiet)
}

function New-Bridge {
    if (-not $RegenBridge -and (Test-Bridge)) { return }
    if (-not (Get-Command flutter_rust_bridge_codegen -ErrorAction SilentlyContinue) -or
        -not (Get-Command cargo-expand -ErrorAction SilentlyContinue)) {
        Fail ("generating the flutter_rust_bridge glue needs flutter_rust_bridge_codegen and cargo-expand:`n" +
              "  cargo install cargo-expand --version $CargoExpandVersion --locked`n" +
              "  cargo install flutter_rust_bridge_codegen --version $FrbVersion --features uuid --locked")
    }
    Need flutter 'bridge'
    Write-Host '==> Generating flutter_rust_bridge glue'
    Push-Location .\flutter
    try { Invoke-Native flutter @('pub', 'get') } finally { Pop-Location }
    Invoke-Native flutter_rust_bridge_codegen @(
        '--rust-input', './src/flutter_ffi.rs',
        '--dart-output', './flutter/lib/generated_bridge.dart',
        '--c-output', './flutter/macos/Runner/bridge_generated.h')
    Copy-Item -Force .\flutter\macos\Runner\bridge_generated.h .\flutter\ios\Runner\bridge_generated.h
    if (-not (Test-Bridge)) { Fail "the generated bridge mistypes bool/int64_t: libclang couldn't find the C headers (stdbool.h, stdint.h)" }
}

# Load the MSVC developer environment (INCLUDE/LIB/LIBPATH) from the Visual
# Studio that actually has the C++ tools. Without it, bindgen's libclang picks the
# newest VS install, which may lack them, and fails on 'stdlib.h' not found.
function Import-MsvcEnv {
    if ($env:INCLUDE) { return }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { Fail 'Visual Studio Installer (vswhere.exe) not found; install the VS 2022 C++ Build Tools' }
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { Fail 'no Visual Studio with the C++ tools (VC.Tools.x86.x64) found; install the VS 2022 C++ Build Tools' }
    Write-Host "==> Using MSVC environment from $vs"
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
    foreach ($line in (& cmd.exe /c "call `"$vcvars`" >nul && set")) {
        if ($line -match '^(INCLUDE|LIB|LIBPATH)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2] }
    }
    if (-not $env:INCLUDE) { Fail "vcvars64.bat from $vs did not set INCLUDE" }
}

function Build-Windows {
    Need flutter windows; Need cargo windows
    Import-MsvcEnv
    Install-VcpkgDeps 'x64-windows-static'
    Write-Host '==> Building Windows client (flutter + cargo)'
    # Recreate the plugin links as this process: Windows refuses to let an elevated
    # build follow links a non-elevated run created ("untrusted mount point").
    $links = '.\flutter\windows\flutter\ephemeral\.plugin_symlinks'
    if (Test-Path $links) { cmd.exe /c rmdir /s /q $links }
    Push-Location .\flutter
    try { Invoke-Native flutter @('pub', 'get') } finally { Pop-Location }
    Invoke-Native $Py ($PyArgs + @('build.py', '--portable', '--flutter', '--skip-portable-pack'))

    Write-Host '==> Packing single-file portable exe'
    if (Test-Path .\rustdesk) { Remove-Item -Recurse -Force .\rustdesk }
    Copy-Item -Recurse .\flutter\build\windows\x64\runner\Release .\rustdesk
    Push-Location .\libs\portable
    try {
        Invoke-Native $Py ($PyArgs + @('-m', 'pip', 'install', '-r', 'requirements.txt'))
        Invoke-Native $Py ($PyArgs + @('.\generate.py', '-f', '..\..\rustdesk\', '-o', '.', '-e', '..\..\rustdesk\rustdesk.exe'))
    } finally { Pop-Location }

    $exeName = "russdesk-$ServerName-windows-x64.exe"
    Copy-Item -Force .\target\release\rustdesk-portable-packer.exe (Join-Path $Dist $exeName)
    $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $Dist $exeName)).Hash.ToLower()
    # sha256sum format, so `sha256sum -c` works too.
    Set-Content -Encoding ascii -Path (Join-Path $Dist 'SHA256SUMS-windows.txt') -Value "$hash *$exeName"
}

function Build-Android {
    Need flutter android; Need cargo android; Need cargo-ndk android; Need bash android
    if (-not $env:ANDROID_NDK_HOME) { Fail 'set ANDROID_NDK_HOME to your Android NDK (r28c)' }
    if (-not $env:VCPKG_ROOT) { Fail 'set VCPKG_ROOT to your vcpkg checkout (see -Help)' }
    $sysroot = Join-Path $env:ANDROID_NDK_HOME 'toolchains\llvm\prebuilt\windows-x86_64\sysroot\usr\lib'
    $abis = @(
        @{ Abi = 'arm64-v8a'; Triple = 'aarch64-linux-android'; LibCxx = 'aarch64-linux-android' },
        @{ Abi = 'armeabi-v7a'; Triple = 'armv7-linux-androideabi'; LibCxx = 'arm-linux-androideabi' })
    foreach ($a in $abis) {
        Write-Host "==> Building Android $($a.Abi) (vcpkg + cargo ndk)"
        Invoke-Native bash @('flutter/build_android_deps.sh', $a.Abi)
        if (Get-Command rustup -ErrorAction SilentlyContinue) { Invoke-Native rustup @('target', 'add', $a.Triple) }
        Invoke-Native cargo @('ndk', '--platform', '21', '--target', $a.Triple, 'build', '--locked', '--release', '--features', 'flutter,hwcodec')
        $jni = ".\flutter\android\app\src\main\jniLibs\$($a.Abi)"
        New-Item -ItemType Directory -Force -Path $jni | Out-Null
        Copy-Item -Force (Join-Path $sysroot "$($a.LibCxx)\libc++_shared.so") $jni
        Copy-Item -Force ".\target\$($a.Triple)\release\liblibrustdesk.so" (Join-Path $jni 'librustdesk.so')
    }
    # Without a release keystore (flutter\android\key.properties), sign with the
    # debug key like RustDesk's CI does, so the APK still installs.
    $gradle = '.\flutter\android\app\build.gradle'
    $original = $null
    if (-not (Test-Path .\flutter\android\key.properties)) {
        $original = [IO.File]::ReadAllText((Resolve-Path $gradle))
        [IO.File]::WriteAllText((Resolve-Path $gradle), $original.Replace('signingConfigs.release', 'signingConfigs.debug'))
    }
    try {
        Write-Host '==> Building APKs'
        Push-Location .\flutter
        try {
            Invoke-Native flutter @('pub', 'get')
            Invoke-Native flutter @('build', 'apk', '--release', '--target-platform', 'android-arm64,android-arm', '--split-per-abi')
        } finally { Pop-Location }
    } finally {
        if ($null -ne $original) { [IO.File]::WriteAllText((Resolve-Path $gradle), $original) }
    }
    foreach ($a in $abis) {
        Copy-Item -Force ".\flutter\build\app\outputs\flutter-apk\app-$($a.Abi)-release.apk" `
            (Join-Path $Dist "russdesk-$ServerName-android-$($a.Abi).apk")
    }
}

Write-Host '==> Baking server config into the client source'
# Start from a clean config.rs when this is a git checkout, so each build is
# reproducible regardless of a previous run.
if (Get-Command git -ErrorAction SilentlyContinue) {
    & git -C $Vendor rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -eq 0) { & git -C $Vendor checkout -- libs/hbb_common/src/config.rs *> $null }
}
Invoke-Native $Py $ConfigureArgs

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
Push-Location $Vendor
try {
    # The bridge generator's libclang needs the MSVC/Windows SDK headers too.
    Import-MsvcEnv
    New-Bridge
    foreach ($t in $Targets) {
        switch ($t) {
            'windows' { Build-Windows }
            'android' { Build-Android }
        }
    }
} finally {
    Pop-Location
}

Write-Host "==> Done. Artifacts in: $Dist"
Get-ChildItem $Dist | Format-Table Name, Length, LastWriteTime -AutoSize
Write-Host ''
Write-Host 'Baked configuration:'
Write-Host "  ID server : $IdServer"
Write-Host "  Relay     : $(if ($Relay) { $Relay } else { '<provided by hbbs at connect time>' })"
Write-Host "  API server: $(if ($ApiServer) { $ApiServer } else { '<derived from ID server>' })"
Write-Host "  Key       : $($Key.Substring(0, [Math]::Min(12, $Key.Length)))..."
if ($Password) {
    Write-Host '  Unattended: yes (shared permanent password, hash only)'
} else {
    Write-Host '  Unattended: no (remote user must accept)'
}
