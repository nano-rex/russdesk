<#
.SYNOPSIS
    Build a RustDesk client with your self-hosted RussDesk server baked in (Windows).

.DESCRIPTION
    PowerShell equivalent of client/build-client.sh. It bakes the ID server,
    relay server, public key and (optionally) a shared unattended password into
    the vendored client source (via configure_client.py), then runs the real
    RustDesk build so the resulting .exe connects to your server with no manual
    Settings -> Network step. Artifacts are copied to client\dist\.

    The toolchain is NOT installed by this script; it must already be present,
    as RustDesk's own build needs (versions match .github/workflows/build-client.yml):
      - Rust 1.75 (x86_64-pc-windows-msvc) and Visual Studio 2022 C++ build tools
      - Flutter 3.24.5
      - Python 3
      - vcpkg with: vcpkg install --triplet x64-windows-static libvpx libyuv opus aom
        and VCPKG_ROOT pointing at it
      - android target only: Java 17, Android NDK r28c (ANDROID_NDK_HOME), cargo-ndk

    Where to get the values: RussDesk console -> Settings -> General,
    or GET /api/admin/client-config.

.PARAMETER Target
    windows (default): single-file portable russdesk-<host>-windows-x64.exe + SHA256SUMS.txt
    android: arm64-v8a + armeabi-v7a release APKs

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

.PARAMETER Check
    Validate and show the config.rs changes, then exit without building.

.PARAMETER Help
    Show this help and exit.

.EXAMPLE
    .\client\build-client.ps1 -IdServer rd.example.com:31116 -Key (Get-Content id_ed25519.pub)

.EXAMPLE
    .\client\build-client.ps1 -IdServer rd.example.com:31116 -Key 'KEY=' -Password 'a-strong-shared-secret'

.EXAMPLE
    $env:RENDEZVOUS_SERVER = 'rd.example.com:31116'; $env:RS_PUB_KEY = 'KEY='
    .\client\build-client.ps1 -Check

.NOTES
    If scripts are blocked, run once per session:
        Set-ExecutionPolicy -Scope Process Bypass
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('windows', 'android')]
    [string]$Target = 'windows',
    [string]$IdServer = $env:RENDEZVOUS_SERVER,
    [string]$Key = $env:RS_PUB_KEY,
    [string]$Relay = $env:RELAY_SERVER,
    [string]$ApiServer = $env:API_SERVER,
    [string]$Password = $env:UNATTENDED_PASSWORD,
    [switch]$Check,
    [Alias('h')]
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

if ($Help) {
    Get-Help $PSCommandPath -Detailed
    exit 0
}

$Here = $PSScriptRoot
$Vendor = Join-Path $Here 'vendor'
$ConfigRs = Join-Path $Vendor 'libs\hbb_common\src\config.rs'
$Dist = Join-Path $Here 'dist'

function Fail([string]$Message, [int]$Code = 1) {
    Write-Host "error: $Message" -ForegroundColor Red
    exit $Code
}

function Need([string]$Command) {
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Fail "'$Command' is required for target '$Target' but was not found"
    }
}

# Run a native command and stop on a non-zero exit code ($ErrorActionPreference
# doesn't cover external programs).
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { Fail "'$Exe $($Arguments -join ' ')' failed (exit $LASTEXITCODE)" $LASTEXITCODE }
}

if (-not $IdServer -or -not $Key) {
    Fail 'set the ID server and key (-IdServer / -Key or RENDEZVOUS_SERVER / RS_PUB_KEY); see -Help' 2
}
$Key = $Key.Trim()
if (-not (Test-Path $ConfigRs)) {
    Fail "vendored client not found at $Vendor (is client\vendor populated?)"
}

# "python" on Windows; fall back to the py launcher. Skip the Microsoft Store
# stub in WindowsApps, which exists without Python being installed.
$Py = $null
$PyArgs = @()
$found = Get-Command python -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
if ($found) {
    $Py = $found.Source
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $Py = 'py'; $PyArgs = @('-3')
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
    switch ($Target) {
        'windows' {
            Need flutter; Need cargo
            if (-not $env:VCPKG_ROOT) {
                Fail 'set VCPKG_ROOT to a vcpkg with: vcpkg install --triplet x64-windows-static libvpx libyuv opus aom'
            }
            Write-Host '==> Building Windows client (flutter + cargo)'
            Invoke-Native flutter @('pub', 'get')
            Invoke-Native $Py ($PyArgs + @('build.py', '--portable', '--flutter', '--skip-portable-pack'))

            Write-Host '==> Packing single-file portable exe'
            if (Test-Path .\rustdesk) { Remove-Item -Recurse -Force .\rustdesk }
            Copy-Item -Recurse .\flutter\build\windows\x64\runner\Release .\rustdesk
            Push-Location .\libs\portable
            try {
                Invoke-Native $Py ($PyArgs + @('-m', 'pip', 'install', '-r', 'requirements.txt'))
                Invoke-Native $Py ($PyArgs + @('.\generate.py', '-f', '..\..\rustdesk\', '-o', '.', '-e', '..\..\rustdesk\rustdesk.exe'))
            } finally { Pop-Location }

            $hostName = ($IdServer -replace '^[a-z]*://', '') -replace '[:/].*$', ''
            $exeName = "russdesk-$hostName-windows-x64.exe"
            Copy-Item -Force .\target\release\rustdesk-portable-packer.exe (Join-Path $Dist $exeName)
            $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $Dist $exeName)).Hash.ToLower()
            # sha256sum format, so `sha256sum -c SHA256SUMS.txt` works too.
            Set-Content -Encoding ascii -Path (Join-Path $Dist 'SHA256SUMS.txt') -Value "$hash *$exeName"
        }
        'android' {
            Need flutter; Need cargo-ndk; Need bash
            if (-not $env:ANDROID_NDK_HOME) { Fail 'set ANDROID_NDK_HOME to your Android NDK' }
            Write-Host '==> Building Rust jniLibs + APK (arm64, arm)'
            # RustDesk's Android build scripts are bash; this needs Git Bash/MSYS on PATH.
            Invoke-Native bash @('flutter/build_android_deps.sh', 'arm64-v8a', 'armeabi-v7a')
            Push-Location .\flutter
            try {
                Invoke-Native flutter @('pub', 'get')
                Invoke-Native bash @('build_android.sh')
            } finally { Pop-Location }
            Get-ChildItem -Recurse -Path .\flutter\build\app\outputs -Filter 'app-*-release.apk' |
                Copy-Item -Destination $Dist
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
