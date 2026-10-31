<#
.SYNOPSIS
    Deploy the rp edge security gateway to a Raspberry Pi from Windows (or any
    machine with PowerShell 7 and OpenSSH).

.DESCRIPTION
    Detects the device architecture over SSH, obtains a matching archive
    (a SHA256-verified GitHub release, a local build, or a given file), copies
    it to the device together with install.sh and runs the installer there.

.EXAMPLE
    ./install.ps1 -Target pi@raspberrypi.local
    ./install.ps1 -Target pi@raspberrypi.local -Version v0.1.0
    ./install.ps1 -Target pi@raspberrypi.local -FromSource
    ./install.ps1 -Target pi@raspberrypi.local -Uninstall -Purge
    ./install.ps1 -Target pi@raspberrypi.local -Triple armv7-unknown-linux-gnueabihf -DryRun
#>
[CmdletBinding()]
param(
    # SSH destination, USER@HOST.
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$|^[A-Za-z0-9._:-]+$')]
    [string] $Target,

    # Release tag (vX.Y.Z) or 'latest'.
    [ValidatePattern('^(latest|v\d+\.\d+\.\d+([-.][A-Za-z0-9.]+)?)$')]
    [string] $Version = 'latest',

    # Build with cargo-zigbuild instead of downloading a release.
    [switch] $FromSource,

    # Install a local rp-<triple>.tar.gz.
    [string] $Archive,

    # GitHub repository OWNER/NAME.
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string] $Repo = $(if ($env:RP_REPO) { $env:RP_REPO } else { 'Jest-Test-Team/rp_app' }),

    # Release download base (mirror or file:///path); default GitHub.
    [string] $BaseUrl = $env:RP_BASE_URL,

    # Rust target triple; detected over SSH when omitted.
    [ValidateSet('armv7-unknown-linux-gnueabihf', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu')]
    [string] $Triple,

    # Binary prefix on the device.
    [ValidatePattern('^/[A-Za-z0-9/_.-]*$')]
    [string] $Prefix = '/usr/local',

    [switch] $Uninstall,
    [switch] $Purge,
    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string] $Message) { Write-Host "==> $Message" }

function Invoke-Step {
    param([string] $Description, [scriptblock] $Action)
    if ($DryRun) { Write-Host "would: $Description"; return }
    & $Action
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "failed ($LASTEXITCODE): $Description" }
}

function Get-TripleForArch([string] $Arch) {
    switch -Regex ($Arch.Trim()) {
        '^(armv7l|armv7|armhf)$' { 'armv7-unknown-linux-gnueabihf'; break }
        '^(aarch64|arm64)$' { 'aarch64-unknown-linux-gnu'; break }
        '^(x86_64|amd64)$' { 'x86_64-unknown-linux-gnu'; break }
        '^armv6l$' { throw 'ARMv6 (Pi 1 / Zero) is not supported' }
        default { throw "unsupported architecture '$Arch'" }
    }
}

function Get-ReleaseUrl([string] $File) {
    if ($BaseUrl) {
        return "$($BaseUrl.TrimEnd('/'))/$Version/$File"
    }
    if ($Version -eq 'latest') { return "https://github.com/$Repo/releases/latest/download/$File" }
    return "https://github.com/$Repo/releases/download/$Version/$File"
}

function Save-Url([string] $Url, [string] $Destination) {
    if ($Url -like 'file://*') {
        Copy-Item -LiteralPath ([Uri] $Url).LocalPath -Destination $Destination
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    }
}

function Get-ReleaseArchive([string] $TargetTriple, [string] $WorkDir) {
    $file = "rp-$TargetTriple.tar.gz"
    $url = Get-ReleaseUrl $file
    $sumsUrl = Get-ReleaseUrl 'SHA256SUMS'
    if ($DryRun) {
        Write-Host "would: download $url"
        Write-Host "would: verify against $sumsUrl"
        return (Join-Path $WorkDir $file)
    }
    Write-Step "downloading $url"
    $dest = Join-Path $WorkDir $file
    $sums = Join-Path $WorkDir 'SHA256SUMS'
    Save-Url $url $dest
    Save-Url $sumsUrl $sums
    $line = Get-Content $sums | Where-Object { ($_ -split '\s+')[1] -in @($file, "*$file") } | Select-Object -First 1
    if (-not $line) { throw "$file is not listed in SHA256SUMS" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "checksum mismatch for $file (expected $expected, got $actual)" }
    Write-Step 'checksum OK'
    return $dest
}

function New-SourceArchive([string] $TargetTriple, [string] $WorkDir) {
    $src = Split-Path -Parent $PSScriptRoot
    foreach ($tool in 'cargo', 'cargo-zigbuild', 'zig', 'tar') {
        if (-not $DryRun -and -not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool not found; -FromSource needs Rust, cargo-zigbuild and zig"
        }
    }
    Invoke-Step "cargo zigbuild --release --locked --target $TargetTriple" {
        cargo zigbuild --release --locked --manifest-path (Join-Path $src 'Cargo.toml') --target $TargetTriple
    }
    $name = "rp-$TargetTriple"
    $out = Join-Path $WorkDir "$name.tar.gz"
    if ($DryRun) { return $out }
    $stage = Join-Path $WorkDir $name
    New-Item -ItemType Directory -Force -Path (Join-Path $stage 'bin'), (Join-Path $stage 'configs') | Out-Null
    foreach ($bin in 'rpctl', 'rp-dns', 'rp-agent', 'rp-mcp') {
        Copy-Item (Join-Path $src "target/$TargetTriple/release/$bin") (Join-Path $stage 'bin/')
    }
    Copy-Item (Join-Path $src 'configs/rp.example.toml') (Join-Path $stage 'configs/')
    Copy-Item (Join-Path $src 'deploy/install.sh') $stage
    tar -C $WorkDir -czf $out $name
    if ($LASTEXITCODE -ne 0) { throw 'tar failed' }
    return $out
}

function Get-InstallScript([string] $WorkDir) {
    $local = Join-Path $PSScriptRoot 'install.sh'
    if (Test-Path $local) { return $local }
    $dest = Join-Path $WorkDir 'install.sh'
    if ($DryRun) { Write-Host "would: download $(Get-ReleaseUrl 'install.sh')"; return $dest }
    Save-Url (Get-ReleaseUrl 'install.sh') $dest
    return $dest
}

foreach ($tool in 'ssh', 'scp') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found; enable the Windows OpenSSH client (Settings > Optional features)"
    }
}
if ($FromSource -and $Archive) { throw '-FromSource and -Archive are mutually exclusive' }

$work = Join-Path ([IO.Path]::GetTempPath()) ("rp-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $installer = Get-InstallScript $work

    if ($Uninstall) {
        $flags = if ($Purge) { '--uninstall --purge' } else { '--uninstall' }
        Invoke-Step "scp install.sh to ${Target}:/tmp/ and run it with $flags" {
            scp -q $installer "${Target}:/tmp/rp-install.sh"
            ssh -t $Target "sudo bash /tmp/rp-install.sh $flags; rm -f /tmp/rp-install.sh"
        }
        return
    }

    if (-not $Triple) {
        $arch = ssh $Target 'uname -m'
        if ($LASTEXITCODE -ne 0) { throw "cannot reach $Target over ssh" }
        $Triple = Get-TripleForArch $arch
    }
    Write-Step "device $Target target: $Triple"

    $pkg = if ($Archive) {
        if (-not (Test-Path -LiteralPath $Archive)) { throw "archive not found: $Archive" }
        (Resolve-Path -LiteralPath $Archive).Path
    } elseif ($FromSource) {
        New-SourceArchive $Triple $work
    } else {
        Get-ReleaseArchive $Triple $work
    }

    $remotePkg = "/tmp/$(Split-Path -Leaf $pkg)"
    Invoke-Step "scp $(Split-Path -Leaf $pkg) and install.sh to ${Target}:/tmp/" {
        scp -q $pkg $installer "${Target}:/tmp/"
    }
    Invoke-Step "ssh $Target sudo bash /tmp/install.sh --archive $remotePkg --prefix $Prefix" {
        ssh -t $Target "sudo bash /tmp/install.sh --archive '$remotePkg' --prefix '$Prefix' && rm -f '$remotePkg' /tmp/install.sh"
    }
    Write-Step 'done — next: ssh to the device and run: sudo rpctl preflight base'
}
finally {
    Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
}
