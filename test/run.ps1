<#
.SYNOPSIS
    Run Robot Framework suites from PowerShell (used by the Windows CI job).
.EXAMPLE
    ./test/run.ps1              # PowerShell installer suites (tag: pwsh)
    ./test/run.ps1 -Tags static,unit
#>
param([string[]] $Tags = @('pwsh'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$venv = Join-Path $PSScriptRoot '.venv'
$py = if ($IsWindows) { Join-Path $venv 'Scripts/python.exe' } else { Join-Path $venv 'bin/python' }
if (-not (Test-Path $py)) {
    $base = if (Get-Command python3 -ErrorAction SilentlyContinue) { 'python3' } else { 'python' }
    & $base -m venv $venv
    & $py -m pip install -q -r (Join-Path $PSScriptRoot 'requirements.txt')
}

$robotArgs = @('-m', 'robot', '--outputdir', (Join-Path $PSScriptRoot 'results'), '--runemptysuite',
    '--exclude', 'perf', '--exclude', 'requires-pi', '--exclude', 'requires-root')
foreach ($t in $Tags) { $robotArgs += @('--include', $t) }
& $py @robotArgs (Join-Path $PSScriptRoot 'suites')
exit $LASTEXITCODE
