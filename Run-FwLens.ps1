# fwlens runner
# Usage:
#   .\Run-FwLens.ps1 analyze
#   .\Run-FwLens.ps1 report
#   .\Run-FwLens.ps1 export
#   .\Run-FwLens.ps1 diff-breach --from-json main.json --to-json feature.json
#   .\Run-FwLens.ps1 call-graph --function sarReturnDataPacket --direction callers
#   .\Run-FwLens.ps1 debug-parse
#   .\Run-FwLens.ps1 analyze --config path\to\fwlens_config.yaml
#
# The default config name is fwlens_config.yaml.  The script looks for it first
# in the working directory (pwd), then next to the script itself.  Run from
# whichever directory contains the config -- no need to pass --config explicitly.
#
# If no virtual environment exists yet (.venv), setup.ps1 is run automatically
# first -- no need to run it separately before the first use.
#
# Pass -NoClean to skip the .pyc cache purge (faster, but risks stale bytecode).

param(
    [Parameter(Position=0)]
    [string]$Command = "analyze",

    [string]$Config = "fwlens_config.yaml",

    [switch]$OpenReport,

    [switch]$NoClean,

    # All remaining arguments are passed through to main.py unchanged.
    # This allows dump-ast options (--file, --var, --fn, --depth) and any
    # future command-specific flags without needing to declare them here.
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$PassThru = @()
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Clear .pyc cache before every run unless suppressed.
# Prevents stale bytecode from masking file changes -- the main cause of
# "I replaced the file but nothing changed" bugs.
if (-not $NoClean) {
    $pycFiles = Get-ChildItem -Path $ScriptDir -Recurse -Filter "*.pyc" -ErrorAction SilentlyContinue
    $count = ($pycFiles | Measure-Object).Count
    if ($count -gt 0) {
        $pycFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "[fwlens] Cleared $count stale .pyc file(s)  (-NoClean to skip)" -ForegroundColor DarkGray
    }
}

# Resolve config first (before venv activation/setup) so that if setup.ps1 needs
# to run, it can validate libclang against the config actually being used --
# not some unrelated config.yaml that happens to sit next to the script.
# For a relative path: try the working directory first, then next to the script.
# This means you can run from wherever the config lives without needing --config.
$ResolvedConfig = $Config
if (-not [System.IO.Path]::IsPathRooted($ResolvedConfig)) {
    $fromPwd    = Join-Path (Get-Location) $ResolvedConfig
    $fromScript = Join-Path $ScriptDir $ResolvedConfig
    if (Test-Path $fromPwd) {
        $ResolvedConfig = $fromPwd
    } elseif (Test-Path $fromScript) {
        $ResolvedConfig = $fromScript
    } else {
        $ResolvedConfig = $fromPwd  # let the error below report the pwd-relative path
    }
}
if (-not (Test-Path $ResolvedConfig)) {
    Write-Host "[fwlens] ERROR: Config file not found: $ResolvedConfig" -ForegroundColor Red
    Write-Host "[fwlens]        Looked in: $(Get-Location) and $ScriptDir" -ForegroundColor Red
    exit 1
}
$Config = $ResolvedConfig

# Activate venv -- bootstrap by running setup.ps1 automatically if it's missing,
# rather than making the user run a separate command first.
$activateScript = Join-Path $ScriptDir ".venv\Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    $setupScript = Join-Path $ScriptDir "setup.ps1"
    if (-not (Test-Path $setupScript)) {
        Write-Host "[fwlens] ERROR: Virtual environment not found, and setup.ps1 is missing too." -ForegroundColor Red
        Write-Host "[fwlens]        Expected it at: $setupScript" -ForegroundColor Red
        exit 1
    }
    Write-Host "[fwlens] Virtual environment not found -- running setup.ps1 first..." -ForegroundColor Yellow
    & $setupScript -ConfigPath $Config
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fwlens] ERROR: setup.ps1 failed -- see output above." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path $activateScript)) {
        Write-Host "[fwlens] ERROR: setup.ps1 ran but the virtual environment still wasn't created at $activateScript" -ForegroundColor Red
        exit 1
    }
    Write-Host "[fwlens] Setup complete -- continuing with $Command..." -ForegroundColor Green
}
& $activateScript

# Run
$mainScript = Join-Path $ScriptDir "main.py"
python $mainScript $Command --config $Config @PassThru

$exitCode = $LASTEXITCODE

if ($exitCode -eq 0 -and ($Command -eq "report" -or $OpenReport)) {
    $reportDir = Join-Path (Split-Path $Config -Parent) "output\reports"
    $report    = Join-Path $reportDir "fwlens_report.html"
    if (Test-Path $report) {
        Start-Process $report
    }
}

exit $exitCode
