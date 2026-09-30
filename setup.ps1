# fwlens setup script
# Run once from the fwlens directory: .\setup.ps1
# Also run automatically by Run-FwLens.ps1 the first time it's used, if no
# virtual environment exists yet.

param(
    # Path to the config.yaml to validate libclang_path against. Defaults to
    # config.yaml next to this script if not given (standalone-run case).
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[fwlens] Setting up environment..." -ForegroundColor Cyan

# Python check
$pythonCmd = $null
foreach ($cmd in @("python", "python3")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 9) {
                $pythonCmd = $cmd
                Write-Host "[fwlens] Found $ver" -ForegroundColor Green
                break
            }
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "[fwlens] ERROR: Python 3.9+ not found on PATH." -ForegroundColor Red
    exit 1
}

# Create venv
$venvPath = Join-Path $ScriptDir ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host "[fwlens] Creating virtual environment..." -ForegroundColor Cyan
    & $pythonCmd -m venv $venvPath
} else {
    Write-Host "[fwlens] Virtual environment already exists." -ForegroundColor Yellow
}

# Activate
$activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Host "[fwlens] ERROR: venv activation script not found at $activateScript" -ForegroundColor Red
    exit 1
}
& $activateScript

# Install deps
Write-Host "[fwlens] Installing dependencies..." -ForegroundColor Cyan
$reqFile = Join-Path $ScriptDir "requirements.txt"
pip install -r $reqFile --quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "[fwlens] ERROR: pip install failed." -ForegroundColor Red
    exit 1
}

Write-Host "[fwlens] Dependencies installed." -ForegroundColor Green

# Validate libclang
Write-Host "[fwlens] Validating libclang..." -ForegroundColor Cyan
if ($ConfigPath -ne "") {
    $configFile = $ConfigPath
} else {
    $configFile = Join-Path $ScriptDir "config.yaml"
}
if (Test-Path $configFile) {
    $clangCheck = python -c @"
import yaml, ctypes, sys, pathlib
with open(r'$configFile') as f:
    cfg = yaml.safe_load(f)
clang_path = cfg.get('tool', {}).get('libclang_path', '')
if clang_path:
    p = pathlib.Path(clang_path)
    if p.exists():
        try:
            ctypes.CDLL(str(p))
            print('OK:' + str(p))
        except Exception as e:
            print('FAIL:' + str(e))
    else:
        print('NOTFOUND:' + str(p))
else:
    print('NOTSET:')
"@
    if ($clangCheck -match "^OK:(.+)") {
        Write-Host "[fwlens] libclang found: $($Matches[1])" -ForegroundColor Green
    } elseif ($clangCheck -match "^NOTFOUND:(.+)") {
        Write-Host "[fwlens] WARNING: libclang_path set in config.yaml but file not found: $($Matches[1])" -ForegroundColor Yellow
        Write-Host "[fwlens]   Install LLVM from https://github.com/llvm/llvm-project/releases" -ForegroundColor Yellow
        Write-Host "[fwlens]   Then update tool.libclang_path in config.yaml" -ForegroundColor Yellow
    } elseif ($clangCheck -match "^NOTSET:") {
        Write-Host "[fwlens] WARNING: tool.libclang_path not set in config.yaml" -ForegroundColor Yellow
        Write-Host "[fwlens]   Set it to the full path of libclang.dll, e.g.:" -ForegroundColor Yellow
        Write-Host "[fwlens]   tool:" -ForegroundColor Yellow
        Write-Host "[fwlens]     libclang_path: C:\LLVM\bin\libclang.dll" -ForegroundColor Yellow
    } else {
        Write-Host "[fwlens] WARNING: libclang validation issue: $clangCheck" -ForegroundColor Yellow
    }
} else {
    Write-Host "[fwlens] WARNING: config.yaml not found -- copy config.example.yaml to config.yaml and edit it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[fwlens] Setup complete." -ForegroundColor Green
Write-Host "[fwlens] Run analysis with: .\Run-FwLens.ps1 analyze" -ForegroundColor Cyan
Write-Host "[fwlens] Run report with:   .\Run-FwLens.ps1 report" -ForegroundColor Cyan

# Explicit success exit code -- otherwise $LASTEXITCODE after `& setup.ps1` from
# Run-FwLens.ps1 would reflect whatever external command last happened to run
# (e.g. the libclang check's python -c), not necessarily 0 on true success.
exit 0
