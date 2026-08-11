# Build script for Enigma Engine GUI.
# Usage:
#   powershell -File tools\build_enigma.ps1              # build + test + deploy
#   powershell -File tools\build_enigma.ps1 -SkipTests   # build + deploy only
#   powershell -File tools\build_enigma.ps1 -RunOnly     # launch only (no build)
#   powershell -File tools\build_enigma.ps1 -Kill        # stop any running instance
param(
    [switch]$SkipTests,
    [switch]$RunOnly,
    [switch]$Kill,
    [string]$Binary = "notepad_test.exe"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$BuildDir = Join-Path $Root "build"
$DistDir  = Join-Path $Root "dist"

# Stop any running instance first.
Get-Process -Name "enigma_gui" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

if ($Kill) { Write-Host "[*] Running instances stopped."; exit 0 }

if (-not $RunOnly) {
    Write-Host "[*] Building enigma_gui..."
    cmake --build $BuildDir --target enigma_gui 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host "[!] BUILD FAILED" -ForegroundColor Red; exit 1 }

    if (-not $SkipTests) {
        Write-Host "[*] Running CTest..."
        Push-Location $BuildDir
        ctest 2>&1
        $code = $LASTEXITCODE
        Pop-Location
        if ($code -ne 0) { Write-Host "[!] TESTS FAILED ($code)" -ForegroundColor Red; exit $code }
    }

    Write-Host "[*] Deploying to dist..."
    Copy-Item (Join-Path $BuildDir "enigma_gui.exe") (Join-Path $DistDir "enigma_gui.exe") -Force
}

$exe = Join-Path $DistDir "enigma_gui.exe"
if (-not (Test-Path $exe)) { Write-Host "[!] $exe not found" -ForegroundColor Red; exit 1 }

Write-Host "[*] Launching $Binary..."
$p = Start-Process -FilePath $exe -ArgumentList $Binary -WorkingDirectory $DistDir -PassThru
Start-Sleep -Seconds 8
if (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Running (pid=$($p.Id))" -ForegroundColor Green
} else {
    Write-Host "[!] Process exited unexpectedly" -ForegroundColor Red
    exit 1
}
