# batch_ghidra_ingest.ps1
# Batch ingest test binaries via Ghidra headless + FKS ingestion
# Usage: .\batch_ghidra_ingest.ps1

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"

# All binaries available for re-export with their FKS family names
$binaries = @(
    # stress/ directory
    @{ Name="ntdll.dll";     Family="ntdll";     Compiler="msvc"; Version="10.0.19041"; Dir="stress" },
    @{ Name="user32.dll";    Family="user32";    Compiler="msvc"; Version="10.0.19041"; Dir="stress" },
    @{ Name="shell32.dll";   Family="shell32";   Compiler="msvc"; Version="10.0.19041"; Dir="stress" },
    @{ Name="d2d1.dll";      Family="d2d1";      Compiler="msvc"; Version="10.0.19041"; Dir="stress" },
    @{ Name="mshtml.dll";    Family="mshtml";    Compiler="msvc"; Version="10.0.19041"; Dir="stress" },
    @{ Name="ntoskrnl.exe";  Family="ntoskrnl";  Compiler="msvc"; Version="10.0.19041"; Dir="stress" }
)

# Create directories
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
New-Item -ItemType Directory -Path $ghidraProj -Force | Out-Null

$successCount = 0
$failCount = 0

foreach ($bin in $binaries) {
    $name = $bin.Name
    $family = $bin.Family
    $srcPath = "$enigmaRoot\test_binaries\$($bin.Dir)\$name"
    $outLib = "$fksDir\${family}_ghidra.fkslib"
    $outJson = "$exportDir\${family}_export.json"

    if (!(Test-Path $srcPath)) {
        Write-Host "SKIP: $name not found at $srcPath" -ForegroundColor Yellow
        continue
    }

    Write-Host ""
    Write-Host "=== Processing $name ===" -ForegroundColor Cyan

    # Step 1: Ghidra headless export
    $env:ENIGMA_GHIDRA_OUTPUT = $outJson

    Write-Host "  [1/2] Running Ghidra headless analysis..."
    $ghidraArgs = @(
        "$ghidraProj", "EnigmaFKS_$family",
        "-import", $srcPath,
        "-postScript", "EnigmaExportFidMatches.java",
        "-scriptPath", $ghidraScript,
        "-readOnly", "-deleteProject"
    )

    $ghidraOutput = & "$ghidraRoot\support\analyzeHeadless.bat" @ghidraArgs 2>&1
    $ghidraExit = $LASTEXITCODE

    if ($ghidraExit -ne 0 -or !(Test-Path $outJson)) {
        Write-Host "  FAIL: Ghidra export failed for $name" -ForegroundColor Red
        $failCount++
        continue
    }

    $jsonSize = [math]::Round((Get-Item $outJson).Length / 1024, 1)
    Write-Host "  Exported: ${jsonSize}KB"

    # Step 2: Create FKS library
    Write-Host "  [2/2] Creating FKS library..."
    & $ingestTool $outJson $outLib --family $family --compiler $bin.Compiler --version $bin.Version 2>&1 | Out-Null

    if (!(Test-Path $outLib)) {
        Write-Host "  FAIL: FKS library creation failed" -ForegroundColor Red
        $failCount++
        continue
    }

    $libSize = [math]::Round((Get-Item $outLib).Length / 1024, 1)
    Write-Host "  Created: ${libSize}KB"
    $successCount++
}

# Step 3: Rebuild LMDB index
Write-Host ""
Write-Host "=== Rebuilding LMDB index ===" -ForegroundColor Cyan
& "$enigmaRoot\build\enigma_fks_build_index.exe" $fksDir 2>&1

Write-Host ""
Write-Host "=== Done: $successCount succeeded, $failCount failed ===" -ForegroundColor Green
