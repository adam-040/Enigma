# batch_optimized_ghidra_export.ps1
# Optimized Ghidra export: batch-imports multiple DLLs in a single headless session
# to share startup cost (~4s per session saved), then ingests each into FKS.
#
# Usage:
#   .\batch_optimized_ghidra_export.ps1 -Dlls @("C:\Windows\System32\foo.dll", ...) -Family "foo"
#
# The export script auto-names output as <family>_export.json.

param(
    [array]$Dlls = @(),
    [array]$Families = @(),
    [int]$TimeoutSec = 900,
    [string]$WaveName = "Optimized Batch"
)

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"
$logFile = "$enigmaRoot\build\optimized_batch.log"

New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

$ok = 0; $skip = 0; $fail = 0

Write-Host "=== $WaveName ($($Dlls.Count) DLLs) ===" -ForegroundColor Cyan
$startTime = Get-Date

# Separate into new vs existing
$toProcess = @()
for ($i = 0; $i -lt $Dlls.Count; $i++) {
    $family = $Families[$i]
    $srcPath = $Dlls[$i]
    $outLib = "$fksDir\${family}_ghidra.fkslib"

    if ((Test-Path $outLib) -and ((Get-Item $outLib).Length -gt 500)) {
        $skip++
        Write-Host "  SKIP: $family already exists" -ForegroundColor DarkGray
    } else {
        $toProcess += @{ Family=$family; SrcPath=$srcPath }
    }
}

if ($toProcess.Count -eq 0) {
    Write-Host "  All $($Dlls.Count) already exist. Nothing to do." -ForegroundColor Green
    return
}

# Pre-clean old JSON files
# Ghidra script outputs <dll_basename>_export.json (from currentProgram.getName())
$importMapping = @{}
foreach ($item in $toProcess) {
    $binName = [System.IO.Path]::GetFileNameWithoutExtension($item.SrcPath)
    $outJson = "$exportDir\${binName}_export.json"
    Remove-Item $outJson -ErrorAction SilentlyContinue
    $importMapping[$item.Family] = @{ Path=$outJson; BinName=$binName }
}

# Run single Ghidra session for ALL DLLs (auto-naming via env dir)
Write-Host "  [Ghidra] Batch importing $($toProcess.Count) DLLs..." -NoNewline
$env:ENIGMA_GHIDRA_OUTPUT = "$exportDir\"

$ghidraArgs = @(
    "$ghidraProj", "EnigmaFKS_Batch",
    "-import"
)
foreach ($item in $toProcess) {
    $ghidraArgs += $item.SrcPath
}
$ghidraArgs += @(
    "-postScript", "EnigmaExportFidMatches.java",
    "-scriptPath", $ghidraScript,
    "-readOnly", "-deleteProject"
)

& "$ghidraRoot\support\analyzeHeadless.bat" @ghidraArgs 2>&1 | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host " Ghidra FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
}

$batchSeconds = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host " done (${batchSeconds}s)" -ForegroundColor Green

# Now ingest each one
$ingestStart = Get-Date
foreach ($item in $toProcess) {
    $family = $item.Family
    $srcPath = $item.SrcPath
    $map = $importMapping[$family]
    $outJson = $map.Path
    $binName = $map.BinName
    $outLib = "$fksDir\${family}_ghidra.fkslib"

    if (!(Test-Path $outJson)) {
        Write-Host "  FAIL (no JSON: $binName): $family" -ForegroundColor Red
        Write-Host "  FAIL (no JSON): $family" -ForegroundColor Red
        $fail++
        continue
    }

    $jsonSize = [math]::Round((Get-Item $outJson).Length / 1024, 1)
    Write-Host "  [Ingest] $binName -> $family (${jsonSize}KB)..." -NoNewline

    & $ingestTool $outJson $outLib --family $family --compiler msvc --version 10.0.19041 2>&1 | Out-Null

    if (!(Test-Path $outLib)) {
        Write-Host " FAIL" -ForegroundColor Red
        $fail++
        continue
    }
    $libSize = [math]::Round((Get-Item $outLib).Length / 1024, 1)
    Write-Host " OK (${libSize}KB)" -ForegroundColor Green
    $ok++
}

$totalTime = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host ""
Write-Host "=== $WaveName Complete ===" -ForegroundColor Green
Write-Host "  Batch Ghidra: ${batchSeconds}s"
Write-Host "  Ingestion:    $([math]::Round(((Get-Date) - $ingestStart).TotalSeconds, 1))s"  
Write-Host "  Total:        ${totalTime}s"
Write-Host "  Results: OK=$ok SKIP=$skip FAIL=$fail" -ForegroundColor Yellow
