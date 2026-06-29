# remigrate_no_relations.ps1
# Re-export and re-ingest libraries that have 0 relations.

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"
$system32 = "C:\Windows\System32"
$stressDir = "$enigmaRoot\test_binaries\stress"

New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

# Libraries with 0 relations that need re-export
# Format: Family, Source DLL name, isLarge (longer timeout)
$needsReExport = @(
    @{ Family="WindowsCodecs"; Dll="WindowsCodecs.dll"; Large=$false },
    @{ Family="mshtml";        Dll="mshtml.dll";        Large=$true },
    @{ Family="msvcp_win";     Dll="msvcp_win.dll";     Large=$false },
    @{ Family="netapi32";      Dll="netapi32.dll";      Large=$false },
    @{ Family="ntmarta";       Dll="ntmarta.dll";       Large=$false },
    @{ Family="ntoskrnl";      Dll="ntoskrnl.exe";      Large=$true },
    @{ Family="ole32";         Dll="ole32.dll";         Large=$false },
    @{ Family="oleaut32";      Dll="oleaut32.dll";      Large=$false },
    @{ Family="profapi";       Dll="profapi.dll";       Large=$false },
    @{ Family="rpcrt4";        Dll="rpcrt4.dll";        Large=$false },
    @{ Family="sechost";       Dll="sechost.dll";       Large=$false },
    @{ Family="shlwapi";       Dll="shlwapi.dll";       Large=$false },
    @{ Family="urlmon";        Dll="urlmon.dll";        Large=$false },
    @{ Family="userenv";       Dll="userenv.dll";       Large=$false },
    @{ Family="uxtheme";       Dll="uxtheme.dll";       Large=$false },
    @{ Family="winhttp";       Dll="winhttp.dll";       Large=$false },
    @{ Family="wininet";       Dll="wininet.dll";       Large=$false },
    @{ Family="ws2_32";        Dll="ws2_32.dll";        Large=$false }
)

$ok = 0
$fail = 0
$timeout = 0

foreach ($lib in $needsReExport) {
    $family = $lib.Family
    $outLib = "$fksDir\${family}_ghidra.fkslib"
    $outJson = "$exportDir\${family}_export.json"

    # Resolve source: try stress dir first, then system32
    $srcPath = "$stressDir\$($lib.Dll)"
    if (!(Test-Path $srcPath)) {
        $srcPath = "$system32\$($lib.Dll)"
    }
    if (!(Test-Path $srcPath)) {
        Write-Host "SKIP: $family - source not found" -ForegroundColor Yellow
        $fail++
        continue
    }

    $timeoutSec = if ($lib.Large) { 900 } else { 600 }

    Write-Host ""
    Write-Host "=== $family ===" -ForegroundColor Cyan

    # Remove old file
    Remove-Item $outLib -ErrorAction SilentlyContinue

    # Step 1: Ghidra export
    $env:ENIGMA_GHIDRA_OUTPUT = $outJson
    Remove-Item $outJson -ErrorAction SilentlyContinue

    Write-Host "  [1/2] Exporting ($timeoutSec s timeout)..." -NoNewline
    $job = Start-Job -ScriptBlock {
        param($gr, $gp, $f, $sp, $gs)
        & "$gr\support\analyzeHeadless.bat" $gp "EnigmaFKS_$f" -import $sp -postScript EnigmaExportFidMatches.java -scriptPath $gs -readOnly -deleteProject 2>&1 | Out-Null
    } -ArgumentList $ghidraRoot, $ghidraProj, $family, $srcPath, $ghidraScript

    $completed = Wait-Job $job -Timeout $timeoutSec
    if ($null -eq $completed) {
        Stop-Job $job
        Remove-Job $job
        Write-Host " TIMEOUT" -ForegroundColor Red
        $timeout++
        continue
    }
    Remove-Job $job

    if (!(Test-Path $outJson)) {
        Write-Host " FAIL (no JSON)" -ForegroundColor Red
        $fail++
        continue
    }

    $jsonSz = [math]::Round((Get-Item $outJson).Length / 1024, 1)
    Write-Host " OK (${jsonSz}KB)" -ForegroundColor Green

    # Step 2: FKS ingest
    Write-Host "  [2/2] Ingesting..." -NoNewline
    & $ingestTool $outJson $outLib --family $family --compiler msvc --version 10.0.19041 2>&1 | Out-Null

    if (Test-Path $outLib) {
        $libSz = [math]::Round((Get-Item $outLib).Length / 1024, 1)
        Write-Host " OK (${libSz}KB)" -ForegroundColor Green
        $ok++
    } else {
        Write-Host " FAIL" -ForegroundColor Red
        $fail++
    }
}

Write-Host ""
Write-Host "=== Re-export Summary ===" -ForegroundColor Green
Write-Host "  Succeeded: $ok"
Write-Host "  Failed:    $fail"
Write-Host "  Timed out: $timeout"
