# migrate_all_to_v3.ps1
# Migrate ALL FKS libraries to schema v3 via full Ghidra pipeline.
# Usage: .\migrate_all_to_v3.ps1 [-TimeoutSeconds 600] [-SkipExisting]

param(
    [int]$TimeoutSeconds = 600,
    [switch]$SkipExisting
)

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
New-Item -ItemType Directory -Path $ghidraProj -Force | Out-Null

# All libraries to process: name, family, source directory priority
$libraries = @(
    # stress/ binaries (known working)
    @{ Name="ntdll.dll";     Family="ntdll";     Dir="stress" },
    @{ Name="user32.dll";    Family="user32";    Dir="stress" },
    @{ Name="shell32.dll";   Family="shell32";   Dir="stress" },
    @{ Name="d2d1.dll";      Family="d2d1";      Dir="stress" },
    @{ Name="kernel32.dll";  Family="kernel32";  Dir="stress" },
    # System32 binaries
    @{ Name="advapi32.dll";       Family="advapi32";       Dir="system32" },
    @{ Name="bcryptprimitives.dll";Family="bcryptprimitives";Dir="system32" },
    @{ Name="cfgmgr32.dll";       Family="cfgmgr32";       Dir="system32" },
    @{ Name="combase.dll";        Family="combase";        Dir="system32" },
    @{ Name="comctl32.dll";       Family="comctl32";       Dir="system32" },
    @{ Name="crypt32.dll";        Family="crypt32";        Dir="system32" },
    @{ Name="d3d11.dll";          Family="d3d11";          Dir="system32" },
    @{ Name="devobj.dll";         Family="devobj";         Dir="system32" },
    @{ Name="dwrite.dll";         Family="dwrite";         Dir="system32" },
    @{ Name="dxgi.dll";           Family="dxgi";           Dir="system32" },
    @{ Name="gdi32.dll";          Family="gdi32";          Dir="system32" },
    @{ Name="gdi32full.dll";      Family="gdi32full";      Dir="system32" },
    @{ Name="iertutil.dll";       Family="iertutil";       Dir="system32" },
    @{ Name="kernelbase.dll";     Family="kernelbase";     Dir="system32" },
    @{ Name="mlang.dll";          Family="mlang";          Dir="system32" },
    @{ Name="msvcp_win.dll";      Family="msvcp_win";      Dir="system32" },
    @{ Name="msvcrt.dll";         Family="msvcrt";         Dir="system32" },
    @{ Name="netapi32.dll";       Family="netapi32";       Dir="system32" },
    @{ Name="ntmarta.dll";        Family="ntmarta";        Dir="system32" },
    @{ Name="ole32.dll";          Family="ole32";          Dir="system32" },
    @{ Name="oleaut32.dll";       Family="oleaut32";       Dir="system32" },
    @{ Name="profapi.dll";        Family="profapi";        Dir="system32" },
    @{ Name="rpcrt4.dll";         Family="rpcrt4";         Dir="system32" },
    @{ Name="sechost.dll";        Family="sechost";        Dir="system32" },
    @{ Name="shlwapi.dll";        Family="shlwapi";        Dir="system32" },
    @{ Name="ucrtbase.dll";       Family="ucrtbase";       Dir="system32" },
    @{ Name="urlmon.dll";         Family="urlmon";         Dir="system32" },
    @{ Name="userenv.dll";        Family="userenv";        Dir="system32" },
    @{ Name="uxtheme.dll";        Family="uxtheme";        Dir="system32" },
    @{ Name="WindowsCodecs.dll";  Family="WindowsCodecs";  Dir="system32" },
    @{ Name="winhttp.dll";        Family="winhttp";        Dir="system32" },
    @{ Name="wininet.dll";        Family="wininet";        Dir="system32" },
    @{ Name="ws2_32.dll";         Family="ws2_32";         Dir="system32" }
)

$results = @()
$successCount = 0
$failCount = 0
$skipCount = 0

foreach ($lib in $libraries) {
    $name = $lib.Name
    $family = $lib.Family
    $outLib = "$fksDir\${family}_ghidra.fkslib"
    $outJson = "$exportDir\${family}_export.json"

    # Resolve source path
    $srcPath = if ($lib.Dir -eq "stress") { "$stressDir\$name" } else { "$system32\$name" }

    if (!(Test-Path $srcPath)) {
        Write-Host "SKIP: $name not found at $srcPath" -ForegroundColor Yellow
        $skipCount++
        $results += [PSCustomObject]@{ Library=$family; Status="SKIP"; Functions=0; Relations=0; Reason="source not found" }
        continue
    }

    # Skip if already migrated (has _ghidra.fkslib with relations)
    if ($SkipExisting -and (Test-Path $outLib)) {
        $libSize = (Get-Item $outLib).Length
        if ($libSize -gt 1000) {
            Write-Host "SKIP: $family already exists ($([math]::Round($libSize/1024,1))KB)" -ForegroundColor DarkGray
            $skipCount++
            $results += [PSCustomObject]@{ Library=$family; Status="SKIP"; Functions=0; Relations=0; Reason="already exists" }
            continue
        }
    }

    Write-Host ""
    Write-Host "=== $family ($name) ===" -ForegroundColor Cyan

    # Step 1: Ghidra headless export
    $env:ENIGMA_GHIDRA_OUTPUT = $outJson
    Remove-Item $outJson -ErrorAction SilentlyContinue

    Write-Host "  [1/2] Ghidra export..." -NoNewline
    $job = Start-Job -ScriptBlock {
        param($ghidraRoot, $ghidraProj, $family, $srcPath, $ghidraScript)
        & "$ghidraRoot\support\analyzeHeadless.bat" $ghidraProj "EnigmaFKS_$family" -import $srcPath -postScript EnigmaExportFidMatches.java -scriptPath $ghidraScript -readOnly -deleteProject 2>&1 | Out-Null
    } -ArgumentList $ghidraRoot, $ghidraProj, $family, $srcPath, $ghidraScript

    $completed = Wait-Job $job -Timeout $TimeoutSeconds
    if ($completed -eq $null) {
        Stop-Job $job
        Remove-Job $job
        Write-Host " TIMEOUT" -ForegroundColor Red
        $failCount++
        $results += [PSCustomObject]@{ Library=$family; Status="TIMEOUT"; Functions=0; Relations=0; Reason="Ghidra export >${TimeoutSeconds}s" }
        continue
    }
    Remove-Job $job

    if (!(Test-Path $outJson)) {
        Write-Host " FAIL" -ForegroundColor Red
        $failCount++
        $results += [PSCustomObject]@{ Library=$family; Status="FAIL"; Functions=0; Relations=0; Reason="no JSON output" }
        continue
    }

    $jsonSize = [math]::Round((Get-Item $outJson).Length / 1024, 1)
    Write-Host " OK (${jsonSize}KB)" -ForegroundColor Green

    # Step 2: FKS ingest
    Write-Host "  [2/2] FKS ingest..." -NoNewline
    & $ingestTool $outJson $outLib --family $family --compiler msvc --version 10.0.19041 2>&1 | Out-Null

    if (!(Test-Path $outLib)) {
        Write-Host " FAIL" -ForegroundColor Red
        $failCount++
        $results += [PSCustomObject]@{ Library=$family; Status="FAIL"; Functions=0; Relations=0; Reason="ingest failed" }
        continue
    }

    $libSize = [math]::Round((Get-Item $outLib).Length / 1024, 1)
    Write-Host " OK (${libSize}KB)" -ForegroundColor Green
    $successCount++
    $results += [PSCustomObject]@{ Library=$family; Status="OK"; Functions=0; Relations=0; Reason="" }
}

# Step 3: Rebuild LMDB index
Write-Host ""
Write-Host "=== Rebuilding LMDB index ===" -ForegroundColor Cyan
& "$enigmaRoot\build\enigma_fks_build_index.exe" $fksDir 2>&1

# Step 4: Summary
Write-Host ""
Write-Host "=== Migration Summary ===" -ForegroundColor Green
Write-Host "  Succeeded: $successCount"
Write-Host "  Failed:    $failCount"
Write-Host "  Skipped:   $skipCount"
Write-Host ""
$results | Format-Table -AutoSize
