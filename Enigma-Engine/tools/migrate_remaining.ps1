# migrate_remaining.ps1
# Continue migration for DLLs not yet processed.

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"
$system32 = "C:\Windows\System32"

New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

$remaining = @(
    @{ Name="msvcp_win.dll";      Family="msvcp_win" },
    @{ Name="msvcrt.dll";         Family="msvcrt" },
    @{ Name="netapi32.dll";       Family="netapi32" },
    @{ Name="ntmarta.dll";        Family="ntmarta" },
    @{ Name="ole32.dll";          Family="ole32" },
    @{ Name="oleaut32.dll";       Family="oleaut32" },
    @{ Name="profapi.dll";        Family="profapi" },
    @{ Name="rpcrt4.dll";         Family="rpcrt4" },
    @{ Name="sechost.dll";        Family="sechost" },
    @{ Name="shell32.dll";        Family="shell32" },
    @{ Name="shlwapi.dll";        Family="shlwapi" },
    @{ Name="ucrtbase.dll";       Family="ucrtbase" },
    @{ Name="urlmon.dll";         Family="urlmon" },
    @{ Name="userenv.dll";        Family="userenv" },
    @{ Name="uxtheme.dll";        Family="uxtheme" },
    @{ Name="WindowsCodecs.dll";  Family="WindowsCodecs" },
    @{ Name="winhttp.dll";        Family="winhttp" },
    @{ Name="wininet.dll";        Family="wininet" },
    @{ Name="ws2_32.dll";         Family="ws2_32" }
)

$ok = 0
$fail = 0

foreach ($lib in $remaining) {
    $outLib = "$fksDir\$($lib.Family)_ghidra.fkslib"

    # Skip if already exists
    if (Test-Path $outLib) {
        $sz = [math]::Round((Get-Item $outLib).Length / 1024, 1)
        Write-Host "SKIP: $($lib.Family) (${sz}KB)" -ForegroundColor DarkGray
        continue
    }

    $srcPath = "$system32\$($lib.Name)"
    if (!(Test-Path $srcPath)) {
        Write-Host "NO SRC: $($lib.Family)" -ForegroundColor Red
        $fail++
        continue
    }

    Write-Host ""
    Write-Host "=== $($lib.Family) ===" -ForegroundColor Cyan

    # Export
    $env:ENIGMA_GHIDRA_OUTPUT = "$exportDir\$($lib.Family)_export.json"
    Remove-Item $env:ENIGMA_GHIDRA_OUTPUT -ErrorAction SilentlyContinue

    Write-Host "  Exporting..." -NoNewline
    $job = Start-Job -ScriptBlock {
        param($gr, $gp, $f, $sp, $gs)
        & "$gr\support\analyzeHeadless.bat" $gp "EnigmaFKS_$f" -import $sp -postScript EnigmaExportFidMatches.java -scriptPath $gs -readOnly -deleteProject 2>&1 | Out-Null
    } -ArgumentList $ghidraRoot, $ghidraProj, $lib.Family, $srcPath, $ghidraScript

    $completed = Wait-Job $job -Timeout 600
    if ($null -eq $completed) {
        Stop-Job $job
        Remove-Job $job
        Write-Host " TIMEOUT" -ForegroundColor Red
        $fail++
        continue
    }
    Remove-Job $job

    if (!(Test-Path $env:ENIGMA_GHIDRA_OUTPUT)) {
        Write-Host " FAIL" -ForegroundColor Red
        $fail++
        continue
    }

    $jsonSz = [math]::Round((Get-Item $env:ENIGMA_GHIDRA_OUTPUT).Length / 1024, 1)
    Write-Host " OK (${jsonSz}KB)" -ForegroundColor Green

    # Ingest
    Write-Host "  Ingesting..." -NoNewline
    & $ingestTool $env:ENIGMA_GHIDRA_OUTPUT $outLib --family $lib.Family --compiler msvc --version 10.0.19041 2>&1 | Out-Null

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
Write-Host "Done: $ok succeeded, $fail failed" -ForegroundColor Green
