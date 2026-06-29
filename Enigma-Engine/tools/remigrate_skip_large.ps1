# remigrate_skip_large.ps1
# Re-export libraries missing relations, skip mshtml/ntoskrnl (too large).

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"
$system32 = "C:\Windows\System32"

$libs = @(
    @{ Family="msvcp_win";     Dll="msvcp_win.dll" },
    @{ Family="netapi32";      Dll="netapi32.dll" },
    @{ Family="ntmarta";       Dll="ntmarta.dll" },
    @{ Family="ole32";         Dll="ole32.dll" },
    @{ Family="oleaut32";      Dll="oleaut32.dll" },
    @{ Family="profapi";       Dll="profapi.dll" },
    @{ Family="rpcrt4";        Dll="rpcrt4.dll" },
    @{ Family="sechost";       Dll="sechost.dll" },
    @{ Family="shlwapi";       Dll="shlwapi.dll" },
    @{ Family="urlmon";        Dll="urlmon.dll" },
    @{ Family="userenv";       Dll="userenv.dll" },
    @{ Family="uxtheme";       Dll="uxtheme.dll" },
    @{ Family="winhttp";       Dll="winhttp.dll" },
    @{ Family="wininet";       Dll="wininet.dll" },
    @{ Family="ws2_32";        Dll="ws2_32.dll" }
)

$ok = 0; $fail = 0
foreach ($lib in $libs) {
    $outLib = "$fksDir\$($lib.Family)_ghidra.fkslib"
    $outJson = "$exportDir\$($lib.Family)_export.json"
    $srcPath = "$system32\$($lib.Dll)"
    if (!(Test-Path $srcPath)) { Write-Host "SKIP: $($lib.Family)"; $fail++; continue }

    Write-Host "$($lib.Family): " -NoNewline
    Remove-Item $outLib -ErrorAction SilentlyContinue
    $env:ENIGMA_GHIDRA_OUTPUT = $outJson
    Remove-Item $outJson -ErrorAction SilentlyContinue

    $job = Start-Job -ScriptBlock { param($gr,$gp,$f,$sp,$gs) & "$gr\support\analyzeHeadless.bat" $gp "EnigmaFKS_$f" -import $sp -postScript EnigmaExportFidMatches.java -scriptPath $gs -readOnly -deleteProject 2>&1|Out-Null } -ArgumentList $ghidraRoot,$ghidraProj,$lib.Family,$srcPath,$ghidraScript
    $c = Wait-Job $job -Timeout 600
    if ($null -eq $c) { Stop-Job $job; Remove-Job $job; Write-Host "TIMEOUT" -Fore Red; $fail++; continue }
    Remove-Job $job
    if (!(Test-Path $outJson)) { Write-Host "FAIL" -Fore Red; $fail++; continue }

    & $ingestTool $outJson $outLib --family $lib.Family --compiler msvc --version 10.0.19041 2>&1|Out-Null
    if (Test-Path $outLib) { Write-Host "OK" -Fore Green; $ok++ } else { Write-Host "FAIL" -Fore Red; $fail++ }
}
Write-Host "`nDone: $ok ok, $fail fail" -Fore Green
