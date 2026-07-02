# Re-ingest all 156 ARM64 fkslibs with --arch arm64 for correct V2 hashes
$ErrorActionPreference = "Stop"

$fidDir = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\fid"
$exportDir = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build\ghidra_exports"
$ingestTool = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\build\enigma_fks_ingest_from_ghidra.exe"

if (-not (Test-Path $ingestTool)) { Write-Host "ERROR: ingest tool not found" -ForegroundColor Red; exit 1 }

# Build mapping: for each export JSON, compute all candidate normalized names
Write-Host "Building export JSON → normalized name mapping..." -ForegroundColor Cyan
$exportMap = @{}  # normalized_lowercase -> json_path
foreach ($json in Get-ChildItem -Path $exportDir -Filter "*_export.json") {
    $base = $json.BaseName  # e.g. "kernel32_export" → "kernel32"
    $base = $base -replace '_export$', ''
    
    # Store under original
    $exportMap[$base] = $json.FullName
    
    # Store under lowercase
    $exportMap[$base.ToLower()] = $json.FullName
    
    # Store under lowercase, dots → underscores
    $normalized = ($base.ToLower() -replace '\.', '_')
    $exportMap[$normalized] = $json.FullName
    
    # Store under lowercase, dots→underscores, .dll removed
    $noext = $normalized -replace '\.dll$', ''
    $exportMap[$noext] = $json.FullName
    
    # Also store under just lowercase of noext
    $exportMap[$noext] = $json.FullName
}

# Now iterate all ARM64 fkslibs and find matching export
$arm64fkslibs = Get-ChildItem -Path $fidDir -Filter "*_arm64_ghidra.fkslib" | Sort-Object Name
$total = $arm64fkslibs.Count
$ok = 0
$fail = 0

Write-Host "Found $total ARM64 fkslibs, starting re-ingestion with --arch arm64..." -ForegroundColor Cyan

foreach ($fks in $arm64fkslibs) {
    # Derive program name base from fkslib name (remove _arm64_ghidra)
    if ($fks.BaseName -match '^(.+)_arm64_ghidra$') {
        $progBase = $matches[1]
    } else {
        Write-Host "  SKIP $($fks.Name): unexpected naming pattern" -ForegroundColor Yellow
        $fail++
        continue
    }
    
    # Try to find matching export JSON
    $jsonPath = $null
    $progLower = $progBase.ToLower()
    
    # Try exact match first, then various normalizations
    $candidates = @(
        $progBase,
        $progLower,
        $progLower -replace '\.', '_',
        ($progLower -replace '\.', '_') -replace '\.dll$', ''
    )
    
    # Special case: remove trailing .dll
    $candidates += $progLower -replace '\.dll$', ''
    
    foreach ($c in $candidates) {
        if ($exportMap.ContainsKey($c)) {
            $jsonPath = $exportMap[$c]
            break
        }
    }
    
    # Special cases for known problematic names
    if (-not $jsonPath) {
        # Try direct basename lookup
        $direct = Join-Path $exportDir "$progBase`_export.json"
        if (Test-Path $direct) { $jsonPath = $direct }
    }
    if (-not $jsonPath) {
        # Try case-insensitive directory search
        $found = Get-ChildItem -Path $exportDir -Filter "*_export.json" | Where-Object {
            $_.BaseName.Length -ge $progBase.Length -and
            ($_.BaseName.StartsWith($progBase, [StringComparison]::OrdinalIgnoreCase) -or
             $progBase.StartsWith($_.BaseName, [StringComparison]::OrdinalIgnoreCase))
        }
        if ($found.Count -eq 1) { $jsonPath = $found.FullName }
        elseif ($found.Count -gt 1) {
            # Prefer shorter match (exact)
            $found = $found | Sort-Object { $_.BaseName.Length }
            $jsonPath = $found[0].FullName
        }
    }
    
    if (-not $jsonPath) {
        Write-Host "  FAIL $($fks.Name): no export JSON found for '$progBase'" -ForegroundColor Red
        $fail++
        continue
    }
    
    # Determine family/compiler from existing fkslib metadata? Use defaults
    # Family: determine from name
    $family = "Unknown"
    $compiler = "msvc"
    
    if ($fks.Name -match 'concrt|vcruntime|msvcp|mfc|vcamp|vccorlib|vcomp') {
        $family = "MSVC Runtime"
    } elseif ($fks.Name -match 'kernel32|kernelbase|ntdll|user32|gdi32|win32u|advapi32|ole32|oleaut32|combase|shell32|shlwapi|comctl32|comdlg32|ws2_32|rpcrt4|bcryptprimitives|crypt32|dnsapi|winhttp|wininet|urlmon|mshtml|ieframe|iertutil|edgehtml|jscript|vbscript|chakra|d2d1|d3d11|d3d12|dxgi|dcomp|dwrite|mfplat|mfcore|windows_media|windows_storage|windowscodecs|uxtheme|dwmapi|propsys|clbcatq|sechost|setupapi') {
        $family = "Windows Shell"
    } elseif ($fks.Name -match 'qt6') {
        $family = "Qt6"
    } elseif ($fks.Name -match 'python') {
        $family = "Python"
    } elseif ($fks.Name -match 'tcl|tk') {
        $family = "Tcl/Tk"
    } elseif ($fks.Name -match 'lib.*msys|mingw|libstdcpp|libgcc|libwinpthread') {
        $family = "MSYS2"
        $compiler = "gcc"
    } elseif ($fks.Name -match 'icu|icuin|icuuc|icudt') {
        $family = "ICU"
    } elseif ($fks.Name -match 'libcrypto|libssl|libcurl|libnghttp2|libexpat|liblzma|libjpeg|libpng|libfreetype|libharfbuzz|libpcre|libffi|libgio|libglib|libgobject|libp11|libgnutls|libunistring|libbz|libisl|libcapstone|libcppdap|sqlite3|zlib1') {
        $family = "MSYS2"
        $compiler = "gcc"
    } elseif ($fks.Name -match 'onnxruntime|directml') {
        $family = "ML/AI"
    } elseif ($fks.Name -match 'd3dcompiler|d3dcsx|d3dx9') {
        $family = "DirectX SDK"
    } elseif ($fks.Name -match 'edgeangle|edgecontent|edgemanager|edgehtml') {
        $family = "Microsoft Edge"
    } elseif ($fks.Name -match 'windows_ui|windows_application|windows_cloud|windows_data|windows_media|windows_state|windows_storage') {
        $family = "Windows Runtime"
    } elseif ($fks.Name -match 'coreui|inputservice|installservice|settingshandlers|starttiledata|systemsettings|udiapiclient|uiautomation|uiribbon|onecoreuap|maprouter|mdmdiagnostics|mispace|wsm|wercpl|wer|faultrep|diagtrack|srh|bingmaps|cdp|explorerframe|thumbcache|twinui|tquery|resutils|wecapi') {
        $family = "Windows Shell"
    } elseif ($fks.Name -match 'ntoskrnl|win32k') {
        $family = "Windows Kernel"
    } else {
        $family = "Windows System"
    }
    
    $fkslibPath = $fks.FullName
    
    Write-Host "  [$($ok+$fail+1)/$total] $($fks.Name)" -ForegroundColor Gray
    $proc = Start-Process -FilePath $ingestTool -ArgumentList "`"$jsonPath`" `"$fkslibPath`" --family `"$family`" --compiler $compiler --arch arm64" -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -eq 0) {
        Write-Host "    OK (family=$family compiler=$compiler)" -ForegroundColor Green
        $ok++
    } else {
        Write-Host "    FAILED exit=$($proc.ExitCode)" -ForegroundColor Red
        $fail++
    }
}

Write-Host "`n=== Re-ingest complete ===" -ForegroundColor Cyan
Write-Host "  Success: $ok / $total" -ForegroundColor $(if($fail -eq 0){'Green'}else{'Yellow'})
Write-Host "  Failed:  $fail / $total" -ForegroundColor $(if($fail -eq 0){'Green'}else{'Red'})
