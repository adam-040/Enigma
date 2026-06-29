# phase_a_ingest.ps1
# Phase A: Add ~150 high-value Windows system DLLs to FKS corpus
# Organized in 4 waves by priority (A1-A8 categories).
#
# Usage:
#   .\phase_a_ingest.ps1                      # Run all waves
#   .\phase_a_ingest.ps1 -Wave 1              # Run only Wave 1
#   .\phase_a_ingest.ps1 -Wave 1 -TimeoutSec 900  # Wave 1 with 900s Ghidra timeout
#   .\phase_a_ingest.ps1 -ListMissing         # Only list what's missing, don't export
#   .\phase_a_ingest.ps1 -ReindexOnly         # Only rebuild LMDB index

param(
    [int]$Wave = 0,           # 0 = all waves, 1-4 = specific wave
    [int]$TimeoutSec = 300,    # Ghidra headless timeout per DLL
    [switch]$ListMissing,      # Only print missing DLL inventory
    [switch]$ReindexOnly,      # Only rebuild LMDB index
    [switch]$Force             # Re-export even if .fkslib exists
)

$ghidraRoot = "C:\Users\pc\Desktop\Crack tools\Ghidra"
$enigmaRoot = "C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine"
$ghidraProj = "$enigmaRoot\build\ghidra_proj"
$ghidraScript = "$enigmaRoot\tools\ghidra_scripts"
$ingestTool = "$enigmaRoot\build\enigma_fks_ingest_from_ghidra.exe"
$fksDir = "$enigmaRoot\fid"
$exportDir = "$enigmaRoot\build\ghidra_exports"
$system32 = "C:\Windows\System32"
$logFile = "$enigmaRoot\build\phase_a_ingest.log"
$reportFile = "$enigmaRoot\build\phase_a_report.csv"

# Existing corpus families (to skip if already present)
$existing = @{}
Get-ChildItem "$fksDir\*.fkslib" | ForEach-Object {
    $fam = $_.Name -replace '_ghidra\.fkslib$',''
    $existing[$fam] = $true
}

# ─── Wave Definitions ─────────────────────────────────────────────────────────
# Each wave entry: Name (DLL filename), Family (FKS family name), Category, Notes
# Organized by decreasing priority and estimated cross-binary reuse.

$wave1 = @(
    # A1 - Kernel32 extensions (highest cross-binary reuse)
    @{ Name="secur32.dll";       Family="secur32";       Cat="A1-Security";     Notes="LSA authentication, SSPI" }
    @{ Name="samcli.dll";        Family="samcli";        Cat="A1-Security";     Notes="SAM client / security" }
    @{ Name="samsrv.dll";        Family="samsrv";        Cat="A1-Security";     Notes="SAM server / account DB" }

    # A2 - COM+ / WMI core
    @{ Name="clbcatq.dll";       Family="clbcatq";       Cat="A2-COM";          Notes="COM+ catalog" }
    @{ Name="es.dll";            Family="es";            Cat="A2-COM";          Notes="Event system" }
    @{ Name="msdart.dll";        Family="msdart";        Cat="A2-COM";          Notes="COM+ runtime services" }
    @{ Name="xmllite.dll";       Family="xmllite";       Cat="A2-XML";          Notes="XML lite parser" }
    @{ Name="msxml3.dll";        Family="msxml3";        Cat="A2-XML";          Notes="MSXML3 parser (legacy)" }
    @{ Name="msxml6.dll";        Family="msxml6";        Cat="A2-XML";          Notes="MSXML6 parser" }

    # A3 - Cryptography / Security
    @{ Name="ncrypt.dll";        Family="ncrypt";        Cat="A3-Crypto";       Notes="Next-gen crypto (CNG)" }
    @{ Name="wintrust.dll";      Family="wintrust";      Cat="A3-Crypto";       Notes="Win trust / Authenticode" }
    @{ Name="dpapi.dll";         Family="dpapi";         Cat="A3-Crypto";       Notes="Data Protection API" }
    @{ Name="credwiz.dll";       Family="credwiz";       Cat="A3-Security";     Notes="Credential backup wizard" }
    @{ Name="tbs.dll";           Family="tbs";           Cat="A3-Security";     Notes="TPM Base Services" }
    @{ Name="bfe.dll";           Family="bfe";           Cat="A3-Security";     Notes="Base Filtering Engine" }

    # A4 - GDI / Printing / Multimedia core
    @{ Name="winspool.drv";      Family="winspool";      Cat="A4-Printing";     Notes="Print spooler (every app)" }
    @{ Name="winmm.dll";         Family="winmm";         Cat="A4-Multimedia";   Notes="Windows multimedia core" }
    @{ Name="winmmbase.dll";     Family="winmmbase";     Cat="A4-Multimedia";   Notes="MM base layer" }
    @{ Name="msacm32.dll";       Family="msacm32";       Cat="A4-Multimedia";   Notes="Audio compression" }
    @{ Name="opengl32.dll";      Family="opengl32";      Cat="A4-Graphics";     Notes="OpenGL loader" }
    @{ Name="dsound.dll";        Family="dsound";        Cat="A4-Multimedia";   Notes="DirectSound" }
    @{ Name="ddraw.dll";         Family="ddraw";         Cat="A4-Graphics";     Notes="DirectDraw" }

    # A5 - Desktop / Input / Shell
    @{ Name="dwmapi.dll";        Family="dwmapi";        Cat="A5-Desktop";      Notes="Desktop Window Manager" }
    @{ Name="imm32.dll";         Family="imm32";         Cat="A5-Input";        Notes="Input Method Editor" }
    @{ Name="msctf.dll";         Family="msctf";         Cat="A5-Input";        Notes="Text Services Framework" }
    @{ Name="win32u.dll";        Family="win32u";        Cat="A5-Desktop";      Notes="Win32 user API (thin layer)" }

    # A6 - System / Setup / Threading
    @{ Name="setupapi.dll";      Family="setupapi";      Cat="A6-Setup";        Notes="Setup API (device install)" }
    @{ Name="msi.dll";           Family="msi";           Cat="A6-Setup";        Notes="Windows Installer" }
    @{ Name="powrprof.dll";      Family="powrprof";      Cat="A6-System";       Notes="Power management API" }
    @{ Name="apphelp.dll";       Family="apphelp";       Cat="A6-System";       Notes="Application compat" }

    # A7 - Storage / File Systems
    @{ Name="fltlib.dll";        Family="fltlib";        Cat="A7-Storage";      Notes="Filter library" }

    # A8 - Network
    @{ Name="dnsapi.dll";        Family="dnsapi";        Cat="A8-Network";      Notes="DNS API" }
    @{ Name="iphlpapi.dll";      Family="iphlpapi";      Cat="A8-Network";      Notes="IP Helper" }
    @{ Name="dhcpcsvc.dll";      Family="dhcpcsvc";      Cat="A8-Network";      Notes="DHCP client" }
    @{ Name="fwpuclnt.dll";      Family="fwpuclnt";      Cat="A8-Network";      Notes="Firewall client" }
    @{ Name="wlanapi.dll";       Family="wlanapi";       Cat="A8-Network";      Notes="WLAN API" }
    @{ Name="mpr.dll";           Family="mpr";           Cat="A8-Network";      Notes="Multiple Provider Router" }
    @{ Name="rasapi32.dll";      Family="rasapi32";      Cat="A8-Network";      Notes="RAS dialup API" }
    @{ Name="sspicli.dll";       Family="sspicli";       Cat="A8-Network";      Notes="SSPI client (security)" }
)

$wave2 = @(
    # A2 - WMI subsystem
    @{ Name="wmi.dll";           Family="wmi";           Cat="A2-WMI";          Notes="WMI core" }
    @{ Name="fastprox.dll";      Family="fastprox";      Cat="A2-WMI";          Notes="WMI fast proxy" }
    @{ Name="wbemprox.dll";      Family="wbemprox";      Cat="A2-WMI";          Notes="WMI provider" }
    @{ Name="wbemcore.dll";      Family="wbemcore";      Cat="A2-WMI";          Notes="WMI core engine" }
    @{ Name="wbemsvc.dll";       Family="wbemsvc";       Cat="A2-WMI";          Notes="WMI service" }

    # A3 - Certificate / Credential Security
    @{ Name="certca.dll";        Family="certca";        Cat="A3-Crypto";       Notes="Certificate CA" }
    @{ Name="certcli.dll";       Family="certcli";        Cat="A3-Crypto";       Notes="Certificate client" }
    @{ Name="certenroll.dll";    Family="certenroll";    Cat="A3-Crypto";       Notes="Certificate enrollment" }
    @{ Name="credui.dll";        Family="credui";        Cat="A3-Security";     Notes="Credential UI dialogs" }
    @{ Name="policymanager.dll"; Family="policymanager"; Cat="A3-Security";     Notes="Policy Manager" }
    @{ Name="efslsaext.dll";     Family="efslsaext";     Cat="A3-Crypto";       Notes="EFS extension" }
    @{ Name="pstorsvc.dll";      Family="pstorsvc";      Cat="A3-Security";     Notes="Protected storage" }
    @{ Name="sppc.dll";          Family="sppc";          Cat="A3-Security";     Notes="Software Protection Platform" }
    @{ Name="sfc.dll";           Family="sfc";           Cat="A3-Security";     Notes="System File Checker" }

    # A4 - Multimedia / Graphics extended
    @{ Name="avifil32.dll";      Family="avifil32";      Cat="A4-Multimedia";   Notes="AVI file handler" }
    @{ Name="msvfw32.dll";       Family="msvfw32";       Cat="A4-Multimedia";   Notes="Video for Windows" }
    @{ Name="glu32.dll";         Family="glu32";         Cat="A4-Graphics";     Notes="OpenGL utility" }
    @{ Name="dinput8.dll";       Family="dinput8";       Cat="A4-Input";        Notes="DirectInput 8" }
    @{ Name="d3dim.dll";         Family="d3dim";         Cat="A4-Graphics";     Notes="Direct3D (old)" }
    @{ Name="compstui.dll";      Family="compstui";      Cat="A4-Printing";     Notes="Print UI common" }

    # A5 - Desktop / Shell extended
    @{ Name="ninput.dll";        Family="ninput";        Cat="A5-Input";        Notes="Touch/hardware input" }
    @{ Name="twinapi.appcore.dll"; Family="twinapi_appcore"; Cat="A5-Desktop";  Notes="WinRT appcore" }
    @{ Name="mrmcorert.dll";     Family="mrmcorert";     Cat="A5-Desktop";      Notes="Modern Resource Manager" }
    @{ Name="resourcepolicyclient.dll"; Family="resourcepolicyclient"; Cat="A5-Desktop"; Notes="Resource policy" }
    @{ Name="propsys.dll";       Family="propsys";       Cat="A5-Shell";        Notes="Property system (metadata)" }
    @{ Name="structuredquery.dll"; Family="structuredquery"; Cat="A5-Shell";    Notes="Structured query" }
    @{ Name="thumbcache.dll";    Family="thumbcache";    Cat="A5-Shell";        Notes="Thumbnail cache" }
    @{ Name="rich20.dll";        Family="rich20";        Cat="A5-Shell";        Notes="RichEdit 2.0" }
    @{ Name="msftedit.dll";      Family="msftedit";      Cat="A5-Shell";        Notes="RichEdit host control" }

    # A6 - Setup / Update
    @{ Name="newdev.dll";        Family="newdev";        Cat="A6-Setup";        Notes="New device wizard" }
    @{ Name="msdelta.dll";       Family="msdelta";       Cat="A6-System";       Notes="Delta compression (update)" }
    @{ Name="aclayer.dll";       Family="aclayer";       Cat="A6-System";       Notes="Application compat layer" }

    # A7 - Storage extended
    @{ Name="vssapi.dll";        Family="vssapi";        Cat="A7-Storage";      Notes="Volume Shadow Copy API" }
    @{ Name="ktmw32.dll";        Family="ktmw32";        Cat="A7-Storage";      Notes="Kernel Transaction Manager" }
    @{ Name="portabledeviceapi.dll"; Family="portabledeviceapi"; Cat="A7-Storage"; Notes="Portable Device API (MTP)" }

    # A8 - Network extended
    @{ Name="winrm.dll";         Family="winrm";         Cat="A8-Network";      Notes="WS-Management" }
    @{ Name="webservices.dll";   Family="webservices";   Cat="A8-Network";      Notes="Web Services API (WWSAPI)" }
    @{ Name="nshwfp.dll";        Family="nshwfp";        Cat="A8-Network";      Notes="WFP network helper" }
    @{ Name="tcpipcfg.dll";      Family="tcpipcfg";      Cat="A8-Network";      Notes="TCP/IP configuration" }
    @{ Name="mprapi.dll";        Family="mprapi";        Cat="A8-Network";      Notes="Routing API" }
    @{ Name="rasman.dll";        Family="rasman";        Cat="A8-Network";      Notes="RAS connection manager" }
)

$wave3 = @(
    # Extended A2 - COM+ Services
    @{ Name="colbact.dll";       Family="colbact";       Cat="A2-COM";          Notes="COM+ activator" }
    @{ Name="eventsystem.dll";   Family="eventsystem";   Cat="A2-COM";          Notes="Event system (COM+)" }
    @{ Name="resutils.dll";      Family="resutils";      Cat="A2-COM";          Notes="Cluster resource utils" }
    @{ Name="clusapi.dll";       Family="clusapi";       Cat="A2-COM";          Notes="Cluster API" }
    @{ Name="wkssvc.dll";        Family="wkssvc";        Cat="A2-COM";          Notes="Workstation service" }
    @{ Name="srvsvc.dll";        Family="srvsvc";        Cat="A2-COM";          Notes="Server service" }

    # A3 - Security extended
    @{ Name="keycredmgr.dll";    Family="keycredmgr";    Cat="A3-Security";     Notes="Key Credential Manager" }
    @{ Name="sfcfiles.dll";      Family="sfcfiles";      Cat="A3-Security";     Notes="SFC file database" }
    @{ Name="sppwinob.dll";      Family="sppwinob";      Cat="A3-Security";     Notes="SPP WinOB (activation)" }
    @{ Name="acspecfc.dll";      Family="acspecfc";      Cat="A3-Security";     Notes="AppCompat spec (shim DB)" }

    # A4 - Multimedia extended
    @{ Name="wdmaud.drv";        Family="wdmaud";        Cat="A4-Multimedia";   Notes="WDM audio driver" }
    @{ Name="quartz.dll";        Family="quartz";        Cat="A4-Multimedia";   Notes="DirectShow (quartz)" }
    @{ Name="msdmo.dll";         Family="msdmo";         Cat="A4-Multimedia";   Notes="DirectShow media objects" }
    @{ Name="devenum.dll";       Family="devenum";       Cat="A4-Multimedia";   Notes="DirectShow device enum" }
    @{ Name="ksuser.dll";        Family="ksuser";        Cat="A4-Multimedia";   Notes="Kernel streaming user" }

    # A5 - Desktop / Accessibility
    @{ Name="uiautomationcore.dll"; Family="uiautomationcore"; Cat="A5-Desktop"; Notes="UI Automation core" }
    @{ Name="oleacc.dll";        Family="oleacc";        Cat="A5-Desktop";      Notes="Active Accessibility" }
    @{ Name="sapi.dll";          Family="sapi";          Cat="A5-Input";        Notes="Speech API (SAPI)" }
    @{ Name="sapirtti.dll";      Family="sapirtti";      Cat="A5-Input";        Notes="SAPI RTTI" }
    @{ Name="magnification.dll"; Family="magnification"; Cat="A5-Desktop";      Notes="Magnifier API" }

    # A5 - Shell extended
    @{ Name="activeds.dll";      Family="activeds";      Cat="A5-Shell";        Notes="Active Directory Service" }
    @{ Name="adsldp.dll";        Family="adsldp";        Cat="A5-Shell";        Notes="ADSI LDAP provider" }
    @{ Name="adsnt.dll";         Family="adsnt";         Cat="A5-Shell";        Notes="ADSI WinNT provider" }
    @{ Name="browselc.dll";      Family="browselc";      Cat="A5-Shell";        Notes="Browse language code page" }

    # A6 - System / Drivers
    @{ Name="drvstore.dll";      Family="drvstore";      Cat="A6-System";       Notes="Driver store" }
    @{ Name="timeapi.dll";       Family="timeapi";       Cat="A6-System";       Notes="Time provider API" }
    @{ Name="batt.dll";          Family="batt";          Cat="A6-System";       Notes="Battery class driver" }
    @{ Name="wtsapi32.dll";      Family="wtsapi32";      Cat="A6-System";       Notes="Remote Desktop Session API" }
    @{ Name="sas.dll";           Family="sas";           Cat="A6-System";       Notes="Secure Attention Sequence" }

    # A7 - Storage / Imaging
    @{ Name="sti.dll";           Family="sti";           Cat="A7-Storage";      Notes="Still Image API" }
    @{ Name="wia.dll";           Family="wia";           Cat="A7-Devices";      Notes="Windows Image Acquisition" }
    @{ Name="wiadefui.dll";      Family="wiadefui";      Cat="A7-Devices";      Notes="WIA default UI" }

    # A8 - Network extended
    @{ Name="fdproxy.dll";       Family="fdproxy";       Cat="A8-Network";      Notes="Function Discovery proxy" }
    @{ Name="fdssdp.dll";        Family="fdssdp";        Cat="A8-Network";      Notes="Function Discovery SSDP" }
    @{ Name="pnrpauto.dll";      Family="pnrpauto";      Cat="A8-Network";      Notes="PNRP auto" }
    @{ Name="pnrpnsp.dll";       Family="pnrpnsp";       Cat="A8-Network";      Notes="PNRP namespace provider" }
    @{ Name="rasdlg.dll";        Family="rasdlg";        Cat="A8-Network";      Notes="RAS dialing UI" }
)

$wave4 = @(
    # Additional COM / RPC servers
    @{ Name="comsvcs.dll";       Family="comsvcs";       Cat="A2-COM";          Notes="COM+ Services (transactions)" }
    @{ Name="txflog.dll";        Family="txflog";        Cat="A2-COM";          Notes="KTM transactional log" }
    @{ Name="xolehlp.dll";       Family="xolehlp";       Cat="A2-COM";          Notes="MSDTC transaction helper" }
    @{ Name="comsnap.dll";       Family="comsnap";       Cat="A2-COM";          Notes="COM+ snap-in" }

    # Security extensions
    @{ Name="cscapi.dll";        Family="cscapi";        Cat="A3-Security";     Notes="Offline files API" }
    @{ Name="cscdll.dll";        Family="cscdll";        Cat="A3-Security";     Notes="Offline files DLL" }
    @{ Name="dpapisrv.dll";      Family="dpapisrv";      Cat="A3-Security";     Notes="DPAPI server" }
    @{ Name="lsasrv.dll";        Family="lsasrv";        Cat="A3-Security";     Notes="LSA server" }

    # Multimedia legacy
    @{ Name="icm32.dll";         Family="icm32";         Cat="A4-Multimedia";   Notes="Image Color Management" }
    @{ Name="iccvid.dll";        Family="iccvid";        Cat="A4-Multimedia";   Notes="Cinepak codec" }
    @{ Name="msrle32.dll";       Family="msrle32";       Cat="A4-Multimedia";   Notes="RLE video codec" }
    @{ Name="msvidc32.dll";      Family="msvidc32";      Cat="A4-Multimedia";   Notes="Video 1 codec" }

    # Remote / WMI extended
    @{ Name="wmiperf.dll";       Family="wmiperf";       Cat="A2-WMI";          Notes="WMI performance adapter" }
    @{ Name="wmiprov.dll";       Family="wmiprov";       Cat="A2-WMI";          Notes="WMI provider loader" }
    @{ Name="wmiutils.dll";      Family="wmiutils";      Cat="A2-WMI";          Notes="WMI utilities" }
    @{ Name="faultrep.dll";      Family="faultrep";      Cat="A6-System";       Notes="Windows Error Reporting" }
    @{ Name="wer.dll";           Family="wer";           Cat="A6-System";       Notes="WER API" }

    # Printing extended
    @{ Name="printui.dll";       Family="printui";       Cat="A4-Printing";     Notes="Print UI dialogs" }
    @{ Name="prntvpt.dll";       Family="prntvpt";       Cat="A4-Printing";     Notes="Print ticket / GDI" }
    @{ Name="inetcpl.cpl";       Family="inetcpl";       Cat="A8-Network";      Notes="Internet Control Panel" }

    # Misc high-value
    @{ Name="ntshrui.dll";       Family="ntshrui";       Cat="A5-Shell";        Notes="Network share UI" }
    @{ Name="cryptnet.dll";      Family="cryptnet";       Cat="A3-Crypto";       Notes="Crypto network (CRL)" }
    @{ Name="imagehlp.dll";      Family="imagehlp";       Cat="A6-System";       Notes="Image helper (PE loader)" }
    @{ Name="dbghelp.dll";       Family="dbghelp";        Cat="A6-System";       Notes="Debug Helper (minidump)" }
    @{ Name="symsrv.dll";        Family="symsrv";         Cat="A6-System";       Notes="Symbol server client" }
    @{ Name="csrss.exe";         Family="csrss";          Cat="A6-System";       Notes="Client/Server Runtime Subsystem" }  # Actually exe but contains many exported funcs
)

# ─── Overlarge binaries (special handling) ─────────────────────────────────────
$overlarge = @(
    @{ Name="ntoskrnl.exe";     Family="ntoskrnl";      Cat="A0-Kernel";       Notes="NT kernel (3k+ funcs)" }
    @{ Name="mshtml.dll";       Family="mshtml";        Cat="A2-Browser";      Notes="Trident HTML engine (3k+ funcs)" }
)

# ─── Helper functions ──────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Color = "Gray")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp $Message" | Out-File -FilePath $logFile -Append
    Write-Host "$timestamp $Message" -ForegroundColor $Color
}

function Export-WithGhidra {
    param(
        [string]$Name,
        [string]$Family,
        [string]$SrcPath
    )

    $outJson = "$exportDir\${Family}_export.json"
    $outLib = "$fksDir\${Family}_ghidra.fkslib"
    $startTime = Get-Date

    # Skip if already exists and not forcing
    if (!$Force -and (Test-Path $outLib)) {
        $size = (Get-Item $outLib).Length
        if ($size -gt 500) {
            Write-Log "  SKIP: $Family already exists ($([math]::Round($size/1024,1))KB)" "DarkGray"
            return @{ Status="SKIP"; Reason="exists" }
        }
    }

    # Step 1: Ghidra headless export (synchronous)
    Remove-Item $outJson -ErrorAction SilentlyContinue
    $env:ENIGMA_GHIDRA_OUTPUT = $outJson

    Write-Host "  [Ghidra] $Family..." -NoNewline
    & "$ghidraRoot\support\analyzeHeadless.bat" $ghidraProj "EnigmaFKS_$family" -import $SrcPath -postScript EnigmaExportFidMatches.java -scriptPath $ghidraScript -readOnly -deleteProject 2>&1 | Out-Null

    if ($LASTEXITCODE -ne 0 -or !(Test-Path $outJson)) {
        Write-Host " FAIL" -ForegroundColor Red
        Write-Log "  FAIL (Ghidra export): $Name ($Family)" "Red"
        return @{ Status="FAIL"; Reason="Ghidra export failed" }
    }

    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    $jsonSize = [math]::Round((Get-Item $outJson).Length / 1024, 1)
    Write-Host " OK (${elapsed}s, ${jsonSize}KB)" -ForegroundColor Green

    # Step 2: FKS ingest
    Write-Host "  [Ingest] $Family..." -NoNewline
    & $ingestTool $outJson $outLib --family $Family --compiler msvc --version 10.0.19041 2>&1 | Out-Null

    if (!(Test-Path $outLib)) {
        Write-Host " FAIL" -ForegroundColor Red
        Write-Log "  FAIL (ingest): $Name ($Family)" "Red"
        return @{ Status="FAIL"; Reason="ingest failed"; JsonSize=$jsonSize }
    }

    $libSize = [math]::Round((Get-Item $outLib).Length / 1024, 1)
    Write-Host " OK (${libSize}KB)" -ForegroundColor Green
    Write-Log "  OK: $Family (${elapsed}s, ${jsonSize}KB JSON, ${libSize}KB FKS)" "Green"
    return @{ Status="OK"; Reason="success"; JsonSize=$jsonSize; LibSize=$libSize }
}

function Process-Wave {
    param([string]$WaveName, [array]$Dlls)

    if ($Dlls.Count -eq 0) { return @() }

    Write-Log "============================================================" "Cyan"
    Write-Log "  $WaveName ($($Dlls.Count) DLLs)" "Cyan"
    Write-Log "============================================================" "Cyan"

    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

    $results = @()
    $ok = 0; $skip = 0; $fail = 0

    foreach ($dll in $Dlls) {
        $name = $dll.Name
        $family = $dll.Family
        $srcPath = "$system32\$name"

        if (!(Test-Path $srcPath)) {
            Write-Log "  SKIP (not found): $name ($Family)" "Yellow"
            $skip++
            $results += [PSCustomObject]@{ Family=$family; Name=$name; Status="SKIP"; Reason="not found" }
            continue
        }

        $result = Export-WithGhidra -Name $name -Family $Family -SrcPath $srcPath
        switch ($result.Status) {
            "OK"     { $ok++ }
            "SKIP"   { $skip++ }
            "FAIL"   { $fail++ }
        }
        $results += [PSCustomObject]@{ Family=$family; Name=$name; Status=$result.Status; Reason=$result.Reason }
    }

    Write-Log "  --- ${WaveName}: OK=$ok SKIP=$skip FAIL=$fail ---" "Yellow"
    return $results
}

# ─── Main ──────────────────────────────────────────────────────────────────────

New-Item -ItemType Directory -Path $enigmaRoot\build -Force | Out-Null
"Phase A Ingest Log" | Out-File -FilePath $logFile

Write-Log "Phase A: Windows System DLL expansion" "Green"
Write-Log "  Ghidra: $ghidraRoot" "Gray"
Write-Log "  FKS dir: $fksDir" "Gray"
Write-Log "  Existing libraries: $($existing.Count)" "Gray"
Write-Log "  Timeout: ${TimeoutSec}s per DLL" "Gray"
Write-Log "  Force re-export: $Force" "Gray"

# ─── List missing mode ─────────────────────────────────────────────────────────
if ($ListMissing) {
    Write-Log "`nListing missing high-value DLLs..." "Cyan"
    $allWaves = $wave1 + $wave2 + $wave3 + $wave4 + $overlarge
    $missing = $allWaves | Where-Object { !$existing.ContainsKey($_.Family) }
    $present = $allWaves | Where-Object { $existing.ContainsKey($_.Family) }
    Write-Log "  Total target: $($allWaves.Count)" "Gray"
    Write-Log "  Already in corpus: $($present.Count)" "Green"
    Write-Log "  Missing: $($missing.Count)" "Yellow"
    Write-Log "`n=== Missing DLLs ===" "Cyan"
    $missing | Select-Object Name, Family, Cat, Notes | Format-Table -AutoSize
    Write-Log "`n=== Already present ===" "Cyan"
    $present | Select-Object Name, Family, Cat | Format-Table -AutoSize
    exit 0
}

# ─── Reindex only mode ─────────────────────────────────────────────────────────
if ($ReindexOnly) {
    Write-Log "`nRebuilding LMDB index..." "Cyan"
    & "$enigmaRoot\build\enigma_fks_build_index.exe" $fksDir 2>&1
    Write-Log "Index rebuild complete." "Green"
    exit 0
}

# ─── Process requested wave(s) ─────────────────────────────────────────────────
Push-Location $enigmaRoot

$allResults = @()

if ($Wave -eq 0 -or $Wave -eq 1) {
    $r = Process-Wave -WaveName "Wave 1 (Top Priority)" -Dlls $wave1
    $allResults += $r
}
if ($Wave -eq 0 -or $Wave -eq 2) {
    $r = Process-Wave -WaveName "Wave 2 (High Priority)" -Dlls $wave2
    $allResults += $r
}
if ($Wave -eq 0 -or $Wave -eq 3) {
    $r = Process-Wave -WaveName "Wave 3 (Medium Priority)" -Dlls $wave3
    $allResults += $r
}
if ($Wave -eq 0 -or $Wave -eq 4) {
    $r = Process-Wave -WaveName "Wave 4 (Extended)" -Dlls $wave4
    $allResults += $r
}

# Handle overlarge binaries (Wave 0 only — extended timeout)
if ($Wave -eq 0) {
    Write-Log "`n============================================================" "Magenta"
    Write-Log "  Overlarge Binaries (special handling, ${TimeoutSec}s timeout)" "Magenta"
    Write-Log "============================================================" "Magenta"
    $r = Process-Wave -WaveName "Overlarge" -Dlls $overlarge
    $allResults += $r
}

# ─── Rebuild LMDB index (always after processing) ──────────────────────────────
Write-Log "`n=== Rebuilding LMDB index ===" "Cyan"
& "$enigmaRoot\build\enigma_fks_build_index.exe" $fksDir 2>&1

# ─── Final summary ─────────────────────────────────────────────────────────────
$totalOk = ($allResults | Where-Object { $_.Status -eq "OK" }).Count
$totalSkip = ($allResults | Where-Object { $_.Status -eq "SKIP" }).Count
$totalFail = ($allResults | Where-Object { $_.Status -eq "FAIL" }).Count
Write-Log "`n============================================================" "Green"
Write-Log "  Phase A Complete" "Green"
Write-Log "  OK: $totalOk Added | SKIP: $totalSkip | FAIL: $totalFail" "Green"
Write-Log "============================================================" "Green"

# Export CSV report
$allResults | Export-Csv -Path $reportFile -NoTypeInformation
Write-Log "Report: $reportFile" "Gray"

Pop-Location
