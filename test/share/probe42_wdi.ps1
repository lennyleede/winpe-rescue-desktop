# ============================================================
# probe42_wdi.ps1 -- READ-ONLY field verification of the WDI framework + native WiFi stack
#                    baked offline into the PE image (2026-10-10 bake).
#
# Why this probe exists:
#   probe79/81 closed the root cause on the live ramdisk: every Wi-Fi miniport that can bind the
#   laptop's AX211 is WDI-based (it imports NdisMRegisterWdiMiniportDriver from ndis.sys, which only
#   forwards to wdiwifi.sys exports). With no wdiwifi file/service key in the image the driver's
#   DriverEntry returns 0xC00000BB -> PnP code 37 + Services\<driver>\Enum\INITSTARTFAILED=1.
#   35 of 48 Wi-Fi packages in D: and X: are WDI, and all 6 INFs claiming PCI\VEN_8086&DEV_7A70 are
#   WDI, so there is no classic package to sidestep with. Runtime repair is impossible in PE
#   (no catroot2/CryptSvc, NtLoadDriver = 0xC0000061, SCM 1060 for runtime keys), so the fix is
#   baked offline: 6 .sys + 4 INF + service keys + covering catalogs. Only a boot can prove it.
#
# What counts as PASS (all from one run):
#   FILES 6/6 WDI+vWiFi .sys, INF 4/4 in X:\Windows\INF, CAT 2/2 in CatRoot
#   SVC   wdiwifi + NdisImPlatform keys exist (Type=1 Start=3, no Group)
#   DEVCODES the Intel adapter leaves 37 (0 = bound, 28 = driver not chosen yet, 52 = CI rejection)
#   INITFAIL Services\<driver>\Enum\INITSTARTFAILED gone
#   VWIFIBUS a "Virtual WiFi Adapter"/vwifibus node exists -> boot-time Include= resolved
#   WLANOPEN rc=0 -> wlansvc alive, which is the actual goal ("PE must be able to reach the network")
#
# It only starts wlansvc if it exists and is stopped (the ramdisk is ephemeral, and being able to
# start it is the acceptance criterion). Nothing else is written; no driver is loaded by hand.
#
# Push + run from the host (LAN straight to the laptop; the PE must be booted from the new stick):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 -Local test\share\probe42_wdi.ps1 `
#     -RemotePath X:\p42.ps1 -StagingB64 X:\p42.b64 -Target administrator@192.168.0.107 -Port 22 -Run
# Output is ASCII only (it comes back through pe-sshd, where multi-line Chinese turns into ??).
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }

$Sys32 = 'X:\Windows\System32'
$Acc = @{ inf = 0; sys = 0; wdi = 0; cat = 0; svckey = 0; paramkey = 0; upper = 'none';
        wlanOpen = -1; wlanSvc = 'unknown'; codes = @(); initfail = 'n/a';
        vwifibusNode = 'no'; setupMissing = -1; drvStart = 'n/a';
        # wifiDev = how many PnP nodes are actually WIRELESS (name match), wifiOk = of those, how many
        # carry problem code 0. Section 7's filter also catches the Ethernet controller (same ClassGuid),
        # so 'devcodes=0,0' alone cannot tell "the WiFi card is healthy" from "there is no WiFi card" --
        # field run 2026-10-10 21:38 (build/scratch/wifi_accept_10102138.txt) is exactly that case:
        # AX211 enumerated code=0, Netwtw14 Running, yet the old READING text said "adapter not enumerated".
        wifiDev = 0; wifiOk = 0 }

O '== 1 BUILD_TAG (which bake is this?) =='
$tag = 'X:\BUILD_TAG.txt'
if (Test-Path $tag) {
  @(Get-Content $tag -EA SilentlyContinue) | ForEach-Object {
    if ("$_" -match '(?i)wlandrv|wifi_patch|vwifi|wdi_|build') { O ('  TAG ' + ($_ -replace '\s+', ' ')) }
  }
} else { O '  TAG absent' }

O '== 2 driver .sys files (4 vWiFi + 2 WDI) =='
foreach ($n in @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys')) {
  $p = Join-Path $Sys32 ('drivers\' + $n)
  if (Test-Path $p) {
    $Acc.sys++; $i = Get-Item $p; $vi = $i.VersionInfo
    O ('  SYS OK   ' + $n + ' ' + $i.Length + 'B ver=' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' +
       $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
  } else { O ('  SYS MISS ' + $n) }
}
foreach ($n in @('wdiwifi.sys', 'NdisImPlatform.sys')) {
  $p = Join-Path $Sys32 ('drivers\' + $n)
  if (Test-Path $p) {
    $Acc.wdi++; $i = Get-Item $p; $vi = $i.VersionInfo
    O ('  WDI OK   ' + $n + ' ' + $i.Length + 'B ver=' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' +
       $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
  } else { O ('  WDI MISS ' + $n) }
}
O ('  WDI_COUNT ' + $Acc.wdi + '/2')

O '== 3 covering catalogs in CatRoot =='
$store = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
if (Test-Path $store) {
  foreach ($pat in @('Microsoft-Windows-Client-Desktop-Required-Package04*.cat',
                     'Microsoft-Windows-Client-Desktop-Required-Package05112*.cat')) {
    $h = @(Get-ChildItem -LiteralPath $store -Filter $pat -File -EA SilentlyContinue)
    if ($h.Count -gt 0) { $Acc.cat++; O ('  CAT OK   ' + $h[0].Name + ' ' + $h[0].Length + 'B') }
    else { O ('  CAT MISS ' + $pat) }
  }
  O ('  CAT_TOTAL ' + (@(Get-ChildItem -LiteralPath $store -Filter *.cat -File -EA SilentlyContinue)).Count)
} else { O '  CAT store absent' }

O '== 4 the four vWiFi INFs in X:\Windows\INF =='
foreach ($n in @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')) {
  $p = 'X:\Windows\INF\' + $n
  if (Test-Path $p) { $Acc.inf++; O ('  INF OK   ' + $n + ' ' + (Get-Item $p).Length + 'B') }
  else { O ('  INF MISS ' + $n) }
}
O ('  INF_COUNT ' + $Acc.inf + '/4')

function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
    }
  }
  return ''
}
# Two path dialects, and mixing them up silently lies (it cost us the false wdi_paramkey=0/2 reading
# on a correctly baked image): Test-Path / Get-Item* need the PROVIDER form 'HKLM:\...', reg.exe needs
# the PLAIN form 'HKLM\...'. ToReg converts a provider/PSPath string into what reg.exe understands.
function ToReg([string]$p) {
  (($p -replace '^Microsoft\.PowerShell\.Core\\Registry::', '') -replace '^HKEY_LOCAL_MACHINE', 'HKLM') -replace '^HKLM:', 'HKLM'
}
$SVCP = 'HKLM:\SYSTEM\CurrentControlSet\Services'      # provider form
$SVCR = 'HKLM\SYSTEM\CurrentControlSet\Services'       # reg.exe form

O '== 5 service keys (Type/Start/ImagePath as baked) =='
foreach ($s in @('vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'wdiwifi', 'NdisImPlatform', 'wlansvc', 'wcmsvc', 'Netman', 'dot3svc')) {
  $k = $SVCR + '\' + $s
  $st = RegGet $k 'Start'; $ty = RegGet $k 'Type'; $im = RegGet $k 'ImagePath'; $gr = RegGet $k 'Group'
  if ("$st" -ne '') {
    $Acc.svckey++
    O ('  SVC ' + $s + ' Type=' + $ty + ' Start=' + $st + ' Group=' + $(if ($gr) { $gr } else { '-' }) + ' Img=' + $im)
  } else { O ('  SVC ' + $s + ' = ABSENT') }
}
# Parameters subkeys must exist for the two WDI drivers (allow lists / trace guid)
foreach ($s in @('wdiwifi', 'NdisImPlatform')) {
  $kp = $SVCP + '\' + $s + '\Parameters'          # PROVIDER form: Test-Path / Get-ItemProperty
  # Why Parameters is the discriminator: the earlier probes hand-wrote wdiwifi/NdisImPlatform service
  # keys onto the RUNNING ramdisk (runtime keys are invisible to the SCM -> Win32_SystemDriver says
  # "not listed", and PnP still reports code 37). The bake writes a Parameters subkey next to every
  # value; a leftover runtime key never has one. So paramkey=0/2 on a booted PE means "this is still
  # the old image with staged files", not "the bake failed".
  if (Test-Path $kp) { $Acc.paramkey++ }
  O ('  PARAM ' + $s + ' = ' + $(if (Test-Path $kp) { 'exists' } else { 'ABSENT' }) +
     ' values=' + $(if (Test-Path $kp) { (@(Get-ItemProperty $kp -EA SilentlyContinue).PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS_' } | ForEach-Object { $_.Name }) -join ',' } else { '-' }))
}
# Is wdiwifi actually loaded? Win32_SystemDriver reflects the SCM/driver state at boot.
O '== 6 loaded state (Win32_SystemDriver) =='
$drvNames = @('wdiwifi', 'NdisImPlatform', 'vwififlt', 'vwifimp', 'vwifibus')
$drvNames += @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue |
               Where-Object { $_.PSChildName -match '(?i)^netwtw|^netwaw|^rtwlane' } |
               ForEach-Object { $_.PSChildName })
foreach ($s in $drvNames) {
  try {
    $d = @(Get-CimInstance Win32_SystemDriver -EA Stop | Where-Object { $_.Name -eq $s })
    if ($d.Count -gt 0) { O ('  LSDRV ' + $s + ' state=' + $d[0].State + ' startmode=' + $d[0].StartMode) }
    else { O ('  LSDRV ' + $s + ' not listed') }
  } catch { O ('  LSDRV ' + $s + ' query failed: ' + $_.Exception.Message) }
}

O '== 7 PnP: adapter problem codes + vwifibus node =='
try {
  $devs = @(Get-CimInstance Win32_PnPEntity -EA Stop |
            Where-Object { ($_.ClassGuid -eq '{4d36e972-e325-11ce-bfc1-08002be10318}' -or
                            $_.Name -match '(?i)wireless|wi.?fi|virtual wifi|802\.11|ax21|ax20|netwtw|rtwlane|mt79') })
  foreach ($x in $devs) {
    $code = $x.ConfigManagerErrorCode
    $Acc.codes += ("{0}" -f $code)
    if ("$($x.Name)" -match '(?i)virtual wifi|vwifibus') { $Acc.vwifibusNode = 'yes' }
    # Count the WIRELESS nodes separately: the ClassGuid filter above also matches the Ethernet controller,
    # so devcodes=0,0 says nothing on its own (see the $Acc comment). Name match is what identifies a WiFi
    # adapter here (Intel(R) Wi-Fi 6E AX211 / Netwtw / rtwlane / MT79 all match).
    if ("$($x.Name)" -match '(?i)wireless|wi.?fi|802\.11|netwtw|rtwlane|mt79|ax2[0-9]|rtl8') {
      $Acc.wifiDev++
      if ($code -eq 0) { $Acc.wifiOk++ }
    }
    O ('  DEV code=' + $code + ' name=' + $x.Name + ' id=' + $x.DeviceID + ' status=' + $x.Status)
  }
  if ($devs.Count -eq 0) { O '  DEV none matched (no wireless NIC enumerated at all?)' }
} catch { O ('  DEV query failed: ' + $_.Exception.Message) }

O '== 8 INITSTARTFAILED + devnode filter chains =='
# The driver service name depends on which package bound the card (Netwtw14 / Netwtw6e / rtwlane...),
# so enumerate the Services keys instead of hard-coding candidates. INITSTARTFAILED=1 under \Enum is
# the fingerprint of a DriverEntry that returned 0xC00000BB -- i.e. wdiwifi still missing.
$cand = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue |
          Where-Object { $_.PSChildName -match '(?i)^netwtw|^netwaw|^rtwlane|^Netwtw|^rtl' })
if ($cand.Count -eq 0) { O '  WLANDRV no wifi driver service key found (card never bound)' }
foreach ($c in $cand) {
  $ke = Join-Path $c.PSPath 'Enum'
  if (Test-Path $ke) {
    $iv = RegGet (ToReg $ke) 'INITSTARTFAILED'
    O ('  INITFAIL ' + $c.PSChildName + ' = ' + $(if ("$iv" -ne '') { $iv } else { 'ABSENT(good)' }))
    if ("$iv" -ne '') { $Acc.initfail = $iv } else { $Acc.initfail = 'absent' }
  } else { O ('  INITFAIL ' + $c.PSChildName + ' = no Enum key (never started)') }
}
$pci = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
if (Test-Path $pci) {
  foreach ($h in @(Get-ChildItem $pci -EA SilentlyContinue)) {
    foreach ($d in @(Get-ChildItem $h.PSPath -EA SilentlyContinue)) {
      $pp = Get-ItemProperty -LiteralPath $d.PSPath -EA SilentlyContinue
      if ($pp -and "$($pp.Service)" -match '(?i)netwtw|netwaw|vwifi|nativewifip') {
        $up = ($pp.UpperFilters -join ',')
        if ($up -match 'vwifibus') { $Acc.upper = 'devnode' }
        O ('  DEVNODE ' + $d.PSChildName + ' svc=' + $pp.Service + ' driver=' + $pp.Driver +
           ' problem=' + $pp.Problem + ' upper=' + $(if ($up) { $up } else { '-' }))
      }
    }
  }
}
$cls = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
$cu = RegGet $cls 'UpperFilters'
if ($cu -match 'vwifibus') { $Acc.upper = 'class' }
O ('  CLASS UpperFilters=' + $(if ($cu) { $cu } else { '-' }))

O '== 9 wlansvc + WlanOpenHandle =='
try {
  $svc = Get-Service -Name wlansvc -EA Stop
  $Acc.wlanSvc = "$($svc.Status)"
  O ('  SVCSTATE wlansvc = ' + $Acc.wlanSvc)
  if ("$($svc.Status)" -eq 'Stopped') {
    Start-Service -Name wlansvc -EA Stop
    Start-Sleep -Seconds 2
    $Acc.wlanSvc = "$((Get-Service -Name wlansvc).Status)"
    O ('  SVCSTART attempted -> ' + $Acc.wlanSvc)
  }
} catch { O ('  SVCSTATE wlansvc problem: ' + $_.Exception.Message) }
try {
  if (-not ('P42.P42W' -as [type])) {
    Add-Type -Namespace P42 -Name P42W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  }
  $nv = 0; $h = [IntPtr]::Zero
  $Acc.wlanOpen = [P42.P42W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
  O ('  WLANOPEN rc=' + $Acc.wlanOpen + ' newVer=' + $nv)
  if ($Acc.wlanOpen -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P42.P42W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('  WLANOPEN call failed: ' + $_.Exception.Message) }

O '== 10 setupapi logs (decisive text) =='
foreach ($lg in @('X:\Windows\INF\setupapi.offline.log', 'X:\Windows\INF\setupapi.dev.log', 'X:\Windows\INF\setupapi.setup.log')) {
  if (Test-Path $lg) {
    $t = @(Get-Content $lg -Encoding Unicode -EA SilentlyContinue)
    $miss = @($t | Where-Object { "$_" -match '(?i)missing included INF|Needed section' })
    if ($Acc.setupMissing -lt 0) { $Acc.setupMissing = $miss.Count }
    O ('  LOG ' + $lg + ' lines=' + $t.Count + ' missing_section_lines=' + $miss.Count)
    foreach ($m in @($miss | Select-Object -Last 5)) { O ('    MISS ' + (("$m" -replace '\s+', ' ').Trim())) }
    foreach ($m in @($t | Where-Object { "$_" -match '(?i)vwifi|wdiwifi|netwtw' } | Select-Object -Last 10)) {
      O ('    WDI ' + (("$m" -replace '\s+', ' ').Trim()))
    }
  } else { O ('  LOG ' + $lg + ' = absent') }
}

O '== 11 VERDICT =='
$codes = $(if ($Acc.codes.Count) { ($Acc.codes -join ',') } else { 'n/a' })
O ('P42 VERDICT wdi_sys=' + $Acc.wdi + '/2 sys=' + $Acc.sys + '/4 inf=' + $Acc.inf + '/4 cat=' + $Acc.cat + '/2' +
   ' svckey_total=' + $Acc.svckey + ' wdi_paramkey=' + $Acc.paramkey + '/2' +
   ' upper=' + $Acc.upper + ' vwifibus_node=' + $Acc.vwifibusNode +
   ' initstartfailed=' + $Acc.initfail + ' devcodes=' + $codes +
   ' wlansvc=' + $Acc.wlanSvc + ' wlanopen=' + $Acc.wlanOpen + ' setupapi_missing=' + $Acc.setupMissing +
   ' wifi_nodes=' + $Acc.wifiDev + '/' + $Acc.wifiOk)
if ($Acc.wlanOpen -eq 0) {
  O 'P42 READING: PASS - wlansvc answers WlanOpenHandle. Native WiFi is alive; proceed to wlan.cmd / the panel.'
} elseif ($Acc.paramkey -lt 2) {
  O 'P42 READING: NOT A BAKE TEST - this PE has no WDI Parameters keys, i.e. the wdiwifi/NdisImPlatform files and keys were hand-staged at runtime. Boot the NEW ISO before drawing any conclusion.'
} elseif ($Acc.wifiOk -ge 1) {
  # 2026-10-10 21:38 field run on the WDI-baked disc (build\scratch\wifi_accept_10102138.txt):
  #   Intel(R) Wi-Fi 6E AX211 160MHz = code 0 / status OK, Netwtw14 state=Running, wdiwifi Running,
  #   INITSTARTFAILED absent, both .cat present -- i.e. the whole driver layer this project baked is DONE,
  #   while wlansvc still answers WlanOpenHandle=1062 and wcmsvc still gets 1068. So from here the evidence
  #   is NOT in PnP anymore: read probe86 on the same boot (CLOSURE + "kind="), do not chase setupapi.
  O ('P42 READING: the WiFi adapter is enumerated and healthy (wireless nodes ok=' + $Acc.wifiOk + '/' + $Acc.wifiDev +
     ') and no code 37/52 is left -- the DRIVER layer is done. What still fails is ABOVE it:')
  O '             wlansvc/wcmsvc. Run probe86 on this same boot; its CLOSURE lines show the dependency tree the SCM'
  O '             really sees and "P86 SVC wlansvc ... kind=" says whether wlansvc crashed or returned an HRESULT.'
} elseif ($Acc.vwifibusNode -eq 'yes' -and -not ($codes -match '37')) {
  O 'P42 READING: vWiFi bus resolved and no code 37 left, but wlansvc still fails - read sections 5/6/9.'
} elseif ($codes -match '37') {
  O 'P42 READING: still code 37 - WDI driver entry failed. Check wdiwifi loaded (section 6) and CI/catalog (code 52 would mean signature).'
} elseif ($codes -match '52') {
  O 'P42 READING: code 52 = code integrity rejected the signature - the covering .cat did not land or does not match the .sys hash.'
} else {
  # reaching here means wifi_nodes=0/0: no PnP node matched a wireless name at all, so the card really is
  # absent / not enumerated (radio killed in BIOS, or no package in the pool bound it -> code 28 path).
  O 'P42 READING: no wireless PnP node at all (wifi_nodes=0/0) and no code 37 - the card is not enumerated. Read section 7 and netdrvfix (code 28 = no driver bound).'
}
O 'P42 END'
