# ============================================================
# probe41.ps1 -- READ-ONLY field verification of the offline-baked native WiFi (vWiFi) stack.
#
# Why this probe exists: everything we can prove from the host side is already proven
# (nwifi.sys covered by the Package04 catalog, 4 INF + 4 .sys baked, 3 service keys written,
# wireless driver pool staged into DriverStore). The one thing no host-side check can answer is
# whether PnP resolves "Include = netvwifibus.inf" from X:\Windows\INF at BOOT time, i.e. whether
# the Intel adapter leaves code 37 and whether wlansvc finally answers WlanOpenHandle.
#
# Run inside WinPE (PS 5.1 ships in the image but is NOT on PATH):
#   X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\probe41.ps1
# Push it from the host:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 -Local test\share\probe41.ps1 `
#     -RemotePath X:\probe41.ps1 -Target administrator@192.168.0.107 -Port 22 -Run
#
# Output is ASCII only (it comes back through pe-sshd). Nothing here writes to disk or registry.
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }

$V_inf   = 0; $V_sys = 0; $V_store = 0; $V_svcKey = 0
$V_upper = 'none'; $V_wlanOpen = -1; $V_wlanSvc = 'unknown'
$V_codes = @(); $V_missing = -1

# 1) which disk is this build? (BUILD_TAG carries the bake evidence line)
O '== 1 TAG =='
$tag = 'X:\BUILD_TAG.txt'
if (Test-Path $tag) {
  @(Get-Content $tag -EA SilentlyContinue) | ForEach-Object {
    if ("$_" -match 'wlandrv|wifi_patch|build|driverstore') { O ('  TAG ' + ($_ -replace '\s+', ' ')) }
  }
} else { O '  TAG X:\BUILD_TAG.txt = absent' }

# 2) the four vWiFi INFs must be in the OS INF folder (that is the only place boot-time
#    Include= resolution can look, because DISM cannot stage inbox INFs -- no [SourceDisks*])
O '== 2 INF files in X:\Windows\INF =='
foreach ($n in @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')) {
  $p = 'X:\Windows\INF\' + $n
  if (Test-Path $p) { $V_inf++; O ('  INF OK   ' + $n + ' ' + (Get-Item $p).Length + 'B') }
  else { O ('  INF MISS ' + $n) }
}
O ('  INF_COUNT ' + $V_inf + '/4')

# 3) the four .sys files, with versions (19041-era stack riding on 26100 NDIS)
O '== 3 driver .sys files =='
foreach ($n in @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys')) {
  $p = 'X:\Windows\System32\drivers\' + $n
  if (Test-Path $p) {
    $V_sys++
    $i = Get-Item $p
    $v = $i.VersionInfo
    O ('  SYS OK   ' + $n + ' ' + $i.Length + 'B ver=' + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' +
       $v.FileBuildPart + '.' + $v.FilePrivatePart)
  } else { O ('  SYS MISS ' + $n) }
}
O ('  SYS_COUNT ' + $V_sys + '/4')

# 4) DriverStore + the in-image oem###.inf copies. Field meaning (2026-10-09 bake, measured):
#    DISM stages netvwififlt/netvwifimp/netnwifi (rc=0) and refuses netvwifibus.inf with rc=13
#    (it is the only one of the four declaring CopyFiles + [DestinationDirs], while none of the
#    four has [SourceDisks*]). A FileRepository dir for the bus may still exist as an ABORTED
#    leftover, so print what is inside each dir instead of trusting the dir count, and count the
#    oem*.inf files that actually carry a vWiFi section -- those are what PnP indexes at boot.
O '== 4 DriverStore / oem inf =='
$fr = 'X:\Windows\System32\DriverStore\FileRepository'
if (Test-Path $fr) {
  $allFr = @(Get-ChildItem $fr -Directory -EA SilentlyContinue)
  foreach ($n in @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')) {
    $ln = $n.ToLower()
    $hits = @($allFr | Where-Object { $_.Name.ToLower().StartsWith($ln + '_') })
    if ($hits.Count -gt 0) { $V_store++ }
    foreach ($h in $hits) {
      $files = @(Get-ChildItem -LiteralPath $h.FullName -File -Recurse -EA SilentlyContinue | ForEach-Object { $_.Name })
      O ('  STORE ' + $n + ' dir=' + $h.Name + ' files=' + $(if ($files.Count) { ($files | Sort-Object) -join ',' } else { 'EMPTY' }))
    }
    if ($hits.Count -eq 0) { O ('  STORE ' + $n + ' dirs=0') }
  }
  O ('  STORE_FR_TOTAL ' + $allFr.Count)
} else { O '  STORE X:\Windows\System32\DriverStore\FileRepository = absent' }
O ('  STORE_COUNT ' + $V_store + '/4 (dir present != package installed; read the files= lines above)')
$oemInf = @(Get-ChildItem 'X:\Windows\INF' -Filter 'oem*.inf' -File -EA SilentlyContinue)
O ('  OEM_INF_TOTAL ' + $oemInf.Count)
$ow = @()
foreach ($f in $oemInf) {
  $t = @(Get-Content -LiteralPath $f.FullName -Encoding Unicode -EA SilentlyContinue)
  $vn = @($t | Where-Object { "$_" -match '(?i)netvwifibus|netvwififlt|netvwifimp|netnwifi' } | Select-Object -First 2)
  if ($vn.Count -gt 0) { $ow += ($f.Name + ' [' + (($t | Where-Object { "$_" -match '^\s*driverver' } | Select-Object -First 1) -replace '\s+', ' ') + ']') }
}
if ($ow.Count -eq 0) { O '  OEM_INF_VWIFI none' } else { foreach ($o2 in $ow) { O ('  OEM_INF_VWIFI ' + $o2) } }

# 5) service keys + start type (reg.exe read-back is authoritative in PE; the WMI class name
#    filter used to miss nativewifip, so do not trust Win32_SystemDriver alone)
function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|DWORD|MULTI_SZ)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
    }
  }
  return ''
}
O '== 5 service keys =='
foreach ($s in @('vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'wlansvc', 'wcmsvc', 'Netman', 'dot3svc')) {
  $k = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $s
  $start = RegGet $k 'Start'; $type = RegGet $k 'Type'; $img = RegGet $k 'ImagePath'
  if ("$start" -ne '') {
    $V_svcKey++
    O ('  SVC ' + $s + ' Start=' + $start + ' Type=' + $type + ' Img=' + $img)
  } else { O ('  SVC ' + $s + ' = ABSENT') }
}
O ('  SVCKEY_COUNT ' + $V_svcKey)

# 6) NDIS filter chains: the class key plus the Intel device's own devnode key.
#    If PnP wrote UpperFilters=vwifibus itself, the Include= resolution worked.
O '== 6 filter chains =='
$cls = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
$cu = RegGet $cls 'UpperFilters'; $cl = RegGet $cls 'LowerFilters'
O ('  CLASS UpperFilters=' + $(if ($cu) { $cu } else { '-' }) + ' LowerFilters=' + $(if ($cl) { $cl } else { '-' }))
if ($cu -match 'vwifibus') { $V_upper = 'class' }
$pci = 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI'
if (Test-Path $pci) {
  foreach ($h in @(Get-ChildItem $pci -EA SilentlyContinue)) {
    foreach ($d in @(Get-ChildItem $h.PSPath -EA SilentlyContinue)) {
      $pp = Get-ItemProperty -LiteralPath $d.PSPath -EA SilentlyContinue
      if ($pp -and "$($pp.Service)" -match '(?i)netwtw|vwifi|nativewifip') {
        $up = ($pp.UpperFilters -join ','); $lo = ($pp.LowerFilters -join ',')
        if ($up -match 'vwifibus') { $V_upper = 'devnode' }
        O ('  DEVNODE ' + $d.PSChildName + ' svc=' + $pp.Service + ' class=' + $pp.Class +
           ' driver=' + $pp.Driver + ' problem=' + $pp.Problem +
           ' upper=' + $(if ($up) { $up } else { '-' }) + ' lower=' + $(if ($lo) { $lo } else { '-' }))
      }
    }
  }
}

# 7) device problem codes -- code 37 was the symptom, code 28 means "no driver bound yet",
#    code 0 means it actually attached.
O '== 7 PnP devices (Net + System devices that look WiFi-ish) =='
try {
  $devs = @(Get-CimInstance Win32_PnPEntity -EA Stop |
            Where-Object { ($_.ClassGuid -eq '{4d36e972-e325-11ce-bfc1-08002be10318}' -or
                            $_.Name -match '(?i)wireless|wi.?fi|virtual wifi|802\.11|ax2|ac ') })
  foreach ($x in $devs) {
    $code = $x.ConfigManagerErrorCode
    $V_codes += ("{0}" -f $code)
    O ('  DEV code=' + $code + ' name=' + $x.Name + ' id=' + $x.DeviceID)
  }
  if ($devs.Count -eq 0) { O '  DEV none matched (is a wireless NIC present at all?)' }
} catch { O ('  DEV query failed: ' + $_.Exception.Message) }

# 8) wlansvc and the actual WiFi API entry point. rc=1062 = "service not running";
#    rc=0 is the first time this project would see a real handle.
O '== 8 wlansvc / WlanOpenHandle =='
try {
  $svc = Get-Service -Name wlansvc -EA Stop
  $V_wlanSvc = "$($svc.Status)"
  O ('  SVCSTATE wlansvc = ' + $V_wlanSvc)
} catch { O ('  SVCSTATE wlansvc unavailable: ' + $_.Exception.Message) }
try {
  if (-not ('P41.P41W' -as [type])) {
    # WlanOpenHandle 是 wlanapi.dll 的导出(不是 wlancfg.dll —— 宿主机上实测 wlancfg.dll 里找不到这个入口点)
    Add-Type -Namespace P41 -Name P41W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  }
  $nv = 0; $h = [IntPtr]::Zero
  $V_wlanOpen = [P41.P41W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
  O ('  WLANOPEN rc=' + $V_wlanOpen + ' newVer=' + $nv)
  if ($V_wlanOpen -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P41.P41W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('  WLANOPEN failed to call: ' + $_.Exception.Message) }

# 9) setupapi offline log -- the decisive text. "Needed section ... not found, might exist in
#    missing included INF" means Include= still did not resolve; absence + a bound device means it did.
O '== 9 setupapi log =='
foreach ($lg in @('X:\Windows\INF\setupapi.offline.log', 'X:\Windows\INF\setupapi.setup.log',
                  'X:\Windows\INF\setupapi.dev.log')) {
  if (Test-Path $lg) {
    $t = @(Get-Content $lg -Encoding Unicode -EA SilentlyContinue)
    O ('  LOG ' + $lg + ' lines=' + $t.Count)
    $miss = @($t | Where-Object { "$_" -match '(?i)missing included INF|Needed section' })
    $vw   = @($t | Where-Object { "$_" -match '(?i)vwifi|nwifi|netwtw' })
    O ('  LOGMISS_COUNT ' + $miss.Count)
    if ($V_missing -lt 0) { $V_missing = $miss.Count }
    foreach ($m in @($miss | Select-Object -Last 6)) { O ('    MISS ' + (("$m" -replace '\s+', ' ').Trim())) }
    foreach ($m in @($vw | Select-Object -Last 12)) { O ('    VWIFI ' + (("$m" -replace '\s+', ' ').Trim())) }
  } else { O ('  LOG ' + $lg + ' = absent') }
}

# 10) one-line verdict for reading over ssh
O '== 10 VERDICT =='
$nicCodes = $(if ($V_codes.Count) { ($V_codes -join ',') } else { 'n/a' })
O ('P41 VERDICT inf=' + $V_inf + '/4 sys=' + $V_sys + '/4 store=' + $V_store + '/4 svckey=' + $V_svcKey +
   ' upper=' + $V_upper + ' wlansvc=' + $V_wlanSvc + ' wlanopen=' + $V_wlanOpen +
   ' devcodes=' + $nicCodes + ' setupapi_missing=' + $V_missing)
if ($V_wlanOpen -eq 0) { O 'P41 READING: wlansvc answered -- native WiFi stack is alive, go on with wlan.cmd' }
elseif ($V_upper -ne 'none' -and $V_wlanOpen -ne 0) { O 'P41 READING: filter chain is in place but wlansvc still fails; read section 5/8 and setupapi above' }
elseif ($V_inf -eq 4) { O 'P41 READING: vWiFi files baked and present, but no UpperFilters written -> boot-time Include= did NOT resolve; next step is decorated packages with [SourceDisks*]' }
else { O 'P41 READING: the bake itself did not land, check BUILD_TAG and re-run patch_wifi.ps1' }
O 'P41 END'
