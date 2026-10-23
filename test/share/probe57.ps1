# probe57 -- LIVE PE. The decisive value diff, then the experiment.
# What we know now:
#  - The PE's baked WiFi service keys are COMPLETE (probe56 section E): wlansvc has
#    Parameters\ServiceDll=%SystemRoot%\System32\wlansvc.dll + ServiceMain=WlanSvcMain, ObjectName,
#    RequiredPrivileges, ServiceSidType; wcmsvc likewise; nativewifip/vwififlt/vwifimp/vwifibus/Ndisuio
#    all look like the 19041 reference. So "the bake wrote a broken key" is dead.
#  - netvwifibus.inf [PnPFilterRegistration] is literally: HKR,,"UpperFilters",0x00010000,"vwifibus"
#    and it is reached only through the NIC INFs' "Include = netvwifibus.inf / Needs = VWiFiBus.HW",
#    which PE's setupapi cannot resolve (probe51). => the adapter devnode has no UpperFilters.
#  - netvwififlt.inf and netnwifi.inf install vwififlt / NativeWifiP as NDIS *filters*
#    (Characteristics=0x40028, Ndi\Service, Ndi\FilterClass, Ndi\FilterMediaTypes=wlan / vwifi,vchannel,
#    FilterRunType 1=MANDATORY for nwifi). Mandatory filters are bound through the adapter's class key
#    Ndi entries, so the diff must include Control\Class\{4d36e972-...} for the adapter, not just Enum.
# probe56 loaded HKLM\P56OFF but its load-verification was wrong so it never unloaded -> reuse it here
# and unload at the end (read-only use of the laptop's own offline hive; no writes to it).
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function RQA([string[]]$a) {
  return @(& reg.exe @a 2>&1 | ForEach-Object { ("" + $_) })
}
function Exists([string]$k) { return (@(RQA @('query', $k))[0] -match '^HKEY') }
function DumpTree([string]$label, [string]$key, [int]$max) {
  $txt = @(RQA @('query', $key, '/s'))
  if ($txt.Count -eq 0) { O ('  ' + $label + ' EMPTY'); return }
  if ($txt[0] -match '^ERROR|Invalid|cannot') { O ('  ' + $label + ' ABSENT :: ' + ($txt[0]).Trim()); return }
  $n = 0
  foreach ($raw in $txt) {
    $l = ($raw -replace '\s+', ' ').Trim()
    if ($l -eq '') { continue }
    $n++
    if ($n -gt $max) { O ('  ' + $label + ' ...TRUNC ' + $max); return }
    if ($l -match '^HKEY_LOCAL_MACHINE') {
      O ('  ' + $label + ' # ' + ($l -replace '^HKEY_LOCAL_MACHINE\\', ''))
    } else { O ('  ' + $label + '   ' + $l) }
  }
}

HDR 'A offline hive handle'
$HK = 'HKLM\P56OFF'
$weLoaded = $false
if (Exists $HK) {
  O '  A P56OFF already mounted (left by probe56) -> reuse'
} else {
  $offRoot = ''
  foreach ($d in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
    if ($d.DeviceID -eq 'X:') { continue }
    if (Test-Path -LiteralPath ($d.DeviceID + '\Windows\System32\config\SYSTEM')) { $offRoot = $d.DeviceID; break }
  }
  O ('  A OFFROOT ' + $(if ($offRoot) { $offRoot } else { 'NONE' }))
  if ($offRoot) {
    O ('  A LOAD ' + ((RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM'))) -join ' | '))
    if (Exists $HK) { $weLoaded = $true }
  }
}
$OFF = $HK + '\ControlSet001'
$have = Exists $OFF
O ('  A HAVE_CONTROLSET001 ' + $have)

if ($have) {
  HDR 'B offline WORKING hive: AX211 devnode tree'
  $fams = @(RQA @('query', ($OFF + '\Enum\PCI')) | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
            Where-Object { ($_ -match '^HKEY') -and ($_ -match 'VEN_8086&DEV_7A70') })
  O ('  B FAMILY ' + $fams.Count)
  foreach ($f in $fams) {
    $insts = @(RQA @('query', $f) | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
               Where-Object { ($_ -match '^HKEY') -and (($_ -replace '\s+', ' ').Trim() -ne $f) })
    foreach ($i in ($insts | Select-Object -First 2)) {
      DumpTree 'OFF-DEV' $i 90
      $offDev = $i
    }
  }
  HDR 'C offline: which driver key / class slot the adapter uses'
  if ($offDev) {
    $drv = ''
    $t = @(RQA @('query', $offDev, '/v', 'Driver')) | Where-Object { $_ -match 'REG_' }
    if ($t.Count) { $drv = (($t[0] -replace '\s+', ' ').Trim() -split '\s+')[-1] }
    $inf = ''
    $t = @(RQA @('query', $offDev, '/v', 'InfPath')) | Where-Object { $_ -match 'REG_' }
    if ($t.Count) { $inf = (($t[0] -replace '\s+', ' ').Trim() -split '\s+')[-1] }
    O ('  C OFF Driver ' + $drv + ' InfPath ' + $inf)
    if ($drv) { DumpTree 'OFF-CLASS' $drv 70 }
    # the class-level Ndi subkey of the class slot is what binds mandatory filters
    foreach ($v in 'UpperFilters', 'LowerFilters', 'Class', 'ClassGUID', 'Service', 'ConfigFlags') {
      $t = @(RQA @('query', $offDev, '/v', $v)) | Where-Object { $_ -match 'REG_' }
      O ('  C OFF DEV ' + $v + ' :: ' + $(if ($t.Count) { (($t[0] -replace '\s+', ' ').Trim()) } else { '-' }))
    }
  }
  HDR 'D offline: the filter components (nwifi / vwififlt / vwifimp) class entries'
  $cls = $OFF + '\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
  $kids = @(RQA @('query', $cls) | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } |
            Where-Object { ($_ -match '^HKEY') -and ($_ -ne $cls.Replace('HKLM', 'HKEY_LOCAL_MACHINE')) })
  O ('  D CLASS_SLOTS ' + $kids.Count)
  foreach ($k in $kids) {
    $n1 = @(RQA @('query', ($k + '\Ndi'), '/v', 'Service')) | Where-Object { $_ -match 'REG_' }
    $n2 = @(RQA @('query', ($k + '\Ndi'), '/v', 'FilterMediaType')) | Where-Object { $_ -match 'REG_' }
    if ($n1.Count) { $svc = (($n1[0] -replace '\s+', ' ').Trim()) }
    if ($svc -match '(?i)NativeWifiP|vwififlt|vwifimp|vwifibus') {
      O ('  D SLOT ' + $k)
      O ('  D   ' + $svc)
      if ($n2.Count) { O ('  D   ' + (($n2[0] -replace '\s+', ' ').Trim())) }
      $t = @(RQA @('query', $k, '/s')) | Where-Object { $_ -match 'REG_' } | Select-Object -First 22
      foreach ($l in $t) { O ('  D    | ' + (($l -replace '\s+', ' ').Trim())) }
    }
  }
}

HDR 'E LIVE PE devnode for the AX211 (full tree)'
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
$liveDev = ''
if ($ents.Count) {
  $p = "$($ents[0].PNPDeviceID)" -split '\\'
  O ('  E PARTS ' + ($p -join ' || '))
  $k = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $p[0] + '\' + $p[1] + '\' + $p[2]
  O ('  E KEY ' + $k)
  if (Exists $k) { $liveDev = $k; DumpTree 'PE-DEV' $k 90 } else { O '  E NOT FOUND' }
}

HDR 'F EXPERIMENT: UpperFilters=vwifibus on the live devnode, restart it'
if ($liveDev -ne '') {
  O ('  F ADD ' + ((RQA @('add', $liveDev, '/v', 'UpperFilters', '/t', 'REG_MULTI_SZ', '/d', 'vwifibus', '/f')) -join ' | '))
  $t = @(RQA @('query', $liveDev, '/v', 'UpperFilters')) | Where-Object { $_ -match 'REG_' }
  O ('  F READBACK ' + (($t -join ' ;; ')))
  $pn = ''
  if ($ents.Count) { $pn = "$($ents[0].PNPDeviceID)" }
  O ('  F RESTART ' + ((@(& pnputil.exe /restart-device $pn 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })) -join ' | '))
  Start-Sleep -Seconds 15
  $d = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($x in $d) { O ('  F AFTER code=' + $x.ConfigManagerErrorCode + ' status=' + $x.Status) }
  DumpTree 'PE-DEV2' $liveDev 40
  $kids = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
            Where-Object { ($_.PNPDeviceID -match '(?i)VWIFI') -or ($_.Name -match '(?i)virtual wireless|Wi-Fi Direct') })
  O ('  F VWIFI_DEVICES ' + $kids.Count)
  foreach ($k2 in $kids) { O ('  F KID ' + $k2.Name + ' | ' + $k2.PNPDeviceID + ' | code=' + $k2.ConfigManagerErrorCode) }
} else { O '  F SKIPPED' }

HDR 'G services after the experiment'
foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip', 'vwifibus', 'vwifimp', 'vwififlt', 'Ndisuio') {
  O ('  G STATE ' + $n + ' = ' + (St $n))
}
try {
  $s = Get-Service nativewifip -EA Stop
  $s.Start()
  Start-Sleep -Seconds 3
  O ('  G nativewifip now ' + (St 'nativewifip'))
} catch {
  $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }
  $code = 'n/a'
  if ($ie -is [ComponentModel.Win32Exception]) { $code = '' + $ie.NativeError }
  O ('  G nativewifip start FAILED code=' + $code + ' msg=' + (($ie.Message -replace '\s+', ' ')))
}
try {
  $s = Get-Service wlansvc -EA Stop
  $s.Start()
  Start-Sleep -Seconds 6
  O ('  G wlansvc now ' + (St 'wlansvc'))
} catch {
  $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }
  O ('  G wlansvc start FAILED ' + (($ie.Message -replace '\s+', ' ')))
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W57 {
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
}
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [W57]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  G WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    O ('  G WLANENUM rc=' + [W57]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt) + ' ifaces=' + $cnt)
  }
} catch { O ('  G WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }

if ($weLoaded) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  O ('  Z UNLOAD ' + ((RQA @('unload', $HK)) -join ' | '))
}
O ('  Z UNLOADCHECK ' + (@(Exists $HK)))
O 'P57 END'
