# probe59 -- LIVE PE. The version theory, tested instead of assumed.
# probe58 wrote UpperFilters=vwifibus on the AX211 devnode and restarted it: still code 37, 0 vWiFi child
# devices. So the missing filter value alone does not explain it -- the wall is that nativewifip (nwifi.sys)
# cannot start here: SCM answers 31 (ERROR_GEN_FAILURE) for it and wlansvc therefore dies on arrival
# (StartOK=True, state stays Stopped, WlanOpenHandle 1062).
# What we have been borrowing is 19041-era: nwifi.sys 10.0.19041.7663, vwififlt 19041.3636, vwifimp/vwifibus
# 19041.1, wlansvc.dll/wlanmsm.dll/wcmsvc.dll 19041.7725, while this PE's kernel/NDIS is 10.0.26100.1.
# probe47/51/53 already ruled out group order, imports, .cat/CI, service-key shape (probe56: the baked keys
# are complete, Parameters\ServiceDll + ServiceMain present) and driver package version.
# NEW LEVER: the laptop's own Windows is mounted read-only inside the PE at D: (probe58 loaded
# D:\Windows\System32\config\SYSTEM fine). If D:\Windows\System32\drivers\nwifi.sys is 26100-era we can test
# the version theory on the ramdisk in minutes -- and the fix needs no download at all.
# This probe: (A) inventory those files, (B) dump devnode values with fixed helpers (reg.exe prints a BLANK
# first line, and @()pipewhere collapses to a scalar -- both mistakes cost probe56/57/58 their sections),
# (C) swap in the 26100 nwifi/vwififlt on X: only and retry the chain. X: is a ramdisk: nothing persists,
# no ISO is touched, D: is only ever read.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function RQA([string[]]$a) { return @(& reg.exe @a 2>&1 | ForEach-Object { ("" + $_) }) }
function Clean([string[]]$t) {
  return @($t | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) } | Where-Object { $_ -ne '' })
}
function Lines([string[]]$t) { return @(Clean $t) }
function Exists([string]$k) {
  $t = @(Lines (RQA @('query', $k)))
  return (@($t | Where-Object { $_ -match '^HKEY' }).Count -gt 0)
}
function GetV([string]$k, [string]$v) {
  if (-not (Exists $k)) { return 'KEYABSENT' }
  $t = @(Lines (RQA @('query', $k, '/v', $v)) | Where-Object { $_ -match 'REG_' })
  if ($t.Count -gt 0) { return $t[0] }
  return '-'
}
function DumpVals([string]$label, [string]$k, [int]$max) {
  if (-not (Exists $k)) { O ('  ' + $label + ' KEY ABSENT ' + $k); return }
  $t = @(Lines (RQA @('query', $k)) | Where-Object { $_ -match 'REG_' })
  O ('  ' + $label + ' VALUES ' + $t.Count)
  $n = 0
  foreach ($l in $t) {
    $n++
    if ($n -gt $max) { O ('  ' + $label + ' ...TRUNC'); return }
    O ('  ' + $label + ' | ' + $l)
  }
}
function FileRow([string]$tag, [string]$root, [string]$leaf) {
  $p = $root + '\' + $leaf
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    O ('  ' + $tag + ' ' + $leaf + ' ' + $i.Length + 'B ver=' + $i.VersionInfo.FileVersion)
  } else { O ('  ' + $tag + ' ' + $leaf + ' 0B ver=MISSING') }
}

HDR 'A the laptop own Windows (D:) vs the PE (X:): WiFi binaries'
foreach ($f in 'System32\drivers\nwifi.sys', 'System32\drivers\vwififlt.sys', 'System32\drivers\vwifimp.sys',
                'System32\drivers\vwifibus.sys', 'System32\drivers\NdisImPlatform.sys',
                'System32\wlansvc.dll', 'System32\wlanapi.dll', 'System32\wlanmsm.dll',
                'System32\wcmsvc.dll', 'System32\dot3svc.dll',
                'System32\drivers\ndisuio.sys', 'System32\ntoskrnl.exe', 'System32\drivers\ndis.sys') {
  FileRow 'D:' 'D:\Windows' $f
  FileRow 'X:' 'X:\Windows' $f
}

HDR 'B devnode values, offline (working) vs live PE'
$offRoot = ''
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
  if ($d.DeviceID -eq 'X:') { continue }
  if (Test-Path -LiteralPath ($d.DeviceID + '\Windows\System32\config\SYSTEM')) { $offRoot = $d.DeviceID; break }
}
O ('  B OFFROOT ' + $(if ($offRoot) { $offRoot } else { 'NONE' }))
$HK = 'HKLM\P59OFF'
$weLoaded = $false
if ($offRoot -and -not (Exists $HK)) {
  O ('  B LOAD ' + ((Lines (RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM')))) -join ' | '))
  if (Exists $HK) { $weLoaded = $true }
}
$OFF = $HK + '\ControlSet001'
$PNPID = ''
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($ents.Count) { $PNPID = "$($ents[0].PNPDeviceID)" }
$p = $PNPID -split '\\'
$liveDev = ''
if ($p.Count -ge 3) { $liveDev = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $p[0] + '\' + $p[1] + '\' + $p[2] }
if (Exists $OFF) {
  $fams = @(Lines (RQA @('query', ($OFF + '\Enum\PCI'))) | Where-Object { ($_ -match '^HKEY') -and ($_ -match 'VEN_8086&DEV_7A70') })
  $offDev = ''
  foreach ($f in $fams) {
    $insts = @(Lines (RQA @('query', $f)) | Where-Object { ($_ -match '^HKEY') -and ($_ -ne $f) })
    if ($insts.Count) { $offDev = $insts[0] }
  }
  O ('  B OFFDEV ' + $(if ($offDev) { $offDev } else { 'NONE' }))
  if ($offDev) { DumpVals 'OFF' $offDev 30 }
  $odrv = (GetV $offDev 'Driver')
  O ('  B OFF ' + $odrv)
  $dk = $odrv -replace '^.*REG_SZ\s+', ''
  O ('  B OFF class slot path :: ' + $dk)
  if ($dk -match '^HKEY_') { DumpVals 'OFFDRVDB' $dk 25 }
  $t = @(Lines (RQA @('query', ($dk + '\Ndi'), '/s')) | Where-Object { $_ -match 'REG_' })
  O ('  B OFF Ndi lines=' + $t.Count)
  foreach ($l in ($t | Select-Object -First 25)) { O ('  OFF-Ndi | ' + $l) }
}
if ($liveDev) { DumpVals 'PE' $liveDev 30 }

HDR 'C C: also check the swap sources are readable and signed'
foreach ($f in 'System32\drivers\nwifi.sys', 'System32\drivers\vwififlt.sys', 'System32\wlansvc.dll') {
  $p2 = 'D:\Windows\' + $f
  if (Test-Path -LiteralPath $p2) {
    $b = @([IO.File]::ReadAllBytes($p2))
    $md5 = ''
    $h = [Security.Cryptography.MD5]::Create()
    $md5 = (($h.ComputeHash($b) | ForEach-Object { $_.ToString('X2') }) -join '')
    O ('  C ' + $f + ' md5=' + $md5 + ' bytes=' + $b.Length)
  } else { O ('  C ' + $f + ' UNREADABLE') }
}
$xh = @()
foreach ($f in 'System32\DRIVERS\nwifi.sys', 'System32\DRIVERS\vwififlt.sys') {
  $p2 = 'X:\Windows\' + $f
  if (Test-Path -LiteralPath $p2) {
    $b = @([IO.File]::ReadAllBytes($p2))
    $h = [Security.Cryptography.MD5]::Create()
    O ('  C ' + $f + ' (in PE) md5=' + (($h.ComputeHash($b) | ForEach-Object { $_.ToString('X2') }) -join '') +
       ' bytes=' + $b.Length)
  }
}

HDR 'D EXPERIMENT: put the 26100 nwifi.sys (+vwififlt) on the ramdisk and retry the chain'
$dNwifi = 'D:\Windows\System32\drivers\nwifi.sys'
$xNwifi = 'X:\Windows\System32\DRIVERS\nwifi.sys'
$swapped = $false
if (Test-Path -LiteralPath $dNwifi) {
  Copy-Item -LiteralPath $dNwifi -Destination ($xNwifi + '.orig') -Force -EA SilentlyContinue
  Copy-Item -LiteralPath $dNwifi -Destination $xNwifi -Force
  $i = Get-Item -LiteralPath $xNwifi
  O ('  D nwifi.sys now ' + $i.Length + 'B ver=' + $i.VersionInfo.FileVersion)
  $swapped = $true
} else { O '  D no D:\Windows\System32\drivers\nwifi.sys to try' }
$dFlt = 'D:\Windows\System32\drivers\vwififlt.sys'
if (Test-Path -LiteralPath $dFlt) {
  Copy-Item -LiteralPath $dFlt -Destination ($xNwifi -replace 'nwifi.sys', 'vwififlt.sys') -Force
  $i = Get-Item -LiteralPath 'X:\Windows\System32\DRIVERS\vwififlt.sys'
  O ('  D vwififlt.sys now ' + $i.Length + 'B ver=' + $i.VersionInfo.FileVersion)
}
try {
  $s = Get-Service nativewifip -EA Stop
  $s.Start(); Start-Sleep -Seconds 3
  O ('  D nativewifip -> ' + (St 'nativewifip'))
} catch {
  $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }
  $code = 'n/a'
  if ($ie -is [ComponentModel.Win32Exception]) { $code = '' + $ie.NativeError }
  O ('  D nativewifip start FAILED code=' + $code + ' msg=' + (($ie.Message -replace '\s+', ' ')))
}
try {
  $s = Get-Service wlansvc -EA Stop
  $s.Start(); Start-Sleep -Seconds 6
  O ('  D wlansvc -> ' + (St 'wlansvc'))
} catch {
  $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }
  O ('  D wlansvc start FAILED ' + (($ie.Message -replace '\s+', ' ')))
}
O ('  D RESTART ' + ((Clean (@(& pnputil.exe /restart-device $PNPID 2>&1 | ForEach-Object { "" + $_ }))) -join ' | '))
Start-Sleep -Seconds 12
foreach ($x in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
                 Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })) {
  O ('  D NIC code=' + $x.ConfigManagerErrorCode + ' status=' + $x.Status)
}
foreach ($n in 'nativewifip', 'wlansvc', 'wcmsvc', 'vwifibus', 'vwifimp', 'vwififlt') {
  O ('  D STATE ' + $n + ' = ' + (St $n))
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W59 {
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
}
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [W59]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  D WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    O ('  D WLANENUM rc=' + [W59]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt) + ' ifaces=' + $cnt)
  }
} catch { O ('  D WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
HDR 'E setupapi tail for the restart'
$log = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path -LiteralPath $log) {
  $t = @(Get-Content -LiteralPath $log -EA SilentlyContinue | Select-Object -Last 45)
  foreach ($l in $t) { O ('  E| ' + (($l -replace '\s+', ' ').Trim())) }
}
if ($weLoaded) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  O ('  Z UNLOAD ' + ((Lines (RQA @('unload', $HK))) -join ' | '))
}
O ('  Z STILL ' + (Exists $HK))
O 'P59 END'
