# probe58 -- LIVE PE. Fixed helper, then the decisive diff + experiment.
# Tooling lesson (this is what broke probe56 B and probe57 A/E): reg.exe's stdout starts with a BLANK line,
# so "first line -match '^HKEY'" is always false. Keys with '&' query fine. Exists() now scans every line.
# Context: netvwifibus.inf [PnPFilterRegistration] = HKR,,"UpperFilters",0x00010000,"vwifibus", reached only
# via the NIC INFs' Include/Needs, which PE setupapi cannot resolve (probe51) -> no UpperFilters ->
# NdisMediumNative802_11 miniport dies 0xC00000BB (code 37). netnwifi.inf / netvwififlt.inf install
# NativeWifiP and vwififlt as NDIS filters (Characteristics 0x40028, Ndi\Service, FilterMediaTypes wlan /
# vwifi+vchannel, nwifi FilterRunType=1 MANDATORY) through class slots under
# Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}, which is the second thing the missing includes
# would have created. So compare offline (working) vs live PE: devnode values AND the class slots.
# Mutations: UpperFilters on the X: ramdevnode only (gone at reboot). Offline hive stays read-only, unloaded
# at the end if this script mounted it.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function RQA([string[]]$a) { return @(& reg.exe @a 2>&1 | ForEach-Object { ("" + $_) }) }
function Clean([string[]]$t) { return @($t | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) } | Where-Object { $_ -ne '' }) }
function Exists([string]$k) { return (@(Clean (RQA @('query', $k))) | Where-Object { $_ -match '^HKEY' }).Count -gt 0 }
function GetV([string]$k, [string]$v) {
  $t = @(Clean (RQA @('query', $k, '/v', $v))) | Where-Object { $_ -match 'REG_' }
  if ($t.Count) { return $t[0] }
  return '-'
}
function DumpVals([string]$label, [string]$k, [int]$max) {
  if (-not (Exists $k)) { O ('  ' + $label + ' ABSENT ' + $k); return 0 }
  $t = @(Clean (RQA @('query', $k))) | Where-Object { $_ -match 'REG_' }
  $n = 0
  foreach ($l in $t) {
    $n++
    if ($n -gt $max) { O ('  ' + $label + ' ...TRUNC'); return $n }
    O ('  ' + $label + ' | ' + $l)
  }
  return $n
}

$HK = 'HKLM\P56OFF'
$weLoaded = $false
if (Exists $HK) { O 'MOUNT P56OFF already present (probe56) -> reuse, will unload at end' } else {
  $offRoot = ''
  foreach ($d in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
    if ($d.DeviceID -eq 'X:') { continue }
    if (Test-Path -LiteralPath ($d.DeviceID + '\Windows\System32\config\SYSTEM')) { $offRoot = $d.DeviceID; break }
  }
  O ('MOUNT OFFROOT ' + $(if ($offRoot) { $offRoot } else { 'NONE' }))
  if ($offRoot) {
    O ('MOUNT LOAD ' + ((Clean (RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM')))) -join ' | '))
    if (Exists $HK) { $weLoaded = $true }
  }
}
$OFF = $HK + '\ControlSet001'
O ('MOUNT HAVE ' + (Exists $OFF))

$PNPID = ''
$liveDev = ''
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($ents.Count) { $PNPID = "$($ents[0].PNPDeviceID)" }
$p = $PNPID -split '\\'
if ($p.Count -ge 3) { $liveDev = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $p[0] + '\' + $p[1] + '\' + $p[2] }
O ('DEV LIVEKEY ' + $liveDev + ' exists=' + (Exists $liveDev))

HDR 'A offline devnode (working Windows) -- the shape we must reproduce'
$offDev = ''
if (Exists $OFF) {
  $fams = @(Clean (RQA @('query', ($OFF + '\Enum\PCI')))) | Where-Object { ($_ -match '^HKEY') -and ($_ -match 'VEN_8086&DEV_7A70') }
  O ('  A FAMILIES ' + $fams.Count)
  foreach ($f in $fams) {
    $insts = @(Clean (RQA @('query', $f))) | Where-Object { ($_ -match '^HKEY') -and ($_ -ne $f) }
    foreach ($i in $insts) { O ('  A INST ' + $i); $offDev = $i }
  }
  if ($offDev) {
    DumpVals 'OFF' $offDev 40 | Out-Null
    foreach ($v in 'UpperFilters', 'LowerFilters', 'Class', 'ClassGUID', 'Service', 'Driver', 'ConfigFlags',
                    'Capabilities', 'LegacyPhysicalDevice') {
      O ('  A ' + $v + ' :: ' + (GetV $offDev $v))
    }
    $t = @(Clean (RQA @('query', ($offDev + '\Ndi'), '/s')))
    O ('  A Ndi lines=' + $t.Count)
    foreach ($l in ($t | Where-Object { $_ -match 'REG_' } | Select-Object -First 20)) { O ('  A Ndi | ' + $l) }
    $drv = (GetV $offDev 'Driver') -replace '^.*REG_SZ\s+', ''
    O ('  A OFFDRV ' + $drv)
  }
}

HDR 'B live PE devnode as-is'
DumpVals 'PE' $liveDev 40 | Out-Null
foreach ($v in 'UpperFilters', 'LowerFilters', 'Class', 'ClassGUID', 'Service', 'Driver', 'ConfigFlags') {
  O ('  B ' + $v + ' :: ' + (GetV $liveDev $v))
}
$t = @(Clean (RQA @('query', ($liveDev + '\Ndi'), '/s')))
O ('  B Ndi lines=' + $t.Count)
foreach ($l in ($t | Where-Object { $_ -match 'REG_' } | Select-Object -First 20)) { O ('  B Ndi | ' + $l) }

HDR 'C class slots: who binds the mandatory filters'
$CLSG = '{4d36e972-e325-11ce-bfc1-08002be10318}'
foreach ($side in @(@('OFF', ($OFF + '\Control\Class\' + $CLSG)), @('PE', ('HKLM\SYSTEM\CurrentControlSet\Control\Class\' + $CLSG)))) {
  $lbl = $side[0]; $cls = $side[1]
  if (-not (Exists $cls)) { O ('  C ' + $lbl + ' CLASS ABSENT'); continue }
  $kids = @(Clean (RQA @('query', $cls))) | Where-Object { ($_ -match '^HKEY\\.*\\[0-9]{4}$') }
  O ('  C ' + $lbl + ' SLOTS ' + $kids.Count)
  foreach ($k in $kids) {
    $svc = (GetV ($k + '\Ndi') 'Service') -replace '^.*REG_SZ\s+', ''
    $cid = (GetV $k 'ComponentId') -replace '^.*REG_SZ\s+', ''
    $mt  = (GetV ($k + '\Ndi') 'FilterMediaType') -replace '^.*REG_SZ\s+', ''
    $rt  = (GetV ($k + '\Ndi') 'FilterRunType') -replace '^.*REG_DWORD\s+', ''
    $all = ($svc + '|' + $cid + '|' + $mt)
    if ($all -match '(?i)NativeWifiP|vwifi|wlan|netwtw|Netwtw14') {
      O ('  C ' + $lbl + ' SLOT ' + ($k -replace '^.*Class\\', '') + ' svc=' + $svc + ' cid=' + $cid +
         ' ftype=' + $mt + ' run=' + $rt)
    }
  }
  # also the class key's own filter list
  foreach ($v in 'UpperFilters', 'LowerFilters') { O ('  C ' + $lbl + ' CLASS ' + $v + ' :: ' + (GetV $cls $v)) }
}

HDR 'D EXPERIMENT: UpperFilters=vwifibus on the live devnode, restart the device'
O ('  D ADD ' + ((Clean (RQA @('add', $liveDev, '/v', 'UpperFilters', '/t', 'REG_MULTI_SZ', '/d', 'vwifibus', '/f'))) -join ' | '))
O ('  D READBACK ' + (GetV $liveDev 'UpperFilters'))
O ('  D RESTART ' + ((Clean (@(& pnputil.exe /restart-device $PNPID 2>&1 | ForEach-Object { "" + $_ }))) -join ' | '))
Start-Sleep -Seconds 15
foreach ($x in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
                 Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })) {
  O ('  D AFTER code=' + $x.ConfigManagerErrorCode + ' status=' + $x.Status + ' name=' + $x.Name)
}
O ('  D UPPER NOW ' + (GetV $liveDev 'UpperFilters'))
$kids = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { ($_.PNPDeviceID -match '(?i)VWIFI') -or ($_.Name -match '(?i)virtual wireless|Wi-Fi Direct') })
O ('  D VWIFI_DEVICES ' + $kids.Count)
foreach ($k2 in $kids) { O ('  D KID ' + $k2.Name + ' | ' + $k2.PNPDeviceID + ' | code=' + $k2.ConfigManagerErrorCode) }

HDR 'E services + wlanapi after the experiment'
foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip', 'vwifibus', 'vwifimp', 'vwififlt', 'Ndisuio') {
  O ('  E STATE ' + $n + ' = ' + (St $n))
}
foreach ($n in 'nativewifip', 'wlansvc', 'wcmsvc') {
  try {
    $s = Get-Service $n -EA Stop
    $s.Start(); Start-Sleep -Seconds 4
    O ('  E START ' + $n + ' -> ' + (St $n))
  } catch {
    $ie = $_.Exception; while ($ie.InnerException) { $ie = $ie.InnerException }
    $code = 'n/a'
    if ($ie -is [ComponentModel.Win32Exception]) { $code = '' + $ie.NativeError }
    O ('  E START ' + $n + ' FAILED code=' + $code + ' msg=' + (($ie.Message -replace '\s+', ' ')))
  }
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W58 {
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
}
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [W58]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  E WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    O ('  E WLANENUM rc=' + [W58]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt) + ' ifaces=' + $cnt)
  }
} catch { O ('  E WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.NetConnectionID })) {
  O ('  E ADAPT ' + $a.Name + ' idx=' + $a.Index + ' mac=' + $a.MACAddress)
}
[GC]::Collect(); [GC]::WaitForPendingFinalizers()
O ('  Z UNLOAD ' + ((Clean (RQA @('unload', $HK))) -join ' | '))
O ('  Z STILL_MOUNTED ' + (Exists $HK))
O 'P58 END'
