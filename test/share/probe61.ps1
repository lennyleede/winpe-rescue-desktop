# probe61 -- LIVE PE, read-only. Find the devnodes that carry the WiFi filters.
# Chain of evidence so far, on real hardware (AX211, PE 10.0.26100.1):
#  - NIC INFs' Include=netvwifibus.inf never resolves in PE (probe51, repeated in probe59's setupapi tail),
#    so PnP never ran [PnPFilterRegistration] (HKR,,"UpperFilters",...,"vwifibus").
#  - probe58 wrote that UpperFilters by hand and restarted the device: still code 37 / 0xC00000BB. So the
#    bus filter alone is not the story.
#  - probe60 diffed the Net class slots: the working machine's adapter slot has Linkage\FilterList with 6
#    filter instances and Control\Network\{4d36e972...} has 19 component folders; the PE adapter slot has
#    NO FilterList at all and Control\Network has 3. FilterList is written by the NetCfg class installer
#    (NetService class key: Installer32=NetCfgx.Dll,NetClassInstaller, NoInstallClass=1 -- q62_pe proved
#    NetCfgx.dll 26100 IS present in the PE).
#  - netnwifi.inf installs as Class=NetService on hardware ID MS_NativeWifiP, netvwififlt.inf likewise:
#    those are *root-enumerated devices*, not just service keys. Our bake wrote the service keys (probe56:
#    complete and correct) but there is nothing to install the devices, so nativewifip has no devnode to
#    attach to (SCM 31) and the mandatory NativeWiFi filter cannot impose on a Native802_11 miniport
#    (FilterRunType=1) -> NDIS STATUS_NOT_SUPPORTED -> code 37 -> wlansvc dies on arrival -> 1062.
# This probe lists every offline Enum\ROOT / Enum\SWD devnode with its Class/Service/HardwareID, plus the
# NetService class slots, and shows the PE side for contrast. That gives the exact registry shape a bake
# must reproduce. No writes except X: ramdisk state we already had; the offline hive is load/query/unload.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function RQA([string[]]$a) { return @(& reg.exe @a 2>&1 | ForEach-Object { ("" + $_) }) }
function Clean([string[]]$t) {
  return @($t | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) } | Where-Object { $_ -ne '' })
}
function Exists([string]$k) { return (@(Clean (RQA @('query', $k)) | Where-Object { $_ -match '^HKEY' }).Count -gt 0) }
function V([string]$k, [string]$v) {
  if (-not (Exists $k)) { return '' }
  $t = @(Clean (RQA @('query', $k, '/v', $v)) | Where-Object { $_ -match 'REG_' })
  if ($t.Count -gt 0) { return (($t[0] -replace '^.*REG_\w+\s+', '') -replace '[^\x20-\x7E]', '?') }
  return ''
}
function Subs([string]$k) {
  if (-not (Exists $k)) { return @() }
  $self = ($k -replace '^HKLM', 'HKEY_LOCAL_MACHINE')
  return @(Clean (RQA @('query', $k)) | Where-Object { ($_ -match '^HKEY') -and ($_ -ne $self) })
}

HDR 'A mount the laptop offline hive read-only'
$offRoot = ''
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
  if ($d.DeviceID -eq 'X:') { continue }
  if (Test-Path -LiteralPath ($d.DeviceID + '\Windows\System32\config\SYSTEM')) { $offRoot = $d.DeviceID; break }
}
$HK = 'HKLM\P61OFF'
$weLoaded = $false
if ($offRoot -and -not (Exists $HK)) {
  O ('  A LOAD ' + ((Clean (RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM')))) -join ' | '))
  if (Exists $HK) { $weLoaded = $true }
}
$OFF = $HK + '\ControlSet001'
$PE = 'HKLM\SYSTEM\CurrentControlSet'

foreach ($side in @(@('OFF', $OFF), @('PE', $PE))) {
  $lbl = $side[0]; $root = $side[1]
  HDR ('B ' + $lbl + ' Enum\ROOT and Enum\SWD devnodes')
  foreach ($bus in 'ROOT', 'SWD') {
    foreach ($f in @(Subs ($root + '\Enum\' + $bus))) {
      $fam = ($f -replace '^.*Enum\\', '')
      $insts = @(Subs $f)
      $first = ''
      if ($insts.Count) { $first = $insts[0] }
      $cls = V $first 'Class'
      $svc = V $first 'Service'
      $hwid = V $first 'HardwareID'
      O ('  B ' + $lbl + ' ' + $bus + '\' + $fam + ' n=' + $insts.Count + ' class=' + $cls +
         ' service=' + $svc + ' hwid=' + $hwid)
      if (($svc + '|' + $fam + '|' + $hwid) -match '(?i)wifi|nwifi|NativeWifi|netservice|network|vwifi') {
        foreach ($i in $insts) {
          O ('  B+ ' + $lbl + ' INST ' + ($i -replace '^.*Enum\\', ''))
          foreach ($v in 'Class', 'ClassGUID', 'Service', 'Driver', 'HardwareID', 'DeviceDesc',
                          'Capabilities', 'InstallState', 'Legacy', 'ConfigFlags', 'UpperFilters') {
            $val = V $i $v
            if ($val -ne '') { O ('  B+   ' + $v + ' = ' + $val) }
          }
          $drv = V $i 'Driver'
          if ($drv -ne '') {
            $dp = $root + '\Control\Class\' + $drv
            if (Exists $dp) {
              O ('  B+   CLASSSLOT ' + $drv)
              foreach ($v in 'DriverDesc', 'Characteristics', 'ComponentId', 'InfPath', 'InfSection', 'NetCfgInstanceId') {
                $val = V $dp $v
                if ($val -ne '') { O ('  B+     ' + $v + ' = ' + $val) }
              }
              foreach ($vv in 'Service', 'FilterClass', 'FilterType', 'FilterRunType') {
                $val = V ($dp + '\Ndi') $vv
                if ($val -ne '') { O ('  B+     Ndi\' + $vv + ' = ' + $val) }
              }
              $val = V ($dp + '\Ndi\Interfaces') 'FilterMediaTypes'
              if ($val -ne '') { O ('  B+     Ndi\Interfaces\FilterMediaTypes = ' + $val) }
            }
          }
        }
      }
    }
  }
  HDR ('C ' + $lbl + ' NetService class {4d36e974-...} slots')
  $ns = $root + '\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}'
  $slots = @(Subs $ns)
  O ('  C ' + $lbl + ' NETSERVICE SLOTS ' + $slots.Count)
  foreach ($s in $slots) {
    $svc = V ($s + '\Ndi') 'Service'
    $cid = V $s 'ComponentId'
    $dd = V $s 'DriverDesc'
    $ch = V $s 'Characteristics'
    $fmt = V ($s + '\Ndi\Interfaces') 'FilterMediaTypes'
    O ('  C ' + $lbl + ' [' + ($s -replace '^.*\\', '') + '] svc=' + $svc + ' cid=' + $cid + ' desc=' + $dd +
       ' chr=' + $ch + ' ftype=' + $fmt)
  }
  HDR ('D ' + $lbl + ' Control\Network\{net class} components')
  $nn = $root + '\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
  $comps = @(Subs $nn)
  O ('  D ' + $lbl + ' COMPONENTS ' + $comps.Count)
  foreach ($c in $comps) {
    $svc = V $c 'Service'
    $cn = V ($c + '\Connection') 'Name'
    $ct = V ($c + '\Connection') 'ConnType'
    $gp = V ($c + '\Connection') 'Guid'
    O ('  D ' + $lbl + ' ' + ($c -replace '^.*\\', '') + ' svc=' + $svc + ' name=' + $cn + ' conn=' + $ct)
  }
}

HDR 'E the adapter FilterList on both sides'
$CLSG = '{4d36e972-e325-11ce-bfc1-08002be10318}'
foreach ($side in @(@('OFF', $OFF, '\0002'), @('PE', $PE, '\0001'))) {
  $lbl = $side[0]; $k = $side[1] + '\Control\Class\' + $CLSG + $side[2]
  O ('  E ' + $lbl + ' RootDevice ' + (V ($k + '\Linkage') 'RootDevice'))
  O ('  E ' + $lbl + ' FilterList ' + ((V ($k + '\Linkage') 'FilterList') -replace '\0', ' | '))
  O ('  E ' + $lbl + ' UpperBind ' + ((V ($k + '\Linkage') 'UpperBind') -replace '\0', ','))
  O ('  E ' + $lbl + ' Bind ' + (V ($k + '\Linkage') 'Bind'))
}
HDR 'F offline: NdisImPlatform devnode + who needs it'
O ('  F OFF Services\NdisImPlatform ImagePath ' + (V ($OFF + '\Services\NdisImPlatform') 'ImagePath'))
O ('  F PE  Services\NdisImPlatform present=' + (Exists ($PE + '\Services\NdisImPlatform')))
if ($weLoaded) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  O ('  Z UNLOAD ' + ((Clean (RQA @('unload', $HK))) -join ' | '))
}
O ('  Z STILL_MOUNTED ' + (Exists $HK))
O 'P61 END'
