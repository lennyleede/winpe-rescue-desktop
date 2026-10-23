# probe60 -- LIVE PE, read-only. The last unexamined layer: network class slots and filter components.
# Where the investigation stands on real hardware (12th gen, AX211, PE = 10.0.26100.1):
#  1. The NIC INFs' "Include = netvwifibus.inf / Needs = VWiFiBus.*" never resolve in this PE
#     (probe51 + probe59 setupapi tail repeat "Needed section [VWiFiBus] not found, might exist in missing
#     included INF." even though X:\Windows\INF\netvwifibus.inf is present).
#  2. probe58 wrote the value that Include would have produced -- devnode UpperFilters=vwifibus -- and
#     restarted the device: still code 37 / Device Status 0x01802400 [0x25 - 0xc00000bb], 0 vWiFi children.
#     So the missing UpperFilters value is necessary but NOT the whole story.
#  3. nativewifip (nwifi.sys) will not start: SCM 31. probe59 swapped in the laptop's own 19041.1415 build
#     and got a signature error instead -> CI is enforced here, and a bare .sys needs its .cat (already in
#     memory as the "domino 1" rule). It also showed the laptop's Windows is 19041 (ntoskrnl 19041.3208),
#     so NO 26100-era nwifi exists on this machine; the version theory cannot be tested from local material.
#  4. probe59 pending start reported problem 0x38 = CM_PROB_NEED_CLASS_CONFIG, i.e. class configuration is
#     what PnP is missing -- and the one thing we have never compared is Control\Class\{4d36e972-...}\00NN.
# netnwifi.inf and netvwififlt.inf install NativeWifiP / vwififlt as NDIS filters via class slots
# (Characteristics 0x40028, Ndi\Service, Ndi\Interfaces\FilterMediaTypes = wlan / vwifi+vchannel,
# nwifi FilterRunType=1 MANDATORY). A Native802_11 miniport whose mandatory filter has no class entry is
# exactly the STATUS_NOT_SUPPORTED we see. This probe dumps both hives' class slots and diffs them, then
# looks for any Enum\ROOT / Enum\SWD devnode behind those components, and reads the offline hive's
# NdisImPlatform (present on D:, missing from the PE).
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function RQA([string[]]$a) { return @(& reg.exe @a 2>&1 | ForEach-Object { ("" + $_) }) }
function Clean([string[]]$t) {
  return @($t | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) } | Where-Object { $_ -ne '' })
}
function Lines([string[]]$t) { return @(Clean $t) }
function Exists([string]$k) {
  return (@(Lines (RQA @('query', $k)) | Where-Object { $_ -match '^HKEY' }).Count -gt 0)
}
function V([string]$k, [string]$v) {
  if (-not (Exists $k)) { return 'KEYABSENT' }
  $t = @(Lines (RQA @('query', $k, '/v', $v)) | Where-Object { $_ -match 'REG_' })
  if ($t.Count -gt 0) { return ($t[0] -replace '^.*REG_\w+\s+', '') }
  return '-'
}
function DumpVals([string]$label, [string]$k, [int]$max) {
  if (-not (Exists $k)) { O ('  ' + $label + ' ABSENT ' + $k); return }
  $t = @(Lines (RQA @('query', $k)) | Where-Object { $_ -match 'REG_' })
  $n = 0
  O ('  ' + $label + ' VALUES ' + $t.Count + ' ' + $k)
  foreach ($l in $t) {
    $n++
    if ($n -gt $max) { O ('  ' + $label + ' ...TRUNC'); return }
    O ('  ' + $label + ' | ' + $l)
  }
}
function SubKeys([string]$k) {
  if (-not (Exists $k)) { return @() }
  return @(Lines (RQA @('query', $k)) | Where-Object { ($_ -match '^HKEY') -and ($_ -ne $k.Replace('HKLM', 'HKEY_LOCAL_MACHINE')) })
}

HDR 'A mount the laptop offline hive read-only'
$offRoot = ''
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
  if ($d.DeviceID -eq 'X:') { continue }
  if (Test-Path -LiteralPath ($d.DeviceID + '\Windows\System32\config\SYSTEM')) { $offRoot = $d.DeviceID; break }
}
O ('  A OFFROOT ' + $(if ($offRoot) { $offRoot } else { 'NONE' }))
$HK = 'HKLM\P60OFF'
$weLoaded = $false
if ($offRoot -and -not (Exists $HK)) {
  O ('  A LOAD ' + ((Lines (RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM')))) -join ' | '))
  if (Exists $HK) { $weLoaded = $true }
}
$OFF = $HK + '\ControlSet001'
$PE = 'HKLM\SYSTEM\CurrentControlSet'
$CLSG = '{4d36e972-e325-11ce-bfc1-08002be10318}'

foreach ($side in @(@('OFF', $OFF), @('PE', $PE))) {
  $lbl = $side[0]; $root = $side[1]
  HDR ('B ' + $lbl + ' class slots under Control\Class\' + $CLSG)
  $cls = $root + '\Control\Class\' + $CLSG
  if (-not (Exists $cls)) { O ('  B ' + $lbl + ' CLASS KEY ABSENT'); continue }
  $slots = @(SubKeys $cls)
  O ('  B ' + $lbl + ' SLOTS ' + $slots.Count)
  foreach ($s in $slots) {
    $cid = V $s 'ComponentId'
    $svc = V ($s + '\Ndi') 'Service'
    $chr = V $s 'Characteristics'
    $fmt = V ($s + '\Ndi\Interfaces') 'FilterMediaTypes'
    $upr = V ($s + '\Ndi\Interfaces') 'UpperRange'
    $lwr = V ($s + '\Ndi\Interfaces') 'LowerRange'
    $desc = V $s 'DriverDesc'
    O ('  B ' + $lbl + ' [' + ($s -replace '^.*\\', '') + '] desc=' + $desc + ' svc=' + $svc + ' cid=' + $cid +
       ' chr=' + $chr + ' ftype=' + $fmt + ' upper=' + $upr + ' lower=' + $lwr)
  }
  HDR ('C ' + $lbl + ' class key own values')
  DumpVals ($lbl + '-CLS') $cls 18
}

HDR 'D the adapter class slot, subtree dump on both sides'
foreach ($side in @(@('OFF', $OFF, '\0002'), @('PE', $PE, '\0001'))) {
  $lbl = $side[0]; $root = $side[1]; $slot = $side[2]
  $k = $root + '\Control\Class\' + $CLSG + $slot
  O ('  D ' + $lbl + ' SLOT ' + $k + ' exists=' + (Exists $k))
  if (Exists $k) {
    DumpVals ($lbl + '-SLOT') $k 24
    $t = @(Lines (RQA @('query', ($k + '\Ndi'), '/s')))
    O ('  D ' + $lbl + ' Ndi lines ' + $t.Count)
    foreach ($l in ($t | Where-Object { $_ -match 'REG_' } | Select-Object -First 30)) { O ('  D ' + $lbl + ' Ndi| ' + $l) }
    foreach ($sq in @(SubKeys ($k + '\Linkage'))) { O ('  D ' + $lbl + ' LINKAGE ' + $sq) }
    DumpVals ($lbl + '-LINK') ($k + '\Linkage') 12
  }
}

HDR 'E Enum devnodes behind the WiFi components (offline)'
foreach ($bus in 'ROOT', 'SWD', 'NDIS', 'VDevice', 'Software') {
  $bk = $OFF + '\Enum\' + $bus
  $fams = @(SubKeys $bk)
  if ($fams.Count -eq 0) { O ('  E ' + $bus + ' none'); continue }
  O ('  E ' + $bus + ' families ' + $fams.Count)
  foreach ($f in $fams) {
    $insts = @(SubKeys $f)
    foreach ($i in ($insts | Select-Object -First 1)) {
      $svc = V $i 'Service'
      $dd = V $i 'DeviceDesc'
      if (($svc + '|' + $dd + '|' + $f) -match '(?i)wifi|nwifi|wlan|Native') {
        O ('  E HIT ' + ($i -replace '^.*Enum\\', '') + ' svc=' + $svc + ' desc=' + $dd +
           ' upper=' + (V $i 'UpperFilters') + ' class=' + (V $i 'Class'))
      }
    }
  }
}
HDR 'F offline NdisImPlatform + the filter INF component ids'
O ('  E OFF Services\NdisImPlatform exists=' + (Exists ($OFF + '\Services\NdisImPlatform')))
DumpVals 'OFF-NIP' ($OFF + '\Services\NdisImPlatform') 12
foreach ($n in 'nativewifip', 'vwififlt', 'vwifimp', 'vwifibus') {
  O ('  E OFF ' + $n + ' Owners=' + (V ($OFF + '\Services\' + $n) 'Owners') +
     ' Tag=' + (V ($OFF + '\Services\' + $n) 'Tag') + ' Start=' + (V ($OFF + '\Services\' + $n) 'Start') +
     ' ErrorControl=' + (V ($OFF + '\Services\' + $n) 'ErrorControl'))
  O ('  E PE  ' + $n + ' Owners=' + (V ($PE + '\Services\' + $n) 'Owners') +
     ' Tag=' + (V ($PE + '\Services\' + $n) 'Tag') + ' Start=' + (V ($PE + '\Services\' + $n) 'Start'))
}
HDR 'G offline: where the Net class itself is configured (ClassKey / InstalledServices)'
foreach ($p in @(($OFF + '\Control\Class\' + $CLSG + '\Ndi'), ($OFF + '\Control\Network\' + $CLSG),
                 ($PE + '\Control\Network\' + $CLSG))) {
  O ('  G ' + $p + ' exists=' + (Exists $p) + ' subs=' + (@(SubKeys $p).Count))
}
DumpVals 'OFF-NET-CLS' ($OFF + '\Control\Network\' + $CLSG) 12
$hits = @(Get-ChildItem -LiteralPath 'X:\Windows\INF' -Filter '*.inf' -EA SilentlyContinue |
          Where-Object { $_.Name -match '(?i)^net(nwifi|vwifi)' })
foreach ($h in $hits) {
  $t = @(Get-Content -LiteralPath $h.FullName -Encoding Unicode -EA SilentlyContinue)
  O ('  G INF ' + $h.Name + ' lines=' + $t.Count)
  foreach ($l in ($t | Where-Object { $_ -match '(?i)^\[MSFT|Characteristics|Class *=|ClassGUID|HardwareVer|AddReg *=|Needs *=' })) {
    O ('  G   | ' + (($l -replace '\s+', ' ').Trim()))
  }
}
if ($weLoaded) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  O ('  Z UNLOAD ' + ((Lines (RQA @('unload', $HK))) -join ' | '))
}
O ('  Z STILL_MOUNTED ' + (Exists $HK))
O 'P60 END'
