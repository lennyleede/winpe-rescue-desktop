# probe63 -- LIVE PE, READ ONLY. Recon needed to build the R8 write test without guessing key layouts.
# Where the chain stands (probe47->61, ISO 1009-182058 on the 12th-gen laptop with Intel AX211):
#   NIC binds to Intel's driver but stops at code 37 / 0xC00000BB because the miniport is
#   NdisMediumNative802_11 (*MediaType=0x10) and the MANDATORY NativeWiFi filter (nwifi,
#   FilterRunType=1, Class=NetService) is never imposed. NetCfg imposes it by writing the adapter
#   slot's Linkage\FilterList -- offline that value holds 12 instances, in the PE it is EMPTY
#   (probe60), and Control\Network has 3 of the offline 19 components (probe61).
#   Hand-writing UpperFilters=vwifibus was already proven insufficient (probe58).
# This pass answers three things before any write:
#   Q1 which exact key carries FilterList on the working (offline D:) hive, and its siblings;
#   Q2 what the "{conn}-{component}-000N" instance IDs resolve to -- real subkeys, where;
#   Q3 the PE's own class slot / Control\Network shape (its own NetCfgInstanceId GUID).
# Only mutation: reg load of the offline SYSTEM hive, unloaded at the end unless already mounted.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$NETCLASS = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$PE = 'HKLM:\SYSTEM\CurrentControlSet'

L '=A boot / binaries'
$os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
L ('  A lastboot=' + $os.LastBootUpTime + ' now=' + (Clean ('' + (Get-Date))))
foreach ($n in 'drivers\nwifi.sys', 'drivers\vwififlt.sys', 'drivers\vwifibus.sys', 'wlansvc.dll') {
  foreach ($pair in @(@('PE', 'X:\Windows\System32'), @('OFF', 'D:\Windows\System32'))) {
    $p = $pair[1] + '\' + $n
    if (Test-Path -LiteralPath $p) {
      $i = Get-Item -LiteralPath $p
      L ('  A ' + $pair[0] + ' ' + $n + ' ' + $i.Length + 'B v=' + (Clean ('' + $i.VersionInfo.FileVersion)))
    } else { L ('  A ' + $pair[0] + ' ' + $n + ' MISSING') }
  }
}

L '=B net devices and their codes'
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086' -or (Clean ('' + $_.Name)) -match '(?i)wireless|wifi|netwtw|network controller' })
foreach ($e in $ents) {
  L ('  B code=' + $e.ConfigManagerErrorCode + ' id=' + $e.PNPDeviceID + ' name=' + (Clean ('' + $e.Name)))
}

L '=C offline hive mount'
$mk = @(Get-ChildItem -LiteralPath 'HKLM:\' -EA SilentlyContinue |
        Where-Object { $_.PSChildName -match '^(P[0-9]+OFF|R8OFF|OFFSYS)$' } | ForEach-Object { $_.PSChildName })
L ('  C already mounted: ' + ($mk -join ','))
$offRoot = ''
foreach ($m in $mk) {
  foreach ($cs in 'ControlSet001', 'CurrentControlSet') {
    $t = 'HKLM:\' + $m + '\' + $cs
    if (Test-Path -LiteralPath $t) { $offRoot = $t; break }
  }
  if ($offRoot -ne '') { break }
}
$mountedFresh = $false
if ($offRoot -eq '') {
  if (-not (Test-Path -LiteralPath 'D:\Windows\System32\config\SYSTEM')) {
    L '  C NO_OFFLINE_WINDOWS (D:\Windows\System32\config\SYSTEM missing) -- offline half skipped'
  } else {
    $r = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
    L ('  C reg load ' + ($r -join '|'))
    foreach ($cs in 'ControlSet001', 'CurrentControlSet') {
      $t = 'HKLM:\R8OFF\' + $cs
      if (Test-Path -LiteralPath $t) { $offRoot = $t; $mountedFresh = $true; break }
    }
  }
}
L ('  C OFFROOT=' + $offRoot + ' fresh=' + $mountedFresh)

$script:n = 0
$script:cap = 4000
function Walk([string]$path, [int]$depth, [int]$maxDepth, [string]$tag) {
  if ($script:n -gt $script:cap) { return }
  $script:n = $script:n + 1
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -ne $gi) {
    $short = $path
    $ix = $path.IndexOf('\Control')
    if ($ix -ge 0) { $short = $path.Substring($ix) }
    foreach ($vn in @($gi.GetValueNames())) {
      if ($vn -match '^(FilterList|UpperFilters|LowerFilters|NetCfgInstanceId|PnpInstanceID|Name|Service|InfPath|ComponentId|Class|Driver|Bind|RouteName)$') {
        $raw = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
        $v = ''
        if ($raw -is [array]) { $v = ($raw -join ';') } else { $v = '' + $raw }
        L ('  V ' + $tag + ' ' + $short + ' | ' + $vn + ' = ' + (Clean $v))
      }
    }
  }
  if ($depth -ge $maxDepth) { return }
  foreach ($sub in @(Get-ChildItem -LiteralPath $path -EA SilentlyContinue)) {
    Walk ($path + '\' + $sub.PSChildName) ($depth + 1) $maxDepth $tag
  }
}

foreach ($side in @(@('OFF', $offRoot), @('PE', $PE))) {
  $tag = $side[0]; $base = $side[1]
  if ($base -eq '') { L ('  ' + $tag + ' base ABSENT, skipped'); continue }
  L ('=D' + $tag + ' Control\Class\{net} (depth 3)')
  $script:n = 0
  Walk ($base + '\Control\Class\' + $NETCLASS) 0 3 ($tag + 'CLASS')
  L ('  walkcount=' + $script:n)
  L ('=E' + $tag + ' Control\Network\{net} (depth 4)')
  $script:n = 0
  Walk ($base + '\Control\Network\' + $NETCLASS) 0 4 ($tag + 'NET')
  L ('  walkcount=' + $script:n)
}

L '=F class slot full dump (4-digit slots only)'
function DumpKey([string]$path, [string]$tag) {
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $gi) { L ('  ' + $tag + ' KEYABSENT ' + $path); return }
  foreach ($vn in @($gi.GetValueNames())) {
    $raw = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $v = ''
    if ($raw -is [array]) { $v = ($raw -join ';') } else { $v = '' + $raw }
    if ($v.Length -gt 260) { $v = $v.Substring(0, 260) + '...' }
    L ('  ' + $tag + ' ' + $vn + ' = ' + (Clean $v))
  }
  L ('  ' + $tag + ' subs=' + (Clean (@(Get-ChildItem -LiteralPath $path -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ',')))
}
foreach ($side in @(@('OFF', $offRoot), @('PE', $PE))) {
  $tag = $side[0]; $base = $side[1]
  if ($base -eq '') { continue }
  $cls = $base + '\Control\Class\' + $NETCLASS
  foreach ($nn in @(Get-ChildItem -LiteralPath $cls -EA SilentlyContinue)) {
    if ($nn.PSChildName -match '^\d{4}$') { DumpKey ($cls + '\' + $nn.PSChildName) ($tag + '-' + $nn.PSChildName) }
  }
}

L '=G PE services relevant to the filter chain'
foreach ($svc in 'wlansvc', 'wcmsvc', 'nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'NdisImPlatform', 'Ndisuio') {
  $t = $PE + '\Services\' + $svc
  $st = '-'
  try { $st = '' + (Get-Service $svc -EA Stop).Status } catch { }
  if (Test-Path -LiteralPath $t) { L ('  G ' + $svc + ' key=yes state=' + $st) }
  else { L ('  G ' + $svc + ' key=ABSENT state=' + $st) }
}

if ($mountedFresh) {
  $r2 = @(& reg.exe unload HKLM\R8OFF 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('=H reg unload ' + ($r2 -join '|'))
} else { L '=H offline hive was already mounted by an earlier probe, left as-is' }
L 'P63 END'
