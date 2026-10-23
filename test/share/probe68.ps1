# probe68 -- LIVE PE. probe66 proved {component store + Linkage\FilterList + pnputil /restart-device} is NOT
# enough (AX211 stays code 37, no NativeWifiP\Parameters\Adapters). probe67 showed WHY restart-device cannot
# work: setupapi.dev.log gained zero lines from it, i.e. the Net class installer (NetCfgx.dll!NetClassInstaller,
# registered as Installer32 on Control\Class\{4d36e974}) never ran, and nothing in the PE appends filters or
# asks NDIS to attach them. FilterList is NetCfg's bookkeeping, written by that installer at INSTALL time.
# So the two candidate live fixes, in order:
#   C: full reinstall of the devnode (/remove-device + /scan-devices) WITH the component store now populated
#      -> does NetClassInstaller bind MS_NativeWiFiPacketFilter by itself?  (if yes: ship = bake store + reinstall)
#   D: netcfg.exe (present in this PE, 65536B) installing the component explicitly.
# Also A: is netnwifi.inf/netvwififlt.inf actually in the PE DriverStore (that is what the installer binds from)?
# and B: NDIS / Network-Setup ETW channels around the attempt.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$PS_CLS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
function Slots([string]$tag) {
  foreach ($nn in @(Get-ChildItem -LiteralPath $PS_CLS -EA SilentlyContinue)) {
    if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
    $g = Get-Item -LiteralPath ($PS_CLS + '\' + $nn.PSChildName)
    $md = Clean ('' + $g.GetValue('MatchingDeviceId', ''))
    if ($md -notmatch 'VEN_8086&DEV_7A70') { continue }
    $lk = $PS_CLS + '\' + $nn.PSChildName + '\Linkage'
    $fl = ''
    if (Test-Path -LiteralPath $lk) { $fl = (Clean ('' + ((Get-Item -LiteralPath $lk).GetValue('FilterList', @()) -join ';'))) }
    L ('  ' + $tag + ' slot=' + $nn.PSChildName + ' NetCfgId=' + (Clean ('' + $g.GetValue('NetCfgInstanceId', ''))) + ' FilterList=[' + (Trim2 $fl 260) + ']')
  }
}
function Codes([string]$tag) {
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  L ('  ' + $tag + ' devnodes=' + $es.Count)
  foreach ($e in $es) { L ('  ' + $tag + ' code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' ' + (Trim2 ('' + $e.Name) 60)) }
}
function Etw([string]$tag) {
  foreach ($ch in 'Microsoft-Windows-NDIS/Operational', 'Microsoft-Windows-NDIS/Diagnostic', 'Microsoft-Windows-Network-Setup/Diagnostic') {
    try {
      $evs = @(Get-WinEvent -LogName $ch -MaxEvents 25 -EA Stop)
      L ('  ' + $tag + ' ' + $ch + ' n=' + $evs.Count)
      foreach ($e in $evs) { L ('  ' + $tag + ' ' + $ch.Substring($ch.IndexOf('/') + 1) + ' id=' + $e.Id + ' lvl=' + $e.Level + ' ' + (Trim2 ('' + $e.Message) 190)) }
    } catch { L ('  ' + $tag + ' ' + $ch + ' ERR ' + (Trim2 ('' + $_.Exception.Message) 120)) }
  }
}

# ---------- A. is the NetService component package in the PE at all? ----------
L '=A netnwifi/netvwififlt package inventory'
foreach ($f in 'netnwifi.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netvwifibus.inf') {
  $p = 'X:\Windows\INF\' + $f
  $s = 'MISSING'
  if (Test-Path -LiteralPath $p) { $s = '' + (Get-Item -LiteralPath $p).Length + 'B' }
  L ('  A ' + $f + ' ' + $s)
}
$ofs = @(Get-ChildItem -LiteralPath 'X:\Windows\INF' -Filter 'oem*.inf' -EA SilentlyContinue)
L ('  A oem inf count=' + $ofs.Count)
foreach ($o in $ofs) {
  $t = @(Get-Content -LiteralPath $o.FullName -Encoding Unicode -EA SilentlyContinue)
  $hit = @($t | Where-Object { (Clean ('' + $_)) -match '(?i)nwifi|vwifi' })
  if ($hit.Count -gt 0) { L ('  A ' + $o.Name + ' mentions vwifi/nwifi lines=' + $hit.Count + ' :: ' + (Trim2 ($hit[0]) 150)) }
}
$pp = @(& pnputil.exe /enum-drivers 2>&1)
$cur = ''
foreach ($ln in $pp) {
  $c = Clean ('' + $ln)
  if ($c -match '(?i)^Published Name\s*:') { $cur = $c }
  if ($c -match '(?i)nwifi|vwifi') { L ('  A PNPUTIL ' + $cur + ' | ' + $c) }
}
L ('  A PNPUTIL total lines=' + $pp.Count)

# ---------- B. baseline before surgery ----------
L '=B baseline'
Slots 'B'
Codes 'B'
Etw 'B'

# ---------- C. full reinstall with the component store populated ----------
L '=C reinstall (remove-device + scan-devices)'
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es.Count -eq 0) { L '  C NO DEVNODE -- ABORT' } else {
  $devid = $es[0].PNPDeviceID
  $r1 = @(& pnputil.exe /remove-device "$devid" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  C REMOVE ' + (Trim2 ($r1 -join '|') 300))
  Start-Sleep -Seconds 3
  $r2 = @(& pnputil.exe /scan-devices 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  C SCAN ' + (Trim2 ($r2 -join '|') 300))
  Start-Sleep -Seconds 8
  $seen = 0
  $firstAt = 0
  for ($try = 0; $try -lt 8; $try++) {
    $now = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
    if ($now.Count -gt 0 -and $seen -eq 0) { $seen = $now.Count; $firstAt = 8 + $try * 5 }
    Start-Sleep -Seconds 5
  }
  if ($seen -eq 0) { L '  C DEVNODE DID NOT REAPPEAR within 48s' } else { L ('  C reappeared after ' + $firstAt + 's, letting it settle') }
  Slots 'C'
  Codes 'C'
  foreach ($n in 'nativewifip', 'vwififlt', 'vwifimp', 'vwifibus', 'wlansvc') { L ('  C STATE ' + $n + ' = ' + (St $n)) }
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) { L ('  C ADAPTERS=[' + (@(Get-ChildItem -LiteralPath $p | ForEach-Object { $_.PSChildName }) -join ',') + ']') } else { L '  C ADAPTERS KEY ABSENT' }
  $sl2 = 'X:\Windows\INF\setupapi.dev.log'
  $t2 = @(Get-Content -LiteralPath $sl2 -EA SilentlyContinue)
  L ('  C setupapi lines now=' + $t2.Count)
  foreach ($h in @($t2 | Select-Object -Last 45)) { $c = Clean ('' + $h); if ($c -ne '') { L ('  C LOG ' + (Trim2 $c 170)) } }
  Etw 'C'
}

# ---------- D. netcfg.exe ----------
L '=D netcfg'
$h = @(& netcfg.exe 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  D USAGE n=' + $h.Count)
foreach ($ln in $h) { if ($ln -ne '') { L ('  D | ' + (Trim2 $ln 200)) } }
foreach ($arg in @(@('-c', 's', '-i', 'MS_NativeWiFiPacketFilter'), @('-c', 's', '-i', 'NativeWifiP'), @('-c', 's', '-i', $NWIFI), @('-s'))) {
  $j = @(& netcfg.exe $arg 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  D RUN [' + ($arg -join ' ') + '] -> ' + (Trim2 ($j -join ' | ') 300))
}
Slots 'D'
Codes 'D'

# ---------- E. what does the store look like now ----------
L '=E store now'
foreach ($k in @($NWIFI, $VFLT)) {
  $kk = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\' + $SVS + '\' + $k
  if (Test-Path -LiteralPath $kk) {
    $gi = Get-Item -LiteralPath $kk
    L ('  E ' + $k + ' values=[' + (@($gi.GetValueNames()) -join ',') + '] subs=[' + (@($gi.GetSubKeyNames()) -join ',') + ']')
  } else { L ('  E ' + $k + ' ABSENT') }
}
L 'P68 END'
