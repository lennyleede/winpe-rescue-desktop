# probe67 -- LIVE PE, read-mostly forensics after probe66's R8 write.
# probe66 verdict so far: component store copied (W1 ok), FilterList written with the exact host/offline
#   instance syntax (W2 ok), pnputil /restart-device reported success, but the AX211 stays code 37,
#   NativeWifiP\Parameters\Adapters never appears and nativewifip StartService = err=31.
#   CI is NOT the blocker this boot (nwifi.sys 758784B v=19041.7663, start code 31 not 577).
# So the question probe67 answers: is the filter DRIVER failing to initialize, or is the BINDING request
#   never being made (no consumer of FilterList / missing NetCfg machinery / wlansvc must run first)?
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
function DumpVals([string]$path, [string]$tag) {
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $gi) { L ('  ' + $tag + ' ABSENT'); return }
  foreach ($vn in @($gi.GetValueNames())) {
    $k = $gi.GetValueKind($vn)
    $v = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $s = ''
    if ($k.ToString() -eq 'MultiString') { $s = (@($v) -join ',') }
    elseif ($v -is [byte[]]) { $s = 'hex:' + (Clean ($BitConverter::ToString($v))) }
    else { $s = '' + $v }
    $nm = '(default)'
    if ($vn -ne '') { $nm = $vn }
    L ('  ' + $tag + ' ' + $nm + ' [' + $k + '] = ' + (Clean $s))
  }
  L ('  ' + $tag + ' SUBS=[' + (@($gi.GetSubKeyNames()) -join ',') + ']')
}

# ---------- 0. is my probe66 write still there? ----------
L '=0 state after probe66'
DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET + '\0001\Linkage') '0PE-LINK'
DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Control\Network\' + $SVS + '\' + $NWIFI) '0PE-NWIFI'

# ---------- 1. service keys: PE vs offline of the SAME laptop ----------
L '=1 service key PE vs offline'
$rr = @(& reg.exe load HKLM\Q67OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  1 reg load q67off ' + ($rr -join '|'))
foreach ($svc in 'nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'wlansvc', 'wcmsvc', 'NdisImPlatform') {
  DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $svc) ('  1PE-' + $svc)
  DumpVals ('HKLM:\Q67OFF\ControlSet001\Services\' + $svc) ('  1OFF-' + $svc)
}

# ---------- 2. is nwifi.sys actually loaded in the kernel? ----------
L '=2 loaded driver modules'
$dq = @(& driverquery.exe /v /fo csv 2>&1)
if ($dq.Count -le 1) { L ('  2 driverquery produced ' + $dq.Count + ' lines: ' + (Clean (($dq -join ' ')))) }
else {
  L ('  2 driverquery lines=' + $dq.Count)
  foreach ($ln in $dq) { if ((Clean ('' + $ln)) -match '(?i)wifi|nwifi|vwifi|ndis') { L ('  2 DQ ' + (Clean ('' + $ln))) } }
}
foreach ($svc in 'nativewifip', 'vwififlt', 'vwifimp', 'vwifibus') {
  $sd = Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -eq $svc }
  if ($null -eq $sd) { L ('  2 SYSDRV ' + $svc + ' not listed') }
  else { L ('  2 SYSDRV ' + $svc + ' state=' + (Clean ('' + $sd.State)) + ' start=' + (Clean ('' + $sd.StartMode)) + ' path=' + (Clean ('' + $sd.PathName))) }
}

# ---------- 3. setupapi log: what did the class installer do on restart-device? ----------
L '=3 setupapi.dev.log'
$sl = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path -LiteralPath $sl) {
  $t = @(Get-Content -LiteralPath $sl -EA SilentlyContinue)
  L ('  3 log lines=' + $t.Count)
  $hits = @($t | Select-Object -Last 400 | Where-Object { (Clean ('' + $_)) -match '(?i)nwifi|vwifi|netwtw|NetCfg|component|filter|Fail|Error' })
  foreach ($h in $hits) { L ('  3 HIT ' + (Clean ('' + $h))) }
  L '  3 tail 25'
  foreach ($h in @($t | Select-Object -Last 25)) { L ('  3 T ' + (Clean ('' + $h))) }
} else { L '  3 NO setupapi.dev.log' }

# ---------- 4. event logs ----------
L '=4 event logs'
try {
  $ev = @(& wevtutil.exe el 2>&1 | Where-Object { (Clean ('' + $_)) -match '(?i)ndis|netprofm|wlansvc|pnp|Setup' })
  L ('  4 channels ' + ($ev -join '|'))
} catch { L ('  4 WEVTUTIL-ERR ' + (Clean ('' + $_.Exception.Message))) }
try {
  $g = @(Get-WinEvent -LogName System -MaxEvents 60 -EA Stop)
  L ('  4 system events=' + $g.Count)
  foreach ($e in $g) { L ('  4 EV ' + $e.TimeCreated.ToString('HHmmss') + ' id=' + $e.Id + ' lvl=' + $e.Level + ' src=' + (Clean ('' + $e.Provider.Name)) + ' | ' + (Clean ('' + $e.Message))) }
} catch { L ('  4 GETWINEVENT-ERR ' + (Clean ('' + $_.Exception.Message))) }

# ---------- 5. NetCfg / class-installer machinery present in PE? ----------
L '=5 netcfg machinery files'
foreach ($n in 'NetCfgx.dll', 'netshell.dll', 'ndisin.dll', 'NETSETUP.DLL', 'ncobjapi.dll', 'hnetcfg.dll',
               'dot3api.dll', 'wlanutil.dll', 'WLanHH.dll', 'wlanext.exe', 'netcfg.exe',
               'drivers\NdisImPlatform.sys', 'drivers\nwifi.sys', 'drivers\vwififlt.sys', 'drivers\vwifimp.sys', 'drivers\vwifibus.sys') {
  $p = 'X:\Windows\System32\' + $n
  $q = 'D:\Windows\System32\' + $n
  $a = 'MISSING'
  if (Test-Path -LiteralPath $p) { $a = '' + (Get-Item -LiteralPath $p).Length }
  $b = 'MISSING'
  if (Test-Path -LiteralPath $q) { $b = '' + (Get-Item -LiteralPath $q).Length }
  L ('  5 FILE ' + $n + ' PE=' + $a + ' OFF=' + $b)
}
DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET) '  5PE-CLSNET'
DumpVals ('HKLM:\Q67OFF\ControlSet001\Control\Class\' + $NET) '  5OFF-CLSNET'
DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $SVS) '  5PE-CLSSVC'
DumpVals ('HKLM:\Q67OFF\ControlSet001\Control\Class\' + $SVS) '  5OFF-CLSSVC'

# ---------- 6. does the offline store record have children PE is missing? ----------
L '=6 store records PE vs OFF'
DumpVals ('HKLM:\Q67OFF\ControlSet001\Control\Network\' + $SVS + '\' + $NWIFI) '  6OFF-NWIFI'
DumpVals ('HKLM:\Q67OFF\ControlSet001\Control\Network\' + $SVS + '\' + $NWIFI + '\Ndi') '  6OFF-NWIFI-Ndi'
DumpVals ('HKLM:\SYSTEM\CurrentControlSet\Control\Network\' + $SVS + '\' + $NWIFI + '\Ndi') '  6PE-NWIFI-Ndi'

# ---------- 7. experiment: wlansvc/wcmsvc FIRST, then restart the device ----------
L '=7 wlansvc-before-bind experiment'
L ('  7 start wlansvc : ' + (St 'wlansvc'))
try { $null = Start-Service wlansvc -EA Stop } catch { L ('  7 START-ERR ' + (Clean ('' + $_.Exception.Message))) }
try { $null = Start-Service wcmsvc -EA Stop } catch { L ('  7 WCM-ERR ' + (Clean ('' + $_.Exception.Message))) }
Start-Sleep -Seconds 4
L ('  7 after 4s wlansvc=' + (St 'wlansvc') + ' wcmsvc=' + (St 'wcmsvc') + ' nativewifip=' + (St 'nativewifip'))
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es.Count -eq 0) { L '  7 NO DEVNODE' } else {
  L ('  7 RESTART ' + ((@(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|'))
}
Start-Sleep -Seconds 10
foreach ($e in $es) { L ('  7 AFTER code=' + $e.ConfigManagerErrorCode + ' ' + (Clean ('' + $e.Name))) }
foreach ($n in 'nativewifip', 'vwififlt', 'vwifimp', 'vwifibus', 'wlansvc', 'wcmsvc') { L ('  7 STATE ' + $n + ' = ' + (St $n)) }
$p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
if (Test-Path -LiteralPath $p) { L ('  7 ADAPTERS=[' + (@(Get-ChildItem -LiteralPath $p | ForEach-Object { $_.PSChildName }) -join ',') + ']') } else { L '  7 ADAPTERS KEY ABSENT' }
$pe2 = 'HKLM:\SYSTEM\CurrentControlSet\Services\vwififlt\Parameters\Adapters'
if (Test-Path -LiteralPath $pe2) { L ('  7 VWIFIFLT-ADAPTERS=[' + (@(Get-ChildItem -LiteralPath $pe2 | ForEach-Object { $_.PSChildName }) -join ',') + ']') } else { L '  7 VWIFIFLT-ADAPTERS ABSENT' }
L 'P67 END'
