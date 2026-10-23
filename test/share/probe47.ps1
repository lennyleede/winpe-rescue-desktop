# probe47 -- LIVE PE, read-only, output prefixed P47.
# New lead after probe46: the laptop's OWN netwtw6e packages (23.60.1.2 and 23.150.0.4) also give
# code 37 in PE, so this is not "the wrong driver version" -- the driver cannot START here.
# probe43/44 showed vwififlt (Start=1 SYSTEM_START, Group=NDIS) and nativewifip (Start=3, Group=NDIS)
# are both Stopped, while the laptop's working Windows has them loaded. NDIS miniport start fails with
# STATUS_NOT_SUPPORTED when a required filter cannot attach.
# Hypothesis: this PE never processes the NDIS system-start group -- i.e. Control\ServiceGroupOrder /
# GroupOrderList is missing or lacks NDIS, so nothing in Group=NDIS with Start=1 gets loaded at boot.
# If true, the fix is an offline registry bake (same path wifi-inject already uses for service keys).
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }

O '== 1 every SYSTEM_START (Start=1) service in the running PE =='
$svcs = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue)
O ('  SYSTEMDRIVER_COUNT ' + $svcs.Count)
foreach ($d in ($svcs | Sort-Object Name)) {
  O ('  DRV ' + $d.Name + ' state=' + $d.State + ' started=' + $d.Started + ' startmode=' + $d.StartMode +
     ' path=' + $(if ($d.PathName) { ($d.PathName -replace '\\', '/') } else { '-' }))
}
O '== 2 Start=1 keys in the live hive and their group =='
foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue)) {
  $p = Get-ItemProperty -LiteralPath $k.PSPath -EA SilentlyContinue
  if ($p.Start -eq 1) {
    $st = 'NA'
    try { $st = "$((Get-Service $k.PSChildName).Status)" } catch { $st = 'NOGET' }
    O ('  S1 ' + $k.PSChildName + ' Group=' + $(if ($p.Group) { $p.Group -join ',' } else { '-' }) + ' status=' + $st)
  }
}
O '== 3 group order tables in the live PE =='
foreach ($g in 'ServiceGroupOrder', 'GroupOrderList') {
  $out = @(& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Control\' + $g) /s 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  if ($out[0] -match 'ERROR') { O ('  ' + $g + ' ABSENT') } else {
    O ('  ' + $g + ' lines=' + $out.Count)
    foreach ($l in ($out | Where-Object { $_ -match 'REG_MULTI_SZ|REG_DWORD' } | Select-Object -First 40)) { O ('    | ' + $l) }
  }
}
O '== 4 same tables in the laptop working Windows (offline SYSTEM hive, read then unload) =='
$hive = 'D:\Windows\System32\config\SYSTEM'
$key = 'HKLM\P47OFF'
$loaded = $false
try {
  & reg.exe load $key $hive 2>&1 | ForEach-Object { O ('  LOAD ' + (($_ -replace '\s+', ' ').Trim())) }
  if (@(& reg.exe query $key 2>&1).Count -gt 1) { $loaded = $true }
  foreach ($g in 'ServiceGroupOrder', 'GroupOrderList') {
    $out = @(& reg.exe query ($key + '\ControlSet001\Control\' + $g) /s 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
    if ($out[0] -match 'ERROR') { O ('  OFF ' + $g + ' ABSENT') } else {
      foreach ($l in ($out | Where-Object { $_ -match 'REG_MULTI_SZ' } | Select-Object -First 12)) { O ('  OFF| ' + $l) }
    }
  }
  foreach ($n in 'vwififlt', 'nativewifip', 'vwifibus', 'Wanarpv6', 'NetBIOS', 'ndisufix') {
    $q = @(& reg.exe query ($key + '\ControlSet001\Services\' + $n) /v Start 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
    $q2 = @(& reg.exe query ($key + '\ControlSet001\Services\' + $n) /v Group 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
    O ('  OFFSVC ' + $n + ' ' + (($q + $q2 | Where-Object { $_ -match 'REG_' }) -join ' ;; '))
  }
} catch { O ('  OFFERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
finally {
  if ($loaded) {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    & reg.exe unload $key 2>&1 | ForEach-Object { O ('  UNLOAD ' + (($_ -replace '\s+', ' ').Trim())) }
  }
  O ('  UNLOADCHECK ' + (@(& reg.exe query $key 2>&1 | ForEach-Object { "$_" })[0] -replace '\s+', ' '))
}
O 'P47 END'
