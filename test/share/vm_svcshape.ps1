# 取 PE 里"已经能跑起来"的同类服务的完整服务键形状, 作为重建镜像时 wlansvc 的模板
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_svcshape.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }

foreach ($n in @('dot3svc', 'wlansvc', 'RpcSs', 'nsi', 'Dhcp', 'BFE', 'MPSSvc')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty $k -EA SilentlyContinue
  if (-not $p) { L ("===== $n : 无服务键 ====="); continue }
  L ("===== $n =====")
  foreach ($v in @('Type', 'Start', 'ErrorControl', 'Group', 'ImagePath', 'ObjectName', 'ServiceSidType', 'DependOnService', 'RequiredPrivileges', 'DelayedAutoStart', 'TrustLevel')) {
    if ($null -ne $p.$v) {
      $val = $p.$v; if ($val -is [Array]) { $val = $val -join ';' }
      L ('  ' + $v + ' = ' + $val)
    }
  }
  $pp = Get-ItemProperty ($k + '\Parameters') -EA SilentlyContinue
  if ($pp) {
    foreach ($v in ($pp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) { L ('  Parameters\' + $v.Name + ' = ' + ($v.Value -join ';')) }
  }
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { L ('  [SCM/CIM] state=' + $q.State + ' pid=' + $q.ProcessId + ' exit=' + $q.ExitCode + ' startname=' + $q.StartName) }
}

L '===== svchost 组表: 与网络有关的几组 ====='
$SH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
foreach ($g in @('LocalSystemNetworkRestricted', 'LocalServiceNetworkRestricted', 'LocalService', 'NetworkService', 'PEWLan')) {
  $v = @((Get-Item $SH).GetValue($g))
  L ('  ' + $g + ' (' + $v.Count + ') = ' + ($v -join ','))
}
L '===== 组子键 (ObjectName/RequiredPrivileges 等组级设置) ====='
foreach ($s in (Get-ChildItem $SH -EA SilentlyContinue)) {
  $nm = $s.PSChildName
  if ($nm -match 'LocalSystemNetworkRestricted|LocalServiceNetworkRestricted|PEWLan') {
    $sp = Get-ItemProperty $s.PSPath
    $props = @(($sp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name + '=' + ($_.Value -join ';') }))
    L ('  [' + $nm + '] ' + ($props -join ' | '))
  }
}
L '===== nwifi/nativewifip 服务键与文件 ====='
foreach ($n in @('nwifi', 'nativewifip', 'Ndisuio', 'wcmsvc')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty $k -EA SilentlyContinue
  if ($p) { L ('  ' + $n + ': Type=' + $p.Type + ' Start=' + $p.Start + ' Group=' + $p.Group + ' Img=' + $p.ImagePath) } else { L ('  ' + $n + ': 无键') }
}

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
