$ErrorActionPreference = 'Continue'
function Show([string]$n) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) {
    Write-Host ($n + ': State=' + $q.State + ' StartMode=' + $q.StartMode + ' PathName=' + $q.PathName + ' Exit=' + $q.ExitCode)
  } else { Write-Host ($n + ': no such service') }
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty $k -EA SilentlyContinue
  if ($p) {
    $d = $p.DependOnService; if ($d -is [Array]) { $d = $d -join ',' }
    Write-Host ('   reg Type=' + $p.Type + ' Start=' + $p.Start + ' Group=' + $p.Group + ' Deps=' + $d + ' Img=' + $p.ImagePath)
  }
}
Write-Host '===== wlansvc 依赖链在真机上的实际状态 ====='
foreach ($n in @('wlansvc', 'nativewifip', 'Ndisuio', 'wcmsvc', 'RpcSs', 'nsi', 'BFE')) { Show $n }
Write-Host '===== wlansvc 注册表全值 ====='
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc' -EA SilentlyContinue).PSObject.Properties |
  Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Write-Host ('  ' + $_.Name + ' = ' + ($_.Value -join ';')) }
Write-Host '===== PE 里也要一起补的文件在主机上的版本 ====='
foreach ($f in @('wlanapi.dll', 'wlanmsm.dll', 'wlancfg.dll', 'wlanutil.dll', 'wcmsvc.dll', 'dmcmnutils.dll', 'mdmregistration.dll', 'wci.dll', 'netshell.dll', 'drivers\nwifi.sys')) {
  $p = Join-Path 'C:\Windows\System32' $f
  if (Test-Path $p) { Write-Host ('  ' + $f + ' ' + (Get-Item $p).Length + '  ' + (Get-Item $p).VersionInfo.FileVersion) }
  else { Write-Host ('  ' + $f + ' MISSING on host') }
}
Write-Host '===== 主机无线网卡驱动 (供 dism /Add-Driver 参考的 INF 名) ====='
$net = Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=TRUE" -EA SilentlyContinue
foreach ($n in $net) {
  $pnp = Get-CimInstance Win32_PnPEntity -Filter "DeviceID='$($n.PNPDeviceID)'" -EA SilentlyContinue
  $inf = if ($pnp) { $pnp.DeviceInstaller } else { '?' }
  Write-Host ('  ' + $n.Name + ' | ' + $n.PNPDeviceID + ' | inf=' + $inf)
}
Write-Host '===== 已注入第三方/系统 WiFi INF 位置 ====='
foreach ($i in @('netwtw*.inf', 'iwnl*.inf', 'RTWlan*.inf', 'athr*.inf', 'bt*bcm*.inf')) {
  $f = Get-ChildItem 'C:\Windows\INF' -Filter $i -EA SilentlyContinue | Select-Object -First 3
  foreach ($x in $f) { Write-Host ('  ' + $x.Name) }
}
