# 主机侧: 看本机 WiFi 栈相关服务键与文件, 决定要往 PE 里补哪些
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_wlanref.ps1
$names = @('nativewifip','Ndisuio','nwifi','wcmsvc','dot3svc','wlansvc','Dnscache')
foreach ($n in $names) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (-not (Test-Path $k)) { Write-Host ($n.PadRight(13) + '无服务键'); continue }
  $p = Get-ItemProperty $k
  $ip = $p.ImagePath
  $f = $null
  if ($ip) {
    $x = $ip -replace '^System32\\', ($env:SystemRoot + '\System32\')
    $x = $x -replace '^\\SystemRoot', $env:SystemRoot
    $x = $x -replace '%SystemRoot%', $env:SystemRoot
    $f = ($x -split ' ')[0]
  }
  Write-Host ($n.PadRight(13) + 'start=' + $p.Start + ' type=' + $p.Type + ' group=' + $p.Group + ' img=' + $ip + ' file存在=' + $(if ($f) { Test-Path $f } else { '?' }))
  $dep = $p.DependOnService
  if ($dep) { Write-Host ('              依赖=' + ($dep -join ',')) }
  if ($n -eq 'wlansvc') {
    Write-Host ('              ServiceDll=' + (Get-ItemProperty ($k + '\Parameters') -EA SilentlyContinue).ServiceDll)
  }
}
Write-Host '--- svchost 组键在哪 (PE 里找不到 CurrentControlSet\Services\svchost) ---'
foreach ($p in @('HKLM:\SYSTEM\CurrentControlSet\Services\svchost','HKLM:\SYSTEM\ControlSet001\Services\svchost')) {
  Write-Host ($p + ' 存在=' + (Test-Path $p))
}
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\svchost') {
  $g = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\svchost').GetValueNames()
  Write-Host ('              组数=' + $g.Count)
}
