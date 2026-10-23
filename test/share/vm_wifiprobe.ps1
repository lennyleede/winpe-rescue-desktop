# PE 侧热测: 不重构建, 直接往运行中的 X: 里补 wlanapi.dll/wlanmsm.dll 并尝试拉起 wlansvc
# 由主机经 frp 隧道下发执行 (test\host_wifiprobe.ps1)
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }

L '===== 1. 取 WiFi 客户端文件 ====='
foreach ($f in @('wlanapi.dll','wlanmsm.dll')) {
  $dst = 'X:\Windows\System32\' + $f
  try {
    Invoke-WebRequest -UseBasicParsing -Uri ('http://172.31.32.1:8000/file/' + $f) -OutFile $dst
    L ('DL ' + $f + ' OK 字节=' + (Get-Item $dst).Length)
  } catch { L ('DL ' + $f + ' 失败: ' + $_.Exception.Message) }
}

L '===== 2. 启动 wlansvc ====='
$ns = (& net.exe start wlansvc 2>&1 | Out-String).Trim()
L ('net start wlansvc => ' + ($ns -replace '\s+', ' '))
Start-Sleep 3
foreach ($n in @('wlansvc')) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { L ($n + ' state=' + $q.State + ' pid=' + $q.ProcessId + ' startmode=' + $q.StartMode) }
  else { L ($n + ' SCM 查不到') }
}

L '===== 3. svchost 里有没有新进程 (wlansvc 起来了才会有) ====='
$pids = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { $_.Id })
L ('svchost pid 数=' + $pids.Count + ' 列表=' + ($pids -join ','))

L '===== 4. 已加载模块检查: 有没有进程装了 wlansvc.dll ====='
$found = $false
foreach ($p in (Get-Process -EA SilentlyContinue)) {
  try {
    foreach ($m in $p.Modules) {
      if ($m.ModuleName -match '^wlansvc\.dll$') { $found = $true; L ('  ' + $p.ProcessName + ' pid=' + $p.Id + ' 装了 wlansvc.dll') }
    }
  } catch {}
}
if (-not $found) { L '  没有任何进程加载 wlansvc.dll' }

L '===== 5. dot3svc 参照 (PE 自带的服务, 看它能否启动) ====='
$nd = (& net.exe start dot3svc 2>&1 | Out-String).Trim()
L ('net start dot3svc => ' + ($nd -replace '\s+', ' '))

L '===== 6. 网卡可见性 (VM 里没有无线网卡, 预期接口数 0) ====='
Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' | ForEach-Object {
  L ('  NA: ' + $_.Name + ' GUID=' + $_.GUID + ' 服务=' + $_.ServiceName + ' 设备=' + $_.AdapterType)
}

$body = $log -join "`r`n"
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
