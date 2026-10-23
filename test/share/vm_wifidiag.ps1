# PE 侧诊断 v2: 用自研 wifi.exe 拿 SCM 的精确错误与依赖链状态
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wifidiag.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$W = 'X:\wifi.exe'

L '===== A. 取 wifi.exe ====='
try {
  Invoke-WebRequest -UseBasicParsing -Uri 'http://172.31.32.1:8000/file/wifi.exe' -OutFile $W
  L ('  DL wifi.exe OK ' + (Get-Item $W).Length + ' 字节')
} catch { L ('  DL 失败: ' + $_.Exception.Message) }

function Run([string]$tag, [string[]]$args2) {
  $o = (& $W @args2 2>&1 | Out-String)
  L ('--- ' + $tag + ' ---')
  foreach ($line in ($o -split "`r?`n")) { if ($line.Trim()) { L ('  ' + $line.Trim()) } }
  return $o
}
function CState([string]$n) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { L ('  CIM ' + $n + ': state=' + $q.State + ' startmode=' + $q.StartMode + ' exit=' + $q.ExitCode + ' pid=' + $q.ProcessId + ' path=' + $q.PathName) }
  else { L ('  CIM ' + $n + ': 查不到') }
}

L '===== B. wlansvc 依赖链 + 精确错误 ====='
Run 'deps wlansvc' @('deps', 'wlansvc') | Out-Null
Run 'svc info wlansvc' @('svc', 'info', 'wlansvc') | Out-Null
CState 'wlansvc'

L '===== C. 起 wlansvc 并逐秒观察状态 ====='
Run 'svc start wlansvc' @('svc', 'start', 'wlansvc') | Out-Null
for ($i = 1; $i -le 12; $i++) {
  Start-Sleep -Seconds 1
  $q = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue
  $st = $(if ($q) { $q.State } else { '?' })
  Run ("svc info wlansvc t=${i}s") @('svc', 'info', 'wlansvc') | Out-Null
  if ($st -eq 'Running' -or $st -eq 'Stopped') { L ('  稳定状态=' + $st + ' (t=' + $i + 's)'); break }
}

L '===== D. 承载 wlansvc 的 svchost 进程 ====='
$ps = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)
foreach ($p in $ps) {
  if ($p.CommandLine -match 'PEWLan|PEWCm|-k ') { L ('  pid=' + $p.ProcessId + ' cmd=' + $p.CommandLine) }
}
L ('  svchost 进程数=' + $ps.Count)

L '===== E. 依赖链上的每一环 (CIM 视角) ====='
foreach ($s in @('RpcSs', 'nsi', 'nsiproxy', 'dot3svc', 'nativewifip', 'Ndisuio', 'wcmsvc', 'nwifi')) { CState $s }

L '===== E2. SCM 缓存里的服务配置 (dot3svc 是 PE 里已能跑起来的参照) ====='
foreach ($s in @('wlansvc', 'dot3svc', 'Dhcp', 'BFE')) { Run ("svc info $s") @('svc', 'info', $s) | Out-Null }

L '===== F. wlanapi 能不能打开 ====='
Run 'status' @('status') | Out-Null

L ('===== 诊断完毕 =====')

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
