# PE 侧热修 v5: 只改 svchost 组表 PEWLan 的语义 (组值 = 服务名列表, 不是 DLL 路径)
# SCM 启动用的是开机时缓存的 ImagePath(-k PEWLan, 无 -p)与 Type=32, 这两样都不动, 单次实验只动一个变量
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wififix5.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$W = 'X:\wifi.exe'
$SVCHOST = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'

try {
  Invoke-WebRequest -UseBasicParsing -Uri 'http://172.31.32.1:8000/file/wifi.exe' -OutFile $W
  L ('A. DL wifi.exe OK ' + (Get-Item $W).Length)
} catch { L ('A. DL 失败: ' + $_.Exception.Message) }
function Run([string]$tag, [string[]]$args2) {
  $o = (& $W @args2 2>&1 | Out-String)
  L ('--- ' + $tag + ' ---')
  foreach ($line in ($o -split "`r?`n")) { if ($line.Trim()) { L ('  ' + $line.Trim()) } }
}

L '===== B. 把 PEWLan 改成服务名列表 ====='
$old = @((Get-Item $SVCHOST).GetValue('PEWLan'))
L ('  改前 PEWLan = ' + ($old -join '|'))
Set-ItemProperty $SVCHOST -Name PEWLan -Value @('wlansvc') -Type MultiString
L ('  改后 PEWLan = ' + (@((Get-Item $SVCHOST).GetValue('PEWLan')) -join '|'))

L '===== C. 起 wlansvc (SCM 用的仍是开机缓存的 Type=32 + -k PEWLan) ====='
Run 'svc start wlansvc' @('svc', 'start', 'wlansvc')
$ok = $false
for ($i = 1; $i -le 15; $i++) {
  Start-Sleep -Seconds 2
  $q = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue
  L ('  t=' + ($i * 2) + 's state=' + $(if ($q) { $q.State } else { '?' }) + ' exit=' + $(if ($q) { $q.ExitCode } else { '?' }) + ' pid=' + $(if ($q) { $q.ProcessId } else { '?' }))
  if ($q -and $q.State -eq 'Running') { $ok = $true; break }
  if ($q -and $q.State -eq 'Stopped') { break }
}

L '===== D. PEWLan 的 svchost 进程 / 模块加载 ====='
foreach ($c in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  if ($c.CommandLine -match 'PEWLan') { L ('  pid=' + $c.ProcessId + ' cmd=' + $c.CommandLine) }
}
$found = $false
foreach ($p in @(Get-Process svchost -EA SilentlyContinue)) {
  try { foreach ($m in $p.Modules) { if ($m.ModuleName -match '^wlansvc\.dll$') { $found = $true; L ('  pid=' + $p.Id + ' 已加载 wlansvc.dll') } } } catch { L ('  pid=' + $p.Id + ' 模块枚举失败: ' + $_.Exception.Message) }
}
if (-not $found) { L '  没有 svchost 加载 wlansvc.dll' }

L '===== E. wlanapi 视角 ====='
Run 'status' @('status')
Run 'svc info wlansvc' @('svc', 'info', 'wlansvc')

L ('===== 结论: ' + $(if ($ok) { 'PEWLan 语义修正后 wlansvc RUNNING (1068 的锅在组表)' } else { '仍然起不来, 组表语义不是唯一原因' }) + ' =====')
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
