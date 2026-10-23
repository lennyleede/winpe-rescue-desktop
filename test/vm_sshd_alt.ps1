# 在活 PE 里把新编的 pe-sshd 以 2222 端口并行起一份, 用来验收"交互命令有响应"的修复
#   为什么不直接换掉 22: 老服务端一杀, 它那条会话的 cmd/powershell 会继承了 :22 的套接字句柄,
#   新实例 bind 就报 "Only one usage of each socket address"(2026-10-05 16:59 实测踩过, 见 test\vm_result_165945_1.txt)
#   并行起最省事: 22 继续跑老的, 2222 跑新的, 主机用同一套用例分别打两个端口做对照
# 由主机侧驱动: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_pe_exec.ps1 -Payload vm_sshd_alt.ps1
param(
  [string]$ServeHost = '192.168.100.1',
  [int]$ServePort = 8000,
  [int]$AltPort = 2222,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Output $s }
$new = 'X:\SSH\pe-sshd-new.exe'
$altLog = 'X:\sshd_alt.log'

Add ('===== vm_sshd_alt ' + (Get-Date -Format 'HH:mm:ss') + ' 并行起新服务端 :2222 =====')
$run = @(Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'")
Add ('[1] 现在跑着的 pe-sshd: ' + (($run | ForEach-Object { 'pid=' + $_.ProcessId }) -join ', '))
# 上一轮热换留下的下载产物是 pe-sshd.new; Windows 创建进程看的是 .exe 扩展名, 先就地改名再复用
if (-not (Test-Path $new) -and (Test-Path 'X:\SSH\pe-sshd.new')) {
  Move-Item 'X:\SSH\pe-sshd.new' $new -Force
  Add '[1b] 把上轮的 X:\SSH\pe-sshd.new 改名为 pe-sshd-new.exe(CreateProcess 只认 .exe)'
}
if (-not (Test-Path $new)) {
  Add ('[2] 先下载新 exe -> ' + $new)
  try {
    (New-Object Net.WebClient).DownloadFile('http://' + $ServeHost + ':' + $ServePort + '/file/pe-sshd.exe', $new)
  } catch { Add ('    !! 下载失败: ' + $_.Exception.Message); exit 1 }
}
Add ('[2] 新 exe ' + $new + ' 大小=' + (Get-Item $new).Length + ' 旧 exe 大小=' + $(if (Test-Path 'X:\SSH\pe-sshd.exe') { (Get-Item 'X:\SSH\pe-sshd.exe').Length } else { 0 }))
if ((Get-Item $new).Length -lt 1000000) { Add '  !! 大小不对, 放弃'; exit 1 }
# 端口是否已被占
$tc = New-Object Net.Sockets.TcpClient
$busy = $false
try { $tc.Connect('127.0.0.1', $AltPort); $busy = $tc.Connected; $tc.Close() } catch { $busy = $false }
Add ('[3] 127.0.0.1:' + $AltPort + ' 占用=' + $busy + $(if ($busy) { ' -> 换个端口 -AltPort 2223' } else { ' -> 空着, 可以用' }))
if ($busy) { exit 1 }
if ($SelfTest) { Add '[4] SelfTest: 不启动, 到此检查全通过'; exit 0 }

if (Test-Path $altLog) { Remove-Item $altLog -Force -EA SilentlyContinue }
$a = '-addr 0.0.0.0:' + $AltPort + ' -hostkey X:\SSH\pe_host_ed25519 -authkeys X:\SSH\authorized_keys -log ' + $altLog
try {
  Start-Process -FilePath $new -ArgumentList $a -WindowStyle Hidden
  Add ('[4] 已启动: ' + $new + ' ' + $a)
} catch { Add ('    !! 启动失败: ' + $_.Exception.Message); exit 1 }
Start-Sleep 3
$n = @(Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'")
Add ('[5] pe-sshd 进程数=' + $n.Count + ' (' + (($n | ForEach-Object { $_.ProcessId }) -join ',') + ')')
$ok2 = $false
try { $t2 = New-Object Net.Sockets.TcpClient; $iar = $t2.BeginConnect('127.0.0.1', $AltPort, $null, $null); $ok2 = $iar.AsyncWaitHandle.WaitOne(3000) -and $t2.Connected; $t2.Close() } catch { }
Add ('[6] 本机连 ' + $AltPort + ' 端口: ' + $ok2)
$tail = '(无日志)'
if (Test-Path $altLog) {
  try {
    $fs = [IO.File]::Open($altLog, 'Open', 'Read', 'ReadWrite')
    $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
    $txt = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
    $tail = (@(($txt -split "`r?`n") | Where-Object { $_ } | Select-Object -Last 3)) -join ' | '
  } catch { $tail = '读日志失败: ' + $_.Exception.Message }
}
Add ('[7] 新实例日志: ' + $tail)
Add ('[8] 主机侧对照验收: powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_cr_test.ps1 -Port ' + $AltPort)
try {
  $body = 'vm_sshd_alt ' + (Get-Date -Format 'HH:mm:ss') + ' 进程数=' + $n.Count + ' 端口' + $AltPort + '本机可连=' + $ok2 + ' | ' + $tail
  (New-Object Net.WebClient).UploadString('http://' + $ServeHost + ':' + $ServePort + '/result', $body) | Out-Null
  Add '[9] 已 POST 回传'
} catch { Add ('[9] POST 失败(不影响): ' + $_.Exception.Message) }
