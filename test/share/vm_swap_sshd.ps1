# 在**正在运行的 PE** 里把 pe-sshd 热换成新版(不必重构建就能验交互修复)
#   由主机侧驱动: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_pe_exec.ps1 -Payload vm_swap_sshd.ps1
#   为什么要脱离当前会话去换: 换服务端会杀死我自己这条 SSH, 所以"停-覆盖-重启"交给一个后台子进程,
#   它跑完把结果 POST 回 host_serve(落 test\vm_result_*.txt), 主机再读。
#   交付前自检(在宿主机上跑, 只打印换血脚本本体, 不碰任何进程):
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_swap_sshd.ps1 -ShowWorker
param(
  [string]$ServeHost = '192.168.100.1',
  [int]$ServePort = 8000,
  [switch]$SelfTest,
  [switch]$ShowWorker
)
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
$exe = 'X:\SSH\pe-sshd.exe'
$new = 'X:\SSH\pe-sshd.new'

function Get-WorkerText($h, $p) {
  $t = @'
$ErrorActionPreference = 'Continue'
Start-Sleep 5
Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'" | ForEach-Object { $null = $_.Terminate() }
Start-Sleep 1
Move-Item 'X:\SSH\pe-sshd.new' 'X:\SSH\pe-sshd.exe' -Force
$fs = [IO.File]::Open('X:\swap.log', 'Append', 'Write', 'ReadWrite')
$sr = New-Object IO.StreamWriter($fs, (New-Object Text.UTF8Encoding($true)))
$sr.WriteLine((Get-Date -Format 'HH:mm:ss') + ' swapped exe=' + (Get-Item 'X:\SSH\pe-sshd.exe').Length)
$sr.Close(); $fs.Close()
Start-Process -FilePath 'X:\SSH\pe-sshd.exe' -WindowStyle Hidden -ArgumentList '-addr 0.0.0.0:22 -hostkey X:\SSH\pe_host_ed25519 -authkeys X:\SSH\authorized_keys -log X:\sshd.log'
Start-Sleep 3
$cnt = @(Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'").Count
$fs2 = [IO.File]::Open('X:\sshd.log', 'Open', 'Read', 'ReadWrite')
$sr2 = New-Object IO.StreamReader($fs2, [Text.Encoding]::UTF8)
$txt = $sr2.ReadToEnd(); $sr2.Close(); $fs2.Close()
$tail = @(($txt -split "`r?`n" | Where-Object { $_ }) | Select-Object -Last 4) -join ' | '
$body = 'pe-sshd 进程数=' + $cnt + ' exe=' + (Get-Item 'X:\SSH\pe-sshd.exe').Length + ' 换于' + (Get-Date -Format 'HH:mm:ss') + ' | 日志尾: ' + $tail
try { (New-Object Net.WebClient).UploadString('http://__HOST__:__PORT__/result', $body) } catch { }
'@
  return ($t -replace '__HOST__', $h -replace '__PORT__', $p)
}

if ($ShowWorker) {
  $out = Join-Path $PSScriptRoot 'share\swap_worker.preview.ps1'
  [IO.File]::WriteAllText($out, (Get-WorkerText $ServeHost $ServePort), (New-Object Text.UTF8Encoding($true)))
  Write-Host ('已写 ' + $out + ' (' + (Get-Item $out).Length + ' 字节), 拿它去跑语法检查')
  exit 0
}

Add ('===== vm_swap_sshd ' + (Get-Date -Format 'HH:mm:ss') + ' 热换 pe-sshd (SelfTest=' + [bool]$SelfTest + ') =====')
$old = @(Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'")
Add ('[1] 运行中的 pe-sshd 进程数=' + $old.Count)
foreach ($p in $old) { Add ('    pid=' + $p.ProcessId + ' 启动=' + $p.CreationDate + ' 路径=' + $p.ExecutablePath) }
if (Test-Path $exe) { Add ('    当前 exe 大小=' + (Get-Item $exe).Length + ' 改时=' + (Get-Item $exe).LastWriteTime) }
Add ('    主机密钥=' + $(if (Test-Path 'X:\SSH\pe_host_ed25519') { '沿用 X:\SSH\pe_host_ed25519(不动它, 免得 known_hosts 又失配)' } else { '(本次开机自动生成的那把)' }))

Add ('[2] 下载新服务端 http://' + $ServeHost + ':' + $ServePort + '/file/pe-sshd.exe')
try {
  (New-Object Net.WebClient).DownloadFile('http://' + $ServeHost + ':' + $ServePort + '/file/pe-sshd.exe', $new)
  Add ('    落地 ' + $new + ' 大小=' + (Get-Item $new).Length)
} catch { Add ('    !! 下载失败: ' + $_.Exception.Message); Add '  => 放弃, 旧服务端继续跑'; exit 1 }
if ((Get-Item $new).Length -lt 1000000) { Add '  !! 大小不对(像是 404 页面), 放弃'; exit 1 }

if ($SelfTest) {
  Add '[3] SelfTest: 只查进程/下载/替换脚本本体, 不杀进程不重启 —— 到这里都 OK'
  exit 0
}

$worker = 'X:\swap_worker.ps1'
[IO.File]::WriteAllText($worker, (Get-WorkerText $ServeHost $ServePort), [Text.Encoding]::ASCII)
Add ('[3] 已写后台换血脚本 ' + $worker + '(' + (Get-Item $worker).Length + ' 字节)')
Add '    它做: 等 5 秒 -> 结束旧进程 -> 覆盖 exe -> 按 startnet 同样的命令行重启 -> POST 回传'
Add '[4] 启动后台进程。本会话随后会被断开, 这是预期, 不是坏了'
try {
  Start-Process -FilePath 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $worker -WindowStyle Hidden
  Add '    已启动'
} catch { Add ('    !! 启动后台进程失败: ' + $_.Exception.Message); exit 1 }
Add '[5] 约 10 秒后结果落在 test\vm_result_*.txt; 之后主机再用 ssh_cr_test 打真 PE 收尾验收'
