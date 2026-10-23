# 一条命令搞定: 从宿主机诊断 WinPE 里的 pe-sshd 到底哪一步断了, 结果同时打印并写 build\ssh_diag.txt
# 用法(普通 PowerShell 即可, 不用管理员):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_diag.ps1 -Ip 192.168.x.x
#   走 frp 映射就加 -Port 6000; 用户名默认 Administrator
param(
  [Parameter(Mandatory)][string]$Ip,
  [int]$Port = 22,
  [string]$User = 'Administrator',
  [int]$TimeoutSec = 25
)
$ErrorActionPreference = 'Stop'
$proj = Split-Path -Parent $PSScriptRoot
$tmp  = Join-Path $proj 'build\ssh_diag'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -ErrorAction SilentlyContinue

$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshExe)) { throw "找不到 $sshExe" }
$report = New-Object System.Collections.Generic.List[string]
function Say($s) { Write-Host $s; $report.Add($s) }

# 私钥拷到临时目录收紧 ACL(宿主机上原文件权限太宽, ssh 会拒绝用), PE 是空密码模式, 有没有钥匙都能连
$key = Join-Path $tmp 'login_key'
$src = Join-Path $proj 'overlay\Scripts\ssh_login_key'
if (Test-Path $src) {
  Copy-Item $src $key -Force
  & icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
} else { $key = $null }
$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=10','-o','BatchMode=yes')

function RunSsh($tag, $args_, $inFile) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $sp = @{ FilePath = $sshExe; ArgumentList = $args_; NoNewWindow = $true; PassThru = $true;
           RedirectStandardOutput = $o; RedirectStandardError = $e }
  if ($inFile) { $sp['RedirectStandardInput'] = $inFile }
  $pi = Start-Process @sp
  $timedOut = $true
  if ($pi.WaitForExit($TimeoutSec * 1000)) { $timedOut = $false } else { try { $pi.Kill() } catch {} }
  # 不加 -Encoding: PE 里 cmd 的输出是 936, 按本机代码页读中文才不会乱
  $txt = ''
  foreach ($f in @($o, $e)) { if (Test-Path $f) { $txt += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`r`n") } }
  return [pscustomobject]@{ Out = ($txt -replace "`r`n", ' / '); TimedOut = $timedOut; Code = $(if ($timedOut) { 'TIMEOUT' } else { 'done' }) }
}

function Trim2($s, $n) { if ($s.Length -gt $n) { return $s.Substring(0, $n) + ' ...' } return $s }

Say "=== 目标 ${User}@${Ip}:${Port} ==="

# [1] TCP 能不能通
$tcp = New-Object Net.Sockets.TcpClient
$iar = $tcp.BeginConnect($Ip, $Port, $null, $null)
$ok = $iar.AsyncWaitHandle.WaitOne(5000)
Say "[1] tcp: $(if ($ok -and $tcp.Connected) { 'OPEN' } else { 'FAIL(端口不通/防火墙/没起 pe-sshd)' })"
$tcp.Close()

# [2] 非交互: 服务端直接 cmd /c 执行, 这条路在第八轮回归里是验证过的
$a = @('-n', '-p', "$Port") + $common
if ($key) { $a = @('-i', $key) + $a }
$r = RunSsh 'exec' ($a + @("${User}@${Ip}", 'echo EXEC_OK & ver & whoami & cd')) $null
Say "[2] exec  : $(if ($r.TimedOut) { 'TIMEOUT(命令跑完不返回, 多半是 Wait 卡住)' } else { 'ok' }) 输出: $(Trim2 $r.Out 240)"

# [3] 交互: 强制分配 pty(-tt), 就是你实机敲 ssh IP 的那种模式
$inFile = Join-Path $tmp 'shell_in'
[IO.File]::WriteAllText($inFile, "echo INT_OK`r`nver`r`ncd`r`nipconfig | findstr IPv4`r`nexit`r`n")
$a2 = @('-p', "$Port", '-tt') + $common
if ($key) { $a2 = @('-i', $key) + $a2 }
$r2 = RunSsh 'pty' ($a2 + @("${User}@${Ip}")) $inFile
Say "[3] pty   : $(if ($r2.TimedOut) { 'TIMEOUT(没有提示符/不回显 => PE 里 cmd 拿不到控制台)' } else { 'ok' }) 输出: $(Trim2 $r2.Out 300)"
$hasPrompt = $r2.Out -match '[A-Z]:\\>'
Say "      有提示符: $hasPrompt / 有 INT_OK: $($r2.Out -match 'INT_OK')"

# [4] 把 PE 侧日志捞回来(每个最多 25 行, 别把整屏 tasklist 灌进报告)
foreach ($q in @(@('sshd',   'type X:\sshd.log'),
                 @('boot',   'type X:\boot.log'),
                 @('status', 'type X:\status.txt'),
                 @('procs', 'tasklist /nh /fo csv | findstr /i cmd'))) {
  $a3 = @('-n', '-p', "$Port") + $common
  if ($key) { $a3 = @('-i', $key) + $a3 }
  $rq = RunSsh $q[0] ($a3 + @("${User}@${Ip}", $q[1])) $null
  Say "[4] $($q[1]) => $(if ($rq.TimedOut) { 'TIMEOUT' } else { 'ok' })"
  $parts = $rq.Out -split ' / ' | Where-Object { $_.Trim() } | Select-Object -First 25
  foreach ($line in $parts) { Say ('      ' + (Trim2 $line.Trim() 140)) }
}

Say "=== 结论 ==="
$verdict = if ($r.TimedOut -and $r2.TimedOut) { '两条都超时: 通道建起来了但服务端没把 cmd 的输出口喂回来' }
elseif ($r2.TimedOut -or -not $hasPrompt) { '非交互能跑、交互没提示符: PE 里的 cmd.exe 拿不到控制台(要 ConPTY 才能真正交互)' }
elseif ($r.Out -notmatch 'EXEC_OK') { 'exec 没有输出: pe-sshd 可能没在跑, 或者 22 上是别的东西' }
else { '两条都正常: 现场可能是客户端侧显示问题, 换 putty/终端再试一次' }
Say $verdict
[IO.File]::WriteAllText((Join-Path $tmp '..\ssh_diag.txt'), ($report -join "`r`n"), (New-Object Text.UTF8Encoding($true)))
Write-Host "已写 build\ssh_diag.txt"
