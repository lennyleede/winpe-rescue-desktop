# 复现"用户在主机控制台直接敲 ssh"的那条路径: 不关校验、不改真实 known_hosts(用副本)
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_user_path.ps1 [-Ip 192.168.100.2]
# 结论写 build\ssh_user_path.txt
param(
  [string]$Ip = '192.168.100.2',
  [int]$Port = 22,
  [int]$WaitSec = 20
)
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $proj 'build\ssh_user_path'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$report = New-Object System.Collections.Generic.List[string]
function Say($s) { Write-Host $s; $report.Add($s) | Out-Null }
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$scanExe = 'C:\Windows\System32\OpenSSH\ssh-keyscan.exe'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
if (-not $user) { $user = $env:USERNAME }
# ssh 会从 stdin 读; 给它一个空文件, 相当于用户敲完命令立刻 Ctrl-D, 避免挂在读输入上
$nullIn = Join-Path $tmp 'stdin_empty.txt'
[IO.File]::WriteAllText($nullIn, '')

# 1) 真实 known_hosts 里这个 IP 记的是哪把钥匙 -> 拷到临时目录, 只读不改原件
$realKh = Join-Path $env:USERPROFILE '.ssh\known_hosts'
$kh = Join-Path $tmp 'known_hosts.copy'
$saved = '(无 known_hosts 文件)'
if (Test-Path $realKh) {
  Copy-Item $realKh $kh -Force
  $lines = @(Get-Content $kh | Where-Object { $_ -match ('^' + [regex]::Escape($Ip) + '[ ,]') })
  $saved = '条数=' + $lines.Count
  if ($lines.Count -gt 0) { $saved += ' 指纹尾=' + (($lines[0] -split ' ')[-1]).Substring(0, 24) }
}
Say ('[1] 主机 known_hosts 里 ' + $Ip + ' 的记录: ' + $saved)

# 2) PE 现在实际出示的主机密钥
$now = '(keyscan 失败)'
$nowFp = ''
if (Test-Path $scanExe) {
  $sk = Join-Path $tmp 'keyscan.txt'
  & $scanExe -p $Port -t ed25519 $Ip 2>$null | Out-File -FilePath $sk -Encoding ascii
  $k = @(Get-Content $sk -ErrorAction SilentlyContinue | Where-Object { $_ -and ($_ -notmatch '^#') })
  if ($k.Count -gt 0) { $nowFp = ($k[0] -split ' ')[-1]; $now = '条数=' + $k.Count + ' 指纹尾=' + $nowFp.Substring(0, 24) }
}
Say ('[2] PE 当前出示的密钥: ' + $now)

# 3) 跑用户会敲的三种命令(默认 StrictHostKeyChecking, 用副本文件, BatchMode 避免卡在密码提示)
function RunSsh($tag, $args_) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $pi = Start-Process -FilePath $sshExe -ArgumentList $args_ -NoNewWindow -PassThru `
        -RedirectStandardOutput $o -RedirectStandardError $e -RedirectStandardInput $nullIn
  $done = $pi.WaitForExit($WaitSec * 1000)
  if (-not $done) { try { $pi.Kill() } catch {} }
  $code = 'TIMEOUT'
  if ($done) { try { $code = $pi.ExitCode } catch { $code = '?' } }
  $txt = ''
  foreach ($f in @($o, $e)) { if (Test-Path $f) { $txt += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`r`n") } }
  $txt = ($txt -replace "`r`n", ' | ') -replace '\s+\| ', '| '
  if ($txt.Length -gt 320) { $txt = $txt.Substring(0, 320) + ' ...' }
  Say ('    ' + $tag + ' => rc=' + $code + '; ' + $txt)
  return $txt
}
Say '[3] 用默认校验(=你控制台的真实行为)依次试:'
$base = @('-p', "$Port", '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', ('UserKnownHostsFile=' + $kh))
$t1 = RunSsh ('A. ssh ' + $Ip + '  (不带用户名)') ($base + @($Ip, 'echo A_OK'))
$t2 = RunSsh ('B. ssh Administrator@' + $Ip) ($base + @('Administrator@' + $Ip, 'echo B_OK'))
$t3 = RunSsh ('C. ssh ' + $user + '@' + $Ip + '  (本机用户名)') ($base + @("$user@$Ip", 'echo C_OK'))

# 4) 判定
Say '[4] 判定'
if ($t1 -match 'REMOTE HOST IDENTIFICATION HAS CHANGED') {
  Say '  ==> 命中: PE 每次开机都重新生成主机密钥(X:\ 是内存盘), 客户端判定为中间人攻击直接拒连。'
  Say '      这正是"之前能连、现在连不上"的原因, 与防火墙无关。'
  Say '      临时解法(用户侧一条命令): ssh-keygen -R 192.168.100.2'
  Say '      根治: pe-sshd 的首次启动生成后把密钥固化进镜像/或 startnet 预置一把固定密钥; 见 sshserver\main.go'
}
if ($t2 -match 'Permission denied') { Say '  ==> 不带 Administrator@ 会用本机用户名登录, 认证被拒。' }
if ($t2 -match 'B_OK') { Say '  ==> 带对用户名且钥匙匹配时, 连接与命令响应都正常。' }
if (($t1 + $t2 + $t3) -notmatch 'IDENTIFICATION HAS CHANGED') { Say '  ==> 没有看到 host key 变化报错; 需要问用户具体敲的是哪条命令/哪个终端。' }

$text = ($report -join "`r`n") + "`r`n"
try { [IO.File]::WriteAllText((Join-Path $proj 'build\ssh_user_path.txt'), $text, (New-Object Text.UTF8Encoding($true))) } catch { Write-Host '写报告失败' }
Say ('已写 build\ssh_user_path.txt')
