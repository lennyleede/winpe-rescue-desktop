# 定性"SSH 连上但敲命令没反应": 同一台 PE、同一个 ssh -tt, 只改行结束符
#   控制台里手敲回车 => 客户端发裸 \r (真终端时本地回显被关, 指望远端 pty 处理)
#   脚本喂文件   => 行尾是 \r\n  (所以之前的自测一直是"假通过")
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_cr_test.ps1 [-Ip 192.168.100.2]
param(
  [string]$Ip = '192.168.100.2',
  [string]$User = 'Administrator',
  [int]$Port = 22,
  [int]$WaitSec = 20
)
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $proj 'build\ssh_cr_test'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -ErrorAction SilentlyContinue
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$key = Join-Path $tmp 'login_key'
$src = Join-Path $proj 'overlay\Scripts\ssh_login_key'
if (Test-Path $src) {
  Copy-Item $src $key -Force
  & icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
}
$kh = Join-Path $tmp 'kh'
$common = @('-i', $key, '-p', "$Port", '-tt', '-o', 'StrictHostKeyChecking=no', "-oUserKnownHostsFile=$kh",
            '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes')

function Feed($tag, $bytes, $mark) {
  $in = Join-Path $tmp ($tag + '.in')
  [IO.File]::WriteAllBytes($in, [Text.Encoding]::ASCII.GetBytes($bytes))
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $pi = Start-Process -FilePath $sshExe -ArgumentList ($common + @("$User@$Ip")) -NoNewWindow -PassThru `
        -RedirectStandardInput $in -RedirectStandardOutput $o -RedirectStandardError $e
  $done = $pi.WaitForExit($WaitSec * 1000)
  if (-not $done) { try { $pi.Kill() } catch {} }
  $txt = ''
  foreach ($f in @($o, $e)) { if (Test-Path $f) { $txt += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`n") } }
  $one = ($txt -replace '[\r\n]+', ' | ')
  if ($one.Length -gt 260) { $one = $one.Substring(0, 260) + ' ...' }
  Write-Host ('  ' + $tag + ' => ' + $(if (-not $done) { 'TIMEOUT(会话一直不返回)' } else { 'rc=' + $pi.ExitCode }) + ' 命中 ' + $mark + '=' + ($txt -match $mark))
  Write-Host ('      ' + $one)
  return ($txt -match $mark)
}

Write-Host '=== 目标 PE 交互式会话, 两种行结束符对比 ==='
# A: CRLF 结尾(=之前脚本喂文件的做法)
$a = Feed 'A_CRLF' "echo MARK_A_OK`r`nver`r`nexit`r`n" 'MARK_A_OK'
# B: 裸 CR 结尾(=你在控制台手敲回车时真实发出的字节)
$b = Feed 'B_CR' "echo MARK_B_OK`rver`rexit`r" 'MARK_B_OK'
# C: 只有 \n 结尾(LF, pty 做过 ICRNL 之后就是这个)
$c = Feed 'C_LF' "echo MARK_C_OK`nver`nexit`n" 'MARK_C_OK'

Write-Host '=== 判定 ==='
if ($a -and -not $b) {
  Write-Host '  ==> 确诊: CRLF 能用、裸 CR 不能用。控制台敲的回车是裸 CR, 服务端没做终端仿真(不转 \r->\n、不回显),'
  Write-Host '      所以 cmd 永远等不到行尾, 表现就是"连上了但敲什么都没反应"。修法在 pe-sshd 里补一个行规范(line discipline)。'
} elseif ($a -and $b) {
  Write-Host '  ==> 两种行尾都能跑, 那问题不在这, 得换个方向查(客户端本地回显/控制台的快速编辑冻结)'
} else {
  Write-Host '  ==> CRLF 这条也没通, 先别急着下结论, 看上面 rc/输出判断是不是连接本身的问题'
}
if (-not $c) { Write-Host '  附: LF 结尾也不通 => 服务端确实完全不碰行结束符, cmd 只认 CRLF/LF? 见上两条对比' }
