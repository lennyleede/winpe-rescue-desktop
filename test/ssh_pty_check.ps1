# pe-sshd 行规范改动的验收: 先在宿主机起一个新编的 pe-sshd, 再用三种行尾 + 退格四种输入打进去
#   背景: 客户端申请 pty 后本地回显被关、回车发裸 \r; 老服务端不转换 => cmd 等不到行尾 => "敲什么都没反应"
#   用法(默认就是本机自测, 不碰 VM):
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_pty_check.ps1
#   要打真 PE 就:  -Local:$false -Ip 192.168.100.2
param(
  [bool]$Local = $true,
  [string]$Ip = '127.0.0.1',
  [int]$Port = 2223,
  [string]$User = 'Administrator',
  [int]$WaitSec = 20
)
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $proj 'build\ssh_pty_check'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -ErrorAction SilentlyContinue
$exe = Join-Path $proj 'overlay\SSH\pe-sshd.exe'
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$svc = $null

if ($Local) {
  foreach ($p in @(Get-Process -Name 'pe-sshd' -ErrorAction SilentlyContinue)) { try { $p.Kill(); $p.WaitForExit(2000) | Out-Null } catch {} }
  $svc = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
    '-addr', ('127.0.0.1:' + $Port), '-hostkey', (Join-Path $proj 'overlay\SSH\pe_host_ed25519'),
    '-authkeys', (Join-Path $proj 'overlay\SSH\authorized_keys'),
    '-shell', 'C:\Windows\System32\cmd.exe', '-log', (Join-Path $tmp 'sshd.log'))
  Start-Sleep 2
  Write-Host ('[0] 本机 pe-sshd pid=' + $svc.Id + ' 存活=' + (-not $svc.HasExited))
} else {
  Write-Host ('[0] 目标 ' + $Ip + ':' + $Port + ' (不打本机服务)')
}

$key = Join-Path $tmp 'login_key'
$src = Join-Path $proj 'overlay\Scripts\ssh_login_key'
if (Test-Path $src) {
  Copy-Item $src $key -Force
  & icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
}
$kh = Join-Path $tmp 'kh'
$common = @('-i', $key, '-p', "$Port", '-tt', '-o', 'StrictHostKeyChecking=no', ("-oUserKnownHostsFile=" + $kh),
            '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes')

function Feed($tag, $bytes, $must, $mustNot) {
  $in = Join-Path $tmp ($tag + '.in')
  [IO.File]::WriteAllBytes($in, [Text.Encoding]::ASCII.GetBytes($bytes))
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $pi = Start-Process -FilePath $sshExe -ArgumentList ($common + @("$User@$Ip")) -NoNewWindow -PassThru `
        -RedirectStandardInput $in -RedirectStandardOutput $o -RedirectStandardError $e
  $done = $pi.WaitForExit($WaitSec * 1000)
  if (-not $done) { try { $pi.Kill() } catch {} }
  $txt = ''
  foreach ($f in @($o, $e)) { if (Test-Path $f) { $txt += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`n") } }
  $hit = ($txt -match $must)
  $notHit = $true
  if ($mustNot) { $notHit = -not ($txt -match $mustNot) }
  $one = ($txt -replace '[\r\n]+', ' | ')
  if ($one.Length -gt 200) { $one = $one.Substring(0, 200) + ' ...' }
  Write-Host ('  ' + $tag + ' => ' + $(if (-not $done) { 'TIMEOUT' } else { '已返回' }) + ' 命中[' + $must + ']=' + $hit + ' 不含[' + $mustNot + ']=' + $notHit)
  Write-Host ('      ' + $one)
  return ($done -and $hit -and $notHit)
}

Write-Host '=== 四种输入(全部走 pty -tt) ==='
$r = @{}
$r['crlf'] = Feed 'A_CRLF' "echo MARK_A`r`nexit`r`n" 'MARK_A' 'ZZZ'
$r['cr']   = Feed 'B_CR'   "echo MARK_B`rexit`r" 'MARK_B' 'ZZZ'
$r['lf']   = Feed 'C_LF'   "echo MARK_C`nexit`n" 'MARK_C' 'ZZZ'
# 退格: 先打两个错字 Z Z 再退两格, 然后打 MARK_D。判据用"cmd 收到的那行"来验:
#   服务端回显里是 "echo ZZ\b \b\b \bMARK_D"(含空格, 连不成串), 只有 cmd 真收到干净行才会打出 "echo MARK_D"
$r['bs']   = Feed 'D_BS'   ("echo ZZ" + [char]0x08 + [char]0x08 + "MARK_D`rexit`r") 'echo MARK_D' ''

Write-Host '=== 判定 ==='
foreach ($k in @('crlf', 'cr', 'lf', 'bs')) { Write-Host ('  ' + $k + ' = ' + $(if ($r[$k]) { 'PASS' } else { 'FAIL' })) }
if ($Local) {
  $logf = Join-Path $tmp 'sshd.log'
  if (Test-Path $logf) {
    $fs = [IO.File]::Open($logf, 'Open', 'Read', 'ReadWrite')
    $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
    $log = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
    Write-Host '--- 服务端日志(截 400 字) ---'
    Write-Host (($log -replace '[\r\n]+', ' | ').Substring(0, [Math]::Min(400, $log.Length)))
  }
  try { $svc.Kill(); $svc.WaitForExit(2000) | Out-Null } catch {}
  Write-Host '  (本机服务已关)'
}
