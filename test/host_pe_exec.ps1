# 主机侧: 通过直连 LAN 的 SSH 在 PE 里执行命令(不需要 frp 隧道, 也不需要用户粘贴)
#   两种用法:
#     -Payload vm_xxx.ps1        把 test\share\vm_xxx.ps1 下发到 X:\p.ps1 并执行(可带 -PayloadArgs)
#     -Cmd 'Get-Date'            直接跑一段 PowerShell 文本
#   前提: PE 防火墙已关(或被放行), 且 -Payload 模式下 host_serve.ps1 在 :8000 起着
#   输出: 回显 + 追加写 test\host_pe_exec_result.txt; 若 payload 自己 POST 了结果, 另存 test\vm_result_*.txt
param(
  [string]$Ip = '192.168.100.2',
  [string]$User = 'Administrator',
  [string]$Payload = '',
  [string]$Cmd = '',
  [string]$PayloadArgs = '',
  [string]$ServeHost = '192.168.100.1',
  [int]$ServePort = 8000,
  [int]$TimeoutSec = 300,
  [switch]$ShowCmd
)
$ErrorActionPreference = 'Stop'
$tmp = Join-Path $env:TEMP ('peexec_' + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$logFile = Join-Path $root 'host_pe_exec_result.txt'

if (-not $Payload -and -not $Cmd) { throw '需要 -Payload <test\share 下的脚本名> 或 -Cmd <PowerShell 文本>' }
if ($Payload -and -not (Test-Path (Join-Path $root ('share\' + $Payload)))) {
  throw ('test\share\' + $Payload + ' 不存在, 先 Copy-Item 过去(host_serve 的 /file/ 只认 share 目录)')
}

$lines = @()
$lines += '$ErrorActionPreference = ''Continue'''
if ($Payload) {
  $lines += ('(New-Object Net.WebClient).DownloadFile(''' + 'http://' + $ServeHost + ':' + $ServePort + '/file/' + $Payload + ''', ''X:\p.ps1'')')
  $lines += ('& X:\p.ps1 ' + $PayloadArgs)
}
if ($Cmd) { $lines += $Cmd }
$psText = ($lines -join "`r`n")
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($psText))

if ($ShowCmd) {
  Write-Host '--- PE 里将执行(明文) ---'
  Write-Host $psText
  Write-Host ('--- EncodedCommand 长度=' + $b64.Length + ' ---')
  exit 0
}

$key = $null
$src = Join-Path $proj 'overlay\Scripts\ssh_login_key'
if (Test-Path $src) {
  $key = Join-Path $tmp 'login_key'
  Copy-Item $src $key -Force
  & icacls.exe $key /inheritance:r '/grant:r' ($env:USERNAME + ':F') | Out-Null
}
$kh = Join-Path $tmp 'kh'
$remote = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64
$args_ = @('-n', '-o', 'StrictHostKeyChecking=no', ('-oUserKnownHostsFile=' + $kh), '-o', 'ConnectTimeout=8', '-o', 'BatchMode=yes')
if ($key) { $args_ = @('-i', $key) + $args_ }
$args_ += @(($User + '@' + $Ip), $remote)

$o = Join-Path $tmp 'out.txt'
$e = Join-Path $tmp 'err.txt'
$pi = Start-Process -FilePath 'C:\Windows\System32\OpenSSH\ssh.exe' -ArgumentList $args_ -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
$timedOut = $true
if ($pi.WaitForExit($TimeoutSec * 1000)) { $timedOut = $false } else { try { $pi.Kill() } catch { } }
$txt = ''
foreach ($f in @($o, $e)) { if (Test-Path $f) { $txt += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`r`n") } }
$head = ('===== host_pe_exec ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' 目标=' + $User + '@' + $Ip + ' payload=' + $Payload + ' args=' + $PayloadArgs + ' =====')
$body = $head + "`r`n" + ('exit=' + $(if ($timedOut) { 'TIMEOUT(已杀)' } else { [string]$pi.ExitCode }) + "`r`n") + $txt
Write-Host $body
try { Add-Content -Path $logFile -Value ($body + "`r`n") -Encoding UTF8 } catch { Write-Host ('写日志失败: ' + $_.Exception.Message) }
if ($timedOut) { exit 2 }
