# 修复"ssh 到 PE 报 REMOTE HOST IDENTIFICATION HAS CHANGED 直接拒连"
#   根因: pe-sshd 的主机密钥存放在 X:(内存盘), 每次开机重新生成, 客户端记录的旧指纹必然对不上
#   本脚本: 先备份 known_hosts, 再把这个 IP 的旧记录换成 PE 当前实际出示的密钥, 最后用默认校验真连一次
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\trust_pe_host.ps1 [-Ip 192.168.100.2] [-User Administrator]
param(
  [string]$Ip = '192.168.100.2',
  [string]$User = 'Administrator',
  [int]$Port = 22,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $proj 'build\trust_pe_host'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
function Say($s) { Write-Host $s }
$keygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$scan = 'C:\Windows\System32\OpenSSH\ssh-keyscan.exe'
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$kh = Join-Path $env:USERPROFILE '.ssh\known_hosts'

Say ('=== 目标 ' + $Ip + ':' + $Port + ' ===')
# [1] 端口在不在
$tcp = New-Object Net.Sockets.TcpClient
$iar = $tcp.BeginConnect($Ip, $Port, $null, $null)
$ok = $iar.AsyncWaitHandle.WaitOne(4000)
Say ('[1] tcp22: ' + $(if ($ok -and $tcp.Connected) { 'OPEN' } else { 'CLOSED(PE 没起来/IP 不对/没插网线级的链路问题)' }))
$tcp.Close()
if (-not $ok) { Say '    端口不通, 后面的写入就不做了。先在 VM 里确认 IP, 或用 test\vm_net_audit.ps1 看链路。'; exit 1 }

# [2] 抓当前密钥
$scanTxt = Join-Path $tmp 'scan.txt'
& $scan -p $Port -t rsa,ed25519 $Ip 2>$null | Out-File -FilePath $scanTxt -Encoding ascii
$newLines = @(Get-Content $scanTxt | Where-Object { $_ -and ($_ -notmatch '^#') })
Say ('[2] PE 当前出示的密钥条数: ' + $newLines.Count)
if ($newLines.Count -eq 0) { Say '    keyscan 抓不到密钥, 不改动 known_hosts。'; exit 1 }
foreach ($l in $newLines) {
  $f = Join-Path $tmp ('one_' + ([Math]::Abs($l.GetHashCode())) + '.pub')
  [IO.File]::WriteAllText($f, (($l -replace ('^' + [regex]::Escape($Ip) + ' '), '') + "`r`n"), [Text.Encoding]::ASCII)
  Say ('    ' + ((& $keygen -l -f $f) -join ' '))
}

# [3] 备份 + 替换该 IP 的记录
if ($SelfTest) { Say '[3] SelfTest: 不写 known_hosts'; }
else {
  $bak = Join-Path $tmp ('known_hosts.bak_' + (Get-Date -Format 'MMdd-HHmmss'))
  if (Test-Path $kh) { Copy-Item $kh $bak -Force } else { [IO.File]::WriteAllText($kh, '') }
  Say ('[3] 已备份原 known_hosts -> ' + $bak)
  $keep = @(Get-Content $kh | Where-Object { $_ -and ($_ -notmatch ('^' + [regex]::Escape($Ip) + '[ ,]')) })
  $all = @($keep) + $newLines
  [IO.File]::WriteAllText($kh, (($all -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
  Say ('    写入完成: 保留 ' + $keep.Count + ' 行其他记录, 新增 ' + $newLines.Count + ' 行 ' + $Ip)
}

# [4] 用默认校验(=你控制台的敲法)真连一次
$probe = 'echo TRUST_OK & cd'
$a = @('-n', '-p', "$Port", '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', "$User@$Ip", $probe)
$o = Join-Path $tmp 'conn.out'; $e = Join-Path $tmp 'conn.err'
foreach ($f in @($o, $e)) { if (Test-Path $f) { Remove-Item $f -Force } }
$empty = Join-Path $tmp 'empty.txt'
[IO.File]::WriteAllText($empty, '')
$pi = Start-Process -FilePath $sshExe -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e -RedirectStandardInput $empty
$done = $pi.WaitForExit(25000)
$out = ''
foreach ($f in @($o, $e)) { if (Test-Path $f) { $out += ((Get-Content $f -Raw -ErrorAction SilentlyContinue) + "`r`n") } }
$code = '?'
if ($done) { try { $code = $pi.ExitCode } catch { $code = '?' } }
$out = ($out -replace "`r`n", ' | ')
if ($out.Length -gt 300) { $out = $out.Substring(0, 300) + ' ...' }
Say ('[4] 默认校验直连: ' + $(if (-not $done) { 'TIMEOUT' } else { 'rc=' + $code }) + ' ' + $out)
if ($SelfTest) { Say '[5] SelfTest 结束(没写文件, 连接探测是只读的)'; exit 0 }
if ($out -match 'TRUST_OK') {
  Say '[5] 判定: 通了。此后你在控制台敲 ssh Administrator@192.168.100.2 不再被 host key 拦。'
  Say '    注意: 只要还是旧 ISO(密钥每次开机变), 重启 PE 后需要再跑一次本脚本;'
  Say '          新 ISO(镜像里已预置 overlay\SSH\pe_host_ed25519)则永久稳定, 换 ISO 那天再跑一次即可。'
} else {
  Say '[5] 判定: 还是连不上。看上面 rc/输出:'
  Say '    - Permission denied => 用户名不对, 用 ssh Administrator@IP'
  Say '    - Connection timed out/refused => 不是密钥问题, 是链路/服务, 跑 test\vm_net_audit.ps1'
}
