# 证明 frp 隧道能把 pe-sshd 的端口穿透出来: 宿主机 frpc -> 本机 frps(:7000) -> :6001 -> pe-sshd(:2222)
# 一条命令跑完, 判定写 test\tunnel_result.txt
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$tmp  = Join-Path $proj 'build\tunnel'
foreach ($procName in @('pe-sshd','frpc')) { foreach ($q in @(Get-Process -Name $procName -EA SilentlyContinue)) { $q.Kill() } }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -EA SilentlyContinue

$report = New-Object System.Collections.Generic.List[string]

# 0) frps 没在跑就自己拉一个(监听 7000)
$frpsAlive = [bool](& netstat.exe -an | Select-String ':7000\s.*LISTENING')
if (-not $frpsAlive) {
  $fsToml = Join-Path $tmp 'frps_local.toml'
  @"
bindPort = 7000
auth.token = "CHANGE_ME"
"@ | Set-Content -Path $fsToml -Encoding ASCII
  $fs = Start-Process -FilePath (Join-Path $proj 'overlay\Desktop\Frp\frps.exe') -PassThru -WindowStyle Hidden `
        -ArgumentList @('-c', $fsToml) -RedirectStandardOutput (Join-Path $tmp 'frps.out') -RedirectStandardError (Join-Path $tmp 'frps.err')
  Start-Sleep 3
  Write-Host ('frps 自启 pid=' + $fs.Id)
  $report.Add('frps=本脚本自启')
} else {
  $report.Add('frps=已在运行(复用)')
}

# 1) pe-sshd 监听 127.0.0.1:2222
$exe = Join-Path $proj 'overlay\SSH\pe-sshd.exe'
$sshLog = Join-Path $tmp 'sshd.log'
$srv = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
  '-addr','127.0.0.1:2222','-hostkey',(Join-Path $tmp 'hk'),
  '-authkeys',(Join-Path $proj 'test\share\authorized_keys'),
  '-shell','C:\Windows\System32\cmd.exe','-log',$sshLog)
Start-Sleep 2

# 2) frpc 把 2222 映射到 frps 的 6001
$toml = Join-Path $tmp 'frpc_local.toml'
@"
serverAddr = "127.0.0.1"
serverPort = 7000
auth.token = "CHANGE_ME"

[[proxies]]
name = "pe-ssh-local"
type = "tcp"
localIP = "127.0.0.1"
localPort = 2222
remotePort = 6001
"@ | Set-Content -Path $toml -Encoding ASCII
$frpcOut = Join-Path $tmp 'frpc.out'
$cli = Start-Process -FilePath (Join-Path $proj 'overlay\Desktop\Frp\frpc.exe') -PassThru `
        -ArgumentList @('-c', $toml) -WindowStyle Hidden -RedirectStandardOutput $frpcOut -RedirectStandardError (Join-Path $tmp 'frpc.err')
Start-Sleep 5
$listen = (& netstat.exe -an | Select-String ':6001\s.*LISTENING' | Out-String).Trim()
Write-Host ('frps 侧 6001 监听: ' + $listen)
$report.Add('frpc_alive=' + (-not $cli.HasExited) + ' sshd_alive=' + (-not $srv.HasExited))
$report.Add('listen_6001=' + $listen)
$report.Add('frpc_out=' + (((Get-Content $frpcOut -Raw -EA SilentlyContinue) + ' ' + (Get-Content (Join-Path $tmp 'frpc.err') -Raw -EA SilentlyContinue)) -replace '\s+',' '))

# 3) 走隧道 ssh
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=10','-o','BatchMode=yes')
function RunSsh($tag, $a, $waitSec) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $pi = Start-Process -FilePath $sshExe -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; return 'TIMEOUT ' + $waitSec + 's 已强杀' }
  return ((Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue))
}
Write-Host '--- 经 6001 隧道: 私钥登录 ---'
$k = RunSsh 'tun_key' (@('-n','-p','6001','-i',$key) + $common + @('Administrator@127.0.0.1','echo TUNNEL_KEY_OK && whoami && cd')) 30
Write-Host $k
Write-Host '--- 经 6001 隧道: 空密码/无凭证 ---'
$n = RunSsh 'tun_anon' (@('-n','-p','6001','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo TUNNEL_ANON_OK && whoami')) 30
Write-Host $n

$vk = if ($k -match 'TUNNEL_KEY_OK') { '通过' } else { '失败' }
$vn = if ($n -match 'TUNNEL_ANON_OK') { '通过' } else { '失败' }
$vp = if ($listen) { '已映射' } else { '未映射, 检查 frps' }
$verdict = '隧道公钥登录 ' + $vk + ' / 隧道空密码登录 ' + $vn + ' / 隧道端口 ' + $vp
Write-Host ('判定: ' + $verdict)
$report.Add('tunnel_key_output=' + ($k -replace '\s+',' '))
$report.Add('tunnel_anon_output=' + ($n -replace '\s+',' '))
$report.Add('server_log=' + (((Get-Content $sshLog -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 12) -join ' || '))
$report.Add('verdict=' + $verdict)
foreach ($q in @($cli, $srv)) { try { $q.Kill() } catch {} }
Set-Content -Path (Join-Path $root 'tunnel_result.txt') -Value ($report -join "`r`n") -Encoding UTF8
