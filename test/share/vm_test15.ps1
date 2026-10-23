# 第十五轮: 在跑着的 PE 里直接落地 pe-sshd + frpc, 证明"能 ssh 进来"这件事
# 在 PE 控制台里粘这一条就够了(结果自动回传本机 :8000/result, 不用抄屏幕):
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr http://172.31.32.1:8000/file/vm_test15.ps1 -OutFile X:\t15.ps1; & X:\t15.ps1"
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$Base = 'http://' + $H + ':8000/file/'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, (($v | Out-String) -replace '\s+$', ''))) }
function DL($name, $dest) {
  try {
    Invoke-WebRequest -UseBasicParsing -Uri ($Base + $name) -OutFile $dest -TimeoutSec 90
    return (Get-Item $dest).Length
  } catch { AL ('DL_fail_' + $name) $_.Exception.Message; return 0 }
}

# ---------- A. 网络底子 ----------
$ips = @(); $gw = @()
try {
  $cfgs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
  foreach ($c in $cfgs) { if ($c.IPAddress) { $ips += @($c.IPAddress) } ; if ($c.DefaultIPGateway) { $gw += @($c.DefaultIPGateway) } }
} catch {
  $txt = & ipconfig.exe 2>&1 | Out-String
  $ips = @([regex]::Matches($txt, 'IPv4 .{0,15}?(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value })
  $gw  = @([regex]::Matches($txt, '网关.{0,20}?(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value })
}
AL 'A_ipv4' (@($ips | Where-Object { $_ -notlike '127.*' -and $_ -notlike '169.254*' }) -join ', ')
AL 'A_gateway' ($gw -join ', ')
$p1 = & ping.exe -n 2 -w 1500 127.0.0.1 2>&1 | Out-String
AL 'A_ping_loopback' $(if ($p1 -match 'TTL=') { 'OK' } else { ($p1 -split "`r`n" | Where-Object { $_.Trim() })[-1] })
$p2 = & ping.exe -n 2 -w 2000 $H 2>&1 | Out-String
AL 'A_ping_host' $(if ($p2 -match 'TTL=') { 'OK' } else { (($p2 -split "`r`n" | Where-Object { $_.Trim() }) | Select-Object -Last 2) -join ' / ' })
if ($gw.Count) {
  $p3 = & ping.exe -n 2 -w 2000 $gw[0] 2>&1 | Out-String
  AL 'A_ping_gw' $(if ($p3 -match 'TTL=') { 'OK' } else { (($p3 -split "`r`n" | Where-Object { $_.Trim() }) | Select-Object -Last 2) -join ' / ' })
}
# 主机在 Default Switch 上不响应 ICMP, 用 TCP 能不能连上 :8000 才算连通
$hostReach = $false
try {
  $c15 = New-Object Net.Sockets.TcpClient
  $c15.Connect($H, 8000); $hostReach = $c15.Connected; $c15.Close()
} catch { }
AL 'A_host_8000_tcp' $(if ($hostReach) { '可连通(TCP)' } else { '连不上' })
$w = & netstat.exe -an 2>&1 | Out-String
AL 'A_tcp_stack' $(if ($w -match 'LISTENING') { 'TCP/IP 栈正常(有 LISTENING 条目)' } else { 'netstat 无输出?' })

# ---------- B. 落地 pe-sshd ----------
New-Item -ItemType Directory -Force -Path 'X:\SSH' | Out-Null
$szExe = DL 'pe-sshd.exe' 'X:\SSH\pe-sshd.exe'
$szAk  = DL 'authorized_keys' 'X:\SSH\authorized_keys'
$szKey = DL 'ssh_login_key' 'X:\tk'
$szCfg = DL 'frpc_test.toml' 'X:\Desktop\Frp\frpc_test.toml'
AL 'B_sizes' ('exe=' + $szExe + ' ak=' + $szAk + ' tk=' + $szKey + ' frpc_toml=' + $szCfg)
AL 'B_ak_head' ((Get-Content 'X:\SSH\authorized_keys' -Raw).Trim().Substring(0, 20))

foreach ($pp in @(Get-Process -Name 'pe-sshd' -ErrorAction SilentlyContinue)) { try { $pp.Kill(); $pp.WaitForExit(3000) | Out-Null } catch {} }
Start-Process -FilePath 'X:\SSH\pe-sshd.exe' -ArgumentList '-addr','0.0.0.0:22','-hostkey','X:\SSH\pe_host_ed25519','-authkeys','X:\SSH\authorized_keys','-shell','X:\Windows\System32\cmd.exe','-log','X:\sshd.log' -WindowStyle Hidden
Start-Sleep 4
AL 'B_proc' (@(Get-Process -Name 'pe-sshd' -ErrorAction SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL 'B_listen22' ((& netstat.exe -an | Select-String 'LISTENING' | Select-String ':22\s' | Out-String).Trim())
AL 'B_hostkey' $(if (Test-Path 'X:\SSH\pe_host_ed25519') { '已生成 ' + (Get-Item 'X:\SSH\pe_host_ed25519').Length + ' 字节' } else { '未生成' })
AL 'B_log_tail' (((Get-Content 'X:\sshd.log' -Encoding UTF8 -ErrorAction SilentlyContinue) | Select-Object -Last 6) -join ' || ')

# ---------- C. 回环登录(公钥 + 空密码两条路, 各自 30s 封顶, 不许把整轮卡死) ----------
function RunSsh($tag, $a, $waitSec) {
  $o = 'X:\' + $tag + '.out'; $e = 'X:\' + $tag + '.err'
  $pi = Start-Process -FilePath 'X:\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; return 'TIMEOUT ' + $waitSec + 's 已强杀' }
  return ((Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue))
}
$sshCommon = @('-o','StrictHostKeyChecking=no','-oUserKnownHostsFile=X:\kh15','-o','ConnectTimeout=10','-o','BatchMode=yes')
$k15 = RunSsh 'c_key' ((@('-n','-i','X:\tk') + $sshCommon + @('Administrator@127.0.0.1','echo PE_SSH_KEY_OK && whoami && cd'))) 30
AL 'C_ssh_key' ($k15.Trim())
AL 'C_key_has_OK' $(if ($k15 -match 'PE_SSH_KEY_OK') { 'YES' } else { 'NO' })
$a15 = RunSsh 'c_anon' ((@('-n','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $sshCommon + @('rescue@127.0.0.1','echo PE_SSH_ANON_OK && whoami'))) 30
AL 'C_ssh_anon' ($a15.Trim())
AL 'C_anon_has_OK' $(if ($a15 -match 'PE_SSH_ANON_OK') { 'YES' } else { 'NO' })
AL 'C_srv_log' (((Get-Content 'X:\sshd.log' -Encoding UTF8 -ErrorAction SilentlyContinue) | Select-Object -Last 10) -join ' || ')

# ---------- D. frpc 出站穿透 ----------
foreach ($pp in @(Get-Process -Name 'frpc' -ErrorAction SilentlyContinue)) { try { $pp.Kill(); $pp.WaitForExit(3000) | Out-Null } catch {} }
Start-Process -FilePath 'X:\Desktop\Frp\frpc.exe' -ArgumentList '-c','X:\Desktop\Frp\frpc_test.toml' -WindowStyle Hidden -WorkingDirectory 'X:\Desktop\Frp'
Start-Sleep 8
AL 'D_frpc_proc' (@(Get-Process -Name 'frpc' -ErrorAction SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL 'D_frpc_log' (((Get-Content 'X:\frpc.log' -Encoding UTF8 -ErrorAction SilentlyContinue) | Select-Object -Last 8) -join ' || ')

# ---------- E. 向日葵 ----------
$sun = @(Get-Process -Name 'SunloginSOS' -ErrorAction SilentlyContinue)
AL 'E_sunlogin' $(if ($sun.Count) { '存活 ' + (@($sun | ForEach-Object { $_.Id }) -join ',') } else { '未运行' })

# ---------- F. 判定 ----------
$v1 = if ($k15 -match 'PE_SSH_KEY_OK') { '公钥登录通过' } else { '公钥登录失败' }
$v2 = if ($a15 -match 'PE_SSH_ANON_OK') { '空密码登录通过' } else { '空密码登录失败' }
$v3 = if ($sun.Count) { '向日葵在跑' } else { '向日葵没跑' }
$verdict = $v1 + ' / ' + $v2 + ' / frpc 见 D_frpc_log / ' + $v3
AL 'F_verdict' $verdict
Write-Host $verdict

$text = $out -join "`r`n"
Set-Content -Path X:\t15.txt -Value $text -Encoding UTF8
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ('http://' + $H + ':8000/result') -InFile X:\t15.txt -TimeoutSec 30 | Out-Null
  Write-Host '结果已回传 172.31.32.1:8000/result'
} catch { Write-Host ('回传失败: ' + $_.Exception.Message) }
