# 第十六轮: 先把占着 22 端口的旧 sshd 和锁住 exe 的旧 pe-sshd 清干净, 再落地新版 pe-sshd 测
# PE 控制台粘这一条(结果自动回传 :8000/result):
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr http://172.31.32.1:8000/file/vm_test16.ps1 -OutFile X:\t16.ps1; & X:\t16.ps1"
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$Base = 'http://' + $H + ':8000/file/'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, (($v | Out-String) -replace '\s+$', ''))) }

# ---------- 0. 清场: 旧 pe-sshd(会锁住 exe 文件) + ISO 自带的 Win32-OpenSSH sshd(会占 22) ----------
foreach ($n in @('pe-sshd','pe16','sshd')) {
  $ids = @(Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
  foreach ($q in @(Get-Process -Name $n -ErrorAction SilentlyContinue)) { try { $q.Kill(); $q.WaitForExit(3000) | Out-Null } catch {} }
  if ($ids.Count) { AL ('0_killed_' + $n) ($ids -join ',') }
}
Start-Sleep 2
$who22 = @()
foreach ($line in @(& netstat.exe -ano | Select-String ':22\s.*LISTENING')) { $who22 += $line.ToString().Trim() }
AL '0_port22_after_kill' $(if ($who22.Count) { ($who22 -join ' / ') } else { '已空' })

# ---------- A. 网络底子 ----------
$ips = @()
try {
  foreach ($c in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -EA Stop)) { if ($c.IPAddress) { $ips += @($c.IPAddress) } }
} catch { }
AL 'A_ipv4' (@($ips | Where-Object { $_ -notlike '127.*' -and $_ -notlike '169.254*' }) -join ', ')
$hostReach = $false
try { $c1 = New-Object Net.Sockets.TcpClient; $c1.Connect($H, 8000); $hostReach = $c1.Connected; $c1.Close() } catch { }
AL 'A_host_8000_tcp' $(if ($hostReach) { '可连通(TCP)' } else { '连不上' })

# ---------- B. 落地新版 pe-sshd(换个文件名, 免得又被上一轮的锁住) ----------
New-Item -ItemType Directory -Force -Path 'X:\SSH' | Out-Null
Remove-Item 'X:\SSH\pe-sshd.exe','X:\sshd.log' -Force -ErrorAction SilentlyContinue
function DL($name, $dest) {
  try { Invoke-WebRequest -UseBasicParsing -Uri ($Base + $name) -OutFile $dest -TimeoutSec 120; return (Get-Item $dest).Length }
  catch { AL ('DL_fail_' + $name) $_.Exception.Message; return 0 }
}
$szExe = DL 'pe-sshd.exe' 'X:\SSH\pe16.exe'
$szAk  = DL 'authorized_keys' 'X:\SSH\authorized_keys'
$szKey = DL 'ssh_login_key' 'X:\tk'
$szCfg = DL 'frpc_test16.toml' 'X:\Desktop\Frp\frpc_test16.toml'
AL 'B_sizes' ('exe=' + $szExe + ' ak=' + $szAk + ' tk=' + $szKey + ' frpc_toml=' + $szCfg)
# 主机上验证过的新版是 3773952 字节, 差太多说明下发的还是旧文件
AL 'B_exe_ok' $(if ($szExe -gt 3700000) { '大小正常(应为新版)' } else { '大小不对, 可能仍是旧版' })

Start-Process -FilePath 'X:\SSH\pe16.exe' -ArgumentList '-addr','0.0.0.0:22','-hostkey','X:\SSH\pe_host_ed25519','-authkeys','X:\SSH\authorized_keys','-shell','X:\Windows\System32\cmd.exe','-log','X:\sshd.log' -WindowStyle Hidden
Start-Sleep 4
AL 'B_proc' (@(Get-Process -Name 'pe16' -ErrorAction SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL 'B_listen22' ((& netstat.exe -an | Select-String 'LISTENING' | Select-String ':22\s' | Out-String).Trim())
AL 'B_log' (((Get-Content 'X:\sshd.log' -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 8) -join ' || ')

# ---------- C. 回环登录(公钥 + 空密码, 各自 30s 封顶) ----------
function RunSsh($tag, $a, $waitSec) {
  $o = 'X:\' + $tag + '.out'; $e = 'X:\' + $tag + '.err'
  $pi = Start-Process -FilePath 'X:\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; return 'TIMEOUT ' + $waitSec + 's 已强杀' }
  return ((Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue))
}
$common = @('-o','StrictHostKeyChecking=no','-oUserKnownHostsFile=X:\kh16','-o','ConnectTimeout=10','-o','BatchMode=yes')
$k16 = RunSsh 'c_key' (@('-n','-i','X:\tk') + $common + @('Administrator@127.0.0.1','echo PE_SSH_KEY_OK && whoami && cd')) 30
AL 'C_ssh_key' ($k16.Trim())
$a16 = RunSsh 'c_anon' (@('-n','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo PE_SSH_ANON_OK && whoami')) 30
AL 'C_ssh_anon' ($a16.Trim())
AL 'C_srv_log' (((Get-Content 'X:\sshd.log' -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 10) -join ' || ')

# ---------- D. frpc 出站穿透(22 -> frps:6000) ----------
foreach ($q in @(Get-Process -Name 'frpc' -EA SilentlyContinue)) { try { $q.Kill(); $q.WaitForExit(3000) | Out-Null } catch {} }
Remove-Item 'X:\frpc.log' -Force -EA SilentlyContinue
Start-Process -FilePath 'X:\Desktop\Frp\frpc.exe' -ArgumentList '-c','X:\Desktop\Frp\frpc_test16.toml' -WindowStyle Hidden -WorkingDirectory 'X:\Desktop\Frp'
Start-Sleep 8
AL 'D_frpc_proc' (@(Get-Process -Name 'frpc' -EA SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL 'D_frpc_log' (((Get-Content 'X:\frpc.log' -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 8) -join ' || ')

# ---------- E. 向日葵(没跑就现拉一次, 6 秒后看是否存活) ----------
$sun = @(Get-Process -Name 'SunloginSOS' -EA SilentlyContinue)
AL 'E_sunlogin_boot' $(if ($sun.Count) { '开机自启后仍在 ' + (@($sun | ForEach-Object { $_.Id }) -join ',') } else { '开机自启后已退出' })
if (-not $sun.Count) {
  if (Test-Path 'X:\Sunlogin\SunloginSOS.exe') {
    Start-Process -FilePath 'X:\Sunlogin\SunloginSOS.exe' -WorkingDirectory 'X:\Sunlogin'
    Start-Sleep 6
    $sun2 = @(Get-Process -Name 'SunloginSOS' -EA SilentlyContinue)
    AL 'E_sunlogin_retry' $(if ($sun2.Count) { '手动拉起后存活 ' + (@($sun2 | ForEach-Object { $_.Id }) -join ',') } else { '手动拉起仍退出' })
  } else { AL 'E_sunlogin_retry' 'X:\Sunlogin\SunloginSOS.exe 不存在' }
}

# ---------- F. 判定 ----------
$v1 = if ($k16 -match 'PE_SSH_KEY_OK') { '公钥登录通过' } else { '公钥登录失败' }
$v2 = if ($a16 -match 'PE_SSH_ANON_OK') { '空密码登录通过' } else { '空密码登录失败' }
$v3 = if ($hostReach) { '出站TCP通' } else { '出站不通' }
$v4 = if (@(Get-Process -Name 'frpc' -EA SilentlyContinue).Count) { 'frpc在跑' } else { 'frpc没跑' }
$v5 = if (@(Get-Process -Name 'SunloginSOS' -EA SilentlyContinue).Count) { '向日葵在跑' } else { '向日葵没跑' }
AL 'F_verdict' ($v3 + ' / ' + $v1 + ' / ' + $v2 + ' / ' + $v4 + ' / ' + $v5)
$text = $out -join "`r`n"
Set-Content -Path X:\t16.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ('http://' + $H + ':8000/result') -InFile X:\t16.txt -TimeoutSec 30 | Out-Null
  Write-Host '结果已回传 172.31.32.1:8000/result'
} catch { Write-Host ('回传失败: ' + $_.Exception.Message) }
