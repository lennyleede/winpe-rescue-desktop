# 第十七轮: 重建后的 v6 ISO 回归(四项需求逐条判定, 全部用镜像自带的文件, 不下载服务端)
# PE 控制台粘这一条(结果自动回传 :8000/result):
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr http://172.31.32.1:8000/file/vm_test17.ps1 -OutFile X:\t17.ps1; & X:\t17.ps1"
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, (($v | Out-String) -replace '\s+$', ''))) }
function DL($name, $dest) {
  try { Invoke-WebRequest -UseBasicParsing -Uri ('http://' + $H + ':8000/file/' + $name) -OutFile $dest -TimeoutSec 60; return (Get-Item $dest).Length }
  catch { AL ('DL_fail_' + $name) $_.Exception.Message; return 0 }
}

# ---------- 需求1: 网络与 ping ----------
$ips = @(); $gw = @()
try {
  foreach ($c in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -EA Stop)) {
    if ($c.IPAddress) { $ips += @($c.IPAddress) }
    if ($c.DefaultIPGateway) { $gw += @($c.DefaultIPGateway) }
  }
} catch { }
AL '1_ipv4' (@($ips | Where-Object { $_ -notlike '127.*' -and $_ -notlike '169.254*' }) -join ', ')
AL '1_gateway' ($gw -join ', ')
foreach ($t in @(@('1_ping_loopback','127.0.0.1'), @('1_ping_host',$H))) {
  $r = & ping.exe -n 2 -w 2000 $t[1] 2>&1 | Out-String
  AL $t[0] $(if ($r -match 'TTL=') { 'OK(有 TTL 回包)' } else { '不通: ' + (($r -split "`r`n" | Where-Object { $_.Trim() }) | Select-Object -Last 2) -join ' / ' })
}
if ($gw.Count) {
  $r = & ping.exe -n 2 -w 2000 $gw[0] 2>&1 | Out-String
  AL '1_ping_gw' $(if ($r -match 'TTL=') { 'OK(有 TTL 回包)' } else { '不通' })
}
$reach = $false
try { $c1 = New-Object Net.Sockets.TcpClient; $c1.Connect($H, 8000); $reach = $c1.Connected; $c1.Close() } catch { }
AL '1_host_8000_tcp' $(if ($reach) { '可连通(TCP)' } else { '连不上' })
# 记录 PE 里有没有防火墙组件(真机上"能不能被 ping 到"取决于它是否被启动)
$fwDll = Test-Path 'X:\Windows\System32\mpssvc.dll'
AL '1_firewall' $(if (-not $fwDll) { 'PE 无 mpssvc.dll -> 不存在挡 ping 的东西' } else { 'PE 有 mpssvc.dll, 默认未启动(未启服务则不挡)' })

# ---------- 需求2: 镜像自带 pe-sshd 开机自启 + 两种登录 ----------
AL '2_boot_log' (((Get-Content 'X:\boot.log' -EA SilentlyContinue) | Select-Object -First 20) -join ' || ')
AL '2_in_image' $(if (Test-Path 'X:\SSH\pe-sshd.exe') { 'X:\SSH\pe-sshd.exe ' + (Get-Item 'X:\SSH\pe-sshd.exe').Length + ' 字节' } else { '镜像里没有 pe-sshd!' })
AL '2_proc' (@(Get-Process -Name 'pe-sshd' -EA SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL '2_listen22' ((& netstat.exe -an | Select-String 'LISTENING' | Select-String ':22\s' | Out-String).Trim())
AL '2_srv_log' (((Get-Content 'X:\sshd.log' -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 6) -join ' || ')
$szKey = DL 'ssh_login_key' 'X:\tk'
AL '2_key_bytes' $szKey
function RunSsh($tag, $a, $waitSec) {
  $o = 'X:\' + $tag + '.out'; $e = 'X:\' + $tag + '.err'
  $pi = Start-Process -FilePath 'X:\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; return 'TIMEOUT ' + $waitSec + 's 已强杀' }
  return ((Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue))
}
$common = @('-o','StrictHostKeyChecking=no','-oUserKnownHostsFile=X:\kh17','-o','ConnectTimeout=10','-o','BatchMode=yes')
$k17 = RunSsh 'k17' (@('-n','-i','X:\tk') + $common + @('Administrator@127.0.0.1','echo T17_KEY_OK && cd && ver')) 30
AL '2_ssh_key' (($k17 -replace '\s+',' ').Trim())
$a17 = RunSsh 'a17' (@('-n','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo T17_ANON_OK && cd')) 30
AL '2_ssh_anon' (($a17 -replace '\s+',' ').Trim())

# ---------- 需求3: 向日葵 ----------
$sun = @(Get-Process -Name 'SunloginSOS' -EA SilentlyContinue)
AL '3_sunlogin' $(if ($sun.Count) { '开机自启存活 pid=' + (@($sun | ForEach-Object { $_.Id }) -join ',') } else { '未运行(缺 DLL 或已退出)' })
$dlls = (@('comctl32.dll','msdmo.dll','pdh.dll') | ForEach-Object {
  $q = 'X:\Windows\System32\' + $_; if (Test-Path $q) { $_ + '=' + [int]((Get-Item $q).Length/1KB) + 'KB' } else { $_ + '=缺' }
}) -join ' '
AL '3_dlls' $dlls

# ---------- 需求4: frp(镜像里的 frpc + 本机 frps 隧道) ----------
$szCfg = DL 'frpc_test16.toml' 'X:\Desktop\Frp\frpc_test17.toml'
AL '4_toml_bytes' $szCfg
foreach ($q in @(Get-Process -Name 'frpc' -EA SilentlyContinue)) { try { $q.Kill(); $q.WaitForExit(3000) | Out-Null } catch {} }
Remove-Item 'X:\frpc.log' -Force -EA SilentlyContinue
Start-Process -FilePath 'X:\Desktop\Frp\frpc.exe' -ArgumentList '-c','X:\Desktop\Frp\frpc_test17.toml' -WindowStyle Hidden -WorkingDirectory 'X:\Desktop\Frp'
Start-Sleep 8
AL '4_frpc_proc' (@(Get-Process -Name 'frpc' -EA SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')
AL '4_frpc_log' (((Get-Content 'X:\frpc.log' -Encoding UTF8 -EA SilentlyContinue) | Select-Object -Last 6) -join ' || ')

# ---------- 桌面 ----------
AL '5_desktop' (@(Get-Process -Name 'mshta' -EA SilentlyContinue | ForEach-Object { 'pid=' + $_.Id }) -join ',')

# ---------- 判定 ----------
$pk = if ($k17 -match 'T17_KEY_OK') { 'SSH公钥登录OK' } else { 'SSH公钥登录失败' }
$pa = if ($a17 -match 'T17_ANON_OK') { 'SSH空密码登录OK' } else { 'SSH空密码登录失败' }
$pn = if ($ips.Count) { '网络OK' } else { '网络失败' }
$s3 = if ($sun.Count) { '向日葵OK' } else { '向日葵失败' }
$f4 = if (@(Get-Process -Name 'frpc' -EA SilentlyContinue).Count) { 'frpc在跑(主机再验 ssh -p 6000)' } else { 'frpc失败' }
AL 'F_verdict' ($pn + ' / ' + $pk + ' / ' + $pa + ' / ' + $s3 + ' / ' + $f4)
$text = $out -join "`r`n"
Set-Content -Path X:\t17.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ('http://' + $H + ':8000/result') -InFile X:\t17.txt -TimeoutSec 30 | Out-Null
  Write-Host '结果已回传 172.31.32.1:8000/result'
} catch { Write-Host ('回传失败: ' + $_.Exception.Message) }
