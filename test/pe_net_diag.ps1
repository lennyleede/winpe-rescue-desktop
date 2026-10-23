# PE 侧网络自检: 结果打印到屏幕并 POST 回主机 test\vm_result_*.txt
# 下发: 主机跑 host_serve.ps1 -Script pe_net_diag.ps1, PE 里 curl /v.ps1 再 powershell -File 执行
param([string]$HostIp = '', [int]$Port = 8000)
$ErrorActionPreference = 'Continue'
if (-not $HostIp) {
  # PE 里没有 Get-NetIPAddress/Get-NetAdapter 的 CIM provider, 只能用 ipconfig 的文本判断自己挂在哪个网段
  $txt = ((& ipconfig 2>&1 | ForEach-Object { $_.ToString() }) -join ' ')
  if ($txt -match '192\.168\.100\.\d+') { $HostIp = '192.168.100.1' } else { $HostIp = '192.168.0.106' }
}
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $L.Add([string]$s) }
function TcpTest($t, $p) {
  if (-not $t) { return 'skipped(no ip)' }
  $c = New-Object Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect($t, $p, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000) -and $c.Connected) { return 'OPEN' }
    return 'SYN-no-answer'
  } catch { return 'ERR ' + $_.Exception.Message } finally { $c.Close() }
}
function Tail($f, $n) {
  if (-not (Test-Path $f)) { return @('(missing ' + $f + ')') }
  @(Get-Content $f -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -Last $n)
}

Add '### 1. 本机 IP / 网卡'
$ipcfg = @(& ipconfig 2>&1 | ForEach-Object { $_.ToString() })
$ipcfg | Where-Object { $_ -match '\S' } | ForEach-Object { Add('  ' + $_.Trim()) }
$ip = ''
foreach ($ln in $ipcfg) { if ($ln -match '(192\.168\.\d+\.\d+)') { $ip = $Matches[1]; break } }
Add ('  => 取到的 IPv4: ' + $ip)

Add '### 1b. 掩码与路由 (ARP 答但 IP 不答时, 先看有没有 /32 或缺到主机的直连路由)'
foreach ($ln in @(& netsh interface ip show config 2>&1 | ForEach-Object { $_.ToString() })) { if ($ln -match '\S') { Add('  ' + $ln.Trim()) } }
$rp = @(& route print 2>&1 | ForEach-Object { $_.ToString() })
if ($rp.Count -eq 0) { Add '  (route.exe 不可用)' } else { foreach ($ln in $rp) { if ($ln -match '0\.0\.0\.0|255\.255|192\.168') { Add('  R ' + (($ln -replace '\s+', ' ').Trim())) } } }

Add '### 2. 谁在监听 (重点看 0.0.0.0:22)'
$ls = @(netstat -ano | Select-String 'LISTENING' | Select-Object -First 25)
if ($ls.Count -eq 0) { Add '  (netstat 没有任何 LISTENING)' } else { $ls | ForEach-Object { Add('  ' + ($_.ToString().Trim() -replace '\s+', ' ')) } }

Add '### 3. 关键进程'
$pr = @(tasklist /nh /fo csv 2>$null | Select-String -Pattern 'pe-sshd|mshta|Sunlogin|cmd' | Select-Object -First 12)
if ($pr.Count -eq 0) { Add '  (没匹配到)' } else { $pr | ForEach-Object { Add('  ' + $_.ToString()) } }

Add '### 4. 端口连通: 回环/本机IP/主机 (区分"服务没起"和"包进不来")'
Add ('  tcp 127.0.0.1:22            -> ' + (TcpTest '127.0.0.1' 22))
Add ('  tcp ' + $ip + ':22            -> ' + (TcpTest $ip 22))
Add ('  tcp ' + $HostIp + ':8000(主机)  -> ' + (TcpTest $HostIp $Port))
if ($ip -notlike '192.168.100.*') { Add ('  tcp 192.168.0.1:80(路由器)     -> ' + (TcpTest '192.168.0.1' 80)) }

Add '### 5. ping'
$pg = @($HostIp)
if ($ip -notlike '192.168.100.*') { $pg += '192.168.0.1' }
foreach ($tgt in $pg) {
  $o = @(& ping -n 2 -w 1000 $tgt 2>&1 | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '\S' })
  Add ('  ping ' + $tgt + ' : ' + (($o | Select-Object -Skip 1) -join ' | '))
}
Add ('  arp: ' + (((& arp -a | Select-String '192\.168') -join ' ; ') -replace '\s+', ' '))

Add '### 6. 防火墙是否在这份 PE 里活着 (WinPE 正常没有)'
foreach ($svc in @('mpssvc', 'bfe')) {
  Add ('  sc query ' + $svc + ' : ' + (((& sc query $svc 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '))
  Add ('  sc qc ' + $svc + '    : ' + (((& sc qc $svc 2>&1 | Select-String 'START_TYPE') -join ' ') -replace '\s+', ' '))
}
Add ('  netsh advfirewall : ' + (((& netsh advfirewall show allprofiles state 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '))

Add '### 7. 日志尾巴'
Add '  -- X:\sshd.log --';   (Tail 'X:\sshd.log' 12)  | ForEach-Object { Add('  ' + $_) }
Add '  -- X:\status.txt --'; (Tail 'X:\status.txt' 10) | ForEach-Object { Add('  ' + $_) }
Add '  -- X:\boot.log --';   (Tail 'X:\boot.log' 12)  | ForEach-Object { Add('  ' + $_) }

Add '### 8. X:\SSH 目录'
if (Test-Path 'X:\SSH') {
  foreach ($f in @(Get-ChildItem 'X:\SSH' -Force)) { Add('  ' + $f.Name + '  ' + $f.Length) }
} else { Add '  (X:\SSH 不存在)' }

Add '### 9. 版本'
Add ('  build=' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuild)

$text = ($L -join "`r`n")
$text | Out-Host
[IO.File]::WriteAllText('X:\pe_net.txt', $text, (New-Object Text.UTF8Encoding($true)))
$body = [Text.Encoding]::UTF8.GetBytes($text)
try {
  (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
  ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功') | Out-Host
} catch {
  ('POST 失败: ' + $_.Exception.Message) | Out-Host
  ('手查: type X:\pe_net.txt') | Out-Host
}
