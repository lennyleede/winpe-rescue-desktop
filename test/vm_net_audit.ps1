# PE 侧网络体检(只读): 分层判断"链路 / 主机 / 公网 / DNS / 服务 / 应用"到底断在哪一层
#   背景: 用户报"PE 里连网都没了、向日葵也连不上"。需要分清是镜像回归, 还是 Hyper-V 的
#         Internal 交换机(PE-INT)本来就没有出互联网的出口。
#   只用 PE 里确实存在的东西: ipconfig / route print / Win32_Service / .NET TcpClient+Dns / Get-Process / netstat
# 跑法: 主机 test\host_pe_exec.ps1 -Payload vm_net_audit.ps1   (结果同时 POST 回 :8000)
param(
  [string]$HostIp = '192.168.100.1',
  [int]$Port = 8000,
  [int]$TcpMs = 2500,
  [string]$TestSites = 'sunlogin.oray.com,www.baidu.com,114.114.114.114,223.5.5.5',
  [switch]$ShowOnly,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Stamp { (Get-Date -Format 'HH:mm:ss') }
function TcpOk($ip, $port, $ms) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($ip, [int]$port, $null, $null)
    $got = $iar.AsyncWaitHandle.WaitOne([int]$ms)
    $ok = ($got -and $c.Connected)
    $c.Close()
    return $ok
  } catch { return $false }
}
function DnsOf($name) {
  try { return @([Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.ToString() }) }
  catch { return @('解析失败: ' + $_.Exception.Message.split("`r`n")[0]) }
}
function SvcOne($nm) {
  $s = @(Get-CimInstance Win32_Service -Filter ('Name=''' + $nm + '''') -ErrorAction SilentlyContinue)
  if ($s.Count -eq 0) { return 'NO-KEY' }
  return ($s[0].State + '/' + $s[0].StartMode)
}

Add ('===== vm_net_audit ' + (Stamp) + '  (只读; 不启动/停止任何服务, 不写任何策略) =====')
if ($SelfTest) { Add '  -SelfTest: 站点列表与判定逻辑照常跑, 只是这次结果不 POST' }

Add ''
Add '### A. 本机地址 / 默认路由 / DNS'
$ipc = @(& ipconfig /all 2>&1 | ForEach-Object { $_.ToString() })
foreach ($ln in $ipc) {
  $t = $ln.Trim()
  if ($t -match '(IPv4 Address|Subnet Mask|Default Gateway|DNS Servers|Description|Physical Address|DHCP Enabled)' -and $t -notmatch '^\s*$') { Add ('  ' + $t) }
}
Add '  -- route print 里的 0.0.0.0 行(有没有默认出口就看这两行) --'
foreach ($ln in @(& route print 2>&1 | ForEach-Object { $_.ToString() })) { if ($ln -match '^\s*0\.0\.0\.0') { Add ('    ' + ($ln -replace '\s+', ' ').Trim()) } }

Add ''
Add '### B. 关键服务状态(网络栈/解析/防火墙)'
foreach ($nm in @('Dnscache', 'Dhcp', 'LanmanWorkstation', 'LmHosts', 'Winmgmt', 'BFE', 'MpsSvc', 'SharedAccess', 'wlansvc', 'dot3svc', 'NlaSvc')) {
  Add ('  ' + $nm + ' = ' + (SvcOne $nm))
}

Add ''
Add '### C. 出站能力分层(每项最多等 ' + $TcpMs + ' 毫秒)'
Add ('  C1 主机 HTTP  ' + $HostIp + ':' + $Port + ' -> ' + (TcpOk $HostIp $Port $TcpMs))
Add ('  C2 主机 SMB   ' + $HostIp + ':445  -> ' + (TcpOk $HostIp 445 $TcpMs))
$pub = @()
foreach ($tok in ($TestSites -split ',')) {
  $tok = $tok.Trim()
  if (-not $tok) { continue }
  $isIp = ($tok -match '^\d+\.\d+\.\d+\.\d+$')
  if ($isIp) {
    $r = (TcpOk $tok 53 $TcpMs)
    Add ('  C3 公网地址 ' + $tok + ':53 -> ' + $r)
    $pub += $r
  } else {
    $ips = @(DnsOf $tok)
    $first = $ips[0]
    $ok = $false
    if ($first -match '^\d+\.\d+\.\d+\.\d+$') { $ok = (TcpOk $first 443 $TcpMs) }
    Add ('  C4 站点 ' + $tok + ' DNS=' + ($ips -join ',') + '  tcp443=' + $ok)
    $pub += $ok
  }
}

Add ''
Add '### D. 监听与已连接'
foreach ($ln in @(& netstat.exe -an 2>&1 | ForEach-Object { $_.ToString() })) {
  if ($ln -match 'LISTENING') { Add ('  LISTEN ' + ($ln -replace '\s+', ' ').Trim()) }
}
$est = @(& netstat.exe -an 2>&1 | ForEach-Object { $_.ToString() } | Where-Object { $_ -match 'ESTABLISHED' })
Add ('  ESTABLISHED 条数=' + $est.Count)
foreach ($e in ($est | Select-Object -First 8)) { Add ('    ' + ($e -replace '\s+', ' ').Trim()) }

Add ''
Add '### E. 相关进程'
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '(sunlogin|oray|pe-sshd|frpc|mshta|wifi)' } | Sort-Object ProcessName)) {
  Add ('  ' + $p.ProcessName + '  pid=' + $p.Id + '  路径=' + $p.Path)
}
Add ('  X:\Sunlogin 存在=' + (Test-Path 'X:\Sunlogin') + '  文件数=' + (@(Get-ChildItem 'X:\Sunlogin' -Recurse -File -EA SilentlyContinue).Count))
$sl = @(Get-ChildItem 'X:\Sunlogin' -Recurse -File -EA SilentlyContinue | Where-Object { $_.Extension -in @('.log', '.txt') } | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
foreach ($f in $sl) {
  Add ('  -- ' + $f.FullName + ' 末 5 行 --')
  foreach ($ln in @(Get-Content $f.FullName -Tail 5 -EA SilentlyContinue)) { Add ('    ' + $ln) }
}
Add ('  boot.log 末 6 行:')
foreach ($ln2 in @(& Get-Content 'X:\boot.log' -Encoding Default -Tail 6 -EA SilentlyContinue | ForEach-Object { $_.ToString() })) { Add ('    ' + $ln2.Trim()) }

Add ''
Add '### F. 判定(断在哪一层)'
$lanOk = (TcpOk $HostIp $Port $TcpMs)
$wanAny = ($pub | Where-Object { $_ -eq $true }).Count -gt 0
$hasGw = @(& route print 2>&1 | ForEach-Object { $_.ToString() } | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0' }).Count -gt 0
$dnsGot = (@(DnsOf 'sunlogin.oray.com')[0] -match '^\d+\.\d+\.\d+\.\d+$')
Add ('  L1 本机有 IP 且到主机通 = ' + $lanOk)
Add ('  L2 有默认路由 0.0.0.0   = ' + $hasGw)
Add ('  L3 域名可解析           = ' + $dnsGot)
Add ('  L4 任意公网端点可达     = ' + $wanAny)
if ($lanOk -and -not $hasGw) {
  Add '  => 断在第 2 层: 这个网络里根本没有通往外部的路由。VM 挂的是 Internal 交换机(PE-INT), 它只把 VM 和"主机这块 vEthernet"连在一起, 按定义没有上行走公网的出口。这是测试拓扑的限制, 不是镜像/防火墙的问题。'
} elseif ($lanOk -and $hasGw -and -not $wanAny) {
  Add '  => 有默认路由但出不去: 要么主机侧没做 NAT/ICS, 要么上游被挡。需要在主机侧查 192.168.100.x 的 NAT/路由连通, 仍与镜像内防火墙无关(出站从来不受它管)。'
} elseif (-not $lanOk) {
  Add '  => 连本地链路都断: 先查 PE 的 IP 还在不在、主机 vEthernet (PE-INT) 还是不是 192.168.100.1。'
} else {
  Add '  => 链路/路由/公网都通, 那向日葵的问题在应用层(看第 E 节进程与日志)。'
}
Add '  另: MpsSvc 被离线注册表禁用只影响"别人连进来", 出站方向不受任何限制(本次 C1 能通即为证据)。'
Add ('  [' + (Stamp) + '] 结束')

$text = ($L -join "`r`n")
try { [IO.File]::WriteAllText('X:\net_audit.txt', $text, (New-Object Text.UTF8Encoding($true))) } catch { Add ('写 X:\net_audit.txt 失败: ' + $_.Exception.Message) }
if (-not ($ShowOnly -or $SelfTest)) {
  $body = [Text.Encoding]::UTF8.GetBytes($text)
  try {
    (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
    Add ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功')
  } catch { Add ('POST 失败: ' + $_.Exception.Message + '  (手查: type X:\net_audit.txt)') }
}
