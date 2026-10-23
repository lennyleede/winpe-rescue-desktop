# 扫一下子网里谁在听 22 端口, 并抓 SSH banner 认出是不是镜像里的 pe-sshd
# 用法(普通 PowerShell, 不用管理员):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\find_pe.ps1
#   只扫某个段: -SubnetList 192.168.0,172.31.38   换端口: -PortList 22,6000
#   跳过已知非 PE 的设备: -Exclude 192.168.0.107
#   (-File 调用时数组参数不会被拆成多个元素, 所以这里用逗号串再自己 split)
param(
  [string]$SubnetList = '192.168.0,172.31.32',
  [string]$PortList = '22',
  [string]$Exclude = '',
  [int]$Concurrency = 64,
  [int]$ConnectMs = 350,
  [int]$BannerMs = 700
)
$ErrorActionPreference = 'Stop'
$Subnets = @($SubnetList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Ports   = @($PortList   -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { [int]$_ })
$Skip    = @($Exclude    -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$targets = New-Object System.Collections.Generic.List[string]
foreach ($s in $Subnets) {
  for ($i = 1; $i -le 254; $i++) {
    $ip = "$s.$i"
    if ($Skip -contains $ip) { continue }
    foreach ($p in $Ports) { $targets.Add($ip + ":$p") }
  }
}
Write-Host ("待扫 " + $targets.Count + " 个 end point ...")

$pool = [runspacefactory]::CreateRunspacePool(1, $Concurrency)
$pool.Open()
$jobs = New-Object System.Collections.Generic.List[object]

$script = {
  param($ep, $cMs, $bMs)
  $ip, $portStr = $ep.Split(':')
  $res = @{ Ep = $ep; Alive = $false; Banner = '' }
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($ip, [int]$portStr, $null, $null)
    if ($iar.AsyncWaitHandle.WaitOne($cMs) -and $c.Connected) {
      $res.Alive = $true
      try {
        $c.ReceiveTimeout = $bMs
        $st = $c.GetStream()
        $buf = New-Object byte[] 64
        $n = $st.Read($buf, 0, 64)
        if ($n -gt 0) { $res.Banner = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '[^\x20-\x7E]', '').Trim() }
      } catch {}
      $c.Close()
    } else { $c.Close() }
  } catch {}
  $res
}

foreach ($ep in $targets) {
  $ps = [powershell]::Create().AddScript($script).AddArgument($ep).AddArgument($ConnectMs).AddArgument($BannerMs)
  $ps.RunspacePool = $pool
  $jobs.Add([pscustomobject]@{ PS = $ps; AR = $ps.BeginInvoke() })
}

$hits = @()
foreach ($j in $jobs) {
  try {
    foreach ($r in $j.PS.EndInvoke($j.AR)) { if ($r.Alive) { $hits += $r } }
  } catch {}
  $j.PS.Dispose()
}
$pool.Close(); $pool.Dispose()

if (-not $hits.Count) {
  Write-Output '没扫到任何在听 22 的主机 => PE 要么没开机/没起来网络, 要么和宿主机不在同一个网段'
} else {
  foreach ($h in $hits) {
    $who = if ($h.Banner -match 'pe-sshd') { '<= 就是镜像里的 pe-sshd' }
           elseif ($h.Banner -match 'SSH') { '<= 是别的 SSH(宿主机自己的 OpenSSH?)' } else { '' }
    Write-Output ("OPEN  " + $h.Ep + "  banner=[" + $h.Banner + "] " + $who)
  }
}

Write-Host '--- 本机 IPv4 与默认路由(核对网段用) ---'
foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254*' })) {
  Write-Host ("  {0,-32} {1}/{2}" -f $a.InterfaceAlias, $a.IPAddress, $a.PrefixLength)
}
Write-Host '--- ARP 表里的邻居(PE 刚连过时 MAC 会是 Intel/Realtek 网卡) ---'
foreach ($l in @((& arp.exe -a | Select-String '动态|dynamic'))) { Write-Host ('  ' + $l.ToString().Trim()) }
