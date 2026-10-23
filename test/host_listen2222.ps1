# 主机侧监听 2222 (300秒)。自检用独立端口 2223，避免误判。
$ErrorActionPreference = 'Continue'

# --- 自检: 主机防火墙是否拦截 172.31.32.1 入站 ---
$tl = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 2223)
$tl.Start()
$probe = New-Object System.Net.Sockets.TcpClient
$self = 'TIMEOUT'
try {
  $ar = $probe.BeginConnect('172.31.32.1', 2223, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(3000)) { $self = $(if ($probe.Connected) { 'OPEN' } else { 'REFUSED' }) }
} catch { $self = 'REFUSED' }
$probe.Close(); $tl.Stop()
Write-Host "SELF-TEST 主机->172.31.32.1:2223 = $self (若 REFUSED/TIMEOUT 则防火墙拦截入站)"

# --- 正式监听 2222, 只接受非主机自身的连接 ---
$l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 2222)
$l.Start()
Write-Host 'HOST-LISTENING 2222 等待 VM 连接 (最多 300 秒)...'
$deadline = (Get-Date).AddSeconds(300)
$connected = $false
while ((Get-Date) -lt $deadline -and -not $connected) {
  if ($l.Pending()) {
    $c = $l.AcceptTcpClient()
    $remote = $c.Client.RemoteEndPoint.ToString()
    if ($remote -like '172.31.32.1:*') {
      Write-Host "忽略主机自身连接 $remote"
      $c.Close(); continue
    }
    Write-Host "VM-CONNECTED from $remote"
    $s = $c.GetStream(); $c.ReceiveTimeout = 5000
    $buf = New-Object byte[] 64
    try { $n = $s.Read($buf, 0, 64); if ($n -gt 0) { Write-Host ('收到数据: ' + [Text.Encoding]::ASCII.GetString($buf, 0, $n)) } } catch {}
    [void]$s.Write([Text.Encoding]::ASCII.GetBytes('HOST-OK'), 0, 7)
    $c.Close(); $connected = $true
  } else { Start-Sleep -Milliseconds 300 }
}
$l.Stop()
if ($connected) { Write-Host 'RESULT: VM->HOST 通路正常' } else { Write-Host 'RESULT: 300 秒内无 VM 连接' }
