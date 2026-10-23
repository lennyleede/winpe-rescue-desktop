$VMIP = '172.31.38.211'
foreach ($port in 22, 2222) {
  $c = New-Object System.Net.Sockets.TcpClient
  $res = 'TIMEOUT'
  try {
    $ar = $c.BeginConnect($VMIP, $port, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(5000)) { $res = $(if ($c.Connected) { 'OPEN' } else { 'REFUSED' }) }
  } catch { $res = 'REFUSED' }
  if ($c.Connected) {
    $s = $c.GetStream()
    $buf = New-Object byte[] 64
    $c.ReceiveTimeout = 3000
    try { $n = $s.Read($buf, 0, 64); if ($n -gt 0) { $res += (' 数据: ' + [Text.Encoding]::ASCII.GetString($buf, 0, $n)) } } catch {}
  }
  $c.Close()
  Write-Host ("端口 {0}: {1}" -f $port, $res)
}
