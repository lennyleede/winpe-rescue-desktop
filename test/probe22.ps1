param([string]$Target = '172.31.38.211')
$c = New-Object System.Net.Sockets.TcpClient
try {
  $r = $c.BeginConnect($Target, 22, $null, $null)
  if ($r.AsyncWaitHandle.WaitOne(1500) -and $c.Connected) { Write-Output 'PORT22_OPEN' } else { Write-Output 'PORT22_CLOSED' }
} catch { Write-Output "ERR: $($_.Exception.Message)" } finally { $c.Close() }
