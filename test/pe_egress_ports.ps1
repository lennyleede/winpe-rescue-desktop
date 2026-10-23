# pe_egress_ports.ps1 -- can the PE reach the frp server's own ssh / http ports (outbound)?
# Decides whether `rescue` can scp an evidence bundle back to the server, or must fall back to
# chunked base64 over the inbound pe-sshd session.
$Target = '203.0.113.10'
Write-Output ('EGRESS-PORTS from PE to ' + $Target)
foreach ($p in @(22, 8022, 7000, 7500, 80, 443, 8080, 8443)) {
  $res = 'timeout'
  try {
    $c = New-Object Net.Sockets.TcpClient
    $ar = $c.BeginConnect($Target, $p, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(4000)) {
      if ($c.Connected) { $res = 'OPEN' } else { $res = 'refused' }
      $c.Close()
    }
  } catch { $res = 'err:' + $_.Exception.GetType().Name }
  Write-Output ('  ' + $p.ToString().PadLeft(5) + ' = ' + $res)
}
Write-Output 'SSH-CLIENT'
foreach ($t in @('X:\OpenSSH\ssh.exe','X:\OpenSSH\scp.exe','X:\OpenSSH\sftp.exe')) {
  Write-Output ('  ' + $t + ' = ' + $(if (Test-Path -LiteralPath $t) { (Get-Item -LiteralPath $t).Length } else { 'absent' }))
}
Write-Output 'HTTPS-PUT-ABILITY'
try {
  $r = Invoke-WebRequest -Uri 'https://www.baidu.com' -Method Head -UseBasicParsing -TimeoutSec 8
  Write-Output ('  Invoke-WebRequest https = ok ' + $r.StatusCode)
} catch { Write-Output ('  Invoke-WebRequest https = FAIL ' + $_.Exception.Message) }
Write-Output 'END'
