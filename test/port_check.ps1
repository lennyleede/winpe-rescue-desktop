param([string]$Host_ = '203.0.113.10', [int[]]$Ports = @(22,7000,7500,8022,80,443,8080))
# Which ports on the frp server are actually reachable from here? This decides the
# PE -> server upload design (scp needs sshd on the server; a PUT endpoint needs a listener).
foreach ($p in $Ports) {
  $r = Test-NetConnection -ComputerName $Host_ -Port $p -WarningAction SilentlyContinue
  Write-Output ('  {0,-5} tcp={1} latency={2}ms' -f $p, $r.TcpTestSucceeded, $r.PingReplyDetails.RoundtripTime)
}
