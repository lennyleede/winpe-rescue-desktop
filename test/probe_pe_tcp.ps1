param([string]$Target = '192.168.100.2', [string]$Ports = '22,135,445,3389', [int]$Ms = 4000)
foreach ($p in ($Ports -split ',')) {
  $port = [int]$p
  $c = New-Object System.Net.Sockets.TcpClient
  $line = 'tcp ' + $port + ' : '
  try {
    $ar = $c.BeginConnect($Target, $port, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne($Ms) -and $c.Connected) {
      $line += 'OPEN'
      $st = $c.GetStream()
      if ($st.CanRead) {
        $b = New-Object byte[] 96
        try {
          $st.ReadTimeout = 3000
          $n = $st.Read($b, 0, 96)
          if ($n -gt 0) { $line += '  banner=' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim() }
        } catch { $line += '  (no banner read)' }
      }
    } else { $line += 'SYN-no-answer' }
  } catch { $line += 'ERR ' + $_.Exception.Message } finally { $c.Close() }
  Write-Host $line
}
Write-Host ('neighbor: ' + (((Get-NetNeighbor -IPAddress $Target -ErrorAction SilentlyContinue) | ForEach-Object { $_.InterfaceAlias + '=' + $_.State + '/' + $_.LinkLayerAddress }) -join ' , '))
$sw = ((& ping -n 2 -w 800 $Target 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
Write-Host ('ping: ' + $sw)
