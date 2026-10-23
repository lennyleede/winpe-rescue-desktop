param([string]$PeIP = '192.168.100.2', [int]$Seconds = 900, [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'wait_pe_int.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8; Write-Host $s }
Add ('wait_pe_int start ' + (Get-Date -Format 'HH:mm:ss') + ' target=' + $PeIP + ' hostip=192.168.100.1')
$mine = @(Get-NetIPAddress -InterfaceAlias 'vEthernet (PE-INT)' -AddressFamily IPv4 -ErrorAction SilentlyContinue)
Add ('host iface ips: ' + (($mine | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }) -join ','))
if ($mine.Count -eq 0) { Add 'HOST HAS NO 192.168.100.1 - abort (would leak to WAN)'; return }
$dl = (Get-Date).AddSeconds($Seconds)
$n = 0
while ((Get-Date) -lt $dl) {
  $n++
  $p = ((& ping -n 2 -w 700 $PeIP 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  $nb = ((Get-NetNeighbor -IPAddress $PeIP -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State + '/' + $_.LinkLayerAddress }) -join ' , ')
  $up = ($p -match 'TTL=\d+' -and $p -notmatch '27\.129')
  if (-not $up) { if ($n % 5 -eq 0) { Add ('#' + $n + ' arp[' + $nb + '] ' + $p) }; Start-Sleep 3; continue }
  Add ('#' + $n + ' PING-OK ' + $p)
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect($PeIP, 22, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
      $st = $c.GetStream(); $b = New-Object byte[] 96
      try { $rd = $st.Read($b, 0, 96); Add ('TCP22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $rd)).Trim()) } catch { Add 'TCP22 OPEN, no banner' }
    } else { Add 'TCP22: SYN no answer' }
  } catch { Add ('TCP22 ERR ' + $_.Exception.Message) } finally { $c.Close() }
  Add ('REACHABLE at ' + (Get-Date -Format 'HH:mm:ss') + ' -> ssh Administrator@' + $PeIP)
  return
}
Add ('TIMEOUT ' + $Seconds + 's: PE never answered on ' + $PeIP)
