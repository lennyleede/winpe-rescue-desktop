# Host side: keep knocking on the PE listener so the PE can tell us what it sees.
# powershell -NoProfile -ExecutionPolicy Bypass -File test\host_hammer.ps1 -Seconds 1800
param([string]$Peer = '192.168.0.108', [int]$PeerPort = 9010, [int]$Seconds = 1800, [string]$Log = '')
$ErrorActionPreference = 'Continue'
if (-not $Log) { $Log = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\hammer.log' }
$deadline = (Get-Date).AddSeconds($Seconds)
$i = 0
while ((Get-Date) -lt $deadline) {
  $i++
  $ts = Get-Date -Format 'HH:mm:ss'
  $c = New-Object Net.Sockets.TcpClient
  $res = ''
  try {
    $ar = $c.BeginConnect($Peer, $PeerPort, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(2000) -and $c.Connected) {
      $s = $c.GetStream(); $b = New-Object byte[] 64
      try { $n = $s.Read($b, 0, 64); $res = 'OPEN reply=' + [Text.Encoding]::ASCII.GetString($b, 0, $n).Trim() }
      catch { $res = 'OPEN no-reply' }
    } else { $res = 'SYN-no-answer' }
  } catch { $res = 'ERR ' + $_.Exception.Message }
  $c.Close()
  ($ts + ' attempt#' + $i + ' -> ' + $Peer + ':' + $PeerPort + ' ' + $res) | Add-Content -Path $Log -Encoding UTF8
  if ($i % 8 -eq 0) {
    $p = ((& ping -n 2 -w 600 $Peer 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
    ($ts + ' ping: ' + $p) | Add-Content -Path $Log -Encoding UTF8
  }
  Start-Sleep -Milliseconds 1500
}
(Get-Date -Format 'HH:mm:ss') + ' hammer done' | Add-Content -Path $Log -Encoding UTF8
