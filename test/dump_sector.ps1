param([string]$Iso, [int]$Sector = 17, [int]$Len = 128)
$fs = [System.IO.File]::OpenRead($Iso)
$br = New-Object System.IO.BinaryReader($fs)
$fs.Position = [long]$Sector * 2048
$b = $br.ReadBytes($Len)
Write-Host ("=== {0}  sector {1} ===" -f $Iso, $Sector)
for ($i = 0; $i -lt $b.Length; $i += 16) {
  $chunk = $b[$i..([Math]::Min($i+15, $b.Length-1))]
  $hex = ($chunk | ForEach-Object { $_.ToString('X2') }) -join ' '
  $asc = -join ($chunk | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
  Write-Host ('{0,4}: {1,-48} {2}' -f ($i*1), $hex, $asc)
}
$fs.Close()
