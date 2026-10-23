param([string]$Iso, [long]$ScanBytes = 20971520)
$fs = [System.IO.File]::OpenRead($Iso)
$br = New-Object System.IO.BinaryReader($fs)
$chunk = 1MB
$overlap = 64
$pos = 0
$prevTail = New-Object byte[] 0
while ($pos -lt $ScanBytes -and $pos -lt $fs.Length) {
  $len = [Math]::Min($chunk, [Math]::Min($ScanBytes - $pos, $fs.Length - $pos))
  $buf = New-Object byte[] ($len + $prevTail.Length)
  [Array]::Copy($prevTail, 0, $buf, 0, $prevTail.Length)
  $data = $br.ReadBytes($len)
  [Array]::Copy($data, 0, $buf, $prevTail.Length, $data.Length)
  $base = $pos - $prevTail.Length
  for ($i = 0; $i -lt ($buf.Length - 32); $i++) {
    if ($buf[$i+7] -eq 0x45 -and $buf[$i+8] -eq 0x4C -and $buf[$i+9] -eq 0x20 -and $buf[$i+10] -eq 0x54 -and $buf[$i+11] -eq 0x4F) {
      $abs = $base + $i
      $id = -join ($buf[($i+7)..($i+29)] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
      if ($id -like 'EL TORITO SPECIFICATION*') {
        Write-Host ("Validation entry at byte {0} (sector {1})" -f $abs, [Math]::Floor($abs/2048))
        $hex = ($buf[$i..($i+95)] | ForEach-Object { $_.ToString('X2') }) -join ' '
        Write-Host ("  bytes: $hex")
        $h = $buf[$i+32]
        Write-Host ("  header byte@+32 = 0x{0:X2}  entries@+38 = {1}" -f $h, [BitConverter]::ToUInt16($buf, $i+38))
      }
    }
  }
  $prevTail = $data[([Math]::Max(0,$data.Length-$overlap))..($data.Length-1)]
  $pos += $len
}
$fs.Close()
Write-Host 'scan done'
