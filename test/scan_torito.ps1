param([string]$Iso = 'D:\QoderProject\国内版\生成winpe\dist\WinPE_Desktop_v5.iso', [int]$MaxSectors = 4096)
$fs = [System.IO.File]::OpenRead($Iso)
$br = New-Object System.IO.BinaryReader($fs)
$found = @()
for ($s = 16; $s -lt $MaxSectors; $s++) {
  $fs.Position = [long]$s * 2048
  $b = $br.ReadBytes(64)
  if ($b.Length -lt 32) { break }
  $id = -join ($b[7..29] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
  if ($id -like 'EL TORITO SPECIFICATION*') {
    Write-Host ("Torito validation entry at sector $s")
    $fs.Position = [long]$s * 2048
    $sec = $br.ReadBytes(2048)
    Write-Host ("  header byte@32 = 0x{0:X2} (expect 0x55), entries = {1}" -f $sec[32], [BitConverter]::ToUInt16($sec, 38))
    $n = [BitConverter]::ToUInt16($sec, 38)
    for ($e = 0; $e -lt $n; $e++) {
      $off = 64 + $e * 32
      $ent = $sec[$off..($off+31)]
      $lba = [BitConverter]::ToUInt32($ent, 10)
      $plat = -join ($ent[2..3] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { ('{0:X2}' -f $_) } })
      Write-Host ("  Entry{0}: bootable=0x{1:X2} media=0x{2:X2} b2-3={3} loadLba={4}" -f $e, $ent[0], $ent[1], (('{0:X2} {1:X2}' -f $ent[2],$ent[3])), $lba)
      if ($lba -gt 0 -and $lba -lt 4194304) {
        $fs.Position = [long]$lba * 2048
        $img = $br.ReadBytes(2048)
        $a = -join ($img[0..63] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
        Write-Host ("    image@{0} ascii: {1}" -f $lba, $a)
      }
    }
    $found += $s
  }
}
if ($found.Count -eq 0) { Write-Host "No torito catalog found in first $MaxSectors sectors" }
# 顺便 dump PVD 64..96 字节
$fs.Position = 16*2048 + 64
$pv = $br.ReadBytes(32)
Write-Host ('PVD bytes 64..95: ' + (($pv | ForEach-Object { $_.ToString('X2') }) -join ' '))
$fs.Close()
