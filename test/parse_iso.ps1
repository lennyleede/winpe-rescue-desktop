param([string]$Iso = 'D:\QoderProject\国内版\生成winpe\dist\WinPE_Desktop_v5.iso')
$fs = [System.IO.File]::OpenRead($Iso)
$br = New-Object System.IO.BinaryReader($fs)

function ReadAt([long]$off, [int]$len) {
  $fs.Position = $off
  return $br.ReadBytes($len)
}
function Hex([byte[]]$b) { ($b | ForEach-Object { $_.ToString('X2') }) -join ' ' }
function Str([byte[]]$b) { -join ($b | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } }) }
function U32([byte[]]$b, [int]$o) { [BitConverter]::ToUInt32($b, $o) }

# Volume descriptors start at sector 16 (32KB). Find PVD (type 1).
$pvd = $null
for ($vds = 16; $vds -lt 20; $vds++) {
  $sec = ReadAt ([long]$vds * 2048) 2048
  if ($sec[0] -eq 1 -and (Str $sec[1..5]) -eq 'CD001') { $pvd = $sec; $pvdLba = $vds; break }
}
if (-not $pvd) { Write-Host 'PVD not found'; exit 1 }
Write-Host ("PVD at sector $pvdLba, volume: '" + (Str $pvd[40..71]).Trim() + "'")

$catLba = U32 $pvd 70
Write-Host ("Boot catalog LBA: $catLba")
$cat = ReadAt ([long]$catLba * 2048) 2048
Write-Host ("Catalog first96: " + (Hex $cat[0..95]))
Write-Host ("Validation id='" + (Str $cat[7..29]) + "'  header0x=" + ('{0:X2}' -f $cat[32]) + "  entries=" + [BitConverter]::ToUInt16($cat, 38))
$entryCount = [BitConverter]::ToUInt16($cat, 38)
for ($e = 0; $e -lt [Math]::Max($entryCount,1); $e++) {
  $off = 64 + $e * 32
  $ent = $cat[$off..($off+31)]
  $bootable = $ent[0]; $media = $ent[1]
  $lba = U32 $ent 10
  $platform = Str $ent[2..3]
  Write-Host ("Entry $e : bootable=0x{0:X2} media=0x{1:X2} loadLba={2} raw={3}" -f $bootable, $media, $lba, (Hex $ent))
  if ($lba -gt 0 -and $lba -lt (2000000000)) {
    $img = ReadAt ([long]$lba * 2048) 2048
    Write-Host ("   image@LBA first64: " + (Hex $img[0..63]))
    Write-Host ("   image ascii: " + (Str $img[0..63]))
    # search EFISYS / MD5 signature within first 64KB
    $big = ReadAt ([long]$lba * 2048) 65536
    $s = Str $big
    if ($s -match 'EFISYS') { Write-Host '   -> contains EFISYS (UEFI fat image)' }
    if ($s -match 'Microsoft') { Write-Host '   -> contains "Microsoft" (BIOS etfsboot)' }
  }
}
$fs.Close()
