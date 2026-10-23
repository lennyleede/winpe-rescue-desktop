param([string]$Iso = '..\dist\WinPE_Desktop_v5.iso')
$Iso = (Resolve-Path $Iso).Path
$sectorLen = 2048
$ident = [Text.Encoding]::ASCII.GetBytes('EL TORITO SPECIFICATION')
$etLba = -1; $catLba = -1; $entries = New-Object System.Collections.Generic.List[string]
$fs = [IO.File]::OpenRead($Iso)
try {
  $total = [int][Math]::Floor($fs.Length / $sectorLen)
  $buf = New-Object byte[] $sectorLen
  $read = { param($s)
    $fs.Position = [int64]$s * $sectorLen
    $off = 0
    while ($off -lt $sectorLen) {
      $n = $fs.Read($buf, $off, $sectorLen - $off)
      if ($n -le 0) { break }
      $off += $n
    }
    ,$buf
  }
  # 1) 前 64 个扇区里找 El Torito 卷描述符 (偏移 7 起为标识串), 其偏移 71 处 4 字节 = 引导目录 LBA
  for ($s = 0; $s -lt [Math]::Min(64, $total); $s++) {
    $b = & $read $s
    $ok = $true
    for ($k = 0; $k -lt $ident.Length; $k++) { if ($b[7 + $k] -ne $ident[$k]) { $ok = $false; break } }
    if ($ok) { $etLba = $s; $catLba = [BitConverter]::ToInt32($b, 71); break }
  }
  # 2) 读引导目录, 逐 32 字节槽找可引导项 (bootInfo 0x88/0x00, 偏移+8 为引导记录 LBA)
  if ($catLba -gt 0 -and $catLba -lt $total) {
    $c = & $read $catLba
    for ($o = 0x20; $o + 32 -le $sectorLen; $o += 32) {
      $bi = $c[$o]
      if ($bi -ne 0x88 -and $bi -ne 0x00) { continue }
      $lba = [BitConverter]::ToInt32($c, $o + 8)
      if ($lba -le 0 -or $lba -ge $total) { continue }
      $entries += ('{0:X2}@{1} -> LBA {2}' -f $bi, $o, $lba)
    }
  }
} finally { $fs.Close() }
if ($etLba -lt 0 -or $catLba -le 0 -or $entries.Count -eq 0) {
  'NOT BOOTABLE (etLba={0} catLba={1} entries={2})' -f $etLba, $catLba, $entries.Count
} else {
  'OK: ET-VD LBA={0}, catalog LBA={1}, boot entries={2}: {3}' -f $etLba, $catLba, $entries.Count, ($entries -join ', ')
}
