# gptdump.ps1 -- capture the GPT bytes as the OFF-DISK safety net (rescue SOP step zero).
#
# Baked from the 2026-10-14 remote rescue drill scenario 4B (docs\rescue-drill, section 7):
#   the drill proved that a single damaged GPT copy is silently reloaded by the firmware, so the
#   realistic emergency is BOTH copies gone - and then the ONLY source left is a byte dump taken
#   BEFORE the fault. This is that tool. It is READ-ONLY (never writes the disk) and its output
#   file names are exactly what gptfix -Repair -DumpDir <dir> expects:
#       gpt_d<disk>_prim_hdr_<stamp>.hex|.bin     (LBA1, 512B)
#       gpt_d<disk>_prim_tab_<stamp>.hex|.bin     (primary entry table)
#       gpt_d<disk>_backup_hdr_<stamp>.hex|.bin   (last LBA, 512B)
#       gpt_d<disk>_backup_tab_<stamp>.hex|.bin   (backup entry table)
#   plus gpt_manifest_<stamp>.txt with geometry + MD5 per blob.
#   .hex (ASCII, survives any transport) and .bin (raw bytes) are written side by side.
#
# WHEN TO RUN (gap 16 of the drill report): before ANY partition surgery, and whenever the machine
# still boots. Copy the output folder OFF the disk under protection (U disk / host pull below).
# Remote pull over ssh: every blob also prints as a 'B64|name|md5|<base64>' line on stdout, so a
# host-side runner can reconstruct the files from the session transcript alone.
#
# Usage:
#   gptdump                      dump every real disk (>1GB, not CD/ramdisk)
#   gptdump -Disk 0              one disk            -OutDir E:\rescue   destination
# Exit line: RESULT=GPTDUMP-OK | GPTDUMP-DAMAGED-SOURCE (captured anyway - bytes are bytes) | GPTDUMP-BAD-*
#
# ASCII output only. Runs in PE and in a live Windows (raw reads are open-share; no writes at all).
param(
  [int]$Disk = -1,
  [string]$OutDir = '',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += (('' + $s) -replace '[^\x20-\x7E]', '?') }
function Flush([string]$dir2) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\gptdump.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($dir2) { try { [IO.File]::AppendAllText($dir2 + '\gpt_dump_log.txt', $t + "`r`n") } catch {} }
  $t | Write-Output
}
function ExText($e) { return ((('' + $e.Exception.Message) + ' [' + $e.Exception.GetType().Name + ']') -replace '[^\x20-\x7E]', '?') }

$BSL = [char]92   # case-insensitive-name discipline: never $BD/$bd here
function DevPath([int]$n) { return ('' + $BSL + $BSL + '.' + $BSL + 'PhysicalDrive' + $n) }
function Crc32([byte[]]$data) {
  $mask = [long]([Convert]::ToUInt32('FFFFFFFF', 16))
  $poly = [long]([Convert]::ToUInt32('EDB88320', 16))
  $c = $mask
  foreach ($b in $data) {
    $c = ($c -bxor [long]$b) -band $mask
    for ($i = 0; $i -lt 8; $i++) {
      if ($c -band 1) { $c = (($c -shr 1) -bxor $poly) -band $mask } else { $c = $c -shr 1 }
    }
  }
  return ($c -bxor $mask) -band $mask
}
function Read-Sectors([int]$diskNum, [long]$byteOffset, [int]$len) {
  $dev = DevPath $diskNum
  $fs = [IO.FileStream]::new($dev, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 512)
  [void]$fs.Seek($byteOffset, [IO.SeekOrigin]::Begin)
  $buf = New-Object byte[] $len
  $got = 0
  while ($got -lt $len) { $n = $fs.Read($buf, $got, ($len - $got)); if ($n -le 0) { break }; $got += $n }
  $fs.Close()
  if ($got -ne $len) { throw ('short read ' + $got + '/' + $len) }
  return ,$buf
}
function Md5Hex([byte[]]$data) {
  $h = [Security.Cryptography.MD5]::Create().ComputeHash($data)
  return (([BitConverter]::ToString($h)) -replace '-', '').ToLowerInvariant()
}
function BytesToHex([byte[]]$b) { return (([BitConverter]::ToString($b)) -replace '-', '') }
function Get-Hdr([byte[]]$b) {
  $o = New-Object PSObject
  $sig = [Text.Encoding]::ASCII.GetString($b, 0, 8)
  $hsz = [int][BitConverter]::ToUInt32($b, 12)
  $stored = [long][BitConverter]::ToUInt32($b, 16)
  $calc = [long](-1)
  if ($hsz -gt 0 -and ($hsz -le $b.Length)) {
    $copy = New-Object byte[] $hsz
    [Array]::Copy($b, 0, $copy, 0, $hsz)
    $copy[16] = 0; $copy[17] = 0; $copy[18] = 0; $copy[19] = 0
    $calc = Crc32 $copy
  }
  $g = New-Object byte[] 16; [Array]::Copy($b, 56, $g, 0, 16)
  $o | Add-Member NoteProperty Sig $sig
  $o | Add-Member NoteProperty CrcStored $stored
  $o | Add-Member NoteProperty CrcCalc $calc
  $o | Add-Member NoteProperty MyLba ([long][BitConverter]::ToUInt64($b, 24))
  $o | Add-Member NoteProperty AltLba ([long][BitConverter]::ToUInt64($b, 32))
  $o | Add-Member NoteProperty EntryLba ([long][BitConverter]::ToUInt64($b, 72))
  $o | Add-Member NoteProperty EntryCount ([long][BitConverter]::ToUInt32($b, 80))
  $o | Add-Member NoteProperty EntrySize ([long][BitConverter]::ToUInt32($b, 84))
  $o | Add-Member NoteProperty EntriesCrc ([long][BitConverter]::ToUInt32($b, 88))
  $o | Add-Member NoteProperty Guid ((New-Object Guid(, $g)).ToString().ToUpper())
  $o | Add-Member NoteProperty Valid (($sig -eq 'EFI PART') -and ($stored -eq $calc) -and ($hsz -eq 92))
  $o | Add-Member NoteProperty TabLen ($o.EntryCount * $o.EntrySize)
  return $o
}
function Emit-Blob([string]$dir, [int]$diskNum, [string]$kind, [byte[]]$data, [string]$stamp) {
  $base = 'gpt_d' + $diskNum + '_' + $kind + '_' + $stamp
  $md5 = Md5Hex $data
  $hexOk = $false; $binOk = $false
  try { [IO.File]::WriteAllText($dir + '\' + $base + '.hex', (BytesToHex $data), [Text.Encoding]::ASCII); $hexOk = $true } catch { Add('hex_write_EX[' + $base + ']=' + (ExText $_)) }
  try { [IO.File]::WriteAllBytes($dir + '\' + $base + '.bin', $data); $binOk = $true } catch { Add('bin_write_EX[' + $base + ']=' + (ExText $_)) }
  Add('BLOB disk=' + $diskNum + ' name=' + $base + ' bytes=' + $data.Length + ' md5=' + $md5 + ' hex=' + $hexOk + ' bin=' + $binOk)
  Add('B64|' + $base + '|' + $md5 + '|' + [Convert]::ToBase64String($data))
  return ('DUMP disk=' + $diskNum + ' kind=' + $kind + ' file=' + $base + ' bytes=' + $data.Length + ' md5=' + $md5)
}

if ($SelfTest) {
  Add('T=' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' MODE=SELFTEST (no disk access)')
  Add('DEVP=' + (DevPath 0))
  $v = Crc32 ([Text.Encoding]::ASCII.GetBytes('123456789'))
  $vOk = ((('{0:X8}' -f $v)) -eq 'CBF43926')
  Add('CRC32_VECTOR=' + ('{0:X8}' -f $v) + ' ok=' + $vOk)
  # the drill's real primary header (gptdump 19:03): parse + geometry
  $fixture = '4546492050415254000001005C00000092424D1E000000000100000000000000FFFF7F07000000002200000000000000DEFF7F0700000000D6B231F216850E40A3C021DF5DB00FF202000000000000008000000080000000E808B1CB00000000'
  $prim = New-Object byte[] 512
  for ($i = 0; $i -lt 96; $i++) { $prim[$i] = [Convert]::ToByte($fixture.Substring($i * 2, 2), 16) }
  $hp = Get-Hdr $prim
  $fOk = $hp.Valid -and ((('{0:X8}' -f $hp.CrcStored)) -eq '1E4D4292') -and ($hp.MyLba -eq 1) -and ($hp.AltLba -eq 125829119) -and
         ($hp.EntryLba -eq 2) -and ($hp.TabLen -eq 16384) -and ($hp.Guid -eq 'F231B2D6-8516-400E-A3C0-21DF5DB00FF2')
  Add('FIXTURE ok=' + $fOk + ' guid=' + $hp.Guid)
  $h2 = ('{0:X8}' -f (Crc32 $prim))   # zero-padded tail must not break anything else; header crc is over 92B
  Add('RESULT=' + $(if ($vOk -and $fOk) { 'GPTDUMP-SELFTEST-OK' } else { 'GPTDUMP-SELFTEST-BAD' }))
  Flush ''
  exit 0
}

Add('T=' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add('HOST=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
$ss = 512
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not $OutDir) {
  # prefer a mounted Windows volume (survives the PE session), else the PE ramdisk root
  $wv = ''
  foreach ($pd in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
    if ($pd.Name -eq 'X') { continue }
    if (Test-Path -LiteralPath ($pd.Root + 'Windows\system32\winload.efi')) { $wv = $pd.Name; break }
  }
  if ($wv) { $OutDir = $wv + ':\Windows\Temp\rescue\gptdump' } else { $OutDir = 'X:\gptdump' }
}
try { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null } catch { Add('ABORT=OUTDIR=' + $OutDir + ' ' + (ExText $_)); Add('RESULT=GPTDUMP-BAD-OUTDIR'); Flush ''; exit 1 }
Add('OUTDIR=' + $OutDir)

$targets = @(Get-Disk -ErrorAction SilentlyContinue |
             Where-Object { ($_.Size -gt 1GB) -and ($_.FriendlyName -notmatch 'ramdisk') -and ($_.FriendlyName -notmatch 'CD') })
if ($Disk -ge 0) { $targets = @($targets | Where-Object { $_.Number -eq $Disk }) }
Add('disks_scanned=' + $targets.Count)
if ($targets.Count -lt 1) { Add('ABORT=NO-CANDIDATE-DISK'); Add('RESULT=GPTDUMP-BAD-NODISK'); Flush $OutDir; exit 1 }

$manifest = @()
$manifest += ('gptdump captured ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' host=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
$anyBad = $false
$rc = 0
foreach ($d in $targets) {
  $n = [int]$d.Number
  $lastLba = [long][Math]::Floor($d.Size / $ss) - 1
  Add('--- disk=' + $n + ' name=' + $d.FriendlyName + ' size=' + $d.Size + ' style=' + $d.PartitionStyle + ' lastLba=' + $lastLba)
  try {
    $h = Read-Sectors $n $ss $ss
    $hp = Get-Hdr $h
    Add('  prim valid=' + $hp.Valid + ' sig=' + $hp.Sig + ' crc=' + ('{0:X8}' -f $hp.CrcStored) + '/' + ('{0:X8}' -f $hp.CrcCalc) +
        ' entryLba=' + $hp.EntryLba + ' tabLen=' + $hp.TabLen + ' guid=' + $hp.Guid)
    $b = Read-Sectors $n ([long]$lastLba * $ss) $ss
    $hb = Get-Hdr $b
    Add('  back valid=' + $hb.Valid + ' sig=' + $hb.Sig + ' crc=' + ('{0:X8}' -f $hb.CrcStored) + '/' + ('{0:X8}' -f $hb.CrcCalc) +
        ' entryLba=' + $hb.EntryLba + ' tabLen=' + $hb.TabLen + ' guid=' + $hb.Guid)
    $pt = $null; $bt = $null
    if ($hp.Valid -and ($hp.TabLen -ge $ss) -and ($hp.TabLen -le 1MB)) {
      $pt = Read-Sectors $n ([long]$hp.EntryLba * $ss) ([int]$hp.TabLen)
      Add('  prim_tab crc_ok=' + ($hp.EntriesCrc -eq (Crc32 $pt)))
    }
    if ($hb.Valid -and ($hb.TabLen -ge $ss) -and ($hb.TabLen -le 1MB)) {
      $bt = Read-Sectors $n ([long]$hb.EntryLba * $ss) ([int]$hb.TabLen)
      Add('  back_tab crc_ok=' + ($hb.EntriesCrc -eq (Crc32 $bt)))
    }
    $good = $hp.Valid -and $hb.Valid -and $pt -and $bt -and ($hp.EntriesCrc -eq (Crc32 $pt)) -and ($hb.EntriesCrc -eq (Crc32 $bt))
    Add('  SAFETY_NET=' + $(if ($good) { 'YES' } else { 'NO (captured anyway - bytes are bytes; a dead copy cannot seed a dump for the both-dead case)' }))
    if (-not $good) { $anyBad = $true }
    $manifest += ('DISK n=' + $n + ' name=' + $d.FriendlyName + ' size=' + $d.Size + ' lastLba=' + $lastLba + ' guid=' + $hp.Guid + ' safety_net=' + $good)
    $manifest += (Emit-Blob $OutDir $n 'prim_hdr' $h $stamp)
    if ($pt) { $manifest += (Emit-Blob $OutDir $n 'prim_tab' $pt $stamp) }
    $manifest += (Emit-Blob $OutDir $n 'backup_hdr' $b $stamp)
    if ($bt) { $manifest += (Emit-Blob $OutDir $n 'backup_tab' $bt $stamp) }
  } catch {
    Add('  disk_EX=' + (ExText $_))
    $anyBad = $true
  }
}
try {
  [IO.File]::WriteAllLines($OutDir + '\gpt_manifest_' + $stamp + '.txt', $manifest, [Text.Encoding]::ASCII)
  Add('MANIFEST=' + $OutDir + '\gpt_manifest_' + $stamp + '.txt')
} catch { Add('manifest_EX=' + (ExText $_)) }
Add('GPTDUMP-COMPLETE outdir=' + $OutDir + ' copy it OFF the protected disk now')
if ($anyBad) { Add('RESULT=GPTDUMP-DAMAGED-SOURCE'); $rc = 2 } else { Add('RESULT=GPTDUMP-OK') }
Flush $OutDir
exit $rc
