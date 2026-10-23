# gptfix.ps1 -- GPT partition-table survey/repair, the 5th tile of the rescue PE panel.
#
# Baked from the 2026-10-14 remote rescue drill scenario 4B (docs\rescue-drill, section 7):
#   lesson 1 (the expensive one): damaging ONE copy of the GPT is NOT a persistent fault - the
#     EDK2 firmware reloads it from the intact copy before the OS even loads (4B-min proved it).
#     The realistic emergency is BOTH copies gone, and then nothing on the disk is left to rebuild
#     from. So repair has exactly two sources and both live in this tool:
#       -Repair              rebuild the dead copy FROM THE INTACT ON-DISK OTHER COPY
#                            (primary-from-backup, or the mirror backup-from-primary);
#       -Repair -DumpDir D   restore byte-exact blobs captured BEFORE the fault by gptdump -
#                            the only source for the both-dead case. Keep dumps OFF the disk
#                            under repair (gap 14: evidence must survive the fault it guards).
#   lesson 2: the "protective MBR" can be purely nominal on real images (55AA signature but an
#     EMPTY partition array, no 0xEE entry), so there is no MBR fallback once GPT is unreadable -
#     and 0xEE must never be a precondition. Real MBR disks are classified and left alone.
#   lesson 3: repair writes RAW SECTORS, so it runs only in the PE (never against a live Windows),
#     only with the disk offline, and the verdict is the READBACK, never the write call.
#
# Usage (inside the PE, or over ssh):
#   gptfix                                  survey every disk: VERDICT lines + the repair command
#   gptfix -Repair -Disk 0                  in-disk rebuild (whichever copy died; idempotent)
#   gptfix -Repair -Disk 0 -DumpDir E:\rescue   gptdump restore (both-dead case)
#   ... add -Reboot to reboot into the restored system when the readback verifies.
# Exit line: RESULT=GPTFIX-OK | GPTFIX-CHECK | GPTFIX-BAD-*
#
# ASCII output only (CP936 console/ssh; Chinese exception text is crushed by Add()).
# Evidence: X:\gptfix.txt + <winvol>:\Windows\Temp\rescue\gptfix_<stamp>.txt (X: is a ramdisk).
param(
  [string]$WinVol = '',
  [int]$Disk = -1,
  [string]$DumpDir = '',
  [switch]$Repair,
  [switch]$Reboot,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += (('' + $s) -replace '[^\x20-\x7E]', '?') }
function Flush([string]$winRoot) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\gptfix.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($winRoot) {
    try {
      $dir = $winRoot + '\Temp\rescue'
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      [System.IO.File]::WriteAllText($dir + '\gptfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt', $t, [System.Text.Encoding]::ASCII)
    } catch {}
  }
  $t | Write-Output
}
function ExText($e) { return ((('' + $e.Exception.Message) + ' [' + $e.Exception.GetType().Name + ']') -replace '[^\x20-\x7E]', '?') }

# ---- raw sector / GPT primitives (all live-validated in the 4B drill) ----
# PowerShell variable names are CASE-INSENSITIVE: the backslash char is $BSL, never $BD/$bd -
# a drill round lost hours when $BD=[char]92 was silently overwritten by a later $bd=@(Get-Disk).
$BSL = [char]92
function DevPath([int]$n) { return ('' + $BSL + $BSL + '.' + $BSL + 'PhysicalDrive' + $n) }
function Crc32([byte[]]$data) {
  # Poly via hex parse. NEVER hand-decimalize: 0xEDB88320 = 3988292384 and PS5.1 reads a bare
  # hex literal above 0x7FFFFFFF as a NEGATIVE Int32.
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
  # buffer=512 explicit: the 4KB default over-reads past the last sector at the disk tail.
  $fs = [IO.FileStream]::new($dev, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite, 512)
  [void]$fs.Seek($byteOffset, [IO.SeekOrigin]::Begin)
  $buf = New-Object byte[] $len
  $got = 0
  while ($got -lt $len) { $n = $fs.Read($buf, $got, ($len - $got)); if ($n -le 0) { break }; $got += $n }
  $fs.Close()
  if ($got -ne $len) { throw ('short read ' + $got + '/' + $len) }
  return ,$buf
}
function Write-Sectors([int]$diskNum, [long]$byteOffset, [byte[]]$data) {
  $dev = DevPath $diskNum
  $fs = [IO.FileStream]::new($dev, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite, 512)
  [void]$fs.Seek($byteOffset, [IO.SeekOrigin]::Begin)
  $off = 0
  while ($off -lt $data.Length) { $rem = $data.Length - $off; $fs.Write($data, $off, $rem); $off += $rem }
  $fs.Flush(); $fs.Close()
}
function Md5Hex([byte[]]$data) {
  $h = [Security.Cryptography.MD5]::Create().ComputeHash($data)
  return (([BitConverter]::ToString($h)) -replace '-', '').ToLowerInvariant()
}
function BytesToHex([byte[]]$b) { return (([BitConverter]::ToString($b)) -replace '-', '') }
function HexToBytes([string]$hex) {
  $hex = ($hex -replace '[^0-9A-Fa-f]', '')
  if (($hex.Length % 2) -ne 0) { throw ('hex length not even: ' + $hex.Length) }
  $out = New-Object byte[] ($hex.Length / 2)
  for ($i = 0; $i -lt $out.Length; $i++) { $out[$i] = [byte][Convert]::ToUInt32($hex.Substring($i * 2, 2), 16) }
  return ,$out
}
function GetU64([byte[]]$b, [int]$o) { return [long][BitConverter]::ToUInt64($b, $o) }
function Set-U64([byte[]]$b, [int]$off, [long]$val) {
  $gb = [BitConverter]::GetBytes($val)
  [Array]::Copy($gb, 0, $b, $off, 8)
}
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
  $z = $true; foreach ($x in $b) { if ($x -ne 0) { $z = $false; break } }
  $g = New-Object byte[] 16; [Array]::Copy($b, 56, $g, 0, 16)
  $o | Add-Member NoteProperty Sig $sig
  $o | Add-Member NoteProperty Hsz $hsz
  $o | Add-Member NoteProperty CrcStored $stored
  $o | Add-Member NoteProperty CrcCalc $calc
  $o | Add-Member NoteProperty MyLba (GetU64 $b 24)
  $o | Add-Member NoteProperty AltLba (GetU64 $b 32)
  $o | Add-Member NoteProperty EntryLba (GetU64 $b 72)
  $o | Add-Member NoteProperty EntryCount ([long][BitConverter]::ToUInt32($b, 80))
  $o | Add-Member NoteProperty EntrySize ([long][BitConverter]::ToUInt32($b, 84))
  $o | Add-Member NoteProperty EntriesCrc ([long][BitConverter]::ToUInt32($b, 88))
  $o | Add-Member NoteProperty Guid ((New-Object Guid(, $g)).ToString().ToUpper())
  $o | Add-Member NoteProperty AllZero $z
  $o | Add-Member NoteProperty Md5 (Md5Hex $b)
  $o | Add-Member NoteProperty Valid (($sig -eq 'EFI PART') -and ($stored -eq $calc) -and ($hsz -eq 92))
  $o | Add-Member NoteProperty TabLen ($o.EntryCount * $o.EntrySize)
  return $o
}
function Stamp-Crc([byte[]]$h) {
  # zero the stored-CRC field, recompute over HeaderSize bytes, write it back in place
  $h[16] = 0; $h[17] = 0; $h[18] = 0; $h[19] = 0
  $hsz = [int][BitConverter]::ToUInt32($h, 12)
  if ($hsz -le 0 -or ($hsz -gt $h.Length)) { $hsz = 92 }
  $crc = [long](Crc32 ($h[0..($hsz - 1)]))
  $cb = [BitConverter]::GetBytes([uint32]$crc)
  [Array]::Copy($cb, 0, $h, 16, 4)
}
function New-PrimaryFromBackup([byte[]]$bakBytes, [long]$lastLba) {
  # Only MyLba/AltLba/PartitionEntryLBA differ between the copies (entries CRC and the usable-LBA
  # bounds carry over verbatim). Primary entries sit at LBA2 by spec.
  $h = New-Object byte[] 512
  [Array]::Copy($bakBytes, 0, $h, 0, 512)
  Set-U64 $h 24 1
  Set-U64 $h 32 $lastLba
  Set-U64 $h 72 2
  Stamp-Crc $h
  return ,$h
}
function New-BackupFromPrimary([byte[]]$priBytes, [long]$lastLba, [long]$bakEntryLba) {
  # the mirror path (rare in the field but symmetric): rebuild the backup from an intact primary
  $h = New-Object byte[] 512
  [Array]::Copy($priBytes, 0, $h, 0, 512)
  Set-U64 $h 24 $lastLba
  Set-U64 $h 32 1
  Set-U64 $h 72 $bakEntryLba
  Stamp-Crc $h
  return ,$h
}
function Test-AllZero([byte[]]$b) { foreach ($x in $b) { if ($x -ne 0) { return $false } }; return $true }
function Inspect-Disk([int]$diskNum, [long]$diskSize) {
  $ss = 512
  $r = New-Object PSObject
  $lastLba = [long][Math]::Floor($diskSize / $ss) - 1
  $r | Add-Member NoteProperty lastLba $lastLba
  $mbr = Read-Sectors $diskNum 0 $ss
  $r | Add-Member NoteProperty mbrSig ((($mbr[510] -eq 0x55) -and ($mbr[511] -eq 0xAA)))
  # protective-MBR truthfulness: real 0xEE entry vs the nominal signature some images carry.
  $ee = $false; $part = $false
  foreach ($i in 0..3) {
    $t = $mbr[446 + ($i * 16) + 4]
    if ($t -eq 0xEE) { $ee = $true } elseif ($t -ne 0) { $part = $true }
  }
  $r | Add-Member NoteProperty mbrEE $ee
  $r | Add-Member NoteProperty mbrHasPart $part
  $hp = Read-Sectors $diskNum $ss $ss
  $r | Add-Member NoteProperty hp (Get-Hdr $hp)
  $hb = Read-Sectors $diskNum ([long]$lastLba * $ss) $ss
  $r | Add-Member NoteProperty hb (Get-Hdr $hb)
  $r | Add-Member NoteProperty hpBytes $hp
  $r | Add-Member NoteProperty hbBytes $hb
  $r | Add-Member NoteProperty pTabOk $false
  $r | Add-Member NoteProperty bTabOk $false
  $r | Add-Member NoteProperty ptBytes $null
  $r | Add-Member NoteProperty btBytes $null
  if ($r.hp.Valid -and ($r.hp.TabLen -ge $ss) -and ($r.hp.TabLen -le 1MB)) {
    $r.ptBytes = Read-Sectors $diskNum ([long]$r.hp.EntryLba * $ss) ([int]$r.hp.TabLen)
    $r.pTabOk = ($r.hp.EntriesCrc -eq (Crc32 $r.ptBytes))
  }
  if ($r.hb.Valid -and ($r.hb.TabLen -ge $ss) -and ($r.hb.TabLen -le 1MB)) {
    $r.btBytes = Read-Sectors $diskNum ([long]$r.hb.EntryLba * $ss) ([int]$r.hb.TabLen)
    $r.bTabOk = ($r.hb.EntriesCrc -eq (Crc32 $r.btBytes))
  }
  return $r
}
function Get-Verdict($r) {
  $pOk = $r.hp.Valid; $bOk = $r.hb.Valid
  if ($pOk -and $bOk -and $r.pTabOk -and $r.bTabOk) { return 'GPT-HEALTHY' }
  if ((-not $pOk) -and $bOk -and $r.bTabOk) { return 'PRIMARY-LOST BACKUP-INTACT' }
  if ($pOk -and $r.pTabOk -and ((-not $bOk) -or (-not $r.bTabOk))) { return 'BACKUP-LOST PRIMARY-INTACT' }
  if ((-not $pOk) -and (-not $bOk)) {
    if ($r.mbrHasPart -and (-not $r.mbrEE)) { return 'MBR-DISK (no GPT here, leave alone)' }
    return 'BOTH-HEADERS-DEAD'
  }
  return 'UNCLASSIFIED'
}

# ---- gptdump file discovery (names: gpt_d<disk>_<kind>_<stamp>.(hex|bin)) ----
function Find-DumpFile([string]$dir, [int]$diskNum, [string]$kind) {
  $cands = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match ('^gpt_d' + $diskNum + '_' + $kind + '_[0-9_]+\.(hex|bin)$') } |
             Sort-Object Name)
  if ($cands.Count -lt 1) { return '' }
  return $cands[$cands.Count - 1].FullName
}
function Load-Blob([string]$path) {
  if ($path.ToLowerInvariant().EndsWith('.bin')) {
    return ,[IO.File]::ReadAllBytes($path)
  }
  $txt = [IO.File]::ReadAllText($path)
  return ,(HexToBytes $txt)
}

# ================================================================ SelfTest
if ($SelfTest) {
  Add('T=' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' MODE=SELFTEST (no disk access)')
  Add('DEVP=' + (DevPath 0) + ' expect=\\\\.\\PhysicalDrive0 ok=' + (((DevPath 0)) -eq ('\' + '\' + '.' + '\' + 'PhysicalDrive0')))
  $v = Crc32 ([Text.Encoding]::ASCII.GetBytes('123456789'))
  $vOk = ((('{0:X8}' -f $v)) -eq 'CBF43926')
  Add('CRC32_VECTOR=' + ('{0:X8}' -f $v) + ' expect=CBF43926 ok=' + $vOk)
  # real primary header captured off the drill VM (gptdump 19:03), padded to 512
  $fixture = '4546492050415254000001005C00000092424D1E000000000100000000000000FFFF7F07000000002200000000000000DEFF7F0700000000D6B231F216850E40A3C021DF5DB00FF202000000000000008000000080000000E808B1CB00000000'
  $prim = New-Object byte[] 512
  $fb = HexToBytes $fixture
  [Array]::Copy($fb, 0, $prim, 0, 96)
  $hp = Get-Hdr $prim
  $fOk = $hp.Valid -and ((('{0:X8}' -f $hp.CrcStored)) -eq '1E4D4292') -and ($hp.Guid -eq 'F231B2D6-8516-400E-A3C0-21DF5DB00FF2') -and
         ($hp.MyLba -eq 1) -and ($hp.AltLba -eq 125829119) -and ($hp.EntryLba -eq 2) -and ($hp.TabLen -eq 16384)
  Add('FIXTURE valid=' + $hp.Valid + ' crc=' + ('{0:X8}' -f $hp.CrcStored) + ' guid=' + $hp.Guid + ' ok=' + $fOk)
  # both rebuild directions must round-trip against the drill's real backup header CRC 90B3FAD9
  $bak = New-BackupFromPrimary $prim 125829119 (125829119 - 32)
  $hb = Get-Hdr $bak
  $bOk = $hb.Valid -and ($hb.MyLba -eq 125829119) -and ($hb.AltLba -eq 1) -and ($hb.EntryLba -eq 125829087) -and
         ((('{0:X8}' -f $hb.EntriesCrc)) -eq 'CBB108E8')
  Add('TO-BACKUP valid=' + $hb.Valid + ' crc=' + ('{0:X8}' -f $hb.CrcStored) + ' entryLba=' + $hb.EntryLba + ' ok=' + $bOk)
  $re = New-PrimaryFromBackup $bak 125829119
  $hr = Get-Hdr $re
  $same = $true
  for ($i = 0; $i -lt 96; $i++) { if ($re[$i] -ne $prim[$i]) { $same = $false } }
  $pOk = $hr.Valid -and ((('{0:X8}' -f $hr.CrcStored)) -eq '1E4D4292') -and $same
  Add('TO-PRIMARY valid=' + $hr.Valid + ' crc=' + ('{0:X8}' -f $hr.CrcStored) + ' bytes96=' + $same + ' ok=' + $pOk)
  # dump-file I/O: write a synthetic set into the temp dir and read it back through the resolver
  try {
    $td = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'gptfix_selftest_' + (Get-Date -Format 'HHmmss'))
    New-Item -ItemType Directory -Force -Path $td | Out-Null
    [IO.File]::WriteAllText(($td + '\gpt_d0_prim_hdr_20261014_190324.hex'), (BytesToHex $prim))
    [IO.File]::WriteAllText(($td + '\gpt_d0_prim_hdr_20261014_200000.hex'), (BytesToHex $bak))   # newer: must win
    [IO.File]::WriteAllBytes(($td + '\gpt_d0_backup_tab_20261014_190324.bin'), (New-Object byte[] 16384))
    $f1 = Find-DumpFile $td 0 'prim_hdr'
    $b1 = Load-Blob $f1
    $ioOk = ((Md5Hex $b1) -eq (Md5Hex $bak)) -and ($f1.EndsWith('200000.hex'))
    $f2 = Find-DumpFile $td 0 'backup_tab'
    $b2 = Load-Blob $f2
    $ioOk = $ioOk -and ($b2.Length -eq 16384) -and ((Find-DumpFile $td 0 'backup_hdr') -eq '')
    Add('DUMPIO newest=' + (Split-Path $f1 -Leaf) + ' hex_roundtrip=' + (((BytesToHex (HexToBytes (BytesToHex $prim))) -eq (BytesToHex $prim))) + ' ok=' + $ioOk)
    Remove-Item -LiteralPath $td -Recurse -Force
  } catch { Add('DUMPIO_EX=' + (ExText $_)); $ioOk = $false }
  $all = $vOk -and $fOk -and $bOk -and $pOk -and $ioOk
  Add('RESULT=' + $(if ($all) { 'GPTFIX-SELFTEST-OK' } else { 'GPTFIX-SELFTEST-BAD' }))
  Flush ''
  exit 0
}

Add('T=' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add('MODE=' + $(if ($Repair) { $(if ($DumpDir) { 'RESTORE-DUMP' } else { 'REPAIR-INDISK' }) } else { 'SURVEY' }))
Add('HOST=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
$sysd = '' + $env:SystemDrive
$isPe = ($sysd -eq 'X:') -or ($env:COMPUTERNAME -eq 'WINPE') -or (Test-Path 'X:\Windows\System32\winpeshl.ini')
Add('PE=' + $isPe)
if ($Repair -and (-not $isPe)) {
  Add('ABORT=REPAIR-PE-ONLY (raw sector writes must never run against a live Windows)')
  Add('RESULT=GPTFIX-BAD-GATE'); Flush ''; exit 1
}
# best-effort: put a copy of the log where the fault cannot reach it (may legitimately be none)
if (-not $WinVol) {
  foreach ($pd in @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
    if ($pd.Name -eq 'X') { continue }
    if (Test-Path -LiteralPath ($pd.Root + 'Windows\system32\winload.efi')) { $WinVol = $pd.Name; break }
  }
}
$winRoot = $(if ($WinVol) { $WinVol + ':\Windows' } else { '' })
Add('WINVOL=' + $(if ($WinVol) { $WinVol } else { '(none mounted)' }))

# ---- enumerate real disks (same filter as the drill: >1GB, not CD, not ramdisk) ----
$targets = @(Get-Disk -ErrorAction SilentlyContinue |
             Where-Object { ($_.Size -gt 1GB) -and ($_.FriendlyName -notmatch 'ramdisk') -and ($_.FriendlyName -notmatch 'CD') })
if ($Disk -ge 0) { $targets = @($targets | Where-Object { $_.Number -eq $Disk }) }
Add('disks_scanned=' + $targets.Count)
if ($targets.Count -lt 1) { Add('ABORT=NO-CANDIDATE-DISK'); Add('RESULT=GPTFIX-BAD-NODISK'); Flush $winRoot; exit 1 }

$ssz = 512
$inspect = @{}
$verdicts = @{}
foreach ($d in $targets) {
  $n = [int]$d.Number
  Add('--- disk=' + $n + ' name=' + $d.FriendlyName + ' size=' + $d.Size + ' style=' + $d.PartitionStyle +
      ' offline=' + $d.IsOffline + ' readonly=' + $d.IsReadOnly)
  try {
    $r = Inspect-Disk $n ([long]$d.Size)
    $inspect[$n] = $r
    Add('  prim: valid=' + $r.hp.Valid + ' sig=' + $r.hp.Sig + ' crc=' + ('{0:X8}' -f $r.hp.CrcStored) + '/' + ('{0:X8}' -f $r.hp.CrcCalc) +
        ' myLba=' + $r.hp.MyLba + ' altLba=' + $r.hp.AltLba + ' entryLba=' + $r.hp.EntryLba + ' guid=' + $r.hp.Guid + ' md5=' + $r.hp.Md5)
    Add('  prim_tab=' + $r.pTabOk + $(if ($r.ptBytes) { ' tab_md5=' + (Md5Hex $r.ptBytes) } else { '' }))
    Add('  back: valid=' + $r.hb.Valid + ' sig=' + $r.hb.Sig + ' crc=' + ('{0:X8}' -f $r.hb.CrcStored) + '/' + ('{0:X8}' -f $r.hb.CrcCalc) +
        ' myLba=' + $r.hb.MyLba + ' altLba=' + $r.hb.AltLba + ' entryLba=' + $r.hb.EntryLba + ' guid=' + $r.hb.Guid + ' md5=' + $r.hb.Md5)
    Add('  back_tab=' + $r.bTabOk + $(if ($r.btBytes) { ' tab_md5=' + (Md5Hex $r.btBytes) } else { '' }))
    Add('  mbr sig55AA=' + $r.mbrSig + ' ee=' + $r.mbrEE + ' has_other_part=' + $r.mbrHasPart +
        ' (ee=False with has_other_part=False means the MBR is nominal: no fallback, do NOT assert on it)')
    $vd = Get-Verdict $r
    $verdicts[$n] = $vd
    Add('  VERDICT=' + $vd)
    if ($vd -eq 'BOTH-HEADERS-DEAD') {
      # informational probe: the standard LBA2 table position, CRC unknowable without a header
      try {
        $probe = Read-Sectors $n ([long]2 * $ssz) 16384
        Add('  probe_lba2_tab md5=' + (Md5Hex $probe) + ' all_zero=' + (Test-AllZero $probe))
      } catch { Add('  probe_lba2_EX=' + (ExText $_)) }
      Add('  FIX_CMD=powershell -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\gptfix.ps1 -Repair -Disk ' + $n + ' -DumpDir <dir with gpt_d' + $n + '_*.hex/.bin (from a PRE-FAULT gptdump)')
    } elseif (($vd -eq 'PRIMARY-LOST BACKUP-INTACT') -or ($vd -eq 'BACKUP-LOST PRIMARY-INTACT')) {
      Add('  FIX_CMD=powershell -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\gptfix.ps1 -Repair -Disk ' + $n)
    }
  } catch { Add('  inspect_EX=' + (ExText $_)); $verdicts[$n] = 'INSPECT-FAILED' }
}

if (-not $Repair) {
  Add('RESULT=GPTFIX-CHECK')
  Add('NEXT=survey is read-only; a fix prints FIX_CMD above. SOP: capture gptdump bytes BEFORE any partition surgery.')
  Flush $winRoot
  exit 0
}

# ---- repair dispatch ----
if ($Disk -lt 0) {
  $fixable = @($verdicts.Keys | Where-Object { $verdicts[$_] -match '^(PRIMARY-LOST|BACKUP-LOST)' -or ($verdicts[$_] -eq 'BOTH-HEADERS-DEAD' -and $DumpDir) })
  if ($fixable.Count -ne 1) {
    Add('ABORT=DISK-AMBIGUOUS (pass -Disk N; fixable=' + ($fixable -join ',') + ')')
    Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
  }
  $Disk = [int]$fixable[0]
  Add('AUTO_DISK=' + $Disk + ' (exactly one fixable target)')
}
if (-not $verdicts.ContainsKey($Disk)) {
  Add('ABORT=DISK-' + $Disk + '-NOT-SCANNED'); Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
}
$cur = $inspect[$Disk]
$vd = $verdicts[$Disk]
Add('REPAIR_TARGET=' + $Disk + ' verdict=' + $vd)

if ($vd -eq 'GPT-HEALTHY') { Add('NOTE=already-healthy-idempotent-skip'); Add('RESULT=GPTFIX-OK'); Flush $winRoot; exit 0 }
if ($vd -eq 'MBR-DISK (no GPT here, leave alone)') { Add('ABORT=MBR-DISK-NOT-A-GPT-REPAIR'); Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1 }
if (($vd -eq 'BOTH-HEADERS-DEAD') -and (-not $DumpDir)) {
  Add('ABORT=BOTH-DEAD-NEED-DUMPDIR (a single surviving copy is required for in-disk rebuild;')
  Add('  otherwise the bytes must come from a pre-fault gptdump - gap 16)')
  Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
}
if ($vd -eq 'INSPECT-FAILED') { Add('ABORT=INSPECT-FAILED'); Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1 }

# ---- build the write plan from the chosen source ----
$planP = $null; $planPT = $null; $planB = $null; $planBT = $null   # bytes; $null = do not touch
if ($DumpDir) {
  Add('DUMPDIR=' + $DumpDir)
  if (-not (Test-Path -LiteralPath $DumpDir)) { Add('ABORT=DUMPDIR-MISSING'); Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1 }
  $kinds = @('prim_hdr', 'prim_tab', 'backup_hdr', 'backup_tab')
  $files = @{}
  $miss = @()
  foreach ($k in $kinds) {
    $f = Find-DumpFile $DumpDir $Disk $k
    if ($f -eq '') { $miss += $k } else { $files[$k] = $f }
  }
  if ($miss.Count -gt 0) {
    Add('ABORT=DUMPFILES-MISSING ' + ($miss -join ',') + ' (need gpt_d' + $Disk + '_<kind>_<stamp>.hex/.bin, all four kinds)')
    Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
  }
  foreach ($k in $kinds) {
    Add('dump[' + $k + ']=' + $files[$k] + ' md5=' + (Md5Hex (Load-Blob $files[$k])))
  }
  $planP  = Load-Blob $files['prim_hdr']
  $planPT = Load-Blob $files['prim_tab']
  $planB  = Load-Blob $files['backup_hdr']
  $planBT = Load-Blob $files['backup_tab']
  # source self-validation: everything below must hold before a single byte is written
  $dp = Get-Hdr $planP; $db = Get-Hdr $planB
  $gOk = $dp.Valid -and $db.Valid -and ($dp.Guid -eq $db.Guid)
  $geoOk = ($dp.MyLba -eq 1) -and ($dp.AltLba -eq $cur.lastLba) -and ($db.MyLba -eq $cur.lastLba) -and ($db.AltLba -eq 1)
  $lenOk = ($planP.Length -eq 512) -and ($planB.Length -eq 512) -and ($planPT.Length -eq $dp.TabLen) -and ($planBT.Length -eq $db.TabLen)
  $tabCrcOk = ((Crc32 $planPT) -eq $dp.EntriesCrc) -and ((Crc32 $planBT) -eq $db.EntriesCrc)
  $crcSameOk = ($dp.EntriesCrc -eq $db.EntriesCrc)
  Add('dump_selfcheck hdr_crc=' + $gOk + ' guid=' + $dp.Guid + ' geometry(altLba==lastLba=' + $cur.lastLba + ')=' + $geoOk +
      ' lengths=' + $lenOk + ' tab_crc=' + $tabCrcOk + ' crcs_agree=' + $crcSameOk)
  if (-not ($gOk -and $geoOk -and $lenOk -and $tabCrcOk -and $crcSameOk)) {
    Add('ABORT=DUMP-SELF-CHECK (dump is not valid, or belongs to another disk geometry)')
    Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
  }
  # idempotence: if the disk already carries these exact bytes, write nothing
  if ($cur.hp.Valid -and ($cur.hp.Md5 -eq (Md5Hex $planP)) -and $cur.hb.Valid -and ($cur.hb.Md5 -eq (Md5Hex $planB)) -and
      $cur.pTabOk -and $cur.bTabOk -and ((Md5Hex $cur.ptBytes) -eq (Md5Hex $planPT)) -and ((Md5Hex $cur.btBytes) -eq (Md5Hex $planBT))) {
    Add('NOTE=dump-bytes-already-on-disk-idempotent-skip')
    Add('RESULT=GPTFIX-OK'); Flush $winRoot; exit 0
  }
} else {
  # in-disk rebuild, either direction
  if ($vd -eq 'PRIMARY-LOST BACKUP-INTACT') {
    $planP  = New-PrimaryFromBackup $cur.hbBytes $cur.lastLba
    $planPT = $cur.btBytes
    Add('INDISK direction=primary-from-backup guid=' + $cur.hb.Guid + ' tabLen=' + $cur.hb.TabLen)
  } elseif ($vd -eq 'BACKUP-LOST PRIMARY-INTACT') {
    $bakEntryLba = [long]($cur.lastLba - [Math]::Ceiling($cur.hp.TabLen / $ssz))
    $planB  = New-BackupFromPrimary $cur.hpBytes $cur.lastLba $bakEntryLba
    $planBT = $cur.ptBytes
    Add('INDISK direction=backup-from-primary guid=' + $cur.hp.Guid + ' tabLen=' + $cur.hp.TabLen + ' bakEntryLba=' + $bakEntryLba)
  } else {
    Add('ABORT=VERDICT-NOT-REPAIRABLE-INDISK (' + $vd + ')'); Add('RESULT=GPTFIX-BAD-GATE'); Flush $winRoot; exit 1
  }
}

# ---- take the disk offline, write, read back, online ----
$dobj = Get-Disk -Number $Disk
$wasOffline = $dobj.IsOffline
$wentOffline = $false
try {
  if (-not $wasOffline) {
    Set-Disk -Number $Disk -IsOffline $true -ErrorAction Stop
    $wentOffline = $true
    Start-Sleep -Seconds 2
    Add('OFFLINE=set')
  } else { Add('OFFLINE=already') }
  if ($DumpDir) {
    Write-Sectors $Disk ([long]$ssz) $planP
    Write-Sectors $Disk ([long]((Get-Hdr $planP).EntryLba) * $ssz) $planPT
    Write-Sectors $Disk ([long]($cur.lastLba) * $ssz) $planB
    Write-Sectors $Disk ([long]((Get-Hdr $planB).EntryLba) * $ssz) $planBT
    Add('written: prim_hdr@LBA1 prim_tab@LBA' + (Get-Hdr $planP).EntryLba + ' back_hdr@LBA' + $cur.lastLba + ' back_tab@LBA' + (Get-Hdr $planB).EntryLba)
  } else {
    if ($vd -eq 'PRIMARY-LOST BACKUP-INTACT') {
      Write-Sectors $Disk ([long]2 * $ssz) $planPT
      Write-Sectors $Disk ([long]$ssz) $planP
      Add('written: prim_tab@LBA2=' + $planPT.Length + 'B prim_hdr@LBA1=' + $planP.Length + 'B')
    } else {
      $bakEntryLba = [long]((Get-Hdr $planB).EntryLba)
      Write-Sectors $Disk ([long]$bakEntryLba * $ssz) $planBT
      Write-Sectors $Disk ([long]($cur.lastLba) * $ssz) $planB
      Add('written: back_tab@LBA' + $bakEntryLba + '=' + $planBT.Length + 'B back_hdr@LBA' + $cur.lastLba + '=' + $planB.Length + 'B')
    }
  }
} catch {
  Add('write_EX=' + (ExText $_))
  Add('RESULT=GPTFIX-BAD-WRITE')
} finally {
  if ($wentOffline) {
    try { Set-Disk -Number $Disk -IsOffline $false -ErrorAction Stop | Out-Null; Add('ONLINE=restored') } catch { Add('online_EX=' + (ExText $_)) }
    try { Update-Disk -Number $Disk -ErrorAction SilentlyContinue | Out-Null } catch {}
  }
}

# ---- the verdict is the readback (nothing else counts) ----
try {
  $after = Inspect-Disk $Disk ([long](Get-Disk -Number $Disk).Size)
  $avd = Get-Verdict $after
  Add('AFTER prim=' + $after.hp.Valid + ' prim_tab=' + $after.pTabOk + ' back=' + $after.hb.Valid + ' back_tab=' + $after.bTabOk + ' VERDICT=' + $avd)
  Add('AFTER prim_md5=' + $after.hp.Md5 + ' back_md5=' + $after.hb.Md5)
  if ($DumpDir) {
    Add('AFTER dump_match prim=' + ($after.hp.Md5 -eq (Md5Hex $planP)) + ' back=' + ($after.hb.Md5 -eq (Md5Hex $planB)))
  }
  $parts = @(Get-Partition -DiskNumber $Disk -ErrorAction SilentlyContinue)
  Add('PART count=' + $parts.Count)
  foreach ($p in $parts) { Add('  part=' + $p.PartitionNumber + ' type=' + $p.Type + ' sizeGB=' + ('{0:N2}' -f ($p.Size / 1GB)) + ' letter=' + $(if ($p.DriveLetter) { $p.DriveLetter } else { '(none)' })) }
  if ($avd -eq 'GPT-HEALTHY') {
    Add('RESULT=GPTFIX-OK')
    if ($Reboot) { Add('REBOOT=wpeutil reboot in 5s'); Flush $winRoot; Start-Sleep -Seconds 5; & wpeutil.exe reboot; exit 0 }
  } else {
    Add('RESULT=GPTFIX-BAD-READBACK')
  }
} catch {
  Add('readback_EX=' + (ExText $_))
  Add('RESULT=GPTFIX-BAD-READBACK')
}
Flush $winRoot
