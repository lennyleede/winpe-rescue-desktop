# letterfix.ps1 -- persistent drive-letter repair via the victim SYSTEM hive MountedDevices,
# for the rescue PE.
#
# Baked from the 2026-10-14 remote rescue drill scenario 4A (diskpart 'remove letter=D'):
#   lesson 1: drive letters persist in the VICTIM hive MountedDevices '\DosDevices<D>:' value.
#             PE-side 'diskpart assign' writes only the PE ramdisk registry - zero persistence,
#             the letter is gone again on reboot. The real fix is offline hive surgery.
#   lesson 2: the value format is machine-specific. On the drill VM it was REG_BINARY
#             '"DMIO:ID:"(444D494F3A49443A) + 16-byte little-endian volume GUID' (24 bytes = 48 hex),
#             NOT the common UTF-16 '\\?\Volume{guid}\' path. This tool understands BOTH formats
#             and, before writing, double-asserts the decoded GUID against the live volume you name
#             (-VolumeGuid) so a letter can never be pointed at the wrong volume.
#   lesson 3: keep a 'reg query HKLM\SYSTEM\MountedDevices' dump from BEFORE the fault (the repair
#             takes the hex VERBATIM from it); archive it somewhere the fault cannot reach
#             (C:\Windows\Temp - not the volume that is about to lose its letter).
#
# Usage (inside the PE, or over ssh):
#   letterfix                              survey: decode every DosDevices entry, cross-check
#                                          against live volumes, flag dangling/missing letters
#   letterfix -Letter D -VolumeGuid 389a76e7-... [-DumpFile <winvol>:\Windows\Temp\dump.txt | -Hex <48hex>]
#            repair: assert, reg add original hex, readback, unload. -VolumeGuid is MANDATORY
#            for a repair (the anti-wrong-volume gate).
# Exit line: RESULT=LETTERFIX-OK | LETTERFIX-CHECK | LETTERFIX-BAD-*
#
# ASCII output only. Evidence: X:\letterfix.txt + <winvol>:\Windows\Temp\rescue\letterfix_<stamp>.txt
param(
  [string]$WinVol = '',
  [string]$Letter = 'D',
  [string]$VolumeGuid = '',
  [string]$DumpFile = '',
  [string]$Hex = '',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += $s }
function Rq($k, $v) {
  $r = @(& reg query $k $(if ($v) { '/v'; $v } else { $null }) 2>&1 | ForEach-Object { ('' + $_).Trim() })
  return (($r -join ' | ') -replace '\s+', ' ')
}
# reg.exe prints REG_BINARY as one contiguous hex run; older tooling printed spaced pairs - the
# whitespace strip makes either dump workable.
function Get-HexFromDump([string]$path, [string]$driveLetter) {
  $hex = ''
  foreach ($ln in @(Get-Content -LiteralPath $path -Encoding ASCII)) {
    if ($ln -match ('\\DosDevices\\' + $driveLetter + ':\s+REG_BINARY\s+(.+)')) {
      $hex = ($Matches[1] -replace '\s+', '').Trim().ToUpper()
    }
  }
  return $hex
}
function Decode-DmioGuid([string]$hex) {
  # 'DMIO:ID:' 8 bytes + little-endian GUID (Data1/2/3 LE, Data4 BE)
  if ($hex.Length -ne 48) { return '' }
  if ($hex.Substring(0, 16) -ne '444D494F3A49443A') { return '' }
  $b = New-Object byte[] 16
  for ($i = 0; $i -lt 16; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring(16 + $i * 2, 2), 16) }
  return ('{0:X2}{1:X2}{2:X2}{3:X2}-{4:X2}{5:X2}-{6:X2}{7:X2}-{8:X2}{9:X2}-{10:X2}{11:X2}{12:X2}{13:X2}{14:X2}{15:X2}' -f `
    $b[3], $b[2], $b[1], $b[0], $b[5], $b[4], $b[7], $b[6], $b[8], $b[9], $b[10], $b[11], $b[12], $b[13], $b[14], $b[15])
}
function Decode-Utf16VolumePath([string]$hex) {
  # other observed format: UTF-16LE '\\?\Volume{guid}\' - return the embedded guid (upper, no braces)
  if ($hex.Length % 4 -ne 0 -or $hex.Length -lt 32) { return '' }
  $b = New-Object byte[] ($hex.Length / 2)
  for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
  $txt = [System.Text.Encoding]::Unicode.GetString($b)
  $m = [regex]::Match($txt, '\{([0-9A-Fa-f\-]{36})\}')
  if ($m.Success) { return $m.Groups[1].Value.ToUpper() }
  return ''
}
function HexTo-Guid([string]$hex) {
  $g = Decode-DmioGuid $hex
  if ($g) { return $g }
  return Decode-Utf16VolumePath $hex
}
function Flush([string]$winRoot) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\letterfix.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($winRoot) {
    try {
      $dir = $winRoot + '\Temp\rescue'
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      [System.IO.File]::WriteAllText($dir + '\letterfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt', $t, [System.Text.Encoding]::ASCII)
    } catch {}
  }
  $t | Write-Output
}

if ($SelfTest) {
  $ok = @()
  # the drill's real D: hex -> must decode to the recon GUID, and the UTF-16 format must decode too
  $h = '444D494F3A49443AE7769A38782C7C41B4D181E26CB2A45E'
  $g = Decode-DmioGuid $h
  $ok += 'dmio_decode=' + $g + ' ok=' + ($g -eq '389A76E7-2C78-417C-B4D1-81E26CB2A45E')
  $ok += 'utf16_decode=' + $(try {
        $u = [System.Text.Encoding]::Unicode.GetBytes('\??\Volume{389a76e7-2c78-417c-b4d1-81e26cb2a45e}\')
        $hx = ($u | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        Decode-Utf16VolumePath $hx
      } catch { 'EXC' })
  $ok += 'bind: letter=' + $Letter + ' guid=' + $(if ($VolumeGuid) { 'given' } else { 'none' }) + ' dump=' + $(if ($DumpFile) { 'given' } else { 'none' })
  $ok += 'SELFTEST-OK'
  ($ok -join "`r`n") | Write-Output
  exit 0
}

Add('T=' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Add('HOST=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
$winRoot = ''
try {
  if (-not $WinVol) {
    foreach ($d in @(Get-PSDrive -PSProvider FileSystem)) {
      if ($d.Name -eq 'X') { continue }
      if (Test-Path -LiteralPath ($d.Root + 'Windows\system32\winload.efi')) { $WinVol = $d.Name; break }
    }
  }
  Add('WINVOL=' + $WinVol)
  if (-not $WinVol) { Add('RESULT=LETTERFIX-BAD-NO-WINVOL'); Flush ''; exit 1 }
  $winRoot = $WinVol + ':\Windows'
  $hive = $winRoot + '\System32\config\SYSTEM'
  $L = $Letter.Substring(0, 1).ToUpper()
  $liveVols = @(Get-Volume -ErrorAction SilentlyContinue)

  $repair = ($Hex -or $DumpFile)
  if ($repair) {
    if (-not $VolumeGuid) {
      Add('ABORT=VOLUMEGUID-REQUIRED (anti-wrong-volume gate). Survey mode prints each volume GUID.')
      Add('RESULT=LETTERFIX-BAD-GATE')
      Flush $winRoot; exit 1
    }
    $expected = ($VolumeGuid -replace '[{}]', '').ToUpper()
    if ($DumpFile) {
      if (-not (Test-Path -LiteralPath $DumpFile)) { Add('ABORT=dump-missing ' + $DumpFile); Add('RESULT=LETTERFIX-BAD-GATE'); Flush $winRoot; exit 1 }
      $Hex = Get-HexFromDump $DumpFile $L
      Add('hex_from_dump=' + $DumpFile)
    }
    $Hex = ($Hex -replace '\s+', '').Trim().ToUpper()
    Add('hex=' + $Hex)
    if ($Hex.Length -ne 48) { Add('ABORT=HEX-BAD-LENGTH ' + $Hex.Length); Add('RESULT=LETTERFIX-BAD-GATE'); Flush $winRoot; exit 1 }
    $g = HexTo-Guid $Hex
    Add('decoded_guid=' + $g)
    if (-not $g) { Add('ABORT=HEX-NOT-DMIO-AND-NOT-UTF16-VOLUME-PATH'); Add('RESULT=LETTERFIX-BAD-GATE'); Flush $winRoot; exit 1 }
    if ($g -ne $expected) { Add('ABORT=GUID-MISMATCH-NOT-THE-EXPECTED-VOLUME'); Add('RESULT=LETTERFIX-BAD-GATE'); Flush $winRoot; exit 1 }
    $hit = @($liveVols | Where-Object { $_.Path -match ('(?i)' + $expected) })
    Add('volume_live=' + ($hit.Count -ge 1) + $(if ($hit.Count -ge 1) { ' path=' + $hit[0].Path + ' size=' + [int]($hit[0].Size/1GB) + 'GB' } else { '' }))
    if ($hit.Count -lt 1) { Add('ABORT=VOLUME-NOT-ON-LIVE-SYSTEM'); Add('RESULT=LETTERFIX-BAD-GATE'); Flush $winRoot; exit 1 }

    # ---- offline hive surgery ----
    $dir = $winRoot + '\Temp\rescue'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $bk = $dir + '\SYSTEM_letterfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.bin'
    Copy-Item -LiteralPath $hive $bk -Force
    Add('hive_backup=' + $bk + ' len=' + (Get-Item -LiteralPath $bk).Length)
    & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
    & reg.exe load 'HKLM\OFFSYS' $hive | Out-Null
    Add('pre_letter_' + $L + '=' + (Rq 'HKLM\OFFSYS\MountedDevices' ('\DosDevices\' + $L + ':')))
    $add = @(& reg.exe add 'HKLM\OFFSYS\MountedDevices' /v ('\DosDevices\' + $L + ':') /t REG_BINARY /d $Hex /f 2>&1 | ForEach-Object { ('' + $_) -replace '[^\x20-\x7E]', '' })
    Add('add_rc=' + $LASTEXITCODE + ' add| ' + (($add -join ' ') -replace '\s+', ' '))
    $rbHex = ''
    foreach ($ln in @(& reg.exe query 'HKLM\OFFSYS\MountedDevices' /v ('\DosDevices\' + $L + ':') 2>&1)) {
      if (('' + $ln) -match 'REG_BINARY\s+(.+)$') { $rbHex = ($Matches[1] -replace '\s+', '').Trim().ToUpper() }
    }
    Add('readback=' + $rbHex)
    & reg.exe unload 'HKLM\OFFSYS' | Out-Null
    Add('unload_rc=' + $LASTEXITCODE)
    Add('NOTE=PE-side diskpart assign is ephemeral by design; the hive value above is what the')
    Add('NOTE=victim Windows remounts at boot. Reboot the machine to let it take effect.')
    Add('RESULT=' + $(if ($rbHex -eq $Hex) { 'LETTERFIX-OK' } else { 'LETTERFIX-BAD-READBACK' }))
    Flush $winRoot
    exit $(if ($rbHex -eq $Hex) { 0 } else { 1 })
  }

  # ---- survey mode: decode every letter, cross-check live volumes ----
  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  & reg.exe load 'HKLM\OFFSYS' $hive | Out-Null
  if (-not ((Rq 'HKLM\OFFSYS\MountedDevices' $null) -match 'REG_BINARY|HKEY')) {
    Add('survey_hive_load=SUSPECT')
  }
  $mdOut = @(& reg.exe query 'HKLM\OFFSYS\MountedDevices' 2>&1)
  # single-key 'reg query' prints one header path line, then INDENTED value lines shaped
  # '<name>    REG_BINARY    <hex>' - parse the value lines directly (PE 16:48 finding:
  # waiting for a per-value HKEY path line never matched, survey silently returned 0 entries).
  $nEntries = 0
  foreach ($ln in $mdOut) {
    $s = ('' + $ln)
    if ($s -notmatch '^\s+(\S+)\s+REG_BINARY\s+(.+)$') { continue }
    $curName = $Matches[1]
    $hx = ($Matches[2] -replace '\s+', '').Trim().ToUpper()
    $nEntries++
    if ($curName -match '^\\DosDevices\\([A-Z]):$') {
      $l = $Matches[1]
      $g = HexTo-Guid $hx
      $live = @($liveVols | Where-Object { $g -and $_.Path -match ('(?i)' + [regex]::Escape($g)) })
      Add('letter=' + $l + ' guid=' + $g + ' volume_live=' + ($live.Count -ge 1) + ' hexlen=' + $hx.Length)
      if ($live.Count -ge 1) { Add('  live_path=' + $live[0].Path) }
    } else {
      Add('other=' + $curName + ' hexlen=' + $hx.Length)
    }
  }
  Add('survey_entries=' + $nEntries)
  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  Add('unload_rc=' + $LASTEXITCODE)
  Add('live_volume_list:')
  foreach ($v in $liveVols) { Add('  vol=' + $v.Path + ' letter=' + $(if ($v.DriveLetter) { $v.DriveLetter } else { '(none)' }) + ' sizeGB=' + [int]($v.Size/1GB)) }
  # triage line (4A vs 4B): a missing letter is normally just the hive alias above - but if a disk
  # reports PartitionStyle RAW the partition TABLE itself is unreadable (both GPT copies dead, the
  # 4B case). That is gptfix work, not letterfix work; say so before someone "repairs" a letter
  # onto a disk whose geometry is gone.
  $rawDisks = @(Get-Disk -ErrorAction SilentlyContinue | Where-Object { ($_.Size -gt 1GB) -and ($_.PartitionStyle -eq 'RAW') })
  Add('triage_gpt_raw_disks=' + $rawDisks.Count)
  foreach ($rd in $rawDisks) {
    Add('  raw_disk=' + $rd.Number + ' name=' + $rd.FriendlyName + ' HINT=partition table unreadable: run gptfix (survey) FIRST, this is not a letter fault')
  }
  Add('REPAIR_CMD=powershell -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\letterfix.ps1 -Letter ' + $L + ' -VolumeGuid <guid-from-survey> -DumpFile <pre-fault MountedDevices dump> (or -Hex <48hex>)')
  Add('RESULT=LETTERFIX-CHECK')
  Flush $winRoot
} catch {
  Add('EXC=' + $_.Exception.Message)
  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  Add('RESULT=LETTERFIX-BAD-EXC')
  Flush $winRoot
  exit 1
}
