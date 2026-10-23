# filefix.ps1 -- offline system-file repair as a three-rung ladder, for the rescue PE.
#
# Baked from the 2026-10-14 remote rescue drill scenario 3 (userinit.exe body overwritten):
#   rung 1  offline sfc:  sfc /scannow /offbootdir=W:\ /offwindir=W:\Windows /offlogfile=<X:\log>
#           WITHOUT /offlogfile there is NO diagnostic detail at all in PE (the victim CBS.log
#           belongs to old online sessions; the PE run does not write into it).
#   the wall: nonSxS components (userinit.exe and friends) have their WinSxS "repair source" as a
#           HARDLINK to the System32 body - corrupting one corrupts both, and sfc honestly reports
#           'source file in store is also corrupted' and cannot reproject. rc=0 does NOT mean fixed.
#   rung 2  restore from a verified baseline backup by rewriting the SHARED file record:
#           Copy-Item truncates and rewrites in place, so the hardlink survives and BOTH ends heal.
#           (del-then-copy breaks the link and leaves a fake "store still corrupt" fault.)
#           Then undo ACL damage: icacls /setowner TrustedInstaller + /reset.
#   rung 3  run sfc once more as an INDEPENDENT verifier - the verdict belongs to sfc, not to the
#           restore action. Expect 'did not find any integrity violations'.
#
# Usage (inside the PE, or over ssh):
#   filefix -Check          rung 1 only: diagnose and list what sfc cannot fix by itself
#   filefix                 rung 1; if violations found and no source given, prints NEEDS-SOURCE
#   filefix -RestoreDir E:\backup   rungs 1-3 with the baseline backups
# One offline sfc pass took ~255 s on the drill VM - budget minutes, and X: logs are ramdisk-only.
# Exit line: RESULT=FILEFIX-OK | FILEFIX-CLEAN | FILEFIX-NEEDS-SOURCE | FILEFIX-INCOMPLETE
#
# ASCII output only. Evidence: X:\filefix.txt + <winvol>:\Windows\Temp\rescue\filefix_<stamp>.txt
param(
  [string]$WinVol = '',
  [string]$RestoreDir = '',
  [switch]$Check,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += $s }
$TiOwner = '*S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'   # TrustedInstaller

# Read an sfc/CBS log the byte-order-safe way: these files are often UTF-16LE, reading them as ANSI
# yields mojibake with '?' between characters (drill lesson).
function Read-OffLog([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return @() }
  $raw = [System.IO.File]::ReadAllBytes($path)
  $enc = 'Default'
  if ($raw.Length -ge 2 -and $raw[0] -eq 0xFF -and $raw[1] -eq 0xFE) { $enc = 'Unicode' }
  elseif ($raw.Length -ge 2 -and ($raw[0] -eq 0xFE -and $raw[1] -eq 0xFF)) { $enc = 'Unicode' }
  elseif ($raw.Length -ge 3 -and $raw[0] -eq 0xEF -and $raw[1] -eq 0xBB -and $raw[2] -eq 0xBF) { $enc = 'UTF8' }
  return @(Get-Content -LiteralPath $path -Encoding $enc -ErrorAction SilentlyContinue)
}
function Sfc-Pass([string]$tag, [string]$winRoot, [string]$offlog) {
  Remove-Item $offlog -Force -ErrorAction SilentlyContinue
  $sfc = Join-Path $env:SystemRoot 'System32\sfc.exe'
  # bootdir = the volume root of the offline Windows: strip the trailing '\Windows'.
  # (2026-10-14 PE finding: without this, /offbootdir gets a bare '\' -> CBS
  #  RtlConvertWin32FilePathToNtFilePath STATUS_INVALID_PARAMETER, sfc dies in 1 s with rc=1.)
  $w = ($winRoot -replace '\\Windows$', '')
  $t0 = Get-Date
  $p = Start-Process -FilePath $sfc `
        -ArgumentList ('/scannow /offbootdir=' + $w + '\ /offwindir=' + $winRoot + ' /offlogfile=' + $offlog) `
        -NoNewWindow -PassThru -Wait
  Add($tag + '_rc=' + $p.ExitCode + ' elapsed_s=' + [int]((Get-Date) - $t0).TotalSeconds)
  $txt = Read-OffLog $offlog
  # the console verdict line ('did not find any integrity violations') is NOT written into the CBS
  # offlog - judge from CBS content: the transaction must complete, and no corruption markers.
  $doneC  = @($txt | Select-String -SimpleMatch 'Verify complete').Count -gt 0
  $wall  = @($txt | Select-String -SimpleMatch 'source file in store is also corrupted').Count -gt 0
  $corrupt = @($txt | Select-String -SimpleMatch 'Found corrupt files', 'Could not reproject', 'Total Detected Corruption').Count -gt 0
  $clean = $doneC -and (-not $wall) -and (-not $corrupt)
  Add($tag + '_verify_complete=' + $doneC)
  $det   = @($txt | Select-String -SimpleMatch 'Found corrupt files', 'Total Detected Corruption' | Select-Object -Last 4)
  foreach ($h in $det) { Add($tag + '| ' + (('' + $h) -replace '[^\x20-\x7E]', '')) }
  $rep = @($txt | Select-String -SimpleMatch 'Could not reproject')
  foreach ($h in $rep) { Add($tag + '| ' + (('' + $h) -replace '[^\x20-\x7E]', '')) }
  # file list sfc could not reproject: '\??\C:\Windows\System32\\userinit.exe' style hits
  $bad = @()
  foreach ($h in @($txt | Select-String -Pattern '\\\?\?\\(.{2,200}?)(;|source file)' )) {
    $m = [regex]::Matches(('' + $h), '\\\?\?\\([A-Za-z]:\\[^\s;]+)')
    foreach ($x in $m) { $bad += $x.Groups[1].Value }
  }
  $bad = @($bad | Select-Object -Unique)
  return @{ rc = $p.ExitCode; clean = $clean; wall = $wall; bad = $bad }
}
function Map-ToOffline([string]$path, [string]$winRoot) {
  # \??\C:\Windows\System32\userinit.exe -> <WinVol>:\Windows\System32\userinit.exe
  return ($winRoot + ( ($path -replace '^[A-Za-z]:\\Windows', '') -replace '\\\\', '\' ))
}
function Flush([string]$winRoot) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\filefix.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($winRoot) {
    try {
      $dir = $winRoot + '\Temp\rescue'
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      [System.IO.File]::WriteAllText($dir + '\filefix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt', $t, [System.Text.Encoding]::ASCII)
    } catch {}
  }
  $t | Write-Output
}

if ($SelfTest) {
  $ok = @()
  $ok += 'ti_owner_sid_len=' + $TiOwner.Length
  $map = Map-ToOffline 'C:\Windows\System32\\userinit.exe' 'C:\Windows'
  $ok += 'map_test=' + $map
  $ok += 'map_ok=' + ($map -eq 'C:\Windows\System32\userinit.exe')
  $ww = ('C:\Windows' -replace '\\Windows$', '')
  $ok += 'bootdir_test=' + $ww + ' ok=' + ($ww -eq 'C:')
  if ($RestoreDir) { $ok += 'restore_dir=' + $RestoreDir + ' exists=' + (Test-Path $RestoreDir) }
  $ok += 'SELFTEST-OK'
  ($ok -join "`r`n") | Write-Output
  exit 0
}

Add('T=' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Add('HOST=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
try {
  if (-not $WinVol) {
    foreach ($d in @(Get-PSDrive -PSProvider FileSystem)) {
      if ($d.Name -eq 'X') { continue }
      if (Test-Path -LiteralPath ($d.Root + 'Windows\system32\winload.efi')) { $WinVol = $d.Name; break }
    }
  }
  Add('WINVOL=' + $WinVol)
  if (-not $WinVol) { Add('RESULT=FILEFIX-BAD-NO-WINVOL'); Flush ''; exit 1 }
  $winRoot = $WinVol + ':\Windows'

  # ---- rung 1: diagnose with offline sfc (always with /offlogfile!) ----
  $r1 = Sfc-Pass 'SFC1' $winRoot ('X:\cbs_off1_' + (Get-Date -Format 'HHmmss') + '.log')
  Add('rung1: clean=' + $r1.clean + ' store_wall=' + $r1.wall + ' unreprojectable=' + $r1.bad.Count)

  if ($Check) {
    foreach ($f in $r1.bad) { Add('check_file=' + $f) }
    Add('RUN_CMD=powershell -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\filefix.ps1 -RestoreDir <drive:\baseline>')
    Add('RESULT=FILEFIX-CHECK-ONLY')
    Flush $winRoot
    exit 0
  }

  if ($r1.clean) { Add('RESULT=FILEFIX-CLEAN'); Flush $winRoot; exit 0 }

  # ---- rung 2: restore the shared file record from verified backups ----
  if (-not $RestoreDir -or -not (Test-Path -LiteralPath $RestoreDir)) {
    foreach ($f in $r1.bad) { Add('need_source=' + (Split-Path -Leaf $f)) }
    Add('HINT=nonSxS store copies are hardlinks; sfc alone cannot fix these. Give -RestoreDir with baseline backups.')
    Add('RESULT=FILEFIX-NEEDS-SOURCE')
    Flush $winRoot
    exit 1
  }
  $restored = 0
  foreach ($f in $r1.bad) {
    $leaf = Split-Path -Leaf $f
    $src = Join-Path $RestoreDir $leaf
    $dst = Map-ToOffline $f $winRoot
    if (-not (Test-Path -LiteralPath $src)) { Add('skip=' + $leaf + ' (no backup in ' + $RestoreDir + ')'); continue }
    if ((Get-Item -LiteralPath $src).Length -lt 64) { Add('skip=' + $leaf + ' (backup too small)'); continue }
    # Copy-Item opens+truncates the existing file: the hardlink to WinSxS survives and both ends heal.
    Copy-Item -LiteralPath $src -Destination $dst -Force
    $h1 = (Get-FileHash -LiteralPath $src -Algorithm MD5).Hash.ToLower()
    $h2 = (Get-FileHash -LiteralPath $dst -Algorithm MD5).Hash.ToLower()
    Add('restore=' + $leaf + ' md5_match=' + ($h1 -eq $h2))
    if ($h1 -ne $h2) { continue }
    $o1 = & icacls.exe $dst /setowner $TiOwner /C /Q 2>&1
    $o2 = & icacls.exe $dst /reset /C /Q 2>&1
    Add('acl=' + $leaf + ' setowner_done=1 reset_done=1')
    $restored++
  }
  Add('rung2_restored=' + $restored)

  # ---- rung 3: sfc again as the independent verifier ----
  $r3 = Sfc-Pass 'SFC2' $winRoot ('X:\cbs_off2_' + (Get-Date -Format 'HHmmss') + '.log')
  Add('rung3: clean=' + $r3.clean + ' store_wall=' + $r3.wall)
  $good = $r3.clean
  Add('RESULT=' + $(if ($good) { 'FILEFIX-OK' } else { 'FILEFIX-INCOMPLETE' }))
  Flush $winRoot
} catch {
  Add('EXC=' + $_.Exception.Message)
  Add('RESULT=FILEFIX-INCOMPLETE')
  Flush $(if ($WinVol) { $WinVol + ':\Windows' } else { '' })
  exit 1
}
