# bootfix.ps1 -- UEFI boot reconstruction with the BOOTSTAT/Recovery cleanup chain, for the rescue PE.
#
# Baked from the 2026-10-14 remote rescue drill (docs\rescue-drill):
#   scenario 1: deleting \EFI\Microsoft (BCD lost, 0xc000000f) was fixed in one shot by
#               'bcdboot <win>:\Windows /s S: /f UEFI' after mounting the ESP by GPT type.
#   scenario 2 lesson (the expensive one): even after the ROOT CAUSE is repaired the machine can
#             still stop on the Recovery intercept (0xc0000001), because BOOTSTAT.DAT keeps the
#             boot-failure counters and they trigger BEFORE the fixed boot path runs. A boot repair
#             that does not clear this chain gets misdiagnosed as "the repair did not work".
#             So the cleanup chain below is ON by default: back up + delete BOOTSTAT.DAT,
#             then bootstatuspolicy=ignoreallfailures + recoveryenabled=no on the store BCD.
#
# Usage (inside the PE, or over ssh):
#   bootfix -Check      read-only survey: what is missing, what the repair would do
#   bootfix             run the repair (bcdboot rebuild + BOOTSTAT cleanup chain)
#   bootfix -SkipBootStatus   rebuild only, leave the failure counters alone
# Exit line the operator reads: RESULT=BOOTFIX-OK | BOOTFIX-INCOMPLETE | BOOTFIX-CHECK-ONLY
#
# ASCII output only (PE console and ssh sessions are CP936). Evidence:
#   X:\bootfix.txt  +  <winvol>:\Windows\Temp\rescue\bootfix_<stamp>.txt  (X: is a ramdisk, never
#   treat it as the only copy; Windows\Temp survives the reboot and is out of reach of drive-letter
#   faults).
param(
  [string]$WinVol = '',           # force the Windows volume letter (auto-detect when empty)
  [string]$EfiLetter = 'S',       # letter to attach the EFI system partition at
  [switch]$Check,                 # survey only, change nothing
  [switch]$SkipBootStatus,        # do not run the BOOTSTAT/Recovery cleanup chain
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += $s }
function Flush([string]$winRoot) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\bootfix.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($winRoot) {
    try {
      $dir = $winRoot + '\Temp\rescue'
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      [System.IO.File]::WriteAllText($dir + '\bootfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt', $t, [System.Text.Encoding]::ASCII)
    } catch {}
  }
  $t | Write-Output
}

if ($SelfTest) {
  $ok = @()
  $ok += 'efi_gpt_type_len=' + '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'.Length
  $ok += 'bind: check=' + [bool]$Check + ' skipbs=' + [bool]$SkipBootStatus + ' efi=' + $EfiLetter + ' winvol=' + $(if ($WinVol) { $WinVol } else { 'auto' })
  $ok += 'SELFTEST-OK'
  ($ok -join "`r`n") | Write-Output
  exit 0
}

Add('T=' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Add('HOST=' + $env:COMPUTERNAME + ' sysdrive=' + $env:SystemDrive)
try {
  # ---- 1) locate the offline Windows volume (winload.efi is the anchor; skip the PE ramdisk X:) ----
  if (-not $WinVol) {
    foreach ($d in @(Get-PSDrive -PSProvider FileSystem)) {
      if ($d.Name -eq 'X' -or $d.Name -eq $EfiLetter) { continue }
      if (Test-Path -LiteralPath ($d.Root + 'Windows\system32\winload.efi')) { $WinVol = $d.Name; break }
    }
  }
  Add('WINVOL=' + $WinVol)
  if (-not $WinVol) { Add('RESULT=BOOTFIX-BAD-NO-WINVOL'); Flush ''; exit 1 }
  $winRoot = $WinVol + ':\Windows'

  # ---- 2) mount the ESP idempotently (by GPT type, scanning every disk, not just disk 0) ----
  $E = $EfiLetter + ':'
  if (-not (Test-Path ($E + '\EFI'))) {
    foreach ($disk in @(Get-Disk -ErrorAction SilentlyContinue)) {
      $p = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
             Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })
      if ($p.Count -ge 1) {
        Add('efi_disk=' + $disk.Number + ' part=' + $p[0].PartitionNumber)
        Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $p[0].PartitionNumber -AccessPath ($E + '\')
        break
      }
    }
  }
  $efiOk = Test-Path ($E + '\EFI')
  Add('efi_mounted=' + $efiOk)
  if (-not $efiOk) { Add('RESULT=BOOTFIX-BAD-NO-ESP'); Flush $winRoot; exit 1 }

  $bcd  = $E + '\EFI\Microsoft\Boot\BCD'
  $boot = $E + '\EFI\Microsoft\Boot\bootmgfw.efi'
  $bs   = $E + '\EFI\Microsoft\Boot\BOOTSTAT.DAT'
  Add('pre_bcd=' + (Test-Path $bcd) + ' pre_bootmgfw=' + (Test-Path $boot) + ' pre_bootstat=' + (Test-Path $bs))

  if ($Check) {
    Add('CHECK: repair would run: bcdboot ' + $WinVol + ':\Windows /s ' + $EfiLetter + ': /f UEFI')
    if (-not $SkipBootStatus) {
      Add('CHECK: then BOOTSTAT chain: backup+delete BOOTSTAT.DAT, bootstatuspolicy=ignoreallfailures, recoveryenabled=no')
    }
    Add('RESULT=BOOTFIX-CHECK-ONLY')
    Flush $winRoot
    exit 0
  }

  # ---- 3) the real repair: bcdboot copies boot files and creates a fresh BCD on the ESP ----
  $bb = @(& bcdboot ($WinVol + ':\Windows') /s $EfiLetter /f UEFI 2>&1 | ForEach-Object { ('' + $_) -replace '[^\x20-\x7E]', '' })
  Add('bcdboot_out=' + (($bb -join ' / ') -replace '\s+', ' '))
  Add('bcdboot_rc=' + $LASTEXITCODE)

  # ---- 4) BOOTSTAT/Recovery cleanup chain (scenario-2 lesson; on unless -SkipBootStatus) ----
  $chainOk = $true
  if (-not $SkipBootStatus) {
    $dir = $winRoot + '\Temp\rescue'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    if (Test-Path $bs) {
      $bk = $dir + '\BOOTSTAT.DAT.bak'
      Copy-Item -LiteralPath $bs $bk -Force
      Remove-Item -LiteralPath $bs -Force
      Add('bootstat=deleted(backup ' + $bk + ')')
    } else { Add('bootstat=absent') }
    $e1 = @(& bcdedit /store $bcd /set '{default}' bootstatuspolicy ignoreallfailures 2>&1 | ForEach-Object { ('' + $_) -replace '[^\x20-\x7E]', '' })
    Add('policy_out=' + (($e1 -join ' ') -replace '\s+', ' ') + ' rc=' + $LASTEXITCODE)
    if ($LASTEXITCODE -ne 0) { $chainOk = $false }
    $e2 = @(& bcdedit /store $bcd /set '{default}' recoveryenabled no 2>&1 | ForEach-Object { ('' + $_) -replace '[^\x20-\x7E]', '' })
    Add('recov_out=' + (($e2 -join ' ') -replace '\s+', ' ') + ' rc=' + $LASTEXITCODE)
    if ($LASTEXITCODE -ne 0) { $chainOk = $false }
    $q3 = @(& bcdedit /store $bcd /enum '{default}' 2>&1 | ForEach-Object { ('' + $_) })
    foreach ($k in @('bootstatuspolicy', 'recoveryenabled')) {
      $hit = @($q3 | Select-String -SimpleMatch $k | Select-Object -First 1)
      Add('now[' + $k + ']=' + (('', ($hit | ForEach-Object { ('' + $_).Trim() })) -join ' '))
      if ($hit.Count -lt 1) { $chainOk = $false }
    }
  } else { Add('bootstat_chain=skipped') }

  # ---- 5) verify artifacts + fresh BCD content ----
  Add('post_bootmgfw=' + (Test-Path $boot))
  Add('post_bcd=' + (Test-Path $bcd))
  if (Test-Path $bcd) {
    $e = @(& bcdedit /store $bcd /enum all 2>&1 | ForEach-Object { '' + $_ })
    Add('bcd_enum_lines=' + $e.Count)
    foreach ($k in @('Windows Boot Manager', 'Windows Boot Loader', 'winload.efi', 'osdevice', 'default')) {
      $hit = @($e | Select-String -SimpleMatch $k | Select-Object -First 1)
      Add('has[' + $k + ']=' + ($hit.Count -gt 0))
    }
  }
  $good = (Test-Path $boot) -and (Test-Path $bcd) -and $chainOk
  Add('RESULT=' + $(if ($good) { 'BOOTFIX-OK' } else { 'BOOTFIX-INCOMPLETE' }))
  Flush $winRoot
} catch {
  Add('EXC=' + $_.Exception.Message)
  Add('RESULT=BOOTFIX-INCOMPLETE')
  Flush $(if ($WinVol) { $WinVol + ':\Windows' } else { '' })
  exit 1
}
