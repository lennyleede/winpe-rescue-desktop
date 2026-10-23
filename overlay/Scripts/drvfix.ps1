# drvfix.ps1 -- offline SYSTEM-hive surgery on boot-critical driver services, for the rescue PE.
#
# Baked from the 2026-10-14 remote rescue drill scenario 2: 'Set-Service stornvme Disabled' on a
# live machine -> INACCESSIBLE_BOOT_DEVICE BSOD; the fix was reg load of the victim hive +
# ControlSet*\services\stornvme Start 4 -> 0. If the machine now lands on the Recovery intercept
# (0xc0000001) after this repair, that is the BOOTSTAT chain, not a failed fix - run bootfix.
#
# Drill lesson kept hard: every hive judgement goes through 'reg.exe query' OUTPUT parsing.
# Test-Path 'HKLM\OFFSYS' (colon missing) queries the FILESYSTEM and misreports a successful
# reg load as a failure - that was a real v1 failure in the drill.
#
# Usage (inside the PE, or over ssh):
#   drvfix                       survey: which services are Disabled(4) and boot-critical (ErrorControl=1)
#   drvfix -Service stornvme -SetStart 0     repair: rewrite Start in every ControlSet that has it
#   drvfix -ListDisabled          full disabled-service list (no ErrorControl filter)
# Start values: 0=Boot 1=System 2=Automatic 3=Manual 4=Disabled.
# Exit line: RESULT=DRVFIX-OK | DRVFIX-CHECK | DRVFIX-BAD-*
#
# ASCII output only. Evidence: X:\drvfix.txt + <winvol>:\Windows\Temp\rescue\drvfix_<stamp>.txt
param(
  [string]$WinVol = '',
  [string]$Service = '',
  [int]$SetStart = -1,
  [switch]$ListDisabled,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$lines = @()
function Add([string]$s) { $script:lines += $s }
function Rq($k, $v) {
  $r = @(& reg query $k $(if ($v) { '/v'; $v } else { $null }) 2>&1 | ForEach-Object { ('' + $_).Trim() })
  return (($r -join ' | ') -replace '\s+', ' ')
}
# 'reg query <key> /s /v <value>' block parser: HKEY path lines switch the current service name.
function Parse-SvcValues([string[]]$regout, [string]$value) {
  $map = @{}
  $cur = ''
  foreach ($ln in $regout) {
    $s = ('' + $ln).TrimEnd()
    if ($s -match '^HKEY_LOCAL_MACHINE\\.*\\Services\\([^\\]+)$') { $cur = $Matches[1]; continue }
    if ($cur -and $s -match ('^\s+' + $value + '\s+REG_DWORD\s+(\S+)')) { $map[$cur] = $Matches[1] }
  }
  return $map
}
function Flush([string]$winRoot) {
  $t = $lines -join "`r`n"
  try { [System.IO.File]::WriteAllText('X:\drvfix.txt', $t, [System.Text.Encoding]::ASCII) } catch {}
  if ($winRoot) {
    try {
      $dir = $winRoot + '\Temp\rescue'
      if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
      [System.IO.File]::WriteAllText($dir + '\drvfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt', $t, [System.Text.Encoding]::ASCII)
    } catch {}
  }
  $t | Write-Output
}

if ($SelfTest) {
  $ok = @()
  $sample = @('HKEY_LOCAL_MACHINE\OFFSYS\ControlSet001\Services\stornvme', '    Start    REG_DWORD    0x4', 'HKEY_LOCAL_MACHINE\OFFSYS\ControlSet001\Services\stornvme\Parameters', 'HKEY_LOCAL_MACHINE\OFFSYS\ControlSet001\Services\foo', '    Start    REG_DWORD    0x3')
  $m = Parse-SvcValues $sample 'Start'
  $ok += 'parse_stornvme=' + $m['stornvme'] + ' parse_foo=' + $m['foo']
  $ok += 'parse_ok=' + ($m['stornvme'] -eq '0x4' -and $m['foo'] -eq '0x3')
  $ok += 'bind: service=' + $Service + ' setstart=' + $SetStart + ' list=' + [bool]$ListDisabled
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
  if (-not $WinVol) { Add('RESULT=DRVFIX-BAD-NO-WINVOL'); Flush ''; exit 1 }
  $winRoot = $WinVol + ':\Windows'
  $hive = $winRoot + '\System32\config\SYSTEM'

  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  $dir = $winRoot + '\Temp\rescue'
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  if ($Service -and $SetStart -ge 0) {
    $bk = $dir + '\SYSTEM_drvfix_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.bin'
    Copy-Item -LiteralPath $hive $bk -Force
    Add('hive_backup=' + $bk + ' len=' + (Get-Item -LiteralPath $bk).Length)
  }
  $r = @(& reg.exe load 'HKLM\OFFSYS' $hive 2>&1 | ForEach-Object { ('' + $_) -replace '[^\x20-\x7E]', '' })
  Add('load_out=' + (($r -join ' ') -replace '\s+', ' '))
  if (-not ((Rq 'HKLM\OFFSYS\Select' 'Current') -match 'REG_DWORD')) {
    Add('RESULT=DRVFIX-BAD-LOAD')
    & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
    Flush $winRoot; exit 1
  }

  # active ControlSet from Select\Current (drill hardcoded 001; productized: resolved, 002 as fallback)
  $q = Rq 'HKLM\OFFSYS\Select' 'Current'
  $cur = ([regex]::Match($q, 'REG_DWORD\s+(\S+)')).Groups[1].Value
  $curNum = [Convert]::ToInt32($cur, $(if ($cur -match '^0x') { 16 } else { 10 }))
  $sets = @(('ControlSet{0:D3}' -f $curNum), 'ControlSet001', 'ControlSet002') | Select-Object -Unique
  Add('select_current=' + $cur + ' sets=' + ($sets -join ','))

  $done = 0
  foreach ($cs in $sets) {
    $csQ = Rq ('HKLM\OFFSYS\' + $cs) $null
    if ($csQ -match 'ERROR') { Add($cs + '=absent'); continue }
    $startMap = Parse-SvcValues @(& reg.exe query ('HKLM\OFFSYS\' + $cs + '\Services') /s /v Start 2>&1) 'Start'
    if ($Service) {
      $svcKey = 'HKLM\OFFSYS\' + $cs + '\Services\' + $Service
      $before = Rq $svcKey 'Start'
      if ($before -match 'REG_DWORD') {
        Add($cs + '.' + $Service + '.before=' + ([regex]::Match($before, 'REG_DWORD\s+(\S+)')).Groups[1].Value)
        $a = @(& reg.exe add $svcKey /v Start /t REG_DWORD /d $SetStart /f 2>&1 | ForEach-Object { '' + $_ })
        Add($cs + '.add_rc=' + $LASTEXITCODE)
        $after = ([regex]::Match((Rq $svcKey 'Start'), 'REG_DWORD\s+(\S+)')).Groups[1].Value
        Add($cs + '.' + $Service + '.after=' + $after)
        try {
          $an = [Convert]::ToUInt32(($after -replace '^0x', ''), 16)
          if ($an -eq [uint32]$SetStart) { $done++ }
        } catch { Add($cs + '.after_parse_fail=1') }
      } else { Add($cs + '.' + $Service + '=absent_or_err') }
    } else {
      # survey: Disabled(4) services; ErrorControl decides boot-criticality
      $ecMap = Parse-SvcValues @(& reg.exe query ('HKLM\OFFSYS\' + $cs + '\Services') /s /v ErrorControl 2>&1) 'ErrorControl'
      $dis = @($startMap.Keys | Where-Object { ([Convert]::ToInt32($startMap[$_], 16)) -eq 4 } | Sort-Object)
      Add($cs + '.disabled=' + $dis.Count)
      foreach ($n in $dis) {
        $ec = $ecMap[$n]
        $crit = ($ec -eq '0x1')
        if ($ListDisabled -or $crit) { Add($cs + '.DISABLED_CANDIDATE=' + $n + ' ErrorControl=' + $ec + ' boot_critical=' + $crit) }
      }
      Add('hint=' + $cs + ': a boot-start driver disabled here = INACCESSIBLE_BOOT_DEVICE; fix with -Service <name> -SetStart 0')
    }
  }
  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  Add('unload_rc=' + $LASTEXITCODE)

  if ($Service) {
    Add('RESULT=' + $(if ($done -gt 0) { 'DRVFIX-OK' } else { 'DRVFIX-BAD-NOT-FIXED' }))
  } else {
    Add('RESULT=DRVFIX-CHECK')
  }
  Flush $winRoot
} catch {
  Add('EXC=' + $_.Exception.Message)
  & reg.exe unload 'HKLM\OFFSYS' 2>&1 | Out-Null
  Add('RESULT=DRVFIX-BAD-EXC')
  Flush $winRoot
  exit 1
}
