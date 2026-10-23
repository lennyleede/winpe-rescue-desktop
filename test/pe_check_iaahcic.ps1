# test/pe_check_iaahcic.ps1 -- runs INSIDE the live PE (pushed by host_push_run.ps1).
# Purpose: prove the newly baked iaAHCIC package is reachable by netdrvfix's runtime path,
# i.e. Resolve-InfList-style lookup finds it in FileRepository, its INF decodes, its declared
# files are next to it, and every ID the shipped stodrv_index.txt maps to iaahcic.inf really is
# declared by that runtime INF. ASCII output only (it travels through ssh + cmd).
$ErrorActionPreference = 'Continue'
$fr = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
$idx = Join-Path $env:SystemRoot 'System32\stodrv_index.txt'

function Read-InfText([string]$f) {
  $b = [IO.File]::ReadAllBytes($f)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
  return [Text.Encoding]::UTF8.GetString($b)
}
function Get-Ids([string]$t) {
  return @([regex]::Matches($t, '(?i)PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') |
    ForEach-Object { 'PCI\VEN_' + $_.Groups[1].Value.ToUpper() + '&DEV_' + $_.Groups[2].Value.ToUpper() } | Sort-Object -Unique)
}

Write-Output 'CHECK=1 index rows mapped to iaahcic.inf'
$idxIds = @()
if (Test-Path -LiteralPath $idx) {
  foreach ($ln in @([IO.File]::ReadAllLines($idx))) {
    $p = $ln -split "`t"
    if ($p.Count -ge 2 -and $p[1].Trim().ToLower() -eq 'iaahcic.inf') { $idxIds += $p[0].Trim().ToUpper() }
  }
}
Write-Output ('  INDEX_ID_COUNT=' + $idxIds.Count)
Write-Output ('  INDEX_IDS=' + (($idxIds | ForEach-Object { ($_ -split 'DEV_')[1] }) -join ' '))

Write-Output 'CHECK=2 runtime lookup of the package (what Resolve-InfList does)'
$dirs = @([IO.Directory]::GetDirectories($fr, 'iaahcic.inf_amd64_*'))
Write-Output ('  STORE_DIRS=' + $dirs.Count)
$infs = @()
foreach ($d in $dirs) { $infs += @([IO.Directory]::GetFiles($d, 'iaahcic.inf')) }
Write-Output ('  RUNTIME_INFS=' + $infs.Count)
foreach ($inf in $infs) {
  $dir = Split-Path -Parent $inf
  $t = Read-InfText $inf
  $dv = if ($t -match '(?im)^\s*DriverVer\s*=\s*([^\r\n]+)') { $matches[1].Trim() } else { '?' }
  $cls = if ($t -match '(?im)^\s*Class\s*=\s*(\S+)') { $matches[1] } else { '?' }
  $ids = @(Get-Ids $t)
  Write-Output ('  INF=' + $dir.Substring($dir.LastIndexOf('\') + 1) + ' DriverVer=' + $dv + ' Class=' + $cls + ' IDS=' + $ids.Count)
  # every [SourceDisksFiles*] declared file must be present, or drvload/pnputil would reject it here too
  $miss = @()
  $inSec = $false
  foreach ($ln in ($t -split "`r?`n")) {
    $l = $ln.Trim()
    if ($l -match '^\s*[\[\]]') { $inSec = ($l -match '(?i)^\[SourceDisksFiles(\.[^\]]*)?\]'); continue }
    if (-not $inSec -or $l -eq '' -or $l.StartsWith(';')) { continue }
    $n = ($l -split '=')[0].Trim().Trim('"')
    if ($n -match '[\\/]') { continue }
    if (-not (Test-Path -LiteralPath (Join-Path $dir $n))) { $miss += $n }
  }
  Write-Output ('  DECLARED_MISSING=' + $(if ($miss.Count) { ($miss -join ',') } else { 'none' }))
  if ($idxIds.Count -gt 0) {
    $notInInf = @($idxIds | Where-Object { $ids -notcontains $_ })
    $extra = @($ids | Where-Object { $idxIds -notcontains $_ })
    Write-Output ('  INDEX_IDS_NOT_DECLARED_BY_RUNTIME_INF=' + $(if ($notInInf.Count) { (($notInInf | ForEach-Object { ($_ -split 'DEV_')[1] }) -join ' ') } else { 'none' }))
    Write-Output ('  RUNTIME_IDS_NOT_IN_INDEX=' + $(if ($extra.Count) { (($extra | ForEach-Object { ($_ -split 'DEV_')[1] }) -join ' ') } else { 'none' }))
  }
}

Write-Output 'CHECK=3 published name and boot-critical placement'
Write-Output ('  SYSTEM32_DRIVERS_IASTORAC=' + $(if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\iaStorAC.sys')) { 'present' } else { 'absent (normal for a package with no matching device in the image; drvload reads it from FileRepository)'}))
Write-Output ('  OEM_INF_OEM154=' + $(if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'INF\oem154.inf')) { 'present' } else { 'absent'}))
Write-Output 'CHECK=4 storage verdict inputs still healthy'
$disks = @(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue | Where-Object { $_.Size -gt 0 })
Write-Output ('  DISKDRIVE_COUNT=' + $disks.Count)
foreach ($d in $disks) { Write-Output ('  DISK ' + (($d.DeviceID -split 'DET')[0]) + ' | ' + $d.Model + ' | bus=' + $d.InterfaceType) }
Write-Output 'PE_CHECK_IAAHCIC_DONE'
