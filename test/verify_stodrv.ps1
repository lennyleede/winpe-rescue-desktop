param(
  [string]$DrvDir = 'overlay\Drivers\Storage',
  # VMD controllers Intel ships enabled-by-default in BIOS on 11th-15th gen. If one of these is
  # missing from every package, a machine of that generation will boot the PE with no visible disk.
  # A282/A382 = Intel RST RAID (HDC class) on 300/400-series - disks also vanish without it.
  # 2826/2827/282F = RST-VROC / workstation RAID.
  [string]$ExpectIds = 'PCI\VEN_8086&DEV_9A0B,PCI\VEN_8086&DEV_467F,PCI\VEN_8086&DEV_A77F,PCI\VEN_8086&DEV_7D0B,PCI\VEN_8086&DEV_AD0B,PCI\VEN_8086&DEV_B06F,PCI\VEN_8086&DEV_A282,PCI\VEN_8086&DEV_2826',
  [switch]$Quiet
)
$ErrorActionPreference = 'Continue'

# Acceptance gate for the storage driver material collected in Step 1.
# Run before touching build.ps1: it answers "is every package complete and signed, and which
# PCI ids would still boot blind?"

function Out2([string]$s) { if (-not $Quiet) { Write-Output $s } }
function Read-InfText([string]$f) {
  $b = [IO.File]::ReadAllBytes($f)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
  }
  return [Text.Encoding]::UTF8.GetString($b)
}
# Every file a [SourceDisksFiles*] section declares must sit next of the inf, otherwise
# DISM /Add-Driver refuses that package with the useless message
# "Error - An error occurred. The driver package could not be installed."
# (2026-10-08: iaAHCIC 17.11.3.1010 lost exactly this way -- the inf declares RstMwService.exe +
#  RstMwEventLogMsg.dll, the pool dir had only iaStorAC.sys, so 6 of 7 storage drivers got in and
#  the AHCI/HDC family was silently absent from the ISO. This gate is the reason it can't repeat.)
function Get-DeclaredFiles([string]$t) {
  # collect every [SourceDisksFiles...] variant, then keep only what setup API would read for x64
  $sets = @{}
  $sec = ''
  foreach ($ln in ($t -split "`r?`n")) {
    $l = $ln.Trim()
    if ($l -match '^\s*[\[\]]') {
      $m = [regex]::Match($l, '(?i)^\[SourceDisksFiles(|\.[^\]]*)\]$')
      $sec = $(if (-not $m.Success) { '' } elseif ($m.Groups[1].Value) { $m.Groups[1].Value.ToLower() } else { 'base' })
      if ($sec) { if (-not $sets.ContainsKey($sec)) { $sets[$sec] = @{} } }
      continue
    }
    if (-not $sec) { continue }
    if ($l -eq '' -or $l.StartsWith(';')) { continue }
    $n = ($l -split '=')[0].Trim().Trim('"')
    if ($n -notmatch '[\\/]' -and $n.Length) { $sets[$sec][$n.ToUpper()] = 1 }
  }
  # arch-specific wins outright (that is what the x64 PE/setup path uses); the unqualified
  # [SourceDisksFiles] is only the fallback when no amd64 section exists.
  $pick = @($sets.Keys | Where-Object { $_ -match '^\.(amd64|ntamd64|nt\.amd64)' })
  if ($pick.Count -eq 0 -and $sets.ContainsKey('base')) { $pick = @('base') }
  $out = @{}
  foreach ($p in $pick) { foreach ($k in @($sets[$p].Keys)) { $out[$k] = 1 } }
  return @($out.Keys | Sort-Object)
}

$fails = @()
$warns = @()
$allIds = @{}
$pkgs = @()

if (-not (Test-Path -LiteralPath $DrvDir)) {
  Write-Output ('FAIL drvdir missing: ' + $DrvDir)
  exit 1
}
foreach ($d in @([IO.Directory]::GetDirectories((Resolve-Path $DrvDir)))) {
  $name = [IO.Path]::GetFileName($d)
  $infs = @([IO.Directory]::GetFiles($d, '*.inf'))
  Out2 ('PKG ' + $name)
  if ($infs.Count -eq 0) { $fails += ($name + ': no .inf'); continue }
  if ($infs.Count -gt 1) { $warns += ($name + ': ' + $infs.Count + ' infs (expect 1)') }
  foreach ($inf in $infs) {
    $t = Read-InfText $inf
    $base = [IO.Path]::GetFileName($inf)
    $cls = if ($t -match '(?im)^\s*Class\s*=\s*(\S+)') { $matches[1] } else { '' }
    $dv  = if ($t -match '(?im)^\s*DriverVer\s*=\s*([^\r\n]+)') { $matches[1].Trim() } else { '' }
    $cat = if ($t -match '(?im)^\s*CatalogFile(?:\.NTamd64)?\s*=\s*(\S+)') { [IO.Path]::GetFileName($matches[1]) } else { '' }
    $ids = @([regex]::Matches($t, '(?i)PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') |
      ForEach-Object { 'PCI\VEN_' + $_.Groups[1].Value.ToUpper() + '&DEV_' + $_.Groups[2].Value.ToUpper() } |
      Sort-Object -Unique)
    $rootOnly = ($t -match '(?i)\$rootstr\$|\{[0-9a-f-]{36}\}\\')
    if ($cls -eq 'SCSIAdapter' -and $ids.Count -eq 0 -and -not $rootOnly) { $warns += ($base + ': SCSIAdapter but no PCI ids parsed') }
    Out2 ('  class=' + $cls + '  DriverVer=' + $dv + '  cat=' + $cat + '  ids=' + $ids.Count + $(if ($rootOnly -and $ids.Count -eq 0) { '  (root-enumerated only)' } else { '' }))
    Out2 ('  ids: ' + ($ids -join ' '))
    if ($cat) {
      $catPath = Join-Path $d $cat
      if (Test-Path -LiteralPath $catPath) { Out2 ('  cat present: ' + (Get-Item -LiteralPath $catPath).Length + 'B') }
      else { $warns += ($base + ': catalog file ' + $cat + ' missing next to inf') }
    } else { $warns += ($base + ': no CatalogFile entry') }
    # --- completeness gate: DISM refuses a package whose declared files are not all in the dir ---
    $declared = @(Get-DeclaredFiles $t)
    $absent = @($declared | Where-Object { -not (Test-Path -LiteralPath (Join-Path $d $_)) })
    Out2 ('  [SourceDisksFiles] declared=' + $declared.Count + ' absent=' + $absent.Count)
    if ($absent.Count) { $fails += ($name + '\' + $base + ': declares but does not contain ' + ($absent -join ',') + '  -- DISM /Add-Driver will reject this package') }
    foreach ($bn in @($declared | Where-Object { $_ -match '\.(SYS|DLL|EXE)$' })) {
      $bp = Join-Path $d $bn
      if (-not (Test-Path -LiteralPath $bp)) { continue }
      $s = Get-AuthenticodeSignature -LiteralPath (Resolve-Path -LiteralPath $bp).ProviderPath
      if ($s.Status -ne 'Valid') { $warns += ($name + '\' + $bn + ': signature ' + $s.Status) }
    }
    foreach ($i in $ids) {
      if (-not $allIds.ContainsKey($i)) { $allIds[$i] = @() }
      $allIds[$i] += ($base + '@' + $dv)
    }
    $pkgs += [pscustomobject]@{ Name=$name; Inf=$base; Class=$cls; Ver=$dv; Ids=$ids }
  }
  foreach ($f in @([IO.Directory]::GetFiles($d))) {
    $ext = [IO.Path]::GetExtension($f).ToLower()
    if ($ext -notin @('.inf', '.cat', '.sys', '.dll', '.exe', '.tm', '.bin')) { $warns += ('unexpected file ' + [IO.Path]::GetFileName($f)) }
  }
}

Write-Output ''
Write-Output ('COVERAGE total distinct pci ids = ' + $allIds.Count)
$expect = @($ExpectIds -split ',' | Where-Object { $_.Trim().Length })
$miss = @()
foreach ($e in $expect) {
  $k = $e.Trim().ToUpper()
  if ($allIds.ContainsKey($k)) { Write-Output ('  EXPECT ' + $k + ' = covered by ' + (($allIds[$k] | Select-Object -Unique) -join ' / ')) }
  else { $miss += $k; Write-Output ('  EXPECT ' + $k + ' = MISSING') }
}
if ($miss.Count) { $fails += ('uncovered ids: ' + ($miss -join ' ')) }

Write-Output ''
Write-Output ('WARNINGS = ' + $warns.Count)
foreach ($w in $warns) { Write-Output ('  warn: ' + $w) }
Write-Output ('FAILURES = ' + $fails.Count)
foreach ($f in $fails) { Write-Output ('  FAIL: ' + $f) }
if ($fails.Count) { Write-Output 'RESULT = NOT READY'; exit 1 }
Write-Output 'RESULT = READY'
exit 0
