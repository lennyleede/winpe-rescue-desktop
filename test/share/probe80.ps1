# test/share/probe80.ps1
# Runs INSIDE the live PE. Goal: decide the material generation for the WiFi bake.
# The host (Win10 LTSC 19044) has wdiwifi.sys / NdisImPlatform.sys / ndiscap.sys and crypt32 says their
# covering catalogs are Microsoft-Windows-Client-Desktop-Required-Package04/05112 + Client-Features-Package0317.
# Package04 is already baked (it covers nwifi/vwififlt/vwifimp/vwifibus and, per the same lookup, wdiwifi).
# Question left open: is the laptop's OWN (D:) copy of those binaries byte-identical to the host copy?
# If yes, the 19041-era files are exactly what this machine's Windows runs with, and there is no
# generation-mismatch risk to argue about. Read-only: hashes, sizes, versions, offline hive build label.
$ErrorActionPreference = 'Continue'
function L([string]$m) { [Console]::Out.WriteLine($m) }
function Trim2([string]$s, [int]$n) { if ($s.Length -le $n) { return $s } return $s.Substring(0, $n) + '...' }

$D = 'D:\Windows'
$OFF = 'HKLM:\W8OFF'

L '=0 offline OS build label (D: volume)'
if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\W8OFF ($D + '\System32\config\SYSTEM') 2>&1 | ForEach-Object { (Trim2 ('' + $_) 120) })
  L ('  0 regload ' + ($rl -join '|'))
}
$cvx = $OFF + '\ControlSet001\Control\ContentIndex'
foreach ($k in @('SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ControlSet001\Control\Windows')) {
  $p = $OFF + '\' + $k
  if (-not (Test-Path -LiteralPath $p)) { L ('  0 ' + (Trim2 $k 50) + ' ABSENT'); continue }
  $ki = Get-Item -LiteralPath $p
  $vals = @()
  foreach ($vn in @('ProductName', 'CurrentBuildNumber', 'CurrentVersion', 'DisplayVersion', 'ReleaseId', 'BuildLab', 'BuildLabEx', 'UBR', 'InstallationType', 'PathName')) {
    $v = $ki.GetValue($vn)
    if ($null -ne $v) { $vals += ($vn + '=' + ('' + $v)) }
  }
  L ('  0 ' + (Trim2 $k 46) + ' ' + (Trim2 ($vals -join ' ') 240))
}
# Version from the shell binary is the most reliable cross-check
foreach ($exe in @('explorer.exe', 'cmd.exe')) {
  $pe2 = $D + '\System32\' + $exe
  if (Test-Path -LiteralPath $pe2) {
    $vi = (Get-Item -LiteralPath $pe2).VersionInfo
    L ('  0 ' + $exe + ' ' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart + ' prod=' + $vi.ProductVersion)
  } else { L ('  0 ' + $exe + ' MISSING') }
}

L '=1 candidate binaries: D: vs host bake list'
# host values measured 2026-10-10 on the workstation (Win10 IoT LTSC 2021, 10.0.19044.7725)
$exp = @{
  'wdiwifi.sys'        = @{ sha = '5121E6A646D43486140FE7A8E4DAF93ED4EF0DB8EA463FCC2DEBDE3C83AFBFF7'; bytes = 967168; cat = 'Package04' }
  'NdisImPlatform.sys' = @{ sha = '77D583B04B9554D355A0D9C7C5573786409B932ED44C32C03F3B073AB498FEB1'; bytes = 135168; cat = 'Package05112' }
  'ndiscap.sys'        = @{ sha = '22B7C50650C27F2D577D3C38B2EF60999746E579D541EE1E1521D025B1D7F730'; bytes = 60928; cat = 'Features-Package0317' }
  'nwifi.sys'          = @{ sha = ''; bytes = 758784; cat = 'Package04' }
  'vwififlt.sys'       = @{ sha = ''; bytes = 77824; cat = 'Package04' }
}
foreach ($n in @('wdiwifi.sys', 'NdisImPlatform.sys', 'ndiscap.sys', 'nwifi.sys', 'vwififlt.sys', 'vwifimp.sys', 'vwifibus.sys')) {
  $src = $D + '\System32\drivers\' + $n
  if (-not (Test-Path -LiteralPath $src)) { L ('  1 ' + $n + ' NO-D-COPY'); continue }
  $fi = Get-Item -LiteralPath $src
  $v = $fi.VersionInfo
  $h = ''
  $hh = @(& certutil.exe -hashfile $src SHA256 2>&1 | ForEach-Object { (Trim2 ('' + $_) 200) })
  foreach ($ln in $hh) { if ($ln -match '^[0-9a-fA-F]{20,}$') { $h = ($ln -replace '[^0-9a-fA-F]', '') } }
  $xe = 'X:\Windows\System32\drivers\' + $n
  $xstate = 'absent'
  if (Test-Path -LiteralPath $xe) { $xstate = ('present ' + (Get-Item -LiteralPath $xe).Length + 'B') }
  $e = $exp[$n]
  $same = '?'
  if ($e -and $e.sha -and $h) { if ($h.ToUpperInvariant() -eq $e.sha.ToUpperInvariant()) { $same = 'IDENTICAL-TO-HOST' } else { $same = 'DIFFERS-FROM-HOST' } }
  $diffsize = ''
  if ($e -and $fi.Length -ne $e.bytes) { $diffsize = ' sizeDiffer(d=' + $fi.Length + ' host=' + $e.bytes + ')' }
  L ('  1 ' + $n.PadRight(20) + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart +
     ' ' + $fi.Length + 'B sha=' + (Trim2 $h 20) + ' vs-host=' + $same + $diffsize + ' X:' + $xstate + ' cat=' + $(if ($e) { $e.cat } else { '-' }))
}

L '=2 Intel miniport in the laptop DriverStore (the one we must service)'
$ds = $D + '\System32\DriverStore\FileRepository'
if (Test-Path -LiteralPath $ds) {
  $hits = @(Get-ChildItem -LiteralPath $ds -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw|netrtw|rtcwifi' } | Select-Object -First 8)
  L ('  2 wifi-ish store dirs=' + $hits.Count)
  foreach ($d2 in $hits) {
    $sys = @(Get-ChildItem -LiteralPath $d2.FullName -Filter '*.sys' -File -EA SilentlyContinue)
    foreach ($s in $sys) {
      $v = $s.VersionInfo
      L ('  2 ' + (Trim2 $d2.Name 46) + ' ' + $s.Name + ' ' + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart + ' ' + $s.Length + 'B')
    }
  }
} else { L '  2 D: DriverStore MISSING' }
# the copy actually bound to the AX211 in this PE
$xds = 'X:\Windows\System32\DriverStore\FileRepository'
foreach ($d3 in @(Get-ChildItem -LiteralPath $xds -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw' })) {
  foreach ($s in @(Get-ChildItem -LiteralPath $d3.FullName -Filter '*.sys' -File -EA SilentlyContinue)) {
    $v = $s.VersionInfo
    L ('  2 X:' + (Trim2 $d3.Name 46) + ' ' + $s.Name + ' ' + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart + ' ' + $s.Length + 'B')
  }
}

L '=3 wdiwifi contract: exports of D: copy vs the ndis thunk it must satisfy'
foreach ($p in @($D + '\System32\drivers\wdiwifi.sys', 'X:\Windows\System32\drivers\wdiwifi.sys')) {
  if (-not (Test-Path -LiteralPath $p)) { L ('  3 ' + (Trim2 $p 46) + ' MISSING'); continue }
  $b = [IO.File]::ReadAllBytes($p)
  $txtU = [Text.Encoding]::Unicode.GetString($b)
  $mU = @([regex]::Matches($txtU, 'Wdi_Ndis[A-Za-z0-9_]*') | ForEach-Object { $_.Value }) | Sort-Object -Unique
  L ('  3 ' + (Trim2 $p 46) + ' ' + $b.Length + 'B Wdi_Ndis*=' + (Trim2 ($mU -join ',') 200))
  # NDIS version the framework claims, if the string table shows it
  $mN = @([regex]::Matches($txtU, 'NdisVersion[0-9A-Za-z_]*') | ForEach-Object { $_.Value }) | Sort-Object -Unique
  L ('  3   NdisVersion-ish=' + (Trim2 (($mN | Select-Object -First 6) -join ',') 140))
}
L 'P80 END'
