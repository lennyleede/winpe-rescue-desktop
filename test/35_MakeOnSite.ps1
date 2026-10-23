# 35_MakeOnSite.ps1 - assemble the on-site (pre-bake) storage validation folder for the USB stick.
#
# The seven Intel storage packages in overlay\Drivers\Storage are deliberately not baked into the ISO
# yet (Step 2 waits for a hot drvload proof on a real 11th-15th gen machine). This builds the drop-in
# folder you copy onto the SAME stick that boots the PE: <stick>\OnSite_1008\{onsite.cmd,Tools,Storage,rescue}.
#
#   powershell -File test\35_MakeOnSite.ps1              # build dist\OnSite_1008
#   powershell -File test\35_MakeOnSite.ps1 -SelfTest     # report only, write nothing
#
# Normal permissions. Nothing here touches D:\winpe_build or any ISO.
param(
  [string]$SrcDrv  = 'overlay\Drivers\Storage',
  [string]$SrcScr  = 'overlay\Scripts',
  [string]$OutDir  = 'dist\OnSite_1008',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'

$tools = @('onsite.ps1','rescue.ps1','rescue.cmd','storageprobe.ps1','storageprobe.cmd',
           'niccheck.ps1','niccheck.cmd','netdrvfix.ps1','netdrvfix.cmd','fw_off.ps1','pe_getdriver.ps1')

if (-not (Test-Path -LiteralPath $SrcDrv)) { throw ('missing ' + $SrcDrv) }
if (-not (Test-Path -LiteralPath $SrcScr)) { throw ('missing ' + $SrcScr) }

$pkgs = @(Get-ChildItem -LiteralPath $SrcDrv -Directory)
$size = [int64]0
foreach ($f in @(Get-ChildItem -LiteralPath $SrcDrv -File -Recurse)) { $size += $f.Length }
Write-Output ('SOURCE drivers = ' + $pkgs.Count + ' packages, ' + [math]::Round($size/1MB,1) + ' MB')
$missing = @($tools | Where-Object { -not (Test-Path -LiteralPath (Join-Path $SrcScr $_)) })
if ($missing.Count) { Write-Output ('  WARN tools missing: ' + ($missing -join ' ')) }
$have = @($tools | Where-Object { Test-Path -LiteralPath (Join-Path $SrcScr $_) })
Write-Output ('SOURCE tools   = ' + $have.Count + ' files')

if ($SelfTest) {
  Write-Output 'SELFTEST: would write'
  Write-Output ('  ' + $OutDir + '\onsite.cmd')
  Write-Output ('  ' + $OutDir + '\README.txt')
  Write-Output ('  ' + $OutDir + '\Tools\ (' + ($have -join ' ') + ')')
  Write-Output ('  ' + $OutDir + '\Storage\ (' + (($pkgs | ForEach-Object { $_.Name }) -join ' ') + ')')
  Write-Output 'SELFTEST = OK (nothing written)'
  exit 0
}

$root = Join-Path $OutDir 'Tools'
$dst  = Join-Path $OutDir 'Storage'
if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $root  -Force | Out-Null
New-Item -ItemType Directory -Path $dst   -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutDir 'rescue') -Force | Out-Null

foreach ($t in $have) { Copy-Item -LiteralPath (Join-Path $SrcScr $t) -Destination (Join-Path $root $t) -Force }
Copy-Item -LiteralPath (Join-Path $SrcScr 'onsite.cmd') -Destination (Join-Path $OutDir 'onsite.cmd') -Force
foreach ($p in $pkgs) { Copy-Item -LiteralPath $p.FullName -Destination (Join-Path $dst $p.Name) -Recurse -Force }

# README for whoever boots the stick: ASCII + CRLF so PE cmd / Notepad read it cleanly.
$readme = @(
'ON-SITE STORAGE DRIVER VALIDATION + EVIDENCE BUNDLE'
'===================================================='
''
'WHAT IS IN HERE'
'  Storage\   7 WHQL Intel storage packages (VMD / RST / VROC), not baked into the ISO yet'
'  Tools\     onsite / rescue / storageprobe / niccheck / netdrvfix scripts'
'  onsite.cmd one command: probe, drvload the package that matches this machine, probe again,'
'             then write the full evidence bundle into rescue\ on this stick'
''
'HOW TO GET IT ONTO THE BOOTS'
'  Burn the PE ISO with Rufus as usual, then copy this whole folder to the stick root. Nothing'
'  else changes. 16 MB total, no single file is near the 4 GB FAT32 limit.'
''
'RUN IT (PE, plain cmd)'
'  1) find the letter the PE gave this stick:'
'       for %d in (c d e f g) do @if exist %d:\OnSite_1008\Storage\iaStorVD_20.2.4.1019\iaStorVD.inf @echo STICK=%d'
'     (if the folder sits at the stick root instead, drop the OnSite_1008\ part)'
'  2) cd /d <letter>:\OnSite_1008   then   onsite.cmd'
'  3) the answer is the last block of <letter>:\OnSite_1008\rescue\onsite.log:'
'       SYSDISK = ok (C:\) | missing      <- can this PE reach the installed Windows'
'       BOUND   = <inf>      | none        <- which package took the controller'
'       DISKS   = n before -> m after'
''
'SWITCHES'
'  onsite.cmd -SkipRescue    driver test only (fast)'
'  onsite.cmd -SkipDrvload   evidence only, touches no driver'
'  onsite.cmd -InfDir <dir>  force a single package folder'
''
'BIOS NOTE'
'  This test is only meaningful with VMD enabled (Intel 11th gen and newer ship it on by default).'
'  If BIOS is set to plain AHCI there is no VMD devnode at all, and onsite says so: that machine'
'  never needed a storage driver. AMD RAIDXpert2 cannot be covered this way - its catalog INF is'
'  root-enumerated and binds no PCI id; switch BIOS to AHCI or fetch the vendor package on site.'
''
'SEND IT BACK OVER frp? (only if you have no other way off the machine)'
'  Keep the zip under 50 MB: the frp uplink measures ~2.7 Mbps, so 50 MB is ~2.5 minutes. Use'
'  rescue -SkipHives  or  -SkipEvents  for a text-only bundle. On the stick itself size is free.'
''
'ORDER OF WORK'
'  Network first, storage second: run niccheck / netdrvfix before anything else if the NIC is bare,'
'  because without an IP there is no remote channel to send any of this anywhere.'
)
Set-Content -LiteralPath (Join-Path $OutDir 'README.txt') -Value $readme -Encoding ASCII

$n = @(Get-ChildItem -LiteralPath $OutDir -Recurse -File)
$bytes = [int64]0
foreach ($f in $n) { $bytes += $f.Length }
Write-Output ('OUT ' + $OutDir + ' = ' + $n.Count + ' files, ' + [math]::Round($bytes/1MB,1) + ' MB')
Write-Output '  root: onsite.cmd README.txt Tools\ Storage\ rescue\'
Write-Output 'LARGEST FILE = ' + ((($n | Sort-Object Length -Descending | Select-Object -First 1).Name) + ' (FAT32 needs <4096MB per file)')
Write-Output 'READY = copy dist\OnSite_1008 onto the boot stick, then run onsite.cmd inside the PE'
