$ErrorActionPreference = 'Continue'
$peRoot = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64'
Write-Output '=== PE amd64 top level (with sizes) ==='
Get-ChildItem $peRoot -Force -EA SilentlyContinue | ForEach-Object { Write-Output ("  {0,-10} {1,15:N0} {2}" -f $_.Mode, $_.Length, $_.Name) }
Write-Output '=== search winpe.wim / boot.wim under the ADK PE dir (any depth) ==='
Get-ChildItem $peRoot -Recurse -Include '*.wim' -File -EA SilentlyContinue | ForEach-Object { Write-Output ("  {0,15:N0} {1} {2}" -f $_.Length, $_.LastWriteTime, $_.FullName) }
Write-Output '=== Media dir ==='
Get-ChildItem (Join-Path $peRoot 'Media') -Force -EA SilentlyContinue | ForEach-Object { Write-Output ("  {0,-10} {1,15:N0} {2}" -f $_.Mode, $_.Length, $_.Name) }
Write-Output '=== our project build media (from last copype) ==='
$b = 'D:\QoderProject\国内版\生成winpe\build\WinPE_amd64'
Get-ChildItem $b -Force -EA SilentlyContinue | ForEach-Object { Write-Output ("  {0,-10} {1,15:N0} {2}" -f $_.Mode, $_.Length, $_.Name) }
Get-ChildItem (Join-Path $b 'media\sources') -Force -EA SilentlyContinue | ForEach-Object { Write-Output ("  {0,-10} {1,15:N0} {2}" -f $_.Mode, $_.Length, $_.Name) }
Write-Output '=== version of ADK boot files (bootmgr) ==='
foreach ($f in @((Join-Path $peRoot 'Media\bootmgr'), 'C:\Windows\System32\bootmgr.exe')) {
  if (Test-Path $f) { $v=(Get-Item $f).VersionInfo; Write-Output ("  " + $f + " -> " + $v.FileVersion) }
}
Write-Output '=== DISM info on our current boot.wim ==='
$w = Join-Path $b 'media\sources\boot.wim'
if (Test-Path $w) { & dism.exe /Get-WimInfo /WimFile:$w 2>&1 | ForEach-Object { Write-Output ('  ' + $_) } }
