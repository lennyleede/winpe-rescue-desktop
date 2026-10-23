$ErrorActionPreference = 'Continue'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Output ("Admin=" + $IsAdmin)
Get-Service vmms, vmcompute, VHDMount -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("Service: " + $_.Name + " = " + $_.Status) }
$mod = Get-Module -ListAvailable HyperV
if ($mod) { Write-Output "HyperV module: available" } else { Write-Output "HyperV module: NOT FOUND" }
if ($mod) {
  Import-Module HyperV -ErrorAction SilentlyContinue
  $vms = Get-VM -ErrorAction SilentlyContinue
  Write-Output ("Existing VM count: " + ($vms | Measure-Object).Count)
  $vms | ForEach-Object { Write-Output ("VM: " + $_.Name + " [" + $_.Status + "]") }
  Write-Output ("VHD path: " + (Get-VMHost).VirtualHardDiskPath)
  Write-Output ("Switches:")
  Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("  " + $_.Name + " [" + $_.SwitchType + "]") }
}
