# Host-side WiFi-stack reference dump (ASCII output). Run on the build host, no admin needed
# unless a registry path says ACCESS. Purpose: give the PE probe a "known good" comparison.
$ErrorActionPreference = 'Continue'
function Sec($t) { Write-Output ''; Write-Output ("==== " + $t + " ====") }

Sec 'HOST_OS'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
Write-Output ('  Caption       : ' + (Get-CimInstance Win32_OperatingSystem).Caption)
Write-Output ('  Version       : ' + $cv.CurrentMajorVersionNumber + '.' + $cv.CurrentMinorVersionNumber + '.' + $cv.CurrentBuildNumber + '.' + $cv.UBR)
Write-Output ('  DisplayVersion: ' + $cv.DisplayVersion)
Write-Output ('  Branch        : ' + $cv.ReleaseId)

Sec 'STACK_FILES_ON_HOST'
foreach ($f in @('wlanapi.dll','wlansvc.dll','wlancfg.dll','wlanmsm.dll','wlanext.exe','wlansec.dll','wlanutil.dll','wlansvcpal.dll','wlanhlp.dll','wcmsvc.dll','dmcmnutils.dll','mdmregistration.dll','wci.dll','netshell.dll','netsh.exe','drivers\nwifi.sys','drivers\ndisuio.sys')) {
  $p = Join-Path $env:SystemRoot ("System32\" + $f)
  if (Test-Path -LiteralPath $p) {
    $vi = (Get-Item -LiteralPath $p).VersionInfo
    Write-Output ('  OK   ' + $f.PadRight(22) + ' v=' + $vi.FileVersion + ' size=' + (Get-Item -LiteralPath $p).Length)
  } else {
    Write-Output ('  MISS ' + $f)
  }
}

Sec 'SERVICE_KEYS_ON_HOST'
foreach ($svc in @('Wlansvc','Wcmsvc','nwifi','NdisCap')) {
  $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
  if (-not (Test-Path $k)) { Write-Output ("  " + $svc + ": NO KEY"); continue }
  $v = Get-ItemProperty $k
  Write-Output ('  ' + $svc + ' ImagePath = ' + $v.ImagePath)
  Write-Output ('  ' + $svc + ' Start=' + $v.StartType + ' Type=' + $v.Type + ' Depend=' + ($v.DependOnService -join ',') + ' SvcDll=' + $v.Parameters.ServiceDll)
}

Sec 'NETSH_HELPERS_ON_HOST'
$nk = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $nk) {
  (Get-Item $nk).GetValueNames() | ForEach-Object {
    Write-Output ('  ' + $_ + ' = ' + (Get-ItemProperty $nk).'$_')
  }
} else { Write-Output '  NO KEY' }

Sec 'ADK_OC_CAB_LIST'
$roots = @('C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs',
           'C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\WinPE_OCs')
foreach ($r in $roots) {
  if (Test-Path $r) {
    Write-Output ('  ' + $r)
    Get-ChildItem $r -File | ForEach-Object { Write-Output ('    ' + $_.Name) } | Sort-Object
    $hit = @(Get-ChildItem $r -File | Where-Object { $_.Name -match '(?i)wifi|wlan|dot3' })
    Write-Output ('    wifi/wlan/dot3 matches = ' + $hit.Count)
    break
  } else { Write-Output ('  (absent) ' + $r) }
}

Sec 'LOADED_PE_IMAGE_SOURCES'
Write-Output '  -- candidate 26100 install sources on this machine (dir names only, no scanning of big trees)'
foreach ($p in @('D:\winpe_build','D:\QoderProject','E:\','F:\')) {
  if (Test-Path $p) { Write-Output ('    exists: ' + $p + ' -> ' + ((Get-ChildItem $p -Directory -EA SilentlyContinue | Select-Object -First 12 | ForEach-Object { $_.Name }) -join ' | ')) }
}
