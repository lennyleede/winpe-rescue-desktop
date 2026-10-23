param([switch]$Install)
$ErrorActionPreference = 'SilentlyContinue'
# probe31 -- why the AX211 miniport stops at code 37 (STATUS_NOT_SUPPORTED) in WinPE.
# setupapi.dev.log says it over and over:  "Needed section [VWiFiBus...] not found, might exist in missing included INF",
# and Netwtw6e.INF has Include=netvwifibus.inf on every install section. WinPE ships no netvwifibus.inf / vwifibus.sys,
# so the native-wifi bus never gets registered and the miniport cannot start.
# -Install takes that bus package from the offline Windows on D: and installs it into the ramdisk, then restarts the
# devnode. Nothing is written to D: or to the stick; X: is a ramdisk and resets on reboot.
$node = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'

function Show-State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Write-Output ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Write-Output ($tag + '|NODE|absent') }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Write-Output ($tag + '|NIC|' + $a.Name + '|enabled=' + $a.NetEnabled + '|guid=' + $a.GUID)
  }
  foreach ($s in 'nativewifip', 'wlansvc', 'wcmsvc', 'vwifibus', 'vwififlt') {
    $sv = Get-Service $s -EA SilentlyContinue
    Write-Output ($tag + '|SVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'absent' }))
  }
}

Write-Output ('PROBE31 ' + (Get-Date -Format 'HH:mm:ss') + ' install=' + [bool]$Install)
Write-Output '== V1. is the virtual WiFi bus in the image at all? =='
foreach ($p in 'X:\Windows\INF\netvwifibus.inf', 'X:\Windows\System32\drivers\vwifibus.sys', 'X:\Windows\System32\drivers\vwififlt.sys',
               'X:\Windows\System32\drivers\nwifi.sys', 'X:\Windows\INF\netvwififlt.inf') {
  Write-Output ('PEFILE|' + $p + '=' + (Test-Path $p))
}
Write-Output ('PE_DRIVERSTORE_VWIFI|' + (@(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'vwifi' }).Name -join ','))
Write-Output '== V2. Net class filters in the running image =='
$nk = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-ce09-08c7e7d9e2b8}'
$np = Get-ItemProperty -LiteralPath $nk -EA SilentlyContinue
Write-Output ('NETCLASS|keyexists=' + (Test-Path -LiteralPath $nk) + '|Upper=' + (($np.UpperFilters | ForEach-Object { $_ }) -join ',') + '|Lower=' + (($np.LowerFilters | ForEach-Object { $_ }) -join ','))
Write-Output ('NETCLASS_SUBKEYS=' + (@(Get-ChildItem -LiteralPath $nk -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ','))
Write-Output '== V3. root-enumerated bus devices present =='
foreach ($x in @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match 'ROOT\\(VWiFi|WIFI)|SWD\\' })) {
  Write-Output ('BUSNODE|' + $x.PNPDeviceID + '|code=' + $x.ConfigManagerErrorCode + '|' + $x.Name)
}
Show-State 'INIT'

if (-not $Install) { Write-Output 'PROBE31 END (read-only pass)'; exit 0 }

Write-Output '== V4. locate the vwifibus package on the offline Windows =='
$src = ''
foreach ($fr in 'D:\Windows\System32\DriverStore\FileRepository', 'C:\Windows\System32\DriverStore\FileRepository') {
  if (-not (Test-Path $fr)) { continue }
  foreach ($d in @(Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'vwifi' })) {
    $infs = @(Get-ChildItem $d.FullName -Filter '*.inf' -File -EA SilentlyContinue)
    $cats = @(Get-ChildItem $d.FullName -Filter '*.cat' -File -EA SilentlyContinue)
    $sysf = @(Get-ChildItem $d.FullName -Filter '*.sys' -File -EA SilentlyContinue)
    Write-Output ('OFFPKG|' + $d.FullName + '|inf=' + ($infs.Name -join ',') + '|cat=' + $cats.Count + '|sys=' + ($sysf.Name -join ','))
    if (-not $src -and $infs.Count -and $sysf.Count) { $src = $infs[0].FullName }
  }
}
Write-Output ('OFF_INF=' + $src)
if (-not $src) {
  Write-Output 'falling back to bare inbox files (copy sys + inf, no package)'
  foreach ($p in 'D:\Windows\System32\drivers\vwifibus.sys', 'D:\Windows\INF\netvwifibus.inf') {
    Write-Output ('OFFFILE|' + $p + '=' + (Test-Path $p) + '|' + (Get-Item $p -EA SilentlyContinue).Length)
  }
}

Write-Output '== V5. install the bus, then restart the devnode =='
if ($src) {
  Write-Output ('DRVLoad_BUS|' + ((& drvload $src 2>&1 | Out-String) -replace '\s+', ' '))
} else {
  foreach ($f in 'D:\Windows\System32\drivers\vwifibus.sys', 'D:\Windows\System32\drivers\vwififlt.sys') {
    if (Test-Path $f) { Copy-Item $f 'X:\Windows\System32\drivers\' -Force; Write-Output ('COPIED|' + (Split-Path $f -Leaf)) }
  }
  if (Test-Path 'D:\Windows\INF\netvwifibus.inf') { Copy-Item 'D:\Windows\INF\netvwifibus.inf' 'X:\Windows\INF\netvwifibus.inf' -Force }
}
Start-Sleep -Seconds 2
Write-Output ('PNPUTIL_DISABLE|' + ((& pnputil /disable-device $node 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 2
Write-Output ('PNPUTIL_ENABLE|' + ((& pnputil /enable-device $node 2>&1 | Out-String) -replace '\s+', ' '))
Write-Output ('PNPUTIL_REMOVE|' + ((& pnputil /remove-device $node 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 2
Write-Output ('PNPUTIL_SCAN|' + ((& pnputil /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 6
Show-State 'AFTER'

Write-Output '== V6. wlansvc + Wlan API =='
$nw = Get-Service nativewifip -EA SilentlyContinue
if ($nw -and $nw.Status -ne 'Running') { try { $nw.Start(); Write-Output 'NATIVEWIFIP_START=ok' } catch { Write-Output ('NATIVEWIFIP_START_EX=' + $_.Exception.Message) } }
Start-Sleep -Seconds 2
Write-Output ('NATIVEWIFIP_NOW=' + (Get-Service nativewifip -EA SilentlyContinue).Status)
$sw = Get-Service wlansvc -EA SilentlyContinue
if ($sw -and $sw.Status -ne 'Running') { try { $sw.Start(); Write-Output 'WLANSVC_START=ok' } catch { Write-Output ('WLANSVC_START_EX=' + $_.Exception.Message) } }
Start-Sleep -Seconds 3
Write-Output ('WLANSVC_NOW=' + (Get-Service wlansvc -EA SilentlyContinue).Status)
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll",CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Write-Output ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n = 0
  $re = [Wapi]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n)
  Write-Output ('WlanEnumInterfaces=' + $re + ' count=' + $n)
  if ($re -eq 0 -and $n -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $g = [Runtime.InteropServices.Marshal]::PtrToStructure($lst, [Type][Guid])
    $dp = [Runtime.InteropServices.Marshal]::ReadIntPtr($lst, 16)
    $st = [Runtime.InteropServices.Marshal]::ReadInt32($lst, 24)
    Write-Output ('IFACE|guid=' + $g + '|state=' + $st + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($dp))
  }
}
Write-Output '== V7. setupapi tail after install =='
$ln = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
foreach ($l in ($ln | Select-Object -Last 25)) { Write-Output ('SAL2|' + $l) }
Write-Output ('FREE_X=' + ((Get-PSDrive X).Free))
Write-Output 'PROBE31 END'
