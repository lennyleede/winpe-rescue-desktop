# probe49 -- LIVE PE. Decisive experiment on the 12th-gen AX211.
# probe48 read the real failure reason for code 37: DEVPKEY_Device_ProblemStatus = 3221225659 = 0xC00000BB
# = STATUS_NOT_SUPPORTED -- the driver image loads but refuses to initialise here. That is the exact status
# NDIS returns when a Native 802.11 miniport comes up and the NativeWiFi layer is not present underneath it:
# nwifi (Microsoft NativeWiFi Filter), vwififlt and nativewifip are all Stopped in this PE. probe47 already
# proved the registry shape is NOT the difference (ServiceGroupOrder byte-identical, vwififlt Start=1/Group=NDIS
# in the PE and in the laptop's working hive, tdx/AFD/NetBT of the same Start=1 class all loaded fine) -- so
# the kernel simply never got these three running before PnP enumerated the NIC.
# Therefore: start them by hand, restart the device, and see whether the miniport binds. If it does, the fix is
# a boot-time script (startnet.cmd brings up nwifi/vwififlt/nativewifip, then /restart-device) and NOT more
# offline registry surgery -- much cheaper to ship and to verify.
# Mutations are runtime-only on the ramdisk (service start + device restart); no file or hive writes.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function CodeNow {
  $c = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' } |
         ForEach-Object { $_.ConfigManagerErrorCode })
  if ($c.Count -eq 0) { return 'GONE' } else { return "$($c[0])" }
}
function ProbStatus {
  $d = @(Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.InstanceId -like '*VEN_8086&DEV_7A70*' } |
         Select-Object -First 1)
  if ($d.Count -eq 0) { return '-' }
  $v = (Get-PnpDeviceProperty -InstanceId $d[0].InstanceId -Key 'DEVPKEY_Device_ProblemStatus' -EA SilentlyContinue).Data
  if ($null -eq $v) { return '-' }
  $hex = '0x{0:X8}' -f [uint32]$v
  $names = @{ '0xC00000BB' = 'STATUS_NOT_SUPPORTED'; '0xC0000001' = 'STATUS_UNSUCCESSFUL';
              '0xC0000135' = 'STATUS_DLL_NOT_FOUND'; '0xC0000034' = 'STATUS_OBJECT_NAME_NOT_FOUND';
              '0xC0000428' = 'STATUS_INVALID_IMAGE_HASH'; '0xC0000043' = 'STATUS_SHARING_VIOLATION';
              '0xC000012C' = 'STATUS_DRIVER_BLOCKED_CRITICAL'; '0x00000000' = 'SUCCESS' }
  $n = if ($names.ContainsKey($hex)) { $names[$hex] } else { '?' }
  return ($v.ToString() + ' ' + $hex + ' ' + $n)
}
function SysPath([string]$img) {
  if (-not $img) { return '' }
  $p = $img -replace '\\SystemRoot\\', 'X:\Windows\' -replace '%SystemRoot%', 'X:\Windows'
  $p = $p -replace '/', '\'
  if ($p -notmatch '^[A-Za-z]:\\') { $p = 'X:\Windows\system32\' + ($p -replace '^[\\]+', '') }
  return $p
}
$N = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
       Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' } | Select-Object -First 1)
$INST = if ($N.Count) { "$($N[0].InstanceId)" } else { '' }
O ('  INSTANCE ' + $(if ($INST) { $INST } else { '-' }))

O '== A baseline: the whole native-wifi chain, key + state + file =='
foreach ($n in @('ndis', 'netio', 'nwifi', 'vwififlt', 'vwifibus', 'vwifimp', 'nativewifip',
                 'Netwtw14', 'Netwtw6e', 'wlansvc', 'wcmsvc', 'mshidkmdf')) {
  $sk = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (-not (Test-Path -LiteralPath $sk)) { O ('  SVC ' + $n + ' KEY_ABSENT'); continue }
  $p = Get-ItemProperty -LiteralPath $sk -EA SilentlyContinue
  $st = '-'
  try { $st = "$(Get-Service $n).Status" } catch { $st = 'NOGET' }
  $f  = SysPath "$($p.ImagePath)"
  $fs = 'NOFILEVAL'
  if ($f) { $fs = $(if (Test-Path -LiteralPath $f) { "$((Get-Item -LiteralPath $f).Length)B" } else { 'MISSING:' + $f }) }
  O ('  SVC ' + $n + ' Start=' + $p.Start + ' Type=' + $p.Type + ' Group=' + ($p.Group -join ',') +
     ' Depend=' + ($p.DependOnService -join ',') + ' state=' + $st + ' file=' + $fs)
}

O '== B file inventory of the staged Intel package =='
foreach ($d in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue |
                 Where-Object { $_.Name -like 'netwtw*' })) {
  $fl = @(Get-ChildItem -LiteralPath $d.FullName -File -EA SilentlyContinue)
  $tot = [Math]::Round((($fl | Measure-Object Length -Sum).Sum) / 1MB, 1)
  O ('  PKGDIR ' + $d.Name + ' files=' + $fl.Count + ' total=' + $tot + 'MB sys=' +
     (($fl | Where-Object { $_.Extension -eq '.sys' } | ForEach-Object { $_.Name }) -join ',') +
     ' dat=' + (($fl | Where-Object { $_.Extension -eq '.dat' } | ForEach-Object { $_.Name }) -join ','))
}
$xf = @(Get-PSDrive -Name 'X' -EA SilentlyContinue)
if ($xf.Count) { O ('  XFREE free=' + [Math]::Round($xf[0].Free / 1MB, 1) + 'MB used=' + [Math]::Round($xf[0].Used / 1MB, 1) + 'MB') }

O '== C start the native-wifi layer by hand =='
foreach ($n in @('nwifi', 'vwififlt', 'vwifimp', 'nativewifip')) {
  try {
    $s = Get-Service $n -EA Stop
    if ("$($s.Status)" -eq 'Running') { O ('  START ' + $n + ' already Running'); continue }
    $s.Start()
    Start-Sleep -Seconds 2
    O ('  START ' + $n + ' -> ' + $s.Status)
  } catch {
    O ('  START ' + $n + ' ERR ' + (($_.Exception.Message) -replace '\s+', ' '))
  }
}
O ('  AFTER_C code=' + @(CodeNow) + ' probstatus=' + @(ProbStatus))

O '== D restart the NIC device and read it back =='
if ($INST) {
  $r = @(& pnputil.exe /restart-device "$INST" 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
  O ('  RESTART ' + ($r -join ' | '))
  Start-Sleep -Seconds 4
} else { O '  RESTART no instance id' }
$enum = ''
foreach ($v in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)) {
  if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
    $i = @(Get-ChildItem $v.PSPath -EA SilentlyContinue) | Select-Object -First 1
    if ($i) { $enum = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI\' + $v.PSChildName + '\' + $i.PSChildName }
  }
}
$upper = '-'
if ($enum) {
  $ep = Get-ItemProperty -LiteralPath $enum -EA SilentlyContinue
  if ($ep -and $ep.UpperFilters) { $upper = ($ep.UpperFilters -join ',') }
}
O ('  AFTER_D code=' + (CodeNow) + ' probstatus=' + (ProbStatus) + ' upper=' + $upper)
foreach ($n in @('nwifi', 'vwififlt', 'nativewifip', 'Netwtw14')) {
  try { O ('  STATE ' + $n + ' = ' + "$(Get-Service $n).Status") } catch { O ('  STATE ' + $n + ' = NOGET') }
}

O '== E wlansvc and the wlanapi view =='
try {
  $w = Get-Service wlansvc -EA Stop
  if ("$($w.Status)" -ne 'Running') { $w.Start(); Start-Sleep -Seconds 4 }
  O ('  WLANSVC ' + $w.Status)
} catch { O ('  WLANSVC ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
try {
  $c = Get-Service wcmsvc -EA Stop
  if ("$($c.Status)" -ne 'Running') { $c.Start(); Start-Sleep -Seconds 2 }
  O ('  WCMSVC ' + $c.Status)
} catch { O ('  WCMSVC ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
try {
  Add-Type -Namespace 'P49' -Name 'P49W' -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list, out int count);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [P49.P49W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  WLANOPEN rc=' + $rc + ' newVer=' + $nv)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    $rc2 = [P49.P49W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt)
    O ('  WLANENUM rc=' + $rc2 + ' ifaces=' + $cnt)
    [void][P49.P49W]::WlanCloseHandle($h, [IntPtr]::Zero)
  }
} catch { O ('  WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
$ad = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
        Where-Object { $_.Name -match '(?i)Wi-Fi|wireless|Virtual WiFi|Network Adapter' } |
        ForEach-Object { $_.Name + '|code=' + $_.ConfigManagerErrorCode })
O ('  DEVICES ' + $(if ($ad.Count) { $ad -join ' ;; ' } else { '-' }))
$ip = @(Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue |
        Where-Object { $_.IPAddress } | ForEach-Object { $_.Description + '=' + ($_.IPAddress -join ',') })
O ('  IPS ' + $(if ($ip.Count) { $ip -join ' ;; ' } else { '-' }))
O 'P49 END'
