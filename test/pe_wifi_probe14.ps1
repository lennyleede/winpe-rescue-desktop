# probe14: probes 8-13 eliminated everything reachable from the live registry (group table is
# correct, ServiceSidType irrelevant, key shape irrelevant, DLL maps, dot3svc-key byte clone still
# error 6, runtime svchost host creation works for five untouched services) -- and they proved new
# SERVICE NAMES cannot be tested live because the SCM's name DB is boot-frozen.
# What was never checked: VERSIONS. Our PE is a 26100 base, but its whole WLAN stack is a 19041.x
# borrowing (this dev machine is 19044 LTSC, that is where the files came from) and ADK WinPE_OCs
# ships no WiFi package at all. A 19041 WlanSvcMain running inside a 26100 svchost/ntdll/rpc is the
# one variable every probe left untouched, and it also explains wall (b) (19041 nwifi.sys refuses
# drvload on 26100 with 0x80070002).
# probe14 therefore looks for a REAL 26100 Windows on the machine the PE is running on, and if it
# finds one, swaps the native wlansvc stack into the ramdisk's System32 and starts the service.
# Ramdisk edits die on reboot, so this is free. Result decides the theory:
#   starts  => 19041/26100 mismatch was the root cause, fix = bake native files
#   error 6 => mismatch theory dead, next cut is the offline image + rebuild
param([switch]$SkipSwap)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function Ver([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'ABSENT' }
  $v = $null
  try { $v = (Get-Item -LiteralPath $p).VersionInfo } catch { }
  if (-not $v) { return 'nofv' }
  $kb = [Math]::Round((Get-Item -LiteralPath $p).Length / 1KB)
  return ((One $v.FileVersion) + ' (' + $kb + 'KB)')
}
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}
$S32     = 'X:\windows\System32'
$SVC     = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$wlanFiles = @('wlansvc.dll','wlanapi.dll','wlanmsm.dll','wlansec.dll','wlansvcpal.dll','wlanext.exe','OneX.dll','dot3svc.dll')

Sec '0_VERSIONS_ON_X'
Log ('  ntdll   = ' + (Ver ($S32 + '\ntdll.dll')))
Log ('  svchost = ' + (Ver ($S32 + '\svchost.exe')))
foreach ($f in $wlanFiles) { Log ('  ' + ('{0,-16}' -f $f) + '= ' + (Ver ($S32 + '\' + $f))) }
Log ('  nwifi.sys      = ' + (Ver ($S32 + '\drivers\nwifi.sys')))
Log ('  ServiceDll     = ' + (One (Get-ItemProperty -LiteralPath ($SVC + '\wlansvc\Parameters') -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll))
Log ('  wlansvc        ' + (SvcState 'wlansvc'))

Sec '0b_WLANAPI_CHILD'
# separate process: a crash inside wlansvc/wlanapi must not eat this log
$w = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class WL14 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int v, IntPtr r, out int neg, out IntPtr h);
  [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr p);
  [DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr p);
  [DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(IntPtr h, IntPtr r);
}
"@
Add-Type -TypeDefinition $src
$h = [IntPtr]::Zero; $neg = 0
$rc = [WL14]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$neg, [ref]$h)
Write-Output ('WlanOpenHandle rc=' + $rc + ' negotiated=' + $neg)
if ($rc -eq 0) {
  $p = [IntPtr]::Zero
  $rc2 = [WL14]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$p)
  $n = -1
  if ($rc2 -eq 0 -and $p -ne [IntPtr]::Zero) {
    $b = New-Object byte[] 4
    [Runtime.InteropServices.Marshal]::Copy($p, $b, 0, 4)
    $n = [BitConverter]::ToUInt32($b, 0)
    [WL14]::WlanFreeMemory($p)
  }
  Write-Output ('WlanEnumInterfaces rc=' + $rc2 + ' interfaces=' + $n)
  [void][WL14]::WlanCloseHandle($h, [IntPtr]::Zero)
}
'@
Set-Content -LiteralPath 'X:\wl14.ps1' -Value $w -Encoding ASCII
function WlanApi { (One (& cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl14.ps1 2>&1'))).Trim() }
Log ('  baseline wlanapi: ' + (WlanApi))

Sec '1_FIND_A_REAL_WINDOWS_ON_THIS_MACHINE'
$found = @()
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
  $r = $d.DeviceID.TrimEnd('\')
  $nt = $r + '\Windows\System32\ntdll.dll'
  $line = ('  ' + $r + ' size=' + [Math]::Round($d.Size / 1GB) + 'GB free=' + [Math]::Round($d.FreeSpace / 1GB) + 'GB fs=' + $d.FileSystem)
  if ($r -eq 'X:') { Log ($line + '  (ramdisk, skip)'); continue }
  $t = $false
  try { $t = Test-Path -LiteralPath $nt } catch { $line += '  READ-ERROR: ' + (One $_.Exception.Message) }
  if ($t) { $line += '  OS=' + (Ver $nt); $found += $r }
  else { $line += '  no \Windows\System32\ntdll.dll (locked/BitLocker/empty?)' }
  Log $line
}
$osroot = $null
if (@($found).Count -gt 0) {
  # prefer a volume that actually has the wlan stack
  foreach ($r in $found) { if (Test-Path -LiteralPath ($r + '\Windows\System32\wlansvc.dll')) { $osroot = $r; break } }
  if (-not $osroot) { $osroot = $found[0] }
  Log ('  CHOSEN OS VOLUME = ' + $osroot)
} else { Log '  NO REAL WINDOWS VOLUME REACHABLE' }

Sec '2_NATIVE_WLAN_STACK'
if ($osroot) {
  $n32 = $osroot + '\Windows\System32'
  foreach ($f in $wlanFiles) { Log ('  ' + ('{0,-16}' -f $f) + '= ' + (Ver ($n32 + '\' + $f))) }
  Log ('  nwifi.sys      = ' + (Ver ($n32 + '\drivers\nwifi.sys')))
  $fr = $n32 + '\DriverStore\FileRepository'
  $nd = @(Get-ChildItem -LiteralPath $fr -Directory -Filter 'nwifi*' -ErrorAction SilentlyContinue |
          Where-Object { (Test-Path -LiteralPath ($_.FullName + '\nwifi.inf')) })
  Log ('  DriverStore nwifi* inf dirs = ' + @($nd).Count)
  foreach ($x in $nd) { Log ('    ' + $x.Name + ' size=' + [Math]::Round((@(Get-ChildItem -LiteralPath $x.FullName -File -Recurse -EA SilentlyContinue) | Measure-Object Length -Sum).Sum / 1KB) + 'KB') }
} else { Log '  skipped' }

Sec '3_WIFI_NIC_ON_THIS_MACHINE'
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue)) {
  $wf = 'no'
  if ((@($a.Name) -imatch 'Wireless|Wi-?Fi|802\.11|WLAN|\bAX\d|AC\d{2}|Centrino|Dual Band|RT[0-9]{4}|IWL').Count -gt 0) { $wf = 'WIFI?' }
  Log ('  adapter ' + ('{0,-32}' -f (One $a.Name)) + ' phys=' + $a.PhysicalAdapter + ' wifi=' + $wf + ' netid=' + (One $a.NetConnectionID) + ' mac=' + $a.MACAddress)
}
foreach ($p in @(Get-CimInstance Win32_PnPEntity -Filter 'PNPClass=''Net''' -ErrorAction SilentlyContinue)) {
  $w = 'no'
  $probe = @($p.Name, $p.DeviceID, $p.ClassGuid)
  if ((@($probe) -imatch '802\.11|WLAN|Wi-?Fi|Wireless|DEV_24FC|DEV_43F|DEV_51|DEV_7A85|RT28|RT88|MT79|IWA').Count -gt 0) { $w = 'WIFI?' }
  Log ('  pnp ' + ('{0,-34}' -f (One $p.Name)) + ' | wf=' + $w + ' status=' + $p.Status + ' id=' + (One $p.DeviceID))
}

Sec '4_LIVE_SWAP_NATIVE_STACK'
if (-not $osroot) { Log '  skipped: no native source'; }
elseif ($SkipSwap) { Log '  skipped: -SkipSwap' }
else {
  $n32 = $osroot + '\Windows\System32'
  New-Item -ItemType Directory -Path 'X:\nat14' -Force | Out-Null
  New-Item -ItemType Directory -Path 'X:\bak14' -Force | Out-Null
  $todo = @('wlansvc.dll','wlanmsm.dll','wlansec.dll','wlansvcpal.dll','wlanapi.dll','OneX.dll')
  foreach ($f in $todo) {
    $src = $n32 + '\' + $f
    if (-not (Test-Path -LiteralPath $src)) { Log ('  native missing: ' + $f); continue }
    Copy-Item -LiteralPath $src -Destination ('X:\nat14\' + $f) -Force -ErrorAction SilentlyContinue
  }
  # import-resolution sanity in a CHILD (flags=0 -> real load, missing import = rc 126/127)
  $child = @'
param([string]$dir)
$src = @"
using System;
using System.Runtime.InteropServices;
public class LL14 {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryExW(string p, IntPtr h, uint f);
}
"@
Add-Type -TypeDefinition $src
foreach ($f in (Get-ChildItem -LiteralPath $dir -File)) {
  $h = [LL14]::LoadLibraryExW($f.FullName, [IntPtr]::Zero, 0)
  $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Output ('  load ' + $f.Name + ' handle=' + $h + ' err=' + $e)
}
'@
  Set-Content -LiteralPath 'X:\ll14.ps1' -Value $child -Encoding ASCII
  Log '  LoadLibraryEx(real) on native copies:'
  $lo = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\ll14.ps1 -dir X:\nat14 2>&1') | Out-String
  foreach ($l in ($lo -split "`r?`n")) { if ((One $l).Length -gt 3) { Log ('  ' + (One $l)) } }
  foreach ($f in @(Get-ChildItem -LiteralPath 'X:\nat14' -File)) {
    $dst = $S32 + '\' + $f.Name
    if (Test-Path -LiteralPath $dst) { Copy-Item -LiteralPath $dst -Destination ('X:\bak14\' + $f.Name) -Force -ErrorAction SilentlyContinue }
    $err = ''
    try { Copy-Item -LiteralPath $f.FullName -Destination $dst -Force -ErrorAction Stop } catch { $err = (One $_.Exception.Message) }
    Log ('  overwrite ' + $f.Name + ' -> ' + $(if ($err) { 'FAIL ' + $err } else { 'ok' }) + ' now=' + (Ver $dst))
  }
  Log ('  net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('  state             : ' + (SvcState 'wlansvc'))
  $wo = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl14.ps1 2>&1') | Out-String
  Log ('  wlanapi: ' + (One $wo).Trim())
}

Sec '5_DRVLOAD_NATIVE_NWIFI'
if ($osroot) {
  $fr = $osroot + '\Windows\System32\DriverStore\FileRepository'
  $nd = @(Get-ChildItem -LiteralPath $fr -Directory -Filter 'nwifi*' -ErrorAction SilentlyContinue |
          Where-Object { (Test-Path -LiteralPath ($_.FullName + '\nwifi.inf')) })
  if (@($nd).Count -eq 0) { Log '  no native nwifi package found' }
  else {
    $sel = $nd[0]
    Copy-Item -LiteralPath $sel.FullName -Destination 'X:\nd14' -Recurse -Force -ErrorAction SilentlyContinue
    $rc = Cmd ('drvload X:\nd14\nwifi.inf')
    Log ('  drvload native nwifi (' + $sel.Name + ') => ' + $rc)
    foreach ($p in @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { (One $_.Name) -imatch 'NativeWiFi|nwifi' })) {
      Log ('    pnp: ' + (One $p.Name) + ' status=' + $p.Status + ' code=' + $p.ConfigManagerErrorCode)
    }
  }
} else { Log '  skipped' }

Sec '6_FINAL'
foreach ($n in @('wlansvc','dot3svc','wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log ('  final ImagePath = ' + (One (Get-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name ImagePath -ErrorAction SilentlyContinue).ImagePath))
Log 'PROBE14_DONE'
