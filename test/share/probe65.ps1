# probe65 -- LIVE PE, THE R8 EXPERIMENT (writes only to the ramdisk registry; reboot restores everything).
#
# Mechanism nailed down on 2026-10-10 (q66_host/q67_host on the 19044 build host, probe63/64 here):
#  1. Every filter component INF carries a fixed NetCfgInstanceId, which IS its component id in the store:
#       netnwifi.inf  -> {E475CF9A-60CD-4439-A75F-0079CE0E18A1}  NativeWiFi, FilterRunType=1 (MANDATORY),
#                                                             FilterClass=ms_medium_converter_top,
#                                                             Ndi\Interfaces\FilterMediumType=*MediaType(16)
#       netvwififlt.inf -> {5CBF81BF-5055-47CD-9055-A76B2B4E3698}  vwififlt, run type 2 (optional)
#       ndiscap.inf {430BDADD..} / wfplwfs.inf {3BFD7820..}{B70D6460..} / netpacer.inf {B5F4D659..}
#  2. The store is HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}
#     \{component id}, carrying Ndi\Service=NativeWifiP etc.  (probe61 looked at Control\Class instead and
#     wrongly concluded "no NetService store"; this is why the earlier routes R1/R2/R7 could not work.)
#  3. NetCfg imposes a filter on an adapter by appending {adapter NetCfgInstanceId}-{component id}-000N to
#     Control\Class\{4d36e972..}\NNNN\Linkage\FilterList.  The AX211 slot in the PE HAS a Linkage key with
#     RootDevice/Export/UpperBind but NO FilterList, and its Control\Network\{4d36e974} store does not exist,
#     so the mandatory NativeWiFi converter is never attached -> the NdisMediumNative802_11 miniport answers
#     0xC00000BB -> code 37 -> wlansvc has no provider (WlanOpenHandle 1062).
#
# So this probe does the two writes by hand on X: and restarts the NIC:
#   W1 copy the two offline component records out of the mounted offline hive (HKLM\R8OFF) into
#      HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e974...}
#   W2 write FilterList on the AX211 class slot, using the PE's own NetCfgInstanceId (it is regenerated at
#      every boot, so nothing here is hardcoded)
# Pass signals: device code 37 -> 0; Services\NativeWifiP\Parameters\Adapters\{conn} appears (the filter
# driver writing its own bind record is exactly what the working machine has); nativewifip -> Running;
# WlanOpenHandle 0 + WlanEnumInterfaces count >= 1.
# Guard: probe59 swapped a 19041.1415 nwifi.sys onto X:, which may fail code integrity now. If the load test
# answers 0xC0000428 the results would be meaningless, so section 0 refuses to write in that case.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'

# ---------- 0. CI guard on the swapped nwifi.sys ----------
L '=0 nwifi loadability (probe59 left a 19041.1415 file here)'
$f = Get-Item -LiteralPath 'X:\Windows\System32\drivers\nwifi.sys' -EA SilentlyContinue
if ($null -eq $f) { L '  0 FILE ABORT' } else {
  $vi = $f.VersionInfo
  L ('  0 FILE ' + $f.Length + 'B v=' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
}
try {
  Add-Type -Namespace P65 -Name W -MemberDefinition @'
using System;using System.Runtime.InteropServices;
public static class W{
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
 public static extern IntPtr OpenSCManager(IntPtr m, IntPtr d, int a);
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
 public static extern IntPtr OpenService(IntPtr s, string n, int a);
 [DllImport("advapi32.dll", SetLastError=true)]
 public static extern bool StartService(IntPtr s, int c, IntPtr v);
 [DllImport("advapi32.dll", SetLastError=true)]
 public static extern bool CloseServiceHandle(IntPtr h);
 public static string Start(string n){
   IntPtr scm = OpenSCManager(IntPtr.Zero, IntPtr.Zero, 1);
   if (scm == IntPtr.Zero) { return "SCMERR=" + Marshal.GetLastWin32Error(); }
   IntPtr h = OpenService(scm, n, 0x10);
   if (h == IntPtr.Zero) { CloseServiceHandle(scm); return "OPENERR=" + Marshal.GetLastWin32Error(); }
   bool ok = StartService(h, 0, IntPtr.Zero);
   int e = Marshal.GetLastWin32Error();
   CloseServiceHandle(h); CloseServiceHandle(scm);
   return "ok=" + ok + " err=" + e;
 }
}
'@ -EA Stop
  $r = [P65.W]::Start('nativewifip')
  L ('  0 SCM start nativewifip : ' + $r)
  if ($r -match 'err=577') { L '  0 VERDICT CI-BLOCKED (ERROR_DRIVER_BLOCKED) -- reboot the PE before trusting any write test'; return }
  L '  0 VERDICT not blocked by code integrity (577), safe to run the write test'
} catch { L ('  0 ADDTYPE-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }

# ---------- 1. offline component records (source of truth, same machine, mounted hive) ----------
L '=1 offline component store read'
$offBase = 'HKLM:\R8OFF\ControlSet001\Control\Network\' + $SVS
if (-not (Test-Path -LiteralPath $offBase)) {
  $rr = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  1 reg load ' + ($rr -join '|'))
}
foreach ($pair in @(@('nwifi', $NWIFI), @('vwififlt', $VFLT))) {
  $k = $offBase + '\' + $pair[1]
  $gi = Get-Item -LiteralPath $k -EA SilentlyContinue
  if ($null -eq $gi) { L ('  1 OFF ' + $pair[0] + ' COMPONENT KEY ABSENT'); continue }
  foreach ($vn in @($gi.GetValueNames())) {
    $raw = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $v = ''
    if ($raw -is [array]) { $v = ($raw -join ';') } else { $v = '' + $raw }
    if ($v.Length -gt 160) { $v = $v.Substring(0, 160) + '...' }
    L ('  1 OFF ' + $pair[0] + ' ' + $vn + ' = ' + (Clean $v))
  }
  L ('  1 OFF ' + $pair[0] + ' subs=' + (Clean (@(Get-ChildItem -LiteralPath $k -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ',')))
}

# ---------- 2. write W1: copy the component records into the PE store ----------
L ('=2 W1 write the two component records into HKLM\SYSTEM\CurrentControlSet\Control\Network\' + $SVS)
$LM = [Microsoft.Win32.Registry]::LocalMachine
function Copy-Tree($src, $dst) {
  foreach ($vn in @($src.GetValueNames())) {
    $kind = $src.GetValueKind($vn)
    $val = $src.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    if ($val -is [array] -and $kind.ToString() -eq 'MultiString') { [void]$dst.SetValue($vn, [string[]]$val, $kind) }
    else { [void]$dst.SetValue($vn, $val, $kind) }
  }
  foreach ($sn in @($src.GetSubKeyNames())) {
    $s2 = $src.OpenSubKey($sn, $false)
    $d2 = $dst.CreateSubKey($sn)
    if (($null -ne $s2) -and ($null -ne $d2)) { Copy-Tree $s2 $d2 }
  }
}
$offRootKey = $LM.OpenSubKey('R8OFF\ControlSet001\Control\Network\' + $SVS, $false)
if ($null -eq $offRootKey) { L '  2 CANNOT OPEN OFFLINE STORE (R8OFF not readable) -- ABORT BEFORE WRITING'; return }
$peRootKey = $LM.CreateSubKey('SYSTEM\CurrentControlSet\Control\Network\' + $SVS)
if ($null -eq $peRootKey) { L '  2 CANNOT CREATE PE STORE -- ABORT'; return }
foreach ($pair in @(@('nwifi', $NWIFI), @('vwififlt', $VFLT))) {
  $s = $offRootKey.OpenSubKey($pair[1], $false)
  if ($null -eq $s) { L ('  2 SKIP ' + $pair[0] + ' (no offline record)'); continue }
  $d = $peRootKey.CreateSubKey($pair[1])
  Copy-Tree $s $d
  L ('  2 WROTE ' + $pair[0] + ' -> ' + $pair[1] + ' values=' + (@($d.GetValueNames()).Count) + ' subs=' + (Clean (@($d.GetSubKeyNames()) -join ',')))
}
$peRootKey.Close(); $offRootKey.Close()

# ---------- 3. write W2: FilterList on the AX211 class slot ----------
L '=3 W2 find the AX211 class slot and write FilterList'
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET
$slot = ''
$netCfgId = ''
foreach ($nn in @(Get-ChildItem -LiteralPath $cls -EA SilentlyContinue)) {
  if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
  $p = $cls + '\' + $nn.PSChildName
  $g = Get-Item -LiteralPath $p
  $mid = Clean ('' + $g.GetValue('MatchingDeviceId', ''))
  if ($mid -match 'VEN_8086&DEV_7A70') { $slot = $p; $netCfgId = Clean ('' + $g.GetValue('NetCfgInstanceId', '')) }
}
if ($slot -eq '') { L '  3 NO AX211 CLASS SLOT -- NIC not installed, abort write' ; return }
L ('  3 SLOT ' + (Clean $slot) + ' NetCfgInstanceId=' + $netCfgId)
$link = Get-Item -LiteralPath ($slot + '\Linkage') -EA SilentlyContinue
if ($null -eq $link) { L '  3 NO LINKAGE KEY'; return }
foreach ($vn in @($link.GetValueNames())) {
  L ('  3 BEFORE ' + $vn + ' = ' + (Clean ('' + ($link.GetValue($vn, $null, 'DoNotExpandEnvironmentNames') -join ';'))))
}
$fl = @(($netCfgId + '-' + $VFLT + '-0000'), ($netCfgId + '-' + $NWIFI + '-0000'))
[void]$link.SetValue('FilterList', [string[]]$fl, 'MultiString')
foreach ($vn in @($link.GetValueNames())) {
  L ('  3 AFTER ' + $vn + ' = ' + (Clean ('' + ($link.GetValue($vn,  $null, 'DoNotExpandEnvironmentNames') -join ';'))))
}

# ---------- 4. restart the NIC and read the verdict ----------
L '=4 restart the AX211 and watch'
$ent = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($ent.Count -eq 0) { L '  4 DEVNODE GONE' } else {
  $pnp = $ent[0].PNPDeviceID
  $r = @(& pnputil.exe /restart-device "$pnp" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  4 RESTART ' + ($r -join ' | '))
}
Start-Sleep -Seconds 8
L ('  4 SCM nativewifip : ' + [P65.W]::Start('nativewifip'))
Start-Sleep -Seconds 3
foreach ($n in 'nativewifip', 'vwififlt', 'wlansvc', 'wcmsvc') {
  $st = 'NOGET'; try { $st = '' + (Get-Service $n -EA Stop).Status } catch {}
  L ('  4 STATE ' + $n + ' = ' + $st)
}
$ad = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
if (Test-Path -LiteralPath $ad) {
  $kids = @(Get-ChildItem -LiteralPath $ad -EA SilentlyContinue)
  L ('  4*** NativeWifiP\Parameters\Adapters count=' + $kids.Count + ' [' + (($kids | ForEach-Object { $_.PSChildName }) -join ' ') + ']')
  foreach ($kk in $kids) {
    $sub = @(Get-ChildItem -LiteralPath ($ad + '\' + $kk.PSChildName) -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
    L ('      ADAPTER ' + $kk.PSChildName + ' instances=[' + ($sub -join ' ') + ']')
  }
} else { L '  4 NativeWifiP\Parameters\Adapters ABSENT (filter never bound)' }
$ad2 = 'HKLM:\SYSTEM\CurrentControlSet\Services\vwififlt\Parameters\Adapters'
if (Test-Path -LiteralPath $ad2) { L ('  4 vwififlt\Parameters\Adapters [' + ((@(Get-ChildItem -LiteralPath $ad2 -EA SilentlyContinue) | ForEach-Object { $_.PSChildName }) -join ' ') + ']') } else { L '  4 vwififlt\Parameters\Adapters ABSENT' }
$ents2 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70|vwifibus|vwifimp|NativeWifi' })
foreach ($e in $ents2) { L ('  4 DEV code=' + $e.ConfigManagerErrorCode + ' id=' + (Clean ('' + $e.PNPDeviceID)) + ' name=' + (Clean ('' + $e.Name))) }
try {
  Add-Type -Namespace P65 -Name Wlan -MemberDefinition @'
using System;using System.Runtime.InteropServices;
public static class WlanA{
 [DllImport("wlanapi.dll", SetLastError=true)]
 public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
 [DllImport("wlanapi.dll", SetLastError=true)]
 public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
 [DllImport("wlanapi.dll")]
 public static extern int WlanCloseHandle(IntPtr handle, IntPtr res);
 public static string Probe(){
   int nv=0; IntPtr h=IntPtr.Zero;
   int rc=WlanOpenHandle(1, IntPtr.Zero, out nv, out h);
   if(rc!=0){return "OPEN rc="+rc;}
   int cnt=0; IntPtr list=IntPtr.Zero;
   int rc2=WlanEnumInterfaces(h, IntPtr.Zero, out list, out cnt);
   WlanCloseHandle(h, IntPtr.Zero);
   return "OPEN rc=0 ENUM rc="+rc2+" interfaces="+cnt;
 }
}
'@ -EA Stop
  L ('  5 WLANAPI : ' + ([P65.WlanA]::Probe()))
} catch { L ('  5 WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
L 'P65 END'
