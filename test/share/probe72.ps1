# probe72 -- LIVE PE. probe71 killed the ETW idea (PE has no readable NDIS/PnP log files) and produced a new
# hard fact: the miniport service itself is Stopped -- driverquery/Win32_SystemDriver say Netwtw14 = Stopped,
# and the class slot's IHVExtensions points at netwtw6e.inf_amd64_c3785d6f1e6d5b0e, a directory that does NOT
# exist in the image. The package that IS installed for the AX211 is netwtw6e.inf_amd64_5433b0cac0a04d0e,
# DriverVer 03/10/2024 23.40.0.4, while THIS laptop's working Windows 10 runs 23.150.0.4 (6-12-2025).
# So before blaming the 19041-vs-26100 WiFi stack, test the driver version itself: the laptop's own DriverStore
# is readable at D:, so drvload the exact package that works in Windows on this very hardware, then re-apply the
# two registry artifacts probe69 identified (instance UpperFilters=vwifibus + class-slot FilterList) and read
# the verdict. Controls: StartService on unrelated stopped NDIS drivers, so err=31 for nativewifip can be
# called out as driver-specific rather than environment-wide.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$DEVPATH = 'SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$LM = [Microsoft.Win32.Registry]::LocalMachine
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P72Scm {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManager(IntPtr m, IntPtr d, int a);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenService(IntPtr s, string n, int a);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartService(IntPtr s, int c, IntPtr v);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool CloseServiceHandle(IntPtr h);
  public static string Start(string n) {
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
public static class P72Wlan {
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
  [DllImport("wlanapi.dll")]
  static extern int WlanCloseHandle(IntPtr handle, IntPtr res);
  public static string Probe() {
    int nv = 0; IntPtr h = IntPtr.Zero;
    int rc = WlanOpenHandle(1, IntPtr.Zero, out nv, out h);
    if (rc != 0) { return "OPEN rc=" + rc; }
    int cnt = 0; IntPtr list = IntPtr.Zero;
    int rc2 = WlanEnumInterfaces(h, IntPtr.Zero, out list, out cnt);
    WlanCloseHandle(h, IntPtr.Zero);
    return "OPEN rc=0 ENUM rc=" + rc2 + " interfaces=" + cnt;
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { L ('  ADDTYPE-ERR ' + (Trim2 ('' + $_.Exception.Message) 300)); return }

function FindSlot {
  $slot = ''
  $id = ''
  foreach ($nn in @(Get-ChildItem -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET) -EA SilentlyContinue)) {
    if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
    $g = Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET + '\' + $nn.PSChildName)
    if ((Clean ('' + $g.GetValue('MatchingDeviceId', ''))) -match 'DEV_7A70') { $slot = $nn.PSChildName; $id = Clean ('' + $g.GetValue('NetCfgInstanceId', '')) }
  }
  $o = @($slot, $id)
  return $o
}
function ReApply([string]$tag) {
  $sl = FindSlot
  L ('  ' + $tag + ' slot=' + $sl[0] + ' id=' + $sl[1])
  $k = $LM.OpenSubKey($DEVPATH, $true)
  if ($null -ne $k) { [void]$k.SetValue('UpperFilters', [string[]]@('vwifibus'), 'MultiString'); L ('  ' + $tag + ' UPPER=[' + (Clean ('' + ($k.GetValue('UpperFilters', @()) -join ';'))) + ']'); $k.Close() }
  if ($sl[0] -ne '' -and $sl[1] -ne '') {
    $w = $LM.OpenSubKey('SYSTEM\CurrentControlSet\Control\Class\' + $NET + '\' + $sl[0] + '\Linkage', $true)
    if ($null -ne $w) {
      $fl = @(($sl[1] + '-' + $VFLT + '-0000'), ($sl[1] + '-' + $NWIFI + '-0000'))
      [void]$w.SetValue('FilterList', [string[]]$fl, 'MultiString')
      L ('  ' + $tag + ' FILTER=[' + (Trim2 ($w.GetValue('FilterList', @()) -join ';') 200) + ']')
      $w.Close()
    }
  }
}
function Report([string]$tag) {
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  if ($es.Count -eq 0) { L ('  ' + $tag + ' DEV no node') }
  foreach ($e in $es) { L ('  ' + $tag + ' DEV code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' drv=' + (Clean ('' + $e.Driver)) + ' ' + (Trim2 ('' + $e.Name) 40)) }
  $sd = Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -eq 'Netwtw14' }
  if ($null -ne $sd) { L ('  ' + $tag + ' NETWTW14 ' + (Clean ('' + $sd.State)) + ' path=' + (Trim2 ('' + $sd.PathName) 130)) }
  foreach ($n in 'nativewifip', 'vwififlt', 'vwifibus', 'wlansvc') { L ('  ' + $tag + ' S ' + $n + '=' + (St $n)) }
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) { L ('  ' + $tag + ' BIND=[' + (@(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ',') + ']') } else { L ('  ' + $tag + ' BIND ABSENT') }
  L ('  ' + $tag + ' WLAN ' + ([P72Wlan]::Probe()))
}

# ---------- 0. controls: is err=31 specific to nwifi? ----------
L '=0 SCM start controls'
foreach ($n in 'NdisTapi', 'NdisWan', 'ndproxy', 'RasAcd', 'vwifibus', 'vwififlt', 'nativewifip') {
  L ('  0 START ' + $n + ' -> ' + [P72Scm]::Start($n) + ' now=' + (St $n))
}

# ---------- 1. every netwtw package on this machine, with DriverVer + AX211 support ----------
L '=1 package inventory (X: pool vs D: live Windows)'
function PkgInfo([string]$root, [string]$tag) {
  $ds = @(Get-ChildItem -LiteralPath $root -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netwtw*' })
  L ('  1 ' + $tag + ' dirs=' + $ds.Count)
  foreach ($d in $ds) {
    $infs = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.inf' -EA SilentlyContinue)
    foreach ($ii in $infs) {
      $t = @(Get-Content -LiteralPath $ii.FullName -Encoding Unicode -EA SilentlyContinue)
      $dv = ''
      foreach ($ln in $t) { if ((Clean ('' + $ln)) -match '(?i)^ *DriverVer') { $dv = Trim2 ('' + $ln) 90 } }
      $has7a70 = @($t | Where-Object { $_ -match 'DEV_7A70' }).Count
      $sysn = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.sys' -EA SilentlyContinue | ForEach-Object { $_.Name })
      L ('  1 ' + $tag + ' ' + $d.Name + ' inf=' + $ii.Name + ' ' + $dv + ' AX211lines=' + $has7a70 + ' sys=' + ($sysn -join ',') + ' bytes=' + (@(Get-ChildItem -LiteralPath $d.FullName -EA SilentlyContinue) | Measure-Object -Property Length -Sum).Sum)
    }
  }
}
PkgInfo 'X:\Windows\System32\DriverStore\FileRepository' 'PE'
PkgInfo 'D:\Windows\System32\DriverStore\FileRepository' 'OFF'

# ---------- 2. drvload the package this laptop uses in its own Windows ----------
L '=2 drvload laptop own package'
$off = @(Get-ChildItem -LiteralPath 'D:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netwtw6e*' })
foreach ($d in $off) {
  $ii = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.inf' -EA SilentlyContinue)
  foreach ($f in $ii) { L ('  2 candidate ' + $f.FullName) }
}
if ($off.Count -eq 0) { L '  2 NO netwtw6e in D: DriverStore' } else {
  $pick = $off[0]
  $inf = @(Get-ChildItem -LiteralPath $pick.FullName -Filter '*.inf' -EA SilentlyContinue)[0]
  $r = @(& drvload.exe /force "$($inf.FullName)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  2 DRVLOAD ' + (Trim2 ($r -join ' | ') 400))
  Start-Sleep -Seconds 12
  Report 'P-DRVLOAD'
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  if ($es.Count -gt 0) { L ('  2 RESTART ' + (Trim2 ((@(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 200)) }
  Start-Sleep -Seconds 10
  Report 'P-RESTART'
}

# ---------- 3. re-apply both registry artifacts, restart, verdict ----------
L '=3 re-apply artifacts'
ReApply 'R'
$es3 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es3.Count -gt 0) {
  L ('  3 RESTART ' + (Trim2 ((@(& pnputil.exe /restart-device "$($es3[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 200))
}
Start-Sleep -Seconds 12
Report 'R'
L ('  3 START nativewifip ' + [P72Scm]::Start('nativewifip'))
L ('  3 START wlansvc ' + [P72Scm]::Start('wlansvc'))
Start-Sleep -Seconds 8
Report 'R2'
L 'P72 END'
