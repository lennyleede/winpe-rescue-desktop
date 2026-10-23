# probe54 -- LIVE PE, read-only apart from service starts, output prefixed P54.
# Why does wlansvc refuse to stay Running?
# probe53 picture of the chain, line by line:
#   vwifibus=Running, vwifimp=Running, vwififlt is loaded (StartService answers 1056 = already running),
#   nativewifip (nwifi.sys 10.0.19041.7663) is Stopped and StartService gives ERROR_GEN_FAILURE(31),
#   Netwtw14 stays code 37 / DEVPKEY_Device_ProblemStatus 0xC00000BB (STATUS_NOT_SUPPORTED) while its INF
#   declares *MediaType = 16 (NdisMediumNative802_11) -- a Native802_11 miniport cannot initialise without
#   the NativeWiFi provider.
#   wlansvc: SCM accepted Start() yet the state stayed Stopped; wcmsvc failed "dependency ... failed".
# On the working laptop wlansvc is a svchost service (Start=2, Type=0x10, Group=TDI,
# DependOnService=nativewifip,RpcSs,Ndisuio,wcmsvc) -- i.e. wlansvc starts nwifi, not the other way round,
# so the order matters: wlansvc up -> nwifi loaded -> pnputil /restart-device -> NIC binds.
# This probe reads the SCM exit codes (win32ExitCode + serviceSpecificExitCode) that SayNoMore gives nothing about,
# checks the Svchost group tables and which svchost -k groups are actually running, then retries the chain.
# SCM note: probe52 proved PowerShell cannot build the SERVICE_STATUS struct reliably here, so the whole
# query is done inside one C# helper (Add-Type -TypeDefinition) instead of Marshal calls from script.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function DLL([string]$rel) {
  $p = 'X:\Windows\System32\' + $rel
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    O ('  FILE ' + $rel + ' ' + $i.Length + 'B ver=' + $i.VersionInfo.FileVersion)
  } else { O ('  FILE ' + $rel + ' MISSING') }
}

HDR '1 wlansvc/wcmsvc modules present'
foreach ($f in 'wlansvc.dll', 'wlanapi.dll', 'wlanutil.dll', 'wlanmsm.dll', 'wcmsvc.dll', 'dot3api.dll',
                'dot3svc.dll', 'RpcRt4.dll', 'secur32.dll', 'ndisimplatform.sys') {
  DLL $f
}
foreach ($f in 'drivers\nwifi.sys', 'drivers\vwififlt.sys', 'drivers\vwifimp.sys', 'drivers\vwifibus.sys',
                'drivers\NdisImPlatform.sys') {
  DLL $f
}

HDR '2 live wlansvc/wcmsvc service key shape'
foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip') {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (Test-Path -LiteralPath $k) {
    $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
    O ('  KEY ' + $n + ' Start=' + $p.Start + ' Type=' + $p.Type + ' Group=' + $(if ($p.Group) { $p.Group } else { '-' }) +
       ' Depend=' + $(if ($p.DependOnService) { $p.DependOnService -join ',' } else { '-' }) +
       ' DDepend=' + $(if ($p.DependOnGroup) { $p.DependOnGroup -join ',' } else { '-' }) +
       ' Image=' + $(if ($p.ImagePath) { $p.ImagePath } else { '-' }))
    O ('       ServiceDll=' + $(if ($p.ServiceDll) { $p.ServiceDll } else { '-' }) +
       ' ServiceMain=' + $(if ($p.ServiceMain) { $p.ServiceMain } else { '-' }))
  } else { O ('  KEY ' + $n + ' ABSENT') }
}

HDR '3 svchost group tables'
$sv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' -EA SilentlyContinue
if ($null -eq $sv) { O '  SVCHOST_KEY ABSENT' } else {
  $props = @($sv.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })
  O ('  groups total = ' + $props.Count)
  foreach ($n in @($props | ForEach-Object { $_.Name })) {
    $lst = @($sv.$n)
    if ($n -match 'LocalSystemNetworkRestricted' -or ($lst -contains 'wlansvc') -or ($lst -contains 'wcmsvc') -or
        ($lst -contains 'nativewifip')) {
      O ('  GROUP ' + $n + ' (' + $lst.Count + ') = ' + ($lst -join ','))
    }
  }
  foreach ($n in 'LocalSystemNetworkRestricted', 'LocalService', 'NetworkService', 'GPSvcGroup', 'ndu') {
    $has = @($props | Where-Object { $_.Name -eq $n }).Count -gt 0
    O ('  HASGROUP ' + $n + ' = ' + $has)
  }
}

HDR '4 svchost processes actually running'
$procs = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -eq 'svchost.exe' })
O ('  svchost count=' + $procs.Count)
foreach ($p in $procs) { O ('  pid=' + $p.ProcessId + ' cmd=' + $p.CommandLine) }

HDR '5 SCM: start + real exit codes'
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class S54 {
  [StructLayout(LayoutKind.Sequential)]
  public struct SS {
    public int serviceType; public int currentState; public int controlsAccepted;
    public int win32ExitCode; public int serviceSpecificExitCode; public int checkPoint; public int waitHint;
  }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern IntPtr OpenSCManager(IntPtr machine, IntPtr db, int access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="OpenServiceW")]
  static extern IntPtr OpenService(IntPtr scm, string name, int access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartService(IntPtr svc, int numArgs, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatus(IntPtr svc, ref SS status);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool CloseServiceHandle(IntPtr h);
  public static string Probe(string name) {
    IntPtr scm = OpenSCManager(IntPtr.Zero, IntPtr.Zero, 0x0001);
    if (scm == IntPtr.Zero) return "OpenSCManager err=" + Marshal.GetLastWin32Error();
    IntPtr h = OpenService(scm, name, 0x0010 | 0x0001);
    if (h == IntPtr.Zero) {
      string r0 = "OpenService err=" + Marshal.GetLastWin32Error();
      CloseServiceHandle(scm); return r0;
    }
    bool ok = StartService(h, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    SS st = new SS();
    bool q = QueryServiceStatus(h, ref st);
    string r = String.Format("query={0} StartOK={1} err={2} state={3} win32Exit={4} specific=0x{5:X8} ckpt={6}",
      q, ok, e, st.currentState, st.win32ExitCode, st.serviceSpecificExitCode, st.checkPoint);
    CloseServiceHandle(h); CloseServiceHandle(scm);
    return r;
  }
}
'@ -EA Stop
  O '  ADDTYPE ok'
} catch { O ('  ADDTYPE-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
foreach ($n in 'RpcSs', 'DcomLaunch', 'nsi', 'wcmsvc', 'wlansvc', 'nativewifip') {
  try { O ('  SCM ' + $n + ' : ' + [S54]::Probe($n)) }
  catch { O ('  SCM ' + $n + ' ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
}
Start-Sleep -Seconds 5
foreach ($n in 'RpcSs', 'DcomLaunch', 'nsi', 'wcmsvc', 'wlansvc', 'nativewifip', 'vwifibus', 'vwifimp', 'vwififlt') {
  O ('  STATE ' + $n + ' = ' + (St $n))
}

HDR '6 restart the AX211 devnode and re-read the problem code'
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
O ('  MATCHES ' + $ents.Count)
if ($ents.Count -gt 0) {
  $pn = "$($ents[0].PNPDeviceID)"
  O ('  PNP ' + $pn)
  $r = @(& pnputil.exe /restart-device $pn 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
  O ('  RESTART ' + ($r -join ' | '))
  Start-Sleep -Seconds 8
  $d = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($x in $d) { O ('  AFTER code=' + $x.ConfigManagerErrorCode + ' status=' + $x.Status + ' name=' + $x.Name) }
}

HDR '7 wlanapi'
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W54 {
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
  [DllImport("wlanapi.dll")]
  public static extern int WlanCloseHandle(IntPtr handle, IntPtr res);
}
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [W54]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  WLANOPEN rc=' + $rc + ' newver=' + $nv)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    $rc2 = [W54]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt)
    O ('  WLANENUM rc=' + $rc2 + ' ifaces=' + $cnt)
    [void][W54]::WlanCloseHandle($h, [IntPtr]::Zero)
  }
} catch { O ('  WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
O 'P54 END'
