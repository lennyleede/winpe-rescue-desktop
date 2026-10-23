# probe71 -- LIVE PE. probe70 settled it: the working machine's registry shape (Enum\..\UpperFilters=vwifibus,
# class-slot Linkage\FilterList with nwifi+vwififlt, component store records, service keys, .cat, .sys) can be
# reproduced 1:1 and NOTHING attaches -- no NativeWifiP\Parameters\Adapters marker, vwifibus/vwififlt stay
# Stopped, device stays code 37. So the blocker is not registry shape any more. probe71 goes after the actual
# failure report: ETW read with -Oldest (probe68's failure was just the missing -Oldest switch on analytic
# channels), the raw CM_DEVNODE status, whether Netwtw14 is even running, and NtLoadDriver's real NTSTATUS for
# the WiFi filter drivers (CI passes this boot, so a 0xC0000428 is no longer the confounder).
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }

try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P71 {
  [DllImport("cfgmgr32.dll")]
  public static extern int CM_Locate_DevNodeW(out int devInst, string szDeviceID, int ulFlags);
  [DllImport("cfgmgr32.dll")]
  public static extern int CM_Get_DevNode_Status(out int status, out int problemCode, int devInst, int ulFlags);
  [DllImport("ntdll.dll")]
  public static extern int NtLoadDriver(string driverServiceName);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool OpenProcessToken(IntPtr p, int a, out IntPtr t);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool LookupPrivilegeValueW(string host, string name, out LUID luid);
  [StructLayout(LayoutKind.Sequential)]
  struct LUID { public int LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  struct TP { public int Count; public int LuidLow; public int LuidHigh; public int Attr; }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP newSt, int len, IntPtr prev, IntPtr rl);
  [DllImport("kernel32.dll")]
  static extern IntPtr GetCurrentProcess();
  public static string DevStatus(string id) {
    int inst = 0;
    int r = CM_Locate_DevNodeW(out inst, id, 0);
    if (r != 0) { return "LOCATE err=" + r; }
    int status = 0; int prob = 0;
    int r2 = CM_Get_DevNode_Status(out status, out prob, inst, 0);
    return "cmr=" + r2 + " status=0x" + status.ToString("X8") + " problem=" + prob;
  }
  public static string EnablePriv() {
    IntPtr tok = IntPtr.Zero;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) { return "TOKEN err=" + Marshal.GetLastWin32Error(); }
    LUID l = new LUID();
    if (!LookupPrivilegeValueW(null, "SeLoadDriverPrivilege", out l)) { return "LOOKUP err=" + Marshal.GetLastWin32Error(); }
    TP tp = new TP();
    tp.Count = 1; tp.LuidLow = l.LowPart; tp.LuidHigh = l.HighPart; tp.Attr = 2;
    if (!AdjustTokenPrivileges(tok, false, ref tp, 16, IntPtr.Zero, IntPtr.Zero)) { return "ADJUST err=" + Marshal.GetLastWin32Error(); }
    return "ok";
  }
  public static string Load(string keyPath) {
    int rc = NtLoadDriver(keyPath);
    return "rc=0x" + rc.ToString("X8") + " dos=" + (rc & 0xFFFF);
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { L ('  ADDTYPE-ERR ' + (Trim2 ('' + $_.Exception.Message) 400)); return }

$DEVID = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'

# ---------- 0. devnode + Netwtw14 truth ----------
L '=0 devnode + miniport'
L ('  0 CM ' + [P71]::DevStatus($DEVID))
L ('  0 EnablePriv ' + [P71]::EnablePriv())
foreach ($svc in 'nativewifip', 'vwififlt', 'vwifibus', 'Netwtw14', 'NdisVirtualBus') {
  $r = [P71]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\' + $svc)
  L ('  0 NtLoadDriver ' + $svc + ' ' + $r)
}
$dq = @(& driverquery.exe /v /fo csv 2>&1)
foreach ($ln in $dq) { if ((Clean ('' + $ln)) -match '(?i)netwtw|wifi|vwifi') { L ('  0 DQ ' + (Trim2 ('' + $ln) 200)) } }
foreach ($n in 'Netwtw14', 'nativewifip', 'vwifibus') {
  $sd = Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -eq $n }
  if ($null -ne $sd) { L ('  0 SYS ' + $n + ' state=' + (Clean ('' + $sd.State)) + ' startmode=' + (Clean ('' + $sd.StartMode)) + ' path=' + (Clean ('' + $sd.PathName))) }
}

# ---------- 1. is the installed Intel package dir intact? ----------
L '=1 intel package dirs'
$dirs = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netwtw*' })
foreach ($d in $dirs) {
  $fl = @(Get-ChildItem -LiteralPath $d.FullName -EA SilentlyContinue)
  $sys = @($fl | Where-Object { $_.Name -like '*.sys' })
  $dll = @($fl | Where-Object { $_.Name -like '*IHV*' })
  L ('  1 ' + $d.Name + ' files=' + $fl.Count + ' sys=' + (@($sys | ForEach-Object { $_.Name }) -join ',') + ' ihv=' + (@($dll | ForEach-Object { $_.Name }) -join ',') + ' bytes=' + (@($fl | Measure-Object -Property Length -Sum).Sum))
}
$ip = 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\IntelIHVRouter14.dll'
L ('  1 stale-pointer IHV exists=' + (Test-Path -LiteralPath $ip))
$k = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netwtw14' -EA SilentlyContinue
if ($null -ne $k) { L ('  1 Netwtw14 ImagePath=' + (Clean ('' + $k.GetValue('ImagePath', '-'))) + ' start=' + $k.GetValue('Start') + ' group=' + (Clean ('' + $k.GetValue('Group', '-')))) }

# ---------- 2. ETW baseline ----------
$CH = 'Microsoft-Windows-NDIS/Diagnostic', 'Microsoft-Windows-NDIS/Operational', 'Microsoft-Windows-Kernel-PnP/Configuration', 'Microsoft-Windows-Kernel-PnP/Driver Diagnostic', 'Microsoft-Windows-Kernel-PnP/Device Management', 'Microsoft-Windows-UserPnp/DeviceInstall', 'Microsoft-Windows-Network-Setup/Diagnostic'
function Etw([string]$tag, [int]$max) {
  foreach ($ch in $CH) {
    $pre = $ch.Replace('Microsoft-Windows-', '')
    try {
      $evs = @(Get-WinEvent -LogName $ch -Oldest -MaxEvents $max -EA Stop)
      L ('  ' + $tag + ' ' + $pre + ' n=' + $evs.Count)
      foreach ($e in $evs) { L ('  ' + $tag + ' ' + $pre + ' [' + $e.TimeCreated.ToString('HH:mm:ss') + '] id=' + $e.Id + ' lvl=' + $e.Level + ' ' + (Trim2 ('' + $e.Message) 210)) }
    } catch { L ('  ' + $tag + ' ' + $pre + ' ERR ' + (Trim2 ('' + $_.Exception.Message) 140)) }
  }
}
L '=2 etw baseline'
Etw 'E0' 45

# ---------- 3. trigger and re-read ----------
L '=3 restart-device then etw again'
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es.Count -eq 0) { L '  3 NO DEVNODE' } else {
  L ('  3 RESTART ' + (Trim2 ((@(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 200))
}
Start-Sleep -Seconds 10
L ('  3 CM after ' + [P71]::DevStatus($DEVID))
L ('  3 NtLoad nativewifip ' + [P71]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\nativewifip'))
Etw 'E1' 45
L 'P71 END'
