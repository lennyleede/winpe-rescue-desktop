# ============================================================
# probe104_wdi_host_account.ps1 -- decide the bake shape for WdiServiceHost
# ============================================================
#   probe102 proved the 1297 is RequiredPrivileges: with [SeChangeNotify;SeImpersonate;SeSystemProfile] the SCM
#   refuses WdiServiceHost (1297 = the logon account cannot be granted that privilege in PE), dropping
#   SeSystemProfilePrivilege makes the start go through (START_OK), and deleting the value outright gives
#   START_ERR=13 (so "just omit it" is not an option either).
#   probe103 could NOT re-measure that service, because probe102 had already deleted the value (FIX orig=[] ->
#   START_ERR=13) -- the live hive carries the previous experiment, which is exactly the trap these probes keep
#   warning about. So this probe restores state explicitly and compares the two candidate bakes:
#     A) ObjectName = NT AUTHORITY\LocalService, RequiredPrivileges = [SeChangeNotify;SeImpersonate]
#        (host minus the one privilege PE cannot grant)
#     B) ObjectName = LocalSystem, RequiredPrivileges = the host's three (LocalSystem holds everything)
#   Each is applied with ChangeServiceConfigW (services.exe keeps its own snapshot of the DB, so writing the hive
#   alone would not be seen by a live start) and then measured with the same 6 s / 100 ms transition curve that
#   made probe103 useful: wcmsvc reached RUNNING at 105 ms and died at 323 ms with win32exit=1067, wlansvc went
#   START_PENDING -> STOP_PENDING -> STOPPED 0x800C0006 in 220 ms with no WlansvcGroup process ever appearing.
#   Whichever candidate actually STAYS Running is what goes into wifi-inject; if neither does, the exit code and
#   the lifetime are still new information about the same wall wlansvc is hitting.
#   Output: single-line ASCII, prefix P104.
param([switch]$DryRun)
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P104 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Runtime.InteropServices;
public static class Pe104 {
  [StructLayout(LayoutKind.Sequential)]
  public struct QUERY_CONFIG {
    public int dwServiceType; public int dwStartType; public int dwErrorControl;
    public IntPtr lpBinaryPathName; public IntPtr lpLoadOrderGroup; public int dwTagId;
    public IntPtr lpDependencies; public IntPtr lpServiceStartName; public IntPtr lpDisplayName;
  }
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr Svc, int InfoLevel, IntPtr Buf, uint Size, out uint Needed);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ChangeServiceConfigW(IntPtr Svc, uint dwServiceType, uint dwStartType, uint dwErrorControl,
      string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies,
      string lpServiceStartName, string lpPassword, string lpDisplayName);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_CHANGE_CONFIG = 0x0002;
  const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
  public static string Start(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "OPENSCMANAGER_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_START | SERVICE_QUERY_STATUS);
      if (sv == IntPtr.Zero) { return "OPENSERVICE_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        if (!StartServiceW(sv, 0, IntPtr.Zero)) { return "START_ERR=" + Marshal.GetLastWin32Error(); }
        return "START_OK";
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
  public static string Status(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "SCM_ERR"; }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_QUERY_STATUS);
      if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        IntPtr buf = Marshal.AllocHGlobal(36);
        try {
          uint need = 0;
          if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) { return "QSS_ERR=" + Marshal.GetLastWin32Error(); }
          int state = Marshal.ReadInt32(buf, 4);
          int win32 = Marshal.ReadInt32(buf, 12);
          int spec = Marshal.ReadInt32(buf, 16);
          uint pid = (uint)Marshal.ReadInt32(buf, 28);
          string sn = state == 1 ? "STOPPED" : state == 2 ? "START_PENDING" : state == 3 ? "STOP_PENDING" :
                      state == 4 ? "RUNNING" : ("state" + state);
          return sn + " win32=0x" + win32.ToString("X8") + "(" + win32 + ") spec=0x" + spec.ToString("X8") + " pid=" + pid;
        } finally { Marshal.FreeHGlobal(buf); }
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
  // The live change SCM actually honours. Pass null to leave a field alone (API wants the SERVICE_NO_CHANGE
  // sentinel for the dwords and NULL for the strings).
  public static string ChangeObject(string name, string account) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "SCM_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_CHANGE_CONFIG);
      if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        if (ChangeServiceConfigW(sv, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, null, null,
                                 IntPtr.Zero, null, account, null, null)) { return "CHANGED->" + account; }
        return "CHANGE_ERR=" + Marshal.GetLastWin32Error();
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe104 begin native=' + $native + ' dryrun=' + $DryRun)

# ---------- 0) what is in the hive right now (probe102/103 left the value deleted -- state matters) ----------
foreach ($n in @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  $rp = @($p.RequiredPrivileges | ForEach-Object { "$_" })
  $kp = Join-Path $k 'Parameters'
  $dll = '' + (Get-ItemProperty -LiteralPath $kp -EA SilentlyContinue).ServiceDll
  $main = '' + (Get-ItemProperty -LiteralPath $kp -EA SilentlyContinue).ServiceMain
  L('NOW ' + $n + ' obj=[' + (C ('' + $p.ObjectName)) + '] type=0x' + ('{0:X}' -f [int]$p.Type) +
    ' privs=[' + ($rp -join ';') + '] dll=[' + (C $dll) + '] main=[' + (C $main) + ']')
}

function Curve([string]$n, [string]$tag) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = 'no-native'
  if ($native) { $r = [Pe104]::Start($n) }
  $t0 = $sw.ElapsedMilliseconds
  $seen = @()
  $runMs = -1
  while ($sw.ElapsedMilliseconds -lt 6000) {
    $s = ''
    if ($native) { $s = [Pe104]::Status($n) }
    if ($s -match 'RUNNING' -and $runMs -lt 0) { $runMs = $sw.ElapsedMilliseconds - $t0 }
    $key = ($s -replace '^state\d+ ', '')
    if (@($seen).Count -eq 0 -or ("$($seen[-1])" -replace '^\d+ms ', '') -ne $key) { $seen += ((($sw.ElapsedMilliseconds - $t0)).ToString() + 'ms ' + $key) }
    Start-Sleep -Milliseconds 80
  }
  L('CURVE ' + $n + ' [' + $tag + '] start=' + $r + ' running_at=' + $runMs + 'ms states=[' +
    (($seen | Select-Object -First 6) -join ' -> ') + ']')
}

# Write a registry value the way that definitely works offline AND live: New-ItemProperty -Force creates or
# replaces, and we read the value straight back so a silently-ignored write can never masquerade as a control.
function SetVal([string]$k, [string]$name, $value, [string]$type) {
  try {
    New-ItemProperty -LiteralPath $k -Name $name -Value $value -PropertyType $type -Force -EA Stop | Out-Null
  } catch { L('SETVAL ERR ' + $name + ' ' + (C $_.Exception.Message)) }
  $back = (Get-ItemProperty -LiteralPath $k -EA SilentlyContinue).$name
  $txt = if ($back -is [array]) { ($back -join ';') } else { "$back" }
  L('SETVAL ' + $name + '=[' + (C $txt) + ']')
}

# ---------- A) host-minus-one-privilege, LocalService ----------
$wdiK = 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost'
if (-not $DryRun) {
  SetVal $wdiK 'RequiredPrivileges' ([string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege')) 'MultiString'
  SetVal $wdiK 'ObjectName' 'NT AUTHORITY\LocalService' 'String'
  if ($native) { L('APPLY A ' + [Pe104]::ChangeObject('WdiServiceHost', 'NT AUTHORITY\LocalService')) }
}
Curve 'WdiServiceHost' 'A localservice 2 privs'

# ---------- B) LocalSystem with the host's three privileges ----------
if (-not $DryRun) {
  # ChangeServiceConfigW refuses to switch the logon account of a RUNNING service (1073), so if A actually
  # took hold and the host stayed up, stop it first -- otherwise B is unmeasurable and we would report that.
  if ("$((Get-Service -Name 'WdiServiceHost' -EA SilentlyContinue).Status)" -eq 'Running') {
    Stop-Service -Name 'WdiServiceHost' -Force -EA SilentlyContinue
    L('APPLY B stopped the running host first, now=' + (Get-Service -Name 'WdiServiceHost' -EA SilentlyContinue).Status)
  }
  SetVal $wdiK 'RequiredPrivileges' ([string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege', 'SeSystemProfilePrivilege')) 'MultiString'
  if ($native) { L('APPLY B ' + [Pe104]::ChangeObject('WdiServiceHost', 'LocalSystem')) }
  SetVal $wdiK 'ObjectName' 'LocalSystem' 'String'
}
Curve 'WdiServiceHost' 'B localsystem 3 privs'

# who is hosting what after the two attempts
foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  $hosted = @(Get-CimInstance Win32_Service -Filter ('ProcessId=' + $p.ProcessId) -EA SilentlyContinue | ForEach-Object { $_.Name })
  $cl = C ('' + $p.CommandLine)
  if ($cl -notmatch '(?i)LocalService|LocalSystemNetwork') { continue }
  L('PROC pid=' + $p.ProcessId + ' cmd=[' + $cl + '] hosts=[' + ($hosted -join ';') + ']')
}

# ---------- C) the other three, same curve, so we get their exit codes side by side ----------
foreach ($n in @('wdisystemhost', 'wcmsvc', 'wlansvc')) {
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  if ("$st" -eq 'Running') { L('CURVE ' + $n + ' already Running'); continue }
  Curve $n 'restart-after-wdi'
}
# one more wlansvc attempt with the WDI hosts having been tried first (order is the host's order)
Curve 'wlansvc' 'second attempt'
L('WLANAPI-STATE ' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status)

# final state, same readout as the NOW lines, so the log closes with what the hive+SCM actually hold now
foreach ($n in @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  $rp = @($p.RequiredPrivileges | ForEach-Object { "$_" })
  L('POST ' + $n + ' obj=[' + (C ('' + $p.ObjectName)) + '] privs=[' + ($rp -join ';') + '] svc=' +
    (Get-Service -Name $n -EA SilentlyContinue).Status)
}
L('probe104 end -- CURVE running_at + win32 code pick the bake; A vs B decides ObjectName/privileges for the disc')
