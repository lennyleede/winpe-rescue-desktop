# probe154 -- can this PE's SCM launch an OWN-PROCESS service at all, and which part of the wlansvc
# record stops it? probe153's fake svchost proved its child works when *we* start it (K1 self test:
# Add-Type compiled, VEH installed, dispatcher reached, 60 log lines written from
# X:\p153_host_out.txt) but when the SCM was asked to start the same script as wlansvc (K2/K3)
# StartService came back ERR=1053 (ERROR_SERVICE_REQUEST_TIMEOUT) and K4 found the log file MISSING --
# not truncated, absent -- so either the process was never created, or it died before its first write.
# That distinction decides the next instrument, so measure it directly instead of guessing.
#
# What is already closed (do not re-test):
#   probe150  FILE + API-SET layer: S1 loadable=82/82 first-fail=none, S2 delay-resolvable=32/34, and
#             ext-ms-win-wlan-grouppolicy -> X:\windows\SYSTEM32\wlgpclnt.dll resolves here.
#             The 2 dead contracts are dead on the healthy host too (build\scratch\p150b_host_control.txt).
#   probe152  WMI: WinMGmt already RUNNING, OBJECTS.DATA present; starting it changed nothing
#             (wlansvc still loaded=36 win32hex=0x800C0006 t=122ms).
#   probe113  Parameters subtree, probe97 DLL closure, probe98 registry path names, probe112 record shape.
#
# Instruments, cheapest first. Each rung answers one yes/no:
#   E0 one EnumServicesStatusExW snapshot of the whole SCM DB -> does ANY type=0x10 service reach RUNNING
#      in this PE? If yes, own-process launching is not broken in principle and the blocker is in the
#      record or the image. dwServiceType lives at SERVICE_STATUS_PROCESS+0 (state@4, exit@12, pid@28).
#   E1 the SCM's own timeouts/policy: ServicesPipeTimeout / fGroupBasedPolicy / startup flags.
#   E2 ladder on a throwaway service (name hm154t, ImagePath = cmd.exe /c echo > marker). Marker appears
#      => the SCM created the process. Then add exactly one wlansvc-record attribute per rung
#      (RequiredPrivileges, DependOnService, ServiceSidType, GroupName) and find which one kills it.
#      RequiredPrivileges is the interesting one: for an OWN-process service the SCM builds the child
#      token from that list, so a privilege LocalSystem does not actually hold in a PE is fatal here even
#      though svchost (shared) hides the difference.
#   E3 wlansvc's own record + a cmd marker ImagePath: same launch mechanism as E2 but the real name, so a
#      difference between E2-last and E3 is a property of the *name* (SCM cache, dependencies already
#      being started, group membership), not of the values.
#   E4 wlansvc's record + powershell marker ImagePath: does powershell.exe itself run when the SCM starts
#      it? Decisive for probe153's silence -- if the marker appears, the fake host died before OpenLog;
#      if it does not, a .NET/CLR process cannot be a service process in this PE and the host must be a
#      compiled native exe.
#   E5 whatever the SCM itself logged (Service Control Manager provider, 7000/7001/7009/7011/7026/7031).
#   E6..E8 wlansvc as TYPE=0x10 (own process) with a svchost body, in the three groups that exist here.
#      This is not a leftover: build\scratch\p154_host_readonly.txt read the HEALTHY reference machine's own
#      SCM DB and WlanSvc is t0x10 there (own pid 6128, not the RpcSs svchost pid) with ImagePath still
#      svchost.exe -k LocalSystemNetworkRestricted -p, and Wcmsvc is t0x10 too, while RpcSs/netprofm/Dhcp
#      are t0x20. Our PE bakes 0x20 + -k WlansvcGroup and probe112 only ever tested 0x20, so the dedicated-
#      svchost hosting model the reference uses is the one untested record difference.
#   E9 probe153's fake host again, now that E3/E4 say whether the SCM creates the process at all.
# Every rung restores or deletes what it made: the test service is deleted at the end, wlansvc's
# ImagePath/Type are put back byte for byte in Z9. Nothing is written to the disc; X: is a RAM disk.
param([switch]$DryRun, [switch]$SelfTest, [string]$Root = 'X:\Windows\System32',
      [string]$TestPrefix = 'hm154', [string]$SvcName = 'wlansvc',
      [string]$MarkerDir = '')
function L([string]$s) { Write-Output ('P154 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = (C $Root)
$svcRel = 'SYSTEM\CurrentControlSet\Services\' + (C $SvcName)
$psExe = (C ([System.IO.Path]::Combine($s32, 'WindowsPowerShell\v1.0\powershell.exe')))
$svcHost = (C ([System.IO.Path]::Combine($s32, 'svchost.exe')))
$cmdExe = (C ([System.IO.Path]::Combine($s32, 'cmd.exe')))

$src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class Cm154 {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool StartServiceW(IntPtr svc, uint argc, IntPtr argv);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool ControlService(IntPtr svc, uint control, IntPtr status);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceStatusEx(IntPtr svc, uint level, IntPtr buf, uint cb, out uint need);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool DeleteService(IntPtr svc);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool EnumServicesStatusExW(IntPtr scm, uint level, uint type, uint state, IntPtr buf,
      uint cb, out uint needed, out uint returned, ref uint resume, string group);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegGetValueW(IntPtr hkey, string sub, string val, uint flags, out uint type,
      IntPtr data, ref uint cb);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegCreateKeyExW(IntPtr hkey, string sub, uint reserved, string cls, uint options,
      uint access, IntPtr sec, out IntPtr key, out uint disp);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegSetValueExW(IntPtr key, string val, uint reserved, uint type, byte[] data, uint cb);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegDeleteKeyW(IntPtr hkey, string sub);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern int RegCloseKey(IntPtr key);

  const uint SC_MANAGER_CONNECT = 0x0001, SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004,
             SERVICE_QUERY_CONFIG = 0x0001, SERVICE_DELETE = 0x00010000;
  const uint RRF_RT_ANY = 0xFFFF, RRF_WOW64_64KEY = 0x00010000, KEY_WRITE = 0x20006;
  static readonly IntPtr HKLM = new IntPtr(-2147483646);

  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : st == 5 ? "CONTINUE_PENDING" : st == 6 ? "PAUSE_PENDING" :
           st == 7 ? "PAUSED" : ("state" + st);
  }

  // ---------- registry ----------
  public static string RegQuery(string sub, string val) {
    uint type = 0, cb = 0;
    int rc = RegGetValueW(HKLM, sub, val, RRF_RT_ANY | RRF_WOW64_64KEY, out type, IntPtr.Zero, ref cb);
    if (rc != 0) return "RC=" + rc;
    IntPtr buf = Marshal.AllocHGlobal((int)cb);
    try {
      rc = RegGetValueW(HKLM, sub, val, RRF_RT_ANY | RRF_WOW64_64KEY, out type, buf, ref cb);
      if (rc != 0) return "RC2=" + rc;
      if (type == 1 || type == 2 || type == 6) return Marshal.PtrToStringUni(buf);
      if (type == 4) return "DWORD=0x" + ((uint)Marshal.ReadInt32(buf)).ToString("X8");
      if (type == 7) {
        string all = Marshal.PtrToStringUni(buf, (int)(cb / 2));
        System.Collections.Generic.List<string> parts =
          new System.Collections.Generic.List<string>();
        foreach (string p in all.Split('\0')) if (p.Length > 0) parts.Add(p);
        return "MULTI[" + string.Join(";", parts.ToArray()) + "]";
      }
      return "type" + type + " cb=" + cb;
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static int RegSetDw(string sub, string val, uint data) {
    IntPtr key; uint disp;
    int rc = RegCreateKeyExW(HKLM, sub, 0, null, 0, KEY_WRITE | 0x0100, IntPtr.Zero, out key, out disp);
    if (rc != 0) return rc;
    try { return RegSetValueExW(key, val, 0, 4, BitConverter.GetBytes(data), 4); }
    finally { RegCloseKey(key); }
  }
  public static int RegSetSz(string sub, string val, string data, bool expand) {
    IntPtr key; uint disp;
    int rc = RegCreateKeyExW(HKLM, sub, 0, null, 0, KEY_WRITE | 0x0100, IntPtr.Zero, out key, out disp);
    if (rc != 0) return rc;
    try {
      byte[] b = Encoding.Unicode.GetBytes(data + "\0");
      return RegSetValueExW(key, val, 0, expand ? 2u : 1u, b, (uint)b.Length);
    } finally { RegCloseKey(key); }
  }
  public static int RegSetMulti(string sub, string val, string[] items) {
    IntPtr key; uint disp;
    int rc = RegCreateKeyExW(HKLM, sub, 0, null, 0, KEY_WRITE | 0x0100, IntPtr.Zero, out key, out disp);
    if (rc != 0) return rc;
    try {
      string all = "";
      foreach (string s in items) all += s + "\0";
      all += "\0";
      byte[] b = Encoding.Unicode.GetBytes(all);
      return RegSetValueExW(key, val, 0, 7, b, (uint)b.Length);
    } finally { RegCloseKey(key); }
  }
  public static int RegDelKey(string sub) { return RegDeleteKeyW(HKLM, sub); }

  // ---------- SCM ----------
  public static string StartAndTime(string svc) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR=" + Marshal.GetLastWin32Error();
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      int serr = started ? 0 : Marshal.GetLastWin32Error();
      string head = "StartService=" + (started ? "OK" : ("ERR=" + serr + " after " + sw.ElapsedMilliseconds +
        "ms")) + " (" + ErrName(serr) + ")";
      int st = -1, pid = 0, wx = 0;
      for (int i = 0; i < 40; i++) {
        IntPtr buf = Marshal.AllocHGlobal(36); uint need = 0;
        if (QueryServiceStatusEx(sv, 0, buf, 36, out need)) {
          st = Marshal.ReadInt32(buf, 4); pid = Marshal.ReadInt32(buf, 28); wx = Marshal.ReadInt32(buf, 12);
        }
        Marshal.FreeHGlobal(buf);
        if (st == 4 || st == 1) break;
        System.Threading.Thread.Sleep(50);
      }
      return head + " | state=" + StateName(st) + " pid=" + pid +
             " win32hex=0x" + ((uint)wx).ToString("X8") + " total=" + sw.ElapsedMilliseconds + "ms";
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  public static string Stop(string svc) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR";
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN err=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      bool r = ControlService(sv, 1, st);
      int e = Marshal.GetLastWin32Error();
      Marshal.FreeHGlobal(st);
      return r ? "STOP sent" : ("stop err=" + e + " (1062=not running, 1052=cannot control)");
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  public static string StopAndDelete(string svc) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR";
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_DELETE);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN err=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      ControlService(sv, 1, st); Marshal.FreeHGlobal(st);
      bool d = DeleteService(sv);
      return "delete=" + d + (d ? "" : (" err=" + Marshal.GetLastWin32Error()));
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  public static string SvcState(string svc) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR";
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN"; }
    try {
      IntPtr buf = Marshal.AllocHGlobal(36); uint need = 0;
      string r = QueryServiceStatusEx(sv, 0, buf, 36, out need)
        ? (StateName(Marshal.ReadInt32(buf, 4)) + " pid=" + Marshal.ReadInt32(buf, 28))
        : ("QSS_ERR=" + Marshal.GetLastWin32Error());
      Marshal.FreeHGlobal(buf);
      return r;
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  static string ErrName(int e) {
    if (e == 1053) return "SERVICE_REQUEST_TIMEOUT(the process never connected to the SCM)";
    if (e == 1056) return "ALREADY_RUNNING";
    if (e == 1058) return "SERVICE_DISABLED_OR_DEPENDENCY_NOT_RUNNING";
    if (e == 1063) return "FAILED_TO_CONNECT_TO_SCM";
    if (e == 1067) return "PROCESS_TERMINDATED";
    if (e == 5) return "ACCESS_DENIED";
    if (e == 2) return "NOT_FOUND";
    if (e == 1072) return "MARKED_FOR_DELETION";
    if (e == 1) return "FUNCTION_NOT_SUPPORTED";
    return "";
  }
  // ENUM_SERVICE_STATUS_PROCESSW: two LPCWSTR then SERVICE_STATUS_PROCESS(36B).
  public static string[] Snapshot() {
    System.Collections.Generic.List<string> res = new System.Collections.Generic.List<string>();
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == IntPtr.Zero) { res.Add("SCM_ERR=" + Marshal.GetLastWin32Error()); return res.ToArray(); }
    try {
      uint needed = 0, returned = 0, resume = 0;
      uint cb = 64u * 1024u;
      IntPtr buf = Marshal.AllocHGlobal((int)cb);
      bool ok = EnumServicesStatusExW(scm, 0, 0x3F0u, 0x03u, buf, cb, out needed, out returned,
                                      ref resume, null);
      int err = Marshal.GetLastWin32Error();
      if (!ok && err != 1) {   // 1 = ERROR_MORE_DATA, fine for a first page
        res.Add("ENUM_ERR=" + err + " needed=" + needed);
        Marshal.FreeHGlobal(buf);
        return res.ToArray();
      }
      int off = 0;
      for (uint i = 0; i < returned; i++) {
        IntPtr pName = Marshal.ReadIntPtr(buf, off);
        IntPtr pDisp = Marshal.ReadIntPtr(buf, off + IntPtr.Size);
        int stOff = off + 2 * IntPtr.Size;
        uint type = (uint)Marshal.ReadInt32(buf, stOff);
        int state = Marshal.ReadInt32(buf, stOff + 4);
        int wx = Marshal.ReadInt32(buf, stOff + 12);
        int pid = Marshal.ReadInt32(buf, stOff + 28);
        string name = Marshal.PtrToStringUni(pName);
        res.Add(name + "|t0x" + type.ToString("X") + "|" + StateName(state) +
                "|pid" + pid + "|0x" + ((uint)wx).ToString("X8"));
        // struct size: 2 pointers + 36 bytes, padded to pointer alignment on x64 -> 16 + 36 = 52 -> 56
        off += (2 * IntPtr.Size) + 36;
        if (IntPtr.Size == 8) off += 4;
        off = (off + (IntPtr.Size - 1)) & ~(IntPtr.Size - 1);
      }
      res.Add("RETURNED=" + returned + " needed=" + needed);
      Marshal.FreeHGlobal(buf);
      return res.ToArray();
    } finally { CloseServiceHandle(scm); }
  }
}
'@

if ($DryRun) {
  L('DRY probe154: E0 EnumServicesStatusExW snapshot(whole SCM DB, type/state/pid), E1 control timeouts,')
  L('DRY E2 throwaway ' + $TestPrefix + 'a..f, one name per rung (cmd.exe writes a marker), adding exactly one')
  L('DRY  wlansvc-record attribute per rung (privileges / dependencies / ServiceSidType / group),')
  L('DRY E4 wlansvc+powershell marker, E5 Service Control Manager events. Test services are deleted, wlansvc')
  L('DRY ImagePath/Type restored; X: RAM disk only, the disc is never touched.')
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1')
  exit 0
}
L('probe154 begin root=[' + $s32 + '] svc=' + $SvcName + ' test=' + $TestPrefix + 'a..f')
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)); L('ABORT'); exit 1 }
if (-not $MarkerDir) {
  $drv = (C $Root); $k = $drv.IndexOf(':')
  if ($k -gt 0) { $MarkerDir = $drv.Substring(0, $k) + ':\p154' } else { $MarkerDir = 'X:\p154' }
}
L('marker dir=' + (C $MarkerDir))
if (-not (Test-Path -LiteralPath $MarkerDir)) { try { New-Item -ItemType Directory -Force -Path $MarkerDir | Out-Null } catch { L('MKDIR FAIL ' + (C $_.Exception.Message)) } }

function Mark([string]$tag) { return (C ([System.IO.Path]::Combine($MarkerDir, 'm_' + $tag + '.txt'))) }
function ReadMark([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'MARKER ABSENT' }
  $t = ''
  try { $t = (Get-Content -LiteralPath $p -Raw -EA SilentlyContinue) } catch { $t = 'READ_ERR' }
  return 'MARKER=[' + (C $t) + ']'
}
function DelMark([string]$p) { try { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -EA SilentlyContinue } } catch { } }

# ---------- E0: what does the SCM actually hold, and is any own-process service RUNNING ----------
$snap = @([Cm154]::Snapshot())
L('E0 snapshot lines=' + $snap.Count)
$all = @(); $own = @(); $run = @(); $ownRun = @()
foreach ($x in $snap) {
  if ($x -match '^(ENUM_ERR|SCM_ERR|RETURNED)') { L('E0 ' + (C $x)); continue }
  $all += $x
  $f = ('' + $x) -split '\|'
  if ($f.Count -lt 3) { L('E0 ODD ' + (C $x)); continue }
  if ($f[1] -eq 't0x10') { $own += $x }
  if ($f[2] -eq 'RUNNING') { $run += $x }
  if ($f[1] -eq 't0x10' -and $f[2] -eq 'RUNNING') { $ownRun += $x }
}
L('E0 enumerated=' + @($all).Count + ' own-process(type0x10)=' + @($own).Count +
  ' own-process RUNNING=' + @($ownRun).Count + ' RUNNING(all types)=' + @($run).Count)
foreach ($x in @($ownRun)) { L('E0 OWN-RUNNING ' + (C $x)) }
foreach ($x in @($all)) {
  if ($x -like 'wlansvc|*' -or $x -like 'wcmsvc|*' -or $x -like 'WdiServiceHost|*' -or
      $x -like 'wdisystemhost|*' -or $x -like 'nativewifip|*' -or $x -like 'RpcSs|*' -or
      $x -like 'Ndisuio|*') { L('E0 relevant ' + (C $x)) }
}

# ---------- E1: the SCM's own patience settings ----------
foreach ($v in @('ServicesPipeTimeout', 'WaitToKillServiceTimeout', 'fGroupBasedPolicy', 'ServiceCtrlTimeout')) {
  L('E1 Control\' + $v + ' = ' + (C ([Cm154]::RegQuery('SYSTEM\CurrentControlSet\Control', $v))))
}
L('E1 wlansvc now ' + (C ([Cm154]::SvcState($SvcName))))
if ($SelfTest) {
  L('SELFTEST read-only pass done (E0+E1 only): no service was created, no record was touched, exit 0')
  exit 0
}

# ---------- E2: the record ladder on a throwaway service ----------
$privs = @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege', 'SeAuditPrivilege', 'SeTcbPrivilege',
           'SeDebugPrivilege', 'SeLoadDriverPrivilege')
$deps = @('nativewifip', 'RpcSs', 'Ndisuio')
# bare ImagePath first: cmd writes a marker, then pings ~3s so QueryServiceStatusEx can see a live pid
function SetBase([string]$rel, [string]$body) {
  $rc = [Cm154]::RegSetSz($rel, 'ImagePath', $body, $false)
  $rc2 = [Cm154]::RegSetDw($rel, 'Type', 0x10)
  $rc3 = [Cm154]::RegSetDw($rel, 'Start', 3)
  $rc4 = [Cm154]::RegSetDw($rel, 'ErrorControl', 1)
  return 'path=' + $rc + ' type=' + $rc2 + ' start=' + $rc3 + ' errctl=' + $rc4
}
function WipeVal([string]$rel, [string]$val) {
  # no RegDeleteValueW in the class; an empty MULTI_SZ reads as "no value" to the SCM
  [void]([Cm154]::RegSetMulti($rel, $val, @()))
}
# one service NAME per rung: DeleteService only marks for deletion, and re-creating a marked name in the
# same second would make OpenService answer 1072 and blur the measurement.
$rungs = @(
  @{ nm = 'a'; tag = 'e2a_bare';   privs = $false; deps = $false; sid = $false; grp = $false },
  @{ nm = 'b'; tag = 'e2b_privs';  privs = $true;  deps = $false; sid = $false; grp = $false },
  @{ nm = 'c'; tag = 'e2c_deps';   privs = $false; deps = $true;  sid = $false; grp = $false },
  @{ nm = 'd'; tag = 'e2d_sid';    privs = $false; deps = $false; sid = $true;  grp = $false },
  @{ nm = 'e'; tag = 'e2e_grp';    privs = $false; deps = $false; sid = $false; grp = $true },
  @{ nm = 'f'; tag = 'e2f_all';    privs = $true;   deps = $true;  sid = $true;  grp = $true }
)
foreach ($r in $rungs) {
  $tag = ('' + $r.tag)
  $svc = ('' + $TestPrefix) + ('' + $r.nm)
  $rel = 'SYSTEM\CurrentControlSet\Services\' + $svc
  $m = Mark $tag
  DelMark $m
  $body = '"' + $cmdExe + '" /c "echo ran_' + $tag + ' > ' + $m + ' & ping -n 4 127.0.0.1 >nul"'
  $setup = SetBase $rel $body
  if ($r.privs) { [void]([Cm154]::RegSetMulti($rel, 'RequiredPrivileges', $privs)) } else { WipeVal $rel 'RequiredPrivileges' }
  if ($r.deps)  { [void]([Cm154]::RegSetMulti($rel, 'DependOnService', $deps)) }      else { WipeVal $rel 'DependOnService' }
  if ($r.sid)   { [void]([Cm154]::RegSetDw($rel, 'ServiceSidType', 1)) }              else { [void]([Cm154]::RegSetDw($rel, 'ServiceSidType', 0)) }
  [void]([Cm154]::RegSetSz($rel, 'ObjectName', 'LocalSystem', $false))
  if ($r.grp)   { [void]([Cm154]::RegSetSz($rel, 'GroupName', 'WlansvcGroup', $false)) } else { WipeVal $rel 'GroupName' }
  $res = [Cm154]::StartAndTime($svc)
  L('E2 ' + $tag + ' setup[' + (C $setup) + '] ' + (C $res))
  L('E2 ' + $tag + ' ' + (C (ReadMark $m)))
  L('E2 ' + $tag + ' cfg ' + (C ([Cm154]::RegQuery($rel, 'ImagePath'))))
  L('E2 ' + $tag + ' cleanup ' + (C ([Cm154]::StopAndDelete($svc))) + ' delkey=' + [Cm154]::RegDelKey($rel))
  Start-Sleep -Milliseconds 400
}

# ---------- E3/E4: wlansvc's own record with a body we can see ----------
$origPath = [Cm154]::RegQuery($svcRel, 'ImagePath')
$origType = [Cm154]::RegQuery($svcRel, 'Type')
L('E3 saved ImagePath [' + (C $origPath) + '] Type ' + (C $origType))
if ('' + $origPath -notmatch '^[A-Za-z]:\\') {
  L('E3 ABORT: ImagePath did not read back as a path, refusing to mutate the record we cannot restore')
  exit 1
}
try {
  $m3 = Mark 'e3_wlansvc_cmd'
  DelMark $m3
  $b3 = '"' + $cmdExe + '" /c "echo wlansvc-ran > ' + $m3 + ' & ping -n 4 127.0.0.1 >nul"'
  L('E3 set ' + (C ([Cm154]::RegSetSz($svcRel, 'ImagePath', $b3, $false))) + ' type ' +
    (C ([Cm154]::RegSetDw($svcRel, 'Type', 0x10))))
  L('E3 ' + (C ([Cm154]::StartAndTime($SvcName))))
  L('E3 ' + (C (ReadMark $m3)))

  # ---------- E4: powershell.exe as the service body: can a CLR process be an SCM service child here ----------
  $m4 = Mark 'e4_wlansvc_ps'
  DelMark $m4
  $b4 = '"' + $psExe + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Set-Content -LiteralPath ''' + $m4 + ''' -Value ps-ran -Encoding ASCII; Start-Sleep -Seconds 8"'
  L('E4 body ' + (C $b4))
  L('E4 set ' + (C ([Cm154]::RegSetSz($svcRel, 'ImagePath', $b4, $false))))
  L('E4 ' + (C ([Cm154]::StartAndTime($SvcName))))
  L('E4 ' + (C (ReadMark $m4)))

  # ---------- E6/E7/E8: the hosting shape the HEALTHY reference machine actually uses ----------
  # build\scratch\p154_host_readonly.txt: the host's own SCM DB says WlanSvc = t0x10
  # (SERVICE_WIN32_OWN_PROCESS) RUNNING with its OWN pid (6128, not the RpcSs svchost pid 1084) even though
  # its ImagePath is still svchost.exe -k LocalSystemNetworkRestricted -p, and Wcmsvc is t0x10 as well.
  # Our PE bakes 0x20 + -k WlansvcGroup; probe112 tested 0x20 with and without -p but NEVER 0x10, so a
  # dedicated svchost instance is the one untested difference in the record -- and it is also the shape
  # probe153 needs, because an own-process service is what makes the SCM create our host process.
  $shapes = @(
    @{ tag = 'E6'; type = 0x10; body = ('"' + $svcHost + '" -k WlansvcGroup -p') },
    @{ tag = 'E7'; type = 0x10; body = ('"' + $svcHost + '" -k WlansvcGroup') },
    @{ tag = 'E8'; type = 0x10; body = ('"' + $svcHost + '" -k LocalSystemNetworkRestricted -p') }
  )
  foreach ($sh in $shapes) {
    $tg = ('' + $sh.tag)
    L($tg + ' set type=0x' + ('{0:X}' -f [int]$sh.type) + ' body [' + (C ('' + $sh.body)) + '] rc=' +
      (C ([Cm154]::RegSetSz($svcRel, 'ImagePath', ('' + $sh.body), $false))) + '/' +
      (C ([Cm154]::RegSetDw($svcRel, 'Type', [uint32]$sh.type))))
    L($tg + ' ' + (C ([Cm154]::StartAndTime($SvcName))))
    L($tg + ' after ' + (C ([Cm154]::SvcState($SvcName))))
    Start-Sleep -Milliseconds 700
    L($tg + ' stop ' + (C ([Cm154]::Stop($SvcName))))
    Start-Sleep -Milliseconds 700
  }

  # ---------- E9: probe153's fake host, launched by the SCM, in this same run ----------
  # X:\p153run.ps1 is already on the PE from this session. probe153's own attempt died at 1053 with Type
  # flipped, so try it again now that E3/E4 establish whether the SCM creates the process at all, and give
  # the child time to Add-Type before reading its log.
  $p153 = 'X:\p153run.ps1'
  if (Test-Path -LiteralPath $p153) {
    $o9 = (C ([System.IO.Path]::Combine($MarkerDir, 'p153_out.txt')))
    try { if (Test-Path -LiteralPath $o9) { Remove-Item -LiteralPath $o9 -Force } } catch { }
    $b9 = '"' + $psExe + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $p153 +
          '" -HostRole -Root "' + $s32 + '" -Out "' + $o9 + '" -PidFile "' + $MarkerDir + '\p153.pid"'
    L('E9 body ' + (C $b9))
    L('E9 set rc=' + (C ([Cm154]::RegSetSz($svcRel, 'ImagePath', $b9, $false))) + '/' +
      (C ([Cm154]::RegSetDw($svcRel, 'Type', 0x10))))
    L('E9 ' + (C ([Cm154]::StartAndTime($SvcName))))
    for ($i = 0; $i -lt 8; $i++) {
      Start-Sleep -Milliseconds 1500
      if (Test-Path -LiteralPath $o9) { L('E9 out appeared after ' + (($i + 1) * 1500) + 'ms'); break }
    }
    if (Test-Path -LiteralPath $o9) {
      $l9 = @(Get-Content -LiteralPath $o9 -EA SilentlyContinue)
      L('E9 out lines=' + $l9.Count)
      foreach ($x in $l9) { L('E9| ' + (C $x)) }
    } else { L('E9 no child log -- ' + (C $o9) + ' never appeared') }
    L('E9 state ' + (C ([Cm154]::SvcState($SvcName))))
    L('E9 stop ' + (C ([Cm154]::Stop($SvcName))))
  } else { L('E9 SKIP ' + $p153 + ' not present') }
}
finally {
  # ---------- Z9: put wlansvc back exactly, even if a rung threw ----------
  L('Z9 restore ImagePath rc=' + (C ([Cm154]::RegSetSz($svcRel, 'ImagePath', ('' + $origPath), $true))))
  if ('' + $origType -like 'DWORD=0x*') {
    $dv = [Convert]::ToUInt32((('' + $origType).Replace('DWORD=0x', '')).Trim(), 16)
    L('Z9 restore Type rc=' + (C ([Cm154]::RegSetDw($svcRel, 'Type', $dv))) + ' value=0x' + $dv.ToString('X8'))
  }
  foreach ($c in @('a', 'b', 'c', 'd', 'e', 'f')) {
    $nm = ('' + $TestPrefix) + $c
    [void]([Cm154]::StopAndDelete($nm))
    [void]([Cm154]::RegDelKey('SYSTEM\CurrentControlSet\Services\' + $nm))
  }
  L('Z9 now ImagePath [' + (C ([Cm154]::RegQuery($svcRel, 'ImagePath'))) + '] Type ' + (C ([Cm154]::RegQuery($svcRel, 'Type'))))
  L('Z9 wlansvc ' + (C ([Cm154]::SvcState($SvcName))))
}

# ---------- E5: what the SCM said ----------
try {
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } -MaxEvents 25 -EA SilentlyContinue)
  L('E5 events=' + @($ev).Count)
  foreach ($e in $ev) { L('E5 ' + (C ($e.TimeCreated.ToString('HH:mm:ss') + ' id=' + $e.Id + ' ' + $e.Message))) }
} catch { L('E5 eventlog EXC ' + (C $_.Exception.Message)) }

L('probe154 end -- judgement: E0 own-process RUNNING>0 means the mechanism exists; then the FIRST E2 rung')
L('whose MARKER is ABSENT names the record attribute that stops the SCM from hosting us. If every E2')
L('marker appears but E3 does not, the blocker is wlansvc the name (cache/dependency chain). If E3 runs')
L('and E4 does not, no .NET process can be a service process here -> the fake host must be a native exe.')
L('E6..E8 are read as the service result, not as a launch test: state=RUNNING with a stable pid means the')
L('dedicated-svchost shape the reference host uses is enough here, and that is bakeable; the same')
L('START_OK|STOPPED 0x800C0006 tail means the hosting model is not the difference either.')
