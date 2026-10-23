# probe112 -- wlansvc SERVICE-RECORD shape ladder, run live in the rescue PE (never touches the disc).
#
# Why this probe exists: probe109/110/111 falsified every "missing thing" hypothesis for wlansvc's
# self-exit (win32 exit 0x800C0006 at ~130ms, 36 modules, last tail ...msxml6,wmiclnt):
#   - the 15 late-bound host modules are all supplied and the file gap is zero (probe110 S6 NEW-FILE-GAP=0);
#   - the whole host-shaped environment layer (registry keys, ProgramData/GroupPolicy dirs, Winmgmt/wcmsvc/
#     EapHost/netprofm/dot3svc up) produced BYTE-IDENTICAL traces at every rung (probe111 R1/R2/R3);
#   - every kernel device object wlansvc opens is openable (\\.\NativeWiFiP, \\.\vwififlt, \\.\NDIS,
#     \\.\WMIGUID, \\.\vwifibus, \\.\PktMonApi -- probe111 S1 all OPEN_OK).
# What has NOT been tested is the only remaining structural difference between us and a PE that ships
# working WiFi: the SERVICE RECORD itself. Two authoritative references, both read offline and decoded
# into build\scratch\p112_wr_svc_wlansvc.txt / p112_ours_svc_wlansvc.txt / p106_host_wdisvc.txt:
#   official WinRE  : Type=0x20 Start=2 ImagePath='...svchost.exe -k WlansvcGroup'  Depend=nativewifip;RpcSs;Ndisuio
#                     + Parameters{ComInterfaceProviders,EapolKeyIpAddress,OEM\SystemCapabilities,
#                      OneXAuthenticator,VendorSpecificIEProviders x3,WfdInterfaceManagement,WFDProvPlugin}
#                     + VirtualizationManager{WindowsPushNotificationPlatformClsid}
#   our image       : Type=0x10 Start=3 ImagePath='...svchost.exe -k LocalSystemNetworkRestricted -p'
#                     Depend=RpcSs only, Parameters has only ServiceDll/ServiceMain/ServiceDllUnloadOnStop
#   healthy host    : Type=0x10 Start=2 ImagePath='...-k LocalSystemNetworkRestricted -p'
#                     Depend=nativewifip;RpcSs;Ndisuio;wcmsvc  (so '-p' + own-group is NOT required for health)
# Rungs therefore isolate one variable at a time, cheapest/most decisive first, and every rung is judged
# with the same two instruments: the module trace (probe111's, unchanged) and wlanapi!WlanEnumInterfaces/
# WlanQueryInterface, which is the acceptance test that actually matters (a service that "runs" but reports
# zero interfaces is still a failure).
#
# Config changes go through ChangeServiceConfigW, NOT raw reg writes: services.exe owns that cache and
# already-registered keys are visible to it while brand-new ones are not (the vwifibus lesson), so the API
# is the only way to be sure the SCM sees the new shape -- and QueryServiceConfigW right after proves it.
# Output: ASCII lines prefixed P112.
param([switch]$DryRun, [switch]$Readonly, [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P112 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = $Root
$svc = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'

# What the WinRE record has and ours lacks, as data (values verbatim from the decoded WinRE dump).
$dllWant = @('wlanapi.dll', 'wlansvc.dll', 'wlansvcpal.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlgpclnt.dll',
             'wmiclnt.dll', 'msxml6.dll', 'WiFiDisplay.dll', 'wfdprov.dll', 'WcnEapAuthProxy.dll',
             'TetheringIeProvider.dll', 'onex.dll', 'gpapi.dll', 'dsrole.dll', 'sysntfy.dll',
             'wifinetworkmanager.dll', 'firewallapi.dll', 'wcmsvc.dll', 'nlaapi.dll', 'netcore.dll',
             'svchost.exe', 'wlanutil.dll', 'IWlanApi.dll')
# (last two are only census lines, not gates -- a missing one is reported, nothing more)

$src = @'
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Pe112 {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr sc, string name, uint a);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool StartServiceW(IntPtr sv, uint n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceStatusEx(IntPtr sv, int lvl, IntPtr buf, uint size, out uint need);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool ControlService(IntPtr sv, uint ctrl, IntPtr status);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceConfigW(IntPtr sv, IntPtr buf, uint size, out uint needed);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool ChangeServiceConfigW(IntPtr sv, uint type, uint start, uint errctl, string path,
      string group, IntPtr tagId, string deps, string objName, string pwd, string disp);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);
  // wlanapi = the instrument that answers the only question that matters: does the service expose
  // a manageable 802.11 interface?
  // NOTE(2026-10-12): the client-open entry point is exported as WlanOpenHandle, NOT WlanOpenConnection --
  // build\scratch\t_p112_exp3.ps1 dumped the host wlanapi.dll (258 exports, zero ordinal-only) and
  // WlanOpenConnection is not among them, so DllImport by that name throws EntryPointNotFoundException.
  // Verified live on the healthy host: WlanOpenHandle(2,...) -> hr=0 neg=2, WlanEnumInterfaces -> nif=1
  // with a real GUID, WlanQueryInterface(opcode 5) -> hr=0 state=3. That is the positive reference.
  [DllImport("wlanapi.dll", EntryPoint = "WlanOpenHandle")]
  static extern int WlanOpenConnection(uint ver, IntPtr res, out uint neg, out IntPtr h);
  [DllImport("wlanapi.dll")] static extern int WlanEnumInterfaces(IntPtr h, IntPtr res, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern int WlanQueryInterface(IntPtr h, ref Guid g, uint opcode,
      IntPtr res, out uint dataSize, out IntPtr data, IntPtr valueType);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr p);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr h, IntPtr res);

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_QUERY_CONFIG = 0x0001, SERVICE_CHANGE_CONFIG = 0x0002;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;

  static IntPtr Open(string name, uint access) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) return IntPtr.Zero;
    try { return OpenServiceW(sm, name, access); } finally { CloseServiceHandle(sm); }
  }
  static string Hr(int v) { return "0x" + ((uint)v).ToString("X8"); }
  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : st == 5 ? "STOP_PENDING" : st == 6 ? "PAUSED" : ("state" + st);
  }
  // SERVICE_STATUS_PROCESS is 36 bytes: state@4, win32exit@12, check@20, pid@28 (probe99).
  public static string Status(string name) {
    IntPtr sv = Open(name, SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      IntPtr buf = Marshal.AllocHGlobal(36);
      try {
        uint need = 0;
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) return "QSS_ERR=" + Marshal.GetLastWin32Error();
        return StateName(Marshal.ReadInt32(buf, 4)) + " win32hex=0x" +
               ((uint)Marshal.ReadInt32(buf, 12)).ToString("X8") + " pid=" + Marshal.ReadInt32(buf, 28);
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  // What the SCM itself has cached for the service -- the control on "did the shape change take effect".
  // Read manually: SERVICE_CONFIGW on x64 is type@0 start@4 errctl@8 path@16 group@24 tag@32 deps@40
  // objname@48 disp@56, which avoids any marshalling guesswork.
  public static string Config(string name) {
    IntPtr sv = Open(name, SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      uint need = 0;
      IntPtr buf = Marshal.AllocHGlobal(2048);
      try {
        if (!QueryServiceConfigW(sv, buf, 2048, out need)) return "QCFG_ERR=" + Marshal.GetLastWin32Error();
        uint type = (uint)Marshal.ReadInt32(buf, 0);
        uint start = (uint)Marshal.ReadInt32(buf, 4);
        string path = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 16));
        string grp = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 24));
        string depsRaw = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 40));
        string obj = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 48));
        List<string> dl = new List<string>();
        if (depsRaw != null) {
          foreach (string p in depsRaw.Split('\0')) if (p.Length > 0) dl.Add(p);
        }
        return "type=0x" + type.ToString("X2") + " start=" + start + " path=[" + path + "] group=[" + grp +
               "] obj=[" + obj + "] deps=[" + string.Join(";", dl.ToArray()) + "]";
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  // -1 for the numeric fields and null for the strings mean "leave that one alone".
  public static string Change(string name, int type, int start, string path, string depsSemi) {
    IntPtr sv = Open(name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      string deps = null;
      if (depsSemi != null) deps = depsSemi.Replace(';', '\0') + "\0\0";
      uint t = type < 0 ? 0xFFFFFFFFu : (uint)type;
      uint s = start < 0 ? 0xFFFFFFFFu : (uint)start;
      bool ok = ChangeServiceConfigW(sv, t, s, 0xFFFFFFFFu, path, null, IntPtr.Zero, deps, null, null, null);
      int err = Marshal.GetLastWin32Error();
      return ok ? "CHG_OK" : ("CHG_ERR=" + err);
    } finally { CloseServiceHandle(sv); }
  }
  // Open a wlanapi client session, enumerate interfaces, and query interface 0's state (opcode 5) and
  // connected flag (opcode 6). State is printed as the raw int on purpose: what matters is the delta
  // against the healthy-host reference (nif=1 state=3 connected=<..>), not our reading of the enum.
  public static string WlanProbe() {
    uint neg = 0; IntPtr h = IntPtr.Zero;
    int r = WlanOpenConnection(2, IntPtr.Zero, out neg, out h);
    if (r != 0) return "OPEN hr=" + Hr(r) + " neg=" + neg;
    try {
      IntPtr list = IntPtr.Zero;
      int e = WlanEnumInterfaces(h, IntPtr.Zero, out list);
      if (e != 0) return "ENUM hr=" + Hr(e) + " neg=" + neg;
      try {
        int n = Marshal.ReadInt32(list, 0);
        if (n <= 0) return "ENUM ok nif=0";
        byte[] gbytes = new byte[16];
        Marshal.Copy(IntPtr.Add(list, 8), gbytes, 0, 16);
        Guid g0 = new Guid(gbytes);
        uint ds = 0; IntPtr dp = IntPtr.Zero;
        int q = WlanQueryInterface(h, ref g0, 5, IntPtr.Zero, out ds, out dp, IntPtr.Zero);
        string st = "hr=" + Hr(q);
        if (q == 0 && dp != IntPtr.Zero && ds >= 4) st = "int=" + Marshal.ReadInt32(dp);
        if (dp != IntPtr.Zero) WlanFreeMemory(dp);
        // opcode 6 = is_connected (one BOOLEAN)
        uint ds2 = 0; IntPtr dp2 = IntPtr.Zero;
        int q2 = WlanQueryInterface(h, ref g0, 6, IntPtr.Zero, out ds2, out dp2, IntPtr.Zero);
        string conn = "?";
        if (q2 == 0 && dp2 != IntPtr.Zero && ds2 >= 1) conn = (Marshal.ReadByte(dp2) != 0) ? "yes" : "no";
        if (dp2 != IntPtr.Zero) WlanFreeMemory(dp2);
        return "nif=" + n + " guid0=" + g0 + " state=" + st + " connected=" + conn;
      } finally { WlanFreeMemory(list); }
    } finally { WlanCloseHandle(h, IntPtr.Zero); }
  }
  // Start without waiting for RUNNING (wlansvc never reaches it today): just report the StartService result
  // and the state after the grace window, the way probe111's StartAndWait did for the other services.
  public static string StartAndWait(string name, int ms) {
    IntPtr sv = Open(name, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      int err = started ? 0 : Marshal.GetLastWin32Error();
      Stopwatch sw = Stopwatch.StartNew();
      int state = 0; uint need = 0;
      while (sw.ElapsedMilliseconds < ms) {
        IntPtr buf = Marshal.AllocHGlobal(36);
        if (QueryServiceStatusEx(sv, 0, buf, 36, out need)) state = Marshal.ReadInt32(buf, 4);
        Marshal.FreeHGlobal(buf);
        if (state == 4) break;
        if (state == 1 && !started && err != 0) break;
        if (state == 1 && sw.ElapsedMilliseconds > 300) break;
        Thread.Sleep(20);
      }
      IntPtr fb = Marshal.AllocHGlobal(36);
      string fin = "QSS_ERR";
      if (QueryServiceStatusEx(sv, 0, fb, 36, out need)) {
        fin = StateName(Marshal.ReadInt32(fb, 4)) + " win32hex=0x" +
              ((uint)Marshal.ReadInt32(fb, 12)).ToString("X8") + " pid=" + Marshal.ReadInt32(fb, 28);
      }
      Marshal.FreeHGlobal(fb);
      return "start=" + (started ? "OK" : ("ERR=" + err)) + " " + fin + " waited=" + sw.ElapsedMilliseconds + "ms";
    } finally { CloseServiceHandle(sv); }
  }
  static string[] ModulesOf(int pid, ref IntPtr cachedH, ref int cachedPid) {
    if (pid <= 0) return new string[0];
    if (cachedH == IntPtr.Zero || cachedPid != pid) {
      if (cachedH != IntPtr.Zero) CloseHandle(cachedH);
      cachedH = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
      cachedPid = pid;
      if (cachedH == IntPtr.Zero) return new string[0];
    }
    IntPtr[] buf = new IntPtr[2048];
    uint needed = 0;
    if (!EnumProcessModulesEx(cachedH, buf, (uint)(buf.Length * IntPtr.Size), out needed, 0x03))
      return new string[0];
    int count = (int)(needed / (uint)IntPtr.Size);
    if (count > buf.Length) count = buf.Length;
    List<string> names = new List<string>(count);
    StringBuilder sb = new StringBuilder(1024);
    for (int i = 0; i < count; i++) {
      sb.Length = 0;
      uint n2 = GetModuleFileNameExW(cachedH, buf[i], sb, (uint)sb.Capacity);
      if (n2 == 0) continue;
      string p = sb.ToString();
      int k = p.LastIndexOf('\\');
      names.Add((k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant());
    }
    return names.ToArray();
  }
  // probe111's trace, unchanged, so the rungs stay comparable with its negative baseline.
  public static string[] Trace(string svcName, int ms) {
    List<string> lines = new List<string>();
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) { lines.Add("SCM_ERR=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    IntPtr sv = OpenServiceW(scm, svcName, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); lines.Add("OPEN_ERR=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      try { ControlService(sv, 1, st); } catch { }
      Marshal.FreeHGlobal(st);
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      string sr = started ? "START_OK" : ("START_ERR=" + Marshal.GetLastWin32Error());
      Stopwatch sw = Stopwatch.StartNew();
      List<string> order = new List<string>();
      HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      IntPtr hCache = IntPtr.Zero; int hPid = 0;
      string lastState = "";
      while (sw.ElapsedMilliseconds < ms) {
        uint need = 0;
        IntPtr buf = Marshal.AllocHGlobal(36);
        int state = 0, win32 = 0; uint pid = 0;
        bool ok = QueryServiceStatusEx(sv, 0, buf, 36, out need);
        if (ok) { state = Marshal.ReadInt32(buf, 4); win32 = Marshal.ReadInt32(buf, 12); pid = (uint)Marshal.ReadInt32(buf, 28); }
        Marshal.FreeHGlobal(buf);
        if (!ok) { lines.Add("t+" + sw.ElapsedMilliseconds + "ms QSS_ERR=" + Marshal.GetLastWin32Error()); break; }
        string sn = StateName(state);
        if (sn != lastState) { lastState = sn; lines.Add("t+" + sw.ElapsedMilliseconds + "ms " + sn + " pid=" + pid); }
        if (pid > 0) {
          foreach (string m in ModulesOf((int)pid, ref hCache, ref hPid))
            if (!seen.Contains(m)) { seen.Add(m); order.Add(m); }
        }
        if (state == 4) break;
        if (state == 1 && sw.ElapsedMilliseconds > 60) break;
        Thread.Sleep(1);
      }
      if (hCache != IntPtr.Zero) CloseHandle(hCache);
      uint need2 = 0;
      IntPtr fb = Marshal.AllocHGlobal(36);
      string fin = "FINAL";
      if (QueryServiceStatusEx(sv, 0, fb, 36, out need2)) {
        fin = "FINAL state=" + Marshal.ReadInt32(fb, 4) + " win32hex=0x" +
              ((uint)Marshal.ReadInt32(fb, 12)).ToString("X8") + " pid=" + Marshal.ReadInt32(fb, 28);
      } else { fin = "FINAL QSS_ERR=" + Marshal.GetLastWin32Error(); }
      Marshal.FreeHGlobal(fb);
      lines.Add("START=" + sr);
      lines.Add(fin + " loaded=" + seen.Count + " t=" + sw.ElapsedMilliseconds + "ms");
      int n = order.Count;
      int from = n > 6 ? n - 6 : 0;
      for (int i = from; i < n; i++) lines.Add("TAIL " + order[i]);
      return lines.ToArray();
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  public static string Ping() { return "Pe112 ping ok"; }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe112 begin native=' + $native + ' dryrun=' + $DryRun + ' root=[' + (C $s32) + ']')

# A vanished wlan line would cost a whole field cycle, so the instrument is wrapped and reports its own
# exceptions instead of letting -ErrorAction SilentlyContinue swallow them.
function WlanLine([string]$tag) {
  if (-not $native) { L('WLAN  [' + $tag + '] skipped: native class unavailable'); return }
  $r = ''
  try { $r = [Pe112]::WlanProbe() }
  catch {
    $r = 'EXCEPTION ' + (C $_.Exception.Message)
    if ($_.Exception.InnerException) { $r += ' inner=' + (C $_.Exception.InnerException.Message) }
  }
  L('WLAN  [' + $tag + '] ' + $r)
}
function Tr([string]$svc2, [string]$tag) {
  if (-not $native) { L('TRACE ' + $svc2 + ' skipped: native class unavailable'); return }
  $lines = @()
  try { $lines = @([Pe112]::Trace($svc2, 3000)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
  $sr = ''; $fin = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^START=') { $sr = (C "$l") } }
  foreach ($l in @($lines)) { if ((C "$l") -match '^FINAL ') { $fin = (C "$l") } }
  $tail = @(@($lines) | Where-Object { (C "$_") -match '^TAIL ' } | ForEach-Object { (C "$_") -replace '^TAIL ','' })
  L('TRACE ' + $svc2 + ' [' + $tag + '] ' + $sr + ' | ' + $fin + ' | tail=' + (@($tail) -join ','))
  WlanLine $tag
}
function Reg([string]$what) {
  $k = Get-Item -LiteralPath $svc -EA SilentlyContinue
  if ($null -eq $k) { L('REG missing service key'); return }
  $v = $k.GetValue($what)
  if ($v -is [array]) { L('REG ' + $what + ' = [' + ((@($v) | ForEach-Object { C "$_" }) -join ';') + ']') }
  else { L('REG ' + $what + ' = [' + (C "$v") + ']') }
}

if ($DryRun) {
  L('DRY P0 would read (no writes): service key values + SCM QueryServiceConfigW view')
  L('DRY P1 would check ' + $dllWant.Count + ' file paths under ' + (C $s32) + ' and the SVCHOST group table')
  L('DRY rungs, each one variable at a time, each followed by trace + WlanEnumInterfaces:')
  L('DRY  R1 ChangeServiceConfigW ImagePath -> "%SystemRoot%\system32\svchost.exe -k LocalSystemNetworkRestricted"' +
    ' (drops the -p flag; the host and WinRE disagree about it, so it is the cheapest A/B)')
  L('DRY  R2 WinRE shape: Type=0x20 + ImagePath "...svchost.exe -k WlansvcGroup" + Start=2 and, BEFORE the ' +
    'change, SOFTWARE\...\SVCHOST WlansvcGroup REG_MULTI_SZ += wlansvc (a key the group must contain or ' +
    'svchost starts and exits like the old WlansvcGroup trap)')
  L('DRY  R3 DependOnService -> nativewifip;RpcSs;Ndisuio;wcmsvc (host shape), starting wcmsvc first')
  L('DRY  R4 the WinRE Parameters subtree + VirtualizationManager, verbatim, each entry gated on its DLL ' +
    'existing in ' + (C $s32) + ' (OneXAuthenticator->WcnEapAuthProxy.dll, WFDProvPlugin->wfdprov.dll, ' +
    'the B7D94B4D IE provider->WiFiDisplay.dll); entries whose DLL is absent are reported and skipped')
  L('DRY  R5 five stop/start cycles with the auth side up (tests the "wlansvc lost a race at boot" theory)')
  L('DRY nothing is written without ChangeServiceConfigW/registry writes; -DryRun performs neither, and a ' +
    'trace stops/starts the service so -DryRun never traces')
  L('probe112 end (DryRun)'); exit 0
}
if (-not (Test-Path -LiteralPath $svc)) { L('ABORT: no wlansvc service key'); exit 1 }

# ---------- P0 current shape, from both readers ----------
L('P0 scm-view  ' + $(if ($native) { [Pe112]::Config('wlansvc') } else { 'n/a' }))
foreach ($v in @('Type', 'Start', 'ErrorControl', 'Group', 'ObjectName', 'ImagePath', 'ServiceSidType',
                 'DependOnService', 'RequiredPrivileges')) { Reg $v }
L('P0 status    ' + $(if ($native) { [Pe112]::Status('wlansvc') } else { 'n/a' }))

# ---------- P1 files and the svchost group table ----------
foreach ($d in @($dllWant)) {
  L('P1 DLL ' + $d + ' present=' + (Test-Path -LiteralPath (Join-Path $s32 $d)))
}
$sk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$sK = Get-Item -LiteralPath $sk -EA SilentlyContinue
$grpNames = @()
if ($null -eq $sK) { L('P1 SVCHOST key ABSENT at ' + $sk) }
else {
  $grpNames = @($sK.GetValueNames())
  foreach ($gn in @($grpNames)) {
    $gv = @($sK.GetValue($gn))
    $in = @($gv | Where-Object { (C "$_").ToLower() -eq 'wlansvc' }).Count -gt 0
    L('P1 GROUP ' + (C $gn) + ' members=' + @($gv).Count + ' wlansvc-in=' + $(if ($in) { 'YES' } else { 'no' }) +
      $(if ($in) { '' } else { ' [' + ((@($gv) | ForEach-Object { C "$_" }) -join ';') + ']' }))
  }
}
L('P1 WlansvcGroup exists=' + (@($grpNames) -contains 'WlansvcGroup'))

# ---------- R0 baseline ----------
if ($Readonly) {
  L('READONLY ends here: nothing above writes, and a trace stops/starts the service, so -Readonly never traces.')
  L('READONLY is also how the acceptance instrument is validated -- on a healthy machine WlanProbe must print')
  L('READONLY nif>=1 with state=interface_open/media_connected; a rung that only makes the service "run"')
  L('READONLY without that line is still a failure.')
  WlanLine 'READONLY'
  L('probe112 end (Readonly)'); exit 0
}
Tr 'wlansvc' 'R0 baseline (post-probe111 environment)'

# ---------- R1: drop the -p flag ----------
$r = 'native-unavailable'
if ($native) { $r = [Pe112]::Change('wlansvc', -1, -1, '%SystemRoot%\system32\svchost.exe -k LocalSystemNetworkRestricted', $null) }
L('R1 change ImagePath (no -p) -> ' + $r)
L('R1 scm-view  ' + $(if ($native) { [Pe112]::Config('wlansvc') } else { 'n/a' }))
Reg 'ImagePath'
Tr 'wlansvc' 'R1 ImagePath without -p'

# ---------- R2: WinRE shape (own svchost group + shared-process type) ----------
$gp = $null
if ($null -ne $sK) { $gp = @($sK.GetValue('WlansvcGroup')) }
if (@($gp).Count -eq 0) {
  Set-ItemProperty -LiteralPath $sk -Name 'WlansvcGroup' -Value @('wlansvc') -Type MultiString -Force -EA SilentlyContinue
  L('R2 SVCHOST WlansvcGroup created = [wlansvc]')
} else {
  $hasW = @($gp | Where-Object { (C "$_").ToLower() -eq 'wlansvc' }).Count -gt 0
  if (-not $hasW) {
    Set-ItemProperty -LiteralPath $sk -Name 'WlansvcGroup' -Value (@($gp) + @('wlansvc')) -Type MultiString -Force -EA SilentlyContinue
    L('R2 SVCHOST WlansvcGroup appended wlansvc, members now=' + @(@($sK.GetValue('WlansvcGroup'))).Count)
  } else { L('R2 SVCHOST WlansvcGroup already lists wlansvc') }
}
if ($native) {
  $r = [Pe112]::Change('wlansvc', 32, 2, '%SystemRoot%\system32\svchost.exe -k WlansvcGroup', $null)
  L('R2 change Type=0x20 Start=2 ImagePath=-k WlansvcGroup -> ' + $r)
  L('R2 scm-view  ' + [Pe112]::Config('wlansvc'))
}
Reg 'Type'
Reg 'ImagePath'
Tr 'wlansvc' 'R2 WinRE service shape'

# ---------- R3: host dependency set ----------
# wcmsvc is left exactly as the image has it (probe109/110/111 proved it goes RUNNING once the late-bound
# modules are in); we only start it here because making wlansvc depend on it means the SCM will refuse the
# start otherwise.
if ($native) { L('R3 wcmsvc before ' + [Pe112]::Status('wcmsvc')) }
if ($native) { L('R3 start wcmsvc ' + [Pe112]::StartAndWait('wcmsvc', 6000)) }
if ($native) {
  $r = [Pe112]::Change('wlansvc', -1, -1, $null, 'nativewifip;RpcSs;Ndisuio;wcmsvc')
  L('R3 change DependOnService=nativewifip;RpcSs;Ndisuio;wcmsvc -> ' + $r)
  L('R3 scm-view  ' + [Pe112]::Config('wlansvc'))
  Reg 'DependOnService'
  Tr 'wlansvc' 'R3 host dependency set'
}

# ---------- R4: the WinRE Parameters subtree, DLL-gated ----------
$pbase = Join-Path $svc 'Parameters'
function Ensure-Key([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { New-Item -LiteralPath $p -Force -EA SilentlyContinue | Out-Null }
  return (Test-Path -LiteralPath $p)
}
function Has-Dll([string]$name) { Test-Path -LiteralPath (Join-Path $s32 $name) }
# The default value is not a named property; the provider needs the raw .NET call with a null name.
function Set-Default([string]$psPath, [string]$val) {
  $rel = ('' + $psPath) -replace '^HKLM:\\', ''
  $k = $null
  try { $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rel, $true) } catch { }
  if ($null -eq $k) { return 'OPEN-FAIL' }
  try { $k.SetValue($null, $val, [Microsoft.Win32.RegistryValueKind]::ExpandString); return 'ok' }
  catch { return 'SET-FAIL ' + (C $_.Exception.Message) }
  finally { $k.Close() }
}
$made = @()
if (Ensure-Key (Join-Path $pbase 'ComInterfaceProviders')) {
  New-ItemProperty -LiteralPath (Join-Path $pbase 'ComInterfaceProviders') -Name 'IHNetIcsSettings' `
    -Value '{46C166AA-3108-11D4-9348-00C04F8EEB71}' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  $made += 'ComInterfaceProviders\IHNetIcsSettings'
}
if (Ensure-Key (Join-Path $pbase 'EapolKeyIpAddress')) {
  New-ItemProperty -LiteralPath (Join-Path $pbase 'EapolKeyIpAddress') -Name 'LocalAddress' `
    -Value '192.168.137.1' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -LiteralPath (Join-Path $pbase 'EapolKeyIpAddress') -Name 'PrefixLength' `
    -Value 24 -PropertyType DWord -Force -EA SilentlyContinue | Out-Null
  $made += 'EapolKeyIpAddress'
}
if (Ensure-Key (Join-Path $pbase 'OEM\SystemCapabilities')) { $made += 'OEM\SystemCapabilities' }
if (Ensure-Key (Join-Path $pbase 'WfdInterfaceManagement')) {
  foreach ($n in @('DisablePhyTypeRestriction', 'DisableSetActiveWfdMgrSidCheck')) {
    New-ItemProperty -LiteralPath (Join-Path $pbase 'WfdInterfaceManagement') -Name $n `
      -Value 0 -PropertyType DWord -Force -EA SilentlyContinue | Out-Null
  }
  $made += 'WfdInterfaceManagement'
}
foreach ($g in @('00666BD7-8CB1-4A35-A3B7-83BA6D5BBEE3', '4D50EE01-EEE0-4E5D-9A41-2F5F32044192')) {
  $p = Join-Path (Join-Path $pbase 'VendorSpecificIEProviders') $g
  if (Ensure-Key $p) {
    New-ItemProperty -LiteralPath $p -Name 'Path' -Value '%SYSTEMROOT%\System32\WlanSvc.dll' `
      -PropertyType ExpandString -Force -EA SilentlyContinue | Out-Null
    $made += ('VendorSpecificIEProviders\' + $g)
  }
}
if (Has-Dll 'WiFiDisplay.dll') {
  $p = Join-Path (Join-Path $pbase 'VendorSpecificIEProviders') 'B7D94B4D-5DB1-4E70-B5C3-DD003EEEBE66'
  if (Ensure-Key $p) {
    New-ItemProperty -LiteralPath $p -Name 'Path' -Value '%SYSTEMROOT%\System32\WiFiDisplay.dll' `
      -PropertyType ExpandString -Force -EA SilentlyContinue | Out-Null
    $made += 'VendorSpecificIEProviders\B7D94B4d(WiFiDisplay)'
  }
} else { L('R4 SKIP OneX/WFD IE provider entries: WiFiDisplay.dll absent from the image') }
if (Has-Dll 'WcnEapAuthProxy.dll') {
  $p = Join-Path $pbase 'OneXAuthenticator'
  if (Ensure-Key $p) {
    L('R4 OneXAuthenticator default -> ' + (Set-Default $p '%SystemRoot%\System32\WcnEapAuthProxy.dll'))
    $made += 'OneXAuthenticator'
  }
} else { L('R4 SKIP OneXAuthenticator: WcnEapAuthProxy.dll absent') }
if (Has-Dll 'wfdprov.dll') {
  $p = Join-Path $pbase 'WFDProvPlugin'
  if (Ensure-Key $p) {
    L('R4 WFDProvPlugin default -> ' + (Set-Default $p '%SystemRoot%\System32\wfdprov.dll'))
    New-ItemProperty -LiteralPath $p -Name 'DllEntryPoint' -Value 'WFDProvGetInfo' -PropertyType String `
      -Force -EA SilentlyContinue | Out-Null
    $made += 'WFDProvPlugin'
  }
} else { L('R4 SKIP WFDProvPlugin: wfdprov.dll absent') }
$p = Join-Path $svc 'VirtualizationManager'
if (Ensure-Key $p) {
  New-ItemProperty -LiteralPath $p -Name 'WindowsPushNotificationPlatformClsid' `
    -Value '0C9281F9-6DA1-4006-8729-DE6E6B61581C' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  $made += 'VirtualizationManager'
}
L('R4 wrote=' + @($made).Count + ' [' + ((@($made) | ForEach-Object { (C (Split-Path $_ -Leaf)) }) -join ';') + ']')
Get-ChildItem -LiteralPath $pbase -EA SilentlyContinue | ForEach-Object {
  L('R4 tree ' + (C $_.PSChildName) + ' vals=' + (@($_.GetValueNames()).Count))
}
Tr 'wlansvc' 'R4 WinRE Parameters subtree'

# ---------- R5: five start cycles, auth side up ----------
if ($native) {
  foreach ($n in @('EapHost', 'dot3svc', 'netprofm')) {
    if (Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n)) {
      L('R5 ' + $n + ' ' + [Pe112]::StartAndWait($n, 6000))
    }
  }
}
for ($i = 1; $i -le 5; $i++) {
  if ($native) { Tr 'wlansvc' ("R5 attempt $i") }
  Start-Sleep -Milliseconds 400
}

# ---------- verdict ----------
if ($native) {
  L('END scm ' + [Pe112]::Config('wlansvc'))
  L('END wlansvc ' + [Pe112]::Status('wlansvc') + ' | wcmsvc ' + [Pe112]::Status('wcmsvc'))
}
WlanLine 'END'
$ad = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
L('END adapters=' + @($ad).Count + ' wifi-ifttype71=' + (@($ad | Where-Object { [int]$_.NetworkInterfaceType -eq 71 }).Count))
L('probe112 end -- baseline to beat (probe111, three rungs identical): state=1 win32hex=0x800C0006 loaded=36 tail=...,wmiclnt.dll')
