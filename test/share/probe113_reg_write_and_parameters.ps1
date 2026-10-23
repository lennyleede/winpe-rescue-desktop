# probe113 -- can we write the registry AT ALL in the live PE, and does the WinRE wlansvc Parameters
# subtree change the self-exit? Run live over ssh (X:\p113run.ps1); never touches the disc.
#
# Why this probe exists (the loose end probe112 left):
#   probe112 rung R4 was supposed to create the official WinRE Parameters subtree and reported
#   "P112 R4 wrote=0 []" with no error text -- every Ensure-Key() came back false. Because the script
#   runs with $ErrorActionPreference='SilentlyContinue', New-Item's failure was swallowed, so R4 is
#   NOT a falsification: it is an UNTESTED rung. The same swallow applies to probe111's registry rungs
#   (it counted $made after New-Item without re-testing Test-Path), so "host-shaped env keys do not
#   matter" is only proven for the directories it re-tested, not for the keys.
#   Meanwhile probe112 PROVED the SYSTEM hive is writable: rung R1's ChangeServiceConfigW returned
#   CHG_OK and the registry then read back the new ImagePath (and the deps list it cleared). So the
#   question is specifically about the PowerShell registry provider vs. the advapi32 calls.
#
# What this probe measures, in order:
#   M0 census  -- for every WinRE target key: provider Test-Path vs native RegOpenKeyExW status code.
#   M1 ladder  -- one scratch key created by each of three mechanisms, each with the error code made
#                 visible: PS provider New-Item, .NET CreateSubKey, native RegCreateKeyExW. Two
#                 locations (HKLM\SOFTWARE and Services\wlansvc\Parameters) so a per-hive answer is
#                 distinguishable from a global one. Plus a file write and the process identity,
#                 because ACCESS_DENIED vs NOT_ENOUGH_QUOTA lead to completely different fixes.
#   M2 write   -- the WinRE Parameters subtree through whichever mechanism worked (DLL-gated, exactly
#                 like probe112 R4, but self-reporting: every create and every value prints its code).
#   M3 verdict -- start wlansvc, take probe111/112's identical module trace, and read the interface
#                 count through wlanapi (WlanOpenHandle is the exported name; WlanOpenConnection is
#                 not exported at all -- build\scratch\t_p112_exp3.ps1).
#   M4 restore -- put the service record back the way P0 found it (probe112's ChangeServiceConfigW
#                 with a null dep string cleared DependOnService as a side effect; the disc still has
#                 nativewifip;RpcSs;Ndisuio, and this boot must stay comparable).
#
# Reference shapes (decoded verbatim, build\scratch\p112_wr_svc_wlansvc.txt / p112_ours_svc_wlansvc.txt):
#   WinRE  wlansvc: Type=0x20 Start=2 ImagePath=%SystemRoot%\system32\svchost.exe -k WlansvcGroup
#                   DependOnService=nativewifip;RpcSs;Ndisuio  + the Parameters subtree below
#   live PE (this boot, probe112 P0): the same shape already baked, minus the Parameters subtree.
# Output: ASCII lines prefixed P113.
param([switch]$DryRun, [switch]$Readonly, [string]$Root = 'X:\Windows\System32')
function L([string]$s) { Write-Output ('P113 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = $Root
$svcPs = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$svcRel = 'SYSTEM\CurrentControlSet\Services\wlansvc'
$parRel = $svcRel + '\Parameters'

$regSrc = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Reg113 {
  static readonly IntPtr HKLM = new IntPtr(-2147483646); // 0x80000002
  const uint KEY_READ = 0x20019, KEY_WRITE = 0x20006, KEY_WOW64_64KEY = 0x0100;

  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegOpenKeyExW(IntPtr h, string sub, uint opt, uint access, out IntPtr res);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegCreateKeyExW(IntPtr h, string sub, uint res, IntPtr cls, uint opt, uint sec,
      IntPtr sa, out IntPtr result, out uint disp);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegCloseKey(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegSetValueExW(IntPtr h, string name, uint res, uint type, byte[] data, uint cb);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegQueryValueExW(IntPtr h, string name, IntPtr res, out uint type, byte[] data, ref uint cb);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegEnumKeyExW(IntPtr h, uint idx, StringBuilder name, ref uint cbName, IntPtr res,
      IntPtr cls, ref uint cbCls, IntPtr lastWrite);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegDeleteKeyW(IntPtr h, string sub);

  static string Code(int rc) {
    return "rc=0x" + ((uint)rc).ToString("X8") + " win32=" + rc;
  }
  public static string Open(string sub, bool write) {
    IntPtr h = IntPtr.Zero;
    int rc = RegOpenKeyExW(HKLM, sub, 0, (write ? KEY_WRITE : KEY_READ) | KEY_WOW64_64KEY, out h);
    if (rc == 0) RegCloseKey(h);
    return Code(rc);
  }
  public static string Exists(string sub) {
    IntPtr h = IntPtr.Zero;
    int rc = RegOpenKeyExW(HKLM, sub, 0, KEY_READ | KEY_WOW64_64KEY, out h);
    if (rc == 0) RegCloseKey(h);
    return rc == 0 ? "YES " + Code(rc) : "NO  " + Code(rc);
  }
  // The decisive primitive: create (or open) a key from the PE process. Returns the disposition too.
  public static string Create(string sub) {
    IntPtr h = IntPtr.Zero; uint disp = 0;
    int rc = RegCreateKeyExW(HKLM, sub, 0, IntPtr.Zero, 0, KEY_WRITE | KEY_WOW64_64KEY, IntPtr.Zero, out h, out disp);
    string d = disp == 1 ? "REG_CREATED_NEW_KEY" : disp == 2 ? "REG_OPENED_EXISTING_KEY" : ("disp=" + disp);
    if (rc == 0) RegCloseKey(h);
    return Code(rc) + " " + d;
  }
  public static string Delete(string sub) { return Code(RegDeleteKeyW(HKLM, sub)); }
  static byte[] U16(string s) { return Encoding.Unicode.GetBytes(s + "\0"); }
  // kind: 1=SZ 2=EXPAND_SZ 3=REG_SZ default value 4=DWORD 7=MULTI_SZ(sep ';')
  public static string Set(string sub, uint kind, string name, string val) {
    IntPtr h = IntPtr.Zero; uint disp = 0;
    int rc = RegCreateKeyExW(HKLM, sub, 0, IntPtr.Zero, 0, KEY_WRITE | KEY_WOW64_64KEY, IntPtr.Zero, out h, out disp);
    if (rc != 0) return Code(rc);
    try {
      byte[] data = null; uint t = kind;
      if (kind == 4) {
        data = new byte[4];
        uint v = uint.Parse(val);
        data[0] = (byte)(v & 0xFF); data[1] = (byte)((v >> 8) & 0xFF);
        data[2] = (byte)((v >> 16) & 0xFF); data[3] = (byte)((v >> 24) & 0xFF);
      } else if (kind == 7) {
        string[] parts = val.Split(';');
        StringBuilder sb = new StringBuilder();
        foreach (string p in parts) if (p.Length > 0) sb.Append(p).Append('\0');
        sb.Append('\0');
        data = Encoding.Unicode.GetBytes(sb.ToString());
      } else {
        if (kind == 3) { t = 1; name = null; }
        data = U16(val);
      }
      int rc2 = RegSetValueExW(h, name, 0, t, data, (uint)data.Length);
      return Code(rc2) + " kind=" + t + " cb=" + data.Length;
    } finally { RegCloseKey(h); }
  }
  public static string Read(string sub, string name) {
    IntPtr h = IntPtr.Zero;
    int rc = RegOpenKeyExW(HKLM, sub, 0, KEY_READ | KEY_WOW64_64KEY, out h);
    if (rc != 0) return Code(rc);
    try {
      uint type = 0, cb = 0;
      int r1 = RegQueryValueExW(h, name, IntPtr.Zero, out type, null, ref cb);
      if (r1 != 0) return Code(r1);
      byte[] buf = new byte[cb];
      int r2 = RegQueryValueExW(h, name, IntPtr.Zero, out type, buf, ref cb);
      if (r2 != 0) return Code(r2);
      if (type == 4) {
        uint v = (uint)(buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24));
        return "DWORD=" + v.ToString("X8");
      }
      string s = Encoding.Unicode.GetString(buf);
      if (type == 7) {
        List<string> parts = new List<string>();
        foreach (string p in s.Split('\0')) if (p.Length > 0) parts.Add(p);
        return "MULTI[" + string.Join(";", parts.ToArray()) + "]";
      }
      return (type == 2 ? "EXPAND[" : "SZ[") + s.TrimEnd('\0') + "]";
    } finally { RegCloseKey(h); }
  }
  public static string Tree(string sub) {
    IntPtr h = IntPtr.Zero;
    int rc = RegOpenKeyExW(HKLM, sub, 0, KEY_READ | KEY_WOW64_64KEY, out h);
    if (rc != 0) return Code(rc);
    try {
      List<string> names = new List<string>();
      StringBuilder sb = new StringBuilder(256);
      for (uint i = 0; i < 256; i++) {
        sb.Length = 0;
        uint cb = (uint)sb.Capacity, cbCls = 0;
        int r = RegEnumKeyExW(h, i, sb, ref cb, IntPtr.Zero, IntPtr.Zero, ref cbCls, IntPtr.Zero);
        if (r != 0) break;
        names.Add(sb.ToString());
      }
      return "n=" + names.Count + " [" + string.Join(";", names.ToArray()) + "]";
    } finally { RegCloseKey(h); }
  }
}
'@

$svcSrc = @'
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Pe113 {
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
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);
  [DllImport("wlanapi.dll", EntryPoint = "WlanOpenHandle")]
  static extern int WlanOpenConnection(uint ver, IntPtr res, out uint neg, out IntPtr h);
  [DllImport("wlanapi.dll")] static extern int WlanEnumInterfaces(IntPtr h, IntPtr res, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern int WlanQueryInterface(IntPtr h, ref Guid g, uint opcode,
      IntPtr res, out uint dataSize, out IntPtr data, IntPtr valueType);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr p);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr h, IntPtr res);

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_QUERY_CONFIG = 0x0001;
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
        if (depsRaw != null) foreach (string p in depsRaw.Split('\0')) if (p.Length > 0) dl.Add(p);
        return "type=0x" + type.ToString("X2") + " start=" + start + " path=[" + path + "] group=[" + grp +
               "] obj=[" + obj + "] deps=[" + string.Join(";", dl.ToArray()) + "]";
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
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
        uint ds2 = 0; IntPtr dp2 = IntPtr.Zero;
        int q2 = WlanQueryInterface(h, ref g0, 6, IntPtr.Zero, out ds2, out dp2, IntPtr.Zero);
        string conn = "?";
        if (q2 == 0 && dp2 != IntPtr.Zero && ds2 >= 1) conn = (Marshal.ReadByte(dp2) != 0) ? "yes" : "no";
        if (dp2 != IntPtr.Zero) WlanFreeMemory(dp2);
        return "nif=" + n + " guid0=" + g0 + " state=" + st + " connected=" + conn;
      } finally { WlanFreeMemory(list); }
    } finally { WlanCloseHandle(h, IntPtr.Zero); }
  }
  static string[] ModulesOf(int pid, ref IntPtr cachedH, ref int cachedPid) {
    if (pid <= 0) return new string[0];
    if (cachedH == IntPtr.Zero || cachedPid != pid) {
      if (cachedH != IntPtr.Zero) CloseHandle(cachedH);
      cachedH = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
      cachedPid = cachedH == IntPtr.Zero ? 0 : pid;
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
  // probe111/probe112's trace, unchanged, so the result is directly comparable with their
  // "loaded=36 win32hex=0x800C0006 t=~130ms tail=...,wmiclnt.dll" negative baseline.
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
      int from = n > 8 ? n - 8 : 0;
      for (int i = from; i < n; i++) lines.Add("TAIL " + order[i]);
      return lines.ToArray();
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
}
'@

if ($DryRun) {
  L('DRY probe113: M0 census, M1 write ladder (3 mechanisms x 2 locations), M2 WinRE Parameters subtree,')
  L('DRY  M3 start wlansvc + module trace + wlanapi interface count, M4 restore the service record.')
  L('DRY scratch keys: HKLM\SOFTWARE\_P113W/_P113N/_P113A and ' + $parRel + '\_P113B, all deleted in M4.')
  L('DRY target subtree under ' + $parRel + ': ComInterfaceProviders, EapolKeyIpAddress, OEM\SystemCapabilities,')
  L('DRY  WfdInterfaceManagement, VendorSpecificIEProviders x2(x3 if WiFiDisplay.dll present)' +
    ' ; plus ' + $svcRel + '\VirtualizationManager. OneXAuthenticator/WFDProvPlugin stay gated on')
  L('DRY  WcnEapAuthProxy.dll/wfdprov.dll, which probe112 P1 reported absent.')
  L('DRY would read ' + (C $svcPs) + ' and ' + (C $s32) + '; no writes, no service starts.')
  $n = 0
  try { Add-Type -TypeDefinition $regSrc -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY Reg113 ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  try { Add-Type -TypeDefinition $svcSrc -Language CSharp -EA Stop | Out-Null; $n += 1 }
  catch { L('DRY Pe113 ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY classes compiled=' + $n + '/2')
  exit 0
}

$reg = $false
try { Add-Type -TypeDefinition $regSrc -Language CSharp -EA Stop | Out-Null; $reg = $true }
catch { L('Reg113 ADDTYPE FAILED ' + (C $_.Exception.Message)) }
$native = $false
try { Add-Type -TypeDefinition $svcSrc -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('Pe113 ADDTYPE FAILED ' + (C $_.Exception.Message)) }
L('probe113 begin reg=' + $reg + ' native=' + $native + ' root=[' + (C $s32) + '] ps=' + $PSVersionTable.PSVersion)

function WlanLine([string]$tag) {
  if (-not $native) { L('WLAN  [' + $tag + '] skipped: native unavailable'); return }
  $r = ''
  try { $r = [Pe113]::WlanProbe() } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  L('WLAN  [' + $tag + '] ' + $r)
}
function Tr([string]$svcName, [string]$tag) {
  if (-not $native) { L('TRACE ' + $svcName + ' [' + $tag + '] skipped: native unavailable'); return }
  $lines = @()
  try { $lines = @([Pe113]::Trace($svcName, 3000)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
  $sr = ''; $fin = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^START=') { $sr = (C "$l") } }
  foreach ($l in @($lines)) { if ((C "$l") -match '^FINAL ') { $fin = (C "$l") } }
  $tail = @(@($lines) | Where-Object { (C "$_") -match '^TAIL ' } | ForEach-Object { (C "$_") -replace '^TAIL ', '' })
  L('TRACE ' + $svcName + ' [' + $tag + '] ' + $sr + ' | ' + $fin + ' | tail=' + (@($tail) -join ','))
  WlanLine $tag
}
function NRead([string]$sub, [string]$name) {
  if (-not $reg) { return 'no Reg113' }
  $r = ''
  try { $r = [Reg113]::Read($sub, $name) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  return $r
}
function NExists([string]$sub) {
  if (-not $reg) { return 'no Reg113' }
  $r = ''
  try { $r = [Reg113]::Exists($sub) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  return $r
}
function NTree([string]$sub) {
  if (-not $reg) { return 'no Reg113' }
  $r = ''
  try { $r = [Reg113]::Tree($sub) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  return $r
}
# Every mutation goes through this: it never swallows, it always re-reads, and it says which mechanism
# was used -- that is the whole point of the probe.
function NSet([string]$mech, [string]$sub, [string]$name, [string]$val, [uint32]$kind) {
  if ($mech -ne 'native') { return 'skipped ' + $mech }
  $r = ''
  try { $r = [Reg113]::Set($sub, $kind, $name, $val) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  $back = NRead $sub $name
  L('  set ' + (C $sub) + '\' + (C $name) + ' -> ' + $r + ' | readback ' + $back)
  return $r
}
function PTest([string]$p) {
  $r = ''
  try { $r = ('' + (Test-Path -LiteralPath $p)) } catch { $r = 'EXC ' + (C $_.Exception.Message) }
  return $r
}

# ---------- M0: census -- provider view vs native view ----------
$openW = 'no Reg113'
if ($reg) { try { $openW = [Reg113]::Open($svcRel, $true) } catch { $openW = 'EXC ' + (C $_.Exception.Message) } }
L('M0 svc open write=' + $openW)
foreach ($k in @($svcRel, $parRel, ($parRel + '\ComInterfaceProviders'), ($parRel + '\EapolKeyIpAddress'),
                 ($parRel + '\OEM'), ($parRel + '\OEM\SystemCapabilities'), ($parRel + '\WfdInterfaceManagement'),
                 ($parRel + '\VendorSpecificIEProviders'), ($parRel + '\OneXAuthenticator'), ($parRel + '\WFDProvPlugin'),
                 ($svcRel + '\VirtualizationManager'), ($svcRel + '\Security'))) {
  $leaf = (C (Split-Path $k -Leaf))
  $ps = PTest ('HKLM:\' + $k)
  L('M0 KEY ' + $leaf.PadRight(24) + ' provider=' + $ps + ' native=' + (NExists $k))
}
L('M0 TREE Parameters   ' + (NTree $parRel))
L('M0 TREE VirtualizMgr ' + (NTree ($svcRel + '\VirtualizationManager')))
L('M0 VAL  DependOnService ' + (NRead $svcRel 'DependOnService'))
L('M0 VAL  Start=' + (NRead $svcRel 'Start') + ' Type=' + (NRead $svcRel 'Type') +
  ' ImagePath=' + (NRead $svcRel 'ImagePath'))
if ($native) { L('M0 scm-view  ' + [Pe113]::Config('wlansvc')) }
if ($native) { L('M0 status    ' + [Pe113]::Status('wlansvc')) }
if ($Readonly) { L('M0 readonly ending here'); exit 0 }

# ---------- M1: write ladder, three mechanisms, two locations ----------
$isAdmin = 'EXC'
try {
  $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
  $prin = New-Object Security.Principal.WindowsPrincipal($wid)
  $isAdmin = '' + $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $isAdmin = 'EXC ' + (C $_.Exception.Message) }
L('M1 whoami=' + (C "$env:USERNAME") + ' isAdmin=' + $isAdmin)
$fp = Join-Path $s32 '_p113_probe.txt'
$fileWrite = 'SKIP'
try {
  Set-Content -LiteralPath $fp -Value 'p113' -EA Stop
  $fileWrite = 'OK ' + (C "$((Get-Item -LiteralPath $fp -EA SilentlyContinue).Length)") + 'B'
  Remove-Item -LiteralPath $fp -Force -EA SilentlyContinue
} catch { $fileWrite = 'FAIL ' + (C $_.Exception.Message) }
L('M1 FILE write under ' + (C $s32) + ' -> ' + (C $fileWrite))

$mech = ''
$w1 = 'SKIP'
try {
  New-Item -LiteralPath 'HKLM:\SOFTWARE\_P113W' -Force -EA Stop | Out-Null
  $w1 = 'OK'
} catch { $w1 = 'EXC ' + (C $_.Exception.Message) }
L('M1 PROVIDER New-Item HKLM\SOFTWARE\_P113W -> ' + $w1 + ' | provider sees=' + (PTest 'HKLM:\SOFTWARE\_P113W') +
  ' | native sees=' + (NExists 'SOFTWARE\_P113W'))
$w2 = 'SKIP'
try {
  $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SOFTWARE\_P113N')
  if ($null -eq $k) { $w2 = 'NULL' } else { $w2 = 'OK'; $k.Dispose() }
} catch { $w2 = 'EXC ' + (C $_.Exception.Message) }
L('M1 .NET CreateSubKey SOFTWARE\_P113N -> ' + $w2 + ' | native sees=' + (NExists 'SOFTWARE\_P113N'))
$w3 = 'SKIP'
if ($reg) { try { $w3 = [Reg113]::Create('SOFTWARE\_P113A') } catch { $w3 = 'EXC ' + (C $_.Exception.Message) } }
L('M1 NATIVE RegCreateKeyExW SOFTWARE\_P113A -> ' + $w3)
$w4 = 'SKIP'
if ($reg) { try { $w4 = [Reg113]::Create($parRel + '\_P113B') } catch { $w4 = 'EXC ' + (C $_.Exception.Message) } }
L('M1 NATIVE RegCreateKeyExW ' + (C $parRel) + '\_P113B -> ' + $w4)
$w5 = 'SKIP'
if ($reg) { try { $w5 = [Reg113]::Set($parRel + '\_P113B', 1, 'T', 'x') } catch { $w5 = 'EXC ' + (C $_.Exception.Message) } }
L('M1 NATIVE RegSetValueExW _P113B\T -> ' + $w5 + ' | readback ' + (NRead ($parRel + '\_P113B') 'T'))
if ($w3 -match 'rc=0x00000000') { $mech = 'native' }
L('M1 MECHANISM=' + $(if ($mech) { $mech } else { 'NONE-WRITE-FAILED: M2/M3 cannot be judged, and the fix is bake-time not run-time' }))

# ---------- M2: the WinRE Parameters subtree, self-reporting ----------
$made = @()
if ($mech -eq 'native') {
  L('M2 gate: WiFiDisplay.dll=' + (Test-Path -LiteralPath (Join-Path $s32 'WiFiDisplay.dll')) +
    ' WcnEapAuthProxy.dll=' + (Test-Path -LiteralPath (Join-Path $s32 'WcnEapAuthProxy.dll')) +
    ' wfdprov.dll=' + (Test-Path -LiteralPath (Join-Path $s32 'wfdprov.dll')))
  $items = @(
    @{ k = $parRel + '\ComInterfaceProviders'; n = 'IHNetIcsSettings'; t = 1; v = '{46C166AA-3108-11D4-9348-00C04F8EEB71}' },
    @{ k = $parRel + '\EapolKeyIpAddress'; n = 'LocalAddress'; t = 1; v = '192.168.137.1' },
    @{ k = $parRel + '\EapolKeyIpAddress'; n = 'PrefixLength'; t = 4; v = '24' },
    @{ k = $parRel + '\OEM'; n = ''; t = 0; v = '' },
    @{ k = $parRel + '\OEM\SystemCapabilities'; n = ''; t = 0; v = '' },
    @{ k = $parRel + '\WfdInterfaceManagement'; n = 'DisablePhyTypeRestriction'; t = 4; v = '0' },
    @{ k = $parRel + '\WfdInterfaceManagement'; n = 'DisableSetActiveWfdMgrSidCheck'; t = 4; v = '0' },
    @{ k = $parRel + '\VendorSpecificIEProviders'; n = ''; t = 0; v = '' },
    @{ k = $parRel + '\VendorSpecificIEProviders\00666BD7-8CB1-4A35-A3B7-83BA6D5BBEE3'; n = 'Path'; t = 2; v = '%SYSTEMROOT%\System32\WlanSvc.dll' },
    @{ k = $parRel + '\VendorSpecificIEProviders\4D50EE01-EEE0-4E5D-9A41-2F5F32044192'; n = 'Path'; t = 2; v = '%SYSTEMROOT%\System32\WlanSvc.dll' },
    @{ k = $svcRel + '\VirtualizationManager'; n = 'WindowsPushNotificationPlatformClsid'; t = 1; v = '0C9281F9-6DA1-4006-8729-DE6E6B61581C' }
  )
  if (Test-Path -LiteralPath (Join-Path $s32 'WiFiDisplay.dll')) {
    $items += @{ k = $parRel + '\VendorSpecificIEProviders\B7D94B4D-5DB1-4E70-B5C3-DD003EEEBE66'; n = 'Path'; t = 2; v = '%SYSTEMROOT%\System32\WiFiDisplay.dll' }
  }
  foreach ($it in $items) {
    $c = 'SKIP'
    try { $c = [Reg113]::Create($it.k) } catch { $c = 'EXC ' + (C $_.Exception.Message) }
    L('M2 KEY ' + (C (Split-Path $it.k -Leaf)).PadRight(40) + ' create -> ' + $c)
    $made += $it.k
    if ($it.t -eq 0) { continue }
    $null = NSet 'native' $it.k $it.n $it.v $it.t
    $made += ($it.k + '\' + $it.n)
  }
  if (Test-Path -LiteralPath (Join-Path $s32 'WcnEapAuthProxy.dll')) {
    $k = $parRel + '\OneXAuthenticator'
    L('M2 KEY OneXAuthenticator create -> ' + ([Reg113]::Create($k)))
    $null = NSet 'native' $k '(default)' '%SystemRoot%\System32\WcnEapAuthProxy.dll' 3
  } else { L('M2 SKIP OneXAuthenticator: WcnEapAuthProxy.dll absent (a default value pointing at a missing DLL would be worse than nothing)') }
  if (Test-Path -LiteralPath (Join-Path $s32 'wfdprov.dll')) {
    $k = $parRel + '\WFDProvPlugin'
    L('M2 KEY WFDProvPlugin create -> ' + ([Reg113]::Create($k)))
    $null = NSet 'native' $k '(default)' '%SystemRoot%\System32\wfdprov.dll' 3
    $null = NSet 'native' $k 'DllEntryPoint' 'WFDProvGetInfo' 1
  } else { L('M2 SKIP WFDProvPlugin: wfdprov.dll absent') }
  L('M2 wrote=' + @($made).Count + ' entries')
  L('M2 TREE Parameters   ' + (NTree $parRel))
  L('M2 TREE VSIEProviders ' + (NTree ($parRel + '\VendorSpecificIEProviders')))
  L('M2 VAL  ComInterfaceProviders\IHNetIcsSettings ' + (NRead ($parRel + '\ComInterfaceProviders') 'IHNetIcsSettings'))
  L('M2 VAL  VirtualizationManager clsid ' + (NRead ($svcRel + '\VirtualizationManager') 'WindowsPushNotificationPlatformClsid'))
} else {
  L('M2 NOT RUN: no working write mechanism (see M1). probe112 R4 is therefore still untested, not falsified.')
}

# ---------- M3: does the subtree change anything? ----------
if ($mech -eq 'native') { Tr 'wlansvc' 'M3 WinRE Parameters subtree present' }
if ($mech -eq 'native') {
  # Second start with the auth/tether side up, because a Parameters entry that names a COM provider is
  # exactly the kind of thing wlansvc resolves lazily after its own init.
  foreach ($n in @('wcmsvc', 'EapHost', 'dot3svc', 'netprofm')) {
    if ($native) {
      $r = ''
      try { $r = [Pe113]::StartAndWait($n, 6000) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
      L('M3 start ' + $n + ' ' + $r)
    }
  }
  Tr 'wlansvc' 'M3 subtree + auth side up'
}

# ---------- M4: restore the record probe112 left mutated ----------
if ($mech -eq 'native') {
  $null = NSet 'native' $svcRel 'DependOnService' 'nativewifip;RpcSs;Ndisuio' 7
  $null = NSet 'native' $svcRel 'Start' '3' 4
  foreach ($sk in @('SOFTWARE\_P113W', 'SOFTWARE\_P113N', 'SOFTWARE\_P113A', ($parRel + '\_P113B'))) {
    $d = 'SKIP'
    try { $d = [Reg113]::Delete($sk) } catch { $d = 'EXC ' + (C $_.Exception.Message) }
    L('M4 delete ' + (C $sk) + ' -> ' + $d)
  }
  L('M4 VAL  DependOnService ' + (NRead $svcRel 'DependOnService') + ' Start=' + (NRead $svcRel 'Start'))
  if ($native) { L('M4 scm-view  ' + [Pe113]::Config('wlansvc')) }
}
L('M4 note: the disc image is untouched; the live keys made here (and the Start=2/dep-clear that probe112 left) die on reboot.')
L('probe113 end -- baseline to beat: probe112 every rung = START_OK then state=1 win32hex=0x800C0006 loaded=36 tail=...,wmiclnt.dll')
