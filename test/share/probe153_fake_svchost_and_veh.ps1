# probe153 -- run wlansvc's own ServiceMain inside a process WE own, started by the real SCM, with a
# vectored exception handler attached, so the first-chance exception behind 0x800C0006 names itself.
#
# Why this probe exists (what the last three closed):
#   probe150: all 82 host-order modules load in the PE by full path (82/82, first-fail=none) and 32/34 of
#     wlansvc.dll's delay contracts resolve here, including ext-ms-win-wlan-grouppolicy -> wlgpclnt.dll.
#     The 2 dead names are noise: ext-ms-win-networking-wlanstorage is ALSO err=126 on the healthy host
#     (build\scratch\p150b_host_control.txt), and nothing on the host's wlansvc module list came from
#     embeddedmodesvcapi.dll. FILE + API-SET LAYERS CLOSED.
#   probe152: WinMGmt is already RUNNING in the PE (pid, Repository OBJECTS.DATA 17MB) and wlansvc still
#     dies at loaded=36 / 0x800C0006 / 122ms, and the host control shows wmiclnt.dll does not even export
#     WmiOpenBlock -- so "it dies on the WMI door" was wrong too. SERVICE/WMi AVAILABILITY CLOSED.
#   probe113: the WinRE Parameters subtree, applied natively and read back, changed nothing.
#   probe114: the trace ends at wmiclnt (host step #48); host step #49 (wlgpclnt) is resolvable here.
#   So the failure is a runtime decision inside WlanSvcMain, and every external signal we can read --
#   SCM status, module list, ETW (probe96: no channels), DBWIN (probe106) -- is silent about it. But a
#   delay-load miss or a failed kernel call RAISES an exception, and a VEH sees first-chance exceptions
#   BEFORE the service's own SEH converts them into that return code. probe86's "it does not crash" only
#   ever proved there was no *unhandled* exception.
#
# How the host is built: the service record is flipped (natively; RegSetValueExW -- the PS registry
# provider has no -LiteralPath in the PE, probe113 M1) so that the SCM itself launches
#   powershell.exe -File <this script> -HostRole
# as the wlansvc service process (Type=0x10 OWN_PROCESS). That keeps the real SCM handshake: our child
# calls StartServiceCtrlDispatcherW with { "wlansvc", <our callback> }, and the callback LoadLibrary's
# wlansvc.dll and calls its exported WlanSvcMain with the argc/argv the SCM handed us. Inside that process
# we install the VEH, log the ordered module growth, and write everything to a file on X: (session 0 has
# no console). Then this parent reads the file, runs the acceptance instrument (WlanOpenHandle +
# WlanEnumInterfaces), and restores the record byte-for-byte.
# Everything lives on the RAM disk: a reboot returns the disc's own WinRE-shaped record.
#
# Judgement:
#   * An exception line like 0xC0000135 / 0xC0000034 / 0xC0000022 with module+offset is the root cause,
#     named. 0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND) would fit the public reading of 0x800C0006
#     ("the system cannot find the specified object") and would tell us WHICH object via the faulting
#     instruction's module.
#   * If the fake host reaches RUNNING and WlanEnumInterfaces lists the Realtek interface, wlansvc itself
#     is fine and the defect is in how the WinRE-shaped svchost hosts it -- which is shippable either way.
#   * If the dispatcher never even calls our callback, the record flip is broken and we restore + retry.
param([switch]$DryRun, [switch]$HostRole, [switch]$SelfTest, [string]$Root = 'X:\Windows\System32',
      [string]$Out = 'X:\p153_host_out.txt', [string]$PidFile = 'X:\p153_child.pid',
      [string]$Entry = 'WlanSvcMain', [string]$SvcName = 'wlansvc', [string]$ExportDump = '')
function L([string]$s) { Write-Output ('P153 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = (C $Root)
$svcRel = 'SYSTEM\CurrentControlSet\Services\wlansvc'
$self = (C $PSCommandPath)

$src = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Hm153 {
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
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegGetValueW(IntPtr h, string sub, string val, uint flags, out uint type,
      IntPtr data, ref uint cb);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegCreateKeyExW(IntPtr h, string sub, uint r, string cls, uint opt, uint acc,
      IntPtr sa, out IntPtr key, out uint disp);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int RegSetValueExW(IntPtr key, string name, uint r, uint type, byte[] data, uint cb);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool StartServiceCtrlDispatcherW(IntPtr table);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  // CharSet must stay ANSI here: there is no GetProcAddressW, and with CharSet.Unicode the marshaller
  // hands the ANSI function a UTF-16 buffer, so it looks up "W" and reports ERROR_PROC_NOT_FOUND(127)
  // for names that are plainly in the export table -- which is exactly how the first host run of this
  // probe "proved" that wlansvc.dll does not export WlanSvcMain.
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr GetProcAddress(IntPtr h, string name);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern int VirtualQuery(IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern uint GetCurrentThreadId();
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr AddVectoredExceptionHandler(uint first, VEH cb);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);

  public delegate uint VEH(IntPtr pointers);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate void SvcMainCb(uint argc, IntPtr argv);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate void NativeSvcMain(uint argc, IntPtr argv);

  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public uint align1;
    public UIntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
    public uint align2;
  }

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004,
             SERVICE_QUERY_CONFIG = 0x0001;
  const uint RRF_RT_ANY = 0xFFFF, RRF_WOW64_64KEY = 0x00010000;
  const uint KEY_WRITE = 0x20006;
  const uint MEM_IMAGE = 0x1000000;
  const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;
  static readonly IntPtr HKLM = new IntPtr(-2147483646);

  static VEH g_veh; static IntPtr g_vehHandle;
  static readonly object g_lock = new object();
  static List<string> g_events = new List<string>();
  static List<string> g_snaps = new List<string>();
  static StreamWriter g_log;
  static Stopwatch g_sw = new Stopwatch();

  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : st == 5 ? "CONTINUE_PENDING" : st == 6 ? "PAUSE_PENDING" :
           st == 7 ? "PAUSED" : ("state" + st);
  }

  // ---------- shared helpers ----------
  public static void OpenLog(string path) {
    g_sw = Stopwatch.StartNew();
    try {
      FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
      g_log = new StreamWriter(fs);
      g_log.AutoFlush = true;
    } catch { g_log = null; }
  }
  public static void Log(string line) {
    lock (g_lock) {
      if (g_log != null) { try { g_log.WriteLine("t" + g_sw.ElapsedMilliseconds + "ms " + line); } catch { } }
    }
  }
  static string ModuleOf(IntPtr addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) return "?";
    if (mbi.Type != MEM_IMAGE) return "not-image(0x" + mbi.Type.ToString("X") + ")";
    StringBuilder sb = new StringBuilder(1024);
    if (GetModuleFileNameExW(GetCurrentProcess(), mbi.AllocationBase, sb, (uint)sb.Capacity) == 0) {
      return "base0x" + ((long)mbi.AllocationBase).ToString("X");
    }
    string p = sb.ToString();
    int k = p.LastIndexOf('\\');
    string nm = k >= 0 ? p.Substring(k + 1) : p;
    return nm.ToLowerInvariant() + "+0x" + ((long)addr - (long)mbi.AllocationBase).ToString("X");
  }
  static uint VehCbk(IntPtr pointers) {
    try {
      IntPtr rec = Marshal.ReadIntPtr(pointers, 0);
      uint code = (uint)Marshal.ReadInt32(rec, 0);
      uint flags = (uint)Marshal.ReadInt32(rec, 4);
      IntPtr addr = Marshal.ReadIntPtr(rec, 16);
      string line;
      lock (g_lock) { line = "EXC 0x" + code.ToString("X8") + " flags=0x" + flags.ToString("X") +
        " at " + ModuleOf(addr) + " n=" + g_events.Count; g_events.Add(line); }
      Log(line);
    } catch { }
    return 0;   // EXCEPTION_CONTINUE_SEARCH -- observe only, never change behaviour
  }
  public static string InstallVeh() {
    g_veh = new VEH(VehCbk);
    g_vehHandle = AddVectoredExceptionHandler(1, g_veh);
    return g_vehHandle == IntPtr.Zero ? ("FAIL err=" + Marshal.GetLastWin32Error()) : "OK";
  }
  public static string[] Modules() {
    List<string> res = new List<string>();
    IntPtr[] mods = new IntPtr[2048]; uint need = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, (uint)(mods.Length * IntPtr.Size), out need, 0x03))
      { res.Add("ENUM_ERR=" + Marshal.GetLastWin32Error()); return res.ToArray(); }
    int count = (int)(need / (uint)IntPtr.Size);
    if (count > mods.Length) count = mods.Length;
    StringBuilder sb = new StringBuilder(1024);
    for (int i = 0; i < count; i++) {
      sb.Length = 0;
      if (GetModuleFileNameExW(GetCurrentProcess(), mods[i], sb, (uint)sb.Capacity) == 0) continue;
      string p = sb.ToString(); int k = p.LastIndexOf('\\');
      res.Add((k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant());
    }
    return res.ToArray();
  }
  public static int ExcCount() { lock (g_lock) { return g_events.Count; } }
  public static string ExcAll(int max) {
    lock (g_lock) {
      int n = g_events.Count; if (n > max) n = max;
      return string.Join(" || ", g_events.GetRange(0, n).ToArray());
    }
  }

  // ---------- parent side ----------
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
        List<string> parts = new List<string>();
        foreach (string p2 in all.Split('\0')) { if (p2.Length > 0) parts.Add(p2); }
        return "MULTI[" + string.Join(";", parts.ToArray()) + "]";
      }
      if (type == 3 || type == 11) return "BINARY[" + cb + "B]";
      return "type" + type + " cb=" + cb;
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static int RegSetSz(string sub, string val, string data, bool expand) {
    IntPtr key; uint disp;
    int rc = RegCreateKeyExW(HKLM, sub, 0, null, 0, KEY_WRITE | 0x0100, IntPtr.Zero,
                             out key, out disp);
    if (rc != 0) return rc;
    try {
      byte[] b = Encoding.Unicode.GetBytes(data + "\0");
      return RegSetValueExW(key, val, 0, expand ? 2u : 1u, b, (uint)b.Length);
    } finally { RegCloseKey(key); }
  }
  public static int RegSetDw(string sub, string val, uint data) {
    IntPtr key; uint disp;
    int rc = RegCreateKeyExW(HKLM, sub, 0, null, 0, KEY_WRITE | 0x0100, IntPtr.Zero, out key, out disp);
    if (rc != 0) return rc;
    try {
      byte[] b = BitConverter.GetBytes(data);
      return RegSetValueExW(key, val, 0, 4, b, (uint)b.Length);
    } finally { RegCloseKey(key); }
  }
  public static string StartAndPoll(string svc, int ms) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR=" + Marshal.GetLastWin32Error();
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      int serr = started ? 0 : Marshal.GetLastWin32Error();
      List<string> seq = new List<string>();
      seq.Add("START=" + (started ? "OK" : ("ERR=" + serr + " (1056=already running)")));
      Stopwatch sw = Stopwatch.StartNew();
      int last = -1;
      while (sw.ElapsedMilliseconds < ms) {
        IntPtr buf = Marshal.AllocHGlobal(36); uint need = 0;
        int st = 1, w = 0, pid = 0;
        bool ok = QueryServiceStatusEx(sv, 0, buf, 36, out need);
        if (ok) { st = Marshal.ReadInt32(buf, 4); w = Marshal.ReadInt32(buf, 12); pid = Marshal.ReadInt32(buf, 28); }
        Marshal.FreeHGlobal(buf);
        if (!ok) { seq.Add("QSS_ERR=" + Marshal.GetLastWin32Error()); break; }
        if (st != last) {
          last = st;
          seq.Add("t" + sw.ElapsedMilliseconds + " " + StateName(st) + " pid=" + pid +
                  " win32hex=0x" + ((uint)w).ToString("X8"));
        }
        if (st == 4) break;
        if (st == 1 && sw.ElapsedMilliseconds > 300) break;
        Thread.Sleep(15);
      }
      seq.Add("final t=" + sw.ElapsedMilliseconds + "ms");
      return string.Join(" | ", seq.ToArray());
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  public static string StopOnly(string svc) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR";
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN"; }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      bool r = ControlService(sv, 1, st);
      int e = Marshal.GetLastWin32Error();
      Marshal.FreeHGlobal(st);
      return r ? "STOPPED" : ("stop err=" + e + " (1062=not running, 1052=cannot control)");
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
        ? StateName(Marshal.ReadInt32(buf, 4)) + " pid=" + Marshal.ReadInt32(buf, 28)
        : ("QSS_ERR=" + Marshal.GetLastWin32Error());
      Marshal.FreeHGlobal(buf);
      return r;
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }

  // ---------- child side: our own svchost ----------
  static NativeSvcMain g_native;
  static string g_dll, g_entry;
  static IntPtr g_hModule;

  static void Callback(uint argc, IntPtr argv) {
    Log("CBK service-main callback invoked argc=" + argc + " thread=" + GetCurrentThreadId());
    try {
      g_hModule = LoadLibraryExW(g_dll, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
      if (g_hModule == IntPtr.Zero) { Log("CBK LOAD_FAIL err=" + Marshal.GetLastWin32Error()); return; }
      string[] modsNow = Modules();
      Log("CBK modules-after-load=" + modsNow.Length);
      IntPtr p = GetProcAddress(g_hModule, g_entry);
      if (p == IntPtr.Zero) {
        Log("CBK NO_EXPORT " + g_entry + " err=" + Marshal.GetLastWin32Error());
        return;
      }
      g_native = (NativeSvcMain)Marshal.GetDelegateForFunctionPointer(p, typeof(NativeSvcMain));
      Log("CBK calling " + g_entry);
      g_native(argc, argv);
      Log("CBK " + g_entry + " RETURNED");
    } catch (Exception e) { Log("CBK MANAGED " + e.GetType().Name + " " + e.Message); }
  }
  public static string RunHost(string dllPath, string entryName, int seconds) {
    g_dll = dllPath; g_entry = entryName;
    Stopwatch sw = Stopwatch.StartNew();
    // Watchdog: the fake host must not outlive the experiment.
    Thread wd = new Thread(delegate () {
      HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      while (sw.ElapsedMilliseconds < seconds * 1000) {
        try {
          string[] m = Modules();
          foreach (string s2 in m) {
            if (!set.Contains(s2)) {
              set.Add(s2);
              int idx = 0;
              lock (g_lock) { idx = g_snaps.Count + 1; g_snaps.Add(s2); }
              Log("MOD " + idx.ToString("000") + " " + s2 + " exc=" + ExcCount());
            }
          }
        } catch { }
        Thread.Sleep(200);
      }
      Log("WATCHDOG end t=" + sw.ElapsedMilliseconds + "ms exc=" + ExcCount());
      Log("FINAL-EXC " + ExcAll(60));
      try { Console.Out.Flush(); } catch { }
      Environment.Exit(0);
    });
    wd.IsBackground = true; wd.Start();

    int sz = 2 * IntPtr.Size;
    IntPtr tbl = Marshal.AllocHGlobal(sz * 2);
    IntPtr name = Marshal.StringToHGlobalUni("wlansvc");
    SvcMainCb cb = new SvcMainCb(Callback);
    IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(cb);
    Marshal.WriteIntPtr(tbl, 0, name);
    Marshal.WriteIntPtr(tbl, IntPtr.Size, cbPtr);
    Marshal.WriteIntPtr(tbl, sz, IntPtr.Zero);
    Marshal.WriteIntPtr(tbl, sz + IntPtr.Size, IntPtr.Zero);
    bool r = StartServiceCtrlDispatcherW(tbl);
    int err = Marshal.GetLastWin32Error();
    GC.KeepAlive(cb);
    string outp = "DISPATCHER " + (r ? "returned TRUE" : ("returned FALSE err=" + err +
        " (1063=not started by the SCM, expected for -SelfTest)"));
    Log(outp);
    return outp;
  }
  public static string DllProbe(string dllPath, string entryName) {
    IntPtr h = LoadLibraryExW(dllPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "LOAD_FAIL err=" + Marshal.GetLastWin32Error();
    IntPtr p = GetProcAddress(h, entryName);
    string r = "load=OK " + entryName + "=" + (p == IntPtr.Zero ? ("NO_EXPORT err=" + Marshal.GetLastWin32Error()) : "found");
    FreeLibrary(h);
    return r;
  }
  // Export names straight out of the file's PE header (data directory #0). GetProcAddress is
  // CASE-SENSITIVE, so this is how the child picks the entry point that actually exists: the record's
  // Parameters\ServiceMain string and the DLL's real export may differ in case, and probe153 must not
  // silently call the wrong thing.
  public static string[] Exports(string path) {
    List<string> res = new List<string>();
    byte[] b;
    try { b = File.ReadAllBytes(path); }
    catch (Exception e) { res.Add("READ_FAIL " + e.GetType().Name); return res.ToArray(); }
    int e_lfanew = BitConverter.ToInt32(b, 0x3C);
    if (BitConverter.ToInt16(b, e_lfanew) != 0x4550) { res.Add("NOT_PE"); return res.ToArray(); }
    int opt = e_lfanew + 24;
    bool is64 = (BitConverter.ToUInt16(b, opt) == 0x20B);
    int dd = opt + (is64 ? 112 : 96);
    int numSec = BitConverter.ToUInt16(b, e_lfanew + 6);
    int sizeOpt = BitConverter.ToUInt16(b, e_lfanew + 20);
    int secOff = e_lfanew + 24 + sizeOpt;
    Func<uint, int> rvaToOff = delegate (uint rva) {
      for (int i = 0; i < numSec; i++) {
        int so = secOff + i * 40;
        uint va = BitConverter.ToUInt32(b, so + 12);
        uint vs = BitConverter.ToUInt32(b, so + 8);
        uint ra = BitConverter.ToUInt32(b, so + 20);
        if (rva >= va && rva < va + Math.Max(vs, 1u)) return (int)(rva - va + ra);
      }
      return -1;
    };
    uint edRva = BitConverter.ToUInt32(b, dd);      // data directory entry 0 = export table
    uint edSize = BitConverter.ToUInt32(b, dd + 4);
    if (edRva == 0 || edSize == 0) { res.Add("NO_EXPORT_DIR"); return res.ToArray(); }
    int ed = rvaToOff(edRva);
    if (ed < 0) { res.Add("ED_MAP_FAIL"); return res.ToArray(); }
    uint numNames = BitConverter.ToUInt32(b, ed + 24);
    int namesOff = rvaToOff(BitConverter.ToUInt32(b, ed + 32));
    if (namesOff < 0) { res.Add("NAMES_MAP_FAIL"); return res.ToArray(); }
    for (int i = 0; i < (int)numNames && i < 4000; i++) {
      int nm = rvaToOff(BitConverter.ToUInt32(b, namesOff + i * 4));
      if (nm < 0) continue;
      StringBuilder sb = new StringBuilder();
      while (nm < b.Length && b[nm] != 0) { sb.Append((char)b[nm]); nm++; }
      res.Add(sb.ToString());
    }
    return res.ToArray();
  }
  // Case-insensitive match of the wanted entry name against the real export table.
  public static string MatchExport(string path, string want) {
    string[] ex = Exports(path);
    foreach (string s in ex) {
      if (string.Equals(s, want, StringComparison.OrdinalIgnoreCase)) return s;
    }
    return "";
  }
}
'@

if ($DryRun) {
  $role = 'parent'
  if ($HostRole) { $role = 'child-fake-svchost' }
  L('DRY probe153 role=' + $role + ' root=[' + $s32 + ']')
  L('DRY  parent: K0 read record natively, K1 find powershell + run -SelfTest, K2 flip ImagePath/Type')
  L('DRY  (0x10) so the SCM starts powershell -File <this> -HostRole, K3 StartService + poll status,')
  L('DRY  K4 dump ' + $Out + ' (VEH first-chance exceptions + ordered modules), K5 WlanOpenHandle/Enum')
  L('DRY  interfaces, K6 restore the record byte for byte.')
  L('DRY  child: VEH + StartServiceCtrlDispatcherW{wlansvc->callback} + LoadLibrary(wlansvc.dll)+')
  L('DRY  ' + $Entry + '(argc,argv); logs to ' + $Out + ', watchdog exits after 20s.')
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1')
  exit 0
}
$ok = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $ok = $true }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)) }
if (-not $ok) { L('ABORT'); exit 1 }

# ---------- -ExportDump: what does this DLL actually export? (host + PE, read-only) ----------
if ($ExportDump) {
  $ep = (C $ExportDump)
  if (-not (Test-Path -LiteralPath $ep)) { L('EXPORTDUMP no such file ' + $ep); exit 1 }
  $exd = @([Hm153]::Exports($ep))
  L('EXPORTDUMP ' + $ep + ' count=' + $exd.Count)
  $shown = 0
  foreach ($x in $exd) {
    if ($shown -ge 200) { L('EXPORTDUMP ... truncated'); break }
    L('EXPORTDUMP| ' + (C $x))
    $shown++
  }
  exit 0
}

# ================= child role =================
$wdll = (C ([System.IO.Path]::Combine($s32, 'wlansvc.dll')))
if ($HostRole) {
  [Hm153]::OpenLog($Out)
  [Hm153]::Log('CHILD begin pid=' + $PID + ' selftest=' + $SelfTest + ' entry=' + $Entry + ' root=[' + $s32 + ']')
  try { Set-Content -LiteralPath $PidFile -Value ('' + $PID) -Encoding ASCII } catch { }
  L('CHILD pid=' + $PID + ' out=' + $Out)
  L('CHILD VEH=' + (C ([Hm153]::InstallVeh())))
  # Entry resolution: svchost reads Parameters\ServiceMain, and GetProcAddress is CASE-SENSITIVE, so the
  # name the record carries and the name the export table carries have to be matched up here rather than
  # guessed -- probe153's first host run showed WlanSvcMain=NO_EXPORT(127) on a machine whose wlansvc is
  # healthy, which is a property of my lookup, not of the service.
  $recEntry = (C ([Hm153]::RegQuery(($svcRel + '\Parameters'), 'ServiceMain')))
  $ex = @([Hm153]::Exports($wdll))
  L('ENTRY record=[' + $recEntry + '] wanted=[' + $Entry + '] exports=' + $ex.Count)
  $cand = @($ex | Where-Object { ('' + $_) -match '(?i)svc|main' })
  L('ENTRY candidates=[' + (C ($cand -join ',')) + ']')
  $use = ''
  if ($Entry) { $use = [Hm153]::MatchExport($wdll, $Entry) }
  if (-not $use -and $recEntry) { $use = [Hm153]::MatchExport($wdll, $recEntry) }
  if (-not $use) { foreach ($x in $cand) { if (('' + $x) -match '(?i)svcmain') { $use = '' + $x; break } } }
  L('ENTRY resolved=[' + $use + ']')
  if (-not $use) { L('CHILD ABORT: wlansvc.dll has no usable service-main export'); exit 2 }
  L('CHILD DLL=' + (C ([Hm153]::DllProbe($wdll, $use))))
  $mods = @([Hm153]::Modules())
  L('CHILD baseline modules=' + $mods.Count)
  $d = [Hm153]::RunHost($wdll, $use, 20)
  L('CHILD ' + (C $d))
  Start-Sleep -Seconds 3
  L('CHILD exc-count=' + [Hm153]::ExcCount())
  L('CHILD EXC ' + (C ([Hm153]::ExcAll(40))))
  exit 0
}

# ================= parent role =================
L('probe153 parent begin root=[' + $s32 + '] svc=' + $SvcName + ' out=' + $Out)

# ---------- K0: the record as it stands (native reads only) ----------
foreach ($v in @('Type', 'Start', 'ErrorControl', 'GroupName', 'ObjectName', 'ImagePath',
                 'DependOnService', 'ServiceSidType', 'RequiredPrivileges', 'Description')) {
  $r = ''
  try { $r = [Hm153]::RegQuery($svcRel, $v) } catch { $r = 'EXC ' + (C $_.Exception.Message) }
  L('K0 ' + (C $v).PadRight(20) + ' ' + (C $r))
}
$origType = [Hm153]::RegQuery($svcRel, 'Type')
$origPath = [Hm153]::RegQuery($svcRel, 'ImagePath')
L('K0 wlansvc ' + (C ([Hm153]::SvcState($SvcName))))

# ---------- K1: can powershell.exe even run here, and does the child script work ----------
$psCandidates = @((C ([System.IO.Path]::Combine($s32, 'WindowsPowerShell\v1.0\powershell.exe'))),
                 (C ([System.IO.Path]::Combine($s32, 'WindowsPowerShell\1.0\powershell.exe'))))
$ps = ''
foreach ($p in $psCandidates) {
  if (Test-Path -LiteralPath $p) { $ps = $p; L('K1 PS found ' + $p + ' ' + (Get-Item -LiteralPath $p).Length + 'B'); break }
  L('K1 PS missing ' + $p)
}
if (-not $ps) { L('K1 ABORT: no powershell in the image'); exit 1 }
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Force -EA SilentlyContinue }
L('K1 selftest script path [' + $self + ']')
$childArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $self,
               '-HostRole', '-SelfTest', '-Root', $s32, '-Out', $Out, '-PidFile', $PidFile,
               '-Entry', $Entry)
try {
  $pr = Start-Process -FilePath $ps -ArgumentList $childArgs -Wait -PassThru -WindowStyle Hidden
  L('K1 SELFTEST exit=' + $pr.ExitCode)
} catch { L('K1 SELFTEST EXC ' + (C $_.Exception.Message)) }
if (Test-Path -LiteralPath $Out) {
  $lines = @(Get-Content -LiteralPath $Out -EA SilentlyContinue)
  L('K1 OUT lines=' + $lines.Count)
  foreach ($x in $lines) { L('K1| ' + (C $x)) }
} else { L('K1 OUT file never appeared -- the child could not write ' + $Out) }

# ---------- K2: hand the service over to our fake host, keeping the real SCM handshake ----------
$cmd = '"' + $ps + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $self +
       '" -HostRole -Root "' + $s32 + '" -Out "' + $Out + '" -PidFile "' + $PidFile +
       '" -Entry ' + $Entry
L('K2 new ImagePath ' + (C $cmd))
$rc1 = [Hm153]::RegSetSz($svcRel, 'ImagePath', $cmd, $false)
L('K2 REG_SET ImagePath rc=' + $rc1 + ' -> now [' + (C ([Hm153]::RegQuery($svcRel, 'ImagePath'))) + ']')
$rc2 = [Hm153]::RegSetDw($svcRel, 'Type', 16)
L('K2 REG_SET Type=0x10(OWN_PROCESS) rc=' + $rc2 + ' -> now ' + (C ([Hm153]::RegQuery($svcRel, 'Type'))))
if (Test-Path -LiteralPath $Out) { Remove-Item -LiteralPath $Out -Force -EA SilentlyContinue }

# ---------- K3: start it for real ----------
L('K3 ' + (C ([Hm153]::StartAndPoll($SvcName, 15000))))
L('K3 after-start state ' + (C ([Hm153]::SvcState($SvcName))))

# ---------- K4: what did the fake host see? ----------
Start-Sleep -Seconds 2
if (Test-Path -LiteralPath $Out) {
  $lines2 = @(Get-Content -LiteralPath $Out -EA SilentlyContinue)
  L('K4 OUT lines=' + $lines2.Count)
  foreach ($x in $lines2) { L('K4| ' + (C $x)) }
} else { L('K4 OUT file never appeared -- the SCM did not run the child, or it could not write') }
if (Test-Path -LiteralPath $PidFile) {
  $cpid = ('' + (Get-Content -LiteralPath $PidFile -EA SilentlyContinue | Select-Object -First 1)).Trim()
  L('K4 child pid=' + $cpid)
  try {
    $pp = Get-Process -Id ([int]$cpid) -EA SilentlyContinue
    if ($pp) { L('K4 child still alive name=' + (C $pp.ProcessName) + ' -> stopping'); Stop-Process -Id ([int]$cpid) -Force -EA SilentlyContinue }
    else { L('K4 child already gone') }
  } catch { L('K4 child-probe EXC ' + (C $_.Exception.Message)) }
}

# ---------- K5: the acceptance instrument ----------
L('K5 WlanOpenHandle-state=' + (C ([Hm153]::SvcState($SvcName))))
$wo = ''
try {
  $t = 'using System;using System.Runtime.InteropServices;public static class Wl153{'+
       '[DllImport("wlanapi.dll",EntryPoint="WlanOpenHandle")]static extern int Open(uint v,IntPtr r,out uint n,out IntPtr h);'+
       '[DllImport("wlanapi.dll")]static extern int Enum(IntPtr h,IntPtr r,out IntPtr l);'+
       '[DllImport("wlanapi.dll")]static extern void Fr(IntPtr p);'+
       '[DllImport("wlanapi.dll")]static extern int Close(IntPtr h,IntPtr r);'+
       'public static string Probe(){uint n=0;IntPtr h=IntPtr.Zero;int r=Open(2,IntPtr.Zero,out n,out h);'+
       'if(r!=0)return "OPEN hr=0x"+((uint)r).ToString("X8");'+
       'try{IntPtr l=IntPtr.Zero;int e=Enum(h,IntPtr.Zero,out l);if(e!=0)return "ENUM hr=0x"+((uint)e).ToString("X8");'+
       'try{return "nif="+Marshal.ReadInt32(l,0);}finally{Fr(l);}'+
       '}finally{Close(h,IntPtr.Zero);}}}'
  Add-Type -TypeDefinition $t -Language CSharp -EA Stop | Out-Null
  $wo = [Wl153]::Probe()
} catch { $wo = 'EXC ' + (C $_.Exception.Message) }
L('K5 WLAN ' + (C $wo))

# ---------- K6: restore the record byte for byte ----------
$rr1 = [Hm153]::RegSetSz($svcRel, 'ImagePath', ('' + $origPath), $true)
$rr2 = 0
if ('' + $origType -match 'DWORD=0x00000020') { $rr2 = [Hm153]::RegSetDw($svcRel, 'Type', 32) }
elseif ('' + $origType -match 'DWORD=0x00000010') { $rr2 = [Hm153]::RegSetDw($svcRel, 'Type', 16) }
L('K6 restore rc-path=' + $rr1 + ' rc-type=' + $rr2)
L('K6 now ImagePath [' + (C ([Hm153]::RegQuery($svcRel, 'ImagePath'))) + '] Type ' + (C ([Hm153]::RegQuery($svcRel, 'Type'))))
try { [Hm153]::StopOnly($SvcName) | Out-Null } catch { }
L('K6 stopped; wlansvc ' + (C ([Hm153]::SvcState($SvcName))))
L('probe153 end -- read K4| EXC lines first (code + module+offset), then whether MOD lines got past')
L('wmiclnt, then K5. 1063 in K1 is expected for the self test; a real run must show the callback line.')
