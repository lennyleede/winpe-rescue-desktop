# probe152 -- the door wlansvc dies at is a CALL, not a DLL. Is it the WMI client API (wmiclnt), and does
# a running WinMGmt let wlansvc through?
#
# Why this probe exists (probe150 rewrote the board):
#   probe150 (build\scratch\p150_run_raw.txt) + its host positive control
#   (build\scratch\p150b_host_control.txt) closed the file and api-set layers outright:
#     S1 loadable=82/82 first-fail=none   -- every module a healthy wlansvc host loads is loadable HERE.
#     S2 32/34 delay contracts resolve HERE, incl. ext-ms-win-wlan-grouppolicy -> wlgpclnt.dll, so the
#        probe114 lead ("it dies at wlgpclnt") is not a load failure.
#     The 2 dead names: ext-ms-win-networking-wlanstorage is dead on the HEALTHY HOST TOO (host pid also
#        gets err=126) -> noise; ext-ms-win-shell-embeddedmode answers embeddedmodesvcapi.dll on the host
#        but nothing on the host's wlansvc module list ever came from it -> not on the death path either.
#   What is left is the sequence itself. The PE's wlansvc host loads 36 modules and its LAST one is
#   wmiclnt.dll -- a *delay-load* of wlansvc.dll (P151 reverse census: wmiclnt is reached from wlansvc's
#   delay table, not from powrprof, which the PE never loads). On the healthy host wmiclnt is step #48 and
#   step #49 is wlgpclnt. So wlansvc calls into the legacy WMI client, and here that call is the last thing
#   it ever does before exiting 0x800C0006 (state=1, pid=0, ~125ms, no crash). WmiOpenBlock-style calls go
#   to the WMI service / \\.\WMI, and a bare ADK WinPE may simply have no WMI stack -- which is exactly the
#   kind of failure that produces no new DLL, no crash, and a fast self-exit.
#
# Instruments, cheapest first, and each one is run on BOTH machines with the same code:
#   V0 census: the WMI stack as files (winmgmt.exe, wbem\*.dll, Repository), the WinMGmt service record
#      read with native advapi (the PS registry provider has no -LiteralPath in the PE -- probe113 M1),
#      plus whether \\.\WMI can be opened at all.
#   V1 the faithful reproduction: enumerate wmiclnt.dll's exports from its PE header, then call
#      WmiOpenBlock("root\cimv2") and ("root\wmi") exactly the way wlansvc's delay helper would, and print
#      the return code. On the host this yields the positive reference; in the PE it either reproduces the
#      door or clears it.
#   V2 (PE only, RAM disk so it dies on reboot): start WinMGmt, re-run V1, then re-trace wlansvc with the
#      probe114 instrument. The judgement is loaded>36 and any module past wmiclnt -- that would mean WMI
#      was the wall.
#   V3 (PE only, -Readonly skips it): if WinMGmt cannot start, print why.
# Read-only unless -Readonly is NOT given; nothing touches the disc, and every handle is closed.
param([switch]$DryRun, [switch]$Readonly, [string]$Root = 'X:\Windows\System32')
function L([string]$s) { Write-Output ('P152 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = (C $Root)

$svcNames = @('WinMGmt', 'WmiApRpl', 'rpcss', 'DcomLaunch', 'wlansvc', 'wcmsvc', 'gpsvc', 'SENS', 'Ndisuio')
$wbemFiles = @('winmgmt.exe', 'wmic.exe', 'wbemprox.dll', 'wbemcomn.dll', 'wbemsvc.dll', 'fastprox.dll',
               'wmiclnt.dll', 'embeddedmodesvcapi.dll', 'wbemmgm.exe', 'repobj.exe', 'frconsol.exe',
               'wmi.prv', 'mofcl64.dll', 'CIMWin32.dll', 'wmiprvsd.dll', 'ncrobapi.dll')
$repoFiles = @('OBJECTS.DATA', 'INDEX.BTR', 'MAPPING1.MAP', 'MAPPING2.MAP', 'MAPPING3.MAP', 'OBJECTS.MAP',
               'FS')

$src = @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Pe152 {
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
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool QueryServiceConfigW(IntPtr sv, IntPtr cfg, uint size, out uint need);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr CreateFileW(string name, uint acc, uint share, IntPtr sa, uint disp,
      uint flags, IntPtr templ);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr GetProcAddress(IntPtr h, string name);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern uint GetModuleFileNameW(IntPtr h, StringBuilder buf, uint size);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004,
             SERVICE_QUERY_CONFIG = 0x0001;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
  const uint GENERIC_READ = 0x80000000, OPEN_EXISTING = 3;
  const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;

  delegate int WmiOpenBlockDel(string path, uint flags, out IntPtr handle);

  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : ("state" + st);
  }
  public static string Status(string svcName) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR=" + Marshal.GetLastWin32Error();
    IntPtr sv = OpenServiceW(scm, svcName, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP |
                            SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN err=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr buf = Marshal.AllocHGlobal(36); uint need = 0;
      string r;
      try {
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) r = "QSS_ERR=" + Marshal.GetLastWin32Error();
        else r = StateName(Marshal.ReadInt32(buf, 4)) + " pid=" + Marshal.ReadInt32(buf, 28);
      } finally { Marshal.FreeHGlobal(buf); }
      return r;
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  // Native config read: the PS registry provider has no -LiteralPath in the PE (probe113 M1), so the
  // service record is read through advapi and decoded by the documented SERVICE_CONFIGW offsets.
  public static string Config(string svcName) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR";
    IntPtr sv = OpenServiceW(scm, svcName, SERVICE_QUERY_CONFIG);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN err=" + Marshal.GetLastWin32Error(); }
    try {
      uint need = 0;
      QueryServiceConfigW(sv, IntPtr.Zero, 0, out need);
      if (need == 0) return "CFG_ERR=" + Marshal.GetLastWin32Error();
      IntPtr buf = Marshal.AllocHGlobal((int)need);
      try {
        if (!QueryServiceConfigW(sv, buf, need, out need)) return "CFG_ERR=" + Marshal.GetLastWin32Error();
        uint type = (uint)Marshal.ReadInt32(buf, 0);
        uint start = (uint)Marshal.ReadInt32(buf, 4);
        string path = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 16));
        string grp = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 24));
        string deps = Flat(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 40)));
        string obj = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, 48));
        path = Flat(path);
        if (path.Length > 150) path = path.Substring(0, 150);
        return "type=0x" + type.ToString("X") + " start=" + start + " grp=[" + grp + "] obj=[" + obj +
               "] deps=[" + deps + "] path=[" + path + "]";
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  static string Flat(string s) {
    if (s == null) return "";
    return s.Replace("\0", ";").Replace("\r", " ").Replace("\n", " ").Trim();
  }
  public static string StartAndWait(string svcName, int ms) {
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) return "SCM_ERR=" + Marshal.GetLastWin32Error();
    IntPtr sv = OpenServiceW(scm, svcName, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); return "NO_OPEN err=" + Marshal.GetLastWin32Error(); }
    try {
      Stopwatch sw = Stopwatch.StartNew();
      IntPtr buf = Marshal.AllocHGlobal(36); uint need = 0; int st = 1;
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      int serr = started ? 0 : Marshal.GetLastWin32Error();
      string first = "START=" + (started ? "OK" : ("ERR=" + serr));
      while (sw.ElapsedMilliseconds < ms) {
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) { Marshal.FreeHGlobal(buf); return first + " QSS_ERR"; }
        st = Marshal.ReadInt32(buf, 4);
        if (st == 4 || st == 1) break;
        Thread.Sleep(20);
      }
      int win32 = 0;
      if (QueryServiceStatusEx(sv, 0, buf, 36, out need)) win32 = Marshal.ReadInt32(buf, 12);
      Marshal.FreeHGlobal(buf);
      return first + " | t=" + sw.ElapsedMilliseconds + "ms " + StateName(st) +
             " win32hex=0x" + ((uint)win32).ToString("X8");
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  // \\.\WMI -- the device the legacy WMI client API talks to. If this cannot even be opened here, no
  // amount of wlansvc plumbing gets past the wmiclnt step.
  public static string WmiDevice() {
    IntPtr h = CreateFileW("\\\\.\\WMI", GENERIC_READ | 0x40000000, 0, IntPtr.Zero, OPEN_EXISTING, 0,
                           IntPtr.Zero);
    if (h == IntPtr.Zero || (long)h == -1L) return "\\\\.\\WMI open FAIL err=" + Marshal.GetLastWin32Error();
    CloseHandle(h);
    return "\\\\.\\WMI open OK";
  }
  // Export names straight out of the file's PE header -- no loader involvement.
  public static string[] Exports(string path) {
    List<string> res = new List<string>();
    byte[] b;
    try { b = File.ReadAllBytes(path); } catch (Exception e) { res.Add("READ_FAIL " + e.GetType().Name); return res.ToArray(); }
    int e_lfanew = BitConverter.ToInt32(b, 0x3C);
    if (BitConverter.ToInt16(b, e_lfanew) != 0x4550) { res.Add("NOT_PE"); return res.ToArray(); }
    int opt = e_lfanew + 24;
    bool is64 = (BitConverter.ToUInt16(b, opt) == 0x20B);
    int dd = opt + (is64 ? 112 : 96);
    uint edRva = BitConverter.ToUInt32(b, dd + 7 * 8);
    uint edSize = BitConverter.ToUInt32(b, dd + 7 * 8 + 4);
    if (edRva == 0) { res.Add("NO_EXPORT_DIR"); return res.ToArray(); }
    int numSec = BitConverter.ToUInt16(b, e_lfanew + 6);
    int sizeOpt = BitConverter.ToUInt16(b, e_lfanew + 20);
    int secOff = e_lfanew + 24 + sizeOpt;   // section table follows the optional header
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
    int ed = rvaToOff(edRva);
    if (ed < 0) { res.Add("ED_MAP_FAIL"); return res.ToArray(); }
    uint numNames = BitConverter.ToUInt32(b, ed + 24);
    uint addrOfNames = BitConverter.ToUInt32(b, ed + 32);
    int namesOff = rvaToOff(addrOfNames);
    if (namesOff < 0) { res.Add("NAMES_MAP_FAIL"); return res.ToArray(); }
    for (int i = 0; i < (int)numNames; i++) {
      int nm = rvaToOff(BitConverter.ToUInt32(b, namesOff + i * 4));
      if (nm < 0) continue;
      StringBuilder sb = new StringBuilder();
      while (nm < b.Length && b[nm] != 0) { sb.Append((char)b[nm]); nm++; }
      res.Add(sb.ToString());
    }
    return res.ToArray();
  }
  // The reproduction itself: load wmiclnt the way the delay helper does, grab WmiOpenBlock, call it.
  public static string WmiOpen(string wmiclntPath, string ns) {
    IntPtr h = LoadLibraryExW(wmiclntPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "LOAD_FAIL err=" + Marshal.GetLastWin32Error();
    try {
      StringBuilder mb = new StringBuilder(1024);
      if (GetModuleFileNameW(h, mb, (uint)mb.Capacity) != 0) wmiclntPath = mb.ToString();
      IntPtr p = GetProcAddress(h, "WmiOpenBlock");
      if (p == IntPtr.Zero) p = GetProcAddress(h, "WmiOpenBlockStub");
      if (p == IntPtr.Zero) return "NO_EXPORT WmiOpenBlock in " + wmiclntPath;
      WmiOpenBlockDel d = (WmiOpenBlockDel)Marshal.GetDelegateForFunctionPointer(p, typeof(WmiOpenBlockDel));
      IntPtr blk;
      int rc = d(ns, 0, out blk);
      string r = "rc=" + rc + " (0x" + ((uint)rc).ToString("X8") + ") handle=" + (long)blk +
                 " lasterr=" + Marshal.GetLastWin32Error();
      return r;
    } finally { FreeLibrary(h); }
  }
  // probe114's ordered trace, unchanged in behaviour: control-stop, start, poll at 1ms, first-seen order.
  public static string[] FullTrace(string svcName, int ms) {
    List<string> outp = new List<string>();
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) { outp.Add("SCM_ERR=" + Marshal.GetLastWin32Error()); return outp.ToArray(); }
    IntPtr sv = OpenServiceW(scm, svcName, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); outp.Add("OPEN_ERR=" + Marshal.GetLastWin32Error()); return outp.ToArray(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      try { ControlService(sv, 1, st); } catch { }
      Marshal.FreeHGlobal(st);
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      outp.Add("START=" + (started ? "OK" : ("ERR=" + Marshal.GetLastWin32Error())));
      Stopwatch sw = Stopwatch.StartNew();
      List<string> order = new List<string>();
      HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      IntPtr hProc = IntPtr.Zero; int pidSeen = 0;
      while (sw.ElapsedMilliseconds < ms) {
        uint need = 0;
        IntPtr buf = Marshal.AllocHGlobal(36);
        int state = 1, win32 = 0; int pid = 0;
        bool ok = QueryServiceStatusEx(sv, 0, buf, 36, out need);
        if (ok) { state = Marshal.ReadInt32(buf, 4); win32 = Marshal.ReadInt32(buf, 12); pid = Marshal.ReadInt32(buf, 28); }
        Marshal.FreeHGlobal(buf);
        if (!ok) { outp.Add("QSS_ERR=" + Marshal.GetLastWin32Error()); break; }
        if (pid > 0) {
          if (hProc == IntPtr.Zero || pidSeen != pid) {
            if (hProc != IntPtr.Zero) CloseHandle(hProc);
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
            pidSeen = pid;
          }
          if (hProc != IntPtr.Zero) {
            IntPtr[] mods = new IntPtr[2048];
            uint needed = 0;
            if (EnumProcessModulesEx(hProc, mods, (uint)(mods.Length * IntPtr.Size), out needed, 0x03)) {
              int count = (int)(needed / (uint)IntPtr.Size);
              if (count > mods.Length) count = mods.Length;
              StringBuilder sb = new StringBuilder(1024);
              for (int i = 0; i < count; i++) {
                sb.Length = 0;
                if (GetModuleFileNameExW(hProc, mods[i], sb, (uint)sb.Capacity) == 0) continue;
                string p = sb.ToString();
                int k = p.LastIndexOf('\\');
                string nm = (k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant();
                if (!seen.Contains(nm)) { seen.Add(nm); order.Add(nm); }
              }
            }
          }
        }
        if (state == 4) { outp.Add("REACHED RUNNING at t=" + sw.ElapsedMilliseconds + "ms"); break; }
        if (state == 1 && sw.ElapsedMilliseconds > 120) {
          outp.Add("STOPPED t=" + sw.ElapsedMilliseconds + "ms win32hex=0x" +
                   ((uint)win32).ToString("X8") + " loaded=" + order.Count);
          break;
        }
        Thread.Sleep(1);
      }
      if (hProc != IntPtr.Zero) CloseHandle(hProc);
      for (int i = 0; i < order.Count; i++) outp.Add("MOD " + (i + 1).ToString("000") + " " + order[i]);
      return outp.ToArray();
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
}
'@

if ($DryRun) {
  L('DRY probe152 root=' + $s32 + ' readonly=' + $Readonly)
  L('DRY V0 census ' + $wbemFiles.Count + ' wbem files + ' + $repoFiles.Count + ' Repository files + ' +
    $svcNames.Count + ' service records (native QueryServiceConfigW) + \\.\WMI open test')
  L('DRY V1 wmiclnt.dll export list (PE header parse) then WmiOpenBlock("root\cimv2") / ("root\wmi")')
  if ($Readonly) { L('DRY V2/V3 SKIPPED (-Readonly): no service starts, no wlansvc trace') }
  else { L('DRY V2 Start WinMGmt, repeat V1, then FullTrace wlansvc 3000ms; V3 only if the start fails') }
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1')
  exit 0
}
$ok = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $ok = $true }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)) }
L('probe152 begin cls=' + $ok + ' root=[' + $s32 + '] readonly=' + $Readonly)
if (-not $ok) { L('ABORT'); exit 1 }

# ---------- V0: is there a WMI stack here at all? ----------
foreach ($f in $wbemFiles) {
  $p = (C ([System.IO.Path]::Combine($s32, 'wbem', $f)))
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    L('V0 FILE ' + (C $f).PadRight(24) + ' yes ' + $i.Length + 'B')
  } else { L('V0 FILE ' + (C $f).PadRight(24) + ' NO') }
}
$repoDir = (C ([System.IO.Path]::Combine($s32, 'wbem', 'Repository')))
if (Test-Path -LiteralPath $repoDir) {
  $ri = @(Get-ChildItem -LiteralPath $repoDir -Force -EA SilentlyContinue)
  $sumB = 0
  foreach ($x in $ri) { if ($x.Length) { $sumB = $sumB + [int64]$x.Length } }
  $mb = [math]::Round(($sumB / 1MB), 2)
  L('V0 REPOSITORY dir yes entries=' + $ri.Count + ' totalMB=' + $mb)
  foreach ($f in $repoFiles) {
    $p = (C ([System.IO.Path]::Combine($repoDir, $f)))
    if (Test-Path -LiteralPath $p) { L('V0 REPO ' + (C $f).PadRight(16) + ' yes ' + (Get-Item -LiteralPath $p).Length + 'B') }
    else { L('V0 REPO ' + (C $f).PadRight(16) + ' NO') }
  }
} else { L('V0 REPOSITORY dir NO') }
$wbemAll = @(Get-ChildItem -LiteralPath (C ([System.IO.Path]::Combine($s32, 'wbem'))) -Force -EA SilentlyContinue)
L('V0 WBEM_DIR filecount=' + $wbemAll.Count)
foreach ($s in $svcNames) {
  $cfg = ''
  try { $cfg = [Pe152]::Config($s) } catch { $cfg = 'EXC ' + (C $_.Exception.Message) }
  $st = ''
  try { $st = [Pe152]::Status($s) } catch { $st = 'EXC ' + (C $_.Exception.Message) }
  L('V0 SVC ' + (C $s).PadRight(12) + ' ' + (C $st) + ' | ' + (C $cfg))
}
$dev = ''
try { $dev = [Pe152]::WmiDevice() } catch { $dev = 'EXC ' + (C $_.Exception.Message) }
L('V0 DEVICE ' + (C $dev))

# ---------- V1: the call wlansvc makes and then dies on ----------
$wmiclnt = (C ([System.IO.Path]::Combine($s32, 'wmiclnt.dll')))
$exp = @()
try { $exp = @([Pe152]::Exports($wmiclnt)) } catch { L('V1 EXPORTS EXC ' + (C $_.Exception.Message)) }
L('V1 EXPORTS wmiclnt.dll count=' + $exp.Count)
$wmi = @($exp | Where-Object { ('' + $_) -like 'Wmi*' })
L('V1 EXPORTS Wmi* =[' + ($wmi -join ',') + ']')
foreach ($ns in @('root\cimv2', 'root\wmi', 'root\subscription')) {
  $r = ''
  try { $r = [Pe152]::WmiOpen($wmiclnt, $ns) } catch { $r = 'EXC ' + (C $_.Exception.Message) }
  L('V1 OPEN ' + (C $ns).PadRight(18) + ' ' + (C $r))
}

# ---------- V2 / V3: does a running WMI service change wlansvc's fate? ----------
if ($Readonly) {
  L('V2 SKIPPED -Readonly (no service starts, no wlansvc trace)')
} else {
  $r = ''
  try { $r = [Pe152]::StartAndWait('WinMGmt', 20000) } catch { $r = 'EXC ' + (C $_.Exception.Message) }
  L('V2 START WinMGmt ' + (C $r))
  L('V2 CFG WinMGmt ' + (C ([Pe152]::Config('WinMGmt'))))
  foreach ($ns in @('root\cimv2', 'root\wmi')) {
    $o = ''
    try { $o = [Pe152]::WmiOpen($wmiclnt, $ns) } catch { $o = 'EXC ' + (C $_.Exception.Message) }
    L('V2 OPEN-AGAIN ' + (C $ns).PadRight(12) + ' ' + (C $o))
  }
  $tr = @()
  try { $tr = @([Pe152]::FullTrace('wlansvc', 4000)) } catch { L('V2 TRACE EXC ' + (C $_.Exception.Message)) }
  $hd = @($tr | Where-Object { ('' + $_) -notlike 'MOD *' })
  L('V2 TRACE wlansvc ' + (C ($hd -join ' ')))
  $i = 0
  foreach ($m in $tr) {
    if ('' + $m -like 'MOD *') { $i++; L('V2 ' + (C $m)) }
  }
  L('V2 TRACE modules=' + $i)
}
L('probe152 end -- judgement: on the host V1 OPEN must succeed (positive reference). In the PE, WmiOpenBlock')
L('failing here while wlansvc dies right after loading wmiclnt is the same door; then V2 (WinMGmt running)')
L('either lifts loaded above 36 -- WMI was the wall -- or leaves the 36/0x800C0006 signature untouched.')
