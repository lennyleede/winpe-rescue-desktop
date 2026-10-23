# probe155 -- call WlanSvcMain inside our own process and let it LIE TO US: stub the four service-control
# APIs so the DLL believes it registered with the SCM, then record every SetServiceStatus it makes, every
# module it loads, and every first-chance exception it raises. That is the only way left to see WHY the
# service exits itself with 0x800C0006, because every layer below it has now been falsified.
#
# What closed the other doors (all measured live on this disc, do not re-test):
#   probe150  files + api sets: S1 loadable=82/82 first-fail=none; S2 32/34 delay names resolve, incl.
#             ext-ms-win-wlan-grouppolicy -> wlgpclnt.dll. The 2 dead names are dead on the healthy host too.
#   probe152  WMI: WinMGmt already RUNNING with a 17MB OBJECTS.DATA; starting it changed nothing.
#   probe113/112  Parameters subtree and every record shape available in WinRE.
#   probe154  hosting model + the SCM's own limits, three results that matter:
#     - E2  every throwaway service we created gave OpenService=1060 (ERROR_SERVICE_DOES_NOT_EXIST) even
#           though the registry writes and read-back succeeded: the RUNNING services.exe built its DB at
#           boot and does not pick up NEW service keys written at runtime (it does honour changed values on
#           existing services -- E3/E4/E6/E7 all used our new ImagePath). So no new service can be hosted
#           in the live PE; only wlansvc's own record can be re-pointed, and offline baking is the only
#           place a new service can appear.
#     - E3  with cmd.exe as wlansvc's own-process body, StartService returned 1053 after 3175ms AND the
#           marker file was written: the SCM does create a process for wlansvc with its real record
#           (6 RequiredPrivileges, 3 dependencies, ServiceSidType=1). Nothing about the record blocks us.
#     - E4/E9  with powershell.exe as that body: 1053 after 469ms and NO marker, no child log after 12s --
#           a CLR process cannot be an SCM-launched service process in this PE. probe153's fake svchost is
#           therefore dead as designed, in this session and baked.
#     - E6/E7  the reference machine's own shape (Type=0x10 own-process svchost, which is what the healthy
#           host really uses for WlanSvc and Wcmsvc per build\scratch\p154_host_readonly.txt) reproduces the
#           identical failure: START_OK then STOPPED win32hex=0x800C0006 in 184ms/241ms. The hosting model
#           is NOT the difference. So the decision is inside the service DLL itself.
#   The exit code itself: 0x800C0006 has severity=1 facility=12 (FACILITY_INTERNET, i.e. the 12000-range
#   WinHTTP/WinINet family, code 6 = UNRECOGNIZED_SCHEME) -- and the literal bytes 06 00 0C 80 appear
#   NOWHERE in wlansvc.dll, wlanapi, wlanmsm, wlansec, wlgpclnt, wlansvcpal, wcnapi, wcncsvc, wifidisplay,
#   onex, eappprxy, dhcpcsvc, dnsapi, winhttp, wldp, msvcp_win, iphlpapi on this machine (host scan,
#   build\scratch output). So it is a value some callee RETURNED, not one wlansvc compares against; we need
#   to see which call, and the status transitions around it.
#
# Instruments (one process, session 1, where the CLR does work):
#   H0 enable the six privileges wlansvc's record asks the host to hold, and report which ones we got. In
#      WinPE the Administrator token normally carries them; if any is refused, a bail-out in the service is
#      our harness's fault, not the disc's, and we must know that before reading anything else.
#   H1 VEH (first-chance only, EXCEPTION_CONTINUE_SEARCH) + module watchdog -- the same plumbing that worked
#      in probe153's self test.
#   H2 LoadLibraryExW(wlansvc.dll, LOAD_WITH_ALTERED_SEARCH_PATH), export table = data directory #0, dump
#      the exports so the entry-point names are read from the image rather than assumed.
#   H3 hook RegisterServiceCtrlHandlerW / RegisterServiceCtrlHandlerExW / SetServiceStatus /
#      StartServiceCtrlDispatcherW (14-byte jmp-abs in the export, VirtualProtect + FlushInstructionCache)
#      and also OutputDebugStringW, because service DLLs narrate their own failures there.
#      Hooking is per-process: nothing on the disc and no other process is affected. advapi32 exports these
#      as thunks into sechost.dll, so each name is resolved in BOTH modules and the addresses are printed;
#      two names landing on one address is reported and only hooked once.
#   H4 call SvchostPushServiceGlobals (wlansvc exports it -- probe153's dump) with a zeroed blob so a
#      dereference reads NULL instead of faulting on garbage, and log that.
#   H5 call WlanSvcMain(1, ["wlansvc"]) on a worker thread exactly the way svchost does, then report the
#      RETURN line, the ordered SetServiceStatus transitions (state/win32exit/specific) and the exceptions.
#   H6 the same call with -NoHooks, as the reverse fixture: if the hooked run and the unhooked run behave
#      identically, the hooks are not what is carrying the service forward and the trace is trustworthy.
#
# FIRST LIVE RUN of exactly this harness on this disc (2026-10-12, wifi_patch 12:10:51, X: RAM disk, before
# the exception-parameter decode existed): H0 all six privileges came back "on"; H1 VEH OK; H2 the image loads
# and exports 7 names incl. WlanSvcMain; H3 all nine patches installed; H4 SvchostPushServiceGlobals accepted
# the blob; H5 WlanSvcMain ran for 110ms and reported, in this order:
#   REG-EX [w]  ->  START_PENDING (waithint 4000)  ->  EXC 0xE0000001  ->  STOP_PENDING (waithint 60000)
#   ->  EXC 0xE06D7363 (MSVC C++ EH)  ->  STOPPED win32=0x800C0006
# and H7's WlanOpenHandle answered hr=0x00000426 (ERROR_SERVICE_NOT_ACTIVE), i.e. nothing came up. The 38
# modules match probe99's SCM-launched trace (tail: msxml6, wmiclnt, wlgpclnt), so in-proc reproduces the real
# failure exactly. Two conclusions: the decision is the DLL's own, 4ms after it reports START_PENDING, and it
# is expressed as a thrown C++ object -- which is why no file, privilege, record shape or hosting model we
# changed ever moved it. The decode added below turns that exception into a named throw site.
#
# SECOND LIVE RUN (raw5) read that record: 0xE06D7363 with p1's _ThrowInfo.pType = wlansvc.dll+0x25ADF0 and
# p2 (the thrown object) = wlansvc.dll+0x250238, i.e. BOTH the type descriptor and the object are static data
# inside wlansvc.dll -- a C++ exception of a type defined by the service itself, thrown by the service itself.
# What that run could not give us was the CALL SITE: bt= was empty everywhere, because RtlCaptureStackBackTrace
# walks the stack of its caller and that caller is the CLR delegate-transition stub, which has no unwind chain
# to continue through (n=0/1 measured on the host too). Table unwinding over the CONTEXT from the same
# EXCEPTION_POINTERS was tried and is fatal (see Scan() below), so the throw's neighbourhood comes from a bounded
# executable-address scan of the exception's own stack, and the offsets it names are turned into function names on the build machine using the CodeView GUID+age that
# PdbInfo prints -- IMAGE_DEBUG_TYPE_CODEVIEW is type 2, not 1, which is why the first version said
# "no-codeview-entry(count=4)".
param([switch]$DryRun, [switch]$NoHooks, [switch]$NoGlobals, [switch]$ListExports, [switch]$HooksOnly,
      [switch]$SelfTestOnly,
      [string]$Root = 'X:\Windows\System32',
      [string]$Out = 'X:\p155_out.txt', [string]$Dll = '', [string]$Entry = 'WlanSvcMain',
      [string]$SvcName = 'wlansvc', [int]$Seconds = 22)
function L([string]$s) { Write-Output ('P155 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = (C $Root)
if (-not $Dll) { $Dll = (C ([System.IO.Path]::Combine($s32, 'wlansvc.dll'))) }

$src = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Hk155 {
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  // ANSI CharSet on purpose: there is no GetProcAddressW and Unicode marshalling hands the ANSI function a
  // UTF-16 name, which reports ERROR_PROC_NOT_FOUND for exports that are plainly there (probe153 lesson).
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr GetProcAddress(IntPtr h, string name);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool VirtualProtect(IntPtr addr, uint size, uint newProt, out uint old);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool FlushInstructionCache(IntPtr h, IntPtr bAddr, uint size);
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern int VirtualQuery(IntPtr addr, out MEMORY_BASIC_INFORMATION info, int len);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern uint GetModuleFileNameW(IntPtr h, StringBuilder buf, uint size);
  [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetCurrentThreadId();
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr AddVectoredExceptionHandler(uint first, VEH cb);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
  static extern IntPtr LoadLibraryA(string name);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool LookupPrivilegeValueW(string sys, string name, out LUID luid);
  // NewState is passed as IntPtr and built with Marshal* so this needs no /unsafe: Add-Type in these probes
  // is compiled without unsafe enabled, and a TOKEN_PRIVILEGES* in the source is a fatal CS0227.
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, IntPtr newStates, uint len,
      IntPtr prevState, IntPtr prevLen);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr GetModuleHandleW(string name);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int FormatMessageW(uint flags, IntPtr src, uint code, uint lang, StringBuilder buf,
      int size, IntPtr args);
  // The native call chain behind a transition. Module+offset is all this can name (there are no symbols in
  // the PE), but the offset is stable, so the frames travel back to the build machine where the matching
  // .pdb is fetched from the Microsoft symbol server by the GUID+age that PdbInfo() prints below.
  [DllImport("ntdll.dll")]
  static extern ushort RtlCaptureStackBackTrace(uint framesToSkip, uint framesToCapture,
      IntPtr[] backtrace, IntPtr[] backtraceHash);
  // The stack capture above is not usable from inside our handler: it walks the stack of ITS caller, and that
  // caller is the CLR's delegate-transitions stub, which has no native unwind chain to continue through, so it
  // answers with 0 frames (bt=n0: measured on the host and on the disc). Table-based unwinding is worse:
  // ntdll!RtlVirtualUnwind raised a HARDWARE access violation on its very first step even given a genuine
  // exception context, a verified image base (allocation base == module handle base) and the correct Rip@248,
  // and in .NET 4+ an AV is a corrupted-state exception that no catch can swallow -- a probe that calls it dies
  // with the service it is studying (host control: build\scratch\t_p155_unwind_host.ps1). Scan() below is what
  // we use instead: it reads the exception's own Rsp upward through the committed region and names every qword
  // that is an executable image address. Host control build\scratch\t_p155_stackscan_host.ps1 resolves a real
  // raise site and the CLR stub above it with exactly this code.
  [DllImport("kernel32.dll")] static extern void RaiseException(uint code, uint flags, uint np, IntPtr args);

  const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;
  const uint MEM_IMAGE = 0x01000000;
  const uint MEM_COMMIT = 0x00001000;      // MEMORY_BASIC_INFORMATION.State: pages that can actually be read
  const uint PAGE_EXECUTE_READWRITE = 0x40;
  const uint TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_QUERY = 0x0008;
  const uint SE_PRIVILEGE_ENABLED = 0x00000002;

  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
    public uint align1; public UIntPtr RegionSize; public uint State; public uint Protect;
    public uint Type; public uint align2;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID { public uint LowPart; public int HighPart; }

  public delegate uint VEH(IntPtr pointers);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr DRegisterW(string serviceName, IntPtr handler);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate IntPtr DRegisterEx(string serviceName, IntPtr handler, IntPtr context);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate bool DSetStatus(IntPtr handle, IntPtr status);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate bool DDispatcher(IntPtr table);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate void DDebugString(IntPtr text);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate void NativeSvcMain(uint argc, IntPtr argv);
  [UnmanagedFunctionPointer(CallingConvention.StdCall)]
  public delegate void NativePushGlobals(IntPtr globals);
  // DWORD WINAPI WlanOpenHandle(DWORD, PVOID, PDWORD, PHANDLE) -- IntPtr args so nothing needs out-marshalling
  [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
  public delegate uint DWlanOpen(uint ver, IntPtr reserved, IntPtr pNeg, IntPtr pHandle);

  static readonly object g_lock = new object();
  static List<string> g_exc = new List<string>();
  static Dictionary<string, int> g_excSeen = new Dictionary<string, int>();
  static List<string> g_status = new List<string>();
  static List<string> g_dbg = new List<string>();
  static List<string> g_snaps = new List<string>();          // every module ever seen, in report order
  static HashSet<string> g_snap = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  static StreamWriter g_log;
  static Stopwatch g_sw = new Stopwatch();
  static Dictionary<IntPtr, string> g_hookedAt = new Dictionary<IntPtr, string>();
  static IntPtr g_module; static NativeSvcMain g_main; static IntPtr g_mainAddr;
  static IntPtr g_argv; static IntPtr g_pName;
  static Thread g_thread; static bool g_returned; static int g_mainT0; static int g_retMs;
  static volatile bool g_poking = false;
  static string g_lastUw = "(no-record)";      // the unwind string of the most recently logged exception

  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : st == 5 ? "CONTINUE_PENDING" : st == 6 ? "PAUSE_PENDING" :
           st == 7 ? "PAUSED" : ("state" + st);
  }

  // ---------- logging ----------
  public static void OpenLog(string path) {
    g_sw = Stopwatch.StartNew();
    try {
      FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
      g_log = new StreamWriter(fs); g_log.AutoFlush = true;
    } catch { g_log = null; }
  }
  public static void Log(string line) {
    lock (g_lock) {
      if (g_log != null) { try { g_log.WriteLine("t" + g_sw.ElapsedMilliseconds + "ms " + line); } catch { } }
    }
    try { Console.Out.WriteLine("P155C " + line); Console.Out.Flush(); } catch { }
  }

  // ---------- modules / exceptions ----------
  static string ModuleOf(IntPtr addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) return "?";
    if (mbi.Type != MEM_IMAGE) return "not-image(0x" + mbi.Type.ToString("X") + ")";
    StringBuilder sb = new StringBuilder(1024);
    if (GetModuleFileNameExW(GetCurrentProcess(), mbi.AllocationBase, sb, (uint)sb.Capacity) == 0)
      return "base0x" + ((long)mbi.AllocationBase).ToString("X");
    string p = sb.ToString(); int k = p.LastIndexOf('\\');
    return (k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant() + "+0x" +
           ((long)addr - (long)mbi.AllocationBase).ToString("X");
  }
  // A parameter is either an address inside some code (then module+offset names the site) or a pointer into a
  // static block. 0xE06D7363 is MSVC's C++ EH code: p0 is the magic 0x19930522, p1 a _ThrowInfo, p2 the thrown
  // object; _ThrowInfo.pType(+24)->name(+8) is the thrown type's literal name. One decode therefore tells us
  // WHICH module threw and WHAT it threw -- which is what the 4ms START_PENDING->STOP_PENDING window hides.
  //
  // This runs INSIDE a vectored exception handler, where a second fault is fatal to the process (the first
  // version of Desc did exactly that on the live disc: it followed p2, a heap/stack pointer, read garbage at
  // +24 and died). So every hop is gated on RegionEnd, which only answers for committed MEM_IMAGE pages and
  // gives the region's last byte -- memory outside an image is described, never dereferenced.
  static long RegionEnd(IntPtr v) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(v, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) return 0;
    if (mbi.Type != MEM_IMAGE) return 0;
    return (long)mbi.BaseAddress + (long)mbi.RegionSize.ToUInt64();
  }
  // Same bound, but for any COMMITTED page (image, private heap, mapped file). A thrown C++ object and often
  // its _ThrowInfo live outside images, and reading committed memory cannot fault -- what killed the previous
  // live run was following a pointer into a page that was not committed at all, which this rejects.
  // Two committed protections still fault on read: PAGE_NOACCESS (0x00) and a GUARD_PAGE (0x100), and a guard
  // page is exactly what a stack probe hits, so both are refused here. A second fault inside the VEH is fatal.
  static long CommittedEnd(IntPtr v) {
    MEMORY_BASIC_INFORMATION mbi;
    if (v == IntPtr.Zero) return 0;
    if (VirtualQuery(v, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    uint p = mbi.Protect & 0xFF;
    if (p == 0x00) return 0;                                    // PAGE_NOACCESS: committed but not readable
    if ((mbi.Protect & 0x100u) != 0) return 0;                  // guard page: reading it raises
    return (long)mbi.BaseAddress + (long)mbi.RegionSize.ToUInt64();
  }
  static string ImageAscii(IntPtr nm, int max) {
    long end = CommittedEnd(nm);
    if (end == 0 || (long)nm >= end) return "";
    int cap = (int)System.Math.Min((long)max, end - (long)nm);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < cap; i++) {
      byte b = Marshal.ReadByte(nm, i);
      if (b == 0) return sb.ToString();
      if (b < 0x20 || b > 0x7e) return "";      // not a printable name -> not our type descriptor
      sb.Append((char)b);
    }
    return "";
  }
  // Raw bytes of a committed structure. The type name decode can legitimately come back empty (the descriptor
  // may not be where this compiler's build puts it, or the throw carries no type), and then the only way to
  // settle it without another disc round trip is to have the bytes in the log.
  static string Hex(IntPtr v, int n) {
    long end = CommittedEnd(v);
    if (end == 0 || (long)v >= end) return "no-commit";
    int cap = (int)System.Math.Min((long)n, end - (long)v);
    StringBuilder sb = new StringBuilder(cap * 2);
    for (int i = 0; i < cap; i++) sb.Append(Marshal.ReadByte(v, i).ToString("x2"));
    return sb.ToString();
  }
  static string Desc(IntPtr v) {
    if (v == IntPtr.Zero) return "0";
    long lval = v.ToInt64();
    if (lval >= 0 && lval < 0x10000) return "0x" + lval.ToString("X");
    string m = ModuleOf(v);
    if (lval < 0) return m + "-neg0x" + lval.ToString("X16");   // a sign-extended HRESULT/NTSTATUS parameter is
                                                                 // the read we most want, so print its value
    if (lval == 0x19930522L) return m + "=EH-MAGIC";
    long end = CommittedEnd(v);
    if (end == 0 || end - (long)v < 32) return m;      // unreadable or too short to be the structure
    IntPtr pType = Marshal.ReadIntPtr(v, 24);
    long te = CommittedEnd(pType);
    if (pType == IntPtr.Zero || te == 0 || te - (long)pType < 16)
      return m + "(struct " + Hex(v, 32) + ")";
    IntPtr nm = Marshal.ReadIntPtr(pType, 8);
    string s = ImageAscii(nm, 140);
    if (s.Length == 0)
      return m + "(struct " + Hex(v, 32) + " pType=" + ModuleOf(pType) + " " + Hex(pType, 24) + ")";
    uint attr = (uint)Marshal.ReadInt32(v, 0);
    return m + "(throw attr=0x" + attr.ToString("X") + " type=[" + s + "])";
  }
  // DescSelfTest: the shapes a C++ EH hands us, exercised WITHOUT raising anything. D3 is the exact input
  // that killed the second live run -- private heap memory full of garbage -- and the answer must be a
  // description, not a fault. D5 walks the real VEH callback with a synthesised x64 EXCEPTION_RECORD whose
  // parameters are (magic, heap-garbage, unmapped-looking heap pointer), which is what 0xE06D7363 carries.
  public static string DescSelfTest() {
    List<string> r = new List<string>();
    r.Add("D0 null=[" + Desc(IntPtr.Zero) + "]");
    r.Add("D1 0x1F=[" + Desc(new IntPtr(0x1F)) + "]");
    r.Add("D2 magic=[" + Desc(new IntPtr(0x19930522L)) + "]");
    IntPtr hp = Marshal.AllocHGlobal(96);
    IntPtr hp2 = Marshal.AllocHGlobal(96);
    for (int i = 0; i < 96; i++) { Marshal.WriteByte(hp, i, 0xCC); Marshal.WriteByte(hp2, i, 0x41); }
    r.Add("D3 heap-garbage=[" + Desc(hp) + "]");
    r.Add("D4 heap-chained=[" + Desc(hp2) + "]");
    IntPtr img = GetModuleHandleW("kernel32.dll");
    r.Add("D5 image-base=[" + Desc(img) + "]");
    // D6: drive VehCbk itself, with the parameters written the way the kernel writes them -- EXCEPTION_RECORD
    // holds ULONG_PTR ExceptionInformation[15] INLINE at +32, so the fixture does too. (The first version of
    // this decoder treated +32 as a pointer to an array; that is what killed the live run.) Parameters here
    // are the C++ EH shape: magic, a _ThrowInfo-looking block, a thrown-object-looking block, and a wild
    // stack-ish address as the fourth, because a real record can carry one.
    IntPtr rec = Marshal.AllocHGlobal(160);
    for (int i = 0; i < 160; i++) Marshal.WriteByte(rec, i, 0);
    Marshal.WriteInt32(rec, 0, unchecked((int)0xE06D7363));
    Marshal.WriteInt64(rec, 16, img.ToInt64() + 0x1000);   // a plausible throw site inside an image
    Marshal.WriteInt32(rec, 24, 4);
    Marshal.WriteInt64(rec, 32, 0x19930522L);
    Marshal.WriteInt64(rec, 40, hp.ToInt64());
    Marshal.WriteInt64(rec, 48, hp2.ToInt64());
    Marshal.WriteInt64(rec, 56, unchecked((long)0x00007FFFFFFFFFFFFFF0L));   // not committed on any machine
    IntPtr ptrs = Marshal.AllocHGlobal(16);
    Marshal.WriteInt64(ptrs, 0, rec.ToInt64());
    Marshal.WriteInt64(ptrs, 8, 0);
    int before = g_exc.Count;
    uint ret = VehCbk(ptrs);
    r.Add("D6 veh ret=" + ret + " new=" + (g_exc.Count - before) +
          " hdr=[" + (g_exc.Count > before ? g_exc[before] : "") + "]" +
          " dec=[" + (g_exc.Count > before + 1 ? g_exc[before + 1] : "") + "]");
    // D7: the same record with a bogus parameter count -- the clamp must hold and still not fault.
    Marshal.WriteInt32(rec, 24, 0x0000FFFF);
    before = g_exc.Count;
    ret = VehCbk(ptrs);
    r.Add("D7 np-abuse ret=" + ret + " new=" + (g_exc.Count - before));
    r.Add("SELFTEST survived=true");
    // The synthetic lines must not linger: g_excSeen is keyed by code@module+offset, and a leftover fake
    // entry with the same key as the real 0xE06D7363 would suppress the one record we came here for.
    lock (g_lock) { g_exc.Clear(); g_excSeen.Clear(); }
    r.Add("D8 exc-list reset (len=" + g_exc.Count + ")");
    Marshal.FreeHGlobal(rec); Marshal.FreeHGlobal(ptrs);
    Marshal.FreeHGlobal(hp); Marshal.FreeHGlobal(hp2);
    return string.Join(" | ", r.ToArray());
  }
  // Backtrace: the caller chain as module+offset. Kept only as a diagnostic -- it reports the count, because
  // measured on both the host and the disc the CLR stub boundary truncates it to 0/1 frames.
  public static string Backtrace(int skip, int max) {
    try {
      IntPtr[] bt = new IntPtr[40];
      ushort n = RtlCaptureStackBackTrace((uint)skip, (uint)(max > 38 ? 38 : max), bt, null);
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < n; i++) {
        if (i > 0) sb.Append(',');
        sb.Append(ModuleOf(bt[i]));
      }
      return "n" + n + ":" + sb.ToString();
    } catch { return "bt-fail"; }
  }
  // Scan: the throw's neighbourhood, read out of the exception's own stack. The x64 CONTEXT (winnt.h,
  // DECLSPEC_ALIGN(16), 1232 bytes) has the six home parameters at 0..47, ContextFlags@48, MxCsr@52, segment
  // words@56..67, EFlags@68, Dr0..Dr7@72..119, then Rax@120 Rcx@128 Rdx@136 Rbx@144 Rsp@152 Rbp@160 Rsi@168
  // Rdi@176 R8@184 R9@192 R10@200 R11@208 R12@216 R13@224 R14@232 R15@240 and Rip@248 -- Rip is NOT at 192
  // (192 is R9; that mistake is what made the first walker name a non-image pc). From Rsp upward every qword
  // that VirtualQuery describes as an EXECUTABLE image page is reported as <bytes from Rsp>:module+offset, so the
  // raiser's own frame appears at a small distance and the wlansvc.dll call sites within a few hundred bytes.
  // This is a scan, not an unwind: stale pointers can also match, which is exactly why the distance is printed
  // (a real chain grows monotonically and plausibly). Nothing outside the committed, non-guard region that
  // contains Rsp is ever dereferenced, so unlike RtlVirtualUnwind this cannot fault inside the handler.
  const int CTX_RIP = 248;
  const int CTX_RSP = 152;
  static string CodeModuleOf(IntPtr a) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(a, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) return null;
    if (mbi.Type != MEM_IMAGE) return null;
    uint p = mbi.Protect & 0xFF;
    if ((p & 0x10) == 0 && (p & 0x20) == 0 && (p & 0x40) == 0) return null;      // not executable
    StringBuilder sb = new StringBuilder(1024);
    if (GetModuleFileNameExW(GetCurrentProcess(), mbi.AllocationBase, sb, (uint)sb.Capacity) == 0) return null;
    string n = sb.ToString(); int k = n.LastIndexOf('\\');
    return (k >= 0 ? n.Substring(k + 1) : n).ToLowerInvariant() + "+0x" +
           ((long)a - (long)mbi.AllocationBase).ToString("X");
  }
  public static string Scan(IntPtr ctx, int slots, int show) {
    if (ctx == IntPtr.Zero) return "no-ctx";
    try {
      long rip = Marshal.ReadInt64(ctx, CTX_RIP);
      long rsp = Marshal.ReadInt64(ctx, CTX_RSP);
      long end = CommittedEnd(new IntPtr(rsp));
      StringBuilder sb = new StringBuilder();
      sb.Append("rip=" + CodeModuleOf(new IntPtr(rip)) + " rsp=0x" + rsp.ToString("X") + " hits=");
      int n = 0, hits = 0;
      for (long a = rsp; a + 8 <= end && n < slots; a += 8, n++) {
        long v = Marshal.ReadInt64(new IntPtr(a));
        if (v < 0x10000) continue;
        string m = CodeModuleOf(new IntPtr(v));
        if (m == null) continue;
        hits++;
        if (hits <= show) sb.Append("+" + (n * 8) + ":" + m + ",");
      }
      return sb.ToString() + " scanned=" + (n * 8) + "B";
    } catch (Exception ex) { return "sc-fail " + ex.GetType().Name; }
  }
  // ScanStrings: the same walk, reporting the qwords that point at readable TEXT instead of at code. The
  // arguments a service hands an XML parser live on its own stack, so this is the cheapest way to learn WHICH
  // document wlansvc was loading when it threw -- the msxml6 frames say what kind of work, only the strings say
  // which input. Reads stay inside the committed region that contains the pointer, so a stale qword cannot
  // fault, and only strings with a marker (path separator, dot-extension, scheme, registry hive) are reported.
  public static string ScanStrings(IntPtr ctx, int slots, int show) {
    if (ctx == IntPtr.Zero) return "no-ctx";
    try {
      long rsp = Marshal.ReadInt64(ctx, CTX_RSP);
      long end = CommittedEnd(new IntPtr(rsp));
      StringBuilder sb = new StringBuilder();
      int n = 0, hits = 0;
      for (long a = rsp; a + 8 <= end && n < slots; a += 8, n++) {
        string s = TextAt(Marshal.ReadInt64(new IntPtr(a)));
        if (s == null) continue;
        hits++;
        if (hits <= show) sb.Append("+" + (n * 8) + ":[" + s + "]");
      }
      return "hits=" + hits + " " + sb.ToString();
    } catch (Exception ex) { return "ss-fail " + ex.GetType().Name; }
  }
  static string TextAt(long v) {
    if (v < 0x10000) return null;
    IntPtr p = new IntPtr(v);
    long end = CommittedEnd(p);
    if (end == 0 || (long)p >= end) return null;
    int cap = (int)System.Math.Min(120L, end - (long)p);
    if (cap < 6) return null;
    byte b1 = Marshal.ReadByte(p, 1);
    StringBuilder a = new StringBuilder();
    for (int i = 0; i < cap; i++) {
      byte b = Marshal.ReadByte(p, i);
      if (b == 0 || b < 0x20 || b > 0x7e) break;
      a.Append((char)b);
    }
    StringBuilder u = new StringBuilder();
    for (int i = 0; i + 1 < cap; i += 2) {
      byte lo = Marshal.ReadByte(p, i), hi = Marshal.ReadByte(p, i + 1);
      if (lo == 0 && hi == 0) break;
      if (hi != 0 || lo < 0x20 || lo > 0x7e) { u.Length = 0; break; }
      u.Append((char)lo);
    }
    string s = (b1 == 0 && u.Length >= 6) ? u.ToString() : a.ToString();
    if (s.Length < 6) return null;
    string low = s.ToLowerInvariant();
    if (!(low.Contains(".xml") || low.Contains("\\") || low.Contains(".dll") || low.Contains("http") ||
          low.Contains("software") || low.Contains(".ini") || low.Contains("system32"))) return null;
    if (s.Length > 96) s = s.Substring(0, 96);
    return s;
  }
  // ScanSelfTest: prove the scanner on a genuine exception before trusting it with wlansvc's throw site.
  // RaiseException with a private code (0x40000001, nothing to do with the service) is seen by our own handler
  // first, on an ordinary stack, so the line it logs must name the raiser AND at least one frame above it. The
  // record is then dropped so it cannot crowd the real ones out of the report.
  public static string ScanSelfTest() {
    try {
      g_lastUw = "(no-record)";
      try { RaiseException(0x40000001u, 0u, 0, IntPtr.Zero); } catch { }
      string s = g_lastUw;
      lock (g_lock) { g_exc.Clear(); g_excSeen.Clear(); }
      bool ok = s.Contains("hits=") && s.Split(',').Length >= 3 && s.IndexOf("sc-fail") < 0;
      return "SC ok=" + (ok ? 1 : 0) + " [" + s + "]";
    } catch (Exception ex) { return "SC fail " + ex.GetType().Name + ": " + ex.Message; }
  }
  // PdbInfo: the CodeView record of the loaded service image, i.e. the exact .pdb this binary was built with.
  // Debug directory = data directory #6; each IMAGE_DEBUG_DIRECTORY is 28 bytes with Type@12 and the RVA of the
  // payload at AddressOfRawData@20. CodeView is type 2 (type 1 is COFF -- the first version of this filtered on
  // 1 and therefore answered "no-codeview-entry(count=4)" for an image that plainly has one), and its payload is
  // 'RSDS' + GUID(16) + Age(4) + path. The GUID+age is what the Microsoft symbol server keys on, so the offsets
  // printed by Scan() can be turned into function names on the build machine.
  public static string PdbInfo(IntPtr baseAddr) {
    try {
      if (baseAddr == IntPtr.Zero) return "no-image";
      int peOff = Marshal.ReadInt32(baseAddr, 0x3C);
      uint magic = (uint)Marshal.ReadInt16(baseAddr, peOff + 24);
      int ddOff = peOff + 24 + (magic == 0x20B ? 112 : 96);
      int dbgRva = Marshal.ReadInt32(baseAddr, ddOff + 6 * 8);
      int dbgSize = Marshal.ReadInt32(baseAddr, ddOff + 6 * 8 + 4);
      if (dbgRva == 0 || dbgSize == 0) return "no-debug-directory";
      int count = dbgSize / 28;
      if (count < 1 || count > 16) count = 1;
      StringBuilder types = new StringBuilder();
      for (int i = 0; i < count; i++) {
        int e = dbgRva + i * 28;
        uint type = (uint)Marshal.ReadInt32(baseAddr, e + 12);
        int raw = Marshal.ReadInt32(baseAddr, e + 20);
        int sz = Marshal.ReadInt32(baseAddr, e + 16);
        if (types.Length > 0) types.Append(',');
        types.Append(type + "/raw0x" + raw.ToString("X") + "/sz" + sz);
        if (type != 2 || raw == 0) continue;                 // 2 = IMAGE_DEBUG_TYPE_CODEVIEW
        if (sz < 24) return "codeview-too-short-" + sz;
        string sig = "" + (char)Marshal.ReadByte(baseAddr, raw) + (char)Marshal.ReadByte(baseAddr, raw + 1) +
                     (char)Marshal.ReadByte(baseAddr, raw + 2) + (char)Marshal.ReadByte(baseAddr, raw + 3);
        if (sig != "RSDS") return "codeview-sig=" + sig;
        uint d1 = (uint)Marshal.ReadInt32(baseAddr, raw + 4);
        ushort d2 = (ushort)Marshal.ReadInt16(baseAddr, raw + 8);
        ushort d3 = (ushort)Marshal.ReadInt16(baseAddr, raw + 10);
        StringBuilder d4 = new StringBuilder();
        for (int k = 0; k < 8; k++) d4.Append(Marshal.ReadByte(baseAddr, raw + 12 + k).ToString("X2"));
        uint age = (uint)Marshal.ReadInt32(baseAddr, raw + 20);
        string path = Marshal.PtrToStringAnsi(new IntPtr((long)baseAddr + raw + 24));
        if (path == null) path = "";
        int slash = path.LastIndexOf('\\');
        string leaf = slash >= 0 ? path.Substring(slash + 1) : path;
        return "PDB " + leaf + " guid=" + d1.ToString("X8") + d2.ToString("X4") + d3.ToString("X4") +
               d4.ToString() + " age=" + age.ToString("X") + " path=[" + path + "]";
      }
      return "no-codeview-entry(count=" + count + " types=" + types + ")";
    } catch (Exception ex) { return "pdb-fail " + ex.GetType().Name; }
  }
  static uint VehCbk(IntPtr pointers) {
    try {
      IntPtr rec = Marshal.ReadIntPtr(pointers, 0);
      uint code = (uint)Marshal.ReadInt32(rec, 0);
      IntPtr addr = Marshal.ReadIntPtr(rec, 16);
      // x64 EXCEPTION_RECORD (this probe proved +16 is ExceptionAddress, so no 8-byte ExceptionNumber):
      // code@0 flags@4 ExceptionRecord@8 ExceptionAddress@16 NumberParameters@24 pad@28
      // Information@32 -- and Information is ULONG_PTR ExceptionInformation[15] INLINE, not a pointer. The
      // first version read *(rec+32) as if it were an array address and dereferenced that, which is a
      // parameter value: on the live disc it pointed at the guard-supervised stack, and the VEH died there.
      uint np = (uint)Marshal.ReadInt32(rec, 24);
      if (np > 8) np = 8;
      string key = "0x" + code.ToString("X8") + "@" + ModuleOf(addr);
      int n;
      lock (g_lock) {
        g_excSeen.TryGetValue(key, out n); g_excSeen[key] = n + 1;
        if (n == 0) {
          // Two lines, in this order: the record header is logged and flushed BEFORE anything is dereferenced.
          // If the parameter decode ever faults, the header line is already on the log and the run still tells
          // us which exception came from which module -- which is more than the previous build managed to do.
          string line = "EXC " + key + " n=" + g_exc.Count + " tid=" + GetCurrentThreadId() + " np=" + np;
          g_exc.Add(line); Log(line);
        }
      }
      if (n != 0) return 0;                      // only the first record of a kind is decoded
      StringBuilder pd = new StringBuilder();
      for (uint i = 0; i < np; i++) {
        string d;
        try { d = Desc(Marshal.ReadIntPtr(rec, 32 + (int)(i * 8))); }
        catch { d = "desc-fail"; }               // a managed catch cannot undo a hardware fault, but it can
        pd.Append(" p").Append(i.ToString()).Append('=').Append(d);   // keep the loop from giving up early
      }
      lock (g_lock) {
        string sc = Scan(Marshal.ReadIntPtr(pointers, 8), 6000, 40);
        string st = ScanStrings(Marshal.ReadIntPtr(pointers, 8), 3000, 8);
        g_lastUw = key + " " + sc;
        string line = "EXCD " + key + " n=" + g_exc.Count + pd.ToString() +
                      " sc=" + sc + " ss=" + st + " bt=" + Backtrace(2, 14);
        g_exc.Add(line); Log(line);
      }
    } catch { }
    return 0;   // EXCEPTION_CONTINUE_SEARCH
  }
  public static string InstallVeh() {
    VEH cb = new VEH(VehCbk);
    IntPtr h = AddVectoredExceptionHandler(1, cb);
    GC.KeepAlive(cb);   // the delegate must outlive the native handler
    return h == IntPtr.Zero ? ("FAIL err=" + Marshal.GetLastWin32Error()) : "OK";
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
  public static int ExcCount() { lock (g_lock) { return g_exc.Count; } }
  public static string ExcAll(int max) {
    lock (g_lock) {
      int n = g_exc.Count; if (n > max) n = max;
      return string.Join(" || ", g_exc.GetRange(0, n).ToArray());
    }
  }
  public static string StatusAll(int max) {
    lock (g_lock) {
      int n = g_status.Count; if (n > max) n = max;
      return string.Join(" || ", g_status.GetRange(0, n).ToArray());
    }
  }
  public static string DbgAll(int max) {
    lock (g_lock) {
      int n = g_dbg.Count; if (n > max) n = max;
      return string.Join(" || ", g_dbg.GetRange(0, n).ToArray());
    }
  }
  // Ordered module census: wlansvc's trace in probe99/114 was read as an ORDER ("the last new module before
  // the bail-out names the callee"), so this returns only the names not reported in a previous call.
  public static string NewSnaps(string baseline) {
    StringBuilder sb = new StringBuilder();
    try {
      string[] m = Modules();
      if (baseline == "seed") {
        lock (g_lock) {
          g_snap.Clear();
          foreach (string s in m) g_snap.Add(s);
          g_snaps.AddRange(m);
        }
        return "seeded=" + m.Length;
      }
      List<string> fresh = new List<string>();
      lock (g_lock) {
        foreach (string s in m) {
          if (!g_snap.Contains(s)) { g_snap.Add(s); fresh.Add(s); }
        }
      }
      if (fresh.Count == 0) return "0";
      sb.Append(fresh.Count.ToString()).Append('[').Append(string.Join(",", fresh.ToArray())).Append(']');
      return sb.ToString();
    } catch (Exception e) { return "SNAP_ERR " + e.GetType().Name + " " + e.Message; }
  }
  public static int SnapCount() { lock (g_lock) { return g_snap.Count; } }

  // ---------- H0: hold the privileges the service record asks for ----------
  // TOKEN_PRIVILEGES for exactly one privilege, laid out by hand so no /unsafe is needed and no struct
  // padding can move the LUID: Count@0(4) LuidLow@4(4) LuidHigh@8(4) Attributes@12(4) = 16 bytes.
  // Using a long for the LUID puts it at offset 8 and the SCM-side call fails with 87 (old lesson).
  public static string EnablePrivileges(string[] names) {
    IntPtr tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok))
      return "TOKEN_ERR=" + Marshal.GetLastWin32Error();
    List<string> res = new List<string>();
    foreach (string n in names) {
      LUID luid;
      if (!LookupPrivilegeValueW(null, n, out luid)) {
        res.Add(n + "=NO_LUID(" + Marshal.GetLastWin32Error() + ")"); continue;
      }
      IntPtr blob = Marshal.AllocHGlobal(16);
      try {
        Marshal.WriteInt32(blob, 1);
        Marshal.WriteInt32(blob, 4, unchecked((int)luid.LowPart));
        Marshal.WriteInt32(blob, 8, luid.HighPart);
        Marshal.WriteInt32(blob, 12, unchecked((int)SE_PRIVILEGE_ENABLED));
        bool ok = AdjustTokenPrivileges(tok, false, blob, 16, IntPtr.Zero, IntPtr.Zero);
        int e = Marshal.GetLastWin32Error();
        // AdjustTokenPrivileges returns TRUE with ERROR_NOT_ALL_ASSIGNED(1300) when the token does not hold
        // the privilege, so rc=True alone is not a grant; 1300 says this process can never host the service
        // faithfully, and on an un-elevated host token that is expected (probe155 H0 control run).
        string verdict;
        if (ok && e == 0) verdict = "on";
        else if (e == 1300) verdict = "NOT-IN-TOKEN";
        else verdict = "rc" + ok + "/err" + e;
        res.Add(n + "=" + verdict);
      } finally { Marshal.FreeHGlobal(blob); }
    }
    return string.Join(" ", res.ToArray());
  }

  // ---------- H3: the hooks ----------
  static DRegisterW g_regW = delegate (string name, IntPtr handler) {
    Log("HOOK RegisterServiceCtrlHandlerW name=[" + name + "]");
    g_status.Add("t" + g_sw.ElapsedMilliseconds + "ms REG-W [" + name + "]");
    return new IntPtr(0x515);           // a SERVICE_STATUS_HANDLE only has to be non-null
  };
  static DRegisterEx g_regEx = delegate (string name, IntPtr handler, IntPtr context) {
    Log("HOOK RegisterServiceCtrlHandlerExW name=[" + name + "]");
    g_status.Add("t" + g_sw.ElapsedMilliseconds + "ms REG-EX [" + name + "]");
    return new IntPtr(0x516);
  };
  static DSetStatus g_setStatus = delegate (IntPtr handle, IntPtr p) {
    try {
      int type = Marshal.ReadInt32(p, 0), st = Marshal.ReadInt32(p, 4), ctrl = Marshal.ReadInt32(p, 8);
      int wx = Marshal.ReadInt32(p, 12), sp = Marshal.ReadInt32(p, 16), cp = Marshal.ReadInt32(p, 20);
      int wh = Marshal.ReadInt32(p, 24);
      string line = "HOOK " + (g_poking ? "(poke) " : "") + "SetServiceStatus handle=0x" +
        ((long)handle).ToString("X") + " type=0x" + ((uint)type).ToString("X") + " state=" + StateName(st) +
        " win32=0x" + ((uint)wx).ToString("X8") + " specific=0x" + ((uint)sp).ToString("X8") +
        " controls=0x" + ((uint)ctrl).ToString("X") + " checkpoint=" + cp + " waithint=" + wh +
        (g_poking ? "" : " bt=" + Backtrace(1, 12));
      Log(line);
      lock (g_lock) { g_status.Add("t" + g_sw.ElapsedMilliseconds + "ms " + (g_poking ? "POKE " : "") +
                                  StateName(st) + " 0x" + ((uint)wx).ToString("X8") +
                                  " spec 0x" + ((uint)sp).ToString("X8")); }
    } catch (Exception e) { Log("HOOK SetServiceStatus MANAGED " + e.Message); }
    return true;
  };
  static DDispatcher g_disp = delegate (IntPtr table) {
    Log("HOOK StartServiceCtrlDispatcherW called from thread=" + GetCurrentThreadId());
    g_status.Add("t" + g_sw.ElapsedMilliseconds + "ms DISPATCHER-CALLED");
    return true;
  };
  static DDebugString g_dbgStr = delegate (IntPtr text) {
    try {
      string s = Marshal.PtrToStringUni(text);
      if (s == null) s = "";
      s = s.TrimEnd('\r', '\n');
      if (s.Length > 0) {
        lock (g_lock) { g_dbg.Add(s); }
        Log("ODB " + s);
      }
    } catch { }
  };

  static DDebugString g_dbgStrA = delegate (IntPtr text) {
    try {
      string s = Marshal.PtrToStringAnsi(text);
      if (s == null) s = "";
      s = s.TrimEnd('\r', '\n');
      if (s.Length > 0) {
        lock (g_lock) { g_dbg.Add(s); }
        Log("ODB-A " + s);
      }
    } catch { }
  };

  public static string Patch(string module, string proc, Delegate stub, string tag) {
    IntPtr hMod = GetModuleHandleOrLoad(module);
    if (hMod == IntPtr.Zero) return tag + " MODULE_ABSENT " + module;
    IntPtr addr = GetProcAddress(hMod, proc);
    if (addr == IntPtr.Zero) return tag + " NO_EXPORT " + proc + " err=" + Marshal.GetLastWin32Error();
    string who;
    if (g_hookedAt.TryGetValue(addr, out who))
      return tag + " addr=" + ((long)addr).ToString("X") + " SAME-AS " + who + " (not patched twice)";
    IntPtr stubPtr = Marshal.GetFunctionPointerForDelegate(stub);
    byte[] jmp = new byte[14];
    jmp[0] = 0xFF; jmp[1] = 0x25;                    // jmp qword ptr [rip+0]
    byte[] t = BitConverter.GetBytes((ulong)stubPtr);
    for (int i = 0; i < 8; i++) jmp[6 + i] = t[i];
    uint old;
    if (!VirtualProtect(addr, 14u, PAGE_EXECUTE_READWRITE, out old))
      return tag + " VPROTECT_FAIL err=" + Marshal.GetLastWin32Error();
    Marshal.Copy(jmp, 0, addr, 14);
    uint tmp;
    VirtualProtect(addr, 14u, old, out tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, 14u);
    g_hookedAt[addr] = tag;
    return tag + " addr=" + ((long)addr).ToString("X") + " mod=" + module + " stub=" +
           ((long)stubPtr).ToString("X") + " ok";
  }
  static IntPtr GetModuleHandleOrLoad(string module) {
    StringBuilder sb = new StringBuilder(512);
    // the module must already be mapped for its export table to be the one the service will use
    IntPtr[] mods = new IntPtr[2048]; uint need = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, (uint)(mods.Length * IntPtr.Size), out need, 0x03))
      return IntPtr.Zero;
    int count = (int)(need / (uint)IntPtr.Size);
    if (count > mods.Length) count = mods.Length;
    string want = module.ToLowerInvariant();
    for (int i = 0; i < count; i++) {
      sb.Length = 0;
      if (GetModuleFileNameExW(GetCurrentProcess(), mods[i], sb, (uint)sb.Capacity) == 0) continue;
      string p = sb.ToString();
      int k = p.LastIndexOf('\\');
      string nm = (k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant();
      if (nm == want) return mods[i];
    }
    return IntPtr.Zero;
  }

  // The four service-control exports live in advapi32 as thunks into sechost.dll, so each name is patched in
  // BOTH modules and Patch() reports when the second name lands on the first address. The stub delegates are
  // static fields, which keeps them alive for the lifetime of the process (a collected delegate would leave
  // the jmp pointing at freed memory).
  public static string InstallHooks() {
    List<string> r = new List<string>();
    r.Add(Patch("advapi32.dll", "RegisterServiceCtrlHandlerW", g_regW, "REG-W"));
    r.Add(Patch("sechost.dll", "RegisterServiceCtrlHandlerW", g_regW, "REG-W-SECHOST"));
    r.Add(Patch("advapi32.dll", "RegisterServiceCtrlHandlerExW", g_regEx, "REG-EX"));
    r.Add(Patch("sechost.dll", "RegisterServiceCtrlHandlerExW", g_regEx, "REG-EX-SECHOST"));
    r.Add(Patch("advapi32.dll", "SetServiceStatus", g_setStatus, "SET-STATUS"));
    r.Add(Patch("sechost.dll", "SetServiceStatus", g_setStatus, "SET-STATUS-SECHOST"));
    r.Add(Patch("advapi32.dll", "StartServiceCtrlDispatcherW", g_disp, "DISP"));
    r.Add(Patch("sechost.dll", "StartServiceCtrlDispatcherW", g_disp, "DISP-SECHOST"));
    r.Add(Patch("kernel32.dll", "OutputDebugStringW", g_dbgStr, "ODB"));
    r.Add(Patch("kernel32.dll", "OutputDebugStringA", g_dbgStrA, "ODB-A"));
    return string.Join(" | ", r.ToArray());
  }

  // ---------- H3b: prove the patches actually fire ----------
  // An empty STATUS list in the real run is only evidence if the jmps are known to work, so call three of
  // the patched export addresses ourselves. The stubs run in-process and never reach the SCM, so this cannot
  // change any service state; g_poking marks the resulting lines and ClearStatus drops them afterwards.
  static IntPtr AddrOf(string mod, string proc) {
    IntPtr h = GetModuleHandleOrLoad(mod);
    if (h == IntPtr.Zero) return IntPtr.Zero;
    return GetProcAddress(h, proc);
  }
  public static string PokeHooks() {
    g_poking = true;
    List<string> r = new List<string>();
    try {
      IntPtr a = AddrOf("advapi32.dll", "RegisterServiceCtrlHandlerW");
      if (a == IntPtr.Zero) r.Add("REGW_ADDR_GONE");
      else {
        DRegisterW f = (DRegisterW)Marshal.GetDelegateForFunctionPointer(a, typeof(DRegisterW));
        IntPtr fake = Marshal.AllocHGlobal(IntPtr.Size);
        IntPtr got = f("poke", fake);
        r.Add("REGW->0x" + ((long)got).ToString("X"));
      }
      a = AddrOf("advapi32.dll", "RegisterServiceCtrlHandlerExW");
      if (a == IntPtr.Zero) r.Add("REGEX_ADDR_GONE");
      else {
        DRegisterEx f = (DRegisterEx)Marshal.GetDelegateForFunctionPointer(a, typeof(DRegisterEx));
        IntPtr got = f("poke", Marshal.AllocHGlobal(IntPtr.Size), IntPtr.Zero);
        r.Add("REGEX->0x" + ((long)got).ToString("X"));
      }
      a = AddrOf("advapi32.dll", "SetServiceStatus");
      if (a == IntPtr.Zero) r.Add("SETSTATUS_ADDR_GONE");
      else {
        DSetStatus f = (DSetStatus)Marshal.GetDelegateForFunctionPointer(a, typeof(DSetStatus));
        // SERVICE_STATUS is 7 DWORDs = 28 bytes; fill it the way a real START_PENDING report would
        IntPtr st = Marshal.AllocHGlobal(28);
        Marshal.WriteInt32(st, 0, 0x20);        // serviceType = own process
        Marshal.WriteInt32(st, 4, 4);           // state = RUNNING
        Marshal.WriteInt32(st, 8, 0x17);        // controls accepted
        Marshal.WriteInt32(st, 12, 0);          // win32ExitCode
        Marshal.WriteInt32(st, 16, 0);          // serviceSpecificExitCode
        Marshal.WriteInt32(st, 20, 0);          // checkpoint
        Marshal.WriteInt32(st, 24, 0);          // waitHint
        bool okv = f(new IntPtr(0x515), st);
        r.Add("SETSTATUS->" + okv);
      }
      return string.Join(" ", r.ToArray()) + " statusSeen=" + StatusAll(6);
    } catch (Exception e) {
      return "POKE MANAGED " + e.GetType().Name + " " + e.Message + " " + string.Join(" ", r.ToArray());
    } finally { g_poking = false; }
  }
  public static string ClearStatus() {
    int n;
    lock (g_lock) { n = g_status.Count; g_status.Clear(); }
    return "dropped=" + n;
  }

  // ---------- H2: exports, read out of the MAPPED image ----------
  // The DLL is already loaded, so an RVA is just base+RVA -- no section-table walk needed. Guarded because a
  // malformed/ordinal-only entry must not kill the probe before it reaches the service main.
  static IntPtr Rva(IntPtr bAddr, uint rva) { return new IntPtr(bAddr.ToInt64() + (long)rva); }
  static List<string> ExportNames(IntPtr bAddr) {
    List<string> names = new List<string>();
    try {
      byte[] head = new byte[1024];
      Marshal.Copy(bAddr, head, 0, 1024);
      int peOff = BitConverter.ToInt32(head, 0x3C);
      ushort magic = BitConverter.ToUInt16(head, peOff + 24);
      int ddOff = peOff + 24 + (magic == 0x20B ? 112 : 96);   // PE32+ optional header size 112
      uint expRva = BitConverter.ToUInt32(head, ddOff);        // data directory #0 = export table
      if (expRva == 0) return names;
      IntPtr e = Rva(bAddr, expRva);
      // IMAGE_EXPORT_DIRECTORY: +0 Characteristics, +4 TimeDateStamp, +8 versions, +12 Name(RVA),
      // +16 OrdinalBase, +20 NumberOfFunctions, +24 NumberOfNames, +28 AddressOfFunctions,
      // +32 AddressOfNames, +36 AddressOfNameOrdinals. (+12 is the DLL-name string: reading it as the name
      // table hands back ASCII bytes as RVAs, which is what the first version of this did.)
      uint addrOfNames = (uint)Marshal.ReadInt32(e, 32);
      uint numNames = (uint)Marshal.ReadInt32(e, 24);
      if (numNames > 4000) numNames = 4000;
      for (uint i = 0; i < numNames; i++) {
        try {
          uint nameRva = (uint)Marshal.ReadInt32(Rva(bAddr, addrOfNames), (int)(i * 4));
          string s = Marshal.PtrToStringAnsi(Rva(bAddr, nameRva));
          if (s == null) s = "";
          if (s.Length > 0) names.Add(s);
        } catch { }
      }
    } catch { }
    return names;
  }
  public static string DllProbe(string path) {
    IntPtr h = LoadLibraryExW(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "load=FAIL err=" + Marshal.GetLastWin32Error();
    g_module = h;
    List<string> names = ExportNames(h);
    string hit = "";
    foreach (string s in names) {
      if (s.IndexOf("Svc", StringComparison.OrdinalIgnoreCase) >= 0 ||
          s.IndexOf("Main", StringComparison.OrdinalIgnoreCase) >= 0 ||
          s.IndexOf("Globals", StringComparison.OrdinalIgnoreCase) >= 0) hit += s + ",";
    }
    return "load=OK base=0x" + ((long)h).ToString("X") + " count=" + names.Count +
           " svc-ish=[" + hit.TrimEnd(',') + "]";
  }
  public static string[] Exports(string path) {
    IntPtr h = g_module;
    if (h == IntPtr.Zero) { h = LoadLibraryExW(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH); g_module = h; }
    if (h == IntPtr.Zero) return new string[] { "LOAD_FAIL err=" + Marshal.GetLastWin32Error() };
    List<string> names = ExportNames(h);
    return names.ToArray();
  }

  // ---------- H5: call the service main the way svchost does ----------
  public static string Resolve(string dllPath, string entryName) {
    if (g_module == IntPtr.Zero)
      g_module = LoadLibraryExW(dllPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (g_module == IntPtr.Zero) return "LOAD_FAIL err=" + Marshal.GetLastWin32Error();
    IntPtr p = GetProcAddress(g_module, entryName);
    if (p == IntPtr.Zero) return "NO_EXPORT " + entryName + " err=" + Marshal.GetLastWin32Error();
    g_main = (NativeSvcMain)Marshal.GetDelegateForFunctionPointer(p, typeof(NativeSvcMain));
    g_mainAddr = p;
    return "OK module=0x" + ((long)g_module).ToString("X") + " " + entryName + "=0x" +
           ((long)p).ToString("X");
  }

  // The service runs on its own thread so the harness can poll status/modules/WLAN while it is still inside
  // ServiceMain -- wlansvc's failure happens ~130ms in, and a blocking call would hide the sequence.
  public static string StartMainThread(string dllPath, string entryName, string svc) {
    string r = Resolve(dllPath, entryName);
    if (r != "OK" && r.IndexOf("OK ") != 0) return r;
    g_argv = Marshal.AllocHGlobal(IntPtr.Size);
    g_pName = Marshal.StringToHGlobalUni(svc);
    Marshal.WriteIntPtr(g_argv, g_pName);
    Log("RUNMAIN " + entryName + " argc=1 argv[0]=[" + svc + "] main=0x" +
        ((long)g_mainAddr).ToString("X"));
    g_thread = new Thread(delegate () {
      g_mainT0 = Environment.TickCount;
      try {
        g_main(1, g_argv);
        g_retMs = Environment.TickCount - g_mainT0;
        g_returned = true;
        Log("RUNMAIN " + entryName + " RETURNED after " + g_retMs + "ms");
      } catch (Exception e) {
        g_returned = true; g_retMs = Environment.TickCount - g_mainT0;
        Log("RUNMAIN MANAGED " + e.GetType().Name + " " + e.Message);
      }
    });
    g_thread.IsBackground = true;
    g_thread.Name = "p155svc";
    g_thread.Start();
    return "started thread=" + g_thread.ManagedThreadId;
  }
  public static string MainState() {
    if (g_thread == null) return "not-started";
    if (g_returned) return "returned after " + g_retMs + "ms";
    return "alive " + (Environment.TickCount - g_mainT0) + "ms thread=" +
           (g_thread.ThreadState.ToString());
  }

  // ---------- H7: does the WLAN RPC endpoint come up in-process ----------
  // If ServiceMain reaches RUNNING here, its RPC server is registered by itself and WlanOpenHandle from this
  // same process can succeed even though the SCM never started the service. It is the cheapest signal that we
  // got past the bail-out, so poll it on every round.
  public static string WlanTry(int version) {
    IntPtr h = GetModuleHandleW("wlanapi.dll");
    if (h == IntPtr.Zero)
      h = LoadLibraryExW("wlanapi.dll", IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "wlanapi load=FAIL err=" + Marshal.GetLastWin32Error();
    IntPtr p = GetProcAddress(h, "WlanOpenHandle");
    if (p == IntPtr.Zero) return "NO_EXPORT WlanOpenHandle err=" + Marshal.GetLastWin32Error();
    DWlanOpen f = (DWlanOpen)Marshal.GetDelegateForFunctionPointer(p, typeof(DWlanOpen));
    IntPtr pNeg = Marshal.AllocHGlobal(4);
    IntPtr pHand = Marshal.AllocHGlobal(IntPtr.Size);
    try {
      Marshal.WriteInt32(pNeg, 0); Marshal.WriteIntPtr(pHand, IntPtr.Zero);
      uint hr = f((uint)version, IntPtr.Zero, pNeg, pHand);
      return "hr=0x" + hr.ToString("X8") + " neg=" + Marshal.ReadInt32(pNeg) +
             " client=0x" + ((long)Marshal.ReadIntPtr(pHand)).ToString("X") +
             " lasterr=" + Marshal.GetLastWin32Error();
    } finally { Marshal.FreeHGlobal(pNeg); Marshal.FreeHGlobal(pHand); }
  }
  public static IntPtr ModuleBase() { return g_module; }
  public static string PushGlobals(string fn) {
    if (g_module == IntPtr.Zero) return "NO MODULE";
    IntPtr p = GetProcAddress(g_module, fn);
    if (p == IntPtr.Zero) return fn + " NO_EXPORT";
    // a zeroed page: the service stores this pointer and dereferences it, so NULL fields read as NULL and
    // the VEH names the offset instead of faulting on whatever memory we would have handed it by accident
    IntPtr blob = Marshal.AllocHGlobal(512);
    for (int i = 0; i < 512; i++) Marshal.WriteByte(blob, i, 0);
    NativePushGlobals d = (NativePushGlobals)Marshal.GetDelegateForFunctionPointer(p, typeof(NativePushGlobals));
    try { d(blob); } catch (Exception e) { return fn + " MANAGED " + e.GetType().Name + " " + e.Message; }
    return fn + " called blob=0x" + ((long)blob).ToString("X");
  }
}
'@

$privList = @('SeTcbPrivilege', 'SeChangeNotifyPrivilege', 'SeImpersonatePrivilege',
              'SeAuditPrivilege', 'SeDebugPrivilege', 'SeLoadDriverPrivilege')

if ($DryRun) {
  L('DRY probe155: H0 enable the ' + $privList.Count + ' privileges wlansvc record asks the host to hold,')
  L('DRY H1 VEH(first-chance, CONTINUE_SEARCH) + ordered module census, H2 export table read out of the')
  L('DRY  mapped image, H3 patch RegisterServiceCtrlHandlerW / ...ExW / SetServiceStatus /')
  L('DRY  StartServiceCtrlDispatcherW + OutputDebugStringW in advapi32 AND sechost (every address printed,')
  L('DRY  a name that lands on an already-patched address is reported instead of double-patched),')
  L('DRY H4 SvchostPushServiceGlobals(zeroed 512B blob), H5 WlanSvcMain(argc=1, argv[0]="wlansvc") on its')
  L('DRY  own thread exactly as svchost does, polled every 1.5s with a WlanOpenHandle probe,')
  L('DRY H6 = -NoHooks reverse fixture. Nothing on the disc changes: hooks are process-local, X: is RAM disk.')
  L('DRY -HooksOnly runs H0..H4 and stops before ServiceMain (the host-side plumbing control), -ListExports')
  L('DRY  dumps the export table read from the mapped image and exits.')
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1')
  if ($n -eq 1) {
    # The exception parameter decoder runs inside a vectored handler, where a second fault kills the
    # process -- and it did exactly that on the live disc. This self-test hands it the shapes a C++ throw
    # really carries (heap garbage, chained pointers, a bogus parameter count) and must not fault.
    $st = (C ([Hk155]::DescSelfTest()))
    L('DRY ' + $st)
    $a0 = $st -match 'D0 null=\[0\]'                       # a NULL parameter is described, not followed
    $a2 = $st -match 'EH-MAGIC'                           # the magic value is recognised as a value
    $a5 = $st -match 'D5 image-base=\[[^\]]*struct [0-9a-f]+'   # an image pointer yields its raw bytes
    $a6 = $st -match 'D6 veh ret=0 new=2'                 # header line + decode line, one record each
    $a7 = $st -match 'dec=\[EXCD [^\]]*p0=[^\]]*EH-MAGIC' # the inline array really starts at +32
    $a8 = $st -match 'D8 exc-list reset \(len=0\)'        # the fake records left no dedup key behind
    $sv = $st -match 'SELFTEST survived=true'
    # Second self-test: the stack scanner. RtlCaptureStackBackTrace from a managed callback is useless here (it
    # stops at the CLR transition stub -- bt=n0: on both host and disc) and RtlVirtualUnwind faults on the first
    # step, so Scan() reads the exception's own stack instead. This raises a private exception code, sees it
    # through our handler with a genuine CONTEXT (Rip@248/Rsp@152), and requires at least two named frames.
    $uw0 = (C ([Hk155]::InstallVeh()))
    $uw = (C ([Hk155]::ScanSelfTest()))
    L('DRY veh-for-scan=' + $uw0 + ' ' + $uw)
    $a9 = $uw -match 'SC ok=1'
    L('DRY SELFTEST-ASSERT null=' + $a0 + ' magic=' + $a2 + ' imagehex=' + $a5 + ' veh=' + $a6 +
      ' inline=' + $a7 + ' reset=' + $a8 + ' survived=' + $sv + ' scan=' + $a9 + ' -> ' +
      $(if ($a0 -and $a2 -and $a5 -and $a6 -and $a7 -and $a8 -and $sv -and $a9) { 'PASS' } else { 'FAIL' }))
  }
  exit 0
}

L('probe155 begin root=[' + $s32 + '] dll=[' + $Dll + '] entry=' + $Entry + ' svc=' + $SvcName +
  ' hooks=' + $(if ($NoHooks) { 'OFF(H6)' } else { 'ON' }) +
  ' globals=' + $(if ($NoGlobals) { 'OFF' } else { 'ON' }) + ' seconds=' + $Seconds)
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)); L('ABORT'); exit 1 }

# $Out is used RAW, not through C(): the ASCII sanitizer would turn a non-ASCII directory into '?' and the
# write would fail with a path error. In the PE every path is ASCII anyway; on a dev box pick an ASCII path.
$outDir = [System.IO.Path]::GetDirectoryName($Out)
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
  try { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
  catch { L('OUTDIR FAIL ' + (C $_.Exception.Message)) }
}
[Hk155]::OpenLog($Out)

# ---------- H0: the token the service expects its host to hold ----------
L('H0 ' + (C ([Hk155]::EnablePrivileges($privList))))

# ---------- H1: first-chance recorder ----------
L('H1 veh ' + (C ([Hk155]::InstallVeh())))
# The decoder below runs inside that handler, so it gets one rehearsal on the real address space before
# anything is loaded: the shapes a C++ throw hands us, including the heap-pointer case that killed the
# previous live run. g_exc/g_excSeen are reset by the self-test itself, so the real records still print.
L('H1b ' + (C ([Hk155]::DescSelfTest())))
# The stack scanner gets the same rehearsal on this machine (see ScanSelfTest above): if this says SC ok=0 then
# every sc= below is meaningless and the instrument, not the service, needs the next run.
L('H1c ' + (C ([Hk155]::ScanSelfTest())))
if ($SelfTestOnly) {
  L('SELFTESTONLY the VEH decoder survived on this machine; no hook was installed and ServiceMain was')
  L('  never called -- this is the pre-flight for a disc where raising one exception is all we need proof of.')
  [Environment]::Exit(0)
}

# ---------- H2: the image, and the entry points it actually exports ----------
L('H2 ' + (C ([Hk155]::DllProbe($Dll))))
if ($ListExports) {
  foreach ($e in @([Hk155]::Exports($Dll))) { L('H2 EXPORT ' + (C $e)) }
  L('H2 export listing only -- ServiceMain was never called; exit 0')
  [Environment]::Exit(0)
}
L('H2 baseline modules ' + (C ([Hk155]::NewSnaps('seed'))))

# ---------- H3: make the DLL believe it is being hosted ----------
if (-not $NoHooks) {
  L('H3 ' + (C ([Hk155]::InstallHooks())))
  L('H3b ' + (C ([Hk155]::PokeHooks())))
  L('H3b cleared ' + (C ([Hk155]::ClearStatus())))
}
else { L('H3 SKIPPED (-NoHooks: reverse fixture, the real calls will fail 1063)') }

# ---------- H4: the globals block svchost always pushes before ServiceMain ----------
if (-not $NoGlobals) { L('H4 ' + (C ([Hk155]::PushGlobals('SvchostPushServiceGlobals')))) }
else { L('H4 SKIPPED (-NoGlobals)') }

# ---------- H5: call WlanSvcMain and watch ----------
# -HooksOnly stops here on purpose: on a machine whose wlansvc is already RUNNING, a second in-proc
# AutoConfig host can contend for the same adapter (radio state, WDI sessions), so the hook/plumbing
# control run must not call ServiceMain. It is the host-side gate; the PE has no working service to
# contend with, which is why the full run only happens there.
if ($HooksOnly) {
  L('HOOKSONLY stops before ServiceMain -- H0..H4 plumbing verified (privileges, VEH, exports, patch table,')
  L('  globals call). STATUS stays empty by design; the transitions below only exist in a real run.')
  L('HOOKSONLY STATUS ' + (C ([Hk155]::StatusAll(10))))
  L('HOOKSONLY newmods ' + (C ([Hk155]::NewSnaps(''))))
  L('HOOKSONLY exc=' + ([Hk155]::ExcCount()) + ' ' + (C ([Hk155]::ExcAll(20))))
  [Environment]::Exit(0)
}
L('H5 resolve ' + (C ([Hk155]::Resolve($Dll, $Entry))))
# The .pdb identity of the image we are about to run: with it, the module+offset frames in the EXCD/STATUS
# lines can be turned into function names on the build machine (Microsoft's public symbol server is reachable
# from here -- build\scratch notes, and the 404 for a bogus GUID proves the endpoint answers).
L('H5 ' + (C ([Hk155]::PdbInfo([Hk155]::ModuleBase()))))
L('H5 ' + (C ([Hk155]::StartMainThread($Dll, $Entry, $SvcName))))
$start = Get-Date
$round = 0
while ($true) {
  Start-Sleep -Milliseconds 1500
  $round++
  $t = [int]((New-TimeSpan -Start $start -End (Get-Date)).TotalMilliseconds)
  $mainSt = (C ([Hk155]::MainState()))
  $new = (C ([Hk155]::NewSnaps('')))
  L('H5 r' + $round + ' t=' + $t + 'ms main=' + $mainSt + ' mods=' + ([Hk155]::SnapCount()) +
    ' exc=' + ([Hk155]::ExcCount()) + ' ' + (C ([Hk155]::WlanTry(2))))
  if ($new -ne '0') {
    $open = $new.IndexOf('[')
    if ($open -ge 0) {
      $fresh = ('' + $new.Substring($open + 1)).TrimEnd(']').Split(',')
      foreach ($f in $fresh) { L('H5 r' + $round + ' MOD ' + (C $f)) }
    } else { L('H5 r' + $round + ' NEW ' + $new) }
  }
  L('H5 r' + $round + ' STATUS ' + (C ([Hk155]::StatusAll(30))))
  if ($mainSt -match 'returned') { L('H5 service main returned, stopping the poll'); break }
  if ($t -ge ($Seconds * 1000)) { L('H5 poll budget ' + $Seconds + 's reached'); break }
}

L('H5 FINAL main=' + (C ([Hk155]::MainState())))
L('H5 FINAL-STATUS ' + (C ([Hk155]::StatusAll(40))))
L('H5 FINAL-EXC ' + (C ([Hk155]::ExcAll(60))))
L('H5 FINAL-ODB ' + (C ([Hk155]::DbgAll(40))))
$allMods = @([Hk155]::Modules())
for ($i = 0; $i -lt $allMods.Count; $i += 12) {
  $hi = [Math]::Min($i + 11, $allMods.Count - 1)
  L('H5 MODS ' + $i + '-' + $hi + ' ' + (C (($allMods[$i..$hi]) -join ',')))
}

L('probe155 end -- order of reading:')
L('  1. the H5 r* STATUS lines. The LAST transition is the answer. REG-W/REG-EX with no START_PENDING after')
L('     it means the DLL bailed before it ever reported a status: the module that first appears in that')
L('     round, plus FINAL-EXC, names the callee it failed on.')
L('  2. START_PENDING then STOPPED win32=0x800C0006 with the same module set probe99 saw means in-proc')
L('     reproduces the real failure exactly -- then FINAL-ODB (OutputDebugStringW narration) is the new text.')
L('  3. if the hooks let it get further than the SCM run ever did, that difference is itself the finding:')
L('     the service needs something from the SCM hand-off, not from the image.')
L('  4. -NoHooks is the reverse fixture: an identical STATUS tail proves the hooks carry nothing.')
L('  5. run this same script on the healthy reference machine with -Root C:\Windows\System32 -Out')
L('     C:\p155_out.txt and diff the transition list; that is the first apples-to-apples wlansvc trace')
L('     this project has had, because the host service is never ours to instrument in-process.')
L('log file: ' + $Out)
[Environment]::Exit(0)
