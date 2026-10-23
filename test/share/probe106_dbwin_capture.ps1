# ============================================================
# probe106_dbwin_capture.ps1 -- hear what svchost/the service DLLs actually say
# ============================================================
#   Where the WiFi service layer stands after probe104/105 (live 12th-gen machine, same boot):
#     * 1297 was our bake's fault: WdiServiceHost had SeSystemProfilePrivilege, which PE's LOCAL SERVICE
#       token cannot hold. Drop it -> SCM accepts the start (START_OK).
#     * 1079 (LocalSystem variant) is structural: an account cannot differ from the other services in its
#       svchost process. Dead end, candidate B is out.
#     * 1052 (ERROR_INVALID_SERVICE_CONTROL, "the requested control is not valid for this service") survives
#       EVERY plumbing explanation we tested:
#         - parent Svchost MULTI_SZ membership: present (probe105 MEMB in_table=True for both hosts)
#         - ServiceSidType=1: already baked (SHAPE sidtype=1)
#         - dedicated, non-split group (the WinRE WlansvcGroup shape): E2 spawned a FRESH svchost
#           (pid 2064 / 2712), START_PENDING, and the service still stopped itself with 1052 after 86-103 ms.
#       A process that lives ~90 ms and reports a code is a DLL that ran and refused, not SCM saying no.
#     * wcmsvc reaches RUNNING at 93 ms and then aborts with 1067 (ERROR_PROCESS_ABORTS = unhandled death)
#       at ~377 ms. wlansvc exits on its own with 0x800C0006 in ~190 ms, with or without the WDI hosts.
#   PE has no event log and no ETW consumer, so every previous probe has been reading exit codes through a
#   keyhole. svchost, however, talks on the debugger channel: it creates the named objects DBWIN_BUFFER /
#   DBWIN_BUFFER_READY / DBWIN_DATA_READY and writes OutputDebugString text there, and `svchost -d -s <svc>`
#   runs one service in debug mode with a real service context. That is DebugView's protocol, and it is ~40
#   lines of P/Invoke. So this probe becomes the consumer, runs each WiFi/WDI service under svchost -d, and
#   prints the text -- which says *why*, not just *that*.
#   Also here, cheap and independent: the environment/directory facts a 26100-era wcmsvc is expected to have
#   (ProgramData / ALLUSERSPROFILE / ServiceProfiles / WcmSvc store dirs). WinRE is 19041-era and has no
#   wcmsvc at all, so the reference cannot answer this one; we measure it directly.
#   Output: single-line ASCII, prefix P106. Nothing here needs a reboot to interpret.
param([string]$Only = '', [switch]$DryRun, [switch]$SelfTest)
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P106 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class Pe106 {
  // ---- debugger channel (DebugView protocol) ----
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateFileMappingW(IntPtr f, IntPtr sa, uint prot, uint maxHi, uint maxLo, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern IntPtr MapViewOfFile(IntPtr m, uint acc, uint offHi, uint offLo, UIntPtr num);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool UnmapViewOfFile(IntPtr p);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr CreateEventW(IntPtr sa, bool manual, bool init, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenEventW(bool inherit, uint access, string name);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool SetEvent(IntPtr h);
  const uint PAGE_READWRITE = 0x04;
  const uint FILE_MAP_WRITE = 0x0002;
  const uint FILE_MAP_READ = 0x0004;
  const uint EVENT_ALL_ACCESS = 0x1F0003;
  const uint WAIT_OBJECT_0 = 0;
  const uint WAIT_TIMEOUT = 0x102;

  static IntPtr _map = IntPtr.Zero, _view = IntPtr.Zero, _ready = IntPtr.Zero, _data = IntPtr.Zero;
  static volatile bool _capturing = false;
  static Thread _th = null;
  static readonly object _lock = new object();
  static List<string> _lines = new List<string>();
  static string _ns = "";

  // PROTOCOL (this is the part that has to be right, and why this file is self-tested before it ships):
  //   producer = kernel32!OutputDebugString, taken when no debugger is attached. It opens the three objects,
  //     WaitsFor the BUFFER_READY event (the monitor's "buffer is free" grant), writes pid@0 + text@4, then
  //     sets DATA_READY.
  //   monitor  = us. Create the objects, GRANT the buffer once up front, then loop:
  //     wait DATA_READY -> read -> GRANT AGAIN.
  // A monitor that waits on BUFFER_READY first (the obvious reading of the name) deadlocks the producer and
  // collects nothing, which is exactly what the first draft of this file did.
  // Session matters: names without "Global\\" live in this session's BaseNamedObjects. In WinPE our shell
  // and the svchost we spawn are both session 0, so the plain name is tried first and Global\\ is the
  // fallback (creating Global\ needs SeCreateGlobalPrivilege).
  public static string Arm(int unused) {
    string[] prefixes = new string[] { "", "Global\\" };
    foreach (string pre in prefixes) {
      IntPtr m = CreateFileMappingW(new IntPtr(-1), IntPtr.Zero, PAGE_READWRITE, 0, 4104, pre + "DBWIN_BUFFER");
      if (m == IntPtr.Zero) { continue; }
      IntPtr v = MapViewOfFile(m, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, new UIntPtr(4104u));
      IntPtr r = CreateEventW(IntPtr.Zero, false, false, pre + "DBWIN_BUFFER_READY");
      if (r == IntPtr.Zero) { r = OpenEventW(false, EVENT_ALL_ACCESS, pre + "DBWIN_BUFFER_READY"); }
      IntPtr d = CreateEventW(IntPtr.Zero, false, false, pre + "DBWIN_DATA_READY");
      if (d == IntPtr.Zero) { d = OpenEventW(false, EVENT_ALL_ACCESS, pre + "DBWIN_DATA_READY"); }
      if (v == IntPtr.Zero || r == IntPtr.Zero || d == IntPtr.Zero) {
        return "ARM_PARTIAL pre=[" + pre + "] map=" + (m != IntPtr.Zero) + " view=" + (v != IntPtr.Zero) +
               " ready=" + (r != IntPtr.Zero) + " data=" + (d != IntPtr.Zero) + " gle=" + Marshal.GetLastWin32Error();
      }
      _map = m; _view = v; _ready = r; _data = d; _ns = pre;
      lock (_lock) { _lines.Clear(); }
      SetEvent(_ready);                       // grant: a producer may fill the buffer right away
      _capturing = true;
      _th = new Thread(new ThreadStart(Loop));
      _th.IsBackground = true;
      _th.Start();
      return "ARMED pre=[" + pre + "] granted=1";
    }
    return "ARM_FAILED gle=" + Marshal.GetLastWin32Error();
  }
  static void Loop() {
    while (_capturing) {
      uint w = WaitForSingleObject(_data, 250);
      if (w != WAIT_OBJECT_0) { continue; }
      int pid = Marshal.ReadInt32(_view, 0);
      byte[] buf = new byte[4096];
      // IntPtr arithmetic goes through Int64; a (ulong) cast does not compile to an IntPtr on x64.
      IntPtr text = new IntPtr(_view.ToInt64() + 4);
      Marshal.Copy(text, buf, 0, 4096);
      int n = Array.IndexOf(buf, (byte)0);
      if (n < 0) { n = 4096; }
      string s = Encoding.UTF8.GetString(buf, 0, n);
      lock (_lock) { if (_lines.Count < 400) { _lines.Add("pid=" + pid + " " + s); } }
      SetEvent(_ready);                       // hand the buffer back so the next writer is not stuck
    }
  }
  // Teardown grants twice more: a producer that is already parked on BUFFER_READY must not be left waiting
  // on an object we just stopped servicing (svchost calling OutputDebugString would hang).
  public static string Disarm() {
    SetEvent(_ready); SetEvent(_ready);
    _capturing = false;
    if (_th != null) { try { _th.Join(1500); } catch { } _th = null; }
    if (_view != IntPtr.Zero) { UnmapViewOfFile(_view); _view = IntPtr.Zero; }
    if (_map != IntPtr.Zero) { CloseHandle(_map); _map = IntPtr.Zero; }
    if (_ready != IntPtr.Zero) { CloseHandle(_ready); _ready = IntPtr.Zero; }
    if (_data != IntPtr.Zero) { CloseHandle(_data); _data = IntPtr.Zero; }
    return "DISARMED ns=[" + _ns + "]";
  }
  public static string Lines() {
    StringBuilder sb = new StringBuilder();
    lock (_lock) { foreach (string s in _lines) { sb.Append("\n    DB :: " + s); } sb.Append("|count=" + _lines.Count); }
    return sb.ToString();
  }
  public static string Capture(string dll, string group, string svc, int ms) {
    string arm = Arm(0);
    string launch = Spawner.Go(dll, group, svc);
    Thread.Sleep(ms);
    string sp = Spawner.Stop();
    StringBuilder sb = new StringBuilder();
    sb.Append(arm + " | launch=" + launch + " | stop=" + sp + " " + Lines());
    sb.Append(" | " + Disarm());
    return sb.ToString();
  }
  // Ping exists so the host-side validator can prove the class compiled and is callable
  // without launching anything.
  public static string Ping() { return "Pe106 ping ok"; }
  public static string LastError() { return "" + Marshal.GetLastWin32Error(); }
}

public static class Spawner {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool CreateProcessW(string app, string cmd, IntPtr sa, IntPtr tsa, bool inherit,
      uint flags, IntPtr env, string dir, STARTUPINFO si, out PROCESS_INFORMATION pi);
  [StructLayout(LayoutKind.Sequential)]
  struct STARTUPINFO {
    public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
    public int x, y, XSize, YSize, XCountChars, YCountChars, XFillAttribute, YFillAttribute;
    public int dwFlags; public short wShowWindow; public short cbReserved2;
    public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct PROCESS_INFORMATION {
    public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId;
  }
  static PROCESS_INFORMATION _pi;
  public static string Go(string exe, string group, string svc) {
    STARTUPINFO si = new STARTUPINFO();
    si.cb = Marshal.SizeOf(si);
    PROCESS_INFORMATION pi;
    string cmd = "\"" + exe + "\" -k " + group + " -d -s " + svc;
    bool ok = CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, null, si, out pi);
    if (!ok) { return "CREATE_ERR=" + Marshal.GetLastWin32Error(); }
    _pi = pi;
    return "pid=" + pi.dwProcessId;
  }
  public static string Stop() {
    if (_pi.hProcess == IntPtr.Zero) { return "no-proc"; }
    bool t = TerminateProcess(_pi.hProcess, 0);
    CloseHandle(_pi.hThread); CloseHandle(_pi.hProcess);
    _pi.hProcess = IntPtr.Zero;
    return t ? "killed" : ("KILL_ERR=" + Marshal.GetLastWin32Error());
  }
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll")]
  static extern bool CloseHandle(IntPtr h);
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe106 begin native=' + $native + ' dryrun=' + $DryRun + ' only=[' + $Only + '] selftest=' + $SelfTest)
if (-not $native) { L('FATAL no native capture; nothing to do'); exit 1 }

# -SelfTest proves the DBWIN handshake in this very process: arm the monitor, then be our own producer.
# Two distinct strings must come back or the instrument is worthless and the field run would print nothing.
if ($SelfTest) {
  L('SELFTEST ' + [Pe106]::Arm(0))
  try {
    Add-Type -TypeDefinition ('using System;using System.Runtime.InteropServices;' +
      'public static class OdsX{[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]' +
      ' public static extern void OutputDebugStringW(string s);}') -EA Stop | Out-Null
  } catch { L('SELFTEST ODS FAILED ' + (C $_.Exception.Message)); exit 1 }
  [OdsX]::OutputDebugStringW('p106-selftest-alpha')
  Start-Sleep -Milliseconds 400
  [OdsX]::OutputDebugStringW('p106-selftest-bravo')
  Start-Sleep -Milliseconds 700
  $ln = [Pe106]::Lines()
  L('SELFTEST LINES' + (C ($ln -replace "`r", '' -replace "`n", ' ~ ')))
  L('SELFTEST ' + $(if ($ln -match 'alpha' -and $ln -match 'bravo') { 'PASS' } else { 'FAIL' }) + ' ' + [Pe106]::Disarm())
  exit 0
}

# ---------- 1) the environment a 26100-era wcmsvc expects, as the PE actually has it ----------
$envK = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$ev = Get-ItemProperty -LiteralPath $envK -EA SilentlyContinue
$ei = Get-Item -LiteralPath $envK -EA SilentlyContinue
$names = @($ei.GetValueNames())
L('ENV names=[' + ($names -join ';') + ']')
foreach ($n in @('ProgramData', 'ALLUSERSPROFILE', 'PUBLIC', 'TEMP', 'TMP', 'SystemRoot', 'windir', 'Path')) {
  $v = '' + $ev.$n
  L('ENV ' + $n + '=[' + (C $v) + ']')
}
foreach ($d in @('X:\ProgramData', 'X:\ProgramData\Microsoft', 'X:\ProgramData\Microsoft\WcmSvc',
                 'X:\Users', 'X:\Windows\ServiceProfiles', 'X:\Windows\ServiceProfiles\LocalService',
                 'X:\Windows\ServiceProfiles\LocalService\AppData', 'X:\Windows\ServiceProfiles\NetworkService',
                 'X:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WcmSvc',
                 'X:\Windows\System32\LogFiles', 'X:\Windows\System32\CatRoot')) {
  L('DIR ' + $d + ' = ' + (Test-Path -LiteralPath $d))
}
foreach ($f in @('wlansvc.dll', 'wcmsvc.dll', 'wcmcsp.dll', 'wdi.dll', 'wlanapi.dll', 'wlanmsm.dll', 'wifiprofiles.dll')) {
  $p = 'X:\Windows\System32\' + $f
  $fi = Get-Item -LiteralPath $p -EA SilentlyContinue
  if (-not $fi) { L('FILE ' + $f + ' = ABSENT'); continue }
  $vi = $fi.VersionInfo
  L('FILE ' + $f + ' size=' + $fi.Length + ' ver=[' + (C ('' + $vi.FileVersion)) + '] prod=[' +
    (C ('' + $vi.ProductVersion)) + ']')
}

# ---------- 2) the chain as it stands this boot ----------
foreach ($n in @('nativewifip', 'vwififlt', 'vwifibus', 'wcmsvc', 'wlansvc', 'WdiServiceHost', 'wdisystemhost',
                 'RpcSs', 'NSI', 'Dnscache', 'BFE', 'mpssvc')) {
  L('SVC ' + $n + ' = ' + (Get-Service -Name $n -EA SilentlyContinue).Status)
}
$fl = ''
try {
  $ck = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001\Linkage'
  $fl = (@((Get-ItemProperty -LiteralPath $ck -EA SilentlyContinue).FilterList) -join ';')
} catch { }
L('FILTERLIST 0001=[' + (C $fl) + ']')
# probe105 E2 created these dedicated groups live; they exist until reboot and are what -d runs against
foreach ($g in @('WdiSvcHostGroup', 'WdiSysHostGroup', 'WlansvcGroup')) {
  $mv = @((Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost').GetValue($g))
  L('GRP ' + $g + ' = [' + (($mv | ForEach-Object { "$_" }) -join ';') + ']')
}
if ($DryRun) { L('probe106 end (DryRun: facts only, nothing captured)'); exit 0 }

# ---------- 3) the instrument: run each service under svchost -d and read the debug channel ----------
$targets = @(
  @{ s = 'WdiServiceHost'; g = 'WdiSvcHostGroup' },
  @{ s = 'wdisystemhost';  g = 'WdiSysHostGroup' },
  @{ s = 'wlansvc';        g = 'WlansvcGroup' },
  @{ s = 'wcmsvc';         g = 'LocalServiceNetworkRestricted' }
)
foreach ($t in $targets) {
  if ($Only -and $t.s -ine $Only) { continue }
  if (@($targets | Where-Object { $_.g -eq $t.g }).Count -eq 0) { L('SKIP ' + $t.s + ' group ' + $t.g + ' not defined'); continue }
  $r = [Pe106]::Capture('X:\windows\system32\svchost.exe', $t.g, $t.s, 5000)
  foreach ($ln in ($r -split "`n")) { L('RUN ' + $t.s + (C $ln)) }
}
L('probe106 end -- RUN lines above are svchost/the DLLs talking; that is the first readable failure reason')
