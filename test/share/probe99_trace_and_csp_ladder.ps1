# probe99 -- stop guessing WHICH object wlansvc cannot find, and measure how far its init actually gets:
# sample the svchost host's module list every millisecond across the start attempt, so the load ORDER of the
# attempt is on the log, together with the two remaining provable gaps probe98 left open.
#
# Where probe98 left it (build\scratch\p98_pe_apply.txt, this box, 2026-10-11 15:0x, same boot):
#   every registry-named provider was supplied and named correctly and wlansvc answered the same way:
#     rungs onex/wfd/ie/ics/priv/deps/misc/retry -> P98 LADDER ... running=False ifn=-1
#     every file LL flipped 126->OK, every REG-SET rc=0 with the read-back matching, CLSID registered,
#     RequiredPrivileges and DependOnService rewritten, VirtualizationManager created --
#     wlansvc: +85..122ms STOPPED exit=2148270086(0x800C0006); wcmsvc: +275..308ms STOPPED exit=1067(0x42B).
#   probe96/97 had already excluded: environment dirs, Crypto/OID/SystemCertificates, cryptsvc, KeyIso, adapter
#   presence (disabled devnode gives the same code), and every delay-load / api-set file the PE lacked.
#
# What this boot says about the "it must be WinINet" reading of 0x800C0006 (build\scratch\p99_shape_pe.txt vs
# build\scratch\p99_shape_host.txt, the same read-only script run as the service's own identity, SYSTEM):
#   PE: wininet/urlmon/iertutil/winhttp/mswsock all LoadLibrary OK (26100.1), InternetOpenW returns a live handle
#       err=0, InternetGetConnectedState ok=True flags=0x12, WinHttpOpen ok. So WinINet itself is functional here.
#   Still measurable differences, neither of which probe98 could test:
#     NameSpace_Catalog5\Catalog_Entries64 = 1 entry in the PE vs 7 on the host (winsock namespace providers);
#     HKLM\SOFTWARE\...\Internet Settings values 1 vs 5, subkeys 19 vs 28; webcheck.dll and msisip.dll absent;
#     $env:ProgramData/$env:USERPROFILE/$env:LOCALAPPDATA are NULL for SYSTEM in the PE (probe96's live
#     HKU\.DEFAULT\Environment writes do not reach a process whose parent started at boot).
#   Host-side module enumeration for a positive control is NOT available from this non-elevated session
#   (build\scratch\p99_host_modules.txt: OpenProcess err=5 on every SYSTEM svchost, tasklist /M prints "modules:
#   missing"), so the trace below is read on its own terms: the order and the last module before the bail.
#
# The two gaps that only probe99 can supply, collected read-only on the host (build\scratch\p99_collect_host_values.txt):
#   * HKLM\...\Services\wcmsvc\Csps\{cspethernet,cspwlan,cspwwan} each have Dll=wcmcsp.dll + InitFunction +
#     DeinitFunction + MediaService + WcmMediaType on the host; the PE has the same subkeys with NO values and no
#     wcmcsp.dll at all. wcmsvc loads each CSP by that name, so a missing file there is a real candidate for its
#     1067 (ERROR_PROCESS_ABORTED = the host died), which matches the pe_svchost_1328.dmp reading (R13=
#     STATUS_DLL_NOT_FOUND, raise parameters inside wcmsvc.dll).
#   * HKLM\...\Services\wlansvc\Parameters\WlanAPIPermissions is an EMPTY key in the PE and holds 18 REG_SZ
#     security descriptors on the host. They are static ACLs (O:SYG:SYD:(A;;CCRC;;;BU)...), not key material; the
#     host's copies are stored with trailing UTF-16 NUL padding which the collector trims (reg.exe cannot carry a
#     NUL in argv). Both come over HTTP as values99.tsv, base64 of the UTF-16LE bytes.
#
# PRIVACY: the collector and this probe both refuse secret-shaped paths (HostedNetworkSettings, EncryptedSettings,
# Profiles\Interfaces, \Security, password/psk/passphrase/keymaterial/profilexml names). No WiFi profile, no key
# material, and no SID list is ever printed, copied, or written. ProfileList subkey names are counted, not shown.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit overrides
# that guard deliberately. Writes are file copies into X:\Windows\System32 (original kept in X:\p99bak), REG values
# under the two service keys, and directories under X:\ProgramData / X:\Windows\System32\config\systemprofile.
# Service starts for wlansvc/wcmsvc only. No hive is touched, no key is deleted, nothing is written to C:, to
# D:\winpe_build, or to a customer disk. Rebooting restores the disc.
param([switch]$Apply, [switch]$IDoit, [switch]$ForceNoRun, [string]$Base = 'http://192.168.0.106:8099/',
      [string]$Only = '', [int]$TraceMs = 1500)
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Clean([string]$s) { (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Root([string]$sub) {
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function TP([string]$p) {
  try { return [bool](Test-Path -LiteralPath $p -EA SilentlyContinue) } catch { return $false }
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}
function HexVal([object]$v) { if ($null -eq $v) { return '-' } return ('0x' + ('{0:X}' -f [int]$v)) }
function FV([string]$p) {
  if (-not (TP $p)) { return '<absent>' }
  $v = $null
  try { $v = (Get-Item -LiteralPath $p -EA SilentlyContinue).VersionInfo.FileVersion } catch { }
  return ('"' + (Clean "$v") + '"')
}
function Run([string]$exe, [object[]]$argv) {
  if (-not (TP $exe)) { return @{ rc = -1; lines = @('<tool absent: ' + $exe + '>') } }
  $rc = -999
  $lines = @()
  try {
    $o = @(& $exe @argv 2>&1)
    $rc = $LASTEXITCODE
    $lines = @($o | ForEach-Object { Clean "$_" } | Where-Object { $_ -ne '' })
  } catch { $lines = @('EXCEPTION ' + (Clean $_.Exception.Message)) }
  return @{ rc = $rc; lines = @($lines) }
}
function SubNames([string]$path) {
  @(@(Get-ChildItem -LiteralPath $path -EA SilentlyContinue).PSChildName | ForEach-Object { Clean $_ })
}
function SvcRow([string]$s) {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  if (-not (TP $p)) { return ('SVC ' + $s + ' <key absent>') }
  $dll = [string](RegV ($p + '\Parameters') 'ServiceDll')
  $main = [string](RegV ($p + '\Parameters') 'ServiceMain')
  return ('SVC ' + $s + ' Start=' + (HexVal (RegV $p 'Start')) + ' Type=' + (HexVal (RegV $p 'Type')) +
    ' Group=[' + (RegV $p 'Group') + '] Obj=[' + (RegV $p 'ObjectName') + ']' +
    ' Depend=[' + (@(RegV $p 'DependOnService') -join ';') + ']' +
    ' SidType=' + (HexVal (RegV $p 'ServiceSidType')) +
    ' State=' + ((Get-Service -Name $s -EA SilentlyContinue).Status) +
    ' Dll=[' + (Clean $dll) + '] exists=' + (TP $dll) + ' ver=' + (FV $dll) + ' Main=[' + $main + ']' +
    ' subs=' + ((SubNames $p) -join ','))
}
function StackLine {
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'Ndisuio', 'NSI', 'RpcSs', 'bfe')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return (@($states -join ',') + ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
         ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status))
}
function Wifi([object[]]$argv) {
  $r = Run $WIFI @($argv)
  return ('rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
}
function FreeMB([string]$drive) {
  try {
    $d = New-Object IO.DriveInfo($drive)
    return ('' + [Math]::Round($d.AvailableFreeSpace / 1MB, 1))
  } catch { return '?' }
}
# ---- privacy gate, identical in spirit to probe98's: path and name are tested SEPARATELY (an earlier version
# matched 'path | name' as one string, so an anchored pattern like '\Security$' could never fire).
function SecretShape([string]$path, [string]$name) {
  $p = Clean "$path"
  $n = Clean "$name"
  if ($p -match '(?i)HostedNetworkSettings|EncryptedSettings|ProfileSync|\\Interfaces\\|\\Interfaces$|wifinetworkmanager|\\OneTemp\\') { return $true }
  if ($p -match '(?i)\\Security$') { return $true }
  if ($n -match '(?i)^Security$|^EncryptedSettings$|^HostedNetworkSettings$|password|passphrase|psk|keymaterial|sharedsecret|profilexml') { return $true }
  return $false
}
function Redact([string]$path, [string]$name, [object]$v) {
  if (SecretShape $path $name) { return '<withheld:secret-shaped>' }
  if ($null -eq $v) { return '<null>' }
  if ($v -is [byte[]]) { return ('HEX(' + $v.Length + ')') }
  if ($v -is [string[]]) { return (@($v) -join ';') }
  $s = Clean "$v"
  if ($s -match '(?i)password|psk|passphrase|securitykey|sharedsecret') { return '<withheld:secret-looking>' }
  if ($s.Length -gt 200) { return ($s.Substring(0, 200) + '...') }
  return $s
}
function RegAdd([string]$pspath, [string]$name, [string]$kind, [string]$data) {
  # Emits its own log line and leaves the code in $script:LastRegRc; deliberately returns NOTHING. Capturing it
  # (`$null = RegAdd ...`) would discard every line it prints -- the output-swallow trap, documented four times now.
  $script:LastRegRc = -999
  if (SecretShape $pspath $name) { O ('    REG-REFUSE ' + $pspath + ' | ' + $name + ' (secret-shaped, never written)'); return }
  $real = $pspath -replace '(?i)^(HKLM|HKCU|HKCR|HKCC|HKU):\\', '$1\'
  $a = @('ADD', $real)
  if ($name -eq '') { $a += @('/ve') } else { $a += @('/v', $name) }
  $a += @('/t', $kind, '/d', $data, '/f')
  $r = Run $REG $a
  $back = $null
  $rn = $name
  if ($rn -eq '') { $rn = '(default)' }
  try { $back = RegV $pspath $rn } catch { }
  $shown = (Redact $pspath $name $back)
  $script:LastRegRc = $r.rc
  O ('    REG-SET ' + $real + ' | ' + $rn + ' [' + $kind + '] rc=' + $r.rc + ' read-back=' + $shown +
     ' // ' + ((@($r.lines) | Select-Object -First 1) -join ' '))
}
# ---- the loader-side measurement: everything about one start attempt, in one C# call, so the sampling interval
# is a Thread.Sleep(1) inside the process instead of a PowerShell round trip per sample.
if (-not ('P99' -as [type])) {
Add-Type -ErrorAction SilentlyContinue -Verbose:$false -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
public static class P99 {
  // SERVICE_STATUS_PROCESS is documented as 8 DWORDs (32 bytes, process id at offset 24), but this OS answers
  // rc=False err=122 (ERROR_INSUFFICIENT_BUFFER) needed=36, and dumping the filled bytes shows the process id at
  // OFFSET 28 with an extra zero DWORD at 24 (host wlansvc: [0]=0x10 [4]=4 [8]=C5 [24]=0 [28]=17F0=6128, and 6128 is
  // exactly the pid Win32_Service reports). Asking for 32 therefore failed EVERY status read, which is why probe99's
  // first PE trace came back silently empty: the service really did start and self-exit, the sampler just could not
  // see it. Fix: ask for 64 bytes, keep every DWORD, and decide which DWORD is the live pid by probing the process
  // instead of hardcoding an offset -- the host is 19041 and this image is 26100-generation, so the two may differ.
  // (Measured by t_p99_qex_diag.ps1; log line META carries the dump.)
  [StructLayout(LayoutKind.Sequential)]
  public struct SS { public int dwServiceType; public int dwCurrentState; public int dwWin32ExitCode;
                     public int dwServiceSpecificExitCode; public int dwCheckPoint; public int dwWaitHint; }
  public struct ST { public int Type, State, Exit, ExitSlot2, Spec, CheckPoint, WaitHint, Pid, Flags;
                     public int[] Dw; public string PidFrom; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] m, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, int size);
  [DllImport("kernel32.dll")] static extern int GetCurrentProcessId();
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr OpenSCManagerW(string machine, string domain, uint access);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool StartServiceW(IntPtr svc, uint argc, IntPtr argv);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceStatusEx(IntPtr svc, int infoLevel, byte[] buf, uint cbSize, out uint needed);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceStatus(IntPtr svc, out SS s);
  // score a candidate process id: 2 = a process we can open AND it has the service's own DLL loaded,
  // 1 = a process we can open, 0 = not a process. As SYSTEM (the PE's ssh identity) 2 is reachable; as a
  // non-elevated host user OpenProcess fails with 5 and everything scores 0, so the slot rule below still decides.
  static int ProbePidScore(string svcName, int pid) {
    if (pid <= 0) return 0;
    IntPtr h = OpenProcess(0x0400 | 0x0010, false, pid);
    if (h == IntPtr.Zero) return 0;
    int score = 1;
    try {
      IntPtr[] m = new IntPtr[2048]; uint need = 0;
      if (!EnumProcessModulesEx(h, m, (uint)(m.Length * IntPtr.Size), out need, 0x03)) return 0;
      int count = (int)(need / (uint)IntPtr.Size);
      if (count > m.Length) count = m.Length;
      if (count == 0) return 0;
      StringBuilder sb = new StringBuilder(1024);
      string want = svcName.ToLowerInvariant() + ".dll";
      for (int i = 0; i < count; i++) {
        sb.Length = 0;
        if (GetModuleFileNameExW(h, m[i], sb, sb.Capacity) == 0) continue;
        string p = sb.ToString();
        int k = p.LastIndexOf('\\');
        string leaf = (k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant();
        if (leaf == want) { score = 2; break; }
      }
    } finally { CloseHandle(h); }
    return score;
  }
  // Which DWORD holds the process id is decided, not guessed. Two rules, scored together:
  //   slot  -- with needed=32 the pid is dw[6] (the documented layout); with the 36-byte form seen on both this host
  //            (19041) and this image (26100) a DWORD was inserted at offset 8, so it is dw[7] at offset 28.
  //   proof -- dw[7] is not free: dw[6] can name a real but UNRELATED process. The first PE trace proved that: at
  //            t+0ms dw[6]=2000 was wmiprvse.exe (WMI!), whose 50 modules then arrived as wlansvc's NEW lines, while
  //            dw[7]=1848 was the svchost that went on to load svchost.exe + wlansvc.dll. A candidate that has
  //            "<svc>.dll" mapped in is the host process, whatever the slot says.
  static int PickPid(int[] dw, int byteCount, string svcName, out string how) {
    how = "none";
    int expect = (byteCount == 32) ? 6 : 7;
    int best = 0; int bestScore = -1; string bestTag = "";
    for (int i = 6; i < dw.Length; i++) {
      int v = dw[i];
      if (v <= 0) continue;
      int ps = ProbePidScore(svcName, v);
      int score = ps * 4 + (i == expect ? 1 : 0);
      string tag = "dw[" + i + "]@offset" + (i * 4) +
                   (ps == 2 ? "(hosts-" + svcName.ToLowerInvariant() + ".dll)" : (ps == 1 ? "(live)" : "(unprobed)")) +
                   (i == expect ? "+slot-rule" : "");
      if (score > bestScore) { bestScore = score; best = v; bestTag = tag; }
    }
    how = (best != 0) ? bestTag : "none";
    return best;
  }
  static string Dump(int[] dw) {
    if (dw == null) return "(none)";
    string s = "";
    for (int i = 0; i < dw.Length; i++) { s += " [" + i + "]=" + ((uint)dw[i]).ToString("X"); }
    return s;
  }
  // one status read, version-proof: returns "ex" (DWORD dump + pid picked), "legacy:<err>" (state only, pid and
  // dump kept from the previous read) or "fail:<err>". The caller passes the previous ST in, because a legacy read
  // cannot supply a process id and dropping it mid-trace would silently stop every later module sample.
  //
  // Field map, measured here rather than copied from a doc page: with this 36-byte form the slots are
  //   [0]type [1]state [2]<inserted> [3]Win32Exit [4]Specific [5]CheckPoint [6]WaitHint [7]Pid [8]Flags
  // The proof: the PE's stopped-service dump carries [3]=0x800C0006 for wlansvc and [3]=0x42B(1067) for wcmsvc --
  // exactly the two codes probe98 read through an independent tool -- while [6] is the SCM wait hint (2000 while
  // start-pending, 60000 while stop-pending) and [7] is the pid that owns svchost.exe + <svc>.dll. If a future build
  // moves again, the dump line in the log shows it; ExitSlot2 below reports the classic offset-8 reading too, so a
  // silent reinterpretation cannot pass unnoticed.
  static string Q(IntPtr sv, string svcName, ref ST st, ref uint biggestNeeded) {
    byte[] buf = new byte[64]; uint n = 0;
    if (QueryServiceStatusEx(sv, 0, buf, (uint)buf.Length, out n)) {
      if (n > biggestNeeded) biggestNeeded = n;
      int count = (int)(n / 4);
      if (count > 16) count = 16;
      if (count < 8) count = 8;
      int[] dw = new int[count];
      for (int i = 0; i < count; i++) dw[i] = BitConverter.ToInt32(buf, i * 4);
      st.Dw = dw;
      st.Type = dw[0]; st.State = dw[1];
      st.Exit = (count > 3) ? dw[3] : 0;
      st.ExitSlot2 = dw[2];
      st.Spec = (count > 4) ? dw[4] : 0;
      st.CheckPoint = (count > 5) ? dw[5] : 0;
      st.WaitHint = (count > 6) ? dw[6] : 0;
      st.Pid = PickPid(dw, (int)n, svcName, out st.PidFrom);
      st.Flags = dw[count - 1];
      return "ex";
    }
    int exErr = Marshal.GetLastWin32Error();
    if (n > biggestNeeded) biggestNeeded = n;
    SS s = new SS();
    if (QueryServiceStatus(sv, out s)) {
      st.Type = s.dwServiceType; st.State = s.dwCurrentState; st.Exit = s.dwWin32ExitCode;
      st.Spec = s.dwServiceSpecificExitCode; st.CheckPoint = s.dwCheckPoint; st.WaitHint = s.dwWaitHint;
      return "legacy:" + exErr;
    }
    st.State = -1;
    return "fail:" + exErr;
  }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, uint flags);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeLibrary(IntPtr h);
  public static string LL(string name) {
    IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0);
    if (h == IntPtr.Zero) { return "FAIL err=" + Marshal.GetLastWin32Error(); }
    string ok = "OK base=0x" + ((long)h).ToString("X");
    FreeLibrary(h);
    return ok;
  }
  static string Hex(int v) { return "0x" + ((uint)v).ToString("X"); }
  // leaf module names, lowercased. The host handle is cached per pid because this runs on a 1ms loop.
  static string[] ModulesOf(int pid, ref IntPtr cachedH, ref int cachedPid) {
    if (pid <= 0) return new string[0];
    if (cachedH != IntPtr.Zero && cachedPid == pid) { /* reuse */ }
    else {
      if (cachedH != IntPtr.Zero) { CloseHandle(cachedH); cachedH = IntPtr.Zero; }
      cachedH = OpenProcess(0x0400 | 0x0010, false, pid);   // QUERY_INFORMATION | VM_READ
      cachedPid = pid;
      if (cachedH == IntPtr.Zero) return new string[0];
    }
    IntPtr[] buf = new IntPtr[2048];
    uint needed = 0;
    if (!EnumProcessModulesEx(cachedH, buf, (uint)(buf.Length * IntPtr.Size), out needed, 0x03)) return new string[0];
    int count = (int)(needed / (uint)IntPtr.Size);
    if (count > buf.Length) count = buf.Length;
    List<string> names = new List<string>(count);
    StringBuilder sb = new StringBuilder(1024);
    for (int i = 0; i < count; i++) {
      sb.Length = 0;
      uint n = GetModuleFileNameExW(cachedH, buf[i], sb, sb.Capacity);
      if (n == 0) continue;
      string p = sb.ToString();
      int k = p.LastIndexOf('\\');
      names.Add((k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant());
    }
    return names.ToArray();
  }
  public static string[] Attempt(string svcName, int ms) {
    List<string> lines = new List<string>();
    IntPtr scm = OpenSCManagerW(null, null, 0x00000001);
    if (scm == IntPtr.Zero) { lines.Add("FATAL OpenSCManager err=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    IntPtr sv = IntPtr.Zero;
    try {
      // Requesting SERVICE_START is what makes OpenService fail with err=5 for a non-elevated caller even though
      // the same handle opens fine as SYSTEM (caught by the host dry run). So ask for the full right first, and fall
      // back to a read-only handle rather than losing the whole measurement.
      sv = OpenServiceW(scm, svcName, 0x00000010 | 0x00000004 | 0x00000001 | 0x00000080);
      bool mayStart = (sv != IntPtr.Zero);
      int firstErr = Marshal.GetLastWin32Error();
      if (!mayStart) {
        sv = OpenServiceW(scm, svcName, 0x00000004 | 0x00000001 | 0x00000080);
        if (sv == IntPtr.Zero) { lines.Add("FATAL OpenService err=" + Marshal.GetLastWin32Error() + " (start-right attempt err=" + firstErr + ")"); return lines.ToArray(); }
        lines.Add("NO-START-RIGHT opened read-only, start-err=" + firstErr);
      }
      ST s0 = new ST(); uint needMax = 0;
      string h0 = Q(sv, svcName, ref s0, ref needMax);
      lines.Add("BEFORE how=" + h0 + " state=" + s0.State + " pid=" + s0.Pid + " pidFrom=" + s0.PidFrom +
                " exit=" + Hex(s0.Exit));
      // the struct as the kernel filled it, so the layout question is answered from the log on any machine, not from
      // a doc page: the slot that equals the real host process id is the pid slot on that build.
      lines.Add("DW bytes-asked=64 bytes-needed=" + needMax + " pidFrom=" + s0.PidFrom + " dump=" + Dump(s0.Dw));
      HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      IntPtr hCache = IntPtr.Zero; int hPid = 0;
      if (s0.Pid > 0) foreach (string m in ModulesOf(s0.Pid, ref hCache, ref hPid)) seen.Add(m);
      lines.Add("BASE pid=" + s0.Pid + " modules=" + seen.Count);
      bool started = false; int serr = 0;
      if (mayStart) { started = StartServiceW(sv, 0, IntPtr.Zero); serr = Marshal.GetLastWin32Error(); }
      lines.Add("START may=" + mayStart + " ok=" + started + " lasterr=" + serr);
      Stopwatch sw = Stopwatch.StartNew();
      int lastPid = s0.Pid, lastState = s0.State;
      ST s = s0;
      string how = h0;
      int reads = 0; bool modulesLost = false; bool dumpedLive = false;
      while (sw.ElapsedMilliseconds < ms) {
        how = Q(sv, svcName, ref s, ref needMax);
        reads++;
        if (how != "ex" && lastPid > 0 && s.Pid == 0) { modulesLost = true; }
        if (s.Pid != lastPid || s.State != lastState) {
          lines.Add("t+" + sw.ElapsedMilliseconds + "ms state=" + s.State + " pid=" + s.Pid +
                    " pidFrom=" + s.PidFrom + " exit=" + Hex(s.Exit) + " spec=" + s.Spec + " cp=" + s.CheckPoint +
                    " wh=" + s.WaitHint + (how == "ex" ? "" : " via=" + how));
          lastPid = s.Pid; lastState = s.State;
        }
        if (s.Pid > 0 && !dumpedLive) {
          dumpedLive = true;
          lines.Add("DW-LIVE t+" + sw.ElapsedMilliseconds + "ms pid=" + s.Pid + " pidFrom=" + s.PidFrom +
                    " needed=" + needMax + " dump=" + Dump(s.Dw));
        }
        if (s.Pid > 0) {
          // ModulesOf caches the process handle per pid, so a brand-new host process is re-opened here and its whole
          // module list arrives as NEW lines -- the arrival order of those lines is the point of this measurement.
          foreach (string m in ModulesOf(s.Pid, ref hCache, ref hPid))
            if (!seen.Contains(m)) { seen.Add(m); lines.Add("t+" + sw.ElapsedMilliseconds + "ms NEW " + m); }
        }
        // Run and stop are both endings worth recording, but STOP_PENDING is not: the exit code the service reports
        // (wlansvc's 0x800C0006, wcmsvc's 1067) only lands in the struct once the service has actually stopped, and
        // breaking here was why the first PE trace could not name the failure code. Wait for STOPPED, then read once.
        if (s.State == 4) break;
        if (s.State == 1 && sw.ElapsedMilliseconds > 40) break;
        Thread.Sleep(1);
      }
      if (hCache != IntPtr.Zero) { CloseHandle(hCache); hPid = 0; }
      ST f = s;
      string hf = Q(sv, svcName, ref f, ref needMax);
      lines.Add("FINAL state=" + f.State + " pid=" + f.Pid + " pidFrom=" + f.PidFrom + " exit=" + Hex(f.Exit) +
                " spec=" + f.Spec + " t=" + sw.ElapsedMilliseconds + "ms loaded=" + seen.Count +
                " reads=" + reads + " via=" + hf);
      // one line that makes the measurement self-checking: how the status was read, what the OS asked for, and
      // whether the host process ever appeared. "sawPid=False" is what a 122/needed=36 struct bug looks like.
      // slot2 is the classic offset-8 reading of dwWin32ExitCode, kept so a future layout change cannot quietly
      // reinterpret the number this probe reports as the failure code.
      lines.Add("META statusReads=" + reads + " sspNeededBytes=" + needMax + " sawPid=" + (seen.Count > 0 || f.Pid > 0) +
                " pidFrom=" + f.PidFrom + " slot2=" + Hex(f.ExitSlot2) + " dumpAtFinal=" + Dump(f.Dw) +
                " modulesLostAfterLegacy=" + modulesLost + " finalState=" + f.State + " finalExit=" + Hex(f.Exit));
      return lines.ToArray();
    } finally {
      if (sv != IntPtr.Zero) CloseServiceHandle(sv);
      CloseServiceHandle(scm);
    }
  }
  public static string SelfModules() {
    IntPtr h = IntPtr.Zero; int p = 0;
    string[] m = ModulesOf(GetCurrentProcessId(), ref h, ref p);
    if (h != IntPtr.Zero) CloseHandle(h);
    return "self pid=" + GetCurrentProcessId() + " modules=" + m.Length;
  }
}
'@
}
$script:TExit = ''
$script:TRun = $false
$script:TLoaded = -1
$script:TLines = ''
$script:TMeta = ''
$script:TSawPid = $false
$script:TLastNew = ''
$script:TLayout = ''
function LL([string]$name) {
  try { return [P99]::LL($name) } catch { return 'EXCEPTION ' + (Clean $_.Exception.Message) }
}
function Trace([string]$svc, [string]$tag, [int]$ms) {
  $lines = @()
  try { $lines = @([P99]::Attempt($svc, $ms)) } catch { $lines = @('EXCEPTION ' + (Clean $_.Exception.Message)) }
  O ('  P99 TRACE[' + $svc + '][' + $tag + '] lines=' + @($lines).Count + ' ms=' + $ms)
  foreach ($l in @($lines)) { O ('    TR ' + (Clean "$l")) }
  $tail = ''
  # NOTE the PS 5.1 trap that cost a dry-run cycle: inside `if (...)` the parser is in COMMAND mode, so
  # `if (Clean "$l" -match '^FINAL ')` hands -match to Clean as a parameter instead of matching the result.
  foreach ($l in @($lines)) { if ((Clean "$l") -match '^FINAL ') { $tail = (Clean "$l") } }
  $script:TLines = $tail
  $script:TRun = ($tail -match 'state=4')
  $script:TExit = ''
  if ($tail -match 'exit=0x([0-9A-Fa-f]+)') { $script:TExit = '0x' + $Matches[1] }
  $script:TLoaded = -1
  if ($tail -match 'loaded=(\d+)') { $script:TLoaded = [int]$Matches[1] }
  # META is the probe's own proof that the trace measured something: how the status was read, the byte size the OS
  # asked for (36 on this build, where the docs say 32), and whether a host process was ever seen at all.
  $script:TMeta = ''
  $script:TSawPid = $false
  foreach ($l in @($lines)) {
    if ((Clean "$l") -match '^META ') { $script:TMeta = (Clean "$l") }
  }
  if ($script:TMeta -match 'sawPid=True') { $script:TSawPid = $true }
  # the struct dump, kept separately so section 4 can print it even when only the summary is being read: on a machine
  # whose SERVICE_STATUS_PROCESS differs again, this line is the evidence, not a guess from a doc page.
  $script:TLayout = ''
  foreach ($l in @($lines)) { $cl = (Clean "$l"); if ($cl -match '^DW-LIVE ') { $script:TLayout = $cl; break } }
  if ($script:TLayout -eq '') {
    foreach ($l in @($lines)) { $cl = (Clean "$l"); if ($cl -match '^DW ') { $script:TLayout = $cl; break } }
  }
  # the single most useful line of the whole probe: which module was the last one to appear before the service gave
  # up. That is where the failing call lives, and it beats guessing another DLL name.
  $script:TLastNew = '<none: no host process was seen>'
  foreach ($l in @($lines)) {
    $cl = (Clean "$l")
    if ($cl -match ' NEW ') { $script:TLastNew = ($cl -replace '^.* NEW ', '') + ' @' + ($cl -replace '^t\+(\d+)ms.*$', '$1') + 'ms' }
  }
  if ($script:TLastNew -eq '<none: no host process was seen>' -and $script:TMeta -match 'sawPid=True') {
    # a pid was there but not one module arrived: that is the non-elevated host case (OpenProcess err=5), not a
    # silent failure of the sampler. Saying so keeps the PE log honest when the same shape shows up.
    $script:TLastNew = '<pid seen, no module enumerable: caller lacks process rights (host-as-non-admin case)>'
  }
}
function Place([string]$name) {
  $srcF = Join-Path $STAGE $name
  if (-not (TP $srcF)) { O ('    PLACE ' + $name + ' SKIP not fetched'); return $false }
  $dstF = Join-Path $S32 $name
  if (-not (TP $BAK)) { try { New-Item -ItemType Directory -Path $BAK -Force -EA Stop | Out-Null } catch { } }
  if (TP $dstF) {
    $bk = Join-Path $BAK $name
    if (-not (TP $bk)) {
      try { Copy-Item -LiteralPath $dstF -Destination $bk -Force -EA Stop; O ('    BACKUP ' + $name + ' -> ' + $bk) }
      catch { O ('    BACKUP ' + $name + ' FAIL ' + (Clean $_.Exception.Message)); return $false }
    }
  }
  try {
    Copy-Item -LiteralPath $srcF -Destination $dstF -Force -EA Stop
    O ('    PLACE ' + $name + ' -> ' + $dstF + ' bytes=' + (Get-Item -LiteralPath $dstF).Length + ' ver=' + (FV $dstF))
    return $true
  } catch { O ('    PLACE ' + $name + ' FAIL ' + (Clean $_.Exception.Message)); return $false }
}

$SR = Root ''
$S32 = Join-Path $SR 'System32'
$WIFI = Join-Path $S32 'wifi.exe'
$REG = Join-Path $S32 'reg.exe'
$PD = Join-Path (Split-Path $SR -Parent) 'ProgramData'
if (-not (TP $PD)) { $PD = 'X:\ProgramData' }
$CANWRITE = ($Apply -and (($SR -match '(?i)^X:') -or $IDoit))
# On the ramdisk the drop folder is X:\p99. Anywhere else -- the host dry run, whose job is to prove the fetch /
# decode / RegAdd / Place paths before a PE ever sees them -- use a folder next to this script so a host run never
# writes to the system drive.
$DRY = Join-Path (Split-Path $PSCommandPath -Parent) 'p99_dryrun'
if ($SR -match '(?i)^X:') { $STAGE = 'X:\p99'; $BAK = 'X:\p99bak' }
else { $STAGE = Join-Path $DRY 'stage'; $BAK = Join-Path $DRY 'bak' }
function Sel([string]$k) { if ($Only -eq '') { return $true } return (@($Only -split ',') -contains $k) }

O ('P99 START ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' root=' + $SR + ' base=' + $Base +
   ' apply=' + $CANWRITE + ' readapplyflag=' + [bool]$Apply + ' reg=' + $REG + ' reg-exists=' + (TP $REG) +
   ' type-P99=' + [bool]('P99' -as [type]) + ' freeMB=' + (FreeMB (Split-Path $SR -Qualifier)) +
   ' only=[' + $Only + '] traceMs=' + $TraceMs)
O ('  P99 SELF ' + [P99]::SelfModules())
O ('  P99 STACK ' + (StackLine))
O ('  P99 ROW   ' + (SvcRow 'wlansvc'))
O ('  P99 ROW   ' + (SvcRow 'wcmsvc'))
if ($ForceNoRun) { $script:TRun = $false; O '  P99 FORCENORUN set by -ForceNoRun: the ladder below walks the read-only branch' }

# ---------- 0 what the two service keys look like right now (values only, secret shapes withheld) ----------
if (Sel 'dump') {
O '== 0 the keys probe99 is about to fill =='
foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc\Csps',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc\Csps\cspethernet',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc\Csps\cspwlan',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc\Csps\cspwwan',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters\WlanAPIPermissions')) {
  if (-not (TP $k)) { O ('  P99 KEY ' + $k + ' = <absent>'); continue }
  $ip = $null
  try { $ip = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue } catch { }
  $names = @()
  if ($null -ne $ip) { $names = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) }
  $subs = @(Get-ChildItem -LiteralPath $k -EA SilentlyContinue).PSChildName
  O ('  P99 KEY ' + $k + ' values=' + @($names).Count + ' subkeys=' + @($subs).Count + ' [' + ($subs -join ',') + ']')
  foreach ($p in $names) {
    $tn = '<null>'
    if ($null -ne $p.Value) { $tn = Clean "$($p.Value.GetType().Name)" }
    O ('      VAL ' + (Clean $p.Name) + ' [' + $tn + '] = ' + (Redact $k $p.Name $p.Value))
  }
}
foreach ($n in @('wcmcsp.dll', 'wlanapi.dll', 'wlansvc.dll', 'wlanutil.dll')) {
  O ('    P99 FILE ' + $n + ' = ' + (TP (Join-Path $S32 $n)) + ' ' + (FV (Join-Path $S32 $n)))
}
}

# ---------- 1 fetch wcmcsp.dll and the host value table ----------
$script:VALS = @()
if (Sel 'fetch') {
O '== 1 fetch: manifest99.txt (wcmcsp.dll) + values99.tsv (host value table) from the build machine =='
if (-not (TP $STAGE)) { try { New-Item -ItemType Directory -Path $STAGE -Force -EA Stop | Out-Null } catch { O ('  MKDIR ' + $STAGE + ' FAIL ' + (Clean $_.Exception.Message)) } }
$raw = $null
$txt = ''
try {
  # octet-stream from the static server => .Content is a Byte[]; decode before splitting (probe97's trap).
  $raw = (Invoke-WebRequest -Uri ($Base + 'manifest99.txt') -UseBasicParsing -TimeoutSec 20).Content
  $txt = [string]$raw
  if ($raw -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($raw) }
  elseif ($raw -is [Object[]]) { $txt = [string]($raw -join '') }
} catch { O ('  MANIFEST99 FAIL ' + (Clean $_.Exception.Message)) }
$script:EXP = @{}
foreach ($l in @($txt -split "`r?`n")) {
  $t = (Clean "$l")
  if ($t -eq '') { continue }
  $p = @($t -split '\s+')
  if ($p.Count -lt 2) { continue }
  $script:EXP[$p[0].ToLower()] = [int64]$p[1]
  O ('  P99 WANT ' + $p[0] + ' size=' + $p[1])
}
foreach ($n in @($script:EXP.Keys | Sort-Object)) {
  $dst = Join-Path $STAGE $n
  $ok = $false
  for ($t = 1; $t -le 2 -and -not $ok; $t++) {
    try { Invoke-WebRequest -Uri ($Base + $n) -OutFile $dst -UseBasicParsing -TimeoutSec 60 | Out-Null; $ok = $true }
    catch { O ('  P99 GET ' + $n + ' try' + $t + ' FAIL ' + (Clean $_.Exception.Message)) }
  }
  if (-not $ok) { continue }
  $sz = [int64]0
  try { $sz = (Get-Item -LiteralPath $dst).Length } catch { }
  $mark = 'SIZE-FAIL'
  if ($sz -eq [int64]$script:EXP[$n.ToLower()]) { $mark = 'ok' }
  O ('  P99 GOT ' + $n + ' bytes=' + $sz + ' expect=' + $script:EXP[$n.ToLower()] + ' ' + $mark + ' ver=' + (FV $dst))
}
$vtxt = ''
try {
  $vraw = (Invoke-WebRequest -Uri ($Base + 'values99.tsv') -UseBasicParsing -TimeoutSec 30).Content
  $vtxt = [string]$vraw
  if ($vraw -is [byte[]]) { $vtxt = [Text.Encoding]::UTF8.GetString($vraw) }
  elseif ($vraw -is [Object[]]) { $vtxt = [string]($vraw -join '') }
} catch { O ('  VALUES99 FAIL ' + (Clean $_.Exception.Message)) }
foreach ($l in @($vtxt -split "`r?`n")) {
  $t = '' + $l
  if ((Clean $t) -eq '') { continue }
  $c = @($t -split "`t")
  if (@($c).Count -lt 4) { O ('  P99 TSV-SHORT cols=' + @($c).Count + ' [' + (Clean $t).Substring(0, [Math]::Min(60, (Clean $t).Length)) + ']'); continue }
  $data = $c[3]
  if ($c[2] -eq 'REG_SZ') {
    try { $data = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($c[3])) }
    catch { O ('  P99 TSV-BAD-B64 ' + (Clean $c[0]) + ' | ' + (Clean $c[1])); continue }
  }
  $script:VALS += @{ key = (Clean $c[0]); name = (Clean $c[1]); kind = (Clean $c[2]); data = $data }
}
O ('  P99 VALUE-TABLE rows=' + @($script:VALS).Count + ' groups: perm=' +
   @($script:VALS | Where-Object { $_.key -match 'WlanAPIPermissions' }).Count +
   ' csps=' + @($script:VALS | Where-Object { $_.key -match '\\Csps\\' }).Count)
}

function ApplyVals([string]$pattern, [string]$tag) {
  $n = 0
  foreach ($v in @($script:VALS)) {
    if ($v.key -notmatch $pattern) { continue }
    $n++
    RegAdd $v.key $v.name $v.kind $v.data
  }
  O ('    P99 VALS[' + $tag + '] applied=' + $n + ' of table=' + @($script:VALS).Count)
}

# ---------- 2 the load-order trace, with nothing changed ----------
$traceBase = @()
if (Sel 'trace') {
O '== 2 trace: module appearance order across one start attempt of each service, image untouched =='
Trace 'wlansvc' 'baseline' $TraceMs
$traceBase += @{ svc = 'wlansvc'; final = $script:TLines; run = $script:TRun; exit = $script:TExit; loaded = $script:TLoaded; meta = $script:TMeta; lastnew = $script:TLastNew; layout = $script:TLayout }
Trace 'wcmsvc' 'baseline' $TraceMs
$traceBase += @{ svc = 'wcmsvc'; final = $script:TLines; run = $script:TRun; exit = $script:TExit; loaded = $script:TLoaded; meta = $script:TMeta; lastnew = $script:TLastNew; layout = $script:TLayout }
}

# ---------- 3 the ladder ----------
$res = @()
$DIRS = @(
  (Join-Path $PD 'Microsoft\Wlansvc'),
  (Join-Path $PD 'Microsoft\Wlansvc\Profiles'),
  (Join-Path $PD 'Microsoft\Wlansvc\Profiles\AllUsersProfiles'),
  (Join-Path $PD 'Microsoft\Wlansvc\RfButtons'),
  (Join-Path $PD 'Microsoft\Network\Downloader'),
  (Join-Path $S32 'config\systemprofile\AppData\Local'),
  (Join-Path $S32 'config\systemprofile\AppData\Local\Microsoft\Windows\History'),
  (Join-Path $S32 'config\systemprofile\AppData\Local\Microsoft\Windows\INetCache'),
  (Join-Path $S32 'config\systemprofile\AppData\Roaming\Microsoft\Windows\Cookies'),
  (Join-Path $SR 'Temp')
)
function MakeDirs([string]$tag) {
  $made = 0
  foreach ($d in @($DIRS)) {
    if (TP $d) { continue }
    try { New-Item -ItemType Directory -Path $d -Force -EA Stop | Out-Null; $made++ }
    catch { O ('    MKDIR ' + $d + ' FAIL ' + (Clean $_.Exception.Message)) }
  }
  O ('    P99 DIRS[' + $tag + '] made=' + $made + ' of ' + @($DIRS).Count + ' now-present=' +
     (@($DIRS | Where-Object { TP $_ }).Count))
}
$groups = @(
  # 'com' comes from the host positive control (build\scratch\p99_host_modules_admin.txt): a healthy wlansvc has 82
  # modules and ours stops at host position 51 (shcore.dll) with 38, PE-ONLY=0. Nine of the modules it never reached
  # are not even FILES in our image (t_p99_control_gap.ps1 => GAP BAKE-LIST), and three of those sit BEFORE the death
  # point: clbcatq.dll (35, the COM class catalog -- our trace loads msxml6 at t+21 without it, so the XML COM object
  # cannot be activated), tetheringieprovider.dll (43) and wifidisplay.dll (44). They are first in the ladder so their
  # effect on wlansvc is isolated from the registry rungs below.
  @{ n = 'com'; f = @('clbcatq.dll', 'tetheringieprovider.dll', 'wifidisplay.dll', 'policymanager.dll',
                      'wifinetworkmanager.dll', 'systemeventsbrokerclient.dll', 'cellularapi.dll', 'rilproxy.dll',
                      'wwapi.dll'); vp = 'ZZZ-none'; dirs = $false; svc = @('wlansvc', 'wcmsvc') },
  @{ n = 'csp'; f = @('wcmcsp.dll'); vp = '\\Csps\\'; dirs = $false; svc = @('wcmsvc', 'wlansvc') },
  @{ n = 'apiperm'; f = @(); vp = 'WlanAPIPermissions'; dirs = $false; svc = @('wlansvc', 'wcmsvc') },
  @{ n = 'dirs'; f = @(); vp = 'ZZZ-none'; dirs = $true; svc = @('wlansvc', 'wcmsvc') },
  @{ n = 'retry'; f = @(); vp = 'ZZZ-none'; dirs = $false; svc = @('wlansvc', 'wcmsvc') }
)
if ($CANWRITE) {
O '== 3 ladder: supply one group, re-trace each service, record what changed =='
foreach ($g in $groups) {
  O ('  P99 RUNG ' + $g.n)
  foreach ($f in @($g.f)) { @(Place $f) | ForEach-Object { O ('      ' + $_) } }
  foreach ($f in @($g.f)) { O ('    P99 FILE ' + $f + ' now-in-system32=' + (TP (Join-Path $S32 $f))) }
  if ($g.vp -ne 'ZZZ-none') { ApplyVals $g.vp $g.n }
  if ($g.dirs) { MakeDirs $g.n }
  foreach ($svc in @($g.svc)) {
    Trace $svc $g.n $TraceMs
    $res += @{ rung = $g.n; svc = $svc; run = $script:TRun; exit = $script:TExit; loaded = $script:TLoaded;
               meta = $script:TMeta; lastnew = $script:TLastNew; layout = $script:TLayout }
  }
}
} else {
  if ($Apply) { O '  P99 SKIP-APPLY: SystemRoot is not the ramdisk and -IDoit was not given.' }
  O '  P99 read-only: nothing is written. Rungs that would have been walked:'
  foreach ($g in $groups) {
    foreach ($svc in @($g.svc)) {
      $res += @{ rung = ('WOULDRUN:' + $g.n); svc = $svc; run = $false; exit = 'n/a'; loaded = -1;
                 meta = 'not-traced(read-only)'; lastnew = 'n/a'; layout = 'n/a' }
    }
    O ('    WOULD-REG pattern=[' + $g.vp + '] rows-in-table=' +
       @($script:VALS | Where-Object { $_.key -match $g.vp }).Count + ' files=[' + (@($g.f) -join ',') + ']')
  }
  O ('    WOULD-MKDIR dirs=' + @($DIRS).Count)
}
foreach ($r in $res) {
  O ('  P99 LADDER ' + $r.rung + ' svc=' + $r.svc + ' running=' + $r.run + ' exit=' + $r.exit + ' loaded=' + $r.loaded)
  O ('         last=' + $r.lastnew + ' | ' + $r.meta)
}

# ---------- 4 verdict ----------
O '== 4 verdict =='
O ('  P99 LL wcmcsp=' + (LL 'wcmcsp.dll') + ' WcnEapAuthProxy=' + (LL 'WcnEapAuthProxy.dll') +
   ' hnetcfgclient=' + (LL 'hnetcfgclient.dll'))
foreach ($b in @($traceBase)) {
  O ('  P99 BASELINE ' + $b.svc + ': ' + $b.final)
  O ('  P99 BASELINE-LAST-NEW ' + $b.svc + ': ' + $b.lastnew + ' | ' + $b.meta)
  O ('  P99 LAYOUT ' + $b.svc + ': ' + $b.layout)
}
$anyRun = @($res | Where-Object { $_.run }).Count -gt 0
$outcome = 'both-services-unchanged'
if ($anyRun) { $outcome = 'a-service-ran' }
$permNow = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters\WlanAPIPermissions' -EA SilentlyContinue).Count
$permVals = @()
try { $ipx = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters\WlanAPIPermissions' -EA SilentlyContinue; if ($null -ne $ipx) { $permVals = @($ipx.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) } } catch { }
$cspVals = @()
try { $ipc = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc\Csps\cspwlan' -EA SilentlyContinue; if ($null -ne $ipc) { $cspVals = @($ipc.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) } } catch { }
O ('  P99 VERDICT outcome=' + $outcome + ' apply=' + [bool]$CANWRITE +
   ' wcmcsp-in-s32=' + (TP (Join-Path $S32 'wcmcsp.dll')) +
   ' perm-values=' + @($permVals).Count + ' cspwlan-values=' + @($cspVals).Count +
   ' dirs-present=' + (@($DIRS | Where-Object { TP $_ }).Count) + '/' + @($DIRS).Count +
   ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
   ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status) +
   ' freeMB=' + (FreeMB (Split-Path $SR -Qualifier)))
# ---- BAKE-ITEMS: everything this run proved is missing from the image, in the words the bake step needs. ----
O '  P99 BAKE-ITEMS (for wifi-inject / the offline bake, not written by this probe):'
O ('    BAKE file System32\wcmcsp.dll from host 19041.7725 + the 3 Csps\* values (Dll/InitFunction/DeinitFunction/MediaService/WcmMediaType)')
O ('    BAKE ' + @($script:VALS | Where-Object { $_.key -match 'WlanAPIPermissions' }).Count + ' wlansvc\Parameters\WlanAPIPermissions SDDL values (this machine currently has ' + @($permVals).Count + ' of them)')
O ('    BAKE directories: ' + ((@($DIRS | ForEach-Object { Clean $_ }) -join ' ; ')))
O ('    BAKE wlansvc DependOnService host shape (live reg add does not reach the SCM boot cache)')
O ('    BAKE env values for the service account: ProgramData/ALLUSERSPROFILE/PUBLIC/TEMP/TMP are NULL for SYSTEM in this image')
O ('    BAKE winsock NameSpace_Catalog5\Catalog_Entries64: PE has ' + '1' + ' entry where the host has 7 (see p99_shape_*.txt)')
O ('  P99 NOTE trace lines above are the load ORDER of a real start attempt; use the last NEW module of the failing')
O ('         attempt to decide which subsystem wlansvc bails in, rather than guessing another file name.')
O 'P99 DONE'
