# probe114 -- the complete ordered module list of a failing wlansvc host, diffed position-by-position
# against the healthy host's 82-module init sequence, plus a FormatMessage hunt for 0x800C0006.
#
# Why this probe exists (what every previous probe threw away):
#   probe99/110/111/112/113 all printed only the LAST 6-8 modules of the trace, and the one aggregate
#   they proved is "pe-only-modules=0" (probe110 S6): every module we load is a module the host loads.
#   That is a set statement. The sequence is the actual signal, and the 6-item tail already shows the
#   sequence is NOT a prefix of the host's: our tail is
#     ntasn1(29) -> mobilenetworking(69) -> wlansvcpal(32) -> oleaut32(33) -> msxml6(35) -> wmiclnt(49)
#   (indices in the host's order) -- i.e. the PE reaches into the host's *late* group (mobilenetworking)
#   while still stopping short of clbcatq(34)/crypt32(36)/dpapi(37)/authz(41)/wifidisplay(43). So the
#   real question is which host step comes first that we never do, and that needs the whole list.
#   Falsified so far, so this is the last structural axis left: files/DLL gap (probe110 S6 = 0),
#   env dirs+keys (probe111), device objects (probe111 S1), service-record shape (probe112 R1-R5,
#   byte-identical traces), WinRE Parameters subtree (probe113 M2/M3 -- 21 entries written and read
#   back natively, trace unchanged), auth-side services (probe111 R2/R3).
#
# Second thing this probe does, cheaply, because nobody has: turn the service-specific exit code into
# text. wlansvc reports 0x800C0006 through SetServiceStatus(dwWin32ExitCode=ERROR_SERVICE_SPECIFIC_ERROR,
# dwServiceSpecificExitCode=0x800C0006), and the service DLLs carry message tables. FormatMessageW with
# FORMAT_MESSAGE_FROM_HMODULE over {wlansvc,wlanmsm,wlansec,wlancfg,wlansvcpal}.exe/dll for the codes
# {0x800C0006, 0x0006, 0xC006, 0x000C0006} may name the failure outright -- the SCM itself resolves the
# 0x800C0006 code via the module, which is how "System error 6" got printed in the 10-12 field log.
#
# Output: ASCII lines prefixed P114. Read-only apart from starting/stopping wlansvc.
param([switch]$DryRun, [string]$Root = 'X:\Windows\System32')
function L([string]$s) { Write-Output ('P114 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = $Root

# The healthy host's wlansvc svchost module load order, verbatim from probe110 (taken by
# build\scratch\t_p110_host82.ps1 on a working wlansvc; index = position in this array).
$hostOrder = @(
  'svchost.exe', 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'sechost.dll', 'rpcrt4.dll', 'bcrypt.dll',
  'ucrtbase.dll', 'combase.dll', 'kernel.appcore.dll', 'msvcrt.dll', 'bcryptprimitives.dll', 'user32.dll',
  'win32u.dll', 'gdi32.dll', 'gdi32full.dll', 'msvcp_win.dll', 'wlansvc.dll', 'dhcpcsvc6.dll', 'ws2_32.dll',
  'advapi32.dll', 'dnsapi.dll', 'onex.dll', 'wlanmsm.dll', 'nsi.dll', 'ncrypt.dll', 'iphlpapi.dll',
  'eappprxy.dll', 'wlansec.dll', 'dhcpcsvc.dll', 'ntasn1.dll', 'wldp.dll', 'wlansvcpal.dll', 'oleaut32.dll',
  'clbcatq.dll', 'msxml6.dll', 'crypt32.dll', 'dpapi.dll', 'cryptbase.dll', 'cryptsp.dll', 'rsaenh.dll',
  'authz.dll', 'tetheringieprovider.dll', 'wifidisplay.dll', 'cfgmgr32.dll', 'devobj.dll', 'sspicli.dll',
  'mswsock.dll', 'wmiclnt.dll', 'wlgpclnt.dll', 'shcore.dll', 'gpapi.dll', 'dsrole.dll', 'sysntfy.dll',
  'wtsapi32.dll', 'winsta.dll', 'usermgrcli.dll', 'powrprof.dll', 'umpdc.dll', 'policymanager.dll',
  'msvcp110_win.dll', 'kerberos.dll', 'userenv.dll', 'msasn1.dll', 'wifinetworkmanager.dll', 'ole32.dll',
  'systemeventsbrokerclient.dll', 'mobilenetworking.dll', 'wlanapi.dll', 'profapi.dll', 'cellularapi.dll',
  'rilproxy.dll', 'windows.storage.dll', 'shlwapi.dll', 'wwapi.dll', 'nlaapi.dll', 'netsetupshim.dll',
  'setupapi.dll', 'netsetupapi.dll', 'devrtl.dll', 'firewallapi.dll', 'fwbase.dll')

$src = @'
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Pe114 {
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
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern int FormatMessageW(uint flags, IntPtr src, uint code, uint lang, StringBuilder buf,
      uint size, IntPtr args);
  [DllImport("wlanapi.dll", EntryPoint = "WlanOpenHandle")]
  static extern int WlanOpenConnection(uint ver, IntPtr res, out uint neg, out IntPtr h);
  [DllImport("wlanapi.dll")] static extern int WlanEnumInterfaces(IntPtr h, IntPtr res, out IntPtr list);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr p);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr h, IntPtr res);

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
  const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
  const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000, FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;

  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 4 ? "RUNNING" : ("state" + st);
  }
  // The point of this probe is the ORDER, so the list is returned in first-seen order and is never
  // re-sorted. Poll at 1ms like probe112 so a 125ms lifetime still yields ~100 samples.
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
  static string Flat(string s) {
    return s.Replace("\r", " ").Replace("\n", " ").Trim();
  }
  // Message-table hunt for the service-specific exit code. Datafile load = no DllMain, no side effects.
  public static string Msg(uint code, string modPath) {
    StringBuilder sb = new StringBuilder(512);
    IntPtr h = LoadLibraryExW(modPath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
    int r = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE, h, code, 0, sb, (uint)sb.Capacity, IntPtr.Zero);
    string hs = h == IntPtr.Zero ? ("h=" + Marshal.GetLastWin32Error()) : "h=ok";
    if (h != IntPtr.Zero) FreeLibrary(h);
    if (r == 0) return "none (" + hs + " fmerr=" + Marshal.GetLastWin32Error() + ")";
    return "[" + Flat(sb.ToString()) + "]";
  }
  public static string SysMsg(uint code) {
    StringBuilder sb = new StringBuilder(512);
    int r = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, IntPtr.Zero, code, 0, sb, (uint)sb.Capacity, IntPtr.Zero);
    if (r == 0) return "none fmerr=" + Marshal.GetLastWin32Error();
    return "[" + Flat(sb.ToString()) + "]";
  }
  public static string WlanCount() {
    uint neg = 0; IntPtr h = IntPtr.Zero;
    int r = WlanOpenConnection(2, IntPtr.Zero, out neg, out h);
    if (r != 0) return "OPEN hr=0x" + ((uint)r).ToString("X8");
    try {
      IntPtr list = IntPtr.Zero;
      int e = WlanEnumInterfaces(h, IntPtr.Zero, out list);
      if (e != 0) return "ENUM hr=0x" + ((uint)e).ToString("X8");
      try { return "nif=" + Marshal.ReadInt32(list, 0); } finally { WlanFreeMemory(list); }
    } finally { WlanCloseHandle(h, IntPtr.Zero); }
  }
}
'@

if ($DryRun) {
  L('DRY probe114: start wlansvc, poll at 1ms for up to 3s, print EVERY module in first-seen order,')
  L('DRY  then diff each name against the healthy host order (' + $hostOrder.Count + ' entries) by index:')
  L('DRY  S2 FIRST-MISSING = the lowest-index host module we never load; S2 MAX-REACHED = the highest host')
  L('DRY  index we do load; S2 SKIPS lists host modules with index < MAX-REACHED that are absent.')
  L('DRY S3 FormatMessage for 0x800C0006 / 6 / 0xC006 against wlansvc.dll, wlanmsm.dll, wlansec.dll,')
  L('DRY  wlancfg.dll, wlansvcpal.dll (datafile loads) plus the system table.')
  L('DRY S4 wlanapi interface count before/after. No registry writes, no file copies, disc untouched.')
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1 hostOrder=' + $hostOrder.Count)
  exit 0
}
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)) }
L('probe114 begin native=' + $native + ' host-order=' + $hostOrder.Count + ' root=[' + (C $s32) + ']')
if (-not $native) { L('ABORT: no native class, nothing to measure'); exit 1 }

$wl = ''
try { $wl = [Pe114]::WlanCount() } catch { $wl = 'EXCEPTION ' + (C $_.Exception.Message) }
L('S0 before ' + $wl)

$lines = @()
try { $lines = @([Pe114]::FullTrace('wlansvc', 3000)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
foreach ($l in @($lines)) { L('S1 ' + (C "$l")) }

$mods = @(@($lines) | Where-Object { (C "$_") -match '^MOD ' } | ForEach-Object { (C "$_") -replace '^MOD \d+ ', '' })
$set = @{}
foreach ($m in $mods) { $set[$m] = $true }
L('S2 count=' + @($mods).Count)
$peIdx = @{}
for ($i = 0; $i -lt $hostOrder.Count; $i++) { $peIdx[('' + $hostOrder[$i]).ToLower()] = $i }
$maxReached = -1
foreach ($m in $mods) { if ($peIdx.ContainsKey($m) -and $peIdx[$m] -gt $maxReached) { $maxReached = $peIdx[$m] } }
$missing = @()
for ($i = 0; $i -lt $hostOrder.Count; $i++) {
  $h = ('' + $hostOrder[$i]).ToLower()
  if (-not $set.ContainsKey($h)) { $missing += ($i.ToString('00') + ':' + $h) }
}
$firstMissing = ''
for ($i = 0; $i -lt $hostOrder.Count; $i++) {
  if (-not $set.ContainsKey(('' + $hostOrder[$i]).ToLower())) { $firstMissing = ('' + $i + ':' + $hostOrder[$i]); break }
}
$skipsBefore = @()
for ($i = 0; $i -le $maxReached -and $i -lt $hostOrder.Count; $i++) {
  if (-not $set.ContainsKey(('' + $hostOrder[$i]).ToLower())) { $skipsBefore += ('' + $hostOrder[$i]) }
}
$extras = @()
foreach ($m in $mods) { if (-not $peIdx.ContainsKey($m)) { $extras += $m } }
L('S2 max-host-index-reached=' + $maxReached + ' [' + $(if ($maxReached -ge 0) { $hostOrder[$maxReached] } else { 'none' }) + ']')
L('S2 first-missing=' + $firstMissing)
L('S2 skips-before-max=' + @($skipsBefore).Count + ' [' + (@($skipsBefore) -join ',') + ']')
L('S2 missing-total=' + @($missing).Count + ' [' + (@($missing) -join ',') + ']')
L('S2 pe-not-in-host=' + @($extras).Count + ' [' + (@($extras) -join ',') + ']')

foreach ($m in @('wlansvc.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlancfg.dll', 'wlansvcpal.dll')) {
  $p = Join-Path $s32 $m
  if (-not (Test-Path -LiteralPath $p)) { L('S3 SKIP ' + $m + ' absent'); continue }
  foreach ($code in @(0x800C0006, 0x00000006, 0x0000C006)) {
    $r = ''
    try { $r = [Pe114]::Msg($code, $p) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
    L('S3 ' + $m + ' code=0x' + ('{0:X8}' -f [uint32]$code) + ' -> ' + (C $r))
  }
}
$sysr = ''
try { $sysr = [Pe114]::SysMsg(0x800C0006) } catch { $sysr = 'EXCEPTION ' + (C $_.Exception.Message) }
L('S3 SYSTEM table 0x800C0006 -> ' + (C $sysr))
$sysr2 = ''
try { $sysr2 = [Pe114]::SysMsg(6) } catch { $sysr2 = 'EXCEPTION ' + (C $_.Exception.Message) }
L('S3 SYSTEM table 6 -> ' + (C $sysr2))

$wl2 = ''
try { $wl2 = [Pe114]::WlanCount() } catch { $wl2 = 'EXCEPTION ' + (C $_.Exception.Message) }
L('S4 after ' + $wl2)
L('probe114 end -- judgement: first-missing + skips-before-max say which host init step we never reach')
