# ============================================================
# probe110_last_four_and_order_diff.ps1 -- finish the late-bound batch and read wlansvc's death point in HOST ORDER
# ============================================================
#   probe109 put 11 of the 15 missing runtime modules into System32 and the result was mixed but decisive:
#     * wcmsvc went RUNNING for the first time (state=4 win32=0 pid=2440) -- it was 1067 every time before.
#     * wlansvc still exits on its own: 0x800C0006 at ~130 ms, loaded=36 (probe99 baseline said 38).
#   Two defects in probe109 kept the rest of the answer from being read, and both are fixed here:
#     (1) S2's import gate tested each staged file against System32 as it stood BEFORE the batch was copied,
#         so a file whose dependency was another member of the same batch failed its own gate. That is exactly
#         what skipped the four we care about most: cellularapi (->rilproxy,wsplib), policymanager
#         (->dmenterprisediagnostics), systemeventsbrokerclient (->BiWinrt), wifinetworkmanager
#         (->policymanager,SystemEventsBrokerClient). The universe is now System32 UNION batch.
#     (2) Tr() filtered NEW lines with the outer foreach variable instead of $_, so module-lines always
#         printed 0 and the arrival order -- the part worth more than the exit code -- was thrown away.
#   What this probe answers in one run: after all 15 are in place, how far does wlansvc get along the
#   healthy host's 82-module load order, and which host-order modules does it not reach? Each gap is
#   annotated in_s32 -- a gap with in_s32=False is a NEW file gap to borrow (the next batch), one with
#   in_s32=True means the file is there and wlansvc simply died before getting to it.
#   Files stay staged at X:\p109 (RAM disk; nothing on the disc is touched). Output: single-line ASCII, P110.
param([switch]$DryRun, [string]$Stage = 'X:\p109', [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P110 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

# The whole probe109 batch, and the four its gate wrongly refused.
$want = @('BiWinrt.dll', 'cellularapi.dll', 'clbcatq.dll', 'cmintegrator.dll', 'dmenterprisediagnostics.dll',
          'npmproxy.dll', 'policymanager.dll', 'rilproxy.dll', 'systemeventsbrokerclient.dll',
          'tetheringieprovider.dll', 'wifidisplay.dll', 'wifinetworkmanager.dll', 'wlgpclnt.dll',
          'wsplib.dll', 'wwapi.dll')
$left = @('cellularapi.dll', 'policymanager.dll', 'systemeventsbrokerclient.dll', 'wifinetworkmanager.dll')
# Services wlansvc depends on (host shape: DEPENDON [nativewifip,RpcSs,Ndisuio,wcmsvc]) -- a dep that is not
# Running is a legitimate reason for an early exit, so read them next to the trace.
$deps = @('nativewifip', 'RpcSs', 'Ndisuio', 'wcmsvc', 'Dhcp', 'LanmanServer')
# Host load order of a healthy wlansvc (build\scratch\p99_host_modules_admin.txt, ORD 1..82, verbatim).
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

public static class Pe110 {
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
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
  // LOAD_WITH_ALTERED_SEARCH_PATH: resolve the file's own imports the way the loader would for a service DLL.
  const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x8;

  static IntPtr Open(string name, uint access) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) return IntPtr.Zero;
    try { return OpenServiceW(sm, name, access); } finally { CloseServiceHandle(sm); }
  }
  // SERVICE_STATUS_PROCESS is 36 bytes on this build (probe99 measured needed=36): state@4, win32exit@12, pid@28.
  public static string Status(string name) {
    IntPtr sv = Open(name, SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      IntPtr buf = Marshal.AllocHGlobal(36);
      try {
        uint need = 0;
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) return "QSS_ERR=" + Marshal.GetLastWin32Error();
        int st = Marshal.ReadInt32(buf, 4);
        int w32 = Marshal.ReadInt32(buf, 12);
        uint pid = (uint)Marshal.ReadInt32(buf, 28);
        string sn = st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
                    st == 4 ? "RUNNING" : ("state" + st);
        return sn + " win32=" + w32 + " pid=" + pid;
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  // Does this file actually load in this image? An import parser cannot answer that (it misses delay +
  // resource + api-set subtleties); the loader can, and a failed LoadLibrary is the honest pre-copy verdict.
  public static string LoadLib(string path) {
    IntPtr h = LoadLibraryExW(path, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "ERR=" + Marshal.GetLastWin32Error();
    CloseHandle(h);
    return "OK";
  }
  static string[] ModulesOf(int pid, ref IntPtr cachedH, ref int cachedPid) {
    if (pid <= 0) return new string[0];
    if (cachedH == IntPtr.Zero || cachedPid != pid) {
      if (cachedH != IntPtr.Zero) { CloseHandle(cachedH); }
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
      uint n = GetModuleFileNameExW(cachedH, buf[i], sb, (uint)sb.Capacity);
      if (n == 0) continue;
      string p = sb.ToString();
      int k = p.LastIndexOf('\\');
      names.Add((k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant());
    }
    return names.ToArray();
  }
  // One start attempt traced at 1 ms, in ARRIVAL ORDER (that order is what maps onto the host's 82).
  public static string[] Trace(string svc, int ms) {
    List<string> lines = new List<string>();
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) { lines.Add("SCM_ERR=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
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
        string sn = state == 1 ? "STOPPED" : state == 2 ? "START_PENDING" : state == 3 ? "STOP_PENDING" :
                    state == 4 ? "RUNNING" : ("state" + state);
        if (sn != lastState) {
          lastState = sn;
          lines.Add("t+" + sw.ElapsedMilliseconds + "ms " + sn + " win32=" + win32 + " pid=" + pid);
        }
        if (pid > 0) {
          foreach (string m in ModulesOf((int)pid, ref hCache, ref hPid))
            if (!seen.Contains(m)) { seen.Add(m); order.Add(m); lines.Add("t+" + sw.ElapsedMilliseconds + "ms NEW " + m); }
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
        int fstate = Marshal.ReadInt32(fb, 4);
        int fwin32 = Marshal.ReadInt32(fb, 12);
        uint fpid = (uint)Marshal.ReadInt32(fb, 28);
        fin = "FINAL state=" + fstate + " win32=" + fwin32 +
              " win32hex=0x" + ((uint)fwin32).ToString("X8") + " pid=" + fpid;
      } else { fin = "FINAL QSS_ERR=" + Marshal.GetLastWin32Error(); }
      Marshal.FreeHGlobal(fb);
      lines.Add("START=" + sr);
      lines.Add(fin + " loaded=" + seen.Count + " t=" + sw.ElapsedMilliseconds + "ms");
      foreach (string m in order) lines.Add("MOD " + m);
      return lines.ToArray();
    } finally {
      CloseServiceHandle(sv); CloseServiceHandle(scm);
    }
  }
  public static string Ping() { return "Pe110 ping ok"; }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe110 begin native=' + $native + ' dryrun=' + $DryRun + ' stage=[' + (C $Stage) +
  '] host-order modules=' + $hostOrder.Count)

# ---------- S0 stage + current placement ----------
$s32 = $Root
$staged = @()
foreach ($n in $want) {
  $p = Join-Path $Stage $n
  if (Test-Path -LiteralPath $p) { $staged += $n; continue }
  L('S0 STAGE-MISSING ' + $n)
}
foreach ($n in @($left)) {
  $d = Join-Path $s32 $n
  L('S0 left ' + $n + ' staged=' + (@($staged) -contains $n) + ' in_s32=' + (Test-Path -LiteralPath $d))
}
L('S0 staged=' + (@($staged).Count) + '/' + $want.Count)
if ($DryRun) {
  L('S1 SKIPPED (DryRun)'); L('S2 SKIPPED (DryRun)'); L('S3 SKIPPED (DryRun)'); L('S4 SKIPPED (DryRun)')
  L('S5 SKIPPED (DryRun): a trace stops and starts wlansvc, which -DryRun must never do')
  L('S6 SKIPPED (DryRun): the order diff needs the trace')
  L('S7 deps would be read read-only: ' + ($deps -join ','))
  L('probe110 end (DryRun)'); exit 0
}

# ---------- S1 live file list, rebuilt here ----------
$have = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $s32 -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $s32 'en-US') -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Split-Path $s32 -Parent) -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
L('S1 live dll count=' + $have.Count + ' batch-in-s32=' +
  (@($want | Where-Object { $have.ContainsKey($_.ToLower()) }).Count) + '/' + $want.Count)

# ---------- S2 import gate; universe = System32 UNION batch (the probe109 bug) ----------
function Get-Imports([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
  if ([BitConverter]::ToInt16($bytes, $e_lfanew) -ne 0x4550) { throw 'not a PE image' }
  $opt = $e_lfanew + 4 + 20
  $is64 = ([BitConverter]::ToUInt16($bytes, $opt) -eq 0x20B)
  $ddOff = $opt + ($(if ($is64) { 112 } else { 96 }))
  $numSec = [BitConverter]::ToUInt16($bytes, $e_lfanew + 6)
  $sizeOpt = [BitConverter]::ToUInt16($bytes, $e_lfanew + 20)
  $secOff = $e_lfanew + 4 + 20 + $sizeOpt
  $secs = @()
  for ($i = 0; $i -lt $numSec; $i++) {
    $so = $secOff + $i * 40
    $secs += @{ va = [BitConverter]::ToUInt32($bytes, $so + 12); vs = [BitConverter]::ToUInt32($bytes, $so + 8);
                ra = [BitConverter]::ToUInt32($bytes, $so + 20) }
  }
  function RvaToOff([uint32]$rva) {
    foreach ($s in $secs) { if ($rva -ge $s.va -and $rva -lt ($s.va + $s.vs)) { return [int]($rva - $s.va + $s.ra) } }
    return -1
  }
  $dlls = @()
  foreach ($dir in @(@(1, 20), @(13, 32))) {
    $rva = [BitConverter]::ToUInt32($bytes, $ddOff + $dir[0] * 8)
    if ($rva -eq 0) { continue }
    $p = RvaToOff $rva
    if ($p -lt 0) { continue }
    for ($k = 0; $k -lt 200; $k++) {
      $attrs = [BitConverter]::ToUInt32($bytes, $p + 0)
      $nameRva = $(if ($dir[1] -eq 20) { [BitConverter]::ToUInt32($bytes, $p + 12) }
                   else { [BitConverter]::ToUInt32($bytes, $p + 4) })
      if ($dir[1] -eq 20) {
        $o1 = [BitConverter]::ToUInt32($bytes, $p + 0); $f1 = [BitConverter]::ToUInt32($bytes, $p + 16)
        if ($nameRva -eq 0 -and $o1 -eq 0 -and $f1 -eq 0) { break }
      } else {
        if ($nameRva -eq 0 -or $attrs -eq 0xFFFFFFFF) { break }
      }
      $o = RvaToOff $nameRva
      if ($o -ge 0) {
        $sb = New-Object System.Text.StringBuilder
        $j = $o
        while ($j -lt $bytes.Length -and $bytes[$j] -ne 0) { [void]$sb.Append([char]$bytes[$j]); $j++ }
        $dlls += $sb.ToString()
      }
      $p += $dir[1]
    }
  }
  return @($dlls)
}
$univ = @{}
foreach ($k in $have.Keys) { $univ[$k] = 1 }
foreach ($n in @($staged)) { $univ[$n.ToLower()] = 1 }
$ok4 = @()
foreach ($n in @($left)) {
  $p = Join-Path $Stage $n
  if (-not (Test-Path -LiteralPath $p)) { L('S2 NO-FILE ' + $n); continue }
  $id = @()
  try { $id = @(Get-Imports $p) } catch { L('S2 PARSE-FAIL ' + $n + ' ' + (C $_.Exception.Message)); continue }
  $miss = @()
  foreach ($d in @($id | Sort-Object -Unique)) {
    $dl = ('' + $d).ToLower()
    if ($dl -like 'api-ms-*' -or $dl -like 'ext-ms-*') { continue }
    if ($dl -eq $n.ToLower()) { continue }
    if (-not $univ.ContainsKey($dl)) { $miss += $d }
  }
  L('S2 ' + $n + ' imports=' + (@($id | Sort-Object -Unique).Count) + ' missing-vs-univ=' + @($miss).Count +
    $(if (@($miss).Count) { ' [' + (@($miss) -join ';') + ']' } else { '' }))
  if (@($miss).Count -eq 0) { $ok4 += $n } else { L('  S2 GATE-FAIL ' + $n) }
}
L('S2 gate-pass=' + (@($ok4).Count) + '/' + (@($left).Count))

# ---------- S3 copy the remaining ones ----------
foreach ($n in @($ok4)) {
  $dstp = Join-Path $s32 $n
  if (Test-Path -LiteralPath $dstp) { L('S3 HAVE-SKIP ' + $n); continue }
  $r = 'copied'
  try { Copy-Item -LiteralPath (Join-Path $Stage $n) -Destination $dstp -Force -EA Stop }
  catch { $r = 'FAILED ' + (C $_.Exception.Message) }
  L('S3 COPY ' + $n + ' -> ' + $r + ' exists=' + (Test-Path -LiteralPath $dstp))
}
$inplace = @($want | Where-Object { Test-Path -LiteralPath (Join-Path $s32 $_) })
L('S3 in-system32-of-batch=' + (@($inplace).Count) + '/' + $want.Count + ' [' + (@($inplace) -join ';') + ']')

# ---------- S4 loader check on every batch member now in System32 ----------
if ($native) {
  foreach ($n in @($inplace)) {
    L('S4 LOADLIB ' + $n + ' -> ' + [Pe110]::LoadLib((Join-Path $s32 $n)))
  }
} else { L('S4 skipped: native class unavailable') }

# ---------- S5 trace ----------
function Tr([string]$svc, [string]$tag, [int]$ms, [switch]$Dump) {
  $script:LastMod = @()
  if (-not $native) { L('TRACE ' + $svc + ' skipped: native class did not compile'); return }
  $lines = @()
  try { $lines = @([Pe110]::Trace($svc, $ms)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
  $fin = ''; $sr = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^FINAL ') { $fin = (C "$l") } }
  foreach ($l in @($lines)) { if ((C "$l") -match '^START=') { $sr = (C "$l") } }
  # ($_ and not $l: probe109 filtered on the stale outer loop variable and always counted 0)
  $news = @(@($lines) | Where-Object { (C "$_") -match '^MOD ' } | ForEach-Object { (C "$_") -replace '^MOD ', '' })
  if (@($news).Count) { $script:LastMod = @($news) }
  L('TRACE ' + $svc + ' [' + $tag + '] ' + $sr + ' | ' + $fin + ' | mod-lines=' + @($news).Count)
  $states = @(@($lines) | Where-Object { (C "$_") -match '^t\+' -and (C "$_") -notmatch ' NEW ' })
  foreach ($s in @($states)) { L('  ' + (C "$s")) }
  if ($Dump) {
    $i = 0
    foreach ($m in @($news)) { $i++; L('  SEQ ' + $i + ' ' + (C $m)) }
  } else {
    $tail = @($news | Select-Object -Last 8)
    L('  tail=' + (@($tail) -join ','))
  }
}
if ($native) {
  foreach ($d in @($deps)) { L('S5 DEP ' + $d + ' ' + [Pe110]::Status($d)) }
}
Tr 'wlansvc' 'A full dump' 3000 -Dump
$wl = @($script:LastMod)
Tr 'wlansvc' 'B reproducibility' 3000
$wb = @($script:LastMod)
L('S5 reproducibility A=' + @($wl).Count + ' B=' + @($wb).Count + ' same-order=' +
  ((@($wl) -join ',') -eq (@($wb) -join ',')))
Tr 'wcmsvc' 'C after the 4' 3000

# ---------- S6 host-order diff ----------
if (@($wl).Count -gt 0) {
  $got = @{}
  foreach ($m in @($wl)) { $got[('' + $m).ToLower()] = 1 }
  $gaps = @(); $maxOrd = 0
  for ($i = 0; $i -lt $hostOrder.Count; $i++) {
    $h = $hostOrder[$i]
    if (-not $got.ContainsKey($h.ToLower())) {
      $inS = Test-Path -LiteralPath (Join-Path $s32 $h)
      $gaps += ($h + '|ord' + ($i + 1) + '|in_s32=' + $inS)
    } else { $maxOrd = $i + 1 }
  }
  L('S6 reached up to host ORD ' + $maxOrd + ' / ' + $hostOrder.Count)
  L('S6 gaps-vs-host-order=' + @($gaps).Count)
  foreach ($g in @($gaps)) { L('  GAP ' + (C $g)) }
  $extra = @(@($wl) | Where-Object { $hostOrder -notcontains $_ })
  L('S6 pe-only-modules=' + (@($extra).Count) + $(if (@($extra).Count) { ' [' + (@($extra) -join ';') + ']' } else { '' }))
  $newFileGap = @($gaps | Where-Object { $_ -match 'in_s32=False' })
  L('S6 NEW-FILE-GAP=' + (@($newFileGap).Count) + $(if (@($newFileGap).Count) { ' -> next borrow: [' +
    ((@($newFileGap) | ForEach-Object { ('' + $_).Split('|')[0] }) -join ';') + ']' } else { ' (every host module exists in the image)' }))
} else { L('S6 skipped: no module set was captured') }

# ---------- S7 final read-only statuses ----------
if ($native) { L('S7 wlansvc ' + [Pe110]::Status('wlansvc') + ' | wcmsvc ' + [Pe110]::Status('wcmsvc')) }
L('probe110 end -- compare ORD/gaps with probe109 (11 files, loaded=36, 0x800C0006) and probe99 (38 modules)')
