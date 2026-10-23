# ============================================================
# probe109_late_bound_modules.ps1 -- supply the DLLs a healthy wlansvc loads that this image does not have
# ============================================================
#   Every earlier "are the files there?" check asked the wrong question. probe107 parsed the PE import
#   tables of wcmsvc/wcmcsp/wlansvc/wdi/wlanmsm in the live image -- static AND delay -- and the answer was
#   MISSING=0, which is why the file layer looked closed. But wlansvc does not reach its failure through an
#   import: it LoadLibrarys whole subsystems at runtime, and those names are invisible to an import parser.
#   The authority for that set is the module list of a HEALTHY wlansvc, captured with admin on the build PC
#   (build\scratch\p99_host_modules_admin.txt, ORD 1..82). The PE's wlansvc host stopped at 38 modules and
#   exited 0x800C0006, so whatever it needed past that point it never got.
#   Diffing the host's 82 runtime modules against the live image, name by name with `if exist` (not against
#   an old saved list -- that list was from a different disc and gave false "present" answers), yields 15
#   files this image does not have, 4,457,864 bytes in total:
#     BiWinrt.dll  cellularapi.dll  clbcatq.dll  cmintegrator.dll  dmenterprisediagnostics.dll
#     npmproxy.dll  policymanager.dll  rilproxy.dll  systemeventsbrokerclient.dll
#     tetheringieprovider.dll  wifidisplay.dll  wifinetworkmanager.dll  wlgpclnt.dll  wsplib.dll  wwapi.dll
#   (Three of them are not leaf files: dmenterprisediagnostics/BiWinrt/wsplib are pulled in by
#    policymanager/systemeventsbrokerclient/cellularapi, which is why they are pushed in the same batch.)
#   These 15 files are staged at X:\p109 by build\scratch\t_p109_push_all.ps1 before this probe runs; X: is
#   a RAM disk, so a live-PE experiment costs nothing on the disc. If wlansvc then survives, the same names
#   go into wifi-inject.ps1's $files list and get baked.
#
#   SECTIONS
#     S0 inventory of the staged batch (what actually arrived, size + version)
#     S1 live image file list, rebuilt here rather than trusted from a previous run
#     S2 import gate per staged file: static(dir 1) + delay(dir 13) against S1 -- a file whose own imports
#        cannot be satisfied would turn STATUS_DLL_NOT_FOUND into a new failure mode and pollute the result
#     S3 copy every gate-passing file into System32 (never overwrite an existing file)
#     S4 trace wlansvc three times and wcmsvc once with the probe99 instrument (1 ms status polling +
#        psapi module enumeration of the transient host process), printing arrival order
#     S5 the full module set the last wlansvc host reached, sorted, for the local diff against the host's 82
#   Output: single-line ASCII, prefix P109.
param([switch]$DryRun, [string]$Stage = 'X:\p109', [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P109 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$want = @('BiWinrt.dll', 'cellularapi.dll', 'clbcatq.dll', 'cmintegrator.dll', 'dmenterprisediagnostics.dll',
          'npmproxy.dll', 'policymanager.dll', 'rilproxy.dll', 'systemeventsbrokerclient.dll',
          'tetheringieprovider.dll', 'wifidisplay.dll', 'wifinetworkmanager.dll', 'wlgpclnt.dll',
          'wsplib.dll', 'wwapi.dll')

$src = @'
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Pe109 {
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

  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;

  static IntPtr Open(string name, uint access) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) return IntPtr.Zero;
    try { return OpenServiceW(sm, name, access); } finally { CloseServiceHandle(sm); }
  }
  // SERVICE_STATUS_PROCESS is 36 bytes on this build (the docs say 32; probe99 measured needed=36 and the
  // legacy 32-byte read truncated the pid). state@4, win32exit@12, specific@16, pid@28.
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
  // One start attempt traced at 1 ms: status transitions, the module set of the transient host process in
  // arrival order, and the exit code once the service has really stopped (that is when dwWin32ExitCode lands).
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
            if (!seen.Contains(m)) { seen.Add(m); lines.Add("t+" + sw.ElapsedMilliseconds + "ms NEW " + m); }
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
      foreach (string m in seen) lines.Add("MOD " + m);
      return lines.ToArray();
    } finally {
      CloseServiceHandle(sv); CloseServiceHandle(scm);
    }
  }
  public static string Ping() { return "Pe109 ping ok"; }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe109 begin native=' + $native + ' dryrun=' + $DryRun + ' stage=[' + (C $Stage) + ']')

# ---------- S0 what arrived ----------
$arrived = @()
foreach ($n in $want) {
  $p = Join-Path $Stage $n
  if (-not (Test-Path -LiteralPath $p)) { L('S0 STAGE-MISSING ' + $n); continue }
  $i = Get-Item -LiteralPath $p
  $arrived += $n
  L('S0 STAGED ' + $n + ' bytes=' + $i.Length + ' ver=' + (C ('' + $i.VersionInfo.FileVersion)))
}
L('S0 staged=' + (@($arrived).Count) + '/' + $want.Count)
if ($DryRun) { L('probe109 end (DryRun: only the stage inventory was read)'); exit 0 }

# ---------- S1 live file list ----------
$s32 = $Root
$have = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $s32 -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $s32 'en-US') -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Split-Path $s32 -Parent) -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
L('S1 live dll count=' + $have.Count + ' already-present-of-batch=' +
  (@($want | Where-Object { $have.ContainsKey($_.ToLower()) }) -join ','))

# ---------- S2 import gate ----------
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
$pass = @()
foreach ($n in @($arrived)) {
  $p = Join-Path $Stage $n
  $id = @()
  try { $id = @(Get-Imports $p) } catch { L('S2 PARSE-FAIL ' + $n + ' ' + (C $_.Exception.Message)); continue }
  $miss = @()
  foreach ($d in @($id | Sort-Object -Unique)) {
    $dl = ('' + $d).ToLower()
    if ($dl -like 'api-ms-*' -or $dl -like 'ext-ms-*') { continue }
    if ($dl -eq $n.ToLower()) { continue }
    if (-not $have.ContainsKey($dl)) { $miss += $d }
  }
  L('S2 ' + $n + ' imports=' + (@($id | Sort-Object -Unique).Count) + ' missing=' + @($miss).Count +
    $(if (@($miss).Count) { ' [' + (@($miss) -join ';') + ']' } else { '' }))
  if (@($miss).Count -eq 0) { $pass += $n } else { L('  GATE-FAIL ' + $n) }
}
L('S2 gate-pass=' + (@($pass).Count) + '/' + (@($arrived).Count))

# ---------- S3 copy into System32 ----------
foreach ($n in @($pass)) {
  $srcp = Join-Path $Stage $n
  $dstp = Join-Path $s32 $n
  if (Test-Path -LiteralPath $dstp) { L('S3 HAVE-SKIP ' + $n); continue }
  $r = 'copied'
  try { Copy-Item -LiteralPath $srcp -Destination $dstp -Force -EA Stop } catch { $r = 'FAILED ' + (C $_.Exception.Message) }
  L('S3 COPY ' + $n + ' -> ' + $r + ' exists=' + (Test-Path -LiteralPath $dstp))
}
$inplace = @($want | Where-Object { Test-Path -LiteralPath (Join-Path $s32 $_.ToLower()) })
L('S3 in-system32-of-batch=' + (@($inplace).Count) + '/' + $want.Count + ' [' + (@($inplace) -join ';') + ']')

# ---------- S4 trace ----------
function Tr([string]$svc, [string]$tag, [int]$ms, [int]$maxLines) {
  if (-not $native) { L('TRACE ' + $svc + ' skipped: native class did not compile'); return }
  $lines = @()
  try { $lines = @([Pe109]::Trace($svc, $ms)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
  $fin = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^FINAL ') { $fin = (C "$l") } }
  $sr = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^START=') { $sr = (C "$l") } }
  $news = @(@($lines) | Where-Object { (C "$l") -match ' NEW ' })
  L('TRACE ' + $svc + ' [' + $tag + '] ' + $sr + ' | ' + $fin + ' | module-lines=' + @($news).Count)
  foreach ($l in ($news | Select-Object -Last $maxLines)) { L('  ' + (C "$l")) }
}
Tr 'wlansvc' 'R1 after batch copy' 3000 12
Tr 'wlansvc' 'R2 reproducibility' 3000 6
Tr 'wcmsvc' 'R1 after batch copy' 3000 8
Tr 'wlansvc' 'R3 final' 3000 60
L('probe109 end -- compare R1..R3 loaded= against the 38-module PE baseline and the 82-module host set')
