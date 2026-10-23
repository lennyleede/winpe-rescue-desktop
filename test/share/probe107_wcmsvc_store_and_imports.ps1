# ============================================================
# probe107_wcmsvc_store_and_imports.ps1 -- attack wcmsvc's 1067 from two sides
# ============================================================
#   probe106 (live, same boot) produced three facts that redirect the whole investigation:
#     1) The DBWIN/debug-channel instrument is worthless here: svchost -d produced 0 lines for all four
#        services, and each child had ALREADY EXITED before we tried to kill it (KILL_ERR=5 on a dead
#        process handle). svchost does not use OutputDebugString, so nothing more comes from that channel.
#     2) The WLAN stack in this PE is 19041.7725 (wlansvc/wcmsvc/wcmcsp/wlanapi/wlanmsm) while wdi.dll is
#        10.0.26100.1 -- the ADK base's own copy. And `wifiprofiles.dll` is ABSENT.
#     3) Session Manager\Environment has NO ProgramData, NO ALLUSERSPROFILE, NO PUBLIC and NO SystemRoot,
#        and the two directories wcmsvc keeps its state in are missing:
#          X:\ProgramData\Microsoft\WcmSvc                              = False
#          X:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WcmSvc = False
#   Why this matters more than the WDI hosts: the healthy host reference (build\scratch\host_wdi_shape_ref.txt)
#   shows wlansvc's DependOnService = nativewifip;RpcSs;Ndisuio;**wcmsvc**. Our wlansvc carries the WinRE
#   dependency list (no wcmsvc) because WinRE has no wcmsvc at all -- but our wlansvc.dll is NOT WinRE's
#   19041.3636-era binary, it is 19041.7725, and probe105 proved wlansvc exits with 0x800C0006 whether or not
#   the WDI hosts run. wcmsvc, on the other hand, demonstrably gets somewhere: it reaches RUNNING at 93 ms and
#   dies at ~377 ms with 1067 (ERROR_PROCESS_ABORTS = the process went away without reporting a stop). A store
#   path that resolves to nothing is exactly the shape of failure that produces.
#   So this probe takes the two cheap shots at 1067 and measures them with the 36-byte SERVICE_STATUS_PROCESS
#   curve, then re-measures wlansvc behind it:
#     E1  create the missing state directories, start wcmsvc again.
#     E2  start mpssvc (BFE is up, mpssvc is not) and start wcmsvc again.
#     E3  whatever wcmsvc now does, start wlansvc again -- that is the service the whole task is about.
#   Plus S2, which needs no reboot and closes the file layer for good: parse the PE headers of
#   wcmsvc/wcmcsp/wlansvc/wdi/wlanmsm in the live image, static AND delay imports, and check every name
#   against the live System32 listing.
#   Output: single-line ASCII, prefix P107.
param([switch]$DryRun, [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P107 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Runtime.InteropServices;
public static class Pe107 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr Svc, int InfoLevel, IntPtr Buf, uint Size, out uint Needed);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  static IntPtr Open(string name, uint access) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return IntPtr.Zero; }
    try { return OpenServiceW(sm, name, access); } finally { CloseServiceHandle(sm); }
  }
  public static string Start(string name) {
    IntPtr sv = Open(name, SERVICE_START | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try { return StartServiceW(sv, 0, IntPtr.Zero) ? "START_OK" : ("START_ERR=" + Marshal.GetLastWin32Error()); }
    finally { CloseServiceHandle(sv); }
  }
  public static string Status(string name) {
    IntPtr sv = Open(name, SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr buf = Marshal.AllocHGlobal(36);
      try {
        uint need = 0;
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) { return "QSS_ERR=" + Marshal.GetLastWin32Error(); }
        int state = Marshal.ReadInt32(buf, 4);
        int win32 = Marshal.ReadInt32(buf, 12);
        uint pid = (uint)Marshal.ReadInt32(buf, 28);
        string sn = state == 1 ? "STOPPED" : state == 2 ? "START_PENDING" : state == 3 ? "STOP_PENDING" :
                    state == 4 ? "RUNNING" : ("state" + state);
        return sn + " win32=" + win32 + " pid=" + pid;
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  public static string Ping() { return "Pe107 ping ok"; }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe107 begin native=' + $native + ' dryrun=' + $DryRun)

function Curve([string]$n, [string]$tag) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = 'no-native'
  if ($native) { $r = [Pe107]::Start($n) }
  $t0 = $sw.ElapsedMilliseconds
  $seen = @(); $runMs = -1; $err = -1
  while ($sw.ElapsedMilliseconds -lt 6000) {
    $s = ''
    if ($native) { $s = [Pe107]::Status($n) }
    if ($s -match 'RUNNING' -and $runMs -lt 0) { $runMs = $sw.ElapsedMilliseconds - $t0 }
    if ($s -match 'win32=(\d+)' -and [int]$Matches[1] -ne 0 -and $err -lt 0) { $err = [int]$Matches[1] }
    if (@($seen).Count -eq 0 -or ("$($seen[-1])" -replace '^\d+ms ', '') -ne $s) {
      $seen += (($sw.ElapsedMilliseconds - $t0).ToString() + 'ms ' + $s)
    }
    Start-Sleep -Milliseconds 60
  }
  L('CURVE ' + $n + ' [' + $tag + '] start=' + $r + ' running_at=' + $runMs + 'ms first_err=' + $err +
    ' states=[' + (($seen | Select-Object -First 6) -join ' -> ') + ']')
}

# ---------- S1 the live file list, used as the reference for every import check below ----------
# $Root is parameterised so the same parser can be dry-run against a healthy Windows install on the build PC
# before it costs a field round-trip (the -SelfTest convention used by every other tool here).
$s32 = $Root
$have = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $s32 -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $s32 'en-US') -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($d in @((Split-Path $s32 -Parent), (Join-Path $s32 'Downlevel'), (Join-Path $s32 'DriverStore\FileRepository'))) {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter '*.dll' -File -Recurse -Depth 1 -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
}
L('S1 root=[' + (C $s32) + '] dlls=' + $have.Count)

# ---------- S2 PE-header import parse, static (dir 1) and delay (dir 13) ----------
function Get-Imports([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
  if ([BitConverter]::ToInt16($bytes, $e_lfanew) -ne 0x4550) { throw 'not a PE image' }
  $opt = $e_lfanew + 4 + 20
  $magic = [BitConverter]::ToUInt16($bytes, $opt)
  $is64 = ($magic -eq 0x20B)
  $ddOff = $opt + $(if ($is64) { 112 } else { 96 })
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
  function ReadAnsi([int]$off) {
    if ($off -lt 0 -or $off -ge $bytes.Length) { return '' }
    $sb = New-Object System.Text.StringBuilder; $j = $off
    while ($j -lt $bytes.Length -and $bytes[$j] -ne 0) { [void]$sb.Append([char]$bytes[$j]); $j++ }
    return $sb.ToString()
  }
  $static = @(); $delay = @()
  # directory 1 = imports, 13 = delay imports
  $descOff = RvaToOff ([BitConverter]::ToUInt32($bytes, $ddOff + 8))
  $p = $descOff
  for ($k = 0; $k -lt 250; $k++) {
    if ($p + 20 -gt $bytes.Length) { break }
    $origThunk = [BitConverter]::ToUInt32($bytes, $p + 0)
    $nameRva = [BitConverter]::ToUInt32($bytes, $p + 12)
    $firstThunk = [BitConverter]::ToUInt32($bytes, $p + 16)
    if ($nameRva -eq 0 -and $origThunk -eq 0 -and $firstThunk -eq 0) { break }
    $static += (ReadAnsi (RvaToOff $nameRva))
    $p += $(if ($is64) { 20 } else { 40 })
  }
  $dOff = RvaToOff ([BitConverter]::ToUInt32($bytes, $ddOff + 13 * 8))
  $q = $dOff
  for ($k = 0; $k -lt 250; $k++) {
    if ($q + 32 -gt $bytes.Length) { break }
    $attr = [BitConverter]::ToUInt32($bytes, $q + 0)
    $dllNameRva = [BitConverter]::ToUInt32($bytes, $q + 4)
    if ($dllNameRva -eq 0) { break }
    # RVAs are section-relative only when the resource-directory form is used (bit 31 of Attributes).
    $rn = $dllNameRva
    if (($attr -band 0x80000000) -ne 0) {
      $secsIdx = ($dllNameRva -band 0xFFFF); $off = ($dllNameRva -shr 16)
      if ($secsIdx -ge 1 -and $secsIdx -le $secs.Count) { $rn = $secs[$secsIdx - 1].va + $off }
    }
    $delay += (ReadAnsi (RvaToOff $rn))
    $q += 32
  }
  return @{ static = @($static | Where-Object { $_ -ne '' } | Sort-Object -Unique);
            delay = @($delay | Where-Object { $_ -ne '' } | Sort-Object -Unique) }
}
$files = @('wcmsvc.dll', 'wcmcsp.dll', 'wlansvc.dll', 'wdi.dll', 'wlanmsm.dll', 'wlanutil.dll')
foreach ($f in $files) {
  $p = Join-Path $s32 $f
  if (-not (Test-Path -LiteralPath $p)) { L('S2 ' + $f + ' ABSENT'); continue }
  $r = $null
  try { $r = Get-Imports $p } catch { L('S2 ' + $f + ' PARSE-FAIL ' + (C $_.Exception.Message)) }
  if (-not $r) { continue }
  $ms = @(); $md = @()
  foreach ($d in $r.static) { $dl = $d.ToLower(); if ($dl -like 'api-ms-*' -or $dl -like 'ext-ms-*' -or $dl -like 'ntdll*') { continue }
    if (-not $have.ContainsKey($dl)) { $ms += $d } }
  foreach ($d in $r.delay) { $dl = $d.ToLower(); if ($dl -like 'api-ms-*' -or $dl -like 'ext-ms-*') { continue }
    if (-not $have.ContainsKey($dl)) { $md += $d } }
  L('S2 ' + $f + ' static=' + @($r.static).Count + ' delay=' + @($r.delay).Count +
    ' MISSING-static=[' + ($ms -join ';') + '] MISSING-delay=[' + ($md -join ';') + ']')
  if (@($md).Count -gt 0) { L('  S2-DELAY ' + $f + ' -> ' + ($md -join ';')) }
}

if ($DryRun) { L('probe107 end (DryRun: file layer only, no directory writes and no service starts)'); exit 0 }

# ---------- E1 the state directories wcmsvc has nowhere to put anything ----------
$dirs = @('X:\ProgramData\Microsoft\WcmSvc', 'X:\ProgramData\Microsoft\Wlansvc',
          'X:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WcmSvc',
          'X:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\WcmSvc',
          'X:\Windows\ServiceProfiles\LocalService\AppData\Local\Packages',
          'X:\ProgramData\Microsoft\Windows\Network Connections')
foreach ($d in $dirs) {
  $before = Test-Path -LiteralPath $d
  if (-not $before) { try { New-Item -ItemType Directory -Path $d -Force -EA Stop | Out-Null } catch { L('E1 MKDIR ERR ' + $d + ' ' + (C $_.Exception.Message)) } }
  L('E1 DIR ' + $d + ' before=' + $before + ' now=' + (Test-Path -LiteralPath $d))
}
Curve 'wcmsvc' 'E1 after creating state dirs'
Curve 'wcmsvc' 'E1 second start'

# ---------- E2 mpssvc up (BFE runs, the filter engine does not) ----------
L('E2 mpssvc ' + [Pe107]::Start('mpssvc') + ' -> ' + (Get-Service -Name mpssvc -EA SilentlyContinue).Status)
Start-Sleep -Seconds 2
Curve 'wcmsvc' 'E2 with mpssvc tried'

# ---------- E3 the service this task is actually about ----------
Curve 'wlansvc' 'E3 after wcmsvc attempts'
Curve 'wlansvc' 'E3 second attempt'
L('E3 STATE wcmsvc=' + (Get-Service -Name wcmsvc -EA SilentlyContinue).Status +
   ' wlansvc=' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status)
# and the interface view wlansvc would have had, straight from wlanapi
try {
  $r = & netsh.exe wlan show interfaces 2>&1 | Out-String
  L('NETSH-IF ' + (C ($r -replace '\s+', ' ')).Substring(0, [Math]::Min(200, (C $r).Length)))
} catch { L('NETSH-IF failed (netsh may not exist in this PE)') }
L('probe107 end -- S2 closes the file layer, E1/E2/E3 say whether wcmsvc can be made to stay up')
