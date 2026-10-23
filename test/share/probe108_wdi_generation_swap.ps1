# ============================================================
# probe108_wdi_generation_swap.ps1 -- is the WDI 1052 a file-generation mismatch?
# ============================================================
#   Where the WiFi stack stands after probe104..107 (all live, 12th-gen machine, this boot family):
#     * BINDING LAYER IS DONE: netdrvfix v3.2 logs WLAN-BIND=ok, WLAN-COMP=2/2, services_running 3/3
#       (nativewifip/vwififlt/vwifibus) and the machine has an IP. Real hardware, real adapter.
#     * WDI HOSTS: WdiServiceHost/wdisystemhost reach START_PENDING and self-stop with win32=1052 in
#       14-94 ms. probe104 killed the privilege defect (1297 -> gone), probe105 killed membership (H1),
#       ServiceSidType (H2) and shared-vs-dedicated/-p groups (E2 spawned a fresh svchost, still 1052).
#       => the refusal is inside wdi.dll's ServiceMain path.
#     * FILES: probe107 parsed static + delay imports of wcmsvc/wcmcsp/wlansvc/wdi/wlanmsm in the live PE
#       and every imported DLL exists. So it is not a missing file.
#   What IS different, and the only structural difference left that nobody has tested: probe106 read the
#   file versions in the live PE and they split into two generations --
#       wlansvc/wcmsvc/wcmcsp/wlanapi/wlanmsm = 10.0.19041.7725   (borrowed from C:\Windows\System32,
#                                                                  see wifi-inject.ps1 $host32)
#       wdi.dll                              = 10.0.26100.1, 118784 bytes (the ADK base image's own copy)
#   wlansvc (19041) is the WDI *client* of wdi.dll (26100); WdiServiceHost's Parameters.ServiceDll points
#   at that same 26100 file. The build host -- a healthy Windows 10 21H2 box whose WiFi works -- has
#   wdi.dll = 10.0.19041.4522, 105472 bytes, i.e. the SAME generation as the WLAN stack we injected.
#   That makes a cross-generation WDI call the last un-probed explanation for 1052, and it is testable
#   without a reboot: the PE's X: is a RAM disk, so the file can be replaced and put back in one run.
#
#   THIS PROBE (one variable at a time, each step measured with the 36-byte SERVICE_STATUS_PROCESS curve):
#     S0 versions in the live PE (base build + the whole WLAN/WDI closure) -- the mismatch, on the record
#     S1 the service keys svchost reads (ImagePath/ObjectName/privs/ServiceDll) -- state, not assumption
#     S2 BASELINE curves: WdiServiceHost, wdisystemhost, wcmsvc, wlansvc
#     S3 static+delay import check of the pushed 19041 candidate against the live file list (a swap that
#        produces STATUS_DLL_NOT_FOUND would be noise, so verify before using it)
#     S4 swap System32\wdi.dll -> candidate (original kept at X:\p108_orig_wdi.dll), re-run all four curves
#     S5 put the original back, re-run the two WDI curves -- if 1052 comes back with the file, the file
#        caused it; if it stays away, the act of touching the directory caused it. Either way it is known.
#   S6 also creates X:\Windows\System32\WDI (the healthy host has that directory, WDI uses it for its
#   per-service working data) before the swap, because the check is free and the failure shape of wdi.dll
#   (start, then immediately stop itself) is compatible with a path that resolves to nothing.
#
#   Candidate file is pushed to X:\p108_cand_wdi.dll by test\host_push_run.ps1 before this script runs.
#   Output: single-line ASCII, prefix P108. Nothing on the disc is modified; X: is RAM.
param([switch]$DryRun, [string]$Cand = 'X:\p108_cand_wdi.dll', [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P108 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Runtime.InteropServices;
public static class Pe108 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool ControlService(IntPtr Svc, uint Control, IntPtr Status);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr Svc, int InfoLevel, IntPtr Buf, uint Size, out uint Needed);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  const uint SERVICE_STOP = 0x0020;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_CONTROL_STOP = 1;
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
  public static string Stop(string name) {
    IntPtr sv = Open(name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      try { return ControlService(sv, SERVICE_CONTROL_STOP, st) ? "STOP_OK" : ("STOP_ERR=" + Marshal.GetLastWin32Error()); }
      finally { Marshal.FreeHGlobal(st); }
    } finally { CloseServiceHandle(sv); }
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
        int spec = Marshal.ReadInt32(buf, 16);
        uint pid = (uint)Marshal.ReadInt32(buf, 28);
        string sn = state == 1 ? "STOPPED" : state == 2 ? "START_PENDING" : state == 3 ? "STOP_PENDING" :
                    state == 4 ? "RUNNING" : ("state" + state);
        return sn + " win32=" + win32 + " spec=0x" + spec.ToString("X8") + " pid=" + pid;
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  public static string Ping() { return "Pe108 ping ok"; }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe108 begin native=' + $native + ' dryrun=' + $DryRun + ' cand=[' + (C $Cand) + ']')

$s32 = $Root
$svcs = @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')

function Ver([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'ABSENT' }
  $i = Get-Item -LiteralPath $p
  $v = '' + $i.VersionInfo.FileVersion
  return (C $v) + '/' + $i.Length
}
function Curve([string]$n, [string]$tag) {
  if ($native) { [void][Pe108]::Stop($n) }
  Start-Sleep -Milliseconds 250
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = 'no-native'
  if ($native) { $r = [Pe108]::Start($n) }
  $t0 = $sw.ElapsedMilliseconds
  $seen = @(); $runMs = -1; $err = -1
  while ($sw.ElapsedMilliseconds -lt 4000) {
    $s = ''
    if ($native) { $s = [Pe108]::Status($n) }
    if ($s -match 'RUNNING' -and $runMs -lt 0) { $runMs = $sw.ElapsedMilliseconds - $t0 }
    if ($s -match 'win32=(\d+)' -and [int]$Matches[1] -ne 0 -and $err -lt 0) { $err = [int]$Matches[1] }
    if (@($seen).Count -eq 0 -or ("$($seen[-1])" -replace '^\d+ms ', '') -ne $s) {
      $seen += (($sw.ElapsedMilliseconds - $t0).ToString() + 'ms ' + $s)
    }
    Start-Sleep -Milliseconds 50
  }
  L('CURVE ' + $n + ' [' + $tag + '] start=' + $r + ' running_at=' + $runMs + 'ms first_err=' + $err +
    ' states=[' + (($seen | Select-Object -First 6) -join ' -> ') + ']')
}

# ---------- S0 versions: the generation split, measured in the live image ----------
$verNames = @('ntdll.dll', 'svchost.exe', 'sechost.dll', 'svcexres.dll', 'wdi.dll', 'wlansvc.dll', 'wcmsvc.dll',
              'wcmcsp.dll', 'wlanapi.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlanutil.dll', 'wci.dll',
              'dmcmnutils.dll', 'deviceassociation.dll', 'drivers\wdiwifi.sys', 'drivers\NdisImPlatform.sys',
              'drivers\nwifi.sys', 'drivers\vwififlt.sys', 'drivers\vwifibus.sys')
foreach ($n in $verNames) { L('VER ' + $n + ' = ' + (Ver (Join-Path $s32 $n))) }
foreach ($f in @(Get-ChildItem -LiteralPath $s32 -Filter 'wdi*' -File -EA SilentlyContinue)) {
  L('WDIFILE ' + $f.Name + ' ' + (C $f.VersionInfo.FileVersion) + '/' + $f.Length)
}
L('S0 dir32_wdi_exists=' + (Test-Path -LiteralPath (Join-Path $s32 'WDI')) +
   ' dir_wdi_werexists=' + (Test-Path -LiteralPath (Join-Path $s32 'WDI\Logs')))

# ---------- S1 what svchost is being told to load ----------
foreach ($n in $svcs) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  $pk = Join-Path $k 'Parameters'
  $pp = Get-ItemProperty -LiteralPath $pk -EA SilentlyContinue
  L('SHAPE ' + $n + ' type=' + ('0x{0:X}' -f [int]$p.Type) + ' start=' + $p.Start + ' obj=[' + (C ('' + $p.ObjectName)) +
    '] img=[' + (C ('' + $p.ImagePath)) + '] privs=[' + (@($p.RequiredPrivileges) -join ';') + ']' +
    ' sidtype=' + $p.ServiceSidType + ' dep=[' + (@($p.DependOnService) -join ';') + ']')
  L('DLL ' + $n + ' ServiceDll=[' + (C ('' + $pp.ServiceDll)) + '] ServiceMain=[' + (C ('' + $pp.ServiceMain)) +
    '] UnloadOnStop=' + $pp.ServiceDllUnloadOnStop)
}

# ---------- S2 baseline ----------
# S0/S1/S3 only read; S2 starts services and S4 rewrites System32. The -DryRun gate therefore sits below
# S3 and S2 is skipped by condition -- the first local dry run proved why: the curve ran anyway and every
# Start came back OPEN_ERR=5 only because the shell was unelevated. A self-test must not touch services.
if (-not $DryRun) { foreach ($n in $svcs) { Curve $n 'S2 baseline' } }

# ---------- S3 import check of the candidate, before it can break anything ----------
function Get-Imports([string]$path) {
  $bytes = [System.IO.File]::ReadAllBytes($path)
  $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
  if ([BitConverter]::ToInt16($bytes, $e_lfanew) -ne 0x4550) { throw 'not a PE image' }
  $opt = $e_lfanew + 4 + 20
  $magic = [BitConverter]::ToUInt16($bytes, $opt)
  $is64 = ($magic -eq 0x20B)
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
  # IMAGE_IMPORT_DESCRIPTOR = 5 DWORDs = 20 bytes, IMAGE_DELAYLOAD_DESCRIPTOR = 8 DWORDs = 32 bytes, and
  # neither changes size between x86 and x64 (unlike the option header) -- probe107 multiplied the static
  # table by $is64 and got 20 anyway, but the same habit here would have walked 24-byte steps through a
  # 32-byte table and reported nonsense names.
  foreach ($dir in @(@(1, 20), @(13, 32))) {
    $impRva = [BitConverter]::ToUInt32($bytes, $ddOff + $dir[0] * 8)
    if ($impRva -eq 0) { continue }
    $p = RvaToOff $impRva
    if ($p -lt 0) { continue }
    $dsz = $dir[1]
    for ($k = 0; $k -lt 200; $k++) {
      if ($dsz -eq 20) {
        $nameRva = [BitConverter]::ToUInt32($bytes, $p + 12)
        $origThunk = [BitConverter]::ToUInt32($bytes, $p + 0)
        $firstThunk = [BitConverter]::ToUInt32($bytes, $p + 16)
        if ($nameRva -eq 0 -and $origThunk -eq 0 -and $firstThunk -eq 0) { break }
      } else {
        $attrs = [BitConverter]::ToUInt32($bytes, $p + 0)
        $nameRva = [BitConverter]::ToUInt32($bytes, $p + 4)
        # 0xFFFFFFFF in Attributes is the "no delay imports" marker the loader honours
        if ($nameRva -eq 0 -or $attrs -eq 0xFFFFFFFF) { break }
      }
      $noff = RvaToOff $nameRva
      $dn = ''
      if ($noff -ge 0) {
        $sb = New-Object System.Text.StringBuilder
        $j = $noff
        while ($j -lt $bytes.Length -and $bytes[$j] -ne 0) { [void]$sb.Append([char]$bytes[$j]); $j++ }
        $dn = $sb.ToString()
      }
      if ($dn -ne '') { $dlls += $dn }
      $p += $dsz
    }
  }
  return @($dlls)
}
$have = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $s32 -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $s32 'en-US') -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
foreach ($f in @(Get-ChildItem -LiteralPath (Split-Path $s32 -Parent) -Filter '*.dll' -File -EA SilentlyContinue)) { $have[$f.Name.ToLower()] = 1 }
L('S3 pe_dll_count=' + $have.Count + ' cand_exists=' + (Test-Path -LiteralPath $Cand) +
  ' cand_ver=' + (Ver $Cand))
$candOk = $false
if (Test-Path -LiteralPath $Cand) {
  $idlls = @()
  try { $idlls = @(Get-Imports $Cand) } catch { L('S3 PARSE FAILED ' + (C $_.Exception.Message)) }
  L('S3 cand import-dlls=' + (@($idlls | Sort-Object -Unique).Count))
  $miss = 0
  foreach ($d in @($idlls | Sort-Object -Unique)) {
    $dl = ('' + $d).ToLower()
    if ($dl -like 'api-ms-*' -or $dl -like 'ext-ms-*') { continue }
    if (-not $have.ContainsKey($dl)) { $miss++; L('  MISSING-IN-PE ' + (C $d)) }
  }
  L('S3 cand MISSING=' + $miss)
  $candOk = ($miss -eq 0 -and @($idlls).Count -gt 0)
}
if ($DryRun) {
  L('probe108 end (DryRun: S0 versions + S1 shape + S3 import gate, no service touched, no file written)')
  exit 0
}

# ---------- S4 the swap ----------
$orig = Join-Path $s32 'wdi.dll'
$bak = 'X:\p108_orig_wdi.dll'
$beforeVer = (Ver $orig)
L('S4 wdi-before=' + $beforeVer)
if (-not (Test-Path -LiteralPath $bak)) {
  try { Copy-Item -LiteralPath $orig -Destination $bak -Force -EA Stop; L('S4 BAKED-TO ' + $bak + ' ' + (Ver $bak)) }
  catch { L('S4 BACKUP FAILED ' + (C $_.Exception.Message)) }
}
if ($candOk) {
  foreach ($n in @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')) { if ($native) { [void][Pe108]::Stop($n) } }
  Start-Sleep -Milliseconds 400
  $sw = ''
  try {
    Remove-Item -LiteralPath $orig -Force -EA Stop
    Copy-Item -LiteralPath $Cand -Destination $orig -Force -EA Stop
    $sw = 'SWAPPED'
  } catch { $sw = 'FAILED ' + (C $_.Exception.Message) }
  L('S4 ' + $sw + ' wdi-after=' + (Ver $orig))
  if (Test-Path -LiteralPath (Join-Path $s32 'WDI')) { L('S4 WDI dir present') }
  else { try { New-Item -ItemType Directory -Force -Path (Join-Path $s32 'WDI') -EA Stop | Out-Null; L('S4 WDI dir CREATED=' + (Test-Path -LiteralPath (Join-Path $s32 'WDI'))) } catch { L('S4 WDI MKDIR FAILED ' + (C $_.Exception.Message)) } }
  foreach ($n in $svcs) { Curve $n 'S4 wdi=19041' }
} else {
  L('S4 SKIPPED SWAP cand_ok=' + $candOk + ' -- candidate failed the import gate')
}

# ---------- S5 put the original back ----------
if (Test-Path -LiteralPath $bak) {
  $rs = ''
  try {
    foreach ($n in @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')) { if ($native) { [void][Pe108]::Stop($n) } }
    Start-Sleep -Milliseconds 400
    Remove-Item -LiteralPath $orig -Force -EA Stop
    Copy-Item -LiteralPath $bak -Destination $orig -Force -EA Stop
    $rs = 'RESTORED'
  } catch { $rs = 'RESTORE FAILED ' + (C $_.Exception.Message) }
  L('S5 ' + $rs + ' wdi-now=' + (Ver $orig) + ' (before was ' + $beforeVer + ')')
  foreach ($n in @('WdiServiceHost', 'wdisystemhost')) { Curve $n 'S5 wdi=original' }
}
L('probe108 end -- compare S2 vs S4 per service: a change only on the WDI hosts is the generation effect')
