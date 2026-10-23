# ============================================================
# probe105_wdi_group_and_debug.ps1 -- why do the WDI hosts stop with 1052?
# ============================================================
#   probe104 results (12th-gen live machine, 15:2x):
#     A) LocalService + privs=[SeChangeNotify;SeImpersonate]  -> START_OK, then STOPPED
#        win32=1052 pid=0 in 14 ms.   1297 is GONE, so the privilege bake defect is proven and fixed.
#     B) LocalSystem  + privs=[3, incl SeSystemProfile]       -> START_ERR=1079
#        1079 = "this service's account differs from the accounts of other services in the same process",
#        i.e. B is structurally impossible while WdiServiceHost shares the LocalService group. B is dead.
#     wdisystemhost (already LocalSystem, privs=[] in the hive)  -> START_OK, START_PENDING pid=1320,
#        then STOPPED 1052 in 94 ms. pid 1320 is the running "-k LocalSystemNetworkRestricted -p" host,
#        so SCM handed the start to an EXISTING svchost and that svchost refused it.
#   Host reference (build\scratch\host_wdi_shape_ref.txt, healthy Win11 desktop):
#     WdiServiceHost : -k LocalService  -p, LocalService, privs=[3 incl SeSystemProfile], ServiceSidType=1,
#                      member of the LocalService MULTI_SZ.
#     wdisystemhost  : -k LocalSystemNetworkRestricted -p, LocalSystem, privs=[8], ServiceSidType=1.
#     wcmsvc         : Type=16, -k LocalServiceNetworkRestricted -p, ServiceSidType=1, DependOn=[RpcSs;NSI].
#     wlansvc        : Type=16, -k LocalSystemNetworkRestricted -p, ServiceSidType=1, DependOn=[nativewifip;RpcSs;Ndisuio;wcmsvc].
#   Two hypotheses are left and this probe separates them with evidence, not guessing:
#     H1 membership  -- our baked service is not in the group MULTI_SZ / the group subkey, so the already
#                       running svchost says "not for me" (that reads exactly like 1052).
#     H2 ServiceSidType=1 (SERVICE_SID_TYPE_UNRESTRICTED) is missing from our bake; SCM only creates the
#        per-service SID when that value is set, and wdi.dll may demand it.
#   SECTION 1 dumps both shapes side by side. SECTION 2 asks svchost itself, in debug mode
#   (-k <group> -d -s <service>), which prints the real reason instead of a bare exit code.
#   SECTION 3 runs the fix a rescue disc can actually ship: a DEDICATED svchost group per WDI host
#   (the same shape WinRE uses for WlansvcGroup), so membership and the account can never conflict, plus
#   ChangeServiceConfig2 SERVICE_CONFIG_SERVICE_SID_INFO=1 applied live for the H2 test.
#
#   DRY-RUN RESULT ON THE LIVE MACHINE (15:3x) -- H1 and H2 are already dead, so E1 became E0 (a reproducibility
#   baseline instead of an experiment):
#     SHAPE WdiServiceHost type=0x20 obj=LocalSystem sidtype=1 grp=LocalService pmod=yes, IMG ...-k LocalService -p
#     SHAPE wdisystemhost  type=0x20 obj=LocalSystem sidtype=1 grp=LocalSystemNetworkRestricted pmod=yes
#     MEMB  WdiServiceHost in_table=True memcount=6 / wdisystemhost in_table=True memcount=5 / group_subkey=True
#     TBL   19 groups incl. WlansvcGroup
#   => ServiceSidType=1 is baked and both hosts ARE in the parent Svchost MULTI_SZ. What is left is H3 (-p split
#   instances read their membership from the group subkey, so the running svchost genuinely does not know them)
#   and wdi.dll itself, which the SECTION 2 debug run answers directly. E2 is the shippable shape either way.
#   Output: single-line ASCII, prefix P105.
param([switch]$DryRun)
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P105 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Runtime.InteropServices;
public static class Pe105 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr Svc, int InfoLevel, IntPtr Buf, uint Size, out uint Needed);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ChangeServiceConfigW(IntPtr Svc, uint dwServiceType, uint dwStartType, uint dwErrorControl,
      string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies,
      string lpServiceStartName, string lpPassword, string lpDisplayName);
  [StructLayout(LayoutKind.Sequential)]
  public struct SID_INFO { public int SidType; }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool ChangeServiceConfig2W(IntPtr Svc, uint InfoLevel, ref SID_INFO Info);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_CHANGE_CONFIG = 0x0002;
  const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
  const uint SERVICE_CONFIG_SERVICE_SID_INFO = 0x00000059;
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
  // null = leave the field alone (the API wants SERVICE_NO_CHANGE for the dwords and NULL for strings).
  public static string Change(string name, string binPath, string account) {
    IntPtr sv = Open(name, SERVICE_CHANGE_CONFIG);
    if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      bool ok = ChangeServiceConfigW(sv, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
          binPath, null, IntPtr.Zero, null, account, null, null);
      if (!ok) { return "CHANGE_ERR=" + Marshal.GetLastWin32Error(); }
      return "CHANGED bin=" + (binPath == null ? "keep" : "new") + " obj=" + (account == null ? "keep" : account);
    } finally { CloseServiceHandle(sv); }
  }
  public static string SetSidType(string name, int sidType) {
    IntPtr sv = Open(name, SERVICE_CHANGE_CONFIG);
    if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      SID_INFO si = new SID_INFO(); si.SidType = sidType;
      bool ok = ChangeServiceConfig2W(sv, SERVICE_CONFIG_SERVICE_SID_INFO, ref si);
      return ok ? ("SIDTYPE->" + sidType) : ("SIDTYPE_ERR=" + Marshal.GetLastWin32Error());
    } finally { CloseServiceHandle(sv); }
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe105 begin native=' + $native + ' dryrun=' + $DryRun)

$svcs = @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')
$sh = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'

# ---------- 1) the shape we actually have, plus group membership read from the live table ----------
$groups = @{}
foreach ($n in $svcs) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  $img = C ('' + $p.ImagePath)
  $g = ''
  if ($img -match '-k\s+(\S+)') { $g = $Matches[1] }
  $groups[$n] = $g
  $rp = @($p.RequiredPrivileges | ForEach-Object { "$_" })
  $sub = @(Get-Item -LiteralPath $k -EA SilentlyContinue).GetSubKeyNames() -join ','
  L('SHAPE ' + $n + ' type=0x' + ('{0:X}' -f [int]$p.Type) + ' start=' + [int]$p.Start +
    ' obj=[' + (C ('' + $p.ObjectName)) + '] sidtype=' + [int]$p.ServiceSidType +
    ' deps=[' + ((@($p.DependOnService | ForEach-Object { "$_" })) -join ';') + ']' +
    ' privs=' + @($rp).Count + ' grp=' + $g + $(if ($img -match '-p\b') { ' pmod=yes' } else { ' pmod=no' }) +
    ' subkeys=[' + $sub + ']')
  L('  IMG ' + $n + ' [' + $img + ']')
}
# the whole group table, as the live svchost processes read it at boot
L('TBL names=' + (@(Get-Item -LiteralPath $sh).GetValueNames() -join ';'))
foreach ($n in $svcs) {
  $g = $groups[$n]
  if (-not $g) { L('MEMB ' + $n + ' group=none (ImagePath has no -k)'); continue }
  $mem = @((Get-Item -LiteralPath $sh).GetValue($g))
  $inTable = @($mem | Where-Object { "$_" -ieq $n }).Count -gt 0
  $subExists = Test-Path -LiteralPath (Join-Path $sh $g)
  $ciso = '' + (Get-ItemProperty -LiteralPath (Join-Path $sh $g) -EA SilentlyContinue).CoInitializeSecurityParam
  L('MEMB ' + $n + ' group=' + $g + ' in_table=' + $inTable + ' memcount=' + @($mem).Count +
    ' group_subkey=' + $subExists + ' CoInitSec=[' + $ciso + ']')
  L('  MEM ' + $g + '=' + (($mem | ForEach-Object { "$_" }) -join ';'))
  # H3 (the one the DryRun left standing): instances started with -p are SPLIT group instances, and Microsoft
  # keeps their membership in the group SUBKEY (DifferentServicesForSplit), not the parent MULTI_SZ. If our
  # baked service is only in the parent table, the already-running svchost legitimately does not know it --
  # which reads exactly like 1052 "the requested control is not valid for this service".
  if ($subExists) {
    $gki = Get-Item -LiteralPath (Join-Path $sh $g)
    $gvn = @($gki.GetValueNames())
    L('  SUB ' + $g + ' values=[' + ($gvn -join ';') + ']')
    foreach ($vn in $gvn) {
      $rawv = $gki.GetValue($vn)
      $txt = if ($rawv -is [array]) { ($rawv -join ';') } else { '' + $rawv }
      if ($txt -imatch $n) { L('  SUBHIT ' + $g + '\' + $vn + ' contains ' + $n) }
      if ($vn -imatch 'DifferentServicesForSplit|ServicesDeleted|SharedState') {
        L('  SUBVAL ' + $vn + '=[' + (C $txt) + ']')
      }
    }
    $hasMe = @($gvn | Where-Object { $gki.GetValue($_) -is [array] -and @($gki.GetValue($_) | Where-Object { "$_" -ieq $n }).Count }).Count -gt 0
    L('  SUBMEMB ' + $n + ' in-subkey-array=' + $hasMe)
  }
}

function Curve([string]$n, [string]$tag) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = 'no-native'
  if ($native) { $r = [Pe105]::Start($n) }
  $t0 = $sw.ElapsedMilliseconds
  $seen = @(); $runMs = -1; $minWin32 = -1
  while ($sw.ElapsedMilliseconds -lt 6000) {
    $s = ''
    if ($native) { $s = [Pe105]::Status($n) }
    if ($s -match 'RUNNING' -and $runMs -lt 0) { $runMs = $sw.ElapsedMilliseconds - $t0 }
    if ($s -match 'win32=(\d+)') {
      $wv = [int]$Matches[1]
      if ($wv -ne 0 -and $minWin32 -lt 0) { $minWin32 = $wv }
    }
    if (@($seen).Count -eq 0 -or ("$($seen[-1])" -replace '^\d+ms ', '') -ne $s) {
      $seen += (($sw.ElapsedMilliseconds - $t0).ToString() + 'ms ' + $s)
    }
    Start-Sleep -Milliseconds 80
  }
  L('CURVE ' + $n + ' [' + $tag + '] start=' + $r + ' running_at=' + $runMs + 'ms last_err=' + $minWin32 +
    ' states=[' + (($seen | Select-Object -First 6) -join ' -> ') + ']')
}

# ---------- 2) ask svchost itself: debug mode prints the reason the exit code hides ----------
if ($DryRun) {
  L('DEBUG skipped (DryRun)')
} else {
  foreach ($n in @('WdiServiceHost', 'wdisystemhost')) {
    $g = $groups[$n]
    if (-not $g) { L('DEBUG ' + $n + ' no group in ImagePath'); continue }
    $out = 'X:\p105_' + $n + '.out'; $err = 'X:\p105_' + $n + '.err'
    Remove-Item -LiteralPath $out, $err -Force -EA SilentlyContinue
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = $null
    try {
      $p = Start-Process -FilePath 'X:\windows\system32\svchost.exe' `
        -ArgumentList @('-k', $g, '-d', '-s', $n) -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    } catch { L('DEBUG ' + $n + ' launch failed ' + (C $_.Exception.Message)) }
    if ($p) {
      while (-not $p.HasExited -and $sw.ElapsedMilliseconds -lt 8000) { Start-Sleep -Milliseconds 200; $p.Refresh() }
      $alive = -not $p.HasExited
      if ($alive) { try { $p.Kill() | Out-Null } catch { } Start-Sleep -Milliseconds 300 }
      $code = 'n/a'
      try { if ($p.HasExited) { $code = '' + $p.ExitCode } } catch { }
      $ob = 0; $eb = 0
      try { $ob = (Get-Item -LiteralPath $out -EA Stop).Length } catch { }
      try { $eb = (Get-Item -LiteralPath $err -EA Stop).Length } catch { }
      L('DEBUG ' + $n + ' -k ' + $g + ' alive=' + $alive + ' exit=' + $code + ' out=' + $ob + 'B err=' + $eb + 'B')
      foreach ($f in @($out, $err)) {
        if ($f -eq $err -and $eb -eq 0) { continue }
        if ($f -eq $out -and $ob -eq 0) { continue }
        foreach ($ln in @(Get-Content -LiteralPath $f -EA SilentlyContinue | Select-Object -First 25)) {
          L('  OUT ' + (C $ln))
        }
      }
    }
  }
}

if ($DryRun) { L('probe105 end (DryRun: shape + membership only)'); exit 0 }

# ---------- 3) the two candidate fixes, measured ----------
# restore the state probe104 left behind first: A is the only viable account/privilege shape.
$wdiK = 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost'
New-ItemProperty -LiteralPath $wdiK -Name 'RequiredPrivileges' `
  -Value ([string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege')) -PropertyType MultiString -Force | Out-Null
New-ItemProperty -LiteralPath $wdiK -Name 'ObjectName' -Value 'NT AUTHORITY\LocalService' -PropertyType String -Force | Out-Null
L('RESTORE ' + [Pe105]::Change('WdiServiceHost', $null, 'NT AUTHORITY\LocalService'))

# E0 = the DryRun already showed ServiceSidType=1 and parent-table membership for both hosts, so H1/H2 are
# dead before we start. Re-measure the restored A shape once: 1052 must reproduce, otherwise nothing below is
# comparable.
foreach ($n in @('WdiServiceHost', 'wdisystemhost')) {
  $hiveSid = '' + (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue).ServiceSidType
  L('E0 ' + $n + ' hive ServiceSidType=' + $hiveSid + ' live API ' + [Pe105]::SetSidType($n, 1))
}
Curve 'WdiServiceHost' 'E0 baseline restored-A shared LocalService'

# E2 = the shippable shape: a dedicated svchost group per host, no -p, membership written fresh.
# This is the same move WinRE uses for WlansvcGroup (see the reference-route memory) and it is the only
# shape difference left standing: wlansvc, the one service we gave its own non-split group, is also the one
# service svchost actually hosted (it got a pid and ran wlansvc.dll to its own 0x800C0006 exit).
# Privileges stay minimal on purpose: the host's wdisystemhost lists 8, PE's LSA policy is trimmed, and
# probe102 already proved that one ungrantable privilege is what 1297 is made of.
$mkGroup = @{
  'WdiServiceHost' = @('WdiSvcHostGroup', 'NT AUTHORITY\LocalService')
  'wdisystemhost'  = @('WdiSysHostGroup', 'LocalSystem')
}
foreach ($n in @('WdiServiceHost', 'wdisystemhost')) {
  $g = $mkGroup[$n][0]; $obj = $mkGroup[$n][1]
  New-ItemProperty -LiteralPath $sh -Name $g -Value ([string[]]@($n)) -PropertyType MultiString -Force | Out-Null
  $gk = Join-Path $sh $g
  if (-not (Test-Path -LiteralPath $gk)) { New-Item -LiteralPath $gk -Force | Out-Null }
  New-ItemProperty -LiteralPath $gk -Name 'CoInitializeSecurityParam' -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -Name 'RequiredPrivileges' `
    -Value ([string[]]@('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege')) -PropertyType MultiString -Force | Out-Null
  L('E2GROUP ' + $n + ' ' + $g + ' memb=' + (@((Get-Item -LiteralPath $sh).GetValue($g)) -join ';') +
    ' subkey=' + (Test-Path -LiteralPath $gk))
  $bp = 'X:\windows\System32\svchost.exe -k ' + $g
  L('E2CFG ' + $n + ' ' + [Pe105]::Change($n, $bp, $obj))
  L('E2IMG ' + $n + ' hive=[' + (C ('' + (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n)).ImagePath)) + ']')
  Curve $n ('E2 dedicated group ' + $g)
}

# who hosts what now -- if E2 worked there is a svchost -k Wdi*HostGroup with our service inside
foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  $cl = C ('' + $p.CommandLine)
  if ($cl -notmatch '(?i)Wdi') { continue }
  $hosted = @(Get-CimInstance Win32_Service -Filter ('ProcessId=' + $p.ProcessId) -EA SilentlyContinue | ForEach-Object { $_.Name })
  L('PROC pid=' + $p.ProcessId + ' cmd=[' + $cl + '] hosts=[' + ($hosted -join ';') + ']')
}

# E3 = with the hosts in whatever state E2 left them, retry the two WLAN services: this is the point of the exercise
foreach ($n in @('wcmsvc', 'wlansvc')) {
  Curve $n 'E3 after wdi hosts'
}
Curve 'wlansvc' 'E3 second attempt'
L('STATE wcmsvc=' + (Get-Service -Name wcmsvc -EA SilentlyContinue).Status +
   ' wlansvc=' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status)
L('probe105 end -- E0/E2 CURVE decides the bake; DEBUG lines say what svchost itself reports')
