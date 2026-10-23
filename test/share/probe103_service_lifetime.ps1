# ============================================================
# probe103_service_lifetime.ps1 -- every wifi service is ACCEPTED then exits; why, and how fast
# ============================================================
#   probe102 decided two things on the live machine:
#     * H1 (svchost group table missing) is DEAD: all 19 groups are defined and each of our four services is
#       listed in the group its ImagePath asks for (NEED ... group_defined=True self_listed_in_group=True).
#     * H2 is CONFIRMED and is a bake bug: WdiServiceHost with RequiredPrivileges
#       [SeChangeNotify;SeImpersonate;SeSystemProfile] -> START_ERR=1297; drop SeSystemProfilePrivilege -> START_OK.
#       (LOCAL SERVICE simply does not hold SeSystemProfilePrivilege in PE: adjusting even SeDebugPrivilege from
#        the admin console returns gle=1300 NOT_ALL_ASSIGNED.) Removing the value entirely is NOT a fix:
#        START_ERR=13.
#   That leaves the real shape of the failure: SCM now accepts everything, but wcmsvc / wlansvc / wdisystemhost /
#   WdiServiceHost all read Stopped a second later, and probe102's svchost census shows they never appear in the
#   -k LocalServiceNetworkRestricted process ([Dhcp;EventLog;lmhosts;WinHttpAutoProxySvc]) and there is no
#   -k WlansvcGroup process at all. So they exit inside ServiceMain, or svchost never gets that far.
#   This probe measures rather than guesses:
#     A) state transitions sampled every 100 ms for 6 s after the start call -- the lifetime IS a clue
#        (38 modules loaded / 130 ms self-exit was probe99's finding for wlansvc);
#     B) which svchost pid appears for the group, and which services it ended up hosting;
#     C) svchost -d <service> -- the documented debug mode, which runs the service in the foreground instead of
#        under the SCM, so whatever it prints (or its exit code) is the service's own words;
#     D) what logging the image even has (Get-WinEvent said the System log file is missing -- enumerate channels).
#   It also applies the H2 fix in the live hive so the tests run against the shape we are about to bake.
#   Output: single-line ASCII, prefix P103.
param([switch]$DryRun)
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P103 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Pe103 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool ControlService(IntPtr Svc, int Control, IntPtr Status);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr Svc, int InfoLevel, IntPtr Buf, uint Size, out uint Needed);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceConfigW(IntPtr Svc, IntPtr Buf, uint BufSize, out uint Needed);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  const uint SERVICE_QUERY_CONFIG = 0x0001;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  // SERVICE_STATUS_PROCESS: 8*4 bytes + pid + checkpoint + wait hint = 36 bytes (probe99 fixed the size bug)
  public static string Status(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "SCM_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_QUERY_STATUS | SERVICE_START);
      if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        IntPtr buf = Marshal.AllocHGlobal(36);
        try {
          uint need = 0;
          if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) { return "QSS_ERR=" + Marshal.GetLastWin32Error(); }
          int type = Marshal.ReadInt32(buf, 0);
          int state = Marshal.ReadInt32(buf, 4);
          uint ctrl = (uint)Marshal.ReadInt32(buf, 8);
          int win32 = Marshal.ReadInt32(buf, 12);
          int spec = Marshal.ReadInt32(buf, 16);
          uint check = (uint)Marshal.ReadInt32(buf, 20);
          uint hint = (uint)Marshal.ReadInt32(buf, 24);
          uint pid = (uint)Marshal.ReadInt32(buf, 28);
          string sn = "";
          switch (state) { case 1: sn = "STOPPED"; break; case 2: sn = "START_PENDING"; break;
            case 3: sn = "STOP_PENDING"; break; case 4: sn = "RUNNING"; break; case 5: sn = "CONTINUE_PENDING"; break;
            case 6: sn = "PAUSE_PENDING"; break; case 7: sn = "PAUSED"; break; default: sn = "state" + state; break; }
          return sn + " win32exit=0x" + win32.ToString("X8") + " specific=0x" + spec.ToString("X8") +
                 " pid=" + pid + " controlsupported=0x" + ctrl.ToString("X") + " ck=" + check + " hint=" + hint;
        } finally { Marshal.FreeHGlobal(buf); }
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
  public static string Start(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "OPENSCMANAGER_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_START);
      if (sv == IntPtr.Zero) { return "OPENSERVICE_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        if (StartServiceW(sv, 0, IntPtr.Zero)) { return "START_OK"; }
        return "START_ERR=" + Marshal.GetLastWin32Error();
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
  // ServiceSidType / RequiredPrivileges are what decide the token; dump the raw config so nothing is guessed.
  public static string SidType(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "SCM_ERR"; }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_QUERY_CONFIG);
      if (sv == IntPtr.Zero) { return "OPEN_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        uint need = 0;
        QueryServiceConfigW(sv, IntPtr.Zero, 0, out need);
        if (need == 0) { return "NO_SIZE"; }
        IntPtr buf = Marshal.AllocHGlobal((int)need);
        try {
          uint n2 = 0;
          if (!QueryServiceConfigW(sv, buf, need, out n2)) { return "QCFG_ERR=" + Marshal.GetLastWin32Error(); }
          // QUERY_SERVICE_CONFIGW: dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName...
          int svcType = Marshal.ReadInt32(buf, 0);
          int startType = Marshal.ReadInt32(buf, 4);
          int errCtl = Marshal.ReadInt32(buf, 8);
          IntPtr pImg = Marshal.ReadIntPtr(buf, 16);
          string img = "";
          try { img = Marshal.PtrToStringUni(pImg); } catch { }
          if (img.Length > 90) { img = img.Substring(0, 90); }
          return "type=0x" + svcType.ToString("X") + " start=0x" + startType.ToString("X") +
                 " errctl=0x" + errCtl.ToString("X") + " img=[" + img + "]";
        } finally { Marshal.FreeHGlobal(buf); }
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe103 begin native=' + $native)

# ---------- 0) apply the H2 fix in the live hive (this is what we will bake next) ----------
$wdiK = 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost'
$orig = @((Get-ItemProperty -LiteralPath $wdiK -EA SilentlyContinue).RequiredPrivileges)
$fixed = @($orig | Where-Object { "$_" -notmatch '(?i)SystemProfile' })
L('FIX WdiServiceHost RequiredPrivileges orig=[' + ($orig -join ';') + '] fixed=[' + ($fixed -join ';') + ']')
if ((-not $DryRun) -and (@($orig).Count -ne @($fixed).Count)) {
  Set-ItemProperty -LiteralPath $wdiK -Name 'RequiredPrivileges' -Value ([string[]]$fixed) -Type MultiString
  L('FIX applied (live hive only; a reboot restores the baked shape)')
}

function StRaw([string]$n) { $s = (Get-Service -Name $n -EA SilentlyContinue).Status; if (-not $s) { return 'n/a' }; return "$s" }

# ---------- A/B) start, then sample the transition curve and the svchost census ----------
$targets = @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')
foreach ($n in $targets) {
  $grp = ''
  $img = '' + (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue).ImagePath
  $m = [regex]::Match($img, '(?i)-k\s+(?<g>[A-Za-z0-9_]+)')
  if ($m.Success) { $grp = $m.Groups['g'].Value }
  L('TARGET ' + $n + ' group=[' + $grp + '] before=' + (StRaw $n) + $(if ($native) { ' ssp=[' + [Pe103]::Status($n) + '] cfg=[' + [Pe103]::SidType($n) + ']' } else { '' }))
  if ((StRaw $n) -eq 'Running') { continue }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $r = 'no-native'
  if ($native) { $r = [Pe103]::Start($n) }
  $t0 = $sw.ElapsedMilliseconds
  $seen = @()
  while ($sw.ElapsedMilliseconds -lt 6000) {
    $s = 'no-native'
    if ($native) { $s = [Pe103]::Status($n) }
    $tag = ($sw.ElapsedMilliseconds - $t0).ToString() + 'ms ' + $s
    if (@($seen).Count -eq 0 -or ("$($seen[-1])" -replace '^\d+ms ', '') -ne ($s)) { $seen += $tag }
    Start-Sleep -Milliseconds 100
  }
  L('CURVE ' + $n + ' start=' + $r + ' states=[' + (($seen | Select-Object -First 8) -join ' -> ') + '] final=' + (StRaw $n))
  # which process exists for that group right now, and what does it host?
  $procs = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue |
             Where-Object { ("$($_.CommandLine)") -match ('(?i)-k\s+' + [regex]::Escape($grp) + '(\s|$)') })
  if (@($procs).Count -eq 0) { L('PROC ' + $n + ' no svchost alive for group ' + $grp) }
  foreach ($p in $procs) {
    $hosted = @(Get-CimInstance Win32_Service -Filter ('ProcessId=' + $p.ProcessId) -EA SilentlyContinue | ForEach-Object { $_.Name })
    L('PROC ' + $n + ' pid=' + $p.ProcessId + ' hosts=[' + ($hosted -join ';') + '] started=' + $p.CreationDate.ToString('HHmmss'))
  }
}

# ---------- C) svchost -d: run the service in the foreground, outside the SCM, and take what it says ----------
foreach ($n in @('wcmsvc', 'WdiServiceHost')) {
  $exe = 'X:\windows\System32\svchost.exe'
  $txt = ''
  try {
    Remove-Item 'X:\p103out.txt', 'X:\p103err.txt' -Force -EA SilentlyContinue
    # no Start-Job here: PE's job engine spawns another powershell, which is exactly the thing we are trying
    # to keep out of the measurement. Start-Process + WaitForExit(8s) + Kill is enough.
    $p = Start-Process -FilePath $exe -ArgumentList @('-d', $n) -PassThru -NoNewWindow `
          -RedirectStandardOutput 'X:\p103out.txt' -RedirectStandardError 'X:\p103err.txt' -EA Stop
    if ($p) {
      $exited = $p.WaitForExit(8000)
      if (-not $exited) { try { $p.Kill(); $exited = $p.WaitForExit(3000) } catch { } }
      $code = 'killed'
      if ($exited) { $code = ('' + $p.ExitCode) }
      $txt = 'exited=' + $exited + ' code=' + $code + ' pid=' + $p.Id
    } else { $txt = 'LAUNCH_FAILED' }
  } catch { $txt = 'ERR ' + (C $_.Exception.Message) }
  $so = ''
  $se = ''
  if (Test-Path 'X:\p103out.txt') { $so = C ((Get-Content 'X:\p103out.txt' -Raw)) }
  if (Test-Path 'X:\p103err.txt') { $se = C ((Get-Content 'X:\p103err.txt' -Raw)) }
  L('DEBUGMODE ' + $n + ' ' + $txt + ' stdout=[' + $so + '] stderr=[' + $se + ']')
  if ($native) { L('DEBUGMODE ' + $n + ' ssp-after=[' + [Pe103]::Status($n) + ']') }
}

# ---------- D) what logging does this image actually have? ----------
try {
  $logs = @(Get-WinEvent -ListLog * -EA Stop | Where-Object { $_.RecordCount -gt 0 } | Select-Object -First 12)
  foreach ($x in $logs) { L('LOG ' + $x.LogName + ' records=' + $x.RecordCount + ' type=' + $x.LogType + ' file=[' + (C ('' + $x.LogFilePath)) + ']') }
  if (@($logs).Count -eq 0) { L('LOG none with records') }
} catch { L('LOG listlog failed: ' + (C $_.Exception.Message)) }
L('LOGFILES dir=[' + (C ((@(Get-ChildItem 'X:\Windows\System32\winevt\Logs' -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ';'))) + ']')

L('probe103 end -- CURVE/PROC say how long each service lives and whether svchost ever hosts it; DEBUGMODE is the service speaking for itself')
