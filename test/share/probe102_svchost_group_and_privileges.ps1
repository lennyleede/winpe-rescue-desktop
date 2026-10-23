# ============================================================
# probe102_svchost_group_and_privileges.ps1 -- live experiment on the two WDI hosts
# ============================================================
#   Where probe101 left us (live machine 192.168.0.102, disc 2026-10-12 14:25):
#     * binding layer FIXED and proven: WLAN-BIND=ok / wifi_entries=2 / vwifibus=True / 3 filter services Running
#     * wlansvc / wcmsvc / wdisystemhost: SCM ACCEPTS the start (START_OK) but each ends Stopped
#     * WdiServiceHost alone is refused at the SCM door: START_ERR=1297
#     * the LSA self-reads are all 0xC0030005/0xC0000022 -- that is THIS token, not the SCM:
#       wlansvc carries 6 RequiredPrivileges and still gets START_OK, so "the name table is unreadable from
#       ssh" is an artefact. Do not conclude from it.
#   Two hypotheses, tested by editing the live (RAM) registry, which is cheap and disappears on reboot:
#     H1 svchost group: PE's SOFTWARE\..\Svchost had NO LocalSystemNetworkRestricted value (probe100 section 7),
#        yet wdisystemhost's ImagePath is '-k LocalSystemNetworkRestricted'. A svchost with no group table
#        loads nothing and exits => the service "starts" and is immediately Stopped. Same shape would explain
#        wlansvc if its group were missing (it is not: WlansvcGroup=[wlansvc]).
#     H2 WdiServiceHost 1297: the only thing its key has that the services which DO start also have is
#        SeSystemProfilePrivilege (host reference: SeChangeNotify;SeImpersonate;SeSystemProfile).
#        Drop that one name -> does the start go through?
#   Writes here touch ONLY the live hive (PE runs from RAM; a reboot resets it) and only for services we baked.
#   Output: single-line ASCII, prefix P102.
param([switch]$DryRun)   # DryRun: read + report only; the svchost-group and privilege writes are skipped.
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P102 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

$src = @'
using System;
using System.Runtime.InteropServices;
public static class Pe102 {
  [StructLayout(LayoutKind.Sequential)]
  struct LUID { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  struct TOKEN_PRIVILEGES {
    // x64 layout: Count at 0, the LUID is 8-byte aligned so it starts at offset 8 (LowPart 8, HighPart 12),
    // Attributes at 16. Without the explicit pad the fields land at 4/8/12 and the call silently does nothing.
    public uint Count; public uint Pad; public uint LuidLow; public int LuidHigh; public uint Attr;
  }
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
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
  // Try to take SeDebugPrivilege so the LSA reads stop being artefacts. Silently fine if the token has no such right.
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenProcessToken(IntPtr Proc, uint Access, out IntPtr Tok);
  [DllImport("kernel32.dll")]
  static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool LookupPrivilegeValueW(string Host, string Name, out LUID Lu);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool AdjustTokenPrivileges(IntPtr Tok, bool Disable, ref TOKEN_PRIVILEGES NewState, uint Len, IntPtr Prev, out uint RetLen);
  const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
  const uint TOKEN_QUERY = 0x0008;
  const uint SE_PRIVILEGE_ENABLED = 0x00000002;
  public static string EnablePriv(string name) {
    IntPtr tok = IntPtr.Zero;
    LUID l = new LUID();
    if (!LookupPrivilegeValueW(null, name, out l)) { return "LOOKUP_ERR=" + Marshal.GetLastWin32Error(); }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out tok)) {
      return "OPENTOKEN_ERR=" + Marshal.GetLastWin32Error();
    }
    try {
      TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
      tp.Count = 1; tp.LuidLow = l.LowPart; tp.LuidHigh = l.HighPart; tp.Attr = SE_PRIVILEGE_ENABLED;
      uint rl = 0;
      if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, out rl)) {
        return "ADJUST_ERR=" + Marshal.GetLastWin32Error();
      }
      int gle = Marshal.GetLastWin32Error();
      return (gle == 0 ? "ENABLED" : "NOT_GRANTED(gle=" + gle + ")");
    } finally { CloseHandle(tok); }
  }
  [DllImport("kernel32.dll")]
  static extern bool CloseHandle(IntPtr H);
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }

L('probe102 begin ps=' + $PSVersionTable.PSVersion.ToString() + ' native=' + $native)
if ($native) {
  foreach ($p in @('SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeSystemProfilePrivilege', 'SeTcbPrivilege')) {
    L('ENABLE ' + $p + ' ' + [Pe102]::EnablePriv($p))
  }
}

function St([string]$n) { $s = (Get-Service -Name $n -EA SilentlyContinue).Status; if (-not $s) { return 'n/a' }; return "$s" }
function TryStart([string]$n, [string]$tag) {
  if (-not $native) { L('START ' + $n + ' ' + $tag + ' no-native'); return }
  $r = [Pe102]::Start($n)
  Start-Sleep -Seconds 4
  L('START ' + $n + ' ' + $tag + ' ' + $r + ' after=' + (St $n))
}

# ---------- A) what svchost groups does the IMAGE declare, and does each of ours exist ----------
L('== A svchost groups vs the -k each baked service asks for ==')
$svk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
$grpHave = @{}
foreach ($nm in @((Get-Item -LiteralPath $svk -EA SilentlyContinue).GetValueNames())) {
  $members = @((Get-Item -LiteralPath $svk).GetValue($nm) | ForEach-Object { "$_" })
  $grpHave[$nm.ToLower()] = $members
  L('GROUPDEF ' + $nm + ' count=' + $members.Count + ' [' + (C (($members -join ';'))) + ']')
}
foreach ($n in @('wlansvc', 'wcmsvc', 'WdiServiceHost', 'wdisystemhost')) {
  $img = '' + (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue).ImagePath
  $m = [regex]::Match($img, '(?i)-k\s+(?<g>[A-Za-z0-9_]+)')
  $g = ''
  if ($m.Success) { $g = $m.Groups['g'].Value }
  $exists = $grpHave.ContainsKey($g.ToLower())
  $listed = $false
  if ($exists) { foreach ($x in $grpHave[$g.ToLower()]) { if ("$x".ToLower() -eq $n.ToLower()) { $listed = $true } } }
  L('NEED ' + $n + ' group=[' + $g + '] group_defined=' + $exists + ' self_listed_in_group=' + $listed)
}

# ---------- B) H1 fix: define the missing group(s) with exactly the services that exist here ----------
L('== B create the missing svchost groups from the services actually present ==')
$need = @{}
foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue)) {
  $n = $k.PSChildName
  $img = '' + (Get-ItemProperty -LiteralPath $k.PSPath -EA SilentlyContinue).ImagePath
  if ($img -notmatch '(?i)svchost') { continue }
  $m = [regex]::Match($img, '(?i)-k\s+(?<g>[A-Za-z0-9_]+)')
  if (-not $m.Success) { continue }
  $g = $m.Groups['g'].Value
  if (-not $need.ContainsKey($g)) { $need[$g] = @() }
  $need[$g] += $n
}
foreach ($g in @($need.Keys | Sort-Object)) {
  if ($grpHave.ContainsKey($g.ToLower())) { continue }
  $svc = @($need[$g])
  L('GROUPFIX missing=' + $g + ' members_in_this_image=[' + ($svc -join ';') + ']')
  if ($DryRun -or (@($svc).Count -eq 0)) { L('GROUPFIX skip write for ' + $g); continue }
  try {
    New-ItemProperty -LiteralPath $svk -Name $g -Value ([string[]]$svc) -PropertyType MultiString -Force -EA Stop | Out-Null
    L('GROUPFIX wrote ' + $g + ' = [' + ($svc -join ';') + ']')
  } catch { L('GROUPFIX write FAILED ' + $g + ' ' + (C $_.Exception.Message)) }
}

# ---------- C) H2 experiment on WdiServiceHost RequiredPrivileges ----------
L('== C WdiServiceHost: is it the privilege list? ==')
$wdiK = 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost'
$orig = @((Get-ItemProperty -LiteralPath $wdiK -EA SilentlyContinue).RequiredPrivileges)
L('ORIG RequiredPrivileges=[' + ($orig -join ';') + ']')
TryStart 'WdiServiceHost' 'before-any-change'
if ((St 'WdiServiceHost') -ne 'Running') {
  if ($DryRun) {
    L('V1/V2 SKIPPED (DryRun): the two hypotheses are decided by editing RequiredPrivileges, nothing was written')
  } else {
    $v1 = @($orig | Where-Object { "$_" -notmatch '(?i)SystemProfile' })
    Set-ItemProperty -LiteralPath $wdiK -Name 'RequiredPrivileges' -Value ([string[]]$v1) -Type MultiString
    L('V1 wrote RequiredPrivileges=[' + ($v1 -join ';') + '] (SeSystemProfilePrivilege dropped)')
    TryStart 'WdiServiceHost' 'v1-no-systemprofile'
    if ((St 'WdiServiceHost') -ne 'Running') {
      Remove-ItemProperty -LiteralPath $wdiK -Name 'RequiredPrivileges' -EA SilentlyContinue
      L('V2 removed RequiredPrivileges entirely')
      TryStart 'WdiServiceHost' 'v2-no-privileges-value'
    }
  }
}

# ---------- D) now that the groups exist, retry the hosts that were silently exiting ----------
TryStart 'wdisystemhost' 'after-groupfix'

# ---------- E) the whole chain in host order, then ask wlanapi ----------
L('== E chain: nsi/RpcSs already up -> WdiServiceHost -> wdisystemhost -> wcmsvc -> wlansvc ==')
foreach ($n in @('WdiServiceHost', 'wdisystemhost', 'wcmsvc', 'wlansvc')) {
  if ((St $n) -eq 'Running') { L('CHAIN ' + $n + ' already Running'); continue }
  TryStart $n 'chain'
}
Start-Sleep -Seconds 2
L('CHAINFINAL WdiServiceHost=' + (St 'WdiServiceHost') + ' wdisystemhost=' + (St 'wdisystemhost') +
  ' wcmsvc=' + (St 'wcmsvc') + ' wlansvc=' + (St 'wlansvc'))

# does svchost actually host them now? (a service can be Running with a dead host process, so check both)
foreach ($p in @(Get-Process -Name svchost -EA SilentlyContinue)) {
  $cl = ''
  try { $cl = C ('' + (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.Id) -EA SilentlyContinue).CommandLine) } catch { }
  $svcs = @()
  try {
    $svcs = @(Get-CimInstance Win32_Service -Filter ('ProcessId=' + $p.Id) -EA SilentlyContinue | ForEach-Object { $_.Name })
  } catch { }
  L('SVCHOST pid=' + $p.Id + ' cmd=[' + $cl + '] services=[' + ($svcs -join ';') + ']')
}

# ---------- F) the point of all this: can wlanapi see an interface? ----------
$wlanSrc = @'
using System;
using System.Runtime.InteropServices;
public static class WlanApi2 {
  [DllImport("wlanapi.dll")]
  public static extern int WlanOpenHandle(uint ClientVersion, IntPtr Reserved, out int NegotiatedVersion, out IntPtr ClientHandle);
  [DllImport("wlanapi.dll")]
  public static extern int WlanCloseHandle(IntPtr ClientHandle, IntPtr Reserved);
  [DllImport("wlanapi.dll")]
  public static extern int WlanEnumInterfaces(IntPtr ClientHandle, IntPtr Reserved, out IntPtr List);
  [DllImport("wlanapi.dll")]
  public static extern void WlanFreeMemory(IntPtr Memory);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)]
  public static extern int WlanScan(IntPtr ClientHandle, IntPtr Reserved, ref Guid InterfaceGuid, IntPtr Dot11Ssid, IntPtr pVendorParameters);
  public static string Probe() {
    int ver = 0; IntPtr h = IntPtr.Zero, list = IntPtr.Zero;
    int r = WlanOpenHandle(1, IntPtr.Zero, out ver, out h);
    if (r != 0) { return "OPEN_ERR=" + r + " (1062=wlansvc not running, 1060=no such service)"; }
    try {
      r = WlanEnumInterfaces(h, IntPtr.Zero, out list);
      if (r != 0) { return "ENUM_ERR=" + r; }
      int count = Marshal.ReadInt32(list, 0);
      if (count <= 0) { return "COUNT=0"; }
      IntPtr e = new IntPtr(list.ToInt64() + 8);
      Guid g = (Guid)Marshal.PtrToStructure(e, typeof(Guid));
      int state = Marshal.ReadInt32(e, 528);
      string desc = "";
      try { desc = Marshal.PtrToStringUni(new IntPtr(e.ToInt64() + 16), 128).TrimEnd((char)0); } catch { }
      if (desc.Length > 40) { desc = desc.Substring(0, 40); }
      int sc = WlanScan(h, IntPtr.Zero, ref g, IntPtr.Zero, IntPtr.Zero);
      return "COUNT=" + count + " state=" + state + " scan_rc=" + sc + " desc=" + desc;
    } finally {
      if (list != IntPtr.Zero) { WlanFreeMemory(list); }
      WlanCloseHandle(h, IntPtr.Zero);
    }
  }
}
'@
try { Add-Type -TypeDefinition $wlanSrc -Language CSharp -EA Stop | Out-Null; L('WLANAPI ' + [WlanApi2]::Probe()) }
catch { L('WLANAPI FAILED ' + (C $_.Exception.Message)) }

# ---------- G) why did things exit? the SCM writes the exit code into the System log if logging exists ----------
L('== G service control manager trail ==')
try {
  $ev = @(Get-WinEvent -LogName 'System' -MaxEvents 60 -EA Stop |
          Where-Object { $_.ProviderName -match '(?i)Service Control Manager' } | Select-Object -First 12)
  foreach ($x in $ev) { L('EVT ' + $x.TimeCreated.ToString('HHmmss') + ' id=' + $x.Id + ' ' + (C $x.Message)) }
  if (@($ev).Count -eq 0) { L('EVT none matched') }
} catch { L('EVT unreadable: ' + (C $_.Exception.Message)) }

L('probe102 end -- NEED/GROUPFIX answer H1, V1/V2 answer H2, WLANAPI is the actual goal')
