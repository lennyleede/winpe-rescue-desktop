# probe150 -- can the PE even LOAD, one by one, the modules the healthy host's wlansvc loads -- in the
# host's load order -- and do wlansvc's delay-load contracts resolve here? The one assumption every
# previous check made for granted.
#
# Why this probe exists:
#   probe114 (build\scratch\p114_run_raw.txt) produced the complete ordered module list of the failing PE
#   wlansvc host for the first time and diffed it against the healthy host's 82-module sequence:
#     PE:  ... ntasn1(host#30) mobilenetworking wlansvcpal oleaut32 msxml6 wmiclnt(host#48) -> EXIT
#     host: ... ntasn1(#30) wldp(#31) wlansvcpal oleaut32 clbcatq msxml6 crypt32 dpapi cryptbase cryptsp
#              rsaenh authz tetheringieprovider wifidisplay cfgmgr32 devobj sspicli mswsock wmiclnt(#48)
#              **wlgpclnt(#49)** shcore gpapi dsrole sysntfy wtsapi32 winsta usermgrcli powrprof ...
#   So the PE dies at the exact step where the host first resolves
#   wlansvc.dll -> ext-ms-win-wlan-grouppolicy-l1-1-0.dll -> wlgpclnt.dll (verbatim in wlansvc.dll's
#   DELAY-LIST). A failed *delay-load* is silent -- the helper raises STATUS_DLL_NOT_FOUND, wlansvc's own
#   SEH converts it to a return code, the service exits without a crash -- which is precisely the
#   "loaded=36, state=1, specific=0x800C0006, ~130ms, no fault" signature probe86/probe99 established.
#   build\scratch\t_p150_closure.ps1 then showed that every borrowed file's *static* imports exist in the
#   image (PE-LACKS-STATIC=none for all 15 late-bound DLLs + wlgpclnt + wlanmsm + wlansec), but it had to
#   label every api-ms-*/ext-ms-* name "APSET-UNVERIFIED": t_wdi_imports_host.ps1's resolver has always
#   counted api sets as satisfied *by definition* (`if ($name -like 'api-*'...) return $true`) and nobody
#   ever tested that in the PE. That is the last unchecked assumption in the file layer.
#
# Instruments, cheapest and most decisive first:
#   S1 ordered LoadLibrary census of the host's 82 modules, each tried twice: with
#      LOAD_WITH_ALTERED_SEARCH_PATH on the full X:\ path (import-satisfiability without touching the
#      caller's default search order) and with DONT_RESOLVE_DLL_REFERENCES. The number to look at is
#      FIRST-FAIL: the lowest host-order module the PE cannot load. If that is wlgpclnt.dll, the
#      divergence is explained by a load failure, not by a missing service decision.
#   S2 wlansvc.dll's own 32 delay-load names, resolved by name the way the loader will do it, and for the
#      api sets the *file that answered* is printed -- that is the only way to see whether
#      ext-ms-win-wlan-grouppolicy-l1-1-0 actually maps to wlgpclnt.dll in this image.
#   S3 retry wlansvc once, so a run of this probe can also show whether anything changed.
# Read-only: FreeLibrary right after each load; no registry, no copies, the disc is untouched.
param([switch]$DryRun, [string]$Root = 'X:\Windows\System32')
function L([string]$s) { Write-Output ('P150 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = (C $Root)

# Host load order of a healthy wlansvc svchost (build\scratch\t_p110_host82.ps1), verbatim.
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

# wlansvc.dll's delay-import directory, verbatim from t_wdi_imports_host.ps1 DELAY-LIST (32 names).
$delay = @('api-ms-win-core-com-l1-1-0.dll', 'api-ms-win-devices-query-l1-1-0.dll',
  'api-ms-win-devices-query-l1-1-1.dll', 'api-ms-win-oobe-notification-l1-1-0.dll',
  'api-ms-win-power-setting-l1-1-0.dll', 'api-ms-win-shell-shellfolders-l1-1-0.dll', 'AUTHZ.dll',
  'bcrypt.dll', 'CRYPT32.dll', 'CRYPTSP.dll', 'deviceassociation.dll', 'DEVOBJ.dll', 'dhcpcsvc.DLL',
  'DSROLE.dll', 'eappcfg.dll', 'EventAggregation.dll', 'ext-ms-win-devmgmt-policy-l1-1-0.dll',
  'ext-ms-win-networking-wlanstorage-l1-1-0.dll', 'ext-ms-win-ntuser-windowclass-l1-1-0.dll',
  'ext-ms-win-session-usermgr-l1-1-0.dll', 'ext-ms-win-session-usertoken-l1-1-0.dll',
  'ext-ms-win-session-wtsapi32-l1-1-0.dll', 'ext-ms-win-shell-embeddedmode-l1-1-0.dll',
  'ext-ms-win-wlan-grouppolicy-l1-1-0.dll', 'ext-ms-win-wlan-scard-l1-1-0.dll', 'IPHLPAPI.DLL',
  'IpNatHlpClient.dll', 'NetSetupApi.dll', 'OLEAUT32.dll', 'profapi.dll', 'SYSNTFY.dll', 'WMICLNT.dll',
  # not in wlansvc's own table, but a *static* import of wlgpclnt.dll (t_p150_closure) and the contract
  # the group-policy path actually goes through, so it belongs in the same census.
  'api-ms-win-security-grouppolicy-l1-1-0.dll', 'api-ms-win-shell-shdirectory-l1-1-0.dll')

$src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class Ld150 {
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern uint GetModuleFileNameW(IntPtr h, StringBuilder buf, uint size);
  const uint DONT_RESOLVE_DLL_REFERENCES = 0x00000001;
  const uint LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008;

  static string Name(IntPtr h) {
    StringBuilder sb = new StringBuilder(1024);
    if (GetModuleFileNameW(h, sb, (uint)sb.Capacity) == 0) return "?err" + Marshal.GetLastWin32Error();
    return sb.ToString();
  }
  // Full-path load: does the loader manage to bring this file in at all (static imports + api sets)?
  public static string ByPath(string fullPath) {
    IntPtr h = LoadLibraryExW(fullPath, IntPtr.Zero, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "FAIL err=" + Marshal.GetLastWin32Error() + " " + NtStatusName(Marshal.GetLastWin32Error());
    string n = Name(h);
    FreeLibrary(h);
    return "OK via=" + n;
  }
  // Import-satisfiability only: DONT_RESOLVE_DLL_REFERENCES still resolves the import directory but
  // skips DllMain/TLS, so nothing in the DLL actually runs.
  public static string ByPathNoMain(string fullPath) {
    IntPtr h = LoadLibraryExW(fullPath, IntPtr.Zero, DONT_RESOLVE_DLL_REFERENCES | LOAD_WITH_ALTERED_SEARCH_PATH);
    if (h == IntPtr.Zero) return "FAIL err=" + Marshal.GetLastWin32Error();
    string n = Name(h);
    FreeLibrary(h);
    return "OK(no-main) via=" + n;
  }
  // The name-as-the-service-uses-it test: a delay helper calls LoadLibrary("ext-ms-win-..."), which the
  // loader resolves through the ApiSetMap and NEVER looks up on disk. Reporting the file that answered is
  // the only way to see whether the contract maps to the DLL we borrowed.
  public static string ByName(string name) {
    IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0);
    if (h == IntPtr.Zero) return "FAIL err=" + Marshal.GetLastWin32Error() + " " + NtStatusName(Marshal.GetLastWin32Error());
    string n = Name(h);
    FreeLibrary(h);
    return "OK via=" + n;
  }
  static string NtStatusName(int e) {
    // 126 ERROR_MOD_NOT_FOUND, 127 ERROR_PROC_NOT_FOUND, 193 ERROR_BAD_EXE_FORMAT,
    // 577 ERROR_DRIVER_BLOCKED, 1114 ERROR_DLL_INIT_FAILED
    if (e == 126) return "(MOD_NOT_FOUND)";
    if (e == 127) return "(PROC_NOT_FOUND)";
    if (e == 193) return "(BAD_EXE_FORMAT)";
    if (e == 1114) return "(DLL_INIT_FAILED)";
    if (e == 5) return "(ACCESS_DENIED)";
    return "";
  }
}
'@

if ($DryRun) {
  L('DRY probe150: S1 LoadLibrary ' + $hostOrder.Count + ' host-order modules from ' + $s32 + ' (altered path + no-main),')
  L('DRY  S2 resolve wlansvc.dll''s ' + $delay.Count + ' delay names BY NAME, printing the file that answered for each api set,')
  L('DRY  S3 one wlansvc start attempt for the record. Frees every handle immediately; no writes, disc untouched.')
  $n = 0
  try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $n = 1 }
  catch { L('DRY ADDTYPE FAILED ' + (C $_.Exception.Message)) }
  L('DRY class compiled=' + $n + '/1')
  exit 0
}
$ld = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $ld = $true }
catch { L('ADDTYPE FAILED ' + (C $_.Exception.Message)) }
L('probe150 begin ld=' + $ld + ' root=[' + $s32 + '] hostOrder=' + $hostOrder.Count + ' delay=' + $delay.Count)
if (-not $ld) { L('ABORT'); exit 1 }

# ---------- S1: the host's module sequence, loadable here or not ----------
$firstFail = ''
$fails = @()
$oks = 0
for ($i = 0; $i -lt $hostOrder.Count; $i++) {
  $n = ('' + $hostOrder[$i])
  $p = $s32 + '\' + $n
  if ($n -eq 'svchost.exe' -or $n -eq 'ntdll.dll' -or $n -eq 'kernel32.dll' -or $n -eq 'kernelbase.dll' -or
      $n -eq 'sechost.dll' -or $n -eq 'rpcrt4.dll' -or $n -eq 'user32.dll' -or $n -eq 'win32u.dll' -or
      $n -eq 'advapi32.dll' -or $n -eq 'ws2_32.dll' -or $n -eq 'ole32.dll') {
    L('S1 ' + ($i + 1).ToString('00') + ' ' + (C $n).PadRight(30) + ' skip(already loaded in this process)')
    $oks++
    continue
  }
  $r1 = ''
  try { $r1 = [Ld150]::ByPath($p) } catch { $r1 = 'EXCEPTION ' + (C $_.Exception.Message) }
  $r2 = ''
  if ($r1 -like 'FAIL*') {
    try { $r2 = [Ld150]::ByPathNoMain($p) } catch { $r2 = 'EXCEPTION ' + (C $_.Exception.Message) }
  }
  $tag = 'OK'
  if ($r1 -like 'FAIL*') { $tag = 'FAIL' }
  L('S1 ' + ($i + 1).ToString('00') + ' ' + (C $n).PadRight(30) + ' ' + (C $r1) + $(if ($r2) { ' | no-main ' + (C $r2) } else { '' }))
  if ($tag -eq 'OK') { $oks++ } else {
    $fails += (($i + 1).ToString('00') + ':' + $n)
    if (-not $firstFail) { $firstFail = (($i + 1).ToString('00') + ':' + $n + ' ' + (C $r1)) }
  }
}
L('S1 loadable=' + $oks + '/' + $hostOrder.Count + ' first-fail=' + $(if ($firstFail) { $firstFail } else { 'none' }))
L('S1 FAILS=' + @($fails).Count + ' [' + (@($fails) -join ',') + ']')

# ---------- S2: wlansvc's delay table, resolved the way the service will ask ----------
$deadSet = @(); $okSet = @()
foreach ($n in $delay) {
  $r = ''
  try { $r = [Ld150]::ByName($n) } catch { $r = 'EXCEPTION ' + (C $_.Exception.Message) }
  L('S2 ' + (C $n).PadRight(46) + ' ' + (C $r))
  if ($r -like 'FAIL*') { $deadSet += $n } else { $okSet += $n }
}
L('S2 delay-resolvable=' + @($okSet).Count + '/' + $delay.Count)
L('S2 DELAY-DEAD=' + @($deadSet).Count + ' [' + (@($deadSet) -join ',') + ']')

# ---------- S3: one start attempt, for the record ----------
L('S3 note: the trace instrument lives in probe114; this probe only answers load-resolvability.')
L('probe150 end -- judgement: S1 first-fail + S2 DELAY-DEAD. An api set that FAILS by name while its host')
L('file loads by path means the ADK ApiSetMap has no entry for it, which no file copy can fix.')
