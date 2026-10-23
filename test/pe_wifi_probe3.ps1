# test/pe_wifi_probe3.ps1 -- runs INSIDE a live PE (push with test\host_push_run.ps1 -Run).
# probe2 proved: no missing DLLs (all LOAD-OK) and dot3svc starts fine with the same svchost shape,
# yet wlansvc stops with win32 exit 6. This probe asks the SCM itself for the numbers:
#   - StartService + poll QueryServiceStatusEx -> win32ExitCode AND serviceSpecificCode
#   - QueryServiceConfig2 -> required privileges / sid type / triggers / preshutdown, PE vs host
#   - whether the WinRT contracts wlansvc.dll imports actually resolve in PE
#   - the real svchost group keys (probe2's "NO SVCHOST KEY" needs explaining: dot3svc works)
#   - netsh helper DLLs resolved the right way (probe2 compared bare names against the CWD)
# -SkipStart makes it safe to run on the build host as the "known good" reference.
# ASCII output only.
param([switch]$SkipStart)
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' ') -replace '\s{2,}', ' ' }
$S32 = Join-Path $env:SystemRoot 'System32'

Sec '0_WHO'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' build=' + [Environment]::OSVersion.Version.Build + ' sysroot=' + $env:SystemRoot)

# ---------- native helpers ----------
$advSrc = @'
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenSCManager(string machine, string database, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenService(IntPtr scm, string name, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool CloseServiceHandle(IntPtr h);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool StartService(IntPtr svc, uint numArgs, IntPtr args);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool QueryServiceStatusEx(IntPtr svc, uint infoLevel, byte[] buf, uint cb, out uint needed);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern uint QueryServiceConfig2(IntPtr svc, uint infoLevel, out IntPtr buf);
public class SvcStatus { public int serviceType; public int currentState; public int controlsAccepted; public int win32ExitCode; public int serviceSpecificCode; public int checkPoint; public int waitHint; public int pid; }
public static string LastErr() { return "win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error(); }
public static IntPtr OpenScm() { return OpenSCManager(null, null, 0x000F003F); }
public static IntPtr OpenSvc(IntPtr scm, string name) { return OpenService(scm, name, 0x000F01FF); }
public static void Close(IntPtr h) { if (h != System.IntPtr.Zero) CloseServiceHandle(h); }
public static bool Start(IntPtr s) { return StartService(s, 0, System.IntPtr.Zero); }
public static SvcStatus Status(IntPtr s) {
  byte[] buf = new byte[48];
  uint need;
  if (!QueryServiceStatusEx(s, 0 /*SC_STATUS_PROCESS_INFO*/, buf, (uint)buf.Length, out need)) return null;
  SvcStatus st = new SvcStatus();
  st.serviceType         = System.BitConverter.ToInt32(buf, 0);
  st.currentState        = System.BitConverter.ToInt32(buf, 4);
  st.controlsAccepted    = System.BitConverter.ToInt32(buf, 8);
  st.win32ExitCode       = System.BitConverter.ToInt32(buf, 12);
  st.serviceSpecificCode = System.BitConverter.ToInt32(buf, 16);
  st.checkPoint          = System.BitConverter.ToInt32(buf, 20);
  st.waitHint            = System.BitConverter.ToInt32(buf, 24);
  st.pid                 = System.BitConverter.ToInt32(buf, 28);
  return st;
}
public static string Privs(IntPtr s) {
  IntPtr p;
  uint rc = QueryServiceConfig2(s, 2 /*REQUIRED_PRIVS*/, out p);
  if (rc == 0 || p == System.IntPtr.Zero) return "rc=0 win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  int n = System.Runtime.InteropServices.Marshal.ReadInt32(p);
  // SERVICE_PRIVILEGES { DWORD count; LPCWSTR list[]; } -- on x64 the array pointer sits at offset 8
  System.IntPtr arr = System.Runtime.InteropServices.Marshal.ReadIntPtr(System.IntPtr.Add(p, System.IntPtr.Size));
  string[] names = new string[n];
  for (int i = 0; i < n; i++) {
    names[i] = System.Runtime.InteropServices.Marshal.PtrToStringUni(
      System.Runtime.InteropServices.Marshal.ReadIntPtr(System.IntPtr.Add(arr, i * System.IntPtr.Size)));
  }
  return "n=" + n + " [" + string.Join(",", names) + "]";
}
public static string SidType(IntPtr s) {
  IntPtr p;
  uint rc = QueryServiceConfig2(s, 5 /*SID_INFO*/, out p);
  if (rc == 0 || p == System.IntPtr.Zero) return "rc=0 win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return "sidType=" + System.Runtime.InteropServices.Marshal.ReadInt32(p);
}
public static string TriggerInfo(IntPtr s) {
  IntPtr p;
  uint rc = QueryServiceConfig2(s, 8 /*TRIGGER_INFO*/, out p);
  if (rc == 0) return "rc=0 win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + " (no trigger info)";
  if (p == System.IntPtr.Zero) return "null buffer";
  int n = System.Runtime.InteropServices.Marshal.ReadInt32(p);
  return "triggerCount=" + n;
}
public static string Preshutdown(IntPtr s) {
  IntPtr p;
  uint rc = QueryServiceConfig2(s, 4 /*PRESHUTDOWN_INFO*/, out p);
  if (rc == 0) return "rc=0 win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return "preshutdownMs=" + System.Runtime.InteropServices.Marshal.ReadInt32(p);
}
'@
$advOk = $false
try { $null = Add-Type -MemberDefinition $advSrc -Name A -Namespace W3 -PassThru -Language CSharp -EA Stop; $advOk = $true; Write-Output '(advapi32 helpers compiled)' }
catch { Write-Output ('  Add-Type(advapi) failed: ' + (One $_.Exception.Message)) }

$ldrSrc = @'
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr LoadLibraryExW(string dll, IntPtr hFile, uint flags);
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true) ]
static extern int FreeLibrary(IntPtr m);
public static string Resolve(string name) {
  // LOAD_LIBRARY_AS_DATAFILE (0x20): the loader still resolves the module and its api-set aliases,
  // but DllMain never runs -- safe for probing crypto/network DLLs we do not want to initialise.
  IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0x20);
  if (h == IntPtr.Zero) {
    int e = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return "FAIL win32=" + e + " (0x" + e.ToString("X8") + ")";
  }
  FreeLibrary(h);
  return "RESOLVE-OK";
}
public static string Contract(string name) {
  // api-set aliases are NOT files; a datafile load of them returns ERROR_FILE_NOT_FOUND(2) even on a
  // healthy system, so contracts have to be probed with an ordinary load (the host module is already
  // resident in this process, so this only bumps a refcount).
  IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0x00000100); // LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
  if (h == IntPtr.Zero) {
    int e = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return "FAIL win32=" + e + " (0x" + e.ToString("X8") + ")";
  }
  FreeLibrary(h);
  return "CONTRACT-OK";
}
'@
$ldrOk = $false
try { $null = Add-Type -MemberDefinition $ldrSrc -Name L -Namespace W3L -PassThru -Language CSharp -EA Stop; $ldrOk = $true }
catch { Write-Output ('  Add-Type(loader) failed: ' + (One $_.Exception.Message)) }

Sec '1_SCM_STATUS_OF_WLAN_AND_WCM'
if ($advOk) {
  $scm = [W3.A]::OpenScm()
  if ($scm -eq [IntPtr]::Zero) { Write-Output ('  OpenSCManager failed ' + [W3.A]::LastErr()) }
  foreach ($s in @('wlansvc','wcmsvc','dot3svc','RpcSs')) {
    $sv = [W3.A]::OpenSvc($scm, $s)
    if ($sv -eq [IntPtr]::Zero) { Write-Output ('  ' + $s + ' OpenService failed ' + [W3.A]::LastErr()); continue }
    $st0 = [W3.A]::Status($sv)
    if ($st0) {
      Write-Output ('  ' + $s.PadRight(9) + ' before: state=' + $st0.currentState + ' exit=' + $st0.win32ExitCode + ' specific=0x' + ('{0:X8}' -f $st0.serviceSpecificCode) + ' pid=' + $st0.pid + ' controls=' + $st0.controlsAccepted)
    } else { Write-Output ('  ' + $s.PadRight(9) + ' QueryServiceStatusEx failed ' + [W3.A]::LastErr()) }
    if (-not $SkipStart -and $st0 -and $st0.currentState -ne 4) {
      $ok = [W3.A]::Start($sv)
      $err = if ($ok) { 'StartService returned true' } else { [W3.A]::LastErr() }
      Write-Output ('      Start -> ' + $err)
      for ($i = 1; $i -le 12; $i++) {
        Start-Sleep -Milliseconds 700
        $st1 = [W3.A]::Status($sv)
        if (-not $st1) { Write-Output '      status read failed'; break }
        Write-Output ('      poll ' + $i + ': state=' + $st1.currentState + ' checkpoint=' + $st1.checkPoint + ' wait=' + $st1.waitHint + ' exit=' + $st1.win32ExitCode + ' specific=0x' + ('{0:X8}' -f $st1.serviceSpecificCode) + ' pid=' + $st1.pid)
        if ($st1.currentState -ne 2) { break }
      }
    }
    Write-Output ('      config: sidType ' + [W3.A]::SidType($sv) + ' | trigger ' + [W3.A]::TriggerInfo($sv) + ' | preshutdown ' + [W3.A]::Preshutdown($sv))
    Write-Output ('      privs:  ' + [W3.A]::Privs($sv))
    [W3.A]::Close($sv)
  }
  [W3.A]::Close($scm)
} else { Write-Output '  advapi helpers unavailable, skipping' }

Sec '2_SVCHOST_GROUP_KEYS'
# The group -> service-name lists live in the SOFTWARE hive, NOT under Services:
#   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST   (probe2 looked in Services\SVCHOST,
#   which does not exist on the host either -- that "NO SVCHOST KEY" line was a false alarm.)
$SH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
if (-not (Test-Path $SH)) { $SH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' }
if (Test-Path $SH) {
  $gi = Get-Item $SH
  Write-Output ('  container = ' + $SH + '  values=' + @($gi.GetValueNames()).Count)
  foreach ($n in $gi.GetValueNames()) {
    if (-not $n) { continue }
    $lst = @($gi.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) | Where-Object { $_ }
    $tag = ''
    if ($lst -contains 'wlansvc') { $tag += ' <wlansvc>' }
    if ($lst -contains 'wcmsvc')  { $tag += ' <wcmsvc>' }
    if ($lst -contains 'dot3svc') { $tag += ' <dot3svc>' }
    if ($tag -ne '' -or $n -match '(?i)network') {
      Write-Output ('    ' + $n.PadRight(34) + ' n=' + $lst.Count + $tag)
      if ($tag) { Write-Output ('        members: ' + ($lst -join ',')) }
    }
  }
  Write-Output ('  wlansvc present in LocalSystemNetworkRestricted = ' + (@($gi.GetValue('LocalSystemNetworkRestricted')) -contains 'wlansvc'))
  Write-Output ('  wcmsvc  present in LocalServiceNetworkRestricted = ' + (@($gi.GetValue('LocalServiceNetworkRestricted')) -contains 'wcmsvc'))
  Write-Output ('  dot3svc present in LocalSystemNetworkRestricted = ' + (@($gi.GetValue('LocalSystemNetworkRestricted')) -contains 'dot3svc'))
} else {
  Write-Output '  SVCHOST container key not found in SOFTWARE -- svchost cannot resolve ANY group'
}
Write-Output '  -- sanity: Services child count'
$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$kids = @(Get-ChildItem $svcRoot -EA SilentlyContinue)
Write-Output ('  Services has ' + $kids.Count + ' child keys')

Sec '3_NETSH_HELPERS_RESOLVED'
$nk = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $nk) {
  $np = Get-Item $nk
  foreach ($n in $np.GetValueNames()) {
    if (-not $n) { continue }
    $dv = [string]$np.GetValue($n)
    $cand = $dv
    if ($cand -notmatch '[\\]') { $cand = Join-Path $S32 $dv }    # registry stores bare dll names
    $cand = [Environment]::ExpandEnvironmentVariables($cand)
    $ex = Test-Path -LiteralPath $cand
    $ld = 'n/a'
    if ($ex -and $ldrOk) { $ld = [W3L.L]::Resolve($cand) }
    Write-Output ('  ' + $n.PadRight(14) + ' -> ' + $cand + ' file=' + $(if ($ex) { 'OK' } else { 'MISSING' }) + ' load=' + $ld)
  }
} else { Write-Output '  NO HKLM\SOFTWARE\Microsoft\Netsh key at all' }

Sec '4_CONTRACT_AND_MODULE_PROBE'
foreach ($m in @('api-ms-win-core-winrt-l1-1-0.dll','api-ms-win-core-winrt-roapi-l2-1-1.dll','api-ms-win-core-winrt-string-l1-1-0.dll','api-ms-win-core-com-l1-1-0.dll','api-ms-win-core-winrt-error-l1-1-1.dll','api-ms-win-service-management-l2-1-0.dll','api-ms-win-security-lsalookup-l2-1-0.dll','api-ms-win-stateseparation-helpers-l1-1-0.dll','wlanutil.dll','wlancfg.dll','wlanapi.dll','dot3cfg.dll','wlanext.exe','OneX.DLL','wintbdrv.dll','nlaapi.dll','winnsi.dll','tbs.dll','msv1_0.dll','wdigest.dll','pku2u.dll','credssp.dll','schannel.dll','wlansec.dll','eappprxy.dll','qwave.dll','ikeext.dll','ncryptsslp.dll','umpdc.dll','mobilenetworking.dll','wimgapi.dll')) {
  $r = 'loader-unavailable'
  if ($ldrOk) {
    if ($m -match '(?i)^(api-ms-win|ext-ms-win)-') { $r = [W3L.L]::Contract($m) } else { $r = [W3L.L]::Resolve($m) }
  }
  Write-Output ('  ' + $m.PadRight(48) + ' ' + $r)
}

Sec '5_STATE_DIRS'
foreach ($d in @('X:\ProgramData', $env:ProgramData, (Join-Path $env:ProgramData 'Microsoft\Wlansvc'), 'C:\ProgramData', (Join-Path $env:SystemRoot 'System32\LogFiles'), (Join-Path $env:SystemRoot 'System32\catroot'), (Join-Path $env:SystemRoot 'System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'))) {
  Write-Output ('  ' + $(if (Test-Path -LiteralPath $d) { 'OK    ' } else { 'ABSENT' }) + ' ' + $d)
}
Write-Output ('  TEMP=' + $env:TEMP + ' exists=' + (Test-Path -LiteralPath $env:TEMP) + ' | USERPROFILE=' + $env:USERPROFILE + ' exists=' + (Test-Path -LiteralPath $env:USERPROFILE))

Sec '6_WIRELESS_DEVNODES'
foreach ($d in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)wireless|wi-fi|wifi|wlan|ax21|network controller' } | Select-Object -First 12)) {
  Write-Output ('    ' + (One ($d.Name + ' | ' + $d.DeviceID + ' | class=' + $d.PNClass + ' | code=' + $d.ConfigManagerErrorCode)))
}
Write-Output '  -- is the native wifi layer visible at all? (Win32_NetworkAdapter with PhysicalAdapter, and MACServiceClass devices)'
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Select-Object -First 8)) {
  Write-Output ('    adapter: ' + (One ($a.Name + ' | guid=' + $a.GUID + ' | physical=' + $a.PhysicalAdapter + ' | devstatus=' + $a.Status)))
}

Sec '7_WLANOPEN_AFTER_PROBE'
if (-not $SkipStart) {
  $apiSrc = @'
[ System.Runtime.InteropServices.DllImport("wlanapi.dll") ]
public static extern int WlanOpenHandle(uint ver, IntPtr r, out uint outVer, out IntPtr handle);
[ System.Runtime.InteropServices.DllImport("wlanapi.dll") ]
public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr r, out IntPtr list, uint timeout);
public static string OpenAndEnum() {
  uint v; IntPtr h;
  int rc = WlanOpenHandle(2, IntPtr.Zero, out v, out h);
  if (rc != 0) return "WlanOpenHandle rc=0x" + rc.ToString("X8") + " (" + rc + ")";
  IntPtr p;
  int e = WlanEnumInterfaces(h, IntPtr.Zero, out p, 5000);
  return "open ok ver=" + v + " WlanEnumInterfaces rc=0x" + e.ToString("X8");
}
'@
  try {
    $null = Add-Type -MemberDefinition $apiSrc -Name Wa -Namespace W3W -PassThru -Language CSharp -EA Stop
    Write-Output ('  ' + [W3W.Wa]::OpenAndEnum())
  } catch { Write-Output ('  wlanapi probe failed: ' + (One $_.Exception.Message)) }
}

Sec '8_NWIFI_DRIVER_TEST'
# wlansvc cannot bind a single radio without the NativeWiFi filter miniport. The PE is 26100 while the
# borrowed nwifi.sys is 19041 -- if NDIS refuses it, WiFi is dead no matter what the service does.
$ndis = Join-Path $S32 'drivers\ndis.sys'
$nw   = Join-Path $S32 'drivers\nwifi.sys'
foreach ($f in @($ndis, $nw, (Join-Path $S32 'drivers\n_dis.sys'))) {
  if (Test-Path -LiteralPath $f) {
    Write-Output ('  file ' + $f + ' v=' + (Get-Item -LiteralPath $f).VersionInfo.FileVersion)
  } else { Write-Output ('  file ' + $f + ' ABSENT') }
}
Write-Output '  -- try to load the borrowed native-wifi filter into the running kernel'
if ($SkipStart) {
  Write-Output '     (skipped: -SkipStart, no driver loading on the reference machine)'
} elseif (Test-Path -LiteralPath $nw) {
  $o = & drvload.exe $nw 2>&1 | Out-String
  Write-Output ('     drvload nwifi -> rc=' + $LASTEXITCODE + ' out=' + (One $o))
}
foreach ($d in @('nativewifip','Ndisuio','ndis')) {
  $q = Get-CimInstance Win32_SystemDriver -Filter "Name='$d'" -EA SilentlyContinue
  if ($q) { Write-Output ('  systemdriver ' + $d + ': State=' + $q.State + ' Started=' + $q.Started + ' StartMode=' + $q.StartMode + ' Path=' + $q.PathName) }
  else { Write-Output ('  systemdriver ' + $d + ': not listed') }
}
Write-Output '  -- is there a 26100 nwifi.sys already inside this image (DriverStore / WinSxS)?'
$found = @()
if ($SkipStart) {
  Write-Output '    (skipped: -SkipStart; the host tree is far too big to walk)'
} else {
foreach ($root in @((Join-Path $env:SystemRoot 'System32\DriverStore'), (Join-Path $env:SystemRoot 'WinSxS'))) {
  if (Test-Path $root) {
    $found += @(Get-ChildItem $root -Recurse -File -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)^nwifi\.sys$' } | Select-Object -First 6)
  } else { Write-Output ('  (absent) ' + $root) }
}
foreach ($f in $found) { Write-Output ('    ' + $f.FullName + ' v=' + $f.VersionInfo.FileVersion + ' size=' + $f.Length) }
if (-not $found.Count) { Write-Output '    no other nwifi.sys in the image' }
}

Sec '9_WLANSVC_KEY_DIFF'
# Print every value of the three service keys so a PE dump can be diffed line-by-line against the host.
foreach ($s in @('wlansvc','wcmsvc','dot3svc')) {
  foreach ($sub in @('', '\Parameters', '\Security', '\EnumDependencies')) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s + $sub
    if (-not (Test-Path $k)) { if ($sub -eq '') { Write-Output ('  KEY MISSING: ' + $s) }; continue }
    $ki = Get-Item $k
    foreach ($vn in $ki.GetValueNames()) {
      $nm2 = if ($vn) { $vn } else { '(default)' }
      $raw = $ki.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
      $type = $ki.GetValueKind($vn)
      $disp = if ($raw -is [array]) { ($raw | ForEach-Object { if ($_ -is [byte]) { ('{0:X2}' -f $_) } else { [string]$_ } }) -join ',' } else { [string]$raw }
      if ($disp.Length -gt 220) { $disp = $disp.Substring(0, 220) + '...' }
      Write-Output ('  ' + $s + $sub + '\' + $nm2 + ' [' + $type + '] = ' + $disp)
    }
  }
}

Sec 'DONE'
Write-Output '  probe3 complete'
