# ============================================================
# probe84_doubles.ps1 -- the SCM appends "-s <service>" itself, so an ImagePath that ALREADY ends with
# "-s <service>" hands svchost a second -s and the host process dies before it can report anything.
#
# probe83 (build/scratch/p83_push_1010.txt) closed the crash theory and opened this one:
#   * StartServiceW returns **1053 immediately**, and 60 polls at 100 ms never saw a new svchost child;
#     WER LocalDumps was ON (WerFault.exe/wermgr.exe are both in the image) and no dump appeared
#     -> nothing crashed, because nothing was ever created (or it died in well under 100 ms).
#   * the PE has no event log files at all (winevt\Logs empty, "System/Application log: cannot find the
#     file"), so 7031/7034-style evidence does not exist here; WER + lifetime watching is all we get.
#   * the delay-load gaps are real but cannot be the 1053: policymanager.dll, embeddedmodesvcapi.dll,
#     wlgpclnt.dll, cmintegrator.dll, deviceassociation.dll, IpNatHlpClient.dll are all ABSENT from the
#     image (and the two ext-ms names that DO have a PE file, nlaapi.dll / wlanstorage, still do not
#     resolve -- 26100 apisetschema maps them elsewhere). Those are feature gaps to bake later, not the
#     reason the process never appears.
#   * the healthy controls, in the same image, same svchost.exe: dot3svc RUNNING with
#     ImagePath "...svchost.exe -k LocalSystemNetworkRestricted -p"  (NO -s)
#     Dhcp       RUNNING with "...svchost.exe -k LocalServiceNetworkRestricted -p" (NO -s)
#   * the two broken ones in this ramdisk hive, from probe47/48's experiments:
#     wlansvc "...svchost.exe -k wlansvcs -p -s wlansvc"   (has -s)
#     wcmsvc  "...svchost.exe -k wcmsvcs -p -s wcmsvc"     (has -s)
#
# The bake does NOT write -s (wifi-inject.ps1 Write-WlanServiceKeys lines 538/559 match dot3svc/Dhcp
# exactly), so this probe is simultaneously (a) the causal A/B/C test of the double -s and (b) a live
# rehearsal of the pristine baked shape -- without waiting for the reboot that task #20 needs.
#
# Order per service: A = start as the hive has it now; B = SetImagePath to the pristine bake shape and
# start; C = put "-s <name>" back on the pristine group and start (proves the direction of causality);
# then, if the service reaches Running, call WlanOpenHandle/WlanEnumInterfaces -- the actual acceptance
# signal for "PE can get on the network over WiFi".
#
# Writes: ChangeServiceConfigW on wlansvc/wcmsvc (ramdisk SCM record + hive, gone on reboot), the svchost
#         group MULTI_SZ values if a group does not list the service, and StartServiceW.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe84_doubles.ps1 -RemotePath X:/p84.ps1 -StagingB64 X:/p84.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# Buffered logging: StartWatch/WlanOpenReport return a VALUE, and a Write-Output inside such a function
# would be collected into that return value (probe50 learned this the hard way). Those functions use
# LogLine, and the caller flushes right after -- so the field run still prints everything in order.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }
function ErrName([int]$e) {
  $m = @{ 5 = 'ACCESS_DENIED'; 87 = 'INVALID_PARAMETER'; 1053 = 'TIMEOUT'; 1056 = 'ALREADY_STARTED';
          1057 = 'INVALID_NAME'; 1058 = 'DISABLED'; 1062 = 'SERVICE_NOT_RUNNING'; 1068 = 'DEPENDENCY_FAILED';
          1069 = 'LOGON_FAILED'; 126 = 'MOD_NOT_FOUND' }
  if ($m.ContainsKey($e)) { return ('' + $e + '_' + $m[$e]) }
  return '' + $e
}
$S32 = 'X:\Windows\System32'
$REG = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SVCHOSTKEY = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
# the two shapes, exactly as wifi-inject.ps1 bakes them
$IMG_WL_BAKE = '%SystemRoot%\System32\svchost.exe -k LocalSystemNetworkRestricted -p'
$IMG_WC_BAKE = '%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p'
$VERD = @{ pre = ''; A = ''; B = ''; C = ''; wcB = ''; child = ''; open = -1; ifaces = -1; grp = '' }

function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim() -replace '\\0', ';')
    }
  }
  return ''
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function GrpOf([string]$img) { if ($img -match '-k\s+(\S+)') { return $matches[1] } return '' }
function HasSvc([string]$img) { if ($img -match '-s\s+(\S+)') { return $matches[1] } return '' }

# ---------- SCM API (the exact marshalling probe49/50/83 proved in PE) ----------
if (-not ('P84.SCM' -as [type])) {
  Add-Type -Namespace P84 -Name SCM -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct SP { public IntPtr p; }
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 4)]
public struct SS {
  public int dwServiceType; public int dwCurrentState; public int dwControlsAccepted;
  public int dwWin32ExitCode; public int dwServiceSpecificExitCode; public int dwCheckPoint; public int dwWaitHint;
}
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern IntPtr OpenSCManagerW(IntPtr machine, IntPtr database, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr OpenServiceW(IntPtr scm, string name, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CloseServiceHandle(IntPtr h);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceStatus(IntPtr svc, ref SS st);
// "ref int needed" + an 8 KB buffer: 16 KB gives 1783 ERROR_INVALID_USER_BUFFER, "out int" throws.
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, int bufsize, ref int needed);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ChangeServiceConfigW(IntPtr svc, int type, int startType, int errorControl,
    IntPtr binPath, IntPtr group, IntPtr tagId, IntPtr deps, IntPtr startName, IntPtr displayName, IntPtr password);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr svc, int numArgs, IntPtr argv);
// SERVICE_CONTROL_STOP = 1 -- section C needs wlansvc back at Stopped, otherwise StartServiceW would
// just answer 1056 ERROR_ALREADY_STARTED and prove nothing.
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ControlService(IntPtr svc, int cmd, ref SS st);
public static int LastErr = 0;
static string Uni(IntPtr p) {
  if (p == IntPtr.Zero) { return ""; }
  string s = System.Runtime.InteropServices.Marshal.PtrToStringUni(p);
  return s == null ? "" : s;
}
static string BlockOut(IntPtr p) {
  if (p == IntPtr.Zero) { return ""; }
  System.Text.StringBuilder sb = new System.Text.StringBuilder();
  IntPtr cur = p;
  for (int guard = 0; guard < 64; guard++) {
    string s = Uni(cur);
    if (s.Length == 0) { break; }
    sb.Append(s); sb.Append(";");
    cur = new IntPtr(cur.ToInt64() + (long)(s.Length + 1) * 2L);
  }
  return sb.ToString();
}
public static IntPtr OpenScm(int access) {
  IntPtr h = OpenSCManagerW(IntPtr.Zero, IntPtr.Zero, access);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return h;
}
public static IntPtr OpenSvc(IntPtr scm, string name, int access) {
  IntPtr h = OpenServiceW(scm, name, access);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return h;
}
public static string Status(IntPtr svc) {
  SS s = new SS();
  bool ok = QueryServiceStatus(svc, ref s);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok) { return "QSS_FAIL=" + LastErr; }
  return "state=" + s.dwCurrentState + " ctrl=0x" + s.dwControlsAccepted.ToString("X") +
         " win32err=" + s.dwWin32ExitCode + " svcerr=" + s.dwServiceSpecificExitCode +
         " checkpoint=" + s.dwCheckPoint + " waithint=" + s.dwWaitHint;
}
public static string DumpConfig(IntPtr svc) {
  // The buffer must outlive every ReadIntPtr: an early FreeHGlobal is a use-after-free, which in PS 5.1
  // is a corrupted-state exception that kills powershell.exe (exit 127) with no message at all.
  int needed = 0;
  int size = 8000;
  IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
  for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
  bool ok = QueryServiceConfigW(svc, buf, size, ref needed);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok && LastErr == 123 && needed > 8 && needed < 60000) {
    System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
    size = needed + 64;
    buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
    for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
    ok = QueryServiceConfigW(svc, buf, size, ref needed);
    LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  }
  if (!ok) { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); return "QFC_FAIL=" + LastErr; }
  // QUERY_SERVICE_CONFIG x64: Type(0) Start(4) ErrCtl(8) [pad] Img(16) Group(24) TagId(32) Deps(40) StartName(48)
  long type = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 0) & 0xFFFFFFFFL;
  long start = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 4) & 0xFFFFFFFFL;
  string img = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 16));
  string deps = BlockOut(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 40));
  string obj = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 48));
  System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
  return "Type=0x" + type.ToString("X") + " Start=0x" + start.ToString("X") + " Obj=[" + obj + "]" +
         " Deps=[" + deps + "] Img=[" + img + "]";
}
public static bool SetImagePath(IntPtr svc, string img) {
  IntPtr p = System.Runtime.InteropServices.Marshal.StringToHGlobalUni(img);
  bool r = ChangeServiceConfigW(svc, -1, -1, -1, p, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (p != IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(p); }
  return r;
}
public static bool StartNow(IntPtr svc) {
  bool r = StartServiceW(svc, 0, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
public static bool StopNow(IntPtr svc) {
  SS s = new SS();
  bool r = ControlService(svc, 1, ref s);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
'@ -EA Stop
}
$script:hScm = [IntPtr]::Zero
foreach ($acc in @(0xF003F, 0x0001)) {
  $hh = [P84.SCM]::OpenScm($acc)
  if ($hh -ne [IntPtr]::Zero) { $script:hScm = $hh; break }
}
if ($script:hScm -eq [IntPtr]::Zero) { O ('FATAL: OpenSCManagerW failed err=' + [P84.SCM]::LastErr); exit 1 }
function HandleOf([string]$name) {
  foreach ($a in @(0xF01FF, 0x0017, 0x0005, 0x0001)) {
    $hh = [P84.SCM]::OpenSvc($script:hScm, $name, $a)
    if ($hh -ne [IntPtr]::Zero) { return $hh }
  }
  return [IntPtr]::Zero
}

# ---------- wlanapi, so a Running service is checked the way the panel will check it ----------
if (-not ('P84.W' -as [type])) {
  Add-Type -Namespace P84 -Name W -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public struct WLAN_INTERFACE_INFO {
  public System.Guid interfaceGuid;
  [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
  public string description;
  public int state;
}
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError = true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[System.Runtime.InteropServices.DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError = true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list);
[System.Runtime.InteropServices.DllImport("wlanapi.dll")]
public static extern void WlanFreeMemory(System.IntPtr mem);
public static string IfaceLine(System.IntPtr list, int i) {
  int stride = System.Runtime.InteropServices.Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
  System.IntPtr item = new System.IntPtr(list.ToInt64() + 8 + (long)i * stride);
  WLAN_INTERFACE_INFO info = (WLAN_INTERFACE_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure(
      item, typeof(WLAN_INTERFACE_INFO));
  return info.description + "|state=" + info.state + "|guid=" + info.interfaceGuid;
}
public static int Count(System.IntPtr list) {
  int n = System.Runtime.InteropServices.Marshal.ReadInt32(list);
  return (n < 0) ? 0 : n;
}
'@ -EA Stop
}
function WlanOpenReport([string]$when) {
  $rc = -1; $nv = 0; $hw = [IntPtr]::Zero
  try {
    $rc = [P84.W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $hw)
    LogLine ('    WLANOPEN(' + (ToAscii $when) + ') rc=' + $rc + ' newVer=' + $nv)
    if ($rc -eq 0 -and $hw -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P84.W]::WlanEnumInterfaces($hw, [IntPtr]::Zero, [ref] $lst)
      $n = 0
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
        $n = [P84.W]::Count($lst)
        LogLine ('      ENUMIF rc=' + $erc + ' items=' + $n)
        for ($ii = 0; $ii -lt $n; $ii++) { LogLine ('        IFACE ' + (ToAscii ([P84.W]::IfaceLine($lst, $ii)))) }
        [void][P84.W]::WlanFreeMemory($lst)
      } else { LogLine ('      ENUMIF rc=' + $erc) }
      $VERD.ifaces = $n
      [void][P84.W]::WlanCloseHandle($hw, [IntPtr]::Zero)
    }
  } catch { LogLine ('    wlan call threw: ' + (ToAscii $_.Exception.Message)) }
  $VERD.open = $rc
}

# ---------- the watch: did the SCM create a host process, and what exact command line? ----------
$script:lastChild = 'none'
function StartWatch([string]$tag, [string]$svc, [int]$polls) {
  $before = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
  $h = HandleOf $svc
  if ($h -eq [IntPtr]::Zero) { LogLine ('  [' + $tag + '] no service handle err=' + [P84.SCM]::LastErr); return 'NOHANDLE' }
  $rec = [P84.SCM]::DumpConfig($h)
  LogLine ('  [' + $tag + '] SCM record ' + $svc + ': ' + (ToAscii $rec))
  $r = [P84.SCM]::StartNow($h)
  $e = [P84.SCM]::LastErr
  LogLine ('    StartServiceW ok=' + $r + ' err=' + (ErrName $e) + ' state=' + (St $svc))
  $found = @()
  for ($i = 0; $i -lt $polls; $i++) {
    Start-Sleep -Milliseconds 100
    $cur = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
    $newOnes = @($cur | Where-Object { $before -notcontains $_ })
    if ($newOnes.Count -gt 0 -and $found.Count -eq 0) { $found = $newOnes }
    if (($i % 10) -eq 9) {   # the SCM/CIM calls are slow: sample once a second, not every poll
      $q = [P84.SCM]::Status($h)
      LogLine ('      +' + [int](($i + 1) * 0.1) + 's new=' + $newOnes.Count + ' ' + (ToAscii $q) + ' svc=' + (St $svc))
    }
    if ((St $svc) -eq 'Running') { break }
  }
  $still = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
  $aliveNew = @($still | Where-Object { $before -notcontains $_ })
  LogLine ('    AFTER polls=' + $polls + ' firstNew=' + ($found -join ',') + ' stillNew=' + ($aliveNew -join ',') +
     ' state=' + (St $svc) + ' ' + (ToAscii ([P84.SCM]::Status($h))))
  # whatever the SCM launched, spelled out -- this is the proof of what it appends
  foreach ($pidTxt in $aliveNew) {
    $cimOne = @(Get-CimInstance Win32_Process -Filter ("ProcessId=" + $pidTxt) -EA SilentlyContinue)
    foreach ($cc in $cimOne) {
      LogLine ('    CHILD pid=' + $pidTxt + ' ppid=' + $cc.ParentProcessId + ' cmd=[' + (ToAscii $cc.CommandLine) + ']')
      $script:lastChild = $cc.CommandLine
    }
  }
  [void][P84.SCM]::CloseServiceHandle($h)
  $vv = 'nochild'
  if ($aliveNew.Count) { $vv = 'childAlive' } elseif ($found.Count) { $vv = 'childDied' }
  return $vv
}
# C only means something if the service can be put back to Stopped first.
# No return value on purpose: every line goes through LogLine, so the caller can use a plain statement
# instead of "| Out-Null" (which would delete the function's own output).
function StopAndWait([string]$svc) {
  $h = HandleOf $svc
  if ($h -eq [IntPtr]::Zero) { LogLine ('  stop ' + $svc + ': no handle'); FlushLog; return }
  $r = [P84.SCM]::StopNow($h)
  $e = [P84.SCM]::LastErr
  LogLine ('  ControlService(STOP) ' + $svc + ' ok=' + $r + ' err=' + (ErrName $e) + ' (1056_STOPPED_ALREADY is fine)')
  for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Milliseconds 200
    if ((St $svc) -ne 'Running') { break }
  }
  LogLine ('  after stop: state=' + (St $svc) + ' ' + (ToAscii ([P84.SCM]::Status($h))))
  [void][P84.SCM]::CloseServiceHandle($h)
  FlushLog
}

O '== 0 the four records, the group table, and the dependencies =='
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $img = RegGet "$REG\$n" 'ImagePath'
  $h = HandleOf $n
  $rec = if ($h -ne [IntPtr]::Zero) { [P84.SCM]::DumpConfig($h) } else { 'no-handle' }
  if ($h -ne [IntPtr]::Zero) { [void][P84.SCM]::CloseServiceHandle($h) }
  O ('  REG  ' + $n + ' img=[' + (ToAscii $img) + '] k=' + (GrpOf $img) + ' s=' + (HasSvc $img) + ' state=' + (St $n))
  O ('  SCM  ' + $n + ' ' + (ToAscii $rec))
}
$tbl = @{}
$script:grpReal = @{}   # lowercased name -> the EXACT value name in the registry
$it = Get-Item $SVCHOSTKEY -EA SilentlyContinue
if ($it) {
  foreach ($vn in @($it.GetValueNames())) {
    $arr = @($it.GetValue($vn) | Where-Object { "$_" })
    $tbl[$vn.ToLower()] = $arr
    $script:grpReal[$vn.ToLower()] = $vn
  }
}
foreach ($g in @('localsystemnetworkrestricted', 'localservicenetworkrestricted', 'wlansvcs', 'wcmsvcs', 'rpcss')) {
  if ($tbl.ContainsKey($g)) { O ('  GRP ' + $g + ' = ' + (($tbl[$g]) -join ',')) } else { O ('  GRP ' + $g + ' ABSENT') }
}
foreach ($n in @('wlansvc', 'wcmsvc')) {
  $g = (GrpOf (RegGet "$REG\$n" 'ImagePath')).ToLower()
  $listed = if ($tbl.ContainsKey($g)) { @($tbl[$g] | Where-Object { "$_".ToLower() -eq $n }).Count } else { 0 }
  O ('  LISTED ' + $n + ' in group [' + $g + '] = ' + $(if ($listed -gt 0) { 'yes' } else { 'NO' }))
}
# the pristine group each service will be moved to, and whether that group lists it.
# Carry the EXACT casing from the bake constants: svchost looks the group up case-insensitively, but a
# write must not leave a second, differently-spelled value behind in the same key.
foreach ($pr in @(@('wlansvc', 'LocalSystemNetworkRestricted'), @('wcmsvc', 'LocalServiceNetworkRestricted'))) {
  $n = $pr[0]; $gExact = $pr[1]; $g = $gExact.ToLower()
  $listed = if ($tbl.ContainsKey($g)) { @($tbl[$g] | Where-Object { "$_".ToLower() -eq $n }).Count } else { 0 }
  $gWrite = $gExact
  if ($script:grpReal.ContainsKey($g)) { $gWrite = $script:grpReal[$g] }
  O ('  PRISTINE ' + $n + ' -> group [' + $g + '] lists it = ' + $(if ($listed -gt 0) { 'yes' } else { 'NO' }))
  if ($listed -eq 0) {
    try {
      $cur = @()
      if ($tbl.ContainsKey($g)) { $cur = @($tbl[$g]) }
      $cur = $cur + $n
      Set-ItemProperty $SVCHOSTKEY -Name $gWrite -Value $cur -Type MultiString -Force -EA Stop
      O ('    FIXED: added ' + $n + ' to ' + $gWrite + ' (svchost reads this table when it starts, so a raw write works)')
      $tbl[$g] = $cur
    } catch { O ('    FIX FAILED: ' + (ToAscii $_.Exception.Message)) }
  }
}
foreach ($d in @('RpcSs', 'DcomLaunch', 'Power', 'EventLog', 'NSI', 'netprofm', 'Dnscache')) {
  O ('  DEP ' + $d + ' = ' + (St $d))
}

O '== 1 wlansvc A: start it exactly as this hive has it now (-k wlansvcs -p -s wlansvc) =='
# StartWatch returns a verdict STRING, so the buffered lines must be flushed by the caller as a bare
# statement -- a FlushLog inside the function would be swallowed into the return value.
$va = StartWatch 'A-as-is' 'wlansvc' 30; FlushLog
$VERD.A = $va

O '== 2 wlansvc B: pristine baked shape, no -s (-k LocalSystemNetworkRestricted -p) =='
StopAndWait 'wlansvc'
$hwl = HandleOf 'wlansvc'
if ($hwl -ne [IntPtr]::Zero) {
  $set = [P84.SCM]::SetImagePath($hwl, $IMG_WL_BAKE)
  O ('  SetImagePath ok=' + $set + ' err=' + (ErrName ([P84.SCM]::LastErr)) + ' img=[' + $IMG_WL_BAKE + ']')
  O ('  now on disk: [' + (ToAscii (RegGet "$REG\wlansvc" 'ImagePath')) + ']')
  [void][P84.SCM]::CloseServiceHandle($hwl)
}
$vb = StartWatch 'B-pristine' 'wlansvc' 60; FlushLog
$VERD.B = $vb
if ($vb -eq 'childAlive') {
  O '  the host process survived -- ask wlanapi what it thinks'
  WlanOpenReport 'after wlansvc B'
} else {
  O '  no surviving host -> skipping the wlanapi probe (it can only answer 1062 without a service)'
}

O '== 3 wlansvc C: put "-s wlansvc" back on the pristine group (reproduces the failure on purpose) =='
StopAndWait 'wlansvc'
$hwl = HandleOf 'wlansvc'
if ($hwl -ne [IntPtr]::Zero) {
  $set = [P84.SCM]::SetImagePath($hwl, ($IMG_WL_BAKE + ' -s wlansvc'))
  O ('  SetImagePath ok=' + $set + ' err=' + (ErrName ([P84.SCM]::LastErr)))
  O ('  now on disk: [' + (ToAscii (RegGet "$REG\wlansvc" 'ImagePath')) + ']')
  [void][P84.SCM]::CloseServiceHandle($hwl)
}
$vc = StartWatch 'C-double-s' 'wlansvc' 20; FlushLog
$VERD.C = $vc
# leave it in the pristine shape for whatever comes next
StopAndWait 'wlansvc'
$hwl = HandleOf 'wlansvc'
if ($hwl -ne [IntPtr]::Zero) { [void][P84.SCM]::SetImagePath($hwl, $IMG_WL_BAKE); [void][P84.SCM]::CloseServiceHandle($hwl) }

O '== 4 wcmsvc B: pristine baked shape (-k LocalServiceNetworkRestricted -p) =='
StopAndWait 'wcmsvc'
$hwc = HandleOf 'wcmsvc'
if ($hwc -ne [IntPtr]::Zero) {
  $set = [P84.SCM]::SetImagePath($hwc, $IMG_WC_BAKE)
  O ('  SetImagePath ok=' + $set + ' err=' + (ErrName ([P84.SCM]::LastErr)))
  O ('  now on disk: [' + (ToAscii (RegGet "$REG\wcmsvc" 'ImagePath')) + ']')
  [void][P84.SCM]::CloseServiceHandle($hwc)
}
$vwc = StartWatch 'B-wcmsvc' 'wcmsvc' 40; FlushLog
$VERD.wcB = $vwc

O '== 5 controls, dumps, and the final records =='
foreach ($n in @('dot3svc', 'Dhcp', 'wlansvc', 'wcmsvc')) {
  $h = HandleOf $n
  $rec = if ($h -ne [IntPtr]::Zero) { [P84.SCM]::DumpConfig($h) } else { 'no-handle' }
  if ($h -ne [IntPtr]::Zero) { [void][P84.SCM]::CloseServiceHandle($h) }
  O ('  END ' + $n + ' state=' + (St $n) + ' ' + (ToAscii $rec))
}
# probe83 armed WER LocalDumps (DumpType=1 minidump, DumpCount=2, X:\pe_dumps). If any host crashed,
# the proof is a file here -- section 3 said nochild/no crash, this closes that loop.
$dumps = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue)
O ('  DUMPS X:\pe_dumps files=' + $dumps.Count)
foreach ($dd in $dumps) { O ('    DUMP ' + (ToAscii $dd.Name) + ' ' + [int]($dd.Length / 1024) + 'KB') }
$procs = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)
$sNames = ((@($procs | ForEach-Object { if ("$($_.CommandLine)" -match '-s\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
O ('  svchost procs=' + $procs.Count + ' -s=' + (ToAscii $sNames))

O '== 6 VERDICT =='
$VERD.pre = 'A=' + $va + ' B=' + $vb + ' C=' + $vc
O ('P84 VERDICT wlansvc A=' + $va + ' B=' + $vb + ' C=' + $vc + ' wcmsvcB=' + $vwc +
   ' wlanopen=' + $VERD.open + ' ifaces=' + $VERD.ifaces +
   ' childCmd=[' + (ToAscii $script:lastChild) + ']')
if ($vb -eq 'childAlive' -and $vc -eq 'nochild') {
  O 'P84 ROOT CAUSE: the double -s. The SCM appends "-s <service>" itself; a baked ImagePath that already ends with -s gives svchost two, the host refuses and dies inside 100 ms, and the SCM can only answer 1053. wifi-inject.ps1 already writes the no--s shape, so the ISO must be re-tested after a reboot -- and probe47/48s -s experiment was what broke this ramdisk.'
}
elseif ($vb -eq 'childAlive') {
  O 'P84 READING: the pristine shape gets a surviving host process; C was inconclusive (it also survived). Look at wlanopen/ifaces above: if WlanOpenHandle now returns 0 the user-mode half is DONE and the remaining work is the device half (task 20).'
}
elseif ($vb -eq 'nochild' -and $va -eq 'nochild') {
  O 'P84 READING: even the pristine dot3svc-shaped ImagePath never produces a child, so the blocker is NOT the command line. Next suspects, in order: the SCM record (Type/Start/Deps/Obj from section 0), and whether svchost will host a group whose member list changed after services.exe read it (a reboot is then unavoidable).'
}
elseif ($vb -eq 'childDied') {
  O 'P84 READING: a child IS created but dies -- that is the delay-load/crash theory again, and with WER LocalDumps still armed (probe83 wrote it) the dump should appear on the next boot; keep polling X:\pe_dumps.'
}
else {
  O 'P84 READING: mixed, read the per-step CHILD/LIFETIME lines.'
}
O 'P84 END'
