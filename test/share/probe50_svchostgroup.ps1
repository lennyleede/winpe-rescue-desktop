# ============================================================
# probe50_svchostgroup.ps1 -- why does the SCM now answer 1053 instead of 1068?
#
# Where probe49 left us (build/scratch/p49_push_1010.txt, live PE):
#   * OpenSCManagerW(0xF003F) via IntPtr.Zero works in PE: scm=ok-0xF003F.
#   * ChangeServiceConfigW / ChangeServiceConfig2W(6) all return True, and the corrected record is read
#     back from the SCM AND lands on disk: obj=[NT Authority\LocalService] privs=[SeChangeNotify,
#     SeImpersonate].
#   * With that pair, StartServiceW wcmsvc no longer answers 1068 -- it answers **1053 ERROR_TIMEOUT**,
#     instantly (waited=0s), and Get-Service settles back to Stopped. wlansvc through the same API path
#     also gives 1053. So the account/privilege pair really was the 1068; what remains is that the
#     service process never reports SERVICE_RUNNING.
#   * At the end of that run: svchost procs=11, "-s=" EMPTY -> no service-host process survived.
#
# The remaining suspect is the svchost side of the handshake, not the SCM's:
#   (a) "-k <group>" must name a value under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost
#       whose MULTI_SZ list contains the service name; svchost reads that table WHEN IT STARTS. If the
#       group is missing (or does not list the service), svchost exits at once -> the SCM's child died
#       without a status -> exactly 1053.  The live hive right now carries the *probe47/48 experiment*
#       shapes (-k wcmsvcs / -k wlansvcs), which no bake writes; whether those group values exist with
#       the right member lists has never been checked.
#   (b) Whether the DLL can even reach ServiceMain in PE (wlansvc.dll imports, msvcp/rt imports) --
#       if a manual svchost with the proven-good group dies the same way, (a) is innocent.
#
# The decisive experiment is to bypass the SCM: start the host process ourselves and watch it.
# Start-Process svchost -k <group> -p -s <name>, wait, read HasExited/ExitCode, then ask the SCM for the
# SERVICE_STATUS it holds (QueryServiceStatus with a real struct -- the earlier draft used "out int" and
# would have read dwServiceType by mistake), and finally call WlanOpenHandle: if a manually launched
# wlansvc answers wlanapi, the user-mode service is fine and only the SCM handoff is broken.
#
# 0 also settles WHICH IMAGE this ramdisk is: probe49's records still had probe47/48's hand-made shapes,
# which cannot survive a reboot, so X:\BUILD_TAG.txt (written by build.ps1 [4h2]) is read first.
#
# Writes: HKLM\SYSTEM\CurrentControlSet\Services\{wcmsvc,wlansvc} through the SCM API (same as probe49),
#         plus short-lived svchost processes on the RAMDISK. X: evaporates on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe50_svchostgroup.ps1 -RemotePath X:/p50.ps1 -StagingB64 X:/p50.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# LogLine buffers output for functions that also return a value; FlushLog must be a bare statement
# ([void](FlushLog) swallows the buffered lines). Aliases beat functions, so no 2-letter names.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }

$REG = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SVC = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$P = @{ scm = 'none'; tag = 'notag'; grp = @(); man = @(); openMid = -1; openEnd = -1 }

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
function FileSig([string]$p) {
  try { $i = Get-Item $p -EA Stop; return ('' + [int]($i.Length / 1024) + 'KB ' + $i.LastWriteTime.ToString('yyyy-MM-dd')) }
  catch { return 'ABSENT' }
}
# Parse "-k <group>" and "-s <service>" out of an ImagePath the way svchost does.
function GrpOf([string]$img) { if ($img -match '-k\s+(\S+)') { return $matches[1] } return '' }
function SvcOf([string]$img) { if ($img -match '-s\s+(\S+)') { return $matches[1] } return '' }

if (-not ('P50.SCM' -as [type])) {
  Add-Type -Namespace P50 -Name SCM -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 4)]
public struct SS {
  public int dwServiceType;
  public int dwCurrentState;
  public int dwControlsAccepted;
  public int dwWin32ExitCode;
  public int dwServiceSpecificExitCode;
  public int dwCheckPoint;
  public int dwWaitHint;
}
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern IntPtr OpenSCManagerW(IntPtr machine, IntPtr database, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr OpenServiceW(IntPtr scm, string name, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CloseServiceHandle(IntPtr h);
// QueryServiceStatus: 7 DWORDs, no pointers, so Pack=4 is the native 28-byte layout. The old draft used
// "out int" and would have silently returned dwServiceType.
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceStatus(IntPtr svc, ref SS st);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr svc, int numArgs, IntPtr argv);
public static int LastErr = 0;
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
  return "type=0x" + ((s.dwServiceType & 0x000000FF).ToString("X")) + " state=" + s.dwCurrentState +
         " ctrl=0x" + s.dwControlsAccepted.ToString("X") + " win32err=" + s.dwWin32ExitCode +
         " svcerr=" + s.dwServiceSpecificExitCode + " checkpoint=" + s.dwCheckPoint +
         " waithint=" + s.dwWaitHint;
}
public static bool StartNow(IntPtr svc) {
  bool r = StartServiceW(svc, 0, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
'@ -EA Stop
}
$script:hScm = [IntPtr]::Zero
foreach ($acc in @(0xF003F, 0x0001)) {
  $h = [P50.SCM]::OpenScm($acc)
  if ($h -ne [IntPtr]::Zero) { $script:hScm = $h; $P.scm = '0x' + ('{0:X}' -f $acc); break }
}
function HandleOf([string]$name) {
  if ($script:hScm -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
  foreach ($a in @(0xF01FF, 0x0017, 0x0005, 0x0001)) {
    $h = [P50.SCM]::OpenSvc($script:hScm, $name, $a)
    if ($h -ne [IntPtr]::Zero) { return $h }
  }
  return [IntPtr]::Zero
}

O '== 0 which image is this ramdisk, and is the WDI bake really in it =='
if (Test-Path 'X:\BUILD_TAG.txt') {
  $tl = @(Get-Content 'X:\BUILD_TAG.txt' -EA SilentlyContinue)
  $P.tag = (($tl | Select-Object -First 1) -replace '[^\x20-\x7E]', '?')
  foreach ($l in ($tl | Select-Object -First 6)) { O ('  TAG | ' + (ToAscii $l)) }
} else { O '  TAG | X:\BUILD_TAG.txt ABSENT' }
foreach ($f in @('drivers\wdiwifi.sys', 'drivers\NdisImPlatform.sys', 'drivers\nwifi.sys', 'drivers\vwifibus.sys',
                 'drivers\vwififlt.sys', 'drivers\vwifimp.sys', 'wlansvc.dll', 'wcmsvc.dll', 'wlanapi.dll',
                 'wifi.exe')) {
  O ('  FILE ' + $f + ' = ' + (FileSig (Join-Path 'X:\Windows\System32' $f)))
}
$devs = @(Get-PnpDevice -Class 'Net' -EA SilentlyContinue | Where-Object { "$($_.InstanceId)" -match 'Wi|WLAN|802' -or "$($_.FriendlyName)" -match '(?i)wire|wlan' })
foreach ($d in $devs) { O ('  WLANDEV ' + (ToAscii $d.FriendlyName) + ' status=' + $d.Status + ' problem=' + $d.ConfigErrorCode) }
if (-not $devs.Count) { O '  WLANDEV none found' }

O '== 1 the svchost group table svchost reads when it starts =='
$tbl = @{}
if (Test-Path $SVC) {
  $it = Get-Item $SVC
  foreach ($vn in @($it.GetValueNames())) {
    $arr = @($it.GetValue($vn) | Where-Object { "$_" })
    $tbl[$vn.ToLower()] = ($arr -join ',')
    O ('  GRP ' + $vn + ' = ' + (ToAscii ($arr -join ',')))
  }
  if (-not $tbl.Count) { O '  GRP table EMPTY' }
} else { O ('  ' + $SVC + ' ABSENT -- svchost cannot resolve ANY -k group') }
foreach ($n in @('wcmsvc', 'wlansvc', 'dot3svc', 'Dhcp')) {
  $img = (RegGet "$REG\$n" 'ImagePath')
  $g = GrpOf $img; $s = SvcOf $img
  $gl = $g.ToLower()
  $verdict = 'NOGROUP'
  if ($tbl.ContainsKey($gl)) {
    $members = @(($tbl[$gl] -split ',') | ForEach-Object { $_.ToLower() })
    if ($members -contains $n.ToLower()) { $verdict = 'OK' } else { $verdict = 'NOTLISTED' }
  }
  $P.grp += "$n/$g=$verdict"
  O ('  CHK ' + $n + ' img=[' + (ToAscii $img) + '] k=' + $g + ' s=' + $s + ' -> group ' + $verdict)
}

O '== 2 what the SCM holds as the service status right now =='
foreach ($n in @('wcmsvc', 'wlansvc')) {
  $h = HandleOf $n
  if ($h -eq [IntPtr]::Zero) { O ('  QSS ' + $n + ' no handle'); continue }
  O ('  QSS ' + $n + ' ' + [P50.SCM]::Status($h) + ' svc=' + (St $n))
  [void][P50.SCM]::CloseServiceHandle($h)
}

O '== 3 bypass the SCM: launch the service host ourselves and watch it =='
if (-not ('P50.W' -as [type])) {
  Add-Type -Namespace P50 -Name W -MemberDefinition @'
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
public static string[] IfaceNames(System.IntPtr list) {
  int n = System.Runtime.InteropServices.Marshal.ReadInt32(list);
  if (n < 0) { n = 0; }
  string[] r = new string[n];
  int stride = System.Runtime.InteropServices.Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
  for (int i = 0; i < n; i++) {
    // WLAN_ENUMERATION: DWORD count, then InterfaceArray[count]; the array starts after those 4 bytes
    // plus the pointer that follows it on x64 (8-byte alignment).
    System.IntPtr item = new System.IntPtr(list.ToInt64() + 8 + (long)i * stride);
    WLAN_INTERFACE_INFO info = (WLAN_INTERFACE_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure(
        item, typeof(WLAN_INTERFACE_INFO));
    r[i] = info.description + "|state=" + info.state + "|guid=" + info.interfaceGuid;
  }
  return r;
}
'@ -EA Stop
}
# Returns ONLY the rc (Write-Output inside a value-returning function would corrupt the return value).
function WlanOpenProbe([string]$when) {
  $rc = -1
  try {
    $nv = 0; $hw = [IntPtr]::Zero
    $rc = [P50.W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $hw)
    LogLine ('      WLANOPEN(' + (ToAscii $when) + ') rc=' + $rc + ' newVer=' + $nv)
    if ($rc -eq 0 -and $hw -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P50.W]::WlanEnumInterfaces($hw, [IntPtr]::Zero, [ref] $lst)
      $names = @()
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) { $names = @([P50.W]::IfaceNames($lst)); [void][P50.W]::WlanFreeMemory($lst) }
      LogLine ('      ENUMIF rc=' + $erc + ' items=' + $names.Count)
      foreach ($x in $names) { LogLine ('        IFACE ' + (ToAscii $x)) }
      [void][P50.W]::WlanCloseHandle($hw, [IntPtr]::Zero)
    }
  } catch { LogLine ('      wlan call failed: ' + (ToAscii $_.Exception.Message)) }
  return $rc
}
$script:pids = @()
function RunHost([string]$tag, [string]$group, [string]$svc) {
  $before = @(Get-Process svchost -EA SilentlyContinue).Count
  $p = $null
  try {
    $p = Start-Process -FilePath 'X:\Windows\System32\svchost.exe' `
                       -ArgumentList @('-k', $group, '-p', '-s', $svc) -PassThru -WindowStyle Hidden
  } catch { LogLine ('      [' + $tag + '] Start-Process failed: ' + (ToAscii $_.Exception.Message)); return $null }
  if ($null -eq $p) { LogLine ('      [' + $tag + '] no process object'); return $null }
  $script:pids += $p.Id
  # 6 s is enough to see an instant exit (a bad -k group dies in milliseconds); if it is still alive the
  # DLL got to ServiceMain and we can ask the SCM and wlanapi while the host is up.
  $exited = $p.WaitForExit(6000)
  $code = -1
  try { if ($exited) { $code = $p.ExitCode } } catch { $code = -2 }
  $after = @(Get-Process svchost -EA SilentlyContinue).Count
  $h = HandleOf $svc
  $qss = 'no-handle'
  if ($h -ne [IntPtr]::Zero) { $qss = [P50.SCM]::Status($h); [void][P50.SCM]::CloseServiceHandle($h) }
  LogLine ('      [' + $tag + '] k=' + $group + ' s=' + $svc + ' pid=' + $p.Id + ' stillAlive=' + (-not $exited) +
           ' exitCode=' + $code + ' procs ' + $before + '->' + $after + ' svc=' + (St $svc))
  LogLine ('      [' + $tag + '] SCM says ' + $svc + ': ' + $qss)
  return @{ alive = (-not $exited); code = $code; pid = $p.Id }
}
# M1/M2: the shapes this ramdisk really carries (probe47/48 hand-made groups; no bake writes them)
$gWc = GrpOf (RegGet "$REG\wcmsvc" 'ImagePath')
$gWl = GrpOf (RegGet "$REG\wlansvc" 'ImagePath')
$r = RunHost 'M1-wcmsvc-ownshape' $gWc 'wcmsvc'; FlushLog; if ($r) { $P.man += "M1:alive=$($r.alive)/code=$($r.code)" }
$r = RunHost 'M2-wlansvc-ownshape' $gWl 'wlansvc'; FlushLog; if ($r) { $P.man += "M2:alive=$($r.alive)/code=$($r.code)" }
if ($r -and $r.alive) {
  $rc = WlanOpenProbe 'while the manual wlansvc host is alive'
  $P.openMid = $rc
}
# M3: the group the BAKE writes, proven good by dot3svc in the same image
$r = RunHost 'M3-wlansvc-bakegroup' 'LocalSystemNetworkRestricted' 'wlansvc'
FlushLog; if ($r) { $P.man += "M3:alive=$($r.alive)/code=$($r.code)" }
if ($r -and $r.alive) { $P.openEnd = (WlanOpenProbe 'while the M3 wlansvc host is alive') }
# CTRL: a service that is already Running. svchost resolves the group, finds the service started, and
# leaves -- a fast exit here is HEALTHY, which is why the exit code matters more than "it exited".
$r = RunHost 'CTRL-dhcp-already-running' 'LocalServiceNetworkRestricted' 'Dhcp'
FlushLog; if ($r) { $P.man += "CTRL:alive=$($r.alive)/code=$($r.code)" }

O '== 4 clean up the hosts we started =='
foreach ($pid2 in $script:pids) {
  try { Stop-Process -Id $pid2 -Force -EA Stop; O ('  KILLED ' + $pid2) } catch { O ('  kill ' + $pid2 + ' ' + (ToAscii $_.Exception.Message)) }
}

O '== 5 what is on disk and in the SCM now =='
foreach ($n in @('wcmsvc', 'wlansvc')) {
  $h = HandleOf $n
  $qss = if ($h -ne [IntPtr]::Zero) { [P50.SCM]::Status($h) } else { 'no-handle' }
  if ($h -ne [IntPtr]::Zero) { [void][P50.SCM]::CloseServiceHandle($h) }
  O ('  END ' + $n + ' ' + $qss + ' svc=' + (St $n) + ' img=[' + (ToAscii (RegGet "$REG\$n" 'ImagePath')) +
     '] privs=[' + (ToAscii (RegGet "$REG\$n" 'RequiredPrivileges')) + '] obj=[' +
     (RegGet "$REG\$n" 'ObjectName') + ']')
}
$procs = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)
$sNames = ((@($procs | ForEach-Object { if ("$($_.CommandLine)" -match '-s\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
O ('  svchost procs=' + $procs.Count + ' -s=' + (ToAscii $sNames))

O '== 6 VERDICT =='
O ('P50 VERDICT tag=' + $P.tag + ' grp=' + ($P.grp -join ',') + ' man=' + ($P.man -join ' ') +
   ' openMid=' + $P.openMid + ' openEnd=' + $P.openEnd)
if ($P.openMid -eq 0 -or $P.openEnd -eq 0) {
  O 'P50 READING: a manually launched svchost got wlansvc far enough to answer wlanapi -> the DLL and the PE runtime are fine, the SCM handoff (group table / start attributes) is the only broken link; bake the group the manual launch used.'
}
elseif ($P.man -match 'M2:alive=True|M3:alive=True') {
  O 'P50 READING: the manual wlansvc host survives but wlanapi still says 1062 -> the service is up without registering with the SCM; the -p/-s protocol in this PE is the suspect, not the key shape.'
}
elseif ($P.grp -match 'group-MISSING|MISSING') {
  O 'P50 READING: the -k group named by the ImagePath is not in the svchost table (or does not list the service) -> svchost exits at once, which is exactly 1053. Fix = bake an ImagePath whose group exists and lists the service.'
}
elseif ($P.man -match 'code=0 ') {
  O 'P50 READING: the manual host exited 0 like the CTRL run -> svchost decided the service was already handled; the SCM record and the process agree, so look at start attributes (auto vs manual) next.'
}
else {
  O 'P50 READING: manual launches die with a nonzero code the SCM never reports -> the DLL is failing before ServiceMain can answer; the next step is the import/DLL layer, not the key shape.'
}
O 'P50 END'

