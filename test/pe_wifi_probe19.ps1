# probe19: probe18 broke the reading that drove probes 7-18.
#
#   wlansvc RAW StartService => TRUE  status{state=1 ...} after{state=2}
#
# i.e. the SCM ACCEPTS the start. "System error 6 / The handle is invalid" is what net.exe prints
# while it waits, not what the SCM returns -- every probe since #7 was steering on that artifact.
# So wlansvc's WlanSvcMain does run, then the service goes back to STOPPED on its own (dot3svc in the
# same LocalSystemNetworkRestricted host survives at pid 1328, so the host did not die).
#
# probe19 measures the self-stop instead of the config shape:
#   S1  trigger via net start, then poll SERVICE_STATUS every 300 ms -> the exact state sequence and
#       the exit code the service reports when it stops (that code names the failing subsystem).
#   S2  trigger via raw StartService, same poll (control).
#   S3  do the borrowed logs lie? compare live dot3api.dll / fwpcd.dll versions with C:'s copies.
#   S4  is wlansvc.dll actually mapped into the host? module list of every svchost.
#   S5  does NotifyServiceStatusChangeW fail with 6 -> confirms the net.exe rendering theory.
#   S6  which nearby services exist at all (netprofm/nsi/NlaSvc/PolicyAgent...), and the Net-class
#       key that carries the "NativeWiFi Only" flag real machines have.
#   S7  race: start + call WlanOpenHandle/WlanEnumInterfaces in a tight loop, printing rc changes.
# Ramdisk only; everything dies at reboot and the stick image is untouched.
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}
function DrvState([string]$n) {
  $d = @(Get-CimInstance Win32_SystemDriver -Filter ('Name=''' + $n + '''') -EA SilentlyContinue)
  if (@($d).Count -eq 0) { return 'NOT-ENUMERATED' }
  return ('State=' + $d[0].State + ' started=' + $d[0].Started + ' startmode=' + $d[0].StartMode)
}
function Ver([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'ABSENT' }
  $f = Get-Item -LiteralPath $p
  $v = ''
  try { $v = [string]$f.VersionInfo.FileVersion } catch { }
  if ([string]::IsNullOrWhiteSpace($v)) { $v = '-' }
  return ($v + ' (' + [Math]::Round($f.Length / 1KB) + 'KB)')
}
$PS  = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services'

Sec 'S0_PREP'
# probe18 restored these; assert again so the run is self-contained
Log ('  reg Type=32            => ' + (Cmd 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v Type /t REG_DWORD /d 32 /f'))
Log ('  reg DependOnService    => ' + (Cmd 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v DependOnService /t REG_MULTI_SZ /d RpcSs /f'))
Log ('  reg Start=3            => ' + (Cmd 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v Start /t REG_DWORD /d 3 /f'))
Log ('  wlansvc  : ' + (SvcState 'wlansvc'))
Log ('  dot3svc  : ' + (SvcState 'dot3svc'))
Log ('  nativewifip: ' + (DrvState 'nativewifip'))

try {
  $src19 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class SC19 {
  [StructLayout(LayoutKind.Sequential)]
  public struct US { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)]
  public struct SN { public uint dwVersion; public IntPtr pszServiceName; public IntPtr pdwStatus; public IntPtr pContext; public uint dwControl; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool QueryServiceStatus(IntPtr svc, byte[] st);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern uint NotifyServiceStatusChangeW(IntPtr svc, uint mask, ref SN w);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  static IntPtr scm = IntPtr.Zero;
  static IntPtr hs = IntPtr.Zero;
  static string Hex(uint v) { return "0x" + v.ToString("X8"); }
  public static string Msg(uint c) {
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x00001300u, IntPtr.Zero, c, 0, b, 512, IntPtr.Zero);
    string t = (n > 0) ? Marshal.PtrToStringUni(b) : "";
    Marshal.FreeHGlobal(b);
    return t.Trim().Replace("\r", " ").Replace("\n", " ");
  }
  public static bool Open(string name) {
    if (scm == IntPtr.Zero) scm = OpenSCManagerW(null, null, 0x0001u);
    if (scm == IntPtr.Zero) return false;
    uint mask = 0x0001u | 0x0004u | 0x0010u | 0x0020u | 0x0080u;
    hs = OpenServiceW(scm, name, mask);
    return hs != IntPtr.Zero;
  }
  public static string Status(string name) {
    if (hs == IntPtr.Zero) { if (!Open(name)) return "OPEN-FAIL err=" + Marshal.GetLastWin32Error(); }
    byte[] st = new byte[32];
    if (!QueryServiceStatus(hs, st)) return "QUERY-FAIL err=" + Marshal.GetLastWin32Error();
    StringBuilder sb = new StringBuilder();
    sb.Append("type=" + BitConverter.ToUInt32(st, 0));
    sb.Append(" state=" + BitConverter.ToUInt32(st, 4));
    sb.Append(" win32exit=" + Hex(BitConverter.ToUInt32(st, 8)) + "(" + BitConverter.ToUInt32(st, 8) + ")");
    sb.Append(" specific=" + Hex(BitConverter.ToUInt32(st, 12)));
    sb.Append(" checkpoint=" + BitConverter.ToUInt32(st, 16));
    sb.Append(" waithint=" + BitConverter.ToUInt32(st, 20));
    return sb.ToString();
  }
  public static string Start(string name) {
    if (!Open(name)) return name + " OPEN-FAIL err=" + Marshal.GetLastWin32Error() + " [" + Msg((uint)Marshal.GetLastWin32Error()) + "]";
    bool ok = StartServiceW(hs, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    return name + " raw StartService => " + (ok ? "accepted" : ("refused err=" + e + " [" + Msg((uint)e) + "]"));
  }
  public static string Close() { hs = IntPtr.Zero; return "handle-cleared"; }
  public static string Notify(string name) {
    if (!Open(name)) return name + " OPEN-FAIL";
    byte[] st = new byte[32];
    QueryServiceStatus(hs, st);
    IntPtr pStatus = Marshal.AllocHGlobal(4);
    Marshal.WriteInt32(pStatus, BitConverter.ToInt32(st, 4));
    SN w = new SN();
    w.dwVersion = 1;
    w.pszServiceName = IntPtr.Zero;
    w.pdwStatus = pStatus;
    w.pContext = IntPtr.Zero;
    w.dwControl = 0;
    uint rc = NotifyServiceStatusChangeW(hs, 0x00000002u, ref w);
    string outp = name + " NotifyServiceStatusChangeW rc=" + rc + " [" + Msg(rc) + "] observedStatus=" + Marshal.ReadInt32(pStatus);
    Marshal.FreeHGlobal(pStatus);
    return outp;
  }
  public static string Load(string key) {
    bool prev = false;
    uint ap = RtlAdjustPrivilege(10, true, false, out prev);
    IntPtr b = Marshal.StringToHGlobalUni(key);
    US u = new US();
    u.Length = (ushort)(key.Length * 2);
    u.MaximumLength = (ushort)((key.Length + 1) * 2);
    u.Buffer = b;
    uint rc = NtLoadDriver(ref u);
    uint dos = RtlNtStatusToDosError(rc);
    Marshal.FreeHGlobal(b);
    return "adjustPriv=0x" + ap.ToString("X8") + " rc=0x" + rc.ToString("X8") + " dos=" + dos + " [" + Msg(dos) + "]";
  }
  [DllImport("ntdll.dll")] public static extern uint RtlAdjustPrivilege(int p, bool en, bool th, out bool prev);
  [DllImport("ntdll.dll")] public static extern uint RtlNtStatusToDosError(uint st);
  [DllImport("ntdll.dll")] public static extern uint NtLoadDriver(ref US s);
}
"@
  Add-Type -TypeDefinition $src19
  $global:OK19 = $true
  Log '  Add-Type SC19 ok'
} catch {
  $global:OK19 = $false
  Log ('  Add-Type SC19 FAILED: ' + (One ([string]$_)))
}

function Timeline([string]$tag) {
  $t0 = Get-Date
  $last = ''
  for ($i = 0; $i -lt 70; $i++) {
    $s = [SC19]::Status('wlansvc')
    if ($s -ne $last) {
      $ms = [int](((Get-Date) - $t0).TotalMilliseconds)
      Log ('    ' + $tag + ' t+' + $ms + 'ms  ' + $s)
      $last = $s
    }
    Start-Sleep -Milliseconds 300
  }
}

Sec 'S1_TIMELINE_AFTER_NET_START'
Log ('  net start wlansvc => ' + (Cmd 'net start wlansvc'))
if ($global:OK19) { Timeline 'NET' }

Sec 'S2_TIMELINE_AFTER_RAW_START'
if ($global:OK19) {
  [void][SC19]::Close()
  Log ('  ' + [SC19]::Start('wlansvc'))
  Timeline 'RAW'
  Log ('  final win32 exit code reported by the service: ' + [SC19]::Status('wlansvc'))
}

Sec 'S3_VERSION_AUDIT_BORROWED_APIDLLS'
foreach ($d in @('dot3api.dll', 'dot3cfg.dll', 'dot3msm.dll', 'fwpcd.dll', 'wcmsvc.dll', 'wlanapi.dll', 'wlansvc.dll', 'wlanutil.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll', 'OneX.dll', 'ndisapi.dll')) {
  $a = Ver ('X:\Windows\System32\' + $d)
  $b = Ver ('C:\Windows\System32\' + $d)
  $flag = 'same-file?'
  if ($a -eq $b) { $flag = 'IDENTICAL-TEXT' } else { $flag = 'DIFFERENT' }
  Log ('  ' + ('{0,-15}' -f $d) + ' X:[' + $a + ']  C:[' + $b + ']  ' + $flag)
}
$OS = 'C:'
Log ('  C: build     = ' + (Ver ($OS + '\Windows\System32\wlansec.dll')))
$kv = (Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion')
Log ('  C: ProductName/ReleaseId = ' + [string]$kv.GetValue('ProductName') + ' / ' + [string]$kv.GetValue('ReleaseId') + ' / ' + [string]$kv.GetValue('DisplayVersion') + ' build ' + [string]$kv.GetValue('CurrentBuildNumber'))

Sec 'S4_SVC_HOST_MODULES'
foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  $mods = @()
  try { $mods = @(Get-Process -Id ([int]$q.ProcessId) -Module -EA SilentlyContinue | Where-Object { (One $_.ModuleName) -imatch 'wlan|dot3|OneX|wcmsvc' } | ForEach-Object { $_.ModuleName }) } catch { }
  Log ('  pid ' + $q.ProcessId + ' k=' + (One ([string]$q.CommandLine)) + ' wlan-mods=[' + ($mods -join ',') + ']')
}

Sec 'S5_NOTIFY_HYPOTHESIS'
# net.exe waits with NotifyServiceStatusChange. If that call is what fails with 6 in this PE, the
# whole "System error 6" story is a net.exe rendering artifact. The call BLOCKS when the handle is
# valid, so run it in a child process and judge by whether it manages to write its answer.
$ntfy = @'
param([string]$Name = '')
$src = @"
using System;
using System.Runtime.InteropServices;
public class NTF {
  [StructLayout(LayoutKind.Sequential)]
  public struct SN { public uint dwVersion; public IntPtr pszServiceName; public IntPtr pdwStatus; public IntPtr pContext; public uint dwControl; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool QueryServiceStatus(IntPtr svc, byte[] st);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern uint NotifyServiceStatusChangeW(IntPtr svc, uint mask, ref SN w);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  public static string Go(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    if (scm == IntPtr.Zero) return name + " OpenSCManager err=" + Marshal.GetLastWin32Error();
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u);
    if (h == IntPtr.Zero) return name + " OpenService err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    QueryServiceStatus(h, st);
    IntPtr pStatus = Marshal.AllocHGlobal(4);
    Marshal.WriteInt32(pStatus, BitConverter.ToInt32(st, 4));
    SN w = new SN();
    w.dwVersion = 1; w.pszServiceName = IntPtr.Zero; w.pdwStatus = pStatus; w.pContext = IntPtr.Zero; w.dwControl = 0;
    uint rc = NotifyServiceStatusChangeW(h, 0x00000002u, ref w);
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x00001300u, IntPtr.Zero, rc, 0, b, 512, IntPtr.Zero);
    string msg = (n > 0) ? Marshal.PtrToStringUni(b) : "";
    Marshal.FreeHGlobal(b); Marshal.FreeHGlobal(pStatus);
    return name + " Notify rc=" + rc + " [" + msg.Trim().Replace("\r"," ").Replace("\n"," ") + "] statusNow=" + Marshal.ReadInt32(pStatus);
  }
}
"@
Add-Type -TypeDefinition $src
$log = 'X:\notify19.txt'
if ($Name -ne '') {
  $r = [NTF]::Go($Name)
  Set-Content -LiteralPath $log -Value $r -Encoding ASCII
}
'@
Set-Content -LiteralPath 'X:\ntfy19.ps1' -Value $ntfy -Encoding ASCII
foreach ($nm in @('wlansvc', 'dot3svc')) {
  Remove-Item -LiteralPath 'X:\notify19.txt' -Force -EA SilentlyContinue
  $p = Start-Process -FilePath $PS -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','X:\ntfy19.ps1','-Name',$nm) -WindowStyle Hidden -PassThru
  $gone = $p.WaitForExit(7000)
  if (-not $gone) { try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch { } }
  $txt = ''
  if (Test-Path -LiteralPath 'X:\notify19.txt') { $txt = (One (Get-Content -LiteralPath 'X:\notify19.txt' -Raw -EA SilentlyContinue)) }
  if ($txt -eq '') { $txt = $(if ($gone) { 'child exited without writing (Add-Type failed?)' } else { 'BLOCKED 7s => the handle WAS valid and Notify waited (so net.exe error 6 is not from this call)' }) }
  Log ('  ' + $nm + ': ' + $txt)
}

Sec 'S6_NEARBY_SERVICES_AND_NET_CLASS'
foreach ($n in @('netprofm', 'nsi', 'NlaSvc', 'PolicyAgent', 'Dnscache', 'LanmanWorkstation', 'RpcSs', 'DcomLaunch', 'LSM', 'wcmsvc', 'dosvc', 'fdPHost')) {
  Log ('  ' + ('{0,-18}' -f $n) + (SvcState $n))
}
$NETCLASS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
$nc = @(Get-ChildItem -LiteralPath $NETCLASS -EA SilentlyContinue)
Log ('  Net class subkeys = ' + @($nc).Count)
foreach ($k in $nc) {
  $ki = Get-Item -LiteralPath $k.PSPath
  $nwf = $ki.GetValue('NativeWiFi Only')
  $nid = [string]$ki.GetValue('NetCfgInstanceId')
  $dsc = [string]$ki.GetValue('DriverDesc')
  if ($nwf -ne $null -or $nid -imatch 'nativewifi|wifi' -or $dsc -imatch 'wifi') {
    Log ('    ' + $k.PSChildName + ' NativeWiFiOnly=' + $nwf + ' NetCfgInstanceId=' + $nid + ' desc=' + $dsc)
  }
}
Log ('  X:\Windows\INF wifi-ish inf names:')
foreach ($f in @(Get-ChildItem -LiteralPath 'X:\Windows\INF' -Filter '*.inf' -EA SilentlyContinue | Where-Object { $_.Name -imatch 'wifi|dot3|ndis|net' })) {
  Log ('    ' + $f.Name)
}

Sec 'S6B_MATERIAL_INF_CAT_BINDINGS'
# two things this stack has never had: a signed .cat for nwifi.sys (NtLoadDriver gave
# STATUS_INVALID_IMAGE_HASH 0xC0000428 = the kernel could not validate the file) and an
# Ndi-NdisService binding that attaches the filter to a device class. Check both sides.
Log ('  X: has CatRoot      = ' + $(if (Test-Path -LiteralPath 'X:\Windows\System32\CatRoot') { 'yes' } else { 'NO' }))
$xcat = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\CatRoot' -Recurse -Filter '*.cat' -EA SilentlyContinue | Where-Object { $_.Name -imatch 'nwifi|dot3|wlan|netnwifi' })
Log ('  X: .cat matching wifi/dot3 = ' + @($xcat).Count)
foreach ($c in @($xcat) | Select-Object -First 8) { Log ('    ' + $c.Name) }
$ccat = @(Get-ChildItem -LiteralPath 'C:\Windows\System32\CatRoot' -Recurse -Filter '*.cat' -EA SilentlyContinue | Where-Object { $_.Name -imatch 'nwifi|dot3|wlan|netnwifi' })
Log ('  C: .cat matching wifi/dot3 = ' + @($ccat).Count)
foreach ($c in @($ccat) | Select-Object -First 8) { Log ('    ' + $c.FullName) }
$pkg = 'C:\Windows\System32\DriverStore\FileRepository\netnwifi.inf_amd64_a2bfd066656fe297'
Log '  C: netnwifi package, every file:'
foreach ($f in @(Get-ChildItem -LiteralPath $pkg -Recurse -File -EA SilentlyContinue)) {
  Log ('    ' + (One $f.FullName) + '  ' + [Math]::Round($f.Length / 1KB) + 'KB')
}
Log '  network adapters and the driver service each binds to:'
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)) {
  Log ('    ' + ('{0,-40}' -f (One ([string]$a.Name))) + ' physical=' + $a.PhysicalAdapter + ' service=' + (One ([string]$a.ServiceName)))
}
Log '  signed-driver view (wifi / virtual / ndis / 802):'
foreach ($d in @(Get-CimInstance Win32_PnPSignedDriver -EA SilentlyContinue | Where-Object { (One ([string]$_.DriverDescription)) -imatch 'wifi|virtual|ndis|802' -or (One ([string]$_.InfName)) -imatch 'nwifi|dot3|ndis' })) {
  Log ('    ' + (One ([string]$d.DriverDescription)) + ' | inf=' + (One ([string]$d.InfName)) + ' | ver=' + (One ([string]$d.DriverVersion)))
}
Log '  NdisVirtualBus children / class roots present:'
foreach ($e in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { (One ([string]$_.DeviceID)) -imatch 'ROOT\\NdisVirtualBus|ROOT\\NWIFI|WiFi' })) {
  Log ('    ' + (One $e.Name) + ' | ' + (One ([string]$e.Status)) + ' | ' + (One ([string]$e.DeviceID)))
}
Log ('  X:\nw18 leftovers from probe18 = ' + ((@(Get-ChildItem -LiteralPath 'X:\nw18' -File -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ', '))
$full = @(Get-ChildItem -LiteralPath $pkg -Recurse -File -EA SilentlyContinue)
if (@($full).Count -gt 0) {
  New-Item -Path 'X:\nw19' -ItemType Directory -Force -EA SilentlyContinue | Out-Null
  foreach ($f in $full) { Copy-Item -LiteralPath $f.FullName -Destination 'X:\nw19' -Force -EA SilentlyContinue }
  Log ('  staged X:\nw19 = ' + ((@(Get-ChildItem -LiteralPath 'X:\nw19' -File -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ', '))
  Log ('  stage: C: nwifi.sys = ' + (Ver 'X:\nw19\nwifi.sys'))
  if (Test-Path -LiteralPath 'X:\nw19\nwifi.sys') {
    # the .sys itself is Microsoft-signed inside the file; only the missing .cat blocked the package.
    # point the existing nativewifip key at the staged copy is NOT possible (kernel loads from
    # System32\DRIVERS), so instead hash-compare the staged file with the one in the image.
    $h1 = (Get-FileHash -LiteralPath 'X:\nw19\nwifi.sys' -Algorithm SHA256 -EA SilentlyContinue).Hash
    $h2 = (Get-FileHash -LiteralPath 'X:\windows\System32\DRIVERS\nwifi.sys' -Algorithm SHA256 -EA SilentlyContinue).Hash
    Log ('  hash staged(C:)=' + $h1)
    Log ('  hash in image  =' + $h2)
    Log ('  same file = ' + $(if ($h1 -eq $h2 -and $h1) { 'YES' } else { 'NO' }))
    Log ('  C: copy has its own .cat = ' + $(if (Test-Path -LiteralPath 'X:\nw19\netnwifi.inf') { 'inf yes' } else { 'inf no' }))
  }
}

Sec 'S7_OPENHANDLE_RACE'
# start and poll inside ONE process so we cannot miss a short RUNNING window
$race = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class WL19 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(uint c1, IntPtr r, out uint n, out IntPtr h);
  [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr p, out int c);
  [DllImport("wlanapi.dll")] public static extern void WlanCloseHandle(IntPtr h, IntPtr r);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool QueryServiceStatus(IntPtr svc, byte[] st);
  public static int State(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u);
    if (h == IntPtr.Zero) return -1;
    byte[] st = new byte[32];
    if (!QueryServiceStatus(h, st)) return -2;
    return (int)BitConverter.ToUInt32(st, 4);
  }
  public static bool Trigger(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u);
    if (h == IntPtr.Zero) return false;
    return StartServiceW(h, 0, IntPtr.Zero);
  }
}
"@
Add-Type -TypeDefinition $src
Write-Output ('  pre-trigger state=' + [WL19]::State('wlansvc'))
$ok = [WL19]::Trigger('wlansvc')
Write-Output ('  in-process raw StartService accepted=' + $ok)
$lastSt = -9; $lastRc = -999
$ver = 0; $hh = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  $st = [WL19]::State('wlansvc')
  $rc = [WL19]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hh)
  if ($st -ne $lastSt -or $rc -ne $lastRc) {
    Write-Output ('  i=' + $i + ' svcState=' + $st + ' WlanOpenHandle rc=' + $rc + ' negotiated=' + $ver)
    $lastSt = $st; $lastRc = $rc
  }
  if ($rc -eq 0) {
    $p = [IntPtr]::Zero; $n = 0
    $r2 = [WL19]::WlanEnumInterfaces($hh, [IntPtr]::Zero, [ref]$p, [ref]$n)
    Write-Output ('  REACHED RUNNING at i=' + $i + ': WlanEnumInterfaces rc=' + $r2 + ' interfaceCount=' + $n)
    [WL19]::WlanCloseHandle($hh, [IntPtr]::Zero)
    break
  }
  Start-Sleep -Milliseconds 50
}
Write-Output ('  race end: svcState=' + [WL19]::State('wlansvc') + ' lastOpenRc=' + $lastRc)
'@
Set-Content -LiteralPath 'X:\race19.ps1' -Value $race -Encoding ASCII
$ro = & cmd.exe /c ($PS + ' -NoProfile -ExecutionPolicy Bypass -File X:\race19.ps1 2>&1') | Out-String
foreach ($l in ($ro -split "`n")) { if ((One $l).Length -gt 1) { Log ((One $l)) } }
Log ('  state after race: ' + (SvcState 'wlansvc') + $(if ($global:OK19) { ' | ' + [SC19]::Status('wlansvc') } else { '' }))

Sec 'S8_FINAL'
Log ('  final wlansvc   : ' + (SvcState 'wlansvc'))
Log ('  final dot3svc   : ' + (SvcState 'dot3svc'))
Log ('  final wcmsvc    : ' + (SvcState 'wcmsvc'))
Log ('  nativewifip     : ' + (DrvState 'nativewifip'))
Log ('  leftovers: X:\race19.ps1, X:\nw18 (die at reboot)')
Log 'PROBE19_DONE'
