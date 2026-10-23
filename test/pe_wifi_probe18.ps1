# probe18: last live-disk cut on the one variable probes 7-17 never actually tested -- whether the
# NativeWiFi filter driver (nwifi.sys) can be made to ENTER the kernel, and whether wlansvc still
# fails with ERROR_INVALID_HANDLE once it has.
#
# Why this is the right question now:
#   - probe17 proved our key already carries Parameters\ServiceMain=WlanSvcMain (theory dead), and
#     that net start wlansvc stays at error 6 with the reference DependOnService set and Type=16.
#   - probe16/17 never loaded the filter: probe16 used New-Item -LiteralPath (unsupported on the
#     registry provider) so the key it "created" did not exist, and its NtLoadDriver P/Invoke passed
#     an LPWSTR where the API takes PUNICODE_STRING -- 0x80000002 was an artifact, not a verdict.
#   - wlansvc's WlanSvcMain opens the NativeWiFi filter (device class {5d0459d3...}) as its first
#     act; with no filter handle available, "invalid handle" is the error its start path reports.
# Three independent load routes are tried, each followed by a fresh start attempt, plus a correctly
# marshalled NtLoadDriver and a raw StartServiceW that prints the SCM's own status block.
# Everything here lives on the ramdisk and dies at reboot. Nothing touches the stick image.
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
  return ('State=' + $d[0].State + ' started=' + $d[0].Started + ' startmode=' + $d[0].StartMode + ' path=' + (One $d[0].PathName))
}
function Ver([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'ABSENT' }
  $f = Get-Item -LiteralPath $p
  $v = ''
  try { $v = [string]$f.VersionInfo.FileVersion } catch { }
  return ((One $v) + '  (' + [Math]::Round($f.Length / 1KB) + 'KB)')
}
$SVC  = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$S32  = 'X:\windows\System32'
$PS   = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

Sec '0_TOOLS_AND_OS_VOLUME'
Log ('  nwifi.sys in image = ' + (Ver ($S32 + '\drivers\nwifi.sys')))
foreach ($t in @('pnputil.exe', 'drvload.exe', 'devcon.exe', 'sc.exe', 'net.exe')) {
  Log ('  tool ' + ('{0,-12}' -f $t) + ' = ' + $(if (Test-Path -LiteralPath ($S32 + '\' + $t)) { 'present' } else { 'ABSENT' }))
}
$OS = ''
foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue)) {
  $r = $d.DeviceID + '\Windows\System32\ntdll.dll'
  if ((Test-Path -LiteralPath $r) -and ($d.DeviceID -ne 'X:')) { $OS = $d.DeviceID; break }
}
Log ('  real Windows volume found = [' + $OS + ']')
if ($OS -ne '') {
  Log ('  its System32\drivers\nwifi.sys = ' + (Ver ($OS + '\Windows\System32\drivers\nwifi.sys')))
}

Sec '1_BASELINE_RESTORE'
# probe17 left Type=16 and a 3-dep list on this ramdisk (only if it was not rebooted since).
Log ('  reg add Type=32          => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v Type /t REG_DWORD /d 32 /f')))
Log ('  reg add DependOnService  => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v DependOnService /t REG_MULTI_SZ /d RpcSs /f')))
Log ('  wlansvc baseline  : ' + (SvcState 'wlansvc'))
Log ('  nativewifip before: ' + (DrvState 'nativewifip'))
$k = Get-Item -LiteralPath ($SVC + '\nativewifip') -EA SilentlyContinue
if ($k) {
  Log ('  nativewifip key: Type=' + $k.GetValue('Type') + ' Start=' + $k.GetValue('Start') +
       ' Group=' + (One ([string]$k.GetValue('Group'))) + ' ImagePath=' +
       (One ([string]$k.GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))))
} else { Log '  nativewifip key ABSENT' }

Sec '2_SCM_CACHED_VIEW_AND_RAW_START'
foreach ($n in @('wlansvc', 'dot3svc')) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -EA SilentlyContinue
  if ($s) {
    Log ('  CIM ' + $n + ': display=[' + (One $s.DisplayName) + '] path=[' + (One $s.PathName) +
         '] started=' + $s.Started + ' acceptStop=' + $s.AcceptStop + ' exitcode=' + $s.ExitCode +
         ' sspec=' + $s.ServiceSpecificExitCode + ' type=' + $s.ServiceType)
  } else { Log ('  CIM ' + $n + ': NOT-IN-SCM-DB') }
}
try {
  $src18 = @"
using System;
using System.Runtime.InteropServices;
public class SC18 {
  [StructLayout(LayoutKind.Sequential)]
  public struct US { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
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
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  [DllImport("ntdll.dll")] public static extern uint RtlAdjustPrivilege(int p, bool en, bool th, out bool prev);
  [DllImport("ntdll.dll")] public static extern uint RtlNtStatusToDosError(uint st);
  [DllImport("ntdll.dll")] public static extern uint NtLoadDriver(ref US s);
  public static string Msg(uint c) {
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x00001300u, IntPtr.Zero, c, 0, b, 512, IntPtr.Zero);
    string t = (n > 0) ? Marshal.PtrToStringUni(b) : "";
    Marshal.FreeHGlobal(b);
    return t.Trim().Replace("\r", " ").Replace("\n", " ");
  }
  public static string Start(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    if (scm == IntPtr.Zero) return name + " RAW: OpenSCManager err=" + Marshal.GetLastWin32Error() + " [" + Msg((uint)Marshal.GetLastWin32Error()) + "]";
    uint mask = 0x0001u | 0x0004u | 0x0010u | 0x0020u | 0x0080u;
    IntPtr h = OpenServiceW(scm, name, mask);
    if (h == IntPtr.Zero) return name + " RAW: OpenService err=" + Marshal.GetLastWin32Error() + " [" + Msg((uint)Marshal.GetLastWin32Error()) + "]";
    byte[] st = new byte[32];
    bool ok0 = QueryServiceStatus(h, st);
    string pre = "";
    if (ok0) {
      uint cs   = BitConverter.ToUInt32(st, 4);
      uint exit = BitConverter.ToUInt32(st, 8);
      uint spc  = BitConverter.ToUInt32(st, 12);
      uint ckp  = BitConverter.ToUInt32(st, 16);
      pre = " status{ok=" + (ok0 ? 1 : 0) + " state=" + cs + " win32exit=" + exit + " specific=" + spc + " checkpoint=" + ckp + "}";
    }
    bool ok = StartServiceW(h, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    string r = name + " RAW StartService => " + (ok ? "TRUE" : ("FALSE err=" + e + " [" + Msg((uint)e) + "]")) + pre;
    byte[] st2 = new byte[20];
    if (QueryServiceStatus(h, st2)) { r += " after{state=" + BitConverter.ToUInt32(st2, 4) + " win32exit=" + BitConverter.ToUInt32(st2, 8) + "}"; }
    return r;
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
    return "adjustPriv=0x" + ap.ToString("X8") + " prev=" + prev + " NtLoadDriver rc=0x" + rc.ToString("X8") +
           " dos=" + dos + " [" + Msg(dos) + "]";
  }
}
"@
  Add-Type -TypeDefinition $src18
  $global:SC18ok = $true
  Log '  Add-Type SC18 ok'
} catch {
  $global:SC18ok = $false
  Log ('  Add-Type SC18 FAILED: ' + (One ([string]$_)))
}
if ($global:SC18ok) {
  Log ('  ' + [SC18]::Start('wlansvc'))
  Log ('  ' + [SC18]::Start('dot3svc'))
}

Sec '3_FIND_SIGNED_NWIFI_PACKAGE'
$pkg = ''
if ($OS -ne '') {
  $fr = $OS + '\Windows\System32\DriverStore\FileRepository'
  $cands = @(Get-ChildItem -LiteralPath $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -imatch 'nwifi|nativewifi' })
  Log ('  FileRepository candidates = ' + ((@($cands) | ForEach-Object { $_.Name }) -join ', '))
  if (@($cands).Count -gt 0) { $pkg = $cands[0].FullName }
}
if ($pkg -eq '') {
  Log '  no packaged netnwifi found on the real volume -> skipping routes A/B, key route only'
} else {
  Log ('  package = ' + $pkg)
  foreach ($f in @(Get-ChildItem -LiteralPath $pkg -File -EA SilentlyContinue)) {
    Log ('    ' + ('{0,-24}' -f $f.Name) + [Math]::Round($f.Length / 1KB) + 'KB')
  }
  New-Item -Path 'X:\nw18' -ItemType Directory -Force -EA SilentlyContinue | Out-Null
  Copy-Item -Path ($pkg + '\*') -Destination 'X:\nw18' -Force -EA SilentlyContinue
  Log ('  copied to X:\nw18: ' + ((@(Get-ChildItem -LiteralPath 'X:\nw18' -File -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ', '))
  Log ('  X:\nw18\nwifi.sys = ' + (Ver 'X:\nw18\nwifi.sys'))
  $inf = 'X:\nw18\netnwifi.inf'
  if (Test-Path -LiteralPath $inf) {
    $lines = @(Get-Content -LiteralPath $inf -EA SilentlyContinue)
    Log ('  inf lines = ' + $lines.Count)
    $i = 0
    foreach ($l in $lines) {
      $i++
      if ($l -imatch '^\s*(AddService|ServiceType|StartType|ServiceBinary|LoadOrderGroup|Class\s*=|ClassGUID|NdisMajorVersion|NdisMinorVersion|DriverMajorVersion|DriverMajorMinVersion|CatalogFile|Signature|Provider|LayoutFile)') {
        Log ('    ' + $i.ToString() + ': ' + (One $l))
      }
    }
  } else { Log '  etnwifi.inf not in the copied set' }
}

Sec '4_ROUTE_A_PNPUTIL_INSTALL'
$nBefore = DrvState 'nativewifip'
if ((Test-Path -LiteralPath ($S32 + '\pnputil.exe')) -and (Test-Path -LiteralPath 'X:\nw18\netnwifi.inf')) {
  Log '  pnputil /add-driver X:\nw18\netnwifi.inf /install'
  $po = & cmd.exe /c 'X:\windows\System32\pnputil.exe -add-driver X:\nw18\netnwifi.inf /install 2>&1' | Out-String
  foreach ($l in ($po -split "`n")) { if ((One $l).Length -gt 1) { Log ('    ' + (One $l)) } }
  Log '  pnputil -e (driver packages, filtered)'
  $pe = & cmd.exe /c 'X:\windows\System32\pnputil.exe -e 2>&1' | Out-String
  $hits = @($pe -split "`n" | Where-Object { (One $_) -imatch 'wifi|nwifi|native' })
  foreach ($h in $hits) { Log ('    ' + (One $h)) }
  Log ('    package-line count matched = ' + @($hits).Count)
} else {
  Log '  route A skipped (pnputil or package missing)'
}
Log ('  nativewifip after A: ' + (DrvState 'nativewifip'))
Log ('  nwifi (pkg name)   : ' + (DrvState 'nwifi'))
Log ('  NdisVirtualBus     : ' + (DrvState 'NdisVirtualBus'))

Sec '5_ROUTE_B_DRVLOAD'
if (Test-Path -LiteralPath 'X:\nw18\netnwifi.inf') {
  Log '  drvload X:\nw18\netnwifi.inf'
  Log ('    => ' + (Cmd 'X:\windows\System32\drvload.exe X:\nw18\netnwifi.inf'))
} else { Log '  route B skipped (no inf)' }
Log ('  nativewifip after B: ' + (DrvState 'nativewifip'))
Log ('  nwifi (pkg name)   : ' + (DrvState 'nwifi'))

Sec '6_ROUTE_C_NTLOADDRIVER'
# make sure the key is a complete, valid service record for the kernel loader
$NK = 'HKLM\SYSTEM\CurrentControlSet\Services\nativewifip'
Log ('  reg add Start=3        => ' + (Cmd ('reg add "' + $NK + '" /v Start /t REG_DWORD /d 3 /f')))
Log ('  reg add Type=1         => ' + (Cmd ('reg add "' + $NK + '" /v Type /t REG_DWORD /d 1 /f')))
Log ('  reg add ErrorControl=1 => ' + (Cmd ('reg add "' + $NK + '" /v ErrorControl /t REG_DWORD /d 1 /f')))
Log ('  reg add Group=NDIS     => ' + (Cmd ('reg add "' + $NK + '" /v Group /t REG_SZ /d NDIS /f')))
Log ('  reg add ImagePath      => ' + (Cmd ('reg add "' + $NK + '" /v ImagePath /t REG_EXPAND_SZ /d "system32\DRIVERS\nwifi.sys" /f')))
Log ('  reg add NdisMajor=6    => ' + (Cmd ('reg add "' + $NK + '" /v NdisMajorVersion /t REG_DWORD /d 6 /f')))
Log ('  reg add NdisMinor=84   => ' + (Cmd ('reg add "' + $NK + '" /v NdisMinorVersion /t REG_DWORD /d 84 /f')))
Log ('  reg add DrvMajor=1     => ' + (Cmd ('reg add "' + $NK + '" /v DriverMajorVersion /t REG_DWORD /d 1 /f')))
Log ('  reg add DrvMinor=0     => ' + (Cmd ('reg add "' + $NK + '" /v DriverMinorVersion /t REG_DWORD /d 0 /f')))
Log ('  file X:\windows\system32\DRIVERS\nwifi.sys = ' + (Ver ($S32 + '\DRIVERS\nwifi.sys')))
Log ('  nativewifip before C: ' + (DrvState 'nativewifip'))
if ($global:SC18ok) {
  Log ('  ROUTE C: ' + [SC18]::Load('\Registry\Machine\System\CurrentControlSet\Services\nativewifip'))
} else { Log '  route C needs SC18 type (unavailable)' }
Log ('  nativewifip after C: ' + (DrvState 'nativewifip'))

Sec '7_WLANSVC_AFTER_FILTER'
$nf = DrvState 'nativewifip'
Log ('  filter state going in: ' + $nf)
Log ('  net start wlansvc : ' + (Cmd 'net start wlansvc'))
Log ('    state = ' + (SvcState 'wlansvc'))
if ($global:SC18ok) { Log ('  ' + [SC18]::Start('wlansvc')) }
Log ('  net start wcmsvc  : ' + (Cmd 'net start wcmsvc'))
Log ('    state = ' + (SvcState 'wcmsvc'))
$ps18 = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class WL18 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(uint c1, IntPtr r, out uint n, out IntPtr h);
  [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr p, out int c);
}
"@
Add-Type -TypeDefinition $src
$ver = 0
$hh = [IntPtr]::Zero
$rc = [WL18]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hh)
Write-Output ('WlanOpenHandle rc=' + $rc + ' negotiated=' + $ver)
if ($rc -eq 0) {
  $p = [IntPtr]::Zero
  $n = 0
  $r2 = [WL18]::WlanEnumInterfaces($hh, [IntPtr]::Zero, [ref]$p, [ref]$n)
  Write-Output ('WlanEnumInterfaces rc=' + $r2 + ' count=' + $n)
}
'@
Set-Content -LiteralPath 'X:\wl18.ps1' -Value $ps18 -Encoding ASCII
$wo = & cmd.exe /c ($PS + ' -NoProfile -ExecutionPolicy Bypass -File X:\wl18.ps1 2>&1') | Out-String
foreach ($l in ($wo -split "`n")) { if ((One $l).Length -gt 1) { Log ('  wlanapi: ' + (One $l)) } }

Sec '8_DEVICE_AND_FINAL'
$CL = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{5d0459d3-400a-4b7b-8165-ed42148036bb}'
Log ('  NativeWiFiFilter class key present = ' + $(if (Test-Path -LiteralPath $CL) { 'YES' } else { 'NO' }))
$ROOT = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT'
Log ('  Enum\ROOT device classes = ' + ((@(Get-ChildItem -LiteralPath $ROOT -EA SilentlyContinue | ForEach-Object { $_.PSChildName })) -join ', '))
$devs = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { (One $_.Name) -imatch 'wifi|wireless|802\.11|NativeWiFi' })
Log ('  PnP entities mentioning wifi = ' + @($devs).Count)
foreach ($d in $devs) { Log ('    ' + (One $d.Name) + ' | ' + (One ([string]$d.Status)) + ' | ' + (One ([string]$d.ClassGuid)) + ' | ' + (One ([string]$d.DeviceID))) }
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
foreach ($d in @('nativewifip', 'Ndisuio', 'NdisVirtualBus', 'NDIS')) { Log ('  final driver ' + $d + ' ' + (DrvState $d)) }
Log '  leftovers on ramdisk: X:\nw18, X:\wl18.ps1 (die at reboot)'
Log 'PROBE18_DONE'
