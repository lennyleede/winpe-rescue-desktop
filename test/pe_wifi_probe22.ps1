# probe22: is wlansvc's abort actually a DOWNSTREAM symptom of the NativeWiFi filter being unloadable?
#
# What changed since probe21 (build/scratch/pw21_raw.txt):
#   * pe_exports.ps1 on the host proves wlansvc.dll DOES export WlanSvcMain as a real (non-forwarded)
#     named export, ordinal 6. So probe21 S6 "GetProcAddress => MISSING err=127" was harness noise and
#     the DLL is not missing its entry point.
#   * Probe21 case C (dot3svc name + wlansvc.dll) reported RUNNING but the host's module list afterwards
#     still showed dot3svc.dll and NO wlansvc.dll, and dot3svc had been running in that very svchost
#     since boot (ServiceDllUnloadOnStop=0). svchost therefore reused its cached in-process instance:
#     case C never executed WlanSvcMain. Case B is equally suspect because dwServiceSpecificExitCode is a
#     LAST-WRITTEN field, so the 0x800C0006 seen there may be case A's stale value.
#   => the "boot-cached record for the NAME wlansvc is poisoned" conclusion is NOT supported.
#      Working theory now: WlanSvcMain runs, its own init fails ~140 ms later and reports a WLAN_E_*
#      status (0x800C0006), because the NativeWiFi filter driver (nativewifip / nwifi.sys) is not loaded
#      and cannot be loaded: probe18 S6 got STATUS_INVALID_IMAGE_HASH (0xC0000428) from NtLoadDriver.
#      On real Windows WLAN AutoConfig starts fine with zero radios BECAUSE the filter is present.
#
# This probe attacks that one link, no rebuild needed (the ramdisk hive dies at reboot anyway):
#   S0  evidence: SecureBoot state, nwifi.sys file, is there ANY .cat in the PE that covers nwifi,
#       plus a POSITIVE CONTROL - NtLoadDriver on a driver the boot already loaded (Ndisuio) must give
#       STATUS_IMAGE_ALREADY_LOADED (0xC000013D), which proves the marshalling is right and that the
#       0xC0000428 was a real verdict about nwifi.sys.
#   S1  turn off code-integrity enforcement + the vulnerable-driver blocklist, retry nativewifip.
#   S2  if the filter loads, start wlansvc immediately and see whether it now reaches RUNNING.
#   S3  final state.
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SetReg([string]$sub, [string]$name, [string]$type, [string]$data) {
  $d = $data
  if ($d -imatch '[\s\\]') { $d = '"' + $d + '"' }
  $r = Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\' + $sub + '" /v ' + $name + ' /t ' + $type + ' /d ' + $d + ' /f')
  return ($sub + '\' + $name + ' <- ' + $data + ' : ' + $r)
}
function DelReg([string]$sub, [string]$name) {
  return ($sub + '\' + $name + ' del : ' + (Cmd ('reg delete "HKLM\SYSTEM\CurrentControlSet\' + $sub + '" /v ' + $name + ' /f')))
}
function Ver([string]$p) {
  if (-not (Test-Path $p)) { return 'ABSENT' }
  $i = Get-Item $p
  return ('{0} ({1}KB)' -f $i.VersionInfo.FileVersion, [int]($i.Length / 1KB))
}
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}

Sec 'S0_PREP_CONTROL_AND_CATALOG_EVIDENCE'
$src22 = @"
using System;
using System.Runtime.InteropServices;
public class SC22 {
  [StructLayout(LayoutKind.Sequential)]
  public struct US { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [DllImport("ntdll.dll")] public static extern uint NtLoadDriver(ref US s);
  [DllImport("ntdll.dll")] public static extern uint RtlNtStatusToDosError(uint st);
  [DllImport("ntdll.dll")] public static extern uint RtlAdjustPrivilege(int p, bool en, bool th, out bool prev);
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
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  public static string Msg(uint c) {
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x00001300u, IntPtr.Zero, c, 0, b, 512, IntPtr.Zero);
    string t = (n > 0) ? Marshal.PtrToStringUni(b) : "";
    Marshal.FreeHGlobal(b);
    return t.Trim().Replace("\r", " ").Replace("\n", " ");
  }
  public static string Privs() {
    bool prev = false;
    uint a = RtlAdjustPrivilege(20, true, false, out prev);
    uint b = RtlAdjustPrivilege(10, true, false, out prev);
    uint c = RtlAdjustPrivilege(1,  true, false, out prev);
    return "SeDebug=0x" + a.ToString("X8") + " SeLoadDriver=0x" + b.ToString("X8") + " SeTakeOwnership=0x" + c.ToString("X8");
  }
  public static string Load(string keyPath) {
    byte[] buf = System.Text.Encoding.Unicode.GetBytes(keyPath);
    US u = new US();
    u.Length = (ushort)(keyPath.Length * 2);
    u.MaximumLength = (ushort)((keyPath.Length + 1) * 2);
    u.Buffer = Marshal.AllocHGlobal(u.MaximumLength);
    Marshal.Copy(buf, 0, u.Buffer, buf.Length);
    uint rc = NtLoadDriver(ref u);
    uint dos = RtlNtStatusToDosError(rc);
    Marshal.FreeHGlobal(u.Buffer);
    string v = "rc=0x" + rc.ToString("X8") + " dos=" + dos;
    if (dos != 0) v += " [" + Msg(dos) + "]";
    return keyPath + " => " + v;
  }
  public static string Status(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u | 0x0020u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    string r = "";
    if (QueryServiceStatus(h, st)) {
      r = "state=" + BitConverter.ToUInt32(st, 4) +
          " win32exit=0x" + BitConverter.ToUInt32(st, 8).ToString("X8") +
          " specific=0x" + BitConverter.ToUInt32(st, 12).ToString("X8");
    } else { r = "QUERY-err=" + Marshal.GetLastWin32Error(); }
    CloseHandle(h);
    return name + " " + r;
  }
  public static string Start(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    bool ok = StartServiceW(h, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    CloseHandle(h);
    return name + " StartService => " + (ok ? "ACCEPTED" : ("refused err=" + e + " [" + Msg((uint)e) + "]"));
  }
}
"@
try { Add-Type -TypeDefinition $src22 -ErrorAction Stop; Log '  Add-Type SC22 ok' }
catch { Log ('  Add-Type FAILED: ' + $_.Exception.Message); Log 'PROBE22_DONE'; return }
Log ('  ' + [SC22]::Privs())

Log ('  nativewifip key : ' + (SvcState 'nativewifip'))
Log ('  nwifi.sys       : ' + (Ver 'X:\Windows\System32\drivers\nwifi.sys'))
Log ('  Ndisuio.sys     : ' + (Ver 'X:\Windows\System32\drivers\ndisuio.sys'))
Log ('  ' + (Cmd 'reg query HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot'))
Log ('  ' + (Cmd 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI" /v Disabled'))

# POSITIVE CONTROL: a driver the boot already loaded. 0xC000013D STATUS_IMAGE_ALREADY_LOADED proves the
# Unicode-string marshalling works, so the 0xC0000428 seen for nativewifip is a real CI verdict.
Log ('  CONTROL already-loaded driver: ' + [SC22]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\Ndisuio'))
Log ('  CONTROL bogus key            : ' + [SC22]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\nosuchsvc12345'))

# which catalog in the image covers nwifi.sys? cats store member names; look for the ascii + utf16 forms.
$cats = @()
$dirs = @()
$catRoot = 'X:\Windows\System32\CatRoot'
if (Test-Path $catRoot) {
  $dirs = @(Get-ChildItem $catRoot -Directory -EA SilentlyContinue)
  foreach ($d in $dirs) { $cats += @(Get-ChildItem $d.FullName -Filter *.cat -File -EA SilentlyContinue) }
}
Log ('  CatRoot dirs=' + $dirs.Count + ' cat files=' + $cats.Count)
$scanned = 0; $skipped = 0; $hits = 0
foreach ($c in $cats) {
  if ($c.Length -gt 4MB) { $skipped++; continue }
  $scanned++
  $bytes = [IO.File]::ReadAllBytes($c.FullName)
  $asc = [Text.Encoding]::ASCII.GetString($bytes)
  $u16 = [Text.Encoding]::Unicode.GetString($bytes)
  $hitN = ($asc -imatch 'nwifi') -or ($u16 -imatch 'nwifi')
  $hitW = ($asc -imatch 'wlan') -or ($u16 -imatch 'wlan')
  if ($hitN -or $hitW) {
    $hits++
    Log ('    HIT ' + $c.Name + ' nwifi=' + $hitN + ' wlan=' + $hitW + ' (' + [int]($c.Length / 1KB) + 'KB)')
  }
  if ($scanned -le 12) { Log ('      seen ' + ('{0,-60}' -f $c.Name) + '(' + [int]($c.Length / 1KB) + 'KB)') }
}
Log ('  scanned=' + $scanned + ' skipped-too-big=' + $skipped + ' cats mentioning wlan/nwifi=' + $hits)

Sec 'S1_BASELINE_LOAD_ATTEMPT'
Log ('  ' + [SC22]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\nativewifip'))
Log ('  ' + [SC22]::Status('nativewifip'))
Log ('  via SCM: ' + [SC22]::Start('nativewifip'))
Start-Sleep -Milliseconds 800
Log ('  ' + [SC22]::Status('nativewifip') + '  ' + (SvcState 'nativewifip'))

Sec 'S2_CI_BYPASS_AND_RETRY'
Log ('  ' + (SetReg 'Control\CI' 'Disabled' 'REG_DWORD' '1'))
Log ('  ' + (SetReg 'Control\CI\Config' 'VulnerableDriverBlocklistEnable' 'REG_DWORD' '0'))
Log ('  ' + (Cmd 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI"'))
Log ('  ' + (Cmd 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config"'))
Log ('  retry nativewifip after CI bypass: ' + [SC22]::Load('\Registry\Machine\SYSTEM\CurrentControlSet\Services\nativewifip'))
Log ('  ' + [SC22]::Status('nativewifip'))
Log ('  via SCM: ' + [SC22]::Start('nativewifip'))
Start-Sleep -Milliseconds 800
Log ('  ' + [SC22]::Status('nativewifip') + '  ' + (SvcState 'nativewifip'))

Sec 'S3_WLANSVC_WITH_AND_WITHOUT_FILTER'
$nf = [SC22]::Status('nativewifip')
Log ('  filter going in: ' + $nf)
Log ('  ' + [SC22]::Start('wlansvc'))
$t0 = Get-Date
$last = ''
for ($i = 0; $i -lt 40; $i++) {
  $s = [SC22]::Status('wlansvc')
  if ($s -ne $last) {
    Log ('    wlansvc t+' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms  ' + $s)
    $last = $s
  }
  if ($s -match 'state=4') { Log '    (RUNNING)'; break }
  Start-Sleep -Milliseconds 50
}
Log ('  wlansvc : ' + (SvcState 'wlansvc') + ' | ' + [SC22]::Status('wlansvc'))
Log ('  nativewifip: ' + (SvcState 'nativewifip'))

Sec 'S4_FINAL'
Log ('  ' + (DelReg 'Control\CI' 'Disabled'))
Log ('  final nativewifip : ' + [SC22]::Status('nativewifip') + '  ' + (SvcState 'nativewifip'))
Log ('  final wlansvc     : ' + [SC22]::Status('wlansvc') + '  ' + (SvcState 'wlansvc'))
Log '  ramdisk hive edits die at reboot; the stick image was not touched'
Log 'PROBE22_DONE'
