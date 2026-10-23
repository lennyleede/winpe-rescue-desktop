# probe20: probe19 changed the question.
#
# What probe19 established (build/scratch/pw19_raw.txt):
#   * raw StartServiceW wlansvc => ACCEPTED. state 2 (START_PENDING) at t+1ms -> 3 (STOP_PENDING)
#     -> 1 (STOPPED) at t+326ms. wcmsvc behaves the same. So the SCM never refused; the service
#     aborts itself in the first frame, and "System error 6" is only what net.exe prints.
#   * S3 version audit: X: is a MIXED stack. Native 26100.1 for dot3api/dot3cfg/dot3msm/wlanutil/
#     OneX, borrowed 19041.7725 for wlansvc/wlanapi/wlanmsm/wlansec/wlansvcpal/wcmsvc.
#     The one service that works (dot3svc) is the 26100-native one; the two that abort are borrowed.
#   * S6B: no netnwifi package exists anywhere reachable -- C:'s FileRepository entry holds only
#     netnwifi.inf + .PNF (no nwifi.sys, no .cat), which is why pnputil said "INF does not contain
#     digital signature information" and NtLoadDriver answered STATUS_INVALID_IMAGE_HASH.
#   * the bench machine has ONE network adapter (Realtek 2.5GbE, service rt640x64) -> no WiFi here.
# So the remaining question is WHY 19041 wlansvc.dll self-stops on a 26100 OS, and whether a shape
# or version-coherence change fixes it. probe19 also shows the exit code the SCM carries:
# serviceSpecific=0x800C0006 (win32 exit 0).
#
# Instruments used here (all ramdisk-only, gone at reboot):
#   S1 svchost -d -s <svc> with real console redirection: svchost's debug host prints the load /
#      entry-point failure to stdout. dot3svc is run as a positive control for the harness.
#   S2 ServiceDllUnloadOnStop=0 + psapi module scan: if wlansvc.dll is still mapped in the host
#      afterwards, the DLL DID load and WlanSvcMain chose to stop; if it is absent, svchost never
#      got the DLL in. Deterministic instead of racing the 300 ms window.
#   S3 shape sweep with the CORRECT instrument (state timeline, not net.exe text): privileges,
#      ServiceSidType, Type=16 dedicated host.
#   S4 coherence test: copy the whole matching 19041 WLAN set from C: into X:\w19041 and point
#      Parameters\ServiceDll there, so wlansvc.dll resolves its siblings from the same build
#      directory instead of mixing with the image's 26100 files.
#   S5 wcmsvc control (same borrowed family, same symptom).
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
function SetReg([string]$key, [string]$name, [string]$type, [string]$data) {
  $r = Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\' + $key + '" /v ' + $name + ' /t ' + $type + ' /d ' + $data + ' /f')
  return ($name + '<-' + $data + ' : ' + $r)
}
$PS   = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$SVC  = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SVCH = 'X:\windows\system32\svchost.exe'

Sec 'S0_PREP'
Log ('  ' + (SetReg 'wlansvc' 'Type' 'REG_DWORD' '32'))
Log ('  ' + (SetReg 'wlansvc' 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'))
Log ('  ' + (SetReg 'wlansvc' 'Start' 'REG_DWORD' '3'))
Log ('  wlansvc : ' + (SvcState 'wlansvc'))
Log ('  dot3svc : ' + (SvcState 'dot3svc'))
Log ('  winevt logs present = ' + $(if (Test-Path -LiteralPath 'X:\Windows\System32\winevt\Logs') { ((@(Get-ChildItem -LiteralPath 'X:\Windows\System32\winevt\Logs' -File -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ',') } else { 'NO winevt\Logs' }))
try {
  $ev = @(Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 5 -EA SilentlyContinue)
  Log ('  Get-WinEvent System entries = ' + @($ev).Count)
  foreach ($e in $ev) { Log ('    ' + $e.TimeCreated + ' id=' + $e.Id + ' ' + (One $e.Provider.Name) + ': ' + (One $e.Message)) }
} catch { Log ('  Get-WinEvent unavailable: ' + (One ([string]$_))) }

try {
  $src20 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class SC20 {
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
  public static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll")]
  public static extern bool EnumProcessModules(IntPtr h, IntPtr[] l, uint cb, out uint need);
  [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
  public static extern uint GetModuleBaseNameW(IntPtr h, IntPtr m, StringBuilder s, uint n);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  [DllImport("ntdll.dll")] public static extern uint RtlAdjustPrivilege(int p, bool en, bool th, out bool prev);
  public static string EnableDebug() {
    bool prev = false;
    // SeDebugPrivilege = 20, needed to read another service host's module list
    uint rc = RtlAdjustPrivilege(20, true, false, out prev);
    return "RtlAdjustPrivilege(SeDebug) rc=0x" + rc.ToString("X8") + " prev=" + prev;
  }
  public static string Msg(uint c) {
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x00001300u, IntPtr.Zero, c, 0, b, 512, IntPtr.Zero);
    string t = (n > 0) ? Marshal.PtrToStringUni(b) : "";
    Marshal.FreeHGlobal(b);
    return t.Trim().Replace("\r", " ").Replace("\n", " ");
  }
  public static string Status(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    if (scm == IntPtr.Zero) return "SCM-err=" + Marshal.GetLastWin32Error();
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u);
    if (h == IntPtr.Zero) return "OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    if (!QueryServiceStatus(h, st)) return "QUERY-err=" + Marshal.GetLastWin32Error();
    CloseHandle(h);
    return "state=" + BitConverter.ToUInt32(st, 4) +
           " win32exit=0x" + BitConverter.ToUInt32(st, 8).ToString("X8") +
           " specific=0x" + BitConverter.ToUInt32(st, 12).ToString("X8");
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
  public static string Wlan(int pid) {
    IntPtr h = OpenProcess(0x0410u, false, pid);
    if (h == IntPtr.Zero) h = OpenProcess(0x1000u, false, pid);
    if (h == IntPtr.Zero) return "pid" + pid + " open-err=" + Marshal.GetLastWin32Error();
    IntPtr[] mods = new IntPtr[2048];
    uint need = 0;
    bool ok = EnumProcessModules(h, mods, (uint)(mods.Length * IntPtr.Size), out need);
    string r;
    if (!ok) { r = "pid" + pid + " enum-err=" + Marshal.GetLastWin32Error(); }
    else {
      int cnt = (int)(need / (uint)IntPtr.Size);
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < cnt; i++) {
        StringBuilder nm = new StringBuilder(300);
        if (GetModuleBaseNameW(h, mods[i], nm, (uint)nm.Capacity) == 0) continue;
        string s = nm.ToString();
        if (s.IndexOf("wlan", StringComparison.OrdinalIgnoreCase) >= 0 ||
            s.IndexOf("dot3", StringComparison.OrdinalIgnoreCase) >= 0 ||
            s.IndexOf("onex", StringComparison.OrdinalIgnoreCase) >= 0 ||
            s.IndexOf("wcmsvc", StringComparison.OrdinalIgnoreCase) >= 0) {
          if (sb.Length > 0) sb.Append(',');
          sb.Append(s);
        }
      }
      r = "pid" + pid + "(" + cnt + " mods)[" + sb.ToString() + "]";
    }
    CloseHandle(h);
    return r;
  }
}
"@
  Add-Type -TypeDefinition $src20
  $global:OK20 = $true
  Log '  Add-Type SC20 ok'
  Log ('  ' + [SC20]::EnableDebug())
} catch {
  $global:OK20 = $false
  Log ('  Add-Type SC20 FAILED: ' + (One ([string]$_)))
}

function TriggerAndWatch([string]$svc, [int]$ms, [string]$tag) {
  if (-not $global:OK20) { Log ('    ' + $tag + ' : SC20 unavailable'); return }
  Log ('    ' + $tag + ' ' + [SC20]::Start($svc))
  $t0 = Get-Date
  $last = ''
  $seq = ''
  for ($i = 0; $i -lt 40; $i++) {
    $s = [SC20]::Status($svc)
    $st = ''
    if ($s -imatch 'state=(\d+)') { $st = $matches[1] }
    if ($st -ne $last) {
      $seq += (' ' + $st + '@' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms')
      $last = $st
    }
    if ($st -eq '1' -and $i -gt 2) { break }
    Start-Sleep -Milliseconds ([Math]::Max(25, [int]($ms / 40)))
  }
  Log ('      state sequence:' + $seq + '  final ' + [SC20]::Status($svc))
}
function HostScan() {
  if (-not $global:OK20) { return }
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    $r = [SC20]::Wlan([int]$q.ProcessId)
    if ($r -imatch 'err=') {
      # psapi path blocked -> fall back to the cmdlet that is proven to work in this PE
      try {
        $ms = @(Get-Process -Id ([int]$q.ProcessId) -Module -EA SilentlyContinue | Where-Object { (One $_.ModuleName) -imatch 'wlan|dot3|onex|wcmsvc' } | ForEach-Object { $_.ModuleName })
        if (@($ms).Count -gt 0) { $r = 'pid' + $q.ProcessId + ' via-Get-Process[' + ($ms -join ',') + ']' }
      } catch { }
    }
    if ($r -imatch '\[(.+)\]$' -and $matches[1].Length -gt 0) {
      Log ('      ' + $r + '  k=' + (One ([string]$q.CommandLine)))
    }
  }
}

Sec 'S1_SVCHOST_DEBUG_HOST_WITH_CONSOLE'
# -d makes svchost run one service in the current console and print its load diagnostics.
foreach ($pair in @(@('wlansvc', 'FAILING'), @('dot3svc', 'CONTROL-should-work'))) {
  $svc = $pair[0]; $role = $pair[1]
  $out = 'X:\svcout_' + $svc + '.txt'
  Remove-Item -LiteralPath $out -Force -EA SilentlyContinue
  $inner = '"' + $SVCH + ' -k LocalSystemNetworkRestricted -d -s ' + $svc + ' > ' + $out + ' 2>&1"'
  & cmd.exe /c ('start /b cmd /c ' + $inner) | Out-Null
  Start-Sleep -Seconds 5
  $dbg = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue | Where-Object { (One ([string]$_.CommandLine)) -imatch '-d -s' })
  foreach ($d in $dbg) {
    Log ('    killing debug host pid=' + $d.ProcessId)
    try { Stop-Process -Id ([int]$d.ProcessId) -Force -EA SilentlyContinue } catch { }
  }
  Start-Sleep -Seconds 1
  Log ('  ' + $role + ' ' + $svc + ' debug output:')
  if (Test-Path -LiteralPath $out) {
    $c = @(Get-Content -LiteralPath $out -EA SilentlyContinue)
    Log ('    lines=' + @($c).Count + ' bytes=' + (Get-Item -LiteralPath $out).Length)
    foreach ($l in $c) { Log ('    | ' + (One $l)) }
  } else { Log '    (no output file at all)' }
}

Sec 'S2_IS_THE_DLL_ACTUALLY_MAPPED'
Log ('  ' + (SetReg 'wlansvc\Parameters' 'ServiceDllUnloadOnStop' 'REG_DWORD' '0'))
Log ('  before trigger, host map:')
HostScan
TriggerAndWatch 'wlansvc' 1200 'S2'
Log ('  after trigger (ServiceDllUnloadOnStop=0 -> a loaded DLL stays mapped):')
HostScan

Sec 'S3_SHAPE_SWEEP'
$variants = @()
$variants += [pscustomobject]@{ Tag = 'v1_baseline';                        Act = { } }
$variants += [pscustomobject]@{ Tag = 'v2_dot3_privileges';                 Act = { Log ('    ' + (SetReg 'wlansvc' 'RequiredPrivileges' 'REG_MULTI_SZ' 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeAuditPrivilege\0SeTcbPrivilege')) } }
$variants += [pscustomobject]@{ Tag = 'v3_ServiceSidType=0';                Act = { Log ('    ' + (SetReg 'wlansvc' 'ServiceSidType' 'REG_DWORD' '0')) } }
$variants += [pscustomobject]@{ Tag = 'v4_ServiceSidType=2';                Act = { Log ('    ' + (SetReg 'wlansvc' 'ServiceSidType' 'REG_DWORD' '2')) } }
$variants += [pscustomobject]@{ Tag = 'v5_no_required_privileges_value';    Act = { Log ('    ' + (Cmd 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v RequiredPrivileges /f')) } }
$variants += [pscustomobject]@{ Tag = 'v6_Type16_dedicated_host';           Act = {
    Log ('    ' + (SetReg 'wlansvc' 'Type' 'REG_DWORD' '16'))
    Log ('    ' + (SetReg 'wlansvc' 'ImagePath' 'REG_EXPAND_SZ' 'X:\windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s wlansvc'))
  } }
foreach ($v in $variants) {
  Log ('  --- ' + $v.Tag)
  & $v.Act
  TriggerAndWatch 'wlansvc' 1200 $v.Tag
}
Log '  restore baseline shape'
Log ('    ' + (SetReg 'wlansvc' 'Type' 'REG_DWORD' '32'))
Log ('    ' + (SetReg 'wlansvc' 'ImagePath' 'REG_EXPAND_SZ' 'X:\windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p'))
Log ('    ' + (SetReg 'wlansvc' 'RequiredPrivileges' 'REG_MULTI_SZ' 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeAuditPrivilege\0SeTcbPrivilege\0SeDebugPrivilege\0SeLoadDriverPrivilege'))
Log ('    ' + (SetReg 'wlansvc' 'ServiceSidType' 'REG_DWORD' '1'))

Sec 'S4_COHERENT_19041_SET_IN_PRIVATE_DIR'
$files = @('wlansvc.dll', 'wlanapi.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll', 'wlanutil.dll',
           'OneX.dll', 'dot3api.dll', 'dot3cfg.dll', 'dot3msm.dll', 'dot3gpclnt.dll', 'wcmsvc.dll',
           'wdi.dll', 'wintask.dll', 'msvcp140.dll')
New-Item -Path 'X:\w19041' -ItemType Directory -Force -EA SilentlyContinue | Out-Null
foreach ($f in $files) {
  $src = 'C:\Windows\System32\' + $f
  if (Test-Path -LiteralPath $src) {
    Copy-Item -LiteralPath $src -Destination ('X:\w19041\' + $f) -Force -EA SilentlyContinue
    Log ('    staged ' + ('{0,-18}' -f $f) + $(try { (One ([string](Get-Item -LiteralPath ('X:\w19041\' + $f)).VersionInfo.FileVersion)) } catch { '?' }))
  } else { Log ('    C: does not have ' + $f) }
}
Log ('  ' + (SetReg 'wlansvc\Parameters' 'ServiceDll' 'REG_EXPAND_SZ' 'X:\w19041\wlansvc.dll'))
TriggerAndWatch 'wlansvc' 1500 'S4-coherent-dir'
Log '  module map after the coherent-dir attempt:'
HostScan
Log ('  net start wlansvc says: ' + (Cmd 'net start wlansvc'))
Log ('  restore ServiceDll => ' + (SetReg 'wlansvc\Parameters' 'ServiceDll' 'REG_EXPAND_SZ' '%SystemRoot%\System32\wlansvc.dll'))

Sec 'S5_WCMSVC_CONTROL'
foreach ($dll in @('%SystemRoot%\System32\wcmsvc.dll', 'X:\w19041\wcmsvc.dll')) {
  Log ('  --- wcmsvc with ServiceDll=' + $dll)
  Log ('    ' + (SetReg 'wcmsvc\Parameters' 'ServiceDll' 'REG_EXPAND_SZ' $dll))
  Log ('    ' + (SetReg 'wcmsvc\Parameters' 'ServiceMain' 'REG_SZ' 'WcmSvcMain'))
  Log ('    ' + (SetReg 'wcmsvc' 'Type' 'REG_DWORD' '32'))
  Log ('    ' + (SetReg 'wcmsvc' 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'))
  TriggerAndWatch 'wcmsvc' 1500 'S5'
}

Sec 'S6_FINAL'
Log ('  final wlansvc : ' + (SvcState 'wlansvc'))
Log ('  final wcmsvc  : ' + (SvcState 'wcmsvc'))
Log ('  final dot3svc : ' + (SvcState 'dot3svc'))
Log ('  ImagePath     : ' + (One ([string](Get-Item -LiteralPath ($SVC + '\wlansvc')).GetValue('ImagePath', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))))
Log ('  ServiceDll    : ' + (One ([string](Get-Item -LiteralPath ($SVC + '\wlansvc\Parameters')).GetValue('ServiceDll', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))))
Log ('  leftovers: X:\svcout_*.txt X:\w19041 X:\race19.ps1 (die at reboot)')
Log 'PROBE20_DONE'
