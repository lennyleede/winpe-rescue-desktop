# probe21: the 2x2 that probes 7-20 never ran.
#
# probe20 (build/scratch/pw20_raw.txt) established:
#   * StartService is ACCEPTED, then state 2(START_PENDING) -> 3(STOP_PENDING) -> 1(STOPPED) inside
#     ~140 ms, with dwServiceSpecificExitCode pinned at 0x800C0006 in EVERY variant (baseline,
#     dot3svc's privileges, ServiceSidType 0/1/2, coherent 19041 set in a private dir).
#     wcmsvc's fingerprint differs (0x42C=1068), so 0x800C0006 is wlansvc-specific, not noise.
#   * deleting RequiredPrivileges changes the answer to err=13 -> the SCM really does re-read the key.
#   * with ServiceDllUnloadOnStop=0 the host's module list (56 mods, psapi walk works: it sees
#     dot3svc.dll/dot3msm/dot3gpclnt/OneX in pid 1328) never shows wlansvc.dll.
#   * svchost -d -s produced zero console output for BOTH wlansvc and working dot3svc, so that
#     instrument is dead in this PE and was dropped.
# probe7's "byte-for-byte dot3svc clone under the name wlansvc also failed" is NOT clean evidence
# any more: that clone carried dot3svc's Parameters\ServiceMain=Dot3SvcMain, so the entry point was
# wrong for whatever DLL it pointed at. The name and the DLL were never varied independently.
#
# This probe runs the matrix (name x dll x ServiceMain), all on boot-cached names, restoring after:
#   A  wlansvc + wlansvc.dll + WlanSvcMain   (known: aborts at ~140ms)
#   B  wlansvc + dot3svc.dll + Dot3SvcMain   (good DLL under the suspect name)
#   C  dot3svc + wlansvc.dll + WlanSvcMain   (suspect DLL under a proven-good name)
#   D  dot3svc + dot3svc.dll + Dot3SvcMain   (home control, must reach RUNNING)
#   B runs & C aborts -> wlansvc.dll cannot initialise on this OS (version/dependency).
#   B aborts & C runs -> the boot-cached record for the NAME wlansvc is the poison.
#   both run          -> only the wlansvc+wlansvc.dll combination fails; look for a specific import.
# Plus a 5 ms-granularity race that catches whether wlansvc.dll is mapped at all, and a direct
# LoadLibraryExW with svchost's search flags on both DLLs, printing the loader's error code.
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
# reg add needs quotes whenever the data has spaces -- probe20 lost two ImagePath writes to that.
function SetReg([string]$sub, [string]$name, [string]$type, [string]$data) {
  $d = $data
  if ($d -imatch '[\s\\]') { $d = '"' + $d + '"' }
  $r = Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\' + $sub + '" /v ' + $name + ' /t ' + $type + ' /d ' + $d + ' /f')
  return ($sub + '\' + $name + ' <- ' + $data + ' : ' + $r)
}
function GetReg([string]$sub, [string]$name) {
  $i = Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $sub) -EA SilentlyContinue
  if (-not $i) { return 'KEY-ABSENT' }
  $v = $i.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($v -is [array]) { return (One ($v -join '|')) }
  return (One ([string]$v))
}
function ReadKey([string]$sub) {
  $p = GetReg ($sub + '\Parameters') 'ServiceDll'
  $m = GetReg ($sub + '\Parameters') 'ServiceMain'
  $i = GetReg $sub 'ImagePath'
  $t = GetReg $sub 'Type'
  return ('ServiceDll=[' + $p + '] ServiceMain=[' + $m + '] Type=' + $t + ' ImagePath=[' + $i + ']')
}
function Configure([string]$svc, [string]$dll, [string]$main) {
  Log ('    configure ' + $svc + ' -> dll=' + $dll + ' main=' + $main)
  Log ('      ' + (SetReg ($svc + '\Parameters') 'ServiceDll' 'REG_EXPAND_SZ' $dll))
  Log ('      ' + (SetReg ($svc + '\Parameters') 'ServiceMain' 'REG_SZ' $main))
  Log ('      ' + (SetReg ($svc + '\Parameters') 'ServiceDllUnloadOnStop' 'REG_DWORD' '0'))
  Log ('      ' + (SetReg $svc 'Type' 'REG_DWORD' '32'))
  Log ('      ' + (SetReg $svc 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'))
}
$PS   = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$SVCD = 'X:\windows\System32\svchost.exe'
$DL   = 'X:\windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p'

Sec 'S0_PREP_AND_BACKUP'
try {
  $src21 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class SC21 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool ControlService(IntPtr svc, uint ctl, byte[] st);
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
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr LoadLibraryExW(string p, IntPtr hfile, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  [DllImport("ntdll.dll")] public static extern uint RtlAdjustPrivilege(int p, bool en, bool th, out bool prev);
  public static string EnableDebug() {
    bool prev = false;
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
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u | 0x0020u);
    if (h == IntPtr.Zero) return "OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    if (!QueryServiceStatus(h, st)) { CloseHandle(h); return "QUERY-err=" + Marshal.GetLastWin32Error(); }
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
  public static string Stop(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0004u | 0x0020u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    bool ok = ControlService(h, 1u, st);
    int e = Marshal.GetLastWin32Error();
    CloseHandle(h);
    return name + " ControlService(STOP) => " + (ok ? "sent" : ("err=" + e + " [" + Msg((uint)e) + "]"));
  }
  public static string Wlan(int pid) {
    IntPtr h = OpenProcess(0x0410u, false, pid);
    if (h == IntPtr.Zero) h = OpenProcess(0x1000u, false, pid);
    if (h == IntPtr.Zero) return "pid" + pid + " open-err=" + Marshal.GetLastWin32Error();
    IntPtr[] mods = new IntPtr[2048];
    uint need = 0;
    if (!EnumProcessModules(h, mods, (uint)(mods.Length * IntPtr.Size), out need)) {
      CloseHandle(h); return "pid" + pid + " enum-err=" + Marshal.GetLastWin32Error();
    }
    int cnt = (int)(need / (uint)IntPtr.Size);
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < cnt; i++) {
      StringBuilder nm = new StringBuilder(300);
      if (GetModuleBaseNameW(h, mods[i], nm, (uint)nm.Capacity) == 0) continue;
      string s = nm.ToString();
      if (s.IndexOf("wlan", StringComparison.OrdinalIgnoreCase) >= 0 ||
          s.IndexOf("dot3", StringComparison.OrdinalIgnoreCase) >= 0 ||
          s.IndexOf("onex", StringComparison.OrdinalIgnoreCase) >= 0) {
        if (sb.Length > 0) sb.Append(',');
        sb.Append(s);
      }
    }
    CloseHandle(h);
    return "pid" + pid + "(" + cnt + ")[" + sb.ToString() + "]";
  }
  public static string Load(string path, string main, uint flags) {
    IntPtr h = LoadLibraryExW(path, IntPtr.Zero, flags);
    int e = Marshal.GetLastWin32Error();
    if (h == IntPtr.Zero) return "flags=0x" + flags.ToString("X") + " LOAD-FAIL err=" + e + " [" + Msg((uint)e) + "]";
    IntPtr m = GetProcAddress(h, main);
    int e2 = Marshal.GetLastWin32Error();
    string r = "flags=0x" + flags.ToString("X") + " loaded, " + main + " => " +
               (m != IntPtr.Zero ? "FOUND" : ("MISSING err=" + e2 + " [" + Msg((uint)e2) + "]"));
    if (!FreeLibrary(h)) r += " (FreeLibrary err=" + Marshal.GetLastWin32Error() + ")";
    return r;
  }
}
"@
  Add-Type -TypeDefinition $src21
  $global:OK21 = $true
  Log '  Add-Type SC21 ok'
  Log ('  ' + [SC21]::EnableDebug())
} catch {
  $global:OK21 = $false
  Log ('  Add-Type SC21 FAILED: ' + (One ([string]$_)))
}
Log ('  BEFORE wlansvc : ' + (ReadKey 'wlansvc'))
Log ('  BEFORE dot3svc : ' + (ReadKey 'dot3svc'))
$grp = (Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST' -EA SilentlyContinue)
if ($grp) { Log ('  group members = ' + (One ($grp.GetValue('LocalSystemNetworkRestricted', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -join '|'))) }

function TriggerAndWatch([string]$svc, [int]$ms, [string]$tag) {
  if (-not $global:OK21) { Log ('    ' + $tag + ' : SC21 unavailable'); return }
  Log ('    ' + $tag + ' ' + [SC21]::Start($svc))
  $t0 = Get-Date
  $last = ''
  $seq = ''
  for ($i = 0; $i -lt 45; $i++) {
    $s = [SC21]::Status($svc)
    $st = ''
    if ($s -imatch 'state=(\d+)') { $st = $matches[1] }
    if ($st -ne $last) { $seq += (' ' + $st + '@' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms'); $last = $st }
    if ($st -eq '1' -and $i -gt 2) { break }
    if ($st -eq '4' -and $i -gt 2) { $seq += ' (RUNNING)'; break }
    Start-Sleep -Milliseconds ([Math]::Max(20, [int]($ms / 45)))
  }
  Log ('      state sequence:' + $seq + '  final ' + [SC21]::Status($svc))
  Log ('      ' + (SvcState $svc))
}
function HostScan([string]$label) {
  if (-not $global:OK21) { return }
  Log ('    ' + $label)
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    $r = [SC21]::Wlan([int]$q.ProcessId)
    if ($r -imatch 'err=') {
      try {
        $ms = @(Get-Process -Id ([int]$q.ProcessId) -Module -EA SilentlyContinue | Where-Object { (One $_.ModuleName) -imatch 'wlan|dot3|onex' } | ForEach-Object { $_.ModuleName })
        if (@($ms).Count -gt 0) { $r = 'pid' + $q.ProcessId + ' via-Get-Process[' + ($ms -join ',') + ']' }
      } catch { }
    }
    if ($r -imatch '\[(.+)\]$' -and $matches[1].Length -gt 0) {
      Log ('      ' + $r + '  k=' + (One ([string]$q.CommandLine)))
    }
  }
}

Sec 'S1_MATRIX_CASE_A_wlansvc_own_dll'
Configure 'wlansvc' '%SystemRoot%\System32\wlansvc.dll' 'WlanSvcMain'
TriggerAndWatch 'wlansvc' 1500 'A'
HostScan '      modules after A:'

Sec 'S2_MATRIX_CASE_B_wlansvc_name_dot3_dll'
Configure 'wlansvc' '%SystemRoot%\System32\dot3svc.dll' 'Dot3SvcMain'
TriggerAndWatch 'wlansvc' 1500 'B'
HostScan '      modules after B:'
Log ('      net start wlansvc says: ' + (Cmd 'net start wlansvc'))

Sec 'S3_MATRIX_CASE_C_dot3_name_wlan_dll'
if ($global:OK21) { Log ('    make sure the wlansvc slot is idle: ' + [SC21]::Stop('wlansvc')) }
Log ('    stop the real dot3svc first: ' + (Cmd 'net stop dot3svc'))
Configure 'dot3svc' '%SystemRoot%\System32\wlansvc.dll' 'WlanSvcMain'
TriggerAndWatch 'dot3svc' 1500 'C'
HostScan '      modules after C:'

Sec 'S4_MATRIX_CASE_D_restore_home'
Configure 'dot3svc' '%SystemRoot%\System32\dot3svc.dll' 'Dot3SvcMain'
if ($global:OK21) { Log ('    idle: ' + [SC21]::Stop('dot3svc')) }
# Configure() leaves DependOnService=RpcSs, strictly easier than the image default
# (RpcSs|Ndisuio|Eaphost), so case D stays a valid positive control.
TriggerAndWatch 'dot3svc' 1500 'D-control'
Configure 'wlansvc' '%SystemRoot%\System32\wlansvc.dll' 'WlanSvcMain'
if ($global:OK21) { Log ('    idle wlansvc again: ' + [SC21]::Stop('wlansvc')) }
Configure 'wlansvc' '%SystemRoot%\System32\wlansvc.dll' 'WlanSvcMain'

Sec 'S4B_SVCHOST_DEBUG_HOST_FIXED_QUOTING'
# probe20 got no output because `start /b cmd /c "..."` eats the first quoted string as a WINDOW
# TITLE, so svchost never ran. With an explicit empty title the debug host really executes and its
# loader diagnostics land in the file.
foreach ($svc in @('wlansvc', 'dot3svc')) {
  $out = 'X:\svcout21_' + $svc + '.txt'
  Remove-Item -LiteralPath $out -Force -EA SilentlyContinue
  $cl = 'start /b "" cmd /c "' + $SVCD + ' -k LocalSystemNetworkRestricted -d -s ' + $svc + ' > ' + $out + ' 2>&1"'
  Log ('  ' + (Cmd $cl))
  Start-Sleep -Seconds 4
  foreach ($d in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue | Where-Object { (One ([string]$_.CommandLine)) -imatch '-d -s' })) {
    Log ('    killing debug host pid=' + $d.ProcessId)
    try { Stop-Process -Id ([int]$d.ProcessId) -Force -EA SilentlyContinue } catch { }
  }
  Start-Sleep -Seconds 1
  if (Test-Path -LiteralPath $out) {
    $c = @(Get-Content -LiteralPath $out -EA SilentlyContinue)
    Log ('  ' + $svc + ' debug output: lines=' + @($c).Count + ' bytes=' + (Get-Item -LiteralPath $out).Length)
    foreach ($l in $c) { Log ('    | ' + (One $l)) }
  } else {
    Log ('  ' + $svc + ': no output file (exit code written nowhere)')
    Log ('    file list: ' + (Cmd ('dir /b X:\svcout21_*')))
  }
}

Sec 'S5_FAST_RACE_IS_WLANSVC_DLL_EVER_MAPPED'
# the race runs inline: psapi is fast enough to sample the ~35 ms START_PENDING window
if ($global:OK21) {
  $hostPid = 0
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    if ((One ([string]$q.CommandLine)) -imatch 'LocalSystemNetworkRestricted') { $hostPid = [int]$q.ProcessId; break }
  }
  Log ('  LocalSystemNetworkRestricted host pid = ' + $hostPid)
  Log '  trigger + poll state and host modules at maximum speed'
  $t0 = Get-Date
  $seenWlan = 'never'
  $lastState = ''
  for ($i = 0; $i -lt 4000; $i++) {
    $st = [SC21]::Status('wlansvc')
    $cur = ''
    if ($st -imatch 'state=(\d+)') { $cur = $matches[1] }
    $mm = [SC21]::Wlan($hostPid)
    if ($mm -imatch 'wlansvc') { $seenWlan = 'YES at i=' + $i + ' t+' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms' }
    if ($cur -ne $lastState) {
      Log ('    i=' + $i + ' t+' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms state=' + $cur + ' host=' + $mm)
      $lastState = $cur
    }
    if ($cur -eq '1' -and $i -gt 5) { break }
  }
  Log ('  iterations=' + $i + '  wlansvc.dll mapped in the host at any point: ' + $seenWlan)
}

Sec 'S6_LOADER_TEST_BOTH_DLLS'
if ($global:OK21) {
  foreach ($pair in @(@('X:\Windows\System32\wlansvc.dll', 'WlanSvcMain'), @('X:\Windows\System32\dot3svc.dll', 'Dot3SvcMain'), @('X:\w19041\wlansvc.dll', 'WlanSvcMain'))) {
    Log ('  ' + $pair[0] + ' main=' + $pair[1])
    foreach ($fl in @([uint32]0, [uint32]0x8, [uint32]0x1008, [uint32]0x2008)) {
      Log ('    ' + [SC21]::Load($pair[0], $pair[1], $fl))
    }
  }
  Log ('  flags: 0x0=default search, 0x8=as-datafile(section only), 0x1008=ignore unknown, 0x2008=not-lockdir')
}

Sec 'S7_SIBLINGS_IN_SYSTEM32_SUBDIR'
New-Item -Path 'X:\Windows\System32\w21' -ItemType Directory -Force -EA SilentlyContinue | Out-Null
foreach ($f in @('wlansvc.dll', 'wlanapi.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll', 'wlanutil.dll', 'OneX.dll', 'wcmsvc.dll')) {
  if (Test-Path -LiteralPath ('X:\w19041\' + $f)) {
    Copy-Item -LiteralPath ('X:\w19041\' + $f) -Destination ('X:\Windows\System32\w21\' + $f) -Force -EA SilentlyContinue
  }
}
Log ('  staged X:\Windows\System32\w21 = ' + ((@(Get-ChildItem -LiteralPath 'X:\Windows\System32\w21' -File -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ', '))
Log ('  ACL of w21 : ' + (One ((Get-Acl -LiteralPath 'X:\Windows\System32\w21' -EA SilentlyContinue).AccessToString -replace "`r`n", ' / ')))
Log ('  ACL of S32 : ' + (One ((Get-Acl -LiteralPath 'X:\Windows\System32' -EA SilentlyContinue).AccessToString -replace "`r`n", ' / ')))
Configure 'wlansvc' 'X:\Windows\System32\w21\wlansvc.dll' 'WlanSvcMain'
TriggerAndWatch 'wlansvc' 1500 'S7-coherent-in-system32-subdir'
HostScan '      modules after S7:'
Configure 'wlansvc' '%SystemRoot%\System32\wlansvc.dll' 'WlanSvcMain'

Sec 'S8_FINAL'
Log ('  final wlansvc : ' + (ReadKey 'wlansvc'))
Log ('  final dot3svc : ' + (ReadKey 'dot3svc'))
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  state ' + $n + ' = ' + (SvcState $n)) }
Log ('  leftovers: X:\w19041, X:\Windows\System32\w21, X:\race19.ps1, X:\svcout_*.txt (die at reboot)')
Log 'PROBE21_DONE'
