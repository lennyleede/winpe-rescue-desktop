# ============================================================
# probe111_env_ladder.ps1 -- the file layer is closed, so test the ENVIRONMENT layer wlansvc reads at init
# ============================================================
#   probe110 result (2026-10-12, live 12th-gen machine): all 82 modules a healthy host wlansvc loads now
#   exist in this image (S6 NEW-FILE-GAP=0), all 15 borrowed files LoadLibrary OK, wcmsvc goes RUNNING,
#   and wlansvc STILL exits on its own: 0x800C0006 at ~125 ms, 36 modules, last one wmiclnt.dll.
#   So the remaining cause is not files. 0x800C0006 is WLAN facility code 6 -- "the system cannot find the
#   specified object" -- which points at a lookup that comes back empty, and wlansvc's own strings name the
#   lookups it performs (build\scratch\p111_host_strings.txt: 49 registry paths + \\.\NativeWiFiP,
#   \\.\vwififlt, \\.\NDIS, WMICLNT.dll, Microsoft-Windows-WLAN-AutoConfig, GroupPolicy, Microsoft\Wlansvc).
#   The healthy host's answers to the same list are recorded in build\scratch\p111_host_env.txt; this probe
#   reads the live PE against that reference, then works a ladder of cheap, additive rungs:
#     S0 service census (read only)          S3 registry census vs the host reference
#     S1 device-object opens (read only)     S4 WMI presence (Winmgmt/wmisvc.dll/Repository)
#     S2 adapter inventory, ifType 71        S5 ETW publisher/channel presence
#     R1 create what the host has and we lack (Wlansvc tree + PowerProfiles values, NetworkList
#        DefaultMediaCost, Winlogon Notifications, ProgramData\Microsoft\Wlansvc\Profiles) -> trace
#     R2 wcmsvc Running + Winmgmt started     -> trace
#   Every rung is followed by a wlansvc trace, so a single run yields a per-rung verdict. Writes go to the
#   RAM disk / in-memory registry of a live PE only -- the disc is not touched. Output: ASCII lines, P111.
param([switch]$DryRun, [string]$Root = 'X:\Windows\System32')
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P111 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }
$s32 = $Root

$svcs = @('wlansvc','wcmsvc','nativewifip','vwififlt','vwifibus','Ndisuio','RpcSs','nsiproxy','BFE','mpssvc',
          'Dhcp','LanmanServer','Winmgmt','EapHost','dot3svc','netprofm','WdiServiceHost','wdisystemhost')
$devs = @('\\.\NativeWiFiP','\\.\vwififlt','\\.\NDIS','\\.\WMIGUID','\\.\vwifibus','\\.\PktMonApi')
# Keys a healthy host has (build\scratch\p111_host_env.txt) -- existence is the question here.
$keyWant = @(
 'SOFTWARE\Microsoft\Cryptography',
 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost',
 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\WiFiDirectAPI',
 'SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Settings\Network',
 'SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE',
 'SOFTWARE\Microsoft\Wlansvc',
 'SOFTWARE\Microsoft\Wlansvc\PowerProfiles',
 'SOFTWARE\Microsoft\Wlansvc\PowerProfiles\ClassAC',
 'SOFTWARE\Microsoft\Wlansvc\PowerProfiles\ClassB',
 'SOFTWARE\Microsoft\Wlansvc\PowerProfiles\ClassG',
 'SOFTWARE\Microsoft\Wlansvc\PowerProfiles\ClassN',
 'SOFTWARE\Microsoft\Wlansvc\Interfaces',
 'SOFTWARE\Microsoft\Wlansvc\Parameters',
 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{9580d7dd-0379-4658-9870-d5be7d52d6de}',
 'SYSTEM\CurrentControlSet\Control\Winlogon\Notifications\Components\Wlansvc',
 'SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\ComInterfaceProviders',
 'SYSTEM\CurrentControlSet\Services\WlanSvc\Parameters\VendorSpecificIEProviders',
 'SYSTEM\CurrentControlSet\Services\WlanSvc\VirtualizationManager',
 'SYSTEM\CurrentControlSet\Services\Wlansvc\Parameters\OneXAuthenticator',
 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-AutoConfig/Operational')
# Host values, copied VERBATIM from build\scratch\p111_host_values.txt / t_p111_pub.ps1 output -- invented
# numbers would test the wrong thing (the first draft had DefaultMediaCost=49/53 and a binary Events value;
# the host has DWord 1/2 and Events as the STRING 'Logoff').
$ppVals = @{ PowerIdle = 15; PowerTail = 280; PowerTxRx = 400; TailDuration = 300 }
$costVals = @{ '3G' = 2; '4G' = 2; 'Default' = 1; 'Ethernet' = 1; 'WiFi' = 1 }
$wlanSvcSubs = @('AnqpCache','Interfaces','Parameters','PowerProfiles','ProfileSync')
$paths = @('X:\ProgramData\Microsoft\Wlansvc', 'X:\ProgramData\Microsoft\Wlansvc\Profiles',
           'X:\ProgramData\Microsoft\Wlansvc\GlobalMachine', ($s32 + '\GroupPolicy'),
           ($s32 + '\GroupPolicy\Machine'), ($s32 + '\wbem\wmisvc.dll'), ($s32 + '\wbem\Repository'),
           ($s32 + '\wbem\WmiApRpl.dll'), ($s32 + '\wmiclnt.dll'), ($s32 + '\WlanEvtProv.dll'),
           ($s32 + '\wlansvc.dll'), ($s32 + '\wlanapi.dll'))

$src = @'
using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32;

public static class Pe111 {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr sc, string name, uint a);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool StartServiceW(IntPtr sv, uint n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool QueryServiceStatusEx(IntPtr sv, int lvl, IntPtr buf, uint size, out uint need);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool ControlService(IntPtr sv, uint ctrl, IntPtr status);
  [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern uint GetCurrentDirectory(uint bufLen, StringBuilder buf);
  [DllImport("psapi.dll", SetLastError = true)]
  static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, uint cb, out uint need, uint filter);
  [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder buf, uint size);

  const uint SC_MANAGER_CONNECT = 0x0001, SC_MANAGER_ALL_ACCESS = 0xF003F;
  const uint SERVICE_START = 0x0010, SERVICE_STOP = 0x0020, SERVICE_QUERY_STATUS = 0x0004;
  const uint PROCESS_QUERY_INFORMATION = 0x0400, PROCESS_VM_READ = 0x0010;
  const uint GENERIC_READ = 0x80000000, OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;

  static IntPtr Open(string name, uint access) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) return IntPtr.Zero;
    try { return OpenServiceW(sm, name, access); } finally { CloseServiceHandle(sm); }
  }
  static string StateName(int st) {
    return st == 1 ? "STOPPED" : st == 2 ? "START_PENDING" : st == 3 ? "STOP_PENDING" :
           st == 4 ? "RUNNING" : st == 5 ? "STOP_PENDING" : st == 6 ? "PAUSED" : ("state" + st);
  }
  // SERVICE_STATUS_PROCESS is 36 bytes here (probe99): state@4, win32exit@12, pid@28.
  public static string Status(string name) {
    IntPtr sv = Open(name, SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      IntPtr buf = Marshal.AllocHGlobal(36);
      try {
        uint need = 0;
        if (!QueryServiceStatusEx(sv, 0, buf, 36, out need)) return "QSS_ERR=" + Marshal.GetLastWin32Error();
        return StateName(Marshal.ReadInt32(buf, 4)) + " win32=" + Marshal.ReadInt32(buf, 12) +
               " pid=" + Marshal.ReadInt32(buf, 28);
      } finally { Marshal.FreeHGlobal(buf); }
    } finally { CloseServiceHandle(sv); }
  }
  // Start a service and wait for RUNNING; returns the final Status() string plus how long it took.
  public static string StartAndWait(string name, int ms) {
    IntPtr sv = Open(name, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) return "OPEN_ERR=" + Marshal.GetLastWin32Error();
    try {
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      int err = started ? 0 : Marshal.GetLastWin32Error();
      Stopwatch sw = Stopwatch.StartNew();
      int state = 0; uint need = 0;
      while (sw.ElapsedMilliseconds < ms) {
        IntPtr buf = Marshal.AllocHGlobal(36);
        if (QueryServiceStatusEx(sv, 0, buf, 36, out need)) state = Marshal.ReadInt32(buf, 4);
        Marshal.FreeHGlobal(buf);
        if (state == 4) break;
        if (state == 1 && !started && err != 0) break;
        if (state == 1 && sw.ElapsedMilliseconds > 300) break;
        Thread.Sleep(20);
      }
      IntPtr fb = Marshal.AllocHGlobal(36);
      string fin = "QSS_ERR";
      if (QueryServiceStatusEx(sv, 0, fb, 36, out need)) {
        fin = StateName(Marshal.ReadInt32(fb, 4)) + " win32=" + Marshal.ReadInt32(fb, 12) +
              " pid=" + Marshal.ReadInt32(fb, 28);
      }
      Marshal.FreeHGlobal(fb);
      return "start=" + (started ? "OK" : ("ERR=" + err)) + " " + fin + " waited=" + sw.ElapsedMilliseconds + "ms";
    } finally { CloseServiceHandle(sv); }
  }
  // Does the kernel-mode device object a user-mode component opens actually exist?
  // CreateFile on \\.\X is the only way to ask without the driver's own API.
  public static string DevOpen(string path) {
    IntPtr h = CreateFileW(path, GENERIC_READ, 3, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
    if (h == IntPtr.Zero) return "FAIL err=" + Marshal.GetLastWin32Error();
    CloseHandle(h);
    return "OPEN_OK";
  }
  static string[] ModulesOf(int pid, ref IntPtr cachedH, ref int cachedPid) {
    if (pid <= 0) return new string[0];
    if (cachedH == IntPtr.Zero || cachedPid != pid) {
      if (cachedH != IntPtr.Zero) CloseHandle(cachedH);
      cachedH = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)pid);
      cachedPid = pid;
      if (cachedH == IntPtr.Zero) return new string[0];
    }
    IntPtr[] buf = new IntPtr[2048];
    uint needed = 0;
    if (!EnumProcessModulesEx(cachedH, buf, (uint)(buf.Length * IntPtr.Size), out needed, 0x03))
      return new string[0];
    int count = (int)(needed / (uint)IntPtr.Size);
    if (count > buf.Length) count = buf.Length;
    List<string> names = new List<string>(count);
    StringBuilder sb = new StringBuilder(1024);
    for (int i = 0; i < count; i++) {
      sb.Length = 0;
      uint n = GetModuleFileNameExW(cachedH, buf[i], sb, (uint)sb.Capacity);
      if (n == 0) continue;
      string p = sb.ToString();
      int k = p.LastIndexOf('\\');
      names.Add((k >= 0 ? p.Substring(k + 1) : p).ToLowerInvariant());
    }
    return names.ToArray();
  }
  // The probe110 instrument, trimmed to what a rung comparison needs (count + tail).
  public static string[] Trace(string svc, int ms) {
    List<string> lines = new List<string>();
    IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (scm == IntPtr.Zero) { lines.Add("SCM_ERR=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    IntPtr sv = OpenServiceW(scm, svc, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (sv == IntPtr.Zero) { CloseServiceHandle(scm); lines.Add("OPEN_ERR=" + Marshal.GetLastWin32Error()); return lines.ToArray(); }
    try {
      IntPtr st = Marshal.AllocHGlobal(36);
      try { ControlService(sv, 1, st); } catch { }
      Marshal.FreeHGlobal(st);
      bool started = StartServiceW(sv, 0, IntPtr.Zero);
      string sr = started ? "START_OK" : ("START_ERR=" + Marshal.GetLastWin32Error());
      Stopwatch sw = Stopwatch.StartNew();
      List<string> order = new List<string>();
      HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
      IntPtr hCache = IntPtr.Zero; int hPid = 0;
      string lastState = "";
      while (sw.ElapsedMilliseconds < ms) {
        uint need = 0;
        IntPtr buf = Marshal.AllocHGlobal(36);
        int state = 0, win32 = 0; uint pid = 0;
        bool ok = QueryServiceStatusEx(sv, 0, buf, 36, out need);
        if (ok) { state = Marshal.ReadInt32(buf, 4); win32 = Marshal.ReadInt32(buf, 12); pid = (uint)Marshal.ReadInt32(buf, 28); }
        Marshal.FreeHGlobal(buf);
        if (!ok) { lines.Add("t+" + sw.ElapsedMilliseconds + "ms QSS_ERR=" + Marshal.GetLastWin32Error()); break; }
        string sn = StateName(state);
        if (sn != lastState) { lastState = sn; lines.Add("t+" + sw.ElapsedMilliseconds + "ms " + sn + " pid=" + pid); }
        if (pid > 0) {
          foreach (string m in ModulesOf((int)pid, ref hCache, ref hPid))
            if (!seen.Contains(m)) { seen.Add(m); order.Add(m); }
        }
        if (state == 4) break;
        if (state == 1 && sw.ElapsedMilliseconds > 60) break;
        Thread.Sleep(1);
      }
      if (hCache != IntPtr.Zero) CloseHandle(hCache);
      uint need2 = 0;
      IntPtr fb = Marshal.AllocHGlobal(36);
      string fin = "FINAL";
      if (QueryServiceStatusEx(sv, 0, fb, 36, out need2)) {
        int fstate = Marshal.ReadInt32(fb, 4);
        int fwin32 = Marshal.ReadInt32(fb, 12);
        fin = "FINAL state=" + fstate + " win32hex=0x" + ((uint)fwin32).ToString("X8") +
              " pid=" + Marshal.ReadInt32(fb, 28);
      } else { fin = "FINAL QSS_ERR=" + Marshal.GetLastWin32Error(); }
      Marshal.FreeHGlobal(fb);
      lines.Add("START=" + sr);
      lines.Add(fin + " loaded=" + seen.Count + " t=" + sw.ElapsedMilliseconds + "ms");
      int n = order.Count;
      int from = n > 6 ? n - 6 : 0;
      for (int i = from; i < n; i++) lines.Add("TAIL " + order[i]);
      return lines.ToArray();
    } finally { CloseServiceHandle(sv); CloseServiceHandle(scm); }
  }
  // ETW publisher lookup by provider NAME (the keys are GUIDs, so a name scan is the only way).
  public static string EtwFind(string needle) {
    StringBuilder sb = new StringBuilder(512);
    using (RegistryKey root = Registry.LocalMachine.OpenSubKey(
             @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers")) {
      if (root == null) return "NO-PUBLISHERS-KEY";
      string[] names = root.GetSubKeyNames();
      int hits = 0;
      foreach (string g in names) {
        using (RegistryKey k = root.OpenSubKey(g)) {
          if (k == null) continue;
          object v = k.GetValue("Name");
          if (v == null) continue;
          string nm = "" + v;
          if (nm.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
            hits++;
            sb.Append(' ').Append(g).Append('=').Append(nm);
          }
        }
      }
      return "count=" + names.Length + " hits=" + hits + (hits > 0 ? "|" + sb.ToString().Trim() : "");
    }
  }
  public static string Ping() { return "Pe111 ping ok cwd=" + EnvCwd(); }
  static string EnvCwd() {
    StringBuilder sb = new StringBuilder(260);
    GetCurrentDirectory((uint)sb.Capacity, sb);
    return sb.ToString();
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE FAILED ' + (C $_.Exception.Message)) }
L('probe111 begin native=' + $native + ' dryrun=' + $DryRun + ' root=[' + (C $s32) + ']')

function Tr([string]$svc, [string]$tag) {
  if (-not $native) { L('TRACE ' + $svc + ' skipped: native class unavailable'); return }
  $lines = @()
  try { $lines = @([Pe111]::Trace($svc, 3000)) } catch { $lines = @('EXCEPTION ' + (C $_.Exception.Message)) }
  $sr = ''; $fin = ''
  foreach ($l in @($lines)) { if ((C "$l") -match '^START=') { $sr = (C "$l") } }
  foreach ($l in @($lines)) { if ((C "$l") -match '^FINAL ') { $fin = (C "$l") } }
  $tail = @(@($lines) | Where-Object { (C "$_") -match '^TAIL ' } | ForEach-Object { (C "$_") -replace '^TAIL ','' })
  L('TRACE ' + $svc + ' [' + $tag + '] ' + $sr + ' | ' + $fin + ' | tail=' + (@($tail) -join ','))
}

if ($DryRun) {
  L('DRY sections that would run read-only: ' + 'S0 services x' + $svcs.Count + ' S1 devices x' + $devs.Count +
    ' S2 adapters S3 keys x' + $keyWant.Count + ' S4/S5 wmi+etw')
  L('DRY R1 would create (and ONLY create, never overwrite): keys Software\Microsoft\Wlansvc\PowerProfiles\Class*' +
    ' + NetworkList\DefaultMediaCost + Winlogon Notifications Components\Wlansvc + dirs ProgramData\Microsoft\Wlansvc\*')
  L('DRY R2 would start Winmgmt (if its key exists) and wcmsvc, then trace wlansvc -- a trace stops/starts a ' +
    'service, so -DryRun never does it')
  L('probe111 end (DryRun)'); exit 0
}

# ---------- S0 service census ----------
foreach ($n in @($svcs)) {
  $k = Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue
  $st = if ($native) { [Pe111]::Status($n) } else { 'n/a' }
  L('S0 SVC ' + $n + ' key=' + $(if ($null -eq $k) { 'no' } else { 'yes' }) + ' start=' +
    $(if ($null -eq $k) { '-' } else { '' + $k.GetValue('Start') }) + ' type=' +
    $(if ($null -eq $k) { '-' } else { '' + $k.GetValue('Type') }) + ' | ' + $st)
}

# ---------- S1 device objects ----------
if ($native) { foreach ($d in @($devs)) { L('S1 DEV ' + $d + ' -> ' + [Pe111]::DevOpen($d)) } }
# ---------- S2 adapters (ifType 71 = IEEE 802.11) ----------
$ad = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces())
foreach ($a in @($ad)) {
  L('S2 ADAPTER ' + (C $a.Name) + ' iftype=' + $a.NetworkInterfaceType + ' up=' + $a.OperationalStatus +
    ' desc=' + (C $a.Description))
}
L('S2 wifi-adapters=' + (@($ad | Where-Object { [int]$_.NetworkInterfaceType -eq 71 }).Count) + '/' + @($ad).Count)
# ---------- S3 registry census ----------
$missK = @()
foreach ($k in @($keyWant)) {
  $p = 'Registry::HKEY_LOCAL_MACHINE\' + $k
  $e = Test-Path -LiteralPath $p
  if (-not $e) { $missK += $k }
  L('S3 KEY ' + $(if ($e) { 'YES' } else { 'NO ' }) + ' ' + $k)
}
L('S3 missing-of-reference=' + @($missK).Count + '/' + @($keyWant).Count)
# ---------- S4 WMI layer / S5 files ----------
foreach ($p in @($paths)) { L('S5 PATH ' + (C $p) + ' exists=' + (Test-Path -LiteralPath $p)) }
if ($native) {
  L('S5 ETW publishers: ' + [Pe111]::EtwFind('WLAN'))
  L('S5 ETW wlansvc-side: ' + [Pe111]::EtwFind('NativeWIFI'))
}
# ---------- R1: create what the host has and we lack ----------
$made = @()
foreach ($c in @('ClassAC','ClassB','ClassG','ClassN','ClassAX','ClassAD')) {
  $p = 'HKLM:\SOFTWARE\Microsoft\Wlansvc\PowerProfiles\' + $c
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -LiteralPath $p -Force -EA SilentlyContinue | Out-Null
    foreach ($vk in $ppVals.Keys) { New-ItemProperty -LiteralPath $p -Name $vk -Value $ppVals[$vk] -PropertyType DWord -Force -EA SilentlyContinue | Out-Null }
    $made += $p
  }
}
$nl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\DefaultMediaCost'
if (-not (Test-Path -LiteralPath $nl)) {
  New-Item -LiteralPath $nl -Force -EA SilentlyContinue | Out-Null
  foreach ($vk in $costVals.Keys) { New-ItemProperty -LiteralPath $nl -Name $vk -Value $costVals[$vk] -PropertyType DWord -Force -EA SilentlyContinue | Out-Null }
  $made += $nl
}
$wn = 'HKLM:\SYSTEM\CurrentControlSet\Control\Winlogon\Notifications\Components\Wlansvc'
if (-not (Test-Path -LiteralPath $wn)) {
  New-Item -LiteralPath $wn -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -LiteralPath $wn -Name 'Friendly Name' -Value 'Wireless Lan Service' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -LiteralPath $wn -Name 'ServiceName' -Value 'Wlansvc' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -LiteralPath $wn -Name 'Events' -Value 'Logoff' -PropertyType String -Force -EA SilentlyContinue | Out-Null
  $made += $wn
}
# Software\Microsoft\Wlansvc and its five host subkeys (AnqpCache/Interfaces/Parameters/PowerProfiles/ProfileSync)
$ws = 'HKLM:\SOFTWARE\Microsoft\Wlansvc'
if (-not (Test-Path -LiteralPath $ws)) {
  New-Item -LiteralPath $ws -Force -EA SilentlyContinue | Out-Null
  New-ItemProperty -LiteralPath $ws -Name 'LayoutVersion' -Value 1 -PropertyType DWord -Force -EA SilentlyContinue | Out-Null
  $made += $ws
}
foreach ($sub in @($wlanSvcSubs)) {
  $p = $ws + '\' + $sub
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -LiteralPath $p -Force -EA SilentlyContinue | Out-Null
    $made += $p
  }
}
foreach ($d in @('X:\ProgramData\Microsoft\Wlansvc','X:\ProgramData\Microsoft\Wlansvc\Profiles',
                 'X:\ProgramData\Microsoft\Wlansvc\GlobalMachine', ($s32 + '\GroupPolicy'),
                 ($s32 + '\GroupPolicy\Machine'), ($s32 + '\GroupPolicy\User'))) {
  if (-not (Test-Path -LiteralPath $d)) {
    New-Item -ItemType Directory -LiteralPath $d -Force -EA SilentlyContinue | Out-Null
    if (Test-Path -LiteralPath $d) { $made += $d }
  }
}
L('R1 created=' + @($made).Count + ' [' + ((@($made) | ForEach-Object { (C (Split-Path $_ -Leaf)) }) -join ';') + ']')
Tr 'wlansvc' 'R1 env keys+dirs present'
# ---------- R2: Winmgmt up, deps proven, then wlansvc ----------
if ($native) {
  L('R2 wcmsvc ' + [Pe111]::StartAndWait('wcmsvc', 4000))
  $wmKey = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt'
  L('R2 winmgmt key=' + $wmKey)
  if ($wmKey) { L('R2 Winmgmt ' + [Pe111]::StartAndWait('Winmgmt', 40000)) }
  L('R2 WmiNotificationRegistration import check: wmiclnt in s32=' + (Test-Path -LiteralPath ($s32 + '\wmiclnt.dll')))
}
Tr 'wlansvc' 'R2 winmgmt+wcmsvc'
# ---------- R3: EapHost + netprofm + dot3svc (the auth/tether side) ----------
if ($native) {
  foreach ($n in @('EapHost','netprofm','dot3svc','LanmanWorkstation')) {
    if (Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n)) {
      L('R3 ' + $n + ' ' + [Pe111]::StartAndWait($n, 6000))
    } else { L('R3 ' + $n + ' no-key') }
  }
}
Tr 'wlansvc' 'R3 auth-side services up'
# ---------- verdict ----------
if ($native) { L('END wlansvc ' + [Pe111]::Status('wlansvc') + ' | wcmsvc ' + [Pe111]::Status('wcmsvc')) }
L('probe111 end -- baseline to beat: probe110 wlansvc 0x800C0006 at ~125ms with 36 modules')
