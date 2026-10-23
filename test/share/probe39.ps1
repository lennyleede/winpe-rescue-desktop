param([string]$Only = '', [switch]$NoLoad)
$ErrorActionPreference = 'SilentlyContinue'
# probe39 -- ask the kernel, not the SCM, to load the borrowed WiFi drivers, and take the exact
# NTSTATUS back. This settles the question every earlier probe could only guess at:
# can 19041-era nwifi / vwifibus / vwififlt / vwifimp load at all on this 26100 NDIS?
#
# Why NtLoadDriver: services.exe builds its service database at boot, so the vwifibus/vwififlt/
# vwifimp keys we wrote by hand are invisible to the SCM (OpenServiceW = 1060, Win32_SystemDriver
# lists nothing) and 'sc start' / StartServiceW can never reach them. NtLoadDriver resolves
# \Registry\Machine\System\CurrentControlSet\Services\<name> straight from the hive and calls the
# kernel, which is exactly the path PnP uses when it loads a filter driver. The Win32 error we kept
# getting for nativewifip (31 = ERROR_GEN_FAILURE) hides the real status; this prints it.
#
# probe38 closed the runtime staging routes: SetupCopyOEMInf = 0xE000020F,
# drvload netvwifibus.inf = 0xE000022F, pnputil /add-driver = "third-party INF has no signature".
Add-Type -Language CSharp @'
using System;using System.Text;using System.Runtime.InteropServices;
public class NtLoad39 {
  [DllImport("ntdll.dll", SetLastError=true)]
  public static extern int NtLoadDriver(string serviceName);
  [DllImport("ntdll.dll", SetLastError=true)]
  public static extern int NtUnloadDriver(string serviceName);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
  // CharSet must be Unicode here: the default is Ansi, and the *W entrypoint then reads the ANSI
  // bytes as UTF-16, looks up a garbage privilege name and fails. That is exactly what produced
  // "LOOKUP-FAIL 1313" + 0xC0000061 on the first probe39 run.
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool LookupPrivilegeValueW(string host, string name, out long luid);
  // Offsets must match the native TOKEN_PRIVILEGES exactly: Count at 0, LowPart 4, HighPart 8,
  // Attributes 12. A 64-bit 'long' field would be aligned to offset 8 and break the layout.
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID_AND_ATTRIBUTES { public int LowPart; public int HighPart; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)]
  public struct TOKEN_PRIVILEGE { public uint Count; public LUID_AND_ATTRIBUTES Luid; }
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr tok, bool disable, ref TOKEN_PRIVILEGE newStates, int length, IntPtr prev, IntPtr retLen);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  public static string Enable() {
    IntPtr tok;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28u, out tok)) return "OPEN-TOKEN-FAIL " + Marshal.GetLastWin32Error();
    long luid;
    if (!LookupPrivilegeValueW(null, "SeLoadDriverPrivilege", out luid)) return "LOOKUP-FAIL " + Marshal.GetLastWin32Error();
    TOKEN_PRIVILEGE tp = new TOKEN_PRIVILEGE();
    tp.Count = 1;
    tp.Luid.LowPart = (int)(luid & 0xFFFFFFFFL);
    tp.Luid.HighPart = (int)(luid >> 32);
    tp.Luid.Attributes = 2u;               // SE_PRIVILEGE_ENABLED
    int size = Marshal.SizeOf(typeof(TOKEN_PRIVILEGE));
    bool ok = AdjustTokenPrivileges(tok, false, ref tp, size, IntPtr.Zero, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    return "SIZE=" + size + " ADJUST ok=" + ok + " err=" + e + " luid=0x" + luid.ToString("X16");
  }
  public static string Hex(int v) { return "0x" + v.ToString("X8"); }
  public static string Load(string svc) {
    string key = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + svc;
    return Hex(NtLoadDriver(key));
  }
}
'@ -EA SilentlyContinue
function Say([string]$m) { Write-Output ('C39|' + $m) }
function Raw([string]$s) { return (($s -replace "`r?`n", ' ; ') -replace '\s{2,}', ' ') }
Write-Output ('PROBE39 ' + (Get-Date -Format 'HH:mm:ss'))
Say ('PRIV=' + [NtLoad39]::Enable())
$w = & whoami.exe /priv 2>&1 | Out-String
$wr = Raw $w
$has = 'no'
if ($w -match '(?i)SeLoadDriverPrivilege') { $has = 'yes' }
Say ('WHOAMI_HAS_LOADDRV=' + $has + '|len=' + $wr.Length + '|' + $wr.Substring(0, [Math]::Min(170, $wr.Length)))
# NtLoadDriver reads ImagePath straight out of the hive and opens the file in kernel context, so a
# missing .sys shows up as 0xC0000034 (STATUS_OBJECT_NAME_NOT_FOUND) instead of the vague Win32 31.
foreach ($f in @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys', 'Netwtw14.sys')) {
  $p = 'X:\Windows\System32\drivers\' + $f
  $o = Get-Item $p -EA SilentlyContinue
  Say ('SYSFILE|' + $f + '|' + $(if ($o) { 'yes|' + $o.Length } else { 'NO' }))
}
foreach ($c in @('Microsoft-Windows-Client-Desktop-Required-Package04~31bf3856ad364e35~amd64~~10.0.19041.7663.cat')) {
  $p = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\' + $c
  $o = Get-Item $p -EA SilentlyContinue
  Say ('CATFILE|' + $c + '|' + $(if ($o) { 'yes|' + $o.Length } else { 'NO' }))
}
$svcs = @('vwifibus', 'vwififlt', 'nativewifip', 'vwifimp')
if ($Only) { $svcs = $Only.Split(',') }
foreach ($s in $svcs) {
  $k = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $s
  $q = Raw (& reg.exe query $k 2>&1 | Out-String)
  $img = Raw (& reg.exe query $k /v ImagePath 2>&1 | Out-String)
  Say ($s + '|KEY|' + $q.Substring(0, [Math]::Min(400, $q.Length)))
  Say ($s + '|IMG|' + $img)
  $st = [NtLoad39]::Load($s)
  Say ($s + '|NTLOAD|' + $st)
  $g = Get-CimInstance Win32_SystemDriver -Filter "Name='$s'" -EA SilentlyContinue
  if ($g) { Say ($s + '|SYSDRV|state=' + $g.State + '|started=' + $g.Started + '|path=' + $g.PathName) } else { Say ($s + '|SYSDRV|not-listed') }
}
Say ('NDIS_VERSION|' + (Raw (& reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\NDIS' /v ImagePath 2>&1 | Out-String)))
if ($NoLoad) { Write-Output 'PROBE39 END'; return }
# If vwifibus loaded, the virtual bus driver should enumerate a Wi-Fi device into PnP; if nwifi/
# nativewifip loaded too, wlansvc can finally answer and WlanOpenHandle stops returning 1062.
& pnputil.exe /scan-devices 2>&1 | Out-String | ForEach-Object { Say ('SCAN|' + (Raw $_)) }
foreach ($s in @('nativewifip', 'wlansvc')) {
  $r = Raw (& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $s) /v Start 2>&1 | Out-String)
  Say ($s + '|STARTREG|' + $r)
}
Start-Sleep -Seconds 8
$d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
foreach ($x in $d) { Say ('NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
$bus = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match '(?i)virtual|wireless|wifi|802\.11' })
foreach ($x in $bus) { Say ('BUSNODE|' + $x.Name + '|code=' + $x.ConfigManagerErrorCode + '|' + $x.Status) }
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi39 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  public static string Open() { int ver; IntPtr h; int r = WlanOpenHandle(1, IntPtr.Zero, out ver, out h);
    return r + " ver=" + ver + " handle=" + (h == IntPtr.Zero ? 0 : 1); }
}
'@ -EA SilentlyContinue
Say ('WlanOpenHandle=' + [Wapi39]::Open())
Write-Output 'PROBE39 END'
