# probe24: put the ONE catalog that covers the image's own nwifi.sys into the running PE and see whether
# code integrity stops rejecting it -- and if it does stop, whether wlansvc then reaches RUNNING.
#
# Facts this builds on (probe22/23 + host-side wintrust lookup, all in build/scratch/):
#   * the PE's X:\Windows\System32\drivers\nwifi.sys is a pristine Microsoft binary: sha256
#     A4454B7AB87410537220C7B000AB433E3268AF0BC9A63E1F9953C5D078282871 == the host's copy.
#   * CryptCATAdminEnumCatalogFromHash on the host says that file is covered by
#     Microsoft-Windows-Client-Desktop-Required-Package04~31bf3856ad364e35~amd64~~10.0.19041.7663.cat
#     in CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE} -- 213KB.
#   * the PE's {F750E6C3-...} store directory is EMPTY; its 786 cats all sit in {127D0A1D-...}.
#   * probe23 proved the operator path itself is fine: NdisTapi / NdisWan / NetAdapterCx / netvsc /
#     RasAcd and six borrowed 19041-era drivers (amdgpio2, iagpio, iaLPSS2i_GPIO2 ...) all load rc=0
#     through the same NtLoadDriver call, while nativewifip alone gets 0xC0000428.
# So the missing ingredient is catalog material, not the service record and not the file.
#
# Live test first (costs 3 minutes, ramdisk edits die at reboot): copy the cat into BOTH stores and
# retry. If CI only builds its catalog table at boot this still fails -- then the same copy has to go
# into boot.wim offline and be validated after a reboot, which is the actual build fix either way.
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
function Ver([string]$p) {
  if (-not (Test-Path $p)) { return 'ABSENT' }
  $i = Get-Item $p
  return ('{0} ({1}KB)' -f $i.VersionInfo.FileVersion, [int]($i.Length / 1KB))
}

Sec 'S0_PREP'
$src24 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class SC24 {
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
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(uint ver, IntPtr res, out uint negotiated, out IntPtr client);
  [DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(IntPtr client, IntPtr res);
  [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr client, IntPtr res, out IntPtr list, IntPtr h);
  [DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr p);
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
    return "SeDebug=0x" + a.ToString("X8") + " SeLoadDriver=0x" + b.ToString("X8");
  }
  public static string Load(string name) {
    string kp = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + name;
    byte[] buf = Encoding.Unicode.GetBytes(kp);
    US u = new US();
    u.Length = (ushort)(kp.Length * 2);
    u.MaximumLength = (ushort)((kp.Length + 1) * 2);
    u.Buffer = Marshal.AllocHGlobal(u.MaximumLength);
    Marshal.Copy(buf, 0, u.Buffer, buf.Length);
    uint rc = NtLoadDriver(ref u);
    Marshal.FreeHGlobal(u.Buffer);
    uint dos = RtlNtStatusToDosError(rc);
    return name + " rc=0x" + rc.ToString("X8") + " dos=" + dos + (dos != 0 ? " [" + Msg(dos) + "]" : " OK");
  }
  public static string Status(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u | 0x0020u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    string r = QueryServiceStatus(h, st) ?
      ("state=" + BitConverter.ToUInt32(st, 4) + " specific=0x" + BitConverter.ToUInt32(st, 12).ToString("X8")) :
      ("QUERY-err=" + Marshal.GetLastWin32Error());
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
  public static string WlanApi() {
    IntPtr client = IntPtr.Zero; uint neg = 0;
    int rc = WlanOpenHandle(2u, IntPtr.Zero, out neg, out client);
    if (rc != 0) return "WlanOpenHandle rc=" + rc;
    string r = "WlanOpenHandle ok negotiated=" + neg;
    IntPtr list = IntPtr.Zero;
    int rc2 = WlanEnumInterfaces(client, IntPtr.Zero, out list, IntPtr.Zero);
    if (rc2 == 0 && list != IntPtr.Zero) {
      int num = Marshal.ReadInt32(list, 0);
      r += " interfaces=" + num;
      WlanFreeMemory(list);
    } else { r += " WlanEnumInterfaces rc=" + rc2; }
    WlanCloseHandle(client, IntPtr.Zero);
    return r;
  }
}
"@
try { Add-Type -TypeDefinition $src24 -ErrorAction Stop; Log '  Add-Type SC24 ok' }
catch { Log ('  Add-Type FAILED: ' + $_.Exception.Message); Log 'PROBE24_DONE'; return }
Log ('  ' + [SC24]::Privs())
Log ('  nativewifip: ' + (SvcState 'nativewifip') + ' | ' + [SC24]::Status('nativewifip'))
Log ('  nwifi.sys  : ' + (Ver 'X:\Windows\System32\drivers\nwifi.sys'))

$ST1 = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$ST2 = 'X:\Windows\System32\CatRoot\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}'
$CATNAME = 'Microsoft-Windows-Client-Desktop-Required-Package04~31bf3856ad364e35~amd64~~10.0.19041.7663.cat'
Log ('  store1 {F750E6C3} cats=' + (@(Get-ChildItem $ST1 -Filter *.cat -File -EA SilentlyContinue)).Count)
Log ('  store2 {127D0A1D} cats=' + (@(Get-ChildItem $ST2 -Filter *.cat -File -EA SilentlyContinue)).Count)

Sec 'S1_ADD_COVERING_CATALOG_TO_BOTH_STORES'
$pushed = 'X:\nwcat.cat'
if (-not (Test-Path $pushed)) { Log ('  !! pushed catalog missing at ' + $pushed); Log 'PROBE24_DONE'; return }
Log ('  pushed file : ' + (Ver $pushed) + ' bytes=' + (Get-Item $pushed).Length)
Log ('  sha256 pushed = ' + (Get-FileHash -Algorithm SHA256 $pushed).Hash)
foreach ($st in @($ST1, $ST2)) {
  $dst = Join-Path $st $CATNAME
  $r = Cmd ('copy /y "' + $pushed + '" "' + $dst + '"')
  Log ('  copy -> ' + $dst + ' : ' + $r)
  Log ('    exists now = ' + (Test-Path $dst) + '  store cat count = ' + (@(Get-ChildItem $st -Filter *.cat -File -EA SilentlyContinue)).Count)
}

Sec 'S2_RETRY_DRIVER_LOAD'
Log ('  ' + [SC24]::Load('nativewifip'))
Log ('  ' + [SC24]::Status('nativewifip'))
Log ('  via SCM: ' + [SC24]::Start('nativewifip'))
Start-Sleep -Milliseconds 600
Log ('  ' + [SC24]::Status('nativewifip') + '  ' + (SvcState 'nativewifip'))

Sec 'S3_WLANSVC_TIMELINE'
Log ('  ' + [SC24]::Start('wlansvc'))
$t0 = Get-Date
$last = ''
for ($i = 0; $i -lt 60; $i++) {
  $s = [SC24]::Status('wlansvc')
  if ($s -ne $last) { Log ('    wlansvc t+' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms  ' + $s); $last = $s }
  if ($s -match 'state=4') { Log '    (RUNNING)'; break }
  Start-Sleep -Milliseconds 50
}
Log ('  wlansvc : ' + (SvcState 'wlansvc') + ' | ' + [SC24]::Status('wlansvc'))
Log ('  ' + [SC24]::WlanApi())

Sec 'S4_FINAL'
foreach ($n in @('nativewifip', 'wlansvc', 'dot3svc', 'wcmsvc')) {
  Log ('  ' + $n + ' : ' + (SvcState $n) + ' | ' + [SC24]::Status($n))
}
Log ('  ' + [SC24]::WlanApi())
Log '  the stick image was NOT touched; ramdisk edits die at reboot'
Log 'PROBE24_DONE'
