# probe25: after probe24 removed the code-integrity wall (nativewifip went 0xC0000428/577 -> 0xC0000001/31),
# decide whether ERROR_GEN_FAILURE is (a) a second real defect in our service record, or (b) simply "this
# bench VM has no 802.11 radio".
#
# Three things this probe adds over probe24:
#   1. wintrust lookup INSIDE the PE -- prove the pushed catalog is actually registered/resolvable, not
#      just present on disk (same CryptCATAdmin* call that named the catalog on the host).
#   2. byte-for-byte compare our nativewifip service record against the host reference shape and fill
#      whatever is missing (DisplayName / ErrorControl / Group / Parameters\DefaultFilterSettings), then
#      retry the load. If dos=31 survives a complete record, the record is not the problem.
#   3. inventory what NDIS/PnP actually sees, so "no radio" is a stated fact rather than an assumption.
#
# Everything happens on the live ramdisk; the stick image is untouched and these edits die at reboot.
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}

Sec 'S0_SNAPSHOT'
$ST1 = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$ST2 = 'X:\Windows\System32\CatRoot\{127D0A1D-4EF2-11D1-8608-00C04FC295EE}'
foreach ($d in @($ST1, $ST2)) {
  $lbl = ($d -split '\\')[-1]
  Log ('  store ' + $lbl.Substring(0,8) + ' cats=' + (@(Get-ChildItem -LiteralPath $d -Filter *.cat -File -EA SilentlyContinue)).Count)
}
Log ('  nwifi.sys : ' + (Get-Item 'X:\Windows\System32\drivers\nwifi.sys').Length + 'B sha256=' + (Get-FileHash -Algorithm SHA256 'X:\Windows\System32\drivers\nwifi.sys').Hash.Substring(0,16))
Log ('  nativewifip: ' + (SvcState 'nativewifip') + ' | wlansvc: ' + (SvcState 'wlansvc'))

$src25 = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class P25 {
  [StructLayout(LayoutKind.Sequential)]
  public struct US { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [DllImport("ntdll.dll")] public static extern uint NtLoadDriver(ref US s);
  [DllImport("ntdll.dll")] public static extern uint NtUnloadDriver(ref US s);
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
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool ControlService(IntPtr svc, uint cmd, byte[] st);
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern uint FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("wintrust.dll")] public static extern int CryptCATAdminAcquireContext2(out IntPtr ctx, ref Guid sub, IntPtr eng, IntPtr hashAlt, uint flags);
  [DllImport("wintrust.dll")] public static extern bool CryptCATAdminReleaseContext(IntPtr ctx, uint flags);
  [DllImport("wintrust.dll")] public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr ctx, IntPtr file, ref uint cbHash, byte[] hash);
  [DllImport("wintrust.dll")] public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr ctx, byte[] hash, uint cbHash, uint flags, ref IntPtr prev);
  [DllImport("wintrust.dll")] public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr ctx, IntPtr catCtx, uint flags);
  [DllImport("wintrust.dll", CharSet=CharSet.Unicode)] public static extern bool CryptCATCatalogInfoFromContext(IntPtr catCtx, byte[] info, uint flags);
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(uint ver, IntPtr res, out uint neg, out IntPtr client);
  [DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(IntPtr client, IntPtr res);

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
  private static US MkKey(string name) {
    string kp = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + name;
    byte[] buf = Encoding.Unicode.GetBytes(kp);
    US u = new US();
    u.Length = (ushort)(kp.Length * 2);
    u.MaximumLength = (ushort)((kp.Length + 1) * 2);
    u.Buffer = Marshal.AllocHGlobal(u.MaximumLength);
    Marshal.Copy(buf, 0, u.Buffer, buf.Length);
    return u;
  }
  public static string Load(string name) {
    US u = MkKey(name);
    uint rc = NtLoadDriver(ref u);
    Marshal.FreeHGlobal(u.Buffer);
    uint dos = RtlNtStatusToDosError(rc);
    return name + " rc=0x" + rc.ToString("X8") + " dos=" + dos + (dos != 0 ? " [" + Msg(dos) + "]" : " OK");
  }
  public static string Unload(string name) {
    US u = MkKey(name);
    uint rc = NtUnloadDriver(ref u);
    Marshal.FreeHGlobal(u.Buffer);
    return name + " unload rc=0x" + rc.ToString("X8");
  }
  public static string Status(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0001u | 0x0004u | 0x0010u | 0x0020u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    string r = QueryServiceStatus(h, st) ?
      ("state=" + BitConverter.ToUInt32(st, 4) + " win32=0x" + BitConverter.ToUInt32(st, 8).ToString("X8") +
                " specific=0x" + BitConverter.ToUInt32(st, 12).ToString("X8")) :
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
  public static string Stop(string name) {
    IntPtr scm = OpenSCManagerW(null, null, 0x0001u);
    IntPtr h = OpenServiceW(scm, name, 0x0004u | 0x0020u);
    if (h == IntPtr.Zero) return name + " OPEN-err=" + Marshal.GetLastWin32Error();
    byte[] st = new byte[32];
    bool ok = ControlService(h, 1u, st);
    int e = Marshal.GetLastWin32Error();
    CloseHandle(h);
    return name + " STOP => " + (ok ? "sent" : ("err=" + e));
  }
  // Which catalog in THIS running PE covers a given file? (WinNT 5.x/6.x store GUID)
  public static string CatalogOf(string path) {
    Guid winnt = new Guid("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
    IntPtr ctx = IntPtr.Zero;
    int rc = CryptCATAdminAcquireContext2(out ctx, ref winnt, IntPtr.Zero, IntPtr.Zero, 0u);
    if (rc != 0) return path + " ACQUIRE-FAIL rc=" + rc;
    IntPtr f = CreateFileW(path, 0x80000000u, 0x7u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
    if (f.ToInt64() == -1) { CryptCATAdminReleaseContext(ctx, 0u); return path + " OPEN-FAIL err=" + Marshal.GetLastWin32Error(); }
    uint cb = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(ctx, f, ref cb, null)) {
      CryptCATAdminReleaseContext(ctx, 0u); CloseHandle(f);
      return path + " HASH-FAIL err=" + Marshal.GetLastWin32Error();
    }
    byte[] hash = new byte[cb];
    if (!CryptCATAdminCalcHashFromFileHandle(ctx, f, ref cb, hash)) {
      CryptCATAdminReleaseContext(ctx, 0u); CloseHandle(f);
      return path + " HASH2-FAIL err=" + Marshal.GetLastWin32Error();
    }
    CloseHandle(f);
    string hex = ""; for (int i = 0; i < hash.Length; i++) hex += hash[i].ToString("X2");
    string r = path + " hash(" + cb + ")=" + hex.Substring(0, Math.Min(32, hex.Length)) + " -> ";
    IntPtr prev = IntPtr.Zero;
    IntPtr cat = CryptCATAdminEnumCatalogFromHash(ctx, hash, cb, 0u, ref prev);
    if (cat == IntPtr.Zero) { CryptCATAdminReleaseContext(ctx, 0u); return r + "NO COVERING CATALOG"; }
    byte[] info = new byte[8 + 4 + (260 * 2)];
    bool ok = CryptCATCatalogInfoFromContext(cat, info, 0u);
    string file = ok ? System.BitConverter.ToString(info, 4, 4).Replace("-","") : "";
    string name = "";
    if (ok) {
      for (int i = 0; i < 260; i++) {
        ushort ch = BitConverter.ToUInt16(info, 8 + i * 2);
        if (ch == 0) break;
        name += (char)ch;
      }
    }
    CryptCATAdminReleaseCatalogContext(ctx, cat, 0u);
    CryptCATAdminReleaseContext(ctx, 0u);
    return r + (ok ? name : ("INFO-FAIL err=" + Marshal.GetLastWin32Error()));
  }
  public static string WlanApi() {
    IntPtr client = IntPtr.Zero; uint neg = 0;
    int rc = WlanOpenHandle(2u, IntPtr.Zero, out neg, out client);
    if (rc != 0) return "WlanOpenHandle rc=" + rc + " [" + Msg((uint)rc) + "]";
    WlanCloseHandle(client, IntPtr.Zero);
    return "WlanOpenHandle OK negotiated=" + neg;
  }
}
"@
try { Add-Type -TypeDefinition $src25 -ErrorAction Stop; Log '  Add-Type P25 ok' }
catch { Log ('  Add-Type FAILED: ' + $_.Exception.Message); Log 'PROBE25_DONE'; return }
Log ('  ' + [P25]::Privs())

Sec 'S1_CATALOG_RESOLVES_INSIDE_PE'
Log ('  ' + [P25]::CatalogOf('X:\Windows\System32\drivers\nwifi.sys'))
Log ('  ' + [P25]::CatalogOf('X:\Windows\System32\wlansvc.dll'))
Log ('  ' + [P25]::CatalogOf('X:\Windows\System32\drivers\ndistapi.sys'))

Sec 'S2_CURRENT_SERVICE_RECORD'
$K = 'HKLM:\SYSTEM\CurrentControlSet\Services\nativewifip'
$p = Get-ItemProperty -Path $K -EA SilentlyContinue
foreach ($n in @('Type','Start','ErrorControl','Group','ImagePath','DisplayName')) {
  $v = $p.$n
  if ($v -is [array]) { $v = ($v | Where-Object { $_ -ne 0 -and $_ -ne 1 }) -join ',' }
  Log ('    {0,-12}= {1}' -f $n, $v)
}
$pk = 'HKLM:\SYSTEM\CurrentControlSet\Services\nativewifip\Parameters'
if (Test-Path $pk) {
  $pp = Get-ItemProperty -Path $pk
  foreach ($ip in $pp.PSObject.Properties) {
    if ($ip.Name -like 'PS*') { continue }
    Log ('    Parameters\{0} = {1}' -f $ip.Name, $ip.Value)
  }
  Log ('    Parameters subkeys = ' + ((Get-ChildItem $pk -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ' | '))
} else { Log '    Parameters KEY ABSENT' }
Log ('    value names in service key = ' + (((Get-Item $K).GetValueNames()) -join ','))

Sec 'S3_ALIGN_RECORD_WITH_HOST'
# Host reference (2026-10-09): Type=1 Start=3 ErrorControl=1 Group=NDIS ImagePath=system32\DRIVERS\nwifi.sys
# DisplayName=@%SystemRoot%\System32\drivers\nwifi.sys,-101 NdisMajorVersion=6 NdisMinorVersion=0x54
# DriverMajorVersion=1 DriverMinorVersion=0  Parameters\DefaultFilterSettings=1
$want = [ordered]@{
  Type = 1; Start = 3; ErrorControl = 1; Group = 'NDIS'
  DisplayName = '@%SystemRoot%\System32\drivers\nwifi.sys,-101'
  ImagePath = 'system32\DRIVERS\nwifi.sys'
  NdisMajorVersion = 6; NdisMinorVersion = 84; DriverMajorVersion = 1; DriverMinorVersion = 0
}
foreach ($e in $want.GetEnumerator()) {
  $cur = (Get-Item $K).GetValue($e.Key, $null)
  if ($cur -is [byte[]]) { $cur = [Text.Encoding]::Unicode.GetString($cur) -replace "`0.*$" }
  $same = ($null -ne $cur) -and ("$cur" -eq "$($e.Value)")
  if (-not $same) {
    $t = if ($e.Value -is [int]) { 'DWord' } else { 'String' }
    Set-ItemProperty -Path $K -Name $e.Key -Value $e.Value -Type $t -EA SilentlyContinue
    Log ('    SET  {0} : was <{1}> -> {2}' -f $e.Key, $cur, $e.Value)
  } else { Log ('    keep {0} = {1}' -f $e.Key, $cur) }
}
if (-not (Test-Path $pk)) { New-Item -Path $pk -Force | Out-Null; Log '    created Parameters key' }
$curDfs = (Get-Item $pk).GetValue('DefaultFilterSettings', $null)
if ($curDfs -ne 1) {
  Set-ItemProperty -Path $pk -Name 'DefaultFilterSettings' -Value 1 -Type DWord
  Log ('    SET  Parameters\DefaultFilterSettings : was <{0}> -> 1' -f $curDfs)
} else { Log '    keep Parameters\DefaultFilterSettings = 1' }

Sec 'S4_RETRY_LOAD_WITH_ALIGNED_RECORD'
Log ('  ' + [P25]::Load('nativewifip'))
Log ('  ' + [P25]::Status('nativewifip'))
Log ('  via SCM: ' + [P25]::Start('nativewifip'))
Start-Sleep -Milliseconds 800
Log ('  ' + [P25]::Status('nativewifip') + ' | ' + (SvcState 'nativewifip'))

Sec 'S5_RETRY_WLANSVC'
Log ('  ' + [P25]::Start('wlansvc'))
$t0 = Get-Date; $last = ''
for ($i = 0; $i -lt 60; $i++) {
  $s = [P25]::Status('wlansvc')
  if ($s -ne $last) { Log ('    wlansvc t+' + [int](((Get-Date) - $t0).TotalMilliseconds) + 'ms ' + $s); $last = $s }
  if ($s -match 'state=4') { Log '    RUNNING'; break }
  Start-Sleep -Milliseconds 50
}
Log ('  ' + [P25]::WlanApi())

Sec 'S6_WHAT_NDIS_ACTUALLY_SEES'
$ad = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)
Log ('  Win32_NetworkAdapter total=' + $ad.Count)
foreach ($a in $ad) {
  Log ('    idx={0} name={1} service={2} phys={3} installed={4} conn={5}' -f `
      $a.DeviceID, $a.Name, $a.ServiceName, $a.PhysicalAdapter, $a.Installed, $a.NetConnectionID)
}
$wifi = @($ad | Where-Object { ($_.Name -match '802\.11|[Ww]ireless|[Ww]i-?[Ff]i|WIFI') -or ($_.ServiceName -match 'nwifi') })
Log ('  adapters that could host NativeWifi = ' + $wifi.Count + ' [' + (($wifi | ForEach-Object { $_.Name }) -join '; ') + ']')
$drv = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -match 'nwifi|ndis|wlan' })
foreach ($d in $drv) { Log ('    sysdriver {0,-16} state={1} start={2} path={3}' -f $d.Name, $d.State, $d.StartMode, $d.PathName) }

Sec 'S7_FINAL'
Log ('  nativewifip: ' + [P25]::Status('nativewifip') + ' | ' + (SvcState 'nativewifip'))
Log ('  wlansvc    : ' + [P25]::Status('wlansvc') + ' | ' + (SvcState 'wlansvc'))
Log ('  ' + [P25]::WlanApi())
Log ('  ' + [P25]::CatalogOf('X:\Windows\System32\drivers\nwifi.sys'))
Log '  ramdisk-only edits; stick image untouched'
Log 'PROBE25_DONE'
