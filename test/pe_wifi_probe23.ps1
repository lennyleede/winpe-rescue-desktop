# probe23: does the manual "load a kernel driver by service key" path work AT ALL in this PE?
#
# probe22 nailed the domino: nativewifip (X:\Windows\System32\drivers\nwifi.sys, 10.0.19041.7663) is
# refused with NtLoadDriver 0xC0000428 STATUS_INVALID_IMAGE_HASH / SCM err=577 ERROR_DRIVER_BLOCKED,
# while the already-loaded 26100-native Ndisuio answers 0xC000010E (IMAGE_ALREADY_LOADED).
# Two ways to read that refusal, and they lead to completely different fixes:
#   (a) the mechanism is fine, nwifi's signature material is what is missing  -> find signed material
#   (b) PE never lets an operator load a kernel driver on demand at all       -> must make it load at
#       boot / bind through PnP instead, and the whole "patch the image" plan changes
# This probe runs the positive control probe22 lacked: take OTHER kernel-driver service keys that are
# sitting STOPPED in this very image and try to load them the same way. Only benign network-stack
# drivers are chosen, and every driver that loads is unloaded again immediately.
# It also fingerprints the PE's own nwifi.sys (sha256/size/version) so a genuine Microsoft copy of the
# same build can be compared byte-for-byte later.
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function Ver([string]$p) {
  if (-not (Test-Path $p)) { return 'ABSENT' }
  $i = Get-Item $p
  return ('{0} ({1}KB)' -f $i.VersionInfo.FileVersion, [int]($i.Length / 1KB))
}

Sec 'S0_SETUP'
$src23 = @"
using System;
using System.Runtime.InteropServices;
public class SC23 {
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
  static US Make(string keyPath) {
    byte[] buf = System.Text.Encoding.Unicode.GetBytes(keyPath);
    US u = new US();
    u.Length = (ushort)(keyPath.Length * 2);
    u.MaximumLength = (ushort)((keyPath.Length + 1) * 2);
    u.Buffer = Marshal.AllocHGlobal(u.MaximumLength);
    Marshal.Copy(buf, 0, u.Buffer, buf.Length);
    return u;
  }
  public static string Privs() {
    bool prev = false;
    uint a = RtlAdjustPrivilege(20, true, false, out prev);
    uint b = RtlAdjustPrivilege(10, true, false, out prev);
    return "SeDebug=0x" + a.ToString("X8") + " SeLoadDriver=0x" + b.ToString("X8");
  }
  public static string Load(string name) {
    US u = Make("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + name);
    uint rc = NtLoadDriver(ref u); Marshal.FreeHGlobal(u.Buffer);
    uint dos = RtlNtStatusToDosError(rc);
    return "load " + name + " rc=0x" + rc.ToString("X8") + " dos=" + dos +
           (dos != 0 ? " [" + Msg(dos) + "]" : "");
  }
  public static string Unload(string name) {
    US u = Make("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + name);
    uint rc = NtUnloadDriver(ref u); Marshal.FreeHGlobal(u.Buffer);
    uint dos = RtlNtStatusToDosError(rc);
    return "unload " + name + " rc=0x" + rc.ToString("X8") + " dos=" + dos;
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
}
"@
try { Add-Type -TypeDefinition $src23 -ErrorAction Stop; Log '  Add-Type SC23 ok' }
catch { Log ('  Add-Type FAILED: ' + $_.Exception.Message); Log 'PROBE23_DONE'; return }
Log ('  ' + [SC23]::Privs())

Sec 'S1_INVENTORY_KERNEL_DRIVER_SERVICES_STOPPED_AND_MANUAL'
$S32 = 'X:\Windows\System32'
function ResolvePath([string]$img) {
  $p = ($img -replace '^\\\?\?', '').Trim()
  if ($p -imatch '^%SystemRoot%') { $p = 'X:\Windows' + ($p -ireplace '^%SystemRoot%', '') }
  elseif ($p -imatch '^\\?SystemRoot') { $p = 'X:\Windows' + ($p -ireplace '^\\?SystemRoot', '') }
  elseif ($p -imatch '^system32(\\|$)') { $p = 'X:\Windows\System32' + ($p -ireplace '^system32', '') }
  elseif ($p -imatch '^[A-Za-z]:\\') { }
  else { $p = 'X:\Windows\System32\' + ($p -replace '^[\\/]+', '') }
  return $p
}
$rows = @()
foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue)) {
  $t = [int]($k.GetValue('Type', 0))
  $st = [int]($k.GetValue('Start', 99))
  if ($t -ne 1) { continue }
  $img = [string]$k.GetValue('ImagePath', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $path = ResolvePath $img
  $v = Ver $path
  $q = [SC23]::Status($k.PSChildName)
  $rows += [pscustomobject]@{
    Name = $k.PSChildName; Start = $st; Path = $path; Ver = $v; State = $q; Native = ($v -match '26100')
  }
}
Log ('  kernel-driver services = ' + $rows.Count)
foreach ($r in ($rows | Where-Object { $_.Start -eq 3 } | Sort-Object Name)) {
  Log ('    ' + ('{0,-18}' -f $r.Name) + ' start=3 native=' + $r.Native + ' ' + $r.Ver + ' | ' + $r.State)
}

Sec 'S2_POSITIVE_CONTROL_LOAD_STOPPED_26100_NATIVE_NET_DRIVERS'
$allow = '^(net|wan|ras|tunnel|ndis|lltd|mslld|pacer|wfp|vwifi|dhcp|lmhosts|nsi)'
$picks = @($rows | Where-Object {
  $_.Start -eq 3 -and $_.Native -and $_.Ver -ne 'ABSENT' -and
  $_.State -match 'state=1 ' -and $_.Name -match $allow -and $_.Name -ne 'nativewifip'
} | Select-Object -First 6)
Log ('  picked ' + $picks.Count + ': ' + ($picks | ForEach-Object { $_.Name }))
foreach ($p in $picks) {
  Log ('    ' + [SC23]::Load($p.Name))
  Log ('      ' + [SC23]::Status($p.Name))
  [void][SC23]::Unload($p.Name)
  Log ('      ' + [SC23]::Unload($p.Name) + ' -> ' + [SC23]::Status($p.Name))
}
Log ('  nativewifip again for the record: ' + [SC23]::Load('nativewifip'))

Sec 'S3_BORROWED_NON_NATIVE_STOPPED_ONES'
# any borrowed (non-26100) kernel driver that is stopped: if these ALSO get 0xC0000428 the story is
# "signature material", if some of them load then nwifi is singled out by something else.
$brow = @($rows | Where-Object { $_.Start -eq 3 -and -not $_.Native -and $_.Ver -ne 'ABSENT' -and $_.State -match 'state=1 ' } | Select-Object -First 6)
Log ('  borrowed stopped drivers = ' + $brow.Count + ': ' + ($brow | ForEach-Object { $_.Name }))
foreach ($p in $brow) {
  Log ('    ' + [SC23]::Load($p.Name))
  [void][SC23]::Unload($p.Name)
}

Sec 'S4_FINGERPRINT_THE_PE_NWIFI'
$f = 'X:\Windows\System32\drivers\nwifi.sys'
Log ('  file    : ' + $f + ' ' + (Ver $f))
try {
  $h = Get-FileHash -Algorithm SHA256 -LiteralPath $f
  Log ('  sha256  : ' + $h.Hash)
} catch { Log ('  Get-FileHash failed: ' + $_.Exception.Message) }
Log ('  bytes   : ' + (Get-Item $f).Length)
Log ('  mtime   : ' + (Get-Item $f).LastWriteTime)
Log ('  md5     : ' + (Cmd ('certutil -hashfile ' + $f + ' MD5')))

Sec 'S5_FINAL'
foreach ($n in @('nativewifip', 'wlansvc', 'dot3svc')) { Log ('  ' + [SC23]::Status($n)) }
Log '  nothing in the stick image was touched; loaded drivers were unloaded again'
Log 'PROBE23_DONE'
