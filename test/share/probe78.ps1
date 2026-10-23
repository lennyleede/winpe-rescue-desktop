# probe78 -- LIVE PE. Everything probe74..77 could close is closed (code integrity, imports, api sets,
# driver version/pool, the four Ndis*/Driver* version values, service SD, Net class registration). The one
# live lever that looked dead was NtLoadDriver, and it turns out to have been MISUSED, not denied:
#   probe74 called RtlAdjustPrivilege(19, TRUE, clientView=FALSE) -> STATUS_SUCCESS, then NtLoadDriver gave
#   0xC0000061 STATUS_PRIVILEGE_NOT_HELD, which we read as "the PE token has no SeLoadDriverPrivilege".
#   Host-side lookup with Advapi32!LookupPrivilegeValueW says otherwise: SeLoadDriverPrivilege = LUID 10 and
#   19 is SeShutdownPrivilege. probe74 enabled the wrong privilege, reported success, and left load-driver
#   disabled. So the PE may well be able to load arbitrary images after all -- which reopens LIVE testing of
#   (a) why the AX211 miniport fails (the exact NTSTATUS behind code 37) and (b) whether NdisImPlatform and
#   wdiwifi load once their offline key + binary are staged (the exact thing we want to bake).
# NOTE ON NAMES: PowerShell variables are CASE-INSENSITIVE -- probe77 lost $OFF because a loop variable was
# called $ofF (same name as $OFF). The offline-hive prefix here is $REFO and no other name contains "refo".
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
function VOf([string]$key, [string]$name) {
  $v = 'ABSENT'
  if (Test-Path -LiteralPath $key) {
    $ki = Get-Item -LiteralPath $key
    if (@($ki.GetValueNames()) -contains $name) { $v = '' + ($ki.GetValue($name) -join ';') }
  }
  return $v
}
$REFO = 'HKLM:\R8OFF'
$CS = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$REGCS = '\Registry\Machine\System\CurrentControlSet\Services'

try {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class P78 {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool K32EnumDeviceDrivers(IntPtr[] lpp, int cb, out int needed);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern int K32GetDeviceDriverBaseNameW(IntPtr drv, StringBuilder buf, int count);
  [DllImport("ntdll.dll")]
  static extern int RtlAdjustPrivilege(int priv, bool enable, bool client, out bool old);
  [DllImport("ntdll.dll")]
  static extern int NtLoadDriver(string key);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenThreadToken(IntPtr th, uint access, bool openAsSelf, out IntPtr tok);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool GetLengthSid(IntPtr sid, out int len);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool LookupPrivilegeValueW(string system, string name, out LUID luid);
  [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  const uint TOKEN_QUERY = 0x0008;
  // TOKEN_USER = 1, TOKEN_PRIVILEGES = 3
  public static string ToHex(int s) {
    uint u = (uint)s;
    string n = "";
    if (u == 0u) n = " OK";
    else if (u == 0xC0000061u) n = " PRIVILEGE_NOT_HELD";
    else if (u == 0xC0000034u) n = " OBJECT_NAME_NOT_FOUND";
    else if (u == 0xC0000035u) n = " OBJECT_NAME_COLLISION";
    else if (u == 0xC0000428u) n = " INVALID_IMAGE_HASH(CI)";
    else if (u == 0xC000000Eu) n = " INVALID_PARAMETER";
    else if (u == 0xC0000225u) n = " NOT_FOUND";
    else if (u == 0xC0000022u) n = " ACCESS_DENIED";
    else if (u == 0x80000006u) n = " DRIVER_UNLOADED";
    return "0x" + u.ToString("X8") + n;
  }
  public static string Enable(int which, bool clientView) {
    bool old;
    return ToHex(RtlAdjustPrivilege(which, true, clientView, out old));
  }
  public static int LuidOf(string name) {
    LUID l;
    if (!LookupPrivilegeValueW(null, name, out l)) return -1;
    return (int)l.LowPart;
  }
  public static string Load(string key) { return ToHex(NtLoadDriver(key)); }
  public static string WhichTok() {
    IntPtr t;
    bool thread = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, out t);
    string r = "threadToken(impersonating)=" + thread;
    if (thread) { CloseHandle(t); }
    return r;
  }
  // luidLoad/luidDebug come from LuidOf() so we compare numbers instead of resolving 30 privilege names.
  public static string TokInfo(int luidLoad, int luidDebug) {
    StringBuilder sb = new StringBuilder();
    IntPtr tok = IntPtr.Zero;
    string src = "none";
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, out tok)) { src = "thread"; }
    else {
      tok = IntPtr.Zero;
      if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out tok)) { src = "process"; }
    }
    if (tok == IntPtr.Zero) return "NO-TOKEN";
    sb.Append("src=" + src);
    // TOKEN_USER = 1 -> first field is a PSID
    int ret = 0;
    int len = 0;
    GetTokenInformation(tok, 1, IntPtr.Zero, 0, out ret);
    IntPtr bu = Marshal.AllocHGlobal(ret > 0 ? ret : 1024);
    if (GetTokenInformation(tok, 1, bu, ret > 0 ? ret : 1024, out len)) {
      IntPtr pSid = Marshal.ReadIntPtr(bu);
      IntPtr ps = IntPtr.Zero;
      if (ConvertSidToStringSidW(pSid, out ps)) { sb.Append(" user=" + Marshal.PtrToStringUni(ps)); }
      Marshal.FreeHGlobal(bu);
    } else { Marshal.FreeHGlobal(bu); sb.Append(" user=QERR"); }
    // TOKEN_PRIVILEGES = 3 -> { DWORD Count; LUID_AND_ATTRIBUTES Privileges[]; }  LUID_AND_ATTRIBUTES is
    // LUID(8 bytes: uint Low + int High) + DWORD Attributes  =>  12 byte stride, NOT 16.
    GetTokenInformation(tok, 3, IntPtr.Zero, 0, out ret);
    IntPtr bp = Marshal.AllocHGlobal(ret > 0 ? ret : 4096);
    if (GetTokenInformation(tok, 3, bp, ret > 0 ? ret : 4096, out len)) {
      int count = Marshal.ReadInt32(bp);
      bool haveLoad = false; bool enabLoad = false; bool haveDebug = false; bool enabDebug = false;
      long at = bp.ToInt64() + 4;
      int enabledCount = 0;
      for (int i = 0; i < count; i++) {
        IntPtr item = new IntPtr(at + (long)i * 12);
        int low = Marshal.ReadInt32(item);
        int attr = Marshal.ReadInt32(item, 8);
        if ((attr & 0x00000002) != 0) enabledCount++;   // SE_PRIVILEGE_ENABLED is 0x2, not 0x20
        if (low == luidLoad) { haveLoad = true; if ((attr & 0x00000002) != 0) enabLoad = true; }
        if (low == luidDebug) { haveDebug = true; if ((attr & 0x00000002) != 0) enabDebug = true; }
      }
      sb.Append(" privs=" + count + " enabled=" + enabledCount +
        " loadDrv(" + luidLoad + ")=" + haveLoad + "/on=" + enabLoad +
        " debug(" + luidDebug + ")=" + haveDebug + "/on=" + enabDebug);
      Marshal.FreeHGlobal(bp);
    } else { sb.Append(" PRIV-QERR=" + Marshal.GetLastWin32Error()); Marshal.FreeHGlobal(bp); }
    CloseHandle(tok);
    return sb.ToString();
  }
  public static string Mods(string needles) {
    IntPtr[] a = new IntPtr[4096];
    int need;
    if (!K32EnumDeviceDrivers(a, a.Length * IntPtr.Size, out need)) return "ENUMERR=" + Marshal.GetLastWin32Error();
    int count = need / IntPtr.Size;
    string[] nd = needles.Replace(',', ';').Split(';');
    StringBuilder hits = new StringBuilder();
    StringBuilder nm = new StringBuilder(300);
    for (int i = 0; i < count; i++) {
      nm.Length = 0;
      if (K32GetDeviceDriverBaseNameW(a[i], nm, nm.Capacity) <= 0) continue;
      string s = nm.ToString().ToLowerInvariant();
      for (int j = 0; j < nd.Length; j++) {
        if (s.IndexOf(nd[j].ToLowerInvariant()) >= 0) { hits.Append(s); hits.Append(','); break; }
      }
    }
    return "total=" + count + " hits=" + hits.ToString();
  }
  static int RvaToOff(int rva, byte[] b, int secOff, int numSec) {
    for (int i = 0; i < numSec; i++) {
      int s = secOff + i * 40;
      int va = (int)BitConverter.ToUInt32(b, s + 12);
      int vs = (int)BitConverter.ToUInt32(b, s + 8);
      int raw = (int)BitConverter.ToUInt32(b, s + 20);
      int rsz = (int)BitConverter.ToUInt32(b, s + 16);
      int span = vs > rsz ? vs : rsz;
      if (rva >= va && rva < va + span) return raw + (rva - va);
    }
    return -1;
  }
  // embedded Authenticode = data directory entry 4 (dd+32 rva, dd+36 size)
  public static string Cert(string path) {
    byte[] b = File.ReadAllBytes(path);
    int e = BitConverter.ToInt32(b, 0x3C);
    int numSec = BitConverter.ToUInt16(b, e + 6);
    ushort sizeOpt = BitConverter.ToUInt16(b, e + 20);
    int opt = e + 24;
    ushort magic = BitConverter.ToUInt16(b, opt);
    int dd = opt + (magic == 0x20B ? 112 : 96);
    uint crva = BitConverter.ToUInt32(b, dd + 32);
    uint csz = BitConverter.ToUInt32(b, dd + 36);
    return "magic=0x" + magic.ToString("X3") + " certRva=" + crva + " certSize=" + csz;
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 300)); return }

# ---------- 0. token / privilege state ----------
# probe74's failure is now explained WITHOUT going live: on this OS SeLoadDriverPrivilege's LUID is not 19.
# RtlAdjustPrivilege takes the LUID low part, so probe74 happily enabled some OTHER privilege, got
# STATUS_SUCCESS, and NtLoadDriver still saw no SeLoadDriverPrivilege -> 0xC0000061. Look the value up.
L '=0 token + privilege state'
$privMap = @()
foreach ($pn in @('SeLoadDriverPrivilege', 'SeIncreaseQuotaPrivilege', 'SeDebugPrivilege', 'SeSystemProfilePrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege', 'SeImpersonatePrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeAuditPrivilege', 'SeCreatePagefilePrivilege', 'SeUnlockPrivilege', 'SeProfileSingleProcessPrivilege', 'SeRaiseBasePriorityPrivilege', 'SeChangeNotifyPrivilege', 'SeCreateSymbolicLinkPrivilege')) {
  $privMap += ('{0}={1}' -f $pn.Replace('Privilege', ''), [P78]::LuidOf($pn))
}
L ('  0 LUIDS ' + (Trim2 ($privMap -join ' ') 1000))
$Luid = [P78]::LuidOf('SeLoadDriverPrivilege')
if ($Luid -lt 0) { $Luid = 10 }
$Ldbg = [P78]::LuidOf('SeDebugPrivilege')
if ($Ldbg -lt 0) { $Ldbg = 20 }
L ('  0 probe74 used index 19; this OS says SeLoadDriverPrivilege=' + $Luid + ' SeDebug=' + $Ldbg)
L ('  0 ' + [P78]::WhichTok())
L ('  0 TOKINFO-0 ' + [P78]::TokInfo($Luid, $Ldbg))
L ('  0 ADJ index=19 client=FALSE -> ' + [P78]::Enable(19, $false) + '   (what probe74 did)')
L ('  0 ADJ index=' + $Luid + ' client=FALSE -> ' + [P78]::Enable($Luid, $false))
L ('  0 ADJ index=' + $Luid + ' client=TRUE  -> ' + [P78]::Enable($Luid, $true))
L ('  0 TOKINFO-1 ' + [P78]::TokInfo($Luid, $Ldbg))

# make sure the offline reference hive is mounted (reused by every later section)
if (-not (Test-Path -LiteralPath ($REFO + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  0 refoload ' + (Trim2 ($rl -join '|') 160))
}
L ('  0 REFO is ' + $REFO + ' present=' + (Test-Path -LiteralPath ($REFO + '\ControlSet001\Services')))
L ('  0 MODULES-0 ' + [P78]::Mods('netwtw14,nwifi,vwififlt,vwifimp,ndisimplatform,wdiwifi,werkernel'))

# ---------- 1. NtLoadDriver with the CORRECT privilege index ----------
L '=1 NtLoadDriver direct'
# The first two are controls: inbox drivers that are not resident in this PE yet. If a control loads, the
# mechanism works and every failure after it is a real answer, not a token artifact.
$targets = @(
  @{ n = 'ndisuio';        stage = $false },
  @{ n = 'ndiscap';        stage = $false },
  @{ n = 'Netwtw14';       stage = $false },
  @{ n = 'nativewifip';    stage = $false },
  @{ n = 'vwififlt';       stage = $false },
  @{ n = 'NdisImPlatform'; stage = $true },
  @{ n = 'wdiwifi';        stage = $true }
)
$NEED = 'netwtw14,nwifi,vwififlt,vwifimp,ndisimplatform,wdiwifi,ndisuio,ndiscap'
function ResolveImg([string]$key) {
  $ip = VOf $key 'ImagePath'
  if ($ip -eq 'ABSENT') { return 'NO-IMAGEPATH' }
  $cand = @()
  $p = $ip
  if ($p -match '(?i)^\\SystemRoot') { $cand += ('X:\Windows' + $p.Substring(11)) }
  elseif ($p -match '(?i)^\\') { $cand += ('X:\Windows\System32\drivers\' + $p.Split('\')[-1]) }
  elseif ($p -match '(?i)^[A-Za-z]:\\') { $cand += $p }
  else { $cand += ('X:\Windows\' + $p); $cand += ('X:\' + $p) }
  foreach ($c in $cand) { if (Test-Path -LiteralPath $c) { return $c + ' EXISTS' } }
  return ($cand[0] + ' MISSING')
}
foreach ($t in $targets) {
  $n = $t.n
  $pk = $CS + '\' + $n
  L ('  1 PRE ' + (Trim2 $n 16) + ' key=' + (Test-Path -LiteralPath $pk) + ' Type=' + (VOf $pk 'Type') + ' Start=' + (VOf $pk 'Start') + ' grp=' + (Trim2 (VOf $pk 'Group') 22) + ' depend=' + (Trim2 (VOf $pk 'DependOnService') 40) + ' img=' + (Trim2 (ResolveImg $pk) 96))
  # for the two images the PE image lacks, build the runtime registration the way the bake would:
  # exact offline key (reg copy keeps the real service SD + Parameters subkey) + the offline .sys file.
  if ($t.stage -and -not (Test-Path -LiteralPath $pk)) {
    $rc = @(& reg.exe copy ($REFO.Replace('HKLM:\', 'HKLM\') + '\ControlSet001\Services\' + $n) ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) '/s' '/f' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
    L ('  1 regcopy ' + $n + ' -> ' + (Trim2 ($rc -join '|') 120))
    $pk2 = $CS + '\' + $n
    L ('  1 copied key now=' + (Test-Path -LiteralPath $pk2) + ' Type=' + (VOf $pk2 'Type') + ' Start=' + (VOf $pk2 'Start') + ' img=' + (Trim2 (ResolveImg $pk2) 96))
  }
  if ($t.stage) {
    $imgX = 'X:\Windows\System32\drivers\' + $n + '.sys'
    if (-not (Test-Path -LiteralPath $imgX)) {
      $srcN = 'D:\Windows\System32\drivers\' + $n + '.sys'
      if (Test-Path -LiteralPath $srcN) {
        $qq = [char]34
        $cp = @(& cmd.exe /c ('copy /y ' + $qq + $srcN + $qq + ' ' + $qq + 'X:\Windows\System32\drivers\' + $qq) 2>&1 | ForEach-Object { (Clean ('' + $_)) })
        L ('  1 stage ' + $n + '.sys -> ' + (Trim2 ($cp -join '|') 120) + ' now=' + (Test-Path -LiteralPath $imgX))
      } else { L ('  1 stage ' + $n + '.sys NO SOURCE') }
    }
  }
  $st = [P78]::Load($REGCS + '\' + $n)
  L ('  1 LOAD ' + (Trim2 $n 16) + ' -> ' + $st)
  L ('  1   ' + [P78]::Mods($NEED) + ' svcState=' + $n + '=' + (St $n))
}

# ---------- 1b. if any of that moved the needle, ask PnP to re-bind the AX211 ----------
L '=1b restart-device after the load attempts'
$devId = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$rs = @(& pnputil.exe /restart-device ($devId) 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  1b RESTART ' + (Trim2 ($rs -join '|') 200))
Start-Sleep -Seconds 6
$d = @(Get-PnpDevice -InstanceId $devId -EA SilentlyContinue)
if ($d.Count -eq 0) {
  $d = @(Get-CimInstance -ClassName Win32_PnPEntity -Query ('SELECT * FROM Win32_PnPEntity WHERE DeviceID="' + $devId + '"') -EA SilentlyContinue)
}
foreach ($x in $d) {
  $pc = 'n/a'
  try { $pc = '' + $x.ConfigManagerErrorCode } catch { }
  L ('  1b DEV code=' + $pc + ' status=' + (Trim2 ('' + $x.Status) 20) + ' name=' + (Trim2 ('' + $x.Name) 40))
}
$pr = @(Get-PnpDeviceProperty -InstanceId $devId -KeyName 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_ProblemStatus' -EA SilentlyContinue)
foreach ($p2 in $pr) { L ('  1b PROP ' + (Trim2 ('' + $p2.KeyName) 34) + '=' + (Trim2 ('' + $p2.Data) 40)) }
L ('  1b ' + [P78]::Mods('netwtw14,nwifi,vwififlt,vwifimp,ndisimplatform,wdiwifi'))
foreach ($s in @('Netwtw14', 'nativewifip', 'vwififlt', 'vwifibus', 'NdisImPlatform', 'wdiwifi', 'wlansvc')) {
  L ('  1b svc ' + (Trim2 $s 16) + '=' + (St $s))
}
$ad = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.PhysicalAdapter })
foreach ($a in $ad) { L ('  1b ADAPTER ' + (Trim2 ('' + $a.Name) 34) + ' svc=' + (Trim2 ('' + $a.ServiceName) 16) + ' enabled=' + $a.NetEnabled + ' mac=' + (Trim2 ('' + $a.MACAddress) 20)) }

# ---------- 2. does the PE keep an event log we can read? (Kernel-PnP 219 would name the status) ----------
L '=2 event log'
$wv = @(Get-Command wevtutil.exe -EA SilentlyContinue)
L ('  2 wevtutil=' + ($wv.Count))
foreach ($what in @('System', 'Microsoft-Windows-Kernel-PnP/Admin', 'Microsoft-Windows-Kernel-PnP/Debug', 'Microsoft-Windows-NDIS/Pefetch', 'Microsoft-Windows-DriverLoad/Debug')) {
  $got = @()
  $err = ''
  try {
    $got = @(Get-WinEvent -LogName $what -MaxEvents 40 -EA Stop)
  } catch { $err = '' + $_.Exception.Message }
  if ($got.Count -eq 0) { L ('  2 ' + (Trim2 $what 42) + ' none (' + (Trim2 $err 90) + ')'); continue }
  $hit = @($got | Where-Object { (Clean ('' + $_.Message)) -match '(?i)netwtw|wifi|ndis|driver.*load|pnp' } | Select-Object -First 6)
  L ('  2 ' + (Trim2 $what 42) + ' total=' + $got.Count + ' hits=' + $hit.Count)
  foreach ($ev in $hit) { L ('  2   [' + $ev.Id + ' ' + $ev.LevelDisplayName + '] ' + (Trim2 ('' + $ev.Message) 230)) }
}

# ---------- 3. full service dumps: broken miniport vs the WORKING wired one vs the offline reference ------
L '=3 full service value dumps'
function DumpSrv([string]$label, [string]$key) {
  if (-not (Test-Path -LiteralPath $key)) { L ('  3 ' + $label + ' ABSENT'); return }
  $ki = Get-Item -LiteralPath $key
  $names = @($ki.GetValueNames())
  L ('  3 ' + $label + ' values=' + $names.Count + ' subs=[' + (@($ki.GetSubKeyNames()) -join ',') + ']')
  foreach ($vn in (@($names | Sort-Object))) {
    $kind = 'ERR'
    try { $kind = '' + $ki.GetValueKind($vn) } catch { }
    $rawv = $ki.GetValue($vn)
    $txt = ''
    if ($rawv -is [byte[]]) { $txt = 'blob(' + $rawv.Length + 'B)' } else { $txt = '' + ($rawv -join ';') }
    if ($txt.Length -gt 150) { $txt = $txt.Substring(0, 150) + '...' }
    L ('  3   ' + (Trim2 $vn 26) + ' [' + (Trim2 $kind 12) + '] ' + (Clean $txt))
  }
  foreach ($sk in @($ki.GetSubKeyNames())) {
    if ($sk -eq 'Security') { continue }
    $sub = Get-Item -LiteralPath ($key + '\' + $sk)
    $sv = @($sub.GetValueNames())
    L ('  3   SUB ' + $sk + ' values=[' + ($sv -join ',') + ']')
    foreach ($vn in $sv) {
      $vv = '' + ($sub.GetValue($vn) -join ';')
      L ('  3     ' + (Trim2 $vn 34) + ' ' + (Trim2 $vv 220))
    }
  }
}
DumpSrv 'PE Netwtw14' ($CS + '\Netwtw14')
DumpSrv 'PE rt640x64(WORKS)' ($CS + '\rt640x64')
DumpSrv 'OFF Netwtw14' ($REFO + '\ControlSet001\Services\Netwtw14')
DumpSrv 'PE nativewifip' ($CS + '\nativewifip')
DumpSrv 'OFF nativewifip' ($REFO + '\ControlSet001\Services\nativewifip')

# ---------- 4. bake list, done right this time (no $ofF/$OFF collision) ----------
L '=4 bake list'
foreach ($s in @('nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'NdisImPlatform', 'wdiwifi', 'NdisVirtualBus', 'WlanSvc', 'NdisUpnp', 'ndiscap')) {
  $pk = $CS + '\' + $s
  $ok = $REFO + '\ControlSet001\Services\' + $s
  $inPE = Test-Path -LiteralPath $pk
  $inOFF = Test-Path -LiteralPath $ok
  $peLine = 'PE=' + $inPE
  if ($inPE) { $peLine += '(' + (VOf $pk 'Type') + '/' + (VOf $pk 'Start') + '/' + (St $s) + ')' }
  $offLine = 'OFF=' + $inOFF
  if ($inOFF) { $offLine += '(' + (VOf $ok 'Type') + '/' + (VOf $ok 'Start') + '/grp=' + (Trim2 (VOf $ok 'Group') 28) + '/dep=' + (Trim2 (VOf $ok 'DependOnService') 40) + ')' }
  L ('  4 SVC ' + (Trim2 $s 16) + ' ' + $peLine + ' ' + $offLine)
}
foreach ($f in @('nwifi.sys', 'vwififlt.sys', 'vwifibus.sys', 'vwifimp.sys', 'NdisImPlatform.sys', 'wdiwifi.sys', 'ndisuio.sys', 'werkernel.sys')) {
  $xp = Test-Path -LiteralPath ('X:\Windows\System32\drivers\' + $f)
  $dp = 'D:\Windows\System32\drivers\' + $f
  $haveD = Test-Path -LiteralPath $dp
  $sz = 'n/a'
  if ($haveD) { $sz = '' + (Get-Item -LiteralPath $dp).Length }
  L ('  4 FILE ' + (Trim2 $f 20) + ' X=' + $xp + ' D=' + $haveD + ' Dbytes=' + $sz)
}

# ---------- 5. covering catalogs the offline OS itself uses (INF CatalogFile -> the .cat beside it) ----------
L '=5 offline package/catalog lookup'
$store = 'D:\Windows\System32\DriverStore\FileRepository'
L ('  5 store dir=' + (Test-Path -LiteralPath $store))
if (Test-Path -LiteralPath $store) {
  $allDirs = @(Get-ChildItem -LiteralPath $store -Directory -EA SilentlyContinue)
  L ('  5 packages=' + $allDirs.Count)
  $pick = @($allDirs | Where-Object { $_.Name -match '(?i)implat|wdiwifi|wifi|ndis|wlan|vwifi' })
  L ('  5 picked=' + $pick.Count)
  foreach ($d in @($pick | Select-Object -First 22)) {
    $cats = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.cat' -File -EA SilentlyContinue | ForEach-Object { $_.Name })
    $infs = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.inf' -File -EA SilentlyContinue)
    $cfv = ''
    foreach ($i2 in $infs) {
      $txt = @(Get-Content -LiteralPath $i2.FullName -Encoding Unicode -EA SilentlyContinue | Select-Object -First 60)
      $m = @($txt | Where-Object { $_ -match '(?i)^\s*CatalogFile' })
      if ($m.Count) { $cfv = ($m -join ';') }
    }
    $sysn = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.sys' -File -EA SilentlyContinue | ForEach-Object { $_.Name })
    L ('  5 PKG ' + (Trim2 $d.Name 54) + ' inf=' + (@($infs | ForEach-Object { $_.Name }) -join ',') + ' cat=' + ($cats -join ',') + ' CatalogFile=' + (Trim2 $cfv 60) + ' sys=' + (Trim2 ($sysn -join ',') 70))
  }
}
# embedded signatures decide whether a bare .sys even needs a catalog: inbox drivers that carry one are fine
foreach ($f in @('NdisImPlatform.sys', 'wdiwifi.sys', 'nwifi.sys', 'vwififlt.sys', 'vwifibus.sys', 'vwifimp.sys')) {
  $dp = 'D:\Windows\System32\drivers\' + $f
  if (-not (Test-Path -LiteralPath $dp)) { L ('  5 SIG ' + $f + ' NOFILE'); continue }
  L ('  5 SIG ' + (Trim2 $f 18) + ' ' + [P78]::Cert($dp))
}

# ---------- 6. NdisImPlatform Parameters allow/block lists (needed verbatim in the bake) ----------
L '=6 NdisImPlatform + wdiwifi offline detail'
foreach ($s in @('NdisImPlatform', 'wdiwifi')) {
  $ok = $REFO + '\ControlSet001\Services\' + $s
  if (-not (Test-Path -LiteralPath $ok)) { L ('  6 ' + $s + ' OFF ABSENT'); continue }
  DumpSrv ('OFF ' + $s) $ok
}
L 'P78 END'
