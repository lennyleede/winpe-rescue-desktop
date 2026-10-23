# probe79 -- LIVE PE. probe78 delivered two hard results and one self-inflicted wound:
#   RESULT A (the PE-refusal mystery is over): DEVPKEY_Device_ProblemStatus on the AX211 devnode is
#     3221225659 = 0xC00000BB = STATUS_NOT_SUPPORTED, i.e. the driver ENTRY itself refuses, and code 37 is
#     CM_PROB_FAILED_DRIVER_ENTRY. Services\Netwtw14\Enum carries INITSTARTFAILED=1 while the working
#     Realtek key does not. So this is not a binding/registry/filter problem at all.
#   RESULT B (probe74's 0xC0000061 explained): the PE shell IS SYSTEM (S-1-5-18) with 31 privileges and
#     SeLoadDriverPrivilege present-but-disabled. Its LUID low part is 10, NOT 19 -- 19 is
#     SeShutdownPrivilege, which is what probe74 "successfully" enabled. With index 10 the privilege now
#     reads enabled on the process token (no impersonation token in this session: client=TRUE -> 0xC000007C).
#   THE WOUND: every NtLoadDriver call in probe78 returned 0x80000002 (STATUS_DATATYPE_MISALIGNMENT)
#     including the controls, because NtLoadDriver takes a PUNICODE_STRING, not a string pointer. This probe
#     marshals it correctly, so the kernel can finally answer: does wdiwifi/NdisImPlatform load on demand,
#     and is Netwtw14's 0xC00000BB reproducible outside PnP?
#   THE MAIN QUESTION: modern Wi-Fi miniports register with the Windows Wi-Fi Driver Framework (wdiwifi.sys)
#     through NDIS's NdisWifiHost* APIs. The PE image HAS NO wdiwifi at all (probe77). If Netwtw14 imports
#     NdisWifiHost* and rt640x64 (which works here) does not, a missing wdiwifi explains a Wi-Fi-only
#     STATUS_NOT_SUPPORTED at driver entry -- and the bake becomes the fix rather than a long shot.
# NAMES: PowerShell variables are case-insensitive (probe77 lost $OFF to a loop var called $ofF), so the
# offline prefix is $REFO and no other name here shares it.
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
$NEED = 'netwtw14,nwifi,vwififlt,vwifimp,ndisimplatform,wdiwifi,ndisuio,werkernel'
$DEV = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'

try {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class P79 {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool K32EnumDeviceDrivers(IntPtr[] lpp, int cb, out int needed);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern int K32GetDeviceDriverBaseNameW(IntPtr drv, StringBuilder buf, int count);
  [DllImport("ntdll.dll")]
  static extern int RtlAdjustPrivilege(int priv, bool enable, bool client, out bool old);
  // NOTE: PCUNICODE_STRING, so take an IntPtr to a {ushort Length; ushort MaximumLength; IntPtr Buffer}.
  [DllImport("ntdll.dll")]
  static extern int NtLoadDriver(IntPtr uni);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool OpenProcessToken(IntPtr p, uint access, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, ref LUID_AND_ATTRIBUTES newState, uint bufLen, IntPtr prev, out IntPtr retLen);
  [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
  const uint TOKEN_ADJUST = 0x0020;
  const uint TOKEN_QUERY = 0x0008;
  const uint SE_PRIVILEGE_ENABLED = 0x00000002;
  [StructLayout(LayoutKind.Sequential)]
  struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
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
  static string StrAt(byte[] b, int off) {
    StringBuilder sb = new StringBuilder();
    while (off >= 0 && off < b.Length && b[off] != 0) { sb.Append((char)b[off]); off++; }
    return sb.ToString();
  }
  static int Header(byte[] b, out int dd, out int secOff, out int numSec) {
    int e = BitConverter.ToInt32(b, 0x3C);
    numSec = BitConverter.ToUInt16(b, e + 6);
    ushort sizeOpt = BitConverter.ToUInt16(b, e + 20);
    int opt = e + 24;
    ushort magic = BitConverter.ToUInt16(b, opt);
    dd = opt + (magic == 0x20B ? 112 : 96);
    secOff = opt + sizeOpt;
    return magic;
  }
  public static string ToHex(int s) {
    uint u = (uint)s;
    return HexTail(u);
  }
  public static string ToHexU(string dec) {
    uint u;
    if (!uint.TryParse(dec, out u)) return "not-decimal(" + dec + ")";
    return HexTail(u);
  }
  static string HexTail(uint u) {
    string n = "";
    if (u == 0u) n = " OK";
    else if (u == 0xC0000061u) n = " PRIVILEGE_NOT_HELD";
    else if (u == 0xC00000BBu) n = " NOT_SUPPORTED";
    else if (u == 0xC0000034u) n = " OBJECT_NAME_NOT_FOUND";
    else if (u == 0xC0000035u) n = " OBJECT_NAME_COLLISION";
    else if (u == 0xC000000Eu) n = " INVALID_PARAMETER";
    else if (u == 0xC0000033u) n = " OBJECT_NAME_INVALID";
    else if (u == 0xC00000F4u) n = " INFO_LENGTH_MISMATCH";
    else if (u == 0xC0000428u) n = " INVALID_IMAGE_HASH(CI)";
    else if (u == 0xC0000001u) n = " UNSUCCESSFUL";
    else if (u == 0xC0000022u) n = " ACCESS_DENIED";
    else if (u == 0xC0000185u) n = " INVALID_DEVICE_STATE";
    else if (u == 0x80000002u) n = " DATATYPE_MISALIGNMENT";
    else if (u == 0x80000001u) n = " GUARD_PAGE";
    return "0x" + u.ToString("X8") + n;
  }
  // 1. privilege: do it the documented way (AdjustTokenPrivileges on the process token) AND RtlAdjust,
  //    then report both so a failure is unambiguous.
  public static string Enable(int luidLow) {
    bool old;
    int a = RtlAdjustPrivilege(luidLow, true, false, out old);
    IntPtr tok;
    string b = "noTok";
    if (OpenProcessToken((IntPtr)(-1), TOKEN_ADJUST | TOKEN_QUERY, out tok)) {
      LUID_AND_ATTRIBUTES laa = new LUID_AND_ATTRIBUTES();
      laa.Luid.LowPart = (uint)luidLow; laa.Luid.HighPart = 0; laa.Attributes = SE_PRIVILEGE_ENABLED;
      IntPtr rl;
      bool ok = AdjustTokenPrivileges(tok, false, ref laa, 0, IntPtr.Zero, out rl);
      b = (ok ? "adj" : "adjFail") + " lasterr=" + Marshal.GetLastWin32Error();
    }
    return "rtl=" + ToHex(a) + " " + b;
  }
  public static string Load(string key) {
    byte[] raw = Encoding.Unicode.GetBytes(key);
    IntPtr buf = Marshal.AllocHGlobal(raw.Length + 2);
    Marshal.Copy(raw, 0, buf, raw.Length);
    Marshal.WriteInt16(buf, (short)0);
    UNICODE_STRING u = new UNICODE_STRING();
    u.Length = (ushort)raw.Length;
    u.MaximumLength = (ushort)(raw.Length + 2);
    u.Buffer = buf;
    GCHandle gh = GCHandle.Alloc(u, GCHandleType.Pinned);
    int st = NtLoadDriver(gh.AddrOfPinnedObject());
    gh.Free();
    Marshal.FreeHGlobal(buf);
    return ToHex(st);
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
  // 2. imported SYMBOL names for one DLL (case-insensitive substring match on the dll name)
  public static string[] ImportSymbols(string path, string dllPart) {
    List<string> l = new List<string>();
    byte[] b = File.ReadAllBytes(path);
    int dd, secOff, numSec;
    int magic = Header(b, out dd, out secOff, out numSec);
    uint impRva = BitConverter.ToUInt32(b, dd + 8);
    if (impRva == 0) return l.ToArray();
    int io = RvaToOff((int)impRva, b, secOff, numSec);
    if (io < 0) return l.ToArray();
    int tsz = magic == 0x20B ? 8 : 4;
    long hi = tsz == 8 ? long.MinValue : (long)0x80000000L;
    for (int d = 0; d < 40; d++) {
      int ent = io + d * 20;
      if (ent + 20 > b.Length) break;
      int oft = BitConverter.ToInt32(b, ent);
      int nameRva = BitConverter.ToInt32(b, ent + 12);
      int ft = BitConverter.ToInt32(b, ent + 16);
      if (oft == 0 && nameRva == 0 && ft == 0) break;
      string dll = StrAt(b, RvaToOff(nameRva, b, secOff, numSec));
      if (dll.ToLowerInvariant().IndexOf(dllPart.ToLowerInvariant()) < 0) continue;
      int thunkRva = oft != 0 ? oft : ft;
      int to = RvaToOff(thunkRva, b, secOff, numSec);
      if (to < 0) continue;
      for (int k = 0; k < 4000; k++) {
        int off = to + k * tsz;
        if (off + tsz > b.Length) break;
        long th = tsz == 8 ? BitConverter.ToInt64(b, off) : (long)(uint)BitConverter.ToInt32(b, off);
        if (th == 0) break;
        if ((th & hi) != 0) { l.Add("#ordinal" + (th & 0xFFFF)); continue; }
        int no = RvaToOff((int)(th & 0x7FFFFFFFL), b, secOff, numSec);
        if (no < 0) continue;
        string sym = StrAt(b, no + 2);
        if (sym.Length > 0) l.Add(sym);
      }
    }
    return l.ToArray();
  }
  public static HashSet<string> Exports(string path) {
    HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    byte[] b = File.ReadAllBytes(path);
    int dd, secOff, numSec;
    Header(b, out dd, out secOff, out numSec);
    uint expRva = BitConverter.ToUInt32(b, dd);
    if (expRva == 0) return set;
    int eo = RvaToOff((int)expRva, b, secOff, numSec);
    if (eo < 0) return set;
    int numNames = BitConverter.ToInt32(b, eo + 24);
    int namesRva = BitConverter.ToInt32(b, eo + 32);
    int no = RvaToOff(namesRva, b, secOff, numSec);
    if (no < 0) return set;
    for (int i = 0; i < numNames; i++) {
      int off = RvaToOff(BitConverter.ToInt32(b, no + i * 4), b, secOff, numSec);
      if (off < 0) continue;
      string s = StrAt(b, off);
      if (s.Length > 0) set.Add(s);
    }
    return set;
  }
  // 3. plain-text scan for a marker (PE refuses MiniNT? look for the literal)
  public static string FindText(string path, object[] needles) {
    byte[] b = File.ReadAllBytes(path);
    string a = Encoding.ASCII.GetString(b);
    string u = Encoding.Unicode.GetString(b);
    StringBuilder sb = new StringBuilder();
    foreach (object o in needles) {
      string nd = o == null ? "" : o.ToString();
      bool inA = a.IndexOf(nd, StringComparison.Ordinal) >= 0;
      bool inU = u.IndexOf(nd, StringComparison.Ordinal) >= 0;
      sb.Append(nd + (inA ? "/A" : "") + (inU ? "/U" : "") + " ");
    }
    return sb.ToString().Trim();
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 300)); return }

# ---------- 0. privilege, the honest way, then NtLoadDriver with a real UNICODE_STRING ----------
L '=0 privilege + corrected NtLoadDriver'
$Luid = 10
L ('  0 ' + [P79]::Enable($Luid))
if (-not (Test-Path -LiteralPath ($REFO + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  0 refoload ' + (Trim2 ($rl -join '|') 160))
}
L ('  0 MODULES-0 ' + [P79]::Mods($NEED))
$targets = @('ndisuio', 'vwififlt', 'nativewifip', 'NdisImPlatform', 'wdiwifi', 'Netwtw14')
foreach ($n in $targets) {
  $pk = $CS + '\' + $n
  $imgX = 'X:\Windows\System32\drivers\' + $n + '.sys'
  if (-not (Test-Path -LiteralPath $pk)) {
    $rc = @(& reg.exe copy ($REFO.Replace('HKLM:\', 'HKLM\') + '\ControlSet001\Services\' + $n) ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) '/s' '/f' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
    L ('  0 regcopy ' + $n + ' -> ' + (Trim2 ($rc -join '|') 100))
  }
  if (-not (Test-Path -LiteralPath $imgX)) {
    $srcN = 'D:\Windows\System32\drivers\' + $n + '.sys'
    if (Test-Path -LiteralPath $srcN) {
      $qq = [char]34
      $cp = @(& cmd.exe /c ('copy /y ' + $qq + $srcN + $qq + ' ' + $qq + 'X:\Windows\System32\drivers\' + $qq) 2>&1 | ForEach-Object { (Clean ('' + $_)) })
      L ('  0 stage ' + $n + '.sys -> ' + (Trim2 ($cp -join '|') 90))
    }
  }
  $line = '  0 ' + (Trim2 $n 16) + ' key=' + (Test-Path -LiteralPath $pk) + ' Type=' + (VOf $pk 'Type') + ' Start=' + (VOf $pk 'Start') + ' img=' + (Trim2 (VOf $pk 'ImagePath') 60) + ' file=' + (Test-Path -LiteralPath $imgX)
  $st = [P79]::Load($REGCS + '\' + $n)
  L ($line + ' LOAD -> ' + $st)
  L ('  0   ' + [P79]::Mods($NEED))
}

# ---------- 1. the discriminator: Wi-Fi-framework imports, miniport vs the working wired driver ----------
L '=1 import symbol compare'
$drvList = @(
  'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys',
  'X:\Windows\System32\drivers\rt640x64.sys',
  'X:\Windows\System32\drivers\nwifi.sys',
  'X:\Windows\System32\drivers\vwififlt.sys',
  'X:\Windows\System32\drivers\NdisImPlatform.sys',
  'D:\Windows\System32\drivers\wdiwifi.sys'
)
$PAT = '(?i)wifi|wdi|IsSystemWindowsPE|PsGetVersion|RtlGetVersion|QuerySystemInformation|MiniNt|WdfRequest|RegisterMiniport'
foreach ($p in $drvList) {
  if (-not (Test-Path -LiteralPath $p)) { L ('  1 ' + (Trim2 $p 76) + ' MISSING'); continue }
  $fn = $p.Split('\')[-1]
  foreach ($dl in @('ntoskrnl', 'ndis')) {
    $syms = @([P79]::ImportSymbols($p, $dl))
    $m = @($syms | Where-Object { $_ -match $PAT })
    L ('  1 ' + (Trim2 $fn 20) + ' <- ' + (Trim2 $dl 10) + ' n=' + $syms.Count + ' interesting=' + (Trim2 ($m -join ',') 220))
  }
}
# who EXPORTS the Wi-Fi host APIs? if ndis.sys is the provider, wdiwifi must be resident for the thunk.
$ndExp = @([P79]::Exports('X:\Windows\System32\drivers\ndis.sys'))
$wf = @($ndExp | Where-Object { $_ -match '(?i)wifi|wdi' })
L ('  1 ndis.sys exports=' + $ndExp.Count + ' wifi-ish=' + $wf.Count + ' [' + (Trim2 ($wf -join ',') 300) + ']')
foreach ($c in @('X:\Windows\System32\drivers\wdiwifi.sys', 'X:\Windows\System32\wdiwifi.sys', 'X:\Windows\System32\drivers\NdisImPlatform.sys')) {
  if (Test-Path -LiteralPath $c) {
    $e = @([P79]::Exports($c))
    L ('  1 ' + (Trim2 $c 60) + ' exports=' + $e.Count + ' wifi-ish=[' + (Trim2 (@($e | Where-Object { $_ -match '(?i)wifi|wdi' }) -join ',') 200) + ']')
  } else { L ('  1 ' + (Trim2 $c 60) + ' MISSING') }
}

# ---------- 2. is this machine's driver entry refusal visible to PnP right now? ----------
L '=2 devnode status after the manual loads'
$rs = @(& pnputil.exe /restart-device $DEV 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  2 RESTART ' + (Trim2 ($rs -join '|') 180))
Start-Sleep -Seconds 8
$pp = @(Get-PnpDeviceProperty -InstanceId $DEV -KeyName 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_ProblemStatus', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverDate', 'DEVPKEY_Device_BusyRestarted' -EA SilentlyContinue)
foreach ($e in $pp) {
  $dv = '' + $e.Data
  if ($e.KeyName -eq 'DEVPKEY_Device_ProblemStatus') { $dv = $dv + ' -> ' + [P79]::ToHexU('' + $e.Data) }
  L ('  2 ' + (Trim2 ('' + $e.KeyName) 34) + ' = ' + (Trim2 $dv 70))
}
L ('  2 ' + [P79]::Mods($NEED))
L ('  2 INITSTARTFAILED=' + (VOf ($CS + '\Netwtw14\Enum') 'INITSTARTFAILED') + ' Netwtw14=' + (St 'Netwtw14') + ' wlansvc=' + (St 'wlansvc'))

# ---------- 3. MiniNT / PE markers + text scan of the two drivers ----------
L '=3 MiniNT markers + text scan'
foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT', 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot', 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager')) {
  $ki2 = Get-Item -LiteralPath $k -EA SilentlyContinue
  $vlist = 'NOKEY'
  if ($ki2) { $vlist = (@($ki2.GetValueNames()) -join ',') }
  L ('  3 KEY ' + (Trim2 $k 56) + ' exists=' + ($null -ne $ki2) + ' values=' + (Trim2 $vlist 200))
}
$mn = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT' -EA SilentlyContinue
if ($mn) { foreach ($vn in @($mn.GetValueNames())) { L ('  3 MiniNT ' + $vn + '=' + (Trim2 ('' + ($mn.GetValue($vn) -join ';')) 120)) } }
$needles = @('MiniNT', 'IoIsSystemWindowsPE', 'Windows PE', 'wdiwifi', 'NdisWifiHost', 'System32\Drivers\wdiwifi')
foreach ($p in @('X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys',
                 'X:\Windows\System32\drivers\rt640x64.sys',
                 'X:\Windows\System32\drivers\nwifi.sys')) {
  if (-not (Test-Path -LiteralPath $p)) { continue }
  L ('  3 TXT ' + (Trim2 ($p.Split('\')[-1]) 16) + ' ' + [P79]::FindText($p, $needles))
}

# ---------- 4. what the offline OS has that this image has not ----------
L '=4 offline vs PE stack'
foreach ($n in @('ndisuio', 'NdisImPlatform', 'wdiwifi', 'ndiscap', 'NativeWifiP', 'WlanSvc', 'wcmsvc')) {
  $pk = $CS + '\' + $n
  $ok = $REFO + '\ControlSet001\Services\' + $n
  $pn = Test-Path -LiteralPath $pk
  $on = Test-Path -LiteralPath $ok
  $img = 'X:\Windows\System32\drivers\' + $n + '.sys'
  $hasImg = Test-Path -LiteralPath $img
  L ('  4 ' + (Trim2 $n 15) + ' PEkey=' + $pn + ' OFFkey=' + $on + ' PEsys=' + $hasImg + ' OFFgrp=' + (Trim2 (VOf $ok 'Group') 14) + ' OFFstart=' + (VOf $ok 'Start') + ' OFFdepend=' + (Trim2 (VOf $ok 'DependOnService') 60))
}
foreach ($c in @('X:\Windows\System32\drivers\NdisImPlatform.sys', 'X:\Windows\System32\drivers\wdiwifi.sys')) {
  if (Test-Path -LiteralPath $c) {
    $e = @([P79]::Exports($c))
    $imp = @([P79]::ImportSymbols($c, 'ndis'))
    L ('  4 staged ' + (Trim2 $c 50) + ' ndisExports=' + $e.Count + ' importsFromNdis=' + $imp.Count + ' [' + (Trim2 (@($imp | Where-Object { $_ -match '(?i)wifi|Host|Register' }) -join ',') 200) + ']')
  }
}
L 'P79 END'
