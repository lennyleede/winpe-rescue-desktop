# probe74 -- LIVE PE, follow-up to probe73. probe73 narrowed the failure to the MINIPORT itself:
#   device code 37 = CM_PROB_FAILED_DRIVER (its service Netwtw14 never starts), and StartService on a
#   PnP-managed service only gives err=50 (no information). probe72 showed nativewifip/vwififlt give err=31
#   while 5 unrelated drivers start fine.
# probe73's "CERT" numbers were WRONG: I read data-directory entry 1 (import table) instead of entry 4
#   (certificate), so the Authenticode conclusion is void and is redone here with the correct offset.
# Two safe questions now decide the root cause:
#   Q1 is Netwtw14.sys (and nwifi/vwififlt) even LOADED into the kernel?  EnumDeviceDrivers answers this with
#      zero risk. Not loaded + imports resolve => code integrity / catalog. Not loaded + import missing => the
#      19041-era stack needs an entry point the 26100 kernel no longer exports. Loaded => failure is at PnP
#      start (firmware / NDIS), a different class of problem.
#   Q2 does the PE registry copy of these services lack values the working (offline) hive has?
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$OFF = 'HKLM:\R8OFF'
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }

try {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class P74 {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool K32EnumDeviceDrivers(IntPtr[] lpp, int cb, out int needed);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern int K32GetDeviceDriverBaseNameW(IntPtr drv, StringBuilder buf, int count);
  [DllImport("ntdll.dll")]
  static extern int RtlAdjustPrivilege(int priv, bool enable, bool client, out bool old);
  [DllImport("ntdll.dll")]
  static extern int NtLoadDriver(string key);

  public static string EnablePriv() {
    bool old;
    int s = RtlAdjustPrivilege(19, true, false, out old);   // 19 = SeLoadDriverPrivilege
    return "rtl=" + ToHex(s);
  }
  public static string Load(string key) { return "status=" + ToHex(NtLoadDriver(key)); }
  static string ToHex(int s) {
    uint u = (uint)s;
    string n = "";
    if (u == 0x00000000) n = " OK";
    else if (u == 0xC0000035) n = " ALREADY_LOADED";
    else if (u == 0xC0000139) n = " ENTRYPOINT_NOT_FOUND";
    else if (u == 0xC0000135) n = " DLL_NOT_FOUND";
    else if (u == 0xC0000428) n = " SIGNATURE_UNTRUSTED";
    else if (u == 0xC0000242) n = " CERT_DISCONTINUED";
    else if (u == 0xC0000001) n = " UNSUCCESSFUL";
    else if (u == 0xC0000022) n = " ACCESS_DENIED";
    else if (u == 0xC0000034) n = " NOT_FOUND";
    else if (u == 0xC00000BB) n = " NOT_SUPPORTED(dev)";
    return "0x" + u.ToString("X8") + n;
  }
  // list loaded kernel modules whose name contains any needle
  public static string Mods(string needlesCsv) {
    IntPtr[] a = new IntPtr[4096];
    int need;
    if (!K32EnumDeviceDrivers(a, a.Length * IntPtr.Size, out need)) return "ENUMERR=" + Marshal.GetLastWin32Error();
    int count = need / IntPtr.Size;
    string[] nd = needlesCsv.Replace(',', ';').Split(';');
    StringBuilder hits = new StringBuilder();
    StringBuilder nm = new StringBuilder(300);
    for (int i = 0; i < count; i++) {
      nm.Length = 0;
      int r = K32GetDeviceDriverBaseNameW(a[i], nm, nm.Capacity);
      if (r <= 0) continue;
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
  static string StrAt(byte[] b, int off) {
    StringBuilder sb = new StringBuilder();
    while (off >= 0 && off < b.Length && b[off] != 0) { sb.Append((char)b[off]); off++; }
    return sb.ToString();
  }

  // export names of a PE file (driver or dll); empty if no export dir
  public static HashSet<string> Exports(string path) {
    HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    byte[] b = File.ReadAllBytes(path);
    int e = BitConverter.ToInt32(b, 0x3C);
    int numSec = BitConverter.ToUInt16(b, e + 6);
    ushort sizeOpt = BitConverter.ToUInt16(b, e + 20);
    int opt = e + 24;
    ushort magic = BitConverter.ToUInt16(b, opt);
    int dd = opt + (magic == 0x20B ? 112 : 96);
    uint expRva = BitConverter.ToUInt32(b, dd);
    if (expRva == 0) return set;
    int secOff = opt + sizeOpt;
    int eo = RvaToOff((int)expRva, b, secOff, numSec);
    if (eo < 0) return set;
    int numNames = BitConverter.ToInt32(b, eo + 24);
    int namesRva = BitConverter.ToInt32(b, eo + 32);
    int no = RvaToOff(namesRva, b, secOff, numSec);
    if (no < 0) return set;
    for (int i = 0; i < numNames; i++) {
      int nrva = BitConverter.ToInt32(b, no + i * 4);
      int off = RvaToOff(nrva, b, secOff, numSec);
      if (off < 0) continue;
      string s = StrAt(b, off);
      if (s.Length > 0) set.Add(s);
    }
    return set;
  }

  // resolve every import of drv against files found in dirsCsv
  public static string Check(string drv, string dirsCsv) {
    byte[] b = File.ReadAllBytes(drv);
    int e = BitConverter.ToInt32(b, 0x3C);
    int numSec = BitConverter.ToUInt16(b, e + 6);
    ushort sizeOpt = BitConverter.ToUInt16(b, e + 20);
    int opt = e + 24;
    ushort magic = BitConverter.ToUInt16(b, opt);
    int dd = opt + (magic == 0x20B ? 112 : 96);
    uint impRva = BitConverter.ToUInt32(b, dd + 8);
    uint certRva = BitConverter.ToUInt32(b, dd + 32);
    uint certSize = BitConverter.ToUInt32(b, dd + 36);
    StringBuilder o = new StringBuilder();
    o.Append("magic=0x"); o.Append(magic.ToString("X4"));
    o.Append(" impRva="); o.Append(impRva);
    o.Append(" cert(entry4)="); o.Append(certRva); o.Append("/"); o.Append(certSize);
    if (impRva == 0) { o.Append(" NO-IMPORT-DIR"); return o.ToString(); }
    int secOff = opt + sizeOpt;
    int io = RvaToOff((int)impRva, b, secOff, numSec);
    if (io < 0) { o.Append(" IMPRAVA-UNMAPPED"); return o.ToString(); }
    int tsz = magic == 0x20B ? 8 : 4;
    string[] dirs = dirsCsv.Split(';');
    Dictionary<string, HashSet<string>> cache = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
    for (int d = 0; d < 40; d++) {
      int ent = io + d * 20;
      if (ent + 20 > b.Length) break;
      int oft = BitConverter.ToInt32(b, ent);
      int nameRva = BitConverter.ToInt32(b, ent + 12);
      int ft = BitConverter.ToInt32(b, ent + 16);
      if (oft == 0 && nameRva == 0 && ft == 0) break;
      string dll = StrAt(b, RvaToOff(nameRva, b, secOff, numSec));
      if (dll.Length == 0) break;
      int thunk = oft != 0 ? oft : ft;
      int to = RvaToOff(thunk, b, secOff, numSec);
      List<string> funcs = new List<string>();
      if (to >= 0) {
        for (int k = 0; k < 512; k++) {
          int p = to + k * tsz;
          if (p + tsz > b.Length) break;
          long raw = tsz == 8 ? (long)BitConverter.ToUInt64(b, p) : (long)BitConverter.ToUInt32(b, p);
          if (raw == 0) break;
          long hi = tsz == 8 ? long.MinValue : 0x80000000L;   // ordinal bit (IMAGE_ORDINAL_FLAG64/32)
          if ((raw & hi) != 0) { funcs.Add("#ord" + (raw & 0xFFFF)); continue; }
          int noff = RvaToOff((int)raw, b, secOff, numSec);
          if (noff < 0) break;
          funcs.Add(StrAt(b, noff + 2));
        }
      }
      string found = null;
      foreach (string dir in dirs) {
        foreach (string cand in new string[] { Path.Combine(dir, dll), Path.Combine(dir, dll + ".sys") }) {
          if (File.Exists(cand)) { found = cand; break; }
        }
        if (found != null) break;
      }
      if (found == null) { o.Append(" | " + dll + " FILE-MISSING(" + funcs.Count + " imports)"); continue; }
      HashSet<string> ex;
      if (!cache.TryGetValue(found, out ex)) {
        try { ex = Exports(found); } catch (Exception) { ex = new HashSet<string>(); }
        cache[found] = ex;
      }
      int miss = 0; StringBuilder ms = new StringBuilder();
      foreach (string f in funcs) {
        if (!ex.Contains(f)) { miss++; if (ms.Length < 200) { ms.Append(f); ms.Append(','); } }
      }
      o.Append(" | " + dll + " n=" + funcs.Count + " exports=" + ex.Count + " missing=" + miss + (miss > 0 ? " [" + ms.ToString() + "]" : ""));
    }
    return o.ToString();
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 400)); return }

# ---------- 0. os / module residency ----------
L '=0 os + loaded modules'
$os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
L ('  0 OS ver=' + (Trim2 ('' + $os.Version) 30) + ' build=' + (Trim2 ('' + $os.BuildNumber) 20))
foreach ($f in @('X:\Windows\System32\ntoskrnl.exe', 'X:\Windows\System32\drivers\ndis.sys', 'X:\Windows\System32\drivers\vwifi.sys')) {
  if (Test-Path -LiteralPath $f) {
    $v = (Get-Item -LiteralPath $f).VersionInfo
    L ('  0 V ' + (Trim2 $f 70) + ' ' + (Trim2 ('' + $v.FileVersion) 40))
  } else { L ('  0 V ' + (Trim2 $f 70) + ' MISSING') }
}
$wp = @(& whoami.exe /priv 2>&1 | ForEach-Object { (Clean ('' + $_)) })
foreach ($w in $wp) { if ($w -match '(?i)load-driver|debug|seimp') { L ('  0 PRIV ' + (Trim2 $w 110)) } }
$mods = [P74]::Mods('ndis,wifi,netwtw,netwaw,tapimount,implatform,wfp,pacer,ndproxy')
L ('  0 MODULES ' + (Trim2 $mods 700))

# ---------- 1. import resolution + real Authenticode field ----------
L '=1 import/export resolution'
$dirs = 'X:\Windows\System32;X:\Windows\System32\drivers'
foreach ($p in @('X:\windows\system32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e\Netwtw14.sys',
                 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys',
                 'X:\Windows\System32\drivers\nwifi.sys',
                 'X:\Windows\System32\drivers\vwififlt.sys',
                 'X:\Windows\System32\drivers\vwifibus.sys')) {
  if (-not (Test-Path -LiteralPath $p)) { L ('  1 CHK ' + (Trim2 $p 88) + ' MISSING'); continue }
  $r = [P74]::Check($p, $dirs)
  L ('  1 CHK ' + (Trim2 $p 88))
  $pieces = @($r -split ' \| ')
  foreach ($pc in $pieces) { L ('      ' + (Trim2 $pc 300)) }
}
$sg = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e' -Filter '*.cat' -EA SilentlyContinue)
foreach ($c in $sg) {
  $sig = ''
  try { $sig = '' + (Get-AuthenticodeSignature -LiteralPath $c.FullName -EA Stop).Status } catch { $sig = 'ERR ' + $_.Exception.Message }
  L ('  1 CAT ' + $c.Name + ' status=' + (Trim2 $sig 60))
}

# ---------- 2. service key diff, PE vs the working offline hive ----------
L '=2 service keys PE vs offline'
if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  $jj = $rl -join '|'
  L ('  2 load ' + (Trim2 $jj 200))
}
L ('  2 R8OFF=' + (Test-Path -LiteralPath ($OFF + '\ControlSet001')))
function DiffSrv([string]$name) {
  $pe = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
  $of = $OFF + '\ControlSet001\Services\' + $name
  $pt = Test-Path -LiteralPath $pe
  $ot = Test-Path -LiteralPath $of
  L ('  2 SRV ' + $name + ' PE=' + $pt + ' OFF=' + $ot)
  if (-not ($pt -and $ot)) { return }
  $a = Get-Item -LiteralPath $pe
  $b = Get-Item -LiteralPath $of
  $an = @($a.GetValueNames())
  $bn = @($b.GetValueNames())
  $all = @($an + $bn | Sort-Object -Unique)
  foreach ($kk in $all) {
    if ($kk -eq 'ImagePath') { continue }
    $pv = ''
    $ov = ''
    if ($an -contains $kk) { $pv = '' + ($a.GetValue($kk) -join ';') }
    if ($bn -contains $kk) { $ov = '' + ($b.GetValue($kk) -join ';') }
    if ($pv -ne $ov) { L ('  2   VAL ' + $kk + ' PE=[' + (Trim2 $pv 90) + '] OFF=[' + (Trim2 $ov 90) + ']') }
  }
  $ssa = @($a.GetSubKeyNames())
  $ssb = @($b.GetSubKeyNames())
  L ('  2   SUBS PE=[' + ($ssa -join ',') + '] OFF=[' + ($ssb -join ',') + ']')
  foreach ($s in @($ssa + $ssb | Sort-Object -Unique)) {
    if ($s -eq 'Security' -or $s -eq 'Enum') { continue }
    $pp = $pe + '\' + $s
    $oo = $of + '\' + $s
    $p2 = Test-Path -LiteralPath $pp
    $o2 = Test-Path -LiteralPath $oo
    if ($p2 -and $o2) {
      $pa = Get-Item -LiteralPath $pp
      $pb = Get-Item -LiteralPath $oo
      $pvn = @($pa.GetValueNames())
      $ovn = @($pb.GetValueNames())
      L ('  2   SUB ' + $s + ' PEvals=[' + ($pvn -join ',') + '] OFFvals=[' + ($ovn -join ',') + ']')
      foreach ($kk in @($pvn + $ovn | Sort-Object -Unique)) {
        $pv = ''
        $ov = ''
        if ($pvn -contains $kk) { $pv = '' + ($pa.GetValue($kk) -join ';') }
        if ($ovn -contains $kk) { $ov = '' + ($pb.GetValue($kk) -join ';') }
        if ($pv -ne $ov) { L ('  2     ' + $s + '\' + $kk + ' PE=[' + (Trim2 $pv 80) + '] OFF=[' + (Trim2 $ov 80) + ']') }
      }
    } elseif ($p2) { L ('  2   SUB ' + $s + ' PEONLY') }
    else { L ('  2   SUB ' + $s + ' OFFONLY') }
  }
}
foreach ($n in 'Netwtw14', 'nativewifip', 'vwififlt', 'vwifibus', 'NdisImPlatform') { DiffSrv $n }

# ---------- 3. direct image load (filters only -- miniport is read from the module list instead) ----------
L '=3 NtLoadDriver filters'
L ('  3 ' + [P74]::EnablePriv())
foreach ($n in 'vwififlt', 'nativewifip') {
  $r = [P74]::Load('\Registry\Machine\System\CurrentControlSet\Services\' + $n)
  L ('  3 LOAD ' + $n + ' -> ' + $r + ' now=' + (St $n))
}
L ('  3 MODULES2 ' + (Trim2 ([P74]::Mods('wifi,ndis')) 400))

L '=4 final'
L ('  4 devnodes=' + (@(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })).Count)
L ('  4 vwifibus=' + (St 'vwifibus') + ' nativewifip=' + (St 'nativewifip') + ' vwififlt=' + (St 'vwififlt') + ' wlansvc=' + (St 'wlansvc'))
L 'P74 END'
