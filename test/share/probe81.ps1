# probe81 -- LIVE PE. probe80 answered the generation question and opened a better one.
#   probe80 RESULT: this laptop's own Windows (D:) is 19041-era (cmd.exe 10.0.19041.746), and its
#     wdiwifi.sys is 10.0.19041.2788 / NdisImPlatform.sys 10.0.19041.546 -- i.e. the machine runs the
#     Windows-Wi-Fi-Driver-Framework from the SAME build family as the workstation copies we bake from
#     (host wdiwifi 10.0.19041.7663, covered by the Microsoft-Windows-Client-Desktop-Required-Package04
#     catalog that is ALREADY in overlay\Cats). So there is no "19041 binary inside a 26100 PE" argument to
#     win: there is no Win11-era copy of these files anywhere on this machine.
#   probe80 LEFT OPEN: which driver GENERATION actually binds PCI\VEN_8086&DEV_7A70 on this laptop.
#     The pool index maps 7A70 to netwtw08.inf and netwtw6e.inf, both of which look WDI-based, and the
#     image's bound package is netwtw6e (Netwtw14 23.50.11.2 + Netwtw16 23.150.0.4). If some package that
#     claims 7A70 registers as a CLASSIC miniport (NdisMRegisterMiniportDriver only), that package can be
#     made to work with no wdiwifi at all -- and it could even be proven live with drvload, before any bake.
# So: classify every Intel Wi-Fi package on D: and X: (WDI vs classic), find every one that claims 7A70,
# read what D:'s own running Windows binds to the AX211, and only then try a live drvload if a
# non-WDI candidate exists. Read-only except the one drvload/restart attempt, all of which reverts on reboot.
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
$DEV = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$DEVKEY = 'PCI\VEN_8086&DEV_7A70'

try {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
public static class P81 {
  static int RvaToOff(int rva, byte[] b, int secOff, int numSec) {
    for (int i = 0; i < numSec; i++) {
      int s = secOff + i * 40;
      int va = (int)BitConverter.ToUInt32(b, s + 12);
      int vs = (int)BitConverter.ToUInt32(b, s + 8);
      int raw = (int)BitConverter.ToUInt32(b, s + 20);
      int rsz = (int)BitConverterToU32Safe(b, s + 16);
      int span = vs > rsz ? vs : rsz;
      if (rva >= va && rva < va + span) return raw + (rva - va);
    }
    return -1;
  }
  static int BitConverterToU32Safe(byte[] b, int off) {
    if (off + 4 > b.Length) return 0;
    return (int)BitConverter.ToUInt32(b, off);
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
  // imported symbol names whose name contains any of the given substrings (cheap filter, avoids huge dumps)
  public static string ImportHits(string path, string dllPart, string filter) {
    StringBuilder hits = new StringBuilder();
    byte[] b;
    try { b = File.ReadAllBytes(path); } catch { return "READ-FAIL"; }
    if (b.Length < 0x40) return "TOO-SMALL";
    int dd, secOff, numSec;
    int magic = Header(b, out dd, out secOff, out numSec);
    uint impRva = BitConverter.ToUInt32(b, dd + 8);
    if (impRva == 0) return "NO-IMPORTS";
    int io = RvaToOff((int)impRva, b, secOff, numSec);
    if (io < 0) return "IMP-RVA-FAIL";
    int tsz = magic == 0x20B ? 8 : 4;
    long hi = tsz == 8 ? long.MinValue : (long)0x80000000L;
    string[] flt = filter.Replace(',', ';').Split(';');
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
        if ((th & hi) != 0) continue;
        int no = RvaToOff((int)(th & 0x7FFFFFFFL), b, secOff, numSec);
        if (no < 0) continue;
        string sym = StrAt(b, no + 2);
        for (int j = 0; j < flt.Length; j++) {
          if (flt[j].Length > 0 && sym.IndexOf(flt[j], StringComparison.OrdinalIgnoreCase) >= 0) {
            hits.Append(sym); hits.Append(','); break;
          }
        }
      }
    }
    return hits.ToString().TrimEnd(',');
  }
  public static int ImportCount(string path, string dllPart) {
    byte[] b;
    try { b = File.ReadAllBytes(path); } catch { return -1; }
    int dd, secOff, numSec;
    int magic = Header(b, out dd, out secOff, out numSec);
    uint impRva = BitConverter.ToUInt32(b, dd + 8);
    if (impRva == 0) return 0;
    int io = RvaToOff((int)impRva, b, secOff, numSec);
    if (io < 0) return 0;
    int tsz = magic == 0x20B ? 8 : 4;
    long hi = tsz == 8 ? long.MinValue : (long)0x80000000L;
    int n = 0;
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
        n++;
      }
    }
    return n;
  }
  // INFs are UTF-16 on the ISO; read them as text and grep for a hardware-id substring
  public static string InfHits(string path, string needle, int max) {
    StringBuilder sb = new StringBuilder();
    string[] lines;
    try { lines = File.ReadAllLines(path, Encoding.Unicode); } catch { return "READ-FAIL"; }
    int n = 0;
    foreach (string ln in lines) {
      if (ln.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
        n++;
        string t = ln.Trim();
        if (t.Length > 150) t = t.Substring(0, 150);
        sb.Append(" | L" + n + ":" + t);
        if (n >= max) break;
      }
    }
    return "hits=" + n + sb.ToString();
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 300)); return }

# ---------- 0. the offline hive is already mounted as R8OFF from probe78 (re-loading the same file fails) ----------
L '=0 D: build + offline hive availability'
$rl = @(& reg.exe query 'HKLM\R8OFF' 2>&1 | ForEach-Object { (Trim2 ('' + $_) 120) })
if ($rl -join ' ' | Select-String -Pattern 'error|not found' -Quiet) {
  $rl2 = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Trim2 ('' + $_) 120) })
  L ('  0 regload ' + ($rl2 -join '|'))
} else { L '  0 R8OFF already loaded (from probe78) - reusing' }
L ('  0 R8OFF services=' + (Test-Path -LiteralPath ($REFO + '\ControlSet001\Services')))
$offCmd = 'D:\Windows\System32\cmd.exe'
if (Test-Path -LiteralPath $offCmd) {
  $ocv = (Get-Item -LiteralPath $offCmd).VersionInfo
  L ('  0 D: cmd.exe ' + $ocv.FileMajorPart + '.' + $ocv.FileMinorPart + '.' + $ocv.FileBuildPart + '.' + $ocv.FilePrivatePart)
}

# ---------- 1. classify every Intel Wi-Fi package on D: and in the PE image ----------
L '=1 Intel Wi-Fi packages: WDI vs classic miniport'
$FLT = 'NdisMRegisterWdiMiniportDriver,NdisMDeregisterWdiMiniportDriver,NdisMRegisterMiniportDriver,NdisMDeregisterMiniportDriver,NdisWifiHost'
$rows = @()
foreach ($root in @('D:\Windows\System32\DriverStore\FileRepository', 'X:\Windows\System32\DriverStore\FileRepository')) {
  if (-not (Test-Path -LiteralPath $root)) { L ('  1 ' + $root + ' MISSING'); continue }
  foreach ($d2 in @(Get-ChildItem -LiteralPath $root -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '^netwtw|^netwaw|^netrtwlan' })) {
    foreach ($s in @(Get-ChildItem -LiteralPath $d2.FullName -Filter '*.sys' -File -EA SilentlyContinue)) {
      $v = $s.VersionInfo
      $ver = '' + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart
      $hits = [P81]::ImportHits($s.FullName, 'ndis', $FLT)
      $kind = 'OTHER'
      if ($hits -match 'NdisMRegisterWdiMiniportDriver') { $kind = 'WDI' }
      elseif ($hits -match 'NdisMRegisterMiniportDriver') { $kind = 'CLASSIC' }
      $rows += ('{0}|{1}|{2}|{3}|{4}|{5}' -f $(if ($root.StartsWith('D:')) { 'D' } else { 'X' }), (Trim2 $d2.Name 44), $s.Name, $ver, $kind, (Trim2 $hits 120))
    }
  }
}
foreach ($r in $rows) { L ('  1 ' + (Trim2 $r 200)) }
L ('  1 rows=' + $rows.Count + ' WDI=' + @($rows | Where-Object { $_ -match '\|WDI\|' }).Count + ' CLASSIC=' + @($rows | Where-Object { $_ -match '\|CLASSIC\|' }).Count)

# ---------- 2. which of those INFs claim this card (7A70), and does the package need VWiFi/WDI? ----------
L '=2 INFs claiming 7A70 (and their Include/Needs references)'
$claim = @()
foreach ($root in @('D:\Windows\System32\DriverStore\FileRepository', 'X:\Windows\System32\DriverStore\FileRepository')) {
  if (-not (Test-Path -LiteralPath $root)) { continue }
  foreach ($d2 in @(Get-ChildItem -LiteralPath $root -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '^netwtw|^netwaw' })) {
    foreach ($inf in @(Get-ChildItem -LiteralPath $d2.FullName -Filter '*.inf' -File -EA SilentlyContinue)) {
      $r = [P81]::InfHits($inf.FullName, 'DEV_7A70', 3)
      if ($r -notmatch 'hits=0' -and $r -ne 'READ-FAIL') {
        $side = 'X'
        if ($root.StartsWith('D:')) { $side = 'D' }
        $claim += ($side + '|' + $d2.Name + '|' + $inf.Name)
        L ('  2 ' + (Trim2 ($side + ' ' + $d2.Name + ' ' + $inf.Name) 80) + ' ' + (Trim2 $r 210))
        $r2 = [P81]::InfHits($inf.FullName, 'vwifibus', 3)
        $r3 = [P81]::InfHits($inf.FullName, 'Include=', 3)
        L ('  2   vwifibus=' + (Trim2 $r2 150) + ' include=' + (Trim2 $r3 150))
      }
    }
  }
}
L ('  2 claimers=' + $claim.Count)

# ---------- 3. what D:'s own Windows binds to the AX211 ----------
L '=3 offline (D:) service keys for Intel Wi-Fi + wdiwifi/NdisImPlatform'
$svcRoot = $REFO + '\ControlSet001\Services'
if (Test-Path -LiteralPath $svcRoot) {
  foreach ($sk in @(Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue)) {
    $nm = $sk.PSChildName
    if ($nm -notmatch '^(Netwtw|Netwaw|wdiwifi|NdisImPlatform|nativewifip|vwifi)') { continue }
    $img = VOf $sk.PSPath 'ImagePath'
    $enumDev = 'no-enum'
    $enumPath = $sk.PSPath + '\Enum'
    if (Test-Path -LiteralPath $enumPath) {
      $eki = Get-Item -LiteralPath $enumPath
      $devs = @()
      foreach ($vn in @($eki.GetValueNames())) {
        if ($vn -match '^\d+$') { $devs += ('' + $eki.GetValue($vn)) }
      }
      if ($devs.Count) { $enumDev = (Trim2 ($devs -join ';') 90) }
    }
    $has7a70 = 'n/a'
    if ($enumDev -ne 'no-enum') { $has7a70 = ($enumDev.ToUpperInvariant().Contains('7A70')) }
    L ('  3 ' + (('{0,-16}' -f $nm)) + ' Type=' + (VOf $sk.PSPath 'Type') + ' Start=' + (VOf $sk.PSPath 'Start') +
       ' Grp=' + (VOf $sk.PSPath 'Group') + ' img=' + (Trim2 $img 64) + ' enum=' + $enumDev + ' has7A70=' + $has7a70)
  }
} else { L '  3 offline services key ABSENT' }

# ---------- 4. live attempt, only if a CLASSIC (no-WDI) 7A70 claimer exists ----------
L '=4 live drvload attempt'
$classic = @($rows | Where-Object { $_ -match '\|CLASSIC\|' })
$classicClaim = @()
foreach ($c in $classic) {
  $parts = $c.Split('|')
  $dirName = $parts[1]
  foreach ($cl in $claim) { if ($cl.Split('|')[1] -eq $dirName) { $classicClaim += $cl } }
}
L ('  4 classic-and-claims-7A70=' + $classicClaim.Count)
if ($classicClaim.Count -gt 0) {
  foreach ($cl in @($classicClaim | Select-Object -First 2)) {
    $p3 = $cl.Split('|')
    $infPath = ''
    if ($p3[0] -eq 'D') { $infPath = 'D:\Windows\System32\DriverStore\FileRepository\' + $p3[1] + '\' + $p3[2] }
    else { $infPath = 'X:\Windows\System32\DriverStore\FileRepository\' + $p3[1] + '\' + $p3[2] }
    L ('  4 DRVLOAD ' + (Trim2 $infPath 100))
    $dl = @(& drvload.exe ($infPath) 2>&1 | ForEach-Object { (Trim2 ('' + $_) 200) })
    L ('  4 rc=' + $LASTEXITCODE + ' out=' + (Trim2 ($dl -join '|') 200))
    Start-Sleep -Seconds 8
    $rs = @(& pnputil.exe /restart-device ($DEV) 2>&1 | ForEach-Object { (Trim2 ('' + $_) 160) })
    L ('  4 RESTART ' + (Trim2 ($rs -join '|') 200))
    Start-Sleep -Seconds 6
    $dd = @(Get-PnpDevice -InstanceId $DEV -EA SilentlyContinue)
    foreach ($x in $dd) { L ('  4 DEV status=' + (Trim2 ('' + $x.Status) 30) + ' problem=' + (Trim2 ('' + $x.ConfigManagerErrorCode) 8) + ' name=' + (Trim2 ('' + $x.FriendlyName) 40)) }
    $ips = @(& ipconfig.exe /all 2>&1 | ForEach-Object { (Trim2 ('' + $_) 120) })
    $wl = @($ips | Where-Object { $_ -match 'Wi-Fi|WLAN|Wireless|802\.11' })
    L ('  4 ipconfig wireless lines=' + $wl.Count)
    foreach ($w in @($wl | Select-Object -First 6)) { L ('  4 W ' + $w) }
    break
  }
} else {
  L '  4 skipped: every package claiming 7A70 is WDI-based, so nothing can bind without wdiwifi at boot'
}
L '  4 svc Netwtw14=' + (St 'Netwtw14') + ' Netwtw16=' + (St 'Netwtw16') + ' wdiwifi=' + (St 'wdiwifi') + ' wlansvc=' + (St 'WlanSvc')
$ad = @(Get-NetAdapter -EA SilentlyContinue | ForEach-Object { (Trim2 ('' + $_.Name + '/' + $_.Status + '/' + $_.InterfaceDescription) 90) })
foreach ($a in $ad) { L ('  4 ADAPTER ' + $a) }
L 'P81 END'
