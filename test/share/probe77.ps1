# probe77 -- LIVE PE. probe76 closed two hypotheses and opened one:
#   CLOSED  driver version: the device is now bound to oem182.inf / DriverVersion 23.150.0.4 with
#           ImagePath ...FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys -- i.e. EXACTLY the
#           package this laptop's own Windows runs -- and it is still code 37 with netwtw14.sys absent from the
#           module list. A pool refresh would not help.
#   CLOSED  service-security-descriptor theory: a runtime-created service is invisible to the PE SCM no matter
#           how it is made (reg add -> 1060; reg copy of a real service key, which carries a real service SD,
#           -> also 1060). So no live run can ever start NdisImPlatform; that fix is bake-and-reboot only.
#   OPEN    Netwtw14.sys is a PE image with a normal import set EXCEPT one entry: ext-ms-win-ntos-werkernel-
#           l1-1-1.dll, an API-SET contract. Only 6 of 198 binaries in our whole driver pool import any api set
#           (NETwtw08/10/14, NETwaw14, rtwlane02 -- all vendor WLAN), and every LAN/WiFi driver that works in
#           this PE imports none. Kernel-mode api-set resolution needs the contract registered AND its host
#           component present; if PE cannot resolve it the image never loads -- which matches "code 37, module
#           never in the list". This probe tests that behaviourally: does any LOADED PE driver import an api
#           set? Plus the definitive bake list (files + service keys + covering catalogs).
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$OFF = 'HKLM:\R8OFF'
$CATD = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }

try {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class P77 {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool K32EnumDeviceDrivers(IntPtr[] lpp, int cb, out int needed);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern int K32GetDeviceDriverBaseNameW(IntPtr drv, StringBuilder buf, int count);
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
  public static string[] ModsAll() {
    IntPtr[] a = new IntPtr[4096];
    int need;
    if (!K32EnumDeviceDrivers(a, a.Length * IntPtr.Size, out need)) return new string[0];
    int count = need / IntPtr.Size;
    List<string> l = new List<string>();
    StringBuilder nm = new StringBuilder(300);
    for (int i = 0; i < count; i++) {
      nm.Length = 0;
      if (K32GetDeviceDriverBaseNameW(a[i], nm, nm.Capacity) <= 0) continue;
      l.Add(nm.ToString().ToLowerInvariant());
    }
    return l.ToArray();
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
      int off = RvaToOff(BitConverter.ToInt32(b, no + i * 4), b, secOff, numSec);
      if (off < 0) continue;
      string s = StrAt(b, off);
      if (s.Length > 0) set.Add(s);
    }
    return set;
  }
  // just the imported module names
  public static string[] ImportNames(string path) {
    byte[] b = File.ReadAllBytes(path);
    int e = BitConverter.ToInt32(b, 0x3C);
    int numSec = BitConverter.ToUInt16(b, e + 6);
    ushort sizeOpt = BitConverter.ToUInt16(b, e + 20);
    int opt = e + 24;
    ushort magic = BitConverter.ToUInt16(b, opt);
    int dd = opt + (magic == 0x20B ? 112 : 96);
    uint impRva = BitConverter.ToUInt32(b, dd + 8);
    List<string> l = new List<string>();
    if (impRva == 0) return l.ToArray();
    int secOff = opt + sizeOpt;
    int io = RvaToOff((int)impRva, b, secOff, numSec);
    if (io < 0) return l.ToArray();
    for (int d = 0; d < 40; d++) {
      int ent = io + d * 20;
      if (ent + 20 > b.Length) break;
      int oft = BitConverter.ToInt32(b, ent);
      int nameRva = BitConverter.ToInt32(b, ent + 12);
      int ft = BitConverter.ToInt32(b, ent + 16);
      if (oft == 0 && nameRva == 0 && ft == 0) break;
      string dll = StrAt(b, RvaToOff(nameRva, b, secOff, numSec));
      if (dll.Length == 0) break;
      l.Add(dll);
    }
    return l.ToArray();
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 300)); return }

# ---------- 0. behavioural api-set test: do any LOADED PE drivers import an api set? ----------
L '=0 loaded-driver import scan'
$loaded = @([P77]::ModsAll())
L ('  0 loaded count=' + $loaded.Count)
$dirDrv = 'X:\Windows\System32\drivers'
$files = @(Get-ChildItem -LiteralPath $dirDrv -Filter '*.sys' -EA SilentlyContinue | ForEach-Object { $_.Name })
L ('  0 driver files on disk=' + $files.Count)
$apiFiles = @()
$missingFiles = @()
$scanned = 0
foreach ($f in $files) {
  $p = $dirDrv + '\' + $f
  $names = @()
  try { $names = @([P77]::ImportNames($p)) } catch { continue }
  $scanned = $scanned + 1
  $api = @($names | Where-Object { $_ -match '^(ext-ms-|api-ms-)' })
  if ($api.Count -gt 0) {
    $isLoaded = $loaded -contains $f.ToLowerInvariant()
    $apiFiles += ('{0}[loaded={1}]{2}' -f $f, $isLoaded, ($api -join '+'))
  }
}
L ('  0 scanned=' + $scanned + ' with-APISET=' + $apiFiles.Count)
foreach ($x in @($apiFiles | Select-Object -First 25)) { L ('  0 A ' + (Trim2 $x 150)) }

# ---------- 1. the PE api-set schema (Win10+ keeps contracts in the .apiset section as UTF-16 strings,
#              NOT in the export table, so read it as text and grep) ----------
L '=1 apisetschema text scan'
foreach ($p in @('X:\Windows\System32\apisetschema.dll', 'D:\Windows\System32\apisetschema.dll')) {
  if (-not (Test-Path -LiteralPath $p)) { L ('  1 ' + (Trim2 $p 46) + ' MISSING'); continue }
  $fi = Get-Item -LiteralPath $p
  $raw = [System.IO.File]::ReadAllBytes($p)
  $asU = [System.Text.Encoding]::Unicode.GetString($raw)
  $asA = [System.Text.Encoding]::ASCII.GetString($raw)
  $mU = @([regex]::Matches($asU, '[A-Za-z0-9._-]*werkernel[A-Za-z0-9._-]*') | ForEach-Object { $_.Value }) | Sort-Object -Unique
  $mA = @([regex]::Matches($asA, '[A-Za-z0-9._-]*werkernel[A-Za-z0-9._-]*') | ForEach-Object { $_.Value }) | Sort-Object -Unique
  $extU = @([regex]::Matches($asU, 'ext-ms-win-ntos-[a-z0-9-]*') | ForEach-Object { $_.Value }) | Sort-Object -Unique
  L ('  1 ' + (Trim2 $p 46) + ' ' + $fi.Length + 'B utf16len=' + $asU.Length + ' ansiLen=' + $asA.Length)
  L ('  1   werkernel-utf16=[' + (Trim2 ($mU -join ',') 200) + '] ansi=[' + (Trim2 ($mA -join ',') 200) + ']')
  L ('  1   ext-ms-win-ntos-* count=' + $extU.Count + ' werkernel present=' + (@($extU | Where-Object { $_ -match 'werkernel' })).Count)
  L ('  1   sample=[' + (Trim2 (($extU | Select-Object -First 8) -join ',') 220) + ']')
}
$dl = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\downlevel' -EA SilentlyContinue | ForEach-Object { $_.Name })
L ('  1 X:downlevel=[' + (Trim2 ($dl -join ',') 240) + ']')

# ---------- 2. Netwtw14 vs the working wired driver, side by side ----------
L '=2 targeted import compare'
foreach ($p in @('X:\windows\system32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys',
                 'X:\Windows\System32\drivers\rt640x64.sys',
                 'X:\Windows\System32\drivers\nwifi.sys',
                 'X:\Windows\System32\drivers\vwififlt.sys',
                 'X:\Windows\System32\drivers\vwifibus.sys')) {
  if (-not (Test-Path -LiteralPath $p)) { L ('  2 ' + (Trim2 $p 78) + ' MISSING'); continue }
  $names = @([P77]::ImportNames($p))
  $fn = $p.Split('\')[-1]
  L ('  2 ' + $fn + ' loaded=' + ($loaded -contains $fn.ToLowerInvariant()) + ' imports=' + ($names -join ','))
}

# ---------- 3. the complete bake list: files + service keys, PE vs the working offline OS ----------
L '=3 bake list'
if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  3 load ' + (Trim2 ($rl -join '|') 140))
}
foreach ($n in @('nwifi.sys', 'vwififlt.sys', 'vwifibus.sys', 'vwifimp.sys', 'NdisImPlatform.sys', 'wdiwifi.sys', 'werkernel.sys', 'ksecdd.sys', 'cng.sys', 'netio.sys', 'Wdf01000.sys')) {
  $peF = Test-Path -LiteralPath ('X:\Windows\System32\drivers\' + $n)
  $ofF = Test-Path -LiteralPath ('D:\Windows\System32\drivers\' + $n)
  $sz = 'n/a'
  if ($ofF) { $sz = '' + (Get-Item -LiteralPath ('D:\Windows\System32\drivers\' + $n)).Length }
  L ('  3 FILE ' + $n + ' PE=' + $peF + ' OFF=' + $ofF + ' OFFbytes=' + $sz)
}
foreach ($s in @('nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'NdisImPlatform', 'wdiwifi', 'NdisVirtualBus', 'NativeWifiP')) {
  $peS = Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s)
  $ofS = Test-Path -LiteralPath ($OFF + '\ControlSet001\Services\' + $s)
  $ofStart = 'n/a'
  if ($ofS) {
    $oi = Get-Item -LiteralPath ($OFF + '\ControlSet001\Services\' + $s)
    if (@($oi.GetValueNames()) -contains 'Start') { $ofStart = '' + $oi.GetValue('Start') }
  }
  $peStart = 'n/a'
  if ($peS) {
    $pi = Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s)
    if (@($pi.GetValueNames()) -contains 'Start') { $peStart = '' + $pi.GetValue('Start') }
  }
  L ('  3 SVC ' + $s + ' PE=' + $peS + '(Start=' + $peStart + ' state=' + (St $s) + ') OFF=' + $ofS + '(Start=' + $ofStart + ')')
}

# ---------- 4. covering catalogs for the files we must bake ----------
L '=4 catalogs'
$ofc = 'D:\Windows\System32\CatRoot\' + $CATD
L ('  4 offline catroot dir=' + (Test-Path -LiteralPath $ofc))
$all = @(Get-ChildItem -LiteralPath $ofc -Filter '*.cat' -Force -EA SilentlyContinue)
L ('  4 offline cat count=' + $all.Count)
$cand = @($all | Where-Object { $_.Name -match '(?i)implat|wifi|ndis|wlan' } | Select-Object -First 40)
L ('  4 candidates=' + (@($cand | ForEach-Object { $_.Name }) -join ','))
foreach ($c in @($cand | Select-Object -First 10)) {
  $dump = @(& certutil.exe -dump $c.FullName 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  $m1 = @($dump | Where-Object { $_ -match '(?i)NdisImPlatform' })
  $m2 = @($dump | Where-Object { $_ -match '(?i)wdiwifi' })
  $m3 = @($dump | Where-Object { $_ -match '(?i)nwifi\.sys' })
  L ('  4 ' + $c.Name + ' implat=' + $m1.Count + ' wdiwifi=' + $m2.Count + ' nwifi=' + $m3.Count + ' lines=' + $dump.Count)
}
L 'P77 END'
