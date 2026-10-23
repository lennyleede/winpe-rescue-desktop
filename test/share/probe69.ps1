# probe69 -- LIVE PE. Where probe67/68 left us:
#   - component store copied + FilterList written + pnputil /restart-device  -> still code 37, no bind record,
#     and setupapi gained ZERO lines for restart-device (the Net class installer never runs on a restart).
#   - pnputil /remove-device + /scan-devices re-ran NetCfg: the class slot got a NEW NetCfgInstanceId and an
#     EMPTY FilterList -> NetCfg knows about nwifi/netvwififlt packages (oem181/oem179 in the store) yet does
#     NOT impose them. netcfg -c s -i ... fails with 0x800f0203.
#   - boot-time setupapi log shows the REAL open failure: "Included INFs = netvwifibus.inf / Needed section
#     [VWiFiBus] / [VWiFiBus.CopyFiles] / [VWiFiBus.PnPFilterRegistration] not found, might exist in missing
#     included INF" -- although overlay\VWiFi\netvwifibus.inf does contain all three sections, so setupapi could
#     not OPEN the included INF by name.
# probe69 therefore answers, by comparing against the SAME laptop's working offline Windows (mounted hive):
#   A. what does the working machine's devnode / class slot / NativeWifiP bind record actually look like?
#   B. what in the PE is missing (DriverDatabase entries, FileRepository dirs, devnode UpperFilters, decorated
#      * values on the class slot)?
#   C. can SetupAPI in this PE open an inbox INF by NAME (that is exactly what Include= needs)?
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$DEVPATH = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$OFF = 'HKLM:\R8OFF'
$PE = 'HKLM:\SYSTEM\CurrentControlSet'
function ValMap([string]$path) {
  $h = @{}
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $gi) { return $h }
  foreach ($vn in @($gi.GetValueNames())) {
    $k = '' + $gi.GetValueKind($vn)
    $v = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $s = ''
    if ($k -eq 'MultiString') { $s = (@($v) -join ';') } elseif ($v -is [byte[]]) { $s = 'bin(' + $v.Length + ')' } else { $s = '' + $v }
    $nm = '(def)'
    if ($vn -ne '') { $nm = $vn }
    $h[$nm] = '[' + $k + '] ' + $s
  }
  return $h
}
function DumpKey([string]$path, [string]$tag) {
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $gi) { L ('  ' + $tag + ' ABSENT'); return }
  $m = ValMap $path
  foreach ($kk in @($m.Keys | Sort-Object)) { L ('  ' + $tag + ' ' + (Trim2 ($kk + ' = ' + $m[$kk]) 300)) }
  L ('  ' + $tag + ' SUBS=[' + (@($gi.GetSubKeyNames()) -join ',') + ']')
}
function DiffKey([string]$offPath, [string]$pePath, [string]$tag) {
  $a = ValMap $offPath
  $b = ValMap $pePath
  if ($a.Count -eq 0) { L ('  ' + $tag + ' OFF ABSENT') }
  if ($b.Count -eq 0) { L ('  ' + $tag + ' PE ABSENT') }
  foreach ($kk in (@($a.Keys) + @($b.Keys) | Sort-Object -Unique)) {
    $ov = ''
    $pv = ''
    if ($a.ContainsKey($kk)) { $ov = $a[$kk] }
    if ($b.ContainsKey($kk)) { $pv = $b[$kk] }
    if ($ov -eq $pv) { continue }
    if ($ov -eq '') { L ('  ' + $tag + ' PEONLY ' + (Trim2 ($kk + ' = ' + $pv) 240)) }
    elseif ($pv -eq '') { L ('  ' + $tag + ' OFFONLY ' + (Trim2 ($kk + ' = ' + $ov) 240)) }
    else { L ('  ' + $tag + ' DIFF ' + $kk + ' OFF=' + (Trim2 $ov 120) + ' PE=' + (Trim2 $pv 120)) }
  }
}

# ---------- 0. hive ready? ----------
L '=0 offline hive'
if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  0 load ' + (Trim2 ($rl -join '|') 200))
}
L ('  0 R8OFF present=' + (Test-Path -LiteralPath ($OFF + '\ControlSet001')))
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }

# ---------- A. devnode keys: working (offline) vs PE ----------
L '=A devnode instance keys'
DumpKey ($OFF + '\ControlSet001\Enum\' + $DEVPATH) 'A-OFF-INST'
DumpKey ($OFF + '\ControlSet001\Enum\' + $DEVPATH + '\Control' + '\' + '0001') 'A-OFF-CTL'
DumpKey ($OFF + '\ControlSet001\Enum\' + $DEVPATH + '\Device Parameters') 'A-OFF-DEVP'
DumpKey ($PE + '\Enum\' + $DEVPATH) 'A-PE-INST'
$peCtl = ''
$cs = @('0000', '0001', '0002')
foreach ($c in $cs) { if (Test-Path -LiteralPath ($PE + '\Enum\' + $DEVPATH + '\Control\' + $c)) { $peCtl = $c } }
L ('  A PE control subkey=' + $peCtl)
DumpKey ($PE + '\Enum\' + $DEVPATH + '\Control\' + $peCtl) 'A-PE-CTL'
DumpKey ($PE + '\Enum\' + $DEVPATH + '\Device Parameters') 'A-PE-DEVP'

# ---------- B. class slot + Ndi + Linkage diff (offline AX211 slot vs PE slot) ----------
L '=B class slot diff'
$offSlot = ''
foreach ($nn in @(Get-ChildItem -LiteralPath ($OFF + '\ControlSet001\Control\Class\' + $NET) -EA SilentlyContinue)) {
  if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
  if ((Clean ('' + (ValMap ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $nn.PSChildName))['MatchingDeviceId'])) -match 'DEV_7A70') { $offSlot = $nn.PSChildName } }
$peSlot = ''
foreach ($nn in @(Get-ChildItem -LiteralPath ($PE + '\Control\Class\' + $NET) -EA SilentlyContinue)) {
  if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
  if ((Clean ('' + (ValMap ($PE + '\Control\Class\' + $NET + '\' + $nn.PSChildName))['MatchingDeviceId'])) -match 'DEV_7A70') { $peSlot = $nn.PSChildName } }
L ('  B offSlot=' + $offSlot + ' peSlot=' + $peSlot)
if ($offSlot -ne '' -and $peSlot -ne '') {
  DiffKey ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $offSlot) ($PE + '\Control\Class\' + $NET + '\' + $peSlot) 'B-SLOT'
  DiffKey ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $offSlot + '\Linkage') ($PE + '\Control\Class\' + $NET + '\' + $peSlot + '\Linkage') 'B-LINK'
  DiffKey ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $offSlot + '\Ndi') ($PE + '\Control\Class\' + $NET + '\' + $peSlot + '\Ndi') 'B-NDI'
  DiffKey ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $offSlot + '\Ndi\Interfaces') ($PE + '\Control\Class\' + $NET + '\' + $peSlot + '\Ndi\Interfaces') 'B-NDIIF'
  $oa = @($offSlot)
  $pa = @($peSlot)
  L ('  B slot subs OFF=[' + (@(Get-Item -LiteralPath ($OFF + '\ControlSet001\Control\Class\' + $NET + '\' + $offSlot)).GetSubKeyNames() -join ',') + ']')
  L ('  B slot subs PE =[' + (@(Get-Item -LiteralPath ($PE + '\Control\Class\' + $NET + '\' + $peSlot)).GetSubKeyNames() -join ',') + ']')
}

# ---------- C. the offline bind record: what a SUCCESS looks like ----------
L '=C offline NativeWifiP/vwififlt bind records'
foreach ($svc in 'NativeWifiP', 'nativewifip', 'vwififlt', 'vwifibus', 'vwifimp') {
  $p = $OFF + '\ControlSet001\Services\' + $svc + '\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) {
    foreach ($c in @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue)) {
      L ('  C OFF ' + $svc + '\Adapters\' + $c.PSChildName)
      foreach ($g in @(Get-ChildItem -LiteralPath $c.PSPath -EA SilentlyContinue)) { L ('  C OFF   child ' + $g.PSChildName + ' vals=[' + (@($g.GetValueNames()) -join ',') + ']') }
    }
  } else { L ('  C OFF ' + $svc + ' no Adapters key') }
}
DumpKey ($PE + '\Services\NativeWifiP\Parameters') 'C-PE-NWIFIPARAM'
DumpKey ($OFF + '\ControlSet001\Services\NativeWifiP\Parameters') 'C-OFF-NWIFIPARAM'

# ---------- D. driver database / file repository for the four MS INFs ----------
L '=D driver database + filerepository'
foreach ($n in 'netnwifi.inf', 'netvwififlt.inf', 'netvwifibus.inf', 'netvwifimp.inf') {
  $pePk = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\DriverDatabase\DriverPackages' -EA SilentlyContinue | Where-Object { $_.PSChildName -like ($n + '_*') })
  $ofPk = @(Get-ChildItem -LiteralPath ($OFF + '\DriverDatabase\DriverPackages') -EA SilentlyContinue | Where-Object { $_.PSChildName -like ($n + '_*') })
  L ('  D ' + $n + ' PEpackages=' + $pePk.Count + ' [' + (@($pePk | ForEach-Object { $_.PSChildName }) -join ',') + ']')
  L ('  D ' + $n + ' OFFpackages=' + $ofPk.Count + ' [' + (Trim2 ((@($ofPk | ForEach-Object { $_.PSChildName }) -join ',') ) 200) + ']')
  $fr = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like ($n + '_*') })
  $frf = @()
  foreach ($d in $fr) { $frf += @(@(Get-ChildItem -LiteralPath $d.FullName -EA SilentlyContinue | ForEach-Object { $_.Name })) }
  L ('  D ' + $n + ' PE FileRepo=[' + (@($fr | ForEach-Object { $_.Name }) -join ',') + '] files=[' + (Trim2 ($frf -join ',') 200) + ']')
  $fr2 = @(Get-ChildItem -LiteralPath 'D:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like ($n + '_*') })
  $frf2 = @()
  foreach ($d in $fr2) { $frf2 += @(@(Get-ChildItem -LiteralPath $d.FullName -EA SilentlyContinue | ForEach-Object { $_.Name })) }
  L ('  D ' + $n + ' OFF FileRepo=[' + (@($fr2 | ForEach-Object { $_.Name }) -join ',') + '] files=[' + (Trim2 ($frf2 -join ',') 200) + ']')
}
L ('  D PE DriverPackages total=' + (@(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\DriverDatabase\DriverPackages' -EA SilentlyContinue)).Count)
L ('  D OFF DriverPackages total=' + (@(Get-ChildItem -LiteralPath ($OFF + '\DriverDatabase\DriverPackages') -EA SilentlyContinue)).Count)

# ---------- E. can SetupAPI open an inbox INF BY NAME in this PE? ----------
L '=E SetupAPI INF name resolution'
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P69Setup {
  [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr SetupOpenInfFileW(string infName, string infSection, int style, out uint errLine);
  [DllImport("setupapi.dll", SetLastError=true)]
  static extern bool SetupFindFirstLineW(IntPtr inf, string section, string key, out IntPtr context);
  [DllImport("setupapi.dll")]
  static extern void SetupCloseInfFile(IntPtr inf);
  [DllImport("setupapi.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool SetupGetInfInformationW(IntPtr infs, uint flags, IntPtr info, uint cb, out uint need);
  public static string Open(string name) {
    uint line = 0;
    IntPtr h = SetupOpenInfFileW(name, null, 0x00000002, out line);
    if (h == IntPtr.Zero || h == new IntPtr(-1)) { return "OPEN-FAIL err=" + Marshal.GetLastWin32Error() + " line=" + line; }
    string okPart = "OPEN-OK";
    IntPtr ctx = IntPtr.Zero;
    bool found = SetupFindFirstLineW(h, "VWiFiBus", null, out ctx);
    int e2 = Marshal.GetLastWin32Error();
    okPart = okPart + " find[VWiFiBus]=" + found + " err=" + e2;
    SetupCloseInfFile(h);
    return okPart;
  }
}
'@ -EA Stop
  foreach ($n in 'netvwifibus.inf', 'netnwifi.inf', 'netvwififlt.inf', 'ndisuio.inf', 'netvwifimp.inf') {
    L ('  E ' + $n + ' -> ' + [P69Setup]::Open($n))
  }
  L ('  E FULLPATH netvwifibus -> ' + [P69Setup]::Open('X:\Windows\INF\netvwifibus.inf'))
  L ('  E FULLPATH netnwifi -> ' + [P69Setup]::Open('X:\Windows\INF\netnwifi.inf'))
  L ('  E WINDIRINF netvwifibus -> ' + [P69Setup]::Open('%windir%\inf\netvwifibus.inf'))
} catch { L ('  E ADDTYPE-ERR ' + (Trim2 ('' + $_.Exception.Message) 250)) }

# ---------- F. does the PE know any NetService component install at all? ----------
L '=F netcfg / component state'
L ('  F netnwifi service keys: nativewifip=' + (St 'nativewifip') + ' vwififlt=' + (St 'vwififlt') + ' vwifibus=' + (St 'vwifibus') + ' vwifimp=' + (St 'vwifimp'))
DumpKey ($PE + '\Control\Network\' + $SVS) 'F-PE-STORE'
DumpKey ($OFF + '\ControlSet001\Control\Network\' + $SVS) 'F-OFF-STORE'
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
foreach ($e in $es) { L ('  F DEV code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' driverKey=' + (Clean ('' + $e.PNPClass)) + ' ' + (Trim2 ('' + $e.Name) 50)) }
L 'P69 END'
