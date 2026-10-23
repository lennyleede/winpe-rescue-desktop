# probe66 -- LIVE PE, the R8 experiment, take 2 (probe65 wrote the component store fine but its FilterList
# write failed and both Add-Type blocks were malformed).
# probe65 results worth keeping:
#   W1 worked: HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318} now holds
#     {E475CF9A-..} (ms_nativewifip, Ndi\Service=NativeWifiP, Ndi\Interfaces\FilterMediaTypes=wlan) and
#     {5CBF81BF-..} (ms_vwifi) copied verbatim out of the offline hive of this very laptop.
#   W2 failed: Get-Item hands back a READ-ONLY RegistryKey, so .SetValue threw UnauthorizedAccessException.
#     Fix = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rel, $true), with a reg.exe fallback.
#   After only W1 + restart-device the AX211 stayed code 37 (expected: FilterList is what NDIS reads).
# Add-Type pitfall: -MemberDefinition takes MEMBERS ONLY (no using-directives, no class declaration);
#   -TypeDefinition takes the whole source. Both blocks here use -TypeDefinition.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'

try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P66Scm {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManager(IntPtr m, IntPtr d, int a);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenService(IntPtr s, string n, int a);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartService(IntPtr s, int c, IntPtr v);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool CloseServiceHandle(IntPtr h);
  public static string Start(string n) {
    IntPtr scm = OpenSCManager(IntPtr.Zero, IntPtr.Zero, 1);
    if (scm == IntPtr.Zero) { return "SCMERR=" + Marshal.GetLastWin32Error(); }
    IntPtr h = OpenService(scm, n, 0x10);
    if (h == IntPtr.Zero) { CloseServiceHandle(scm); return "OPENERR=" + Marshal.GetLastWin32Error(); }
    bool ok = StartService(h, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    CloseServiceHandle(h); CloseServiceHandle(scm);
    return "ok=" + ok + " err=" + e;
  }
}
'@ -EA Stop
  L '  ADDTYPE scm ok'
} catch { L ('  ADDTYPE-SCM-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')); return }

function St([string]$n) { $x='NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch {}; return $x }
function Dev([string]$tag) {
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($e in $es) { L ('  ' + $tag + ' code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' ' + (Clean ('' + $e.Name))) }
  if ($es.Count -eq 0) { L ('  ' + $tag + ' NO DEVNODE') }
}
function BindRec([string]$tag) {
  foreach ($svc in 'NativeWifiP', 'nativewifip', 'vwififlt') {
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $svc + '\Parameters\Adapters'
    if (Test-Path -LiteralPath $p) {
      $kids = @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
      L ('  ' + $tag + ' ' + $svc + '\Parameters\Adapters =[' + ($kids -join ' ') + ']')
    }
  }
}

# ---------- 0. CI guard ----------
L '=0 nwifi loadability'
$f = Get-Item -LiteralPath 'X:\Windows\System32\drivers\nwifi.sys' -EA SilentlyContinue
if ($null -ne $f) {
  $vi = $f.VersionInfo
  L ('  0 FILE ' + $f.Length + 'B v=' + $vi.FileMajorPart + '.' + $vi.FileMinorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
}
$s0 = [P66Scm]::Start('nativewifip')
L ('  0 START nativewifip : ' + $s0 + ' state=' + (St 'nativewifip'))
if ($s0 -match 'err=577') { L '  0 VERDICT CI-BLOCKED, reboot the PE first (probe59 left an uncatalogued 19041.1415 nwifi.sys)'; return }

# ---------- 1. W1 component store (idempotent, re-copy) ----------
L '=1 component store'
$LM = [Microsoft.Win32.Registry]::LocalMachine
$offRootKey = $LM.OpenSubKey('R8OFF\ControlSet001\Control\Network\' + $SVS, $false)
if ($null -eq $offRootKey) {
  $rr = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  1 reg load ' + ($rr -join '|'))
  $offRootKey = $LM.OpenSubKey('R8OFF\ControlSet001\Control\Network\' + $SVS, $false)
}
if ($null -eq $offRootKey) { L '  1 NO OFFLINE STORE -- ABORT'; return }
function Copy-Tree($src, $dst) {
  foreach ($vn in @($src.GetValueNames())) {
    $kind = $src.GetValueKind($vn)
    $val = $src.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    if ($kind.ToString() -eq 'MultiString') { [void]$dst.SetValue($vn, [string[]]$val, $kind) }
    else { [void]$dst.SetValue($vn, $val, $kind) }
  }
  foreach ($sn in @($src.GetSubKeyNames())) {
    $s2 = $src.OpenSubKey($sn, $false)
    $d2 = $dst.CreateSubKey($sn)
    if (($null -ne $s2) -and ($null -ne $d2)) { Copy-Tree $s2 $d2 }
  }
}
$peRootKey = $LM.CreateSubKey('SYSTEM\CurrentControlSet\Control\Network\' + $SVS)
foreach ($pair in @(@('nwifi', $NWIFI), @('vwififlt', $VFLT))) {
  $s = $offRootKey.OpenSubKey($pair[1], $false)
  if ($null -eq $s) { L ('  1 SKIP ' + $pair[0] + ' offline record missing'); continue }
  $d = $peRootKey.CreateSubKey($pair[1])
  Copy-Tree $s $d
  $ndi = $d.OpenSubKey('Ndi')
  $ifc = $null
  if ($null -ne $ndi) { $ifc = $ndi.OpenSubKey('Interfaces') }
  $vSvc = '-'; $vCls = '-'; $vTyp = '-'; $vRun = '-'; $vMed = '-'
  if ($null -ne $ndi) {
    $vSvc = '' + $ndi.GetValue('Service', '-')
    $vCls = '' + $ndi.GetValue('FilterClass', '-')
    $vTyp = '' + $ndi.GetValue('FilterType', '-')
    $vRun = '' + $ndi.GetValue('FilterRunType', '-')
  }
  if ($null -ne $ifc) { $vMed = '' + $ifc.GetValue('FilterMediaTypes', '-') }
  L ('  1 WROTE ' + $pair[0] + ' values=' + (@($d.GetValueNames()).Count) + ' Ndi.Service=' + $vSvc +
     ' FilterClass=' + $vCls + ' FilterType=' + $vTyp + ' FilterRunType=' + $vRun + ' FilterMediaTypes=' + $vMed)
}
$peRootKey.Close(); $offRootKey.Close()

# ---------- 2. W2 FilterList on the AX211 class slot ----------
L '=2 FilterList write'
$rel = ''
$id = ''
$clsRel = 'SYSTEM\CurrentControlSet\Control\Class\' + $NET
$clsPS = 'HKLM:\' + $clsRel
foreach ($nn in @(Get-ChildItem -LiteralPath $clsPS -EA SilentlyContinue)) {
  if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
  $g = Get-Item -LiteralPath ($clsPS + '\' + $nn.PSChildName)
  if ((Clean ('' + $g.GetValue('MatchingDeviceId', ''))) -match 'VEN_8086&DEV_7A70') {
    $rel = $clsRel + '\' + $nn.PSChildName + '\Linkage'
    $id = Clean ('' + $g.GetValue('NetCfgInstanceId', ''))
  }
}
if ($rel -eq '') { L '  2 NO AX211 CLASS SLOT -- abort'; return }
L ('  2 slot rel=' + $rel + ' NetCfgInstanceId=' + $id)
$fl = @(($id + '-' + $VFLT + '-0000'), ($id + '-' + $NWIFI + '-0000'))
$w = $LM.OpenSubKey($rel, $true)
if ($null -eq $w) { L '  2 OpenSubKey(writable) returned NULL' } else {
  L ('  2 writable handle ok, before FilterList=[' + (Clean ('' + ($w.GetValue('FilterList', @()) -join ';'))) + ']')
  try {
    [void]$w.SetValue('FilterList', [string[]]$fl, 'MultiString')
    L '  2 .NET SetValue ok'
  } catch {
    L ('  2 .NET SetValue FAILED ' + (($_.Exception.Message) -replace '\s+', ' '))
    $rr2 = @(& reg.exe add ('HKLM\' + $rel) /v FilterList /t REG_MULTI_SZ /d ($fl -join ';') /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
    L ('  2 reg.exe add ' + ($rr2 -join '|'))
  }
  L ('  2 AFTER FilterList=[' + (Clean ('' + ($w.GetValue('FilterList', @()) -join ';'))) + ']')
  $w.Close()
}

# ---------- 3. rebind and watch ----------
L '=3 restart-device'
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es.Count -eq 0) { L '  3 NO DEVNODE' } else {
  $r = @(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  3 RESTART ' + ($r -join ' | '))
}
Start-Sleep -Seconds 8
Dev 'AFTER-RESTART'
L ('  3 START nativewifip : ' + [P66Scm]::Start('nativewifip') + ' state=' + (St 'nativewifip'))
Start-Sleep -Seconds 3
Dev 'AFTER-NWIFI'
L ('  3 restart again : ' + (@(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) }) -join '|'))
Start-Sleep -Seconds 8
Dev 'AFTER-RESTART2'
foreach ($n in 'nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'wlansvc', 'wcmsvc') { L ('  3 STATE ' + $n + ' = ' + (St $n)) }
BindRec 'REC'
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P66Wlan {
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
  [DllImport("wlanapi.dll")]
  static extern int WlanCloseHandle(IntPtr handle, IntPtr res);
  public static string Probe() {
    int nv = 0; IntPtr h = IntPtr.Zero;
    int rc = WlanOpenHandle(1, IntPtr.Zero, out nv, out h);
    if (rc != 0) { return "OPEN rc=" + rc; }
    int cnt = 0; IntPtr list = IntPtr.Zero;
    int rc2 = WlanEnumInterfaces(h, IntPtr.Zero, out list, out cnt);
    WlanCloseHandle(h, IntPtr.Zero);
    return "OPEN rc=0 ENUM rc=" + rc2 + " interfaces=" + cnt;
  }
}
'@ -EA Stop
  L ('  4 WLANAPI : ' + ([P66Wlan]::Probe()))
} catch { L ('  4 WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
L ('  4 wlansvc START : ' + [P66Scm]::Start('wlansvc') + ' state=' + (St 'wlansvc'))
Start-Sleep -Seconds 4
L ('  4 WLANAPI after wlansvc : ' + ([P66Wlan]::Probe()))
BindRec 'AFTER-WLANSVC'
Dev 'FINAL'
L 'P66 END'
