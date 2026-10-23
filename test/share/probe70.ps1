# probe70 -- LIVE PE, the decisive R8b experiment.
# probe69 found the one artifact the WORKING Windows on this very laptop has and the PE does not:
#   A-OFF-INST  Enum\PCI\VEN_8086&DEV_7A70&...\3&11583659&0&A3 : UpperFilters = vwifibus   (REG_MULTI_SZ)
#   A-PE-INST   same key: NO UpperFilters value at all.
# That value is exactly what netvwifibus.inf's [VWiFiBus.PnPFilterRegistration] writes
# (HKR,,"UpperFilters",0x00010000,"vwifibus"), i.e. the section the Intel INF asks for through
# "Include = netvwifibus.inf" and which setupapi could not resolve at boot.
# Second artifact (from probe66): Control\Class\{4d36e972}\NNNN\Linkage\FilterList carrying the nwifi +
#   vwififlt component instances. Offline also proves what SUCCESS looks like: a key
#   Services\NativeWifiP\Parameters\Adapters\{adapter NetCfgInstanceId}\{E475CF9A..}-0000 (empty marker).
# P1 = write both, restart-device. P2 = if P1 fails, full reinstall then write both again and restart
#    (a reinstall regenerates NetCfgInstanceId and clears FilterList, so the writes must come AFTER it).
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VFLT = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$DEVPATH = 'SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$LM = [Microsoft.Win32.Registry]::LocalMachine
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
function FindSlot {
  $best = ''
  $id = ''
  foreach ($nn in @(Get-ChildItem -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET) -EA SilentlyContinue)) {
    if ($nn.PSChildName -notmatch '^\d{4}$') { continue }
    $g = Get-Item -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET + '\' + $nn.PSChildName)
    if ((Clean ('' + $g.GetValue('MatchingDeviceId', ''))) -match 'DEV_7A70') { $best = $nn.PSChildName; $id = Clean ('' + $g.GetValue('NetCfgInstanceId', '')) }
  }
  $out = @($best, $id)
  return $out
}
function WriteUpper([string]$tag) {
  $k = $LM.OpenSubKey($DEVPATH, $true)
  if ($null -eq $k) { L ('  ' + $tag + ' UPPER instance key NOT OPENABLE'); return }
  try { [void]$k.SetValue('UpperFilters', [string[]]@('vwifibus'), 'MultiString'); L ('  ' + $tag + ' UPPER SetValue ok') }
  catch { L ('  ' + $tag + ' UPPER SetValue FAIL ' + (Trim2 ('' + $_.Exception.Message) 160)) }
  L ('  ' + $tag + ' UPPER now=[' + (Clean ('' + ($k.GetValue('UpperFilters', @()) -join ';'))) + ']')
  $k.Close()
}
function WriteFilter([string]$tag, [string]$slot, [string]$id) {
  if ($slot -eq '' -or $id -eq '') { L ($tag + ' NO SLOT/ID'); return }
  $rel = 'SYSTEM\CurrentControlSet\Control\Class\' + $NET + '\' + $slot + '\Linkage'
  $fl = @(($id + '-' + $VFLT + '-0000'), ($id + '-' + $NWIFI + '-0000'))
  $w = $LM.OpenSubKey($rel, $true)
  if ($null -eq $w) { L ('  ' + $tag + ' FILTER no writable Linkage handle'); return }
  try { [void]$w.SetValue('FilterList', [string[]]$fl, 'MultiString'); L ('  ' + $tag + ' FILTER SetValue ok') }
  catch { L ('  ' + $tag + ' FILTER SetValue FAIL ' + (Trim2 ('' + $_.Exception.Message) 160)) }
  L ('  ' + $tag + ' FILTER now=[' + (Trim2 ($w.GetValue('FilterList', @()) -join ';') 240) + ']')
  $w.Close()
}
function Report([string]$tag) {
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($e in $es) { L ('  ' + $tag + ' DEV code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status))) }
  if ($es.Count -eq 0) { L ('  ' + $tag + ' DEV no node') }
  foreach ($n in 'nativewifip', 'vwififlt', 'vwifibus', 'vwifimp', 'wlansvc') { L ('  ' + $tag + ' S ' + $n + '=' + (St $n) + ' ') }
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) {
    foreach ($c in @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue)) {
      L ('  ' + $tag + ' BIND Adapters\' + $c.PSChildName + ' children=[' + (@(Get-ChildItem -LiteralPath $c.PSPath -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ',') + ']')
    }
  } else { L ('  ' + $tag + ' BIND Adapters ABSENT') }
  $kids = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { (Clean ('' + $_.Name)) -match '(?i)virtual (wifi|adapter)|wi-fi direct|vwifi' })
  L ('  ' + $tag + ' VWiFi-DEVICES=' + $kids.Count + ' ' + (Trim2 ((@($kids | ForEach-Object { (Clean ('' + $_.Name)) + '(' + $_.ConfigManagerErrorCode + ')' }) -join ';')) 200))
  L ('  ' + $tag + ' WLAN ' + ([P70Wlan]::Probe()))
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P70Scm {
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
public static class P70Wlan {
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
  L '  ADDTYPE ok'
} catch { L ('  ADDTYPE-ERR ' + (Trim2 ('' + $_.Exception.Message) 200)); return }

# ---------- 0. CI guard ----------
L '=0 guard'
$f = Get-Item -LiteralPath 'X:\Windows\System32\drivers\nwifi.sys' -EA SilentlyContinue
if ($null -eq $f) { L '  0 nwifi.sys ABORT'; return }
$vi = $f.VersionInfo
L ('  0 FILE ' + $f.Length + 'B v=' + $vi.FileMajorPart + '.' + $vi.FileBuildPart + '.' + $vi.FilePrivatePart)
$s0 = [P70Scm]::Start('nativewifip')
L ('  0 START nativewifip ' + $s0)
if ($s0 -match 'err=577') { L '  0 VERDICT CI-BLOCKED reboot first'; return }
L ('  0 vwifibus.sys ' + ((Test-Path -LiteralPath 'X:\Windows\System32\drivers\vwifibus.sys')) + ' netvwifibus.inf ' + ((Test-Path -LiteralPath 'X:\Windows\INF\netvwifibus.inf')))

# ---------- P1: write both, restart device ----------
L '=P1 write UpperFilters + FilterList, restart-device'
$sl = FindSlot
L ('  P1 slot=' + $sl[0] + ' NetCfgId=' + $sl[1])
WriteUpper 'P1'
WriteFilter 'P1' $sl[0] $sl[1]
$es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es.Count -eq 0) { L '  P1 NO DEVNODE' } else {
  L ('  P1 RESTART ' + (Trim2 ((@(& pnputil.exe /restart-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 250))
}
Start-Sleep -Seconds 12
Report 'P1'

# ---------- P2: full reinstall, then write both again ----------
L '=P2 reinstall then write'
if ($es.Count -gt 0) {
  L ('  P2 REMOVE ' + (Trim2 ((@(& pnputil.exe /remove-device "$($es[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 200))
  Start-Sleep -Seconds 3
  L ('  P2 SCAN ' + (Trim2 ((@(& pnputil.exe /scan-devices 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 200))
  Start-Sleep -Seconds 25
}
$sl2 = FindSlot
L ('  P2 slot=' + $sl2[0] + ' NetCfgId=' + $sl2[1])
WriteUpper 'P2'
WriteFilter 'P2' $sl2[0] $sl2[1]
$es2 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
if ($es2.Count -eq 0) { L '  P2 NO DEVNODE AFTER SCAN' } else {
  L ('  P2 RESTART ' + (Trim2 ((@(& pnputil.exe /restart-device "$($es2[0].PNPDeviceID)" 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join '|') 250))
}
Start-Sleep -Seconds 12
Report 'P2'
L ('  P2 START nativewifip ' + [P70Scm]::Start('nativewifip'))
Start-Sleep -Seconds 4
Report 'P2b'
L ('  P2 START wlansvc ' + [P70Scm]::Start('wlansvc'))
Start-Sleep -Seconds 6
Report 'P3'
$sl3 = FindSlot
L ('  FINAL slot=' + $sl3[0] + ' id=' + $sl3[1])
L 'P70 END'
