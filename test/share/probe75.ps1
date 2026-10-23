# probe75 -- LIVE PE. probe74 produced two concrete, bake-able image gaps and one hard fact:
#   FACT   Netwtw14.sys is NOT in the loaded-module list at all (total=214, only ndis/ndisvirtualbus/ndistapi/
#          ndiswan/ndproxy/vwifibus matched), while its imports all resolve (ntoskrnl 105/0 missing, NDIS 49/0,
#          cng 10/0, hal 2/0, WDFLDR 5/0) and it carries a valid embedded Authenticode (cert entry4 =
#          5507584/19624) plus a Valid Netwtw6e.cat. So this is neither a signature nor an import problem --
#          the image is never brought in.
#   GAP A  HKLM\...\Services\Netwtw14 in the PE has NO NdisMajorVersion / NdisMinorVersion / DriverMajorVersion
#          / DriverMinorVersion, while the same laptop's WORKING offline hive has 6 / 60 / 11 / 2.
#   GAP B  Services\NdisImPlatform exists offline but is ABSENT in the PE -- that is the NDIS IM (filter) driver
#          host, which is exactly what nwifi.sys / vwififlt.sys need; it explains their err=31 and the missing
#          NativeWifiP bind marker.
# (Also learned: NtLoadDriver is useless here -- 0xC0000061 STATUS_PRIVILEGE_NOT_HELD even after RtlAdjustPrivilege
#  returns OK, and PE has no whoami.exe.)
# This probe: (1) read the declared versions straight from the INF (authoritative for the bake), (2) use the PE's
# own WORKING wired NICs as the control for GAP A, (3) dump NdisImPlatform + the Net class key, then (4) apply both
# fixes live and restart the device.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$peCls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET
$OFF = 'HKLM:\R8OFF'
$DEVID = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$SVCX = 'X:\windows\system32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e\Netwtw6e.INF'
$SVCD = 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw6e.INF'
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
function VOf([string]$key, [string]$name) {
  $v = 'ABSENT'
  if (Test-Path -LiteralPath $key) {
    $i = Get-Item -LiteralPath $key
    if (@($i.GetValueNames()) -contains $name) { $v = '' + ($i.GetValue($name) -join ';') }
  }
  return $v
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P75 {
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool K32EnumDeviceDrivers(IntPtr[] lpp, int cb, out int needed);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern int K32GetDeviceDriverBaseNameW(IntPtr drv, StringBuilder buf, int count);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManager(IntPtr m, IntPtr d, int a);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenService(IntPtr s, string n, int a);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartService(IntPtr s, int c, IntPtr v);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
  [DllImport("wlanapi.dll")]
  static extern int WlanCloseHandle(IntPtr handle, IntPtr res);
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
  public static string Wlan() {
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
} catch { $m = '' + $_.Exception.Message; L ('  ADDTYPE-ERR ' + (Trim2 $m 300)); return }

function Dev([string]$tag) {
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($e in $es) { L ('  ' + $tag + ' code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' ' + (Trim2 ('' + $e.Name) 40)) }
  if ($es.Count -eq 0) { L ('  ' + $tag + ' NO DEVNODE') }
}
function Bind([string]$tag) {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) {
    $kids = @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
    L ('  ' + $tag + ' BIND=[' + (Trim2 ($kids -join ',') 200) + ']')
  } else { L ('  ' + $tag + ' BIND ABSENT') }
}
function Verdict([string]$tag) {
  Dev $tag
  L ('  ' + $tag + ' ' + (Trim2 ([P75]::Mods('netwtw,nwifi,vwifii,vwifi,implatform')) 300))
  Bind $tag
  L ('  ' + $tag + ' svc: Netwtw14=' + (St 'Netwtw14') + ' nativewifip=' + (St 'nativewifip') + ' vwififlt=' + (St 'vwififlt') + ' vwifibus=' + (St 'vwifibus') + ' NdisImPlatform=' + (St 'NdisImPlatform'))
  L ('  ' + $tag + ' ' + (Trim2 ([P75]::Wlan()) 120))
}

# ---------- 0. what does the INF itself declare ----------
L '=0 INF declared versions (authoritative for the bake)'
foreach ($inf in @($SVCX, $SVCD)) {
  if (-not (Test-Path -LiteralPath $inf)) { L ('  0 ' + (Trim2 $inf 80) + ' MISSING'); continue }
  $lines = @(Get-Content -LiteralPath $inf -Encoding Unicode -EA SilentlyContinue)
  $sec = ''
  $shown = 0
  foreach ($ln in $lines) {
    $t = (Clean ('' + $ln))
    if ($t -match '^\s*\[.*\]\s*$') { $sec = $t; continue }
    if ($t -match '(?i)^(NdisMajorVersion|NdisMinorVersion|DriverMajorVersion|DriverMinorVersion)\s*=') {
      L ('  0 ' + (Trim2 $sec 40) + ' ' + (Trim2 $t 80))
      $shown = $shown + 1
      if ($shown -ge 12) { break }
    }
  }
  L ('  0 ' + (Trim2 $inf 80) + ' lines=' + $lines.Count + ' hits=' + $shown)
}
if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  $jj = $rl -join '|'
  L ('  0 load ' + (Trim2 $jj 160))
}
$offSrv = $OFF + '\ControlSet001\Services\Netwtw14'
foreach ($vv in 'NdisMajorVersion', 'NdisMinorVersion', 'DriverMajorVersion', 'DriverMinorVersion') {
  $kd = 'n/a'
  if (Test-Path -LiteralPath $offSrv) { $oi = Get-Item -LiteralPath $offSrv; if (@($oi.GetValueNames()) -contains $vv) { $kd = '' + $oi.GetValueKind($vv) } }
  L ('  0 OFF ' + $vv + ' = ' + (VOf $offSrv $vv) + ' kind=' + $kd)
}

# ---------- 1. control: the PE's own WORKING adapters -- do they carry those values? ----------
L '=1 working-adapter control'
$ads = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.PhysicalAdapter })
foreach ($a in $ads) {
  $sn = '' + $a.ServiceName
  $sk = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $sn
  $nd = VOf $sk 'NdisMajorVersion'
  $nm2 = VOf $sk 'NdisMinorVersion'
  $dm = VOf $sk 'DriverMajorVersion'
  $st14 = VOf $sk 'Start'
  L ('  1 ADAPTER ' + (Trim2 ('' + $a.Name) 34) + ' svc=' + (Trim2 $sn 22) + ' netEnabled=' + (Clean ('' + $a.NetEnabled)) + ' Start=' + $st14 + ' NdisMaj=' + $nd + ' NdisMin=' + $nm2 + ' DrvMaj=' + $dm)
}
$svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
# WMI's NetworkAdapter class can be thin in PE, so read the Net class slots directly: every slot names the
# service it belongs to, which is exactly the population to compare against Netwtw14.
foreach ($sl in @(Get-ChildItem -LiteralPath $peCls -EA SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })) {
  $sn2 = '' + $sl.GetValue('Service')
  $sk2 = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $sn2
  $ncid = '' + $sl.GetValue('NetCfgInstanceId')
  L ('  1 SLOT ' + $sl.PSChildName + ' svc=' + (Trim2 $sn2 22) + ' desc=' + (Trim2 ('' + $sl.GetValue('DriverDesc')) 26) + ' NdisMaj=' + (VOf $sk2 'NdisMajorVersion') + ' NdisMin=' + (VOf $sk2 'NdisMinorVersion') + ' DrvMaj=' + (VOf $sk2 'DriverMajorVersion') + ' Start=' + (VOf $sk2 'Start') + ' state=' + (St $sn2))
}
$grp = @()
foreach ($k in @(Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue)) {
  $g = ''
  try { $g = '' + $k.GetValue('Group') } catch { }
  if ($g -eq 'NDIS') {
    $has = 'no'
    if (@($k.GetValueNames()) -contains 'NdisMajorVersion') { $has = 'yes' }
    $grp += ('{0}:{1}:{2}' -f $k.PSChildName, $has, (St $k.PSChildName))
  }
}
L ('  1 NDIS-group services=' + $grp.Count + ' withNdisMaj=' + (@($grp | Where-Object { $_ -match ':yes:' })).Count)
L ('  1 LIST ' + (Trim2 (($grp -join ' ') ) 1000))

# ---------- 2. NdisImPlatform: offline reference + file presence ----------
L '=2 NdisImPlatform'
$op = $OFF + '\ControlSet001\Services\NdisImPlatform'
$pp = 'HKLM:\SYSTEM\CurrentControlSet\Services\NdisImPlatform'
L ('  2 OFF=' + (Test-Path -LiteralPath $op) + ' PE=' + (Test-Path -LiteralPath $pp))
if (Test-Path -LiteralPath $op) {
  $oi = Get-Item -LiteralPath $op
  foreach ($vn in @($oi.GetValueNames())) {
    $vv = '' + ($oi.GetValue($vn) -join ';')
    $kk = ''
    try { $kk = '' + $oi.GetValueKind($vn) } catch { }
    L ('  2 OFF ' + $vn + ' [' + $kk + '] ' + (Trim2 $vv 130))
  }
  L ('  2 OFF SUBS=[' + (@($oi.GetSubKeyNames()) -join ',') + ']')
}
foreach ($f in @('X:\Windows\System32\drivers\NdisImPlatform.sys', 'X:\Windows\System32\DRIVERS\NdisImPlatform.sys')) {
  if (Test-Path -LiteralPath $f) {
    $fi = Get-Item -LiteralPath $f
    L ('  2 FILE ' + (Trim2 $f 60) + ' ' + $fi.Length + 'B v=' + (Trim2 ('' + $fi.VersionInfo.FileVersion) 30))
  } else { L ('  2 FILE ' + (Trim2 $f 60) + ' MISSING') }
}
$d = @(Get-ChildItem -LiteralPath 'D:\Windows\System32\drivers' -Filter 'NdisImPlatform.sys' -EA SilentlyContinue)
foreach ($x in $d) { L ('  2 D-FILE ' + $x.Name + ' ' + $x.Length + 'B v=' + (Trim2 ('' + $x.VersionInfo.FileVersion) 30)) }
# if the PE image simply lacks the binary, stage it on the ramdisk so section 4 can test the real path
if (-not (Test-Path -LiteralPath 'X:\Windows\System32\drivers\NdisImPlatform.sys')) {
  $src2 = 'D:\Windows\System32\drivers\NdisImPlatform.sys'
  if (Test-Path -LiteralPath $src2) {
    $cp = @(& cmd.exe /c "copy /y `"$src2`" `"X:\Windows\System32\drivers\`"" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
    $cpj = $cp -join '|'
    L ('  2 STAGED sys -> ' + (Trim2 $cpj 160))
    L ('  2 STAGED now=' + (Test-Path -LiteralPath 'X:\Windows\System32\drivers\NdisImPlatform.sys'))
  } else { L '  2 NO SOURCE SYS' }
}

# ---------- 3. Net class key top values: PE vs offline ----------
L '=3 Net class installer registration'
$peCls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET
$ofCls = $OFF + '\ControlSet001\Control\Class\' + $NET
if ((Test-Path -LiteralPath $peCls) -and (Test-Path -LiteralPath $ofCls)) {
  $pa = Get-Item -LiteralPath $peCls
  $pb = Get-Item -LiteralPath $ofCls
  $allk = @(@($pa.GetValueNames()) + @($pb.GetValueNames()) | Sort-Object -Unique)
  foreach ($kk in $allk) {
    $pv = ''
    $ov = ''
    if (@($pa.GetValueNames()) -contains $kk) { $pv = '' + ($pa.GetValue($kk) -join ';') }
    if (@($pb.GetValueNames()) -contains $kk) { $ov = '' + ($pb.GetValue($kk) -join ';') }
    if ($pv -ne $ov) { L ('  3 ' + $kk + ' PE=[' + (Trim2 $pv 110) + '] OFF=[' + (Trim2 $ov 110) + ']') }
  }
  L ('  3 INST32 PE=[' + (VOf $peCls 'Installer32') + '] OFF=[' + (VOf $ofCls 'Installer32') + ']')
  L ('  3 UPPER  PE=[' + (VOf $peCls 'UpperFilters') + '] OFF=[' + (VOf $ofCls 'UpperFilters') + ']')
} else { L '  3 class key pair incomplete' }

# ---------- 4. apply both fixes live ----------
L '=4 apply'
$LM = [Microsoft.Win32.Registry]::LocalMachine
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
$offRoot = $LM.OpenSubKey('R8OFF\ControlSet001\Services\NdisImPlatform', $false)
$peRoot = $LM.CreateSubKey('SYSTEM\CurrentControlSet\Services\NdisImPlatform')
if (($null -ne $offRoot) -and ($null -ne $peRoot)) {
  Copy-Tree $offRoot $peRoot
  [void]$peRoot.SetValue('Start', 3, 'DWord')
  $ck = Get-Item -LiteralPath $pp
  L ('  4 COPIED NdisImPlatform values=[' + (@($ck.GetValueNames()) -join ',') + '] Start=' + (VOf $pp 'Start') + ' Type=' + (VOf $pp 'Type') + ' Group=' + (Trim2 (VOf $pp 'Group') 30) + ' Img=' + (Trim2 (VOf $pp 'ImagePath') 90))
  $ck.GetSubKeyNames() | ForEach-Object { L ('  4  sub ' + $_) }
} else { L ('  4 COPY FAILED off=' + ($null -ne $offRoot) + ' pe=' + ($null -ne $peRoot)) }
L ('  4 START NdisImPlatform -> ' + [P75]::Start('NdisImPlatform') + ' now=' + (St 'NdisImPlatform'))
L ('  4 MODS ' + (Trim2 ([P75]::Mods('implatform,wifi')) 260))

$srv14 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netwtw14'
$w = $LM.OpenSubKey('SYSTEM\CurrentControlSet\Services\Netwtw14', $true)
if ($null -ne $w) {
  [void]$w.SetValue('NdisMajorVersion', 6, 'DWord')
  [void]$w.SetValue('NdisMinorVersion', 60, 'DWord')
  [void]$w.SetValue('DriverMajorVersion', 11, 'DWord')
  [void]$w.SetValue('DriverMinorVersion', 2, 'DWord')
  L ('  4 WROTE Netwtw14 NdisMaj=' + (VOf $srv14 'NdisMajorVersion') + ' NdisMin=' + (VOf $srv14 'NdisMinorVersion') + ' DrvMaj=' + (VOf $srv14 'DriverMajorVersion') + ' DrvMin=' + (VOf $srv14 'DriverMinorVersion'))
} else { L '  4 Netwtw14 key NOT WRITABLE' }
Verdict '4-BEFORE'

L '=5 restart-device with fixes in place'
$r1 = @(& pnputil.exe /restart-device "$DEVID" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$rr = $r1 -join '|'
L ('  5 RESTART ' + (Trim2 $rr 260))
Start-Sleep -Seconds 15
Verdict '5-AFTER'
L ('  5 START Netwtw14 -> ' + [P75]::Start('Netwtw14') + ' now=' + (St 'Netwtw14'))

# ---------- 6. full reinstall: does the class installer write the values itself? ----------
L '=6 remove-device + scan-devices (re-runs the class installer)'
$rm = @(& pnputil.exe /remove-device "$DEVID" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$rmj = $rm -join '|'
L ('  6 REMOVE ' + (Trim2 $rmj 200))
Start-Sleep -Seconds 4
$sc = @(& pnputil.exe /scan-devices 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$scj = $sc -join '|'
L ('  6 SCAN ' + (Trim2 $scj 200))
$seen = 0
for ($i = 0; $i -lt 6; $i++) {
  Start-Sleep -Seconds 6
  $seen = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' }).Count
  if ($seen -gt 0) { break }
}
L ('  6 devnodes=' + $seen)
foreach ($vv in 'NdisMajorVersion', 'DriverMajorVersion') { L ('  6 AFTER-REINSTALL ' + $vv + '=' + (VOf $srv14 $vv)) }
Verdict '6-FINAL'
L '=7 setupapi tail'
$t = @(Get-Content -LiteralPath 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
$tail = @($t | Select-Object -Last 18)
foreach ($h in $tail) { $c = Clean ('' + $h); if ($c -ne '') { L ('  7 ' + (Trim2 $c 170)) } }
L 'P75 END'
