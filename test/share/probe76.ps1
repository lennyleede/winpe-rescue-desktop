# probe76 -- LIVE PE. probe75 gave three hard results:
#   R1 the PE's WORKING wired NIC (rt640x64, netEnabled=True, Running) DOES carry NdisMajorVersion=6 /
#      NdisMinorVersion=40 / DriverMajorVersion=10 while Netwtw14 has none -- so that gap is real and correlates
#      with broken-vs-working. BUT writing 6/60/11/2 into Services\Netwtw14 changed nothing (restart-device and a
#      full remove+scan both leave code=37, netwtw14.sys absent from the module list). Neither INF declares those
#      values (0 hits in 3859 / 4735 INF lines), so they are class-installer-written; my numbers were guesses.
#   R2 NdisImPlatform -- the NDIS IM (filter) driver host that nwifi.sys and vwififlt.sys need -- is missing from
#      the PE in BOTH forms (no service key, no X:\...\drivers\NdisImPlatform.sys), while the offline hive has it:
#      Type=1 Start=3 ErrorControl=1 ImagePath=System32\drivers\NdisImPlatform.sys + a Parameters subkey.
#      Offline binary = 135,168B v10.0.19041.546.
#   R3 a service key created at runtime was INVISIBLE to the SCM: OpenService(NdisImPlatform) -> 1060
#      ERROR_SERVICE_DOES_NOT_EXIST, even though reg/Get-Item read the key back fine. If the PE's SCM never
#      accepts runtime-created services, live testing of any service bake is impossible and only an offline
#      re-cut can validate it -- that methodology question is settled here first.
# Sections: =0 current binding after probe75's reinstall  =1 does the SCM see a runtime-created service?
#   =2 stage NdisImPlatform.sys + its covering catalog, register the service from a copied key (so it inherits a
#   real service SD), and try to start it, then the two WiFi filters  =3 finally force the device onto the
#   laptop's own 23.150.0.4 package and see whether code 37 is driver-version-driven  =4 verdict.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$NET = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$CATD = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$OFF = 'HKLM:\R8OFF'
$DEVID = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$INST = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$SRV14 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netwtw14'
$peCls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $NET
$N = 'HKLM:\SYSTEM\CurrentControlSet\Services\NdisImPlatform'
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
public static class P76 {
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
    return "opened ok=" + ok + " err=" + e;
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
function Verdict([string]$tag) {
  Dev $tag
  L ('  ' + $tag + ' ' + (Trim2 ([P76]::Mods('netwtw,nwifi,vwifi,implatform,wdiwifi')) 300))
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) {
    $kids = @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
    L ('  ' + $tag + ' BIND=[' + (Trim2 ($kids -join ',') 180) + ']')
  } else { L ('  ' + $tag + ' BIND ABSENT') }
  L ('  ' + $tag + ' Netwtw14=' + (St 'Netwtw14') + ' nativewifip=' + (St 'nativewifip') + ' vwififlt=' + (St 'vwififlt') + ' vwifibus=' + (St 'vwifibus') + ' NdisImPlatform=' + (St 'NdisImPlatform') + ' wlansvc=' + (St 'wlansvc'))
  L ('  ' + $tag + ' ' + (Trim2 ([P76]::Wlan()) 120))
}

if (-not (Test-Path -LiteralPath ($OFF + '\ControlSet001'))) {
  $rl = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  $jj = $rl -join '|'
  L ('  pre load ' + (Trim2 $jj 160))
}

# ---------- 0. what did probe75's remove+scan bind the device to? ----------
L '=0 binding after reinstall'
$slot = VOf $INST 'Driver'
L ('  0 instance Driver=' + $slot + ' UpperFilters=' + (VOf $INST 'UpperFilters') + ' ConfigFlags=' + (VOf $INST 'ConfigFlags') + ' Service=' + (VOf $INST 'Service'))
$slotKey = $peCls + '\' + ($slot -replace '.*\\', '')
if ($slot -ne 'ABSENT' -and (Test-Path -LiteralPath $slotKey)) {
  $si = Get-Item -LiteralPath $slotKey
  foreach ($vn in @('ComponentId', 'InfPath', 'DriverDate', 'DriverVersion', 'ProviderName', 'DriverPackage') ) {
    L ('  0 slot ' + $vn + '=' + (Trim2 (VOf $slotKey $vn) 90))
  }
} else { L '  0 slot key unreadable' }
L ('  0 svc ImagePath=' + (Trim2 (VOf $SRV14 'ImagePath') 120))
L ('  0 which package is that? 5433b0(23.40)=' + (VOf $SRV14 'ImagePath').Contains('5433b0') + ' c3785d(23.150)=' + (VOf $SRV14 'ImagePath').Contains('c3785d') + ' 477c02(23.60)=' + (VOf $SRV14 'ImagePath').Contains('477c02'))
Verdict '0'

# ---------- 1. methodology: can the PE SCM see a service created at runtime? ----------
L '=1 SCM visibility of runtime-created services'
$probe = 'HKLM:\SYSTEM\CurrentControlSet\Services\P76Probe'
$ra = @(& reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\P76Probe' /v Type /t REG_DWORD /d 1 /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$raj = $ra -join '|'
L ('  1 add Type ' + (Trim2 $raj 90))
$rb = @(& reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\P76Probe' /v Start /t REG_DWORD /d 3 /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  1 add Start ' + (Trim2 ($rb -join '|') 90))
$rc = @(& reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\P76Probe' /v ErrorControl /t REG_DWORD /d 1 /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$rd = @(& reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\P76Probe' /v ImagePath /t REG_EXPAND_SZ /d "System32\drivers\wanarp.sys" /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
$rdj = $rd -join '|'
L ('  1 add ImagePath ' + (Trim2 $rdj 90))
L ('  1 key exists=' + (Test-Path -LiteralPath $probe) + ' values=[' + (@((Get-Item -LiteralPath $probe -EA SilentlyContinue).GetValueNames()) -join ',') + ']')
L ('  1 START P76Probe -> ' + [P76]::Start('P76Probe') + ' get-service=' + (St 'P76Probe'))
L ('  1 MODULES ' + (Trim2 ([P76]::Mods('wanarp')) 200))
$rdel = @(& reg.exe delete 'HKLM\SYSTEM\CurrentControlSet\Services\P76Probe' /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  1 cleanup delete ' + (Trim2 ($rdel -join '|') 90))

# ---------- 2. NdisImPlatform: binary + covering catalog + service registered from a real service key ----------
L '=2 NdisImPlatform staging'
$offP = $OFF + '\ControlSet001\Services\NdisImPlatform'
foreach ($vn in @((Get-Item -LiteralPath $offP -EA SilentlyContinue).GetValueNames())) {
  L ('  2 OFF ' + $vn + '=' + (Trim2 (VOf $offP $vn) 110))
}
L ('  2 OFF Parameters=[' + (Trim2 (@((Get-Item -LiteralPath ($offP + '\Parameters') -EA SilentlyContinue).GetValueNames()) -join ',') 120) + ']')
foreach ($w in @('X:\Windows\System32\drivers\wdiwifi.sys', 'X:\Windows\System32\drivers\NdisImPlatform.sys')) {
  L ('  2 PE file ' + (Trim2 $w 46) + '=' + (Test-Path -LiteralPath $w))
}
L ('  2 PE wdiwifi service=' + (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\wdiwifi') + ' OFF wdiwifi=' + (Test-Path -LiteralPath ($OFF + '\ControlSet001\Services\wdiwifi')))
$cats = @(Get-ChildItem -LiteralPath ('D:\Windows\System32\CatRoot\' + $CATD) -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)implat|ndis|wifi' })
L ('  2 D: cat candidates=' + (@($cats | ForEach-Object { $_.Name }) -join ','))
$hit = ''
foreach ($c in @($cats | Select-Object -First 12)) {
  $dump = @(& certutil.exe -dump $c.FullName 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  $m = @($dump | Where-Object { $_ -match '(?i)NdisImPlatform' })
  if ($m.Count -gt 0) {
    $mm = ($m[0])
    L ('  2 CAT-HIT ' + $c.Name + ' -> ' + (Trim2 $mm 120))
    $hit = $c.FullName
    break
  }
}
if ($hit -eq '') { L '  2 no cat covers it among candidates (will still try without)' }
$sysSrc = 'D:\Windows\System32\drivers\NdisImPlatform.sys'
$c1 = @(& cmd.exe /c "copy /y `"$sysSrc`" `"X:\Windows\System32\drivers\`"" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  2 copy sys ' + (Trim2 ($c1 -join '|') 120))
if ($hit -ne '') {
  $q = [char]34
  $catDir = 'X:\Windows\System32\CatRoot\' + $CATD
  $cmdline = 'copy /y ' + $q + $hit + $q + ' ' + $q + ($catDir + '\') + $q
  $c2 = @(& cmd.exe /c $cmdline 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  2 copy cat ' + (Trim2 ($c2 -join '|') 120))
  L ('  2 cat now in PE=' + (Test-Path -LiteralPath ($catDir + '\' + $hit.Split('\')[-1])))
}
# wipe the key probe75 created (the SCM ignored it) and rebuild it by copying a real service key, so the new
# key inherits a genuine service security descriptor instead of a plain inherited ACL
$del = @(& reg.exe delete 'HKLM\SYSTEM\CurrentControlSet\Services\NdisImPlatform' /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  2 del old ' + (Trim2 ($del -join '|') 100))
$cp = @(& reg.exe copy 'HKLM\SYSTEM\CurrentControlSet\Services\ndistapi' 'HKLM\SYSTEM\CurrentControlSet\Services\NdisImPlatform' /s /f 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  2 reg copy ndistapi-> ' + (Trim2 ($cp -join '|') 140))
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
$srcK = $LM.OpenSubKey('R8OFF\ControlSet001\Services\NdisImPlatform', $false)
$dstK = $LM.OpenSubKey('SYSTEM\CurrentControlSet\Services\NdisImPlatform', $true)
if (($null -ne $srcK) -and ($null -ne $dstK)) {
  Copy-Tree $srcK $dstK
  # the copied donor key brought its own values/subkeys; drop anything the offline NdisImPlatform does not have
  $keepV = @($srcK.GetValueNames())
  $keepS = @($srcK.GetSubKeyNames())
  foreach ($vn in @($dstK.GetValueNames())) {
    if ($keepV -notcontains $vn) { try { $dstK.DeleteValue($vn, $true) } catch { } }
  }
  foreach ($sn in @($dstK.GetSubKeyNames())) {
    if ($keepS -notcontains $sn) { try { $dstK.DeleteSubKeyTree($sn, $false) } catch { } }
  }
  [void]$dstK.SetValue('Start', 3, 'DWord')
  [void]$dstK.SetValue('Group', 'NDIS', 'String')
}
L ('  2 key after rebuild=' + (Test-Path -LiteralPath $N))
$ki = Get-Item -LiteralPath $N -EA SilentlyContinue
$kn = 'n/a'
$vvv = 'n/a'
if ($null -ne $ki) { $kn = @($ki.GetSubKeyNames()) -join ','; $vvv = @($ki.GetValueNames()) -join ',' }
L ('  2 now values=[' + $vvv + '] subs=[' + $kn + '] Img=' + (Trim2 (VOf $N 'ImagePath') 80) + ' Type=' + (VOf $N 'Type') + ' Start=' + (VOf $N 'Start') + ' Depend=' + (Trim2 (VOf $N 'DependOnService') 60))
if ($null -ne $ki) {
  L ('  2 START NdisImPlatform -> ' + [P76]::Start('NdisImPlatform') + ' get-service=' + (St 'NdisImPlatform'))
  L ('  2 MODULES ' + (Trim2 ([P76]::Mods('implatform,wifi')) 240))
  L ('  2 retry filters: ' + [P76]::Start('nativewifip') + ' / ' + [P76]::Start('vwififlt'))
  L ('  2 MODULES2 ' + (Trim2 ([P76]::Mods('implatform,wifi')) 240))
} else { L '  2 SKIP start (key missing)' }

# ---------- 3. is code 37 driver-version-driven? force the laptop's own 23.150 package ----------
L '=3 bind 23.150.0.4 (the driver this AX211 runs under this laptop Windows)'
$inf150 = 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw6e.INF'
L ('  3 inf exists=' + (Test-Path -LiteralPath $inf150))
$a1 = @(& pnputil.exe /add-driver "$inf150" /install 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  3 ADD-DRIVER ' + (Trim2 ($a1 -join '|') 260))
Start-Sleep -Seconds 6
$rm = @(& pnputil.exe /remove-device "$DEVID" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  3 REMOVE ' + (Trim2 ($rm -join '|') 140))
Start-Sleep -Seconds 4
$sc = @(& pnputil.exe /scan-devices 2>&1 | ForEach-Object { (Clean ('' + $_)) })
L ('  3 SCAN ' + (Trim2 ($sc -join '|') 140))
for ($i = 0; $i -lt 8; $i++) {
  Start-Sleep -Seconds 6
  $n2 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' }).Count
  if ($n2 -gt 0) { break }
}
$slot2 = VOf $INST 'Driver'
L ('  3 instance Driver=' + $slot2 + ' UpperFilters=' + (VOf $INST 'UpperFilters'))
L ('  3 svc ImagePath=' + (Trim2 (VOf $SRV14 'ImagePath') 120))
Verdict '3-AFTER-150'
L ('  3 RESTART -> ' + (Trim2 (@(& pnputil.exe /restart-device "$DEVID" 2>&1 | ForEach-Object { (Clean ('' + $_)) }) -join '|') 200))
Start-Sleep -Seconds 12
Verdict '3-RESTARTED'

L '=4 setupapi tail'
$t = @(Get-Content -LiteralPath 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
foreach ($h in @($t | Select-Object -Last 22)) { $c2 = Clean ('' + $h); if ($c2 -ne '') { L ('  4 ' + (Trim2 $c2 165)) } }
L 'P76 END'
