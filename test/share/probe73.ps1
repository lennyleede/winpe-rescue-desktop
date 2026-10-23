# probe73 -- LIVE PE, follow-up to probe72. Two things to settle:
#  1. probe72's controls show the PE loads kernel drivers on demand just fine (NdisTapi/NdisWan/ndproxy/RasAcd/
#     vwifibus all ok=True err=0 -> Running) while vwififlt and nativewifip give err=31. Those two are the NDIS
#     "filter" services, so err=31 on demand is not by itself proof of breakage. The real new fact is that
#     Netwtw14 itself is Stopped with the device at code 37 -- so test the MINIPORT directly (err=577 would mean
#     code integrity blocked the Intel package; err=31 would mean its DriverEntry failed) and look at the package
#     contents/catalog, because DISM imported the pool with /ForceUnsigned.
#  2. probe72 never actually tested the laptop's own working package: PE drvload has no /force switch.
#     Retry plain `drvload <D:\...\Netwtw6e.INF>` for 23.150.0.4 (and 23.60.1.2), which is the driver this very
#     AX211 runs successfully under this very laptop's Windows 10.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Trim2([string]$s, [int]$n) { $t = (Clean $s); if ($t.Length -gt $n) { $t = $t.Substring(0, $n) }; return $t }
$DEVID = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
function St([string]$n) { $x = 'NOGET'; try { $x = '' + (Get-Service $n -EA Stop).Status } catch { }; return $x }
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class P73Scm {
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
  public static string CertDir(string path) {
    // PE optional-header DATA_DIRECTORY[4] = certificate / Authenticode. 0 => catalog-signed only.
    try {
      byte[] b = System.IO.File.ReadAllBytes(path);
      if (b.Length < 0x100) { return "TOOSMALL"; }
      int e_lfanew = BitConverter.ToInt32(b, 0x3C);
      int optOff = e_lfanew + 24;
      ushort magic = BitConverter.ToUInt16(b, optOff);
      int ddOff = optOff + (magic == 0x20B ? 112 : 96);
      uint certRva = BitConverter.ToUInt32(b, ddOff + 8);
      uint certSize = BitConverter.ToUInt32(b, ddOff + 12);
      return "magic=0x" + magic.ToString("X4") + " certRva=" + certRva + " certSize=" + certSize;
    } catch (Exception ex) { return "ERR " + ex.Message; }
  }
}
'@ -EA Stop
  L '  ADDTYPE ok'
} catch { L ('  ADDTYPE-ERR ' + (Trim2 ('' + $_.Exception.Message) 300)); return }

L '=0 miniport loadability (the device is code 37 with Netwtw14 Stopped)'
L ('  0 CM ' + (Trim2 ((@(& pnputil.exe /enum-devices /instanceid "$DEVID" /drivers /problemcodes 2>&1 | ForEach-Object { (Clean ('' + $_)) })) -join ' | ') 500))
foreach ($n in 'Netwtw14', 'Netwtw08', 'Netwtw10', 'nativewifip', 'vwififlt') {
  L ('  0 START ' + $n + ' -> ' + [P73Scm]::Start($n) + ' now=' + (St $n))
}
foreach ($p in @('X:\windows\system32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e\Netwtw14.sys',
                 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw14.sys',
                 'X:\Windows\System32\drivers\nwifi.sys', 'D:\Windows\System32\drivers\nwifi.sys')) {
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    L ('  0 CERT ' + (Trim2 $p 100) + ' ' + $i.Length + 'B ' + [P73Scm]::CertDir($p))
  } else { L ('  0 CERT ' + (Trim2 $p 100) + ' MISSING') }
}
$cat = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}' -Filter 'oem1*.cat' -EA SilentlyContinue)
L ('  0 CatRoot oem1xx cat count=' + $cat.Count + ' names=[' + (Trim2 ((@($cat | ForEach-Object { $_.Name }) -join ',') ) 300) + ']')
L ('  0 oem161.cat present=' + (Test-Path -LiteralPath 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\oem161.cat'))
$fr = @(Get-ChildItem -LiteralPath 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e' -EA SilentlyContinue)
L ('  0 X:5433b0 files=[' + (@($fr | ForEach-Object { $_.Name }) -join ',') + ']')
$fr2 = @(Get-ChildItem -LiteralPath 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e' -EA SilentlyContinue)
L ('  0 D:c3785d files=[' + (@($fr2 | ForEach-Object { $_.Name }) -join ',') + ']')

# ---------- 1. drvload the laptop's own working package (no /force -- PE drvload has none) ----------
L '=1 drvload 23.150 / 23.60 from D: DriverStore'
foreach ($dn in 'netwtw6e.inf_amd64_c3785d6f1e6d5b0e', 'netwtw6e.inf_amd64_477c028818b7a796') {
  $infp = 'D:\Windows\System32\DriverStore\FileRepository\' + $dn + '\Netwtw6e.INF'
  if (-not (Test-Path -LiteralPath $infp)) { L ('  1 ' + $dn + ' INF MISSING'); continue }
  $r = @(& drvload.exe "$infp" 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('  1 DRVLOAD ' + $dn + ' -> ' + (Trim2 ($r -join ' | ') 400))
  Start-Sleep -Seconds 12
  $es = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($e in $es) { L ('  1 AFTER ' + $dn + ' code=' + $e.ConfigManagerErrorCode + ' status=' + (Clean ('' + $e.Status)) + ' ' + (Trim2 ('' + $e.Name) 40)) }
  $sd = Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -like 'Netwtw*' }
  foreach ($s in $sd) { L ('  1 SYS ' + $s.Name + ' state=' + (Clean ('' + $s.State)) + ' path=' + (Trim2 ('' + $s.PathName) 130)) }
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\NativeWifiP\Parameters\Adapters'
  if (Test-Path -LiteralPath $p) { L ('  1 BIND ' + $dn + ' [' + (Trim2 (@(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | ForEach-Object { $_.PSChildName }) -join ',') 200) + ']') } else { L ('  1 BIND ABSENT') }
  L ('  1 wlansvc=' + (St 'wlansvc') + ' nativewifip=' + (St 'nativewifip') + ' vwififlt=' + (St 'vwififlt') + ' vwifibus=' + (St 'vwifibus'))
}
# ---------- 2. what did setupapi say about it ----------
L '=2 setupapi tail'
$t = @(Get-Content -LiteralPath 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
L ('  2 lines=' + $t.Count)
foreach ($h in @($t | Select-Object -Last 40)) { $c = Clean ('' + $h); if ($c -ne '') { L ('  2 ' + (Trim2 $c 190)) } }
L ('  2 devnodes now=' + (@(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })).Count)
L 'P73 END'
