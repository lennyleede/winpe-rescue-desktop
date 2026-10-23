param([switch]$SkipCopy)
$ErrorActionPreference = 'SilentlyContinue'
# probe38 -- stage the Microsoft vWiFi INFs with SetupCopyOEMInf, the API that does not care about
# publisher signatures (pnputil refused: "third-party INF does not contain digital signature
# information"; drvload refused: 0xE000022F), then let PnP install the adapter from scratch so the
# Include = netvwifibus.inf / Needs = VWiFiBus.* sections have somewhere to resolve to.
#
# probe37 also corrected a big measurement error: Get-DevKeyPath returns a .NET-name path
# (HKEY_LOCAL_MACHINE\...), so every earlier "filters are still empty" reading was Get-ItemProperty
# silently failing on a path form it does not accept. Read the devnode with reg.exe from now on.
# What probe37 proved with trustworthy reads:
#   * reg.exe CAN write UpperFilters/LowerFilters on the devnode and they stick.
#   * pnputil /restart-device reports success but does NOT re-bind the filter stack -- still code=37.
#   * /remove-device + /scan-devices re-created the devnode and SetupAPI re-ran the Intel install
#     (Service=Netwtw14 came back) yet wrote NO UpperFilters at all -- the Include= still did not resolve.
#   * drvload <.sys> says 0x80070002 even though the file is there -- drvload cannot load a bare .sys here.
#   * Win32_SystemDriver never lists vwifibus, because services.exe only knows the drivers registered
#     at boot; raw Services\ keys are invisible to it (that is the 1060 we kept seeing).
Add-Type -Language CSharp @'
using System;using System.Text;using System.Runtime.InteropServices;
public class OemInf38 {
  [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool SetupCopyOEMInfW(string src, string media, int infoType, int flags,
      StringBuilder orig, int origSize, ref int origNeeded, StringBuilder dest);
  public static string Copy(string src) {
    StringBuilder o = new StringBuilder(260);
    StringBuilder d = new StringBuilder(260);
    int need = 0;
    bool ok = SetupCopyOEMInfW(src, null, 0, 0, o, o.Capacity, ref need, d);
    int e = Marshal.GetLastWin32Error();
    if (!ok) return "COPY-FAIL err=" + e;
    return "COPY-OK oem=" + o.ToString() + " dest=" + d.ToString();
  }
}
'@ -EA SilentlyContinue
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm38 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenSCManagerW(string m,string d,uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenServiceW(IntPtr s,string n,uint a);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool StartServiceW(IntPtr s,uint a,IntPtr v);
  [DllImport("advapi32.dll")] public static extern bool CloseServiceHandle(IntPtr h);
  public static string TryStart(string svc) {
    IntPtr m = OpenSCManagerW(null,null,0xF0039u);
    if (m == IntPtr.Zero) return "OPENSCM-FAIL " + Marshal.GetLastWin32Error();
    IntPtr s = OpenServiceW(m, svc, 0x10u | 0xF003Fu);
    if (s == IntPtr.Zero) { string r = "OPENSVC-FAIL " + Marshal.GetLastWin32Error(); CloseServiceHandle(m); return r; }
    bool ok = StartServiceW(s, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    CloseServiceHandle(s); CloseServiceHandle(m);
    return (ok ? "START-OK" : "START-FAIL err=" + e);
  }
}
'@ -EA SilentlyContinue
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi38 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue
function Say([string]$m) { Write-Output ('C38|' + $m) }
function Raw([string]$s) { return (($s -replace "`r?`n", ' ; ') -replace '\s{2,}', ' ') }
function Get-DevKeyPath {
  $d = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'VEN_8086&DEV_7A70' })
  if ($d.Count -eq 0) { return '' }
  $i = @(Get-ChildItem -LiteralPath $d[0].PSPath -EA SilentlyContinue)
  if ($i.Count -eq 0) { return '' }
  return (($i[0].Name) -replace '^.*::HKEY_LOCAL_MACHINE', 'HKLM')
}
function State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Say ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Say ($tag + '|NODE|absent') }
  $k = Get-DevKeyPath
  if ($k) {
    Say ($tag + '|UPPER|' + (Raw (& reg.exe query $k /v UpperFilters 2>&1 | Out-String)))
    Say ($tag + '|LOWER|' + (Raw (& reg.exe query $k /v LowerFilters 2>&1 | Out-String)))
    Say ($tag + '|SERVICE|' + (Raw (& reg.exe query $k /v Service 2>&1 | Out-String)))
    Say ($tag + '|DRIVER|' + (Raw (& reg.exe query $k /v Driver 2>&1 | Out-String)))
  } else { Say ($tag + '|KEY|absent') }
  foreach ($s in 'vwifibus', 'vwififlt', 'nativewifip', 'wlansvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Say ($tag + '|SCMSVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'not-in-scm' }))
  }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Say ($tag + '|NIC|' + $a.Name + '|status=' + $a.NetConnectionStatus)
  }
}
Write-Output ('PROBE38 ' + (Get-Date -Format 'HH:mm:ss') + ' skipCopy=' + [bool]$SkipCopy)
if (-not $SkipCopy) {
  Write-Output '== V1. SetupCopyOEMInf the four Microsoft WiFi INFs =='
  foreach ($n in 'netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf') {
    $p = 'X:\Windows\INF\' + $n
    if (-not (Test-Path $p)) { Say ('COPY|' + $n + '|absent'); continue }
    Say ('COPY|' + $n + '|' + [OemInf38]::Copy($p))
  }
}
foreach ($d in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netvwifi*' -or $_.Name -like 'netnwifi*' })) {
  Say ('FILEREPO|' + $d.Name + '|' + ((@(Get-ChildItem $d.FullName -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))
}
$et = (@(& pnputil.exe /enum-drivers 2>&1) -join "`r`n")
foreach ($b in ($et -split "`r`n`r`n")) {
  if ($b -match '(?i)netvwifi|netnwifi') { Say ('STAGED|' + (($b -split "`r`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' / ')) }
}
Say ('OEM_INF_FILES_IN_WINDOWS|' + ((@(Get-ChildItem 'X:\Windows\INF' -Filter 'oem*.inf' -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))

Write-Output '== V2. rebuild the devnode so PnP installs Intel from scratch with the include present =='
$k = Get-DevKeyPath
$nodeId = ''
if ($k) { $nodeId = ('PCI\' + (($k -split '\\')[-2]) + '\' + (($k -split '\\')[-1])) }
Say ('NODE_ID=' + $nodeId)
if ($nodeId) {
  $m0 = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count
  Say ('REMOVE|' + (Raw (& pnputil.exe /remove-device $nodeId 2>&1 | Out-String)))
  Start-Sleep -Seconds 2
  Say ('SCAN|' + (Raw (& pnputil.exe /scan-devices 2>&1 | Out-String)))
  Start-Sleep -Seconds 14
  State 'AFTER_REBUILD'
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @(); if ($m0 -lt $all.Count) { $new = $all[$m0..($all.Count - 1)] }
  Say ('SAL_NEW=' + $new.Count)
  Say ('SAL_MISSING_INCLUDE=' + @($new | Where-Object { $_ -match 'missing included INF' }).Count)
  Say ('SAL_VWIFIBUS=' + @($new | Where-Object { $_ -match '(?i)vwifibus' }).Count)
  foreach ($l in @($new | Where-Object { $_ -match '(?i)vwifibus|UpperFilters|Device Status|Device problem|!!!|Unable|Exit status|AddService' } | Select-Object -First 25)) {
    Say ('SAL|' + ($l -replace '\s+', ' ').Trim())
  }
}

Write-Output '== V3. start the stack and ask the WiFi API =='
Say ('TRYSTART_VWIFIBUS=' + [Scm38]::TryStart('vwifibus'))
Say ('TRYSTART_NATIVEWIFIP=' + [Scm38]::TryStart('nativewifip'))
Say ('TRYSTART_WLANSVC=' + [Scm38]::TryStart('wlansvc'))
$prevT = 0
foreach ($t in 3, 8, 15) { Start-Sleep -Seconds ($t - $prevT); $prevT = $t; State ('T+' + $t) }
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi38]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Say ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n2 = 0
  $re = [Wapi38]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n2)
  Say ('WlanEnumInterfaces=' + $re + ' count=' + $n2)
  if ($re -eq 0 -and $n2 -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $g = [Runtime.InteropServices.Marshal]::PtrToStructure($lst, [Type][Guid])
    $dp = [Runtime.InteropServices.Marshal]::ReadIntPtr($lst, 16)
    $st = [Runtime.InteropServices.Marshal]::ReadInt32($lst, 24)
    Say ('IFACE|guid=' + $g + '|state=' + $st + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($dp))
  }
}
Write-Output 'PROBE38 END'
