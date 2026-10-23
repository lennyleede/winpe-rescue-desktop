param([switch]$SkipIntelReinstall)
$ErrorActionPreference = 'SilentlyContinue'
# probe36 -- stage the Microsoft vWiFi packages the way PE's pnputil actually allows, then install
# Intel on top of them and see whether Include=netvwifibus.inf finally resolves.
#
# probe35 learned:
#   * PE's pnputil has NO /stage switch (usage screen, rc=1). Supported: /add-driver <inf> [/subdirs] [/install].
#     /add-driver without /install is the stage-only form.
#   * All seven Package01 .cat files are ALREADY in the PE CatRoot, so the vWiFi INFs' catalog is not
#     the missing piece.
#   * "pnputil /delete-driver <intel> /uninstall /force" + "/remove-device" + drvload leaves the node gone
#     and the log says "dvs: Unable to find any matching devices." -- so /scan-devices has to come first
#     and Intel has to be added with /install while the device is present.
# The question this run answers: does a *staged* netvwifibus.inf (DriverStore) make SetupAPI resolve
# Include = netvwifibus.inf / Needs = VWiFiBus.* at all -- i.e. is %windir%\INF not searched in PE?
function Say([string]$m) { Write-Output ('C36|' + $m) }
function Get-DevKeyPath {
  $d = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'VEN_8086&DEV_7A70' })
  if ($d.Count -eq 0) { return '' }
  $i = @(Get-ChildItem -LiteralPath $d[0].PSPath -EA SilentlyContinue)
  if ($i.Count -eq 0) { return '' }
  return (($i[0].Name) -replace '^.*::HKEY_LOCAL_MACHINE', 'HKLM')
}
function Get-NodeId {
  $k = Get-DevKeyPath
  if ($k) { return ('PCI\' + (($k -split '\\')[-2]) + '\' + (($k -split '\\')[-1])) }
  return ''
}
function State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Say ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Say ($tag + '|NODE|absent') }
  $k = Get-DevKeyPath
  if ($k) {
    $v = Get-ItemProperty -LiteralPath ($k -replace '^HKLM', 'HKLM:') -EA SilentlyContinue
    Say ($tag + '|FILTERS|Upper=' + (($v.UpperFilters) -join ',') + '|Lower=' + (($v.LowerFilters) -join ',') + '|Service=' + $v.Service + '|Driver=' + $v.Driver)
    $rq = ((& reg.exe query $k /v UpperFilters 2>&1 | Out-String) -replace "`r?`n", ' ; ' -replace '\s{2,}', ' ')
    Say ($tag + '|REGQ_UPPER|' + $rq)
  } else { Say ($tag + '|FILTERS|no devnode key') }
  foreach ($s in 'vwifibus', 'vwififlt', 'nativewifip', 'wlansvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Say ($tag + '|SCMSVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'not-in-scm' }))
  }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Say ($tag + '|NIC|' + $a.Name + '|status=' + $a.NetConnectionStatus)
  }
}
function SalStats([int]$from, [string]$tag) {
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @(); if ($from -lt $all.Count) { $new = $all[$from..($all.Count - 1)] }
  Say ($tag + '|SAL_NEW=' + $new.Count)
  Say ($tag + '|SAL_MISSING_INCLUDE=' + @($new | Where-Object { $_ -match 'missing included INF' }).Count)
  Say ($tag + '|SAL_VWIFI=' + @($new | Where-Object { $_ -match '(?i)vwifibus|VWiFiBus' }).Count)
  $st = (($new | Where-Object { $_ -match '(?i)Device Status|Device problem|Unable to|Exit status|!!!' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) | Select-Object -First 14) -join ' // '
  Say ($tag + '|SAL_STATUS=' + $st)
  foreach ($l in @($new | Where-Object { $_ -match '(?i)vwifibus|VWiFiBus|UpperFilters|nativewifip' } | Select-Object -First 12)) {
    Say ($tag + '|SAL|' + ($l -replace '\s+', ' ').Trim())
  }
}
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm36 {
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
public class Wapi36 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue

Write-Output ('PROBE36 ' + (Get-Date -Format 'HH:mm:ss') + ' skipIntel=' + [bool]$SkipIntelReinstall)
$offInf = 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw6e.INF'
Say ('OFFLINE_INF_EXISTS=' + (Test-Path $offInf))

Write-Output '== Z0. bring the devnode back (probe35 removed it) =='
Say ('SCAN|' + ((& pnputil.exe /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 6
State 'AFTER_SCAN'

Write-Output '== Z1. stage netvwifibus/netvwififlt/netvwifimp with /add-driver (no /stage in PE) =='
foreach ($n in 'netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf') {
  $p = 'X:\Windows\INF\' + $n
  if (-not (Test-Path $p)) { Say ('ADD|' + $n + '|absent'); continue }
  $o = ((& pnputil.exe /add-driver $p 2>&1 | Out-String) -replace '\s+', ' ')
  Say ('ADD|' + $n + '|rc=' + $LASTEXITCODE + '|' + $o)
}
foreach ($d in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netvwifi*' -or $_.Name -like 'netnwifi*' })) {
  Say ('FILEREPO|' + $d.Name + '|' + ((@(Get-ChildItem $d.FullName -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))
}
$txt = (@(& pnputil.exe /enum-drivers 2>&1) -join "`r`n")
foreach ($b in ($txt -split "`r`n`r`n")) {
  if ($b -match '(?i)netvwifi|netnwifi') { Say ('STAGED|' + (($b -split "`r`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' / ')) }
}
Say ('VWIFIBUS_SCM_AFTER_STAGE=' + [Scm36]::TryStart('vwifibus'))

Write-Output '== Z2. install Intel on top of the staged packages =='
if (-not $SkipIntelReinstall) {
  $m0 = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count
  $o = ((& pnputil.exe /add-driver $offInf /install 2>&1 | Out-String) -replace '\s+', ' ')
  Say ('INTEL_ADD_INSTALL|rc=' + $LASTEXITCODE + '|' + $o)
  Start-Sleep -Seconds 10
  State 'AFTER_INTEL'
  SalStats $m0 "Z2"
}

Write-Output '== Z3. driver-entry start attempt, then the WiFi API =='
Say ('TRYSTART_VWIFIBUS=' + [Scm36]::TryStart('vwifibus'))
Say ('TRYSTART_NATIVEWIFIP=' + [Scm36]::TryStart('nativewifip'))
Say ('TRYSTART_WLANSVC=' + [Scm36]::TryStart('wlansvc'))
$prevT = 0
foreach ($t in 3, 8, 15) { Start-Sleep -Seconds ($t - $prevT); $prevT = $t; State ('T+' + $t) }
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi36]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Say ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n2 = 0
  $re = [Wapi36]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n2)
  Say ('WlanEnumInterfaces=' + $re + ' count=' + $n2)
  if ($re -eq 0 -and $n2 -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $g = [Runtime.InteropServices.Marshal]::PtrToStructure($lst, [Type][Guid])
    $dp = [Runtime.InteropServices.Marshal]::ReadIntPtr($lst, 16)
    $st = [Runtime.InteropServices.Marshal]::ReadInt32($lst, 24)
    Say ('IFACE|guid=' + $g + '|state=' + $st + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($dp))
  }
}
if ((Get-Service wlansvc -EA SilentlyContinue).Status -eq 'Running') {
  $o = (& X:\Windows\System32\wifi.exe --scan 2>&1 | Out-String)
  foreach ($l in (($o -split "`r?`n") | Select-Object -First 12)) { Say ('WIFI|' + $l) }
}
Write-Output 'PROBE36 END'
