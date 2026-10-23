param([switch]$SkipLoad)
$ErrorActionPreference = 'SilentlyContinue'
# probe37 -- bypass the staging dead-end and test the filter hypothesis directly.
#
# probe36 proved the staging route is closed at runtime:
#   pnputil /add-driver X:\Windows\INF\netvwifibus.inf  ->  rc=0xE000020F
#   "The third-party INF does not contain digital signature information."
# An inbox Microsoft INF has no CatalogFile= directive of its own, so once it is treated as a
# third-party package pnputil demands a signature it does not have. (At build time DISM
# /Add-Driver /ForceUnsigned is the escape hatch -- that stays on the todo list.)
# Also: pnputil /add-driver <intel> /install says "up-to-date", rc=259, and re-runs nothing, so it
# cannot be used to force a reinstall.
#
# What has NOT been tested yet, and is what this probe does:
#   1. write UpperFilters=vwifibus on the devnode and PROVE with reg.exe that it landed
#      (earlier runs printed rc=0 but a read-back showed nothing -- never resolved).
#   2. load vwifibus.sys into the kernel with 'drvload <.sys>'. The PnP manager/ndis read
#      Services\vwifibus straight from the registry, so the services.exe boot cache that makes
#      OpenServiceW return 1060 should not matter here.
#   3. restart the devnode with 'pnputil /restart-device' (present in PE per the usage screen) --
#      unlike /remove-device + /scan-devices it does not delete the devnode key, so the filters we
#      just wrote survive into the new start attempt.
#   4. if Upper alone is not enough, add LowerFilters=nativewifip (the shape older WiFi drivers use)
#      and restart again. The host's working AC 9260 has Upper=vwifibus, Lower empty.
function Say([string]$m) { Write-Output ('C37|' + $m) }
function Get-DevKeyPath {
  $d = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'VEN_8086&DEV_7A70' })
  if ($d.Count -eq 0) { return '' }
  $i = @(Get-ChildItem -LiteralPath $d[0].PSPath -EA SilentlyContinue)
  if ($i.Count -eq 0) { return '' }
  return (($i[0].Name) -replace '^.*::HKEY_LOCAL_MACHINE', 'HKLM')
}
function Raw([string]$s) { return (($s -replace "`r?`n", ' ; ') -replace '\s{2,}', ' ') }
function Write-Filter([string]$key, [string]$name, [string]$value) {
  $o = (& reg.exe add $key /v $name /t REG_MULTI_SZ /d $value /f 2>&1 | Out-String)
  Say ('WRITE|' + $name + '=' + $value + '|rc=' + $LASTEXITCODE + '|' + (Raw $o))
  $q = (& reg.exe query $key /v $name 2>&1 | Out-String)
  Say ('READBACK|' + $name + '|' + (Raw $q))
}
function State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Say ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Say ($tag + '|NODE|absent') }
  $k = Get-DevKeyPath
  if ($k) {
    $q = (& reg.exe query $k 2>&1 | Out-String)
    $up = ((& reg.exe query $k /v UpperFilters 2>&1 | Out-String))
    $lo = ((& reg.exe query $k /v LowerFilters 2>&1 | Out-String))
    $sv = ((& reg.exe query $k /v Service 2>&1 | Out-String))
    Say ($tag + '|KEY|' + $k)
    Say ($tag + '|UPPER|' + (Raw $up))
    Say ($tag + '|LOWER|' + (Raw $lo))
    Say ($tag + '|SERVICE|' + (Raw $sv))
  } else { Say ($tag + '|KEY|absent') }
  $sd = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -match 'vwifi|nwifi|Netwtw|NDIS' })
  foreach ($x in $sd) { Say ($tag + '|SYSDRV|' + $x.Name + '|state=' + $x.State + '|start=' + $x.StartMode) }
}
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm37 {
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
public class Wapi37 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue

Write-Output ('PROBE37 ' + (Get-Date -Format 'HH:mm:ss') + ' skipLoad=' + [bool]$SkipLoad)

Write-Output '== Y0. stage the Microsoft INFs the only way PE allows: drvload (it skips publisher validation) =='
foreach ($n in 'netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf') {
  $p = 'X:\Windows\INF\' + $n
  if (-not (Test-Path $p)) { Say ('MS_DRVLOAD|' + $n + '|absent'); continue }
  $o = ((& drvload $p 2>&1 | Out-String) -replace '\s+', ' ')
  Say ('MS_DRVLOAD|' + $n + '|rc=' + $LASTEXITCODE + '|' + $o)
}
foreach ($d in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netvwifi*' -or $_.Name -like 'netnwifi*' })) {
  Say ('MS_FILEREPO|' + $d.Name + '|' + ((@(Get-ChildItem $d.FullName -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))
}
$et = (@(& pnputil.exe /enum-drivers 2>&1) -join "`r`n")
foreach ($b in ($et -split "`r`n`r`n")) {
  if ($b -match '(?i)netvwifi|netnwifi') { Say ('MS_STAGED|' + (($b -split "`r`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' / ')) }
}
Say ('MS_SCM_VWIFIBUS=' + [Scm37]::TryStart('vwifibus'))

$k = Get-DevKeyPath
Say ('DEVKEY=' + $k)
if (-not $k) {
  Say ('PRE_SCAN|' + (Raw ((& pnputil.exe /scan-devices 2>&1 | Out-String))))
  Start-Sleep -Seconds 8
  $k = Get-DevKeyPath
  Say ('DEVKEY_AFTER_SCAN=' + $k)
}
$nodeId = ''
if ($k) { $nodeId = ('PCI\' + (($k -split '\\')[-2]) + '\' + (($k -split '\\')[-1])) }
Say ('NODE_ID=' + $nodeId)
State 'INIT'

Write-Output '== Y1. rebuild the devnode so PnP re-runs the staged Intel install with netvwifibus now resolvable =='
if ($nodeId) {
  $m0 = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count
  Say ('REMOVE|' + (Raw ((& pnputil.exe /remove-device $nodeId 2>&1 | Out-String))))
  Start-Sleep -Seconds 2
  Say ('SCAN|' + (Raw ((& pnputil.exe /scan-devices 2>&1 | Out-String))))
  Start-Sleep -Seconds 12
  State 'AFTER_REBUILD'
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @(); if ($m0 -lt $all.Count) { $new = $all[$m0..($all.Count - 1)] }
  Say ('SAL_NEW=' + $new.Count)
  Say ('SAL_MISSING_INCLUDE=' + @($new | Where-Object { $_ -match 'missing included INF' }).Count)
  Say ('SAL_VWIFIBUS=' + @($new | Where-Object { $_ -match '(?i)vwifibus' }).Count)
  foreach ($l in @($new | Where-Object { $_ -match '(?i)vwifibus|UpperFilters|Device Status|Device problem|!!!|Unable|Exit status' } | Select-Object -First 25)) {
    Say ('SAL|' + ($l -replace '\s+', ' ').Trim())
  }
}

if (-not $SkipLoad) {
  Write-Output '== Y2. load vwifibus.sys / vwififlt.sys straight into the kernel with drvload =='
  foreach ($f in 'vwifibus.sys', 'vwififlt.sys') {
    $p = 'X:\Windows\System32\drivers\' + $f
    if (-not (Test-Path $p)) { Say ('DRVLOAD|' + $f + '|absent'); continue }
    $o = ((& drvload $p 2>&1 | Out-String) -replace '\s+', ' ')
    Say ('DRVLOAD|' + $f + '|rc=' + $LASTEXITCODE + '|' + $o)
  }
  State 'AFTER_DRVLOAD_SYS'
}

Write-Output '== Y3. hand-written UpperFilters, proved by reg.exe, then restart the device =='
$k = Get-DevKeyPath
if ($k) {
  $nodeId = ('PCI\' + (($k -split '\\')[-2]) + '\' + (($k -split '\\')[-1]))
  Write-Filter $k 'UpperFilters' 'vwifibus'
  $m1 = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count
  Say ('RESTART|' + (Raw ((& pnputil.exe /restart-device $nodeId 2>&1 | Out-String))))
  Start-Sleep -Seconds 8
  State 'AFTER_RESTART'
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @(); if ($m1 -lt $all.Count) { $new = $all[$m1..($all.Count - 1)] }
  Say ('SAL_NEW=' + $new.Count)
  foreach ($l in @($new | Where-Object { $_ -match '(?i)vwifibus|Device Status|problem|!!!|Unable' } | Select-Object -First 20)) {
    Say ('SAL|' + ($l -replace '\s+', ' ').Trim())
  }
}

$n = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
if ($k -and $n.Count -and $n[0].ConfigManagerErrorCode -ne 0) {
  Write-Output '== Y4. still failing -> add LowerFilters=nativewifip and restart again =='
  Write-Filter $k 'LowerFilters' 'nativewifip'
  Say ('RESTART2|' + (Raw ((& pnputil.exe /restart-device $nodeId 2>&1 | Out-String))))
  Start-Sleep -Seconds 8
  State 'AFTER_RESTART2'
  Say ('TRYSTART_NATIVEWIFIP=' + [Scm37]::TryStart('nativewifip'))
  Say ('RESTART3|' + (Raw ((& pnputil.exe /restart-device $nodeId 2>&1 | Out-String))))
  Start-Sleep -Seconds 8
  State 'AFTER_RESTART3'
}

Write-Output '== Y5. WiFi stack =='
Say ('TRYSTART_VWIFIBUS=' + [Scm37]::TryStart('vwifibus'))
Say ('TRYSTART_NATIVEWIFIP=' + [Scm37]::TryStart('nativewifip'))
Say ('TRYSTART_WLANSVC=' + [Scm37]::TryStart('wlansvc'))
$prevT = 0
foreach ($t in 3, 8, 15) { Start-Sleep -Seconds ($t - $prevT); $prevT = $t; State ('T+' + $t) }
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi37]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Say ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n2 = 0
  $re = [Wapi37]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n2)
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
Write-Output 'PROBE37 END'
