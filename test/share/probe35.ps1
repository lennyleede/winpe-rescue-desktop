param([switch]$NoReinstall)
$ErrorActionPreference = 'SilentlyContinue'
# probe35 -- make SetupAPI resolve Include=netvwifibus.inf by STAGING the Microsoft INF into the
# PE driver store, then reinstall the adapter and see whether the devnode finally gets
# UpperFilters=vwifibus (written by the INF, not by hand) and code 37 clears.
#
# Why staging: probe34 proved that copying netvwifibus.inf into X:\Windows\INF is NOT enough --
# drvload still logged "Needed section [VWiFiBus] not found, might exist in missing included INF"
# for all three Needs= sections, and the devnode ended with no Service/Driver/UpperFilters at all.
# Windows 10+ resolves Include= INFs out of the DriverStore index, so the package has to be staged.
#
# Host evidence (wintrust lookup): the vWiFi INFs are covered by
#   Microsoft-Windows-Client-Desktop-Required-Package01~...~10.0.19041.7663.cat
# while vwifibus/vwififlt/vwifimp/nwifi .sys are covered by Package04 (the one we already ship).
# So a Package01 .cat has to come along too, or the staging signature check fails.
# NOTE the log helper is called Say, not Cat: 'cat' is a built-in alias (Get-Content) and an alias
# beats a function in PowerShell's command resolution order, so a function named Cat silently
# swallowed every call -- that is why the first probe35 run printed almost nothing.
function Say([string]$m) { Write-Output ('C35|' + $m) }
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
  } else { Say ($tag + '|FILTERS|no devnode key') }
  foreach ($s in 'vwifibus', 'vwififlt', 'nativewifip', 'wlansvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Say ($tag + '|SCMSVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'not-in-scm' }))
  }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Say ($tag + '|NIC|' + $a.Name + '|status=' + $a.NetConnectionStatus)
  }
}
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm35 {
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
public class Wapi35 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue

Write-Output ('PROBE35 ' + (Get-Date -Format 'HH:mm:ss'))
Say ('SCAN|' + ((& pnputil.exe /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 3
State 'INIT'

$catDir = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$srcCat = @(Get-ChildItem 'D:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}' -Filter 'Microsoft-Windows-Client-Desktop-Required-Package01*.cat' -EA SilentlyContinue)
Say ('P01_FOUND=' + $srcCat.Count)
foreach ($c in $srcCat) {
  $d = Join-Path $catDir $c.Name
  if (Test-Path $d) { Say ('P01_ALREADY|' + $c.Name) }
  else {
    try { Copy-Item $c.FullName $d -Force -EA Stop; Say ('P01_COPIED|' + $c.Name + '|' + (Get-Item $d).Length) }
    catch { Say ('P01_COPY_FAIL|' + $c.Name + '|' + $_.Exception.Message) }
  }
}
foreach ($n in 'netvwifibus.inf', 'netnwifi.inf', 'netvwififlt.inf', 'netvwifimp.inf') {
  Say ('INF_IN_WINDOWS|' + $n + '=' + (Test-Path ('X:\Windows\INF\' + $n)))
}

Write-Output '== S1. stage the Microsoft vWiFi packages into the PE driver store =='
foreach ($n in 'netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf') {
  $p = 'X:\Windows\INF\' + $n
  if (-not (Test-Path $p)) { Say ('STAGE|' + $n + '|absent INF'); continue }
  $o = ((& pnputil.exe /add-driver $p /stage 2>&1 | Out-String) -replace '\s+', ' ')
  Say ('STAGE|' + $n + '|rc=' + $LASTEXITCODE + '|' + $o)
}
foreach ($d in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netvwifi*' })) {
  Say ('FILEREPO|' + $d.Name + '|' + ((@(Get-ChildItem $d.FullName -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))
}

Write-Output '== S2. staged Intel package (published name) and the offline package to load =='
$txt = (@(& pnputil.exe /enum-drivers 2>&1) -join "`r`n")
$pub = ''
foreach ($b in ($txt -split "`r`n`r`n")) {
  if ($b -match '(?i)netwtw') {
    Say ('BLOCK|' + (($b -split "`r`n" | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' / '))
    $m = [regex]::Match($b, 'Published Name\s*:\s*(oem\d+\.inf)')
    if ($m.Success) { $pub = $m.Groups[1].Value }
  }
}
if ($pub) { Say ('INTEL_PUBNAME=' + $pub) } else { Say 'INTEL_PUBNAME=none' }
$storeInf = ''; $iv = ''
foreach ($d in @(Get-ChildItem 'D:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -like 'netwtw*.inf_*' })) {
  foreach ($f in @(Get-ChildItem $d.FullName -Filter '*.INF' -EA SilentlyContinue)) {
    $bb = [IO.File]::ReadAllBytes($f.FullName)
    $t = $(if ($bb.Length -ge 2 -and $bb[0] -eq 0xFF -and $bb[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($bb) } else { [Text.Encoding]::ASCII.GetString($bb) })
    if ($t -notmatch 'DEV_7A70') { continue }
    $v = ([regex]'(?i)DriverVer\s*=\s*([^;\r\n]+)').Match($t).Groups[1].Value.Trim()
    if (-not $storeInf) { $storeInf = $f.FullName; $iv = $v }
    elseif ($v -gt $iv) { $storeInf = $f.FullName; $iv = $v }
  }
}
Say ('OFFLINE_INF=' + $storeInf + ' ver=' + $iv)

if (-not $NoReinstall -and $storeInf) {
  Write-Output '== S3. clean the node, reinstall, and count how many Needed-section errors remain =='
  if ($pub) { Say ('DELDRV|' + ((& pnputil.exe /delete-driver $pub /uninstall /force 2>&1 | Out-String) -replace '\s+', ' ')) }
  $nid = Get-NodeId
  if ($nid) { Say ('REMOVE|' + ((& pnputil.exe /remove-device $nid 2>&1 | Out-String) -replace '\s+', ' ')) }
  Start-Sleep -Seconds 2
  $m0 = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count
  $lo = ((& drvload $storeInf 2>&1 | Out-String) -replace '\s+', ' ')
  Say ('LOAD|' + $lo + ' rc=' + $LASTEXITCODE)
  Start-Sleep -Seconds 8
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @(); if ($m0 -lt $all.Count) { $new = $all[$m0..($all.Count - 1)] }
  Say ('SAL_NEW=' + $new.Count)
  Say ('SAL_NEEDED_MISSING=' + @($new | Where-Object { $_ -match 'missing included INF' }).Count)
  Say ('SAL_VWIFI_LINES=' + @($new | Where-Object { $_ -match '(?i)vwifibus|VWiFi|nativewifi|UpperFilters|AddService' }).Count)
  Say ('SAL_STATUS=' + (($new | Where-Object { $_ -match '(?i)Device Status|Device problem|Exit status|Unable to' } | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' // '))
  foreach ($l in @($new | Where-Object { $_ -match '(?i)vwifibus|VWiFi|nativewifi|UpperFilters|AddService' } | Select-Object -First 25)) {
    Say ('SAL|' + ($l -replace '\s+', ' ').Trim())
  }
  State 'AFTER_S3'
}

Write-Output '== S4. start the stack =='
Say ('TRYSTART_VWIFIBUS=' + [Scm35]::TryStart('vwifibus'))
Say ('TRYSTART_NATIVEWIFIP=' + [Scm35]::TryStart('nativewifip'))
Say ('TRYSTART_WLANSVC=' + [Scm35]::TryStart('wlansvc'))
$prevT = 0
foreach ($t in 3, 8, 15) {
  Start-Sleep -Seconds ($t - $prevT); $prevT = $t
  State ('T+' + $t)
}
State 'FINAL'
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi35]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Say ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n2 = 0
  $re = [Wapi35]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n2)
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
Write-Output 'PROBE35 END'
