param([switch]$SkipHotfix)
$ErrorActionPreference = 'SilentlyContinue'
# probe34 -- the decisive reinstall, done in the right order this time.
#
# What probe33 proved:
#   * Intel's Netwtw6e.INF references netvwifibus.inf three times per install variant
#     (Needs = VWiFiBus.CopyFiles / VWiFiBus.PnPFilterRegistration.HW / VWiFiBus.Services).
#     It never references netnwifi.inf -- so the native-WiFi filter is NOT attached by the
#     adapter INF; NDIS imposes it itself on an 802.11 medium miniport.
#   * Hand-written Services\vwifibus|vwififlt|vwifimp keys are complete in the registry
#     (reg query shows every value) yet invisible to the SCM: OpenServiceW -> 1060, Get-Service absent.
#     That is services.exe's boot-time database, not a bad key -- but the PnP manager loads filter
#     drivers by reading Services\<name> directly, so the kernel side can still use them.
#   * pnputil /delete-driver <pkg> /uninstall /force deletes the FileRepository folder too,
#     so drvload of the X: store path afterwards fails with 0x80070002. The package has to come
#     from the machine's own offline store on D: again (same as probe29).
#
# A: drvload the D: store INF now that X:\Windows\INF has netvwifibus.inf + vwifibus.sys and the
#    service keys exist -> does SetupAPI write UpperFilters=vwifibus itself, and does code 37 clear?
#    Also: does the INF's AddService=vwifibus make the service SCM-visible (1060 gone)?
# B: only if A still leaves code!=0 -- write Upper/Lower filters by hand and rebuild the node with
#    /remove-device + /scan-devices (the only thing that re-runs a failing driver entry in PE).
$drvDirs = @(Get-ChildItem 'D:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue |
             Where-Object { $_.Name -like 'netwtw*.inf_*' })
$Inf = ''
foreach ($d in $drvDirs) {
  foreach ($f in @(Get-ChildItem $d.FullName -Filter '*.INF' -EA SilentlyContinue)) {
    $b = [IO.File]::ReadAllBytes($f.FullName)
    $t = $(if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($b) } else { [Text.Encoding]::ASCII.GetString($b) })
    if ($t -notmatch 'DEV_7A70') { continue }
    $v = ([regex]'(?i)DriverVer\s*=\s*([^;\r\n]+)').Match($t).Groups[1].Value.Trim()
    if (-not $Inf) { $Inf = $f.FullName; $InfVer = $v }
    elseif ($v -gt $InfVer) { $Inf = $f.FullName; $InfVer = $v }
  }
}
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
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  if ($d.Count) { return $d[0].PNPDeviceID }
  return ''
}
function SalMark { return @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue).Count }
function SalDump([int]$from, [string]$tag) {
  $all = @(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue)
  $new = @()
  if ($from -lt $all.Count) { $new = $all[$from..($all.Count - 1)] }
  Write-Output ($tag + '|SAL_NEW_LINES=' + $new.Count)
  foreach ($l in ($new | Where-Object { $_ -match '(?i)Needed section|VWiFiBus|NWifi|UpperFilters|LowerFilters|Device Status|problem|DiInstallDriver|Unable to|error|Exit status|CopyFiles|AddService' } | Select-Object -First 45)) {
    Write-Output ($tag + '|SAL|' + ($l -replace '\s+', ' ').Trim())
  }
}
function State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Write-Output ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Write-Output ($tag + '|NODE|absent') }
  $k = Get-DevKeyPath
  if ($k) {
    $v = Get-ItemProperty -LiteralPath ($k -replace '^HKLM', 'HKLM:') -EA SilentlyContinue
    Write-Output ($tag + '|FILTERS|Upper=' + (($v.UpperFilters) -join ',') + '|Lower=' + (($v.LowerFilters) -join ',') + '|Service=' + $v.Service + '|Driver=' + $v.Driver)
    $cls = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $v.Driver) -EA SilentlyContinue
    if ($cls) { Write-Output ($tag + '|CLASSINF|' + $cls.InfPath) }
  } else { Write-Output ($tag + '|FILTERS|no devnode key') }
  foreach ($s in 'vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'wlansvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Write-Output ($tag + '|SCMSVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'not-in-scm' }))
  }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Write-Output ($tag + '|NIC|' + $a.Name + '|enabled=' + $a.NetEnabled + '|status=' + $a.NetConnectionStatus + '|guid=' + $a.GUID)
  }
}
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm34 {
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
public class Wapi34 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue

Write-Output ('PROBE34 ' + (Get-Date -Format 'HH:mm:ss') + ' storeInf=' + $Inf + ' ver=' + $InfVer)
Write-Output ('PRE|netvwifibus.inf=' + (Test-Path 'X:\Windows\INF\netvwifibus.inf') +
              ' netnwifi.inf=' + (Test-Path 'X:\Windows\INF\netnwifi.inf') +
              ' vwifibus.sys=' + (Test-Path 'X:\Windows\System32\drivers\vwifibus.sys') +
              ' vwififlt.sys=' + (Test-Path 'X:\Windows\System32\drivers\vwififlt.sys') +
              ' vwifimp.sys=' + (Test-Path 'X:\Windows\System32\drivers\vwifimp.sys'))
State 'INIT'

Write-Output '== A. drvload from the offline store (Microsoft vWiFi INF now present) =='
$m0 = SalMark
Write-Output ('DRVLOAD|' + ((& drvload $Inf 2>&1 | Out-String) -replace '\s+', ' ') + ' rc=' + $LASTEXITCODE)
Start-Sleep -Seconds 8
State 'AFTER_DRVLOAD'
SalDump $m0 'A'

Write-Output ('A_VWIFIBUS_ENUM|' + ((& reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\vwifibus' /s 2>&1 | Out-String) -replace "`r?`n", ' ; ' -replace '\s{2,}', ' '))
Write-Output ('A_VWIFIBUS_SCMSTART=' + [Scm34]::TryStart('vwifibus'))
Write-Output ('A_SYSDRVWIFIBUS|' + ((Get-CimInstance Win32_SystemDriver -Filter "Name='vwifibus'" -EA SilentlyContinue | ForEach-Object { 'state=' + $_.State + ' start=' + $_.StartMode }) -join ' '))

if (-not $SkipHotfix) {
  $n = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  $k = Get-DevKeyPath
  $v = Get-ItemProperty -LiteralPath ($k -replace '^HKLM', 'HKLM:') -EA SilentlyContinue
  if ($n.Count -and ($n[0].ConfigManagerErrorCode -ne 0 -or -not $v.UpperFilters)) {
    Write-Output '== B. node still not OK / filters missing -> write them and rebuild the node =='
    $null = (& reg.exe add $k /v UpperFilters /t REG_MULTI_SZ /d vwifibus /f 2>&1 | Out-String)
    $null = (& reg.exe add $k /v LowerFilters /t REG_MULTI_SZ /d nativewifip /f 2>&1 | Out-String)
    $chk = Get-ItemProperty -LiteralPath ($k -replace '^HKLM', 'HKLM:')
    Write-Output ('B_FILTERS_NOW|Upper=' + (($chk.UpperFilters) -join ',') + '|Lower=' + (($chk.LowerFilters) -join ',') + '|Service=' + $chk.Service)
    $nodeId = Get-NodeId
    $m1 = SalMark
    Write-Output ('B_NODE_ID=' + $nodeId)
    Write-Output ('B_REMOVE|' + ((& pnputil /remove-device $nodeId 2>&1 | Out-String) -replace '\s+', ' '))
    Start-Sleep -Seconds 2
    Write-Output ('B_SCAN|' + ((& pnputil /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
    Start-Sleep -Seconds 10
    State 'AFTER_REBUILD'
    SalDump $m1 'B'
  } else {
    Write-Output '== B. skipped: node already OK with UpperFilters set =='
  }
}

Write-Output '== C. start the stack and see whether wlansvc survives =='
Write-Output ('C_TRYSTART_NATIVEWIFIP=' + [Scm34]::TryStart('nativewifip'))
Write-Output ('C_TRYSTART_WLANSVC=' + [Scm34]::TryStart('wlansvc'))
$prevT = 0
foreach ($t in 2, 6, 10, 20) {
  Start-Sleep -Seconds ($t - $prevT); $prevT = $t
  Write-Output ('T+' + $t + ' wlansvc=' + (Get-Service wlansvc -EA SilentlyContinue).Status +
                ' nativewifip=' + (Get-Service nativewifip -EA SilentlyContinue).Status)
}
State 'FINAL'
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi34]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Write-Output ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n2 = 0
  $re = [Wapi34]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n2)
  Write-Output ('WlanEnumInterfaces=' + $re + ' count=' + $n2)
  if ($re -eq 0 -and $n2 -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $g = [Runtime.InteropServices.Marshal]::PtrToStructure($lst, [Type][Guid])
    $dp = [Runtime.InteropServices.Marshal]::ReadIntPtr($lst, 16)
    $st = [Runtime.InteropServices.Marshal]::ReadInt32($lst, 24)
    Write-Output ('IFACE|guid=' + $g + '|state=' + $st + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($dp))
  }
}
if ((Get-Service wlansvc -EA SilentlyContinue).Status -eq 'Running') {
  $o = (& X:\Windows\System32\wifi.exe --scan 2>&1 | Out-String)
  foreach ($l in (($o -split "`r?`n") | Select-Object -First 12)) { Write-Output ('WIFI|' + $l) }
}
Write-Output 'PROBE34 END'
