param([switch]$Hotfix)
$ErrorActionPreference = 'SilentlyContinue'
# probe32 -- compare the AX211 devnode in this PE with what a working Windows puts on a WiFi devnode.
# Working hypothesis (from X:\Windows\INF\setupapi.dev.log): Netwtw6e.INF has Include=netvwifibus.inf and
# Needs=VWiFiBus.* sections, but WinPE ships no netvwifibus.inf / netnwifi.inf, so the devnode never gets
# UpperFilters=vwifibus / LowerFilters=nativewifip => NdisMRegisterMiniport fails => code 37 / 0xC00000BB.
# -Hotfix copies the three Microsoft inbox pieces (sys + inf) in and writes the filters by hand, then restarts
# the devnode. Everything happens in the ramdisk; reboot undoes it.
$nodePath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
$dev = @(Get-ChildItem -LiteralPath $nodePath -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'VEN_8086&DEV_7A70' })
$instPath = ''
if ($dev.Count) {
  $inst = @(Get-ChildItem -LiteralPath $dev[0].PSPath -EA SilentlyContinue)
  if ($inst.Count) { $instPath = $inst[0].PSPath }
}
$nodeId = ''
if ($instPath) { $nodeId = (Split-Path (Split-Path $instPath -Parent) -Leaf) + '\' + (Split-Path $instPath -Leaf) }
Write-Output ('PROBE32 ' + (Get-Date -Format 'HH:mm:ss') + ' hotfix=' + [bool]$Hotfix)
Write-Output ('DEVNODE_PATH=' + $instPath + ' NODE_ID=' + $nodeId)
if ($instPath) {
  $p = Get-ItemProperty -LiteralPath $instPath
  Write-Output ('DEVNODE|Upper=' + (($p.UpperFilters) -join ',') + '|Lower=' + (($p.LowerFilters) -join ',') +
                '|Service=' + $p.Service + '|Class=' + $p.Class + '|Driver=' + $p.Driver +
                '|ProblemStatus=' + ($p.ProblemStatus -join ',') + '|Legacy=' + (($p.Legacy) -join ','))
  $drv = $p.Driver
  if ($drv) {
    $dp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $drv
    $q = Get-ItemProperty -LiteralPath $dp -EA SilentlyContinue
    Write-Output ('CLASS_ENTRY|key=' + [bool](Test-Path -LiteralPath $dp) + '|inf=' + $q.InfPath + '|sec=' + $q.InfSection + '|' + $q.DriverDesc +
                  '|Characteristics=' + $q.Characteristics + '|MediaType=' + $q.MediaType + '|BusType=' + $q.'*BusType' + '|NetClassInstalled=' + $q.NetClassInstalled)
    foreach ($sk in @(Get-ChildItem -LiteralPath $dp -EA SilentlyContinue)) { Write-Output ('  CLASS_SUB|' + $sk.PSChildName) }
  }
}
Write-Output '== W1. Net class key in this PE (correct GUID is 4d36e972-e325-11ce-...) =='
$netGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$nck = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $netGuid
Write-Output ('NETCLASS_EXISTS=' + (Test-Path -LiteralPath $nck))
if (Test-Path -LiteralPath $nck) {
  $c = Get-ItemProperty -LiteralPath $nck
  Write-Output ('NETCLASS|Class=' + $c.Class + '|Upper=' + (($c.UpperFilters) -join ',') + '|Lower=' + (($c.LowerFilters) -join ',') +
                '|Installer32=' + $c.Installer32 + '|NoInstallClass=' + $c.NoInstallClass + '|subs=' + @(Get-ChildItem -LiteralPath $nck -EA SilentlyContinue).Count)
  foreach ($s in @(Get-ChildItem -LiteralPath $nck -EA SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })) {
    $q = Get-ItemProperty -LiteralPath $s.PSPath -EA SilentlyContinue
    Write-Output ('  ENTRY|' + $s.PSChildName + '|inf=' + $q.InfPath + '|sec=' + $q.InfSection + '|svc=' + $q.NetCfgInstanceid + '|' + $q.DriverDesc)
  }
}
Write-Output '== W2. which inbox INFs / sys files exist in the image =='
foreach ($f in 'X:\Windows\INF\netnwifi.inf', 'X:\Windows\INF\netvwifibus.inf', 'X:\Windows\INF\netvwififlt.inf', 'X:\Windows\INF\netvwifimp.inf',
               'X:\Windows\System32\drivers\vwifibus.sys', 'X:\Windows\System32\drivers\vwififlt.sys', 'X:\Windows\System32\drivers\vwifimp.sys',
               'X:\Windows\System32\drivers\ndiscap.sys', 'X:\Windows\System32\drivers\pacer.sys', 'X:\Windows\System32\wlansvc.dll') {
  Write-Output ('IMG|' + $f + '=' + (Test-Path $f))
}
Write-Output '== W3. services present =='
foreach ($s in 'nativewifip', 'vwifibus', 'vwififlt', 'vwifimp', 'Netwtw14', 'NdisCap', 'psched', 'NdisVirtualBus') {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  $v = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  Write-Output ('SVC|' + $s + '|key=' + [bool](Test-Path -LiteralPath $k) + '|Start=' + $v.Start + '|Type=' + $v.Type +
                '|Group=' + $v.Group + '|Img=' + $v.ImagePath + '|state=' + $(if (Get-Service $s -EA SilentlyContinue) { (Get-Service $s).Status } else { '-' }))
}
Write-Output '== W4. exact Win32 error when SCM starts nativewifip =='
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm {
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenSCManagerW(string m,string d,uint a);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenServiceW(IntPtr s,string n,uint a);
  [DllImport("advapi32.dll",SetLastError=true)] public static extern bool StartServiceW(IntPtr s,uint a,IntPtr v);
  [DllImport("advapi32.dll")] public static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("kernel32",CharSet=CharSet.Unicode)] public static extern uint FormatMessageW(uint f,IntPtr src,uint code,uint lang,IntPtr buf,int size,IntPtr args);
  public static string TryStart(string svc) {
    IntPtr m = OpenSCManagerW(null,null,0xF0039u);
    if (m == IntPtr.Zero) return "OPENSCM-FAIL " + Marshal.GetLastWin32Error();
    IntPtr s = OpenServiceW(m, svc, 0x10u /*SERVICE_START*/ | 0xF003F);
    if (s == IntPtr.Zero) { string r = "OPENSVC-FAIL " + Marshal.GetLastWin32Error(); CloseServiceHandle(m); return r; }
    bool ok = StartServiceW(s, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    IntPtr b = Marshal.AllocHGlobal(512);
    uint n = FormatMessageW(0x1300u, IntPtr.Zero, (uint)e, 0, b, 512, IntPtr.Zero);
    string msg = (n>0) ? Marshal.PtrToStringUni(b).Replace("\r"," ").Replace("\n"," ") : "";
    CloseServiceHandle(s); CloseServiceHandle(m);
    return (ok ? "START-OK" : "START-FAIL err=" + e + " :" + msg);
  }
}
'@ -EA SilentlyContinue
Write-Output ('NATIVEWIFIP_TRYSTART=' + [Scm]::TryStart('nativewifip'))
Write-Output ('WLANSVC_TRYSTART=' + [Scm]::TryStart('wlansvc'))

if (-not $Hotfix) { Write-Output 'PROBE32 END (read-only)'; exit 0 }

Write-Output '== W5. hand the adapter the filters a working Windows would give it =='
foreach ($pair in @(
  @('D:\Windows\System32\drivers\vwifibus.sys', 'X:\Windows\System32\drivers\vwifibus.sys'),
  @('D:\Windows\System32\drivers\vwififlt.sys', 'X:\Windows\System32\drivers\vwififlt.sys'),
  @('D:\Windows\System32\drivers\vwifimp.sys',  'X:\Windows\System32\drivers\vwifimp.sys'),
  @('D:\Windows\INF\netvwifibus.inf', 'X:\Windows\INF\netvwifibus.inf'),
  @('D:\Windows\INF\netvwififlt.inf', 'X:\Windows\INF\netvwififlt.inf'),
  @('D:\Windows\INF\netvwifimp.inf',  'X:\Windows\INF\netvwifimp.inf'),
  @('D:\Windows\INF\netnwifi.inf',    'X:\Windows\INF\netnwifi.inf'))) {
  if (Test-Path $pair[0]) {
    try { Copy-Item $pair[0] $pair[1] -Force -EA Stop; Write-Output ('COPY_OK|' + (Split-Path $pair[1] -Leaf)) }
    catch { Write-Output ('COPY_FAIL|' + $pair[1] + '|' + $_.Exception.Message) }
  } else { Write-Output ('COPY_SRC_ABSENT|' + $pair[0]) }
}
$catStore = 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
foreach ($cf in @(Get-ChildItem 'D:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}' -Filter 'Microsoft-Windows-Client-Desktop-Required-Package04*.cat' -EA SilentlyContinue)) {
  $dst = Join-Path $catStore $cf.Name
  if (-not (Test-Path $dst)) { Copy-Item $cf.FullName $dst -Force; Write-Output ('CAT_OK|' + $cf.Name) } else { Write-Output ('CAT_ALREADY|' + $cf.Name) }
}
function Add-RegVal([string]$key, [string]$name, [string]$type, [string]$data) {
  $o = ((& reg.exe add $key /v $name /t $type /d $data /f 2>&1 | Out-String) -replace '\s+', ' ')
  Write-Output ('REGADD|' + $key + '|' + $name + '=' + $data + '|rc=' + $LASTEXITCODE + '|' + $o)
}
function Ensure-Svc([string]$name, [string]$img, [string]$start, [string]$type, [string]$group) {
  $key = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $name
  $null = (& reg.exe add $key /f 2>&1 | Out-String)
  Add-RegVal $key 'ImagePath' 'REG_EXPAND_SZ' $img
  Add-RegVal $key 'Start' 'REG_DWORD' $start
  Add-RegVal $key 'Type' 'REG_DWORD' $type
  Add-RegVal $key 'ErrorControl' 'REG_DWORD' '1'
  Add-RegVal $key 'DisplayName' 'REG_EXPAND_SZ' ('@%SystemRoot%\System32\drivers\' + $name + '.sys,-257')
  if ($group) { Add-RegVal $key 'Group' 'REG_SZ' $group }
  $null = (& reg.exe add ($key + '\Enum') /v 0 /t REG_BINARY /d 00 /f 2>&1 | Out-String)
}
Ensure-Svc 'vwifibus' '\SystemRoot\System32\drivers\vwifibus.sys' '3' '1' ''
Ensure-Svc 'vwififlt' 'System32\drivers\vwififlt.sys' '1' '1' 'NDIS'
Ensure-Svc 'vwifimp'  'system32\drivers\vwifimp.sys' '3' '1' 'NDIS'
Write-Output ('TRYSTART_VWIFIBUS=' + [Scm]::TryStart('vwifibus'))
Write-Output ('TRYSTART_VWIFIFLT=' + [Scm]::TryStart('vwififlt'))
if ($instPath) {
  $instKey = ($instPath -replace '^HKLM:', 'HKLM')
  Add-RegVal $instKey 'UpperFilters' 'REG_MULTI_SZ' 'vwifibus'
  Add-RegVal $instKey 'LowerFilters' 'REG_MULTI_SZ' 'nativewifip'
  $chk = Get-ItemProperty -LiteralPath $instPath
  Write-Output ('DEVNODE_NOW|Upper=' + (($chk.UpperFilters) -join ',') + '|Lower=' + (($chk.LowerFilters) -join ','))
}
Write-Output ('PNPUTIL_REMOVE|' + ((& pnputil /remove-device $nodeId 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 2
Write-Output ('PNPUTIL_SCAN|' + ((& pnputil /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 8
$d2 = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
foreach ($x in $d2) { Write-Output ('NODE3|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
Write-Output ('NATIVEWIFIP3=' + (Get-Service nativewifip -EA SilentlyContinue).Status)
Write-Output ('WLANSVC3=' + (Get-Service wlansvc -EA SilentlyContinue).Status)
Write-Output ('TRYSTART_WLANSVC3=' + [Scm]::TryStart('wlansvc'))
Write-Output ('WLANSVC4=' + (Get-Service wlansvc -EA SilentlyContinue).Status)
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
  Write-Output ('NIC3|' + $a.Name + '|enabled=' + $a.NetEnabled + '|guid=' + $a.GUID + '|netconnstatus=' + $a.NetConnectionStatus)
}
Write-Output 'PROBE32 END'
