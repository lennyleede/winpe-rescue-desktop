param([switch]$Reinstall, [switch]$Fix)
$ErrorActionPreference = 'SilentlyContinue'
# probe33 -- finish the native-WiFi chain on the live PE.
# Facts so far (probe32): the driver installs and the adapter object appears, but the devnode has
# UpperFilters / LowerFilters EMPTY, so NDIS never attaches vwifibus + nativewifip. That happened
# because at drvload time the image had no netvwifibus.inf / netnwifi.inf (both are now copied in).
# nativewifip's start error is now 31 (ERROR_GEN_FAILURE), no longer 577 ERROR_DRIVER_BLOCKED,
# i.e. the .cat fix holds on real hardware; it has no adapter to bind yet.
# -Reinstall: drop the staged package, re-add it now that the included INFs exist, and only if the
# filters are STILL missing write them by hand with reg.exe (correct HKLM path this time) and restart.
$infId  = 'oem155.inf'
$store  = 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw6e.INF'

function Get-DevKeyPath {
  $d = @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'VEN_8086&DEV_7A70' })
  if ($d.Count -eq 0) { return '' }
  $i = @(Get-ChildItem -LiteralPath $d[0].PSPath -EA SilentlyContinue)
  if ($i.Count -eq 0) { return '' }
  return (($i[0].Name) -replace '^.*::HKEY_LOCAL_MACHINE', 'HKLM')
}
function RegQ([string]$key) { return ((& reg.exe query $key 2>&1 | Out-String) -replace "`r?`n", ' ; ' -replace '\s{2,}', ' ') }
function RegA([string]$key, [string]$name, [string]$type, [string]$data) {
  $o = ((& reg.exe add $key /v $name /t $type /d $data /f 2>&1 | Out-String) -replace '\s+', ' ')
  Write-Output ('REGADD|' + $name + '=' + $data + '|rc=' + $LASTEXITCODE + '|' + $o)
}
# pnputil 要的实例路径 = PNPDeviceID + '\' + 注册表里的 instance 叶子
function Get-NodeId {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  if ($d.Count -eq 0) { return '' }
  $k = Get-DevKeyPath
  if (-not $k) { return $d[0].PNPDeviceID }
  return ($d[0].PNPDeviceID + '\' + (($k -split '\\')[-1]))
}
# probe32 的 Ensure-Svc 有 bug（$name_key 未定义、$vals 从未使用），所以三个 vWiFi 服务键其实一个字没写，
# 这解释了 OpenServiceW 的 1060 ERROR_SERVICE_DOES_NOT_EXIST。这里用显式命令行逐值重写，写完立刻回读验证。
function Ensure-Svc([string]$name, [string]$img, [int]$start, [int]$type, [string]$group, [string]$disp) {
  $key = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $name
  $null = (& reg.exe add $key /f 2>&1 | Out-String)
  RegA $key 'ImagePath'    'REG_EXPAND_SZ' $img
  RegA $key 'Start'        'REG_DWORD' "$start"
  RegA $key 'Type'         'REG_DWORD' "$type"
  RegA $key 'ErrorControl' 'REG_DWORD' '1'
  if ($group) { RegA $key 'Group' 'REG_SZ' $group }
  if ($disp)  { RegA $key 'DisplayName' 'REG_SZ' $disp }
  Write-Output ('VERIFY|' + (RegQ $key))
  Write-Output ('GETSVC|' + $name + '=' + $(if (Get-Service $name -EA SilentlyContinue) { (Get-Service $name).Status } else { 'absent' }))
}
function State([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' })
  foreach ($x in $d) { Write-Output ($tag + '|NODE|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  if ($d.Count -eq 0) { Write-Output ($tag + '|NODE|absent') }
  $k = Get-DevKeyPath
  if ($k) {
    $v = Get-ItemProperty -LiteralPath ($k -replace '^HKLM', 'HKLM:') -EA SilentlyContinue
    Write-Output ($tag + '|FILTERS|Upper=' + (($v.UpperFilters) -join ',') + '|Lower=' + (($v.LowerFilters) -join ',') + '|Service=' + $v.Service)
  } else { Write-Output ($tag + '|FILTERS|no devnode key') }
  foreach ($s in 'nativewifip', 'vwifibus', 'vwififlt', 'wlansvc', 'wcmsvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Write-Output ($tag + '|SVC|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'absent' }))
  }
  foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
    Write-Output ($tag + '|NIC|' + $a.Name + '|enabled=' + $a.NetEnabled + '|status=' + $a.NetConnectionStatus)
  }
}

Write-Output ('PROBE33 ' + (Get-Date -Format 'HH:mm:ss') + ' reinstall=' + [bool]$Reinstall)
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Scm33 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenSCManagerW(string m,string d,uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr OpenServiceW(IntPtr s,string n,uint a);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool StartServiceW(IntPtr s,uint a,IntPtr v);
  [DllImport("advapi32.dll")] public static extern bool CloseServiceHandle(IntPtr h);
  public static string TryStart(string svc) {
    IntPtr m = OpenSCManagerW(null,null,0xF0039u);
    if (m == IntPtr.Zero) return "OPENSCM-FAIL " + Marshal.GetLastWin32Error();
    IntPtr s = OpenServiceW(m, svc, 0x10u | 0x000F003Fu);
    if (s == IntPtr.Zero) { string r = "OPENSVC-FAIL " + Marshal.GetLastWin32Error(); CloseServiceHandle(m); return r; }
    bool ok = StartServiceW(s, 0, IntPtr.Zero);
    int e = Marshal.GetLastWin32Error();
    CloseServiceHandle(s); CloseServiceHandle(m);
    return (ok ? "START-OK" : "START-FAIL err=" + e);
  }
}
'@ -EA SilentlyContinue
Write-Output ('SCM_TYPES_OK=' + ([bool]([Scm33]::TryStart('nativewifip').Length -gt 0)))
State 'INIT'
Write-Output ('QUERY_VWIFIBUS_KEY|' + (RegQ 'HKLM\SYSTEM\CurrentControlSet\Services\vwifibus'))
Write-Output ('QUERY_VWIFIBUS_SCM|' + ((Get-Service vwifibus -EA SilentlyContinue).Status))
Write-Output ('IMG_INF|netvwifibus=' + (Test-Path 'X:\Windows\INF\netvwifibus.inf') + ' netnwifi=' + (Test-Path 'X:\Windows\INF\netnwifi.inf'))
Write-Output '== X0. netnwifi.inf shape (what the included INF actually registers) =='
function InfLines([string]$p, [string]$pattern, [string]$tag, [int]$max) {
  if (-not (Test-Path $p)) { Write-Output ($tag + '|ABSENT|' + $p); return }
  $b = [IO.File]::ReadAllBytes($p)
  $t = $(if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($b) } else { [Text.Encoding]::ASCII.GetString($b) })
  $n = 0
  foreach ($l in (($t -split "`r?`n") | Where-Object { $_ -match $pattern })) {
    $n++; if ($n -gt $max) { return }
    Write-Output ($tag + '|' + (Split-Path $p -Leaf) + '|' + ($l -replace '\s+', ' ').Trim())
  }
  Write-Output ($tag + '|lines=' + $n)
}
InfLines 'X:\Windows\INF\netnwifi.inf'         '(?i)AddService|AddReg|LowerFilters|UpperFilters|^\[|HKR|Ndi|Filter' 'INFSEC' 60
InfLines 'X:\Windows\INF\netvwifibus.inf'      '(?i)AddService|AddReg|LowerFilters|UpperFilters|^\[|HKR'           'INFSEC' 40
InfLines $store                                '(?i)^\s*(Include|Needs)\s*='                                      'ADAPTINC' 30
InfLines 'X:\Windows\INF\netvwififlt.inf'      '(?i)AddService|AddReg|^\[|HKR|ServiceBinary'                       'FLTINF'  25
InfLines 'X:\Windows\INF\netvwifimp.inf'       '(?i)AddService|AddReg|^\[|HKR|ServiceBinary'                       'IMPINF'  25

if ($Fix) {
  Write-Output '== W1. create the three vWiFi service keys (host shapes) so the filters can actually load =='
  Ensure-Svc 'vwifibus' '\SystemRoot\System32\drivers\vwifibus.sys' 3 1 ''      '@%SystemRoot%\System32\drivers\vwifibus.sys,-257'
  Ensure-Svc 'vwififlt' 'System32\drivers\vwififlt.sys'             3 1 'NDIS'  '@%SystemRoot%\System32\drivers\vwififlt.sys,-259'
  Ensure-Svc 'vwifimp'  'System32\drivers\vwifimp.sys'              3 1 'NDIS'  '@%SystemRoot%\System32\drivers\vwifimp.sys,-257'
  foreach ($f in 'vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys') {
    Write-Output ('SYSFILE|' + $f + '=' + (Test-Path ('X:\Windows\System32\drivers\' + $f)))
  }
}
if ($Reinstall) {
  Write-Output '== X1. reinstall the staged package so the Include= sections resolve =='
  Write-Output ('PNPUTIL_DELDRV|' + ((& pnputil /delete-driver $infId /uninstall /force 2>&1 | Out-String) -replace '\s+', ' '))
  $nodeId = Get-NodeId
  if ($nodeId) {
    Write-Output ('NODE_ID=' + $nodeId)
    Write-Output ('PNPUTIL_REMOVE|' + ((& pnputil /remove-device $nodeId 2>&1 | Out-String) -replace '\s+', ' '))
  }
  Start-Sleep -Seconds 2
  Write-Output ('DRVLOAD|' + ((& drvload $store 2>&1 | Out-String) -replace '\s+', ' ') + ' rc=' + $LASTEXITCODE)
  Start-Sleep -Seconds 6
  State 'AFTER_DRVLOAD'
  $k2 = Get-DevKeyPath
  $v2 = Get-ItemProperty -LiteralPath ($k2 -replace '^HKLM', 'HKLM:') -EA SilentlyContinue
  if (-not $v2.UpperFilters -or -not $v2.LowerFilters) {
    Write-Output '== X2. filters still missing -> write them by hand and restart the devnode =='
    RegA $k2 'UpperFilters' 'REG_MULTI_SZ' 'vwifibus'
    RegA $k2 'LowerFilters' 'REG_MULTI_SZ' 'nativewifip'
    $n2 = Get-NodeId
    if ($n2) {
      Write-Output ('PNPUTIL_DISABLE|' + ((& pnputil /disable-device $n2 2>&1 | Out-String) -replace '\s+', ' '))
      Start-Sleep -Seconds 2
      Write-Output ('PNPUTIL_ENABLE|' + ((& pnputil /enable-device $n2 2>&1 | Out-String) -replace '\s+', ' '))
      Start-Sleep -Seconds 5
    }
  }
}
Write-Output '== X3. final push: start the stack in dependency order =='
Write-Output ('TRYSTART_VWIFIBUS=' + [Scm33]::TryStart('vwifibus'))
Write-Output ('TRYSTART_VWIFIFLT=' + [Scm33]::TryStart('vwififlt'))
Write-Output ('TRYSTART_NATIVEWIFIP=' + [Scm33]::TryStart('nativewifip'))
Write-Output ('NATIVEWIFIP_STATE=' + (Get-Service nativewifip -EA SilentlyContinue).Status)
Write-Output ('TRYSTART_WCMSVC=' + [Scm33]::TryStart('wcmsvc'))
Write-Output ('TRYSTART_WLANSVC=' + [Scm33]::TryStart('wlansvc'))
foreach ($t in 2, 4, 6, 8, 10) {
  Start-Sleep -Seconds 2
  Write-Output ('T+' + $t + ' wlansvc=' + (Get-Service wlansvc -EA SilentlyContinue).Status +
                ' nativewifip=' + (Get-Service nativewifip -EA SilentlyContinue).Status +
                ' wcmsvc=' + (Get-Service wcmsvc -EA SilentlyContinue).Status)
}
Write-Output ('NODE_FINAL=' + ((Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'PCI\VEN_8086&DEV_7A70*' } | ForEach-Object { 'code=' + $_.ConfigManagerErrorCode + ' st=' + $_.Status }) -join ' '))
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi33 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll", CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue
$ver = 0; $hk = [IntPtr]::Zero
$rh = [Wapi33]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk)
Write-Output ('WlanOpenHandle=' + $rh + ' ver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n = 0
  $re = [Wapi33]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n)
  Write-Output ('WlanEnumInterfaces=' + $re + ' count=' + $n)
  if ($re -eq 0 -and $n -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $g = [Runtime.InteropServices.Marshal]::PtrToStructure($lst, [Type][Guid])
    $dp = [Runtime.InteropServices.Marshal]::ReadIntPtr($lst, 16)
    $st = [Runtime.InteropServices.Marshal]::ReadInt32($lst, 24)
    Write-Output ('IFACE|guid=' + $g + '|state=' + $st + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($dp))
  }
}
Write-Output '== X4. the in-image WiFi tool (only meaningful once an interface exists) =='
$wx = 'X:\Windows\System32\wifi.exe'
Write-Output ('WIFI_EXE=' + (Test-Path $wx))
$sw = (Get-Service wlansvc -EA SilentlyContinue).Status
if ((Test-Path $wx) -and ($sw -eq 'Running')) {
  $o = (& $wx --scan 2>&1 | Out-String)
  foreach ($l in (($o -split "`r?`n") | Select-Object -First 15)) { Write-Output ('WIFI|' + $l) }
}
Write-Output '== X5. setupapi tail =='
foreach ($l in (@(Get-Content 'X:\Windows\INF\setupapi.dev.log' -EA SilentlyContinue) | Select-Object -Last 20)) { Write-Output ('SAL3|' + $l) }
State 'END'
Write-Output 'PROBE33 END'
