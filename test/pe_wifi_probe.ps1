# test/pe_wifi_probe.ps1 -- runs INSIDE a live PE (pushed via test\host_push_run.ps1).
# Question it answers: can the borrowed host WiFi stack (wlansvc/wcmsvc/wlanapi/netsh) actually run
# in this 26100-based PE, and what does the wireless NIC look like from PE's side?
# Read-only except one benign action: it tries to START wlansvc (a ramdisk PE, nothing persists).
# ASCII output only -- it travels back through pe-sshd + frp.
$ErrorActionPreference = 'Continue'
$PS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

function Sec([string]$t) { Write-Output ('===== ' + $t + ' =====') }

Sec 'WHO'
Write-Output ('  PE=' + $env:COMPUTERNAME + ' build=' + (Get-CimInstance Win32_OperatingSystem).BuildNumber +
  ' ufl=' + [Environment]::OSVersion.Version.Build + ' sku=' + (Get-CimInstance Win32_OperatingSystem).SystemSKU)

Sec '1_WIFI_DEVICE_IS_IT_CLASS_NET'
foreach ($d in @(Get-CimInstance Win32_PnPEntity -Filter "PNClass='Net'" -EA SilentlyContinue)) {
  Write-Output ('  NET ' + $d.ConfigManagerErrorCode + ' | ' + $d.Name + ' | ' + $d.DeviceID)
}
Write-Output '  -- every class=Net devnode above; a code=28 Network Controller is an unbound NIC'

Sec '2_SERVICE_IMAGE_FILES'
foreach ($f in @('System32\wlansvc.dll', 'System32\wlanapi.dll', 'System32\wlanext.exe', 'System32\wlanmsm.dll',
                 'System32\wlancfg.dll', 'System32\wlansec.dll', 'System32\wci.dll', 'System32\wcmsvc.dll',
                 'System32\dmcmnutils.dll', 'System32\mdmregistration.dll', 'System32\netshell.dll',
                 'System32\drivers\nwifi.sys', 'System32\drivers\ndisuio.sys', 'System32\netsh.exe')) {
  $p = Join-Path $env:SystemRoot $f
  Write-Output ('  ' + $(if (Test-Path -LiteralPath $p) { 'OK  ' } else { 'MISS' }) + ' ' + $f)
}

Sec '3_SERVICES_AND_DEPS'
foreach ($s in @('wlansvc', 'wcmsvc', 'RpcSs', 'Dhcp', 'nsi', 'NDIS', 'dot3svc', 'SNMP')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  if (-not (Test-Path $k)) { Write-Output ('  ' + $s + ' = NO KEY'); continue }
  $sv = Get-ItemProperty $k
  $st = 'unknown'
  try { $q = Get-CimInstance Win32_Service -Filter "Name='" + $s + "'" -EA Stop; if ($q) { $st = $q.State } } catch { }
  Write-Output ('  ' + $s.PadRight(9) + ' Start=' + $sv.StartType + ' State=' + $st +
    $(if ($sv.DependOnService) { ' Deps=' + ($sv.DependOnService -join ',') } else { '' }))
}

Sec '4_TRY_START_WLANSVC'
$r = & net.exe start wlansvc 2>&1 | Out-String
Write-Output ('  net start wlansvc -> ' + (($r -replace "`r?`n", ' ') -replace '\s{2,}', ' ').Trim())
try { Start-Service wlansvc -EA Stop; Write-Output '  Start-Service wlansvc = OK' }
catch { Write-Output ('  Start-Service wlansvc threw: ' + $_.Exception.Message) }
Start-Sleep -Seconds 3
try {
  $q = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA Stop
  Write-Output ('  wlansvc state now = ' + $q.State + ' startmode=' + $q.StartMode + ' pid=' + $q.ProcessId)
} catch { Write-Output ('  cannot read wlansvc state: ' + $_.Exception.Message) }
Write-Output '  -- net start wcmsvc (the one that hands out the connection UI; harmless if it fails)'
$r2 = & net.exe start wcmsvc 2>&1 | Out-String
Write-Output ('  net start wcmsvc -> ' + (($r2 -replace "`r?`n", ' ') -replace '\s{2,}', ' ').Trim())

Sec '5_NETSH_WLAN_ASKS'
foreach ($a in @('show interfaces', 'show drivers', 'show settings', 'show networks', 'show profiles')) {
  $o = & netsh.exe wlan $a 2>&1 | Out-String
  $o = ($o -replace "`r`n", ' | ') -replace '\s{2,}', ' '
  if ($o.Length -gt 600) { $o = $o.Substring(0, 600) + '...' }
  Write-Output ('  netsh wlan ' + $a + ' -> ' + $o.Trim())
}

Sec '6_WLANAPI_DIRECT_CALL'
# netsh can be missing/broken even when wlansvc runs; P/Invoke proves the API path the HTA would use.
$src = @'
using System;using System.Runtime.InteropServices;
public static class W{
 [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(uint v,IntPtr r,out uint o,out IntPtr h);
 [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr h,IntPtr r,out IntPtr i,ulong t);
 [DllImport("wlanapi.dll")] public static extern int WlanGetAvailableNetworkList(IntPtr h,ref Guid d,IntPtr r,ulong t,out IntPtr l);
 [StructLayout(LayoutKind.Sequential)] public struct II{public Guid id;[MarshalAs(UnmanagedType.ByvalTStr)]public string d;public uint st;public uint mm;}
 public static string Go(){
  uint ver=0;IntPtr h=IntPtr.Zero;
  int a=WlanOpenHandle(2,IntPtr.Zero,out ver,out h);
  if(a!=0)return "WlanOpenHandle=0x"+a.ToString("X8");
  IntPtr p=IntPtr.Zero;int e=WlanEnumInterfaces(h,IntPtr.Zero,out p,0);
  if(e!=0)return "open ok(ver="+ver+") WlanEnumInterfaces=0x"+e.ToString("X8");
  II i=(II)Marshal.PtrToStructure(p,typeof(II));
  IntPtr l=IntPtr.Zero;int g=WlanGetAvailableNetworkList(h,ref i.id,IntPtr.Zero,0,out l);
  return "open ok ver="+ver+" ifacesGUID="+i.id+" desc="+i.d+" state="+i.st+" WlanGetAvailableNetworkList=0x"+g.ToString("X8");
 }
}
'@
$ok = $false
try {
  $ad = Add-Type -MemberDefinition $src -Name WlanProbe -Namespace P -Language CSharp -PassThru -EA Stop
  $ad | Out-Null
  $ok = $true
} catch {
  # PS may refuse C# without a compiler in PE; report the exact reason instead of guessing
  Write-Output ('  Add-Type failed: ' + $_.Exception.Message)
}
if ($ok) { Write-Output ('  P/Invoke -> ' + [P.W]::Go()) }

Sec '7_STARTNET_AND_HTA_WIRING'
foreach ($f in @('X:\Windows\System32\wlan.cmd', 'X:\Windows\System32\startnet.cmd', 'X\Desktop\Wlan', 'X:\Desktop\Wlan')) {
  Write-Output ('  ' + $(if (Test-Path -LiteralPath $f) { 'OK  ' } else { 'MISS' }) + ' ' + $f)
}
Write-Output 'PE_WIFI_PROBE_DONE'
