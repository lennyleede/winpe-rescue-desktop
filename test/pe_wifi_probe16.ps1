# probe16: probe15 was decisive in a way it did not intend.
#  * Entry-point CASE theory is dead: our image stores every key lowercase (wlansvc, dot3svc,
#    wcmsvc, defragsvc) while the DLLs export WlanSvcMain / Dot3SvcMain / WcmSvcMain, i.e. the
#    lowercase "<name>Main" never matches case-exactly -- yet dot3svc and wcmsvc host fine. svchost
#    clearly does not need the key case to match, so "-s WlanSvc" / cased group members failing with
#    the same error 6 was expected.
#  * The real signal: dot3svc -- a service we KNOW works -- was moved into a brand new group with a
#    brand new host and it DIED (1067 process terminated unexpectedly), then started PERFECTLY when
#    put back home (in the boot host). So "new host at runtime" is not a reliable path in this PE.
#    wlansvc has never had a working baseline anywhere, in any shape.
# That leaves the one structural difference between wlansvc and the services that do run:
#    wlansvc is useless without the NativeWiFi filter driver nwifi.sys, and our borrowed stack put
#    the FILE on X: (19041.7663) but ADK/WinPE never shipped a WiFi package, so there is no
#    nwifi.inf, no catalog and quite possibly no Services key -> the driver is never in the kernel.
#    WlanSvcMain opening a handle to a filter that does not exist is a textbook ERROR_INVALID_HANDLE,
#    which "net start" prints as exactly "System error 6. The handle is invalid."
# This machine's own C: (found by probe14) is a real Windows 10 19041 install, so it should contain
# the matching signed nwifi package -- everything needed to test the theory live, on the ramdisk.
# If wlansvc starts after nwifi is loaded, the root cause is settled and the fix is a build-time one:
# ship nwifi.inf+cat+sys (and the WLAN class hooks) instead of the bare .sys.
param([switch]$SkipStart)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function Ver([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return 'ABSENT' }
  try { $v = (Get-Item -LiteralPath $p).VersionInfo } catch { return 'nofv' }
  if (-not $v) { return 'nofv' }
  return ((One $v.FileVersion) + ' (' + [Math]::Round((Get-Item -LiteralPath $p).Length / 1KB) + 'KB)')
}
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}
function KeyVals([string]$n) {
  $k = $SVC + '\' + $n
  if (-not (Test-Path -LiteralPath $k)) { return 'KEY ABSENT' }
  $i = Get-Item -LiteralPath $k
  $o = @()
  foreach ($v in @('Type','Start','ErrorControl','Group','ImagePath','ObjectName','DependOnService','DisplayName')) {
    $val = $i.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -ne $val) { $o += ($v + '=' + (One ($val -join ','))) }
  }
  return ($o -join ' ;; ')
}
$SVC   = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$S32   = 'X:\windows\System32'
$W     = 'X:\nwifi16'

Sec '0_IS_NWIFI_EVEN_REGISTERED'
Log ('  file X:\...\drivers\nwifi.sys = ' + (Ver ($S32 + '\drivers\nwifi.sys')))
Log ('  Services\nwifi     => ' + (KeyVals 'nwifi'))
foreach ($n in @('NdisVirtualBus','NativeWiFiFilter','WlanSvc','dot3svc','wcmsvc','nsi','ndis','NetBT')) {
  Log ('  Services\' + ('{0,-16}' -f $n) + ' => ' + $(if (Test-Path -LiteralPath ($SVC + '\' + $n)) { 'exists' } else { 'ABSENT' }))
}
$wifiish = @([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services').GetSubKeyNames()) |
           Where-Object { $_ -imatch 'wifi|wlan|ndis|netbt|dot3' }
Log ('  service keys matching wifi/wlan/ndis/dot3: ' + ($wifiish -join ','))
$drv = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { (One $_.Name) -imatch 'nwifi|wlan|ndis' })
foreach ($d in $drv) { Log ('  driver ' + ('{0,-14}' -f $d.Name) + ' state=' + $d.State + ' start=' + $d.StartMode + ' path=' + (One $d.PathName)) }
Log ('  running drivers = ' + ((@(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -EA SilentlyContinue) | ForEach-Object { $_.Name }) -join ','))
Log ('  baseline wlansvc ' + (SvcState 'wlansvc'))

Sec '1_FIND_A_SIGNED_NWIFI_PACKAGE'
$src = $null
foreach ($r in @('C:','D:','E:','F:')) {
  if ($r -eq 'X:') { continue }
  if (-not (Test-Path -LiteralPath ($r + '\Windows\System32\drivers\nwifi.sys'))) { continue }
  Log ('  ' + $r + ' has nwifi.sys = ' + (Ver ($r + '\Windows\System32\drivers\nwifi.sys')))
  $fr = $r + '\Windows\System32\DriverStore\FileRepository'
  $cands = @(Get-ChildItem -LiteralPath $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -imatch 'nwifi|nativewifi' })
  $cn = (@($cands) | ForEach-Object { $_.Name }) -join ','
  Log ('    FileRepository wifi dirs = [' + $cn + ']')
  foreach ($c in $cands) {
    $inf = Join-Path $c.FullName 'nwifi.inf'
    if (Test-Path -LiteralPath $inf) { $src = @{ dir = $c.FullName; inf = $inf }; break }
  }
  $sysinf = $r + '\Windows\INF\nwifi.inf'
  Log ('    ' + $sysinf + ' exists = ' + (Test-Path -LiteralPath $sysinf))
  if ($src) { break }
}
if (-not $src) { Log '  no packaged nwifi.inf found on any reachable volume -> hand-written inf path' }
else { Log ('  USING PACKAGE: ' + $src.dir) }

Sec '2_INSTALL_NWIFI'
New-Item -ItemType Directory -Path $W -Force | Out-Null
$infPath = $W + '\nwifi.inf'
if ($src) {
  Copy-Item -LiteralPath $src.dir -Destination 'X:\nwifi16\pkg' -Recurse -Force -ErrorAction SilentlyContinue
  $found = @(Get-ChildItem -LiteralPath 'X:\nwifi16\pkg' -File -EA SilentlyContinue)
  Log ('  copied package files = ' + (($found | ForEach-Object { $_.Name }) -join ','))
  # the packaged inf refers to files by layout name; drvload needs them next to it, which they are
  Copy-Item -LiteralPath ($src.dir + '\nwifi.inf') -Destination $infPath -Force -ErrorAction SilentlyContinue
} else {
  $inf = @'
[Version]
Signature="$WINDOWS NT$"
Class=System
ClassGuid={4d36e97d-e325-11ce-bfc1-08002be10318}
Provider=%Prov%
DriverVer=10/09/2026,10.0.19041.7663

[Manufacturer]
%Prov%=Std,NTamd64

[Std.NTamd64]
%DevDesc%=Dev_Install,ROOT\NWIFI

[Dev_Install]
CopyFiles=DrvCopy

[Dev_Install.Services]
AddService = nwifi,2,nwifi_Service

[ClassInstall32]
Addreg = ClassAddReg

[ClassAddReg]
HKR,,,,%DevDesc%

[DrvCopy]
nwifi.sys

[DestinationDirs]
DefaultDestDir = 12

[nwifi_Service]
DisplayName   = %SvcDesc%
ServiceType   = 1
StartType     = 3
ErrorControl  = 1
ServiceBinary = %12%\nwifi.sys
LoadOrderGroup= NDIS

[SourceDisksNames]
1=%Disk%,,

[SourceDisksFiles]
nwifi.sys=1

[Strings]
Prov="PE rescue"
Disk="PE rescue media"
DevDesc="NativeWiFi Filter (manual PE load)"
SvcDesc="NativeWiFi Filter"
'@
  Set-Content -LiteralPath $infPath -Value $inf -Encoding ASCII
  Copy-Item -LiteralPath ($S32 + '\drivers\nwifi.sys') -Destination ($W + '\nwifi.sys') -Force -ErrorAction SilentlyContinue
  Log '  hand-written root-device inf written'
}
Log ('  inf = ' + $infPath + ' exists=' + (Test-Path -LiteralPath $infPath))
Log ('  nwifi.sys next to it = ' + (Ver ($W + '\nwifi.sys')))

# Route A (no installer, no new SERVICE name needed -- the kernel reads the key itself, so the
# boot-frozen SCM name table cannot block us): write a plain driver Services key and NtLoadDriver it.
$nk = $SVC + '\nwifi'
if (-not (Test-Path -LiteralPath $nk)) { New-Item -LiteralPath $nk -Force | Out-Null; Log '  created Services\nwifi' }
$kimg = Get-Item -LiteralPath $nk
foreach ($v in @($kimg.GetValueNames())) { Log ('  pre-existing value ' + $v + '=' + (One ($kimg.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -join ','))) }
Set-ItemProperty -LiteralPath $nk -Name 'Type'         -Value 1     -Type DWord
Set-ItemProperty -LiteralPath $nk -Name 'Start'        -Value 3     -Type DWord
Set-ItemProperty -LiteralPath $nk -Name 'ErrorControl' -Value 1     -Type DWord
Set-ItemProperty -LiteralPath $nk -Name 'Group'        -Value 'NDIS' -Type String
Set-ItemProperty -LiteralPath $nk -Name 'ImagePath'    -Value 'System32\DRIVERS\nwifi.sys' -Type ExpandString
Set-ItemProperty -LiteralPath $nk -Name 'ObjectName'   -Value 'LocalSystem' -Type String
Log ('  Services\nwifi now => ' + (KeyVals 'nwifi'))
$nt = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class ND16 {
  [DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(int p, bool en, bool thread, out bool prev);
  [DllImport("ntdll.dll", CharSet=CharSet.Unicode)] public static extern int NtLoadDriver(string key);
}
"@
Add-Type -TypeDefinition $src
$prev = $false
$ap = [ND16]::RtlAdjustPrivilege(10, $true, $false, [ref]$prev)
Write-Output ('RtlAdjustPrivilege(SeLoadDriver=10) rc=0x{0:X8} prev={1}' -f $ap, $prev)
$k = '\Registry\Machine\System\CurrentControlSet\Services\nwifi'
$rc = [ND16]::NtLoadDriver($k)
Write-Output ('NtLoadDriver(' + $k + ') rc=0x{0:X8}' -f $rc)
'@
Set-Content -LiteralPath 'X:\nt16.ps1' -Value $nt -Encoding ASCII
if (-not $SkipStart) {
  $no = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\nt16.ps1 2>&1') | Out-String
  foreach ($l in ($no -split "`r?`n")) { if ((One $l).Length -gt 3) { Log ('  ROUTE A: ' + (One $l)) } }
}
$running = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { ((One $_.Name) -ieq 'nwifi') -and ((One $_.State) -imatch 'Running') })
Log ('  ROUTE A result: nwifi running = ' + (@($running).Count -gt 0))

# Route B: the installer path, only if A did not get the driver in.
if (-not $SkipStart -and @($running).Count -eq 0) {
  Log ('  drvload => ' + (Cmd ('drvload ' + $infPath)))
}
Log ('  after drvload: Services\nwifi => ' + (KeyVals 'nwifi'))
$d2 = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { (One $_.Name) -imatch 'nwifi' })
foreach ($d in $d2) { Log ('  driver ' + $d.Name + ' state=' + $d.State + ' started=' + $d.Started + ' path=' + (One $d.PathName)) }
foreach ($p in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { (One $_.Name + ' ' + (One $_.DeviceID)) -imatch 'nwifi|NativeWiFi|ROOT\\NWIFI' })) {
  Log ('  pnp: ' + (One $p.Name) + ' status=' + $p.Status + ' code=' + $p.ConfigManagerErrorCode + ' id=' + (One $p.DeviceID))
}
Log ('  try net start nwifi (drivers answer 2185 normally, harmless): ' + (Cmd 'net start nwifi'))

Sec '3_START_WLANSVC_WITH_FILTER_PRESENT'
# probe15's raw advapi32 attempt died on OpenSCManager (err=123) because $null marshals as "" --
# [NullString]::Value is the real NULL. Getting the raw StartService code matters: "System error 6"
# is net's rendering; we want to know whether 6 comes from the SCM or from the service itself.
$raw = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class SC16 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool QueryServiceStatus(IntPtr svc, byte[] st);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern int FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
}
"@
Add-Type -TypeDefinition $src
function Msg([int]$c) {
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(512)
  $n = [SC16]::FormatMessageW(0x1300, [IntPtr]::Zero, [uint32]$c, 0, $buf, 512, [IntPtr]::Zero)
  $t = ''
  if ($n -gt 0) { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf) }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
  return (($t -replace '\s+', ' ').Trim())
}
$scm = [SC16]::OpenSCManagerW([NullString]::Value, [NullString]::Value, 0x0001 -bor 0x0010)
if ($scm -eq [IntPtr]::Zero) { Write-Output ('OpenSCManager FAIL err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); return }
foreach ($nm in @('wlansvc','nwifi')) {
  $h = [SC16]::OpenServiceW($scm, $nm, 0x0010 -bor 0x0040 -bor 0x1000 -bor 0x0005)
  if ($h -eq [IntPtr]::Zero) { Write-Output ($nm + ' OpenService FAIL err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); continue }
  $ok = [SC16]::StartServiceW($h, 0, [IntPtr]::Zero)
  $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  $st = New-Object byte[] 28
  [void][SC16]::QueryServiceStatus($h, $st)
  $svcState = [BitConverter]::ToInt32($st, 4)
  $win32Exit = [BitConverter]::ToInt32($st, 12)
  Write-Output ($nm + ' StartService ok=' + $ok + ' err=' + $e + ' [' + (Msg $e) + '] svcState=' + $svcState + ' reportedWin32Exit=' + $win32Exit)
}
'@
Set-Content -LiteralPath 'X:\raw16.ps1' -Value $raw -Encoding ASCII
if (-not $SkipStart) {
  $ro = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\raw16.ps1 2>&1') | Out-String
  foreach ($l in ($ro -split "`r?`n")) { if ((One $l).Length -gt 3) { Log ('  RAW: ' + (One $l)) } }
}
if (-not $SkipStart) {
  Log ('  net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state = ' + (SvcState 'wlansvc'))
  $wo = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl14.ps1 2>&1') | Out-String
  Log ('  wlanapi: ' + (One $wo).Trim())
  Log ('  net start wcmsvc : ' + (Cmd 'net start wcmsvc') + ' | ' + (SvcState 'wcmsvc'))
}

Sec '4_SECOND_ATTEMPT_AND_RETRY_LOGIC'
# a first failure can be a transient ordering issue: retry once after the wcmsvc attempt
if (-not $SkipStart) {
  Start-Sleep -Seconds 2
  Log ('  retry net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state = ' + (SvcState 'wlansvc'))
  $wo2 = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl14.ps1 2>&1') | Out-String
  Log ('  wlanapi again: ' + (One $wo2).Trim())
}

Sec '5_FINAL'
foreach ($n in @('wlansvc','dot3svc','wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log ('  final ImagePath wlansvc = ' + (One (Get-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name ImagePath -EA SilentlyContinue).ImagePath))
Log ('  NOTE left-behind on the ramdisk: Services\nwifi key, X:\nwifi16, X:\raw16.ps1, X:\nt16.ps1 (all die on reboot)')
Log 'PROBE16_DONE'
