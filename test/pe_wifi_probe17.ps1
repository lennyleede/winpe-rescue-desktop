# probe17: the reference dump from a Windows where WiFi actually works (this dev box, 19044) says our
# image is missing two things, and both are consistent with every probe 7-16 result.
#
#   (1) HKLM\...\Services\wlansvc\Parameters on a working box holds THREE values:
#           ServiceDll               = %SystemRoot%\System32\wlansvc.dll
#           ServiceDllUnloadOnStop   = 1
#           ServiceMain              = "WlanSvcMain"      <-- svchost's entry-point override
#       svchost derives the entry point as "<service name>Main"; our key is lowercase "wlansvc", so
#       without ServiceMain it asks wlansvc.dll for "wlansvcMain", which does not exist (the export
#       is WlanSvcMain -- measured in probe15 0b). A host that cannot resolve the entry point fails
#       the start immediately, and "net start" renders that as "System error 6 / handle is invalid".
#       This is the only variable probe7-16 never touched: probe15's export table showed dot3svc.dll
#       has mains=[Dot3SvcMain] only, so dot3svc must ALSO carry a ServiceMain override -- check it.
#   (2) there is NO "nwifi" service key on a working box. The driver lives under the name
#       "nativewifip" (Type=1, Group=NDIS, Start=3, ImagePath=system32\DRIVERS\nwifi.sys, plus
#       NdisMajorVersion=6 / NdisMinorVersion=84 / DriverMajorVersion=1 / DriverMinorVersion=0 and
#       Parameters\DefaultFilterSettings=1), and real wlansvc depends on it:
#           DependOnService = nativewifip, RpcSs, Ndisuio, wcmsvc ; Type=16 ; Start=2 ; Group=TDI
#       Our PE has a nativewifip key but the driver is not loaded (probe16 running-driver list), and
#       only lists RpcSs as a dependency.
# probe16 could not test any of this: New-Item has no -LiteralPath on the registry provider, so the
# nwifi key was never created and NtLoadDriver returned 0x80000002 (a null result); and its
# OpenServiceW access mask contained the invalid bit 0x1000, which is why RAW failed with err=5.
param([switch]$SkipStart)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}
function DrvState([string]$n) {
  $d = @(Get-CimInstance Win32_SystemDriver -Filter ('Name=''' + $n + '''') -EA SilentlyContinue)
  if (@($d).Count -eq 0) { return 'NOT-ENUMERATED' }
  return ('State=' + $d[0].State + ' started=' + $d[0].Started + ' startmode=' + $d[0].StartMode + ' path=' + (One $d[0].PathName))
}
function DumpKey([string]$n) {
  $k = $SVC + '\' + $n
  if (-not (Test-Path -LiteralPath $k)) { Log ('  ' + $n + ' : KEY ABSENT'); return }
  $i = Get-Item -LiteralPath $k
  Log ('  [' + $n + '] stored case="' + $i.PSChildName + '"')
  foreach ($v in $i.GetValueNames()) {
    if ($v -eq '') { continue }
    $t = $i.GetValueKind($v)
    $val = $i.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($val -is [array]) { $s = ($val -join '|') } elseif ($t -eq 'Binary') { $s = '[' + $val.Length + 'B]' } else { $s = [string]$val }
    if ($s.Length -gt 200) { $s = $s.Substring(0, 200) + '...' }
    Log ('     ' + ('{0,-19}' -f $v) + $t + ' = ' + $s)
  }
  foreach ($sk in $i.GetSubKeyNames()) {
    Log ('     subkey ' + $sk)
    $j = $i.OpenSubKey($sk)
    foreach ($v in $j.GetValueNames()) {
      if ($v -eq '') { continue }
      $t = $j.GetValueKind($v)
      $val = $j.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($val -is [array]) { $s = ($val -join '|') } elseif ($t -eq 'Binary') { $s = '[' + $val.Length + 'B]' } else { $s = [string]$val }
      if ($s.Length -gt 160) { $s = $s.Substring(0, 160) + '...' }
      Log ('        ' + ('{0,-19}' -f $v) + $t + ' = ' + $s)
    }
  }
}
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$S32 = 'X:\windows\System32'
$W   = 'X:\nwifi17'

Sec '0_FULL_KEY_DUMP_VS_HOST_REFERENCE'
foreach ($n in @('wlansvc','nativewifip','dot3svc','wcmsvc')) { DumpKey $n }
Log ('  file drivers\nwifi.sys      = ' + $(if (Test-Path -LiteralPath ($S32 + '\drivers\nwifi.sys')) { 'present' } else { 'ABSENT' }))
Log ('  file drivers\nativewifip.sys= ' + $(if (Test-Path -LiteralPath ($S32 + '\drivers\nativewifip.sys')) { 'present' } else { 'ABSENT' }))
Log ('  nativewifip driver state: ' + (DrvState 'nativewifip'))
Log ('  wlansvc state            : ' + (SvcState 'wlansvc'))

Sec '1_RAW_SCM_VIEW'
$raw = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class SC17 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, uint sz, out uint needed);
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool QueryServiceStatus(IntPtr svc, byte[] st);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  public static extern int FormatMessageW(uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
}
"@
Add-Type -TypeDefinition $src
function Msg([int]$c) {
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(512)
  $n = [SC17]::FormatMessageW(0x1300, [IntPtr]::Zero, [uint32]$c, 0, $buf, 512, [IntPtr]::Zero)
  $t = ''
  if ($n -gt 0) { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf) }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
  return (($t -replace '\s+', ' ').Trim())
}
$scm = [SC17]::OpenSCManagerW([NullString]::Value, [NullString]::Value, 0x0001)
if ($scm -eq [IntPtr]::Zero) { Write-Output ('OpenSCManager FAIL err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); return }
foreach ($nm in @('wlansvc','dot3svc','nativewifip')) {
  $h = [SC17]::OpenServiceW($scm, $nm, 0x0001 -bor 0x0004 -bor 0x0010 -bor 0x0080)
  if ($h -eq [IntPtr]::Zero) {
    $e0 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Output ($nm + ' OpenService FAIL err=' + $e0 + ' [' + (Msg $e0) + ']')
    continue
  }
  $need = 0
  [void][SC17]::QueryServiceConfigW($h, [IntPtr]::Zero, 0, [ref]$need)
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$need)
  $okq = [SC17]::QueryServiceConfigW($h, $buf, [uint32]$need, [ref]$need)
  if ($okq) {
    # QUERY_SERVICE_CONFIGW x64: type 0, start 4, errctl 8, binaryPath 16, group 24, tagId 32,
    # dependencies 40 (pointer to a packed MULTI_SZ, not an array of pointers), startName 48
    $R32 = [Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
    $St2 = [Runtime.InteropServices.Marshal]::ReadInt32($buf, 4)
    $Er  = [Runtime.InteropServices.Marshal]::ReadInt32($buf, 8)
    $pImg  = [Runtime.InteropServices.Marshal]::ReadInt64($buf, 16)
    $pGrp  = [Runtime.InteropServices.Marshal]::ReadInt64($buf, 24)
    $pDep  = [Runtime.InteropServices.Marshal]::ReadInt64($buf, 40)
    $pAcct = [Runtime.InteropServices.Marshal]::ReadInt64($buf, 48)
    function StrAt([long]$a) { if ($a -eq 0) { return '' } return [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]$a) }
    $deps = ''
    if ($pDep -ne 0) {
      $cur = $pDep
      for ($x = 0; $x -lt 10; $x++) {
        $s = StrAt ([long]$cur)
        if ([string]::IsNullOrEmpty($s)) { break }
        $deps += ($s + '|')
        $cur += (([int]$s.Length) + 1) * 2
      }
    }
    Write-Output ($nm + ' CONFIG type=' + $R32 + ' start=' + $St2 + ' errctl=' + $Er + ' image=[' + (StrAt $pImg) + '] group=[' + (StrAt $pGrp) + '] deps=[' + $deps + '] acct=[' + (StrAt $pAcct) + ']')
  } else {
    Write-Output ($nm + ' QueryServiceConfig FAIL err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
}
'@
Set-Content -LiteralPath 'X:\raw17.ps1' -Value $raw -Encoding ASCII
$ro = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\raw17.ps1 2>&1') | Out-String
foreach ($l in ($ro -split "`n")) { if ((One $l).Length -gt 3) { Log ('  ' + (One $l)) } }

Sec '2_FIX_PARAMETERS_SERVICEMAIN'
$P = $SVC + '\wlansvc\Parameters'
if (-not (Test-Path -LiteralPath $P)) { Log '  Parameters subkey ABSENT -> creating' ; Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters" /f') | Out-Null }
$pi = Get-Item -LiteralPath $P -EA SilentlyContinue
Log ('  before: ' + ((@($pi.GetValueNames()) -join ',')))
Log ('  reg add ServiceMain => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters" /v ServiceMain /t REG_SZ /d WlanSvcMain /f')))
Log ('  reg add ServiceDllUnloadOnStop => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters" /v ServiceDllUnloadOnStop /t REG_DWORD /d 1 /f')))
$pi2 = Get-Item -LiteralPath $P -EA SilentlyContinue
foreach ($v in @($pi2.GetValueNames())) {
  $t = $pi2.GetValueKind($v)
  Log ('  after: ' + $v + ' ' + $t + ' = ' + (One ($pi2.GetValue($v, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) | Out-String)).Trim())
}
if (-not $SkipStart) {
  Log ('  TRY 1 net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state = ' + (SvcState 'wlansvc'))
}

Sec '3_LOAD_NATIVEWIFIP_DRIVER'
$NK = 'HKLM\SYSTEM\CurrentControlSet\Services\nativewifip'
Log ('  set Start=3  => ' + (Cmd ('reg add "' + $NK + '" /v Start /t REG_DWORD /d 3 /f')))
Log ('  NdisMajor=6  => ' + (Cmd ('reg add "' + $NK + '" /v NdisMajorVersion /t REG_DWORD /d 6 /f')))
Log ('  NdisMinor=84 => ' + (Cmd ('reg add "' + $NK + '" /v NdisMinorVersion /t REG_DWORD /d 84 /f')))
Log ('  DrvMajor=1   => ' + (Cmd ('reg add "' + $NK + '" /v DriverMajorVersion /t REG_DWORD /d 1 /f')))
Log ('  DrvMinor=0   => ' + (Cmd ('reg add "' + $NK + '" /v DriverMinorVersion /t REG_DWORD /d 0 /f')))
Log ('  Group=NDIS   => ' + (Cmd ('reg add "' + $NK + '" /v Group /t REG_SZ /d NDIS /f')))
Log ('  ImagePath    => ' + (Cmd ('reg add "' + $NK + '" /v ImagePath /t REG_EXPAND_SZ /d "system32\DRIVERS\nwifi.sys" /f')))
Cmd ('reg add "' + $NK + '\Parameters" /v DefaultFilterSettings /t REG_DWORD /d 1 /f') | Out-Null
Log ('  Parameters\DefaultFilterSettings added')
Log ('  nativewifip now: ' + (DrvState 'nativewifip'))
$nt = @'
param([string]$svcName)
$src = @"
using System;
using System.Runtime.InteropServices;
public class ND17 {
  [DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(int p, bool en, bool thread, out bool prev);
  [DllImport("ntdll.dll", CharSet=CharSet.Unicode)] public static extern int NtLoadDriver(string key);
}
"@
Add-Type -TypeDefinition $src
$prev = $false
$ap = [ND17]::RtlAdjustPrivilege(10, $true, $false, [ref]$prev)
$k = '\Registry\Machine\System\CurrentControlSet\Services\' + $svcName
$rc = [ND17]::NtLoadDriver($k)
Write-Output ('NtLoadDriver(' + $svcName + ') adjustPriv=0x{0:X8} rc=0x{1:X8}' -f $ap, $rc)
'@
Set-Content -LiteralPath 'X:\nt17.ps1' -Value $nt -Encoding ASCII
if (-not $SkipStart) {
  $no = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\nt17.ps1 -svcName nativewifip 2>&1') | Out-String
  foreach ($l in ($no -split "`n")) { if ((One $l).Length -gt 3) { Log ('  ROUTE: ' + (One $l)) } }
  Log ('  nativewifip after load: ' + (DrvState 'nativewifip'))
}

Sec '4_START_WLANSVC_WITH_DEPS'
if (-not $SkipStart) {
  Log ('  TRY 2 net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state = ' + (SvcState 'wlansvc'))
  # full dependency set and process shape from the working reference
  Log ('  set DependOnService => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v DependOnService /t REG_MULTI_SZ /d "nativewifip\0RpcSs\0Ndisuio" /f')))
  Log ('    readback = ' + (One ((Get-Item -LiteralPath ($SVC + '\wlansvc')).GetValue('DependOnService', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -join '|')))
  Log ('  TRY 3 net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state = ' + (SvcState 'wlansvc'))
  Log ('  set Type=16 (own process, like a real box) => ' + (Cmd ('reg add "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v Type /t REG_DWORD /d 16 /f')))
  Log ('  TRY 4 net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Start-Sleep -Seconds 2
  Log ('    state = ' + (SvcState 'wlansvc'))
  $wo = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl14.ps1 2>&1') | Out-String
  Log ('  wlanapi: ' + (One $wo).Trim())
  Log ('  svchosts now: ')
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    if ((One $q.CommandLine) -imatch 'LocalSystemNetworkRestricted|wlansvc') { Log ('    ' + $q.ProcessId + ':' + (One $q.CommandLine)) }
  }
}

Sec '5_FINAL'
foreach ($n in @('wlansvc','dot3svc','wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
foreach ($d in @('nativewifip','Ndisuio')) { Log ('  final driver ' + $d + ' ' + (DrvState $d)) }
Log 'PROBE17_DONE'
