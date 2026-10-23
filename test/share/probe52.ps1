# probe52 -- LIVE PE. Last fork in the road, then we know which bake to write.
# probe51 closed the include question with the machine's own words:
#   inf: Included INFs = netvwifibus.inf            (PnP knows the include exists)
#   inf: Needed section [VWiFiBus] / [VWiFiBus.CopyFiles] / [VWiFiBus.PnPFilterRegistration]
#        not found, might exist in missing included INF.        (x many, every install attempt)
# and probe50 showed the consequence: live devnode has NO UpperFilters, the laptop's working devnode has
# UpperFilters=vwifibus. Netwtw14 then refuses to initialise: Device Status 0x01802400 [0x25 - 0xc00000bb].
# Two independent things can still be the reason the vWiFi layer never attaches, and the fix differs:
#   (1) registration: netvwifibus.inf is not a *properly installed* package in the image (DISM refused it,
#       rc=13, leaving oem178.inf + a half-made FileRepository dir, vwifibus/vwififlt/vwifimp Owners empty).
#   (2) loadability:  the borrowed stack is 19041-era while this PE kernel is 26100 (probe40), and
#       vwififlt(Start=1,Group=NDIS) is Stopped in a booted PE while tdx/AFD/NetBT of the same class loaded,
#       nativewifip historically returning dos=31 on StartService.
# This probe settles (2) at runtime: give vwififlt a Manual start type (ramdisk only, gone on reboot), start
# each filter with real SCM calls that report the Win32 code, then restart the NIC and re-read code+status.
# If vwififlt/nativewifip CAN load here, (2) is dead and the whole fix is (1) = stage netvwifibus.inf properly.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output ('  ' + $s) }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function CodeNow {
  $c = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' } |
         ForEach-Object { $_.ConfigManagerErrorCode })
  if ($c.Count -eq 0) { return 'GONE' } else { return "$($c[0])" }
}
function ProbStatus {
  $d = @(Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.InstanceId -like '*VEN_8086&DEV_7A70*' })
  if ($d.Count -eq 0) { return '-' }
  $v = (Get-PnpDeviceProperty -InstanceId $d[0].InstanceId -Key 'DEVPKEY_Device_ProblemStatus' -EA SilentlyContinue).Data
  if ($null -eq $v) { return '-' }
  return ($v.ToString() + ' 0x' + ('{0:X8}' -f [uint32]$v))
}
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
$PNP = if ($ents.Count) { "$($ents[0].PNPDeviceID)" } else { '' }
HDR '0 device'
O ('PNPDEVICEID ' + $(if ($PNP) { $PNP } else { 'none' }))
O ('code=' + (CodeNow) + ' status=' + (ProbStatus))

HDR '1 SCM calls that actually report the Win32 error'
try {
  Add-Type -Namespace 'P52' -Name 'Scm' -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)]
public struct SERVICE_STATUS {
  public int serviceType; public int currentState; public int controlsAccepted;
  public int win32ExitCode; public int serviceSpecificExitCode; public int checkPoint; public int waitHint;
}
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenSCManager(string machine, string db, int access);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenService(IntPtr scm, string name, int access);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool StartService(IntPtr svc, int numArgs, IntPtr args);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool QueryServiceStatus(IntPtr svc, ref SERVICE_STATUS status);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool CloseServiceHandle(IntPtr h);
'@ -EA Stop
  O 'ADDTYPE ok'
} catch { O ('ADDTYPE-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
function ScmStart([string]$name) {
  $scm = [P52.Scm]::OpenSCManager($null, $null, 1)             # SC_MANAGER_CONNECT
  if ($scm -eq [IntPtr]::Zero) { return ('OpenSCManager err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  $h = [P52.Scm]::OpenService($scm, $name, 0x14)               # SERVICE_START | SERVICE_QUERY_STATUS
  $r = ''
  if ($h -eq [IntPtr]::Zero) {
    $r = 'OpenService err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ' (1060=service does not exist)'
  } else {
    $ok = [P52.Scm]::StartService($h, 0, [IntPtr]::Zero)
    $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $st = New-Object 'P52.Scm+SERVICE_STATUS'
    [void][P52.Scm]::QueryServiceStatus($h, [ref]$st)
    $r = ('Start ok=' + $ok + ' err=' + $e + ' state=' + $st.currentState +
          ' win32exit=' + $st.win32ExitCode + ' specific=' + $st.serviceSpecificExitCode)
    [void][P52.Scm]::CloseServiceHandle($h)
  }
  [void][P52.Scm]::CloseServiceHandle($scm)
  return $r
}
foreach ($n in @('ndisuio', 'vwifibus', 'vwifimp', 'nativewifip')) {
  O ('BEFORE ' + $n + ' : ' + (ScmStart $n))
}

HDR '2 vwififlt is Start=1 (kernel-load only, SCM refuses those) -> make it Manual for this session'
$k = 'HKLM\SYSTEM\CurrentControlSet\Services\vwififlt'
$orig = ((& reg.exe query $k /v Start 2>&1 | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) |
         Where-Object { $_ -match 'REG_DWORD' })
O ('ORIG ' + ($orig -join ''))
& reg.exe add $k /v Start /t REG_DWORD /d 3 /f | Out-Null
O ('NOW  ' + ((& reg.exe query $k /v Start 2>&1 | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join ' | '))
O ('TRY vwififlt : ' + (ScmStart 'vwififlt'))
try { O ('STATE vwififlt = ' + "$(Get-Service vwififlt).Status") } catch { O 'STATE vwififlt = NOGET' }

HDR '3 with vwififlt (hopefully) loaded, restart the NIC and read it back'
if ($PNP) {
  $r = @(& pnputil.exe /restart-device "$PNP" 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
  O ('RESTART ' + ($r -join ' | '))
  Start-Sleep -Seconds 5
} else { O 'RESTART skipped (no device id)' }
O ('code=' + (CodeNow) + ' status=' + (ProbStatus))
foreach ($n in @('vwififlt', 'vwifibus', 'nativewifip', 'Netwtw14')) {
  try { O ('STATE ' + $n + ' = ' + "$(Get-Service $n).Status") } catch { O ('STATE ' + $n + ' = NOGET') }
}

HDR '4 wlansvc + wlanapi after the experiment'
O ('TRY wlansvc : ' + (ScmStart 'wlansvc'))
Start-Sleep -Seconds 3
try {
  Add-Type -Namespace 'P52' -Name 'W' -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list, out int count);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [P52.W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    $rc2 = [P52.W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt)
    O ('WLANENUM rc=' + $rc2 + ' ifaces=' + $cnt)
    [void][P52.W]::WlanCloseHandle($h, [IntPtr]::Zero)
  }
} catch { O ('WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
$ents2 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
           Where-Object { $_.Name -match '(?i)Wi-Fi|wireless|Virtual WiFi|Network Adapter' })
foreach ($e in $ents2) { O ('DEV ' + $e.Name + ' code=' + $e.ConfigManagerErrorCode) }
Write-Output 'P52 END'
