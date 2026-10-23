# probe50 -- LIVE PE, read-only (offline hive is loaded, read and unloaded in finally). Output P50.
# Where we are:
#   probe48: code 37 carries DEVPKEY_Device_ProblemStatus = 3221225659 = 0xC00000BB = STATUS_NOT_SUPPORTED,
#            i.e. Netwtw14.sys loads but its entry refuses. Live PE Netwtw14 key: Start=3 Type=1 Group=NDIS,
#            no DependOnService, ImagePath -> DriverStore FileRepository (file present, 5,564,832B), and
#            *** no Parameters subkey ***.
#   probe49: nwifi/netio service keys absent -- and the HOST also has no nwifi or netio key (verified on the
#            desktop), the NativeWiFi filter key is called nativewifip with ImagePath system32\DRIVERS\nwifi.sys.
#            So "nwifi missing" is NOT our gap; our bake matches the host. vwififlt/nativewifip refused a manual
#            Start() but the Win32 code was lost in the .NET wrapper text.
#   (probe48/49 sections that walked Enum\PCI printed junk: Get-ChildItem was handed $null and listed X:\ root,
#    so the live devnode values were never actually read.)
# This probe therefore does the one comparison that has not been done cleanly:
#   the SAME devnode and the SAME Netwtw## service key, read out of the laptop's working offline SYSTEM hive (D:)
#   and out of the live PE, value by value. Whatever the working machine has and the PE lacks is the fix list.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output ('  ' + $s) }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function RQ([string]$key, [string]$sw) {
  $a = @('query', $key)
  if ($sw) { $a += $sw }
  return @(& reg.exe @a 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
}
function DumpKey([string]$label, [string]$key) {
  $o = RQ $key ''
  if ($o.Count -eq 0 -or ($o[0] -match 'ERROR')) { O ($label + ' NOT_FOUND'); return }
  foreach ($l in $o) { O ($label + ' | ' + $l) }
}
function FindNode([string]$root, [string]$needle) {
  # returns "<root>\<hid>\<iid>" for the first match of $needle under $root, or ''
  $subs = @(RQ $root '' | Where-Object { $_ -match '^HKEY' -and $_ -match [regex]::Escape($needle) })
  foreach ($s in $subs) {
    $kids = @(RQ $s '' | Where-Object { $_ -match '^HKEY' -and $_ -ne $s })
    if ($kids.Count -gt 0) { return $kids[0] }
  }
  return ''
}

HDR '0 device identity as PnP sees it'
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
$PEID = ''
foreach ($e in $ents) { $PEID = "$($e.PNPDeviceID)"; O ('LIVE_PNP ' + $PEID + ' | name=' + $e.Name +
  ' | code=' + $e.ConfigManagerErrorCode + ' | service=' + $e.Service + ' | class=' + $e.ClassGuid) }
if (-not $PEID) { O 'LIVE_PNP none' }

HDR '1 LIVE PE devnode values'
$liveNode = FindNode 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI' 'VEN_8086&DEV_7A70'
if ($liveNode) { DumpKey 'LIVE' $liveNode } else { O 'LIVE devnode NOT FOUND via reg' }

HDR '2 LIVE PE Netwtw## service key (values + subkeys)'
$liveSvc = ''
if ($liveNode) {
  $sv = @(RQ $liveNode '/v Service' | Where-Object { $_ -match 'REG_SZ' })
  if ($sv.Count) { $liveSvc = (($sv[0] -replace '^.*REG_SZ\s+', '') -replace '\s+', ' ').Trim() }
}
O ('LIVE devnode Service=' + $(if ($liveSvc) { $liveSvc } else { '-' }))
if ($liveSvc) {
  DumpKey 'LIVESVC' ('HKLM\SYSTEM\CurrentControlSet\Services\' + $liveSvc)
  $sk = RQ ('HKLM\SYSTEM\CurrentControlSet\Services\' + $liveSvc) '/s'
  foreach ($l in @($sk | Where-Object { $_ -match '^HKEY' })) { O ('LIVESVC-SUB | ' + $l) }
}

HDR '3 exact StartService error codes (Advapi32, not the .NET wrapper text)'
try {
  Add-Type -Namespace 'P50' -Name 'P50A' -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenService(string s, int access);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool StartService(IntPtr h, int num, IntPtr args);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool CloseServiceHandle(IntPtr h);
'@ -EA Stop
} catch { O ('ADDTYPE-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
foreach ($n in @('nativewifip', 'vwififlt', 'vwifimp', 'Netwtw14', 'wlansvc')) {
  try {
    $h = [P50.P50A]::OpenService($n, 0x10)          # SERVICE_START
    if ($h -eq [IntPtr]::Zero) {
      O ('START ' + $n + ' OpenService err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
      continue
    }
    $ok = [P50.P50A]::StartService($h, 0, [IntPtr]::Zero)
    $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    [void][P50.P50A]::CloseServiceHandle($h)
    $mean = $(if ($ok) { 'STARTED/pending' } elseif ($e -eq 1056) { 'ERROR_SERVICE_ALREADY_RUNNING' }
              elseif ($e -eq 31) { 'ERROR_GEN_FAILURE' } elseif ($e -eq 577) { 'ERROR_INVALID_SIGNATURE' }
              elseif ($e -eq 1068) { 'ERROR_SERVICE_DEPENDENCY_FAIL' } elseif ($e -eq 2) { 'ERROR_FILE_NOT_FOUND' }
              elseif ($e -eq 3) { 'ERROR_PATH_NOT_FOUND' } elseif ($e -eq 193) { 'ERROR_BAD_EXE_FORMAT' }
              elseif ($e -eq 5) { 'ERROR_ACCESS_DENIED' } elseif ($e -eq 1058) { 'ERROR_SERVICE_DISABLED' }
              else { '' })
    O ('START ' + $n + ' ok=' + $ok + ' err=' + $e + ' ' + $mean)
  } catch { O ('START ' + $n + ' EXC ' + (($_.Exception.Message) -replace '\s+', ' ')) }
}

HDR '4 laptop working Windows: offline SYSTEM hive, same two keys'
$hive = 'D:\Windows\System32\config\SYSTEM'
$off  = 'HKLM\P50OFF'
$loaded = $false
try {
  $lr = @(& reg.exe load $off $hive 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
  O ('LOAD ' + ($lr -join ' | '))
  if (@(RQ $off '').Count -gt 1) { $loaded = $true }
  $cs = $off + '\ControlSet001'
  $offNode = FindNode ($cs + '\Enum\PCI') 'VEN_8086&DEV_7A70'
  if ($offNode) { DumpKey 'OFF' $offNode } else { O 'OFF devnode NOT FOUND' }
  $offSvc = ''
  if ($offNode) {
    $sv = @(RQ $offNode '/v Service' | Where-Object { $_ -match 'REG_SZ' })
    if ($sv.Count) { $offSvc = (($sv[0] -replace '^.*REG_SZ\s+', '') -replace '\s+', ' ').Trim() }
  }
  O ('OFF devnode Service=' + $(if ($offSvc) { $offSvc } else { '-' }))
  if ($offSvc) {
    DumpKey 'OFFSVC' ($cs + '\Services\' + $offSvc)
    foreach ($l in @(RQ ($cs + '\Services\' + $offSvc) '/s') | Where-Object { $_ -match '^HKEY' }) {
      O ('OFFSVC-SUB | ' + $l)
    }
    $pp = RQ ($cs + '\Services\' + $offSvc + '\Parameters') ''
    foreach ($l in $pp) { O ('OFFPARAM | ' + $l) }
  }
  foreach ($n in @('nativewifip', 'nwifi', 'vwififlt', 'vwifimp', 'vwifibus')) {
    DumpKey ('OFF-' + $n) ($cs + '\Services\' + $n)
  }
  $ok1 = @(RQ ($cs + '\Control\GroupOrderList') '/v NDIS' | Where-Object { $_ -match 'REG_BINARY' })
  O ('OFF GOL NDIS ' + $(if ($ok1.Count) { $ok1[0] } else { 'ABSENT' }))
} catch { O ('OFFERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
finally {
  HDR '5 PE GroupOrderList + unload'
  $lk = @(RQ 'HKLM\SYSTEM\CurrentControlSet\Control\GroupOrderList' '/v NDIS' | Where-Object { $_ -match 'REG_BINARY' })
  O ('PE GOL NDIS ' + $(if ($lk.Count) { $lk[0] } else { 'ABSENT' }))
  O ('PE GOL valuecount ' + (@(RQ 'HKLM\SYSTEM\CurrentControlSet\Control\GroupOrderList' '' | Where-Object { $_ -match 'REG_' }).Count))
  if ($loaded) {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    $ur = @(& reg.exe unload $off 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
    O ('UNLOAD ' + ($ur -join ' | '))
  }
  O ('UNLOADCHECK ' + ((RQ $off '')[0]))
}

HDR '6 live end state'
$ents2 = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
           Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
foreach ($e in $ents2) { O ('CODE ' + $e.ConfigManagerErrorCode) }
$ip = @(Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue |
        Where-Object { $_.IPAddress } | ForEach-Object { $_.Description + '=' + ($_.IPAddress -join ',') })
O ('IPS ' + $(if ($ip.Count) { $ip -join ' ;; ' } else { '-' }))
Write-Output 'P50 END'
