# ============================================================
# probe44_svcauth.ps1 -- make wlansvc/wcmsvc match the host authority INSIDE the running PE,
#                        then find out whether the SCM honours it and whether WlanOpenHandle answers.
#
# Why this probe exists (2026-10-10, field data from probe42 + probe43 on the 12th-gen laptop):
#   The WDI bake worked: AX211 is code 0, wdiwifi + Netwtw14 Running, the card shows up as a real
#   Win32_NetworkAdapter with a MAC. What is left is the service half: wlansvc is Stopped and
#   WlanOpenHandle returns 1062 (ERROR_SERVICE_NOT_ACTIVE).
#   probe43 compared our baked keys against a read-only dump of a running Windows 10 19044
#   (build\scratch\q_host_wlansvc_1010.txt) and the divergences are exact and few:
#     wlansvc  host: Type=0x10(share) Start=0x2(auto) Group=TDI Depend=nativewifip,RpcSs,Ndisuio,wcmsvc
#              ours: Type=0x20(own)   Start=0x3(manual) Depend=RpcSs
#     wcmsvc   host: Type=0x10 Start=0x2 Group=TDI ObjectName=NT AUTHORITY\LocalService
#                        RequiredPrivileges=SeChangeNotifyPrivilege,SeImpersonatePrivilege
#              ours: Type=0x20 Start=0x3 Group=-   ObjectName=LocalService
#                        RequiredPrivileges=...,SeAuditPrivilege,SeTcbPrivilege   <- NOT holdable by
#                        a LocalService token: svchost cannot enable them and refuses to dispatch.
#   Two independent reasons why svchost would never run WlanSvcMain, and both are key-shape, not
#   driver-shape. probe43's StartService path died before it could print the code (OpenSCManagerW
#   returned lasterr=123), so this probe takes the error from sc.exe / ServiceController instead.
#
# Runtime caveat we are explicitly testing for: the SCM loads the Services keys at boot and caches
# each service's config. `sc config` updates that cache; a raw registry write does NOT. Section 4
# prints `sc qc` before and after the write, which tells us whether a live edit can validate at all
# or whether the answer only comes after the next bake + reboot.
#
# Writes: only HKLM\SYSTEM\CurrentControlSet\Services\{wlansvc,wcmsvc} (+ their Parameters) on the
# RAMDISK, and only attempts to START services. Nothing else is touched; X: evaporates on reboot.
#
# Push + run from the host (one command, result comes back automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe44_svcauth.ps1 -RemotePath X:/p44.ps1 -StagingB64 X:/p44.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# Output ASCII only (it comes back through pe-sshd).
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
$A = @{ baseErr = -1; afterErr = -1; afterErrWc = -1; cacheStale = 'unknown'; wlanOpen = -1;
        wlState = 'unknown'; wcState = 'unknown'; netshSeen = 'no' }

$SVCR = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SCX  = 'X:\Windows\System32\sc.exe'
function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
    }
  }
  return ''
}
# sc.exe wrapper. Named Invoke-Sc, NOT "SC": in Windows PowerShell the bare word sc can hit a
# built-in alias, and aliases beat functions -- that trap already cost us a run (the RV alias turned
# a helper into Remove-Variable). Args are passed as an ARRAY so a value containing spaces
# ("NT AUTHORITY\LocalService") reaches sc.exe quoted correctly instead of as one lump string.
function Invoke-Sc {
  param([string[]]$ScArgs)
  @(& $SCX @ScArgs 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() } | Where-Object { $_ -ne '' })
}
function Start-SvcAndReport([string]$name) {
  # The authoritative Win32 code for a failed start, from two independent sources:
  #   sc.exe  -> "[SC] StartService FAILED 1053:" (the SCM's own number, no marshalling involved;
  #               probe43's OpenSCManagerW P/Invoke returned lasterr=123 and proved we cannot trust it here)
  #   .NET    -> Win32Exception.NativeErrorCode from ServiceController.Start()
  $txt = @(Invoke-Sc @('start', $name))
  $code = -1
  foreach ($l in $txt) { if ($l -match '(?i)FAILED\s+(\d+)') { $code = [int]$matches[1]; break } }
  $inner = -1
  $already = 'unknown'
  try { $already = "$((Get-Service -Name $name -EA Stop).Status)" } catch { }
  if ($already -ne 'Running') {
    try {
      $c = New-Object System.ServiceProcess.ServiceController($name)
      $c.Start()
    } catch {
      $ie = $_.Exception
      while ($ie -and -not ($ie -is [System.ComponentModel.Win32Exception])) { $ie = $ie.InnerException }
      if ($ie) { $inner = $ie.NativeErrorCode }
      O ('    ' + $name + ' NET: ' + ($_.Exception.Message -replace '\s+', ' '))
    }
  } else { O ('    ' + $name + ' already Running before this call') }
  foreach ($l in @($txt | Select-Object -First 6)) { O ('    ' + $name + ' SC: ' + $l) }
  # Give the state machine a moment, then ask what it settled on.
  $wait = 0
  $now = 'unknown'
  while ($wait -lt 20) {
    try { $now = "$((Get-Service -Name $name -EA Stop).Status)" } catch { $now = 'gone' }
    if ($now -eq 'Running' -or $now -eq 'Stopped') { break }
    Start-Sleep -Seconds 2; $wait += 2
  }
  O ('    ' + $name + ' code_from_sc=' + $code + ' code_from_net=' + $inner + ' settled=' + $now)
  if ($now -eq 'Running') { return 0 }
  if ($inner -ge 0) { return $inner }
  return $code
}

O '== 1 channel sanity =='
O ('  sc.exe present = ' + (Test-Path $SCX) + '   netsh present = ' + (Test-Path 'X:\Windows\System32\netsh.exe'))
O ('  whoami = ' + (& whoami.exe 2>&1 | Out-String).Trim())

O '== 2 baseline: what does the SCM itself say about the two services =='
foreach ($n in @('wlansvc', 'wcmsvc')) {
  O ('  --- sc qc ' + $n + ' (the SCM CACHED config) ---')
  @(Invoke-Sc @('qc', $n) | Select-Object -First 12) | ForEach-Object { O ('    qc: ' + $_) }
  O ('  --- registry truth for ' + $n + ' ---')
  O ('    reg: Type=' + (RegGet "$SVCR\$n" 'Type') + ' Start=' + (RegGet "$SVCR\$n" 'Start') +
     ' Group=' + (RegGet "$SVCR\$n" 'Group') + ' Obj=' + (RegGet "$SVCR\$n" 'ObjectName') +
     ' Depend=' + (RegGet "$SVCR\$n" 'DependOnService'))
  O ('    privs=' + (RegGet "$SVCR\$n" 'RequiredPrivileges'))
}
try { [void][Reflection.Assembly]::LoadWithPartialName('System.ServiceProcess') } catch { }
O '  BASELINE START wlansvc'
$A.baseErr = Start-SvcAndReport 'wlansvc'
@(Invoke-Sc @('query', 'wlansvc') | Select-Object -First 6) | ForEach-Object { O ('    q: ' + $_) }

O '== 3 write the host authority shape (live hive, RAMDISK only) =='
# 0x10 = SERVICE_WIN32_SHARE_PROCESS, 0x20 = OWN_PROCESS. svchost only dispatches services the SCM
# considers shareable, so a -k group member declared 0x20 never reaches ServiceMain -> 1053.
$w = @(
  @('wlansvc', 'Type',            'REG_DWORD',     '0x10'),
  @('wlansvc', 'Start',           'REG_DWORD',     '0x2'),
  @('wlansvc', 'ErrorControl',    'REG_DWORD',     '0x1'),
  @('wlansvc', 'Group',           'REG_SZ',        'TDI'),
  @('wlansvc', 'ObjectName',      'REG_SZ',        'LocalSystem'),
  @('wlansvc', 'ServiceSidType',  'REG_DWORD',     '0x1'),
  @('wlansvc', 'DependOnService', 'REG_MULTI_SZ',  'nativewifip\0RpcSs\0Ndisuio\0wcmsvc'),
  @('wlansvc', 'RequiredPrivileges', 'REG_MULTI_SZ',
     'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeAuditPrivilege\0SeTcbPrivilege\0SeDebugPrivilege\0SeLoadDriverPrivilege'),
  @('wcmsvc',  'Type',            'REG_DWORD',     '0x10'),
  @('wcmsvc',  'Start',           'REG_DWORD',     '0x2'),
  @('wcmsvc',  'ErrorControl',    'REG_DWORD',     '0x1'),
  @('wcmsvc',  'Group',           'REG_SZ',        'TDI'),
  @('wcmsvc',  'ObjectName',      'REG_SZ',        'NT AUTHORITY\LocalService'),
  @('wcmsvc',  'ServiceSidType',  'REG_DWORD',     '0x1'),
  @('wcmsvc',  'DependOnService', 'REG_MULTI_SZ',  'RpcSs\0NSI'),
  # LocalService cannot hold SeAuditPrivilege/SeTcbPrivilege; svchost enables RequiredPrivileges at
  # startup and fails the whole dispatch when one cannot be enabled. Host has exactly these two.
  @('wcmsvc',  'RequiredPrivileges', 'REG_MULTI_SZ', 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege')
)
foreach ($e in $w) {
  $k = "$SVCR\" + $e[0]
  $out = @(& reg.exe add $k /f /v $e[1] /t $e[2] /d $e[3] 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  O ('  SET ' + $e[0] + '\' + $e[1] + ' -> ' + $e[3] + '  rc=' + $LASTEXITCODE +
     ' ' + (($out | Where-Object { $_ -match 'ERROR|error' } | Select-Object -First 1)))
}
# Parameters: host shape (ServiceDll/ServiceMain already matched, DllUnloadOnStop confirmed = 0x1)
foreach ($e in @(@('wlansvc', '%SystemRoot%\System32\wlansvc.dll', 'WlanSvcMain'),
                 @('wcmsvc',  '%SystemRoot%\System32\wcmsvc.dll',  'WcmSvcMain'))) {
  $kp = "$SVCR\$($e[0])\Parameters"
  @(& reg.exe add $kp /f /v ServiceDll /t REG_EXPAND_SZ /d $e[1] 2>&1 | Out-Null)
  @(& reg.exe add $kp /f /v ServiceMain /t REG_SZ /d $e[2] 2>&1 | Out-Null)
  @(& reg.exe add $kp /f /v ServiceDllUnloadOnStop /t REG_DWORD /d 0x1 2>&1 | Out-Null)
  O ('  PARAMS ' + $e[0] + ' ServiceDll=' + (RegGet $kp 'ServiceDll') + ' ServiceMain=' + (RegGet $kp 'ServiceMain') +
     ' UnloadOnStop=' + (RegGet $kp 'ServiceDllUnloadOnStop'))
}
# sc config is the only way to push a change into the SCM's live cache (raw reg writes do not).
foreach ($e in @('wlansvc', 'wcmsvc')) {
  @(Invoke-Sc @('config', $e, 'start=', 'auto')) | ForEach-Object { O ('    cfg: ' + $_) }
}
O ('  obj= for wcmsvc (sc config also refreshes the cache):')
@(Invoke-Sc @('config', 'wcmsvc', 'obj=', 'NT AUTHORITY\LocalService')) | ForEach-Object { O ('    cfg: ' + $_) }
@(Invoke-Sc @('config', 'wlansvc', 'depend=', 'nativewifip/RpcSs/Ndisuio/wcmsvc')) | ForEach-Object { O ('    cfg: ' + $_) }
$A.cacheStale = $(if ((RegGet "$SVCR\wlansvc" 'Type') -eq '0x10' -and ((Invoke-Sc @('qc', 'wlansvc')) -join ' ') -match '(?i)OWN_PROCESS') { 'yes' } else { 'no' })

O '== 4 does the SCM see the new Type? (decides runtime-validate vs bake+reboot) =='
foreach ($n in @('wlansvc', 'wcmsvc')) {
  $qc = @(Invoke-Sc @('qc', $n)) -join ' | '
  O ('  QC ' + $n + ' TYPE_LINE: ' + $(if ($qc -match '(SERVICE_TYPE\s*:\s*[A-Z_]+)') { $matches[1] } else { $qc }))
  O ('  QC ' + $n + ' START_TYPE: ' + $(if ($qc -match '(START_TYPE\s*:\s*[A-Z_]+)') { $matches[1] } else { '-' }))
}
O ('  SCM_CACHE_STALE = ' + $A.cacheStale + ' (yes = registry says 0x10 but the SCM still calls it OWN_PROCESS; only a reboot can prove the bake)')

O '== 5 start again and ask the WiFi API =='
O '  START wcmsvc first (wlansvc depends on it now)'
$A.afterErrWc = Start-SvcAndReport 'wcmsvc'
try { $A.wcState = "$((Get-Service wcmsvc -EA Stop).Status)" } catch { }
O '  START wlansvc'
$A.afterErr = Start-SvcAndReport 'wlansvc'
try { $A.wlState = "$((Get-Service wlansvc -EA Stop).Status)" } catch { }
Start-Sleep -Seconds 3
@(Invoke-Sc @('query', 'wlansvc') | Select-Object -First 8) | ForEach-Object { O ('    q: ' + $_) }

# Baseline WlanOpenHandle was 1062; call it again after the start attempt.
try {
  if (-not ('P44.P44W' -as [type])) {
    Add-Type -Namespace P44 -Name P44W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  }
  $nv = 0; $h = [IntPtr]::Zero
  $A.wlanOpen = [P44.P44W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
  O ('  WLANOPEN rc=' + $A.wlanOpen + ' newVer=' + $nv)
  if ($A.wlanOpen -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P44.P44W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('  WLANOPEN call failed: ' + $_.Exception.Message) }

# netsh wlan is the cheapest end-to-end proof: interfaces + visible SSIDs.
# Args go through as separate tokens: `netsh wlan "show interfaces"` (one lump string) makes netsh
# report "command not found", because it re-parses its own argv.
foreach ($c in @(,@('show', 'interfaces'), @('show', 'networks'))) {
  $o = @(& netsh.exe wlan @c 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() } | Where-Object { $_ -ne '' })
  O ('  NETSH wlan ' + ($c -join ' ') + ' lines=' + $o.Count)
  foreach ($l in @($o | Select-Object -First 18)) { O ('    NS: ' + $l) }
  $joined = ($o -join ' ')
  if ($joined -match '(?i)No wireless networks|There is no wireless interface|cannot be found|not running|failed to initialize|command was not found') { $A.netshSeen = 'no' }
  elseif ($joined -match '(?i)SSID \d+ :|Interface name') { $A.netshSeen = 'yes' }
}

O '== 6 VERDICT =='
O ('P44 VERDICT baseErr=' + $A.baseErr + ' afterErr_wcmsvc=' + $A.afterErrWc + ' afterErr_wlansvc=' + $A.afterErr +
   ' cache_stale=' + $A.cacheStale + ' wlansvc=' + $A.wlState + ' wcmsvc=' + $A.wcState +
   ' wlanopen=' + $A.wlanOpen + ' networks_visible=' + $A.netshSeen)
if ($A.wlanOpen -eq 0) { O 'P43/P44 READING: wlansvc runs with the host key shape -> the bake is a key-shape fix, bake it and reboot to confirm.' }
elseif ($A.cacheStale -eq 'yes') { O 'P44 READING: the SCM kept the boot-time cache, so a live edit cannot settle it -> bake Type/Start/Group/Depend/ObjectName/Privileges and reboot.' }
elseif ($A.afterErr -eq 1053) { O 'P44 READING: 1053 with the authority shape applied -> svchost loaded but WlanSvcMain never signalled: look for a missing DLL import or RPC endpoint, not key shape.' }
elseif ($A.afterErr -eq 1068) { O 'P44 READING: 1068 = one of nativewifip/Ndisuio/wcmsvc could not be started -> fix that service, wlansvc is fine.' }
elseif ($A.afterErr -eq 1069) { O 'P44 READING: 1069 = logon failure -> ObjectName not resolvable in PE (check NT AUTHORITY\LocalService for wcmsvc).' }
elseif ($A.afterErr -eq 5)    { O 'P44 READING: 5 = access denied -> service DACL (Security subkey), not the WiFi stack.' }
else { O ('P44 READING: still failing with code=' + $A.afterErr + ' - section 2/4/5 above localise it.') }
O 'P44 END'
