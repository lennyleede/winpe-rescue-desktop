# ============================================================
# probe48_wcmobj.ps1 -- crack wcmsvc's instant 1068 (the only thing standing between us and wlansvc),
# then retry wlansvc with wcmsvc actually up.
#
# probe47 settled (live, 2026-10-10 bake, X: ramdisk):
#   wlansvc's key shape is now INDISTINGUISHABLE from services that start on demand here:
#     dot3svc / Netman / hidserv = Type 0x20, IMG '%SystemRoot%\...\svchost.exe -k <group> -p',
#     wlansvc = same shape, same group (LocalSystemNetworkRestricted), privs are a superset of dot3svc's,
#     ServiceDll exists, WlanSvcMain is a real export.
#   `-k <group> -p -s wlansvc` (candidate 2) DID spawn a dedicated svchost: procs 11 -> 12 with
#     '-s=wlansvc' visible, then the service went Stopped inside ~2s. So svchost + ServiceMain run and
#     the service quits on its own. That is a runtime failure, not a key-shape failure.
#   wcmsvc fails EARLIER and differently: code=1068 returned instantly (waited=0s), no process spawned,
#     even with DependOnService absent and with Dhcp's exact IMG/ObjectName/privileges.
#   The one variable that separates the services that start on demand (Netman, dot3svc, hidserv =
#     LocalSystem) from wcmsvc (NT Authority\LocalService) is ObjectName. Dhcp/NSI/LmHosts run as
#     LocalService too, but they were started AT BOOT; nothing LocalService has been startable ON
#     DEMAND in this PE so far.
#   The PE has NO System event log ('Could not retrieve information about the System log. Error: The
#     system cannot find the file specified.'), so the SCM's own explanation is unavailable -- we have
#     to bisect the key ourselves.
# => probe48 factorial on wcmsvc: -s form, LocalSystem, no Group, no TriggerInfo, its own svchost group;
#    and once wcmsvc is up, retry wlansvc (its host-side dependency list says it needs wcmsvc at init,
#    which is the most likely reason WlanSvcMain gives up after 2s).
#
# Writes: HKLM\SYSTEM\CurrentControlSet\Services\{wlansvc,wcmsvc}(+Parameters, TriggerInfo) +
#         HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost (one group value) + start attempts.
#         All on the RAMDISK. X: evaporates on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe48_wcmobj.ps1 -RemotePath X:/p48.ps1 -StagingB64 X:/p48.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# LogLine buffers output from functions that also return a value; FlushLog must be its own statement
# ([void](FlushLog) would swallow the success stream). Aliases beat functions: no short names here.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }

$REG  = 'HKLM\SYSTEM\CurrentControlSet\Services'
$REGP = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SVCH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$P = @{ steps = @(); wl = @(); openEnd = -1; ifaces = -1; wcFinal = 'n/a'; wlFinal = 'n/a' }

function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim() -replace '\\0', ';')
    }
  }
  return ''
}
function RegSet([string]$key, [string]$name, [string]$type, [string]$data) {
  $out = @(& reg.exe add "$key" /f /v $name /t $type /d $data 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  $err = (@($out | Where-Object { $_ -match '(?i)error' }) | Select-Object -First 1)
  O ('    set ' + ($key -split '\\')[-1] + '\' + $name + ' = ' + $data + ' rc=' + $LASTEXITCODE + $(if ($err) { ' ' + $err } else { '' }))
}
function RegDel([string]$key, [string]$name) {
  [void](& reg.exe delete "$key" /f /v $name 2>&1)
  O ('    del ' + ($key -split '\\')[-1] + '\' + $name + ' rc=' + $LASTEXITCODE)
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function SubKeys([string]$keyPath) {
  # provider API, not reg.exe: reg.exe truncates long paths with '...' and lies about absence
  try { return @(Get-ChildItem -LiteralPath $keyPath -EA Stop | ForEach-Object { $_.PSChildName }) } catch { return @() }
}
function ValNames([string]$keyPath) {
  try { return @(Get-Item -LiteralPath $keyPath -EA Stop).GetValueNames() } catch { return @() }
}
function SvchostProcs() {
  try { return @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA Stop) } catch { return @() }
}
function SvchostSig([string]$tag) {
  $p = SvchostProcs
  $sNames = ((@($p | ForEach-Object { if ("$($_.CommandLine)" -match '-s\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
  LogLine ('      [' + $tag + '] svchost procs=' + $p.Count + ' -s=' + (ToAscii $sNames))
}
function TryStart([string]$n) {
  $code = -1
  try { $c = New-Object System.ServiceProcess.ServiceController($n); $c.Start() }
  catch {
    $ie = $_.Exception
    while ($ie -and -not ($ie -is [System.ComponentModel.Win32Exception])) { $ie = $ie.InnerException }
    if ($ie) { $code = $ie.NativeErrorCode }
    else { LogLine ('      ' + $n + ' ex: ' + (ToAscii ($_.Exception.Message -replace '\s+', ' '))) }
  }
  $w = 0; $s = St $n
  while ($w -lt 20 -and ($s -eq 'StartPending' -or $s -eq 'StopPending')) {
    if ($w -eq 0) { SvchostSig ($n + '-pending') }
    Start-Sleep -Seconds 2; $w += 2; $s = St $n
  }
  LogLine ('      TRYSTART ' + $n + ' code=' + $code + ' state=' + $s + ' waited=' + $w + 's svchost=' + (SvchostProcs).Count)
  if ($code -lt 0 -and $s -eq 'Running') { $code = 0 }
  return $code
}
if (-not ('P48.P48W' -as [type])) {
  Add-Type -Namespace P48 -Name P48W -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public struct WLAN_INTERFACE_INFO {
  public System.Guid interfaceGuid;
  [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
  public string description;
  public int state;
}
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError = true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[System.Runtime.InteropServices.DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError = true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list);
[System.Runtime.InteropServices.DllImport("wlanapi.dll")]
public static extern void WlanFreeMemory(System.IntPtr mem);
public static string[] IfaceNames(System.IntPtr list) {
  int n = System.Runtime.InteropServices.Marshal.ReadInt32(list);
  if (n < 0) { n = 0; }
  string[] r = new string[n];
  int stride = System.Runtime.InteropServices.Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO));
  for (int i = 0; i < n; i++) {
    System.IntPtr item = new System.IntPtr(list.ToInt64() + 8 + (long)i * stride);
    WLAN_INTERFACE_INFO info = (WLAN_INTERFACE_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure(
        item, typeof(WLAN_INTERFACE_INFO));
    r[i] = info.description + "|state=" + info.state + "|guid=" + info.interfaceGuid;
  }
  return r;
}
'@ -EA Stop
}
function WlanOpen([string]$tag) {
  try {
    $nv = 0; $h = [IntPtr]::Zero
    $rc = [P48.P48W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
    LogLine ('      WLANOPEN[' + $tag + '] rc=' + $rc + ' newVer=' + $nv)
    $n = -1
    if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P48.P48W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref] $lst)
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
        $names = [P48.P48W]::IfaceNames($lst)
        $n = $names.Count
        foreach ($x in $names) { LogLine ('        IFACE ' + $x) }
        [void][P48.P48W]::WlanFreeMemory($lst)
      }
      LogLine ('      ENUMIF rc=' + $erc + ' items=' + $n)
      [void][P48.P48W]::WlanCloseHandle($h, [IntPtr]::Zero)
    }
    $P.ifaces = $n
    return $rc
  } catch { LogLine ('      WLAN call failed: ' + (ToAscii $_.Exception.Message)); return -2 }
}

O '== 0 forensics that are actually available in this PE =='
O ('  wevtutil = ' + $(if (Get-Command wevtutil.exe -EA SilentlyContinue) { 'present' } else { 'absent' }))
try {
  $logs = @(Get-WinEvent -ListLog * -EA Stop | ForEach-Object { $_.LogName })
  O ('  logs registered=' + $logs.Count + ' [' + (($logs | Select-Object -First 12) -join ',') + ']')
  $sys = @($logs | Where-Object { $_ -match '(?i)^System$|^Application$|WLAN|AutoConfig|Configuration' })
  O ('  interesting=' + ($sys -join ','))
} catch { O ('  Get-WinEvent -ListLog failed: ' + (ToAscii $_.Exception.Message)) }
O ('  winevt dir = ' + (Test-Path 'X:\Windows\System32\winevt') + ' logs dir = ' + (Test-Path 'X:\Windows\System32\winevt\Logs'))

O '== 1 full shape diff: wcmsvc (instant 1068) vs dot3svc (starts on demand) =='
foreach ($n in @('wcmsvc', 'dot3svc', 'wlansvc')) {
  O ('  KEY ' + $n)
  O ('    values   = ' + ((ValNames ($REGP + '\' + $n)) -join ','))
  O ('    subkeys  = ' + ((SubKeys ($REGP + '\' + $n)) -join ','))
  O ('    Type=' + (RegGet "$REG\$n" 'Type') + ' Start=' + (RegGet "$REG\$n" 'Start') +
     ' Obj=[' + (RegGet "$REG\$n" 'ObjectName') + '] Group=[' + (RegGet "$REG\$n" 'Group') +
     '] deps=[' + (RegGet "$REG\$n" 'DependOnService') + '] Delay=' + (RegGet "$REG\$n" 'DelayedAutoStart') +
     ' ErrorControl=' + (RegGet "$REG\$n" 'ErrorControl') + ' status=' + (St $n))
  O ('    IMG=[' + (RegGet "$REG\$n" 'ImagePath') + ']')
  O ('    privs=' + (RegGet "$REG\$n" 'RequiredPrivileges') + ' SidType=' + (RegGet "$REG\$n" 'SidType') +
     ' FailureCmd=' + (RegGet "$REG\$n" 'FailureCommandLine'))
  O ('    Parameters values=' + ((ValNames ($REGP + '\' + $n + '\Parameters')) -join ',') +
     ' ServiceDll=' + (RegGet "$REG\$n\Parameters" 'ServiceDll') + ' ServiceMain=' + (RegGet "$REG\$n\Parameters" 'ServiceMain'))
  $ti = @(SubKeys ($REGP + '\' + $n + '\TriggerInfo'))
  O ('    TriggerInfo subkeys=' + $ti.Count + ' [' + ($ti -join ',') + ']')
}

O '== 2 wcmsvc factorial: which single variable makes the SCM return 1068 =='
$baseImg = RegGet "$REG\wcmsvc" 'ImagePath'
$dotPrivs = (RegGet "$REG\dot3svc" 'RequiredPrivileges') -replace ';', '\0'
O ('  W1 control, key exactly as probe47 left it (LocalService, group IMG, no deps)')
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W1_ctrl=$c"
O ('  W2 add the explicit -s form (this is what spawned a dedicated svchost for wlansvc)')
RegSet "$REG\wcmsvc" 'ImagePath' 'REG_EXPAND_SZ' ($baseImg + ' -s wcmsvc')
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W2_dash_s=$c"
O ('  W3 ObjectName = LocalSystem (all on-demand starters here are LocalSystem)')
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' 'LocalSystem'
RegSet "$REG\wcmsvc" 'RequiredPrivileges' 'REG_MULTI_SZ' $dotPrivs
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W3_localsystem=$c"
O ('  W4 keep LocalSystem and drop Group=TDI as well')
RegDel "$REG\wcmsvc" 'Group'
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W4_nogroup=$c"
O ('  W5 keep LocalSystem, no Group, and remove TriggerInfo if it exists')
if (Test-Path ($REGP + '\wcmsvc\TriggerInfo')) {
  [void](& reg.exe delete "$REG\wcmsvc\TriggerInfo" /f 2>&1)
  O ('    TriggerInfo deleted rc=' + $LASTEXITCODE)
} else { O '    no TriggerInfo to delete' }
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W5_notrigger=$c"
O ('  W6 give wcmsvc its OWN svchost group so it does not share the running LocalServiceNetworkRestricted host')
RegSet 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost' 'wcmsvcs' 'REG_SZ' 'wcmsvc'
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' 'NT Authority\LocalService'
RegSet "$REG\wcmsvc" 'RequiredPrivileges' 'REG_MULTI_SZ' 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeCreateGlobalPrivilege'
RegSet "$REG\wcmsvc" 'ImagePath' 'REG_EXPAND_SZ' '%SystemRoot%\system32\svchost.exe -k wcmsvcs -p -s wcmsvc'
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W6_owngroup_ls=$c"
O ('  W7 own group but LocalSystem')
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' 'LocalSystem'
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "W7_owngroup_sys=$c"
$P.wcFinal = St 'wcmsvc'
O ('  wcmsvc ends as ' + $P.wcFinal)

O '== 3 wlansvc retry once wcmsvc is whatever it is =='
O ('  L1 as it stands now (its own IMG from probe47 candidate 2)')
$c = TryStart 'wlansvc'; FlushLog; $P.wl += "L1_now=$c"
O ('  L2 with the host dependency list written back, in dependency order')
foreach ($d in @('NdisImPlatform', 'nativewifip', 'wcmsvc')) {
  $s = St $d
  if ($s -ne 'Running') { $dc = TryStart $d; FlushLog; O ('    dep ' + $d + ' -> code=' + $dc + ' state=' + (St $d)) }
  else { O ('    dep ' + $d + ' already Running') }
}
RegSet "$REG\wlansvc" 'DependOnService' 'REG_MULTI_SZ' 'nativewifip\0RpcSs\0Ndisuio\0wcmsvc'
$c = TryStart 'wlansvc'; FlushLog; $P.wl += "L2_depsup=$c"
O ('  L3 with the plain group host IMG (no -s) like dot3svc uses')
RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' '%SystemRoot%\system32\svchost.exe -k LocalSystemNetworkRestricted -p'
$c = TryStart 'wlansvc'; FlushLog; $P.wl += "L3_groupimg=$c"
O ('  L4 own svchost group + -s, deps satisfied')
RegSet 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost' 'wlansvcs' 'REG_SZ' 'wlansvc'
RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' '%SystemRoot%\system32\svchost.exe -k wlansvcs -p -s wlansvc'
$c = TryStart 'wlansvc'; FlushLog; $P.wl += "L4_owngroup=$c"
$P.wlFinal = St 'wlansvc'
SvchostSig 'after-wl'; FlushLog
$P.openEnd = WlanOpen 'final'; FlushLog

O '== 4 kernel-side state after all that =='
foreach ($s in @('ndisimplatform', 'nativewifip', 'vwifibus', 'vwififlt', 'vwifimp', 'wdiwifi', 'Netwtw14', 'Eaphost', 'nsi', 'rpcss')) {
  O ('  SVC ' + $s + ' = ' + (St $s) + ' Start=' + (RegGet "$REG\$s" 'Start') + ' Type=' + (RegGet "$REG\$s" 'Type'))
}

O '== 5 VERDICT =='
O ('P48 VERDICT wc=' + ($P.steps -join ' ') + ' wcState=' + $P.wcFinal +
   ' wl=' + ($P.wl -join ' ') + ' wlState=' + $P.wlFinal +
   ' wlanopen=' + $P.openEnd + ' ifaces=' + $P.ifaces)
if ($P.openEnd -eq 0) { O 'P48 READING: wlansvc is UP and wlanapi answers -> bake the winning key shape; WiFi is reachable from PE.' }
elseif ($P.wcFinal -eq 'Running') { O 'P48 READING: wcmsvc runs with the shape marked by the winning W-step -> apply that to wcmsvc in the bake and re-test wlansvc (L-steps show what wlansvc still needs).' }
elseif ($P.wlFinal -eq 'Running') { O 'P48 READING: wlansvc runs but wlanapi still refuses -> look at the L-step that made it Running and the interface enumeration above.' }
elseif (($P.steps -join ' ') -match 'W3_localsystem=0|W4_nogroup=0|W7_owngroup_sys=0') { O 'P48 READING: LocalSystem variant reached Running then died later; the 1068 was the LocalService account, so the bake must choose an account PE can start on demand.' }
else { O 'P48 READING: 1068 survived every variable -> the SCM refuses wcmsvc for a reason outside these keys (compare with a fresh LocalService service we could add, e.g. w32time) or the account itself cannot be started on demand in PE.' }
O 'P48 END'
