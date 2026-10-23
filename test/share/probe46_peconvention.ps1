# ============================================================
# probe46_peconvention.ps1 -- start wlansvc/wcmsvc the way THIS image starts every other service.
#
# What probe45 settled (live, on the 12th-gen laptop, X: ramdisk of the 2026-10-10 15:21 bake):
#   Q1 = SCM_SEES_LIVE_EDITS. Get-Service reported StartType=Automatic right after we wrote Start=0x2,
#        so the SCM re-reads the service config -> a live experiment IS valid in PE, no reboot needed
#        for the diagnosis (a reboot is still needed for the shipped-image acceptance).
#   wcmsvc returned 1068 (ERROR_DEPENDENT_SERVICES_RUNNING) in all three dependency variants
#        (none / RpcSs / RpcSs+NSI) -- so the 1068 was NOT about our dependency list.
#   No new svchost process ever appeared (procs=11 and the same 9 groups at every step), i.e. the SCM
#        refused to launch anything for these two services.
#   Section 1 is the real find: in THIS image every svchost-hosted service is Type=0x20 (own process)
#        with a -k group ImagePath -- RpcSs, NSI, Dhcp, LmHosts, eventlog, hidserv, TimeBrokerSvc,
#        Netman, dot3svc, svsvc, WinHttpAutoProxySvc all say 0x20, and six of them are Running.
#        The host authority (Win10 19044) uses 0x10 (share process) for wlansvc/wcmsvc.
#        Aligning to the HOST's Type=0x10 made both services unstartable here: on this build the shared
#        path goes through the service-hosting framework, which PE does not run, so the SCM's implicit
#        dependency fails and hands back 1068 whatever we put in DependOnService.
# => The image's own convention beats the host authority. probe46 switches both services back to
#    Type=0x20 and takes it from there, one variable at a time, printing the SCM's code each step.
#
# Also verified here: ObjectName spelling that THIS SCM accepts (compare against Dhcp, which is
# Running as a LocalService service in the same image), the ServiceMain exports really being present
# in the two DLLs, and whether SvcHostSvc/ServiceHostingService exists at all in PE.
#
# Writes: HKLM\SYSTEM\CurrentControlSet\Services\{wlansvc,wcmsvc}(+Parameters) and service start
#         attempts, all on the RAMDISK. Nothing else. X: evaporates on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe46_peconvention.ps1 -RemotePath X:/p46.ps1 -StagingB64 X:/p46.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# LogLine buffers output produced inside a function that ALSO returns a value: Write-Output would be
# swallowed into the return value, and a short helper name is dangerous -- 'oh' is a built-in alias of
# Out-Host and aliases beat functions in command-name resolution (probe45 learned that the hard way).
# FlushLog EMITS the buffer and must be called as its own statement. Do NOT wrap it in [void](...) or
# a subexpression: PowerShell captures a subexpression's whole success stream, so the lines would be
# discarded instead of printed.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }

$REG  = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SVCH = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$P = @{ steps = @(); openEnd = -1; ifaces = -1; mainExports = 'n/a'; svcHostSvc = 'n/a'; objOk = 'n/a' }

function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
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
function St([string]$n)  { try { "$((Get-Service -Name $n -EA Stop).Status)" }    catch { 'ABSENT' } }
function Sty([string]$n) { try { "$((Get-Service -Name $n -EA Stop).StartType)" } catch { 'ABSENT' } }
function TryStart([string]$n) {
  $code = -1
  try {
    $c = New-Object System.ServiceProcess.ServiceController($n)
    $c.Start()
  } catch {
    $ie = $_.Exception
    while ($ie -and -not ($ie -is [System.ComponentModel.Win32Exception])) { $ie = $ie.InnerException }
    if ($ie) { $code = $ie.NativeErrorCode }
    else { LogLine ('      ' + $n + ' ex: ' + ($_.Exception.Message -replace '\s+', ' ')) }
  }
  $w = 0; $s = St $n
  while ($w -lt 20 -and ($s -eq 'StartPending' -or $s -eq 'StopPending')) {
    Start-Sleep -Seconds 2; $w += 2; $s = St $n
  }
  LogLine ('      TRYSTART ' + $n + ' code=' + $code + ' state=' + $s + ' waited=' + $w + 's svchost=' + (SvchostCount))
  if ($code -lt 0 -and $s -eq 'Running') { $code = 0 }
  return $code
}
function SvchostCount() {
  try { return @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA Stop).Count } catch { return -1 }
}
function SvchostGroups() {
  try {
    $p = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA Stop)
    return (($p | ForEach-Object { if ("$($_.CommandLine)" -match '-k\s+(\S+)') { $matches[1] } else { '?' } }) | Sort-Object -Unique) -join ','
  } catch { return 'query-failed' }
}
if (-not ('P46.P46L' -as [type])) {
  Add-Type -Namespace P46 -Name P46L -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr LoadLibraryExW(string f, System.IntPtr h, int flags);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
public static extern System.IntPtr GetProcAddress(System.IntPtr module, string proc);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool FreeLibrary(System.IntPtr module);
public static bool HasExport(string dllPath, string fn) {
  System.IntPtr m = LoadLibraryExW(dllPath, System.IntPtr.Zero, 0);
  if (m == System.IntPtr.Zero) { return false; }
  System.IntPtr p = GetProcAddress(m, fn);
  FreeLibrary(m);
  return p != System.IntPtr.Zero;
}
'@ -EA Stop
}
function WlanOpen([string]$tag) {
  if (-not ('P46.P46W' -as [type])) {
    Add-Type -Namespace P46 -Name P46W -MemberDefinition @'
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
  try {
    $nv = 0; $h = [IntPtr]::Zero
    $rc = [P46.P46W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
    LogLine ('      WLANOPEN[' + $tag + '] rc=' + $rc + ' newVer=' + $nv)
    $n = -1
    if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P46.P46W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref] $lst)
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
        $names = [P46.P46W]::IfaceNames($lst)
        $n = $names.Count
        foreach ($x in $names) { LogLine ('        IFACE ' + $x) }
        [void][P46.P46W]::WlanFreeMemory($lst)
      }
      LogLine ('      ENUMIF rc=' + $erc + ' items=' + $n)
      [void][P46.P46W]::WlanCloseHandle($h, [IntPtr]::Zero)
    }
    $P.ifaces = $n
    return $rc
  } catch { LogLine ('      WLAN call failed: ' + $_.Exception.Message); return -2 }
}

O '== 0 does this build use the service-hosting framework at all? =='
$P.svcHostSvc = $(if (Test-Path 'X:\Windows\System32\SvcHostSvc.exe') { 'exe-present' } else { 'exe-absent' })
O ('  SvcHostSvc.exe = ' + $P.svcHostSvc + '   ServiceHostingService key = ' +
   (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ServiceHostingService') +
   '  status = ' + (St 'ServiceHostingService'))
# The image's own convention, taken from services that are actually RUNNING in this PE.
O '  PE convention (services the SCM already started here):'
foreach ($n in @('RpcSs', 'NSI', 'Dhcp', 'LmHosts', 'EventLog', 'hidserv')) {
  O ('    REF ' + $n + ' Type=' + (RegGet "$REG\$n" 'Type') + ' Start=' + (RegGet "$REG\$n" 'Start') +
     ' Obj=' + (RegGet "$REG\$n" 'ObjectName') + ' Group=' + (RegGet "$REG\$n" 'Group') +
     ' privs=' + (RegGet "$REG\$n" 'RequiredPrivileges') + ' status=' + (St $n))
}
$P.objOk = "$((RegGet "$REG\Dhcp" 'ObjectName'))|$((RegGet "$REG\LmHosts" 'ObjectName'))"
O ('  LocalService spelling that THIS SCM accepts (from a running LocalService service) = ' + $P.objOk)

O '== 1 ServiceMain exports really exist in the two DLLs =='
$P.mainExports = 'n/a'
try {
  $a = [P46.P46L]::HasExport('X:\Windows\System32\wlansvc.dll', 'WlanSvcMain')
  $b = [P46.P46L]::HasExport('X:\Windows\System32\wcmsvc.dll',  'WcmSvcMain')
  $P.mainExports = "WlanSvcMain=$a WcmSvcMain=$b"
} catch { O ('  export check failed: ' + $_.Exception.Message) }
O ('  EXPORTS ' + $P.mainExports + '  (LoadLibraryExW succeeding already proved the imports resolve)')

O '== 2 back to the image convention: Type=0x20 for both, one variable at a time =='
O ('  before: wlansvc Type=' + (RegGet "$REG\wlansvc" 'Type') + ' Start=' + (RegGet "$REG\wlansvc" 'Start') +
   ' wcmsvc Type=' + (RegGet "$REG\wcmsvc" 'Type') + ' Start=' + (RegGet "$REG\wcmsvc" 'Start'))
RegSet "$REG\wlansvc" 'Type'  'REG_DWORD' '0x20'
RegSet "$REG\wcmsvc"  'Type'  'REG_DWORD' '0x20'
RegSet "$REG\wlansvc" 'Start' 'REG_DWORD' '0x2'
RegSet "$REG\wcmsvc"  'Start' 'REG_DWORD' '0x2'
O ('  SCM now says: wlansvc StartType=' + (Sty 'wlansvc') + ' wcmsvc StartType=' + (Sty 'wcmsvc'))

O '  step a: wcmsvc, Type=0x20, depend=RpcSs+NSI, ObjectName=NT AUTHORITY\LocalService'
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' 'NT AUTHORITY\LocalService'
RegSet "$REG\wcmsvc" 'RequiredPrivileges' 'REG_MULTI_SZ' 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege'
RegSet "$REG\wcmsvc" 'DependOnService' 'REG_MULTI_SZ' 'RpcSs\0NSI'
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "wc/0x20/auth-obj=$c"
O '  step b: same but ObjectName spelled the way the RUNNING Dhcp service spells it'
$alt = (RegGet "$REG\Dhcp" 'ObjectName')
if (-not $alt) { $alt = 'LocalService' }
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' $alt
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "wc/0x20/obj=$alt=$c"
O '  step c: no dependencies at all'
RegDel "$REG\wcmsvc" 'DependOnService'
$c = TryStart 'wcmsvc'; FlushLog; $P.steps += "wc/0x20/nodeps=$c"
try { $P.wcState = "$((Get-Service wcmsvc -EA Stop).Status)" } catch { $P.wcState = 'gone' }

O '  step d: wlansvc, Type=0x20, depend=RpcSs (the shape the bake currently produces)'
RegSet "$REG\wlansvc" 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'
$c = TryStart 'wlansvc'; FlushLog; $P.steps += "wl/0x20/deps=rpcss=$c"
O '  step e: wlansvc with the full host dependency set (nativewifip,RpcSs,Ndisuio,wcmsvc)'
RegSet "$REG\wlansvc" 'DependOnService' 'REG_MULTI_SZ' 'nativewifip\0RpcSs\0Ndisuio\0wcmsvc'
$c = TryStart 'wlansvc'; FlushLog; $P.steps += "wl/0x20/deps=full=$c"
O '  step f: wlansvc with no dependencies at all'
RegDel "$REG\wlansvc" 'DependOnService'
$c = TryStart 'wlansvc'; FlushLog; $P.steps += "wl/0x20/nodeps=$c"
try { $P.wlState = "$((Get-Service wlansvc -EA Stop).Status)" } catch { $P.wlState = 'gone' }
$P.openEnd = WlanOpen 'final'; FlushLog

O '== 3 a control experiment: does any NEW svchost start for a service we know works? =='
# Netman is in the same group, same shape, Type=0x20, and it is Stopped. If Netman starts cleanly
# while wlansvc does not, the difference is inside wlansvc, not in svchost/the group.
O '  step g: Netman (same group, baked by us, currently Stopped)'
$c = TryStart 'netman'; FlushLog; $P.steps += "netman=$c"
O '  step h: dot3svc (same group, needs Eaphost which is Stopped)'
$c = TryStart 'dot3svc'; FlushLog; $P.steps += "dot3svc=$c"
O ('  SVCHOST now procs=' + (SvchostCount) + ' groups=' + (SvchostGroups))

O '== 4 driver-side consequence (does nwifi load once wlansvc asks for it?) =='
foreach ($s in @('nativewifip', 'Ndisuio', 'vwifibus', 'vwififlt', 'NdisImPlatform')) {
  $d = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -eq $s })
  O ('  DRV ' + $s + ' state=' + $(if ($d.Count) { $d[0].State } else { 'n/a' }) + ' startmode=' +
     $(if ($d.Count) { $d[0].StartMode } else { 'n/a' }))
}

O '== 5 VERDICT =='
O ('P46 VERDICT svcHostSvc=' + $P.svcHostSvc + ' exports=' + $P.mainExports + ' localServiceObj=' + $P.objOk +
   ' steps=' + ($P.steps -join ' ') + ' wcmsvc=' + $P.wcState + ' wlansvc=' + $P.wlState +
   ' wlanopen=' + $P.openEnd + ' ifaces=' + $P.ifaces)
if ($P.openEnd -eq 0) { O 'P46 READING: wlansvc runs with Type=0x20 -> bake Type=0x20 (image convention), NOT the host authority 0x10.' }
elseif (($P.steps -join ' ') -match 'nodeps=1068') { O 'P46 READING: 1068 with no dependencies at all -> an implicit dependency (service-hosting framework / group) is what the SCM cannot satisfy.' }
elseif (($P.steps -join ' ') -match '=1053') { O 'P46 READING: 1053 -> svchost launched but ServiceMain never signalled; compare with the Netman control step.' }
elseif (($P.steps -join ' ') -match '=1069') { O 'P46 READING: 1069 -> logon failure, the ObjectName spelling is not resolvable in PE.' }
elseif (($P.steps -join ' ') -match '=5\b') { O 'P46 READING: 5 -> access denied; the service DACL (Security subkey) needs baking.' }
else { O 'P46 READING: see steps above; a code that never appears means the SCM refused before dispatch.' }
O 'P46 END'
