# ============================================================
# probe43_svcstart.ps1 -- why does wlansvc still fail to start now that the WDI fix landed?
#
# Context (2026-10-10 15:21 bake, verified by probe42 on the 12th-gen laptop):
#   PASS  wdiwifi.sys + NdisImPlatform.sys baked, both covering .cat in CatRoot,
#         Intel AX211 devcode 37 -> code 0 / status=OK, Win32_SystemDriver: wdiwifi=Running,
#         Netwtw14=Running. The driver half of the WiFi line is fixed.
#   FAIL  wlansvc still Stopped, Start-Service fails, WlanOpenHandle rc=1062;
#         vwifibus/vwififlt/vwifimp all Stopped, no vwifibus/virtual-adapter node,
#         class UpperFilters empty.
# So the question left is: which prerequisite does wlansvc miss -- a dependency service, the
# NetCfg component store (Control\Network + Linkage\FilterList), or a missing DLL/import?
# PE has no System/Application event log, so the failure code must be pulled from the SCM itself.
#
# READ-ONLY except one thing: it attempts to START wlansvc (and wcmsvc/RpcSs if stopped), which is
# the acceptance criterion itself and evaporates with the ramdisk. It never writes registry/files.
#
# Push + run from the host:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 -Local test\share\probe43_svcstart.ps1 `
#     -RemotePath X:\p43.ps1 -StagingB64 X:\p43.b64 -Target administrator@192.168.0.107 -Port 22 -Run
# Output ASCII only (it comes back through pe-sshd).
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
$A = @{ paramkey = 0; filterlist = -1; ctrlNet = -1; adapters = -1; startRc = -1; startErr = -1;
        wl32 = -1; spec = 0; wlanOpen = -1; wlanSvc = 'unknown'; deps = @() }

# PS path pitfall (bit us in probe42): Test-Path needs the provider-qualified form 'HKLM:\',
# while reg.exe wants 'HKLM\'. Without the colon Test-Path resolves against the CURRENT drive and
# silently returns False -- that is what made wdi_paramkey look like 0/2 on a correctly baked image.
# The reverse is also true: feeding the COLON form to reg.exe makes it query a nonexistent key and
# print an empty value for everything -- that is what made section 3 come back blank last run.
$SVCR  = 'HKLM:\SYSTEM\CurrentControlSet\Services'   # provider form: Test-Path / Get-ItemProperty
$SVCRN = 'HKLM\SYSTEM\CurrentControlSet\Services'    # plain form:  reg.exe
function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
    }
  }
  return ''
}

O '== 1 WDI Parameters subkeys (bake-shape proof, HKLM:\ this time) =='
foreach ($s in @('wdiwifi', 'NdisImPlatform')) {
  $kp = "$SVCR\$s\Parameters"
  if (Test-Path $kp) { $A.paramkey++ }
  $vals = @()
  if (Test-Path $kp) {
    foreach ($p in @((Get-ItemProperty $kp -EA SilentlyContinue).PSObject.Properties)) {
      if ($p.Name -notmatch '^PS_') { $vals += ($p.Name + '=' + ("$($p.Value)" -replace '\s+', ';')) }
    }
  }
  O ('  PARAM ' + $s + ' exists=' + (Test-Path $kp) + ' values=' + $(if ($vals.Count) { $vals -join ' | ' } else { '-' }))
}
O ('  PARAMKEY ' + $A.paramkey + '/2 (2 = keys came from the offline bake, not runtime hand-writing)')

O '== 2 dependency / plumbing services =='
foreach ($n in @('RpcSs', 'DcomLaunch', 'Dnssd', 'Nsi', 'Winmgmt', 'mpssvc', 'lmhosts', 'netprofm', 'FDResPub', 'upnphost', 'dot3svc', 'Netman', 'wcmsvc', 'wlansvc')) {
  try {
    $sv = Get-Service -Name $n -EA Stop
    O ('  SVC ' + $n + ' status=' + $sv.Status + ' starttype=' + $sv.StartType + ' deps=' +
       ((@($sv.ServicesDependedOn) | ForEach-Object { $_.Name }) -join ','))
  } catch { O ('  SVC ' + $n + ' = ' + $_.Exception.Message.Split("`n")[0]) }
}
# 1068 (ERROR_DEPENDENT_SERVICES_RUNNING) is only useful if we know WHICH dep is missing or stopped.
# reg.exe renders REG_MULTI_SZ as one line with literal backslash-zero between entries, so split on
# the TWO-CHARACTER sequence (a regex '\0' would match a real NUL and split nothing).
foreach ($n in @('wlansvc', 'wcmsvc', 'nativewifip')) {
  $dep = (RegGet "$SVCRN\$n" 'DependOnService') -replace '\\0', ';'
  if (-not $dep) { continue }
  foreach ($d in (@($dep -split ';' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() }))) {
    $exists = Test-Path "$SVCR\$d"
    $stt2 = 'ABSENT'
    if ($exists) { try { $stt2 = "$((Get-Service -Name $d -EA Stop).Status)" } catch { $stt2 = 'no-SCM-entry' } }
    O ('  DEP ' + $n + ' -> ' + $d + ' key=' + $exists + ' status=' + $stt2)
  }
}

O '== 3 wlansvc / wcmsvc key shape as booted =='
# Host authority (read-only dump in build\scratch\q_host_wlansvc.ps1, 2026-10-10):
#   wlansvc : Type=0x10 Start=0x2 ErrorControl=0x1 Group=TDI
#             DependOnService=nativewifip\0RpcSs\0Ndisuio\0wcmsvc  ObjectName=LocalSystem SidType=0x1
#             ImagePath=%SystemRoot%\system32\svchost.exe -k LocalSystemNetworkRestricted -p
#             RequiredPrivileges=SeCreateGlobalPrivilege;SeImpersonatePrivilege;SeIncreaseQuotaPrivilege;
#                                  SeTcbPrivilege;SeAssignPrimaryTokenPrivilege;SeRestorePrivilege
#             Parameters{ServiceDll=WlanSvc.dll, ServiceMain=WlanSvcMain, ServiceDllUnloadOnStop=1}
#             subkeys Security + VirtualizationManager
#   wcmsvc  : Type=0x10 Start=0x2 Group=TDI Depend=RpcSs\0NSI
#             ObjectName=NT Authority\LocalService RequiredPrivileges=SeChangeNotifyPrivilege;SeImpersonatePrivilege
#             Parameters ServiceMain=WcmSvcMain, subkeys Csps\{cspethernet,cspwlan,cspwwan} Security TriggerInfo\0
# Every field below is printed with a '!=' marker when it deviates, because a svchost-hosted service
# (Type 0x10) that is baked as Type 0x20 never gets a -k group, and Start=3 Manual services are simply
# not started at boot -- both produce exactly the 1062 we see.
$EXP = @{
  wlansvc = @{ Type = '0x10'; Start = '0x2'; Group = 'TDI'; ObjectName = 'LocalSystem' }
  wcmsvc  = @{ Type = '0x10'; Start = '0x2'; Group = 'TDI'; ObjectName = 'NT Authority\LocalService' }
}
foreach ($s in @('wlansvc', 'wcmsvc')) {
  $k = "$SVCRN\$s"
  $ty = RegGet $k 'Type'; $stt = RegGet $k 'Start'; $gp = RegGet $k 'Group'
  $dep = RegGet $k 'DependOnService'; $dp = RegGet $k 'DependOnGroup'; $on = RegGet $k 'ObjectName'
  $ip = RegGet $k 'ImagePath'; $rp = RegGet $k 'RequiredPrivileges'; $sd = RegGet $k 'ServiceSidType'
  $E = $EXP[$s]
  $diff = @()
  foreach ($f in @('Type', 'Start', 'Group', 'ObjectName')) {
    $cur = $(if ($f -eq 'Type') { $ty } elseif ($f -eq 'Start') { $stt } elseif ($f -eq 'Group') { $gp } else { $on })
    if ("$cur" -notmatch ('(?i)' + [regex]::Escape($E[$f]))) { $diff += ($f + '!=' + $E[$f]) }
  }
  O ('  KEY ' + $s + ' Type=' + $(if ($ty) { $ty } else { '-' }) + ' Start=' + $(if ($stt) { $stt } else { '-' }) +
     ' ErrorControl=' + $(if ((RegGet $k 'ErrorControl')) { RegGet $k 'ErrorControl' } else { '-' }) +
     ' Group=' + $(if ($gp) { $gp } else { '-' }) + ' Depend=' + $(if ($dep) { $dep } else { '-' }) +
     ' DependGroup=' + $(if ($dp) { $dp } else { '-' }))
  O ('       ImagePath=' + $(if ($ip) { $ip } else { '-' }))
  O ('       ObjectName=' + $(if ($on) { $on } else { '-' }) + ' SidType=' + $(if ($sd) { $sd } else { '-' }) +
     ' RequiredPrivileges=' + $(if ($rp) { $rp } else { '-' }))
  $kpN = "$SVCRN\$s\Parameters"
  if (Test-Path "$SVCR\$s\Parameters") {
    O ('       Parameters ServiceDll=' + $(if ((RegGet $kpN 'ServiceDll')) { RegGet $kpN 'ServiceDll' } else { '-' }) +
       ' ServiceMain=' + $(if ((RegGet $kpN 'ServiceMain')) { RegGet $kpN 'ServiceMain' } else { '-' }) +
       ' DllUnloadOnStop=' + $(if ((RegGet $kpN 'ServiceDllUnloadOnStop')) { RegGet $kpN 'ServiceDllUnloadOnStop' } else { '-' }))
  } else { O '       Parameters = ABSENT' }
  $sk = @()
  foreach ($sub in @('Security', 'VirtualizationManager', 'Csps', 'TriggerInfo', 'Enum')) {
    if (Test-Path "$SVCR\$s\$sub") { $sk += $sub }
  }
  O ('       subkeys=' + $(if ($sk.Count) { $sk -join ',' } else { '-' }) + '  DIVERGE_FROM_HOST: ' +
     $(if ($diff.Count) { ($diff -join ' ') } else { 'none' }))
}
# svchost group membership is what actually makes -k LocalSystemNetworkRestricted resolve.
# Host-verified location (2026-10-10): HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost has
# 50 values incl. both groups we need; HKLM\SYSTEM\CurrentControlSet\Services\svchost has ZERO values.
# wifi-inject writes into the SOFTWARE one (PE_SYS\Microsoft\Windows NT\CurrentVersion\SVCHOST), which
# is why the previous run printed ABSENT -- it looked in the SYSTEM hive.
O '  SVCHOST groups (SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost = the real table):'
$SGN = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$all = @(& reg.exe query $SGN 2>&1 | ForEach-Object { "$_" })
$nvals = @($all | Where-Object { $_ -match '^\s+\S+\s+REG_' }).Count
O ('    group table values total = ' + $nvals + ' (host live machine = 50)')
foreach ($gn in @('LocalSystemNetworkRestricted', 'LocalServiceNetworkRestricted', 'DcomLaunch', 'netsvcs')) {
  $v = RegGet $SGN $gn
  O ('    svchost\' + $gn + ' = ' + $(if ($v) { $v } else { 'ABSENT -> svchost cannot host it' }))
}

O '== 4 service DLLs present + loadable =='
foreach ($d in @('wlansvc.dll', 'wlanmsm.dll', 'wlanapi.dll', 'wci.dll', 'wcimage.dll', 'dot3api.dll', 'dot3cfg.dll', 'netcore.dll', 'ndisimplatform?')) {
  if ($d -like '*?*' -and -not (Test-Path ("X:\Windows\System32\" + $d))) { O ('  DLL ' + $d + ' = absent (optional)'); continue }
  $p = 'X:\Windows\System32\' + $d
  if (Test-Path $p) { O ('  DLL OK   ' + $d + ' ' + (Get-Item $p).Length + 'B') }
  else { O ('  DLL MISS ' + $d) }
}
try {
  if (-not ('P43.P43L' -as [type])) {
    Add-Type -Namespace P43 -Name P43L -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr LoadLibraryExW(string f, IntPtr h, int flags);
[DllImport("kernel32.dll")] public static extern bool FreeLibrary(IntPtr m);
'@ -EA Stop
  }
  $h = [P43.P43L]::LoadLibraryExW('X:\Windows\System32\wlansvc.dll', [IntPtr]::Zero, 0)
  $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  O ('  LOADLIB wlansvc.dll handle=' + $h + ' err=' + $e)
  if ($h -ne [IntPtr]::Zero) { [void][P43.P43L]::FreeLibrary($h) }
} catch { O ('  LOADLIB failed: ' + $_.Exception.Message) }

O '== 5 StartService through the SCM, with the real error code =='
try {
  if (-not ('P43.P43S' -as [type])) {
    Add-Type -Namespace P43 -Name P43S -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenSCManagerW(string m, string d, int a);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenServiceW(IntPtr s, string n, int a);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool StartServiceW(IntPtr svc, int nArgs, IntPtr args);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool QueryServiceStatus(IntPtr svc, ref SERVICE_STATUS st);
[StructLayout(LayoutKind.Sequential)]
public struct SERVICE_STATUS { public int serviceType; public int currentState;
  public int controlsAccepted; public int win32ExitCode; public int serviceSpecificExitCode;
  public int checkPoint; public int waitHint; }
[DllImport("advapi32.dll", SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr h);
'@ -EA Stop
  }
  # CloseServiceHandle lives in advapi32 (the previous run declared it in kernel32 and the whole
  # block died with "unable to find an entry point" before printing a single lasterr).
  $scm = [P43.P43S]::OpenSCManagerW($null, $null, 0x0001)      # SC_MANAGER_CONNECT
  $sme = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  O ('  SCM handle=' + $scm + ' lasterr=' + $sme + $(if ($scm -eq [IntPtr]::Zero) { ' -> OpenSCManagerW FAILED, everything below is meaningless' } else { '' }))
  if ($scm -ne [IntPtr]::Zero) {
    # dependency order first (starting wlansvc while wcmsvc/nativewifip are down would only ever
    # return 1068 and hide the real answer); SERVICE_START(0x10)|SERVICE_QUERY(0x1)
    foreach ($n in @('DcomLaunch', 'RpcSs', 'Nsi', 'Ndisuio', 'nativewifip', 'wcmsvc', 'wlansvc')) {
      $st = New-Object P43.P43S+SERVICE_STATUS
      $svc = [P43.P43S]::OpenServiceW($scm, $n, 0x0011)
      if ($svc -eq [IntPtr]::Zero) {
        O ('  START ' + $n + ' OpenService rc=0 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() +
           ' (2=ERROR_FILE_NOT_FOUND: no service key at all)')
        continue
      }
      $ok = [P43.P43S]::StartServiceW($svc, 0, [IntPtr]::Zero)
      $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
      $q = [P43.P43S]::QueryServiceStatus($svc, [ref] $st)
      O ('  START ' + $n + ' ok=' + $ok + ' lasterr=' + $le + ' qrc=' + $q + ' state=' + $st.currentState +
         ' win32Exit=' + $st.win32ExitCode + ' specific=0x' + ('{0:X8}' -f $st.serviceSpecificExitCode))
      if ($n -eq 'wlansvc') { $A.startRc = $le; $A.startErr = $le; $A.wl32 = $st.win32ExitCode; $A.spec = $st.serviceSpecificExitCode }
      [void][P43.P43S]::CloseServiceHandle($svc)
    }
    [void][P43.P43S]::CloseServiceHandle($scm)
  }
} catch { O ('  START block failed: ' + $_.Exception.Message) }
Start-Sleep -Seconds 2
try { $A.wlanSvc = "$((Get-Service wlansvc -EA Stop).Status)" } catch { }
O ('  SVCSTATE wlansvc now = ' + $A.wlanSvc)

O '== 6 NetCfg shape: adapter list / FilterList / Control-Network components =='
try {
  $ad = @(Get-CimInstance Win32_NetworkAdapter -EA Stop)
  $A.adapters = $ad.Count
  foreach ($x in $ad) {
    O ('  NADAPTER ' + $x.Name + ' svc=' + $x.ServiceName + ' phys=' + $x.PhysicalAdapter +
       ' guid=' + $x.GUID + ' mac=' + $(if ($x.MACAddress) { $x.MACAddress } else { '-' }) +
       ' netenabled=' + $x.NetEnabled)
  }
  O ('  NADAPTER_TOTAL ' + $ad.Count)
} catch { O ('  NADAPTER query failed: ' + $_.Exception.Message) }
$pci = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
if (Test-Path $pci) {
  foreach ($h in @(Get-ChildItem $pci -EA SilentlyContinue)) {
    foreach ($d in @(Get-ChildItem $h.PSPath -EA SilentlyContinue)) {
      $pp = Get-ItemProperty -LiteralPath $d.PSPath -EA SilentlyContinue
      if ($pp -and "$($pp.Service)" -match '(?i)^netwtw|^netwaw|^rtwlane') {
        $lk = Join-Path $d.PSPath 'Linkage'
        $fl = @()
        if (Test-Path $lk) { $fl = @((Get-ItemProperty $lk -EA SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -match 'FilterList' }) }
        $A.filterlist = $fl.Count
        O ('  DEVNODE ' + $d.PSChildName + ' svc=' + $pp.Service + ' upper=' + (($pp.UpperFilters -join ',')) +
           ' lower=' + (($pp.LowerFilters -join ',')) + ' FilterList_vals=' + $fl.Count)
        foreach ($f in $fl) {
          O ('    FILTERLIST ' + $f.Name + ' = ' + ((@($f.Value) -join ' ;; ')))
        }
      }
    }
  }
}
$clsKey = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
O ('  CLASS UpperFilters=' + $(if ((RegGet $clsKey 'UpperFilters')) { RegGet $clsKey 'UpperFilters' } else { '-' }) +
   ' LowerFilters=' + $(if ((RegGet $clsKey 'LowerFilters')) { RegGet $clsKey 'LowerFilters' } else { '-'}))
$cnPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
if (Test-Path $cnPath) {
  $comps = @(Get-ChildItem $cnPath -EA SilentlyContinue)
  $A.ctrlNet = $comps.Count
  foreach ($c in $comps) {
    $sub = @(Get-ChildItem $c.PSPath -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
    # the component's "name"/"ComponentId"/"Class" values are read with the provider (Get-ItemProperty),
    # not reg.exe -- reg.exe needs the backslash form and PSChildName/PSPath here are already provider paths.
    $cp = Get-ItemProperty -LiteralPath $c.PSPath -EA SilentlyContinue
    $nm = "$($cp.name)"
    if (-not $nm) { $nm = "$($cp.ComponentId)" }
    O ('  CTRLNET ' + $c.PSChildName + ' name=' + $(if ($nm) { $nm } else { '-' }) +
       ' drv=' + $(if ("$($cp.Driver)") { $cp.Driver } else { '-' }) + ' instances=' + ($sub -join ','))
  }
  O ('  CTRLNET_TOTAL ' + $comps.Count + ' (offline reference machine had 19)')
} else { O '  CTRLNET = absent' }

O '== 7 loaded state of the WiFi driver stack =='
foreach ($s in @('wdiwifi', 'NdisImPlatform', 'vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'Netwtw14', 'Ndisuio')) {
  try {
    $d = @(Get-CimInstance Win32_SystemDriver -EA Stop | Where-Object { $_.Name -eq $s })
    if ($d.Count -gt 0) { O ('  LSDRV ' + $s + ' state=' + $d[0].State + ' startmode=' + $d[0].StartMode + ' path=' + $d[0].PathName) }
    else { O ('  LSDRV ' + $s + ' not listed') }
  } catch { O ('  LSDRV ' + $s + ' query failed') }
}

O '== 8 WlanOpenHandle =='
try {
  if (-not ('P43.P43W' -as [type])) {
    Add-Type -Namespace P43 -Name P43W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  }
  $nv = 0; $h = [IntPtr]::Zero
  $A.wlanOpen = [P43.P43W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
  O ('  WLANOPEN rc=' + $A.wlanOpen + ' newVer=' + $nv)
  if ($A.wlanOpen -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P43.P43W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('  WLANOPEN call failed: ' + $_.Exception.Message) }

O '== 9 VERDICT =='
O ('P43 VERDICT paramkey=' + $A.paramkey + '/2 start_wlansvc=' + $A.startErr + ' wl32exit=' + $A.wl32 +
   ' specific=0x' + ('{0:X8}' -f [int]$A.spec) + ' wlansvc=' + $A.wlanSvc +
   ' wlanopen=' + $A.wlanOpen + ' nadapters=' + $A.adapters + ' filterlist_vals=' + $A.filterlist +
   ' ctrlnet_comps=' + $A.ctrlNet)
if ($A.wlanOpen -eq 0) { O 'P43 READING: PASS - wlansvc live, WiFi API answers. Next: connect UX.' }
elseif ($A.startErr -eq 1053) { O 'P43 READING: 1053 = service did not respond in time -> svchost loaded the DLL but WlanSvcMain never signalled; suspect missing RPC/ncacn endpoint or a import wlansvc.dll needs.' }
elseif ($A.startErr -eq 1068) { O 'P43 READING: 1068 = dependency not running -> read section 2, fix that dependency (RpcSs/Netman), not the driver.' }
elseif ($A.startErr -eq 5)    { O 'P43 READING: 5 ERROR_ACCESS_DENIED -> the SCM handle or the service DACL (Security subkey) is wrong, not the WiFi stack.' }
elseif ($A.startErr -eq 2)    { O 'P43 READING: 2 ERROR_FILE_NOT_FOUND -> ImagePath target missing (svchost.exe) or service key absent.' }
elseif ($A.startErr -eq 42018 -or $A.startErr -eq 0x800C0006) { O 'P43 READING: WLAN_E_* from the service itself -> wlansvc started but rejected the environment; check nativewifip/vwifibus attached (section 6/7).' }
elseif ($A.startErr -eq 0) { O 'P43 READING: StartService returned success but WlanOpenHandle still fails -> RPC/rpcss endpoint issue inside wlansvc.' }
else { O ('P43 READING: wlansvc start failed with lasterr=' + $A.startErr + ' - look up that Win32 code against section 2/3/4 above.') }
O 'P43 END'
