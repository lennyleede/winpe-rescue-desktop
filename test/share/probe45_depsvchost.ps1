# ============================================================
# probe45_depsvchost.ps1 -- localise the 1068, and find out whether the SCM sees live key edits.
#
# What probe42/43/44 established on the 12th-gen laptop (boot of the 2026-10-10 15:21 bake):
#   DRIVER HALF IS FIXED : wdiwifi + Netwtw14 Running, AX211 code 0, real adapter + MAC.
#   SERVICE HALF IS NOT  : WlanOpenHandle = 1062 (ERROR_SERVICE_NOT_ACTIVE), wlansvc Stopped.
#   probe44 wrote the host authority shape onto the live ramdisk hive and retried:
#     wcmsvc -> ServiceController.Start() threw NativeErrorCode 1068
#               (ERROR_DEPENDENT_SERVICES_RUNNING -- one of its dependencies could not be started),
#               even though RpcSs and NSI are both Running.
#     wlansvc -> no synchronous error (async dispatch), state went back to Stopped.
#   sc.exe and whoami.exe are NOT in this image, so the SCM's own view comes from Get-Service (which
#   reads through the SCM, not the hive) and from the real svchost command lines (Win32_Process shows
#   which -k group actually got launched -- that doubles as the cache probe).
#
# Questions, in order, each step restoring what it changed:
#   Q1 Does the SCM see the Start=0x2 (auto) that probe44 wrote, or is it serving the boot-time cache?
#   Q2 Which dependency of wcmsvc produces the 1068? (peel them off one at a time)
#   Q3 Is svchost launched for those groups at all, and with what group name?
#   Q4 Does a private one-service svchost group change anything?
#   Q5 If wlansvc comes up: does WlanOpenHandle answer and WlanEnumInterfaces list the AX211?
#
# Writes: HKLM\SYSTEM\CurrentControlSet\Services\{wlansvc,wcmsvc}(+Parameters),
#         HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost (one new group value),
#         plus service START attempts. All on the RAMDISK; X: evaporates on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe45_depsvchost.ps1 -RemotePath X:/p45.ps1 -StagingB64 X:/p45.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
// LogLine buffers the output of functions that ALSO return a value: Write-Output would join the
// return value, and the previous helper was named OH -- which is a built-in alias of Out-Host, and
// command-name resolution puts aliases above functions, so every log call became a cmdlet invocation
// that died with a positional-parameter error. Buffer, then flush at statement level.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { foreach ($l in @($script:LOG)) { Write-Output $l }; $script:LOG.Clear() }
$REG  = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SVCH = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$SVCP = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$R = @{ q1 = 'unknown'; wcDeps = @(); wlDeps = @(); openBase = -1; openEnd = -1; ifaces = -1 }

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
  $err = @($out | Where-Object { $_ -match '(?i)error' }) | Select-Object -First 1
  O ('    set ' + ($key -split '\\')[-1] + '\' + $name + ' = ' + $data + ' rc=' + $LASTEXITCODE + $(if ($err) { ' ' + $err } else { '' }))
}
function RegDel([string]$key, [string]$name) {
  $out = @(& reg.exe delete "$key" /f /v $name 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  $err = @($out | Where-Object { $_ -match '(?i)error' }) | Select-Object -First 1
  O ('    del ' + ($key -split '\\')[-1] + '\' + $name + ' rc=' + $LASTEXITCODE + $(if ($err) { ' ' + $err } else { '' }))
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function Sty([string]$n) { try { "$((Get-Service -Name $n -EA Stop).StartType)" } catch { 'ABSENT' } }

# Start a service and return the authoritative Win32 code. Start() is async: pre-dispatch failures
# (1068/1069/5) throw synchronously; a dispatch that never completes only shows up as the final state,
# so -1 here means "no code was reported and it is not Running" (= svchost never called ServiceMain).
function TryStart([string]$n) {
  $code = -1
  try {
    $c = New-Object System.ServiceProcess.ServiceController($n)
    $c.Start()
  } catch {
    $ie = $_.Exception
    while ($ie -and -not ($ie -is [System.ComponentModel.Win32Exception])) { $ie = $ie.InnerException }
    if ($ie) { $code = $ie.NativeErrorCode }
    else { LogLine ('    ' + $n + ' ex: ' + ($_.Exception.Message -replace '\s+', ' ')) }
  }
  $w = 0; $s = St $n
  while ($w -lt 12 -and ($s -eq 'StartPending' -or $s -eq 'StopPending')) {
    Start-Sleep -Seconds 2; $w += 2; $s = St $n
  }
  LogLine ('    TRYSTART ' + $n + ' code=' + $code + ' state=' + $s + ' wait=' + $w + 's')
  if ($code -lt 0 -and $s -eq 'Running') { $code = 0 }
  return $code
}
function SvchostLines([string]$tag) {
  $p = @()
  try { $p = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA Stop) } catch { }
  $g = @($p | ForEach-Object { if ("$($_.CommandLine)" -match '-k\s+(\S+)') { $matches[1] } else { '?' } })
  O ('  SVCHOST[' + $tag + '] procs=' + $p.Count + ' groups=' + (($g | Sort-Object -Unique) -join ','))
}

# WlanEnumInterfaces needs the real WLAN_INTERFACE_INFO layout: GUID(16) + WCHAR[256](512) + state(4)
# = 532 bytes per item, first item at offset 8 of the list (two DWORD counts before it).
if (-not ('P45.P45W' -as [type])) {
  # No `using` directives here: Add-Type -MemberDefinition pastes the body INSIDE a generated class,
  # where using-statements are illegal. Everything is fully qualified instead.
  Add-Type -Namespace P45 -Name P45W -MemberDefinition @'
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
    r[i] = info.description + "|state=" + info.state + "|guid=" + info.interfaceGuid + "|stride=" + stride;
  }
  return r;
}
'@ -EA Stop
}
function WlanOpen([string]$tag) {
  try {
    $nv = 0; $h = [IntPtr]::Zero
    $rc = [P45.P45W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
    LogLine ('  WLANOPEN[' + $tag + '] rc=' + $rc + ' newVer=' + $nv)
    $n = -1
    if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P45.P45W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref] $lst)
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
        $names = [P45.P45W]::IfaceNames($lst)
        $n = $names.Count
        LogLine ('    ENUMIF rc=0 items=' + $n)
        foreach ($x in $names) { LogLine ('      IFACE ' + $x) }
        [void][P45.P45W]::WlanFreeMemory($lst)
      } else { LogLine ('    ENUMIF rc=' + $erc) }
      [void][P45.P45W]::WlanCloseHandle($h, [IntPtr]::Zero)
    }
    $R.ifaces = $n
    return $rc
  } catch { LogLine ('    WLAN call failed: ' + $_.Exception.Message); return -2 }
}

O '== 0 starting state (probe44 already wrote the host authority shape into the live hive) =='
foreach ($n in @('wlansvc', 'wcmsvc')) {
  O ('  ' + $n + ' REG: Type=' + (RegGet "$REG\$n" 'Type') + ' Start=' + (RegGet "$REG\$n" 'Start') +
     ' Group=' + (RegGet "$REG\$n" 'Group') + ' Obj=' + (RegGet "$REG\$n" 'ObjectName') +
     ' Depend=' + (RegGet "$REG\$n" 'DependOnService'))
  O ('       ' + $n + ' IMG: ' + (RegGet "$REG\$n" 'ImagePath'))
  O ('       ' + $n + ' SCM: Status=' + (St $n) + ' StartType=' + (Sty $n))
}
# Q1: probe44 set Start=0x2 (Automatic). If Get-Service still says Manual, the SCM is serving the
# boot-time cache and no live write can validate -> the only proof path is bake + reboot.
$R.q1 = $(if ((Sty 'wlansvc') -eq 'Automatic') { 'SCM_SEES_LIVE_EDITS' } elseif ((Sty 'wlansvc') -eq 'Manual') { 'SCM_CACHE_STALE' } else { 'unknown' })
O ('  Q1 = ' + $R.q1)
SvchostLines 'boot'

O '== 1 svchost group tables + member health (a poisoned group member kills every service in it) =='
$gq = @(& reg.exe query $SVCH 2>&1 | ForEach-Object { "$_" })
O ('  group table values = ' + @($gq | Where-Object { $_ -match '^\s+\S+\s+REG_' }).Count + ' (host live machine = 50)')
foreach ($g in @('LocalSystemNetworkRestricted', 'LocalServiceNetworkRestricted')) {
  $members = @((((RegGet $SVCH $g) -replace '\\0', ';') -split ';' | Where-Object { $_.Trim() -ne '' }) | ForEach-Object { $_.Trim() })
  O ('  GROUP ' + $g + ' members=' + ($members -join ','))
  foreach ($m in $members) {
    $dll = RegGet "$REG\$m\Parameters" 'ServiceDll'
    $disk = 'n/a'
    if ($dll) { $disk = $(if (Test-Path ($dll -replace '%SystemRoot%', 'X:\Windows')) { 'yes' } else { 'MISSING' }) }
    O ('    MEMBER ' + $m + ' key=' + (Test-Path "$SVCP\$m") + ' status=' + (St $m) + ' start=' +
       (RegGet "$REG\$m" 'Start') + ' type=' + (RegGet "$REG\$m" 'Type') + ' dll=' + $(if ($dll) { $dll } else { '-' }) +
       ' dllOnDisk=' + $disk)
  }
}

O '== 2 dependency chain, two levels deep =='
foreach ($n in @('wlansvc', 'wcmsvc', 'nativewifip', 'Ndisuio', 'NSI', 'RpcSs', 'netprofm')) {
  $dep = ((RegGet "$REG\$n" 'DependOnService') -replace '\\0', ',')
  $dg  = ((RegGet "$REG\$n" 'DependOnGroup') -replace '\\0', ',')
  O ('  DEP ' + $n + ' key=' + (Test-Path "$SVCP\$n") + ' start=' + (RegGet "$REG\$n" 'Start') +
     ' type=' + (RegGet "$REG\$n" 'Type') + ' status=' + (St $n) + ' depend=' + $(if ($dep) { $dep } else { '-' }) +
     ' dependGroup=' + $(if ($dg) { $dg } else { '-' }))
  foreach ($d in @($dep -split ',' | Where-Object { $_ -ne '' })) {
    O ('      ' + $n + ' -> ' + $d + ' key=' + (Test-Path "$SVCP\$d") + ' status=' + (St $d) +
       ' start=' + (RegGet "$REG\$d" 'Start') + ' img=' + $(if ((RegGet "$REG\$d" 'ImagePath')) { RegGet "$REG\$d" 'ImagePath' } else { '-' }))
  }
}
O ('  EXTRA nsiproxy=' + (St 'nsiproxy') + ' TcpIp=' + (St 'TcpIp') + ' Afd=' + (St 'Afd') +
   ' PSched=' + (St 'PSched') + ' BFE=' + (St 'BFE') + ' mpssvc=' + (St 'mpssvc') + ' Eaphost=' + (St 'Eaphost') +
   ' Dhcp=' + (St 'Dhcp') + ' EventLog=' + (St 'EventLog'))

O '== 3 Q2: peel wcmsvc dependencies off one at a time (which one is the 1068?) =='
$origWc = ((RegGet "$REG\wcmsvc" 'DependOnService') -replace '\\0', '/')
O ('  saved wcmsvc depend = ' + $(if ($origWc) { $origWc } else { '-' }))
O '  step a: DependOnService removed'
RegDel "$REG\wcmsvc" 'DependOnService'
$R.wcDeps += 'none=' + (TryStart 'wcmsvc'); [void](FlushLog)
SvchostLines 'wc-nodeps'
$R.openBase = WlanOpen 'after-wc-nodeps'; [void](FlushLog)
O '  step b: depend = RpcSs'
RegSet "$REG\wcmsvc" 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'
$R.wcDeps += 'rpcss=' + (TryStart 'wcmsvc'); [void](FlushLog)
O '  step c: depend = RpcSs + NSI (host shape)'
RegSet "$REG\wcmsvc" 'DependOnService' 'REG_MULTI_SZ' 'RpcSs\0NSI'
$R.wcDeps += 'rpcss+nsi=' + (TryStart 'wcmsvc'); [void](FlushLog)
if ($origWc) { RegSet "$REG\wcmsvc" 'DependOnService' 'REG_MULTI_SZ' ($origWc -replace '/', '\0') }

O '== 4 Q2/Q4: wlansvc, dependency set then a private svchost group =='
$origWl = ((RegGet "$REG\wlansvc" 'DependOnService') -replace '\\0', '/')
$origImg = (RegGet "$REG\wlansvc" 'ImagePath')
O ('  saved wlansvc depend = ' + $(if ($origWl) { $origWl } else { '-' }) + '  ImagePath = ' + $origImg)
O '  step a: depend = RpcSs only (pre-authority shape, which also failed)'
RegSet "$REG\wlansvc" 'DependOnService' 'REG_MULTI_SZ' 'RpcSs'
$R.wlDeps += 'rpcss=' + (TryStart 'wlansvc'); [void](FlushLog)
SvchostLines 'wl-rpcss'
O '  step b: no DependOnService at all'
RegDel "$REG\wlansvc" 'DependOnService'
$R.wlDeps += 'nodeps=' + (TryStart 'wlansvc'); [void](FlushLog)
SvchostLines 'wl-nodeps'
O '  step c: private svchost group containing ONLY wlansvc'
RegSet $SVCH 'wlansvcs' 'REG_MULTI_SZ' 'wlansvc'
RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' '%SystemRoot%\System32\svchost.exe -k wlansvcs -p'
$R.wlDeps += 'privgrp=' + (TryStart 'wlansvc'); [void](FlushLog)
SvchostLines 'wl-privgrp'
$R.openEnd = WlanOpen 'after-wl-privgrp'; [void](FlushLog)
O '  step d: restore ImagePath + saved dependency list'
if ($origImg) { RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' $origImg }
if ($origWl) { RegSet "$REG\wlansvc" 'DependOnService' 'REG_MULTI_SZ' ($origWl -replace '/', '\0') }

O '== 5 VERDICT =='
O ('P45 VERDICT q1=' + $R.q1 + ' wcmsvc=' + ($R.wcDeps -join ' ') + ' wlansvc=' + ($R.wlDeps -join ' ') +
   ' wlanopen=' + $R.openBase + '/' + $R.openEnd + ' ifaces=' + $R.ifaces)
if ($R.openEnd -eq 0) { O 'P45 READING: wlansvc ran live. Whatever step it happened in is the shape wifi-inject must bake, then reboot to confirm.' }
elseif ($R.q1 -eq 'SCM_CACHE_STALE') { O 'P45 READING: the SCM kept the boot-time config, so these live edits cannot settle Type/Start -- bake them and reboot.' }
elseif ($R.wcDeps -join ' ' -match 'none=1053|rpcss=1053') { O 'P45 READING: 1053 = svchost launched but no ServiceMain signal -> group/DLL problem, not a dependency problem.' }
elseif ($R.wcDeps -join ' ' -match 'none=0') { O 'P45 READING: wcmsvc runs with NO dependencies -> one of RpcSs/NSI is what the SCM cannot start in PE; keep wcmsvc dependency-free in the bake.' }
else { O 'P45 READING: still failing -> compare section 1 group-member health and section 2 dep chain against the codes above.' }
O 'P45 END'
