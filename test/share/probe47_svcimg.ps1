# ============================================================
# probe47_svcimg.ps1 -- why does wlansvc die in 2s and wcmsvc return 1068? Copy the ImagePath shape of
# the services this PE actually runs, and read the System event log for the SCM's own reason.
#
# What probe46 settled (live on the 12th-gen laptop, 2026-10-10 bake):
#   SvcHostSvc.exe ABSENT and no ServiceHostingService key -> this build never uses the service-hosting
#        framework, which is why aligning to the host's Type=0x10 was a dead end.
#   Every svchost-hosted service in the image is Type=0x20 with a -k group ImagePath, and they run:
#        RpcSs/NSI/Dhcp/LmHosts/EventLog/hidserv Running; and after we switched wlansvc/wcmsvc to
#        Type=0x20, the CONTROL services Netman and dot3svc (same group, same ObjectName class) both
#        went Stopped -> Running from a single Start(). So the svchost machinery itself is fine.
#   wlansvc now behaves differently than before: Start() raised NO error (code=-1), the service went
#        StartPending and came back Stopped within ~2s. That is the SCM dispatching svchost and the
#        service failing on its own -- no longer an SCM refusal.
#   wcmsvc still returns 1068 in every dependency variant including "no DependOnService at all".
#   Both ServiceMain exports are really there (WlanSvcMain=True WcmSvcMain=True).
# => The remaining difference has to be in the key shape we baked: ImagePath (does this build's own
#    Type=0x20 convention need `-s <service>`?) and the svchost group table. probe47 mirrors a service
#    that demonstrably starts here, and asks the event log what the SCM thinks went wrong.
#
# Writes: HKLM\SYSTEM\CurrentControlSet\Services\{wlansvc,wcmsvc}(+Parameters) + start attempts, all on
#         the RAMDISK. Nothing else. X: evaporates on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe47_svcimg.ps1 -RemotePath X:/p47.ps1 -StagingB64 X:/p47.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# LogLine buffers output produced inside a function that ALSO returns a value. FlushLog must be called
# as its own statement -- [void](FlushLog) or $(FlushLog) would capture the success stream and throw the
# lines away. Short helper names are dangerous here: aliases beat functions ('oh' = Out-Host).
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }

$REG  = 'HKLM\SYSTEM\CurrentControlSet\Services'
$SVCH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost'
$P = @{ img = @(); openEnd = -1; ifaces = -1; wl = 'n/a'; wc = 'n/a' }

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
  # PE is an English build, so reg.exe messages are ASCII; keep this file ASCII-only (no CJK here).
  $err = (@($out | Where-Object { $_ -match '(?i)error' }) | Select-Object -First 1)
  O ('    set ' + ($key -split '\\')[-1] + '\' + $name + ' = ' + $data + ' rc=' + $LASTEXITCODE + $(if ($err) { ' ' + $err } else { '' }))
}
function RegDel([string]$key, [string]$name) {
  [void](& reg.exe delete "$key" /f /v $name 2>&1)
  O ('    del ' + ($key -split '\\')[-1] + '\' + $name + ' rc=' + $LASTEXITCODE)
}
function St([string]$n)  { try { "$((Get-Service -Name $n -EA Stop).Status)" }    catch { 'ABSENT' } }
function Expand([string]$p) {
  if (-not $p) { return '' }
  $r = $p -replace '(?i)^%SystemRoot%', 'X:\Windows' -replace '(?i)^%systemroot%', 'X:\Windows'
  return $r
}
function SvchostProcs() {
  try { return @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA Stop) } catch { return @() }
}
function SvchostSig([string]$tag) {
  $p = SvchostProcs
  # parenthesise before -join: 'a' + ($x -join ',') -replace ... chains the operators over the whole
  # expression and silently produces one mashed line (bit us in q_host_wlansvc.ps1).
  $sNames = ((@($p | ForEach-Object { if ("$($_.CommandLine)" -match '-s\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
  $groups   = ((@($p | ForEach-Object { if ("$($_.CommandLine)" -match '-k\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
  LogLine ('      [' + $tag + '] svchost procs=' + $p.Count + ' -s=' + (ToAscii $sNames) + ' groups=' + (ToAscii $groups))
}
function EventTail([string]$tag, [int]$n) {
  try {
    $all = @(Get-WinEvent -LogName System -MaxEvents 400 -EA Stop)
    LogLine ('      [' + $tag + '] System log readable, events pulled=' + $all.Count)
    $ev = @($all | Where-Object { "$($_.ProviderName)" -match '(?i)Service Control Manager|WLAN|wlansvc|wcmsvc|AutoConfig' } | Select-Object -First $n)
    foreach ($e in $ev) {
      $m = ''
      try { $m = ("$($e.Message)" -replace '\s+', ' ') } catch { $m = '(no message)' }
      # the loop variable is $e -- a stray $_ here is empty (foreach does not populate $ automatic)
      LogLine ('      EV ' + $e.TimeCreated.ToString('HH:mm:ss') + ' id=' + $e.Id + ' lvl=' + $e.Level +
               ' prov=' + (ToAscii $e.ProviderName) + ' | ' + (ToAscii $m))
    }
    if (-not $ev.Count) { LogLine ('      [' + $tag + '] no matching System events yet') }
  } catch {
    LogLine ('      [' + $tag + '] Get-WinEvent failed: ' + (ToAscii $_.Exception.Message))
    try {
      $g = @(Get-EventLog -LogName System -Newest 60 -EA Stop |
             Where-Object { $_.Source -match '(?i)Service Control|WLAN' } | Select-Object -First $n)
      foreach ($e in $g) { LogLine ('      EV2 ' + $e.TimeGenerated.ToString('HH:mm:ss') + ' id=' + $e.EventId + ' src=' + $e.Source + ' | ' + (ToAscii ($e.Message -replace '\s+', ' '))) }
      LogLine ('      [' + $tag + '] Get-EventLog rows=' + $g.Count)
    } catch { LogLine ('      [' + $tag + '] Get-EventLog failed too: ' + (ToAscii $_.Exception.Message)) }
  }
}
function TryStart([string]$n) {
  $code = -1
  try {
    $c = New-Object System.ServiceProcess.ServiceController($n)
    $c.Start()
  } catch {
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
if (-not ('P47.P47W' -as [type])) {
  Add-Type -Namespace P47 -Name P47W -MemberDefinition @'
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
    $rc = [P47.P47W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $h)
    LogLine ('      WLANOPEN[' + $tag + '] rc=' + $rc + ' newVer=' + $nv)
    $n = -1
    if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) {
      $lst = [IntPtr]::Zero
      $erc = [P47.P47W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref] $lst)
      if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
        $names = [P47.P47W]::IfaceNames($lst)
        $n = $names.Count
        foreach ($x in $names) { LogLine ('        IFACE ' + $x) }
        [void][P47.P47W]::WlanFreeMemory($lst)
      }
      LogLine ('      ENUMIF rc=' + $erc + ' items=' + $n)
      [void][P47.P47W]::WlanCloseHandle($h, [IntPtr]::Zero)
    }
    $P.ifaces = $n
    return $rc
  } catch { LogLine ('      WLAN call failed: ' + (ToAscii $_.Exception.Message)); return -2 }
}

O '== 0 the key shape of services that DO start here vs the two that do not =='
foreach ($n in @('RpcSs', 'NSI', 'Dhcp', 'LmHosts', 'EventLog', 'hidserv', 'Netman', 'dot3svc', 'wlansvc', 'wcmsvc')) {
  $dll = Expand (RegGet "$REG\$n\Parameters" 'ServiceDll')
  $img = RegGet "$REG\$n" 'ImagePath'
  O ('  SVC ' + $n + ' Type=' + (RegGet "$REG\$n" 'Type') + ' Start=' + (RegGet "$REG\$n" 'Start') +
     ' Obj=' + (RegGet "$REG\$n" 'ObjectName') + ' Group=' + (RegGet "$REG\$n" 'Group') +
     ' deps=' + (RegGet "$REG\$n" 'DependOnService') + ' status=' + (St $n))
  O ('      IMG ' + $(if ($img) { $img } else { '(absent)' }))
  O ('      DLL ' + $(if ($dll) { $dll + ' exists=' + (Test-Path $dll) } else { '(absent)' }) +
     ' Main=' + (RegGet "$REG\$n\Parameters" 'ServiceMain') +
     ' unloadOnStop=' + (RegGet "$REG\$n\Parameters" 'ServiceDllUnloadOnStop'))
  O ('      PRIV ' + (RegGet "$REG\$n" 'RequiredPrivileges'))
}

O '== 1 the svchost group table this build reads (SOFTWARE side) =='
try {
  $it = Get-Item -LiteralPath $SVCH -EA Stop
  foreach ($nm in @($it.GetValueNames())) {
    $vals = (@($it.GetValue($nm)) -join ',')
    $who = @($vals -split '[ ,]+' | Where-Object { $_ } | ForEach-Object { $nm2 = $_; $st = (St $nm2); if ($st -ne 'ABSENT') { ($nm2 + ':' + $st) } })
    O ('  GROUP ' + $nm + ' = ' + $vals + '   [' + ($who -join ' ') + ']')
  }
} catch { O ('  svchost table read failed: ' + $_.Exception.Message) }

O '== 2 event log right now (baseline before we touch anything) =='
EventTail 'baseline' 12; FlushLog

O '== 3 wlansvc: ImagePath mirrored from a service that starts on this build =='
# Netman and dot3svc both went Running from one Start() in probe46, with ObjectName=LocalSystem like
# wlansvc. Copy THEIR suffix convention (-p / -s) instead of guessing.
$netImg = RegGet "$REG\Netman" 'ImagePath'
$dhcpImg = RegGet "$REG\Dhcp" 'ImagePath'
O ('  model netman IMG = ' + $(if ($netImg) { $netImg } else { '(absent)' }))
O ('  model dhcp   IMG = ' + $(if ($dhcpImg) { $dhcpImg } else { '(absent)' }))
function ShapeImg([string]$model, [string]$grp, [string]$svc) {
  $hasP = ($model -match '(?i)\s-p(\s|$)')
  $hasS = ($model -match '(?i)-s\s+\S+')
  $exe = 'X:\Windows\System32\svchost.exe'
  if ($model -match '(?i)^(.*?)svchost\.exe') { $exe = $matches[1] + 'svchost.exe' }
  $r = $exe + ' -k ' + $grp
  if ($hasP) { $r += ' -p' }
  if ($hasS) { $r += ' -s ' + $svc }
  return $r
}
RegSet "$REG\wlansvc" 'Type'  'REG_DWORD' '0x20'
RegSet "$REG\wcmsvc"  'Type'  'REG_DWORD' '0x20'
RegSet "$REG\wlansvc" 'Start' 'REG_DWORD' '0x2'
RegSet "$REG\wcmsvc"  'Start' 'REG_DWORD' '0x2'
RegDel "$REG\wlansvc" 'DependOnService'
RegDel "$REG\wcmsvc"  'DependOnService'

$c = TryStart 'wlansvc'; FlushLog; $P.wl = "asis=$c"
O ('  wlansvc as baked (Type 0x20, no deps) -> ' + $c + ' state=' + (St 'wlansvc'))
$img1 = ShapeImg $netImg 'LocalSystemNetworkRestricted' 'wlansvc'
O ('  candidate 1 (model shape, own group): ' + $img1)
RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' $img1
$c = TryStart 'wlansvc'; FlushLog; EventTail 'wl-c1' 10; FlushLog; $P.wl += " img1=$c"
O ('  -> code=' + $c + ' state=' + (St 'wlansvc'))
$img2 = ShapeImg $netImg 'LocalSystemNetworkRestricted' 'wlansvc'
if ($netImg -notmatch '(?i)-s\s+\S+') {
  $img2 = $img2 + ' -s wlansvc'
  O ('  candidate 2 (+ explicit -s): ' + $img2)
  RegSet "$REG\wlansvc" 'ImagePath' 'REG_EXPAND_SZ' $img2
  $c = TryStart 'wlansvc'; FlushLog; EventTail 'wl-c2' 10; FlushLog; $P.wl += " img2=$c"
  O ('  -> code=' + $c + ' state=' + (St 'wlansvc'))
} else { O '  candidate 2 skipped: the model already uses -s' }

O '== 4 wcmsvc: same mirror, LocalService side (Dhcp runs as LocalService here) =='
$img3 = ShapeImg $dhcpImg 'LocalServiceNetworkRestricted' 'wcmsvc'
O ('  candidate (model shape): ' + $img3)
RegSet "$REG\wcmsvc" 'ImagePath' 'REG_EXPAND_SZ' $img3
RegSet "$REG\wcmsvc" 'ObjectName' 'REG_SZ' 'NT Authority\LocalService'
RegSet "$REG\wcmsvc" 'RequiredPrivileges' 'REG_MULTI_SZ' 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeCreateGlobalPrivilege'
$c = TryStart 'wcmsvc'; FlushLog; EventTail 'wc-c1' 10; FlushLog; $P.wc = "img1=$c"
O ('  -> code=' + $c + ' state=' + (St 'wcmsvc'))
$img4 = RegGet "$REG\Dhcp" 'ImagePath'
if ($img4 -match '(?i)-s\s+\S+') {
  RegSet "$REG\wcmsvc" 'ImagePath' 'REG_EXPAND_SZ' ($img4 -replace '(?i)-s\s+\S+', '-s wcmsvc')
  O ('  candidate (DHCP IMG verbatim, -s wcmsvc): ' + (RegGet "$REG\wcmsvc" 'ImagePath'))
  $c = TryStart 'wcmsvc'; FlushLog; EventTail 'wc-c2' 10; FlushLog; $P.wc += " img2=$c"
  O ('  -> code=' + $c + ' state=' + (St 'wcmsvc'))
} else {
  O ('  candidate skipped: DHCP has no -s in its IMG (' + $img4 + '), a plain group host would collide with the running Dhcp')
}

O '== 5 final state and wlanapi =='
O ('  wlansvc status=' + (St 'wlansvc') + ' wcmsvc status=' + (St 'wcmsvc') +
   ' netman=' + (St 'netman') + ' dot3svc=' + (St 'dot3svc'))
SvchostSig 'final'; FlushLog
$P.openEnd = WlanOpen 'final'; FlushLog
EventTail 'final' 14; FlushLog

O '== 6 VERDICT =='
O ('P47 VERDICT netmanImg=[' + $netImg + '] dhcpImg=[' + $dhcpImg + '] wl=' + $P.wl +
   ' wc=' + $P.wc + ' wlState=' + (St 'wlansvc') + ' wcState=' + (St 'wcmsvc') +
   ' wlanopen=' + $P.openEnd + ' ifaces=' + $P.ifaces)
if ($P.openEnd -eq 0) { O 'P47 READING: wlansvc is UP -> the missing piece was the key shape, record which candidate worked and bake exactly that.' }
elseif ($P.wl -match 'img1=0|img2=0') { O 'P47 READING: wlansvc started (wlanapi still blocked) -> wcmsvc/driver side is next; the ImagePath candidate is the fix.' }
elseif ($P.wl -match 'asis=-1') { O 'P47 READING: wlansvc still dies ~2s after dispatch with no SCM error -> read the EV lines above; the cause is inside ServiceMain (dll/privileges/deps at runtime), not the key shape.' }
elseif ($P.wc -match '1068') { O 'P47 READING: wcmsvc 1068 even with the ImagePath of a service that runs -> the SCM resolves something else for wcmsvc; compare its EV lines with DHCP.' }
else { O 'P47 READING: see EV lines; the event log carries the SCM error the Start() path hides.' }
O 'P47 END'
