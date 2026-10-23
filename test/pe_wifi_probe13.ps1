# probe13: probe12 killed two theories with one blow -- five untouched services (defragsvc,
# DiagTrack, wersvc, swprv, PolicyAgent) all started successfully into BRAND NEW svchost hosts,
# so runtime host creation is fine in this PE; and the recovered texts show the two failures are
# DIFFERENT errors (dot3svc in a fresh group = 1067 process terminated unexpectedly, wlansvc in
# the existing healthy host = 6). Same host, same group, same -p: dot3svc.dll loads, wlansvc.dll
# yields 6. The DLL itself LoadLibrary's cleanly and WlanSvcMain is exported, so the suspicion is
# now WlanSvcMain running and reporting 6 itself.
# probe12 also swallowed the -d evidence ($o = DebugRun captured the function's own Log output),
# so Log now writes straight to the console stream and -d runs are kept ALIVE for a second test:
# if svchost -d can host wlansvc, WlanOpenHandle from another process should return 0 -- that is
# both a diagnosis and a possible rescue-day workaround.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n)  { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s)  { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c)  { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}
$SVCH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC  = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$GRP  = 'LocalSystemNetworkRestricted'

Sec '0_CHILD_HARNESS'
# WlanOpenHandle runs in a CHILD so a crash cannot eat this log.
$child = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class WL13 {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int v, IntPtr r, out int neg, out IntPtr h);
  [DllImport("wlanapi.dll")] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr p);
  [DllImport("wlanapi.dll")] public static extern int WlanQueryInterface(IntPtr h, ref Guid id, int code, IntPtr r, out IntPtr d, out int sz);
  [DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr p);
  [DllImport("wlanapi.dll")] public static extern int WlanCloseHandle(IntPtr h, IntPtr r);
}
"@
Add-Type -TypeDefinition $src
$h = [IntPtr]::Zero; $neg = 0
$rc = [WL13]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$neg, [ref]$h)
Write-Output ("  WlanOpenHandle rc=" + $rc + " negotiated=" + $neg)
if ($rc -eq 0) {
  $p = [IntPtr]::Zero
  $rc2 = [WL13]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$p)
  Write-Output ("  WlanEnumInterfaces rc=" + $rc2)
  if ($rc2 -eq 0 -and $p -ne [IntPtr]::Zero) {
    # DOT11_INTERFACE_LIST starts with the interface count (DWORD)
    $buf = New-Object byte[] 4
    [Runtime.InteropServices.Marshal]::Copy($p, $buf, 0, 4)
    Write-Output ("  interface count=" + [BitConverter]::ToUInt32($buf, 0))
    [WL13]::WlanFreeMemory($p)
  }
  [void][WL13]::WlanCloseHandle($h, [IntPtr]::Zero)
}
'@
Set-Content -LiteralPath 'X:\wl13.ps1' -Value $child -Encoding ASCII

Sec '1_SVCHOST_DEBUG_WLANSVC_KEPT_ALIVE'
$G2 = 'peWlanGrp'
Set-ItemProperty -LiteralPath $SVCH -Name $G2 -Value @('wlansvc') -Type MultiString
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G2 + ' -p') -Type ExpandString
$of = 'X:\dbg_wlan.out'
del $of -ErrorAction SilentlyContinue
$p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('X:\windows\System32\svchost.exe -k ' + $G2 + ' -d -s wlansvc > ' + $of + ' 2>&1') -PassThru -NoNewWindow
$dbgPid = 0
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 100
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    $cl = One $q.CommandLine
    if ($cl -imatch ('(?i)-k\s+' + $G2) -and $cl -imatch ('(?i)-s\s+wlansvc')) { $dbgPid = $q.ProcessId }
  }
}
$alive = [bool](Get-Process -Id $dbgPid -ErrorAction SilentlyContinue)
Log ('  wlansvc -d : svchost pid=' + $dbgPid + ' alive after 6s=' + $alive)
Log ('  console: ' + (One (Get-Content $of -Raw -ErrorAction SilentlyContinue)).Trim())
Log ('  (if alive=true the DLL runs fine outside the SCM -> the fault is the SCM/svchost handshake, not wlansvc.dll)')

Sec '2_WLANAPI_WHILE_DEBUG_HOST_UP'
if ($alive) {
  $o = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\wl13.ps1 2>&1') | Out-String
  Log ((One $o).Trim())
} else {
  Log '  skipped: no live debug host'
}

Sec '3_HEALTHY_CONTROLS_MINUS_D'
# Control A: a service we never touched, in -d mode, must stay alive (proves the -d instrument).
$gc = Get-Item -LiteralPath ($SVC + '\dot3svc')
$o2 = 'X:\dbg_dot3.out'
del $o2 -ErrorAction SilentlyContinue
$pd = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('X:\windows\System32\svchost.exe -k ' + $GRP + ' -d -s dot3svc > ' + $o2 + ' 2>&1') -PassThru -NoNewWindow
$dpid = 0
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 100
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    $cl = One $q.CommandLine
    if ($cl -imatch ('(?i)-s\s+dot3svc')) { $dpid = $q.ProcessId }
  }
}
Log ('  CONTROL dot3svc -d : pid=' + $dpid + ' alive after 6s=' + [bool](Get-Process -Id $dpid -ErrorAction SilentlyContinue))
Log ('  console: ' + (One (Get-Content $o2 -Raw -ErrorAction SilentlyContinue)).Trim())

Sec '4_WLANSVC_INTO_A_FRESH_HOST_OF_A_HEALTHY_GROUP'
# Third shape never tried: keep wlansvc ALONE in its own new group but WITHOUT -p (shared-host
# semantics) -- this is how swprv/defragsvc/etc. run successfully at runtime.
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G2) -Type ExpandString
Log ('  wlansvc shared shape in fresh group: ' + (Cmd 'net start wlansvc'))
Log ('    ' + (SvcState 'wlansvc'))
# And Type=16 (own process, no svchost sharing) with the same svchost image path.
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'Type' -Value 16 -Type DWord
Log ('  wlansvc Type=16 shared group: ' + (Cmd 'net start wlansvc'))
Log ('    ' + (SvcState 'wlansvc'))
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'Type' -Value 32 -Type DWord

Sec '5_CLEANUP_AND_FINAL'
if ($dbgPid) { Cmd ('taskkill /f /pid ' + $dbgPid) | Out-Null }
if ($dpid)   { Cmd ('taskkill /f /pid ' + $dpid) | Out-Null }
Cmd ('taskkill /f /pid ' + $p.Id) | Out-Null
Cmd ('taskkill /f /pid ' + $pd.Id) | Out-Null
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString
Remove-ItemProperty -LiteralPath $SVCH -Name $G2 -ErrorAction SilentlyContinue
$orig = @((Get-Item -LiteralPath $SVCH).GetValue($GRP)) | Where-Object { $_ -ne 'wlansvcb' }
Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value $orig -Type MultiString
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log ('  final group list: ' + ($orig -join ','))
Log 'PROBE13_DONE'
