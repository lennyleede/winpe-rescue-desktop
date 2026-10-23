# probe12: probe11 reframed the problem. Two DIFFERENT failures are now visible:
#   (A) wlansvc into the EXISTING group host (pid 1328) -> error 6, no new process.
#   (C) dot3svc into that same host -> starts fine.  So the host can load dot3svc.dll but not
#       wlansvc.dll, even though wlansvc.dll LoadLibrary's cleanly in a normal process.
#   (B/D) ANY service moved into a freshly created group (no host yet) -> that service fails,
#       including the healthy dot3svc.  Suggests runtime-created svchost hosts are broken in
#       this PE, which would make B/D a red herring for wlansvc.
# probe11's net text was truncated because the watcher read the file while net was still
# running. Here every case is synchronous (full text) and the decisive control is services we
# never touched, whose groups have no host process.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { Write-Output $m }
function Sec([string]$n)  { Log ''; Log ('===== ' + $n + ' =====') }
function One([string]$s)  { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c)  { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}
$SVCH    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC     = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$GRP     = 'LocalSystemNetworkRestricted'

function DebugRun([string]$group, [string]$svc) {
  # svchost -d is BLOCKING (it stays up until Ctrl+C when the service runs fine), so it must not
  # be called synchronously. Liveness is itself the measurement: alive after 8s => the DLL loaded
  # and ServiceMain ran; exited immediately => the failure is inside that load/run path.
  $of = 'X:\dbg_' + $svc + '.out'
  $ef = 'X:\dbg_' + $svc + '.err'
  del $of, $ef -ErrorAction SilentlyContinue
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('X:\windows\System32\svchost.exe -k ' + $group + ' -d -s ' + $svc + ' > ' + $of + ' 2>&1') -PassThru -NoNewWindow
  $pidSvch = 0
  for ($i = 0; $i -lt 80; $i++) {
    Start-Sleep -Milliseconds 100
    foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
      $cl = One $q.CommandLine
      if ($cl -imatch ('(?i)-k\s+' + [regex]::Escape($group)) -and $cl -imatch ('(?i)-s\s+' + [regex]::Escape($svc))) { $pidSvch = $q.ProcessId }
    }
  }
  $aliveNow = [bool](Get-Process -Id $p.Id -ErrorAction SilentlyContinue)
  Cmd ('taskkill /f /t /pid ' + $p.Id) | Out-Null
  if ($pidSvch -gt 0) { Cmd ('taskkill /f /pid ' + $pidSvch) | Out-Null }
  $oc = One (Get-Content $of -Raw -ErrorAction SilentlyContinue)
  if ($oc.Length -gt 300) { $oc = $oc.Substring(0, 300) }
  Log ('    cmd alive after 8s=' + $aliveNow + ' ; observed svchost pid=' + $pidSvch + ' ; console=' + $oc.Trim())
}

Sec '0_RECOVER_PROBE11_FULL_TEXTS'
foreach ($f in @('X:\ns11_wlansvc.txt', 'X:\ns11_dot3svc.txt', 'X:\ns_wlansvc.txt', 'X:\ns_dot3svc.txt')) {
  if (Test-Path $f) { Log ('  ' + $f + ' :: ' + (One (Get-Content $f -Raw -ErrorAction SilentlyContinue)).Trim()) } else { Log ('  ' + $f + ' absent') }
}

Sec '1_WHICH_GROUPS_HAVE_NO_HOST'
# Map every svchost group value -> the services it lists, and whether a host process for that
# group exists. A group with no host is where a runtime CreateProcess must happen.
$hosts = @{}
foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  $cl = One $p.CommandLine
  if ($cl -match '-k\s+(\S+)') { $hosts[$Matches[1].ToLower()] = $p.ProcessId }
}
$sk = Get-Item -LiteralPath $SVCH
$nohost = @()
foreach ($vn in @($sk.GetValueNames())) {
  if ($sk.GetValueKind($vn) -ne 'MultiString') { continue }
  if (-not $hosts.ContainsKey($vn.ToLower())) {
    $nohost += [pscustomobject]@{ Group = $vn; Members = (@($sk.GetValue($vn)) -join ',') }
  }
}
Log ('  hosts: ' + (($hosts.Keys | Sort-Object) -join ','))
foreach ($n in $nohost) { Log ('  NO HOST: ' + $n.Group + ' -> ' + $n.Members) }

Sec '2_CONTROLS_SERVICES_WITHOUT_HOST'
# Pick stopped services from host-less groups and start them SYNCHRONOUSLY. These services were
# never touched by wifi-inject -- if they also fail, runtime svchost creation is broken in this
# PE and probe11 B/D prove nothing about wlansvc.
$cands = @()
foreach ($n in $nohost) {
  foreach ($m in ($n.Members -split ',')) {
    if (-not $m) { continue }
    $st = Get-CimInstance Win32_Service -Filter ('Name=''' + $m + '''') -ErrorAction SilentlyContinue
    if ($st -and $st.State -eq 'Stopped') { $cands += [pscustomobject]@{ Group = $n.Group; Name = $m } }
  }
}
Log ('  candidates (stopped, group has no host): ' + (($cands | ForEach-Object { $_.Name + '@' + $_.Group }) -join ' '))
foreach ($c in ($cands | Select-Object -First 6)) {
  $o = Cmd ('net start ' + $c.Name)
  if ($o.Length -gt 240) { $o = $o.Substring(0, 240) }
  Log ('  CONTROL ' + $c.Name + ' [' + $c.Group + '] => ' + $o)
  Log ('      state: ' + (SvcState $c.Name))
}

Sec '3_SYNCHRONOUS_AB_CD'
Log ('  wlansvc @original group : ' + (Cmd 'net start wlansvc'))
Log ('      ' + (SvcState 'wlansvc'))
$o = Cmd ('net start dot3svc')
Log ('  dot3svc @original group : ' + $o + ' || ' + (SvcState 'dot3svc'))
# One more shape on wlansvc: per-service host with an explicit -s, and the shared shape.
foreach ($shape in @(
  ('%SystemRoot%\System32\svchost.exe -k ' + $GRP + ' -p -s wlansvc'),
  ('%SystemRoot%\System32\svchost.exe -k ' + $GRP))) {
  Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value $shape -Type ExpandString
  $o = Cmd 'net start wlansvc'
  if ($o.Length -gt 240) { $o = $o.Substring(0, 240) }
  Log ('  wlansvc shape [' + $shape + '] => ' + $o)
  Log ('      ' + (SvcState 'wlansvc'))
}
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString

Sec '4_SVCHOST_DEBUG_CONSOLE'
# svchost -d runs the group's services in the CONSOLE and does not talk to the SCM. It is the
# only way in PE to see the loader's own text. Put wlansvc alone in a group, run it via cmd so
# the redirection is done by cmd itself (probe8/9 captured nothing through Start-Process).
$G2 = 'peWlanGrp'
Set-ItemProperty -LiteralPath $SVCH -Name $G2 -Value @('wlansvc') -Type MultiString
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G2 + ' -p') -Type ExpandString
$o = DebugRun $G2 'wlansvc'
Log ('  svchost -d -s wlansvc done')
# Also whether it even gets as far as loading the DLL: verify with our own ServiceMain probe.
$src = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class W5M {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
  static extern IntPtr GetProcAddress(IntPtr h, string n);
  public static string Test(string dll, string main) {
    IntPtr h = LoadLibraryExW(dll, IntPtr.Zero, 0x00000100);
    if (h == IntPtr.Zero) { int e = Marshal.GetLastWin32Error(); return "LOAD FAIL " + e; }
    IntPtr p = GetProcAddress(h, main);
    if (p == IntPtr.Zero) { return "OK loaded, entry " + main + " NOT FOUND " + Marshal.GetLastWin32Error(); }
    return "OK loaded, entry " + main + " present";
  }
}
"@
Add-Type -TypeDefinition $src
Write-Output ('  ' + [W5M]::Test('X:\windows\System32\wlansvc.dll', 'WlanSvcMain'))
Write-Output ('  ' + [W5M]::Test('X:\windows\System32\dot3svc.dll', 'Dot3SvcMain'))
'@
Set-Content -LiteralPath 'X:\w5m.ps1' -Value $src -Encoding ASCII
foreach ($line in @(& cmd.exe /c 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\w5m.ps1 2>&1')) { Log ('  entrypoint ' + (One $line).Trim()) }

Sec '5_SVCHOST_DEBUG_FOR_DOT3_CONTROL'
$G1 = 'peDot3Grp'
Set-ItemProperty -LiteralPath $SVCH -Name $G1 -Value @('dot3svc') -Type MultiString
[void](DebugRun $G1 'dot3svc')
Log ('  (above = healthy control: -d should STAY alive)')
Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value ('%SystemRoot%\system32\svchost.exe -k ' + $G1 + ' -p') -Type ExpandString
$o = Cmd 'net start dot3svc'
Log ('  dot3svc in NEW group (fresh host) => ' + $o)
Log ('      ' + (SvcState 'dot3svc'))

Sec '6_RESTORE_AND_FINAL'
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString
Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value ('%SystemRoot%\system32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString
foreach ($g in @($G1, $G2)) { Remove-ItemProperty -LiteralPath $SVCH -Name $g -ErrorAction SilentlyContinue }
Cmd 'net stop dot3svc' | Out-Null
$o = Cmd 'net start dot3svc'
Log ('  dot3svc back home: ' + $o + ' || ' + (SvcState 'dot3svc'))
$orig = @((Get-Item -LiteralPath $SVCH).GetValue($GRP)) | Where-Object { $_ -ne 'wlansvcb' }
Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value $orig -Type MultiString
Log ('  group list: ' + ((Get-Item -LiteralPath $SVCH).GetValue($GRP) -join ','))
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log 'PROBE12_DONE'
