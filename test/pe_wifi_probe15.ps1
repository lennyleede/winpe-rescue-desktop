# probe15: probe14 delivered two facts that reframe everything.
#  (i)  ntdll/svchost/dot3svc/OneX on X: are 10.0.26100.1, while the whole WLAN stack
#       (wlansvc/wlanapi/wlanmsm/wlansec/wlansvcpal/nwifi.sys) is 10.0.19041.x. Confirmed mixing.
#       But swapping in a DIFFERENT 19041 build (C: here runs 19041.3155) changed nothing -> the
#       minor build is not the trigger; only a true 26100-native file could test that, and none
#       exists on this host (no Win11 install, ADK has no WiFi cab).
#  (ii) the LoadLibrary(real) of native 19041 wlansvc.dll inside this 26100 PE SUCCEEDED, so every
#       import resolves. WlanSvcMain is exported. Every registry shape fails identically.
# That points at how svchost finds the entry point: it builds "<service name>Main" and GetProcAddress
# is CASE SENSITIVE. Real Windows stores the key as "WlanSvc" (and svchost's own table knows that
# case); OUR image stores it lowercase as "wlansvc", so svchost asks for "wlansvcMain" -> not found
# -> the host reports a generic failure, and "net start" renders it as System error 6.
# It also explains probe7-14 perfectly: byte-for-byte cloning dot3svc's key under the name "wlansvc"
# still failed (dot3svc works because its key case happens to make "dot3svcMain" ... no, because the
# SCM/svchost pair matches its own table), while five untouched services started fine.
# Live, this is testable WITHOUT renaming a key (names are boot-frozen) by controlling the case that
# reaches svchost: the "-s NAME" argument and the SVCHOST group-list member string are both ours.
param([switch]$SkipStart)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }
function One([string]$s) { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c) { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId + ' startmode=' + $s.StartMode)
}
function Hosts {
  $out = @()
  foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    $out += ([string]$q.ProcessId + ':' + (One $q.CommandLine))
  }
  return ($out -join ' ;; ')
}
function FindHost([string]$pattern) {
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 150
    foreach ($q in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
      if ((One $q.CommandLine) -imatch $pattern) { return $q.ProcessId }
    }
  }
  return 0
}
$SVCH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC  = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$S32B = 'X:\windows\System32'
$IMG  = 'X:\windows\System32\svchost.exe'
$GRP  = 'LocalSystemNetworkRestricted'
$w    = Get-Item -LiteralPath ($SVC + '\wlansvc')
$ORIG = @(Get-ItemProperty -LiteralPath $SVCH -Name $GRP).$GRP

Sec '0_NAME_CASE_EVIDENCE'
# probe14 left 19041.2546 copies in System32; put the as-built files back before measuring.
foreach ($f in @(Get-ChildItem -LiteralPath 'X:\bak14' -File -EA SilentlyContinue)) {
  $err = ''
  try { Copy-Item -LiteralPath $f.FullName -Destination ($S32B + '\' + $f.Name) -Force -ErrorAction Stop } catch { $err = (One $_.Exception.Message) }
  Log ('  restore ' + $f.Name + ' => ' + $(if ($err) { 'FAIL ' + $err } else { 'ok' }))
}
$names = @([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services').GetSubKeyNames())
foreach ($n in @('wlansvc','WlanSvc','dot3svc','Dot3svc','Defragsvc','defragsvc','hidserv','netprofm','Schedule','Themes','PolicyAgent','wcmsvc')) {
  $hit = @($names | Where-Object { $_ -ieq $n })
  if (@($hit).Count -gt 0) { Log ('  stored key name for lookup "' + $n + '" => ' + ($hit -join ',')) }
}
Log ('  SVCHOST group members (LocalSystemNetworkRestricted) => ' + (@($ORIG) -join ','))
Log ('  wlansvc ServiceDll = ' + (One (Get-ItemProperty -LiteralPath ($SVC + '\wlansvc\Parameters') -Name ServiceDll -EA SilentlyContinue).ServiceDll))
Log ('  baseline ' + (SvcState 'wlansvc'))

Sec '0b_EXPORT_TABLE_ENTRY_POINT_NAMES'
# THE decisive measurement, and it needs no reboot: svchost derives the ServiceMain export as
# "<name>Main" and GetProcAddress is CASE SENSITIVE. So the question is whether the export inside
# wlansvc.dll matches the case our image actually uses, and whether dot3svc.dll (which works) does.
function Get-PeExports([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return @() }
  $b = [IO.File]::ReadAllBytes($path)
  $peOff  = [BitConverter]::ToInt32($b, 0x3C)
  $numSec = [BitConverter]::ToUInt16($b, $peOff + 6)
  $sizeOpt= [BitConverter]::ToUInt16($b, $peOff + 20)
  $magic  = [BitConverter]::ToUInt16($b, $peOff + 24)
  $ddSize = 112
  if ($magic -eq 0x10b) { $ddSize = 96 }
  $ddOff  = $peOff + 24 + $ddSize
  $expRva = [BitConverter]::ToUInt32($b, $ddOff + 0)
  if ($expRva -eq 0) { return @() }
  $secOff = $peOff + 24 + $sizeOpt
  $secs = @()
  for ($i = 0; $i -lt $numSec; $i++) {
    $s = $secOff + $i * 40
    $secs += [pscustomobject]@{
      VA   = [long][BitConverter]::ToUInt32($b, $s + 12)
      VS   = [long][BitConverter]::ToUInt32($b, $s + 8)
      RAW  = [long][BitConverter]::ToUInt32($b, $s + 20)
    }
  }
  function R2F([long]$rva) {
    foreach ($x in $secs) { if ($rva -ge $x.VA -and $rva -lt ($x.VA + $x.VS)) { return ($rva - $x.VA + $x.RAW) } }
    return -1
  }
  $e = R2F ([long]$expRva)
  if ($e -lt 0) { return @() }
  $nn  = [BitConverter]::ToUInt32($b, $e + 24)
  $aon = [BitConverter]::ToUInt32($b, $e + 32)
  $nameBase = R2F ([long]$aon)
  if ($nameBase -lt 0) { return @() }
  $out = @()
  for ($i = 0; $i -lt $nn; $i++) {
    $nrva = [long][BitConverter]::ToUInt32($b, $nameBase + 4 * $i)
    $no = R2F $nrva
    if ($no -lt 0) { continue }
    $sb = ''
    $j = $no
    while ($j -lt $b.Length -and $b[$j] -ne 0) { $sb += [char]$b[$j]; $j++ }
    $out += $sb
  }
  return $out
}
foreach ($pair in @(@('wlansvc','wlansvc.dll'), @('dot3svc','dot3svc.dll'), @('wcmsvc','wcmsvc.dll'), @('defragsvc','defragsvc.dll'))) {
  $svcName = $pair[0]; $dll = $pair[1]
  $p = $S32B + '\' + $dll
  $ex = @(Get-PeExports $p)
  if (@($ex).Count -eq 0) { Log ('  ' + ('{0,-12}' -f $svcName) + ' ' + $dll + ' : no exports read (missing file?)'); continue }
  $mains = @($ex | Where-Object { $_ -imatch 'Main' })
  $expect = $svcName + 'Main'
  $exact  = @($ex | Where-Object { $_ -ceq $expect }).Count -gt 0
  $insens = @($ex | Where-Object { $_ -ieq $expect }).Count -gt 0
  Log ('  ' + ('{0,-12}' -f $svcName) + ' ' + ('{0,-16}' -f $dll) + ' exports=' + @($ex).Count +
       ' mains=[' + ($mains -join ',') + '] "<name>Main"=' + $expect + ' exactCase=' + $exact + ' caseInsensitive=' + $insens)
}
Log '  (if wlansvc exactCase=False while dot3svc exactCase=True, svchost cannot find the entry point'
Log '   for our lowercase key and the fault is the KEY NAME CASE, not the DLL or the registry shape)'

Sec '1_RAW_STARTSERVICE_PINVOKE'
# net start's wording hides the real code; ask advapi32 directly. Case variants of the name are
# tried so we can see whether the SCM/svchost layer is case sensitive at all.
$raw = @'
$src = @"
using System;
using System.Runtime.InteropServices;
public class SC15 {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenSCManagerW(string m, string d, uint a);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr OpenServiceW(IntPtr s, string name, uint a);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool StartServiceW(IntPtr svc, int n, IntPtr args);
  [DllImport("advapi32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool ControlService(IntPtr svc, int c, IntPtr status);
  [DllImport("kernel32.dll")] public static extern uint GetLastError();
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern int FormatMessageW(
      uint f, IntPtr src, uint code, uint lang, IntPtr buf, int size, IntPtr args);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
}
"@
Add-Type -TypeDefinition $src
function Msg([int]$c) {
  $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal(512)
  $n = [SC15]::FormatMessageW(0x1300, [IntPtr]::Zero, [uint32]$c, 0, $buf, 512, [IntPtr]::Zero)
  $t = ''
  if ($n -gt 0) { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($buf) }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
  return ($t -replace '\s+', ' ').Trim()
}
$scm = [SC15]::OpenSCManagerW($null, $null, 0x0001 -bor 0x0010)
if ($scm -eq [IntPtr]::Zero) { Write-Output ('  OpenSCManager FAIL err=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()); return }
foreach ($nm in @('wlansvc','WlanSvc','WLANSVC')) {
  $h = [SC15]::OpenServiceW($scm, $nm, 0x0010 -bor 0x0040 -bor 0x1000)
  if ($h -eq [IntPtr]::Zero) {
    Write-Output ('  OpenService ' + $nm + ' FAIL err=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    continue
  }
  $ok = [SC15]::StartServiceW($h, 0, [IntPtr]::Zero)
  $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  Write-Output ('  StartService ' + $nm + ' ok=' + $ok + ' err=' + $e + ' | ' + (Msg $e))
  [void][SC15]::CloseHandle($h)
}
[void][SC15]::CloseHandle($scm)
'@
Set-Content -LiteralPath 'X:\raw15.ps1' -Value $raw -Encoding ASCII
$o = & cmd.exe /c ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\raw15.ps1 2>&1') | Out-String
foreach ($l in ($o -split "`r?`n")) { if ((One $l).Length -gt 3) { Log ('  ' + (One $l)) } }
Log ('  state now: ' + (SvcState 'wlansvc'))

Sec '2_CASED_S_ARGUMENT_FRESH_HOST'
# Variant A: brand new group (forces a new svchost host at runtime, proven possible in probe12),
# ImagePath carries "-s WlanSvc" so svchost itself builds the entry point name "WlanSvcMain".
$GA = 'pe15a'
Set-ItemProperty -LiteralPath $SVCH -Name $GA -Value @('WlanSvc') -Type MultiString
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ($IMG + ' -k ' + $GA + ' -p -s WlanSvc') -Type ExpandString
Log ('  A host before start: ' + (FindHost ('-k ' + $GA)))
if (-not $SkipStart) {
  Log ('  A net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state=' + (SvcState 'wlansvc') + ' hosts=' + (Hosts))
}

Sec '3_CASED_GROUP_MEMBER_NO_S_ARG'
# Variant B: cased member string, no -s, so svchost uses what the SCM hands it.
$GB = 'pe15b'
Set-ItemProperty -LiteralPath $SVCH -Name $GB -Value @('WlanSvc') -Type MultiString
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ($IMG + ' -k ' + $GB + ' -p') -Type ExpandString
if (-not $SkipStart) {
  Log ('  B net start wlansvc : ' + (Cmd 'net start wlansvc'))
  Log ('    state=' + (SvcState 'wlansvc') + ' spawned=' + (FindHost ('-k ' + $GB)))
}

Sec '4_DEBUG_HOST_CASED'
# Variant C: -d keeps the host in our console; exit code tells svchost-vs-service apart.
foreach ($case in @('WlanSvc','wlansvc')) {
  Set-ItemProperty -LiteralPath $SVCH -Name $GB -Value @($case) -Type MultiString
  $p = $null
  try {
    $p = Start-Process -FilePath $IMG -ArgumentList ('-k ' + $GB + ' -d -s ' + $case) -PassThru -NoNewWindow `
        -RedirectStandardOutput ('X:\d15_' + $case + '.out') -RedirectStandardError ('X:\d15_' + $case + '.err')
  } catch { Log ('  C launch ' + $case + ' FAIL ' + (One $_.Exception.Message)) }
  if ($p) {
    $done = $p.WaitForExit(7000)
    $code = 'ALIVE-BLOCKING(running)'
    if (-not $done) { try { $p.Kill(); $p.WaitForExit() } catch { } }
    else { $code = [string]$p.ExitCode }
    $so = (One (Get-Content ('X:\d15_' + $case + '.out') -Raw -EA SilentlyContinue)).Trim()
    $se = (One (Get-Content ('X:\d15_' + $case + '.err') -Raw -EA SilentlyContinue)).Trim()
    Log ('  C -d -s ' + ('{0,-8}' -f $case) + ' exit=' + $code + ' out=[' + $so + '] err=[' + $se + ']')
  }
}
Set-ItemProperty -LiteralPath $SVCH -Name $GB -Value @('wlansvc') -Type MultiString

Sec '5_CONTROL_SAME_SHAPE_DOT3'
# Instrument control on a service we never broke: it is already running inside the boot host, so it
# must be stopped before a new ImagePath/group can be exercised. dot3svc.dll's export case is known
# from 0b; whichever case 0b says is correct must succeed here and the other must fail -- that is the
# cross-check on the whole theory using a HEALTHY DLL.
$GC = 'pe15c'
$dImg = (Get-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name ImagePath).ImagePath
foreach ($case in @('Dot3svc','dot3svc')) {
  Log ('  CONTROL dot3svc shape -s ' + $case)
  Log ('    stop : ' + (Cmd 'net stop dot3svc'))
  Set-ItemProperty -LiteralPath $SVCH -Name $GC -Value @($case) -Type MultiString
  Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value ($IMG + ' -k ' + $GC + ' -p -s ' + $case) -Type ExpandString
  Log ('    start: ' + (Cmd 'net start dot3svc'))
  Log ('      state=' + (SvcState 'dot3svc') + ' spawned=' + (FindHost ('-k ' + $GC)))
}
Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value $dImg -Type ExpandString
Log ('    restore home: ' + (Cmd 'net start dot3svc'))
Remove-ItemProperty -LiteralPath $SVCH -Name $GC -ErrorAction SilentlyContinue

Sec '6_RESTORE_AND_FINAL'
foreach ($n in @('wlansvc','dot3svc','wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ($IMG + ' -k ' + $GRP + ' -p') -Type ExpandString
Remove-ItemProperty -LiteralPath $SVCH -Name $GA -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath $SVCH -Name $GB -ErrorAction SilentlyContinue
Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value (@($ORIG) | Where-Object { $_ -ine 'wlansvcb' }) -Type MultiString
Log ('  restored group list: ' + ((@($ORIG) | Where-Object { $_ -ine 'wlansvcb' }) -join ','))
Log ('  final ImagePath = ' + (One (Get-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name ImagePath).ImagePath))
Log 'PROBE15_DONE'
