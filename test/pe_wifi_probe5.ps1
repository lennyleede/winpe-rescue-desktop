# test/pe_wifi_probe5.ps1 -- runs INSIDE a live PE (push with test\host_push_run.ps1).
# What probe2/3/probe4 already proved: every static import of the borrowed WLAN stack resolves in the
# 26100 PE, the svchost group registration is right, and the wlansvc/wcmsvc key shape matches dot3svc --
# yet wlansvc never reaches STARTING (pid=0, controls=0 => its ServiceMain never registered a handler).
# This probe answers the three questions that can still partition the space, in one round trip:
#   A. does X:\...\wlansvc.dll actually EXPORT WlanSvcMain, and is the copied file byte-identical to the
#      client OS's copy (a truncated/ wrong-arch copy would explain everything)?
#   B. which DLL names does wlansvc.dll only pull in at RUNTIME (string scan), and are they in the image?
#   C. A/B in a throwaway svchost group: same plumbing, dot3svc.dll vs wlansvc.dll. That tells us whether
#      SCM/svchost/PE is at fault or wlansvc.dll's own initialisation is.
# Look + one controlled experiment; everything it creates in the live ramdisk registry it deletes again.
# ASCII output only (PE console + certutil round trip).
param([switch]$SkipHarness)
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' ') -replace '\s{2,}', ' ' }
function Hex([byte[]]$b, [int]$n) {
  if ($null -eq $b) { return 'null' }
  $m = [Math]::Min($n, $b.Length)
  if ($m -le 0) { return '' }
  return (($b[0..($m - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
}
$S32 = Join-Path $env:SystemRoot 'System32'

Sec '0_WHO'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' build=' + [Environment]::OSVersion.Version.Build +
              ' sysroot=' + $env:SystemRoot + ' user=' + $env:UserName)
$who = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Write-Output ('  elevated=' + $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) +
              ' (SCM access needs this; win32=5 below means the probe ran unelevated)')
$bt = Join-Path $env:SystemRoot 'BUILD_TAG.txt'
if (-not (Test-Path $bt)) { $bt = 'X:\BUILD_TAG.txt' }
if (Test-Path $bt) { Write-Output ('  BUILD_TAG=' + (One (((Get-Content $bt -EA SilentlyContinue) -join ' | ')))) }

# ---------- native helpers (MemberDefinition only: no using/class allowed here) ----------
$advSrc = @'
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool CloseServiceHandle(IntPtr h);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool StartServiceW(IntPtr svc, uint numArgs, IntPtr args);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool ControlService(IntPtr svc, uint control, ref SvcStatus st);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool QueryServiceStatusEx(IntPtr svc, uint infoLevel, byte[] buf, uint cb, out uint needed);
public class SvcStatus { public int serviceType; public int currentState; public int controlsAccepted; public int win32ExitCode; public int serviceSpecificCode; public int checkPoint; public int waitHint; public int pid; }
public static string LastErr() { return "win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + " (0x" + System.Runtime.InteropServices.Marshal.GetLastWin32Error().ToString("X8") + ")"; }
public static IntPtr OpenScm() { return OpenSCManagerW(null, null, 0x000F003F); }
public static IntPtr OpenSvc(IntPtr scm, string name) { return OpenServiceW(scm, name, 0x000F01FF); }
public static void Close(IntPtr h) { if (h != System.IntPtr.Zero) CloseServiceHandle(h); }
public static bool Start(IntPtr s) { return StartServiceW(s, 0, System.IntPtr.Zero); }
public static bool Stop(IntPtr s) { SvcStatus st = new SvcStatus(); return ControlService(s, 1 /*SERVICE_STOP*/, ref st); }
public static byte[] Raw(IntPtr s) {
  byte[] buf = new byte[32];
  uint need;
  if (!QueryServiceStatusEx(s, 0 /*SC_STATUS_PROCESS_INFO*/, buf, (uint)buf.Length, out need)) return null;
  return buf;
}
public static int[] Cfg(IntPtr s) {
  byte[] buf = Raw(s);
  if (buf == null) return null;
  return new int[] {
    System.BitConverter.ToInt32(buf, 0), System.BitConverter.ToInt32(buf, 4),
    System.BitConverter.ToInt32(buf, 8), System.BitConverter.ToInt32(buf, 12),
    System.BitConverter.ToInt32(buf, 16), System.BitConverter.ToInt32(buf, 28) };
}
'@
$advOk = $false
try { $null = Add-Type -MemberDefinition $advSrc -Name A -Namespace W5 -PassThru -Language CSharp -EA Stop; $advOk = $true }
catch { Write-Output ('  Add-Type(advapi) failed: ' + (One $_.Exception.Message)) }

$ldrSrc = @'
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr LoadLibraryExW(string name, IntPtr h, uint flags);
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true) ]
static extern bool FreeLibrary(IntPtr h);
public static string Resolve(string name) {
  IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0x20 /*AS_DATAFILE*/);
  if (h == System.IntPtr.Zero) {
    int e = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return "FAIL win32=" + e + " (0x" + e.ToString("X8") + ")";
  }
  FreeLibrary(h);
  return "RESOLVE-OK";
}
public static string Load(string name) {
  IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0x00000100 /*SEARCH_DEFAULT_DIRS*/);
  if (h == System.IntPtr.Zero) {
    int e = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return "FAIL win32=" + e + " (0x" + e.ToString("X8") + ")";
  }
  FreeLibrary(h);
  return "LOAD-OK";
}
'@
$ldrOk = $false
try { $null = Add-Type -MemberDefinition $ldrSrc -Name L -Namespace W5L -PassThru -Language CSharp -EA Stop; $ldrOk = $true }
catch { Write-Output ('  Add-Type(loader) failed: ' + (One $_.Exception.Message)) }

function StatusLine($s) {
  $c = [W5.A]::Cfg($s)
  if ($null -eq $c) { return 'QueryServiceStatusEx failed ' + [W5.A]::LastErr() }
  $names = @{ 1 = 'STOPPED'; 2 = 'STARTING'; 3 = 'STOPPING'; 4 = 'RUNNING'; 5 = 'CONTINUE_PENDING'; 7 = 'PAUSED' }
  $sn = if ($names.ContainsKey($c[1])) { $names[$c[1]] } else { [string]$c[1] }
  return ('state=' + $sn + ' type=0x' + ('{0:X8}' -f $c[0]) + ' controls=' + $c[2] +
          ' exit=0x' + ('{0:X8}' -f $c[3]) + ' specific=0x' + ('{0:X8}' -f $c[4]) + ' pid=' + $c[5])
}

# ---------- PE export table (data directory index 0) ----------
function Get-PeExports([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return @('ABSENT') }
  $b = [IO.File]::ReadAllBytes($path)
  if ($b.Length -lt 0x40) { return @('TOO_SMALL') }
  if ([BitConverter]::ToUInt16($b, 0) -ne 0x5A4D) { return @('NOT_MZ') }
  $pe = [int][BitConverter]::ToInt32($b, 0x3C)
  if ([BitConverter]::ToUInt32($b, $pe) -ne 0x00004550) { return @('NOT_PE') }
  $machine = [int][BitConverter]::ToUInt16($b, ($pe + 4))
  $sizeOpt = [int][BitConverter]::ToUInt16($b, ($pe + 20))
  $opt     = $pe + 24
  $magic   = [int][BitConverter]::ToUInt16($b, $opt)
  $dirBase = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
  $expRva  = [int][BitConverter]::ToUInt32($b, $dirBase)
  $nSec    = [int][BitConverter]::ToUInt16($b, ($pe + 6))
  $sec     = $opt + $sizeOpt
  $secs = @()
  for ($i = 0; $i -lt $nSec; $i++) {
    $o = $sec + ($i * 40)
    $secs += [pscustomobject]@{
      VA   = [int][BitConverter]::ToUInt32($b, ($o + 12))
      VS   = [int][BitConverter]::ToUInt32($b, ($o + 8))
      RawO = [int][BitConverter]::ToUInt32($b, ($o + 20))
      RawS = [int][BitConverter]::ToUInt32($b, ($o + 16))
    }
  }
  if ($expRva -eq 0) { return @("NO_EXPORT_DIR machine=0x$('{0:X4}' -f $machine)") }
  # RVA -> file offset. AddressOfNames holds RVAs, so every read below has to go through this map;
  # using the RVA straight as a file offset is what made the first version print garbage names.
  $rva2off = {
    param([int]$r)
    foreach ($s in $secs) {
      if ($r -ge $s.VA -and ($r + 4) -le ($s.VA + [Math]::Max($s.VS, $s.RawS))) { return ($s.RawO + ($r - $s.VA)) }
    }
    return -1
  }
  $eo = & $rva2off $expRva
  if ($eo -lt 0) { return @("EXPORT_RVA_NOT_IN_SECTION machine=0x$('{0:X4}' -f $machine)") }
  $nFuncs = [int][BitConverter]::ToUInt32($b, ($eo + 20))
  $nNames = [int][BitConverter]::ToUInt32($b, ($eo + 24))
  $addrNm = [int][BitConverter]::ToUInt32($b, ($eo + 32))
  $anOff  = & $rva2off $addrNm
  $hdrTxt = ("machine=0x$('{0:X4}' -f $machine) magic=0x$('{0:X4}' -f $magic) numberOfFunctions=$nFuncs numberOfNames=$nNames")
  if ($anOff -lt 0) { return @($hdrTxt + ' ADDRESS_OF_NAMES_NOT_IN_SECTION') }
  $res = @()
  $res += $hdrTxt
  $lim = [Math]::Min($nNames, 400)
  for ($i = 0; $i -lt $lim; $i++) {
    $nrOffFile = & $rva2off ([int][BitConverter]::ToUInt32($b, ($anOff + ($i * 4))))
    if ($nrOffFile -lt 0) { continue }
    $sb = New-Object Text.StringBuilder 64
    for ($j = 0; $j -lt 60; $j++) {
      $p2 = $nrOffFile + $j
      if ($p2 -ge $b.Length) { break }
      $ch = $b[$p2]
      if ($ch -eq 0) { break }
      [void]$sb.Append([char]$ch)
    }
    $res += $sb.ToString()
  }
  return $res
}

# ---------- A: exports + integrity ----------
$Stack = @('wlanapi.dll','wlansvc.dll','wlancfg.dll','wlanmsm.dll','wlanext.exe','wlansec.dll',
           'wlanutil.dll','wlansvcpal.dll','wlanhlp.dll','wcmsvc.dll','dmcmnutils.dll','mdmregistration.dll',
           'wci.dll','netshell.dll','dot3svc.dll','netsh.exe')
Sec '1_STACK_FILES_PRESENT'
foreach ($f in $Stack) {
  $p = Join-Path $S32 $f
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    Write-Output ('  OK    ' + $f.PadRight(22) + ' ' + $i.Length.ToString().PadLeft(9) + ' v=' + (One $i.VersionInfo.FileVersion))
  } else { Write-Output ('  ABSENT ' + $f) }
}
foreach ($f in @('drivers\nwifi.sys','drivers\ndisuio.sys','drivers\ndis.sys')) {
  $p = Join-Path $S32 $f
  if (Test-Path -LiteralPath $p) {
    Write-Output ('  OK    ' + $f.PadRight(22) + ' ' + (Get-Item -LiteralPath $p).Length.ToString().PadLeft(9) + ' v=' + (One (Get-Item -LiteralPath $p).VersionInfo.FileVersion))
  } else { Write-Output ('  ABSENT ' + $f) }
}

Sec '2_EXPORTS_OF_WLANSVC_DOT3_WCM'
foreach ($f in @('wlansvc.dll','dot3svc.dll','wcmsvc.dll')) {
  $ex = @(Get-PeExports (Join-Path $S32 $f))
  Write-Output ('  --- ' + $f + ' (first names follow, total shown=' + ($ex.Count - 1) + ')')
  Write-Output ('      ' + (One ($ex[0])))
  $want = @{ 'wlansvc.dll' = 'WlanSvcMain'; 'dot3svc.dll' = 'Dot3SvcMain'; 'wcmsvc.dll' = 'WcmSvcMain' }[$f]
  $hasMain  = $ex -contains $want
  $hasSvcMain = $ex -contains 'ServiceMain'
  Write-Output ('      LOOKUP ' + $want + ' => ' + $hasMain + '   |  ServiceMain => ' + $hasSvcMain)
  Write-Output ('      sample: ' + (One (($ex | Select-Object -Skip 1 -First 40) -join ',')))
}

Sec '3_HASH_VS_CLIENT_OS'
$clientRoots = @()
foreach ($d in (Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue)) {
  $w = Join-Path $d.Root 'Windows\System32\ntdll.dll'
  if (Test-Path -LiteralPath $w) { $clientRoots += $d.Root }
}
Write-Output ('  windows-bearing roots = ' + ($clientRoots -join ' '))
foreach ($cr in $clientRoots) {
  if (($cr + '\').TrimEnd('\') -eq $env:SystemDrive) { continue }
  $c32 = Join-Path $cr 'Windows\System32'
  Write-Output ('  -- comparing PE copy against ' + $c32)
  foreach ($f in ($Stack + @('drivers\nwifi.sys'))) {
    $a = Join-Path $S32 $f
    $b = Join-Path $c32 $f
    if (-not (Test-Path -LiteralPath $a)) { Write-Output ('     ' + $f.PadRight(22) + ' PE copy ABSENT'); continue }
    if (-not (Test-Path -LiteralPath $b)) { Write-Output ('     ' + $f.PadRight(22) + ' client copy ABSENT'); continue }
    $ha = (Get-FileHash -LiteralPath $a -Algorithm SHA256 -EA SilentlyContinue).Hash
    $hb = (Get-FileHash -LiteralPath $b -Algorithm SHA256 -EA SilentlyContinue).Hash
    $sa = (Get-Item -LiteralPath $a).Length
    $sb = (Get-Item -LiteralPath $b).Length
    $same = if ($ha -and $hb -and ($ha -eq $hb)) { 'IDENTICAL' } else { 'DIFFERENT' }
    Write-Output ('     ' + $f.PadRight(22) + ' ' + $same + ' peSize=' + $sa + ' osSize=' + $sb +
                  ' peVer=' + (One (Get-Item -LiteralPath $a).VersionInfo.FileVersion) +
                  ' osVer=' + (One (Get-Item -LiteralPath $b).VersionInfo.FileVersion))
  }
  break
}

# ---------- B: runtime DLL/contract names pulled in by the service DLLs themselves ----------
# The import table (probe2) only covers what the loader binds up front. wlansvc also calls
# GetModuleHandle/LoadLibrary and api-set contracts at runtime; a contract the 26100 PE does not
# publish would kill its init long before the SCM sees a status handler. dot3svc.dll is the control:
# it starts fine in this same image, so whatever fails for wlansvc has to fail for wlansvc only.
function Scan-DllStrings([string]$path, [string]$label, $idx) {
  if (-not (Test-Path -LiteralPath $path)) { Write-Output ("  " + $label + ": file absent"); return }
  $bytes = [IO.File]::ReadAllBytes($path)
  $ascii = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  $uni   = [Text.Encoding]::Unicode.GetString($bytes)
  $pat = '[A-Za-z0-9_\-\.\$\[\]]{2,48}\.(?:dll|DLL)'
  $hits = @{}
  foreach ($mm in @([regex]::Matches($ascii, $pat))) { $n = [IO.Path]::GetFileName($mm.Value).ToLower(); if ($n -notmatch '^(w|n)?api-ms|^ext-ms') { $hits[$n] = 1 } }
  foreach ($mm in @([regex]::Matches($uni,   $pat))) { $n = [IO.Path]::GetFileName($mm.Value).ToLower(); if ($n -notmatch '^(w|n)?api-ms|^ext-ms') { $hits[$n] = 1 } }
  $setPat = '(?:api|ext)-ms-[A-Za-z0-9_\-]{4,60}\.dll'
  $sets = @{}
  foreach ($mm in @([regex]::Matches($ascii, $setPat))) { $sets[[IO.Path]::GetFileName($mm.Value).ToLower()] = 1 }
  foreach ($mm in @([regex]::Matches($uni,   $setPat))) { $sets[[IO.Path]::GetFileName($mm.Value).ToLower()] = 1 }
  $real = @($hits.Keys | Sort-Object)
  $ws   = @($sets.Keys | Sort-Object)
  Write-Output ('  -- ' + $label + ': real-dll names=' + $real.Count + ' contract names=' + $ws.Count)
  foreach ($n in $real) {
    $present = $idx.ContainsKey($n)
    $r = if ($ldrOk -and $present) { [W5L.L]::Resolve($n) } elseif ($present) { 'file-present (loader n/a)' } else { 'NOT-IN-IMAGE' }
    if (($r -like 'FAIL*') -or ($r -eq 'NOT-IN-IMAGE')) {
      Write-Output ('      ' + $n.PadRight(32) + ' ' + $r)
    }
  }
  $setFail = 0
  foreach ($n in $ws) {
    $r = if ($ldrOk) { [W5L.L]::Load($n) } else { 'loader-unavailable' }
    if ($r -like 'FAIL*') { $setFail++; Write-Output ('      CONTRACT ' + $n.PadRight(48) + ' ' + $r) }
  }
  Write-Output ('      contracts that do NOT resolve here = ' + $setFail + ' / ' + $ws.Count)
  $sysPat = '[A-Za-z0-9_\-\.]{2,48}\.(?:sys|SYS)'
  $d = @{}
  foreach ($mm in @([regex]::Matches($ascii, $sysPat))) { $d[[IO.Path]::GetFileName($mm.Value).ToLower()] = 1 }
  foreach ($mm in @([regex]::Matches($uni,   $sysPat))) { $d[[IO.Path]::GetFileName($mm.Value).ToLower()] = 1 }
  foreach ($n in @($d.Keys | Sort-Object)) {
    if (-not $idx.ContainsKey(('drivers\' + $n))) { Write-Output ('      driver named, not in PE drivers: ' + $n) }
  }
}
Sec '4_RUNTIME_STRINGS_SCAN'
$idx = @{}
foreach ($fi in @(Get-ChildItem $S32 -File -EA SilentlyContinue)) { $idx[$fi.Name.ToLower()] = $fi.Name }
$drvDir = Join-Path $S32 'drivers'
if (Test-Path -LiteralPath $drvDir) { foreach ($di in @(Get-ChildItem $drvDir -File -EA SilentlyContinue)) { $idx[('drivers\' + $di.Name).ToLower()] = $di.Name } }
Write-Output ('  index size = ' + $idx.Count + ' names (System32 files + drivers)')
Scan-DllStrings (Join-Path $S32 'wlansvc.dll')  'wlansvc.dll'  $idx
Scan-DllStrings (Join-Path $S32 'dot3svc.dll')  'dot3svc.dll'  $idx
Scan-DllStrings (Join-Path $S32 'wlansvcpal.dll') 'wlansvcpal.dll' $idx

# ---------- primary measurement: one clean start attempt with full status ----------
Sec '5_START_ATTEMPT_WLANSVC'
if ($advOk) {
  $scm = [W5.A]::OpenScm()
  if ($scm -eq [IntPtr]::Zero) { Write-Output ('  OpenSCManager failed ' + [W5.A]::LastErr()) }
  foreach ($s in @('wlansvc','dot3svc','wcmsvc','RpcSs','Ndisuio','nativewifip','nsi','netprofm','Dnscache','fdPHost','LSM')) {
    $sv = [W5.A]::OpenSvc($scm, $s)
    if ($sv -eq [IntPtr]::Zero) { Write-Output ('  ' + $s.PadRight(12) + ' OpenService failed ' + [W5.A]::LastErr()); continue }
    Write-Output ('  ' + $s.PadRight(12) + ' ' + (StatusLine $sv))
    [W5.A]::Close($sv)
  }
  Write-Output '  -- attempt to start wlansvc'
  $sv = [W5.A]::OpenSvc($scm, 'wlansvc')
  if ($sv -ne [IntPtr]::Zero) {
    $ok = [W5.A]::Start($sv)
    Write-Output ('     StartService => ' + $ok + ' ' + [W5.A]::LastErr())
    for ($i = 1; $i -le 8; $i++) {
      Start-Sleep -Milliseconds 600
      Write-Output ('     poll ' + $i + ': ' + (StatusLine $sv))
      $raw = [W5.A]::Raw($sv)
      if ($i -le 2) { Write-Output ('        raw=' + (Hex $raw 32)) }
      $c = [W5.A]::Cfg($sv)
      if ($c -and ($c[1] -ne 2)) { break }
    }
    [W5.A]::Close($sv)
  }
  [W5.A]::Close($scm)
} else { Write-Output '  advapi helpers unavailable' }

# ---------- C: A/B harness in a throwaway svchost group ----------
Sec '6_A_B_HARNESS'
$SVCROOT = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$grp = 'peharness'
$svcDot = 'peDot3Host'
$svcWan = 'peWlanHost'
if ($SkipHarness) {
  Write-Output '  skipped (-SkipHarness)'
} else {
  try {
    function New-Harness([string]$name, [string]$dll, [string]$main) {
      $k = Join-Path $SVCROOT $name
      if (Test-Path $k) { Remove-Item $k -Recurse -Force }
      New-Item $k -Force | Out-Null
      Set-ItemProperty $k -Name Type -Value 32 -Type DWord -Force
      Set-ItemProperty $k -Name Start -Value 3 -Type DWord -Force
      Set-ItemProperty $k -Name ErrorControl -Value 1 -Type DWord -Force
      Set-ItemProperty $k -Name ImagePath -Value ("%SystemRoot%\System32\svchost.exe -k $grp -s $name") -Type ExpandString -Force
      Set-ItemProperty $k -Name ObjectName -Value 'LocalSystem' -Type String -Force
      Set-ItemProperty $k -Name ServiceSidType -Value 1 -Type DWord -Force
      $p = Join-Path $k 'Parameters'
      New-Item $p -Force | Out-Null
      Set-ItemProperty $p -Name ServiceDll -Value ("%SystemRoot%\System32\$dll") -Type ExpandString -Force
      Set-ItemProperty $p -Name ServiceMain -Value $main -Type String -Force
      Write-Output ('  created ' + $name + ' -> ' + $dll + ' / ' + $main)
    }
    $cur = @((Get-ItemProperty $SH -Name $grp -EA SilentlyContinue).$grp) | Where-Object { $_ }
    $cur = ($cur + @($svcDot, $svcWan)) | Where-Object { $_ } | Select-Object -Unique
    Set-ItemProperty $SH -Name $grp -Value $cur -Type MultiString -Force
    Write-Output ('  group ' + $grp + ' = ' + ($cur -join ','))
    New-Harness $svcDot 'dot3svc.dll' 'Dot3SvcMain'
    New-Harness $svcWan 'wlansvc.dll' 'WlanSvcMain'
    if ($advOk) {
      $scm2 = [W5.A]::OpenScm()
      foreach ($nm in @($svcDot, $svcWan)) {
        $sv = [W5.A]::OpenSvc($scm2, $nm)
        if ($sv -eq [IntPtr]::Zero) { Write-Output ('  ' + $nm + ' OpenService failed ' + [W5.A]::LastErr()); continue }
        $ok = [W5.A]::Start($sv)
        Write-Output ('  start ' + $nm + ' => ' + $ok + ' ' + [W5.A]::LastErr())
        for ($i = 1; $i -le 8; $i++) {
          Start-Sleep -Milliseconds 600
          $line = StatusLine $sv
          Write-Output ('     ' + $nm + ' poll ' + $i + ': ' + $line)
          $c = [W5.A]::Cfg($sv)
          if ($c -and ($c[1] -ne 2)) { break }
        }
        if ($ok) { Write-Output ('     stop ' + $nm + ' => ' + ([W5.A]::Stop($sv)) + ' ' + [W5.A]::LastErr()) }
        [W5.A]::Close($sv)
      }
      [W5.A]::Close($scm2)
    }
  } catch {
    Write-Output ('  harness error: ' + (One $_.Exception.Message))
  } finally {
    foreach ($nm in @($svcDot, $svcWan)) {
      $k = Join-Path $SVCROOT $nm
      if (Test-Path $k) { Remove-Item $k -Recurse -Force -EA SilentlyContinue; Write-Output ('  cleaned ' + $nm) }
    }
    if (Get-ItemProperty $SH -Name $grp -EA SilentlyContinue) {
      Remove-ItemProperty $SH -Name $grp -Force -EA SilentlyContinue
      Write-Output ('  cleaned group value ' + $grp)
    }
  }
}

Sec '7_SVCHOST_PROCESSES'
foreach ($pr in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  Write-Output ('  pid=' + $pr.ProcessId + ' cmd=' + (One $pr.CommandLine))
}
Write-Output '  -- child of each svchost? (which services actually resident)'
foreach ($pr in @(Get-CimInstance Win32_Process -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)^wlan' })) {
  Write-Output ('  wlan proc: pid=' + $pr.ProcessId + ' name=' + $pr.Name + ' cmd=' + (One $pr.CommandLine))
}

Sec '8_WLANOPEN_HANDLE'
$apiSrc = @'
[ System.Runtime.InteropServices.DllImport("wlanapi.dll") ]
public static extern int WlanOpenHandle(uint ver, IntPtr r, out uint outVer, out IntPtr handle);
public static string Open() {
  uint v; IntPtr h;
  int rc = WlanOpenHandle(2, IntPtr.Zero, out v, out h);
  if (rc != 0) return "WlanOpenHandle rc=0x" + rc.ToString("X8");
  return "open ok ver=" + v;
}
'@
try {
  $null = Add-Type -MemberDefinition $apiSrc -Name Wa -Namespace W5W -PassThru -Language CSharp -EA Stop
  Write-Output ('  ' + [W5W.Wa]::Open())
} catch { Write-Output ('  wlanapi probe failed: ' + (One $_.Exception.Message)) }

Sec '9_WLANSVC_TRIGGER_AND_DEPS_NOW'
foreach ($k in @('wlansvc','dot3svc')) {
  $p = Join-Path $SVCROOT $k
  if (-not (Test-Path $p)) { Write-Output ('  MISSING ' + $k); continue }
  $ki = Get-Item $p
  foreach ($vn in $ki.GetValueNames()) {
    if ($vn -notin @('Type','Start','DependOnService','RequiredPrivileges','ObjectName','ImagePath','Group','ServiceSidType')) { continue }
    $raw = $ki.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $disp = if ($raw -is [array]) { ($raw -join ',') } else { [string]$raw }
    Write-Output ('  ' + $k + '\' + $vn + ' = ' + (One $disp))
  }
}

Sec 'DONE'
Write-Output '  probe5 complete'
