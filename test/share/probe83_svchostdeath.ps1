# ============================================================
# probe83_svchostdeath.ps1 -- svchost CAN load and enter both service DLLs (probe82), so why does the
# service never report RUNNING (1053)? Two possibilities are left and they need different fixes:
#
#   (A) the service host process DIES -- a delay-loaded call hits one of the names probe82 proved are
#       missing in this image (deviceassociation.dll, IpNatHlpClient.dll, ext-ms-win-networking-wlanstorage,
#       ext-ms-win-devmgmt-policy, ext-ms-win-shell-embeddedmode, ext-ms-win-wlan-grouppolicy,
#       ext-ms-win-net-cmvpn, ext-ms-win-networking-nlaapi). On the host those ext-ms names are backed by
#       policymanager.dll / embeddedmodesvcapi.dll / wlgpclnt.dll / cmintegrator.dll / nlaapi.dll
#       (build/scratch/t_apiset_host.ps1), so the fix is a file list. A crash also leaves evidence:
#       WER LocalDumps writes a minidump, and the Application log records an Application Error with the
#       exception code.
#   (B) the service host returns from ServiceMain on its own without ever calling SetServiceStatus with
#       RUNNING -- no crash, no dump, no exit-code event; the fix is then whatever the service refuses to
#       do in PE (device absence, RPC, storage), not a file.
#
# This probe separates them with three independent instruments, cheapest first:
#   1. the event log, IF the PE image carries wevtapi + a running EventLog service: the SCM writes 7031/7034
#      ("terminated unexpectedly") and Application Error writes the faulting module + exception code;
#   2. a 100 ms-lifetime watch on the svchost children the SCM creates for wlansvc/wcmsvc -- a child that
#      appears and vanishes is a death, a child that stays is a service still booting itself;
#   3. WER LocalDumps for svchost.exe turned ON before the start attempt, so a crash leaves a .dmp we can
#      pull over the LAN and read the exception stream from (no debugger needed).
#
# Writes: HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting(+LocalDumps\svchost.exe), the directory
#         X:\pe_dumps, and StartServiceW on wlansvc/wcmsvc. All of it is the ramdisk and evaporates on
#         reboot. It also READS the offline-hive-loaded System registry through reg.exe only.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe83_svchostdeath.ps1 -RemotePath X:/p83.ps1 -StagingB64 X:/p83.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }
function ErrName([int]$e) {
  $m = @{ 5 = 'ACCESS_DENIED'; 87 = 'INVALID_PARAMETER'; 1008 = 'ALREADY_RUNNING'; 1053 = 'TIMEOUT';
          1056 = 'ALREADY_STARTED'; 1057 = 'INVALID_NAME'; 1058 = 'DISABLED'; 1062 = 'SERVICE_NOT_RUNNING';
          1068 = 'DEPENDENCY_FAILED'; 1069 = 'LOGON_FAILED'; 126 = 'MOD_NOT_FOUND'; 193 = 'NOT_A_WIN32_APP' }
  if ($m.ContainsKey($e)) { return ('' + $e + '_' + $m[$e]) }
  return '' + $e
}
$S32 = 'X:\Windows\System32'
$REG = 'HKLM\SYSTEM\CurrentControlSet\Services'
$DUMP = 'X:\pe_dumps'
$VERD = @{ evtlog = 'unknown'; newpid = ''; dump = 'none'; wer = 'unknown'; starts = ''; apiset = '' }

# ---------- SCM access (same proven marshalling as probe49/50) ----------
if (-not ('P83.SCM' -as [type])) {
  Add-Type -Namespace P83 -Name SCM -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack = 4)]
public struct SS {
  public int dwServiceType; public int dwCurrentState; public int dwControlsAccepted;
  public int dwWin32ExitCode; public int dwServiceSpecificExitCode; public int dwCheckPoint; public int dwWaitHint;
}
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern IntPtr OpenSCManagerW(IntPtr machine, IntPtr database, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr OpenServiceW(IntPtr scm, string name, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CloseServiceHandle(IntPtr h);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceStatus(IntPtr svc, ref SS st);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr svc, int numArgs, IntPtr argv);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ControlService(IntPtr svc, int cmd, ref SS st);
public static int LastErr = 0;
public static IntPtr OpenScm(int access) {
  IntPtr h = OpenSCManagerW(IntPtr.Zero, IntPtr.Zero, access);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return h;
}
public static IntPtr OpenSvc(IntPtr scm, string name, int access) {
  IntPtr h = OpenServiceW(scm, name, access);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return h;
}
public static string Status(IntPtr svc) {
  SS s = new SS();
  bool ok = QueryServiceStatus(svc, ref s);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok) { return "QSS_FAIL=" + LastErr; }
  return "state=" + s.dwCurrentState + " ctrl=0x" + s.dwControlsAccepted.ToString("X") +
         " win32err=" + s.dwWin32ExitCode + " svcerr=" + s.dwServiceSpecificExitCode +
         " checkpoint=" + s.dwCheckPoint + " waithint=" + s.dwWaitHint;
}
public static bool StartNow(IntPtr svc) {
  bool r = StartServiceW(svc, 0, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
public static bool StopNow(IntPtr svc) {
  SS s = new SS();
  bool r = ControlService(svc, 1, ref s);   // SERVICE_STOP
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
'@ -EA Stop
}
$script:hScm = [IntPtr]::Zero
foreach ($acc in @(0xF003F, 0x0001)) {
  $hh = [P83.SCM]::OpenScm($acc)
  if ($hh -ne [IntPtr]::Zero) { $script:hScm = $hh; break }
}
function HandleOf([string]$name) {
  if ($script:hScm -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
  foreach ($a in @(0xF01FF, 0x0017, 0x0005, 0x0001)) {
    $hh = [P83.SCM]::OpenSvc($script:hScm, $name, $a)
    if ($hh -ne [IntPtr]::Zero) { return $hh }
  }
  return [IntPtr]::Zero
}
# ---------- loader helper for the apiset gap table ----------
if (-not ('P83.W' -as [type])) {
  Add-Type -Namespace P83 -Name W -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, int flags);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeLibrary(IntPtr h);
public static int LastErr = 0;
// Try the name as a System32 file first, then through the search path / apiset schema, and never leave
// the module loaded. "NULL=126" is ERROR_MOD_NOT_FOUND: either the file is not there or the apiset has no
// mapping to a DLL that is.
public static string TryLoad(string nm) {
  string full = "X:\\Windows\\System32\\" + nm;
  IntPtr h = LoadLibraryExW(full, IntPtr.Zero, 0x8);
  if (h == IntPtr.Zero) { h = LoadLibraryExW(nm, IntPtr.Zero, 0); }
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (h == IntPtr.Zero) { return "NULL=" + LastErr; }
  string t = "OK";
  FreeLibrary(h);
  return t;
}
'@ -EA Stop
}
function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim() -replace '\\0', ';')
    }
  }
  return ''
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function FileSig([string]$p) {
  try { $i = Get-Item $p -EA Stop; return ('' + [int]($i.Length / 1024) + 'KB ' + $i.LastWriteTime.ToString('yyyy-MM-dd')) }
  catch { return 'ABSENT' }
}

O '== 0 can this PE even keep a log? (wevtapi + EventLog service + WER binaries) =='
foreach ($f in @('wevtapi.dll', 'WerFault.exe', 'svchost.exe', 'wermgr.exe', 'apisetschema.dll')) {
  O ('  FILE ' + $f + ' = ' + (FileSig (Join-Path $S32 $f)))
}
O ('  STATE EventLog = ' + (St 'EventLog') + '  EventSystem = ' + (St 'EventSystem'))
try {
  $ver = (Get-Item (Join-Path $S32 'apisetschema.dll') -EA Stop).VersionInfo.FileVersion
  O ('  APISETSCHEMA version = ' + (ToAscii "$ver"))
} catch { O '  APISETSCHEMA version unreadable' }
$logs = @()
try {
  $logs = @(Get-WinEvent -ListLog * -EA SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })
  O ('  LOGS with records = ' + $logs.Count)
  foreach ($lg in ($logs | Select-Object -First 12)) {
    O ('    LOG ' + (ToAscii $lg.LogName) + ' records=' + $lg.RecordCount + ' file=' + (ToAscii $lg.LogFilePath))
  }
} catch { O ('  Get-WinEvent unavailable: ' + (ToAscii $_.Exception.Message)) }

O '== 1 WER LocalDumps ON for svchost.exe, before we start anything =='
if (-not (Test-Path $DUMP)) { try { New-Item -ItemType Directory -Path $DUMP -Force -EA Stop | Out-Null } catch { O ('  mkdir fail: ' + (ToAscii $_.Exception.Message)) } }
$WER = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
try {
  if (-not (Test-Path $WER)) { New-Item $WER -Force -EA Stop | Out-Null }
  Set-ItemProperty $WER 'DontShowUI' 1 -Type DWord -Force -EA Stop
  $ld = Join-Path $WER 'LocalDumps'
  if (-not (Test-Path $ld)) { New-Item $ld -Force -EA Stop | Out-Null }
  $sk = Join-Path $ld 'svchost.exe'
  if (-not (Test-Path $sk)) { New-Item $sk -Force -EA Stop | Out-Null }
  Set-ItemProperty $sk 'DumpFolder' $DUMP -Type String -Force -EA Stop
  Set-ItemProperty $sk 'DumpType' 1 -Type DWord -Force -EA Stop     # minidump: carries the exception stream
  Set-ItemProperty $sk 'DumpCount' 2 -Type DWord -Force -EA Stop
  $VERD.wer = 'on'
  O ('  WER key written: ' + (ToAscii $sk) + ' DumpFolder=' + $DUMP + ' DumpType=1 (minidump, ~100KB: the X: ramdisk has no room for a full dump, and the exception stream is all we need)')
} catch { $VERD.wer = 'fail:' + (ToAscii $_.Exception.Message); O ('  WER setup failed: ' + (ToAscii $_.Exception.Message)) }
$pre = @(Get-ChildItem $DUMP -Recurse -File -EA SilentlyContinue)
O ('  dumps already in ' + $DUMP + ' = ' + $pre.Count)

# ---------- 2 start it and watch the child ----------
function StartAndWatch([string]$svc) {
  $before = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
  $h = HandleOf $svc
  if ($h -eq [IntPtr]::Zero) { O ('  START ' + $svc + ' no handle (scm=' + [P83.SCM]::LastErr + ')'); return 'NOHANDLE' }
  O ('  START ' + $svc + ' before: svchost procs=' + $before.Count + ' state=' + (St $svc))
  $r = [P83.SCM]::StartNow($h)
  $e = [P83.SCM]::LastErr
  O ('    StartServiceW ok=' + $r + ' err=' + (ErrName $e))
  # one CIM pass right away: it is slow, so do it while a just-created child may still be alive
  $cimNow = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)
  foreach ($c in ($cimNow | Where-Object { $before -notcontains "$($_.ProcessId)" })) {
    O ('    NEW pid=' + $c.ProcessId + ' ppid=' + $c.ParentProcessId + ' cmd=[' + (ToAscii $c.CommandLine) + ']')
  }
  # then a 100 ms-lifetime watch for ~6 s: appears-and-vanishes = death, stays = still working
  $lives = @{}
  for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 100
    $cur = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
    foreach ($cp in ($cur | Where-Object { $before -notcontains $_ })) {
      if (-not $lives.ContainsKey($cp)) { $lives[$cp] = @{ first = $i; last = $i } } else { $lives[$cp].last = $i }
    }
  }
  $lastSeen = @(Get-Process svchost -EA SilentlyContinue | ForEach-Object { "$($_.Id)" })
  foreach ($k in @($lives.Keys)) {
    $still = if ($lastSeen -contains $k) { 'ALIVE' } else { 'GONE' }
    O ('    LIFETIME pid=' + $k + ' firstPoll=' + $lives[$k].first + ' lastPoll=' + $lives[$k].last +
       ' of 60 -> ' + $still)
  }
  if (-not $lives.Count) { O '    LIFETIME none of the 60 polls saw a new svchost (child died inside 100ms, or never spawned)' }
  $q = [P83.SCM]::Status($h)
  O ('    SCM now says ' + $svc + ': ' + $q + ' state=' + (St $svc))
  [void][P83.SCM]::CloseServiceHandle($h)
  $verdict = $(if (-not $lives.Count) { 'nochild' } else {
    $gone = @(@($lives.Keys) | Where-Object { $lastSeen -notcontains $_ }).Count
    if ($gone -eq $lives.Count) { 'allDied' } elseif ($gone -eq 0) { 'allAlive' } else { 'mixed' }
  })
  O ('    WATCHRESULT ' + $svc + ' new=' + $lives.Count + ' died=' + $(if ($lives.Count) { @(@($lives.Keys) | Where-Object { $lastSeen -notcontains $_ }).Count } else { 0 }) + ' -> ' + $verdict)
  return $verdict
}

O '== 2 wlansvc: start through the SCM and watch its host process =='
$wv = StartAndWatch 'wlansvc'
O '== 3 wcmsvc: same =='
$cv = StartAndWatch 'wcmsvc'
# the control: dot3svc has the same shape and IS running in this image, so start something that is known
# good and see what a healthy service looks like on these same instruments (it is already Running, so this
# only prints the SCM status; starting a running service costs 1056).
$hdot = HandleOf 'dot3svc'
if ($hdot -ne [IntPtr]::Zero) {
  O ('  CTRL dot3svc ' + [P83.SCM]::Status($hdot) + ' state=' + (St 'dot3svc'))
  [void][P83.SCM]::CloseServiceHandle($hdot)
}

O '== 4 evidence left behind: dumps, .wer reports, and the event log =='
$dumps = @(Get-ChildItem $DUMP -Recurse -File -EA SilentlyContinue)
O ('  DUMPDIR ' + $DUMP + ' files=' + $dumps.Count)
foreach ($d in $dumps) { O ('    DUMP ' + (ToAscii $d.Name) + ' ' + [int]($d.Length / 1024) + 'KB ' + $d.LastWriteTime.ToString('HH:mm:ss')) }
if ($dumps.Count) { $VERD.dump = $dumps.Count + 'files' }
foreach ($rd in @('X:\ProgramData\Microsoft\Windows\WER\ReportQueue', 'X:\ProgramData\Microsoft\Windows\WER\ReportArchive',
                  'X:\windows\System32\winevt\Logs')) {
  $items = @(Get-ChildItem $rd -Recurse -File -EA SilentlyContinue)
  if ($items.Count) {
    O ('  DIR ' + $rd + ' files=' + $items.Count)
    foreach ($x in ($items | Select-Object -First 8)) { O ('    ' + (ToAscii $x.Name) + ' ' + $x.Length + 'B ' + $x.LastWriteTime.ToString('MM-dd HH:mm')) }
  } else { O ('  DIR ' + $rd + ' nothing') }
}
# try regardless of what -ListLog reported: a PE that never touched the log can show 0 records and still
# answer a direct Get-WinEvent once we have started a service.
if ($logs.Count -ge 0) {
  foreach ($lg in @('System', 'Application', 'Setup')) {
    try {
      $ev = @(Get-WinEvent -LogName $lg -MaxEvents 120 -EA Stop)
      $rel = @($ev | Where-Object { ("$($_.ProviderName)" -match '(?i)Service Control|Application Error|Windows Error|Restart') -or ("$($_.Message)" -match '(?i)wlansvc|wcmsvc|svchost|wlan') })
      O ('  EVT ' + $lg + ' total=' + $ev.Count + ' relevant=' + $rel.Count)
      foreach ($x in ($rel | Select-Object -First 12)) {
        $msg = ((("$($x.Message)") -replace '\s+', ' ')).Substring(0, [Math]::Min(220, "$($x.Message)".Length))
        O ('    ' + $x.TimeCreated.ToString('HH:mm:ss') + ' id=' + $x.Id + ' lvl=' + $x.LevelDisplayName +
           ' src=' + (ToAscii $x.ProviderName) + ' | ' + (ToAscii $msg))
      }
      $VERD.evtlog = 'yes'
    } catch { $VERD.evtlog = 'no'; O ('  EVT ' + $lg + ' unreadable: ' + (ToAscii $_.Exception.Message)) }
  }
}

O '== 5 the delay-load gaps: who backs them on the host, and is that file in this PE? =='
# host answers from build/scratch/t_apiset_host.ps1 (19041 build; ext-ms names are not files, they are
# schema mappings -- the file listed after -> is what the loader actually mapped the apiset to)
$pairs = @(
  @('ext-ms-win-devmgmt-policy-l1-1-0.dll',        'policymanager.dll'),
  @('ext-ms-win-shell-embeddedmode-l1-1-0.dll',    'embeddedmodesvcapi.dll'),
  @('ext-ms-win-wlan-grouppolicy-l1-1-0.dll',      'wlgpclnt.dll'),
  @('ext-ms-win-net-cmvpn-l1-1-0.dll',             'cmintegrator.dll'),
  @('ext-ms-win-networking-nlaapi-l1-1-0.dll',     'nlaapi.dll'),
  @('ext-ms-win-networking-wlanstorage-l1-1-0.dll', '(no mapping even on the host: Win11-only apiset)'),
  @('deviceassociation.dll',                       'deviceassociation.dll'),
  @('IpNatHlpClient.dll',                          'IpNatHlpClient.dll')
)
$missCount = 0
foreach ($pr in $pairs) {
  $hostFile = $pr[1]
  $present = if ($hostFile -match '\.dll$') { "$(Test-Path (Join-Path $S32 $hostFile))" } else { 'n/a' }
  $loadApi = ''
  try {
    $loadApi = [P83.W]::TryLoad($pr[0])
  } catch { $loadApi = 'NOCCLASS' }
  O ('  GAP ' + $pr[0] + ' host backs it with [' + $hostFile + '] presentInPE=' + $present + ' loadInPE=' + $loadApi)
  if ($present -eq 'False' -or $loadApi -match 'NULL') { $missCount++ }
}
$VERD.apiset = 'gaps=' + $missCount + '/' + $pairs.Count

O '== 6 VERDICT =='
$VERD.newpid = 'wlansvc=' + $wv + ',wcmsvc=' + $cv
$VERD.starts = 'wl=' + $wv + ' wc=' + $cv
O ('P83 VERDICT wer=' + $VERD.wer + ' evtlog=' + $VERD.evtlog + ' watch=' + $VERD.newpid +
   ' dumps=' + $VERD.dump + ' apisetGaps=' + $VERD.apiset +
   ' dot3=' + (St 'dot3svc') + ' dhcp=' + (St 'Dhcp'))
if ($VERD.newpid -match 'allDied' -and $VERD.dump -ne 'none') {
  O 'P83 READING: (A) CONFIRMED -- the SCM child dies and WER wrote a dump. Pull the .dmp (LAN ssh is fast) and the exception code decides: 0xC0000135 = a delay-load name is missing (bake the file list above), 0xC0000409/0xC0000005 = the service code itself faults on PE state. Fix = add the missing host files (policymanager/embeddedmodesvcapi/wlgpclnt/cmintegrator/deviceassociation/IpNatHlpClient) and re-bake.'
}
elseif ($VERD.newpid -match 'allDied') {
  O 'P83 READING: the child dies but WER wrote nothing -- either WER is not wired in this image or the exit was clean (ServiceMain returned). Next: check the event log lines above for 7031/7034, and if silent, instrument by making the service DLL unloadable on purpose (rename test) to see whether the SCM answer changes at all.'
}
elseif ($VERD.newpid -match 'nochild') {
  O 'P83 READING: no svchost child appeared in 60 polls -- the SCM is not even creating the process, so the answer is in the service record (Start/Type/ObjectName/error-control), not in the DLL. Re-read the QSS line above and compare with dot3svc.'
}
elseif ($VERD.newpid -match 'allAlive') {
  O 'P83 READING: the child SURVIVES but never reports RUNNING -> (B): wlansvc/wcmsvc are inside ServiceMain doing something that never finishes in PE (RPC call, device enumeration, storage). Check what the surviving host is waiting on: get its thread stacks next.'
}
else {
  O 'P83 READING: mixed result -- look at the per-PID LIFETIME lines and the EVT/DUMP lines together.'
}
O 'P83 END'
