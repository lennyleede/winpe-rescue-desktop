# ============================================================
# probe86_wer_arm_and_trigger.ps1 -- give wlansvc a crash dump to leave behind, or prove it does not
# crash at all.
#
# WHY
# probe85 ran cleanly in the field but found NOTHING to parse (build/scratch/p85_push_1010.txt):
#   pe_dumps files=0 / X: free MB=485 / WER LocalDumps svchost.exe: (empty) / after the re-trigger svc=Stopped
# Two reasons, both mundane and both fixable here:
#   1. X: is the RAMDISK. It is rebuilt at every boot, so X:\pe_dumps did not exist on this boot, and WER
#      LocalDumps with a DumpFolder that does not exist writes nothing at all (no error, no event). The keys
#      probe83/probe84 wrote are gone too -- that is why the readback line was empty.
#   2. probe85 only re-armed when it saw no exception stream, and it never created the folder.
# It also asked a sharper question than "what is the code": the one dump we DID pull
# (build/scratch/drydumps/pe_svchost_1328.dmp, decoded by probe85 and build/scratch/p85_threads3.ps1) is the
# wcmsvc host -- 42 modules include wcmsvc.dll and NOT wlansvc.dll -- so wlansvc has still never produced a
# dump. Either its svchost dies in a way WER misses, or it does not crash at all and just returns an error
# code (0x800C0006), which would mean the remaining gap is the delay-load layer, not a faulting instruction.
# This probe decides which, by running the SAME trigger for a control service we KNOW crashes (wcmsvc,
# probe84 record D: win32err=1067) and for wlansvc, with WER armed properly in both cases:
#   * wcmsvc dumps and wlansvc does not  -> wlansvc's ServiceMain returns an error, it does not fault.
#     Stop chasing dumps; bake the six missing delay-load backing files (probe82's list).
#   * both dump                           -> read wlansvc's code/params/stack with probe85 or on the host.
#   * neither dumps, WerFault never runs   -> WER is not usable in this PE; switch to the loader snapshot.
#
# FIRST FIELD RUN (2026-10-10 21:1x, build/scratch/p86_push_1010.txt) -- answered it, and the control moved:
#   wlansvc: StartServiceW ok=True, poll0 state=2 hostpid=1328 (svchost -k LocalSystemNetworkRestricted -p),
#            poll1 state=1 win32=0x800C0006, WerFault polls=0, dumps=0   => it RAN and did NOT fault.
#   wcmsvc : StartServiceW ok=False err=1068 ERROR_DEPENDENCY_NOT_RUNNING, never got a pid => the control that
#            probe84 saw crash with 1067 is now refused before any process exists, so it cannot validate WER.
#   folder/keys were fine this time (writable=yes, readback DumpFolder/DumpCount/DumpType all present), and
#   0x800C0006 decodes on this machine's message table as "the system cannot find the specified object"
#   (build/scratch/fm2_out_utf8.txt) -- an environment rejection, consistent with the WDI framework still being
#   absent from this disc (probe81). Consequence: this probe is re-run on the WDI-baked ISO before any
#   wlansvc.dll-side baking is decided, which is why RunOne now RECORDS kind= per service. The 1068 itself is
#   NOT a cold dependency (run 2, build/scratch/p86_push_1010b.txt: RpcSs and Nsi were both state=4 and wcmsvc
#   still answered 1068 after the retry), so section 1b also prints QueryServiceConfigW's own Deps=[..] for
#   wlansvc/wcmsvc/RpcSs/Nsi -- reg.exe can truncate a REG_MULTI_SZ display, the SCM record cannot.
#
# FIELD RUN 4 (2026-10-10 20:5x, build/scratch/p86_push_1010d.txt) -- clean, and the two open threads it left
#   are what sections 1c and the P86 DISC line are for:
#     wlansvc  start=yes hostpids=[1328] endState=1 win32=0x800C0006 kind=returned-error dumps+0 werfaultPolls=0
#     wcmsvc   start=no  err=1068 retries=1 hostpids=[]               kind=refused-by-scm
#     QFC wcmsvc Deps=[RpcSs;] while RpcSs state=4 hostpid=1240 AND Nsi state=4 hostpid=1664 => the 1068 is NOT
#     explained by anything at dependency level 1, so NoteSvc now walks the whole closure (RpcSs -> RpcEptMapper,
#     DcomLaunch; Nsi -> NsiProxy) and prints StatusEx + Deps for every node.
#   And P86 DISC turned out to be load-bearing in a way I did not expect: X:\BUILD_TAG.txt (probe42 section 1) and
#   the new FIX line show runs 1-4 + the 21:38/21:49 acceptance passes were all ONE boot of the 2026-10-10 15:21
#   disc, which ALREADY has the WDI framework baked (wdi_paramkey=2/2, both .cat, and the AX211 enumerates code 0
#   with Netwtw14 Running -- code 37 is gone). What that disc does NOT have is the service-layer alignment
#   (wlansvc_type=0x20, wcmsvc_obj=[LocalService], delay_dll=4/7). So 0x800C0006 here is a NEW-driver-layer /
#   OLD-service-layer measurement, and the closure proves the 1068 is not explained by level 1 OR level 2:
#   CLOSURE RpcSs / RpcEptMapper / DcomLaunch are all state=4 while wcmsvc stays 1068 with Deps=[RpcSs;].
#
# Writes: creates X:\pe_dumps, writes WER LocalDumps for svchost.exe (DumpType=1 MiniDump -- the shape that
#         produced the complete stream 3/4/5/6 set in the reference dump, and 762 KB instead of a full
#         memory dump on a 485 MB RAMDISK), starts/stops wcmsvc and wlansvc through the SCM.
#         All on the RAMDISK, gone on reboot. Nothing touches the service records.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe86_wer_arm_and_trigger.ps1 -RemotePath X:/p86.ps1 -StagingB64 X:/p86.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# Then pull whatever appeared (remote path MUST be single-quoted or Git Bash eats the backslashes):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_pull_from_pe.ps1 `
#     -RemoteFile 'X:\pe_dumps\svchost.exe.PID.dmp' -LocalFile 'build/scratch/drydumps/pe_XXX.dmp' `
#     -Staging 'X:\pull86.b64' -Target administrator@192.168.0.107 -Port 22
# and parse it on the host:
#   powershell -NoProfile -ExecutionPolicy Bypass -File build/scratch/t_p85_dryrun.ps1 `
#     -RealDump build/scratch/drydumps/pe_XXX.dmp
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }

# ---------- SCM API, the marshalling probe49/50/83/84 proved in this PE ----------
if (-not ('P86.SCM' -as [type])) {
  Add-Type -Namespace P86 -Name SCM -MemberDefinition @'
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
// Explicit ...W entry point, so no CharSet/A-W mangling is involved; every string is read by hand below.
// "ref int needed" + an 8 KB buffer: 16 KB gives 1783 ERROR_INVALID_USER_BUFFER, "out int" throws.
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, int bufsize, ref int needed);
// SERVICE_STATUS_PROCESS x64 = SERVICE_STATUS (7 DWORDs = 28 bytes) then dwProcessId at +28. This is how
// the host process id is read WITHOUT racing a poll against a process that lives ~150 ms.
// NOTE the second parameter is SC_STATUS_TYPE (0 = SC_STATUS_TYPE_INFO) and it is NOT optional: declaring
// this without it compiles and runs, then fails with err=124 ERROR_INVALID_LEVEL (the buffer pointer lands
// in InfoLevel). Caught by build/scratch/t_p86_statusex_host.ps1 before any field round trip.
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceStatusEx(IntPtr svc, int infoLevel, IntPtr buf, int size, ref int needed);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr svc, int numArgs, IntPtr argv);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ControlService(IntPtr svc, int cmd, ref SS st);
public static int LastErr = 0;
static string Uni(IntPtr p) {
  if (p == IntPtr.Zero) { return ""; }
  string s = System.Runtime.InteropServices.Marshal.PtrToStringUni(p);
  return s == null ? "" : s;
}
// DependOnService is a double-null-terminated block, so it has to be walked name by name -- a single
// PtrToStringUni would stop at the first name and hide exactly the second dependency this probe needs.
static string BlockOut(IntPtr p) {
  if (p == IntPtr.Zero) { return ""; }
  System.Text.StringBuilder sb = new System.Text.StringBuilder();
  IntPtr cur = p;
  for (int guard = 0; guard < 64; guard++) {
    string s = Uni(cur);
    if (s.Length == 0) { break; }
    sb.Append(s); sb.Append(";");
    cur = new IntPtr(cur.ToInt64() + (long)(s.Length + 1) * 2L);
  }
  return sb.ToString();
}
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
public static string StatusEx(IntPtr svc) {
  IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(64);
  for (int i = 0; i < 64; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
  int needed = 0;
  bool ok = QueryServiceStatusEx(svc, 0, buf, 64, ref needed);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok) { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); return "QSSE_FAIL=" + LastErr; }
  int type = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 0);
  int state = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 4);
  int ctrl = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 8);
  int win32 = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 12);
  int svcerr = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 16);
  int cp = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 20);
  int wh = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 24);
  int pid = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 28);
  System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
  // win32 is printed BOTH ways: 1067=PROCESS_ABORTED (the host crashed) and a bare 0x800C0006 (the service
  // reported an HRESULT of its own) look nothing alike in decimal.
  return "state=" + state + " type=0x" + type.ToString("X") + " ctrl=0x" + ctrl.ToString("X") +
         " win32=" + win32 + "/0x" + win32.ToString("X8") + " svcerr=" + svcerr +
         " checkpoint=" + cp + " waithint=" + wh + " hostpid=" + pid;
}
public static bool StartNow(IntPtr svc) {
  bool r = StartServiceW(svc, 0, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
// The SCM's OWN view of the service record, which is what decides 1068. reg.exe can truncate a REG_MULTI_SZ
// display, so a printed "DependOnService=[RpcSs]" is not proof there is only one dependency -- and the field
// run showed wcmsvc answering 1068 while BOTH RpcSs and Nsi were state=4. DumpConfig walks the whole
// double-null block, so it cannot miss a second name. Marshalling copied from probe84, where it worked in PE.
public static string DumpConfig(IntPtr svc) {
  // The buffer must outlive every ReadIntPtr: an early FreeHGlobal is a use-after-free, which in PS 5.1 is a
  // corrupted-state exception that kills powershell.exe with no message at all.
  int needed = 0;
  int size = 8000;
  IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
  for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
  bool ok = QueryServiceConfigW(svc, buf, size, ref needed);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok && LastErr == 123 && needed > 8 && needed < 60000) {
    System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
    size = needed + 64;
    buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
    for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
    ok = QueryServiceConfigW(svc, buf, size, ref needed);
    LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  }
  if (!ok) { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); return "QFC_FAIL=" + LastErr; }
  // QUERY_SERVICE_CONFIG x64: Type(0) Start(4) ErrCtl(8) [pad] Img(16) Group(24) TagId(32) Deps(40) StartName(48)
  long type = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 0) & 0xFFFFFFFFL;
  long start = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 4) & 0xFFFFFFFFL;
  string grp = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 24));
  string img = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 16));
  string deps = BlockOut(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 40));
  string obj = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 48));
  System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
  return "Type=0x" + type.ToString("X") + " Start=0x" + start.ToString("X") + " Group=[" + grp + "]" +
         " Obj=[" + obj + "] Deps=[" + deps + "] Img=[" + img + "]";
}
public static bool StopNow(IntPtr svc) {
  SS s = new SS();
  bool r = ControlService(svc, 1, ref s);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
'@ -EA Stop
}
$script:hScm = [IntPtr]::Zero
foreach ($acc in @(0xF003F, 0x0001)) {
  $hh = [P86.SCM]::OpenScm($acc)
  if ($hh -ne [IntPtr]::Zero) { $script:hScm = $hh; break }
}
if ($script:hScm -eq [IntPtr]::Zero) { O ('FATAL OpenSCManagerW err=' + [P86.SCM]::LastErr); exit 1 }
function HandleOf([string]$name) {
  foreach ($a in @(0xF01FF, 0x0017, 0x0005, 0x0001)) {
    $hh = [P86.SCM]::OpenSvc($script:hScm, $name, $a)
    if ($hh -ne [IntPtr]::Zero) { return $hh }
  }
  return [IntPtr]::Zero
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function DumpNames {
  $d = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue | Sort-Object LastWriteTime)
  $s = ''
  foreach ($f in $d) { $s += ($f.Name + '=' + [int]($f.Length / 1KB) + 'KB ') }
  if ($s -eq '') { $s = '(none)' }
  return $s.Trim()
}

O '== 0 the pieces WER needs, and whether they exist in this PE =='
$have = @(Get-ChildItem 'X:\windows\system32' -Filter 'Wer*.exe' -EA SilentlyContinue | ForEach-Object { $_.Name })
O ('  Wer binaries: ' + (($have | Sort-Object -Unique) -join ',') + ' (probe84 saw WerFault wake up, so the writers exist)')
O ('  WerSvc state=' + (St 'WerSvc') + '  wermgr running=' + $(if (@(Get-Process wermgr -EA SilentlyContinue).Count) { 'yes' } else { 'no' }))
$freeMB = -1
foreach ($x in @(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='X:'" -EA SilentlyContinue)) { $freeMB = [int]($x.FreeSpace / 1MB) }
O ('  X: free MB=' + $freeMB)

O '== 1 create the folder FIRST, then arm LocalDumps (a DumpFolder that does not exist writes nothing) =='
try {
  if (-not (Test-Path 'X:\pe_dumps')) { New-Item -ItemType Directory -Path 'X:\pe_dumps' -Force -EA Stop | Out-Null }
  O ('  folder created/exists, writable=' + $(try { Set-Content 'X:\pe_dumps\wtest.tmp' 'x' -EA Stop; Remove-Item 'X:\pe_dumps\wtest.tmp' -Force -EA SilentlyContinue; 'yes' } catch { 'NO: ' + $_.Exception.Message }))
} catch { O ('  FATAL cannot make X:\pe_dumps: ' + (ToAscii $_.Exception.Message)) }
$wk = 'HKLM:\SYSTEM\Microsoft\Windows\Windows Error Reporting\LocalDumps\svchost.exe'
try {
  $k = 'HKLM:\SYSTEM\Microsoft\Windows\Windows Error Reporting'
  if (-not (Test-Path (Join-Path $k 'LocalDumps'))) { New-Item (Join-Path $k 'LocalDumps') -Force -EA Stop | Out-Null }
  if (-not (Test-Path $wk)) { New-Item $wk -Force -EA Stop | Out-Null }
  Set-ItemProperty $wk 'DumpFolder' 'X:\pe_dumps' -Type String -Force -EA Stop
  Set-ItemProperty $wk 'DumpCount' 2 -Type DWord -Force -EA Stop
  Set-ItemProperty $wk 'DumpType' 1 -Type DWord -Force -EA Stop
} catch { O ('  arm failed: ' + (ToAscii $_.Exception.Message)) }
$wr = ''
foreach ($vn in @(try { @((Get-Item $wk -EA Stop).GetValueNames()) } catch { @() })) {
  $wr += ($vn + '=' + (Get-ItemProperty $wk -Name $vn).$vn + ' ')
}
O ('  readback svchost.exe: ' + (ToAscii $wr))
$g = ''
foreach ($nm in @('wlansvc', 'wcmsvc')) {
  $hh = HandleOf $nm
  if ($hh -ne [IntPtr]::Zero) {
    $g += ($nm + '[' + (St $nm) + ' ' + ([P86.SCM]::StatusEx($hh)) + '] ')
    [void][P86.SCM]::CloseServiceHandle($hh)
  } else { $g += ($nm + '[OPEN_FAIL] ') }
}
O ('  services before: ' + (ToAscii $g))

# ---- dependencies, because 1068 is the SCM refusing to start something wlansvc/wcmsvc needs ----
O '== 1b the dependency chain (field run 1: wcmsvc answered err=1068 ERROR_DEPENDENCY_NOT_RUNNING) =='
foreach ($nm in @('wlansvc', 'wcmsvc')) {
  $deps = ''
  $o = @(& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $nm) /v DependOnService 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) { if ($l -match 'REG_MULTI_SZ\s+(.*)$') { $deps = (($matches[1] -replace '\\0', ',') -replace '\s+', ' ').Trim() } }
  O ('  ' + $nm + ' DependOnService=[' + (ToAscii $deps) + ']')
}
# Nsi is on the real machine's wcmsvc list (build/scratch/q56_host.txt: RpcSs,NSI); the bake deliberately drops
# it. If the service or nsi.dll is missing in the PE, adding it back would CAUSE a permanent 1068, so measure first.
foreach ($d in @('RpcSs', 'Nsi', 'Dnscache', 'netprofm', 'nsi.dll')) {
  $line = ''
  if ($d -like '*.dll') {
    $line = ('file=' + $(if (Test-Path -LiteralPath ('X:\windows\system32\' + $d)) { 'present' } else { 'ABSENT' }))
  } else {
    $hh = HandleOf $d
    if ($hh -eq [IntPtr]::Zero) {
      $line = 'key ABSENT (err=' + [P86.SCM]::LastErr + ')'
    } else {
      $line = (ToAscii ([P86.SCM]::StatusEx($hh)))
      $st = ''
      $o = @(& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $d) /v Start 2>&1 | ForEach-Object { "$_" })
      foreach ($l in $o) { if ($l -match 'REG_DWORD\s+(0x[0-9a-fA-F]+)') { $st = $matches[1] } }
      $line += ' Start=' + $st
      [void][P86.SCM]::CloseServiceHandle($hh)
    }
  }
  O ('  DEP ' + $d + ': ' + $line)
}
function Ensure-Running([string]$nm) {
  $hh = HandleOf $nm
  if ($hh -eq [IntPtr]::Zero) { return 'open-failed' }
  $txt = [P86.SCM]::StatusEx($hh)
  if ($txt -notmatch 'state=4') {
    [void][P86.SCM]::StartNow($hh)
    for ($i = 0; $i -lt 20; $i++) {
      $txt = [P86.SCM]::StatusEx($hh)
      if ($txt -match 'state=4') { break }
      Start-Sleep -Milliseconds 150
    }
  }
  [void][P86.SCM]::CloseServiceHandle($hh)
  return $txt
}
O ('  after Ensure-Running RpcSs: ' + (ToAscii (Ensure-Running 'RpcSs')))
O ('  after Ensure-Running Nsi:    ' + (ToAscii (Ensure-Running 'Nsi')))
O '  (QueryServiceConfigW reads the SCM record: Deps=[a;b;] is walked to the double null, so it cannot be truncated)'
foreach ($nm in @('wlansvc', 'wcmsvc', 'RpcSs', 'Nsi')) {
  $hh = HandleOf $nm
  if ($hh -ne [IntPtr]::Zero) {
    O ('  QFC ' + $nm + ' ' + (ToAscii ([P86.SCM]::DumpConfig($hh))))
    [void][P86.SCM]::CloseServiceHandle($hh)
  } else { O ('  QFC ' + $nm + ' OPEN_FAIL err=' + [P86.SCM]::LastErr) }
}

# ---- 1c the WHOLE closure, not just the first level ----
# Field run 4 left wcmsvc answering 1068 while its own record said Deps=[RpcSs;] and RpcSs was state=4. That is
# only consistent if something *deeper* in the dependency tree is not running: the SCM walks the tree
# transitively (RpcSs -> RpcEptMapper, DcomLaunch; Nsi -> NsiProxy), and section 1b never looked below level 1.
# NoteSvc is breadth/depth-agnostic: a visited map ends the recursion, and every node prints its own
# StatusEx + Deps so the reader can see which name is the one that is not RUNNING.
$script:SEEN = @{}
function NoteSvc([string]$nm) {
  if (-not $nm) { return }
  if (@($script:SEEN.Keys).Count -gt 40) { return }        # runaway guard, the real closure is ~8 services
  if ($script:SEEN.ContainsKey($nm)) { return }
  $script:SEEN[$nm] = 1
  $hh = HandleOf $nm
  if ($hh -eq [IntPtr]::Zero) {
    $e = [P86.SCM]::LastErr
    $hint = 'other'
    if ($e -eq 1060) { $hint = 'not in the boot-time SCM database (service key absent or added after boot)' }
    if ($e -eq 5)    { $hint = 'access denied for this access mask' }
    O ('  CLOSURE ' + $nm + ': OPEN_FAIL err=' + $e + ' => ' + $hint)
    return
  }
  $cfgTxt = ToAscii ([P86.SCM]::DumpConfig($hh))
  $depBlk = ''
  if ($cfgTxt -match 'Deps=\[([^\]]*)\]') { $depBlk = $matches[1] }
  O ('  CLOSURE ' + $nm + ': ' + (ToAscii ([P86.SCM]::StatusEx($hh))) + ' ' + $cfgTxt)
  [void][P86.SCM]::CloseServiceHandle($hh)
  foreach ($nd in (@($depBlk -split ';') | Where-Object { $_ })) { NoteSvc ('' + $nd) }
}
O '== 1c dependency closure (level 2 too: RpcSs -> RpcEptMapper/DcomLaunch, Nsi -> NsiProxy) =='
foreach ($seed in @('wlansvc', 'wcmsvc')) { NoteSvc $seed }
O ('  CLOSURE nodes=' + @($script:SEEN.Keys).Count)

foreach ($nm in @('wlansvc', 'wcmsvc')) {
  $img = ''
  $o = @(& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $nm) /v ImagePath 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) { if ($l -match 'REG_\S+\s+(.*)$') { $img = ($matches[1] -replace '\s+', ' ').Trim() } }
  O ('  ' + $nm + ' ImagePath=[' + (ToAscii $img) + ']')
}

# ---------- the run: same shape for the control service and for wlansvc ----------
# Each run is RECORDED, not just printed. The field result of the first run (build/scratch/p86_push_1010.txt)
# shows why: a dump can only exist if a host process actually faulted, and here neither service reached that
# point (wcmsvc was refused at the SCM with 1068 ERROR_DEPENDENCY_NOT_RUNNING and never got a pid, wlansvc got
# pid 1328, lived ~150 ms and stopped with win32=0x800C0006 -- an HRESULT it reported itself, not a fault).
# So "no dump" alone cannot indict WER; the verdict needs (did a host run?) x (how did it end?) x (a dump?).
$script:REC = @{}
function RunOne([string]$nm) {
  # NAMES ARE CASE-INSENSITIVE IN PowerShell: an earlier version of this function used $R for the record and
  # $r for the StartServiceW boolean, i.e. the SAME variable. The boolean overwrote the hashtable and every
  # later property write threw. Never name anything $r/$R, $v/$V, $b64/$B64 in this codebase.
  $res = @{ name = $nm; startok = 'no'; starterr = -1; pids = @(); state = -1; win32 = -1; wf = 0;
          dumps0 = 0; dumps1 = 0; kind = 'unknown'; retries = 0 }
  $res.dumps0 = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue).Count
  LogLine ('---- ' + $nm)
  $hh = HandleOf $nm
  if ($hh -eq [IntPtr]::Zero) {
    LogLine ('   OPEN_FAIL err=' + [P86.SCM]::LastErr)
    $res.kind = 'open-failed'
    $script:REC[$nm] = $res
    return
  }
  [void][P86.SCM]::StopNow($hh)
  for ($i = 0; $i -lt 8; $i++) { Start-Sleep -Milliseconds 250; if ((St $nm) -eq 'Stopped') { break } }
  LogLine ('   before start state=' + (St $nm))
  $startOk = [P86.SCM]::StartNow($hh)
  $e = [P86.SCM]::LastErr
  # A cold dependency chain answers 1068 even when the service itself is fine: the SCM will not wait for a
  # dependency it just had to start. The field run's control hit exactly this, so give it ONE retry after
  # nudging the dependencies, and record that a retry happened (kind=refused-by-scm must mean "twice").
  if (-not $startOk -and $e -eq 1068) {
    LogLine ('   1068 on the first attempt -> Ensure-Running RpcSs/Nsi and retry once')
    [void](Ensure-Running 'RpcSs')
    [void](Ensure-Running 'Nsi')
    Start-Sleep -Milliseconds 400
    $res.retries = 1
    $startOk = [P86.SCM]::StartNow($hh)
    $e = [P86.SCM]::LastErr
    LogLine ('   retry StartServiceW ok=' + $startOk + ' err=' + $e)
  }
  $res.startok = $(if ($startOk) { 'yes' } else { 'no' })
  $res.starterr = $e
  LogLine ('   StartServiceW ok=' + $startOk + ' err=' + $e + ' ' + $(if ($e -eq 0) { '' } elseif ($e -eq 1053) { '(timeout: no SERVICE_RUNNING and no stop)' } elseif ($e -eq 1056) { '(already started)' } elseif ($e -eq 1068) { '(ERROR_DEPENDENCY_NOT_RUNNING: the SCM refused it, so no host process ever existed to crash)' } else { '' }))
  $seen = @()
  $lastPid = -1
  $lastState = -1
  $lastWin32 = -1
  for ($i = 0; $i -lt 40; $i++) {
    $txt = [P86.SCM]::StatusEx($hh)
    if ($txt -match 'hostpid=(\d+)') {
      $p = [int64]$matches[1]
      if ($p -gt 0 -and $p -ne $lastPid) {
        $lastPid = $p
        $res.pids += $p
        $cc = @(Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p) -EA SilentlyContinue)
        $cmd = ''
        if (@($cc).Count) { $cmd = "$($cc[0].CommandLine)" }
        $seen += ('pid=' + $p + ' cmd=[' + (ToAscii $cmd) + ']')
      }
    }
    if ($txt -match 'state=(\d+)') { $lastState = [int] $matches[1] }
    # dwWin32ExitCode is signed in the struct; keep the full 32 bits so 0x800C0006 stays recognizable.
    if ($txt -match 'win32=(-?\d+)/0x([0-9A-Fa-f]{8})') { $lastWin32 = [int64]('0x' + $matches[2]) }
    if ($i -lt 3 -or ($i % 8) -eq 0) { LogLine ('   poll' + $i + ' ' + (ToAscii $txt)) }
    if ($txt -match 'state=1') { break }        # STOPPED: the host is gone, decision made
    Start-Sleep -Milliseconds 150
  }
  $res.state = $lastState
  $res.win32 = $lastWin32
  LogLine ('   final ' + (ToAscii ([P86.SCM]::StatusEx($hh))) + ' Get-Service=' + (St $nm))
  LogLine ('   CHILDREN seen=' + $seen.Count)
  foreach ($c in $seen) { LogLine ('     ' + $c) }
  [void][P86.SCM]::CloseServiceHandle($hh)
  # WerFault is the process that actually writes the dump; watch for it and give it time.
  $wf = 0
  for ($i = 0; $i -lt 30; $i++) {
    if (@(Get-Process WerFault -EA SilentlyContinue).Count) { $wf++ }
    Start-Sleep -Milliseconds 250
  }
  $res.wf = $wf
  $res.dumps1 = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue).Count
  LogLine ('   WerFault observed in ' + [int](30 * 250 / 1000) + 's window=' + $wf + ' polls -> dumps now: ' + (DumpNames))
  # classify how the service ended, which is the only thing that makes a missing dump meaningful
  if (@($res.pids).Count -eq 0) {
    $res.kind = $(if ($res.startok -eq 'no') { 'refused-by-scm' } else { 'no-host-pid' })
  } elseif ($res.state -eq 4) {
    $res.kind = 'running'
  } elseif ($res.win32 -eq 1067) {
    $res.kind = 'faulted'                       # PROCESS_ABORTED: the host died abnormally -> WER should fire
  } else {
    $res.kind = 'returned-error'                # reported an HRESULT of its own and stopped cleanly
  }
  $script:REC[$nm] = $res
}

O '== 2 control: wcmsvc, which probe84 record D proved crashes (win32=1067) =='
RunOne 'wcmsvc'
O '   (flushing the control result before wlansvc so a wlansvc crash cannot blend the two)'
$linesA = @($script:LOG); $script:LOG.Clear()
foreach ($l in $linesA) { Write-Output $l }
$dAfterCtrl = DumpNames
$script:ctrlCount = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue).Count
O ('  DUMPS_AFTER_WCMSVC ' + $dAfterCtrl + ' count=' + $script:ctrlCount)

O '== 3 test: wlansvc, the service this whole line is about =='
RunOne 'wlansvc'
$linesB = @($script:LOG); $script:LOG.Clear()
foreach ($l in $linesB) { Write-Output $l }
$dAll = DumpNames
# The verdict compares COUNTS, not names: both hosts are svchost.exe, so a wlansvc dump differs from the
# wcmsvc one only by the pid embedded in its file name (that is what CHILDREN above records).
$script:testCount = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue).Count
O ('  DUMPS_AFTER_WLANSVC ' + $dAll + ' count=' + $script:testCount)

O '== 4 every dump now on disk, newest last =='
foreach ($f in @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue | Sort-Object LastWriteTime)) {
  # the pid inside the file name is what ties a dump to a host: 1328's module list had wcmsvc.dll and no
  # wlansvc.dll, so names must be matched against the CHILDREN pids printed above, never guessed.
  O ('  FILE ' + (ToAscii $f.Name) + ' ' + [int]($f.Length / 1KB) + 'KB mtime=' + $f.LastWriteTime.ToString('HH:mm:ss'))
}

# ---------- is this boot actually the disc we baked? ----------
# probe42's wdi_paramkey check says the same thing from the registry; this one reads the FILES and the SCM's
# own view, because a missing .sys or a service key that only exists at runtime (1060) makes every wlansvc
# reading below worthless: it would be measuring the OLD image. $PeRoot is a parameter so the same function
# can be dry-run on the build PC against C:\Windows (build/scratch/t_p86_disc_host.ps1), where every item is
# present, and against an empty folder, where none is.
function DiscEvidence([string]$PeRoot) {
  $s32 = Join-Path $PeRoot 'System32'
  $sysWant = @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys', 'wdiwifi.sys', 'NdisImPlatform.sys')
  $dllWant = @('wlansvc.dll', 'wcmsvc.dll', 'wlanapi.dll', 'wlanmsm.dll',
               'deviceassociation.dll', 'IpNatHlpClient.dll', 'WFDSConMgr.dll')
  $sysMiss = @(); $sysN = 0
  foreach ($y in $sysWant) {
    if (Test-Path -LiteralPath (Join-Path $s32 ('drivers\' + $y))) { $sysN++ } else { $sysMiss += $y }
  }
  $dllMiss = @(); $dllN = 0
  foreach ($f in $dllWant) {
    if (Test-Path -LiteralPath (Join-Path $s32 $f)) { $dllN++ } else { $dllMiss += $f }
  }
  $catN = 0
  $catDir = Join-Path $s32 ('CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}')
  foreach ($cpat in @('Microsoft-Windows-Client-Desktop-Required-Package04*.cat',
                      'Microsoft-Windows-Client-Desktop-Required-Package05112*.cat')) {
    if (@(Get-ChildItem -LiteralPath $catDir -Filter $cpat -File -EA SilentlyContinue).Count) { $catN++ }
  }
  # SCM-visible, not registry-visible: a key written into the hive after boot is invisible here (1060), which
  # is exactly the difference between "baked offline" and "a probe tried to fix it at runtime".
  $keyMiss = @(); $keyN = 0
  foreach ($n in @('wdiwifi', 'NdisImPlatform', 'vwifibus', 'vwififlt', 'vwifimp', 'nativewifip')) {
    $hh = HandleOf $n
    if ($hh -ne [IntPtr]::Zero) { $keyN++; [void][P86.SCM]::CloseServiceHandle($hh) } else { $keyMiss += $n }
  }
  $baked = ($sysN -eq $sysWant.Count) -and ($keyN -ge 5) -and ($catN -ge 1)
  # FIX LEVEL -- read straight from the RUNNING service records, not from a hive we cannot open at runtime.
  # $baked alone cannot separate the 15:21 disc (WDI in, service keys still Type=0x20 + bare 'LocalService',
  # no delay DLLs) from the disc that carries the 2026-10-10 evening alignment: both say baked-disc, and the
  # whole point of this line is that a wlansvc reading from the two is a DIFFERENT data point.
  #   wtype=0x20 + wimg=[svchost.exe -k WlansvcGroup] (no -p) + wdeps carrying nativewifip/RpcSs/Ndisuio
  #        -> the 2026-10-12 official-WinRE alignment landed. WinRE hosts wlansvc through its OWN svchost group
  #        (SOFTWARE\...\Svchost\WlansvcGroup=[wlansvc], CoInitializeSecurityParam=1) instead of the desktop
  #        LocalSystemNetworkRestricted+-p shape the reference PC uses. The pre-alignment discs read either
  #        Type=0x20 with the old command line (2026-10-09 morning) or Type=0x10 + -k LocalSystemNetworkRestricted -p
  #        (2026-10-10 evening), so this line is what separates the three wlansvc data points from each other.
  #   comp=2/2 -> the two netcfg component records (ms_vwifi / ms_nativewifip) are in the LIVE
  #        Control\Network\{4d36e974-...} key, i.e. the offline bake landed and netcfg read it at boot. Without them
  #        the WLAN adapter's Linkage has no FilterList entry for vwififlt/nativewifip, so the miniport binds with
  #        no WiFi filter behind it -- which is what the 2026-10-12 WinRE-vs-ours diff singled out as THE delta.
  #   cobj=[NT Authority\LocalService] -> the full special account name landed (bare 'LocalService' is not an
  #        account name, so that key only fails at logon once its deps are met: 1069 waiting down the road)
  #   delay_dll=7/7 -> deviceassociation / IpNatHlpClient / WFDSConMgr were borrowed for the delay-load gaps
  $fixMiss = @(); $wType = '-'; $cObj = '-'; $wImg = '-'; $wDeps = '-'
  foreach ($sh in @(@{ n = 'wlansvc'; k = 'wtype'; want = 'Type=0x20' }, @{ n = 'wcmsvc'; k = 'cobj'; want = 'Obj=[NT Authority\LocalService]' })) {
    $hs = HandleOf $sh.n
    if ($hs -eq [IntPtr]::Zero) { $fixMiss += ($sh.k + '=open' + [P86.SCM]::LastErr); continue }
    $cf = ToAscii ([P86.SCM]::DumpConfig($hs))
    [void][P86.SCM]::CloseServiceHandle($hs)
    if ($sh.k -eq 'wtype') {
      if ($cf -match 'Type=(0x[0-9A-Fa-f]+)') { $wType = $matches[1] }
      if ($cf -match 'Img=\[([^\]]*)\]')      { $wImg = $matches[1] }
      if ($cf -match 'Deps=\[([^\]]*)\]')     { $wDeps = $matches[1] }
      if ($wImg -notmatch '-k\s+WlansvcGroup') { $fixMiss += ('wimg=-k_WlansvcGroup got:' + $wImg) }
      if ($wImg -match '\s-p(\s|$)')           { $fixMiss += 'wimg=no_-p got:-p-present' }
      foreach ($dn in @('nativewifip', 'RpcSs', 'Ndisuio')) {
        if (($wDeps -split ';') -notcontains $dn) { $fixMiss += ('wdep_' + $dn + ' got:[' + $wDeps + ']') }
      }
    }
    if ($sh.k -eq 'cobj')  { if ($cf -match 'Obj=\[([^\]]*)\]')       { $cObj = $matches[1] } }
    if ($cf -notmatch [regex]::Escape($sh.want)) { $fixMiss += ($sh.k + '=' + $sh.want + ' got:' + $cf) }
  }
  if ($dllN -ne $dllWant.Count) { $fixMiss += ('delay_dll=' + $dllN + '/' + $dllWant.Count) }
  # svchost group and the two netcfg component records, read from the LIVE registry. Both come from the baked
  # hive, so "they are here" is proof the offline injection landed (a runtime reg write would show up here too,
  # which is why the component half is judged on ComponentId, not on the key existing).
  $wgTxt = '-'
  $shv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost' -EA SilentlyContinue
  $wgN = @(@($shv.WlansvcGroup) | Where-Object { $_ })
  $wgTxt = (@($wgN) -join '+')
  if ($wgTxt -eq '') { $wgTxt = '(empty)' }
  if ($wgTxt -ne 'wlansvc') { $fixMiss += ('svchost_grp=[' + $wgTxt + ']') }
  $ncRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
  $compN = 0
  foreach ($cg in @(@('{5CBF81BF-5055-47CD-9055-A76B2B4E3698}', 'ms_vwifi'),
                    @('{E475CF9A-60CD-4439-A75F-0079CE0E18A1}', 'ms_nativewifip'))) {
    $cidv = '' + (Get-ItemProperty (Join-Path $ncRoot $cg[0]) -EA SilentlyContinue).ComponentId
    if ($cidv -eq $cg[1]) { $compN++ } else { $fixMiss += ('comp_' + $cg[1] + '=[' + $cidv + ']') }
  }
  $fixed = ($fixMiss.Count -eq 0)
  $ln = ('P86 DISC root=' + $PeRoot + ' wdi_vwifi_sys=' + $sysN + '/' + $sysWant.Count +
         ' svc_scm=' + $keyN + '/6 delay_dll=' + $dllN + '/' + $dllWant.Count + ' cat=' + $catN + '/2' +
         ' wlansvc_type=' + $wType + ' wlansvc_img=[' + $wImg + '] wlansvc_deps=[' + $wDeps + ']' +
         ' svchost_grp=[' + $wgTxt + '] comp=' + $compN + '/2' +
         ' wcmsvc_obj=[' + $cObj + ']' +
         ' verdict=' + $(if (-not $baked) { 'NOT-the-baked-disc' } elseif ($fixed) { 'baked-disc+aligned' } else { 'baked-disc-OLD-keys' }))
  if ($sysMiss.Count) { $ln += (' missing_sys=' + ($sysMiss -join ',')) }
  if ($keyMiss.Count) { $ln += (' missing_scm=' + ($keyMiss -join ',')) }
  if ($dllMiss.Count) { $ln += (' missing_dll=' + ($dllMiss -join ',')) }
  $fixLn = ('P86 DISC FIX wtype=' + $wType + ' wimg=[' + $wImg + '] wdeps=[' + $wDeps + ']' +
           ' sgrp=[' + $wgTxt + '] comp=' + $compN + '/2 cobj=[' + $cObj + ']' +
           ' delay_dll=' + $dllN + '/' + $dllWant.Count +
           ' ok=' + $(if ($fixed) { 'yes' } else { 'no' }))
  if ($fixMiss.Count) { $fixLn += (' missing=' + (($fixMiss | ForEach-Object { ($_ -split '=')[0] }) -join ',')) }
  return @{ line = $ln; fixLine = $fixLn; baked = $baked; fixed = $fixed }
}

O '== 5 VERDICT =='
$script:DISC = DiscEvidence 'X:\windows'
O $script:DISC.line
O $script:DISC.fixLine
$nA = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue).Count
O ('P86 WER ARMED folder=X:\pe_dumps DumpType=1 DumpCount=2 readback=' + (ToAscii $wr))
O ('P86 ALL     dumps=[' + $dAll + '] fileCount=' + $nA)
$rc = 'none'
$rt = 'none'
$wl = -1
$wlpids = ''
$wlerr = -1
# SNAPSHOT first. RunOne stores under $script:REC, and the field run showed how a loop-local whose name
# differs from that container only by letter case ($Rec vs $REC) silently replaced the map mid-verdict and made
# wlansvc look like it had never run. Copying the pairs out removes the whole class, and KEYS= makes it visible
# if a record is genuinely missing.
$keys = ''
if ($script:REC -is [hashtable]) { $keys = (@($script:REC.Keys) -join ',') } else { $keys = 'NOT-A-HASH' }
O ('P86 REC KEYS=' + $keys)
$pairs = @()
foreach ($nm in @('wcmsvc', 'wlansvc')) {
  if ($script:REC -is [hashtable] -and $script:REC.ContainsKey($nm)) { $pairs += @{ n = $nm; r = $script:REC[$nm] } }
  else { O ('P86 SVC ' + $nm + ' DID NOT RUN (open failed?)') }
}
foreach ($pr in $pairs) {
  $nm = $pr.n
  $res = $pr.r
  $added = [int] $res.dumps1 - [int] $res.dumps0
  $ws = ''
  if ($res.win32 -ge 0) { $ws = ('0x' + ([uint32]([int64] $res.win32 -band 0xFFFFFFFFL)).ToString('X8')) }
  O ('P86 SVC ' + $nm + ' start=' + $res.startok + '/err=' + $res.starterr + ' retries=' + $res.retries +
     ' hostpids=[' + ($res.pids -join ',') + ']' +
     ' endState=' + $res.state + ' win32=' + $ws + ' kind=' + $res.kind +
     ' dumps+' + $added + ' werfaultPolls=' + $res.wf)
  if ($nm -eq 'wcmsvc') { $rc = $res.kind } else { $rt = $res.kind }
  # take the exit code, the pids and the start error from the SAME snapshot, never from a second lookup
  # into $script:REC (that map is the thing the last field run managed to clobber mid-verdict)
  if ($nm -eq 'wlansvc') {
    $wl = [int64] $res.win32
    $wlpids = ($res.pids -join ',')
    $wlerr = [int] $res.starterr
  }
}
# The HRESULT wlansvc has been reporting since probe19, glossed from this machine's own message table
# (build/scratch/fm2_out_utf8.txt): 0x800C0006 => "the system cannot find the specified object".
if ($wl -eq 2148270086) {
  O 'P86 NOTE wlansvc exit code 0x800C0006 = the system cannot find the specified object.'
  O '         The service reached its own code without faulting, so the question is only WHICH object -- that answer'
  O '         depends on the disc this boot came from, and P86 READING below splits on exactly that.'
}
# The decision is (did a host ever run?) x (how did it end?) x (did it leave a dump?) -- see the comment on
# RunOne. Branch order matters: "nothing ran" must be checked before "WER did not write", because a service
# the SCM refused can never produce a dump and does not say anything about WER.
if ($rt -eq 'running') {
  O 'P86 READING: wlansvc reached RUNNING. WiFi is up (or at least the service is); go straight to probe42 for the adapter/WlanOpenHandle verdict.'
} elseif ($rt -eq 'faulted') {
  if ($script:testCount -gt $script:ctrlCount) {
    O 'P86 READING: wlansvc faulted AND added a dump of its own. Pull it and parse it on the host (see the header); the code/params/stack name the next file to bake.'
  } else {
    O 'P86 READING: wlansvc faulted (win32=1067) and WerFault left nothing, so WER LocalDumps really is unusable in this PE. Do not build any more of the plan on crash dumps: use the loader/setupapi evidence instead.'
  }
} elseif ($rt -eq 'returned-error') {
  O ('P86 READING: wlansvc ran a host process (pid ' + $wlpids +
      ') and STOPPED WITHOUT FAULTING, reporting an HRESULT of its own. A dump will never exist for this behaviour, so stop' +
      ' chasing crash dumps. The remaining question is what the service could not find, and the answer depends on the disc:')
  if ($script:DISC -is [hashtable] -and [bool] $script:DISC.baked) {
    # 2026-10-10 21:38: on the WDI-baked disc the adapter enumerates code 0 with the native miniport Running (probe42),
    # so the old "the object it cannot find is the WiFi adapter" reading is no longer true here. What is left lives ABOVE
    # the driver layer: the service-record shape and the delay-load backends wlansvc.dll wants.
    O ('             On THIS disc the WDI stack IS baked (see P86 DISC above), so if probe42 for this same boot shows a')
    O ('             wireless node at code 0 with the miniport Running, the missing object is above the driver layer.')
    if ([bool] $script:DISC.fixed) {
      O ('             This boot also carries the reference-machine service keys (P86 DISC FIX ok=yes), so the key shape is')
      O ('             eliminated as the explanation. What remains is a delay-load backend the image does not have')
      O ('             (deviceassociation / IpNatHlpClient / WFDSConMgr) or a dependency the SCM never lets it reach -- for')
      O ('             the second one, read the section 1c CLOSURE lines and name the first node that is not state=4.')
    } else {
      O ('             This disc still predates the service-key alignment (P86 DISC FIX ok=no above), so the key shape stays a')
      O ('             live suspect alongside the delay-load backends (deviceassociation / IpNatHlpClient / WFDSConMgr), and the')
      O ('             wlansvc number here is a measurement of the OLD service layer -- see the DISC CAVEAT at the end.')
    }
  } else {
    O ('             On an image WITHOUT the WDI framework (wdiwifi.sys/NdisImPlatform, see probe81) that "object" is the native')
    O ('             WiFi adapter itself, so re-run this probe on the WDI-baked disc before concluding anything about')
    O ('             wlansvc.dll and its delay-load files.')
  }
} elseif ($rt -eq 'refused-by-scm' -or $rt -eq 'no-host-pid') {
  O ('P86 READING: wlansvc never got a host process this time (StartServiceW err=' + $wlerr +
      '), same as the control (' + $rc + '). Nothing could crash, so this run says nothing about WER; section 1c walks the' +
      ' dependency tree two levels deep, read the CLOSURE lines for the first node that is not state=4.')
  O '             (a level-1 dependency can be RUNNING while a level-2 one is not -- that is how 1068 survives here)'
} else {
  O 'P86 READING: inconclusive, read the P86 SVC lines above.'
}
# The disc check is the guard on everything above: measuring wlansvc on the old image a fifth time would look
# like a fifth data point but is the same environment.
if ($script:DISC -is [hashtable] -and -not [bool] $script:DISC.baked) {
  O 'P86 DISC CAVEAT: this boot is NOT the disc with the WDI framework baked in (see the P86 DISC line above), so the'
  O '         wlansvc/wcmsvc readings in this output are readings of the OLD image. Boot the ISO whose wifi-inject'
  O '         evidence line ends wdi_sys=2/2 wdi_svc=2/2 wdi_cat=1/1 flags=none + svc-shape flags=none, then re-run.'
} elseif ($script:DISC -is [hashtable] -and -not [bool] $script:DISC.fixed) {
  # 2026-10-10 21:38 field run: the 15:21 disc IS WDI-baked (wifi adapter code 0, no code 37 -- see probe42), but its
  # service records still have the pre-alignment shape and none of the three borrowed delay DLLs. Its wlansvc result
  # (0x800C0006) is therefore a measurement of the OLD service layer, not a verdict on the alignment.
  O ('P86 DISC CAVEAT: the WDI stack is baked, but this disc predates the 2026-10-10 evening service-key alignment (' +
    $script:DISC.fixLine + ').')
  O '         So the wlansvc/wcmsvc readings above are the behaviour of the OLD SERVICE LAYER on a NEW driver layer -- real'
  O '         data point about the driver half, not yet a test of the key shape. Boot the ISO whose wifi-inject line ends'
  O '         svc-shape: ... flags=none and whose P86 DISC FIX prints ok=yes, then re-run to compare kind= / win32=.'
}
O ('P86 CONTROL kind=' + $rc + ' dumps=' + $dAfterCtrl)
O 'P86 END'
