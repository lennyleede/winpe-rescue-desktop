# ============================================================
# probe49_scmcache.ps1 -- read the config the SCM ACTUALLY uses (its in-memory record), then fix it
# through the SCM API instead of the registry, and see if wcmsvc starts.
#
# Why the registry is the wrong place to look (probe48):
#   wcmsvc returned 1068 for SEVEN different key shapes in a row -- -s form, LocalSystem, no Group,
#   no TriggerInfo, its own svchost group -- while wlansvc behaved completely differently under the same
#   edits. Raw registry writes change what QueryServiceConfig READS; the START path uses the service
#   record services.exe built when it loaded the hive at boot. Only ChangeServiceConfigW /
#   ChangeServiceConfig2W go through services.exe and refresh that record.
#   That matches the bake: wifi-inject.ps1 writes wlansvc with ObjectName=LocalSystem and privileges
#   LocalSystem really holds, and it dispatches; it writes wcmsvc with ObjectName='LocalService' (Dhcp
#   in this same image uses 'NT Authority\LocalService') AND RequiredPrivileges including
#   SeAuditPrivilege+SeTcbPrivilege, which the LocalService account can never hold. An account the SCM
#   cannot resolve/satisfy is exactly what surfaces as ERROR_DEPENDENT_SERVICES_RUNNING (1068).
#
# probe49: (1) dump the SCM's cached record for wcmsvc/wlansvc/dot3svc/Netman/Dhcp next to the registry
# values, (2) push corrections through the API (ObjectName, RequiredPrivileges, DependOnService),
# (3) StartServiceW wcmsvc, then wlansvc, then WlanOpenHandle/WlanEnumInterfaces -- the real chain.
#
# MARSHALLING NOTE (this is why probe43's OpenSCManagerW returned handle=0 lasterr=123 even on a host
# where Get-Service works): PowerShell binds a $null argument for a `string` P/Invoke parameter as an
# EMPTY STRING, and OpenSCManagerW("") fails with ERROR_PATH_NOT_FOUND(123). Every nullable pointer in
# this probe is therefore an explicit IntPtr parameter, and the wrappers pass IntPtr.Zero.
#
# Writes: the SCM's cached records for {wcmsvc,wlansvc} + start attempts, on the RAMDISK. X: evaporates
#         on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe49_scmcache.ps1 -RemotePath X:/p49.ps1 -StagingB64 X:/p49.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# LogLine buffers output from functions that also return a value; FlushLog must be its own statement
# ([void](FlushLog) captures the success stream and discards it). Aliases beat functions: no short names.
$script:LOG = New-Object System.Collections.ArrayList
function LogLine([string]$s) { [void]$script:LOG.Add($s) }
function FlushLog { $lines = @($script:LOG); $script:LOG.Clear(); foreach ($l in $lines) { Write-Output $l } }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }

$REG = 'HKLM\SYSTEM\CurrentControlSet\Services'
$P = @{ steps = @(); wl = @(); openEnd = -1; ifaces = -1; scm = 'none'; via = 'n/a' }

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

if (-not ('P49.SCM' -as [type])) {
  Add-Type -Namespace P49 -Name SCM -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct SP { public IntPtr p; }

[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern IntPtr OpenSCManagerW(IntPtr machine, IntPtr database, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr OpenServiceW(IntPtr scm, string name, int access);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CloseServiceHandle(IntPtr h);
// MARSHALLING (host-proved 2026-10-10 15:5x, build/scratch/t_qsc_variants.ps1): with "out int needed"
// .NET throws EntryPointNotFoundException, and with a 16 KB / 12 KB buffer the call fails with
// lasterr=1783 ERROR_INVALID_USER_BUFFER. "ref int needed" + an 8 KB buffer works (needed=338/366).
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool QueryServiceConfigW(IntPtr svc, IntPtr buf, int bufsize, ref int needed);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ChangeServiceConfigW(IntPtr svc, int type, int startType, int errorControl,
    IntPtr binPath, IntPtr group, IntPtr tagId, IntPtr deps, IntPtr startName, IntPtr displayName, IntPtr password);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool ChangeServiceConfig2W(IntPtr svc, int level, ref SP info);
[System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
public static extern bool StartServiceW(IntPtr svc, int numArgs, IntPtr argv);

public static int LastErr = 0;

public static IntPtr OpenScm(int access) {
  IntPtr h = OpenSCManagerW(IntPtr.Zero, IntPtr.Zero, access);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return h;
}
static IntPtr Dup(string s) {
  if (s == null) { return IntPtr.Zero; }
  return System.Runtime.InteropServices.Marshal.StringToHGlobalUni(s);
}
public static bool SetStartName(IntPtr svc, string name) {
  IntPtr p = Dup(name);
  bool r = ChangeServiceConfigW(svc, -1, -1, -1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, p, IntPtr.Zero, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (p != IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(p); }
  return r;
}
public static bool SetImagePath(IntPtr svc, string img) {
  IntPtr p = Dup(img);
  bool r = ChangeServiceConfigW(svc, -1, -1, -1, p, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (p != IntPtr.Zero) { System.Runtime.InteropServices.Marshal.FreeHGlobal(p); }
  return r;
}
public static bool SetDeps(IntPtr svc, string[] deps) {
  int bytes = 2;
  foreach (string s in deps) { bytes += (s.Length + 1) * 2; }
  IntPtr block = System.Runtime.InteropServices.Marshal.AllocHGlobal(bytes);
  long off = 0;
  foreach (string s in deps) {
    foreach (char c in s) { System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)c); off += 2; }
    System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)0); off += 2;
  }
  System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)0);
  bool r = ChangeServiceConfigW(svc, -1, -1, -1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, block, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  System.Runtime.InteropServices.Marshal.FreeHGlobal(block);
  return r;
}
public static bool SetPrivileges(IntPtr svc, string[] privs) {
  int bytes = 2;
  foreach (string s in privs) { bytes += (s.Length + 1) * 2; }
  IntPtr block = System.Runtime.InteropServices.Marshal.AllocHGlobal(bytes);
  long off = 0;
  foreach (string s in privs) {
    foreach (char c in s) { System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)c); off += 2; }
    System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)0); off += 2;
  }
  System.Runtime.InteropServices.Marshal.WriteInt16(block, (int)off, (short)0);
  SP holder = new SP(); holder.p = block;
  // SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6
  bool r = ChangeServiceConfig2W(svc, 6, ref holder);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  System.Runtime.InteropServices.Marshal.FreeHGlobal(block);
  return r;
}
static string Uni(IntPtr p) {
  if (p == IntPtr.Zero) { return ""; }
  string s = System.Runtime.InteropServices.Marshal.PtrToStringUni(p);
  return s == null ? "" : s;
}
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
public static string DumpConfig(IntPtr svc) {
  // MARSHALLING, host-proved 2026-10-10 (build/scratch/t_qsc_variants.ps1, 20 calls):
  //   bufsize 16384 or 12288 -> FALSE / lasterr 1783 ERROR_INVALID_USER_BUFFER, whatever else we do
  //   bufsize 8192 or 4096 + "ref int needed" -> TRUE, needed=338(Dhcp) 366(wlansvc)
  //   bufsize 8192/4096 + "out int needed"    -> EntryPointNotFoundException thrown by .NET
  // The real record is ~400 bytes, so 8000 is ample; ERROR_MORE_DATA(123) still gets one sized retry.
  // And the buffer must outlive every read: freeing it early is a use-after-free, which in PS 5.1 is a
  // corrupted-state exception -- it kills powershell.exe (exit 127) instead of throwing anything.
  int needed = 0;
  int size = 8000;
  IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
  for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
  bool ok = QueryServiceConfigW(svc, buf, size, ref needed);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (!ok && LastErr == 123 && needed > 8 && needed < 60000) {  // ERROR_MORE_DATA: resize and try once
    System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
    size = needed + 64;
    buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
    for (int i = 0; i < size; i += 8) { System.Runtime.InteropServices.Marshal.WriteInt64(buf, i, 0L); }
    ok = QueryServiceConfigW(svc, buf, size, ref needed);
    LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  }
  if (!ok) {
    System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
    return "QFC_FAIL=" + LastErr + " needed=" + needed;
  }
  // QUERY_SERVICE_CONFIG on x64: 3 dwords + pad; img(16) group(24) tagId(32) deps(40) startName(48)
  long type = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 0) & 0xFFFFFFFFL;
  long start = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 4) & 0xFFFFFFFFL;
  long err = System.Runtime.InteropServices.Marshal.ReadInt32(buf, 8) & 0xFFFFFFFFL;
  string img = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 16));
  string grp = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 24));
  string deps = BlockOut(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 40));
  string obj = Uni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, 48));
  System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
  return "Type=0x" + type.ToString("X") + " Start=0x" + start.ToString("X") +
         " ErrCtl=0x" + err.ToString("X") + " Obj=[" + obj + "] Group=[" + grp + "]" +
         " Deps=[" + deps + "] Img=[" + img + "]";
}
public static bool StartNow(IntPtr svc) {
  bool r = StartServiceW(svc, 0, IntPtr.Zero);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return r;
}
'@ -EA Stop
}
# A service handle .NET already opened for us, if advapi32 ever lets us down: ServiceController keeps
# an internal SafeHandle; reflection reaches it. It only grants QUERY_CONFIG/QUERY_STATUS/START access.
# Windows PowerShell does not load System.ServiceProcess by default; Get-Service happens to pull it in,
# but load it explicitly so the fallback cannot depend on which cmdlet ran first.
Add-Type -AssemblyName System.ServiceProcess -EA SilentlyContinue
function HandleByReflection([string]$name) {
  try {
    $sc = New-Object System.ServiceProcess.ServiceController($name)
    $tp = $sc.GetType()
    $flags = [System.Reflection.BindingFlags]'NonPublic,Instance,Public'
    $prop = $tp.GetProperty('Handle', $flags)
    if (-not $prop) { return [IntPtr]::Zero }
    $sh = $prop.GetValue($sc, $null)
    if ($null -eq $sh) { return [IntPtr]::Zero }
    $fld = $sh.GetType().GetField('handle', [System.Reflection.BindingFlags]'NonPublic,Public,Instance')
    if ($fld) { return [IntPtr]$fld.GetValue($sh) }
    $ph = $sh.GetType().GetProperty('Handle', [System.Reflection.BindingFlags]'Public,Instance')
    if ($ph) { return [IntPtr]$ph.GetValue($sh, $null) }
    return [IntPtr]::Zero
  } catch { return [IntPtr]::Zero }
}

O '== 0 SCM handle (explicit IntPtr.Zero for machine/database) =='
$script:hScm = [IntPtr]::Zero
foreach ($acc in @(0xF003F, 0x0001, 0x0002, 0x0017)) {
  $h = [P49.SCM]::OpenScm($acc)
  O ('  OpenScm access=0x' + ('{0:X}' -f $acc) + ' handle=' + $(if ($h -ne [IntPtr]::Zero) { 'OK' } else { 'ZERO' }) +
     ' lasterr=' + [P49.SCM]::LastErr)
  if ($h -ne [IntPtr]::Zero) { $script:hScm = $h; $P.scm = 'ok-0x' + ('{0:X}' -f $acc); break }
}
O ('  SCM handle = ' + $P.scm)
function OpenSvc([string]$name, [int]$access) {
  if ($script:hScm -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
  try { return [P49.SCM]::OpenServiceW($script:hScm, $name, $access) } catch { return [IntPtr]::Zero }
}
function OpenSvcAny([string]$name) {
  # SERVICE_CHANGE_CONFIG(0x2) needs an elevated SCM handle; query-only(0x1) does not, so a non-elevated
  # shell can still read the cached record even though it cannot push a correction.
  foreach ($a in @(0xF01FF, 0x0017, 0x0002, 0x0001)) {
    $h = OpenSvc $name $a
    if ($h -ne [IntPtr]::Zero) { return $h }
  }
  return [IntPtr]::Zero
}

O '== 1 the record the SCM uses vs the registry (the whole point) =='
foreach ($n in @('wcmsvc', 'wlansvc', 'dot3svc', 'Netman', 'Dhcp')) {
  $h = OpenSvc $n 0xF01FF
  if ($h -eq [IntPtr]::Zero) { $h = OpenSvc $n 0x0017 }
  $via = 'advapi'
  if ($h -eq [IntPtr]::Zero) {
    $h = HandleByReflection $n
    $via = 'reflection'
    if ($h -eq [IntPtr]::Zero) { O ('  MEM ' + $n + ' no handle at all (advapi lasterr=' + [P49.SCM]::LastErr + ')'); continue }
  }
  O ('  MEM(' + $via + ') ' + $n + ' ' + (ToAscii ([P49.SCM]::DumpConfig($h))))
  O ('      REG ' + $n + ' Type=' + (RegGet "$REG\$n" 'Type') + ' Start=' + (RegGet "$REG\$n" 'Start') +
     ' Obj=[' + (RegGet "$REG\$n" 'ObjectName') + '] Group=[' + (RegGet "$REG\$n" 'Group') +
     '] Deps=[' + (RegGet "$REG\$n" 'DependOnService') + '] Privs=[' + (RegGet "$REG\$n" 'RequiredPrivileges') + ']')
  O ('      STATE ' + $n + ' = ' + (St $n))
  if ($via -eq 'advapi') { [void][P49.SCM]::CloseServiceHandle($h) }
}

O '== 2 push corrections through the SCM itself, then StartServiceW =='
function ApiStart([string]$name, [IntPtr]$h) {
  # no QueryServiceStatus import: SERVICE_STATUS begins with dwServiceType, so an 'out int' would read
  # the wrong field. StartServiceW's lasterr is the decisive number; Get-Service reports the settled state.
  $okS = [P49.SCM]::StartNow($h)
  $le = [P49.SCM]::LastErr
  $w = 0; $s = St $name
  while ($w -lt 20 -and ($s -eq 'StartPending' -or $s -eq 'StopPending')) {
    Start-Sleep -Seconds 2; $w += 2; $s = St $name
  }
  LogLine ('      StartServiceW ' + $name + ' ok=' + $okS + ' lasterr=' + $le + ' waited=' + $w + 's svc=' + $s)
  return @{ ok = $okS; err = $le; state = $s }
}
function Step([string]$name, [string]$label, [scriptblock]$body) {
  $h = OpenSvc $name 0xF01FF
  if ($h -eq [IntPtr]::Zero) {
    LogLine ('  [' + $name + '/' + $label + '] OpenService(0xF01FF) failed lasterr=' + [P49.SCM]::LastErr +
             ' -- cannot change the cached record without SERVICE_CHANGE_CONFIG')
    return -1
  }
  & $body $h
  $r = ApiStart $name $h
  [void][P49.SCM]::CloseServiceHandle($h)
  return $r.err
}
# W1: the host-authority LocalService pair -- account spelled like Dhcp spells it, privileges limited
#     to what that account can actually hold (no SeAudit, no SeTcb).
$code = Step 'wcmsvc' 'W1_obj+2privs' {
  param($h)
  $ok = [P49.SCM]::SetStartName($h, 'NT Authority\LocalService')
  $e1 = [P49.SCM]::LastErr
  $ok2 = [P49.SCM]::SetPrivileges($h, @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege'))
  LogLine ('      W1 SetStartName ok=' + $ok + ' err=' + $e1 + ' SetPrivileges(2) ok=' + $ok2 +
           ' err=' + [P49.SCM]::LastErr + ' memNow=' + (ToAscii ([P49.SCM]::DumpConfig($h))))
}
$P.steps += "W1=$code"; FlushLog
O ('  W1 obj=NT Authority\LocalService + privs=2 -> code=' + $code + ' state=' + (St 'wcmsvc'))

$code = Step 'wcmsvc' 'W2_localsystem' {
  param($h)
  $ok = [P49.SCM]::SetStartName($h, 'LocalSystem')
  $ok2 = [P49.SCM]::SetPrivileges($h, @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege', 'SeAuditPrivilege'))
  LogLine ('      W2 SetStartName(LocalSystem) ok=' + $ok + ' err=' + [P49.SCM]::LastErr +
           ' SetPrivileges(4) ok=' + $ok2 + ' err=' + [P49.SCM]::LastErr + ' mem=' + (ToAscii ([P49.SCM]::DumpConfig($h))))
}
$P.steps += "W2=$code"; FlushLog
O ('  W2 obj=LocalSystem + privs=4 -> code=' + $code + ' state=' + (St 'wcmsvc'))

$code = Step 'wcmsvc' 'W3_ls_badauth' {
  param($h)
  # the bake's literal value: bare 'LocalService' -- the SCM must resolve that string to an account
  $ok = [P49.SCM]::SetStartName($h, 'LocalService')
  LogLine ('      W3 SetStartName(bare LocalService, the shape the bake writes) ok=' + $ok +
           ' err=' + [P49.SCM]::LastErr + ' mem=' + (ToAscii ([P49.SCM]::DumpConfig($h))))
}
$P.steps += "W3=$code"; FlushLog
O ('  W3 obj=bare LocalService + privs=4 (bake shape) -> code=' + $code + ' state=' + (St 'wcmsvc'))

$code = Step 'wcmsvc' 'W4_fix_pair' {
  param($h)
  $ok = [P49.SCM]::SetStartName($h, 'NT Authority\LocalService')
  $ok2 = [P49.SCM]::SetPrivileges($h, @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege'))
  $ok3 = [P49.SCM]::SetDeps($h, @('RpcSs'))
  LogLine ('      W4 obj fixed + privs=2 + deps=RpcSs ok=' + $ok + '/' + $ok2 + '/' + $ok3 +
           ' errs=' + [P49.SCM]::LastErr + ' mem=' + (ToAscii ([P49.SCM]::DumpConfig($h))))
}
$P.steps += "W4=$code"; FlushLog
O ('  W4 obj=NT Authority\LocalService + privs=2 + deps=RpcSs -> code=' + $code + ' state=' + (St 'wcmsvc'))
O ('  wcmsvc now ' + (St 'wcmsvc') + '; wlansvc depends on it being up')

$code = Step 'wlansvc' 'L1_after_wc' {
  param($h)
  $ok2 = [P49.SCM]::SetPrivileges($h, @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege', 'SeAuditPrivilege',
                                        'SeTcbPrivilege', 'SeDebugPrivilege', 'SeLoadDriverPrivilege'))
  LogLine ('      L1 wlansvc SetPrivileges(6) ok=' + $ok2 + ' err=' + [P49.SCM]::LastErr +
           ' mem=' + (ToAscii ([P49.SCM]::DumpConfig($h))))
}
$P.wl += "L1=$code"; FlushLog
O ('  L1 wlansvc after the wcmsvc attempts -> code=' + $code + ' state=' + (St 'wlansvc'))

O '== 3 what the SCM holds now, and which svchost is live =='
foreach ($n in @('wcmsvc', 'wlansvc')) {
  $h = OpenSvc $n 0xF01FF
  if ($h -eq [IntPtr]::Zero) { $h = HandleByReflection $n }
  if ($h -ne [IntPtr]::Zero) {
    O ('  MEM2 ' + $n + ' ' + (ToAscii ([P49.SCM]::DumpConfig($h))) + ' svcState=' + (St $n))
  } else { O ('  MEM2 ' + $n + ' no handle') }
}
$procs = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)
$sNames = ((@($procs | ForEach-Object { if ("$($_.CommandLine)" -match '-s\s+(\S+)') { $matches[1] } }) | Sort-Object -Unique)) -join ','
O ('  svchost procs=' + $procs.Count + ' -s=' + (ToAscii $sNames))
O ('  on disk: wcmsvc privs=[' + (RegGet "$REG\wcmsvc" 'RequiredPrivileges') + '] obj=[' +
   (RegGet "$REG\wcmsvc" 'ObjectName') + '] wlansvc deps=[' + (RegGet "$REG\wlansvc" 'DependOnService') + ']')

O '== 4 wlanapi, the thing we actually need =='
if (-not ('P49.W' -as [type])) {
  Add-Type -Namespace P49 -Name W -MemberDefinition @'
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
  $nv = 0; $hw = [IntPtr]::Zero
  $rc = [P49.W]::WlanOpenHandle(2, [IntPtr]::Zero, [ref] $nv, [ref] $hw)
  $P.openEnd = $rc
  LogLine ('  WLANOPEN rc=' + $rc + ' newVer=' + $nv)
  if ($rc -eq 0 -and $hw -ne [IntPtr]::Zero) {
    $lst = [IntPtr]::Zero
    $erc = [P49.W]::WlanEnumInterfaces($hw, [IntPtr]::Zero, [ref] $lst)
    if ($erc -eq 0 -and $lst -ne [IntPtr]::Zero) {
      $names = [P49.W]::IfaceNames($lst)
      $P.ifaces = $names.Count
      foreach ($x in $names) { LogLine ('    IFACE ' + $x) }
      [void][P49.W]::WlanFreeMemory($lst)
    }
    LogLine ('  ENUMIF rc=' + $erc + ' items=' + $P.ifaces)
    [void][P49.W]::WlanCloseHandle($hw, [IntPtr]::Zero)
  }
} catch { LogLine ('  WLAN call failed: ' + (ToAscii $_.Exception.Message)) }
FlushLog

O '== 5 VERDICT =='
O ('P49 VERDICT scm=' + $P.scm + ' wc=' + ($P.steps -join ' ') +
   ' wcState=' + (St 'wcmsvc') + ' wl=' + ($P.wl -join ' ') + ' wlState=' + (St 'wlansvc') +
   ' wlanopen=' + $P.openEnd + ' ifaces=' + $P.ifaces)
if ($P.openEnd -eq 0) { O 'P49 READING: wlanapi answers in PE -> the account/privilege pair was the blocker; bake the W4 pair for wcmsvc and the reboot acceptance is all that is left.' }
elseif (($P.steps -join ' ') -match 'W1=0|W2=0|W4=0') { O 'P49 READING: wcmsvc reaches Running through the API but wlansvc still dies -> account pair solved, wlansvc still needs something at runtime (nativewifip/wdiwifi).' }
elseif ($P.scm -eq 'none') { O 'P49 READING: no SCM handle even with IntPtr.Zero -> the API path is closed in PE, only the MEM/reflection dump is informative; the reboot test decides.' }
elseif (($P.steps -join ' ') -match '1068') { O 'P49 READING: still 1068 after pushing through the API -> the cached record was NOT the problem; look at the MEM vs REG lines.' }
else { O 'P49 READING: see codes; a code other than 1068 means the account/privilege pair was the blocker and what remains is a different failure.' }
O 'P49 END'
