# ============================================================
# probe100_wlan_live.ps1 -- live machine 192.168.0.102, the layer AFTER WLAN-BIND=ok
# ============================================================
#   The boot log already proves the filter-binding layer is fixed (task #41):
#     WLAN-BIND = ok (devnodes 1 / wifi_filter_entries 2 / vwifibus=True / services_running 3/3)
#   But it surfaced the next blocker:
#     WDI-HOST = 0/2   WdiServiceHost=Stopped wdisystemhost=Stopped
#     net start WdiServiceHost -> System error 1297
#       ("No privilege has been granted to the service account that the service requires to run",
#        i.e. the service account is missing SeServiceLogonRight / "Log on as a service")
#   This probe answers ONE question: is 1297 "no PE service that logs on as anything but LocalSystem
#   can start", or is it something specific to the two keys we baked?
#   Two independent evidence lines, so we are not guessing:
#     A  control group -- every account the image's services log on as and whether it runs, plus
#        starting someone else's LocalService/NetworkService service to see if it fails with 1297 too;
#     B  read the right directly -- advapi32 LsaEnumerateAccountRights for S-1-5-18 / S-1-5-19 / S-1-5-20,
#        looking for SE_SERVICE_LOGON_NAME in the list.
#   Starting goes through StartServiceW + Marshal.GetLastWin32Error, because WMI's StartService ReturnValue
#   is a different code space and cannot show 1297 (that mismatch is what sent us in circles last round).
#   Output: single-line ASCII, prefix P100, grep on the host. Writes nothing to the registry.
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P100 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

L('probe100 begin ps=' + $PSVersionTable.PSVersion.ToString())

# ---------- 0) native helpers: StartService win32 code + LSA account rights ----------
$src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Pe100 {
  // ---- StartService with the real win32 code ----
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  static IntPtr OpenSCManagerLocal() { return OpenSCManagerW(null, null, SC_MANAGER_CONNECT); }
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_QUERY_STATUS = 0x0004;
  const uint SERVICE_START = 0x0010;
  public static string Start(string name) {
    IntPtr sm = OpenSCManagerLocal();   // NULL machine + SERVICES_ACTIVE_DATABASE
    if (sm == IntPtr.Zero) { return "OPENSCMANAGER_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_START | SERVICE_QUERY_STATUS);
      if (sv == IntPtr.Zero) { return "OPENSERVICE_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        bool ok = StartServiceW(sv, 0, IntPtr.Zero);
        if (ok) { return "START_OK"; }
        return "START_ERR=" + Marshal.GetLastWin32Error();
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }

  // ---- LSA account rights ----
  [StructLayout(LayoutKind.Sequential)]
  struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern int LsaOpenPolicy(IntPtr SystemName, ref OBJECT_ATTRIBUTES ObjectAttributes, int Access, out IntPtr PolicyHandle);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern int LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, out IntPtr ListOfRights, out uint CountOfRights);
  [DllImport("advapi32.dll")]
  static extern int LsaFreeMemory(IntPtr Buffer);
  [DllImport("advapi32.dll")]
  static extern int LsaClose(IntPtr PolicyHandle);
  const int POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
  public static string Rights(byte[] sid) {
    IntPtr sh = IntPtr.Zero, list = IntPtr.Zero, pol = IntPtr.Zero;
    uint cnt = 0;
    try {
      sh = Marshal.AllocHGlobal(sid.Length);
      Marshal.Copy(sid, 0, sh, sid.Length);
      OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
      oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
      int r = LsaOpenPolicy(IntPtr.Zero, ref oa, POLICY_VIEW_LOCAL_INFORMATION, out pol);
      if (r != 0) { return "LSA_OPEN_ERR=0x" + r.ToString("X8"); }
      r = LsaEnumerateAccountRights(pol, sh, out list, out cnt);
      // hex, not decimal: 0xC0000022 (access denied, i.e. the shell is not elevated) is readable at a
      // glance, while -1073741790 sent me looking for a bug that was just missing admin rights.
      if (r != 0) { return "LSA_ENUM_ERR=0x" + r.ToString("X8"); }
      StringBuilder sb = new StringBuilder();
      // UNICODE_STRING: x64 -> Buffer at offset 8, x86 -> offset 4. Length is a USHORT at offset 0.
      int nameOffset = IntPtr.Size == 8 ? 8 : 4;
      for (uint i = 0; i < cnt; i++) {
        IntPtr e = Marshal.ReadIntPtr(list, (int)(i * IntPtr.Size));
        int len = Marshal.ReadInt16(e) & 0xFFFF;
        IntPtr buf = Marshal.ReadIntPtr(e, nameOffset);
        string nm = "";
        try { nm = Marshal.PtrToStringUni(buf, len / 2); } catch { }
        if (i > 0) { sb.Append(','); }
        sb.Append(nm);
      }
      return "N=" + cnt + " [" + sb.ToString() + "]";
    } finally {
      if (list != IntPtr.Zero) { LsaFreeMemory(list); }
      if (pol != IntPtr.Zero) { LsaClose(pol); }
      if (sh != IntPtr.Zero) { Marshal.FreeHGlobal(sh); }
    }
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE add-type FAILED ' + (C $_.Exception.Message)) }

# ---------- 1) material layer (the two hosts need svchost, wlansvc needs these dlls) ----------
foreach ($f in @('svchost.exe', 'wdi.dll', 'wcmcsp.dll', 'wlansvc.dll', 'wcmsvc.dll', 'wlanapi.dll',
                 'wlanmsm.dll', 'wlansec.dll', 'wdiservicehost.dll', 'wdisystemhost.dll')) {
  $p = 'X:\Windows\System32\' + $f
  $e = Test-Path -LiteralPath $p
  $z = 0
  if ($e) { $z = (Get-Item -LiteralPath $p).Length }
  L('FILE32 ' + $f + ' present=' + $e + ' bytes=' + $z)
}
# rights live in the SECURITY/SAM policy, so whether PE even has those hives decides how we can fix it
foreach ($h in @('SYSTEM', 'SOFTWARE', 'SECURITY', 'SAM', 'DEFAULT')) {
  $p = 'X:\Windows\System32\config\' + $h
  L('HIVE ' + $h + ' present=' + (Test-Path -LiteralPath $p))
}

# ---------- 2) the services we care about: shape, then one native start attempt ----------
function SvcRow([string]$n, [switch]$TryStart) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  if (-not $p) { L('SVC ' + $n + ' KEY=ABSENT'); return }
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  if (-not $st) { $st = 'n/a' }
  L(('SVC {0} state={1} type=0x{2:X} start=0x{3:X} obj=[{4}] group=[{5}] deps=[{6}] img=[{7}]' -f `
     $n, $st, [int]$p.Type, [int]$p.Start, (C ('' + $p.ObjectName)), (C ('' + $p.Group)),
     (@([string[]]$p.DependOnService) -join ';'), (C ('' + $p.ImagePath))))
  if ($TryStart -and ("$st" -ne 'Running')) {
    $r = 'no-native'
    if ($native) { $r = [Pe100]::Start($n) }
    L('START ' + $n + ' ' + $r)
    Start-Sleep -Seconds 3
    $st2 = (Get-Service -Name $n -EA SilentlyContinue).Status
    if (-not $st2) { $st2 = 'n/a' }
    L('AFTER ' + $n + ' state=' + $st2)
  }
}
L('== 2 the wifi stack services ==')
foreach ($n in @('wlansvc', 'wcmsvc', 'WdiServiceHost', 'wdisystemhost')) { SvcRow $n -TryStart }
foreach ($n in @('nativewifip', 'vwififlt', 'vwifibus', 'NdisImPlatform', 'wdiwifi')) { SvcRow $n }

# ---------- 3) control A: every account a service logs on as, and whether it runs ----------
L('== 3 control: service logon accounts in this image ==')
$agg = @{}
$lsNames = @()
foreach ($k in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue)) {
  $n = $k.PSChildName
  $p = Get-ItemProperty -LiteralPath $k.PSPath -EA SilentlyContinue
  $o = ('' + $p.ObjectName) -replace '(?i)^NT AUTHORITY\\', ''
  $o = (C $o)
  if (-not $o) { $o = '(none/kernel)' }
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  if (-not $st) { $st = 'n/a' }
  $key = $o + '|' + $st
  if (-not $agg.ContainsKey($key)) { $agg[$key] = 0 }
  $agg[$key] = $agg[$key] + 1
  if ($o -match '(?i)^(LocalService|NetworkService)$') {
    $lsNames += ($n + '=' + $st + '|t0x' + ('{0:X}' -f [int]$p.Type) + '|s0x' + ('{0:X}' -f [int]$p.Start))
  }
}
foreach ($key in @($agg.Keys | Sort-Object)) {
  $parts = $key -split '\|'
  L('GROUP obj=' + $parts[0] + ' state=' + ($parts[1..($parts.Count - 1)] -join '|') + ' count=' + $agg[$key])
}
L('LSNS total=' + $lsNames.Count + ' ' + (C (($lsNames | Select-Object -First 25) -join ' ')))

# ---------- 4) control B: start someone ELSE'S LocalService/NetworkService service, same code? ----------
$tried = @()
foreach ($n in @('Dnscache', 'fdPHost', 'fdrespub', 'PNRPsvc', 'LanmanWorkstation', 'Wcmsvc', 'Themes',
                 'ShellHWDetection', 'ProfIEn', 'SENS', 'wcncsvc', 'fhsvc')) {
  $p = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue
  if (-not $p) { continue }
  $o = (C (('' + $p.ObjectName) -replace '(?i)^NT AUTHORITY\\', ''))
  if ($o -notmatch '(?i)^(LocalService|NetworkService)$') { continue }
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  if ("$st" -eq 'Running') { L('CONTROL ' + $n + ' ALREADY-RUNNING on ' + $o + ' (so 1297 is NOT about the account)'); continue }
  if (@($tried).Count -ge 2) { continue }
  $tried += $n
  L('CONTROL pick=' + $n + ' obj=' + $o)
  SvcRow $n -TryStart
}
if (@($tried).Count -eq 0) { L('CONTROL none (no stopped LS/NS service available to start)') }

# ---------- 5) read the right directly: is SE_SERVICE_LOGON_NAME granted at all? ----------
if ($native) {
  L('== 5 lsa rights ==')
  foreach ($who in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')) {
    try {
      # GetBinaryForm rather than .BinaryRepresentation: the property hands back a 0-length array on
      # the .NET Framework PS 5.1 ships with (verified on the host: 'sid bytes=0'), which made
      # AllocHGlobal(0) return NULL and the whole read die with a NullReferenceException.
      $si = New-Object System.Security.Principal.SecurityIdentifier($who)
      $sid = New-Object byte[] $si.BinaryLength
      $si.GetBinaryForm($sid, 0)
      $t = [Pe100]::Rights($sid)
      $has = if ($t -match 'SE_SERVICE_LOGON_NAME') { 'YES' } else { 'NO' }
      L('RIGHTS ' + $who + ' bytes=' + $sid.Length + ' se_service_logon=' + $has + ' ' + $t)
    } catch { L('RIGHTS ' + $who + ' ERR ' + (C $_.Exception.Message)) }
  }
}

# ---------- 6) what the binding layer was for: an interface wlansvc can manage ----------
L('== 6 adapter: interface wlansvc can manage ==')
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
foreach ($k in @(Get-ChildItem $cls -EA SilentlyContinue)) {
  if ($k.PSChildName -notmatch '^\d{4}$') { continue }
  $p = Get-ItemProperty -LiteralPath $k.PSPath -EA SilentlyContinue
  $fl = @()
  $lk = Join-Path $k.PSPath 'Linkage'
  if (Test-Path -LiteralPath $lk) {
    $j = Get-ItemProperty -LiteralPath $lk -Name 'FilterList' -EA SilentlyContinue
    if ($j) { $fl = @($j.PSObject.Properties['FilterList'].Value | ForEach-Object { "$_" }) }
  }
  $w = 0
  foreach ($e in $fl) { if ($e -match '(?i)nativewifip|E475CF9A|5CBF81BF') { $w++ } }
  $ncid = C ('' + $p.'*NetConnectionID')
  if ($w -eq 0 -and -not $ncid) { continue }
  L('CLS ' + $k.PSChildName + ' connid=[' + $ncid + '] medium=[' + (C ('' + $p.MediumType)) +
    '] wifi_entries=' + $w + ' fl=' + $fl.Count + ' drv=[' + (C ('' + $p.Driver)) + ']')
}
L('TCPIP_INTERFACES = ' + @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Interfaces' -EA SilentlyContinue).Count)
foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Interfaces' -EA SilentlyContinue)) {
  $p = Get-ItemProperty -LiteralPath $i.PSPath -EA SilentlyContinue
  L('IF ' + (C ('' + $p.Description)) + ' dhcp=[' + (C ('' + $p.DhcpIPAddress)) + '] ip=[' +
    (C (@([string[]]$p.IPAddress) -join ';')) + ']')
}

# ---------- 7) svchost groups as the image sees them (baked by task #40) ----------
L('== 7 svchost groups in the image ==')
$sv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
$sp = Get-ItemProperty -LiteralPath $sv -EA SilentlyContinue
if ($sp) {
  foreach ($nm in @($sp.PSObject.Properties.Name)) {
    if ($nm -match '^PS') { continue }
    $v = @($sp.$nm | ForEach-Object { "$_" })
    L('SVCHOST ' + $nm + ' = [' + ($v -join ';') + ']')
  }
  foreach ($g in @(Get-ChildItem $sv -EA SilentlyContinue)) {
    $gp = Get-ItemProperty -LiteralPath $g.PSPath -EA SilentlyContinue
    L('SVCHOSTSUB ' + $g.PSChildName + ' CoInitializeSecurityParam=' + ('' + $gp.CoInitializeSecurityParam) +
      ' AuthenticationCapability=' + ('' + $gp.AuthenticationCapability))
  }
} else { L('SVCHOST key ABSENT') }

L('probe100 end -- GROUP/LSNS + RIGHTS are the verdict on 1297; SVC/START carry the win32 code')
