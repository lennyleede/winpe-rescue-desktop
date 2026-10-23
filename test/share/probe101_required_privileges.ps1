# ============================================================
# probe101_required_privileges.ps1 -- why WdiServiceHost alone gives 1297
# ============================================================
#   probe100 on the live machine (192.168.0.102, disc 2026-10-12 14:25) settled two things:
#     1) the binding layer is FIXED:  WLAN-BIND=ok / wifi_entries=2 / vwifibus=True / 3 services Running,
#        and CLS 0001 now reads fl=2 wifi_entries=2.
#     2) 1297 is NOT "PE cannot log on as a service": LanmanWorkstation (NETWORK SERVICE) went START_OK and
#        is Running, Dnscache (NETWORK SERVICE) was already Running, 8 LocalService services are Running.
#        Only WdiServiceHost gives START_ERR=1297.
#   1297 = ERROR_NO_SUCH_PRIVILEGE. SCM looks up every name in the service key's RequiredPrivileges through
#   LsaLookupPrivilegeValue; a name that is not in this machine's LSA privilege list makes the start fail
#   with 1297 before the service process is even created. The host's WdiServiceHost requires
#   SeChangeNotifyPrivilege;SeImpersonatePrivilege;SeSystemProfilePrivilege -- a PE (minimal LSA policy)
#   very plausibly does not carry SeSystemProfilePrivilege.
#   So this probe reads the two lists and intersects them. It writes nothing.
#     A) every value of the four service keys, so we can diff against the host dump we already have;
#     B) the LSA policy's full privilege list (LsaQueryInformationPolicy PolicyPrivilegeInformation=2),
#        plus per-service: which RequiredPrivileges entries are MISSING there -- that is the verdict;
#     C) wcmsvc -> wlansvc, the order the host declares: start them in dependency order and see who dies.
#   Output: single-line ASCII, prefix P101.
$ErrorActionPreference = 'SilentlyContinue'
function L([string]$s) { Write-Output ('P101 ' + $s) }
function C([string]$s) { ((("$s") -replace '[^\x20-\x7e]', '?') -replace '\s+', ' ').Trim() }

L('probe101 begin ps=' + $PSVersionTable.PSVersion.ToString())

$src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Pe101 {
  [StructLayout(LayoutKind.Sequential)]
  struct LUID { public uint LowPart; public int HighPart; }
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenSCManagerW(string Machine, string Database, uint Access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr OpenServiceW(IntPtr Sc, string Name, uint Access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool StartServiceW(IntPtr Svc, uint NumArgs, IntPtr Args);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr H);
  const uint SC_MANAGER_CONNECT = 0x0001;
  const uint SERVICE_START = 0x0010;
  public static string Start(string name) {
    IntPtr sm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
    if (sm == IntPtr.Zero) { return "OPENSCMANAGER_ERR=" + Marshal.GetLastWin32Error(); }
    try {
      IntPtr sv = OpenServiceW(sm, name, SERVICE_START);
      if (sv == IntPtr.Zero) { return "OPENSERVICE_ERR=" + Marshal.GetLastWin32Error(); }
      try {
        if (StartServiceW(sv, 0, IntPtr.Zero)) { return "START_OK"; }
        return "START_ERR=" + Marshal.GetLastWin32Error();
      } finally { CloseServiceHandle(sv); }
    } finally { CloseServiceHandle(sm); }
  }

  [StructLayout(LayoutKind.Sequential)]
  struct OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [StructLayout(LayoutKind.Sequential)]
  struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)]
  struct LSA_PRIVILEGE_INFO { public uint Count; public IntPtr Privileges; }
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern int LsaOpenPolicy(IntPtr SystemName, ref OBJECT_ATTRIBUTES ObjectAttributes, int Access, out IntPtr PolicyHandle);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern int LsaQueryInformationPolicy(IntPtr PolicyHandle, int InformationClass, out IntPtr Buffer);
  [DllImport("advapi32.dll")]
  static extern int LsaFreeMemory(IntPtr Buffer);
  [DllImport("advapi32.dll")]
  static extern int LsaClose(IntPtr PolicyHandle);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern int LsaLookupPrivilegeValue(ref LSA_UNICODE_STRING Name, out LUID Value);
  const int POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
  const int PolicyPrivilegeInformation = 2;
  static int NameOffset { get { return IntPtr.Size == 8 ? 8 : 4; } }
  static string ReadUcs(IntPtr e) {
    int len = Marshal.ReadInt16(e) & 0xFFFF;
    IntPtr buf = Marshal.ReadIntPtr(e, NameOffset);
    if (len == 0 || buf == IntPtr.Zero) { return ""; }
    try { return Marshal.PtrToStringUni(buf, len / 2); } catch { return ""; }
  }
  // The machine's privilege list -- what LsaLookupPrivilegeValue can possibly resolve.
  public static string Privileges() {
    IntPtr pol = IntPtr.Zero, buf = IntPtr.Zero;
    try {
      OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
      oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
      int r = LsaOpenPolicy(IntPtr.Zero, ref oa, POLICY_VIEW_LOCAL_INFORMATION, out pol);
      if (r != 0) { return "LSA_OPEN_ERR=0x" + r.ToString("X8"); }
      r = LsaQueryInformationPolicy(pol, PolicyPrivilegeInformation, out buf);
      if (r != 0) { return "LSA_QUERY_ERR=0x" + r.ToString("X8"); }
      // count is the first ULONG; the array pointer follows (x64: offset 8 because of alignment)
      uint cnt = (uint)Marshal.ReadInt32(buf);
      IntPtr arr = Marshal.ReadIntPtr(buf, IntPtr.Size == 8 ? 8 : 4);
      StringBuilder sb = new StringBuilder();
      for (uint i = 0; i < cnt; i++) {
        IntPtr e = Marshal.ReadIntPtr(arr, (int)(i * IntPtr.Size));
        if (i > 0) { sb.Append(','); }
        sb.Append(ReadUcs(e));
      }
      return "N=" + cnt + " [" + sb.ToString() + "]";
    } finally {
      if (buf != IntPtr.Zero) { LsaFreeMemory(buf); }
      if (pol != IntPtr.Zero) { LsaClose(pol); }
    }
  }
  // Does THIS machine know this privilege name at all? Same call the SCM makes.
  public static int Lookup(string name) {
    LSA_UNICODE_STRING u = new LSA_UNICODE_STRING();
    byte[] b = System.Text.Encoding.Unicode.GetBytes(name);
    u.Length = (ushort)b.Length;
    u.MaximumLength = (ushort)(b.Length + 2);
    u.Buffer = Marshal.AllocHGlobal(b.Length + 2);
    try {
      Marshal.Copy(b, 0, u.Buffer, b.Length);
      Marshal.WriteInt16(u.Buffer, b.Length, 0);
      LUID v;
      int r = LsaLookupPrivilegeValue(ref u, out v);
      return r;   // 0 = STATUS_SUCCESS, 0xC000002C = STATUS_NO_SUCH_PRIVILEGE
    } finally { Marshal.FreeHGlobal(u.Buffer); }
  }
}
'@
$native = $false
try { Add-Type -TypeDefinition $src -Language CSharp -EA Stop | Out-Null; $native = $true }
catch { L('NATIVE add-type FAILED ' + (C $_.Exception.Message)) }

# ---------- A) the four keys, every value ----------
foreach ($n in @('wlansvc', 'wcmsvc', 'WdiServiceHost', 'wdisystemhost')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $ki = Get-Item -LiteralPath $k -EA SilentlyContinue
  if (-not $ki) { L('KEY ' + $n + ' ABSENT'); continue }
  foreach ($vn in @($ki.GetValueNames())) {
    $kind = '' + $ki.GetValueKind($vn)
    $v = $ki.GetValue($vn)
    if ($kind -match 'MultiString') { $v = @($v | ForEach-Object { "$_" }) -join ';' }
    L('VAL ' + $n + '\' + $vn + ' [' + $kind + '] = ' + (C ('' + $v)))
  }
}

# ---------- B) the machine privilege list + per-service missing names ----------
if ($native) {
  $pl = [Pe101]::Privileges()
  L('LSA_PRIVILEGES ' + $pl)
  foreach ($n in @('wlansvc', 'wcmsvc', 'WdiServiceHost', 'wdisystemhost')) {
    $rp = @((Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue).RequiredPrivileges)
    if (@($rp).Count -eq 0 -or -not $rp[0]) { L('PRIV ' + $n + ' RequiredPrivileges=(none) -> SCM grants no extra privilege, cannot be the 1297 source'); continue }
    $miss = @()
    foreach ($p in $rp) {
      if (-not $p) { $miss += '(empty entry)'; continue }
      $r = [Pe101]::Lookup("$p")
      if ($r -ne 0) { $miss += ($p + '=0x' + ('{0:X8}' -f $r)) }
    }
    L('PRIV ' + $n + ' count=' + @($rp).Count + ' unresolvable=[' + ($miss -join ',') + ']' +
      $(if (@($miss).Count -gt 0) { '  <== THIS is why SCM returns 1297' } else { '  all resolve' }))
  }
}

# ---------- C) dependency order, then who dies ----------
function Step([string]$n) {
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  L('STEP before ' + $n + ' = ' + $st)
  if ("$st" -eq 'Running') { return }
  if ($native) { L('STEP start ' + $n + ' ' + [Pe101]::Start($n)) }
  Start-Sleep -Seconds 3
  L('STEP after  ' + $n + ' = ' + (Get-Service -Name $n -EA SilentlyContinue).Status)
}
foreach ($n in @('nsi', 'RpcSs', 'Dnscache', 'wcmsvc', 'wlansvc', 'WdiServiceHost', 'wdisystemhost')) { Step $n }
# does svchost exist for them? which services live in a process now
foreach ($p in @(Get-Process -Name svchost -EA SilentlyContinue)) {
  $args2 = ''
  try { $args2 = (C ('' + (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $p.Id) -EA SilentlyContinue).CommandLine)) } catch { }
  L('SVCHOSTPID ' + $p.Id + ' cmd=[' + $args2 + ']')
}
L('FINAL wlansvc=' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status +
  ' wcmsvc=' + (Get-Service -Name wcmsvc -EA SilentlyContinue).Status +
  ' WdiServiceHost=' + (Get-Service -Name WdiServiceHost -EA SilentlyContinue).Status +
  ' wdisystemhost=' + (Get-Service -Name wdisystemhost -EA SilentlyContinue).Status)

# ---------- D) the wlan interface wlansvc would manage, via wlanapi ----------
# If wlansvc ever stays Running, the real question is whether EnumerateInterfaces returns the chip.
# netsh is not in PE, so call wlanapi directly (wlanapi.dll is present per probe100).
$wlanSrc = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class WlanApi {
  [DllImport("wlanapi.dll")]
  public static extern int WlanOpenHandle(uint ClientVersion, IntPtr Reserved, out int NegotiatedVersion, out IntPtr ClientHandle);
  [DllImport("wlanapi.dll")]
  public static extern int WlanCloseHandle(IntPtr ClientHandle, IntPtr Reserved);
  [DllImport("wlanapi.dll")]
  public static extern int WlanEnumInterfaces(IntPtr ClientHandle, IntPtr Reserved, out IntPtr List);
  [DllImport("wlanapi.dll")]
  public static extern void WlanFreeMemory(IntPtr Memory);
  // WLAN_INTERFACE_INFO_LIST { DWORD NumberOfItems; DWORD Index; WLAN_INTERFACE_INFO[] }  -- the array is INLINE
  // at offset 8, not a pointer. Each element: GUID(16) + WCHAR Description[256](512) + state DWORD at +528.
  public static string Interfaces() {
    int ver = 0; IntPtr h = IntPtr.Zero, list = IntPtr.Zero;
    int r = WlanOpenHandle(1, IntPtr.Zero, out ver, out h);
    if (r != 0) { return "OPEN_ERR=" + r + " (1062 = wlansvc not running, 1060 = no such service)"; }
    try {
      r = WlanEnumInterfaces(h, IntPtr.Zero, out list);
      if (r != 0) { return "ENUM_ERR=" + r; }
      int count = Marshal.ReadInt32(list, 0);
      if (count <= 0) { return "COUNT=0 ver=" + ver; }
      IntPtr e = new IntPtr(list.ToInt64() + 8);
      Guid g = (Guid)Marshal.PtrToStructure(e, typeof(Guid));
      string desc = "";
      try { desc = Marshal.PtrToStringUni(new IntPtr(e.ToInt64() + 16), 128).TrimEnd((char)0); } catch { }
      int state = Marshal.ReadInt32(e, 528);
      if (desc.Length > 48) { desc = desc.Substring(0, 48); }
      return "COUNT=" + count + " first{guid=" + g.ToString("N").Substring(0, 8) + " state=" + state +
             " desc=" + desc + "} ver=" + ver;
    } finally {
      if (list != IntPtr.Zero) { WlanFreeMemory(list); }
      WlanCloseHandle(h, IntPtr.Zero);
    }
  }
}
'@
try { Add-Type -TypeDefinition $wlanSrc -Language CSharp -EA Stop | Out-Null; L('WLANAPI ' + [WlanApi]::Interfaces()) }
catch { L('WLANAPI add-type/call FAILED ' + (C $_.Exception.Message)) }

L('probe101 end -- VAL/PRIV lines are the verdict on 1297; STEP/FINAL/WLANAPI say how far the stack now gets')
