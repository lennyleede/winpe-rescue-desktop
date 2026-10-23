param([int]$Controls = 5)
$ErrorActionPreference = 'SilentlyContinue'
# probe40 -- is 0x80000002 (STATUS_INVALID_DEVICE_STATE, which is also what Win32 error 31 maps from)
# a verdict about the WiFi drivers, or a verdict about NtLoadDriver inside WinPE?
#
# probe39 (after fixing the ANSI/Unicode LookupPrivilegeValue bug -- SeLoadDriverPrivilege is held,
# ADJUST ok=True err=0) loaded vwifibus / vwififlt / nativewifip / vwifimp and every single one came
# back 0x80000002. That number is *not* a code-signing rejection (that would be 0xC0000428 /
# 0xC000022F / 0xC0000042), so CI is no longer blocking us. But four identical answers from four
# different drivers is suspicious, so this probe loads control drivers that have nothing to do with
# WiFi and compares.
#
#   controls all 0x80000002  -> NtLoadDriver is blocked in PE; only PnP/SCM at boot can start
#                               drivers, which means the recipe must be baked into the image.
#   controls 0x00000000      -> the API works here, so the WiFi drivers themselves refuse to
#                               initialize -> compare the NDIS/file versions below to find why.
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Nt40 {
  [DllImport("ntdll.dll", SetLastError=true)] public static extern int NtLoadDriver(string serviceName);
  [DllImport("ntdll.dll", SetLastError=true)] public static extern int NtUnloadDriver(string serviceName);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool LookupPrivilegeValueW(string h, string n, out long luid);
  [StructLayout(LayoutKind.Sequential)] public struct LA { public int Low; public int High; public uint Attr; }
  [StructLayout(LayoutKind.Sequential)] public struct TP { public uint Count; public LA Luid; }
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, int l, IntPtr p, IntPtr r);
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  public static string Enable() {
    IntPtr tok; if (!OpenProcessToken(GetCurrentProcess(), 0x28u, out tok)) return "OPEN-TOKEN-FAIL " + Marshal.GetLastWin32Error();
    long luid; if (!LookupPrivilegeValueW(null, "SeLoadDriverPrivilege", out luid)) return "LOOKUP-FAIL " + Marshal.GetLastWin32Error();
    TP tp = new TP(); tp.Count = 1; tp.Luid.Low = (int)(luid & 0xFFFFFFFFL); tp.Luid.High = (int)(luid >> 32); tp.Luid.Attr = 2u;
    bool ok = AdjustTokenPrivileges(tok, false, ref tp, Marshal.SizeOf(typeof(TP)), IntPtr.Zero, IntPtr.Zero);
    return "ok=" + ok + " err=" + Marshal.GetLastWin32Error();
  }
  public static string Load(string svc) { return "0x" + NtLoadDriver("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + svc).ToString("X8"); }
  public static string Unload(string svc) { return "0x" + NtUnloadDriver("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" + svc).ToString("X8"); }
}
'@ -EA SilentlyContinue
function Say([string]$m) { Write-Output ('C40|' + $m) }
function Raw([string]$s) { return (($s -replace "`r?`n", ' ; ') -replace '\s{2,}', ' ') }
function Ver([string]$p) {
  $o = Get-Item $p -EA SilentlyContinue
  if (-not $o) { return 'absent' }
  $v = $o.VersionInfo
  return ($v.FileMajorPart.ToString() + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart + '|' + $o.Length)
}
Write-Output ('PROBE40 ' + (Get-Date -Format 'HH:mm:ss'))
Say ('PRIV=' + [Nt40]::Enable())

# A. whose build is this really? the cats in the image are 19041-era; if PE's NDIS is 19041 and the
# borrowed drivers are 19041 too, a version mismatch is off the table.
Say ('BUILD|' + (Raw (& reg.exe query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' /v CurrentBuild 2>&1 | Out-String)))
Say ('BUILDNUM|' + (Raw (& reg.exe query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' /v CurrentBuildNumber 2>&1 | Out-String)))
Say ('UBR|' + (Raw (& reg.exe query 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' /v UBR 2>&1 | Out-String)))
foreach ($p in @(
  'X:\Windows\System32\drivers\ndis.sys',
  'X:\Windows\System32\drivers\nwifi.sys',
  'X:\Windows\System32\drivers\vwifibus.sys',
  'X:\Windows\System32\drivers\vwififlt.sys',
  'X:\Windows\System32\drivers\vwifimp.sys',
  'X:\Windows\System32\ntoskrnl.exe',
  'D:\Windows\System32\drivers\ndis.sys',
  'D:\Windows\System32\drivers\nwifi.sys',
  'D:\Windows\System32\drivers\vwifibus.sys')) {
  Say ('VER|' + $p + '|' + (Ver $p))
}

# B. NDIS version the image advertises, and what nativewifip asks for.
$np = Raw (& reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\Ndis' /v ImagePath 2>&1 | Out-String)
Say ('NDIS_I|' + $np)
$nv = Raw (& reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters' 2>&1 | Out-String)
Say ('NDIS_PARAMS|' + $nv.Substring(0, [Math]::Min(400, $nv.Length)))
foreach ($n in @('nativewifip', 'vwifibus', 'vwififlt', 'vwifimp')) {
  $r = Raw (& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) /v NdisMinorVersion 2>&1 | Out-String)
  Say ('NEEDSMINOR|' + $n + '|' + $r)
}

# C. controls: stopped, SCM-known drivers that have nothing to do with WiFi.
$all = @(Get-CimInstance Win32_SystemDriver)
Say ('SCMDRV_TOTAL=' + $all.Count)
$stopped = @($all | Where-Object { $_.State -eq 'Stopped' -and $_.Name -notmatch '(?i)vwifi|nwifi|nativewifip|Netwtw' })
Say ('SCMDRV_STOPPED=' + $stopped.Count + '|' + (($stopped | ForEach-Object { $_.Name }) -join ',' ))
$pick = @($stopped | Select-Object -First $Controls | ForEach-Object { $_.Name })
foreach ($n in @($pick)) {
  $ip = Raw (& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) /v ImagePath 2>&1 | Out-String)
  Say ('CTRL|' + $n + '|IMG=' + $ip)
  Say ('CTRL|' + $n + '|NTLOAD=' + [Nt40]::Load($n))
  $g = Get-CimInstance Win32_SystemDriver -Filter "Name='$n'" -EA SilentlyContinue
  if ($g) { Say ('CTRL|' + $n + '|NOW=' + $g.State) }
}

# D. the WiFi four again, in the same process, so the comparison is apples-to-apples.
foreach ($n in @('vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'Netwtw14')) {
  Say ('WIFI|' + $n + '|NTLOAD=' + [Nt40]::Load($n))
}
Say ('WIFI|nativewifip|UNLOAD=' + [Nt40]::Unload('nativewifip'))
Say ('WIFI|nativewifip|RELOAD=' + [Nt40]::Load('nativewifip'))
Write-Output 'PROBE40 END'
