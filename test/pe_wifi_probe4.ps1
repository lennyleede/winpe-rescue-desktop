# test/pe_wifi_probe4.ps1 -- runs INSIDE a live PE.
# probe2/3 established: every borrowed WiFi DLL resolves, dot3svc starts in the SAME svchost group,
# yet wlansvc stops immediately with an HRESULT-shaped exit code (0x800C0006 as read from
# SERVICE_STATUS_PROCESS). The stack in the image is 19041 while the PE base is 26100, so version
# skew is the leading suspect -- and the bench's own Windows partition is mounted right here.
#
# This probe only LOOKS:
#   A. what build is the client OS on the mounted system disk, and what version is its WiFi stack
#   B. does that OS carry a matching nwifi.sys / Intel AX211 (netwtw*) driver package
#   C. the PE's svchost group membership (correct registry location) + full service-key diff
#   D. raw SERVICE_STATUS_PROCESS bytes, decoded by hand (probe3's Config2 helpers caused an AV)
# Nothing is copied, no registry is written, no service is stopped.
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' ') -replace '\s{2,}', ' ' }
$S32 = Join-Path $env:SystemRoot 'System32'

Sec '0_A_WHOS_HERE'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' pebuild=' + [Environment]::OSVersion.Version.Build + ' sysroot=' + $env:SystemRoot)

function DriveRole([string]$d) {
  $w = Join-Path $d 'Windows'
  if (-not (Test-Path $w)) { return 'no-windows' }
  $ram = $false
  try {
    $vol = Get-Volume -DriveLetter $d.TrimEnd(':') -EA Stop
    if ($vol.BusType -eq 'File Backed Virtual' -or $vol.IsHidden -eq $true) { $ram = $true }
  } catch { }
  return ('has-windows' + $(if ($ram) { ' (ramdisk-looking)' } else { '' }))
}
$cands = @()
foreach ($dl in (Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue)) {
  $root = $dl.Root
  if (-not $root) { continue }
  $letter = $root.Substring(0, 1)
  $r = DriveRole ($letter + ':\')
  Write-Output ('  drive ' + $root + ' -> ' + $r + '  (used=' + [Math]::Round($dl.Used/1MB) + 'MB free=' + [Math]::Round($dl.Free/1MB) + 'MB)')
  if ($r -like 'has-windows*' -and $root -notlike ($env:SystemRoot.Substring(0, 2) + '*')) { $cands += ($letter + ':\') }
}
Write-Output ('  candidate client OS roots = ' + ($cands -join ' '))

Sec '1_A_CLIENT_OS_STACK_VERSIONS'
foreach ($root in $cands) {
  $cs = $root + 'Windows\System32'
  Write-Output ('  -- from ' + $cs)
  foreach ($f in @('ntdll.dll','wlansvc.dll','wlanapi.dll','wcmsvc.dll','wlancfg.dll','wlanmsm.dll','wlansec.dll','wlanutil.dll','wlansvcpal.dll','wlanhlp.dll','dmcmnutils.dll','mdmregistration.dll','wci.dll','netshell.dll','netsh.exe','drivers\nwifi.sys','drivers\ndisuio.sys','dot3svc.dll')) {
    $p = Join-Path $cs $f
    if (Test-Path -LiteralPath $p) {
      Write-Output ('     ' + $f.PadRight(24) + ' ' + (Get-Item -LiteralPath $p).VersionInfo.FileVersion)
    } else { Write-Output ('     ' + $f.PadRight(24) + ' ABSENT') }
  }
}

Sec '2_A_WIFI_DRIVER_PACKAGES_ON_CLIENT_OS'
foreach ($root in $cands) {
  $fr = Join-Path $root 'Windows\System32\DriverStore\FileRepository'
  if (-not (Test-Path $fr)) { Write-Output ('  ' + $fr + ' ABSENT'); continue }
  $dirs = @(Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)^netwtw|^netw|^rtwlan|^bcm|^bcml|^mtfwp|^wcfxs|^athw|^athwb|^intelwlan|^netbul' })
  Write-Output ('  ' + $root + ' wireless-looking FileRepository dirs = ' + $dirs.Count)
  foreach ($d in $dirs | Select-Object -First 25) {
    $infs = @(Get-ChildItem $d.FullName -File -Filter '*.inf' -EA SilentlyContinue)
    foreach ($i in $infs) {
      $t = ''
      try { $t = [IO.File]::ReadAllText($i.FullName) } catch { }
      $dv = ''
      if ($t -match '(?im)^DriverVer\s*=\s*([0-9/]+)\s*,\s*([0-9.]+)') { $dv = $Matches[2] }
      $ids = @([regex]::Matches($t, '(?i)PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}') | ForEach-Object { $_.Value.ToUpper() } | Sort-Object -Unique)
      Write-Output ('     ' + $d.Name + ' :: ' + $i.Name + ' DriverVer=' + $dv + ' ids=' + ($ids -join ' '))
    }
  }
}

Sec '3_C_SVCHOST_GROUPS_IN_PE'
$SH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
if (Test-Path $SH) {
  $gi = Get-Item $SH
  Write-Output ('  container ok, values=' + @($gi.GetValueNames()).Count)
  foreach ($n in @('LocalSystemNetworkRestricted','LocalServiceNetworkRestricted','NetworkService','LocalService')) {
    $lst = @($gi.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) | Where-Object { $_ }
    Write-Output ('  ' + $n.PadRight(32) + ' n=' + $lst.Count)
    Write-Output ('      ' + ($lst -join ','))
    Write-Output ('      wlansvc=' + ($lst -contains 'wlansvc') + ' wcmsvc=' + ($lst -contains 'wcmsvc') + ' dot3svc=' + ($lst -contains 'dot3svc'))
  }
} else { Write-Output '  NO SVCHOST CONTAINER' }

Sec '4_C_FULL_SERVICE_KEY_DUMP'
foreach ($s in @('wlansvc','wcmsvc','dot3svc')) {
  foreach ($sub in @('', '\Parameters', '\Security', '\EnumDependencies', '\TriggerInfo')) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s + $sub
    if (-not (Test-Path $k)) { if ($sub -eq '') { Write-Output ('  KEY MISSING: ' + $s) }; continue }
    $ki = Get-Item $k
    foreach ($vn in $ki.GetValueNames()) {
      $nm2 = if ($vn) { $vn } else { '(default)' }
      $raw = $ki.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
      $type = $ki.GetValueKind($vn)
      $disp = if ($raw -is [array]) { ($raw | ForEach-Object { if ($_ -is [byte]) { ('{0:X2}' -f $_) } else { [string]$_ } }) -join ',' } else { [string]$raw }
      if ($disp.Length -gt 200) { $disp = $disp.Substring(0, 200) + '...' }
      Write-Output ('  ' + $s + $sub + '\' + $nm2 + ' [' + $type + '] = ' + $disp)
    }
  }
}

Sec '5_D_RAW_SERVICE_STATUS'
$src = @'
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool QueryServiceStatusEx(IntPtr svc, uint infoLevel, byte[] buf, uint cb, out uint needed);
[ System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError=true) ]
static extern bool CloseServiceHandle(IntPtr h);
public static string Open() {
  IntPtr scm = OpenSCManagerW(null, null, 0x00010001); // SC_MANAGER_CONNECT | QUERY
  if (scm == System.IntPtr.Zero) return "OpenSCManager win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  return scm.ToString();
}
public static string Dump(IntPtr scm, string name) {
  IntPtr s = OpenServiceW(scm, name, 0x00000005); // QUERY_CONFIG | QUERY_STATUS
  if (s == System.IntPtr.Zero) return name + ": OpenService win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  byte[] buf = new byte[48];
  uint need;
  bool ok = QueryServiceStatusEx(s, 0, buf, (uint)buf.Length, out need);
  CloseServiceHandle(s);
  if (!ok) return name + ": QueryServiceStatusEx win32=" + System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  string hex = System.BitConverter.ToString(buf, 0, 36);
  int state = System.BitConverter.ToInt32(buf, 4);
  int ctrl  = System.BitConverter.ToInt32(buf, 8);
  int w32   = System.BitConverter.ToInt32(buf, 12);
  int spec  = System.BitConverter.ToInt32(buf, 16);
  int pid   = System.BitConverter.ToInt32(buf, 28);
  return name + " state=" + state + " controls=" + ctrl + " win32Exit=" + w32 + " (0x" + ((uint)w32).ToString("X8") +
         ") specific=" + spec + " (0x" + ((uint)spec).ToString("X8") + ") pid=" + pid + " raw=" + hex;
}
'@
try {
  $null = Add-Type -MemberDefinition $src -Name Scm -Namespace P4 -PassThru -Language CSharp -EA Stop
  $scmS = [P4.Scm]::Open()
  if ($scmS -match '^\d+$') {
    $scm = [IntPtr]::Parse($scmS)
    foreach ($n in @('wlansvc','wcmsvc','dot3svc','nsi','RpcSs')) { Write-Output ('  ' + [P4.Scm]::Dump($scm, $n)) }
  } else { Write-Output ('  ' + $scmS) }
} catch { Write-Output ('  scm probe failed: ' + (One $_.Exception.Message)) }

Sec '6_PE_LOG_AND_TRIGGER_LEFTOVERS'
Write-Output ('  wlansvc log = ' + $(if (Test-Path 'X:\wlansvc.log') { (Get-Content 'X:\wlansvc.log' -Raw) } else { '(none)' }))
foreach ($p in @("$env:SystemRoot\System32\winevt\Logs", "$env:SystemRoot\System32\winevt")) {
  Write-Output ('  ' + $(if (Test-Path $p) { 'OK   ' } else { 'ABSENT' }) + ' ' + $p)
}
$evl = @(Get-ChildItem (Join-Path $env:SystemRoot 'System32\winevt\Logs') -File -EA SilentlyContinue)
Write-Output ('  evtx files present = ' + $evl.Count + ' names=' + (($evl | ForEach-Object { $_.Name }) -join ' '))

Sec 'DONE'
Write-Output '  probe4 complete'
