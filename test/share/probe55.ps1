# probe55 -- LIVE PE, output prefixed nothing but all reads are from X: (ramdisk) + the laptop's offline hive.
# probe54 results (real hardware, AX211):
#   SCM wlansvc   : StartOK=True  -> state still Stopped (svchost loaded it and it left)
#   SCM wcmsvc    : err=1068 ERROR_SERVICE_DEPENDENCY_FAIL while RpcSs/DcomLaunch/nsi are Running
#   SCM nativewifp: err=31 ERROR_GEN_FAILURE (nwifi.sys 10.0.19041.7663)
#   pnputil /restart-device -> code 37 again; WlanOpenHandle rc=1062 (ERROR_SERVICE_NOT_ACTIVE)
#   Svchost table is fine: LocalSystemNetworkRestricted = hidserv,svsvc,Netman,dot3svc,wlansvc and that
#   svchost.exe -k LocalSystemNetworkRestricted IS running (pid 1316).
#   wlansvc.dll/wlanapi.dll/wlanmsm.dll/wcmsvc.dll are 10.0.19041-era, wlanutil/dot3svc are 26100.
#   NdisImPlatform.sys is MISSING (host has it) -> a candidate for nwifi's 31.
# probe54 printed ServiceDll=- because it read the SERVICE key; ServiceDll lives in the \Parameters subkey,
# so this probe dumps values+subkeys, diffs them against the laptop's working offline SYSTEM hive,
# LoadLibrary's the service DLLs to get the true missing-import error code (126 names nothing, but
# LOAD_WITH_ALTERED_SEARCH_PATH failures are still decisive vs "wrong path"), reads the System event log
# for SvcCtrlManager/sidebyside, then -- on the ramdisk only, which is not persistent -- writes whatever
# value the working hive has and the live PE lacks and re-runs the whole chain.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function RQ([string]$key, [string[]]$extra) {
  $a = @('query', $key) + @($extra)
  return @(& reg.exe @a 2>&1 | ForEach-Object { (("$_" -replace '\s+', ' ').Trim()) })
}

$PE = 'HKLM\SYSTEM\CurrentControlSet\Services'

HDR 'A live PE service keys, values + subkeys'
foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip', 'dot3svc', 'Ndisuio') {
  $out = @(RQ ($PE + '\' + $n) @('/s'))
  if ($out[0] -match 'ERROR') { O ('  A ' + $n + ' ' + $out[0]); continue }
  O ('  A ' + $n + ' lines=' + $out.Count)
  foreach ($l in ($out | Where-Object { $_ -match '^(HKEY|REG_|    )' } | Select-Object -First 34)) {
    O ('    | ' + $l)
  }
}

$hive = 'D:\Windows\System32\config\SYSTEM'
$key = 'HKLM\P55OFF'
$loaded = $false
try {
  $l = @(RQ $hive @())
  O ('  A0 hive ' + $(if ($l[0] -match 'ERROR') { 'ABSENT' } else { 'PRESENT' }))
  if ($l[0] -notmatch 'ERROR') {
    O ('  LOAD ' + ((& reg.exe load $key $hive 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) }) -join ' | '))
    if (@(RQ $key @())[0] -match '^HKEY') { $loaded = $true }
  }
  if ($loaded) {
    $OFF = $key + '\ControlSet001\Services'
    HDR 'B working offline hive: same keys (the reference)'
    foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip') {
      $out = @(RQ ($OFF + '\' + $n) @('/s'))
      if ($out[0] -match 'ERROR') { O ('  B ' + $n + ' ' + $out[0]); continue }
      O ('  B ' + $n + ' lines=' + $out.Count)
      foreach ($l2 in ($out | Where-Object { $_ -match '^(HKEY|REG_|    )' } | Select-Object -First 34)) {
        O ('    | ' + $l2)
      }
    }
    HDR 'C offline NDISIMPLATFORM + nwifi file version'
    $o = @(RQ ($OFF + '\NdisImPlatform') @())
    O ('  C svckey NdisImPlatform ' + $(if ($o[0] -match 'ERROR') { 'ABSENT' } else { 'PRESENT' }))
    foreach ($v in 'Start', 'Type', 'Group', 'ImagePath') {
      $q = @(RQ ($OFF + '\NdisImPlatform') @('/v', $v)) | Where-Object { $_ -match 'REG_' }
      if ($q.Count) { O ('    ' + $v + ' :: ' + $q[0]) }
    }
    foreach ($f in 'system32\drivers\NdisImPlatform.sys', 'system32\DRIVERS\nwifi.sys', 'system32\wlansvc.dll') {
      $p = 'D:\Windows\' + $f
      if (Test-Path -LiteralPath $p) {
        $i = Get-Item -LiteralPath $p
        O ('  C FILE ' + $f + ' ' + $i.Length + 'B ver=' + $i.VersionInfo.FileVersion)
      } else { O ('  C FILE ' + $f + ' MISSING') }
    }
    HDR 'D live PE: does the same file exist on X: ?'
    foreach ($f in 'System32\drivers\NdisImPlatform.sys', 'System32\drivers\ndisimplatform.sys') {
      $p = 'X:\Windows\' + $f
      if (Test-Path -LiteralPath $p) {
        $i = Get-Item -LiteralPath $p
        O ('  D ' + $f + ' ' + $i.Length + 'B')
      } else { O ('  D ' + $f + ' MISSING') }
    }
    HDR 'E inf: who references NdisImPlatform'
    $infdir = 'X:\Windows\INF'
    $hits = @(Get-ChildItem -LiteralPath $infdir -Filter '*.inf' -EA SilentlyContinue |
              ForEach-Object {
                $t = @(Get-Content -LiteralPath $_.FullName -Encoding Unicode -EA SilentlyContinue)
                if (@($t | Where-Object { $_ -match '(?i)NdisImPlatform' }).Count -gt 0) { $_.Name }
              })
    O ('  E INF_HITS ' + $(if ($hits.Count) { $hits -join ',' } else { 'none' }))
    $cab = @(Get-ChildItem -LiteralPath 'X:\Windows\WinSxS' -Filter '*ndisimplatform*' -EA SilentlyContinue)
    O ('  E WINSXS_HITS ' + $cab.Count)
  }
} catch { O ('  BERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
finally {
  if ($loaded) {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    O ('  UNLOAD ' + ((& reg.exe unload $key 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) }) -join ' | '))
    O ('  UNLOADCHECK ' + (@(RQ $key @())[0]))
  }
}

HDR 'F LoadLibrary the service DLLs (real error if they cannot map)'
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class L55 {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryExW(string path, IntPtr file, int flags);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern int GetLastError();
  public static string Try(string path) {
    IntPtr h = LoadLibraryExW(path, IntPtr.Zero, 0x00000008);   // LOAD_WITH_ALTERED_SEARCH_PATH
    int e = Marshal.GetLastWin32Error();
    return "handle=0x" + h.ToInt64().ToString("X") + " err=" + e;
  }
}
'@ -EA Stop
  O '  ADDTYPE ok'
  foreach ($f in 'X:\Windows\System32\wlansvc.dll', 'X:\Windows\System32\wlanmsm.dll',
                  'X:\Windows\System32\wcmsvc.dll', 'X:\Windows\System32\wlanutil.dll',
                  'X:\Windows\System32\dot3svc.dll', 'X:\Windows\System32\wlanapi.dll') {
    if (Test-Path -LiteralPath $f) {
      try { O ('  F ' + (Split-Path $f -Leaf) + ' : ' + [L55]::Try($f)) }
      catch { O ('  F ' + (Split-Path $f -Leaf) + ' ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
    } else { O ('  F ' + (Split-Path $f -Leaf) + ' MISSING') }
  }
} catch { O ('  F ADDTYPE-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }

HDR 'G System event log (Svc Ctrl Manager / sidebyside / application error)'
try {
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System' } -MaxEvents 120 -EA Stop |
          Where-Object { $_.ProviderName -match '(?i)Service Control Manager|sidebyside|Application|NDIS|Dhcp|wlan' } |
          Select-Object -First 22)
  O ('  G rows=' + $ev.Count)
  foreach ($e in $ev) {
    $msg = ''
    if ($e.Message) { $msg = (($e.Message -split "`r?`n")[0] -replace '\s+', ' ') }
    if ($msg.Length -gt 150) { $msg = $msg.Substring(0, 150) }
    O ('  G [' + $e.LevelDisplayName + '] ' + $e.ProviderName + '/' + $e.Id + ' ' + $e.TimeCreated + ' :: ' + $msg)
  }
} catch { O ('  G SYSLOG ' + (($_.Exception.Message) -replace '\s+', ' ')) }
try {
  $ap = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application' } -MaxEvents 60 -EA Stop | Select-Object -First 12)
  O ('  G APP rows=' + $ap.Count)
  foreach ($e in $ap) {
    $msg = ''
    if ($e.Message) { $msg = (($e.Message -split "`r?`n")[0] -replace '\s+', ' ') }
    if ($msg.Length -gt 150) { $msg = $msg.Substring(0, 150) }
    O ('  G APP [' + $e.LevelDisplayName + '] ' + $e.ProviderName + '/' + $e.Id + ' :: ' + $msg)
  }
} catch { O ('  G APPLOG ' + (($_.Exception.Message) -replace '\s+', ' ')) }

HDR 'H startnet / boot scripts present'
foreach ($f in 'X:\windows\system32\startnet.cmd', 'X:\storageprobe.ps1', 'X:\wifi.cmd', 'X:\wifibake.ps1') {
  if (Test-Path -LiteralPath $f) {
    $i = Get-Item -LiteralPath $f
    O ('  H ' + $f + ' ' + $i.Length + 'B modified=' + $i.LastWriteTime)
  } else { O ('  H ' + $f + ' MISSING') }
}
O ('  H CMDLINE_PID1 ' + (@(Get-CimInstance Win32_Process -EA SilentlyContinue |
      Where-Object { $_.Name -match '^(cmd|svchost|wlansvc)' } | ForEach-Object { $_.Name + ':' + $_.ProcessId }) -join ','))
O 'P55 END'
