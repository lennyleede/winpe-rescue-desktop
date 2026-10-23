# probe44 -- LIVE PE, read-only, ASCII only, output prefixed P44.
# Where probe42/43 left us: the bake is complete (INF/sys/keys/DriverStore), IncludedInfs is recorded,
# UpperFilters=vwifibus is on the devnode and SCM reports vwifibus as Running -- yet the AX211 stays
# code 37 = CM_PROB_FAILED_DRIVER_ENTRY and CIM shows Netwtw14 Stopped/False. So the thing that fails
# is the miniport START, not the registration. probe41/43 could not say why because PE writes almost
# no setupapi text (setupapi.dev.log = 1 line).
# This probe looks where PE actually records it: (a) WDF present? modern Intel WiFi is a WDF driver and
# needs Wdf01000.sys + the matching framework version; (b) is every [SourceDisksFiles] member really in
# the package dir; (c) the System event log (Kernel-PnP / NDIS / Service Control Manager) which carries
# the real status string.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function RGV([string]$key, [string]$name) {
  $o = @(& reg.exe query $key /v $name 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|MULTI_SZ|DWORD|BINARY)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim())
    }
  }
  return ''
}

# 1) WDF framework present? (Intel Netwtw* is a WDF driver; without Wdf01000 the load fails at once)
O '== 1 WDF =='
foreach ($f in 'Wdf01000.sys', 'WdfLdr.sys') {
  $p = 'X:\Windows\System32\drivers\' + $f
  if (Test-Path $p) {
    $v = (Get-Item $p).VersionInfo
    O ('  WDF ' + $f + ' ' + $v.FileMajorPart + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart)
  } else { O ('  WDF ' + $f + ' = ABSENT') }
}
foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Services\Wdf01000', 'HKLM:\SYSTEM\CurrentControlSet\Services\WdfLdr') {
  O ('  WDF SVC ' + (Split-Path $k -Leaf) + ' exists=' + (Test-Path $k) +
     ' Start=' + $(if (Test-Path $k) { (Get-ItemProperty $k -EA SilentlyContinue).Start } else { '-' }) +
     ' Img=' + $(if (Test-Path $k) { (Get-ItemProperty $k -EA SilentlyContinue).ImagePath } else { '-' }))
}

# 2) the staged Intel package: does every file its INF declares really exist?
O '== 2 package contents =='
$pkg = 'X:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_5433b0cac0a04d0e'
if (-not (Test-Path $pkg)) {
  $hits = @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue |
            Where-Object { $_.Name -match 'netwtw' })
  foreach ($h in $hits) { O ('  PKGFALLBACK ' + $h.Name) }
  if ($hits.Count -gt 0) { $pkg = $hits[0].FullName }
}
if (Test-Path $pkg) {
  $files = @(Get-ChildItem -LiteralPath $pkg -Recurse -File -EA SilentlyContinue)
  O ('  PKGDIR ' + (Split-Path $pkg -Leaf) + ' files=' + $files.Count + ' MB=' +
     [Math]::Round(((($files | Measure-Object Length -Sum).Sum) / 1MB), 1))
  foreach ($f in ($files | Sort-Object Name)) { O ('    F ' + ($f.FullName.Substring($pkg.Length + 1)) + ' ' + $f.Length) }
} else { O '  PKGDIR absent' }

# 3) what the installed INF itself says (Class / decorated sections / CatalogFile / Needs)
O '== 3 oem inf [Version] =='
$oi = @(Get-ChildItem 'X:\Windows\INF' -Filter 'oem161.inf' -File -EA SilentlyContinue)
if ($oi.Count -gt 0) {
  $t = @(Get-Content -LiteralPath $oi[0].FullName -Encoding Unicode -EA SilentlyContinue)
  foreach ($l in ($t | Select-Object -First 24)) { $s = ("$l" -replace '\s+', ' ').Trim(); if ($s -ne '') { O ('  IV ' + $s) } }
} else { O '  OEM161 ABSENT' }

# 4) event log -- the only place PE keeps the real failure string
O '== 4 event log =='
foreach ($src in 'Microsoft-Windows-Kernel-PnP', 'Microsoft-Windows-NDIS', 'Service Control Manager', 'Netwtw14', 'DriverFrameworks-UserMode', 'Microsoft-Windows-Kernel-General') {
  try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = $src } -MaxEvents 6 -EA Stop)
    O ('  EVT ' + $src + ' n=' + $ev.Count)
    foreach ($e in $ev) { O ('    E' + $e.Id + ' ' + $e.LevelDisplayName + ' ' + (($e.Message) -replace '\s+', ' ')) }
  } catch { O ('  EVT ' + $src + ' ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
}

# 5) current device state + the filter service state after probe42/43 touched it
O '== 5 state now =='
$dev = $null
foreach ($v in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)) {
  if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
    $inst = @(Get-ChildItem $v.PSPath -EA SilentlyContinue) | Select-Object -First 1
    if ($inst) { $dev = @{ reg = ('HKLM\SYSTEM\CurrentControlSet\Enum\PCI\' + $v.PSChildName + '\' + $inst.PSChildName)
                           full = ('PCI\' + $v.PSChildName + '\' + $inst.PSChildName) } }
  }
}
if ($dev) {
  O ('  CODE ' + @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
        Where-Object { $_.PNPDeviceID -eq $dev.full } | ForEach-Object { $_.ConfigManagerErrorCode }))
  O ('  UPPER ' + (RGV $dev.reg 'UpperFilters') + ' LOWER ' + (RGV $dev.reg 'LowerFilters') + ' SVC ' + (RGV $dev.reg 'Service'))
}
foreach ($n in 'vwifibus', 'vwififlt', 'nativewifip', 'Netwtw14', 'wlansvc') {
  $st = 'NOKEY'
  if (Test-Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n)) {
    try { $st = "$((Get-Service $n).Status)" } catch { $st = 'ERR' }
  }
  O ('  SVCNOW ' + $n + '=' + $st)
}
$h = [IntPtr]::Zero; $nv = 0
try {
  Add-Type -Namespace P44 -Name P44W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $rc = [P44.P44W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  WLANOPEN rc=' + $rc)
  if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P44.P44W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('  WLANOPEN-FAIL ' + (($_.Exception.Message) -replace '\s+', ' ')) }
O 'P44 END'
