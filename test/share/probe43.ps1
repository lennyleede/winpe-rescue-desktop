# probe43 -- LIVE PE read + two bounded experiments, ASCII only, output prefixed P43.
# Why: probe42 proved UpperFilters=vwifibus alone does NOT clear code 37 (restart-device ok, still 37),
# and PE writes essentially no setupapi text (setupapi.dev.log = 1 line), so we have no "who failed" answer.
# This probe gets the answer two ways:
#   (1) dump the *class instance* key the device uses (Driver= value) and compare its Ndi shape to a
#       working Windows (build\scratch\host_vwifi_class.ps1 runs the same dump on the host);
#   (2) ask SCM to StartService each member of the stack and print the exact Win32 error -- probe23
#       already proved SCM errors are discriminating in PE (577 before the .cat, 31 after).
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
# NOTE: never name a function "RV" -- that is the built-in alias for Remove-Variable and the alias wins.
function RGV([string]$key, [string]$name) {
  $o = @(& reg.exe query $key /v $name 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|MULTI_SZ|DWORD|BINARY)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim())
    }
  }
  return ''
}
function DumpKey([string]$label, [string]$reg) {
  if (-not (Test-Path ($reg -replace '^HKLM', 'HKEY_LOCAL_MACHINE'))) {
    $ex = @(& reg.exe query $reg 2>&1 | ForEach-Object { "$_" })
    if ($ex[0] -match 'ERROR') { O ('   ' + $label + ' KEY ABSENT'); return }
  }
  $out = @(& reg.exe query $reg 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  O ('   ' + $label + ' [' + $reg + ']')
  foreach ($l in $out) { if ($l -ne '') { O ('     | ' + $l) } }
}

$dev = $null
foreach ($v in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)) {
  if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
    $inst = @(Get-ChildItem $v.PSPath -EA SilentlyContinue) | Select-Object -First 1
    if ($inst) {
      $dev = @{ reg = ('HKLM\SYSTEM\CurrentControlSet\Enum\PCI\' + $v.PSChildName + '\' + $inst.PSChildName)
                full = ('PCI\' + $v.PSChildName + '\' + $inst.PSChildName) }
    }
  }
}
if (-not $dev) { O 'P43 FATAL AX211 not under Enum\PCI'; O 'P43 END'; exit 0 }
O ('P43 DEV ' + $dev.full)
O ('P43 code      = ' + @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
      Where-Object { $_.PNPDeviceID -eq $dev.full } | ForEach-Object { $_.ConfigManagerErrorCode }))
$svc = RGV $dev.reg 'Service'
$drv = RGV $dev.reg 'Driver'
$up  = RGV $dev.reg 'UpperFilters'
$lo  = RGV $dev.reg 'LowerFilters'
O ('P43 Service=[' + $svc + '] Driver=[' + $drv + '] Upper=[' + $up + '] Lower=[' + $lo + ']')

# 1) the class-install keys a working Windows keeps its Ndi shape in
if ($drv -ne '') { DumpKey 'CLASSINST' ('HKLM\SYSTEM\CurrentControlSet\Control\Class\' + $drv) }
$netGuid = '{4d36e972-e325-11ce-bfc1-08002be10318}'
DumpKey 'CLASS_ROOT' ('HKLM\SYSTEM\CurrentControlSet\Control\Class\' + $netGuid)
O ('   CLASS_NDI_SUBKEYS ' + (@(Get-ChildItem ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $netGuid) -EA SilentlyContinue |
      ForEach-Object { $_.PSChildName }) -join ','))

# 2) SCM start attempts -- the discriminating error codes
foreach ($n in 'vwifibus', 'vwififlt', 'nativewifip', $svc) {
  if (-not $n) { continue }
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (-not (Test-Path $p)) { O ('   START ' + $n + ' SERVICE KEY ABSENT'); continue }
  $st = ''
  try { $st = (Get-Service $n -EA Stop).Status } catch { $st = 'NOGET ' + ($_.Exception.Message -replace '\s+', ' ') }
  $r = ''
  try {
    $s2 = Get-Service $n
    if ("$($s2.Status)" -ne 'Running') { $s2.Start(); Start-Sleep -Seconds 2 }
    $r = 'OK now=' + (Get-Service $n).Status
  } catch { $r = 'FAIL ' + (($_.Exception.Message) -replace '\s+', ' ') }
  $sc = @(& sc.exe start $n 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  O ('   START ' + $n + ' before=' + $st + ' ps=' + $r + ' sc=' + ($sc -join ' / '))
  O ('        Start=' + (RGV ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) 'Start') +
     ' Group=' + (RGV ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) 'Group') +
     ' ImagePath=' + (RGV ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) 'ImagePath') +
     ' Depend=' + (RGV ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n) 'DependOnService'))
}

# 3) is the .sys actually on disk where ImagePath points, and does NDIS see any wifi filter?
foreach ($y in 'vwifibus.sys', 'vwififlt.sys', 'nwifi.sys', 'vwifimp.sys') {
  $fp = 'X:\Windows\System32\drivers\' + $y
  O ('   SYSFILE ' + $y + ' = ' + (Test-Path $fp))
}
O ('   NDIS_FILTERS ' + (@(& reg.exe query ('HKLM\SYSTEM\CurrentControlSet\Services\NetBT') 2>&1 | ForEach-Object { "$_" }).Count))
# 4) last chance for a reason string: the devnode's own problem text + any ReinstallDriver
O ('   REINSTALL ' + (RGV $dev.reg 'ReinstallDriver'))
O ('   ENUMSTATUS ' + (RGV $dev.reg 'InstallState'))
O ('   CONFIGFLAGS ' + (RGV $dev.reg 'ConfigFlags'))
# 5) does removing + rescanning (fresh install from the staged INF) change anything? probe41 said the
#    handwritten filters get wiped; here we only report the resulting code, no further edits.
$s5 = RGV $dev.reg 'Class'
O ('   CLASS ' + $s5)
O 'P43 END'
