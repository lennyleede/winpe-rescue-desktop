# probe48 -- LIVE PE, read-only, output prefixed P48.
# probe47 killed the group-order hypothesis: the PE's Control\ServiceGroupOrder is BYTE-IDENTICAL to the
# laptop's working hive (NDIS is present, in the same position), and vwififlt has Start=1/Group=NDIS in both.
# So the registry shape of the vWiFi stack is not what differs. What still differs is the OUTCOME:
# the AX211 miniport sits at code 37 (CM_PROB_FAILED_DRIVER_ENTRY) even with the laptop's own known-good
# package (probe46), while the Realtek 8125 in the same PE reaches code 0.
# This probe goes after the driver's OWN service key -- the one pnputil/drvload create for Netwtw## -- because
# no earlier probe has read it: Start/Type/Group/DependOnService/ImagePath + what happens when SCM starts it
# by hand (the exception text carries the Win32 error, e.g. 1068 dependency-missing / 31 failed / 577 signing).
# It also grabs DEVPKEY_Device_ProblemStatus (the human status string PnP stores) and the tail of the live
# setupapi.dev.log for the 7A70 devnode, which is the only place PE records why a driver entry was refused.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function RGV([string]$k, [string]$v) {
  $o = @(& reg.exe query $k /v $v 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
  $hit = @($o | Where-Object { $_ -match (' ' + [regex]::Escape($v) + ' REG_') })
  if ($hit.Count -gt 0) { return $hit[0] }
  return '-'
}

O '== 1 the WLAN device and its problem status =='
$dev = @(Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.InstanceId -like '*VEN_8086&DEV_7A70*' })
if ($dev.Count -eq 0) { O '  NO_AX211_DEVICE'; }
foreach ($d in $dev) {
  $id = $d.InstanceId
  O ('  DEV instance=' + $id)
  O ('  DEV status=' + $d.Status + ' problem=' + $d.ConfigErrorCode + ' class=' + $d.Class +
     ' service=' + $d.Service + ' friendly=' + $d.FriendlyName)
  foreach ($k in 'DEVPKEY_Device_ProblemStatus', 'DEVPKEY_Device_ProblemCode', 'DEVPKEY_Device_DriverInfPath',
                 'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverDate',
                 'DEVPKEY_Device_DriverServiceKeyPath', 'DEVPKEY_Device_ClassInstaller',
                 'DEVPKEY_Device_UpperFilters', 'DEVPKEY_Device_LowerFilters',
                 'DEVPKEY_Device_BackgroundInitialise') {
    $v = (Get-PnpDeviceProperty -InstanceId $id -Key $k -EA SilentlyContinue).Data
    O ('  KEY ' + $k + ' = ' + $(if ($null -eq $v) { '-' } elseif ($v -is [array]) { $v -join ',' } else { "$v" }))
  }
  $svc = "$($d.Service)"
  if (-not $svc) {
    # Service can be empty on some reads -- fall back to the registry Driver value.
    $drvKey = (Get-PnpDeviceProperty -InstanceId $id -Key 'DEVPKEY_Device_Driver' -EA SilentlyContinue).Data
    O ('  DRVKEY ' + $(if ($drvKey) { $drvKey } else { '-' }))
    $regPath = 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI' + '\' + ($id -replace '\\\\?0$', '')
    O ('  ENUMTRY ' + $regPath)
  }
}

O '== 2 the enum key for the device (authoritative Service + filters) =='
$enumRoot = 'HKLM\SYSTEM\CurrentControlSet\Enum\PCI'
$node = @($null)
foreach ($n in @(Get-ChildItem $enumRoot -EA SilentlyContinue)) {
  if ($n.PSChildName -like '*VEN_8086&DEV_7A70*') { $node = @($n) }
}
$svcName = ''
foreach ($n in $node) {
  foreach ($i in @(Get-ChildItem $n.PSPath -EA SilentlyContinue)) {
    $p = Get-ItemProperty -LiteralPath $i.PSPath -EA SilentlyContinue
    O ('  ENUM ' + $i.PSChildName + ' Service=' + $p.Service + ' Driver=' + $p.Driver +
       ' Class=' + $p.Class + ' Mfg=' + $p.Mfg + ' Upper=' + ($p.UpperFilters -join ',') +
       ' Lower=' + ($p.LowerFilters -join ',') + ' DeviceInst=' + $p.DeviceInstanceID)
    if ($p.Service) { $svcName = "$($p.Service)" }
  }
}

O '== 3 that service key in the live PE hive =='
if (-not $svcName) { $svcName = 'Netwtw14' }
$sk = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $svcName
O ('  SVCNAME ' + $svcName)
if (Test-Path -LiteralPath $sk) {
  $p = Get-ItemProperty -LiteralPath $sk -EA SilentlyContinue
  O ('  START=' + $p.Start + ' TYPE=' + $p.Type + ' GROUP=' + ($p.Group -join ',') +
     ' DEPEND=' + ($p.DependOnService -join ',') + ' ERRORCONTROL=' + $p.ErrorControl)
  O ('  IMAGE=' + $p.ImagePath)
  foreach ($s in 'Parameters', 'Enum', 'NetworkAddress') {
    O ('  SUBKEY ' + $s + ' = ' + (Test-Path -LiteralPath (Join-Path $sk $s)))
  }
  O ('  STATE = ' + $(try { "$(Get-Service $svcName).Status" } catch { 'NOGET' }))
  O ('  FILE  = ' + $(try { $f = $p.ImagePath -replace '%SystemRoot%', 'X:\Windows' -replace '^system32', 'X:\Windows\system32'
       if ($f -notmatch '^[A-Za-z]:') { $f = 'X:\Windows\system32\' + ($f -replace '^[\\/]', '') }
       $fi = Get-Item $f -EA SilentlyContinue
       if ($fi) { $fi.Length.ToString() + 'B ver=' + $fi.VersionInfo.ProductVersion + ' at ' + $f } else { 'MISSING ' + $f }
     } catch { 'ERR' }))
  O '  trying SCM Start() by hand =='
  try {
    $svc = Get-Service $svcName -EA Stop
    $svc.Start()
    Start-Sleep -Seconds 3
    O ('  STARTED state=' + $svc.Status)
  } catch {
    O ('  STARTERR ' + (($_.Exception.Message) -replace '\s+', ' '))
    O ('  INNER ' + $(if ($_.Exception.InnerException) { (($_.Exception.InnerException.Message) -replace '\s+', ' ') } else { '-' }))
  }
  # which declared dependency is missing?
  foreach ($dep in @($p.DependOnService)) {
    if ($dep) {
      $ok = Test-Path -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $dep)
      $st = '-'
      try { $st = "$(Get-Service $dep).Status" } catch { $st = 'NOGET' }
      O ('  DEP ' + $dep + ' keyPresent=' + $ok + ' state=' + $st)
    }
  }
} else {
  O ('  SERVICES_KEY_ABSENT ' + $svcName)
}

O '== 4 setupapi.dev.log: the 7A70 sections, errors only =='
$slog = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path -LiteralPath $slog) {
  $lines = @(Get-Content -LiteralPath $slog -EA SilentlyContinue)
  O ('  LOG lines=' + $lines.Count)
  $idx = @()
  for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'DEV_7A70') { $idx += $i } }
  O ('  HITS ' + $idx.Count)
  $shown = @{}
  foreach ($h in ($idx | Select-Object -Last 2)) {
    for ($j = [Math]::Max(0, $h - 2); $j -lt [Math]::Min($lines.Count, $h + 120); $j++) {
      $l = "$($lines[$j])"
      if ($l -match '(!!!|\-\-\-|>>> |Start services|device install|Driver package|service|install state|Stylize)' -and
          -not $shown.ContainsKey($j)) {
        $shown[$j] = $true
        O ('  L' + $j + ' ' + ($l -replace '\s+', ' ').Trim().Substring(0, [Math]::Min(150, ($l -replace '\s+', ' ').Trim().Length)))
      }
    }
  }
} else { O '  LOG ABSENT' }
O 'P48 END'
