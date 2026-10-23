# onsite.ps1 -- real-machine storage driver validation + evidence capture, run straight off the USB stick.
#
# Why this exists: the seven packages in overlay\Drivers\Storage are deliberately NOT baked into the
# current ISO (Step 2 waits for proof that they bind). So the field box boots the existing PE and this
# script feeds the INFs to drvload from removable media, proves whether the Intel VMD / RST controller
# really binds, and leaves the evidence bundle ON THE STICK (no frp uplink needed to get it off).
#
# Usage inside the PE (plain cmd; the stick letter is whatever the BIOS gave it):
#   D:\> D:\onsite.cmd                 (shim uses the absolute powershell path - PS is not in PATH)
# Options: -SkipDrvload  -SkipRescue  -InfDir D:\Storage  -OutRoot D:\rescue  -SelfTest
#
# Judgment rule (learned the hard way, see project memory): drvload's exit code is worthless, it
# returns 0 even when nothing bound. Success is measured by  (a) the devnode losing its problem code
# and  (b) Get-Disk / <drive>:\Windows\System32\config\SOFTWARE appearing.
#
# ASCII output only: PE consoles are not CP936-safe for non-ASCII text.

param(
  [string]$InfDir = '',
  [string]$OutRoot = '',
  [string[]]$Inf = @(),
  [switch]$SkipDrvload,
  [switch]$SkipRescue,
  [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:PsExe  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:Log    = ''
$script:Stick  = ''

function Stamp { return (Get-Date).ToString('HH:mm:ss') + '  ' }
function Say([string]$s) {
  $s = ($s -replace '[^\x20-\x7E]', '?')
  Write-Output ((Stamp) + $s)
  if ($script:Log) {
    try { Add-Content -LiteralPath $script:Log -Value ((Stamp) + $s) -Encoding ASCII } catch { }
  }
}
function Sec([string]$s) { Say ''; Say ('==== ' + $s + ' ====') }

# ---------------------------------------------------------------- storage state
function Get-DiskState {
  $d = @()
  try { $d = @(Get-Disk -ErrorAction SilentlyContinue) } catch { Say ('  Get-Disk FAIL ' + $_.Exception.Message) }
  return $d
}
function Describe-Disks([object[]]$disks) {
  Say ('  disk count = ' + $disks.Count)
  foreach ($x in $disks) {
    $sz = 0
    if ($x.Size) { $sz = [math]::Round($x.Size / 1GB, 0) }
    $rp = ''
    foreach ($p in @($x | Get-Partition -ErrorAction SilentlyContinue)) {
      if ($p.AccessPaths) { $rp = ($p.AccessPaths -join ',') }
    }
    Say ('    ' + $x.Number + ' ' + (Ascii1 $x.FriendlyName) + ' bus=' + $x.BusType + ' ' + $sz + 'GB part=' + $rp)
  }
}
function Ascii1([string]$s) { if ($s) { return ($s -replace '[^\x20-\x7E]', '?') } return '' }

function Get-OfflineWindows {
  $hits = @()
  foreach ($l in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne 'X' })) {
    $p = ($l.Root -replace '\\+$', '') + '\Windows\System32\config\SOFTWARE'
    try { if ([IO.File]::Exists($p)) { $hits += ($l.Root) } } catch { }
  }
  return $hits
}

function Get-PnpSnapshot {
  $rows = @()
  try {
    $rows = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
      Where-Object { $_.DeviceID -and ($_.DeviceID -match '^PCI\\|^USB\\') })
  } catch { Say ('  PnP query FAIL ' + $_.Exception.Message) }
  return $rows
}

function Describe-ProblemDevices([object[]]$rows) {
  $bad = @($rows | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
  Say ('  problem devnodes = ' + $bad.Count)
  foreach ($d in $bad) {
    Say ('    code=' + $d.ConfigManagerErrorCode + ' class=' + (Ascii1 $d.PNPClass) + ' ' + (Ascii1 $d.DeviceID))
  }
}

# ---------------------------------------------------------------- inf parsing (UTF-16 aware)
function Read-InfText([string]$f) {
  $b = [IO.File]::ReadAllBytes($f)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
  }
  return [Text.Encoding]::UTF8.GetString($b)
}
function Get-InfIds([string]$f) {
  $t = Read-InfText $f
  return @([regex]::Matches($t, '(?i)PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') |
    ForEach-Object { 'PCI\VEN_' + $_.Groups[1].Value.ToUpper() + '&DEV_' + $_.Groups[2].Value.ToUpper() } |
    Sort-Object -Unique)
}
function Test-IdOnBus([string]$id, [object[]]$rows) {
  # DeviceID looks like PCI\VEN_8086&DEV_467F&SUBSYS_...&REV_00\<serial> - prefix match, not equality.
  foreach ($d in $rows) { if ($d.DeviceID.ToUpper().StartsWith($id.ToUpper() + '&')) { return $d } }
  return $null
}

# ---------------------------------------------------------------- main
$here = ''
if ($PSCommandPath) { $here = Split-Path -Parent $PSCommandPath }
if (-not $here) { $here = (Get-Location).Path }
$stickRoot = $here
if ((Split-Path -Leaf $here) -eq 'Tools') { $stickRoot = Split-Path -Parent $here }

$cand = @($InfDir, (Join-Path $stickRoot 'Storage'), (Join-Path $here '..\Drivers\Storage'),
         (Join-Path $here '..\..\overlay\Drivers\Storage'))
foreach ($c in $cand) {
  if ($c -and (Test-Path -LiteralPath $c)) { $script:Stick = (Resolve-Path -LiteralPath $c).Path; break }
}
if (-not $script:Stick) { Write-Output 'FAIL no Storage folder found (expected <stick>\Storage)'; exit 1 }
if (-not $OutRoot) { $OutRoot = (Join-Path (Split-Path -Parent $script:Stick) 'rescue') }

$pkgs = @([IO.Directory]::GetDirectories($script:Stick) | Sort-Object)
if ($Inf.Count -gt 0) { $pkgs = @($Inf | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } ) }

Say ('ONSITE start  selftest=' + [bool]$SelfTest)
Say ('  inf dir    = ' + $script:Stick)
Say ('  out root   = ' + $OutRoot)
Say ('  packages   = ' + $pkgs.Count)
Say ('  computer   = ' + $env:COMPUTERNAME + '  os=' + [Environment]::OSVersion.Version.ToString())
$os = $null
try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue } catch { }
if ($os) { Say ('  build      = ' + $os.Version + ' (' + $os.BuildNumber + ')  ' + (Ascii1 $os.Caption)) }

if (-not $SelfTest) {
  try {
    if (-not [IO.Directory]::Exists($OutRoot)) { [IO.Directory]::CreateDirectory($OutRoot) | Out-Null }
    $script:Log = Join-Path $OutRoot 'onsite.log'
    Say ('  log        = ' + $script:Log)
  } catch { Write-Output ('  WARN out root not writable: ' + $_.Exception.Message) }
} else { $script:Log = '' }

# ---- [1] tools onto the ramdisk (so 'storageprobe' / 'rescue' work by name)
Sec 'TOOLS'
if ($SelfTest) {
  Say '  selftest: skip ramdisk install'
} else {
  $sys32 = Join-Path $env:SystemRoot 'System32'
  $srcs  = @()
  if ((Split-Path -Leaf $here) -eq 'Tools') { $srcs = @([IO.Directory]::GetFiles($here, '*.ps1')) + @([IO.Directory]::GetFiles($here, '*.cmd')) }
  if ($srcs.Count -eq 0) { Say '  running from System32 already, nothing to install' }
  foreach ($f in $srcs) {
    $dst = Join-Path $sys32 ([IO.Path]::GetFileName($f))
    try { Copy-Item -LiteralPath $f -Destination $dst -Force; Say ('  installed ' + [IO.Path]::GetFileName($f)) }
    catch { Say ('  copy FAIL ' + [IO.Path]::GetFileName($f) + ' ' + $_.Exception.Message) }
  }
}

# ---- [2] state BEFORE
Sec 'BEFORE'
$disksB = @(Get-DiskState)
Describe-Disks $disksB
$offB = @(Get-OfflineWindows)
Say ('  offline windows roots = ' + $(if ($offB.Count) { $offB -join ' ' } else { 'NONE (cannot reach the installed OS)' }))
$rowsB = @(Get-PnpSnapshot)
Say ('  pci/usb devnodes = ' + $rowsB.Count)
Describe-ProblemDevices $rowsB

$probePs = Join-Path $env:SystemRoot 'System32\storageprobe.ps1'
if (-not $SelfTest -and (Test-Path -LiteralPath $probePs)) {
  Say '  running storageprobe (before)'
  $o = & $script:PsExe -NoProfile -ExecutionPolicy Bypass -File $probePs 2>&1
  $o | ForEach-Object { Say ('    ' + ($_ -replace '[^\x20-\x7E]', '?')) }
  if (Test-Path -LiteralPath 'X:\storageprobe.txt') {
    try { Copy-Item -LiteralPath 'X:\storageprobe.txt' -Destination (Join-Path $OutRoot 'storageprobe-before.txt') -Force; Say '    saved storageprobe-before.txt' } catch { }
  }
}

# ---- [3] which package matches this machine, then drvload
Sec 'MATCH'
$plan = @()
foreach ($p in $pkgs) {
  $infs = @([IO.Directory]::GetFiles($p, '*.inf'))
  foreach ($i in $infs) {
    $ids = @(Get-InfIds $i)
    $need = @()
    $boundIds = @()
    foreach ($id in $ids) {
      $d = Test-IdOnBus $id $rowsB
      if (-not $d) { continue }
      # code 0 means something already owns the controller - drvload would be pointless (and can regress it).
      if ($d.ConfigManagerErrorCode -eq 0) { $boundIds += ($id + ' code=0 ' + (Ascii1 $d.PNPClass)) }
      else { $need += ($id + ' code=' + $d.ConfigManagerErrorCode) }
    }
    $shown = ''
    if ($need.Count)      { $shown = 'NEEDS DRIVER: ' + ($need -join ' / ') }
    elseif ($boundIds.Count) { $shown = 'already bound: ' + ($boundIds -join ' / ') }
    else                  { $shown = 'no id on this bus' }
    Say ('  ' + [IO.Path]::GetFileName($p) + ' ids=' + $ids.Count + '  ' + $shown)
    if ($need.Count -gt 0) { $plan += [pscustomobject]@{ Inf = $i; Hit = $need } }
  }
}

Sec 'DRVLOAD'
$bound = ''
if ($SkipDrvload) { Say '  skipped by switch' }
elseif ($plan.Count -eq 0) {
  if ($offB.Count -gt 0) { Say '  no unbound storage devnode and the OS disk is already visible -> nothing to do (sysdisk=ok)' }
  else { Say '  NONE of the packages declares an id present on this bus - see the problem devnode list above' }
} else {
  foreach ($p in $plan) {
    Say ('  drvload ' + $p.Inf)
    if ($SelfTest) { Say '    selftest: not loading drivers'; $bound = $p.Inf; break }
    $o = & cmd.exe /c ('drvload ' + $p.Inf) 2>&1
    ($o | Out-String).Trim() -split "`r?`n" | ForEach-Object { Say ('    ' + ($_ -replace '[^\x20-\x7E]', '?')) }
    Start-Sleep -Seconds 4
    $rows = @(Get-PnpSnapshot)
    $disks = @(Get-DiskState)
    $off = @(Get-OfflineWindows)
    Say ('    after: disks=' + $disks.Count + ' offline=' + $(if ($off.Count) { $off -join ' ' } else { 'NONE' }))
    # PE ignores "reboot required" installs: a code18 devnode needs remove-device + rescan, not drvload.
    foreach ($h in $p.Hit) {
      $id = ($h -split ' ')[0]
      $d = Test-IdOnBus $id $rows
      if ($d -and $d.ConfigManagerErrorCode -eq 18) {
        Say ('    code18 on ' + $id + ' -> pnputil /remove-device + /scan-devices')
        & cmd.exe /c ('pnputil /remove-device "' + $d.DeviceID + '"') 2>&1 | ForEach-Object { Say ('    ' + ($_ -replace '[^\x20-\x7E]', '?')) }
        & cmd.exe /c 'pnputil /scan-devices' 2>&1 | ForEach-Object { Say ('    ' + ($_ -replace '[^\x20-\x7E]', '?')) }
        Start-Sleep -Seconds 5
      }
    }
    $rows = @(Get-PnpSnapshot)
    $disks = @(Get-DiskState)
    $off = @(Get-OfflineWindows)
    Describe-ProblemDevices $rows
    if ($disks.Count -gt $disksB.Count -or ($off.Count -gt 0 -and $offB.Count -eq 0)) {
      Say ('  BOUND = ' + $p.Inf + '  (disks ' + $disksB.Count + ' -> ' + $disks.Count + ', offline roots ' + $off.Count + ')')
      $bound = $p.Inf
      break
    }
    Say ('  not bound by ' + [IO.Path]::GetFileName($p.Inf) + ' (rc is meaningless, judged by state)')
  }
}

# ---- [4] state AFTER + second probe
Sec 'AFTER'
$disksA = @(Get-DiskState)
Describe-Disks $disksA
$offA = @(Get-OfflineWindows)
Say ('  offline windows roots = ' + $(if ($offA.Count) { $offA -join ' ' } else { 'NONE' }))
if (-not $SelfTest -and (Test-Path -LiteralPath $probePs)) {
  Say '  running storageprobe (after)'
  $o = & $script:PsExe -NoProfile -ExecutionPolicy Bypass -File $probePs 2>&1
  $o | ForEach-Object { Say ('    ' + ($_ -replace '[^\x20-\x7E]', '?')) }
  if (Test-Path -LiteralPath 'X:\storageprobe.txt') {
    try { Copy-Item -LiteralPath 'X:\storageprobe.txt' -Destination (Join-Path $OutRoot 'storageprobe-after.txt') -Force; Say '    saved storageprobe-after.txt' } catch { }
  }
}

# ---- [5] full evidence bundle onto the stick
Sec 'RESCUE'
$rescuePs = Join-Path $env:SystemRoot 'System32\rescue.ps1'
if ($SelfTest) {
  Say ('  selftest: would run ' + $rescuePs + ' -OutRoot ' + $OutRoot)
} elseif ($SkipRescue) { Say '  skipped by switch' }
elseif (-not (Test-Path -LiteralPath $rescuePs)) { Say '  rescue.ps1 absent - copy Tools into System32 first' }
else {
  Say '  building the bundle on the stick (takes a few minutes on a real machine)'
  $o = & $script:PsExe -NoProfile -ExecutionPolicy Bypass -File $rescuePs -OutRoot $OutRoot 2>&1
  ($o | Out-String).Trim() -split "`r?`n" | ForEach-Object { Say ('  ' + ($_ -replace '[^\x20-\x7E]', '?')) }
}

Sec 'VERDICT'
Say ('  SYSDISK = ' + $(if ($offA.Count -gt 0) { 'ok (' + ($offA -join ' ') + ')' } else { 'missing' }))
Say ('  BOUND   = ' + $(if ($bound) { $bound } else { 'none' }))
Say ('  DISKS   = ' + $disksB.Count + ' before -> ' + $disksA.Count + ' after')
Say ('  STICK   = ' + (Split-Path -Parent $script:Stick))
Say ('  OUT     = ' + $OutRoot)
Say ('  COPY BACK = ' + $OutRoot + '\rescue\*.zip + onsite.log + storageprobe-*.txt onto the stick, then read them under Windows')
if ($SelfTest) { Say 'SELFTEST = dry run finished (no driver load, no writes outside the stick)' }
