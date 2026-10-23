# storageprobe.ps1 - WinPE storage / BSOD-rescue readiness probe
# Type: storageprobe   (shim: %SystemRoot%\System32\storageprobe.cmd)
# ASCII only on purpose: PE console codepage is not 936, non-ASCII text printed by 'type' turns into '?' garbage.
# Output: X:\storageprobe.txt  (also echoed to stdout so a remote SSH session sees the verdict block)
#
# What it answers, in order:
#   1) can this PE see the target disk at all            -> DISKS / SYSDISK = ok|missing
#   2) if not, which PCI/USB device is unbound + is it covered
#                                                        -> UNBOUND = <hardware id> , INDEX = hit|miss
#   3) which storage drivers actually live in the image   -> STOR_INF
#   4) is the disk BitLocker-encrypted / locked          -> BITLOCKER = ...
#   5) is the rescue channel itself healthy              -> NET / SSHD / FRPC / EGRESS
#   6) what to do next                                   -> NEXT = ...
#
# -SelfTest runs entirely off-box against captured fixtures, no admin / no PE needed.

param(
  [string]$IdxPath  = '',
  [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$OutFile = 'X:\storageprobe.txt'
$Lines   = New-Object System.Collections.Generic.List[string]

function Stamp { return (Get-Date).ToString('HH:mm:ss') + '  ' }
function Say([string]$s) { $Lines.Add((Stamp) + $s); Write-Output ((Stamp) + $s) }
function Sec([string]$s) { $Lines.Add(''); $Lines.Add('==== ' + $s + ' ===='); Write-Output (''); Write-Output ('==== ' + $s + ' ====') }

# PCI\VEN_15AD&DEV_0740&SUBSYS_074015AD&REV_10\3&61AAA01&0&3F  ->  PCI\VEN_15AD&DEV_0740&SUBSYS_074015AD&REV_10
# (drop the instance path; that is the form the driver index and INF [Models] sections use)
function Get-HwId([string]$devInst) {
  if ([string]::IsNullOrWhiteSpace($devInst)) { return '' }
  $k = $devInst.LastIndexOf('\')
  if ($k -lt 1) { return $devInst }
  return $devInst.Substring(0, $k)
}

# Storage driver names we care about: the gap between the PE inbox stack and modern machines.
$StorInfWanted = @(
  'iaVmd.inf',        # Intel VMD (11th gen+ default on many OEM laptops/desktops)
  'iaStorD.inf',      # Intel RST (new)
  'iaStorVD.inf',     # Intel RST VMD class (old naming)
  'iaStorAC.inf', 'iaStorVC.inf', 'iaStorT.inf',
  'iastorv.inf',      # Intel RST (legacy AHCI/RAID)
  'amdrc.inf', 'raidix64.inf', 'amdahcix64.inf',   # AMD RAIDXpert2 / AMD AHCI
  'stornvme.inf', 'storahci.inf', 'amdsata.inf', 'amdsbs.inf',
  'vsmraid.inf', 'nvraid.inf', 'megasas2.inf', 'megasas.inf'
)

try {
  if ($SelfTest) {
    # offline dry run: prove the parsing/lookup helpers without touching a PE
    Write-Output 'SELFTEST start'
    $t1 = Get-HwId 'PCI\VEN_15AD&DEV_0740&SUBSYS_074015AD&REV_10\3&61AAA01&0&3F'
    $ok1 = ($t1 -eq 'PCI\VEN_15AD&DEV_0740&SUBSYS_074015AD&REV_10')
    Write-Output ('  Get-HwId strips instance path : ' + $ok1 + '  -> ' + $t1)
    $t2 = Get-HwId 'USB\VID_0BDA&PID_8153\001000000'
    $ok2 = ($t2 -eq 'USB\VID_0BDA&PID_8153')
    Write-Output ('  Get-HwId on USB              : ' + $ok2 + '  -> ' + $t2)
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $root = Split-Path -Parent (Split-Path -Parent $here)     # overlay\Scripts -> project root
    $fixture = Join-Path $root 'test\fixtures\netdrv_index_sample.txt'
    if (Test-Path -LiteralPath $fixture) {
      $map = @{}
      foreach ($ln in @(Get-Content -LiteralPath $fixture -EA 0)) {
        $c = $ln.Trim()
        if ($c.Length -eq 0 -or $c.StartsWith('#')) { continue }
        $parts = $c -split "`t"
        if ($parts.Count -ge 2 -and $parts[1].Trim().Length -gt 0) { $map[$parts[0].Trim().ToUpper()] = $parts[1].Trim() }
      }
      Write-Output ('  fixture index entries        : ' + $map.Count)
      Write-Output ('  lookup e1000e id             : ' + $map.ContainsKey('PCI\VEN_8086&DEV_10D3'))
    } else {
      Write-Output ('  fixture missing (ok if never generated): ' + $fixture)
    }
    Write-Output ('  wanted storage infs          : ' + $StorInfWanted.Count)
    Write-Output 'SELFTEST done'
    return
  }

  if (-not $IdxPath) { $IdxPath = Join-Path $env:SystemRoot 'System32\netdrv_index.txt' }

  Sec 'BUILD'
  if (Test-Path X:\BUILD_TAG.txt) {
    Get-Content X:\BUILD_TAG.txt -EA 0 | Select-Object -First 6 | ForEach-Object { Say ('BUILD| ' + $_) }
  } else {
    Say 'BUILD| X:\BUILD_TAG.txt not found (old ISO?)'
  }
  $os = Get-CimInstance Win32_OperatingSystem -EA 0
  Say ('OS| ' + $os.Caption + ' ' + $os.Version + ' LastBoot=' + $os.LastBootUpTime)

  Sec 'DISKS (what the PE can actually enumerate)'
  $disks = @(Get-Disk -EA 0)
  Say ('DISK_COUNT = ' + $disks.Count)
  foreach ($d in $disks) {
    Say ('DISK| #' + $d.Number + ' | ' + $d.FriendlyName + ' | bus=' + $d.BusType + ' | ' + [math]::Round($d.Size/1GB,1) + 'GB | style=' + $d.PartitionStyle + ' | health=' + $d.HealthStatus + ' | op=' + $d.OperationalStatus + ' | offline=' + $d.IsOffline)
  }
  foreach ($w in @(Get-CimInstance Win32_DiskDrive -EA 0)) {
    Say ('WMI_DISK| ' + $w.DeviceID + ' | ' + $w.Model + ' | ' + $w.InterfaceType + ' | ' + $w.PNPDeviceID)
  }
  $allParts = @(Get-Partition -EA 0)
  Say ('PARTITION_COUNT = ' + $allParts.Count)
  foreach ($p in $allParts) {
    $drv = ''
    if ($p.AccessPaths) { $drv = ($p.AccessPaths -join ',') }
    Say ('PART| disk#' + $p.DiskNumber + ' part#' + $p.PartitionNumber + ' | ' + $p.Type + ' | ' + [math]::Round($p.Size/1GB,1) + 'GB | sys=' + $p.IsSystem + ' | access=' + $drv)
  }

  Sec 'SYSVOLUME (the real test: is there a Windows folder on a fixed disk)'
  $vols = @(Get-CimInstance Win32_LogicalDisk -EA 0)
  $syscand = @()
  $hiveOk  = @()
  foreach ($v in $vols) {
    $hasWin = $false
    $hasHive = $false
    if ($v.DeviceID) {
      # $v.DeviceID is 'D:\'; TrimEnd leaves 'D:'. Join-Path turns that into 'D:\Windows' -- building
      # the string by hand produced 'D::\Windows', which never exists, so SYSDISK reported 'missing'
      # on a machine where the OS partition was plainly visible (found by the 12th-gen real machine).
      $l = $v.DeviceID.TrimEnd('\')
      if (Test-Path (Join-Path $l 'Windows')) { $hasWin = $true }
      if (Test-Path (Join-Path $l 'Windows\System32\config\SOFTWARE')) { $hasHive = $true }
    }
    $sz = if ($v.Size) { [math]::Round($v.Size/1GB,1) } else { 0 }
    $fr = if ($v.FreeSpace) { [math]::Round($v.FreeSpace/1GB,1) } else { 0 }
    Say ('VOL| ' + $v.DeviceID + ' | ' + $v.VolumeName + ' | ' + $v.FileSystem + ' | type=' + $v.DriveType + ' | ' + $sz + 'GB free=' + $fr + 'GB | Windows=' + $hasWin + ' hive=' + $hasHive)
    if ($hasWin -and $v.DriveType -eq 3) { $syscand += $v.DeviceID }
    if ($hasHive) { $hiveOk += $v.DeviceID }
  }
  $sysdisk = if ($syscand.Count -gt 0) { 'ok' } else { 'missing' }
  Say ('SYSDISK = ' + $sysdisk + '  candidates=' + ($syscand -join ',') + '  offline_hive_on=' + ($hiveOk -join ','))

  Sec 'PROBLEM DEVICES (full list, NOT filtered to NIC class)'
  $prob = @(Get-CimInstance Win32_PnPEntity -EA 0 | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
  Say ('PROBLEM_COUNT = ' + $prob.Count)
  $unbound = @()
  foreach ($p in $prob) {
    Say ('PROB| code=' + $p.ConfigManagerErrorCode + ' | class=' + $p.PNPClass + ' | ' + $p.Name + ' | ' + $p.DeviceID)
    if ($p.DeviceID -match '^(PCI|USB|ACPI)\\') { $unbound += (Get-HwId $p.DeviceID) }
  }
  $unbound = @($unbound | Where-Object { $_.Length -gt 0 } | Sort-Object -Unique)
  Say ('UNBOUND = ' + $(if ($unbound.Count) { $unbound -join ' ; ' } else { 'none' }))

  # look the unbound ids up in the index the image actually ships
  Sec 'DRIVER INDEX LOOKUP (does the baked index cover the unbound ids?)'
  $idxMap = @{}
  if (Test-Path -LiteralPath $IdxPath) {
    foreach ($ln in @(Get-Content -LiteralPath $IdxPath -EA 0)) {
      $c = $ln.Trim()
      if ($c.Length -eq 0 -or $c.StartsWith('#')) { continue }
      $parts = $c -split "`t"
      if ($parts.Count -ge 2 -and $parts[1].Trim().Length -gt 0) { $idxMap[$parts[0].Trim().ToUpper()] = $parts[1].Trim() }
    }
    Say ('INDEX_FILE = ' + $IdxPath + '  entries=' + $idxMap.Count)
    $hit = 0; $miss = 0
    foreach ($u in $unbound) {
      $k = $u.ToUpper()
      if ($idxMap.ContainsKey($k)) { $hit++; Say ('HIT | ' + $u + ' -> ' + $idxMap[$k]) }
      else {
        $miss++
        # try the shortened PCI form VEN_x&DEV_y as a second key
        $short = ''
        if ($k -match 'VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') { $short = 'PCI\VEN_' + $matches[1] + '&DEV_' + $matches[2] }
        if ($short -and $idxMap.ContainsKey($short)) { Say ('HIT | ' + $short + ' (short form) -> ' + $idxMap[$short]) }
        else { Say ('MISS| ' + $u) }
      }
    }
    if ($unbound.Count -eq 0) { Say 'LOOKUP = nothing to look up (no unbound devices)' }
    Say ('INDEX_RESULT = hit ' + $hit + ' / miss ' + $miss)
  } else {
    Say ('INDEX_FILE = ' + $IdxPath + ' NOT FOUND (netdrvfix index missing from image?)')
  }

  Sec 'STORAGE DRIVERS PRESENT IN THE IMAGE'
  # Two places a driver can live: the inbox INF cache (drvload can use it directly) and the
  # staged DriverStore (what pnputil /enum-drivers lists). Check both, or you get a false
  # "no storage drivers" reading -- the staged list alone said exactly that once already.
  $infDir   = Join-Path $env:SystemRoot 'INF'
  $storeDir = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
  $inboxNames = @()
  if (Test-Path -LiteralPath $infDir) {
    # guard against 8.3 short names that end in .inf but whose long name is something else
    $inboxNames = @([IO.Directory]::GetFiles($infDir, '*.inf') |
      Where-Object { ([IO.Path]::GetExtension($_) -ieq '.inf') } |
      ForEach-Object { [IO.Path]::GetFileName($_) })
  }
  $storeNames = @()
  if (Test-Path -LiteralPath $storeDir) {
    $storeNames = @([IO.Directory]::GetFiles($storeDir, '*.inf', 'AllDirectories') |
      Where-Object { ([IO.Path]::GetExtension($_) -ieq '.inf') } |
      ForEach-Object { [IO.Path]::GetFileName($_) })
  }
  Say ('INF_CACHE = ' + $infDir + '  files=' + $inboxNames.Count)
  Say ('DRIVERSTORE = ' + $storeDir + '  inf=' + $storeNames.Count)
  $storish = @($inboxNames | Where-Object { $_ -match '(?i)^(ia|stor|amd|nvraid|vsmraid|megasas|nvd|pciide|uli|sis)' })
  Say ('INBOX_STORAGEISH = ' + $(if ($storish.Count) { ($storish | Sort-Object -Unique) -join ' ' } else { 'none' }))
  $sysDir = Join-Path $env:SystemRoot 'System32\drivers'
  $sysNames = @()
  if (Test-Path -LiteralPath $sysDir) {
    $sysNames = @([IO.Directory]::GetFiles($sysDir, '*.sys') | ForEach-Object { [IO.Path]::GetFileName($_) })
  }
  Say ('DRIVERS_DIR = ' + $sysDir + '  sys=' + $sysNames.Count)
  $absentWanted = @()
  foreach ($w in $StorInfWanted) {
    $base = [IO.Path]::GetFileNameWithoutExtension($w)
    $inInbox = @($inboxNames | Where-Object { $_ -ieq $w }).Count -gt 0
    $inStore = @($storeNames | Where-Object { $_ -ieq $w }).Count -gt 0
    # some inbox drivers ship a .sys whose INF lives under a different name (storahci.sys is
    # installed by disk.inf), so a missing INF alone does not mean the device cannot bind.
    $hasSys  = @($sysNames | Where-Object { $_ -ieq ($base + '.sys') }).Count -gt 0
    $st = 'ABSENT'
    if ($inInbox -and $inStore) { $st = 'inbox+staged' }
    elseif ($inInbox) { $st = 'inbox only' }
    elseif ($inStore) { $st = 'staged only' }
    elseif ($hasSys) { $st = 'sys only, no inf' }
    else { $absentWanted += $w }
    Say ('STOR_INF| ' + $w + ' = ' + $st + $(if ($hasSys) { ' [sys present]' } else { '' }))
  }
  Say ('STOR_ABSENT = ' + $(if ($absentWanted.Count) { $absentWanted -join ' ' } else { 'none' }))
  $enumOut = (& pnputil.exe /enum-drivers 2>&1 | Out-String)
  $classCount = @{}
  foreach ($ln in ($enumOut -split "`r?`n")) {
    if ($ln -match '^\s*Class(?: Name)?\s*:\s*(.+?)\s*$') {
      $cn = $matches[1].Trim()
      if ($classCount.ContainsKey($cn)) { $classCount[$cn] = $classCount[$cn] + 1 } else { $classCount[$cn] = 1 }
    }
  }
  Say ('STAGED_PACKAGES = ' + $classCount.Count + ' classes: ' + (($classCount.GetEnumerator() | Sort-Object -Descending Value | ForEach-Object { $_.Key + '=' + $_.Value }) -join ' '))

  Sec 'BITLOCKER'
  $mb = & manage-bde.exe -status 2>&1 | Out-String
  $cur = ''
  foreach ($ln in ($mb -split "`r?`n")) {
    $t = $ln.Trim()
    if ($t -match '^Volume [A-Z]:') { $cur = $t }
    if ($t -match 'Conversion Status|Percentage Encrypted|Lock Status|Protection Status') {
      Say ('BDE| ' + $cur + ' | ' + ($t -replace '\s{2,}', ' '))
    }
  }
  if ($mb -match 'BitLocker Drive Encryption: Configuration Tool') { Say 'BDE| manage-bde usable' } else { Say 'BDE| manage-bde output unexpected' }

  Sec 'RESCUE CHANNEL'
  $ip = @(Get-CimInstance Win32_NetworkAdapterConfiguration -EA 0 | Where-Object { $_.IPEnabled })
  foreach ($i in $ip) { Say ('NIC| ' + $i.Description + ' | ip=' + (($i.IPAddress | Select-Object -First 1)) + ' | gw=' + (($i.DefaultIPGateway | Select-Object -First 1)) + ' | mac=' + $i.MACAddress) }
  $sshUp = $false
  $l22 = @(Get-NetTCPConnection -LocalPort 22 -State Listen -EA 0)
  if ($l22.Count) { $sshUp = $true }
  else { $ns = (& netstat.exe -ano 2>&1 | Select-String ':22\s.*LISTENING'); if (@($ns).Count) { $sshUp = $true } }
  Say ('SSHD = ' + $(if ($sshUp) { 'listening on 22' } else { 'NOT listening' }))
  $frpc = @(Get-Process frpc -EA 0); $sl = @(Get-Process SunloginSOS -EA 0)
  Say ('FRPC = ' + $(if ($frpc.Count) { 'running pid=' + $frpc[0].Id } else { 'not running (on-site must click the FRP panel)' }))
  Say ('SUNLOGIN = ' + $(if ($sl.Count) { 'running pid=' + $sl[0].Id } else { 'not running' }))
  $egress = 'fail'
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri 'https://www.baidu.com' -TimeoutSec 10
    $egress = 'ok(' + $r.StatusCode + ')'
  } catch { $egress = 'fail(' + $_.Exception.Message + ')' }
  Say ('EGRESS_HTTPS = ' + $egress)

  Sec 'VERDICT'
  Say ('DISKS = ' + $disks.Count + '  PARTITIONS = ' + $allParts.Count)
  Say ('SYSDISK = ' + $sysdisk)
  Say ('PROBLEM_DEVICES = ' + $prob.Count)
  Say ('UNBOUND_PCI = ' + $(if ($unbound.Count) { $unbound -join ' ; ' } else { 'none' }))
  $saTxt = 'not-measured'
  if ($null -ne $absentWanted) {
    $saTxt = $(if ($absentWanted.Count) { $absentWanted -join ' ' } else { 'none (all wanted infs present)' })
  }
  Say ('STOR_ABSENT = ' + $saTxt)
  Say ('CHANNEL = sshd/' + $(if ($sshUp) {'up'} else {'down'}) + ' frpc/' + $(if ($frpc.Count) {'up'} else {'down'}) + ' egress/' + $(if ($egress -like 'ok*') {'up'} else {'down'}))
  if ($sysdisk -eq 'ok') {
    if ($egress -notlike 'ok*') {
      Say 'NEXT = sysdisk is readable but egress failed: rescue can still run over the SSH channel, only bulk file pull is blocked.'
    } else {
      Say 'NEXT = storage + channel both fine, proceed to rescue probe.'
    }
  } elseif ($disks.Count -eq 0) {
    Say 'NEXT = NO disk device visible at all -> storage controller driver missing (VMD / RST / RAID mode).'
    Say 'NEXT = check UNBOUND_PCI above against the storage index; drvload <iaVmd.inf|iaStorD.inf|amdrc.inf>, or BIOS -> storage mode AHCI as the no-driver workaround.'
  } else {
    Say 'NEXT = disks are visible but no \Windows folder found: OS partition may be BitLocker-locked, offline, unformatted, or this machine has no Windows install.'
    Say 'NEXT = manage-bde -unlock <vol>: -rp <recovery password>  (read-only checks first; unlocking needs user confirmation).'
  }
} catch {
  Say ('FATAL = ' + $_.Exception.Message)
} finally {
  if (-not $SelfTest) {
    try {
      [IO.File]::WriteAllLines($OutFile, $Lines, [Text.Encoding]::ASCII)
      Write-Output ((Stamp) + 'WROTE ' + $OutFile)
    } catch { Write-Output ((Stamp) + 'WROTE_FAILED ' + $OutFile) }
  }
}
