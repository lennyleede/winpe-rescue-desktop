# rescue.ps1 -- one-command BSOD / black-screen evidence bundle for the rescue PE.
#
# Usage (inside the PE, or over ssh):   rescue            or   powershell -File X:\rescue.ps1
#
# Everything is read-only except the bundle folder it creates. The offline Windows it examines is
# found by probing for \Windows\System32\config\SOFTWARE on every fixed drive (X: is the ramdisk and
# is skipped). The registry is read with reg load / reg unload in a try/finally so no hive is left
# mounted if a query fails.
#
# ASCII output ONLY: PE logs and ssh sessions are read in CP936, non-ASCII becomes garbage.
#
# After it finishes it prints three lines the operator needs:
#   BUNDLE = X:\rescue\rescue_<host>_<time>.zip
#   SIZE   = <n> bytes
#   SHA256 = <hex>
# and the matching host-side pull command. Keep the bundle under ~50 MB: the frp uplink runs about
# 2.7 Mbps, i.e. 50 MB takes ~2.5 minutes.
param(
  [string]$OutRoot = 'X:\rescue',
  [string]$TargetRoot = '',      # force the offline Windows drive (e.g. D) when auto-detect picks wrong
  [switch]$SkipHives,          # SYSTEM+SOFTWARE hives dominate the size; skip for a text-only bundle
  [switch]$SkipEvents,         # evtx parsing is the slowest section
  [switch]$NoZip
)
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- report plumbing
$Lines = New-Object Collections.Generic.List[string]
function Stamp { return (Get-Date).ToString('HH:mm:ss') + '  ' }
# The PE console and the ssh session are CP936, and this file must stay ASCII (project rule).
# Localised strings (network adapter names, WMI captions) would garble, so every report line is
# squeezed to printable ASCII before it reaches the log.
function Ascii([string]$s) { return ($s -replace '[^\x20-\x7E]', '?') }
function Say([string]$s) { $s = Ascii $s; $Lines.Add((Stamp) + $s); Write-Output ((Stamp) + $s) }
function Sec([string]$s) {
  $s = Ascii $s
  $Lines.Add(''); $Lines.Add('==== ' + $s + ' ====')
  Write-Output (''); Write-Output ('==== ' + $s + ' ====')
}
function Run([string]$exe, [string]$args_) {
  # capture one external command's stdout. Everything goes through cmd.exe /c so the line behaves
  # exactly as it would if typed in the PE console -- PowerShell's own native-argument quoting is
  # the thing that mangles 'reg load HKLM\RES "C:\path with space"'.
  try {
    $o = & cmd.exe /c ($exe + ' ' + $args_) 2>&1
    return (($o | Out-String).Trim())
  } catch { return 'RUN-FAIL ' + $_.Exception.Message }
}
function Add-File([string]$label, [string]$src, [string]$destName) {
  # copy one artefact into the bundle; logs what happened so a missing file is not silent
  if (-not (Test-Path -LiteralPath $src)) { Say ('  file ' + $label + ' = absent'); return }
  $item = Get-Item -LiteralPath $src
  if ($item.PSIsContainer) { Say ('  file ' + $label + ' = directory, skipped'); return }
  $name = $destName
  if (-not $name) { $name = $label.Replace(' ', '_') + '__' + $item.Name }
  $dst = Join-Path $Bundle $name
  try {
    Copy-Item -LiteralPath $src -Destination $dst -Force
    $n = (Get-Item -LiteralPath $dst).Length
    Say ('  file ' + $label + ' = copied ' + $n + 'B -> ' + $name)
    $script:BundleBytes += $n
    $script:CopyCount++
  } catch { Say ('  file ' + $label + ' = COPY-FAIL ' + $_.Exception.Message) }
}
function Tail-To([string]$label, [string]$src, [int]$count, [string]$destName) {
  if (-not (Test-Path -LiteralPath $src)) { Say ('  tail ' + $label + ' = absent'); return }
  try {
    $t = Get-Content -LiteralPath $src -Tail $count -ErrorAction Stop
    $dst = Join-Path $Bundle $destName
    Set-Content -LiteralPath $dst -Value $t -Encoding ASCII
    Say ('  tail ' + $label + ' = ' + $t.Count + ' lines -> ' + $destName)
    $script:BundleBytes += (Get-Item -LiteralPath $dst).Length
  } catch { Say ('  tail ' + $label + ' = FAIL ' + $_.Exception.Message) }
}

function Test-File([string]$p) {
  # [IO.File]::Exists returns false instead of throwing PermissionDenied the way Test-Path does on
  # a locked hive (observed on the host as a non-admin; in the PE everything is readable).
  try { return [IO.File]::Exists($p) } catch { return $false }
}
function Test-Dir([string]$p) {
  try { return [IO.Directory]::Exists($p) } catch { return $false }
}

$Start = Get-Date
Say ('rescue start ' + $Start.ToString('yyyy-MM-dd HH:mm:ss'))

# ---------------------------------------------------------------- bundle folder
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$Bundle = Join-Path $OutRoot ('bundle_' + $env:COMPUTERNAME + '_' + $Start.ToString('yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $Bundle | Out-Null
$script:BundleBytes = 0
$script:CopyCount = 0
$script:DumpCount = 0
$script:LastBugcheck = ''
$script:CrashDumpEnabled = ''
$script:HiveCopied = $false
Say ('BUNDLE DIR = ' + $Bundle)

# ---------------------------------------------------------------- locate the offline Windows
Sec 'TARGET WINDOWS ROOT'
$cands = @()
$drives = @(Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Free -ne $null -and $_.Name -ne 'X' })
foreach ($d in $drives) {
  $root = $d.Root.TrimEnd('\')
  $sysCfg = Join-Path $root 'Windows\System32\config\SOFTWARE'
  if (Test-File $sysCfg) {
    $cands += [pscustomobject]@{ Root = $root; FreeGB = [math]::Round($d.Free/1GB, 1) }
  } elseif (Test-Dir (Join-Path $root 'Windows\System32')) {
    Say ('  ' + $root + '\ has Windows but the SOFTWARE hive is not readable here (needs admin / is not a target)')
  }
}
if ($cands.Count -eq 0) {
  Say 'OFFLINE_WINDOWS = none found (no drive has \Windows\System32\config\SOFTWARE)'
  Say 'NOTE = storage drivers may be missing: run storageprobe first, drvload the right inf, re-run rescue.'
  $Tgt = $null
} else {
  foreach ($c in $cands) { Say ('candidate = ' + $c.Root + '\  free=' + $c.FreeGB + 'GB') }
  $Tgt = ($cands | Select-Object -First 1).Root
  Say ('OFFLINE_WINDOWS = ' + $Tgt + '\  (first candidate; set $Tgt manually if wrong)')
}
if ($TargetRoot) {
  $probe = Join-Path $TargetRoot 'Windows\System32\config\SOFTWARE'
  if (Test-File $probe) {
    $Tgt = $TargetRoot.TrimEnd('\')
    Say ('OFFLINE_WINDOWS = ' + $Tgt + '\  (forced with -TargetRoot)')
  } else {
    Say ('-TargetRoot ' + $TargetRoot + ' has no readable SOFTWARE hive, ignoring it')
  }
}

# ---------------------------------------------------------------- system identity
Sec 'SYSTEM'
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
Say ('PE computername = ' + $env:COMPUTERNAME)
if ($os) {
  Say ('PE build        = ' + $os.Caption + ' ' + $os.Version + ' build ' + $os.BuildNumber)
  Say ('PE last boot    = ' + $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))
} else { Say 'PE build        = (Win32_OperatingSystem unavailable)' }
if (Test-Path X:\BUILD_TAG.txt) {
  foreach ($l in (Get-Content X:\BUILD_TAG.txt -ErrorAction SilentlyContinue)) { Say ('  tag | ' + $l) }
} else { Say '  X:\BUILD_TAG.txt absent (image predates the tag file)' }

# ---------------------------------------------------------------- disks / partitions / volumes
Sec 'DISKS'
try {
  foreach ($d in (Get-Disk -ErrorAction Stop)) {
    Say ('  disk ' + $d.Number + ' bus=' + $d.BusType + ' size=' + [math]::Round($d.Size/1GB) + 'GB health=' + $d.HealthStatus +
         ' partitionStyle=' + $d.PartitionStyle + ' isBoot=' + $d.IsBoot + ' offline=' + $d.IsOffline)
  }
} catch { Say ('  Get-Disk FAIL ' + $_.Exception.Message) }
foreach ($p in (Get-Partition -ErrorAction SilentlyContinue)) {
  Say ('  part disk' + $p.DiskNumber + ' #' + $p.PartitionNumber + ' type=' + $p.Type + ' size=' + [math]::Round($p.Size/1MB) +
       'MB access=' + $(if ($p.AccessPaths) { $p.AccessPaths -join ',' } else { 'none' }))
}
foreach ($v in (Get-Volume -ErrorAction SilentlyContinue)) {
  Say ('  vol ' + $(if ($v.DriveLetter) { $v.DriveLetter + ':' } else { '(no letter)' }) + ' fs=' + $v.FileSystem +
       ' health=' + $v.HealthStatus + ' sizeRem=' + [math]::Round($v.SizeRemaining/1GB, 1) + 'GB')
}
Say ('  Win32_PageFileUsage = ' + ((Get-WmiObject Win32_PageFileUsage -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ','))

# ---------------------------------------------------------------- problem devices
Sec 'PROBLEM DEVICES'
$prob = @(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
          Where-Object { $_.ConfigManagerErrorCode -ne 0 } |
          Sort-Object ConfigManagerErrorCode, Name)
if ($prob.Count -eq 0) { Say '  none' }
foreach ($p in $prob) {
  $hw = ''
  if ($p.PNPDeviceID) {
    $k = $p.PNPDeviceID.LastIndexOf('\')
    if ($k -gt 0) { $hw = $p.PNPDeviceID.Substring(0, $k) }
  }
  Say ('  code' + $p.ConfigManagerErrorCode + ' | ' + $p.Name + ' | ' + $hw)
}

# ---------------------------------------------------------------- crash configuration (offline hive)
Sec 'CRASH CONTROL (offline registry)'
$mounted = $false
$rbName = 'HKLM\RES'
if ($Tgt) {
  $sysHive = Join-Path $Tgt 'Windows\System32\config\SYSTEM'
  if (Test-Path -LiteralPath $sysHive) {
    $out = Run 'reg.exe' ('load ' + $rbName + ' "' + $sysHive + '"')
    if ($out -match 'created successfully|operation completed') { $mounted = $true }
    Say ('  reg load = ' + $(if ($mounted) { 'ok' } else { 'FAIL: ' + $out }))
  } else { Say '  SYSTEM hive absent' }
}
if ($mounted) {
  try {
    # the offline system's active control set is a number, not the literal 'CurrentControlSet'
    $sel = Run 'reg.exe' ('query ' + $rbName + '\Select /v Current')
    $csNum = 'ControlSet001'
    if ($sel -match 'REG_DWORD\s+0x([0-9a-fA-F]+)') {
      $csNum = 'ControlSet' + ([convert]::ToInt32($matches[1], 16)).ToString('000')
    }
    if ((Run 'reg.exe' ('query ' + $rbName + '\' + $csNum)) -match 'ERROR') {
      Say ('  ' + $csNum + ' not present, falling back to ControlSet001')
      $csNum = 'ControlSet001'
    }
    Say ('  active control set = ' + $csNum)
    $cs = $rbName + '\' + $csNum
    foreach ($val in @('CrashDumpEnabled', 'AutoReboot', 'MiniDumpDir', 'LastBugCheck', 'Overwrite', 'FilterPaths', 'DumpFile', 'LogFilePath')) {
      $r = Run 'reg.exe' ('query ' + $cs + '\Control\CrashControl /v ' + $val)
      if ($r -match $val) {
        $line = ($r -split "`r?`n" | Where-Object { $_ -match $val }) -join ''
        Say ('  ' + ($line -replace '\s+', ' ').Trim())
        if ($val -eq 'CrashDumpEnabled' -and $line -match '0x([0-9a-fA-F]+)') { $script:CrashDumpEnabled = '0x' + $matches[1] }
        if ($val -eq 'LastBugCheck' -and $line -match '0x([0-9a-fA-F]+)') { $script:LastBugcheck = '0x' + $matches[1] }
      }
    }
    foreach ($sub in @('\Control\ComputerName\ComputerName',
                       '\Control\Session Manager\Kernel',
                       '\Control\Session Manager\Environment',
                       '\Control\BootVerification\ProgramAuditPaths')) {
      $r = Run 'reg.exe' ('query ' + $cs + $sub)
      if ($r -notmatch 'ERROR') { foreach ($l in ($r -split "`r?`n")) { if ($l.Trim()) { Say ('  ' + ($l -replace '\s+',' ').Trim()) } } }
    }
    # last shutdown / crash bookkeeping
    $r = Run 'reg.exe' ('query ' + $cs + '\Control\Windows /v ErrorMode')
    if ($r -notmatch 'ERROR') { Say ('  ' + (($r -split "`r?`n" | Where-Object { $_ -match 'ErrorMode' }) -join '')) }
    # which display driver is started -- black screen usually shows up here
    $r = Run 'reg.exe' ('query ' + $cs + '\Control\Video')
    $guids = @([regex]::Matches($r, '\{[0-9a-fA-F-]{36}\}') | ForEach-Object { $_.Value } | Sort-Object -Unique)
    Say ('  Control\Video instances = ' + $guids.Count)
    foreach ($g in ($guids | Select-Object -First 8)) {
      $q = Run 'reg.exe' ('query ' + $cs + '\Control\Video\' + $g + '\0000 /v DeviceName')
      if ($q -match 'DeviceName') { Say ('  video ' + (($q -split "`r?`n" | Where-Object { $_ -match 'DeviceName' }) -join '')) }
    }
  } finally {
    $u = Run 'reg.exe' ('unload ' + $rbName)
    Say ('  reg unload = ' + $(if ($u -match 'SUCCESS|completed') { 'ok' } else { $u }))
  }
} else {
  Say '  registry not read (no offline SYSTEM hive or load failed)'
}

# ---------------------------------------------------------------- event logs (offline evtx)
Sec 'EVENT LOGS (offline .evtx)'
if ($SkipEvents) {
  Say '  skipped (-SkipEvents)'
} elseif ($Tgt) {
  $logDir = Join-Path $Tgt 'Windows\System32\winevt\Logs'
  foreach ($lg in @('System.evtx', 'Application.evtx')) {
    $p = Join-Path $logDir $lg
    if (-not (Test-File $p)) { Say ('  ' + $lg + ' absent'); continue }
    Say ('  reading ' + $lg + ' (this takes a minute on a real machine)')
    $rows = @()
    try {
      $rows = @(Get-WinEvent -FilterHashtable @{ Path = $p; Level = 1, 2, 3 } -MaxEvents 60 -ErrorAction SilentlyContinue)
    } catch { Say ('    read FAIL ' + $_.Exception.Message) }
    Say ('    critical+error+warning rows = ' + $rows.Count)
    foreach ($e in $rows) {
      $msg = ''
      if ($e.Message) { $msg = ($e.Message -replace '\s+', ' ') }
      if ($msg.Length -gt 180) { $msg = $msg.Substring(0, 180) + '...' }
      Say ('    ' + $e.TimeCreated.ToString('MM-dd HH:mm:ss') + ' id=' + $e.Id + ' lvl=' + $e.LevelDisplayName + ' src=' + $e.ProviderName + ' | ' + $msg)
    }
    # the bugcheck record itself
    try {
      $bsod = @(Get-WinEvent -FilterHashtable @{ Path = $p; Id = 41, 1001, 6008, 1000 } -MaxEvents 12 -ErrorAction SilentlyContinue)
      foreach ($e in $bsod) {
        $msg = ''
        if ($e.Message) { $msg = ($e.Message -replace '\s+', ' ') }
        if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + '...' }
        Say ('    KEY id=' + $e.Id + ' ' + $e.TimeCreated.ToString('MM-dd HH:mm:ss') + ' | ' + $msg)
      }
    } catch {}
  }
} else { Say '  no offline Windows to read' }

# ---------------------------------------------------------------- bugcheck signature (no debugger needed)
Sec 'BUGCHECK SIGNATURE'
# Event 1001 (WER-SystemErrorReporting) already carries stop code + 4 parameters + the minidump path,
# and the .wer files carry the problem bucket. That is enough for first-pass triage without WinDbg.
$any = $false
if ($Tgt) {
  $sysLog = Join-Path $Tgt 'Windows\System32\winevt\Logs\System.evtx'
  if (Test-File $sysLog) {
    # Get-WinEvent throws 'No events were found...' when the filter matches nothing -- that is an
    # empty answer, not a failure, so catch it and report it as such.
    $ev = @()
    try {
      $ev = @(Get-WinEvent -FilterHashtable @{ Path = $sysLog; Id = 1001, 41, 6008 } -MaxEvents 12 -ErrorAction Stop)
    } catch {
      if ($_.Exception.Message -match 'No events were found') { $ev = @() }
      else { Say ('  System.evtx read FAIL ' + $_.Exception.Message) }
    }
    foreach ($e in $ev) {
      $any = $true
      Say ('  ' + $e.ProviderName + ' id=' + $e.Id + ' ' + $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))
      foreach ($pr in $e.Properties) {
        $v = if ($pr.Value) { ($pr.Value | Out-String) -replace '\s+', ' ' } else { '' }
        if ($v.Trim()) { Say ('    ' + $pr.Name + ' = ' + $v.Trim()) }
      }
    }
    if (-not $ev.Count) { Say '  no 1001/41/6008 records in System.evtx (never bugchecked since the log was created)' }
  } else { Say '  System.evtx absent' }
}
# the .wer reports are read straight from the target disk (they are copied later in CRASH DUMPS).
# Most WER folders are application noise (Store/Update failures), so crash-shaped reports are
# detected by content and printed first.
if ($Tgt) {
  $werAll = @()
  foreach ($wer in @('ReportArchive', 'ReportQueue')) {
    $dir = Join-Path $Tgt ('ProgramData\Microsoft\Windows\WER\' + $wer)
    if (-not (Test-Dir $dir)) { continue }
    $werAll += @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -eq '.wer' } |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 40 |
                 ForEach-Object { [pscustomobject]@{ Src = $_; Kind = $wer } })
  }
  $parsed = @()
  foreach ($it in $werAll) {
    $raw = ''
    try { $raw = [IO.File]::ReadAllText($it.Src.FullName, [Text.Encoding]::Unicode) } catch { $raw = '' }
    if (-not $raw) { continue }
    $isCrash = ($raw -match '(?i)BCCode|BlueScreen|LiveBucket|APRCRASH|BEX|APP_CRASH|HangType|Problem Signature')
    $et = ''
    if ($raw -match '(?m)^EventType=(.+)$') { $et = $matches[1].Trim() }
    $parsed += [pscustomobject]@{ Crash = $isCrash; EventType = $et; Src = $it.Src; Kind = $it.Kind; Raw = $raw }
  }
  $crashes = @($parsed | Where-Object { $_.Crash })
  Say ('  wer reports = ' + $parsed.Count + '  crash-shaped = ' + $crashes.Count)
  foreach ($c in ($crashes | Select-Object -First 6)) {
    $any = $true
    $kv = @($c.Raw -split "`r?`n" | Where-Object {
      $_ -match '^(EventType|Problem Signature|Sig\[\d+\]\.(Name|Value)|Response\.BucketId|Bucket|BCCode|App Name|Module Name|OS Version)' })
    Say ('  CRASH ' + $c.Kind + '\' + $c.Src.Directory.Name + ' ' + $c.Src.LastWriteTime.ToString('yyyy-MM-dd HH:mm') + ' EventType=' + $c.EventType)
    foreach ($l in ($kv | Select-Object -First 16)) { Say ('    ' + (($l -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim()) }
  }
  if (-not $crashes.Count) {
    # nothing crash-shaped: show what IS there so the operator knows the WER folder was not empty
    foreach ($c in ($parsed | Select-Object -First 3)) {
      Say ('  (non-crash) ' + $c.EventType + ' ' + $c.Src.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
    }
    if ($parsed.Count) { $any = $true }
  }
}
if (-not $any) { Say '  nothing to sign -- combine with PROBLEM DEVICES and the event-log section above' }

# ---------------------------------------------------------------- minidumps + WER
Sec 'CRASH DUMPS'
if ($Tgt) {
  $miniDir = Join-Path $Tgt 'Windows\Minidump'
  if (Test-Path -LiteralPath $miniDir) {
    $dmps = @(Get-ChildItem -LiteralPath $miniDir -Filter '*.dmp' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    Say ('  ' + $miniDir + ' = ' + $dmps.Count + ' dump(s)')
    foreach ($dm in ($dmps | Select-Object -First 3)) {
      Say ('    ' + $dm.Name + ' ' + $dm.Length + 'B written ' + $dm.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
      Add-File ('minidump_' + $dm.BaseName) $dm.FullName ('minidump_' + $dm.Name)
      $script:DumpCount++
    }
  } else { Say '  Minidump folder absent (no kernel dump ever taken, or CrashDumpEnabled=0)' }
  foreach ($mem in @((Join-Path $Tgt 'Windows\MEMORY.DMP'))) {
    if (Test-Path -LiteralPath $mem) {
      $sz = [math]::Round((Get-Item -LiteralPath $mem).Length/1MB)
      Say ('  MEMORY.DMP present = ' + $sz + 'MB -- NOT copied (the ramdisk is 512MB and the uplink is 2.7Mbps).')
      Say ('  read it on site, or run the analysis in the PE with cdb/windbg copied in.')
    } else { Say '  MEMORY.DMP absent' }
  }
  foreach ($wer in @('ReportArchive', 'ReportQueue')) {
    $dir = Join-Path $Tgt ('ProgramData\Microsoft\Windows\WER\' + $wer)
    if (Test-Path -LiteralPath $dir) {
      $files = @(Get-ChildItem -LiteralPath $dir -Recurse -Filter '*.wer' -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 8)
      Say ('  WER ' + $wer + ' .wer files = ' + $files.Count)
      $i = 0
      foreach ($f in $files) { $i++; Add-File ('wer_' + $wer + '_' + $i) $f.FullName ('wer_' + $wer + '_' + $i + '.wer') }
    } else { Say ('  WER ' + $wer + ' absent') }
  }
}

# ---------------------------------------------------------------- boot store
Sec 'BOOT (BCD)'
if ($Tgt) {
  # The system partition is often unlettered in PE, so walk every partition access path
  # (drive letters and \\?\Volume{guid}\ both work with bcdedit /store) instead of guessing C:\Boot.
  $paths = @()
  foreach ($p in (Get-Partition -ErrorAction SilentlyContinue)) {
    foreach ($ap in ($p.AccessPaths | Where-Object { $_ })) { $paths += $ap }
  }
  $stores = @()
  foreach ($ap in $paths) {
    foreach ($rel in @('EFI\Microsoft\Boot\BCD', 'Boot\BCD')) {
      $cand = $ap.TrimEnd('\') + '\' + $rel
      if (Test-File $cand) { $stores += $cand }
    }
  }
  Say ('  partitions probed = ' + $paths.Count + '  BCD stores found = ' + $stores.Count)
  foreach ($bs in $stores) {
    Say ('  store ' + $bs)
    $o = Run 'bcdedit.exe' ('/store "' + $bs + '" /enum all')
    foreach ($l in ($o -split "`r?`n")) { if ($l.Trim()) { Say ('    ' + $l.Trim()) } }
    Add-File 'bcd_store' $bs ('bcd_' + ($bs -replace '[\\:{}]', '_'))
  }
  if (-not $stores.Count) { Say '  NO BCD STORE anywhere -- boot configuration is damaged or the disk is offline' }
  foreach ($bl in @((Join-Path $Tgt 'Windows\System32\winload.exe'),
                    (Join-Path $Tgt 'Windows\System32\config\SOFTWARE'),
                    (Join-Path $Tgt 'Windows\System32\Recovery\Winre.wim'))) {
    Say ('  bootfile ' + $bl + ' = ' + $(if (Test-File $bl) { 'present' } else { 'ABSENT' }))
  }
}

# ---------------------------------------------------------------- drivers staged on the offline image
Sec 'DRIVERS'
if ($Tgt) {
  # pnputil enumerates the RUNNING image (the PE). The offline system's own packages are the
  # oem*.inf files in its \Windows\INF plus its DriverStore folders.
  $o = Run 'pnputil.exe' ('/enum-drivers')
  $pkgs = @([regex]::Matches($o, '(?im)^\s*Published Name\s*:\s*(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() })
  $sto = @([regex]::Matches($o, '(?im)^\s*Class Name\s*:\s*(SCSIAdapter|IDE|RAID|DiskDrive|HDC|System)\b') | ForEach-Object { $_.Groups[1].Value })
  Say ('  PE staged packages = ' + $pkgs.Count + '  storage-class of those = ' + $sto.Count)
  $infDir = Join-Path $Tgt 'Windows\INF'
  if (Test-Path -LiteralPath $infDir) {
    # -Filter is not used on purpose: 8.3 short names make it report false hits in this project
    $all = @(Get-ChildItem -LiteralPath $infDir -File -ErrorAction SilentlyContinue)
    $oem = @($all | Where-Object { $_.Name -match '^oem\d+\.inf$' })
    $hits = @($all | Where-Object { $_.Name -match '(?i)^(iastor|iaahci|iavmd|iahci|stor|nvme|amdrc|rcraid|raid|megasas|vsm|pciide|uli|sis|nvraid)' -and $_.Name -match '\.inf$' })
    Say ('  offline \Windows\INF entries = ' + $all.Count + '  oem*.inf = ' + $oem.Count + '  storage-named = ' + $hits.Count)
    foreach ($f in ($oem | Select-Object -First 25)) { Say ('    oem | ' + $f.Name + ' ' + $f.Length + 'B') }
    foreach ($f in ($hits | Select-Object -First 25)) { Say ('    stor| ' + $f.Name + ' ' + $f.Length + 'B') }
  } else { Say '  offline \Windows\INF absent' }
  $store = Join-Path $Tgt 'Windows\System32\DriverStore\FileRepository'
  if (Test-Path -LiteralPath $store) {
    $dirs = @(Get-ChildItem -LiteralPath $store -Directory -ErrorAction SilentlyContinue)
    $sdirs = @($dirs | Where-Object { $_.Name -match '(?i)^(iastor|iaahci|iavmd|stor|nvme|amdrc|rcraid|raid|megasas|vsm|pciide|uli|sis|nvraid)' })
    Say ('  offline DriverStore folders = ' + $dirs.Count + '  storage-named = ' + $sdirs.Count)
    foreach ($d in ($sdirs | Select-Object -First 20)) { Say ('    ds  | ' + $d.Name) }
  } else { Say '  offline DriverStore absent' }
}

# ---------------------------------------------------------------- storage probe (reuse)
Sec 'STORAGEPROBE'
if (Test-Path -LiteralPath 'X:\Windows\System32\storageprobe.ps1') {
  $sp = @(& 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File 'X:\Windows\System32\storageprobe.ps1' 2>&1)
  foreach ($l in $sp) { if ("$l".Trim()) { Say ('  sp | ' + ("$l").Trim()) } }
  Set-Content -LiteralPath (Join-Path $Bundle 'storageprobe.txt') -Value $sp -Encoding ASCII
  $script:BundleBytes += (Get-Item -LiteralPath (Join-Path $Bundle 'storageprobe.txt')).Length
} else {
  Say '  storageprobe.ps1 not in this image'
}

# ---------------------------------------------------------------- bitlocker
Sec 'BITLOCKER'
foreach ($d in @('C:', 'D:', 'E:', 'F:')) {
  if (-not (Get-PSDrive -Name $d.TrimEnd(':') -ErrorAction SilentlyContinue)) { continue }
  $o = Run 'manage-bde.exe' ('-status ' + $d)
  if ($o -match 'Conversion Status|Protection State|Percentage|Key Protectors|error|Error') {
    foreach ($l in ($o -split "`r?`n")) {
      if ($l -match 'Conversion Status|Protection State|Percentage|Volume|Key Protectors|Numeric|Password|error') {
        Say ('  ' + ($l -replace '\s+', ' ').Trim())
      }
    }
  }
}

# ---------------------------------------------------------------- setup / servicing traces
Sec 'SETUP TRACES'
if ($Tgt) {
  Tail-To 'setupact.log' (Join-Path $Tgt 'Windows\Panther\setupact.log') 120 'panther_setupact_tail.txt'
  Tail-To 'setupapi.dev.log' (Join-Path $Tgt 'Windows\INF\setupapi.dev.log') 150 'setupapi_dev_tail.txt'
  Tail-To 'CBS.log' (Join-Path $Tgt 'Windows\Logs\CBS\CBS.log') 120 'cbs_tail.txt'
  foreach ($mp in @('Windows\Logs\MinimalMode.log', 'Windows\logs\MoLocalLauncher', 'Windows\Logs\DISM\dism.log')) {
    $p = Join-Path $Tgt $mp
    if (Test-Path -LiteralPath $p) { Add-File ('trace_' + ([IO.Path]::GetFileNameWithoutExtension($mp))) $p ('trace_' + ([IO.Path]::GetFileName($mp))) }
  }
}

# ---------------------------------------------------------------- network / channel health
Sec 'CHANNEL'
# Get-NetIPAddress / Get-NetRoute / Get-NetTCPConnection silently return nothing on some PE builds;
# the WMI classes and netstat are what storageprobe already proved working here, so use those.
$ips = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
         Where-Object { $_.IPEnabled })
foreach ($a in $ips) {
  Say ('  iface | ' + $a.Description + ' ip=' + (($a.IPAddress | Select-Object -First 2) -join ',') +
       ' gw=' + (($a.DefaultIPGateway | Select-Object -First 1)) + ' mac=' + $a.MACAddress)
}
$ns = Run 'netstat.exe' ('-ano -p TCP')
$l22 = @($ns -split "`r?`n" | Where-Object { $_ -match ':22\s' -and $_ -match 'LISTENING' })
Say ('  sshd listening = ' + $(if ($l22.Count) { 'yes (' + $l22.Count + ' socket)' } else { 'NO' }))
$procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'frpc|sshd|SunloginSOS' } | ForEach-Object { $_.ProcessName })
Say ('  rescue processes = ' + $(if ($procs.Count) { ($procs | Sort-Object -Unique) -join ',' } else { 'none' }))
try {
  $r = Invoke-WebRequest -Uri 'https://www.baidu.com' -UseBasicParsing -TimeoutSec 10
  Say ('  egress = ok ' + $r.StatusCode)
} catch { Say ('  egress = FAIL ' + $_.Exception.Message) }

# ---------------------------------------------------------------- hive copies (the big ones)
Sec 'HIVE COPIES'
if ($SkipHives) {
  Say '  skipped (-SkipHives)'
} elseif ($Tgt) {
  $free = (Get-PSDrive -Name ($Tgt.Substring(0, 1)) -ErrorAction SilentlyContinue).Free
  $cfg = Join-Path $Tgt 'Windows\System32\config'
  $need = 0
  foreach ($h in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT', 'BCD')) {
    $p = Join-Path $cfg $h
    if (Test-Path -LiteralPath $p) { $need += (Get-Item -LiteralPath $p).Length }
  }
  Say ('  hives total = ' + [math]::Round($need/1MB) + 'MB, free on X: = ' + [math]::Round((Get-PSDrive X).Free/1MB) + 'MB')
  if ($need -gt 0.6 * (Get-PSDrive X).Free) {
    Say '  TOO BIG for the ramdisk: copying SYSTEM only. Re-run with -SkipHives for a text-only bundle.'
    Add-File 'hive_SYSTEM' (Join-Path $cfg 'SYSTEM') 'hive_SYSTEM'
    $script:HiveCopied = $true
  } else {
    foreach ($h in @('SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'DEFAULT')) {
      $p = Join-Path $cfg $h
      if (Test-Path -LiteralPath $p) { Add-File ('hive_' + $h) $p ('hive_' + $h); $script:HiveCopied = $true } else { Say ('  hive ' + $h + ' absent') }
    }
  }
}

# ---------------------------------------------------------------- verdict
Sec 'VERDICT'
Say ('OFFLINE_WINDOWS = ' + $(if ($Tgt) { $Tgt + '\' } else { 'none -- storage driver likely missing, run storageprobe' }))
Say ('DUMPS_COLLECTED = ' + $script:DumpCount + '  LAST_BUGCHECK = ' + $(if ($script:LastBugcheck) { $script:LastBugcheck } else { 'unknown' }))
Say ('CRASH_DUMP_ENABLED = ' + $(if ($script:CrashDumpEnabled) { $script:CrashDumpEnabled } else { 'unknown' }))
Say ('HIVES_IN_BUNDLE = ' + $(if ($SkipHives) { 'no (-SkipHives)' } elseif ($script:HiveCopied) { 'yes (this bundle IS the pre-repair backup)' } else { 'none copied' }))
Say ('NEXT = pull it with  test\host_pull_from_pe.ps1 -RemoteFile <BUNDLE> -LocalFile <name>.zip  (keep under 50MB, the uplink is ~2.7Mbps)')

# ---------------------------------------------------------------- write report, zip, print pull line
Sec 'BUNDLE'
Set-Content -LiteralPath (Join-Path $Bundle 'report.txt') -Value $Lines -Encoding ASCII
Say ('  report.txt = ' + (Get-Item -LiteralPath (Join-Path $Bundle 'report.txt')).Length + 'B')
Say ('  bundle uncompressed = ' + [math]::Round($script:BundleBytes/1MB, 1) + 'MB')

$zip = ''
if ($NoZip) {
  Say '  zip skipped (-NoZip)'
} else {
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = Join-Path $OutRoot ('rescue_' + $env:COMPUTERNAME + '_' + $Start.ToString('yyyyMMdd-HHmmss') + '.zip')
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    [IO.Compression.ZipFile]::CreateFromDirectory($Bundle, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
    $z = Get-Item -LiteralPath $zip
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    Say ('  zip = ' + $z.FullName + ' ' + $z.Length + 'B (' + [math]::Round($z.Length/1MB, 1) + 'MB)')
    Write-Output ''
    Write-Output ('BUNDLE = ' + $z.FullName)
    Write-Output ('SIZE   = ' + $z.Length + ' bytes')
    Write-Output ('SHA256 = ' + $hash)
    Write-Output ('PULL   = powershell -File test\host_pull_from_pe.ps1 -RemoteFile "' + $z.FullName + '" -LocalFile rescue\<name>.zip')
  } catch {
    Say ('  ZIP FAIL ' + $_.Exception.Message + ' -- bundle folder stays as-is')
    Write-Output ('BUNDLE = ' + $Bundle)
  }
}
if (-not $zip) { Write-Output ('BUNDLE = ' + $Bundle) }
Say ('rescue done in ' + [math]::Round(((Get-Date) - $Start).TotalSeconds, 1) + 's')
