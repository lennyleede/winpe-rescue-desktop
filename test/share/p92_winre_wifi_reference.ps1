# p92 -- WinRE is the only Microsoft-supplied PE that carries WiFi (the ADK has no WinPE-WiFi.cab: the OC
# reference says WinPE-WiFi-Package "is included in the base winre.wim file, and not available separately"),
# so its image is the authoritative reference for what a WiFi-capable PE must look like OFFLINE.
#
# probe90 measured the live PE and found the gap: X:\ has only 2 records under
#   Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}   (ms_netbios, ms_server)
# while a working Windows has 13, incl. ms_nativewifip (netnwifi.inf) and ms_vwifi (netvwififlt.inf); the wireless
# class instance's Linkage\FilterList holds one EMPTY string there versus 13 entries on the host. Creating those
# records at runtime made vwifibus go Running but nativewifip/vwififlt/vwifimp stayed Stopped and no vwifimp child
# appeared (build\scratch\p90_pe_apply.txt) -- i.e. the shape alone is not enough, and the binding is decided when
# PnP first configures the device at boot. So the fix has to be baked offline, and this script reads the reference:
#   1. packages present in winre.wim (look for the WiFi/WDI packages),
#   2. the DriverStore packages for netnwifi/netvwififlt/netvwifimp/netvwifibus (+ their .cat),
#   3. the SYSTEM hive of winre.wim: the NetService component records + every Net class instance Linkage/Ndi,
#   4. the same three readings from OUR current boot.wim, so the diff is on one page.
#
# READ-ONLY BY CONSTRUCTION: both images are mounted /ReadOnly, the hives are COPIED before reg load, every mount
# is released /Discard in the finally block, and nothing writes into D:\winpe_build or into the ISO. Scratch lives
# under this project's build\ folder. Needs administrator because DISM mount + reg load require it.
param([string]$WinRe = 'auto',
      [string]$Ours  = 'D:\QoderProject\国内版\生成winpe\build\WinPE_amd64\media\sources\boot.wim',
      [ValidateSet('full', 'skip')] [string]$OnBusy = 'full',
      [switch]$DryLocate)
$ErrorActionPreference = 'Continue'
$Root    = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Scratch = Join-Path $Root 'build\scratch'
$MountP  = Join-Path $Root 'build\winre_mount'
$MountO  = Join-Path $Root 'build\ours_mount'
$OUT     = Join-Path $Scratch 'p92_winre_wifi_reference.txt'
$REGX    = Join-Path $env:WINDIR 'System32\reg.exe'
$DismExe = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe'
if (-not (Test-Path -LiteralPath $DismExe)) {
  $w = @(Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10' -Recurse -Filter 'Dism.exe' -EA SilentlyContinue |
        Where-Object { "$($_.FullName)" -match '(?i)amd64' })
  if ($w.Count) { $DismExe = $w[0].FullName }
}
if (Test-Path -LiteralPath $OUT) { Remove-Item -LiteralPath $OUT -Force -EA SilentlyContinue }
# Defender/indexers can hold a freshly created log for a second, and losing the run's evidence over a sharing
# violation is worse than a second file name -- retry, then fall back to a per-PID log and say so.
$script:OutFallback = $OUT + '.' + $PID + '.txt'
$script:LoggedTo    = $OUT
function Say([string]$s) {
  # stdout, not the pipeline: Say is called from inside functions whose return value the caller iterates, and a
  # Write-Output here would show up as an extra "found file" line (that is what made the first locator self-feed).
  try { [Console]::WriteLine($s) } catch { Write-Host $s }
  foreach ($tg in @($OUT, $script:OutFallback)) {
    if (-not $tg) { continue }
    for ($i = 0; $i -lt 8; $i++) {
      try { Add-Content -LiteralPath $tg -Value $s -Encoding UTF8
            if ($tg -ne $script:LoggedTo) { $script:LoggedTo = $tg }
            return }
      catch { Start-Sleep -Milliseconds 200 }
    }
  }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ('P92 START ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' dism=' + $DismExe + ' admin=' + $isAdmin)
if (-not $isAdmin -and -not $DryLocate) {
  Say 'P92 REFUSE: this script mounts WIM images and loads registry hives, both need elevation.'
  Say ('        run: powershell -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"')
  Say 'P92 END'
  return
}
foreach ($p in @($DismExe)) {
  if (-not (Test-Path -LiteralPath $p)) { Say ('P92 MISSING ' + $p); Say 'P92 END'; return }
}
$free = (Get-PSDrive -Name ($Root.Substring(0, 1))).Free
Say ('  scratch drive free MB=' + [int]($free / 1MB))
if ($free -lt 4GB) { Say 'P92 REFUSE: less than 4 GB free for the read-only mounts and the winre copy'; Say 'P92 END'; return }

# ---------------- locate the WinRE image ----------------
# On a modern Lenovo/Win11 box the recovery image does NOT live in C:\Windows\System32\Recovery (that folder only
# holds ReAgent.xml); it sits on the letterless 1GB "WinRE_DRV" partition. A volume-GUID path is readable once
# elevated, but DISM wants an ordinary path, so such an image is COPIED to this project's scratch folder and the
# copy is what gets mounted -- the recovery partition is never written to.
$script:WinReCopy = ''
$script:UnreadableRecovery = @()
function WimsIn([string]$dir) {
  # .NET's Directory API accepts a \\?\Volume{guid}\ root literally; Get-ChildItem -LiteralPath frequently does not,
  # which is exactly why the first version of this locator reported NOTFOUND on a machine that has WinRE.
  # Every log line here is [void]-wrapped: Say writes to the output stream, and inside a function that stream IS the
  # return value, so an un-wrapped Say would feed the caller's own log text back as "found files".
  $r = @()
  try {
    if (-not [IO.Directory]::Exists($dir)) { [void](Say ('    probe <no-dir>  ' + $dir)); return @() }
    $r = @([IO.Directory]::GetFiles($dir, '*.wim', [IO.SearchOption]::TopDirectoryOnly))
    [void](Say ('    probe ' + $dir + ' wim_files=' + $r.Count))
  } catch { [void](Say ('    probe ' + $dir + ' ERROR ' + $_.Exception.Message))
            if ($dir -match 'Recovery') { $script:UnreadableRecovery += $dir }
            return @() }
  foreach ($f in $r) {
    $len = 0
    try { $len = (New-Object IO.FileInfo $f).Length } catch { }
    [void](Say ('      | ' + $f + ' bytes=' + $len))
  }
  return $r
}
function Find-WinRe {
  $roots = @()
  foreach ($v in @(Get-Volume -EA SilentlyContinue)) {
    $lab  = $(if ($v.FileSystemLabel) { $v.FileSystemLabel } elseif ($v.DriveLetter) { ($v.DriveLetter + ':') } else { 'letterless' })
    $root = ''
    if ($v.DriveLetter) { $root = ($v.DriveLetter + ':\') } elseif ($v.Path) { $root = $v.Path }
    if (-not $root) { continue }
    [void](Say ('  P92 VOLUME ' + $lab + ' root=' + $root + ' size=' + [math]::Round($v.Size / 1MB, 0) + 'MB free=' +
         [math]::Round($v.SizeRemaining / 1MB, 0) + 'MB'))
    foreach ($sub in @('Windows\System32\Recovery', 'Recovery', '')) { $roots += ($root + $sub) }
  }
  $roots += 'C:\Windows\System32\Recovery'
  # reagentc is the authoritative answer to "where is my recovery image"; its path line is plain ASCII.
  foreach ($sw in @('/locateimage', '/info')) {
    try {
      $o = @(& "$env:WINDIR\System32\reagentc.exe" $sw 2>&1 | ForEach-Object { "$_" })
      [void](Say ('  P92 REAGENTC ' + $sw + ' rc=' + $LASTEXITCODE + ' lines=' + $o.Count))
      foreach ($l in @($o | Where-Object { $_ -match '(?i)\.wim' })) {
        $m = [regex]::Match($l, '([A-Za-z]:\\[^"\r\n]*?\.wim|\\\\\?\\Volume[^"\r\n]*?\.wim)')
        if ($m.Success) { [void](Say ('    P92 REAGENTC-PATH ' + $m.Value)); $roots = @($m.Value) + $roots }
      }
    } catch { [void](Say ('  P92 REAGENTC ' + $sw + ' unavailable: ' + $_.Exception.Message)) }
  }
  $best = $null
  $seenFiles = @()
  foreach ($d in @($roots | Select-Object -Unique)) {
    $w = @(WimsIn $d)
    $seenFiles += $w
    foreach ($f in $w) {
      if ("$f" -notmatch '(?i)winre|recover') { continue }
      if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { continue }
      $len = 0
      try { $len = (New-Object IO.FileInfo $f).Length } catch { }
      if ($len -lt 100MB) { [void](Say ('      skip small wim ' + $f + ' bytes=' + $len)); continue }
      if (-not $best -or $len -gt $best.bytes) { $best = @{ path = "$f"; bytes = $len } }
    }
  }
  [void](Say ('  P92 LOCATE scanned_dirs=' + (@($roots | Select-Object -Unique).Count) + ' wim_files_seen=' + @($seenFiles).Count))
  return $best
}
if ($WinRe -ne 'auto') {
  if (-not (Test-Path -LiteralPath $WinRe)) { Say ('  P92 MISSING (given by -WinRe) ' + $WinRe + ' -- only OURS will be read.') ; $WinRe = '' }
  else {
    $gb = 0; try { $gb = (New-Object IO.FileInfo $WinRe).Length } catch { }
    Say ('  P92 WINRE given by -WinRe, using it as-is bytes=' + $gb)
  }
} else {
  $h = Find-WinRe
  if (-not $h) {
    Say 'P92 NOTFOUND: no readable winre.wim on this machine.'
    if (@($script:UnreadableRecovery).Count -gt 0) {
      Say ('  P92 DENIED dirs=' + (@($script:UnreadableRecovery).Count) + ' -> ' + (@($script:UnreadableRecovery) | Select-Object -First 2 -Unique))
      Say '        The recovery volume is there but its ACL refuses even this token. Next: a non-destructive read test'
      Say '        (open 4 bytes, no write) before any copy. If that also fails, the WinRE reference is out of reach'
      Say '        on this box and the bake decision goes to the host-spec + live-PE route.'
      $probe = @($script:UnreadableRecovery | Sort-Object { if ("$_" -match '\\\?\\Volume') { 0 } else { 1 } } | Select-Object -First 2)
      foreach ($d in $probe) {
        foreach ($nm in @('Winre.wim', 'WinRE.wim', 'winre.wim')) {
          $cand = $d + '\' + $nm
          try {
            $fs = [IO.File]::Open($cand, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $b = New-Object byte[] 4; [void]$fs.Read($b, 0, 4); $fs.Close()
            Say ('    P92 PROBE-READ ok ' + $cand)
            $h = @{ path = $cand; bytes = $(try { (New-Object IO.FileInfo $cand).Length } catch { 0 }) }
            break
          } catch { Say ('    P92 PROBE-READ refused ' + $cand + ' : ' + $_.Exception.Message) }
        }
      }
    }
    if (-not $h) {
      $WinRe = ''
      Say 'P92 NO-WINRE: continuing with OURS only (that reading alone still documents what the current bake produces).'
      Say '        To supply the reference anyway, copy Winre.wim off the 12th-gen laptop (it boots a Windows volume'
      Say '        whose recovery image is readable there) and re-run with -WinRe <path>.'
    }
  }
  if ($h) {
    Say ('  P92 FOUND-WINRE ' + $h.path + ' bytes=' + $h.bytes)
    if ($h.path -match '^\\\\\?\\Volume') {
      $cp = Join-Path $Scratch 'p92_winre_copy.wim'
      Say ('  P92 COPY the GUID-path image to ' + $cp + ' (read-only source; DISM needs an ordinary path)')
      try {
        Copy-Item -LiteralPath $h.path -Destination $cp -Force -EA Stop
      } catch { Say ('  P92 COPY FAILED: ' + $_.Exception.Message) }
      $got = $(if (Test-Path -LiteralPath $cp) { (Get-Item -LiteralPath $cp).Length } else { 0 })
      Say ('  P92 COPY got=' + $got + ' expected=' + $h.bytes + ' match=' + ($got -eq $h.bytes))
      if ($got -ne $h.bytes) {
        if ($got -gt 0) { Remove-Item -LiteralPath $cp -Force -EA SilentlyContinue }
        $WinRe = ''
        Say 'P92 NO-WINRE: the copy did not complete, so the recovery volume stays untouched and only OURS is read.'
      } else { $script:WinReCopy = $cp; $WinRe = $cp }
    } else { $WinRe = $h.path }
  }
}
if ($WinRe) {
  Say ('  winre image used = ' + $WinRe + ' bytes=' + (Get-Item -LiteralPath $WinRe).Length +
       ' mtime=' + (Get-Item -LiteralPath $WinRe).LastWriteTime)
} else { Say '  winre image used = <none>' }
if ($DryLocate) { Say 'P92 DRYLOCATE: nothing was mounted. Re-run without -DryLocate as administrator.'; return }

# ---------------- hive reader (works on a COPIED hive, never in place) ----------------
function DumpHive([string]$hiveFile, [string]$tag) {
  if (-not (Test-Path -LiteralPath $hiveFile)) { Say ('  P92 HIVE ' + $tag + ' <absent> ' + $hiveFile); return }
  $loadName = 'P92HIVE'
  $lp = "HKLM\$loadName"
  & $REGX unload $lp 2>&1 | Out-Null
  $r = @(& $REGX load $lp ('"' + $hiveFile + '"') 2>&1 | ForEach-Object { "$_" })
  Say ('  P92 REGLOAD ' + $tag + ' rc=' + $LASTEXITCODE + ' out=' + (($r | Select-Object -First 1) -replace '\s+', ' '))
  if ($LASTEXITCODE -ne 0) { return }
  try {
    $cs = "Registry::$lp\ControlSet001"
    if (-not (Test-Path -LiteralPath $cs)) { $cs = "Registry::$lp\" + ((Get-Item -LiteralPath "Registry::$lp" -EA SilentlyContinue).GetValue('CurrentControlSet') -replace '\s*$','') }
    Say ('  P92 CCS ' + $tag + ' -> ' + $cs)

    $nsPath = "$cs\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}"
    if (Test-Path -LiteralPath $nsPath) {
      $comps = @(Get-ChildItem -LiteralPath $nsPath -EA SilentlyContinue)
      Say ('  P92 NSCOMPONENTS ' + $tag + ' instances=' + $comps.Count)
      $cids = @($comps | ForEach-Object { ("$((Get-ItemProperty -LiteralPath $_.PSPath -EA SilentlyContinue).ComponentId)").ToLower() })
      $script:Comps[$tag] = ($cids -join ',')
      $script:HasNwifi[$tag] = $(if ($cids -contains 'ms_nativewifip') { 1 } else { 0 })
      $script:HasVwifi[$tag] = $(if ($cids -contains 'ms_vwifi') { 1 } else { 0 })
      foreach ($c in $comps) {
        $ip = Get-ItemProperty -LiteralPath $c.PSPath -EA SilentlyContinue
        $svc = (Get-ItemProperty -LiteralPath (Join-Path $c.PSPath 'Ndi') -EA SilentlyContinue).Service
        $fmt = (Get-ItemProperty -LiteralPath (Join-Path $c.PSPath 'Ndi\Interfaces') -EA SilentlyContinue).FilterMediaTypes
        Say ('    P92 COMP ' + $tag + ' ' + $c.PSChildName + ' cid=[' + $ip.ComponentId + '] inf=[' + $ip.InfPath +
             '] sect=[' + $ip.InfSection + '] svc=[' + $svc + '] fmts=[' + $fmt + ']')
      }
    } else { Say ('  P92 NSCOMPONENTS ' + $tag + ' <key absent>') }

    $cls = "$cs\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    if (Test-Path -LiteralPath $cls) {
      $ins = @(Get-ChildItem -LiteralPath $cls -EA SilentlyContinue)
      Say ('  P92 NETCLASS ' + $tag + ' instances=' + $ins.Count)
      foreach ($i in $ins) {
        $ip = Get-ItemProperty -LiteralPath $i.PSPath -EA SilentlyContinue
        $svc = (Get-ItemProperty -LiteralPath (Join-Path $i.PSPath 'Ndi') -EA SilentlyContinue).Service
        $fl = @((Get-ItemProperty -LiteralPath (Join-Path $i.PSPath 'Linkage') -EA SilentlyContinue).FilterList)
        Say ('    P92 CLSINST ' + $tag + ' ' + $i.PSChildName + ' svc=[' + $svc + '] desc=[' + $ip.DriverDesc +
             '] ncfg=[' + $ip.NetCfgInstanceId + '] inf=[' + $ip.InfPath + '] included=[' + $ip.IncludedInfs +
             '] filterlist=' + $fl.Count)
        foreach ($e in $fl) { Say ('      | ' + $e) }
        $upr = (Get-ItemProperty -LiteralPath (Join-Path $i.PSPath 'Ndi\Interfaces') -EA SilentlyContinue).UpperRange
        $lor = (Get-ItemProperty -LiteralPath (Join-Path $i.PSPath 'Ndi\Interfaces') -EA SilentlyContinue).LowerRange
        Say ('      | Ndi\Interfaces Upper=[' + $upr + '] Lower=[' + $lor + ']')
        if (-not $script:MaxFl.ContainsKey($tag) -or $fl.Count -gt $script:MaxFl[$tag]) { $script:MaxFl[$tag] = $fl.Count }
      }
    } else { Say ('  P92 NETCLASS ' + $tag + ' <key absent>') }

    foreach ($s in @('nativewifip', 'vwififlt', 'vwifimp', 'vwifibus', 'wdiwifi', 'NdisImPlatform', 'wlansvc', 'wcmsvc', 'ndiscap')) {
      $p = "$cs\Services\$s"
      if (-not (Test-Path -LiteralPath $p)) { Say ('  P92 SVC ' + $tag + ' ' + $s + ' <absent>'); continue }
      $ip = Get-ItemProperty -LiteralPath $p -EA SilentlyContinue
      $subs = @(Get-ChildItem -LiteralPath $p -Recurse -EA SilentlyContinue)
      Say ('  P92 SVC ' + $tag + ' ' + $s + ' Type=' + $ip.Type + ' Start=' + $ip.Start + ' Group=[' + $ip.Group +
           '] ImagePath=[' + $ip.ImagePath + '] Owners=[' + (@($ip.Owners) -join ',') + '] Subkeys=' + $subs.Count)
      foreach ($sub in @($subs | Select-Object -First 6)) { Say ('      | ' + $sub.PSPath.Substring($p.Length + 1)) }
    }
    # the device-side half: does WinRE carry the filter devnodes / UpperFilters anywhere?
    $setup = "$cs\Control\Network"
    Say ('  P92 NETWORK-CLASSES ' + $tag + ' = ' + ((@(Get-ChildItem -LiteralPath $setup -EA SilentlyContinue) | ForEach-Object { $_.PSChildName }) -join ' '))
  } finally {
    & $REGX unload "HKLM\$loadName" 2>&1 | Out-Null
    Say ('  P92 REGUNLOAD ' + $tag + ' rc=' + $LASTEXITCODE)
  }
}

# ---------------- per-image reading ----------------
function ReadImage([string]$wim, [string]$tag, [string]$mountDir) {
  Say ('==== ' + $tag + ' :: ' + $wim + ' ====')
  if (-not $wim) { Say ('  P92 SKIP ' + $tag + ' -- no image path to read'); return }
  if (-not (Test-Path -LiteralPath $wim)) { Say ('  P92 WIM <absent> ' + $wim); return }
  # SAFETY: never touch a WIM that is currently attached/mounted by someone else (an in-flight build would lose
  # its injected layers). -OnBusy skip leaves such an image completely alone.
  $di = @(Get-DiskImage -ImagePath $wim -EA SilentlyContinue | Where-Object { $_.Attached })
  # SAFETY: never touch a WIM that a DISM session already has mounted (an in-flight build would lose its injected
  # layers). Get-DiskImage only sees attached ISO/WIM files, so the authoritative check is DISM's own list.
  $mi = @(& $DismExe /Get-MountedImageInfo 2>&1 | ForEach-Object { "$_" })
  $mine = @($mi | Where-Object { $_ -match ([regex]::Escape($wim)) })
  $busy = @(@($di).Count + @($mine).Count)
  if ($busy -gt 0) {
    Say ('  P92 BUSY ' + $tag + ' -- this WIM already has a mount/attach session (' + $busy +
         ' line(s), OnBusy=' + $OnBusy + ') -> skipped, nothing was touched')
    foreach ($l in @($mine | Select-Object -First 3)) { Say ('    | ' + (($l -replace '\s+', ' ').Trim())) }
    return
  }
  & $DismExe /Get-WimInfo /WimFile:$wim 2>&1 | ForEach-Object { "$_" } |
      Where-Object { $_ -match '(?i)index|name|size|description' } | ForEach-Object { Say ('  WIMINFO | ' + ($_ -replace '\s+', ' ').Trim()) }
  if (Test-Path -LiteralPath $mountDir) {
    & $DismExe /Unmount-Wim /MountDir:$mountDir /Discard 2>&1 | Out-Null
    Remove-Item -LiteralPath $mountDir -Recurse -Force -EA SilentlyContinue
  }
  New-Item -ItemType Directory -Force -Path $mountDir | Out-Null
  $m = @(& $DismExe /Mount-Wim /WimFile:$wim /Index:1 /MountDir:$mountDir /ReadOnly 2>&1 | ForEach-Object { "$_" })
  Say ('  P92 MOUNT ' + $tag + ' rc=' + $LASTEXITCODE + ' last=' + (($m | Select-Object -Last 2) -join ' / '))
  if ($LASTEXITCODE -ne 0) { return }
  $script:Mounted = $script:Mounted + @($mountDir)
  try {
    $p = @(& $DismExe /Get-Packages /Image:$mountDir /Format:Table 2>&1 | ForEach-Object { "$_" })
    $wifi = @($p | Where-Object { $_ -match '(?i)wifi|wlan|dot3|ndis|Wireless|WCN|VDI|ImBus|Native' })
    Say ('  P92 PACKAGES ' + $tag + ' total_lines=' + $p.Count + ' wifi_like=' + $wifi.Count)
    foreach ($l in @($wifi | Select-Object -First 25)) { Say ('    | ' + (($l -replace '\s+', ' ').Trim())) }
    foreach ($f in @('Windows\INF\netnwifi.inf', 'Windows\INF\netvwififlt.inf', 'Windows\INF\netvwifimp.inf', 'Windows\INF\netvwifibus.inf',
                     'Windows\System32\drivers\nwifi.sys', 'Windows\System32\drivers\vwififlt.sys', 'Windows\System32\drivers\vwifimp.sys',
                     'Windows\System32\drivers\vwifibus.sys', 'Windows\System32\drivers\wdiwifi.sys', 'Windows\System32\drivers\NdisImPlatform.sys',
                     'Windows\System32\wlansvc.dll', 'Windows\System32\wlanext.exe')) {
      $q = Join-Path $mountDir $f
      Say ('  P92 FILE ' + $tag + ' ' + $f + ' exists=' + (Test-Path -LiteralPath $q))
    }
    $fr = Join-Path $mountDir 'Windows\System32\DriverStore\FileRepository'
    if (Test-Path -LiteralPath $fr) {
      $pk = @(Get-ChildItem -LiteralPath $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)^net(nwifi|vwifi)' })
      Say ('  P92 DRVSTORE ' + $tag + ' net*nwifi/netvwifi packages=' + $pk.Count)
      foreach ($k in $pk) {
        $files = @(Get-ChildItem -LiteralPath $k.FullName -Recurse -File -EA SilentlyContinue)
        $cats = @($files | Where-Object { $_.Extension -eq '.cat' } | ForEach-Object { $_.Name })
        $infs = @($files | Where-Object { $_.Extension -eq '.inf' } | ForEach-Object { $_.Name })
        Say ('    P92 PKG ' + $tag + ' ' + $k.Name + ' files=' + $files.Count + ' inf=[' + ($infs -join ',') + '] cat=[' + ($cats -join ',') + ']')
      }
      Say ('    P92 DRVSTORE ' + $tag + ' total packages=' + (@(Get-ChildItem -LiteralPath $fr -Directory -EA SilentlyContinue).Count))
    } else { Say ('  P92 DRVSTORE ' + $tag + ' <FileRepository absent>') }
    $hiveSrc = Join-Path $mountDir 'Windows\System32\config\SYSTEM'
    $hiveDst = Join-Path $Scratch ('p92_hive_' + $tag + '.SYSTEM')
    if (Test-Path -LiteralPath $hiveSrc) {
      Copy-Item -LiteralPath $hiveSrc -Destination $hiveDst -Force
      Say ('  P92 HIVECOPY ' + $tag + ' bytes=' + (Get-Item -LiteralPath $hiveDst).Length)
      DumpHive $hiveDst $tag
    } else { Say ('  P92 HIVE ' + $tag + ' <SYSTEM hive absent>') }
  } finally {
    & $DismExe /Unmount-Wim /MountDir:$mountDir /Discard 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 1 | ForEach-Object { Say ('  P92 UNMOUNT ' + $tag + ' | ' + ($_ -replace '\s+', ' ')) }
  }
}

$script:Mounted = @()
$script:Comps   = @{}
$script:HasNwifi = @{}
$script:HasVwifi = @{}
$script:MaxFl   = @{}
try {
  ReadImage $WinRe 'WINRE' $MountP
  if (Test-Path -LiteralPath $Ours) { ReadImage $Ours 'OURS' $MountO }
  else {
    Say ('==== OURS :: ' + $Ours + ' ====')
    Say '  P92 WIM <absent> -- no built working image yet; run build.ps1 first or pass -Ours <boot.wim>.'
  }
} finally {
  foreach ($md in @($script:Mounted)) { & $DismExe /Unmount-Wim /MountDir:$md /Discard 2>&1 | Out-Null }
  # /Cleanup-Mountpoints is image-global, so it only runs when THIS script actually created a mount; a build in
  # progress must not have its stale-session bookkeeping touched.
  if (@($script:Mounted).Count -gt 0) { & $DismExe /Cleanup-Mountpoints 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 1 | ForEach-Object { Say ('  P92 CLEANUP | ' + ($_ -replace '\s+', ' ')) } }
  if ($script:WinReCopy -and (Test-Path -LiteralPath $script:WinReCopy)) {
    Remove-Item -LiteralPath $script:WinReCopy -Force -EA SilentlyContinue
    Say ('  P92 DROP-COPY ' + $script:WinReCopy + ' still_present=' + (Test-Path -LiteralPath $script:WinReCopy))
  }
}

Say '== verdict =='
$wR = $(if ($script:Comps.ContainsKey('WINRE')) { 'read' } else { 'unread' })
$oR = $(if ($script:Comps.ContainsKey('OURS'))  { 'read' } else { 'unread' })
Say ('  P92 STATE winre=' + $wR + ' ours=' + $oR +
     ' winre_ms_nativewifip=' + $(if ($script:HasNwifi.ContainsKey('WINRE')) { $script:HasNwifi['WINRE'] } else { '-' }) +
     ' winre_ms_vwifi=' + $(if ($script:HasVwifi.ContainsKey('WINRE')) { $script:HasVwifi['WINRE'] } else { '-' }) +
     ' ours_ms_nativewifip=' + $(if ($script:HasNwifi.ContainsKey('OURS')) { $script:HasNwifi['OURS'] } else { '-' }) +
     ' ours_ms_vwifi=' + $(if ($script:HasVwifi.ContainsKey('OURS')) { $script:HasVwifi['OURS'] } else { '-' }) +
     ' winre_max_filterlist=' + $(if ($script:MaxFl.ContainsKey('WINRE')) { $script:MaxFl['WINRE'] } else { '-' }) +
     ' ours_max_filterlist=' + $(if ($script:MaxFl.ContainsKey('OURS')) { $script:MaxFl['OURS'] } else { '-' }))
Say ('  P92 COMPS WINRE [' + $(if ($script:Comps.ContainsKey('WINRE')) { $script:Comps['WINRE'] } else { '-' }) + ']')
Say ('  P92 COMPS OURS [' + $(if ($script:Comps.ContainsKey('OURS'))  { $script:Comps['OURS']  } else { '-' }) + ']')
if ($wR -eq 'read') {
  if ($script:HasNwifi['WINRE'] -eq 1) {
    Say 'P92 READING: Microsoft ships the ms_nativewifip component record inside a PE/RE hive. That settles it --'
    Say '         wifi-inject writes the same two records into boot.wim offline and netdrvfix only tops up the'
    Say '         per-machine FilterList/UpperFilters at boot.'
  } else {
    Say 'P92 READING: WinRE has NO ms_nativewifip record either, yet WiFi works there -- so the component store is'
    Say '         NOT populated at bake time. Look at the WINRE filterlist / SVC Owners lines instead: if WinRE is'
    Say '         also empty there, Microsoft relies on PnP populating it on first boot, and our fix belongs in'
    Say '         netdrvfix (before wlansvc starts), not in the offline hive.'
  }
} else {
  Say 'P92 READING: no WinRE reference on this box (recovery volume ACL). The offline-bake design therefore goes on'
  Say '         the host-shape spec already measured in build\scratch\_host_wifi_components.txt, and the live-PE'
  Say '         acceptance run is the arbiter: if the baked records + netdrvfix FilterList produce a vwifimp child,'
  Say '         the theory held without needing WinRE at all.'
}
Say ('P92 LOGFILE ' + $script:LoggedTo)
Say 'P92 WINRE WIFI REFERENCE END'
