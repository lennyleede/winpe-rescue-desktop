# probe93 -- let the SUPPORTED installer do the job: NETCFG on the live PE.
#
# Why this probe exists (chain of negatives already measured on this box):
#   * probe90 -Apply hand-wrote BOTH component records (Control\Network\{4d36e974-...}\{E475CF9A..}=ms_nativewifip
#     and {5CBF81BF..}=ms_vwifi), appended the per-adapter Linkage\FilterList instances and UpperFilters=vwifibus,
#     then did `pnputil /restart-device`. Result: only vwifibus reached Running; nativewifip/vwififlt/vwifimp stayed
#     Stopped, vwifimp_nodes=0, wlansvc still 0x800C0006. => the bind decision is made while PnP FIRST-CONFIGURES the
#     adapter; either the records have to exist before that, or a real installer has to re-run the class-install and
#     bind pass (NetCfgx/NetClassInstaller is the supported way to do that).
#   * p92 read the offline image hive: Control\Network\{4d36e974-...} holds only ms_netbios and ms_server (2 records;
#     the working host has 13). So the records are missing from the IMAGE, not just at runtime.
#   * The PE carries netcfg.exe + netcfgx.dll + netshell.dll + ncobjapi.dll (build\scratch\pe_s32_list.txt line 806),
#     so the supported path is testable on the live RAMDISK.
#
# FIRST -Apply RUN (2026-10-11 14:2x, build\scratch\p93_apply_1011.txt) -- the supported installer DOES work here:
#   * `netcfg -v -l X:\windows\INF\oem181.inf -c s -i MS_NativeWifiP` -> rc=0, "Trying to install MS_NativeWifiP ...
#     done.", and **nativewifip went RUNNING** (first time ever measured on this box; wdiwifi/vwifibus were already
#     Running after the WDI bake, vwififlt/vwifimp still Stopped, vwifimp_nodes=0, wlansvc still Stopped).
#   * before that call `netcfg -v -q ms_nativewifip` answered "is not installed" even though probe90's hand-written
#     record key {E475CF9A-...} was present -> NetCfg's installed-set is NOT "the record key exists"; the installer
#     writes more than the key, and its own rebind pass is what attaches the filter. It also rewrote the adapter's
#     Linkage\FilterList down to its single entry (dropping the hand-written ms_vwifi one), so ms_vwifi has to go
#     through the same installer -- which is why this version of the ladder continues until a vwifimp child or a
#     running wlansvc shows up.
#   * the PE's class registrations are complete: Control\Class\{4d36e974-...} = NetService with
#     Installer32=NetCfgx.Dll,NetClassInstaller + NoInstallClass=1 + NoDisplayClass, matching the host exactly
#     (build\scratch\_host_class_reg.txt), and the adapter class instance is host-shaped (*IfType=71 *MediaType=16
#     IncludedInfs=netvwifibus.inf wifipro in Ndi\Interfaces\UpperRange) -- so nothing about the class plumbing is
#     missing; only the component INSTALL pass was.
#   * X:\windows\INF\SetupAPI.txt does not exist in this PE (exists=False), so the setupapi counters below stay 0;
#     the FileRepository/oem inventory and the netcfg rc/lines are the real evidence.
#
# What this measures, in order:
#   1 the installer tooling actually on the disc (files, versions, `netcfg /?` text);
#   2 what the offline DISM /Add-Driver left behind (DriverStore FileRepository, Windows\INF\oem###.inf, the covering
#     .cat in CatRoot) -- netcfg validates a catalog, so this decides which INF form it can accept;
#   3 baseline: component records / adapter class instances / FilterList / UpperFilters / stack / adapters;
#   4 with -Apply, a short installer ladder, re-measuring the records after every rung;
#   5 after the ladder: restart the WLAN devnode, bring wlansvc, `netsh wlan show interfaces`.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit overrides
# that guard deliberately. Only devnodes whose driver service matches the WLAN whitelist get restarted -- the Realtek
# wired adapter carrying this ssh session is never touched. Everything lives on the RAMDISK: a reboot restores it.
# Nothing is written to the ISO, to D:\winpe_build, or to a customer disk.
param([switch]$Apply, [switch]$IDoit, [string]$Only = '')
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Clean([string]$s) { (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Root([string]$sub) {
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}
function HexVal([object]$v) { if ($null -eq $v) { return '-' } return ('0x' + ('{0:X}' -f [int]$v)) }
function FV([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) { return '<absent>' }
  $v = $null
  try { $v = (Get-Item -LiteralPath $p -EA SilentlyContinue).VersionInfo.FileVersion } catch { }
  return ('"' + (Clean "$v") + '"')
}
# Run a native tool with an ARRAY of arguments. Switches and values must stay separate elements ('/v Owners' glued
# into one argument is an Invalid Argument for reg.exe).
function Run([string]$exe, [object[]]$argv) {
  if (-not (Test-Path -LiteralPath $exe)) { return @{ rc = -1; lines = @('<tool absent: ' + $exe + '>') } }
  $rc = -999
  $lines = @()
  try {
    $o = @(& $exe @argv 2>&1)
    $rc = $LASTEXITCODE
    $lines = @($o | ForEach-Object { Clean "$_" } | Where-Object { $_ -ne '' })
  } catch { $lines = @('EXCEPTION ' + (Clean $_.Exception.Message)) }
  return @{ rc = $rc; lines = @($lines) }
}
# Microsoft inbox INFs are UTF-16LE. Plain Select-String on them silently returns nothing, which already caused a
# "the file is empty" misreading on this project, so sniff the BOM and fall back to the ANSI codepage. Results are
# cached: several sections re-scan the same INF set.
$script:InfCache = @{}
function InfText([string]$p) {
  if ($script:InfCache.ContainsKey($p)) { return @($script:InfCache[$p]) }
  $out = @()
  if (Test-Path -LiteralPath $p) {
    $enc = 'Default'
    try {
      $b = [IO.File]::ReadAllBytes($p)
      if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $enc = 'Unicode' }
    } catch { }
    try { $out = @(Get-Content -LiteralPath $p -Encoding $enc -EA SilentlyContinue | ForEach-Object { Clean "$_" }) }
    catch { $out = @() }
  }
  $script:InfCache[$p] = $out
  return $out
}
function InfHits([string]$p, [string]$pat) { return @(@(InfText $p) | Where-Object { $_ -match $pat }) }
# Diff the ADAPTER CLASS INSTANCE against the working host (build\scratch\_host_wifi_bind_ref2.txt). The host's
# Intel AC 9260 slot carries *IfType=71 *MediaType=16 NetType=WLAN IncludedInfs=netvwifibus.inf and a Linkage with
# RootDevice/Export/FilterList/UpperBind -- those are the values NDIS and NetCfg read when they decide which
# mandatory filter attaches, so a missing one here is a candidate root cause the component records cannot explain.
$CLS_WANT = @('DriverDesc', 'NetCfgInstanceId', 'IncludedInfs', 'InfPath', 'InfSection', 'Characteristics',
              '*IfType', '*MediaType', '*PhysicalMediaType', 'NetType', 'ProviderName', 'ComponentId',
              'Class', 'ClassGUID', 'BusType', 'DriverVersion', 'PnPCapabilities', 'MatchingDeviceId')
$LNK_WANT = @('RootDevice', 'Export', 'BindFilters', 'FilterList', 'UpperBind', 'LowerBind', 'Route', 'Routes')
function DumpClass([string]$ck, [string]$tag) {
  if (-not (Test-Path -LiteralPath $ck)) { O ('    P93 ' + $tag + ' <absent> ' + $ck); return }
  $ip = Get-ItemProperty -LiteralPath $ck -EA SilentlyContinue
  foreach ($n in $CLS_WANT) {
    if ($null -eq $ip.$n) { O ('    P93 ' + $tag + ' ' + $n + ' = <absent>'); continue }
    $v = $ip.$n
    if ($v -is [array]) { $v = ($v -join ';') }
    if (("$v").Length -gt 90) { $v = ("$v").Substring(0, 90) + '...' }
    O ('    P93 ' + $tag + ' ' + $n + ' = ' + (Clean "$v"))
  }
  $names = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
  O ('    P93 ' + $tag + ' total_values=' + $names.Count + ' subs=' +
     ((@(Get-ChildItem -LiteralPath $ck -EA SilentlyContinue)).PSChildName -join ','))
  $lk = Join-Path $ck 'Linkage'
  if (Test-Path -LiteralPath $lk) {
    $j = Get-ItemProperty -LiteralPath $lk -EA SilentlyContinue
    foreach ($n in $LNK_WANT) {
      if ($null -eq $j.$n) { O ('    P93 ' + $tag + ' Linkage\' + $n + ' = <absent>'); continue }
      $v = $j.$n
      if ($v -is [array]) { $v = ($v -join ';') }
      if (("$v").Length -gt 220) { $v = ("$v").Substring(0, 220) + '...' }
      O ('    P93 ' + $tag + ' Linkage\' + $n + ' = ' + (Clean "$v"))
    }
  } else { O ('    P93 ' + $tag + ' Linkage <absent>') }
  $ni = Join-Path $ck 'Ndi\Interfaces'
  if (Test-Path -LiteralPath $ni) {
    $j = Get-ItemProperty -LiteralPath $ni -EA SilentlyContinue
    foreach ($p in @($j.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
      $v = $p.Value
      if ($v -is [array]) { $v = ($v -join ';') }
      if (("$v").Length -gt 160) { $v = ("$v").Substring(0, 160) + '...' }
      O ('    P93 ' + $tag + ' Ndi\Interfaces\' + $p.Name + ' = ' + (Clean "$v"))
    }
  } else { O ('    P93 ' + $tag + ' Ndi\Interfaces <absent>') }
}

$SR   = Root ''
$S32  = Join-Path $SR 'System32'
$INFDIR = Join-Path $SR 'INF'
$PNPU = Join-Path $S32 'pnputil.exe'
$REGX = Join-Path $S32 'reg.exe'
$NCFG = Join-Path $S32 'netcfg.exe'
$NSH  = Join-Path $S32 'netsh.exe'
$DRVL = Join-Path $S32 'drvload.exe'
$ENUMPS = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
$ENUM   = 'HKLM\SYSTEM\CurrentControlSet\Enum'
$CLSNET   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class'
$NS       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI_ID = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VWIFI_ID = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'
$CATDIR   = Join-Path $S32 'CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
$SETUPAPI = Join-Path $INFDIR 'SetupAPI.txt'
$script:Cls = @()

# setupapi.csv/SetupAPI.txt is where PnP writes "needed section ... might exist in missing included INF". Counting
# its WiFi-related lines before and after each installer call is the only way to see whether the call actually ran a
# class-install pass, even when the visible result is still code 0 / Stopped.
function SaHits {
  # InfText caches per path; SetupAPI.txt grows while the probe runs, so drop its entry before every read.
  if ($script:InfCache.ContainsKey($SETUPAPI)) { $script:InfCache.Remove($SETUPAPI) }
  return @(InfHits $SETUPAPI '(?i)nwifi|vwifi|native')
}

function Shape {
  # wireless adapter devnodes (driver service matches the WLAN whitelist) + how many vwifimp children exist.
  $devs = @(); $vi = 0
  foreach ($bus in @(Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
    foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
      foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
        $svc = "$($ip.Service)"
        if ($svc -match '(?i)^vwifimp$') { $vi++; continue }
        if ($svc -notmatch $WLAN_SVC) { continue }
        $id = $bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName
        $devs += @{ id = $id; reg = ($ENUM + '\' + $id); ps = ($ENUMPS + '\' + $id); svc = $svc;
                    up = (@($ip.UpperFilters) -join ','); drv = ("$($ip.Driver)") }
      }
    }
  }
  return @{ devs = $devs; vwifimp = $vi }
}
function StackLine {
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return (@($states -join ',') + ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status))
}
function FlOf([string]$ck) {
  # 'Linkage\FilterList' ABSENT must come out as an EMPTY array. Reading the property off $null gives $null, and
  # @($null) has Count=1, so every absent FilterList used to be reported as "count=1" -- on the 12:10 disc that
  # hid the real finding (the adapter has NO FilterList value at all, host has 13 entries incl. both WiFi filters).
  $j = Get-ItemProperty -LiteralPath (Join-Path $ck 'Linkage') -Name 'FilterList' -EA SilentlyContinue
  $v = $null
  if ($j) { $v = @($j.PSObject.Properties['FilterList'].Value) }
  if ($null -eq $v) { return @() }
  $keep = @($v | Where-Object { "$_" -ne '' })
  if ($keep.Count -eq 0 -and (@($v).Count -eq 1) -and ("$($v[0])" -eq '')) { return @() }
  return @($v)
}
function RefreshCls {
  # rebuild the adapter CLASS instances; NetCfgInstanceId is the prefix of every FilterList entry.
  $script:Cls = @()
  $sh = Shape
  foreach ($d in @($sh.devs)) {
    if ($d.drv -eq '') { continue }
    $ck = Join-Path $CLSNET $d.drv
    if (-not (Test-Path -LiteralPath $ck)) { continue }
    $ncfg = [string](RegV $ck 'NetCfgInstanceId')
    $script:Cls += @{ id = $d.id; ck = $ck; ncfg = $ncfg; reg = $d.reg; ps = $d.ps }
  }
  return $sh
}
function Snapshot {
  # the cheap signal the ladder watches: do the two component records exist, and is anything bound?
  $n = @(Get-ChildItem -LiteralPath $NS -EA SilentlyContinue).Count
  $nw = (Test-Path -LiteralPath (Join-Path $NS $NWIFI_ID))
  $vw = (Test-Path -LiteralPath (Join-Path $NS $VWIFI_ID))
  $maxfl = 0; $hits = 0
  foreach ($c in @($script:Cls)) {
    $fl = @(FlOf $c.ck)
    if ($fl.Count -gt $maxfl) { $maxfl = $fl.Count }
    foreach ($e in $fl) { if ("$e" -match 'E475CF9A|5CBF81BF') { $hits++ } }
  }
  return ('records=' + $n + ' nwifi=' + $nw + ' vwifi=' + $vw + ' max_filterlist=' + $maxfl +
          ' wifi_filter_entries=' + $hits)
}

O ('P93 START root=' + $SR + ' apply=' + $Apply.IsPresent + ' only=[' + $Only + ']')
O ('  P93 STACK ' + (StackLine))

O '== 0 which disc is this, and what did the BOOT pass leave behind =='
# 2026-10-12: the 12:10 bake changed the service shape (Type=0x20 / -k WlansvcGroup / three deps) and added the two
# netcfg component records offline. Whether THAT disc bound the filters at boot is the whole question this probe now
# answers, so print the disc stamp and the boot-time binding evidence before touching anything:
#   wifi_patch=  -> which patch_wifi run this ISO came from (X:\BUILD_TAG.txt)
#   shape=       -> wlansvc Type/ImagePath/DependOnService as the SCM actually sees them
#   records=     -> the two component records netcfg sees (baked offline => must be 2/2 now)
#   filterlist=  -> how many Linkage\FilterList entries the wireless class instance got at boot,
#                   and how many of them name E475CF9A(ms_nativewifip)/5CBF81BF(ms_vwifi)
#   upperfilter= -> the adapter devnode's UpperFilters (Intel's WinT INF writes vwifibus there; the Win11 "WinA"
#                   sections do NOT -- that is the current leading explanation for vwifibus never appearing)
foreach ($tp in @('X:\BUILD_TAG.txt', (Join-Path $SR 'BUILD_TAG.txt'))) {
  if (Test-Path -LiteralPath $tp) {
    foreach ($l in @(Get-Content -LiteralPath $tp -EA SilentlyContinue)) {
      if (("$l" -match '(?i)^(build|wifi_patch|wlandrv)')) { O ('  P93 TAG ' + (Clean "$l")) }
    }
    break
  }
}
$sk = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
if (Test-Path -LiteralPath $sk) {
  $sp = Get-ItemProperty -LiteralPath $sk -EA SilentlyContinue
  O ('  P93 SHAPE wlansvc Type=0x' + ('{0:X}' -f [int]$sp.Type) + ' Start=0x' + ('{0:X}' -f [int]$sp.Start) +
     ' Img=[' + (Clean ('' + $sp.ImagePath)) + '] Deps=[' + (@([string[]]$sp.DependOnService) -join ';') + ']')
}
$shb = RefreshCls
$bootUpper = 'none'
$bootFlHits = 0
O ('  P93 BOOT ' + (Snapshot))
foreach ($c in @($script:Cls)) {
  $fl = @(FlOf $c.ck)
  $wh = 0
  foreach ($e in $fl) { if ("$e" -match 'E475CF9A|5CBF81BF') { $wh++ } }
  $bootFlHits += $wh
  O ('  P93 BOOT-FL ' + $c.ck + ' count=' + $fl.Count + ' wifi_entries=' + $wh)
  $lk = Get-ItemProperty -LiteralPath (Join-Path $c.ck 'Linkage') -EA SilentlyContinue
  O ('    P93 BOOT-UPPERBIND=[' + (Clean (@([string[]]$lk.UpperBind) -join ';')) + ']')
}
# UpperFilters lives on the Enum DEVICE-INSTANCE key, not on the class key, so read it from the device list
# (RefreshCls hands back the same Shape result the later sections use; $script:Cls itself has no .up).
foreach ($d in @($shb.devs)) { O ('    P93 BOOT-DEV ' + $d.id + ' svc=' + $d.svc + ' Upper=[' + $d.up + ']') }
foreach ($d in @($shb.devs)) { if ($d.up -match 'vwifibus') { $bootUpper = 'vwifibus' } }

O '== 1 the component installer tooling on this disc =='
foreach ($t in @('netcfg.exe', 'netcfgx.dll', 'netshell.dll', 'ncobjapi.dll', 'NetCfgNotifyObjectHost.exe',
                 'netman.dll', 'drvload.exe', 'pnputil.exe', 'netsh.exe', 'wlanext.exe', 'wlansvc.dll',
                 'wlanapi.dll', 'hnetcfg.dll', 'NETSETUP.DLL')) {
  $p = Join-Path $S32 $t
  $sz = ''
  if (Test-Path -LiteralPath $p) { $sz = ' bytes=' + ((Get-Item -LiteralPath $p -EA SilentlyContinue).Length) }
  $ex = (Test-Path -LiteralPath $p)
  O ('  P93 TOOL ' + $t + ' exists=' + $ex + $sz + ' version=' + (FV $p))
}
$h = Run $NCFG @('/?')
O ('  P93 NETCFG-HELP rc=' + $h.rc + ' lines=' + $h.lines.Count)
foreach ($l in @($h.lines | Select-Object -First 30)) { O ('    | ' + $l) }
# From that help text the real syntax is:  netcfg [-v] [-l <full-path-to-component-INF>] -c <p|s|c> -i <comp-id>
# (arguments MUST be in that order), plus the read-only query form  netcfg [-v] -q <comp-id>.
foreach ($q in @('ms_nativewifip', 'ms_vwifi', 'MS_NativeWifiP')) {
  $r = Run $NCFG @('-v', '-q', $q)
  O ('  P93 NCFG-Q ' + $q + ' rc=' + $r.rc + ' lines=' + $r.lines.Count)
  foreach ($l in @($r.lines | Select-Object -First 3)) { O ('    | ' + $l) }
}

O '== 2 what the offline DISM /Add-Driver left: FileRepository, oem###.inf, covering .cat =='
$fsroot = Join-Path $S32 'DriverStore\FileRepository'
$rootok = (Test-Path -LiteralPath $fsroot)
$pkgs = @()
if ($rootok) {
  $pkgs = @(Get-ChildItem -LiteralPath $fsroot -Directory -EA SilentlyContinue |
            Where-Object { $_.PSChildName -match '(?i)^net(nwifi|vwifi)' })
}
O ('  P93 DRVSTORE packages=' + $pkgs.Count + ' root_exists=' + $rootok)
foreach ($d in $pkgs) {
  $files = @(Get-ChildItem -LiteralPath $d.FullName -Recurse -File -EA SilentlyContinue)
  $names = @($files | ForEach-Object { $_.PSChildName } | Sort-Object)
  $shown = ($names -join ',')
  O ('    P93 PKG ' + $d.PSChildName + ' files=' + $names.Count + ' [' + $shown + ']')
}
$oems = @(Get-ChildItem -LiteralPath $INFDIR -Filter 'oem*.inf' -File -EA SilentlyContinue)
O ('  P93 OEM-INF count=' + $oems.Count)
foreach ($f in $oems) {
  $hits = @(InfHits $f.FullName '(?i)nwifi|vwifi|MS_NWIFI|NativeWifi')
  if ($hits.Count -eq 0) { continue }
  $clsLine = @(@(InfText $f.FullName) | Where-Object { $_ -match '(?i)^Class\s*=' } | Select-Object -First 1)
  O ('    P93 OEM ' + $f.PSChildName + ' matches=' + $hits.Count + ' Class=[' + ($clsLine -join '') + ']')
  foreach ($l in @($hits | Select-Object -First 3)) { O ('          | ' + $l) }
}
foreach ($i in @('netnwifi.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netvwifibus.inf')) {
  $p = Join-Path $INFDIR $i
  $ok = (Test-Path -LiteralPath $p)
  $b = 0
  if ($ok) { $b = (Get-Item -LiteralPath $p).Length }
  O ('  P93 INBOX-INF ' + $i + ' windows\INF=' + $ok + ' bytes=' + $b)
}
$catok = (Test-Path -LiteralPath $CATDIR)
$cats = @(Get-ChildItem -LiteralPath $CATDIR -Filter '*.cat' -File -EA SilentlyContinue)
O ('  P93 CATROOT ' + $CATDIR + ' exists=' + $catok + ' cats=' + $cats.Count)
foreach ($c in @($cats | Where-Object { $_.PSChildName -match '(?i)Package0(4|5112)' })) {
  O ('    P93 CAT ' + $c.PSChildName + ' bytes=' + $c.Length)
}

O '== 3 baseline: component records, adapter class instances, bindings =='
$nsok = (Test-Path -LiteralPath $NS)
if (-not $nsok) { O ('  P93 NS-CLASS-KEY <absent> ' + $NS) }
$null = RefreshCls
O ('  P93 BASE ' + (Snapshot))
foreach ($c in @($script:Cls)) {
  $n = @(FlOf $c.ck).Count
  O ('    P93 CLSINST ' + $c.ck + ' NetCfgInstanceId=[' + $c.ncfg + '] FilterList=' + $n)
  DumpClass $c.ck 'CLS1'
}
O '== 3b (still baseline) the CLASS registrations NetCfg installs into, and the adapter CONNECTION key =='
# netcfg installs a NetService component through NetCfgx!NetClassInstaller, which is registered on the CLASS key.
# If that class key is absent or lacks Installer32/Characteristics, no `-l ... -c s -i ...` call can ever install,
# and the offline bake has to write the record itself. The connection key under Control\Network\{4d36e972}\{ncfg}
# is what makes the adapter a network CONNECTION at all (host: Name=WLAN, PnPInstanceId, MediaSubType=2).
foreach ($g in @('{4d36e972-e325-11ce-bfc1-08002be10318}', '{4d36e973-e325-11ce-bfc1-08002be10318}',
                '{4d36e974-e325-11ce-bfc1-08002be10318}', '{4d36e975-e325-11ce-bfc1-08002be10318}')) {
  $p = Join-Path $CLSNET $g
  if (-not (Test-Path -LiteralPath $p)) { O ('  P93 CLASSKEY ' + $g + ' <absent>'); continue }
  $ip = Get-ItemProperty -LiteralPath $p -EA SilentlyContinue
  $inst = @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })
  $vals = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
  O ('  P93 CLASSKEY ' + $g + ' instances=' + $inst.Count + ' vals=[' + ($vals -join ',') + ']')
  foreach ($n in @('Class', 'ClassGuid', 'ClassDesc', 'Installer32', 'NoInstallClass', 'NoStaticClass',
                   'Characteristics', 'UpperFilters', 'LowerFilters', 'IconPath', 'Security', 'EnumPropPages32')) {
    if ($null -eq $ip.$n) { continue }
    $v = $ip.$n
    if ($v -is [array]) { $v = ($v -join ';') }
    if (("$v").Length -gt 100) { $v = ("$v").Substring(0, 100) + '...' }
    O ('    P93 CK ' + $g.Substring(1, 8) + ' ' + $n + ' = ' + (Clean "$v"))
  }
}
$NETCLS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
$netinst = @(Get-ChildItem -LiteralPath $NETCLS -EA SilentlyContinue)
O ('  P93 NETCONN instances=' + $netinst.Count)
foreach ($k in $netinst) {
  $conn = Join-Path $k.PSPath 'Connection'
  if (-not (Test-Path -LiteralPath $conn)) { O ('    P93 NETCONN ' + $k.PSChildName + ' <no Connection subkey>'); continue }
  $ip = Get-ItemProperty -LiteralPath $conn -EA SilentlyContinue
  $vals = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name })
  O ('    P93 NETCONN ' + $k.PSChildName + ' vals=[' + ($vals -join ',') + '] Name=[' + (Clean "$($ip.Name)") +
     '] PnpInstanceId=[' + (Clean "$($ip.PnpInstanceId)") + '] MediaSubType=' + (HexVal $ip.MediaSubType) +
     ' *IfType=' + (HexVal $ip.'*IfType'))
}
$sh0 = Shape
O ('  P93 DEVICES wlan=' + @($sh0.devs).Count + ' vwifimp_nodes=' + $sh0.vwifimp)
foreach ($d in @($sh0.devs)) { O ('    P93 DEV ' + $d.id + ' svc=' + $d.svc + ' Upper=[' + $d.up + '] classkey=[' + $d.drv + ']') }
$script:Sa0 = @(SaHits)
$sasz = 0
if (Test-Path -LiteralPath $SETUPAPI) { $sasz = (Get-Item -LiteralPath $SETUPAPI).Length }
O ('  P93 SETUPAPI ' + $SETUPAPI + ' exists=' + (Test-Path -LiteralPath $SETUPAPI) + ' bytes=' + $sasz +
   ' wifi_lines=' + $script:Sa0.Count)
foreach ($l in @($script:Sa0 | Select-Object -Last 6)) { O ('    | ' + $l) }

O '== 4 installer ladder (only with -Apply; every rung re-measures the records) =='
# Which INF to hand the installer: netnwifi.inf declares the component through section MS_NWIFI.Install, so find the
# INF on this disc whose body contains that section (the DISM-staged copy is oem###.inf, the bake also left the bare
# inbox name). Intel/vendor INFs only write `Include = netvwifibus.inf`, so MS_NWIFI is the discriminator.
$nsInf  = @($oems | Where-Object { @(InfHits $_.FullName 'MS_NWIFI').Count -gt 0 } | Select-Object -First 1)
$fltInf = @($oems | Where-Object { @(InfHits $_.FullName 'VWiFiFlt|ms_vwifi').Count -gt 0 } | Select-Object -First 1)
if ($nsInf.Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $INFDIR 'netnwifi.inf'))) { $nsInf = @((Get-Item -LiteralPath (Join-Path $INFDIR 'netnwifi.inf'))) }
if ($fltInf.Count -eq 0 -and (Test-Path -LiteralPath (Join-Path $INFDIR 'netvwififlt.inf'))) { $fltInf = @((Get-Item -LiteralPath (Join-Path $INFDIR 'netvwififlt.inf'))) }
$nsPath = ''; if ($nsInf.Count -gt 0) { $nsPath = $nsInf[0].FullName }
$flPath = ''; if ($fltInf.Count -gt 0) { $flPath = $fltInf[0].FullName }
O ('  P93 LADDER-INF nwifi=[' + $nsPath + '] flt=[' + $flPath + ']')

# Syntax taken from `netcfg /?` on this very machine (section 1): arguments MUST come in the order
#   netcfg [-v] [-l <full-path-to-component-INF>] -c <p|s|c> -i <comp-id>
# The component IDs come out of the INF class-registration lines this probe just read:
#   oem181.inf (netnwifi.inf)     : %MS_NWIFI.DisplayName% = MS_NWIFI.Install, MS_NativeWifiP
#   oem179.inf (netvwififlt.inf)  : %vwififlt_Desc%       = Install,            ms_vwifi
# The oem### number is assigned by DISM per build, so a boot-time recipe must NOT depend on it: the rungs named
# 'inbox' hand netcfg the baked Windows\INF\netnwifi.inf / netvwififlt.inf path directly. If an 'inbox' rung reaches
# the same result, the fix is one deterministic line in the PE boot path instead of a registry guess.
$inboxN = Join-Path $INFDIR 'netnwifi.inf'
$inboxF = Join-Path $INFDIR 'netvwififlt.inf'
$Ladder = @()
if ($nsPath -ne '') { $Ladder += @{ n = 'ncfg-i-nwifi';    e = $NCFG; a = @('-v', '-l', $nsPath, '-c', 's', '-i', 'MS_NativeWifiP') } }
if ($flPath -ne '') { $Ladder += @{ n = 'ncfg-i-vwifi';    e = $NCFG; a = @('-v', '-l', $flPath, '-c', 's', '-i', 'ms_vwifi') } }
if (Test-Path -LiteralPath $inboxF) { $Ladder += @{ n = 'ncfg-inbox-vwifi'; e = $NCFG; a = @('-v', '-l', $inboxF, '-c', 's', '-i', 'ms_vwifi') } }
$Ladder += @{ n = 'ncfg-u-nwifi';    e = $NCFG; a = @('-v', '-u', 'MS_NativeWifiP') }
if (Test-Path -LiteralPath $inboxN) { $Ladder += @{ n = 'ncfg-inbox-nwifi'; e = $NCFG; a = @('-v', '-l', $inboxN, '-c', 's', '-i', 'MS_NativeWifiP') } }
if ($nsPath -ne '') { $Ladder += @{ n = 'ncfg-restore';    e = $NCFG; a = @('-v', '-l', $nsPath, '-c', 's', '-i', 'MS_NativeWifiP') } }
if ($nsPath -ne '') { $Ladder += @{ n = 'pnputil-install'; e = $PNPU; a = @('/add-driver', $nsPath, '/install') } }
if ($nsPath -ne '') { $Ladder += @{ n = 'drvload-nwifi';   e = $DRVL; a = @($nsPath) } }

if (-not $Apply) {
  O ('  P93 SKIP ladder (read-only run; re-deliver with -Apply). LADDER-PLAN steps=' + $Ladder.Count)
  foreach ($s in $Ladder) {
    $cmdline = $s.e + ' ' + (@($s.a) -join ' ')
    O ('    P93 PLAN ' + $s.n + ' -> ' + (Clean $cmdline))
  }
} elseif (($SR -notmatch '(?i)^X:') -and -not $IDoit) {
  O ('  P93 REFUSE mutate: SystemRoot=' + $SR + ' is not the RAMDISK. The read-only results above stand.')
} else {
  foreach ($s in $Ladder) {
    if ($Only -ne '' -and $s.n -notlike ('*' + $Only + '*')) { continue }
    $r = Run $s.e @($s.a)
    O ('  P93 RUN ' + $s.n + ' rc=' + $r.rc + ' lines=' + $r.lines.Count)
    foreach ($l in @($r.lines | Select-Object -First 6)) { O ('    | ' + $l) }
    Start-Sleep -Seconds 3
    $null = RefreshCls
    $shx = Shape
    $sn = Snapshot
    O ('    P93 AFTER ' + $s.n + ': ' + $sn + ' | stack=' + (StackLine) + ' vwifimp_nodes=' + $shx.vwifimp)
    $sa = @(SaHits)
    O ('    P93 SETUPAPI wifi_lines=' + $sa.Count + ' delta_vs_base=' + ($sa.Count - @($script:Sa0).Count))
    if ($sa.Count -gt 0) { O ('      | last: ' + (@($sa | Select-Object -Last 1) -join '')) }
    # probe90 already put the two component records in place, so the record count is NOT progress; on 2026-10-11
    # 14:2x nativewifip:Running after the first rung proved netcfg attaching the filter is its own step. The ladder
    # only stops at the ACTUAL goal: a virtual miniport child (vWiFi end-to-end) or wlansvc running.
    $wlx = "$((Get-Service -Name wlansvc -EA SilentlyContinue).Status)"
    if ($shx.vwifimp -gt 0 -or "$wlx" -eq 'Running') {
      O ('  P93 PROGRESS ' + $s.n + ' reached the goal (vwifimp_nodes=' + $shx.vwifimp + ' wlansvc=' + $wlx + ') -- stopping the ladder')
      break
    }
  }
}

O '== 5 bind pass: restart the wireless devnode, then read the stack again =='
$null = RefreshCls
if (-not $Apply) {
  O '  P93 SKIP (read-only run)'
} elseif (@($script:Cls).Count -eq 0) {
  O '  P93 SKIP restart: no wireless class instance found'
} else {
  foreach ($c in @($script:Cls)) {
    $o = @(& $PNPU '/restart-device' $c.id 2>&1 | ForEach-Object { Clean "$_" })
    $rc = $LASTEXITCODE
    O ('  P93 PNP restart ' + $c.id + ' rc=' + $rc + ' lines=' + $o.Count)
    foreach ($l in @($o | Select-Object -First 3)) { O ('    | ' + $l) }
  }
  Start-Sleep -Seconds 8
}

O '== 6 re-measure =='
$sh2 = RefreshCls
O ('  P93 STACK2 ' + (StackLine))
$snap = Snapshot
O ('  P93 STATE2 ' + $snap)
O ('  P93 VWIFIMP_NODES=' + $sh2.vwifimp + ' wlan_devices=' + @($sh2.devs).Count)
foreach ($d in @($sh2.devs)) { O ('    P93 DEV2 ' + $d.id + ' Upper=[' + $d.up + ']') }
foreach ($c in @($script:Cls)) {
  $fl = @(FlOf $c.ck)
  O ('    P93 FL2 ' + $c.ck + ' count=' + $fl.Count)
  foreach ($e in $fl) { if ("$e" -match 'E475CF9A|5CBF81BF') { O ('        | NOW ' + $e) } }
  DumpClass $c.ck 'CLS2'
}
try {
  $svc = Get-Service -Name wlansvc -EA Stop
  if ("$($svc.Status)" -ne 'Running') { Start-Service -Name wlansvc -EA Stop; Start-Sleep -Seconds 4 }
  $ws = (Get-Service -Name wlansvc -EA SilentlyContinue).Status
  O ('  P93 WLANSVC -> ' + $ws)
} catch { O ('  P93 WLANSVC start failed: ' + (Clean $_.Exception.Message)) }
# net.exe prints the SCM's own error line (1062 ERROR_SERVICE_NEVER_STARTED / 1068 dependency / 577 CI), which is a
# harder number than the .NET wrapper's generic "Failed to start service".
$NETX = Join-Path $S32 'net.exe'
$n1 = Run $NETX @('start', 'wlansvc')
O ('  P93 NET-START rc=' + $n1.rc + ' lines=' + $n1.lines.Count)
foreach ($l in @($n1.lines | Select-Object -First 6)) { O ('    | ' + $l) }
$ni = Run $NSH @('wlan', 'show', 'interfaces')
O ('  P93 NETSH-WLAN rc=' + $ni.rc + ' lines=' + $ni.lines.Count)
foreach ($l in @($ni.lines | Select-Object -First 12)) { O ('    | ' + $l) }
$n2 = Run $NSH @('wlan', 'show', 'networks', 'bssid')
O ('  P93 NETSH-NETWORKS rc=' + $n2.rc + ' lines=' + $n2.lines.Count)
foreach ($l in @($n2.lines | Select-Object -First 10)) { O ('    | ' + $l) }
$nas  = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)
$wifi = @($nas | Where-Object { "$($_.Name)$($_.Description)$($_.ServiceName)" -match '(?i)wireless|wi-fi|wifi|wlan|netwtw|netwaw|rtwlane' })
O ('  P93 ADAPTERS total=' + $nas.Count + ' wifi_or_wfd=' + $wifi.Count)
foreach ($a in $wifi) { O ('    P93 NAPA ' + (Clean $a.Name) + ' svc=' + $a.ServiceName + ' physical=' + $a.PhysicalAdapter) }
$saF = @(SaHits)
O ('  P93 SETUPAPI2 wifi_lines=' + $saF.Count + ' delta_vs_base=' + ($saF.Count - @($script:Sa0).Count))
foreach ($l in @($saF | Select-Object -Last 10)) { O ('    | ' + $l) }
# NetCfg's own view of "installed" (section 1 says NOT installed even while probe90's hand-written record key exists,
# so this query is the authoritative check of what the installer actually registered).
foreach ($q in @('MS_NativeWifiP', 'ms_vwifi', 'MS_VWiFiImp')) {
  $rq = Run $NCFG @('-v', '-q', $q)
  $first = ''
  if ($rq.lines.Count -gt 0) { $first = $rq.lines[0] }
  O ('  P93 NCFG-Q2 ' + $q + ' rc=' + $rq.rc + ' | ' + $first)
}

O '== 7 verdict =='
$run = @(@('nativewifip', 'vwifibus', 'vwififlt', 'vwifimp') | Where-Object { "$((Get-Service -Name $_ -EA SilentlyContinue).Status)" -eq 'Running' }).Count
$wl  = "$((Get-Service -Name wlansvc -EA SilentlyContinue).Status)"
$stk = StackLine
# The working host records the ATTACHED upper filters in the adapter class instance Linkage\UpperBind. If nwifi /
# vwififlt never show up there, NDIS was never told to open them, no matter how complete the component records are.
$ub = ''
$mt = ''
foreach ($c in @($script:Cls)) {
  $lkv = Get-ItemProperty -LiteralPath (Join-Path $c.ck 'Linkage') -EA SilentlyContinue
  if ($null -ne $lkv.UpperBind) { $ub = (@($lkv.UpperBind) -join ';') }
  $cip = Get-ItemProperty -LiteralPath $c.ck -EA SilentlyContinue
  if ($null -ne $cip.'*MediaType') { $mt = "$($cip.'*MediaType')" }
}
$attached = ($stk -match 'nativewifip:Running') -or ($sh2.vwifimp -gt 0)
$outcome = 'no-progress'
if (-not (Test-Path -LiteralPath $NCFG)) { $outcome = 'netcfg-absent' }
elseif (-not $Apply)                     { $outcome = 'read-only' }
elseif ($sh2.vwifimp -gt 0)              { $outcome = 'vwifimp-children-present' }
elseif ($attached)                       { $outcome = 'nativewifip-running-no-children' }
elseif ("$wl" -eq 'Running')             { $outcome = 'wlansvc-running-no-children' }
elseif ($snap -match 'nwifi=False')      { $outcome = 'installer-refused-no-record' }
elseif ($run -ge 2)                      { $outcome = 'record-present-stack-partial' }
O ('P93 VERDICT outcome=' + $outcome + ' apply=' + $Apply.IsPresent + ' netcfg=' + (Test-Path -LiteralPath $NCFG) +
   ' help_rc=' + $h.rc + ' stack=' + $stk + ' stack_running=' + $run + '/4 vwifimp_nodes=' + $sh2.vwifimp +
   ' wlansvc=' + $wl + ' boot_upper=' + $bootUpper + ' boot_filter_hits=' + $bootFlHits +
   ' media_type=[' + $mt + '] upperbind=[' + (Clean $ub) + '] [' + $snap + ']')
if (-not $Apply) {
  O 'P93 READING: read-only pass. Compare the CLS1 block with the working host in'
  O '         build\scratch\_host_wifi_bind_ref2.txt (host: *IfType=71 *MediaType=16 NetType=WLAN'
  O '         IncludedInfs=netvwifibus.inf, Linkage\UpperBind lists the filters that actually attached). Whatever'
  O '         value the host has and CLS1 lacks is the bake target; the component records alone are already proved'
  O '         insufficient by probe90.'
} elseif ($sh2.vwifimp -gt 0 -or $attached) {
  O 'P93 READING: a supported installer call attached the native WiFi filter -- the rung that printed PROGRESS is the'
  O '         fix. Either run that exact command from the PE boot path or reproduce its registry writes offline in'
  O '         wifi-inject.ps1, and the WiFi half of the rescue image is done.'
} elseif ($outcome -eq 'installer-refused-no-record') {
  O 'P93 READING: netcfg ran and refused; the rc and the lines above name the reason. If it is a catalog/signature'
  O '         complaint, the offline fix has to write the component records + FilterList into the SYSTEM hive in'
  O '         wifi-inject.ps1 so they exist at FIRST configure -- the one thing probe90 proved a running PE cannot'
  O '         retroactively do.'
} else {
  O 'P93 READING: the installer calls ran and the records/FilterList are in place, yet Linkage\UpperBind still does'
  O '         not list the WiFi filters and nativewifip never starts. Binding is decided at first configure, so the'
  O '         fix is offline: bake the CLS1-vs-host diff into wifi-inject.ps1/netdrvfix.ps1 and accept on a fresh'
  O '         boot -- a live restart-device will not re-run the NetCfg bind pass for this devnode.'
}
O 'P93 END'
