# probe90 -- the WDI COMPONENT RECORDS: read them on the live PE, diff against the working host, and (with
# -Apply) create exactly what is missing, then restart the wireless device and measure.
#
# What a working machine actually does (host forensics, build\scratch\host_component_records.txt +
# host_filterservice_class.txt + _host_wifi_components.txt, all read-only on 2026-10-11):
#   * the WiFi light-weight filters are NOT devnodes and have NO Control\Class instance. They are registered as
#     network COMPONENT records:
#       Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}\{E475CF9A-60CD-4439-A75F-0079CE0E18A1}
#         Characteristics=0x40028 ComponentId=ms_nativewifip InfPath=netnwifi.inf InfSection=MS_NWIFI.Install
#         Ndi\Service=NativeWifiP  Ndi\Interfaces UpperRange=noupper LowerRange=nolower FilterMediaTypes=wlan
#       Control\Network\{4d36e974-...}\{5CBF81BF-5055-47CD-9055-A76B2B4E3698}
#         ComponentId=ms_vwifi InfPath=netvwififlt.inf InfSection=Install Ndi\Interfaces FilterMediaTypes=vwifi,vchannel
#   * and they attach to each adapter through that adapter's CLASS instance:
#       Control\Class\{4d36e972-...}\NNNN\Linkage\FilterList (REG_MULTI_SZ) entries
#         "{adapter NetCfgInstanceId}-{component GUID}-0000"; the host's Intel AC 9260 line carries 14 entries,
#         among them ...-{E475CF9A(ms_nativewifip)}-0000 and ...-{5CBF81BF(ms_vwifi)}-0000,
#       plus Ndi\Interfaces UpperRange=ndis5,wifipro,... LowerRange=ethernet,wlan,vwifi, IncludedInfs=netvwifibus.inf.
#   * the adapter DEVNODE additionally carries UpperFilters=vwifibus (what probe89 hand-wrote: vwifibus went
#     Running, but vwifimp_nodes stayed 0 and nativewifip/vwififlt stayed Stopped -- consistent with the component
#     records plus FilterList entries being the missing half: without them NDIS has nothing to bind nwifi to, so no
#     native WiFi interface object appears and wlansvc returns 0x800C0006).
#
# MUTATION SAFETY: the write path only runs with -Apply, only when SystemRoot is the RAMDISK (X:), and only on
# devnodes/class instances whose driver service matches the WLAN whitelist. The Realtek wired adapter that carries
# this ssh session is never touched. Everything lives on the RAMDISK: rebooting restores the disc state. Nothing
# is written to the ISO, to D:\winpe_build, or to a customer disk.
param([switch]$Apply, [switch]$IDoit)
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Root([string]$sub) {
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}
function HexVal([object]$v) { if ($null -eq $v) { return '-' } return ('0x' + ('{0:X}' -f [int]$v)) }
$SR = Root ''
$PNPU = Join-Path (Join-Path $SR 'System32') 'pnputil.exe'
$REGX = Join-Path (Join-Path $SR 'System32') 'reg.exe'
$ENUMPS = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
$ENUM   = 'HKLM\SYSTEM\CurrentControlSet\Enum'
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'
$CLSNET   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class'
$NS       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
$NWIFI_ID = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'
$VWIFI_ID = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
$script:Cls = @()

function Shape {
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

O ('P90 START root=' + $SR + ' apply=' + $Apply.IsPresent)
O ('  P90 STACK ' + (StackLine))

O '== 1 WiFi filter COMPONENT records under Control\Network\{4d36e974-...} (NetService class) =='
if (-not (Test-Path -LiteralPath $NS)) {
  O ('  P90 NS-CLASS-KEY <absent> ' + $NS)
} else {
  $comps = @(Get-ChildItem -LiteralPath $NS -EA SilentlyContinue)
  O ('  P90 NS-COMPONENT instances=' + $comps.Count)
  foreach ($c in $comps) {
    $ip = Get-ItemProperty -LiteralPath $c.PSPath -EA SilentlyContinue
    $svc = (RegV (Join-Path $c.PSPath 'Ndi') 'Service')
    $fmt = (RegV (Join-Path $c.PSPath 'Ndi\Interfaces') 'FilterMediaTypes')
    O ('    P90 COMP ' + $c.PSChildName + ' cid=[' + $ip.ComponentId + '] inf=[' + $ip.InfPath + ']' +
       ' sect=[' + $ip.InfSection + '] char=' + (HexVal $ip.Characteristics) +
       ' Ndi/Service=[' + $svc + '] FilterMediaTypes=[' + $fmt + ']')
  }
}
foreach ($w in @(@('ms_nativewifip', $NWIFI_ID, 'netnwifi.inf'), @('ms_vwifi', $VWIFI_ID, 'netvwififlt.inf'))) {
  $p = Join-Path $NS $w[1]
  O ('  P90 NEED ' + $w[0] + ' key=' + $w[1] + ' present=' + (Test-Path -LiteralPath $p) + ' (installed by ' + $w[2] + ')')
}

O '== 2 the wireless adapter class instance: Ndi\Interfaces + Linkage\FilterList =='
$sh = Shape
O ('  P90 DEVICES wlan=' + @($sh.devs).Count + ' vwifimp_nodes=' + $sh.vwifimp)
foreach ($d in @($sh.devs)) {
  O ('    P90 DEV ' + $d.id + ' svc=' + $d.svc + ' Upper=[' + $d.up + '] classkey=[' + $d.drv + ']')
  if ($d.drv -eq '') { O '      P90 CLS <no Driver value>'; continue }
  $ck = Join-Path $CLSNET $d.drv
  if (-not (Test-Path -LiteralPath $ck)) { O ('      P90 CLS <absent> ' + $d.drv); continue }
  $ncfg = "$((RegV $ck 'NetCfgInstanceId'))"
  $script:Cls += @{ id = $d.id; ck = $ck; ncfg = $ncfg; reg = $d.reg; ps = $d.ps }
  O ('      P90 CLS ' + $d.drv + ' NetCfgInstanceId=[' + $ncfg + '] IncludedInfs=[' + (RegV $ck 'IncludedInfs') +
     '] Characteristics=' + (HexVal (RegV $ck 'Characteristics')) + ' *IfType=' + (RegV $ck '*IfType'))
  O ('      P90 NDI UpperRange=[' + (RegV (Join-Path $ck 'Ndi\Interfaces') 'UpperRange') +
     '] LowerRange=[' + (RegV (Join-Path $ck 'Ndi\Interfaces') 'LowerRange') + ']')
  $fl = @((Get-ItemProperty -LiteralPath (Join-Path $ck 'Linkage') -Name 'FilterList' -EA SilentlyContinue).PSObject.Properties['FilterList'].Value)
  O ('      P90 FILTERLIST count=' + $fl.Count)
  foreach ($e in $fl) { O ('        | ' + $e) }
}

O '== 3 files and service records the stack needs =='
foreach ($f in @('INF\netnwifi.inf', 'INF\netvwififlt.inf', 'INF\netvwifimp.inf', 'INF\netvwifibus.inf',
                 'System32\drivers\nwifi.sys', 'System32\drivers\vwififlt.sys', 'System32\drivers\vwifimp.sys',
                 'System32\drivers\vwifibus.sys', 'System32\drivers\wdiwifi.sys')) {
  O ('  P90 FILE ' + $f + ' exists=' + (Test-Path -LiteralPath (Join-Path $SR $f)))
}
foreach ($s in @('nativewifip', 'vwififlt', 'vwifimp', 'vwifibus', 'wdiwifi', 'NdisImPlatform')) {
  $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
  if (-not (Test-Path -LiteralPath $p)) { O ('  P90 SVC ' + $s + ' <absent>'); continue }
  O ('  P90 SVC ' + $s + ' Start=' + (RegV $p 'Start') + ' Group=[' + (RegV $p 'Group') + ']' +
     ' ImagePath=[' + (RegV $p 'ImagePath') + '] State=' + ((Get-Service -Name $s -EA SilentlyContinue).Status) +
     ' Subkeys=' + (@(Get-ChildItem -LiteralPath $p -EA SilentlyContinue).Count))
}

O '== 4 remedy: create the missing component records + FilterList entries, then restart the device =='
if (-not $Apply) {
  O '  P90 SKIP (read-only run; re-run with -Apply to mutate the live PE)'
} elseif (($SR -notmatch '(?i)^X:') -and -not $IDoit) {
  O ('  P90 REFUSE mutate: SystemRoot=' + $SR + ' is not the RAMDISK. The read-only results above stand.')
} else {
  function EnsureComp([string]$guid, [string]$cid, [string]$inf, [string]$sect, [string]$desc, [string]$svc, [string]$fmts) {
    $p = Join-Path $NS $guid
    $existed = Test-Path -LiteralPath $p
    if (-not $existed) {
      New-Item -Path (Join-Path $p 'Ndi\Interfaces') -Force -EA SilentlyContinue | Out-Null
    }
    Set-ItemProperty -LiteralPath $p -Name 'ComponentId' -Value $cid -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'InfPath' -Value $inf -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'InfSection' -Value $sect -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'Characteristics' -Value 262184 -Type DWord -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'Description' -Value $desc -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'LocDescription' -Value $desc -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath $p -Name 'NetCfgInstanceId' -Value $guid -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath (Join-Path $p 'Ndi') -Name 'Service' -Value $svc -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath (Join-Path $p 'Ndi') -Name 'HelpText' -Value $desc -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath (Join-Path $p 'Ndi\Interfaces') -Name 'UpperRange' -Value 'noupper' -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath (Join-Path $p 'Ndi\Interfaces') -Name 'LowerRange' -Value 'nolower' -Type String -EA SilentlyContinue
    Set-ItemProperty -LiteralPath (Join-Path $p 'Ndi\Interfaces') -Name 'FilterMediaTypes' -Value $fmts -Type String -EA SilentlyContinue
    O ('  P90 MKCOMP ' + $cid + ' ' + $guid + ' created=' + (-not $existed) + ' cid=[' + (RegV $p 'ComponentId') +
       '] svc=[' + (RegV (Join-Path $p 'Ndi') 'Service') + '] fmts=[' + (RegV (Join-Path $p 'Ndi\Interfaces') 'FilterMediaTypes') + ']')
  }
  EnsureComp $NWIFI_ID 'ms_nativewifip' 'netnwifi.inf' 'MS_NWIFI.Install' '@%windir%\System32\drivers\nwifi.sys,-101' 'NativeWifiP' 'wlan'
  EnsureComp $VWIFI_ID 'ms_vwifi' 'netvwififlt.inf' 'Install' '@%windir%\System32\drivers\vwififlt.sys,-105' 'vwififlt' 'vwifi,vchannel'

  foreach ($c in @($script:Cls)) {
    if ($c.ncfg -eq '') { O ('  P90 FL SKIP ' + $c.id + ' (class instance has no NetCfgInstanceId)'); continue }
    $lk = Join-Path $c.ck 'Linkage'
    if (-not (Test-Path -LiteralPath $lk)) { New-Item -Path $lk -Force -EA SilentlyContinue | Out-Null }
    $cur = @((Get-ItemProperty -LiteralPath $lk -Name 'FilterList' -EA SilentlyContinue).PSObject.Properties['FilterList'].Value)
    $want = @(($c.ncfg + '-' + $NWIFI_ID + '-0000'), ($c.ncfg + '-' + $VWIFI_ID + '-0000'))
    $new  = @(@($cur) + @($want) | Where-Object { "$_" -ne '' } | Select-Object -Unique)
    Set-ItemProperty -LiteralPath $lk -Name 'FilterList' -Value $new -Type MultiString -EA SilentlyContinue
    $back = @((Get-ItemProperty -LiteralPath $lk -Name 'FilterList' -EA SilentlyContinue).PSObject.Properties['FilterList'].Value)
    O ('  P90 FL ' + $c.id + ' before=' + @($cur).Count + ' after=' + $back.Count)
    foreach ($e in $back) { if ("$e" -match 'E475CF9A|5CBF81BF') { O ('        | NOW ' + $e) } }
    $o = @(& $REGX 'add' $c.reg '/v' 'UpperFilters' '/t' 'REG_MULTI_SZ' '/d' 'vwifibus' '/f' 2>&1 | ForEach-Object { "$_" })
    O ('  P90 UPPERFILTERS rc=' + $LASTEXITCODE + ' readback=[' + (@(RegV $c.ps 'UpperFilters') -join ',') + ']')
  }
  Start-Sleep -Seconds 1
  if (@($script:Cls).Count -gt 0) {
    $a = @(& $PNPU '/restart-device' $script:Cls[0].id 2>&1 | ForEach-Object { "$_" })
    O ('  P90 PNP restart rc=' + $LASTEXITCODE + ' lines=' + $a.Count)
    foreach ($l in @($a | Select-Object -First 4)) { O ('    | ' + (($l -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim()) }
    Start-Sleep -Seconds 8
  } else { O '  P90 PNP restart skipped: no wireless class instance to patch' }
}

O '== 5 re-measure =='
$sh2 = Shape
O ('  P90 STACK2 ' + (StackLine))
O ('  P90 AFTER vwifimp_nodes=' + $sh2.vwifimp + ' wlan=' + @($sh2.devs).Count)
foreach ($d in @($sh2.devs)) { O ('    P90 DEV2 ' + $d.id + ' Upper=[' + $d.up + ']') }
O ('  P90 NS-COMPONENT2 nwifi=' + (Test-Path -LiteralPath (Join-Path $NS $NWIFI_ID)) +
   ' vwifi=' + (Test-Path -LiteralPath (Join-Path $NS $VWIFI_ID)) +
   ' instances=' + (@(Get-ChildItem -LiteralPath $NS -EA SilentlyContinue).Count))
try {
  $svc = Get-Service -Name wlansvc -EA Stop
  if ("$($svc.Status)" -ne 'Running') { Start-Service -Name wlansvc -EA Stop; Start-Sleep -Seconds 4 }
  O ('  P90 WLANSVC -> ' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status)
} catch { O ('  P90 WLANSVC start failed: ' + (($_.Exception.Message) -replace '[^\x20-\x7E]', '?')) }
$nas  = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)
$wifi = @($nas | Where-Object { "$($_.Name)$($_.Description)$($_.ServiceName)" -match '(?i)wireless|wi-fi|wifi|wlan|netwtw|netwaw|rtwlane' })
O ('  P90 ADAPTERS total=' + $nas.Count + ' wifi_or_wfd=' + $wifi.Count)
foreach ($a in $wifi) { O ('    P90 NAPA ' + $a.Name + ' svc=' + $a.ServiceName + ' physical=' + $a.PhysicalAdapter + ' netenabled=' + $a.NetEnabled) }

O '== 6 verdict =='
$run = @(@('nativewifip', 'vwifibus', 'vwififlt', 'vwifimp') | Where-Object { "$((Get-Service -Name $_ -EA SilentlyContinue).Status)" -eq 'Running' }).Count
$wl  = "$((Get-Service -Name wlansvc -EA SilentlyContinue).Status)"
$outcome = 'no-wdi-binding'
if (@($sh2.devs).Count -eq 0) { $outcome = 'device-gone' }
elseif ($sh2.vwifimp -gt 0) { $outcome = 'vwifimp-children-present' }
elseif ("$wl" -eq 'Running') { $outcome = 'wlansvc-running-no-children' }
elseif ($run -ge 2) { $outcome = 'partial-stack-running' }
O ('P90 VERDICT outcome=' + $outcome + ' apply=' + $Apply.IsPresent +
   ' nwifi_record=' + (Test-Path -LiteralPath (Join-Path $NS $NWIFI_ID)) +
   ' stack_running=' + $run + '/4 vwifimp_nodes=' + $sh2.vwifimp + ' wlansvc=' + $wl)
if (-not $Apply) {
  O 'P90 READING: read-only pass. Diff section 1 (component records) and section 2 (FilterList, Ndi Interfaces)'
  O '         against the host reference in the header, then re-deliver the same probe with -Apply.'
} elseif ($outcome -eq 'vwifimp-children-present' -or "$wl" -eq 'Running') {
  O 'P90 READING: the component records plus the per-adapter FilterList entries were the missing half. Bake them'
  O '         offline into the PE hive in wifi-inject.ps1 (Control\Network\{4d36e974} component keys + the class'
  O '         instances FilterList), keep UpperFilters=vwifibus, and the WDI stack should come up on its own.'
} else {
  O 'P90 READING: records present and the filter bound, yet still no native WiFi interface. Next suspect is the'
  O '         component device install itself (netnwifi.inf as a NetService INF has to be installed by netcfg/'
  O '         pnputil, not just copied), so measure whether NDIS even opened nwifi.sys: read the P90 STACK2 line'
  O '         and nativewifip Parameters Subkeys.'
}
O 'P90 END'
