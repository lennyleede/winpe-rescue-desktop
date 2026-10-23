# probe87 -- WDI BINDING SHAPE: the same readings on the host and inside the live PE, so a red line in PE is
# compared against measured truth instead of against my theory of what WDI needs.
#
# Why this exists (2026-10-10 22:30 disc, acceptance pass build\scratch\accept_run_10102230.txt):
#   P86 DISC verdict=baked-disc+aligned / FIX ok=yes  -> the service-key alignment IS on the booted disc, and it
#   moved wcmsvc from "SCM refused it (err=1068)" to "SCM started it, host pid 2496, it died with win32=0x42B
#   (1067 ERROR_SERVICE_TERMINATED), kind=faulted". wlansvc is UNCHANGED: host pid 2712, still returns
#   0x800C0006 with delay_dll=7/7 present. So the key shape and the delay-load backends are both spent variables.
#   probe42 on the same boot: adapter enumerated (wifi_nodes=1/1, devcodes=0,0, Netwtw14 Running, initstartfailed
#   absent) but upper=none and vwifibus_node=no.
#
# The reference readings from build\scratch\host_wdi_binding.txt (this machine, a WORKING WiFi host):
#   nativewifip  state=Running  Type=1 Start=3 Group=[NDIS]
#   wdiwifi      state=Running  Type=1 Start=3 Group=[]        Parameters=ForceLogsInMiniDump,WppRecorder_TraceGuid
#   NdisImPlatform state=STOPPED Type=1 Start=3 Group=[]       <- stopped is NORMAL, do not treat it as a defect
#   vwifibus     state=Running  Type=1 Start=3 Group=[]
#   vwififlt     state=Running  Type=1 Start=1 Group=[NDIS]
#   vwifimp      state=Running  Type=1 Start=3 Group=[NDIS]
#   PCI devnode of the card: UpperFilters=[vwifibus]   (the CLASS key has no filter lists at all)
# So the question this probe answers in one run: does the PE's wireless devnode carry vwifibus as an upper filter,
# and are nativewifip/wdiwifi/vwifibus/vwififlt actually loaded? If the filter is missing, wlansvc's "specified
# object" has a name: the native WiFi interface object that only exists once WDI is attached to the miniport.
#
# READ-ONLY. It touches no registry value and starts/stops nothing. Run it on the host and in the PE with the
# same command shape; the PE copy is pushed through test\host_push_run.ps1.
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }
function Root([string]$sub) {
  # X:\windows in PE, %SystemRoot% on the host -- one script, two machines.
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}

$SRV = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$want = @('nativewifip', 'wdiwifi', 'NdisImPlatform', 'vwifibus', 'vwififlt', 'vwifimp', 'wlansvc', 'wcmsvc')
# host truth for the WDI-layer drivers; NdisImPlatform is deliberately NOT in the want-run list (it is
# Stopped on a healthy machine), and wlansvc/wcmsvc are reported but not judged here (probe86 owns those).
$wantRun = @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp')

O ('P87 START root=' + (Root '') + ' ps=' + $PSVersionTable.PSVersion.ToString())

O '== 1 the WDI-layer driver services: is the framework actually loaded =='
$stateMap = @{}
foreach ($n in $want) {
  $p = Join-Path $SRV $n
  if (-not (Test-Path $p)) { O ('  P87 SVC ' + $n + ' KEY=absent'); $stateMap[$n] = 'absent'; continue }
  $st = (Get-Service -Name $n -EA SilentlyContinue).Status
  if ("$st" -eq '') { $st = '-' }
  $stateMap[$n] = "$st"
  $pp = Join-Path $p 'Parameters'
  $pnames = ''
  if (Test-Path $pp) { $pnames = ((@(Get-Item $pp).Property) -join ',') }
  O ('  P87 SVC ' + $n + ' state=' + $st + ' Type=' + (RegV $p 'Type') + ' Start=' + (RegV $p 'Start') +
     ' Group=[' + (RegV $p 'Group') + ']' + ' Params=[' + $pnames + ']')
}

O '== 2 the wireless device instances: the upper filter that attaches WDI to the miniport =='
# Host truth measured 2026-10-10 23:0x (build\scratch\t_p87_enum_shape.ps1): walking THREE levels of Enum, the
# wifi-related devnodes on a working machine are
#   PCI\VEN_8086&DEV_2526...\4&...            service=Netwtw08   UpperFilters=[vwifibus]
#   {5d624f94-8850-40c3-a3fa-a4fd2080baf3}\vwifimp_wfd\5&...    service=vwifimp   (4 of them = the
#       "Microsoft Wi-Fi Direct Virtual Adapter" instances)
# There is NO devnode whose Service is vwifibus -- vwifibus is a bus FILTER hanging off the adapter's UpperFilters,
# so the first version's "vwifibus devnode must exist" criterion was an instrument bug (it read gaps on a healthy
# host). What actually identifies the attachment is: the adapter carries vwifibus as an upper filter, AND vwifimp
# virtual-adapter nodes exist.
$found = 0; $withVb = 0; $vwifimpNodes = 0; $vwifibusNodes = 0
foreach ($bus in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
  foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
    foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
      $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
      $svc = "$($ip.Service)"
      if ($svc -match '^vwifimp$') { $vwifimpNodes++; continue }
      if ($svc -match '^vwifibus$') { $vwifibusNodes++ }
      if ($svc -notmatch '(?i)^netwtw|^netwaw|^rtwlane|^netw|^rtl|nativewifip') { continue }
      $found++
      $up = @($ip.UpperFilters)
      $prob = $ip.Problem
      $ek = Join-Path $inst.PSPath 'Enum'
      $isf = ''
      if (Test-Path $ek) { $isf = ("$(RegV $ek 'INITSTARTFAILED')") }
      if ($up -contains 'vwifibus') { $withVb++ }
      O ('  P87 DEVNODE ' + $bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName +
         ' svc=' + $svc + ' Upper=[' + ($up -join ',') + ']' +
         ' Problem=' + $(if ("$prob" -eq '') { '-' } else { $prob }) +
         ' INITSTARTFAILED=' + $(if ($isf -eq '') { 'absent' } else { $isf }))
    }
  }
}
if ($found -eq 0) { O '  P87 DEVNODE none of the wireless driver services is referenced by a devnode' }
O ('  P87 ENUM vwifimp_nodes=' + $vwifimpNodes + ' vwifibus_service_nodes=' + $vwifibusNodes +
   ' (host truth: vwifimp=4, vwifibus service nodes are not what carries the bus)')

O '== 3 class-level filter lists (host truth: both empty, so a value here would be an anomaly) =='
$cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
O ('  P87 CLASS Upper=[' + (@(RegV $cls 'UpperFilters') -join ',') +
   '] Lower=[' + (@(RegV $cls 'LowerFilters') -join ',') + ']')

O '== 4 verdict (reference = build\scratch\host_wdi_binding.txt, measured on a working machine) =='
$missRun = @($wantRun | Where-Object { $stateMap[$_] -ne 'Running' })
$missing = @()
foreach ($n in $wantRun) { if (-not (Test-Path (Join-Path $SRV $n))) { $missing += $n } }
$gaps = @()
if ($missing.Count) { $gaps += ('svc_key_absent=' + ($missing -join ',')) }
if ($missRun.Count) { $gaps += ('not_running=' + (($missRun | ForEach-Object { $_ + '/' + $stateMap[$_] }) -join ',')) }
if ($found -eq 0) { $gaps += 'no_wireless_devnode' }
elseif ($withVb -eq 0) { $gaps += 'vwifibus_not_upper_filter_of_adapter' }
if ($vwifimpNodes -eq 0) { $gaps += 'no_vwifimp_nodes' }
$layerTxt = (@($wantRun | ForEach-Object { $_ + ':' + $stateMap[$_] }) -join ',')
O ('P87 VERDICT wdilayer=' + $layerTxt)
O ('P87 VERDICT adapter_nodes=' + $found + ' with_vwifibus_upper=' + $withVb +
   ' vwifimp_nodes=' + $vwifimpNodes + ' gaps=' + $(if ($gaps.Count) { $gaps -join ',' } else { 'none' }))
if ($gaps.Count -eq 0) {
  O 'P87 READING: the binding shape matches the working host. If wlansvc still returns 0x800C0006 here, the'
  O '         missing object is something the service looks up at runtime rather than the WDI attachment.'
} elseif ($gaps -join ',' -match 'vwifibus_not_upper_filter|no_vwifimp_nodes') {
  O 'P87 READING: the card bound but WDI is NOT attached to it (host truth: the adapter devnode carries'
  O '         UpperFilters=vwifibus and vwifimp virtual-adapter nodes exist). Without that there is no native WiFi'
  O '         interface object, which is exactly the kind of thing wlansvc reports as "the specified object".'
} else {
  O ('P87 READING: the WDI layer itself is not loaded in this environment (' + ($gaps -join ',') +
      ') -- fix that before reading wlansvc.')
}
O 'P87 END'
