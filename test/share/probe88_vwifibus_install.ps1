# probe88 -- WHY vwifibus is not attached to the miniport in PE. READ-ONLY (no registry writes, no device actions).
#
# Where this came from (2026-10-10/11):
#   probe87 on the aligned disc (build\scratch\p87_pe_run.txt):
#     PCI\VEN_8086&DEV_7A70...\3&11583659&0&A3 svc=Netwtw14 Upper=[] Problem=0, vwifimp_nodes=0,
#     wdilayer=nativewifip:Stopped, wdiwifi:Running, vwifibus:Stopped, vwififlt:Stopped, vwifimp:Stopped
#   probe87 on the working host (build\scratch\p87_host.txt / host_wdi_binding.txt):
#     adapter devnode UpperFilters=[vwifibus], 4 vwifimp_wfd nodes, nativewifip/vwifibus/vwififlt/vwifimp Running.
#   No native WiFi interface object exists without that attachment, which is the object wlansvc cannot find
#   (0x800C0006 = ERROR_WLAN_NO_OBJECT / "the system cannot find the specified object").
#
# Two theories already MEASURED OUT, so this probe does not chase them:
#   (a) "the shipped Intel packages lack the VWiFiBus wiring" -- FALSE. build\scratch\pool_vwifibus_wiring.txt:
#       the curated Wlan_Intel_23x_20240310 INFs carry 276 (Netwtw08.INF) / 114 (Netwtw6e.INF) VWiFiBus
#       references and 138 / 57 Include lines, exactly like the host's installed oem57.inf.
#   (b) "netvwifibus.inf is missing from the image" -- the bake copies netvwifibus/netvwififlt/netvwifimp/netnwifi
#       .inf into Windows\INF and their .sys into System32\drivers (wifi-inject A3), with DISM staging 3/4
#       (only netvwifibus.inf is refused rc=13). This probe verifies what is ACTUALLY on the booted disc.
#
# What this probe is for: the install-time chain. Which INF really bound the card, does that INF ask for the
# VWiFiBus sections, can setupapi resolve Include=netvwifibus.inf in this image, and what does the PE's own
# setupapi log say about it. Those readings decide between "get netvwifibus.inf into the DriverStore properly",
# "re-install the INF so the HW section runs again", and "the filter never gets written by an INF install in PE".
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Root([string]$sub) {
  # X:\Windows in PE, %SystemRoot% on the host -- one script, two machines.
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}
function FileSize([string]$p) {
  if (Test-Path -LiteralPath $p) { return ((Get-Item -LiteralPath $p).Length) }
  return -1
}
function InfShape([string]$p) {
  # Count the wiring an INF really carries, the same way build\scratch\t_pool_vwifibus_wiring.ps1 counted it,
  # so a PE reading is directly comparable with the host/pool readings.
  if (-not (Test-Path -LiteralPath $p)) { return 'MISSING' }
  $t = @(Get-Content -LiteralPath $p -EA SilentlyContinue)
  $needs = @($t | Where-Object { $_ -match 'VWiFiBus' })
  $inc   = @($t | Where-Object { $_ -match '^\s*Include\s*=' })
  $filtHw = @($t | Where-Object { $_ -match 'VWiFiBus\.PnPFilterRegistration' })
  return ('lines=' + $t.Count + ' VWiFiBus_refs=' + $needs.Count + ' Include_lines=' + $inc.Count +
          ' PnPFilterReg_HW=' + $filtHw.Count)
}

$SR   = Root ''
$SR32 = Join-Path $SR 'System32'
$FR   = Join-Path $SR32 'DriverStore\FileRepository'
O ('P88 START root=' + $SR + ' ps=' + $PSVersionTable.PSVersion.ToString())

O '== 1 the vWiFi/WDI stack files as they exist on THIS booted image =='
# Host truth: all of these exist there too, so a full green here means "the pieces are on the disc" and the
# remaining question is purely whether PnP wired them to the device.
$infWant = @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')
$sysWant = @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys', 'wdiwifi.sys', 'NdisImPlatform.sys')
$infGot = 0
foreach ($i in $infWant) {
  $f = Join-Path (Join-Path $SR 'INF') $i
  $sz = FileSize $f
  if ($sz -ge 0) { $infGot++ }
  O ('  P88 INF ' + $i + ' = ' + $(if ($sz -ge 0) { "$sz bytes" } else { 'ABSENT' }))
}
$sysGot = 0
foreach ($y in $sysWant) {
  $f = Join-Path (Join-Path $SR32 'drivers') $y
  $sz = FileSize $f
  if ($sz -ge 0) { $sysGot++ }
  O ('  P88 SYS ' + $y + ' = ' + $(if ($sz -ge 0) { "$sz bytes" } else { 'ABSENT' }))
}
O ('  P88 FILES inf=' + $infGot + '/' + $infWant.Count + ' sys=' + $sysGot + '/' + $sysWant.Count)
# netvwifibus.inf is the one DISM refuses to stage (rc=13). If it is absent from Windows\INF on the booted
# disc, then the Include= in the Intel INF cannot resolve and UpperFilters will never be written.
O ('  P88 NETVWIFIBUS_IN_WINDOWS_INF = ' + $(if (Test-Path -LiteralPath (Join-Path $SR 'INF\netvwifibus.inf')) { 'yes' } else { 'NO' }))

O '== 2 DriverStore: which wireless packages are really staged =='
if (Test-Path -LiteralPath $FR) {
  $pkgs = @(Get-ChildItem -LiteralPath $FR -Directory -EA SilentlyContinue |
            Where-Object { $_.Name -match '(?i)^netwtw|^netwaw|^netvwifi|^netnwifi|^vwifi|^rtwlane|^bcmwl|^mtkwl' })
  foreach ($pk in $pkgs) {
    $infs = @(Get-ChildItem -LiteralPath $pk.PSPath -Filter '*.inf' -EA SilentlyContinue)
    $shape = ''
    foreach ($x in $infs) { $shape += (' [' + $x.Name + ' ' + (InfShape $x.FullName) + ']') }
    O ('  P88 FR ' + $pk.Name + ' inf_count=' + $infs.Count + $shape)
  }
  O ('  P88 FR matched_packages=' + $pkgs.Count + ' (a half-staged netvwifibus dir would show inf_count=0)')
} else { O ('  P88 FR ' + $FR + ' ABSENT') }

O '== 3 the adapter binding record: which INF/section installed the card =='
# HKLM\CurrentControlSet\Enum\<bus>\<prov>\<inst> has Driver={class guid}\NNNN; that class instance carries
# InfPath/InfSection -- i.e. the exact INF whose [*.HW] section was supposed to write UpperFilters=vwifibus.
$clsNet = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$bindList = @()
foreach ($bus in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
  foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
    foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
      $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
      $svc = "$($ip.Service)"
      if ($svc -notmatch '(?i)^netwtw|^netwaw|^rtwlane|^bcmwl|^mtkwl|^netw|^rtl') { continue }
      $dn = $bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName
      $up = @($ip.UpperFilters)
      $lk = Join-Path $inst.PSPath 'Linkage'
      $fl = ''
      if (Test-Path -LiteralPath $lk) { $fl = (@(RegV $lk 'FilterList') -join ',') }
      O ('  P88 DEVNODE ' + $dn + ' svc=' + $svc + ' driver=' + ("$($ip.Driver)") +
         ' problem=' + $(if ("$($ip.Problem)" -eq '') { '-' } else { $ip.Problem }) +
         ' Upper=[' + ($up -join ',') + '] LinkageFilterList=[' + $fl + ']')
      $bindList += @{ dn = $dn; svc = $svc; drv = "$($ip.Driver)"; up = ($up -join ',') }
    }
  }
}
if ($bindList.Count -eq 0) { O '  P88 DEVNODE no wireless-miniport service referenced by any devnode' }
foreach ($b in $bindList) {
  if ($b.drv -notmatch [regex]::Escape($clsNet)) {
    O ('  P88 BIND ' + $b.svc + ' driver key is not a Net class instance: ' + $b.drv)
    continue
  }
  $ck = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $b.drv
  if (-not (Test-Path -LiteralPath $ck)) { O ('  P88 BIND class instance ABSENT ' + $b.drv); continue }
  $infPath  = "$((RegV $ck 'InfPath'))"
  $infSec   = "$((RegV $ck 'InfSection'))"
  $mfgSec   = "$((RegV $ck 'MatchingInfSection'))"
  $prov2    = "$((RegV $ck 'Provider'))"
  O ('  P88 CLSKEY ' + $b.drv + ' InfPath=' + $infPath + ' InfSection=' + $infSec +
     ' MatchingInfSection=[' + ($mfgSec -join ',') + '] Provider=' + $prov2 +
     ' DriverVer=' + (RegV $ck 'DriverVer') + ' CatalogFile=' + (RegV $ck 'CatalogFile'))
  $cand = @((Join-Path $SR ("INF\" + $infPath)), (Join-Path $SR32 ("INF\" + $infPath)))
  if (Test-Path -LiteralPath $FR) {
    $hit = @(Get-ChildItem -LiteralPath $FR -Recurse -Filter $infPath -EA SilentlyContinue | Select-Object -First 1)
    foreach ($h in $hit) { $cand += $h.FullName }
  }
  $foundFile = ''
  foreach ($c in $cand) { if ($c -and (Test-Path -LiteralPath $c)) { $foundFile = $c; break } }
  if ($foundFile) {
    O ('  P88 BINDINF ' + $foundFile + ' ' + (InfShape $foundFile))
  } else {
    O ('  P88 BINDINF ' + $infPath + ' NOT FOUND in Windows\INF or DriverStore -> searched ' + ($cand -join ' | '))
  }
}

O '== 4 what the PE setupapi log says about VWiFiBus and the wireless install =='
# This is the decisive section: setupapi prints the Include-resolution complaint verbatim when it cannot find
# a needed section ("Needed section [VWiFiBus...] not found, might exist in missing included INF"), and it
# prints the CopyFiles/AddReg lines when it does run the filter registration.
$logs = @((Join-Path $SR 'INF\setupapi.dev.log'), (Join-Path $SR 'INF\setupapi.applog'))
foreach ($lg in $logs) {
  if (-not (Test-Path -LiteralPath $lg)) { O ('  P88 LOG ' + $lg + ' ABSENT'); continue }
  O ('  P88 LOG ' + $lg + ' size=' + (FileSize $lg))
  $pat = 'vwifibus|vwifimp|vwififlt|nwifi|VWiFiBus|Needed section|not found|netwtw|netwaw|DEV_7A70|UpperFilters'
  $m = @(Get-Content -LiteralPath $lg -EA SilentlyContinue | Where-Object { $_ -match ('(?i)' + $pat) })
  O ('  P88 LOG matched_lines=' + $m.Count)
  foreach ($l in @($m | Select-Object -Last 45)) { O ('    | ' + ($l -replace '[^\x20-\x7E]', '?').Trim()) }
}

O '== 5 user-mode view: any native WiFi object at all =='
try {
  $nas = @(Get-CimInstance Win32_NetworkAdapter -EA Stop)
  foreach ($a in $nas) {
    if ("$($a.Name)$($a.Description)$($a.ServiceName)" -notmatch '(?i)wireless|wifi|wlan|netwtw|netwaw|virtual') { continue }
    O ('  P88 NAPA ' + $a.Name + ' desc=' + $a.Description + ' svc=' + $a.ServiceName +
       ' physical=' + $a.PhysicalAdapter + ' netenabled=' + $a.NetEnabled +
       ' mac=' + $a.MACAddress + ' guid=' + $a.GUID)
  }
  O ('  P88 NAPA total_adapters=' + $nas.Count)
} catch { O ('  P88 NAPA query failed: ' + $_.Exception.Message) }
foreach ($d in @('wlanapi.dll', 'wcmsvc.dll', 'wdiwifi.dll', 'wlanext.exe')) {
  $f = Join-Path $SR32 $d
  O ('  P88 DLL ' + $d + ' = ' + $(if ((FileSize $f) -ge 0) { (FileSize $f).ToString() + ' bytes' } else { 'ABSENT' }))
}

O '== 6 verdict =='
$gaps = @()
if (-not (Test-Path -LiteralPath (Join-Path $SR 'INF\netvwifibus.inf'))) { $gaps += 'netvwifibus_inf_absent' }
if ($sysGot -lt $sysWant.Count) { $gaps += 'stack_sys_missing=' + ($sysWant.Count - $sysGot) }
$anyUpper = @($bindList | Where-Object { $_.up -match 'vwifibus' }).Count
if ($bindList.Count -eq 0) { $gaps += 'no_wireless_devnode' } elseif ($anyUpper -eq 0) { $gaps += 'vwifibus_not_upper_filter' }
$logSaysMissing = $false
foreach ($lg in $logs) {
  if (Test-Path -LiteralPath $lg) {
    if (@(Get-Content -LiteralPath $lg -EA SilentlyContinue | Where-Object {
            $_ -match '(?i)VWiFiBus.*not found|Needed section \[VWiFiBus' }).Count -gt 0) { $logSaysMissing = $true }
  }
}
if ($logSaysMissing) { $gaps += 'setupapi_says_vwifibus_section_missing' }
O ('P88 VERDICT files=' + $infGot + '/' + $infWant.Count + 'inf+' + $sysGot + '/' + $sysWant.Count + 'sys' +
   ' devnodes=' + $bindList.Count + ' with_vwifibus_upper=' + $anyUpper +
   ' gaps=' + $(if ($gaps.Count) { $gaps -join ',' } else { 'none' }))
if ($gaps.Count -eq 0 -and $anyUpper -eq 0) {
  O 'P88 READING: every file the host has is on this disc, yet the devnode carries no vwifibus upper filter.'
  O '         That means the filter was never WRITTEN for this device (no INF HW section ran for it, or the'
  O '         card bound through a path that does not apply Include/Needs), not that the stack is missing.'
} elseif ($gaps -join ',' -match 'setupapi_says_vwifibus_section_missing') {
  O 'P88 READING: setupapi still cannot resolve the VWiFiBus sections, so the Include= in the Intel INF never'
  O '         applied UpperFilters. The fix has to make netvwifibus.inf resolvable the way setupapi looks it up.'
} elseif ($gaps.Count -eq 0) {
  O 'P88 READING: nothing looks missing in this section -- the attachment is present, so look above the files.'
} else {
  O ('P88 READING: pieces are missing on the booted disc (' + ($gaps -join ',') + ') -- restore them before')
  O '         reading wlansvc again.'
}
O 'P88 END'
