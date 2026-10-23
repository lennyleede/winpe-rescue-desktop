# ============================================================
# test\share\probe104_vwifibus_upper.ps1 -- the last untested hook in the WiFi binding chain
#
# WHY (2026-10-12, from build\scratch\wifi_accept_1012_bind.txt on the aligned 12:10 disc):
#   probe93's netcfg ladder, run live on that disc, got the stack to
#     nativewifip:Running  wdiwifi:Running  vwififlt:Running   (wifi_filter_entries=2/2)
#   and STILL stopped there:
#     vwifibus:Stopped  vwifimp:Stopped  vwifimp_nodes=0  wlansvc=Stopped
#   The FilterList entries are what netcfg writes (ms_vwifi + ms_nativewifip) -- done.
#   The OTHER, independent hook is the vendor INF's [DDInstall.HW] Include=netvwifibus.inf
#   Needs=VWiFiBus.PnPFilterRegistration.HW, whose only visible effect is
#     Enum\<adapter devnode>\UpperFilters = vwifibus   (host: exactly this one value, class key has none --
#                                                        build\scratch\t_p105_host_upper.ps1)
#   On our disc the adapter reads Upper=[] because the offline DISM /Add-Driver of netvwifibus.inf fails
#   (vwifi_dism=3/4), so PnP never runs that hook, so no virtual-WiFi bus -> no vwifimp child -> wlansvc 1068.
#
# THIS PROBE tests exactly one thing: does hand-writing that one value + restarting the wireless devnode
# attach vwifibus (and then vwifimp), and does wlansvc finally start? If yes, the fix is a 3-line step in the
# PE boot path (netdrvfix, after the miniport is bound), and it is hardware-agnostic.
#
# SAFETY: read-only unless -Apply. With -Apply it writes ONE value on ONE device-instance key (the wireless
# adapter, matched by driver service) and restarts THAT devnode only -- never the wired adapter carrying ssh.
# Everything lives on the X: RAMDISK; a reboot restores it. Nothing is written to the ISO or to any disk.
# ============================================================
param([switch]$Apply, [string]$Only = '')
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Clean([string]$s) { (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'
$PNPU = 'X:\Windows\System32\pnputil.exe'
if (-not (Test-Path -LiteralPath $PNPU)) { $PNPU = 'pnputil.exe' }

function WlanNodes {
  $devs = @(); $vi = 0
  foreach ($bus in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
    foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
      foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
        $svc = "$($ip.Service)"
        if ($svc -match '(?i)^vwifimp$') { $vi++; continue }
        if ($svc -notmatch $WLAN_SVC) { continue }
        $devs += @{ id = ($bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName)
                    ps = $inst.PSPath; svc = $svc
                    up = (@($ip.UpperFilters) -join ';'); drv = ("$($ip.Driver)") }
      }
    }
  }
  return @{ devs = $devs; vwifimp = $vi }
}
function StackLine {
  $p = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp', 'Ndisuio', 'wcmsvc', 'wlansvc')) {
    $p += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return ($p -join ',')
}
function PrintStack([string]$tag, $sh) {
  # NOTE: this must NOT also return the shape. A PowerShell function's Write-Output lines are part of its return
  # stream, so "$x = Report ..." used to swallow every printed line into $x (the read-only dry-run above lost its
  # BOOT lines that way). Print here, return nothing; callers keep the shape they already asked WlanNodes for.
  O ('  P104 ' + $tag + ' ' + (StackLine))
  O ('    P104 ' + $tag + ' vwifimp_nodes=' + $sh.vwifimp + ' wlan=' + @($sh.devs).Count)
  foreach ($d in @($sh.devs)) { O ('    P104 ' + $tag + ' DEV ' + $d.id + ' svc=' + $d.svc + ' Upper=[' + $d.up + ']') }
}

O ('P104 START apply=' + $Apply.IsPresent + ' only=[' + $Only + ']')
$sh0 = WlanNodes
PrintStack 'BOOT' $sh0
$sys32 = 'X:\Windows\System32'
foreach ($f in @('drivers\vwifibus.sys', 'drivers\vwifimp.sys', 'drivers\vwififlt.sys', 'drivers\nwifi.sys')) {
  $p = Join-Path $sys32 $f
  O ('  P104 FILE ' + $f + ' exists=' + (Test-Path -LiteralPath $p) + ' bytes=' +
     $(if (Test-Path -LiteralPath $p) { (Get-Item -LiteralPath $p).Length } else { '-' }))
}
if (-not $Apply) {
  O '  P104 PLAN (read-only): for every wireless devnode set UpperFilters=vwifibus (REG_MULTI_SZ), then'
  O '         pnputil /restart-device <that devnode>, sleep, re-read the stack, then Start-Service wlansvc.'
  O ('P104 VERDICT outcome=read-only vwifimp_nodes=' + $sh0.vwifimp + ' upper0=[' +
     ((@($sh0.devs) | ForEach-Object { $_.up }) -join '|') + ']')
  return
}

O '== 1 write the one value the vendor .HW hook would have written =='
foreach ($d in @($sh0.devs)) {
  if ($Only -ne '' -and $d.id -notmatch $Only) { O ('  P104 SKIP ' + $d.id); continue }
  $cur = @()
  $ip = Get-ItemProperty -LiteralPath $d.ps -EA SilentlyContinue
  if ($ip) { $cur = @($ip.PSObject.Properties['UpperFilters'].Value) }
  $want = @('vwifibus')
  foreach ($e in @($cur)) { if (("$e") -and ($want -notcontains "$e")) { $want += "$e" } }
  New-ItemProperty -LiteralPath $d.ps -Name 'UpperFilters' -Value $want -PropertyType MultiString -Force | Out-Null
  $after = (@((Get-ItemProperty -LiteralPath $d.ps -EA SilentlyContinue).UpperFilters) -join ';')
  O ('  P104 WRITE ' + $d.id + ' was=[' + (Clean ($cur -join ';')) + '] now=[' + (Clean $after) + ']')
}

O '== 2 rebind the devnode so PnP re-runs the filter attach =='
$sh1 = WlanNodes
foreach ($d in @($sh1.devs)) {
  $o = @(& $PNPU '/restart-device' $d.id 2>&1 | ForEach-Object { Clean "$_" })
  O ('  P104 PNP restart ' + $d.id + ' rc=' + $LASTEXITCODE + ' lines=' + $o.Count)
  foreach ($l in @($o | Select-Object -First 3)) { O ('    | ' + $l) }
}
Start-Sleep -Seconds 10
$sh2 = WlanNodes
PrintStack 'AFTER' $sh2

O '== 3 does wlansvc start now? =='
$w = (Get-Service -Name wlansvc -EA SilentlyContinue)
O ('  P104 WLANSVC before=' + "$($w.Status)")
try { Start-Service -Name wlansvc -EA Stop; O '  P104 START-OK' }
catch { O ('  P104 START-FAIL ' + (Clean $_.Exception.Message)) }
Start-Sleep -Seconds 5
$ns = @(& net.exe start wlansvc 2>&1 | ForEach-Object { Clean "$_" })
O ('  P104 NET-START rc=' + $LASTEXITCODE + ' lines=' + $ns.Count)
foreach ($l in @($ns | Select-Object -First 6)) { O ('    | ' + $l) }
$sh3 = WlanNodes
PrintStack 'WLAN' $sh3
$nt = @(& netsh.exe wlan show interfaces 2>&1 | ForEach-Object { Clean "$_" })
O ('  P104 NETSH rc=' + $LASTEXITCODE + ' lines=' + $nt.Count)
foreach ($l in @($nt | Select-Object -First 6)) { O ('    | ' + $l) }

$busUp = (("$((Get-Service -Name vwifibus -EA SilentlyContinue).Status)") -eq 'Running')
$impUp = ($sh3.vwifimp -gt 0)
$wlUp  = (("$((Get-Service -Name wlansvc -EA SilentlyContinue).Status)") -eq 'Running')
$outcome = 'no-progress'
if ($wlUp -and $impUp) { $outcome = 'wlansvc-running-with-vwifimp' }
elseif ($wlUp)         { $outcome = 'wlansvc-running-no-vwifimp' }
elseif ($busUp)        { $outcome = 'vwifibus-running-wlansvc-stopped' }
elseif ($impUp)        { $outcome = 'vwifimp-children-no-bus' }
O ('P104 VERDICT outcome=' + $outcome + ' vwifibus=' +
   ("$((Get-Service -Name vwifibus -EA SilentlyContinue).Status)") + ' vwififlt=' +
   ("$((Get-Service -Name vwififlt -EA SilentlyContinue).Status)") + ' nativewifip=' +
   ("$((Get-Service -Name nativewifip -EA SilentlyContinue).Status)") + ' vwifimp_nodes=' + $sh3.vwifimp +
   ' wlansvc=' + ("$((Get-Service -Name wlansvc -EA SilentlyContinue).Status)") +
   ' upper_final=[' + ((@($sh3.devs) | ForEach-Object { $_.up }) -join '|') + ']')
if ($wlUp) {
  O 'P104 READING: THIS IS THE FIX -- write UpperFilters=vwifibus on the wireless devnode after the miniport is'
  O '         bound, restart that devnode, then start wlansvc. Put those three steps in the PE boot path (netdrvfix).'
} elseif ($busUp) {
  O 'P104 READING: vwifibus attached but wlansvc still not up -- read P104 WLAN stack line and NET-START text above'
  O '         for which dependency is still not Running.'
} else {
  O 'P104 READING: writing the value did not attach the bus. Check P104 WRITE above (value really landed) and the'
  O '         P104 PNP restart rc. If the write landed and the restart rc=0 but vwifibus is still Stopped, the'
  O '         problem is the vwifibus package itself (DISM refused netvwifibus.inf offline), not the binding.'
}
