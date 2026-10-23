# probe89 -- attach vwifibus to the wireless miniport IN THE LIVE PE, and measure what it takes.
# THIS SCRIPT MUTATES THE RUNNING PE: it writes one registry value (UpperFilters on the WIRELESS devnode only)
# and calls pnputil /add-driver, /restart-device, /remove-device, /scan-devices. Everything lives on the RAMDISK
# (X:), so a reboot restores the disc state; it never touches the ISO, the customer's disks, the host, or the
# wired adapter this session is connected through (the devnode filter below is a WLAN-only whitelist).
#
# Why a mutation probe is justified now (probe88, build\scratch\p88_pe_run.txt):
#   - every file the working host has is on this disc: netvwifibus/netvwififlt/netvwifimp/netnwifi .inf in
#     X:\windows\INF (4/4) and vwifibus/vwififlt/vwifimp/nwifi/wdiwifi/NdisImPlatform .sys (6/6);
#   - the store package dir matches the host in shape (netvwifibus.inf_amd64_f52d5ad58116f6f0 holds one INF file,
#     and the HOST's own copy is also INF-only) -- so "half-staged package" is not the difference either;
#   - the card is bound and clean: PCI\VEN_8086&DEV_7A70... svc=Netwtw14, no Problem code, class key
#     {4d36e972...}\0001 InfPath=oem161.inf -> the netwtw6e package INF carries 114 VWiFiBus refs, 57 Include
#     lines and 19 [VWiFiBus.PnPFilterRegistration*] uses;
#   - yet setupapi, while configuring that very package, logs
#         inf:  Included INFs = netvwifibus.inf
#         inf:  Needed section [VWiFiBus.CopyFiles] not found, might exist in missing included INF.
#         inf:  Needed section [VWiFiBus] not found ...
#         inf:  Needed section [VWiFiBus.PnPFilterRegistration] not found ...
#     i.e. it sees the directive and still cannot open the file. Consequence: UpperFilters=vwifibus is never
#     written -> no vwifibus bus -> no native WiFi interface object -> wlansvc returns 0x800C0006 (probe86).
#
# The earlier "runtime patching is useless" conclusion (#22, 2026-10-10) was measured while the card was code 37,
# wdiwifi was absent, and the hand-written vwifibus service key was invisible to OpenServiceW (1060). Those
# preconditions are gone on the aligned disc, so the experiment has to be re-run instead of inherited.
#
# Ladder (each step is re-measured; B only runs if A did not attach, C only if children are still missing):
#   A  pnputil /add-driver X:\windows\INF\netvwifibus.inf (runtime store import) -> restart the device. If this
#      attaches, the durable fix is to get the offline image to do the same import and nothing hand-written ships.
#   B  write UpperFilters=vwifibus exactly like [VWiFiBus.PnPFilterRegistration.HW] would (HKR,,"UpperFilters",
#      0x00010000,"vwifibus") -> /restart-device.
#   C  keep the written value and force a fresh install from the store: /remove-device + /scan-devices.
param([switch]$IDoit)
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
$SR   = Root ''
if (($SR -notmatch '(?i)^X:') -and -not $IDoit) {
  Write-Output ('P89 REFUSE: SystemRoot is ' + $SR + ', not a RAMDISK PE boot. This probe restarts and may')
  Write-Output '        reinstall the wireless adapter, which on a working machine is not a harmless read.'
  Write-Output '        Re-run with -IDoit only if you really mean to mutate this OS instance.'
  Write-Output 'P89 END'
  return
}
$PNPU = Join-Path (Join-Path $SR 'System32') 'pnputil.exe'
$REGX = Join-Path (Join-Path $SR 'System32') 'reg.exe'
$ENUM = 'HKLM\SYSTEM\CurrentControlSet\Enum'
$ENUMPS = 'HKLM:\SYSTEM\CurrentControlSet\Enum'

# WLAN vendor services only. Deliberately narrow: writing UpperFilters on the Realtek 2.5GbE devnode would put
# this rescue session's own network path at risk, and that adapter is not what WDI needs.
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|rtwlane\d*|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'

function Shape {
  $devs = @(); $vi = 0
  foreach ($bus in @(Get-ChildItem ("Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum") -EA SilentlyContinue)) {
    foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
      foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
        $svc = "$($ip.Service)"
        if ($svc -match '(?i)^vwifimp$') { $vi++; continue }
        if ($svc -notmatch $WLAN_SVC) { continue }
        $id = $bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName
        $devs += @{ id = $id; reg = ($ENUM + '\' + $id); ps = ($ENUMPS + '\' + $id);
                   svc = $svc; up = (@($ip.UpperFilters) -join ','); prob = ("$($ip.Problem)") }
      }
    }
  }
  return @{ devs = $devs; vwifimp = $vi }
}
function Report([string]$tag) {
  $sh = Shape
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  O ('  P89 SHAPE after=' + $tag + ' vwifimp_nodes=' + $sh.vwifimp + ' stack=[' + ($states -join ',') +
     '] wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status))
  foreach ($d in $sh.devs) {
    O ('    P89 DEV ' + $d.id + ' svc=' + $d.svc + ' Upper=[' + $d.up + '] problem=' +
       $(if ($d.prob -eq '') { '-' } else { $d.prob }))
  }
  $script:Last = $sh
}
function Attached { return @(@($script:Last.devs) | Where-Object { $_.up -match 'vwifibus' }).Count }
function RunPnp([string[]]$a, [string]$label) {
  if (-not (Test-Path -LiteralPath $PNPU)) { O ('  P89 PNP ' + $label + ' -> pnputil ABSENT at ' + $PNPU); return }
  $o = @(& $PNPU @a 2>&1 | ForEach-Object { "$_" })
  O ('  P89 PNP ' + $label + ' rc=' + $LASTEXITCODE + ' lines=' + $o.Count +
     ' args=' + (($a | ForEach-Object { ($_ -replace '[^\x20-\x7E]', '?') }) -join ' '))
  foreach ($l in @($o | Where-Object { $_ -match '(?i)package|device|error|cannot|installed|restart|remov|driver' } |
                   Select-Object -First 6)) {
    O ('    | ' + ((($l -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim()))
  }
}

O ('P89 START root=' + $SR + ' pnputil=' + $(if (Test-Path -LiteralPath $PNPU) { 'yes' } else { 'NO' }) +
   ' reg=' + $(if (Test-Path -LiteralPath $REGX) { 'yes' } else { 'NO' }))
Report 'baseline'
if (@($script:Last.devs).Count -eq 0) {
  O ('P89 VERDICT outcome=no_wireless_devnode vwifimp_nodes=' + $script:Last.vwifimp)
  O 'P89 END -- there is nothing to attach WDI to; fix the driver binding (netdrvfix / pool) first.'
  return
}
$target = @($script:Last.devs)[0]

O '== 1 attempt A: import netvwifibus.inf into the store at runtime, then restart the device =='
$ni = Join-Path $SR 'INF\netvwifibus.inf'
O ('  P89 ADDDRV ' + $ni + ' exists=' + (Test-Path -LiteralPath $ni))
RunPnp @('/add-driver', $ni) 'add-driver'
RunPnp @('/add-driver', $ni, '/install') 'add-driver-install'
Start-Sleep -Seconds 2
RunPnp @('/restart-device', $target.id) 'restart-after-A'
Start-Sleep -Seconds 5
Report 'A'
$attached = Attached
O ('  P89 AFTER-A attached=' + $attached + '/' + @($script:Last.devs).Count)

O '== 2 attempt B: write UpperFilters=vwifibus on the wireless devnode, then restart =='
if ($attached -eq 0) {
  foreach ($d in @($script:Last.devs)) {
    $o = @(& $REGX 'add' $d.reg '/v' 'UpperFilters' '/t' 'REG_MULTI_SZ' '/d' 'vwifibus' '/f' 2>&1 |
           ForEach-Object { "$_" })
    O ('  P89 REGADD ' + $d.id + ' rc=' + $LASTEXITCODE + ' out=' + (($o | Select-Object -First 2) -join ' / '))
    $back = (@(RegV $d.ps 'UpperFilters') -join ',')
    O ('    P89 REGREAD ' + $d.id + ' Upper=[' + $back + ']')
  }
  Start-Sleep -Seconds 1
  RunPnp @('/restart-device', $target.id) 'restart-after-B'
  Start-Sleep -Seconds 6
  Report 'B'
  $attached = Attached
  O ('  P89 AFTER-B attached=' + $attached + '/' + @($script:Last.devs).Count + ' vwifimp_nodes=' + $script:Last.vwifimp)
} else { O '  P89 SKIP B (A already attached the filter)' }

O '== 3 attempt C: keep the value and force a fresh install from the store =='
if ($attached -gt 0 -and $script:Last.vwifimp -eq 0) {
  RunPnp @('/remove-device', $target.id) 'remove'
  Start-Sleep -Seconds 2
  RunPnp @('/scan-devices') 'scan'
  Start-Sleep -Seconds 8
  Report 'C'
  $attached = Attached
} else {
  O ('  P89 SKIP C (attached=' + $attached + ' vwifimp_nodes=' + $script:Last.vwifimp +
     '; C only makes sense once the filter is on but children are missing)')
}

O '== 4 endpoint: is there a native WiFi object now, and does wlansvc survive =='
Report 'final'
$withUp = Attached
$final  = $script:Last
try {
  $svc = Get-Service -Name wlansvc -EA Stop
  if ("$($svc.Status)" -ne 'Running') { Start-Service -Name wlansvc -EA Stop; Start-Sleep -Seconds 3 }
  O ('  P89 WLANSVC -> ' + (Get-Service -Name wlansvc -EA SilentlyContinue).Status)
} catch { O ('  P89 WLANSVC start attempt failed: ' + $_.Exception.Message) }
$nas  = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)
$wifi = @($nas | Where-Object { "$($_.Name)$($_.Description)$($_.ServiceName)" -match '(?i)wireless|wi-fi|wifi|wlan|netwtw|netwaw|rtwlane' })
O ('  P89 ADAPTERS total=' + $nas.Count + ' wifi_or_wfd=' + $wifi.Count)
foreach ($a in $wifi) { O ('    P89 NAPA ' + $a.Name + ' svc=' + $a.ServiceName + ' physical=' + $a.PhysicalAdapter + ' netenabled=' + $a.NetEnabled) }

O '== 5 verdict =='
$running = @(@('nativewifip', 'vwifibus', 'vwififlt', 'vwifimp') | Where-Object {
               "$((Get-Service -Name $_ -EA SilentlyContinue).Status)" -eq 'Running' }).Count
$outcome = 'device-gone'
if (@($final.devs).Count -gt 0) {
  if ($withUp -gt 0 -and $final.vwifimp -gt 0) { $outcome = 'attached+vwifimp-children' }
  elseif ($withUp -gt 0) { $outcome = 'filter-present-but-no-children' }
  else { $outcome = 'still-not-attached' }
}
O ('P89 VERDICT outcome=' + $outcome + ' upper=' + $withUp + '/' + @($final.devs).Count +
   ' vwifimp_nodes=' + $final.vwifimp + ' stack_running=' + $running + '/4')
if ($outcome -eq 'attached+vwifimp-children') {
  O 'P89 READING: WDI attached at runtime and the virtual adapters exist. Re-run probe86 and probe42 on this same'
  O '         boot: if wlansvc now stays up, the fix is a boot-time step in netdrvfix (write the filter for every'
  O '         bound WLAN devnode + restart it), and the setupapi Include problem stops blocking us.'
} elseif ($outcome -eq 'filter-present-but-no-children') {
  O 'P89 READING: the filter value survives and PnP sees it, but no vwifimp child appeared -- read the stack=[] '
  O '         line: whichever of vwifibus/nativewifip/vwififlt is still Stopped is the object that failed to load,'
  O '         and that is a driver-signature/N-dis binding question, not a registry-shape question.'
} else {
  O ('P89 READING: runtime patching still does not attach WDI (' + $outcome + ') on a disc where the whole stack is')
  O '         present. That reinstates conclusion #22 with valid preconditions, and the fix must go back to install'
  O '         time: make netvwifibus.inf resolvable so the vendor INF writes the filter itself.'
}
O 'P89 END'
