# probe95 -- the last two candidate objects wlansvc needs and this PE may not have: the WDI user-mode host
# (WdiServiceHost + the vendor IntelIHVRouter DLL) and the Base Filtering Engine (BFE).
#
# Where probe94 left it (build\scratch\p94_apply_1011.txt, this very box, 2026-10-11 13:31):
#   every runtime-visible fix was applied and wlansvc still returned the same code:
#     P94 RUN ndisuio start-> rc=0 StartService OK      -> Ndisuio Running, \\.\Ndisuio OPEN-OK
#     P94 RUN params-subkeys / datastore / software-keys / netsh-wlancfg / wcmsvc / restart-wifi-dev  (all rc=0)
#     P94 VERDICT outcome=ndisuio-running-wlansvc-still-returns-error wlansvc=Stopped interfaces=0
#                                                       exit=2148270086(0x800C0006)
#   So the driver stack (nativewifip/wdiwifi/vwifibus/vwififlt/NSI/Ndisuio) is fully up and wlansvc's own registry
#   shape, data store and SOFTWARE trees match the host, and WlanSvcMain still bails out during its own init.
#
# What is STILL different from the working host, and why it is the right thing to chase next:
#   _host_wlan_ref3.txt / _host_wifi_ref.txt / _host_wdi_ref.txt (host, all running):
#     WdiServiceHost Type=32 Start=3 'NT AUTHORITY\LocalService' svchost -k LocalService
#                    Parameters ServiceDll=%SystemRoot%\system32\wdi.dll ServiceMain=ServiceMain state=RUNNING(4)
#     WdiSystemHost  ... same shape, also RUNNING on the host.
#     PE (p94_ro_1011.txt): `SVC WdiServiceHost <key absent>`, `FAIL OpenService(WdiServiceHost): 1060`.
#   The adapter's WDI/IHV hookup itself is NOT the gap -- probe64 already dumped both sides (build\scratch\p64_raw.txt):
#     <PEN1> KEY IHVExtensions  ExtensibilityDLL = X:\windows\System32\DriverStore\FileRepository\
#                                 netwtw6e.inf_amd64_c3785d6f1e6d5b0e\IntelIHVRouter14.dll
#     <OFFN2> the identical row in the offline image => the INF's [Reg_IHV_Router_14] did run.
#     (overlay\Drivers\Wlan\Wlan_Intel_23x_20240310\Netwtw6e.INF line 1062:
#        HKR,Ndi\IHVExtensions, ExtensibilityDLL, 0, "%13%\IntelIHVRouter14.dll")
#   On a WDI adapter the WiFi interface object is produced by the vendor handler INSIDE WdiServiceHost, so if the
#   service host cannot exist, the object wlansvc is looking for cannot exist either.
#
# But 0x800C0006 is also in the FWP_E_* range (Windows Filtering Platform), and wlansvc opens an FWP engine session
# for the hosted-network/firewall hookup during init. WinPE ships no BFE by default, and NOTHING this session checked
# whether BFE exists on this disc (grep of every PE log under build\scratch finds no bfe/mpssvc row at all).
# If wlansvc's own init calls FwpmEngineOpen0 against a stopped BFE, it bails exactly the way we see.
#
# Why this probe can answer the BFE half and only narrow the WDI half: services.exe builds its service database when
# it starts, so a service key CREATED after boot is invisible (OpenService 1060 -- the vwifibus lesson, and exactly
# why WdiServiceHost can only be proven after an offline bake). Starting a service that is ALREADY baked, and
# disabling/enabling a devnode, are live operations. So:
#   * BFE: if the key exists on this disc, start it and retry wlansvc -- answered on this boot, no rebuild.
#   * WDI: two live substitutes -- (a) can the vendor handler DLL even LoadLibrary in PE (a missing import there is
#     an offline-fixable file gap, not a service gap), and (b) with the WLAN devnode DISABLED (no WDI adapter at all)
#     does wlansvc start cleanly? If yes, the failure is adapter/WDI-driven; if it still returns 0x800C0006 with zero
#     WiFi adapters, the failure is inside the service's own environment and WdiServiceHost is not the cause.
#
# Sections: 1 every service + DLL wlansvc talks to, existence and state; 2 the svchost group registrations;
# 3 the WDI/IHV hookup on this machine's WLAN adapter + the vendor handler DLL (loadability);
# 4 baseline wifi.exe status + wlansvc start timeline; 5 with -Apply the ladder
#   ensure-drivers / bfe / mpssvc / netsh-wlancfg / disable-adapter / enable-adapter; 6 verdict + BAKE-ITEMS.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit overrides
# that guard deliberately. Only network services that already exist get started; the WLAN devnode is disabled and put
# back inside the same rung sequence (the wired Realtek adapter carrying this ssh session is never touched). No
# customer disk, no ISO, no D:\winpe_build is written. Everything lives on the RAMDISK: rebooting restores the disc.
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
function SubNames([string]$path) {
  @(@(Get-ChildItem -LiteralPath $path -EA SilentlyContinue).PSChildName | ForEach-Object { Clean $_ })
}
function ValNames([string]$path) {
  $ip = Get-ItemProperty -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $ip) { return @() }
  @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Clean $_.Name })
}
# One line per service row, worded exactly like the host dumps so the two are diffable by eye.
function SvcRow([string]$s) {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  if (-not (Test-Path -LiteralPath $p)) { return ('SVC ' + $s + ' <key absent>') }
  $dll = [string](RegV ($p + '\Parameters') 'ServiceDll')
  $main = [string](RegV ($p + '\Parameters') 'ServiceMain')
  $img = [string](RegV $p 'ImagePath')
  $st = (Get-Service -Name $s -EA SilentlyContinue).Status
  return ('SVC ' + $s + ' Start=' + (HexVal (RegV $p 'Start')) + ' Type=' + (HexVal (RegV $p 'Type')) +
    ' Group=[' + (RegV $p 'Group') + '] Obj=[' + (RegV $p 'ObjectName') + ']' +
    ' Depend=[' + (@(RegV $p 'DependOnService') -join ';') + ']' +
    ' SidType=' + (HexVal (RegV $p 'ServiceSidType')) + ' Priv=' + (@(RegV $p 'RequiredPrivileges') -join ';') +
    ' State=' + $st + ' Image=[' + (Clean $img) + '] Dll=[' + (Clean $dll) + '] Main=[' + $main + ']' +
    ' subs=' + ((SubNames $p) -join ','))
}
# does the SCM itself know this service (OpenService), i.e. is it in the boot-time database?
function Wifi([object[]]$argv) {
  $r = Run $WIFI @($argv)
  return ('rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
}
function StackLine {
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp', 'Ndisuio', 'NSI')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return (@($states -join ',') + ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
         ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status))
}
function NdisuioOpen {
  $dev = '\\.\Ndisuio'
  $h = $null
  try {
    $h = [System.IO.File]::Open($dev, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite,
                                [System.IO.FileShare]::None)
    $r = ('OPEN-OK ' + $dev)
    return $r
  } catch {
    $m = Clean $_.Exception.Message
    if ($m.Length -gt 70) { $m = $m.Substring(0, 70) }
    return ('OPEN-FAIL ' + $dev + ' ' + $m)
  } finally { if ($h) { try { $h.Dispose() } catch { } } }
  return 'OPEN-FAIL \\.\Ndisuio <not attempted>'
}
# the one measurement this probe exists for: does WlanSvcMain still bail, and with what code?
# NOTE: everything this function emits goes through O/Write-Output, so the CALLER MUST NOT assign the result
# to a variable -- ` $x = TryWlan 'tag' ` would swallow every log line into $x and the log would show nothing
# (exactly what happened in the first -Apply run). Call it bare and read $script:WRun / $script:WIfn afterwards.
$script:WRun = $false
$script:WIfn = -1
function TryWlan([string]$tag) {
  $s = Run $WIFI @('svc', 'start', 'wlansvc')
  $i = Wifi @('svc', 'info', 'wlansvc')
  $w = Run $WIFI @('svc', 'watch', 'wlansvc', '3000', 'start')
  $st = Wifi @('status')
  $row = SvcRow 'wlansvc'
  O ('  P95 TRY[' + $tag + '] start-> rc=' + $s.rc + ' ' + (@($s.lines) -join ' // '))
  O ('  P95 TRY[' + $tag + '] info  ' + $i)
  foreach ($l in @($w.lines | Select-Object -First 12)) { O ('    | ' + $l) }
  O ('  P95 TRY[' + $tag + '] row   ' + $row)
  O ('  P95 TRY[' + $tag + '] wifi  ' + $st)
  $script:WRun = ($i -match '(?i)state=RUNNING\(4\)|state=Running')
  $script:WIfn = -1
  if ($st -match 'interfaces=(\d+)') { $script:WIfn = [int]$Matches[1] }
}
# WLAN devnodes: id (for pnputil), driver service, and the PnP problem code.
function Shape {
  $devs = @()
  foreach ($bus in @(Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
    foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
      foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
        $svc = "$($ip.Service)"
        if ($svc -notmatch $WLAN_SVC) { continue }
        $devs += @{ id = ($bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName);
                    ps = ('HKLM:\SYSTEM\CurrentControlSet\Enum\' + $bus.PSChildName + '\' + $prov.PSChildName +
                          '\' + $inst.PSChildName);
                    svc = $svc; prob = [int]$ip.Problem; cfg = [int]$ip.ConfigFlags; drv = ("$($ip.Driver)") }
      }
    }
  }
  return @{ devs = $devs }
}
function Expand-P([string]$v) {
  if ($v -eq '') { return '' }
  $s = $v -replace '(?i)%systemroot%', $SR
  $s = $s -replace '(?i)%13%', (Join-Path $S32 'DriverStore\FileRepository')
  return $s
}

$SR     = Root ''
$S32    = Join-Path $SR 'System32'
$INFDIR = Join-Path $SR 'INF'
$REGX   = Join-Path $S32 'reg.exe'
$NET    = Join-Path $S32 'net.exe'
$PNPU   = Join-Path $S32 'pnputil.exe'
$NSH    = Join-Path $S32 'netsh.exe'
$WIFI   = Join-Path $S32 'wifi.exe'
$NCFG   = Join-Path $S32 'netcfg.exe'
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'
$SVCREOT  = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$DRVSTORE = Join-Path $S32 'DriverStore\FileRepository'
$CLSNET   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class'   # + the devnode Driver value, which is {4d36e972-...}\00NN
# the service objects wlansvc touches, in one list: WiFi stack + the two WDI hosts + the FWP/RPC/WMI plumbing.
$SVC_SET = @('wlansvc', 'wcmsvc', 'WdiServiceHost', 'WdiSystemHost', 'BFE', 'mpssvc', 'RpcSs', 'DcomLaunch',
             'EventLog', 'Winmgmt', 'NSI', 'Ndisuio', 'nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp',
             'netprofm', 'nlasvc', 'KeyIso', 'Schedule', 'gpsvc', 'RasMan', 'dot3svc', 'TermService')
$DLL_SET = @('wdi.dll', 'bfe.dll', 'fwpkcim.mpdll', 'mpssvc.dll', 'fwpuclnt.dll', 'BFECore', 'wlanutil.dll',
             'wlansvc.dll', 'wlanapi.dll', 'wlanext.exe', 'dot3cfg.dll', 'wlancfg.dll', 'ndisimplatform_uimonitor.dll')

O ('P95 START root=' + $SR + ' apply=' + $Apply.IsPresent + ' only=[' + $Only + '] drive=' + $env:SystemDrive)
O ('  P95 STACK ' + (StackLine))
O ('  P95 NDISUIO-DEVICE ' + (NdisuioOpen))
$sh = Shape
foreach ($d in @($sh.devs)) {
  O ('  P95 DEV ' + $d.id + ' svc=' + $d.svc + ' problem=' + $d.prob + ' cfgflags=' + $d.cfg + ' drv=' + $d.drv)
}

O '== 1 every service wlansvc talks to: does the key exist, and can the SCM open it =='
foreach ($s in @($SVC_SET)) {
  if ($Only -ne '' -and $Only -notlike ('*' + $s + '*')) { continue }
  O ('  P95 ROW ' + (SvcRow $s))
  O ('  P95 SCM ' + $s + ' -> ' + (Wifi @('svc', 'info', $s)))
}
O '== 1b the DLLs behind them (a missing file is an offline bake gap, not a theory) =='
foreach ($t in @($DLL_SET)) {
  $p = Join-Path $S32 $t
  $ex = (Test-Path -LiteralPath $p)
  $sz = ''
  if ($ex) { $sz = ' bytes=' + ((Get-Item -LiteralPath $p -EA SilentlyContinue).Length) }
  O ('  P95 DLL ' + $t + ' exists=' + $ex + $sz + ' version=' + (FV $p))
}

O '== 2 svchost group registration: which group strings exist and whether wlansvc/wcmsvc are inside them =='
$SVCH = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost'
O ('  P95 SVCHOST-KEY present=' + (Test-Path -LiteralPath $SVCH) + ' values=' + ((ValNames $SVCH) -join ','))
foreach ($g in @('LocalService', 'NetworkService', 'LocalSystemNetworkRestricted', 'LocalServiceNetworkRestricted',
                 'netsvcs', 'bfe', 'rpcgrp', 'WdiServiceHost')) {
  $v = @(RegV $SVCH $g)
  $has = ''
  if (@($v).Count -gt 0) {
    $has = ' wlansvc=' + (@(@($v) | Where-Object { "$_" -match '(?i)^wlansvc$' }).Count -gt 0) +
            ' wcmsvc=' + (@(@($v) | Where-Object { "$_" -match '(?i)^wcmsvc$' }).Count -gt 0) +
            ' bfe=' + (@(@($v) | Where-Object { "$_" -match '(?i)^bfe$' }).Count -gt 0) +
            ' wdi=' + (@(@($v) | Where-Object { "$_" -match '(?i)wdiservicehost' }).Count -gt 0)
  }
  O ('  P95 GROUP ' + $g + ' count=' + @($v).Count + $has)
}

O '== 3 the WDI/IHV hookup on THIS adapter, and whether the vendor handler can load =='
foreach ($d in @($sh.devs)) {
  if ($d.drv -eq '') { O ('  P95 CLS ' + $d.id + ' has no Driver value'); continue }
  $ck = Join-Path $CLSNET $d.drv
  if (-not (Test-Path -LiteralPath $ck)) { O ('  P95 CLS ' + $d.drv + ' <class instance absent>'); continue }
  O ('  P95 CLS ' + $d.id + ' class=' + $d.drv + ' values=' + ((ValNames $ck) -join ',') +
     ' subs=' + ((SubNames $ck) -join ','))
  $ihv = Join-Path $ck 'Ndi\IHVExtensions'
  $dll = [string](RegV $ihv 'ExtensibilityDLL')
  O ('  P95 IHV-REG key=' + (Test-Path -LiteralPath $ihv) + ' ExtensibilityDLL=[' + (Clean $dll) + ']')
  $exp = Expand-P $dll
  if ($exp -ne '') {
    O ('  P95 IHV-FILE expanded=' + (Clean $exp) + ' exists=' + (Test-Path -LiteralPath $exp) +
       ' bytes=' + ((Get-Item -LiteralPath $exp -EA SilentlyContinue).Length))
    $r = Run $WIFI @('dllload', $exp, 'DllGetClassObject')
    O ('  P95 IHV-LOAD rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
  }
  $ndi = Join-Path $ck 'Ndi'
  O ('  P95 NDI subs=' + ((SubNames $ndi) -join ',') + ' Service=' + (RegV $ndi 'Service'))
  $ii = Join-Path $ndi 'Interfaces'
  O ('  P95 NDI-IF Upper=' + (RegV $ii 'UpperRange') + ' Lower=' + (RegV $ii 'LowerRange'))
  foreach ($vn in @('*WdiRscIPv4', '*WdiRscIPv6', '*RscIPv4', '*RscIPv6', '*IhvFastRoaming', '*Wi-FiDirect')) {
    O ('  P95 WDI-VAL ' + $vn + ' = ' + (HexVal (RegV $ck $vn)))
  }
}
O ('  P95 DRVSTORE-WLAN packages=' + (@(Get-ChildItem -LiteralPath $DRVSTORE -Directory -EA SilentlyContinue |
     Where-Object { $_.PSChildName -match '(?i)^net(wtw|waw|nwifi|vwifi)' }).Count))
foreach ($pk in @(Get-ChildItem -LiteralPath $DRVSTORE -Directory -EA SilentlyContinue |
                  Where-Object { $_.PSChildName -match '(?i)^net(wtw|waw)' })) {
  $files = @(Get-ChildItem -LiteralPath $pk.FullName -File -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
  O ('  P95 PKG ' + $pk.PSChildName + ' files=[' + ($files -join ',') + ']')
}
O ('  P95 WDI-DLL ' + (Wifi @('dllload', (Join-Path $S32 'wdi.dll'), 'ServiceMain')))

O '== 3b version skew: every WiFi user-mode DLL and WiFi driver on this disc, with its build =='
# The WiFi user-mode files were borrowed (ADK ships no WinPE WiFi package). If the borrowed wlansvc.dll is a
# different Windows build than the NDIS/nwifi/wdi pieces it talks to, that is a candidate for exactly this kind
# of "my counterpart does not exist" self-exit -- so record the builds, and every alternate copy on the disc.
foreach ($t in @('wlansvc.dll', 'wlanapi.dll', 'wlanutil.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll',
                 'wlanext.exe', 'wlancfg.dll', 'wdi.dll', 'bfe.dll', 'fwpuclnt.dll', 'wcmsvc.dll',
                 'drivers\nwifi.sys', 'drivers\ndisuio.sys', 'drivers\wdiwifi.sys', 'drivers\NdisImPlatform.sys',
                 'drivers\vwififlt.sys', 'drivers\vwifimp.sys', 'drivers\vwifibus.sys')) {
  $p = Join-Path $S32 $t
  O ('  P95 VER ' + $t + ' exists=' + (Test-Path -LiteralPath $p) + ' version=' + (FV $p) +
     ' bytes=' + ((Get-Item -LiteralPath $p -EA SilentlyContinue).Length))
}
$found = @()
try {
  $found = @(Get-ChildItem -LiteralPath $SR -Recurse -File -EA SilentlyContinue |
             Where-Object { $_.PSChildName -match '(?i)^(wlansvc|wlanapi|wlanutil|wdi)\.(dll|exe)$' } |
             Select-Object -First 24)
} catch { O ('  P95 SCAN-ERR ' + (Clean $_.Exception.Message)) }
foreach ($f in @($found)) {
  O ('  P95 COPY ' + (Clean $f.FullName) + ' bytes=' + $f.Length + ' version=' + (FV $f.FullName))
}

O '== 4 baseline: what wlansvc does with nothing touched =='
O ('  P95 DEPS-WLANSCV ' + (Wifi @('deps', 'wlansvc')))
TryWlan 'baseline'
$baseRun = $script:WRun

if (-not $Apply) {
  O ''
  O '  P95 read-only pass only. Re-run with -Apply to walk the ladder (BFE, mpssvc, netsh wlancfg,'
  O '  the probe93 driver-ensure recipe, and the disable/enable-adapter experiment).'
} else {
  $isRam = ($SR -match '(?i)^X:')
  if (-not $isRam -and -not $IDoit) {
    O ('  P95 REFUSING to mutate: SystemRoot=' + $SR + ' is not the RAMDISK. -IDoit overrides this.')
  } else {
    O ''
    O '== 5 the ladder: one rung per candidate object, wlansvc retried after every rung =='
    $Rungs = @('ensure-drivers', 'bfe', 'mpssvc', 'netsh-wlancfg', 'disable-adapter', 'enable-adapter')
    $res = @()
    foreach ($rung in $Rungs) {
      if ($Only -ne '' -and $Only -notlike ('*' + $rung + '*')) { continue }
      O ('---- rung ' + $rung)
      if ($rung -eq 'ensure-drivers') {
        foreach ($pair in @(@('netnwifi.inf', 'MS_NativeWifiP'), @('netvwififlt.inf', 'ms_vwifi'))) {
          $inf = Join-Path $INFDIR $pair[0]
          $r = Run $NCFG @('-v', '-l', $inf, '-c', 's', '-i', $pair[1])
          O ('  P95 RUN netcfg ' + $pair[1] + ' rc=' + $r.rc + ' last=' + (@($r.lines | Select-Object -Last 2) -join ' // '))
        }
        $r = Run $WIFI @('svc', 'start', 'Ndisuio')
        O ('  P95 RUN ndisuio start rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
        O ('  P95 RUN ndisuio device ' + (NdisuioOpen))
      }
      if ($rung -eq 'bfe' -or $rung -eq 'mpssvc') {
        $svcName = 'BFE'
        if ($rung -eq 'mpssvc') { $svcName = 'mpssvc' }
        $p = Join-Path $SVCREOT $svcName
        if (-not (Test-Path -LiteralPath $p)) {
          O ('  P95 RUN ' + $rung + ' <key absent> -- nothing to start, this is a BAKE item')
        } else {
          $r = Run $WIFI @('svc', 'start', $svcName)
          O ('  P95 RUN ' + $rung + ' start rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
          $i = Wifi @('svc', 'info', $svcName)
          O ('  P95 RUN ' + $rung + ' info ' + $i)
        }
      }
      if ($rung -eq 'netsh-wlancfg') {
        $r = Run $REGX @('add', 'HKLM\SOFTWARE\Microsoft\Netsh', '/v', 'wlancfg', '/t', 'REG_SZ', '/d',
                         'wlancfg.dll', '/f')
        O ('  P95 RUN netsh-reg rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
        $h = Run $NSH @('wlan', 'show', 'interfaces')
        O ('  P95 RUN netsh wlan show interfaces rc=' + $h.rc)
        foreach ($l in @($h.lines | Select-Object -First 10)) { O ('    | ' + $l) }
        $h2 = Run $NSH @('wlan', 'show', 'networks')
        O ('  P95 RUN netsh wlan show networks rc=' + $h2.rc)
        foreach ($l in @($h2.lines | Select-Object -First 6)) { O ('    | ' + $l) }
      }
      if ($rung -eq 'disable-adapter' -or $rung -eq 'enable-adapter') {
        if (@($sh.devs).Count -eq 0) { O '  P95 RUN no WLAN devnode found, skipped'; }
        else {
          $verb = '/disable-device'
          if ($rung -eq 'enable-adapter') { $verb = '/enable-device' }
          foreach ($d in @($sh.devs)) {
            $r = Run $PNPU @($verb, $d.id)
            O ('  P95 RUN pnputil ' + $verb + ' ' + $d.id + ' rc=' + $r.rc +
               ' last=' + (@($r.lines | Select-Object -Last 2) -join ' // '))
          }
          $sh2 = Shape
          foreach ($d in @($sh2.devs)) {
            O ('  P95 RUN dev now ' + $d.id + ' problem=' + $d.prob + ' cfgflags=' + $d.cfg)
          }
          O ('  P95 RUN stack ' + (StackLine))
        }
      }
      TryWlan $rung
      $res += @{ rung = $rung; running = $script:WRun; ifn = $script:WIfn }
      if ($script:WRun) { O ('  P95 RUNG ' + $rung + ' took wlansvc RUNNING'); break }
    }
    O ('  P95 STACK-END ' + (StackLine))
    $sh3 = Shape
    foreach ($d in @($sh3.devs)) {
      O ('  P95 DEV-END ' + $d.id + ' svc=' + $d.svc + ' problem=' + $d.prob)
    }
    O ('  P95 STATUS-END ' + (Wifi @('status')))
    O ('  P95 BFE-ROW ' + (SvcRow 'BFE') + ' | ' + (Wifi @('svc', 'info', 'BFE')))
    O ('  P95 WDI-ROW ' + (SvcRow 'WdiServiceHost') + ' | ' + (Wifi @('svc', 'info', 'WdiServiceHost')))
  }
}

O ''
O '== 6 verdict =='
$nd = (Get-Service -Name Ndisuio -EA SilentlyContinue).Status
$bfeKey = (Test-Path -LiteralPath (Join-Path $SVCREOT 'BFE'))
$bfeRun = ((Get-Service -Name BFE -EA SilentlyContinue).Status)
$wdiKey = (Test-Path -LiteralPath (Join-Path $SVCREOT 'WdiServiceHost'))
$ihvDll = ''
foreach ($d in @($sh.devs)) {
  if ($d.drv -eq '') { continue }
  $v = [string](RegV (Join-Path $CLSNET ($d.drv + '\Ndi\IHVExtensions')) 'ExtensibilityDLL')
  if ($v -ne '') { $ihvDll = $v; break }
}
$outcome = 'unknown'
if ($baseRun) { $outcome = 'wlansvc-runs-in-read-only-baseline' }
elseif (-not $Apply) { $outcome = 'read-only-baseline-wlansvc-still-fails' }
elseif (@($res | Where-Object { $_.running }).Count -gt 0) {
  $outcome = 'rung-fixed-it:' + (@(@($res | Where-Object { $_.running }) | ForEach-Object { $_.rung }) -join ',')
}
elseif ((-not $bfeKey)) { $outcome = 'bfe-service-key-absent-cannot-be-fixed-at-runtime' }
elseif ($bfeRun -ne 'Running' -and $nd -eq 'Running') { $outcome = 'bfe-present-not-running-wlansvc-still-fails' }
elseif ($wdiKey -eq $false) { $outcome = 'wdi-service-host-absent-wlansvc-still-fails' }
else { $outcome = 'ladder-exhausted-wlansvc-still-fails' }
O ('  P95 VERDICT outcome=' + $outcome + ' bfe_key=' + $bfeKey + ' bfe_state=' + $bfeRun +
   ' ndisuio=' + $nd + ' wdi_key=' + $wdiKey + ' ihv_dll=[' + (Clean $ihvDll) + ']' +
   ' baseline_exit=' + (Wifi @('svc', 'info', 'wlansvc')))
O ('  P95 IFACE ' + (Wifi @('status')))
O '  BAKE-ITEMS (what wifi-inject / the boot path still has to carry, judged by this run):'
O ('    bfe: service key exists=' + $bfeKey + ' state=' + $bfeRun + ' (if absent: wlansvc FWP calls cannot work)')
O ('    WdiServiceHost/WdiSystemHost: exists=' + $wdiKey + ' (1060 => bake offline, services.exe cache is boot-frozen)')
O ('    IHV handler DLL registered=' + ($ihvDll -ne '') + ' -> ' + (Clean $ihvDll))
O ('    Ndisuio: ' + (SvcRow 'Ndisuio'))
O ('    wlansvc deps on host are nativewifip;RpcSs;Ndisuio;wcmsvc -> PE row: ' + (SvcRow 'wlansvc'))
O ('    netsh wlan usable (wlancfg registered) -> ' + (Wifi @('status')))
O 'P95 END'
