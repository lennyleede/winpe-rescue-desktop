# probe94 -- the layer UNDER wlansvc: why WlanSvcMain still returns 0x800C0006 after probe93's netcfg bind.
#
# Where probe93 left the problem (build\scratch\p93_apply2_1011.txt, this very box):
#   * the SUPPORTED installer works: `netcfg -v -l X:\windows\INF\netnwifi.inf -c s -i MS_NativeWifiP` (and
#     netvwififlt.inf / ms_vwifi) returns rc=0 and takes nativewifip + vwififlt RUNNING. The driver layer is done.
#   * wlansvc nevertheless still starts a host process and exits by itself with win32=0x800C0006 (probe86:
#     "kind=returned-error", no dump, no WER fault) => the service body bails during its own init.
#     VERDICT was outcome=nativewifip-running-no-children, vwifimp_nodes=0.
#
# What the working host has and this PE does not (read-only forensics 2026-10-11, all under build\scratch):
#   _host_wlan_ref2.txt / _host_wlan_ref3.txt / _host_wifi_ref.txt:
#     wlansvc DependOnService = nativewifip;RpcSs;Ndisuio;wcmsvc   (PE: only RpcSs -- wifi-inject wrote it that way
#                                                                    on purpose, to avoid 1068 on boxes with no WLAN)
#     Ndisuio      Group=NDIS Start=3 Type=1 Running on the host; NdisMinorVersion=30 + an empty Parameters subkey.
#                  PE: Group=PNP (our own bake wrote PNP), Start=3, State=Stopped.
#     WdiServiceHost type=32 Start=3 LocalService svchost -k LocalService, Parameters ServiceDll=%SystemRoot%\system32\
#                  wdi.dll ServiceMain=ServiceMain, RequiredPrivileges=SeChangeNotify+SeImpersonate+SeSystemProfile,
#                  ServiceSidType=1, Running on the host. Whether the PE's SCM even knows it is section 2 below.
#     wlansvc\Parameters on the host carries 9 SUBKEYS (ComInterfaceProviders, EapolKeyIpAddress, HostedNetworkSettings,
#                  OEM, OneXAuthenticator, VendorSpecificIEProviders, WfdInterfaceManagement, WFDProvPlugin,
#                  WlanAPIPermissions) -- our bake only ever wrote the three values, so a service that reads one of
#                  those keys at init finds nothing.
#     SOFTWARE\Microsoft\Wlansvc host tree = LayoutVersion+AllowAPMode + AnqpCache, Interfaces, Parameters\VWiFiSettings,
#                  PowerProfiles\{ClassA,ClassB,ClassG,ClassN}, ProfileSync\{AllUsers,PerUser}. PE has only
#                  LayoutVersion + AnqpCache.
#     SOFTWARE\Microsoft\WcmSvc host = CMPOL + 9 subkeys. PE = <absent>.
#     SOFTWARE\Microsoft\Netsh host registers 21 helpers incl. wlancfg=wlancfg.dll (310784 B in System32);
#                  PE registers 9 and has no wlancfg.dll => that is why "netsh wlan ..." is not found in PE.
#     C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{guid}\*.xml on the host; X:\ProgramData\Microsoft exists but
#                  has NO Wlansvc folder on the PE.
#   _pe_svc94_1011.txt (PE side, same lens): wcmsvc exit=1067 (faulted), netprofm exit=1077, nlasvc ServiceDll was
#   baked as netprofmsvc.dll (host: System32\nlasvc.dll) and netprofm carries the host's NLAsvc dep list
#   [NSI,RpcSs,TcpIp] instead of [RpcSs,nlasvc] -- a real bake bug, logged here so the fix goes into wifi-inject.
#
# THE LEADING HYPOTHESIS, and why it is testable at RUNTIME: wlansvc is a user-mode CONSUMER of Ndisuio -- the NDIS
# Usermode I/O Protocol driver creates the control device (\\.\Ndisuio) that nwifi/the native WiFi filter is reached
# through, which is exactly why the host lists Ndisuio in wlansvc's DependOnService. On this PE Ndisuio is Stopped,
# so the object wlansvc opens does not exist => "cannot find the specified object". Starting an already-baked service
# is a live SCM operation (unlike CREATING a service key, which services.exe cannot see until the next boot -- the
# vwifibus lesson), so `wifi.exe svc start Ndisuio` + retry wlansvc answers it on this boot, no rebuild needed.
# Same asymmetry makes the registry/data-store rungs meaningful: the SCM service DB is cached at boot, but a service
# reads its own Parameters / SOFTWARE\Microsoft\Wlansvc keys and its ProgramData folder live, at start time.
#
# Sections: 1 identity/stack; 2 what the SCM can see (wifi.exe svc info + deps + status); 3 the PE<->host diffs
# (service rows, wlansvc\Parameters subkeys, SOFTWARE trees, files, data store, \\.\Ndisuio open test);
# 4 with -Apply a short ladder -- start Ndisuio, create the wlansvc data store + the missing SOFTWARE keys, start
# wcmsvc, retry wlansvc after every rung and re-run `wifi.exe status`; 5 verdict + the exact list of rows wifi-inject
# still has to bake.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit overrides
# that guard deliberately. Only the WLAN-relevant services get started; the Realtek wired adapter carrying this ssh
# session is never touched and no customer disk is written. Everything lives on the RAMDISK: rebooting restores the
# disc state. Nothing is written to the ISO, to D:\winpe_build, or to a customer disk.
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
# One line per service row, in the same words the host dump used, so the two are diffable by eye.
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
function StackLine {
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp', 'Ndisuio', 'NSI')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return (@($states -join ',') + ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
         ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status))
}
# wlansvc reaches the native WiFi filter through the Ndisuio control device; opening it is the cheapest direct proof
# that the object the service is looking for exists (or not) at this moment.
function NdisuioOpen {
  foreach ($dev in @('\\.\Ndisuio', '\\.\NdisWanAdapter', '\\.\NDIS')) {
    $h = $null
    try {
      $h = [System.IO.File]::Open($dev, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite,
                                  [System.IO.FileShare]::None)
      $r = ('OPEN-OK ' + $dev)
      $h.Dispose()
      return $r
    } catch {
      $m = Clean $_.Exception.Message
      if ($m.Length -gt 70) { $m = $m.Substring(0, 70) }
      if ($dev -eq '\\.\Ndisuio') { return ('OPEN-FAIL ' + $dev + ' ' + $m) }
    } finally { if ($h) { try { $h.Dispose() } catch { } } }
  }
  return 'OPEN-FAIL \\.\Ndisuio <not attempted>'
}
function Wifi([object[]]$argv) {
  $r = Run $WIFI @($argv)
  return ('rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
}
# WLAN devnodes on this box (driver service matches the vendor whitelist), for the restart-device rung.
function Shape {
  $devs = @()
  foreach ($bus in @(Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum' -EA SilentlyContinue)) {
    foreach ($prov in @(Get-ChildItem $bus.PSPath -EA SilentlyContinue)) {
      foreach ($inst in @(Get-ChildItem $prov.PSPath -EA SilentlyContinue)) {
        $ip = Get-ItemProperty -LiteralPath $inst.PSPath -EA SilentlyContinue
        $svc = "$($ip.Service)"
        if ($svc -notmatch $WLAN_SVC) { continue }
        $devs += @{ id = ($bus.PSChildName + '\' + $prov.PSChildName + '\' + $inst.PSChildName); svc = $svc }
      }
    }
  }
  return @{ devs = $devs }
}

$SR    = Root ''
$S32   = Join-Path $SR 'System32'
$INFDIR = Join-Path $SR 'INF'
$REGX  = Join-Path $S32 'reg.exe'
$NET   = Join-Path $S32 'net.exe'
$ICAC  = Join-Path $S32 'icacls.exe'
$PNPU  = Join-Path $S32 'pnputil.exe'
$NSH   = Join-Path $S32 'netsh.exe'
$WIFI  = Join-Path $S32 'wifi.exe'
$WLAN_SVC = '(?i)^(netwtw|netwaw|rtwlane|rtwlanu|bcmwl|mtkwl|mtkwecx|athw|iwlwifi|netwlan)'
$SVCREOT = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$WLSW  = 'HKLM:\SOFTWARE\Microsoft\Wlansvc'
$WCSW  = 'HKLM:\SOFTWARE\Microsoft\WcmSvc'
$PD    = Join-Path ($env:SystemDrive + '\') 'ProgramData'
$PDL   = Join-Path $PD 'Microsoft\Wlansvc'
$PDLI  = Join-Path $PDL 'Profiles\Interfaces'
$PDWC  = Join-Path $PD 'Microsoft\WcmSvc'
# the subkeys a healthy wlansvc has under its own Parameters (host: _host_wlan_ref3.txt)
$PAR_WANT = @('ComInterfaceProviders', 'EapolKeyIpAddress', 'HostedNetworkSettings', 'OEM', 'OneXAuthenticator',
              'VendorSpecificIEProviders', 'WfdInterfaceManagement', 'WFDProvPlugin', 'WlanAPIPermissions')
$SW_WANT  = @('AnqpCache', 'Interfaces', 'Parameters', 'PowerProfiles', 'ProfileSync')
$WIFI_SVC = @('wlansvc', 'wcmsvc', 'Ndisuio', 'WdiServiceHost', 'NSI', 'netprofm', 'nlasvc', 'dot3svc', 'DusmSvc')

O ('P94 START root=' + $SR + ' apply=' + $Apply.IsPresent + ' only=[' + $Only + '] drive=' + $env:SystemDrive)
O ('  P94 STACK ' + (StackLine))
O ('  P94 NDISUIO-DEVICE-BEFORE ' + (NdisuioOpen))
O ('  P94 WIFI-TOOL exists=' + (Test-Path -LiteralPath $WIFI) + ' bytes=' + ((Get-Item -LiteralPath $WIFI -EA SilentlyContinue).Length) +
   ' version=' + (FV $WIFI))

O '== 1 what the SCM can see right now (wifi.exe is the only honest lens: it uses OpenService, not the registry) =='
foreach ($s in @($WIFI_SVC)) {
  O ('  P94 ROW ' + (SvcRow $s))
  O ('  P94 SCM ' + $s + ' -> ' + (Wifi @('svc', 'info', $s)))
}
O ('  P94 DEPS-WLANSCV ' + (Wifi @('deps', 'wlansvc')))
O ('  P94 STATUS-BASE ' + (Wifi @('status')))

O '== 2 the wlansvc service body: Parameters values + the 9 host subkeys =='
$wlp = $SVCREOT + '\wlansvc\Parameters'
O ('  P94 WLPARAM values=' + ((ValNames $wlp) -join ',') + ' subs=' + ((SubNames $wlp) -join ','))
foreach ($k in @($PAR_WANT)) {
  $p = Join-Path $wlp $k
  $have = (Test-Path -LiteralPath $p)
  $extra = ''
  if ($have) { $extra = ' values=' + ((ValNames $p) -join ',') + ' subs=' + ((SubNames $p) -join ',') }
  O ('  P94 WLPARAM-SUB ' + $k + ' present=' + $have + $extra)
}
O ('  P94 WCMSVC-SUBS ' + ((SubNames ($SVCREOT + '\wcmsvc')) -join ',') +
   ' | host has Csps(cspethernet,cspwlan,cspwwan),Parameters,Security,TriggerInfo')
$csps = $SVCREOT + '\wcmsvc\Csps'
O ('  P94 WCMSVC-CSPs present=' + (Test-Path -LiteralPath $csps) + ' subs=' + ((SubNames $csps) -join ','))
O ('  P94 WDI-FILE wdi.dll exists=' + (Test-Path -LiteralPath (Join-Path $S32 'wdi.dll')) +
   ' bytes=' + ((Get-Item -LiteralPath (Join-Path $S32 'wdi.dll') -EA SilentlyContinue).Length) +
   ' | ndisuio.sys exists=' + (Test-Path -LiteralPath (Join-Path $S32 'drivers\ndisuio.sys')) +
   ' bytes=' + ((Get-Item -LiteralPath (Join-Path $S32 'drivers\ndisuio.sys') -EA SilentlyContinue).Length) +
   ' | nlasvc.dll exists=' + (Test-Path -LiteralPath (Join-Path $S32 'nlasvc.dll')) +
   ' | wlancfg.dll exists=' + (Test-Path -LiteralPath (Join-Path $S32 'wlancfg.dll')))
O ('  P94 WDI-DLLLOAD ' + (Wifi @('dllload', 'wdi.dll', 'ServiceMain')))
O ('  P94 WL-DLLLOAD ' + (Wifi @('dllload', 'wlansvc.dll', 'WlanSvcMain')))

O '== 3 the SOFTWARE trees wlansvc/wcmsvc read, and the data store they write =='
foreach ($t in @(@($WLSW, 'WLANSVC'), @($WCSW, 'WCMSCV'))) {
  $p = $t[0]; $tag = $t[1]
  if (-not (Test-Path -LiteralPath $p)) { O ('  P94 ' + $tag + ' <key absent> ' + $p); continue }
  O ('  P94 ' + $tag + ' values=' + ((ValNames $p) -join ',') + ' subs=' + ((SubNames $p) -join ','))
  foreach ($c in @(Get-ChildItem -LiteralPath $p -EA SilentlyContinue)) {
    O ('      SUB ' + $c.PSChildName + ' values=' + ((ValNames $c.PSPath) -join ',') +
       ' kids=' + ((SubNames $c.PSPath) -join ','))
  }
}
foreach ($k in @($SW_WANT)) {
  O ('  P94 WLANSVC-NEED ' + $k + ' present=' + (Test-Path -LiteralPath (Join-Path $WLSW $k)) + ' (host has it)')
}
O ('  P94 NETSH-HELPERS values=' + ((ValNames 'HKLM:\SOFTWARE\Microsoft\Netsh') -join ',') +
   ' | host registers wlancfg/dot3cfg/wwancfg/WcnNetsh/...')
O ('  P94 PROFILELIST ProgramData=[' + (RegV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' 'ProgramData') +
   '] Public=[' + (RegV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' 'Public') + ']')
foreach ($d in @($PD, (Join-Path $PD 'Microsoft'), $PDL, $PDLI, $PDWC,
                 (Join-Path $SR 'ServiceProfiles'), (Join-Path $SR 'ServiceProfiles\LocalService'),
                 (Join-Path $SR 'ServiceProfiles\LocalService\AppData'),
                 (Join-Path $SR 'ServiceProfiles\LocalService\AppData\Local\Microsoft\Wlansvc'),
                 (Join-Path $env:SystemDrive 'Users\Public'))) {
  $e = (Test-Path -LiteralPath $d)
  $kids = ''
  if ($e) { $kids = ' kids=' + ((SubNames $d) -join ',') }
  O ('  P94 DIR ' + $d + ' exists=' + $e + $kids)
}

O '== 4 ladder (only with -Apply; every rung re-starts wlansvc and re-runs wifi.exe status) =='
# Everything below is still visible to the RUNNING stack without a reboot:
#   * starting an ALREADY-BAKED service (Ndisuio/wcmsvc) is a live SCM call -- unlike CREATING a service key, which
#     services.exe cannot see until the next boot (the vwifibus lesson), so a missing WdiServiceHost is reported as a
#     bake item and never "fixed" at runtime;
#   * a service reads its own Parameters / SOFTWARE\Microsoft\Wlansvc keys and its ProgramData folder live, at start
#     time, so creating those before the retry is a real test of the "cannot find the specified object" theory.
$Rungs = @('ndisuio', 'params-subkeys', 'datastore', 'software-keys', 'wcmsvc-csps', 'netsh-wlancfg',
           'wcmsvc', 'wlansvc', 'restart-wifi-dev')
if (-not $Apply) {
  O '  P94 LADDER-PLAN (read-only run; re-deliver with -Apply)'
  foreach ($r in @($Rungs)) { O ('    P94 PLAN ' + $r) }
} elseif (($SR -notmatch '(?i)^X:') -and -not $IDoit) {
  O ('  P94 REFUSE mutate: SystemRoot=' + $SR + ' is not the RAMDISK. The read-only results above stand.')
} else {
  foreach ($r in @($Rungs)) {
    if ($Only -ne '' -and $r -notlike ('*' + $Only + '*')) { continue }
    if ($r -eq 'ndisuio') {
      $a = Wifi @('svc', 'start', 'Ndisuio')
      O ('  P94 RUN ndisuio start-> ' + $a)
      Start-Sleep -Seconds 2
      $n = Run $NET @('start', 'Ndisuio')
      O ('    net start rc=' + $n.rc + ' ' + (@($n.lines) -join ' // '))
      O ('    P94 ROW-AFTER ' + (SvcRow 'Ndisuio'))
      O ('    P94 NDISUIO-DEVICE ' + (NdisuioOpen))
    }
    if ($r -eq 'params-subkeys') {
      # host: _host_wlan_ref3.txt -- wlansvc\Parameters carries nine SUBKEYS and our bake wrote only the three values.
      # A service reads its own Parameters key at start time (the SCM service DB is the only thing cached at boot),
      # so creating them here is a genuine test, not a cosmetic one. Values inside them are copied where the host
      # dump showed a value name; the rest are created empty because "key exists with no values" is a different
      # failure than "RegOpenKeyEx returns 2 (ERROR_FILE_NOT_FOUND)".
      $PVAL = @{
        'HostedNetworkSettings'   = @('HostedNetworkSsid', 'HostedNetworkKey', 'HostedNetworkMaxClients',
                                      'HostedNetworkMode', 'HostedNetworkBand', 'HostedNetworkSoftApState');
        'WlanAPIPermissions'      = @();
        'WfdInterfaceManagement'  = @();
        'WFDProvPlugin'           = @();
        'ComInterfaceProviders'   = @();
        'EapolKeyIpAddress'       = @();
        'OEM'                     = @();
        'OneXAuthenticator'       = @();
        'VendorSpecificIEProviders' = @()
      }
      foreach ($k in @($PAR_WANT)) {
        $p = $wlp + '\' + $k
        if (-not (Test-Path -LiteralPath $p)) {
          $native = ($p -replace '^HKLM:', 'HKLM')
          $g = Run $REGX @('add', $native, '/f')
          O ('    REG-ADD ' + $native + ' rc=' + $g.rc + ' ' + (@($g.lines | Select-Object -Last 1) -join ''))
        } else { O ('    REG-KEY already there ' + $p) }
      }
      O ('    P94 WLPARAM-AFTER subs=' + ((SubNames $wlp) -join ',') + ' values=' + ((ValNames $wlp) -join ','))
      # the same for the connection manager: the host has Csps\{cspethernet,cspwlan,cspwwan}
      foreach ($k in @(($SVCREOT + '\wcmsvc\Csps'), ($SVCREOT + '\wcmsvc\Csps\cspwlan'),
                       ($SVCREOT + '\wcmsvc\Csps\cspethernet'), ($SVCREOT + '\wcmsvc\Csps\cspwwan'))) {
        if (-not (Test-Path -LiteralPath $k)) {
          $native = ($k -replace '^HKLM:', 'HKLM')
          $g = Run $REGX @('add', $native, '/f')
          O ('    REG-ADD ' + $native + ' rc=' + $g.rc)
        } else { O ('    REG-KEY already there ' + $k) }
      }
    }
    if ($r -eq 'wcmsvc-csps') {
      # Ndisuio is a hard dependency of dot3svc and of the host's wlansvc row; the CSP keys above are what the
      # connection manager walks when it registers itself -- this rung only retries the service and samples it,
      # because wcmsvc's 1067 (process aborted) is the second half of the same story.
      $a = Wifi @('svc', 'start', 'wcmsvc')
      O ('  P94 RUN wcmsvc-csps start-> ' + $a)
      $wt = Wifi @('svc', 'watch', 'wcmsvc', '4000')
      O ('    watch: ' + $wt)
      O ('    P94 ROW-AFTER ' + (SvcRow 'wcmsvc'))
    }
    if ($r -eq 'netsh-wlancfg') {
      # wlancfg.dll IS on this disc (section 2) but SOFTWARE\Microsoft\Netsh never registers it, which is exactly
      # why "netsh wlan ..." answers 'The following command was not found'. netsh reads that key live.
      $g = Run $REGX @('add', 'HKLM\SOFTWARE\Microsoft\Netsh', '/v', 'wlancfg', '/t', 'REG_SZ', '/d', 'wlancfg.dll', '/f')
      O ('  P94 RUN netsh-wlancfg reg rc=' + $g.rc + ' ' + (@($g.lines | Select-Object -Last 1) -join ''))
      $ns = Run $NSH @('wlan', 'show', 'interfaces')
      O ('    netsh wlan show interfaces rc=' + $ns.rc + ' ' + ((@($ns.lines) | Select-Object -First 6) -join ' // '))
      $nt = Run $NSH @('wlan', 'show', 'networks', 'bssid')
      O ('    netsh wlan show networks rc=' + $nt.rc + ' ' + ((@($nt.lines) | Select-Object -First 4) -join ' // '))
    }
    if ($r -eq 'datastore') {
      foreach ($d in @($PDL, (Join-Path $PDL 'Profiles'), $PDLI)) {
        if (-not (Test-Path -LiteralPath $d)) {
          try { $null = New-Item -ItemType Directory -Path $d -Force -EA Stop; O ('    MKDIR ' + $d + ' ok') }
          catch { O ('    MKDIR ' + $d + ' FAIL ' + (Clean $_.Exception.Message)) }
        } else { O ('    MKDIR ' + $d + ' already there') }
      }
      $ic = Run $ICAC @($PDL, '*S-1-5-18:(OI)(CI)(F)', '*S-1-5-19:(OI)(CI)(F)', '*S-1-5-20:(OI)(CI)(F)',
                         '*S-1-3-0:(OI)(CI)(IO)(F)')
      O ('    icacls rc=' + $ic.rc + ' ' + ((@($ic.lines) | Select-Object -Last 2) -join ' // '))
      O ('    P94 DIR-AFTER ' + $PDL + ' exists=' + (Test-Path -LiteralPath $PDL) + ' kids=' + ((SubNames $PDL) -join ','))
    }
    if ($r -eq 'software-keys') {
      foreach ($k in @(($WLSW + '\Interfaces'), ($WLSW + '\Parameters'), ($WLSW + '\Parameters\VWiFiSettings'),
                       ($WLSW + '\PowerProfiles'), ($WLSW + '\PowerProfiles\ClassN'), ($WLSW + '\PowerProfiles\ClassAC'),
                       ($WLSW + '\PowerProfiles\ClassG'), ($WLSW + '\PowerProfiles\ClassB'),
                       ($WLSW + '\ProfileSync'), ($WLSW + '\ProfileSync\AllUsers'),
                       ($WLSW + '\ProfileSync\AllUsers\Profiles'), ($WLSW + '\ProfileSync\PerUser'),
                       $WCSW, ($WCSW + '\Policy'), ($WCSW + '\Selection'), ($WCSW + '\Tethering'),
                       ($WCSW + '\wifinetworkmanager'))) {
        $ex = (Test-Path -LiteralPath $k)
        if (-not $ex) {
          $native = ($k -replace '^HKLM:', 'HKLM')
          $g = Run $REGX @('add', $native, '/f')
          O ('    REG-ADD ' + $native + ' rc=' + $g.rc + ' ' + (@($g.lines | Select-Object -Last 1) -join ''))
        } else { O ('    REG-KEY already there ' + $k) }
      }
      $g2 = Run $REGX @('add', 'HKLM\SOFTWARE\Microsoft\Wlansvc', '/v', 'AllowAPMode', '/t', 'REG_DWORD', '/d', '0', '/f')
      O ('    REG-VAL AllowAPMode rc=' + $g2.rc)
      O ('    P94 WLANSVC-AFTER values=' + ((ValNames $WLSW) -join ',') + ' subs=' + ((SubNames $WLSW) -join ','))
    }
    if ($r -eq 'wcmsvc') {
      $a = Wifi @('svc', 'start', 'wcmsvc')
      O ('  P94 RUN wcmsvc start-> ' + $a)
      $wt = Wifi @('svc', 'watch', 'wcmsvc', '3000')
      O ('    watch: ' + $wt)
      O ('    P94 ROW-AFTER ' + (SvcRow 'wcmsvc'))
    }
    if ($r -eq 'wlansvc') {
      $a = Wifi @('svc', 'start', 'wlansvc')
      O ('  P94 RUN wlansvc start-> ' + $a)
      Start-Sleep -Seconds 3
      O ('    info: ' + (Wifi @('svc', 'info', 'wlansvc')))
    }
    if ($r -eq 'restart-wifi-dev') {
      $sh = Shape
      foreach ($d in @($sh.devs)) {
        $rr = Run $PNPU @('/restart-device', $d.id)
        O ('  P94 RUN restart ' + $d.id + ' rc=' + $rr.rc + ' ' + ((@($rr.lines) | Select-Object -First 2) -join ' // '))
      }
      if (@($sh.devs).Count -eq 0) { O '  P94 RUN restart-wifi-dev <no WLAN devnode found>' }
      Start-Sleep -Seconds 3
    }
    # re-measure after every rung; the goal is an interface object, not a record count
    O ('    P94 STACK-AFTER ' + (StackLine))
    $inf = Wifi @('status')
    O ('    P94 STATUS-AFTER ' + $inf)
    $ifn = 0
    if ($inf -match 'interfaces=(\d+)') { $ifn = [int]$Matches[1] }
    $wlx = (Get-Service -Name wlansvc -EA SilentlyContinue).Status
    if ($ifn -gt 0 -or "$wlx" -eq 'Running') {
      O ('  P94 PROGRESS after ' + $r + ': interfaces=' + $ifn + ' wlansvc=' + $wlx + ' -- stopping the ladder')
      break
    }
  }
}

O '== 5 final measurement =='
O ('  P94 STACK-FINAL ' + (StackLine))
O ('  P94 NDISUIO-DEVICE-FINAL ' + (NdisuioOpen))
foreach ($s in @('Ndisuio', 'WdiServiceHost', 'wlansvc', 'wcmsvc')) { O ('  P94 ROW-FINAL ' + (SvcRow $s)) }
$fs = Wifi @('status')
O ('  P94 STATUS-FINAL ' + $fs)
$fin = 0
if ($fs -match 'interfaces=(\d+)') { $fin = [int]$Matches[1] }
if ($fin -gt 0) { O ('  P94 SCAN-FINAL ' + (Wifi @('scan'))) }
O ('  P94 WLANSVC-IFACE-KEYS subs=' + ((SubNames ($WLSW + '\Interfaces')) -join ','))
O ('  P94 WLANSVC-DIR-FINAL ' + $PDL + ' exists=' + (Test-Path -LiteralPath $PDL) + ' kids=' + ((SubNames $PDL) -join ','))
O ('  P94 WLPARAM-FINAL subs=' + ((SubNames ($SVCREOT + '\wlansvc\Parameters')) -join ','))
$ads = @()
try { $ads = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue) }
catch { O ('  P94 CIM-ERR ' + (Clean $_.Exception.Message)) }
foreach ($ad in @($ads | Select-Object -First 12)) {
  O ('  P94 ADAPTER ' + (Clean "$($ad.Name)") + ' phys=' + $ad.PhysicalAdapter + ' guid=[' + $ad.GUID + ']' +
     ' netenabled=' + $ad.NetEnabled + ' status=' + (Clean "$($ad.NetConnectionStatus)"))
}

O '== 6 verdict =='
$outcome = 'no-progress'
$wlF = (Get-Service -Name wlansvc -EA SilentlyContinue).Status
$ndF = (Get-Service -Name Ndisuio -EA SilentlyContinue).Status
$infF = Wifi @('svc', 'info', 'wlansvc')
if (-not $Apply) {
  $outcome = 'read-only'
} elseif ($fin -gt 0) {
  $outcome = 'wifi-interface-present'
} elseif ("$wlF" -eq 'Running') {
  $outcome = 'wlansvc-running-no-interface'
} elseif ("$ndF" -eq 'Running') {
  $outcome = 'ndisuio-running-wlansvc-still-returns-error'
} elseif ($infF -match '1060') {
  $outcome = 'wlansvc-invisible-to-scm'
} else {
  $outcome = 'ndisuio-not-running-ladder-exhausted'
}
O ('  P94 VERDICT outcome=' + $outcome + ' ndisuio=' + $ndF + ' wlansvc=' + $wlF + ' interfaces=' + $fin +
   ' device=[' + (NdisuioOpen) + '] info=[' + $infF + ']')
O '  P94 BAKE-ITEMS (what wifi-inject / the boot path still has to carry, from the diffs above):'
foreach ($b in @(
  'wlansvc DependOnService on the host = nativewifip;RpcSs;Ndisuio;wcmsvc. The PE row is intentionally RpcSs-only (no',
  '  1068 on boxes without WLAN hardware), so the boot path must START Ndisuio before wlansvc -- this probe decides',
  '  whether that is the object that was missing. Ndisuio itself must be baked as Group=NDIS (we write PNP),',
  '  NdisMajorVersion=6 NdisMinorVersion=30, plus the empty Parameters subkey (host: _host_wlan_ref3.txt)',
  'wlansvc\Parameters host subkeys: ' + ($PAR_WANT -join ', ') + ' -- a service reads its own Parameters live, so any',
  '  of these being absent is a candidate for "cannot find the specified object"',
  'SOFTWARE\Microsoft\Wlansvc tree (AnqpCache, Interfaces, Parameters\VWiFiSettings, PowerProfiles\{ClassAC,ClassB,',
  '  ClassG,ClassN}, ProfileSync\{AllUsers,PerUser}) + AllowAPMode; SOFTWARE\Microsoft\WcmSvc tree (CMPOL + 9 subkeys)',
  'WdiServiceHost service key (Type=32 Start=3, NT AUTHORITY\LocalService, svchost -k LocalService -p,',
  '  wdi.dll!ServiceMain, RequiredPrivileges SeChangeNotify+SeImpersonate+SeSystemProfile, ServiceSidType=1).',
  '  If section 2 printed <key absent> this can ONLY be proven after a rebuild: services.exe cannot see a service',
  '  key created after boot (the vwifibus lesson), so no runtime rung attempts it',
  'ProgramData\Microsoft\Wlansvc\Profiles\Interfaces must exist (host keeps the per-interface SSID .xml there)',
  'bake bug found on the way: PE nlasvc ServiceDll was written as netprofmsvc.dll (host: System32\nlasvc.dll) and PE',
  '  netprofm carries the host nlasvc dep list [NSI;RpcSs;TcpIp] instead of [RpcSs;nlasvc], with ObjectName',
  '  NetworkService instead of NT AUTHORITY\LocalService -- fix both rows',
  'netsh wlan needs wlancfg.dll on the disc AND a wlancfg value under SOFTWARE\Microsoft\Netsh; until then the',
  '  acceptance test uses wifi.exe (already baked into System32)'
)) { O ('    | ' + $b) }
O 'P94 DONE'
