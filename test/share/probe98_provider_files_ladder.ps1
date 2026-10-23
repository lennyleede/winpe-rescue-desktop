# probe98 -- the values, not the import table: what this PE's own wlansvc/wcmsvc keys actually hold, then supply
# the five provider files those values name by PATH and the values themselves, retrying the service after each group.
#
# Where probe97 left it (build\scratch\p97_pe_apply.txt, this box, same boot, -Apply ladder):
#   every file the loader could not find was copied and every LoadLibrary flipped 126 -> OK, contracts included,
#   and wlansvc still answered, at all eight rungs, exactly:
#     StartService OK -> +0ms STOP_PENDING(3) -> +~120ms STOPPED(1) exit=2148270086(0x800C0006) specific=0
#   P97 VERDICT outcome=wlansvc-still-0x800C0006 ... now-in-system32=[wcmapi,rmclient,wlgpclnt,policymanager,
#   embeddedmodesvcapi,cmintegrator,es,tspkg,pku2u]. So the missing-FILE theory for the delay-load set is closed.
#   build\scratch\t_p98_const_scan_host.ps1 then scanned 13 WiFi user-mode modules for the immediate
#   06 00 0C 80 -> total_constant_sites=0: the code is produced by a callee, not returned from these modules.
#
# What no earlier probe could see: wlansvc loads several providers BY PATH FROM THE REGISTRY, so the names never
# appear in an import table (probe82's closure walk) and never appear as a delay-load (probe96/97's LL ladder).
# build\scratch\p98_host_regshape2.txt (host, read-only, the fixed Drive() dump) shows the real shape:
#   Parameters\OneXAuthenticator(default)      = ...\WcnEapAuthProxy.dll
#   Parameters\WFDProvPlugin(default)          = ...\wfdprov.dll        (+ DllEntryPoint = WFDProvGetInfo)
#   Parameters\VendorSpecificIEProviders\{guid}\Path = ...\TetheringIeProvider.dll / ...\WiFiDisplay.dll /
#                                                      ...\WlanSvc.dll (x2, the service already has that one)
#   Parameters\ComInterfaceProviders\IHNetIcsSettings = {46C166AA-3108-11D4-9348-00C04F8EEB71}
#     -> HKLM\SOFTWARE\Classes\CLSID\{...}\InProcServer32(default) = ...\hnetcfgclient.dll, ThreadingModel=Both
#   plus Parameters\WfdInterfaceManagement (2 DWORD), Parameters\EapolKeyIpAddress (LocalAddress, PrefixLength),
#   VirtualizationManager\WindowsPushNotificationPlatformClsid, RequiredPrivileges (7 SIDs incl. SeTcb/SeDebug/
#   SeLoadDriver), DependOnService = nativewifip RpcSs Ndisuio wcmsvc (the PE row reads Depend=[RpcSs] only).
# build\scratch\t_p98_stage_providers.ps1 checked all five files against THIS BOOT's PE file list
# (pe_s32_1011.txt, 1257 names): every one is ABSENT-in-pe, staged into the HTTP drop folder with manifest98.txt.
#
# SECOND SIGNAL, same probe, almost free: wcmsvc does not stay up either (probe97 reached START_PENDING
# checkpoint=15 and ended Stopped). If wlansvc and wcmsvc die with the SAME code, the shared object -- not a
# per-service provider -- is the root cause, and that reframes everything. Section 2 therefore watches both.
#
# PRIVACY / SAFETY RULES enforced in code, not just comment:
#   * no value under HostedNetworkSettings / EncryptedSettings / Security / ProfileSync / Wlansvc\Interfaces /
#     wifinetworkmanager is ever printed or written -- those carry this machine's WiFi key material and must not
#     cross the ssh channel or end up in an image. Redact() and SafePath() refuse them by name.
#   * byte values print as HEX(len) only for the withheld shapes.
#   * MUTATION: nothing written unless -Apply AND SystemRoot is the ramdisk (X:); -IDoit overrides on purpose.
#     Writes are file copies into X:\Windows\System32 (backup kept in X:\p98bak) plus reg add under EXISTING
#     service keys. Values under Parameters are read by wlansvc when it starts, so they take effect live; the two
#     WDI *service* keys stay on the offline list because services.exe builds its database at boot.
#   * no hive touched, nothing under D:\winpe_build, no ISO, no customer disk. Rebooting restores the disc.
param([switch]$Apply, [switch]$IDoit, [switch]$ForceNoRun, [string]$Base = 'http://192.168.0.106:8099/', [string]$Only = '')
$ErrorActionPreference = 'Continue'

function O([string]$s) { Write-Output $s }
function Clean([string]$s) { (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
function Root([string]$sub) {
  $c = Get-WmiObject Win32_OperatingSystem -EA SilentlyContinue
  if ($c -and $c.SystemDirectory) { return (Split-Path $c.SystemDirectory -Parent) }
  return $env:SystemRoot
}
function TP([string]$p) {
  try { return [bool](Test-Path -LiteralPath $p -EA SilentlyContinue) } catch { return $false }
}
function RegV([string]$path, [string]$name) {
  (Get-ItemProperty -LiteralPath $path -Name $name -EA SilentlyContinue).PSObject.Properties[$name].Value
}
function HexVal([object]$v) { if ($null -eq $v) { return '-' } return ('0x' + ('{0:X}' -f [int]$v)) }
function FV([string]$p) {
  if (-not (TP $p)) { return '<absent>' }
  $v = $null
  try { $v = (Get-Item -LiteralPath $p -EA SilentlyContinue).VersionInfo.FileVersion } catch { }
  return ('"' + (Clean "$v") + '"')
}
function Run([string]$exe, [object[]]$argv) {
  if (-not (TP $exe)) { return @{ rc = -1; lines = @('<tool absent: ' + $exe + '>') } }
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
function SvcRow([string]$s) {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  if (-not (TP $p)) { return ('SVC ' + $s + ' <key absent>') }
  $dll = [string](RegV ($p + '\Parameters') 'ServiceDll')
  $main = [string](RegV ($p + '\Parameters') 'ServiceMain')
  return ('SVC ' + $s + ' Start=' + (HexVal (RegV $p 'Start')) + ' Type=' + (HexVal (RegV $p 'Type')) +
    ' Group=[' + (RegV $p 'Group') + '] Obj=[' + (RegV $p 'ObjectName') + ']' +
    ' Depend=[' + (@(RegV $p 'DependOnService') -join ';') + ']' +
    ' Priv=[' + (@(RegV $p 'RequiredPrivileges') -join ';') + ']' +
    ' SidType=' + (HexVal (RegV $p 'ServiceSidType')) +
    ' State=' + ((Get-Service -Name $s -EA SilentlyContinue).Status) +
    ' Dll=[' + (Clean $dll) + '] exists=' + (TP $dll) + ' ver=' + (FV $dll) + ' Main=[' + $main + ']' +
    ' subs=' + ((SubNames $p) -join ','))
}
function Wifi([object[]]$argv) {
  $r = Run $WIFI @($argv)
  return ('rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
}
function StackLine {
  $states = @()
  foreach ($n in @('nativewifip', 'wdiwifi', 'vwifibus', 'vwififlt', 'vwifimp', 'Ndisuio', 'NSI', 'RpcSs', 'bfe')) {
    $states += ($n + ':' + ((Get-Service -Name $n -EA SilentlyContinue).Status))
  }
  return (@($states -join ',') + ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
         ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status))
}
# ---- privacy gates. Both the printer and the writer go through these, so a secret cannot ride the channel.
# Test path and name SEPARATELY: the earlier version matched against 'path | name', so an anchor like '\Security$'
# could never fire (the combined string ends with the value name) and Services\wcmsvc\Security printed its bytes.
function SecretShape([string]$path, [string]$name) {
  $p = Clean "$path"
  $n = Clean "$name"
  if ($p -match '(?i)HostedNetworkSettings|EncryptedSettings|ProfileSync|\\Interfaces\\|\\Interfaces$|wifinetworkmanager|\\OneTemp\\') { return $true }
  if ($p -match '(?i)\\Security$') { return $true }
  if ($n -match '(?i)^Security$|^EncryptedSettings$|^HostedNetworkSettings$|password|passphrase|psk|keymaterial|sharedsecret|profilexml') { return $true }
  return $false
}
function Redact([string]$path, [string]$name, [object]$v) {
  if (SecretShape $path $name) { return '<withheld:secret-shaped>' }
  if ($null -eq $v) { return '<null>' }
  if ($v -is [byte[]]) { return ('HEX(' + $v.Length + ') ' + ((($v | Select-Object -First 12) | ForEach-Object { '{0:X2}' -f $_ }) -join '')) }
  if ($v -is [string[]]) { return (@($v) -join ';') }
  $s = Clean "$v"
  if ($s -match '(?i)password|psk|passphrase|securitykey|sharedsecret') { return '<withheld:secret-looking>' }
  if ($s.Length -gt 220) { return ($s.Substring(0, 220) + '...') }
  return $s
}
function Drive([string]$n) {
  if ($n -match '(?i)^Microsoft\.PowerShell\.Core\\Registry::') { $n = $n -replace '(?i)^Microsoft\.PowerShell\.Core\\Registry::', '' }
  if ($n -match '(?i)^HKEY_LOCAL_MACHINE\\') { return 'HKLM:\' + $n.Substring('HKEY_LOCAL_MACHINE\'.Length) }
  return $n
}
function DumpKey([string]$pspath) {
  $ip = $null
  try { $ip = Get-ItemProperty -LiteralPath $pspath -EA SilentlyContinue } catch { }
  if ($null -eq $ip) { O '      <no-values>'; return }
  $names = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })
  if ($names.Count -eq 0) { O '      <no-values>'; return }
  foreach ($p in $names) {
    $tn = '<null>'
    if ($null -ne $p.Value) { $tn = Clean "$($p.Value.GetType().Name)" }
    O ('      VAL ' + (Clean $p.Name) + ' [' + $tn + '] = ' + (Redact $pspath $p.Name $p.Value))
  }
}
# Get-ChildItem hands back .Name as 'HKEY_LOCAL_MACHINE\...', which the HKLM: drive will not accept. Reading it
# directly looks like "key has no values" and silently wastes a whole round trip -- convert first (probe98 lesson).
function DumpTree([string]$pspath) {
  O ('  P98 TREE ' + $pspath)
  if (-not (TP $pspath)) { O '    <absent>'; return }
  O '    (self)'
    $ip = $null
    try { $ip = Get-ItemProperty -LiteralPath $pspath -EA SilentlyContinue } catch { }
    $names = @()
    if ($null -ne $ip) { $names = @($ip.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) }
    if ($names.Count -eq 0) { O '      <no-values>' }
    foreach ($p in $names) {
      $tn = '<null>'
      if ($null -ne $p.Value) { $tn = Clean "$($p.Value.GetType().Name)" }
      O ('      VAL ' + (Clean $p.Name) + ' [' + $tn + '] = ' + (Redact $pspath $p.Name $p.Value))
    }
  foreach ($k in @(Get-ChildItem -LiteralPath $pspath -Recurse -EA SilentlyContinue)) {
    O ('    KEY ' + (Clean $k.Name))
    DumpKey (Drive $k.Name)
  }
}
function RegAdd([string]$pspath, [string]$name, [string]$kind, [string]$data) {
  # Logs its own line and leaves the code in $script:LastRegRc. Deliberately returns NOTHING: the caller must not
  # capture it, and `$null = RegAdd ...` would discard every log line this function prints -- the same output-swallow
  # trap that cost probe97 its PLACE rows (documented a third time here so nobody re-does it).
  $script:LastRegRc = -999
  if (SecretShape $pspath $name) { O ('    REG-REFUSE ' + $pspath + ' | ' + $name + ' (secret-shaped, never written)'); return }
  $real = $pspath -replace '(?i)^(HKLM|HKCU|HKCR|HKCC|HKU):\\', '$1\'
  # 'ADD' is the verb -- without it reg.exe answers "invalid parameter/option - '<the key name>'", which looks like a
  # path problem but is a missing argument (the %TEMP% harness build\scratch\t_p98_regexe_probe.ps1 caught it).
  $a = @('ADD', $real)
  if ($name -eq '') { $a += @('/ve') } else { $a += @('/v', $name) }
  $a += @('/t', $kind, '/d', $data, '/f')
  $r = Run $REG $a
  $back = $null
  # the unnamed value reads back under the property name '(default)', not '' -- without this the read-back of every
  # OneXAuthenticator / WFDProvPlugin / CLSID default value would look empty.
  $rn = $name
  if ($rn -eq '') { $rn = '(default)' }
  try { $back = RegV $pspath $rn } catch { }
  $shown = (Redact $pspath $name $back)
  if ($shown.Length -gt 200) { $shown = $shown.Substring(0, 200) + '...' }
  $script:LastRegRc = $r.rc
  O ('    REG-SET ' + $real + ' | ' + $rn + ' [' + $kind + '] rc=' + $r.rc + ' read-back=' + $shown +
     ' // ' + ((@($r.lines) | Select-Object -First 2) -join ' '))
}
# NOTE (the probe95/96/97 trap, keep it): callers MUST NOT assign this result -- assigning swallows every
# Write-Output line it emits. State travels in $script:WRun / $script:WIfn / $script:SExit instead.
$script:WRun = $false
$script:WIfn = -1
$script:SExit = ''
function TrySvc([string]$svc, [string]$tag, [string]$extra) {
  $s = Run $WIFI @('svc', 'start', $svc)
  $i = Wifi @('svc', 'info', $svc)
  $w = Run $WIFI @('svc', 'watch', $svc, '3000', 'start')
  O ('  P98 TRY[' + $svc + '][' + $tag + '] start-> rc=' + $s.rc + ' ' + (@($s.lines) -join ' // '))
  O ('  P98 TRY[' + $svc + '][' + $tag + '] info  ' + $i)
  foreach ($l in @($w.lines | Select-Object -First 8)) { O ('    | ' + $l) }
  $st = ''
  try { $st = [string](Get-Service -Name $svc -EA SilentlyContinue).Status } catch { }
  $script:WRun = (($i -match '(?i)state=RUNNING\(4\)|state=Running') -or ($st -eq 'Running'))
  $script:SExit = ''
  $all = (@($w.lines) -join ' ') + ' ' + $i
  if ($all -match 'exit=2148270086\(0x800C0006\)') { $script:SExit = '0x800C0006' }
  elseif ($all -match 'exit=(\d+)\(0x([0-9A-Fa-f]+)\)') { $script:SExit = '0x' + $Matches[2] }
  if ($extra -ne '') {
    $row = SvcRow $svc
    O ('  P98 TRY[' + $svc + '][' + $tag + '] row   ' + $row)
  }
}
function TryWlan([string]$tag) {
  TrySvc 'wlansvc' $tag 'row'
  $st = Wifi @('status')
  O ('  P98 TRY[wlan][' + $tag + '] wifi  ' + $st)
  $script:WIfn = -1
  if ($st -match 'interfaces=(\d+)') { $script:WIfn = [int]$Matches[1] }
}
if (-not ('Ldr98' -as [type])) {
  Add-Type -ErrorAction SilentlyContinue -Verbose:$false -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Ldr98 {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, uint flags);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool FreeLibrary(IntPtr h);
  public static string Try(string name) {
    IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0);
    if (h == IntPtr.Zero) { return "FAIL err=" + Marshal.GetLastWin32Error(); }
    string ok = "OK base=0x" + ((long)h).ToString("X");
    FreeLibrary(h);
    return ok;
  }
}
'@
}
function LL([string]$name) {
  try { return [Ldr98]::Try($name) } catch { return 'EXCEPTION ' + (Clean $_.Exception.Message) }
}
function FreeMB([string]$drive) {
  try {
    $d = New-Object IO.DriveInfo($drive)
    return ('' + [Math]::Round($d.AvailableFreeSpace / 1MB, 1))
  } catch { return '?' }
}

$SR = Root ''
$S32 = Join-Path $SR 'System32'
$WIFI = Join-Path $S32 'wifi.exe'
$REG = Join-Path $S32 'reg.exe'
$CANWRITE = ($Apply -and (($SR -match '(?i)^X:') -or $IDoit))
# On the ramdisk the drop folder is X:\p98. Anywhere else -- i.e. the host dry run, whose job is to prove the
# fetch / dump / RegAdd code paths before a PE ever sees them -- use a folder next to this script and refuse every
# write, so a host run stays read-only as far as Windows is concerned.
$DRY = Join-Path (Split-Path $PSCommandPath -Parent) 'p98_dryrun'
if ($SR -match '(?i)^X:') { $STAGE = 'X:\p98'; $BAK = 'X:\p98bak' }
else { $STAGE = Join-Path $DRY 'stage'; $BAK = Join-Path $DRY 'bak' }
function Sel([string]$k) { if ($Only -eq '') { return $true } return (@($Only -split ',') -contains $k) }

# ---- what the host has and the PE may not: providers named by registry value, with the exact X:-valid path ----
$X = 'X:\Windows\System32'
$PROV = @(
  @{ n = 'onex'; f = @('WcnEapAuthProxy.dll');
     v = @( @{ k = 'Parameters\OneXAuthenticator'; nm = ''; kind = 'REG_SZ'; data = ($X + '\WcnEapAuthProxy.dll') } ) },
  @{ n = 'wfd'; f = @('wfdprov.dll');
     v = @( @{ k = 'Parameters\WFDProvPlugin'; nm = ''; kind = 'REG_SZ'; data = ($X + '\wfdprov.dll') },
            @{ k = 'Parameters\WFDProvPlugin'; nm = 'DllEntryPoint'; kind = 'REG_SZ'; data = 'WFDProvGetInfo' } ) },
  @{ n = 'ie'; f = @('TetheringIeProvider.dll', 'WiFiDisplay.dll');
     v = @( @{ k = 'Parameters\VendorSpecificIEProviders\{02166b50-0459-44d9-9ec1-073431b7d9c9}'; nm = 'Path'; kind = 'REG_SZ'; data = ($X + '\TetheringIeProvider.dll') },
            @{ k = 'Parameters\VendorSpecificIEProviders\{B7D94B4D-5DB1-4E70-B5C3-DD003EEEBE66}'; nm = 'Path'; kind = 'REG_SZ'; data = ($X + '\WiFiDisplay.dll') },
            @{ k = 'Parameters\VendorSpecificIEProviders\{00666BD7-8CB1-4A35-A3B7-83BA6D5BBEE3}'; nm = 'Path'; kind = 'REG_SZ'; data = ($X + '\WlanSvc.dll') },
            @{ k = 'Parameters\VendorSpecificIEProviders\{4D50EE01-EEE0-4E5D-9A41-2F5F32044192}'; nm = 'Path'; kind = 'REG_SZ'; data = ($X + '\WlanSvc.dll') } ) },
  @{ n = 'ics'; f = @('hnetcfgclient.dll');
     v = @( @{ k = 'Parameters\ComInterfaceProviders'; nm = 'IHNetIcsSettings'; kind = 'REG_SZ'; data = '{46C166AA-3108-11D4-9348-00C04F8EEB71}' },
            @{ k = 'SOFTWARE-CLSID'; nm = ''; kind = 'REG_SZ'; data = ($X + '\hnetcfgclient.dll') },
            @{ k = 'SOFTWARE-CLSID'; nm = 'ThreadingModel'; kind = 'REG_SZ'; data = 'Both' } ) },
  @{ n = 'priv'; f = @();
     v = @( @{ k = ''; nm = 'RequiredPrivileges'; kind = 'REG_MULTI_SZ';
              data = 'SeChangeNotifyPrivilege\0SeImpersonatePrivilege\0SeAuditPrivilege\0SeTcbPrivilege\0SeDebugPrivilege\0SeLoadDriverPrivilege' } ) },
  @{ n = 'deps'; f = @();
     v = @( @{ k = ''; nm = 'DependOnService'; kind = 'REG_MULTI_SZ'; data = 'nativewifip\0RpcSs\0Ndisuio\0wcmsvc' } ) },
  @{ n = 'misc'; f = @();
     v = @( @{ k = 'Parameters\WfdInterfaceManagement'; nm = 'DisablePhyTypeRestriction'; kind = 'REG_DWORD'; data = '0' },
            @{ k = 'Parameters\WfdInterfaceManagement'; nm = 'DisableSetActiveWfdMgrSidCheck'; kind = 'REG_DWORD'; data = '0' },
            @{ k = 'Parameters\EapolKeyIpAddress'; nm = 'LocalAddress'; kind = 'REG_SZ'; data = '192.168.137.1' },
            @{ k = 'Parameters\EapolKeyIpAddress'; nm = 'PrefixLength'; kind = 'REG_DWORD'; data = '24' },
            @{ k = 'VirtualizationManager'; nm = 'WindowsPushNotificationPlatformClsid'; kind = 'REG_SZ'; data = '0C9281F9-6DA1-4006-8729-DE6E6B61581C' } ) },
  @{ n = 'retry'; f = @(); v = @() }
)
$WLANBASE = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$CLSIDPATH = 'HKLM:\SOFTWARE\Classes\CLSID\{46C166AA-3108-11D4-9348-00C04F8EEB71}\InProcServer32'

O ('P98 START ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' root=' + $SR + ' base=' + $Base +
   ' apply=' + $CANWRITE + ' readapplyflag=' + [bool]$Apply + ' reg=' + $REG + ' reg-exists=' + (TP $REG) +
   ' freeMB=' + (FreeMB (Split-Path $SR -Qualifier)) + ' only=[' + $Only + ']')
O ('  P98 STACK ' + (StackLine))
O ('  P98 ROW   ' + (SvcRow 'wlansvc'))
O ('  P98 ROW   ' + (SvcRow 'wcmsvc'))

# ---------- 0 this PE's own shape, with values ----------
if (Sel 'dump') {
O '== 0 what THIS image has under the two service keys (values printed, secret shapes withheld) =='
DumpTree $WLANBASE
DumpTree ('HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc')
O ('  P98 FILES providers in System32:')
foreach ($n in @('WcnEapAuthProxy.dll', 'wfdprov.dll', 'TetheringIeProvider.dll', 'WiFiDisplay.dll',
                 'hnetcfgclient.dll', 'WlanSvc.dll', 'wlansvcpal.dll', 'wcmcsp.dll', 'WcnEapPeerProxy.dll',
                 'eappsvc.dll', 'onex.dll')) {
  O ('    P98 FILE ' + $n + ' = ' + (TP (Join-Path $S32 $n)) + ' ' + (FV (Join-Path $S32 $n)))
}
}

# ---------- 1 fetch ----------
if (Sel 'fetch') {
O '== 1 fetch: pull the five registry-named provider files into X:\p98 and verify every byte count =='
if (-not (TP $STAGE)) { try { New-Item -ItemType Directory -Path $STAGE -Force -EA Stop | Out-Null } catch { O ('  MKDIR ' + $STAGE + ' FAIL ' + (Clean $_.Exception.Message)) } }
$man = @()
$raw = $null
try {
  # the static server answers octet-stream, so .Content is a Byte[] here -- decode before splitting (probe97).
  $raw = (Invoke-WebRequest -Uri ($Base + 'manifest98.txt') -UseBasicParsing -TimeoutSec 20).Content
  $txt = [string]$raw
  if ($raw -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($raw) }
  elseif ($raw -is [Object[]]) { $txt = [string]($raw -join '') }
  $man = @($txt -split "`r?`n")
} catch { O ('  MANIFEST FAIL ' + (Clean $_.Exception.Message)) }
$tn = '<none>'
try { if ($null -ne $raw) { $tn = [string]$raw.GetType().Name } } catch { }
O ('  P98 MANIFEST98 type=' + $tn + ' lines=' + @($man).Count)
$script:EXP = @{}
foreach ($l in @($man)) {
  $t = (Clean "$l")
  if ($t -eq '') { continue }
  $p = @($t -split '\s+')
  if ($p.Count -lt 2) { continue }
  $script:EXP[$p[0].ToLower()] = [int64]$p[1]
  O ('  P98 WANT ' + $p[0] + ' size=' + $p[1] + ' ' + ($p[2]))
}
foreach ($n in @($script:EXP.Keys | Sort-Object)) {
  $dst = Join-Path $STAGE $n
  $ok = $false
  for ($t = 1; $t -le 2 -and -not $ok; $t++) {
    try { Invoke-WebRequest -Uri ($Base + $n) -OutFile $dst -UseBasicParsing -TimeoutSec 60 | Out-Null; $ok = $true }
    catch { O ('  P98 GET ' + $n + ' try' + $t + ' FAIL ' + (Clean $_.Exception.Message)) }
  }
  if (-not $ok) { continue }
  $sz = [int64]0
  try { $sz = (Get-Item -LiteralPath $dst).Length } catch { }
  $ver = ''
  try { $ver = (Clean "$((Get-Item -LiteralPath $dst).VersionInfo.FileVersion)") } catch { }
  $mark = 'SIZE-FAIL'
  if ($sz -eq [int64]$script:EXP[$n.ToLower()]) { $mark = 'ok' }
  O ('  P98 GOT ' + $n + ' bytes=' + $sz + ' expect=' + $script:EXP[$n.ToLower()] + ' ' + $mark + ' ver=' + $ver)
}
O '  P98 LL-BEFORE (by name, the way wlansvc LoadLibrarys the value path):'
foreach ($n in @('WcnEapAuthProxy.dll', 'wfdprov.dll', 'TetheringIeProvider.dll', 'WiFiDisplay.dll',
                 'hnetcfgclient.dll', 'netshell.dll', 'hnetcfg.dll')) {
  O ('    P98 LL ' + $n + ' = ' + (LL $n))
}
}

# ---------- 2 baseline: BOTH services ----------
if (Sel 'base') {
O '== 2 baseline: one start attempt each for wlansvc and wcmsvc with nothing touched =='
TryWlan 'baseline'
TrySvc 'wcmsvc' 'baseline' 'row'
O ('  P98 BASELINE wlansvc-exit=' + $script:SExit + ' (last watched service) running=' + $script:WRun)
# Test scaffolding, host side only: on the build machine wlansvc genuinely runs, so a read-only run would skip the
# whole ladder and the WOULDRUN branch would never be exercised before the PE sees it. -ForceNoRun forces that branch.
if ($ForceNoRun) { $script:WRun = $false; O '  P98 FORCENORUN set by -ForceNoRun: the ladder below walks the read-only branch' }
}

# ---------- 3 ladder ----------
$res = @()
function Place([string]$name) {
  $srcF = Join-Path $STAGE $name
  if (-not (TP $srcF)) { O ('    PLACE ' + $name + ' SKIP not fetched'); return $false }
  $dstF = Join-Path $S32 $name
  if (-not (TP $BAK)) { try { New-Item -ItemType Directory -Path $BAK -Force -EA Stop | Out-Null } catch { } }
  if (TP $dstF) {
    $bk = Join-Path $BAK $name
    if (-not (TP $bk)) {
      try { Copy-Item -LiteralPath $dstF -Destination $bk -Force -EA Stop; O ('    BACKUP ' + $name + ' -> ' + $bk) }
      catch { O ('    BACKUP ' + $name + ' FAIL ' + (Clean $_.Exception.Message)); return $false }
    }
  }
  try {
    Copy-Item -LiteralPath $srcF -Destination $dstF -Force -EA Stop
    O ('    PLACE ' + $name + ' -> ' + $dstF + ' bytes=' + (Get-Item -LiteralPath $dstF).Length + ' ver=' + (FV $dstF))
    return $true
  } catch { O ('    PLACE ' + $name + ' FAIL ' + (Clean $_.Exception.Message)); return $false }
}
function SetValues([object[]]$vals) {
  foreach ($v in @($vals)) {
    if ($v.k -eq 'SOFTWARE-CLSID') {
      RegAdd $CLSIDPATH $v.nm $v.kind $v.data
      continue
    }
    $p = $WLANBASE
    if ($v.k -ne '') { $p = $WLANBASE + '\' + $v.k }
    RegAdd $p $v.nm $v.kind $v.data
  }
}
foreach ($g in $PROV) {
  if (Sel $g.n) {
    if ($script:WRun) { O ('  P98 RUNG ' + $g.n + ' skipped, wlansvc is already Running'); $res += @{ rung = $g.n; files = (@($g.f) -join ','); vals = @($g.v).Count; running = $true; ifn = $script:WIfn }; continue }
    O ('  P98 RUNG ' + $g.n)
    if ($CANWRITE) {
      # NOT `[void](Place $f)` -- that discards Place's whole output stream (the probe97 field run lost its
      # PLACE/BACKUP rows that way). Capture and re-emit.
      foreach ($f in @($g.f)) { @(Place $f) | ForEach-Object { O ('      ' + $_) } }
      foreach ($f in @($g.f)) { O ('    P98 LL ' + $f + ' = ' + (LL $f)) }
      SetValues @($g.v)
      if ($g.n -eq 'deps') {
        TrySvc 'wcmsvc' ('pre-' + $g.n) ''
        O ('    P98 wcmsvc after pre-start: ' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status))
      }
      TryWlan $g.n
      if ($g.n -eq 'ics') { O ('    P98 LL hnetcfgclient after = ' + (LL 'hnetcfgclient.dll')) }
      $res += @{ rung = $g.n; files = (@($g.f) -join ','); vals = @($g.v).Count; running = $script:WRun; ifn = $script:WIfn }
    } else {
      if ($Apply) { O '    P98 SKIP-WRITE: SystemRoot is not the ramdisk and -IDoit was not given.' }
      O ('    P98 read-only: would place [' + (@($g.f) -join ',') + '] and set ' + @($g.v).Count + ' value(s):')
      foreach ($v in @($g.v)) {
        $p = $WLANBASE
        if ($v.k -eq 'SOFTWARE-CLSID') { $p = $CLSIDPATH }
        elseif ($v.k -ne '') { $p = $WLANBASE + '\' + $v.k }
        $dn = $v.nm
        if ($dn -eq '') { $dn = '(default)' }
        O ('      WOULD-REG ' + (Clean $p) + ' | ' + $dn + ' [' + $v.kind + '] = ' + $v.data)
      }
      $res += @{ rung = ('WOULDRUN:' + $g.n); files = (@($g.f) -join ','); vals = @($g.v).Count; running = $false; ifn = -1 }
    }
  }
}
foreach ($r in $res) {
  O ('  P98 LADDER ' + $r.rung + ' files=[' + $r.files + '] vals=' + $r.vals + ' running=' + $r.running + ' ifn=' + $r.ifn)
}

# ---------- 4 verdict ----------
O '== 4 verdict =='
$inS32 = @()
foreach ($n in @('WcnEapAuthProxy.dll', 'wfdprov.dll', 'TetheringIeProvider.dll', 'WiFiDisplay.dll', 'hnetcfgclient.dll')) {
  if (TP (Join-Path $S32 $n)) { $inS32 += $n }
}
$outcome = 'wlansvc-still-dies'
if ($script:WRun) { $outcome = 'wlansvc-running' }
O ('  P98 LL-AFTER: onex=' + (LL 'WcnEapAuthProxy.dll') + ' wfd=' + (LL 'wfdprov.dll') +
   ' tether=' + (LL 'TetheringIeProvider.dll') + ' wfdi=' + (LL 'WiFiDisplay.dll') +
   ' ics=' + (LL 'hnetcfgclient.dll'))
O ('  P98 VERDICT outcome=' + $outcome + ' apply=' + [bool]$CANWRITE +
   ' now-in-system32=[' + ($inS32 -join ',') + ']' +
   ' backups=' + (@(Get-ChildItem -LiteralPath $BAK -File -EA SilentlyContinue).Count) +
   ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
   ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status) +
   ' ifn=' + $script:WIfn + ' last-exit=' + $script:SExit)
O '  BAKE-ITEMS (what a rung proved missing; wifi-inject should carry the files AND these values):'
foreach ($g in $PROV) {
  foreach ($f in @($g.f)) {
    O ('    file ' + $f + ' staged=' + (TP (Join-Path $STAGE $f)) + ' pe-now=' + (TP (Join-Path $S32 $f)) +
       ' ver=' + (FV (Join-Path $S32 $f)))
  }
  foreach ($v in @($g.v)) {
    $p = 'SYSTEM\CurrentControlSet\Services\wlansvc'
    if ($v.k -eq 'SOFTWARE-CLSID') { $p = 'SOFTWARE\Classes\CLSID\{46C166AA-3108-11D4-9348-00C04F8EEB71}\InProcServer32' }
    elseif ($v.k -ne '') { $p = $p + '\' + $v.k }
    $nm = $v.nm
    if ($nm -eq '') { $nm = '(default)' }
    O ('    reg  ' + $p + ' | ' + $nm + ' [' + $v.kind + '] = ' + $v.data)
  }
}
O ('    NOTE the paths above are X:-valid for the running ramdisk; a bake must keep them X:-absolute or use the' +
   ' image systemroot the same way wifi-inject already rewrites ImagePath/ServiceDll.')
O ('    NOTE HostedNetworkSettings / EncryptedSettings / Security / profile keys are deliberately never copied:' +
   ' they hold per-machine WiFi key material.')
O ('P98 LOGTIME ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
O 'P98 DONE'
