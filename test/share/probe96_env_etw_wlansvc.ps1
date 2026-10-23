# probe96 -- wlansvc returns 0x800C0006 inside its own init (probe95, this box): what object is missing?
#
# Where probe95 left it (build\scratch\p95_apply3_1011.txt, 2026-10-11 14:20, same PE):
#   * driver stack is up at boot with no manual step: nativewifip/wdiwifi/vwifibus/vwififlt/Ndisuio/NSI all Running;
#   * the WDI/IHV hookup on the AX211 devnode is COMPLETE (Ndi\IHVExtensions\ExtensibilityDLL ->
#     DriverStore\...\netwtw6e.inf_amd64_5433b0cac0a04d0e\IntelIHVRouter14.dll, wifi.exe dllload -> LoadLibraryEx OK,
#     GetProcAddress(ServiceMain) OK, *WdiRscIPv4/6 registered);
#   * BFE is baked and RUNNING (so the FWP/BFE theory is dead -- and FWP_E_* codes are 0x8032xxxx, not 0x800Cxxxx);
#   * DECISIVE: with the WLAN devnode disabled (pnputil rc=0, cfgflags=1, wdiwifi/vwifibus Stopped) wlansvc still
#     self-exits in ~120ms with the same exit=2148270086(0x800C0006) -> the failure is NOT adapter- or
#     IHV-session-driven. It happens before wlansvc enumerates any interface.
#   NOTE the honest half-step: that rung excludes the ADAPTER side of WDI. It does NOT exclude the WDI service
#   layer, because WdiServiceHost/WdiSystemHost keys are absent here (1060) and services.exe freezes its service
#   database at boot, so those two can only be proven after an offline bake + reboot. They stay bake items.
#
# What probe94/95 already fixed live with no change in the code: the 9 wlansvc\Parameters subkeys, the whole
# HKLM\SOFTWARE\Microsoft\Wlansvc + WcmSvc trees, ProgramData\Microsoft\Wlansvc\Profiles\Interfaces, wcmsvc Csps,
# netsh wlancfg registration, Ndisuio start, devnode restart, mpssvc/BFE, the driver stack.
#
# 0x800C0006 is HRESULT facility 12 with code 6. build\gomod\golang.org\x\sys\windows\zerrors_windows.go:6601 names
# exactly that value INET_E_OBJECT_NOT_FOUND, and every community report of this wlansvc code reads "the system
# cannot find the specified object" -- i.e. a NAME/PATH that resolves to nothing, not a crash. probe86 ruled out a
# crash (no dump, no WER). So this probe chases the two ways a name can resolve to nothing in a RAMDISK image:
#
#   (A) the machine environment / known-folder layer. t_pe_quickcrypto.ps1 (build\scratch\pq_pe_1011.txt, THIS PE,
#       13:59) measured the process block a service-shaped process actually gets:
#         PQ ENV ProgramData= ALLUSERS= public=      <- ALL THREE EMPTY
#       while the directories themselves exist (X:\ProgramData\Microsoft\Wlansvc\Profiles, ServiceProfiles\
#       LocalService + NetworkService with NTUSER.DAT, System32\Microsoft\Protect\S-1-5-18, catroot2 with a live
#       ESE store). If %ProgramData%/%ALLUSERSPROFILE% are not in the environment block wlansvc inherits, every
#       path it builds by expansion is empty => "object not found", and it fails before touching an adapter,
#       exactly as measured. Section 1 reads SM\Environment, HKU\.DEFAULT\Environment (LocalSystem's profile hive),
#       the service key's own Environment value and the Shell Folders keys, and -Apply rung env-default writes the
#       three values into HKU\.DEFAULT\Environment (that hive is the one CreateEnvironmentBlock consults for the
#       LocalSystem account, and the SCM builds the child's block per start, so unlike a new SERVICE KEY this can
#       take effect on this boot).
#   (B) the crypto/profile-object layer. ProgramData\Microsoft\Crypto\RSA\MachineKeys and \Crypto\Keys EXIST BUT
#       ARE EMPTY, and \Crypto\OID and \SystemCertificates DO NOT EXIST, while wlansvc delay-loads AUTHZ, bcrypt,
#       CRYPT32 and CRYPTSP (probe82) and encrypts profile passwords through DPAPI. Sections 2 measures the LSA /
#       crypto shape; -Apply rung crypto-dirs creates the missing stores and retries.
#   (C) whatever the image itself already wrote down: section 3 reads the System/Application logs and every
#       WLAN/Wdi/Ndis/Firewall channel that exists in this PE (base64-UTF8 so a localized string survives the
#       ASCII remote channel), and -Apply rung enable-channels turns the channels on, clears them, starts wlansvc
#       and dumps what it recorded. This is the measurement most likely to name the object outright.
#   (D) the six delay-load names probe82 flagged as unresolvable here (ext-ms-win-networking-wlanstorage,
#       ext-ms-win-wlan-grouppolicy, ext-ms-win-devmgmt-policy, deviceassociation.dll, IpNatHlpClient.dll,
#       ext-ms-win-shell-embeddedmode): section 4 LoadLibrarys each the way the loader would and says which ones
#       have no host DLL in this image.
#   (E) the version skew probe95 counted but could not judge: the PE is 26100.1 and the borrowed WiFi user-mode
#       stack is 19041 (host is Win10 19041.4522, wifi-inject.ps1:460 -- ADK ships no WinPE WiFi package).
#       Section 5 lists both sides per file so a same-build borrow can be decided on facts.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit
# overrides that guard deliberately. Writes stay inside HKU\.DEFAULT\Environment, ProgramData stores and ETW
# channel enablement; no service key is deleted, no hive is unloaded, the wired Realtek adapter carrying this ssh
# session is never touched, and nothing is written to the ISO, to D:\winpe_build or to a customer disk. The
# ramdisk is restored by rebooting.
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
    ' Env=' + (@(RegV $p 'Environment') -join ';') +
    ' SidType=' + (HexVal (RegV $p 'ServiceSidType')) +
    ' State=' + $st + ' Image=[' + (Clean $img) + '] Dll=[' + (Clean $dll) + '] Main=[' + $main + ']' +
    ' subs=' + ((SubNames $p) -join ','))
}
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
# A localized event string must survive an ASCII-only remote channel: emit base64(UTF8) next to the ASCII form.
function MsgB64([string]$s) {
  if ([string]::IsNullOrEmpty($s)) { return '' }
  $t = $s
  if ($t.Length -gt 420) { $t = $t.Substring(0, 420) + '...' }
  try { return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)) } catch { return '<b64-fail>' }
}
# HKU:\.DEFAULT may not be present as a drive everywhere; never let a path probe print a red error.
function TP([string]$p) {
  try { return [bool](Test-Path -LiteralPath $p -EA SilentlyContinue) } catch { return $false }
}
# LogFilePath / MessageFile arrive with %SystemRoot% still in them; expand before testing.
function ExPath([string]$p) {
  if ([string]::IsNullOrEmpty($p)) { return '' }
  $s = $p -replace '(?i)%systemroot%', $SR
  $s = $s -replace '(?i)%sysdir%', $S32
  $s = $s -replace '(?i)%programdata%', $PD
  return $s
}
function EventLine([string]$tag, [object]$e) {
  $msg = ''
  try { $msg = [string]$e.Message } catch { $msg = '<no text>' }
  $tm = ''
  try { $tm = $e.TimeCreated.ToString('MM-dd HH:mm:ss') } catch { }
  return ('  P96 ' + $tag + ' ' + $tm + ' prov=[' + (Clean "$($e.ProviderName)") + '] id=' + $e.Id +
    ' lvl=' + $e.Level + ' b64len=' + $msg.Length + ' b64=' + (MsgB64 $msg))
}
# NOTE (the probe95 trap, keep it): the caller MUST NOT assign TryWlan's result -- assigning swallows every
# Write-Output line it emits. State travels in $script:WRun / $script:WIfn instead.
$script:WRun = $false
$script:WIfn = -1
function TryWlan([string]$tag) {
  $s = Run $WIFI @('svc', 'start', 'wlansvc')
  $i = Wifi @('svc', 'info', 'wlansvc')
  $w = Run $WIFI @('svc', 'watch', 'wlansvc', '3000', 'start')
  $st = Wifi @('status'); $row = SvcRow 'wlansvc'
  O ('  P96 TRY[' + $tag + '] start-> rc=' + $s.rc + ' ' + (@($s.lines) -join ' // '))
  O ('  P96 TRY[' + $tag + '] info  ' + $i)
  foreach ($l in @($w.lines | Select-Object -First 10)) { O ('    | ' + $l) }
  O ('  P96 TRY[' + $tag + '] row   ' + $row)
  O ('  P96 TRY[' + $tag + '] wifi  ' + $st)
  $svcSt = ''
  try { $svcSt = [string](Get-Service -Name wlansvc -EA SilentlyContinue).Status } catch { }
  $script:WRun = (($i -match '(?i)state=RUNNING\(4\)|state=Running') -or ($svcSt -eq 'Running'))
  $script:WIfn = -1
  if ($st -match 'interfaces=(\d+)') { $script:WIfn = [int]$Matches[1] }
}

$SR = Root ''
$S32 = Join-Path $SR 'System32'
$WIFI = Join-Path $S32 'wifi.exe'
$we = Join-Path $S32 'wevtutil.exe'
$want = @()
$PD = Join-Path (Split-Path $SR -Parent) 'ProgramData'
if (-not (Test-Path -LiteralPath $PD)) { $PD = 'X:\ProgramData' }
$CANWRITE = ($Apply -and (($SR -match '(?i)^X:') -or $IDoit))
function Sel([string]$k) { if ($Only -eq '') { return $true } return (@($Only -split ',') -contains $k) }

O ('P96 START ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' root=' + $SR + ' programdata=' + $PD +
   ' apply=' + $CANWRITE + ' readapplyflag=' + [bool]$Apply + ' only=[' + $Only + ']')
O ('  P96 STACK ' + (StackLine))

# ---------- 1 the environment block a LocalSystem process really gets in this image ----------
if (Sel 'env') {
O '== 1 machine env / known folders: the three variables that came back EMPTY in the quick check =='
$ci = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
O ('  P96 BUILD ProductName=[' + (Clean "$($ci.ProductName)") + '] CurrentVersion=' + $ci.CurrentVersion +
   '.' + $ci.CurrentBuildNumber + ' CurrentBuild=' + (Clean "$($ci.CurrentBuild)") + ' UBR=' + $ci.UBR +
   ' BuildLab=[' + (Clean "$($ci.BuildLabEx)") + '] SystemRoot=' + $SR)
foreach ($f in @('svchost.exe', 'services.exe', 'wininit.exe', 'smss.exe', 'lsass.exe', 'winlogon.exe', 'wevtutil.exe', 'net.exe', 'sc.exe', 'reg.exe', 'icacls.exe', 'whoami.exe', 'wmic.exe', 'drvload.exe', 'pnputil.exe')) {
  O ('  P96 EXE ' + $f + ' ' + (FV (Join-Path $S32 $f)) + ' exists=' + (Test-Path -LiteralPath (Join-Path $S32 $f)))
}
foreach ($n in @('lsass', 'services', 'svchost', 'winlogon', 'csrss', 'smss', 'wmiprvse', 'LogonUI', 'dwm', 'explorer')) {
  O ('  P96 PROC ' + $n + ' count=' + (@(Get-Process -Name $n -EA SilentlyContinue).Count))
}
$sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
O ('  P96 SM-ENV present=' + (Test-Path -LiteralPath $sm) + ' values=' + ((ValNames $sm) -join ','))
foreach ($v in @('ALLUSERSPROFILE', 'APPDATA', 'CommonProgramFiles', 'DriverData', 'LOCALAPPDATA', 'OS',
                 'ProgramData', 'ProgramFiles', 'PUBLIC', 'SystemRoot', 'TEMP', 'TMP', 'WINDIR', 'Path')) {
  $val = RegV $sm $v
  if ($null -eq $val) { $val = '<absent>' }
  O ('  P96 SM-ENV-VAL ' + $v + '=[' + (Clean "$val") + ']')
}
$de = 'HKU:\.DEFAULT\Environment'
O ('  P96 DEFAULT-ENV present=' + (TP $de) + ' values=' + ((ValNames $de) -join ','))
foreach ($v in @('ALLUSERSPROFILE', 'ProgramData', 'PUBLIC', 'TEMP', 'TMP')) {
  O ('  P96 DEFAULT-ENV-VAL ' + $v + '=[' + (Clean "$(RegV $de $v)") + ']')
}
O ('  P96 PROC-ENV ProgramData=[' + $env:ProgramData + '] ALLUSERSPROFILE=[' + $env:ALLUSERSPROFILE +
   '] PUBLIC=[' + $env:PUBLIC + '] TEMP=[' + $env:TEMP + '] userprofile=[' + $env:USERPROFILE + ']')
try { O ('  P96 KNOWNFOLDER CommonAppData=[' + ([Environment]::GetFolderPath('CommonApplicationData')) + ']') }
catch { O ('  P96 KNOWNFOLDER CommonAppData FAIL ' + (Clean $_.Exception.Message)) }
try { O ('  P96 KNOWNFOLDER CommonProgramFiles=[' + ([Environment]::GetFolderPath('CommonProgramFiles')) + ']') }
catch { O ('  P96 KNOWNFOLDER CommonProgramFiles FAIL ' + (Clean $_.Exception.Message)) }
foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
                 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList')) {
  O ('  P96 FOLDER-KEY ' + $k + ' present=' + (Test-Path -LiteralPath $k) + ' values=' + ((ValNames $k) -join ','))
}
$shf = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
foreach ($v in @('Common AppData', 'Common Programs', 'Common Start Menu', 'Common Documents', 'Common Templates', 'Common Desktop')) {
  O ('  P96 SHELLFOLDER ' + $v + '=[' + (Clean "$(RegV $shf $v)") + ']')
}
O ('  P96 PROFILELIST ProfilesDirectory=[' + (Clean "$(RegV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' 'ProfilesDirectory')") + '] Default=[' + (Clean "$(RegV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' 'Default')") + '] keys=' + ((SubNames 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') -join ','))
}

# ---------- 2 LSA / crypto / profile objects (the facility-12 "object not found" suspects) ----------
if (Sel 'crypto') {
O '== 2 the object stores a service init can fail to find: LSA, cryptsvc, machine key sets, cert stores =='
foreach ($s in @('cryptsvc', 'KeyIso', 'SamSs', 'Seclogon', 'TBS', 'RpcEptMapper', 'EFS', 'Dnscache', 'nsiproxy')) {
  O ('  P96 ROW ' + (SvcRow $s))
}
foreach ($s in @('cryptsvc', 'KeyIso', 'SamSs')) { O ('  P96 SCM ' + $s + ' -> ' + (Wifi @('svc', 'info', $s))) }
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
O ('  P96 LSA values=' + ((ValNames $lsa) -join ','))
foreach ($v in @('Security Packages', 'Notification Packages', 'Authentication Packages', 'LsaCfgFlags', 'FIPSAlgorithmPolicy')) {
  O ('  P96 LSA-VAL ' + $v + '=[' + (@(RegV $lsa $v) -join ';') + ']')
}
foreach ($f in @('lsasrv.dll', 'msv1_0.dll', 'schannel.dll', 'kerberos.dll', 'wdigest.dll', 'tspkg.dll',
                 'pku2u.dll', 'secur32.dll', 'bcrypt.dll', 'crypt32.dll', 'ncrypt.dll', 'authz.dll',
                 'cryptnet.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll', 'wlanapi.dll', 'wlanutil.dll',
                 'wlansvc.dll', 'eappprxy.dll')) {
  O ('  P96 DLL ' + $f + ' ' + (FV (Join-Path $S32 $f)))
}
foreach ($p in @((Join-Path $PD 'Microsoft\Crypto'), (Join-Path $PD 'Microsoft\Crypto\RSA'),
                 (Join-Path $PD 'Microsoft\Crypto\RSA\MachineKeys'), (Join-Path $PD 'Microsoft\Crypto\Keys'),
                 (Join-Path $PD 'Microsoft\Crypto\OID'), (Join-Path $PD 'Microsoft\SystemCertificates'),
                 (Join-Path $PD 'Microsoft\SystemCertificates\Root'), (Join-Path $PD 'Microsoft\SystemCertificates\CA'),
                 (Join-Path $PD 'Microsoft\SystemCertificates\My'), (Join-Path $PD 'Microsoft\Crypto\PCPKSP'),
                 (Join-Path $S32 'catroot'), (Join-Path $S32 'catroot2'),
                 (Join-Path $S32 'Microsoft\Protect'), (Join-Path $S32 'Microsoft\Protect\S-1-5-18'),
                 (Join-Path $PD 'Microsoft\Wlansvc\Profiles\Interfaces'),
                 (Join-Path $PD 'Microsoft\Windows\WER'), (Join-Path $PD 'Microsoft\Network\Connections'),
                 (Join-Path $SR 'ServiceProfiles\LocalService\AppData\Roaming'),
                 (Join-Path $SR 'ServiceProfiles\NetworkService\AppData\Roaming'))) {
  $e = TP $p
  $kids = ''
  if ($e) { $kids = ' kids=' + (@(Get-ChildItem -LiteralPath $p -Force -EA SilentlyContinue).Count) +
                   ' [' + (((@(Get-ChildItem -LiteralPath $p -Force -EA SilentlyContinue | Select-Object -First 8).PSChildName)) -join ',') + ']' }
  O ('  P96 DIR ' + $p + ' exists=' + $e + $kids)
}
foreach ($rk in @('HKLM:\SOFTWARE\Microsoft\Cryptography',
                  'HKLM:\SOFTWARE\Microsoft\Cryptography\Providers',
                  'HKLM:\SOFTWARE\Microsoft\Cryptography\OID',
                  'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais',
                  'HKLM:\SOFTWARE\Microsoft\Cryptography\RNG')) {
  O ('  P96 CRYPTO-REG ' + $rk + ' present=' + (Test-Path -LiteralPath $rk) + ' values=' + ((ValNames $rk) -join ','))
}
O ('  P96 MACHINEGUID [' + (Clean "$(RegV 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')") + ']')
foreach ($d in @((Join-Path $PD 'Microsoft\Crypto\RSA\MachineKeys'), (Join-Path $PD 'Microsoft\Crypto\Keys'))) {
  if (Test-Path -LiteralPath $d) {
    try {
      $ac = Get-Acl -LiteralPath $d
      O ('  P96 ACL ' + $d + ' owner=[' + (Clean $ac.Owner) + '] rules=' + (@($ac.Access).Count) +
         ' sddl-len=' + $ac.Sddl.Length)
    } catch { O ('  P96 ACL ' + $d + ' FAIL ' + (Clean $_.Exception.Message)) }
  }
}
}

# ---------- 3 what the image already wrote down ----------
if (Sel 'evt') {
O '== 3 event forensics: which channels exist here, and what the System log says about wlansvc =='
O ('  P96 WEVTUTIL exists=' + (TP $we))
$logs = @()
try { $logs = @(Get-WinEvent -ListLog * -EA SilentlyContinue) }
catch { O ('  P96 LISTLOG FAIL ' + (Clean $_.Exception.Message)) }
O ('  P96 LOG-COUNT ' + $logs.Count + ' names=[' + ((@($logs | ForEach-Object { $_.LogName }) | Select-Object -First 40) -join ',') + ']')
$want = @($logs | Where-Object { $_.LogName -match '(?i)wlan|wdi|ihv|ndis|autoconf|firewall|mpssvc|bfe|dhcp|dns|netpro|nla' })
O ('  P96 LOG-WANT count=' + $want.Count)
foreach ($l in $want) {
  $fp = ''
  try { $fp = [string]$l.LogFilePath } catch { }
  $xp = ExPath $fp
  O ('  P96 LOG ' + $l.LogName + ' enabled=' + $l.IsEnabled + ' type=' + $l.LogType + ' iso=' + $l.IsolationType +
     ' records=' + $l.RecordCount + ' file=[' + (Clean $xp) + '] fileExists=' + (TP $xp))
}
$pkPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers'
$pk = @(Get-ChildItem -LiteralPath $pkPath -EA SilentlyContinue)
O ('  P96 PUBLISHERS total=' + $pk.Count)
foreach ($p in $pk) {
  $pn = ''
  try { $pn = [string](Get-Item -LiteralPath $p.PSPath -EA SilentlyContinue).GetValue('') } catch { }
  if ($pn -notmatch '(?i)wlan|wdi|ihv|ndis|autoconf|firewall|mpssvc|bfe') { continue }
  $sf = [string](RegV $p.PSPath 'SymbolFile')
  $mf = [string](RegV $p.PSPath 'MessageFile')
  $en = RegV $p.PSPath 'Enabled'
  $xp = ExPath $mf
  O ('  P96 PUB ' + $p.PSChildName + ' name=[' + (Clean $pn) + '] enabled=' + (HexVal $en) +
     ' msgFile=[' + (Clean $xp) + '] exists=' + (TP $xp))
}
# the same dump for every WLAN/Wdi channel that carries records: on the host this is the SUCCESS sequence
# wlansvc writes when it starts, here it is either empty (no manifest baked) or the failure record itself.
foreach ($l in $want) {
  $rc = -1
  try { $rc = [int]$l.RecordCount } catch { }
  if (-not $l.IsEnabled) { O ('  P96 CHAN ' + $l.LogName + ' disabled, records=' + $rc); continue }
  if ($rc -le 0) { O ('  P96 CHAN ' + $l.LogName + ' enabled but empty'); continue }
  try {
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $l.LogName } -MaxEvents 12 -EA SilentlyContinue)
    O ('  P96 CHAN ' + $l.LogName + ' records=' + $rc + ' dumping=' + $evs.Count)
    foreach ($e in $evs) { O (EventLine 'EVC' $e) }
  } catch { O ('  P96 CHAN ' + $l.LogName + ' FAIL ' + (Clean $_.Exception.Message)) }
}
foreach ($ln in @('System', 'Application')) {
  $n = 0
  try {
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $ln } -MaxEvents 40 -EA SilentlyContinue)
    $n = $evs.Count
    O ('  P96 ' + $ln.ToUpper() + ' newest=' + $n)
    foreach ($e in $evs) {
      if ($e.ProviderName -match '(?i)Service Control Manager|WLAN|Wdi|Ndis|Microsoft-Windows-TaskScheduler|Application Error|Windows Error Reporting|Dhcp-Client|Microsoft-Windows-Kernel-General') {
        O (EventLine ('EV-' + $ln.Substring(0, 3).ToUpper()) $e)
      }
    }
    $hits = @($evs | Where-Object { (Clean "$($_.Message)") -match '(?i)wlansvc|WLAN AutoConfig|AutoConfig' })
    O ('  P96 ' + $ln.ToUpper() + '-WLANSVC-MATCHES ' + $hits.Count)
    foreach ($e in $hits) { O (EventLine 'EVM' $e) }
  } catch { O ('  P96 ' + $ln.ToUpper() + '-READ FAIL ' + (Clean $_.Exception.Message)) }
}
}

# ---------- 4 the six delay-load names probe82 flagged, resolved the way the loader would ----------
if (Sel 'delay') {
O '== 4 delay loads: which of the names wlansvc reaches for lazily have no host DLL in this image =='
Add-Type -ErrorAction SilentlyContinue -Verbose:$false -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Ldr96 {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, uint flags);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr GetProcAddress(IntPtr h, string name);
  public static string Try(string name) {
    IntPtr h = LoadLibraryExW(name, IntPtr.Zero, 0);
    if (h == IntPtr.Zero) { return "FAIL err=" + Marshal.GetLastWin32Error(); }
    string ok = "OK base=0x" + ((long)h).ToString("X");
    FreeLibrary(h);
    return ok;
  }
}
'@
$delay = @('deviceassociation.dll', 'IpNatHlpClient.dll', 'ext-ms-win-networking-wlanstorage-l1-1-0.dll',
           'ext-ms-win-wlan-grouppolicy-l1-1-0.dll', 'ext-ms-win-devmgmt-policy-lcdl-1-1-0.dll',
           'ext-ms-win-shell-embeddedmode-l1-1-0.dll', 'wlanstorage.dll', 'wlgpclnt.dll', 'policymanager.dll',
           'embeddedmodesvcapi.dll', 'cmintegrator.dll', 'EventAggregation.dll', 'es.dll', 'authz.dll',
           'bcrypt.dll', 'cryptsp.dll', 'dsrole.dll', 'dhcpcsvc.dll', 'eappcfg.dll', 'devobj.dll', 'wcmapi.dll')
foreach ($d in $delay) {
  $line = ''
  try { $line = [Ldr96]::Try($d) } catch { $line = 'EXCEPTION ' + (Clean $_.Exception.Message) }
  O ('  P96 LL ' + $d + ' file=' + (Test-Path -LiteralPath (Join-Path $S32 $d)) + ' LoadLibrary=' + $line)
}
foreach ($s in @('WdiServiceHost', 'WdiSystemHost')) { O ('  P96 ROW ' + (SvcRow $s)) }
$wdiUsers = @()
foreach ($p in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue)) {
  $dll = [string](RegV ($p.PSPath + '\Parameters') 'ServiceDll')
  if ($dll -match '(?i)wdi\.dll') { $wdiUsers += ($p.PSChildName + '=' + (Clean $dll)) }
}
O ('  P96 WDI-DLL-USERS ' + (@($wdiUsers) -join ',') + ' (empty => nothing in this image hosts wdi.dll)')
O ('  P96 DLLLOAD wdi.dll ServiceMain -> ' + (Wifi @('dllload', (Join-Path $S32 'wdi.dll'), 'ServiceMain')))
foreach ($x in @('WdiGetServiceHostInterfaces', 'WdiInitializeServiceSansHost', 'WdiInstanceManagerCreateSession',
                 'WdiRegisterDHCPAPI', 'WdiUninitializeServiceSansHost')) {
  O ('  P96 DLLLOAD wdi.dll ' + $x + ' -> ' + (Wifi @('dllload', (Join-Path $S32 'wdi.dll'), $x)))
}
O ('  P96 DLLLOAD wlansvc.dll WlanSvcMain -> ' + (Wifi @('dllload', (Join-Path $S32 'wlansvc.dll'), 'WlanSvcMain')))
}

# ---------- 5 the borrow skew, file by file ----------
if (Sel 'skew') {
O '== 5 version skew: PE-native 26100 services against the 19041 WiFi stack borrowed off this host =='
foreach ($f in @('wlansvc.dll', 'wlanapi.dll', 'wlanext.exe', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll',
                 'wlanutil.dll', 'wlancfg.dll', 'dot3cfg.dll', 'wdi.dll', 'bfe.dll', 'mpssvc.dll', 'fwpuclnt.dll',
                 'nsisvc.dll', 'netprofmsvc.dll', 'nlaapi.dll', 'MobileNetworking.dll', 'OneX.dll', 'DNSAPI.dll',
                 'dhcpcsvc6.DLL', 'rpcrt4.dll', 'wldclient.dll', 'eappsvc.dll', 'ehostsvc.dll', 'onedot3m.dll')) {
  $p = Join-Path $S32 $f
  $v = FV $p
  $tag = ''
  if ($v -match '19041') { $tag = ' <- borrowed' }
  elseif ($v -match '26100') { $tag = ' <- PE-native' }
  O ('  P96 VER ' + $f + ' ' + $v + $tag)
}
foreach ($f in @('nwifi.sys', 'wdiwifi.sys', 'NdisImPlatform.sys', 'vwififlt.sys', 'vwifimp.sys', 'vwifibus.sys',
                 'ndisuio.sys')) {
  $p = Join-Path $S32 ('drivers\' + $f)
  O ('  P96 VER-SYS ' + $f + ' ' + (FV $p))
}
}

# ---------- 6 the ladder ----------
$res = @()
if ($CANWRITE) {
O '== 6 -Apply ladder: each rung writes one object this probe says may be missing, then retries wlansvc =='
$rungs = @('env-default', 'crypto-dirs', 'enable-channels', 'cryptsvc', 'keyiso', 'retry')
foreach ($rung in $rungs) {
  if ($script:WRun) { O ('  P96 RUNG ' + $rung + ' skipped, wlansvc is already Running'); continue }
  O ('  P96 RUNG ' + $rung)
  switch ($rung) {
    'env-default' {
      foreach ($kv in @(@('ALLUSERSPROFILE', $PD), @('ProgramData', $PD),
                        @('PUBLIC', (Join-Path (Split-Path $PD -Parent) 'Users\Public')),
                        @('TEMP', (Join-Path $SR 'TEMP')), @('TMP', (Join-Path $SR 'TEMP')))) {
        $r = Run (Join-Path $S32 'reg.exe') @('add', 'HKU\.DEFAULT\Environment', '/v', $kv[0], '/t', 'REG_EXPAND_SZ', '/d', $kv[1], '/f')
        O ('    REG-ADD HKU\.DEFAULT\Environment\' + $kv[0] + '=' + $kv[1] + ' rc=' + $r.rc + ' ' + (@($r.lines) -join ' '))
      }
      O ('    DEFAULT-ENV-AFTER values=' + ((ValNames 'HKU:\.DEFAULT\Environment') -join ','))
      TryWlan 'env-default'
    }
    'crypto-dirs' {
      foreach ($d in @((Join-Path $PD 'Microsoft\Crypto\OID'), (Join-Path $PD 'Microsoft\SystemCertificates'),
                       (Join-Path $PD 'Microsoft\SystemCertificates\Root'),
                       (Join-Path $PD 'Microsoft\SystemCertificates\CA'),
                       (Join-Path $PD 'Microsoft\SystemCertificates\My'),
                       (Join-Path $PD 'Microsoft\Crypto\RSA\MachineKeys'))) {
        if (Test-Path -LiteralPath $d) { O ('    MKDIR ' + $d + ' already exists'); continue }
        try { New-Item -ItemType Directory -Path $d -Force -EA Stop | Out-Null; O ('    MKDIR ' + $d + ' ok') }
        catch { O ('    MKDIR ' + $d + ' FAIL ' + (Clean $_.Exception.Message)) }
      }
      $ic = Run (Join-Path $S32 'icacls.exe') @((Join-Path $PD 'Microsoft\Crypto\RSA\MachineKeys'), '/grant', 'SYSTEM:(OI)(CI)F')
      O ('    icacls MachineKeys rc=' + $ic.rc + ' ' + (@($ic.lines) -join ' // '))
      TryWlan 'crypto-dirs'
    }
    'enable-channels' {
      if (-not (TP $we)) { O '    wevtutil absent, cannot enable channels' }
      elseif (@($want).Count -eq 0) { O '    no WLAN/Wdi/Ndis/Firewall channel exists in this image at all' }
      else {
        $names = @($want | ForEach-Object { $_.LogName })
        O ('    channels to enable=[' + ($names -join ',') + ']')
        foreach ($n in $names) {
          $r = Run $we @('sl', $n, '/e:true')
          O ('    WEVTUTIL sl ' + $n + ' /e:true rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
        }
        TryWlan 'after-enable'
        foreach ($n in $names) {
          $r = Run $we @('qe', $n, '/c:15', '/rd:true', '/f:text')
          O ('    QEU ' + $n + ' rc=' + $r.rc + ' lines=' + @($r.lines).Count)
          foreach ($l in @($r.lines | Select-Object -First 40)) { O ('      | ' + $l) }
          try {
            $evs = @(Get-WinEvent -FilterHashtable @{ LogName = $n } -MaxEvents 15 -EA SilentlyContinue)
            foreach ($e in $evs) { O (EventLine 'EVCH' $e) }
          } catch { O ('      Get-WinEvent FAIL ' + (Clean $_.Exception.Message)) }
        }
      }
    }
    'cryptsvc' {
      $r = Run $WIFI @('svc', 'start', 'cryptsvc')
      O ('    start cryptsvc rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
      O ('    info cryptsvc ' + (Wifi @('svc', 'info', 'cryptsvc')))
      TryWlan 'cryptsvc'
    }
    'keyiso' {
      $r = Run $WIFI @('svc', 'start', 'KeyIso')
      O ('    start KeyIso rc=' + $r.rc + ' ' + (@($r.lines) -join ' // '))
      O ('    lsass after ' + (@(Get-Process -Name lsass -EA SilentlyContinue).Count))
      TryWlan 'keyiso'
    }
    'retry' { TryWlan 'final' }
  }
  $res += @{ rung = $rung; running = $script:WRun; ifn = $script:WIfn }
}
} else {
  if ($Apply) { O '  P96 SKIP-APPLY: SystemRoot is not the ramdisk and -IDoit was not given.' }
  O ('  P96 BASELINE (read-only, one wlansvc start attempt with nothing touched):')
  TryWlan 'baseline'
  $res += @{ rung = 'baseline'; running = $script:WRun; ifn = $script:WIfn }
}
foreach ($r in $res) { O ('  P96 LADDER ' + $r.rung + ' running=' + $r.running + ' ifn=' + $r.ifn) }

# ---------- 7 verdict ----------
$outcome = 'wlansvc-still-0x800C0006'
if ($script:WRun) { $outcome = 'wlansvc-running' }
$smPd = RegV $sm 'ProgramData'
$dePd = RegV 'HKU:\.DEFAULT\Environment' 'ProgramData'
O '== 7 verdict =='
O ('  P96 VERDICT outcome=' + $outcome +
   ' smenv_programdata=[' + (Clean "$smPd") + '] defaultenv_programdata=[' + (Clean "$dePd") + ']' +
   ' defaultenv_present=' + (TP 'HKU:\.DEFAULT\Environment') + ' machinekeys_items=' +
   (@(Get-ChildItem -LiteralPath (Join-Path $PD 'Microsoft\Crypto\RSA\MachineKeys') -Force -EA SilentlyContinue).Count) +
   ' syscerts=' + (TP (Join-Path $PD 'Microsoft\SystemCertificates')) +
   ' oid=' + (TP (Join-Path $PD 'Microsoft\Crypto\OID')) +
   ' wdi_host_key=' + (TP 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost') +
   ' wlan_logs=' + @($want).Count + ' ifn=' + $script:WIfn)
if (-not $Apply) {
  O ''
  O '  P96 read-only pass only. Re-run with -Apply to walk the ladder (HKU\.DEFAULT\Environment values, the'
  O '       missing crypto/cert-store directories, enable+clear every WLAN/Wdi channel and capture what wlansvc'
  O '       records while it dies, then cryptsvc / KeyIso / a final retry).'
}
O '  BAKE-ITEMS (what wifi-inject / the boot path still has to carry, judged by this run):'
if ($null -eq $smPd) {
  O ('    SM\Environment carries NO ProgramData value (ALLUSERSPROFILE=' +
     (Clean "$(RegV $sm 'ALLUSERSPROFILE')") + ' PUBLIC=' + (Clean "$(RegV $sm 'PUBLIC')") +
     ') => the env block a LocalSystem service inherits has nowhere to expand to;')
  O '      bake all three into HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment.'
} else {
  O ('    SM\Environment ProgramData=[' + (Clean "$smPd") + '] -- present, so the env theory needs the' +
     ' DEFAULT-ENV/ServiceProfiles rows above to say the same.')
}
O ('    WdiServiceHost + WdiSystemHost service keys: exists=' +
   (TP 'HKLM:\SYSTEM\CurrentControlSet\Services\WdiServiceHost') +
   ' (host shape Type=32 Start=3 LocalService svchost -k LocalService wdi.dll ServiceMain; only provable offline)')
O ('    crypto stores: OID=' + (TP (Join-Path $PD 'Microsoft\Crypto\OID')) +
   ' SystemCertificates=' + (TP (Join-Path $PD 'Microsoft\SystemCertificates')) +
   ' -- create in the image if absent')
O ('    nlasvc/netprofm rows and the LocalService group membership stay from probe95 (rc=0 measured there).')
O ('P96 LOGTIME ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
O 'P96 DONE'
