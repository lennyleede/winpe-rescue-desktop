# probe97 -- supply the files the PE does not carry, one at a time, and see whether wlansvc's self-exit changes.
#
# Where probe96 left it (build\scratch\p96_apply_1011.txt, this box, 2026-10-11 14:22, same boot):
#   every *object* candidate was created live and wlansvc answered the same way each time:
#     RUNG env-default   HKU\.DEFAULT\Environment ALLUSERSPROFILE/ProgramData/PUBLIC/TEMP/TMP reg add rc=0
#     RUNG crypto-dirs   Crypto\OID + SystemCertificates\{Root,CA,My} MKDIR ok, icacls MachineKeys rc=0
#     RUNG cryptsvc      already RUNNING(4)      RUNG keyiso  StartService OK
#     every rung:  +85..122ms state=STOPPED(1) exit=2148270086(0x800C0006)   (LADDER running=False x6)
#   and 0x800C0006 decoded on this machine as "the system cannot find the specified object" (fm2_out_utf8.txt),
#   i.e. the WinINet facility-12 family -- NOT FWP_E_* (0x8032xxxx), which is why probe95's BFE theory died.
#   probe95 also proved it is not adapter-driven: with the WLAN devnode DISABLED (zero WiFi adapters) the service
#   returns the identical code, so WlanSvcMain bails in its own init.
#
# What is still different from a machine where wlansvc runs, and has never been supplied:
#   probe96 section 4 LoadLibrary'd the names wlansvc/wlanext reach for lazily and six of them have NO file here.
#   build\scratch\t_p97_apisetmap.ps1 (host, 19041, read-only) resolves each contract name to its backing file:
#     ext-ms-win-wlan-grouppolicy-l1-1-0    -> wlgpclnt.dll            (ABSENT in PE)
#     ext-ms-win-devmgmt-policy-l1-1-0      -> policymanager.dll       (ABSENT in PE)
#     ext-ms-win-shell-embeddedmode-l1-1-0  -> embeddedmodesvcapi.dll  (ABSENT in PE)
#     ext-ms-win-networking-wlanstorage-... -> LOADFAIL 126 ON THE HOST TOO  => not a PE gap, ignore
#     ext-ms-win-oobe-notification-l1-1-0   -> LOADFAIL 126 ON THE HOST TOO  => not a PE gap, ignore
#     wcmapi.dll  rmclient.dll  cmintegrator.dll  es.dll  tspkg.dll  pku2u.dll  (ABSENT in PE)
#   Checked against the file list pulled from THIS boot (build\scratch\pe_s32_1011.txt, 1257 names), not an old disc.
#   The other difference probe96 measured but could not judge: wlansvc.dll is a 19041 borrow sitting on a 26100
#   image whose own wlanutil.dll / wdi.dll are 26100. probe96 could not compare wdi.dll exports against the host
#   because wifi.exe is a PE-side tool, so build\scratch\pe_exports.ps1 ran on the host instead: the host's wdi.dll
#   has 53 exports and does NOT contain WdiInitializeServiceSansHost / WdiGetServiceHostInterfaces /
#   WdiInstanceManagerCreateSession either => those FAIL-127 rows in the PE were my wrong guesses, not a gap.
#
# So this probe answers one question with measurements instead of reasoning: if the objects wlansvc asks for are
# these files, giving them to the running image changes the exit code. Each rung copies from X:\p97 (fetched over
# HTTP from the build machine) into X:\Windows\System32, re-runs the LoadLibrary check the way the loader does,
# then starts wlansvc and records the state timeline. Files that already exist are backed up to X:\p97bak first.
# Sections: 1 fetch+verify, 2 baseline, 3 the rung ladder, 4 verdict + BAKE-ITEMS.
#
# MUTATION SAFETY: nothing is written unless -Apply, and only when SystemRoot is the RAMDISK (X:); -IDoit
# overrides that guard deliberately. Writes are file copies inside X:\Windows\System32 (backup kept) and service
# starts for wlansvc/wcmsvc; no registry key is deleted, no hive touched, no ISO / D:\winpe_build / customer disk
# written. Rebooting restores the disc.
param([switch]$Apply, [switch]$IDoit, [string]$Base = 'http://192.168.0.106:8099/', [string]$Only = '')
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
function TP([string]$p) {
  try { return [bool](Test-Path -LiteralPath $p -EA SilentlyContinue) } catch { return $false }
}
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
  $img = [string](RegV $p 'ImagePath')
  $st = (Get-Service -Name $s -EA SilentlyContinue).Status
  return ('SVC ' + $s + ' Start=' + (HexVal (RegV $p 'Start')) + ' Type=' + (HexVal (RegV $p 'Type')) +
    ' Group=[' + (RegV $p 'Group') + '] Obj=[' + (RegV $p 'ObjectName') + ']' +
    ' Depend=[' + (@(RegV $p 'DependOnService') -join ';') + ']' +
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
# NOTE (the probe95/96 trap, keep it): callers MUST NOT assign TryWlan's result -- assigning it swallows every
# Write-Output line the function emits. State travels in $script:WRun / $script:WIfn instead.
$script:WRun = $false
$script:WIfn = -1
function TryWlan([string]$tag) {
  $s = Run $WIFI @('svc', 'start', 'wlansvc')
  $i = Wifi @('svc', 'info', 'wlansvc')
  $w = Run $WIFI @('svc', 'watch', 'wlansvc', '3000', 'start')
  $st = Wifi @('status'); $row = SvcRow 'wlansvc'
  O ('  P97 TRY[' + $tag + '] start-> rc=' + $s.rc + ' ' + (@($s.lines) -join ' // '))
  O ('  P97 TRY[' + $tag + '] info  ' + $i)
  foreach ($l in @($w.lines | Select-Object -First 10)) { O ('    | ' + $l) }
  O ('  P97 TRY[' + $tag + '] row   ' + $row)
  O ('  P97 TRY[' + $tag + '] wifi  ' + $st)
  $svcSt = ''
  try { $svcSt = [string](Get-Service -Name wlansvc -EA SilentlyContinue).Status } catch { }
  $script:WRun = (($i -match '(?i)state=RUNNING\(4\)|state=Running') -or ($svcSt -eq 'Running'))
  $script:WIfn = -1
  if ($st -match 'interfaces=(\d+)') { $script:WIfn = [int]$Matches[1] }
}
# LoadLibrary exactly the way the loader would, by name, and report the Win32 code -- this is the gate a
# delay-load sits behind, so it is the thing that has to flip from 126 to OK for a rung to count as supplied.
# Same shape as probe96 section 4 (build\scratch\p96_apply_1011.txt proves it answers in the field). Note the
# Add-Type pitfall: -Namespace/-Name only wrap -MemberDefinition code, so a -TypeDefinition must declare its own
# public class and be called by THAT name -- [Ldr97.X] would be "type not found".
if (-not ('Ldr97' -as [type])) {
  Add-Type -ErrorAction SilentlyContinue -Verbose:$false -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Ldr97 {
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
  try { return [Ldr97]::Try($name) } catch { return 'EXCEPTION ' + (Clean $_.Exception.Message) }
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
$PD = Join-Path (Split-Path $SR -Parent) 'ProgramData'
if (-not (TP $PD)) { $PD = 'X:\ProgramData' }
$CANWRITE = ($Apply -and (($SR -match '(?i)^X:') -or $IDoit))
# On the ramdisk the drop folder lives next to the OS (X:\p97). Anywhere else -- i.e. the host dry run, whose whole
# job is to prove the fetch/verify/LL code paths before a PE ever sees them -- use a folder next to this script, on
# the build volume, so a host run never writes to the system drive. Place() only ever writes to $S32 when -Apply AND
# $SR is X:, so the host run stays read-only as far as Windows is concerned.
$DRY = Join-Path (Split-Path $PSCommandPath -Parent) 'p97_dryrun'
if ($SR -match '(?i)^X:') { $STAGE = 'X:\p97'; $BAK = 'X:\p97bak' }
else { $STAGE = Join-Path $DRY 'stage'; $BAK = Join-Path $DRY 'bak' }
function Sel([string]$k) { if ($Only -eq '') { return $true } return (@($Only -split ',') -contains $k) }

O ('P97 START ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' root=' + $SR + ' base=' + $Base +
   ' apply=' + $CANWRITE + ' readapplyflag=' + [bool]$Apply + ' freeMB=' + (FreeMB (Split-Path $SR -Qualifier)) +
   ' only=[' + $Only + ']')
O ('  P97 STACK ' + (StackLine))
O ('  P97 ROW   ' + (SvcRow 'wlansvc'))

# ---------- 1 fetch the staged files over HTTP ----------
# Why HTTP: the ssh channel pushes as chunked base64 through cmd 'echo' (~0.3s per 2KB chunk, so 1.5MB is minutes
# and each chunk is a fresh ssh handshake). The PE has a wired route to the build machine and WinHTTP works here
# (measured this boot: Invoke-WebRequest of the connecttest probe returned), so a plain GET is seconds.
if (Sel 'fetch') {
O '== 1 fetch: pull the host-staged candidates into X:\p97 and verify every byte count =='
if (-not (TP $STAGE)) { try { New-Item -ItemType Directory -Path $STAGE -Force -EA Stop | Out-Null } catch { O ('  MKDIR ' + $STAGE + ' FAIL ' + (Clean $_.Exception.Message)) } }
$man = @()
$raw = $null
try {
  # A plain static server often sends no charset, and then PowerShell hands back a byte[] instead of a string.
  # Measured on the host with the same server (build\scratch\t_p97_preflight.ps1): -split on that byte[] yields one
  # line per NUMBER, so decode explicitly before parsing.
  $raw = (Invoke-WebRequest -Uri ($Base + 'manifest.txt') -UseBasicParsing -TimeoutSec 20).Content
  $txt = [string]$raw
  if ($raw -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($raw) }
  elseif ($raw -is [Object[]]) { $txt = [string]($raw -join '') }
  $man = @($txt -split "`r?`n")
} catch { O ('  MANIFEST FAIL ' + (Clean $_.Exception.Message)) }
$tn = '<none>'
try { if ($null -ne $raw) { $tn = [string]$raw.GetType().Name } } catch { }
O ('  P97 MANIFEST type=' + $tn + ' lines=' + @($man).Count)
$script:EXP = @{}
foreach ($l in @($man)) {
  $t = (Clean "$l")
  if ($t -eq '') { continue }
  $p = @($t -split '\s+')
  if ($p.Count -lt 2) { continue }
  $script:EXP[$p[0].ToLower()] = [int64]$p[1]
  O ('  P97 WANT ' + $p[0] + ' size=' + $p[1] + ' ' + ($p[2]))
}
foreach ($n in @($script:EXP.Keys | Sort-Object)) {
  $dst = Join-Path $STAGE $n
  $ok = $false
  for ($t = 1; $t -le 2 -and -not $ok; $t++) {
    try {
      Invoke-WebRequest -Uri ($Base + $n) -OutFile $dst -UseBasicParsing -TimeoutSec 60 | Out-Null
      $ok = $true
    } catch { O ('  P97 GET ' + $n + ' try' + $t + ' FAIL ' + (Clean $_.Exception.Message)) }
  }
  if (-not $ok) { continue }
  $sz = [int64]0
  try { $sz = (Get-Item -LiteralPath $dst).Length } catch { }
  $ver = ''
  try { $ver = (Clean "$((Get-Item -LiteralPath $dst).VersionInfo.FileVersion)") } catch { }
  $mark = 'SIZE-FAIL'
  if ($sz -eq [int64]$script:EXP[$n.ToLower()]) { $mark = 'ok' }
  O ('  P97 GOT ' + $n + ' bytes=' + $sz + ' expect=' + $script:EXP[$n.ToLower()] + ' ' + $mark + ' ver=' + $ver)
}
if (Sel 'fetch') {
  O ('  P97 LL-BEFORE (the way the loader resolves them, nothing copied yet):')
  foreach ($n in @('wcmapi.dll', 'ext-ms-win-wlan-grouppolicy-l1-1-0.dll', 'ext-ms-win-devmgmt-policy-l1-1-0.dll',
                   'ext-ms-win-devmgmt-policy-lcdl-1-1-0.dll', 'ext-ms-win-shell-embeddedmode-l1-1-0.dll',
                   'ext-ms-win-networking-wlanstorage-l1-1-0.dll', 'ext-ms-win-wlan-scard-l1-1-0.dll',
                   'ext-ms-win-session-usermgr-l1-1-0.dll',
                   'wlgpclnt.dll', 'policymanager.dll', 'embeddedmodesvcapi.dll', 'cmintegrator.dll', 'es.dll',
                   'rmclient.dll', 'tspkg.dll', 'pku2u.dll')) {
    O ('    P97 LL ' + $n + ' = ' + (LL $n))
  }
}
}

# ---------- 2 baseline ----------
if (Sel 'base') {
O '== 2 baseline: one wlansvc start attempt with nothing touched =='
TryWlan 'baseline'
}

# ---------- 3 the rung ladder ----------
$res = @()
function Place([string]$name) {
  # copy X:\p97\<name> into System32, keeping whatever the image already had at X:\p97bak\<name>
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
$groups = @()
if ($CANWRITE) {
O '== 3 rung ladder: supply one group of files, re-check the loader, retry wlansvc =='
# Two known limits on the swap rungs, read the exit code with them in mind:
#  * a file already mapped by another process cannot be replaced -- Copy-Item gives a sharing violation, Place
#    prints FAIL and the ladder moves on (wlanutil/wdi are loaded by svchost hosts other than wlansvc's).
#  * wlansvc runs in svchost -k LocalSystemNetworkRestricted; if that host already mapped the 26100 wdi.dll or
#    wlanutil.dll, wlansvc's delay-load resolves to the loaded module no matter which file is on disc.
#    So a swap rung that changes nothing is not evidence the pairing is fine; wifi.exe svc info shows whether the
#    host pid (and therefore the mapped set) actually changed hands.
$groups = @(
  @{ n = 'wcm'; f = @('wcmapi.dll', 'rmclient.dll') },
  @{ n = 'gp'; f = @('wlgpclnt.dll') },
  @{ n = 'dm'; f = @('policymanager.dll') },
  @{ n = 'emb'; f = @('embeddedmodesvcapi.dll') },
  @{ n = 'cm'; f = @('cmintegrator.dll', 'es.dll') },
  @{ n = 'lsa'; f = @('tspkg.dll', 'pku2u.dll') },
  @{ n = 'swap-wlanutil'; f = @('wlanutil.dll') },
  @{ n = 'swap-wdi'; f = @('wdi.dll') },
  @{ n = 'retry'; f = @() }
)
foreach ($g in $groups) {
  if ($script:WRun) { O ('  P97 RUNG ' + $g.n + ' skipped, wlansvc is already Running'); continue }
  O ('  P97 RUNG ' + $g.n)
  # NOT `[void](Place $f)` -- that discards Place's whole output stream, and the 10-11 field run then had the copies
  # proven only indirectly (LL flipped 126->OK, now-in-system32, backups) with no PLACE/BACKUP rows in the log.
  # Capture into an array and re-emit; the third variant of this trap (see TryWlan above).
  foreach ($f in @($g.f)) { @(Place $f) | ForEach-Object { O ('      ' + $_) } }
  foreach ($f in @($g.f)) { O ('    P97 LL ' + $f + ' = ' + (LL $f)) }
  if ($g.n -eq 'gp') { O ('    P97 LL contract grouppolicy = ' + (LL 'ext-ms-win-wlan-grouppolicy-l1-1-0.dll')) }
  if ($g.n -eq 'dm') { O ('    P97 LL contract devmgmt-policy = ' + (LL 'ext-ms-win-devmgmt-policy-l1-1-0.dll') +
                            ' / lcdl form = ' + (LL 'ext-ms-win-devmgmt-policy-lcdl-1-1-0.dll')) }
  if ($g.n -eq 'emb') { O ('    P97 LL contract embeddedmode = ' + (LL 'ext-ms-win-shell-embeddedmode-l1-1-0.dll')) }
  if ($g.n -eq 'wcm') {
    $cw = Run $WIFI @('svc', 'start', 'wcmsvc')
    O ('    start wcmsvc rc=' + $cw.rc + ' ' + (@($cw.lines) -join ' // '))
    O ('    info wcmsvc ' + (Wifi @('svc', 'info', 'wcmsvc')))
  }
  TryWlan $g.n
  $res += @{ rung = $g.n; files = (@($g.f) -join ','); running = $script:WRun; ifn = $script:WIfn }
}
} else {
  if ($Apply) { O '  P97 SKIP-APPLY: SystemRoot is not the ramdisk and -IDoit was not given.' }
  O '  P97 read-only: no file is copied. Rungs that would have been walked:'
  $groups = @(
    @{ n = 'wcm'; f = @('wcmapi.dll', 'rmclient.dll') },
    @{ n = 'gp'; f = @('wlgpclnt.dll') },
    @{ n = 'dm'; f = @('policymanager.dll') },
    @{ n = 'emb'; f = @('embeddedmodesvcapi.dll') },
    @{ n = 'cm'; f = @('cmintegrator.dll', 'es.dll') },
    @{ n = 'lsa'; f = @('tspkg.dll', 'pku2u.dll') },
    @{ n = 'swap-wlanutil'; f = @('wlanutil.dll') },
    @{ n = 'swap-wdi'; f = @('wdi.dll') },
    @{ n = 'retry'; f = @() }
  )
  # Registered through the same summary loop the -Apply branch uses, prefixed WOULDRUN so a read-only row can never
  # be read as a measurement. This also proves the summary statement itself is reachable (probe96 lost its ladder
  # to a brace that closed the foreach early, which only a host run would show).
  foreach ($g in $groups) { $res += @{ rung = ('WOULDRUN:' + $g.n); files = (@($g.f) -join ','); running = $false; ifn = -1 } }
}
foreach ($r in $res) {
  O ('  P97 LADDER ' + $r.rung + ' files=[' + $r.files + '] running=' + $r.running + ' ifn=' + $r.ifn)
}

# ---------- 4 verdict ----------
O '== 4 verdict =='
$placed = @()
if (TP $STAGE) { $placed = @((Get-ChildItem -LiteralPath $STAGE -File -EA SilentlyContinue).Name | Sort-Object) }
$inS32 = @()
foreach ($n in @('wcmapi.dll', 'rmclient.dll', 'wlgpclnt.dll', 'policymanager.dll', 'embeddedmodesvcapi.dll',
                 'cmintegrator.dll', 'es.dll', 'tspkg.dll', 'pku2u.dll')) {
  if (TP (Join-Path $S32 $n)) { $inS32 += $n }
}
$outcome = 'wlansvc-still-0x800C0006'
if ($script:WRun) { $outcome = 'wlansvc-running' }
O ('  P97 LL-AFTER: wcmapi=' + (LL 'wcmapi.dll') + ' grouppolicy=' + (LL 'ext-ms-win-wlan-grouppolicy-l1-1-0.dll') +
   ' devmgmt=' + (LL 'ext-ms-win-devmgmt-policy-l1-1-0.dll') + ' embeddedmode=' +
   (LL 'ext-ms-win-shell-embeddedmode-l1-1-0.dll') + ' wlanstorage=' + (LL 'ext-ms-win-networking-wlanstorage-l1-1-0.dll'))
O ('  P97 VERDICT outcome=' + $outcome + ' apply=' + [bool]$CANWRITE + ' fetched=' + @($placed).Count +
   ' now-in-system32=[' + ($inS32 -join ',') + ']' +
   ' backups=' + (@(Get-ChildItem -LiteralPath $BAK -File -EA SilentlyContinue).Count) +
   ' wlansvc=' + ((Get-Service -Name wlansvc -EA SilentlyContinue).Status) +
   ' wcmsvc=' + ((Get-Service -Name wcmsvc -EA SilentlyContinue).Status) +
   ' ifn=' + $script:WIfn)
O '  BAKE-ITEMS (files this run proved the image is missing; wifi-inject carries them if a rung changed anything):'
foreach ($n in @('wcmapi.dll', 'rmclient.dll', 'wlgpclnt.dll', 'policymanager.dll', 'embeddedmodesvcapi.dll',
                 'cmintegrator.dll', 'es.dll', 'tspkg.dll', 'pku2u.dll')) {
  O ('    ' + $n + ' host-copy-staged=' + (TP (Join-Path $STAGE $n)) + ' pe-now=' + (TP (Join-Path $S32 $n)) +
     ' ver=' + (FV (Join-Path $S32 $n)))
}
O ('    WdiServiceHost + WdiSystemHost service keys stay on the offline list (services.exe builds its database at' +
   ' boot, so a key created now is invisible -- host shape Type=32 Start=3, wdi.dll ServiceMain, -k LocalService /' +
   ' -k LocalSystemNetworkRestricted).')
O ('P97 LOGTIME ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
O 'P97 DONE'
