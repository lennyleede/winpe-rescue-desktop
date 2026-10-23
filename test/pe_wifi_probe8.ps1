# probe8: probe7 proved the config is NOT the variable -- a byte-for-byte clone of the
# WORKING dot3svc key, restored under the NAME wlansvc, still gives System error 6, while
# a bogus ImagePath DOES change the error (=> SCM re-reads config at start time).
# So either (a) the SCM's boot-time service DB has a poisoned entry for the name "wlansvc",
# or (b) svchost refuses names that are absent from its group table.
# This probe measures the group table and runs the fresh-name A/B. Live ramdisk only.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { Write-Output $m }
function Sec([string]$n)  { Log ''; Log ("===== " + $n + " =====") }

function NetStart([string]$n) {
  $o  = & cmd.exe /c ("net start " + $n + " 2>&1") | Out-String
  $rc = $LASTEXITCODE
  $t  = ($o -replace '\s+', ' ').Trim()
  if ($t.Length -gt 220) { $t = $t.Substring(0, 220) }
  return ("rc={0} out={1}" -f $rc, $t)
}

function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ("Name='" + $n + "'") -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ("State={0} pid={1} start={2} path={3}" -f $s.State, $s.ProcessId, $s.StartMode, $s.PathName)
}

function SvchostList {
  $ps = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -ErrorAction SilentlyContinue)
  if ($ps.Count -eq 0) { return '(none)' }
  return (($ps | ForEach-Object { ('{0}:[{1}]' -f $_.ProcessId, $_.CommandLine) }) -join ' ;; ')
}

function Dump-Key([string]$path) {
  $k = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
  if (-not $k) { Log ("    KEY ABSENT: " + $path); return $null }
  foreach ($vn in $k.GetValueNames()) {
    if ($vn -eq '') { $vn = '(default)' }
    $kind = $k.GetValueKind($vn)
    $val  = $k.GetValue($vn)
    $txt  = ($val | Out-String) -replace '\s+', ' '
    if ($txt.Length -gt 160) { $txt = $txt.Substring(0, 160) + '...' }
    Log ("    {0} [{1}] = {2}" -f $vn, $kind, $txt.Trim())
  }
  foreach ($sk in $k.GetSubKeyNames()) { Log ("    subkey: " + $sk) }
  return $k
}

$SVCH  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC   = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$WLANH = 'HKLM\SYSTEM\CurrentControlSet\Services\wlansvc'
$GRP   = 'LocalSystemNetworkRestricted'

Sec '0_WHO'
Log ('  computer=' + $env:COMPUTERNAME + ' build=' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuild).CurrentBuild)
$who = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
Log ('  elevated=' + $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) {
  Log ('  before: ' + $n + ' ' + (SvcState $n))
}

Sec '1_SVCHOST_GROUP_TABLE'
# Every REG_MULTI_SZ value in the SVCHOST key is a group -> service-name list.
# Print, for each list, its size and whether our three names are members.
$sk = Get-Item -LiteralPath $SVCH -ErrorAction SilentlyContinue
if (-not $sk) {
  Log '  SVCHOST KEY ABSENT'
} else {
  $names = @($sk.GetValueNames())
  Log ('  values=' + $names.Count + ' subkeys=' + (($sk.GetSubKeyNames()) -join ','))
  foreach ($vn in $names) {
    $kind = $sk.GetValueKind($vn)
    $val  = $sk.GetValue($vn)
    if ($kind -eq 'MultiString') {
      $lst = @($val)
      $hit = @()
      foreach ($q in @('wlansvc', 'dot3svc', 'wcmsvc')) { if ($lst -imatch ('^' + $q + '$')) { $hit += $q } }
      Log ('  LIST {0} count={1} membersOfInterest={2}' -f $vn, $lst.Count, ($hit -join ','))
    } else {
      $t = ($val | Out-String) -replace '\s+', ' '
      if ($t.Length -gt 120) { $t = $t.Substring(0, 120) + '...' }
      Log ('  VAL  {0} [{1}] = {2}' -f $vn, $kind, $t.Trim())
    }
  }
  # which list actually owns dot3svc, and is wlansvc in the same one?
  $owner = @()
  foreach ($vn in $names) {
    if ($sk.GetValueKind($vn) -ne 'MultiString') { continue }
    $l = @($sk.GetValue($vn))
    if ($l -imatch ('^' + $GRP + '$') -or ($vn -imatch $GRP)) { $owner += $vn }
  }
  Log ('  entries matching group name "{0}": {1}' -f $GRP, ($owner -join ','))
}

Sec '2_BACKUP'
$b1 = & cmd.exe /c ('reg save "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST" X:\svchost_key.hiv /y 2>&1') | Out-String
Log ('  reg save SVCHOST => ' + (($b1 -replace '\s+', ' ').Trim()))
$b2 = & cmd.exe /c ('reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST" X:\svchost_dump.txt /y 2>&1') | Out-String
Log ('  reg export SVCHOST => ' + (($b2 -replace '\s+', ' ').Trim()))
$b3 = & cmd.exe /c ('reg save ' + $WLANH + ' X:\wlansvc_key.hiv /y 2>&1') | Out-String
Log ('  reg save wlansvc   => ' + (($b3 -replace '\s+', ' ').Trim()))

if ($LookOnly) { Sec 'LOOKONLY_STOP'; exit 0 }

Sec '3_FRESH_NAME_CONTROL'
# The name "wlansvcb" did not exist when services.exe built its DB. It carries the very same
# bytes as the failing wlansvc key. Two answers, both decisive:
#   NOT-IN-SCM-DB / rc=2 name invalid  -> SCM DB is frozen at boot; live edits to *names* are
#                                         meaningless and only an offline rebuild can fix this.
#   System error 6 as well             -> the poison is in the config/DLL, not the name.
#   it STARTS                           -> the name "wlansvc" itself is poisoned in the DB.
$NEW = 'wlansvcb'
& cmd.exe /c ('reg delete "HKLM\SYSTEM\CurrentControlSet\Services\' + $NEW + '" /f 2>&1') | Out-Null
$r = & cmd.exe /c ('reg restore HKLM\SYSTEM\CurrentControlSet\Services\' + $NEW + ' X:\wlansvc_key.hiv 2>&1') | Out-String
Log ('  reg restore ' + $NEW + ' => rc=' + $LASTEXITCODE + ' out=' + (($r -replace '\s+', ' ').Trim()))
Dump-Key ($SVC + '\' + $NEW)
Log ('  net start ' + $NEW + ' : ' + (NetStart $NEW))
Log ('  ' + $NEW + ' ' + (SvcState $NEW))
Log ('  wlansvc  ' + (SvcState 'wlansvc'))
Log ('  svchost: ' + (SvchostList))

Sec '4_ADD_NAMES_TO_GROUP_TABLE'
# If the group table is what gates svchost, membership must be added for BOTH names.
if ($sk) {
  $gname = $null
  foreach ($vn in @($sk.GetValueNames())) {
    if ($sk.GetValueKind($vn) -ne 'MultiString') { continue }
    if (@($sk.GetValue($vn)) -imatch ('^' + $GRP + '$')) { $gname = $vn; break }
  }
  if (-not $gname) { foreach ($vn in @($sk.GetValueNames())) { if ($vn -imatch $GRP) { $gname = $vn; break } } }
  Log ('  group value name holding ' + $GRP + ' = ' + $gname)
  if ($gname) {
    $cur = @($sk.GetValue($gname))
    Log ('  wlansvc in list = ' + [bool]($cur -imatch '^wlansvc$') + ' ; ' + $NEW + ' in list = ' + [bool]($cur -imatch ('^' + $NEW + '$')))
    $add = @($cur)
    if ($add -inotmatch '^wlansvc$') { $add += 'wlansvc' }
    if ($add -inotmatch ('^' + $NEW + '$')) { $add += $NEW }
    if ($add.Count -gt $cur.Count) {
      Set-ItemProperty -LiteralPath $SVCH -Name $gname -Value $add -Type MultiString
      Log ('  appended => count ' + $cur.Count + ' -> ' + ((@((Get-Item -LiteralPath $SVCH).GetValue($gname))).Count))
    } else {
      Log '  both names already members; nothing appended'
    }
    Log ('  retry net start ' + $NEW + ' : ' + (NetStart $NEW))
    Log ('  retry net start wlansvc : ' + (NetStart 'wlansvc'))
    Log ('  svchost: ' + (SvchostList))
  }
}

Sec '5_SVCHOST_DEBUG_FOR_WLANSVC'
# Ask svchost itself to host ONLY wlansvc, verbosely, into files. If it never even prints,
# the process is not the failure point; if it prints, we finally get the real reason.
foreach ($tgt in @('wlansvc', $NEW)) {
  $oi = 'X:\sd_' + $tgt + '.out'
  $ei = 'X:\sd_' + $tgt + '.err'
  del $oi, $ei -ErrorAction SilentlyContinue
  try {
    $p = Start-Process -FilePath 'X:\windows\system32\svchost.exe' `
        -ArgumentList @('-k', $GRP, '-d', '-s', $tgt) `
        -RedirectStandardOutput $oi -RedirectStandardError $ei -NoNewWindow -PassThru
    $done = $p.WaitForExit(7000)
    if (-not $done) { $p.Kill() }
    Log ('  svchost -d -s ' + $tgt + ' : exited=' + $done + ' pid=' + $p.Id)
  } catch {
    Log ('  svchost -d -s ' + $tgt + ' EXCEPTION: ' + $_.Exception.Message)
  }
  $oc = ''
  $ec = ''
  if (Test-Path $oi) { $oc = ((Get-Content $oi -Raw) -replace '\s+', ' ') }
  if (Test-Path $ei) { $ec = ((Get-Content $ei -Raw) -replace '\s+', ' ') }
  if ($oc.Length -gt 300) { $oc = $oc.Substring(0, 300) }
  if ($ec.Length -gt 300) { $ec = $ec.Substring(0, 300) }
  Log ('    stdout=' + $oc)
  Log ('    stderr=' + $ec)
  Log ('    ' + $tgt + ' after -d : ' + (SvcState $tgt))
  Log ('    svchost: ' + (SvchostList))
}

Sec '6_RESTORE_AND_FINAL'
& cmd.exe /c ('reg delete "HKLM\SYSTEM\CurrentControlSet\Services\' + $NEW + '" /f 2>&1') | Out-Null
Log ('  deleted ' + $NEW + ' key')
Dump-Key ($SVC + '\wlansvc')
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc', $NEW)) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log ('  final svchost: ' + (SvchostList))
Log 'PROBE8_DONE'
