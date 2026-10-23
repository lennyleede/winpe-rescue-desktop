# probe9: probe8 proved wlansvc IS in the svchost group table and still fails, but the
# fresh-name test never ran (reg restore cannot CREATE a new service key: rc=1).
# Also probe8 appended a duplicate 'wlansvc' into the group list because array -inotmatch
# returns a FILTERED ARRAY (always truthy), so step 0 repairs that first.
# Crux measurement: does a svchost process ever get created for wlansvc? If none appears,
# services.exe itself refuses (name-bound); if one appears and dies in ms, the fault is
# inside svchost/the DLL.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { Write-Output $m }
function Sec([string]$n)  { Log ''; Log ('===== ' + $n + ' =====') }
function One([string]$s)  { ($s | Out-String) -replace '\s+', ' ' }

function NetStart([string]$n) {
  $o  = & cmd.exe /c ('net start ' + $n + ' 2>&1') | Out-String
  $rc = $LASTEXITCODE
  $t  = One $o
  if ($t.Length -gt 200) { $t = $t.Substring(0, 200) }
  return ('rc=' + $rc + ' out=' + $t.Trim())
}
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}
function ProcSet {
  $h = @{}
  foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $h[[string]$p.ProcessId] = $p.Name }
  return $h
}
function Dump-Key([string]$path, [int]$max) {
  $k = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
  if (-not $k) { Log ('    KEY ABSENT: ' + $path); return $null }
  foreach ($vn in @($k.GetValueNames())) {
    $nm = $vn; if ($nm -eq '') { $nm = '(default)' }
    $t = One ($k.GetValue($vn))
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max) + '...' }
    Log ('    ' + $nm + ' [' + $k.GetValueKind($vn) + '] = ' + $t.Trim())
  }
  foreach ($skn in @($k.GetSubKeyNames())) { Log ('    subkey: ' + $skn) }
  return $k
}
$SVCH   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVCHHK = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SVCHHKD = 'HKLM\SYSTEM\CurrentControlSet\Services'
$GRP    = 'LocalSystemNetworkRestricted'

Sec '0_REPAIR_SVCHOST_AND_BASELINE'
# X: is a fresh ramdisk after a reboot, so the probe8 backup may not exist. Create it now:
# a pristine group list also means probe8's duplicate entry is already gone.
if (-not (Test-Path 'X:\svchost_key.hiv')) {
  $s0 = & cmd.exe /c ('reg save ' + $SVCHHK + ' X:\svchost_key.hiv /y 2>&1') | Out-String
  Log ('  no backup on X: -> reg save SVCHOST => ' + (One $s0).Trim())
  Log '  (fresh boot: probe8 edits are gone, group list is back to the image version)'
} else {
  $r = & cmd.exe /c ('reg restore ' + $SVCHHK + ' X:\svchost_key.hiv 2>&1') | Out-String
  Log ('  reg restore SVCHOST => ' + (One $r).Trim())
}
$gl = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))
Log ('  group list now count=' + $gl.Count + ' unique=' + @($gl | Select-Object -Unique).Count)
Log ('  members: ' + ($gl -join ','))
Log ('  wlansvc ' + (SvcState 'wlansvc') + ' ; dot3svc ' + (SvcState 'dot3svc'))

Sec '1_SVCHOST_GROUP_SUBKEYS'
# The group SUBKEY may carry per-service data that a hand-written service key cannot satisfy.
foreach ($g in @($GRP, 'netsvcs', 'LocalServiceNetworkRestricted')) {
  Log ('  --- ' + $g)
  [void](Dump-Key ($SVCH + '\' + $g) 120)
}

Sec '2_WLAN_LIKE_SERVICE_KEYS'
foreach ($k in @(Get-ChildItem -LiteralPath $SVC -ErrorAction SilentlyContinue)) {
  $n = $k.PSChildName
  if ($n -imatch 'wlan|nwifi|dot3|wcmsvc|eaphost|ndis') {
    $t = ''
    $dv = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
    if ($dv) { $t = ' [SCM: ' + $dv.State + '/' + $dv.ProcessId + ']' } else { $t = ' [not in SCM]' }
    Log ('  ' + $n + $t + '  dll=' + (One ($k.GetValue('Parameters')) ))
    $pd = Get-Item -LiteralPath ($SVC + '\' + $n + '\Parameters') -ErrorAction SilentlyContinue
    if ($pd) { Log ('      ServiceDll=' + (One $pd.GetValue('ServiceDll')).Trim() + ' ServiceMain=' + (One $pd.GetValue('ServiceMain')).Trim()) }
  }
}

if ($LookOnly) { Sec 'LOOKONLY_STOP'; exit 0 }

Sec '3_DOES_A_SVCHOST_EVER_SPAWN'
$before = ProcSet
$pids   = @()
$job = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('net start wlansvc > X:\ns_wlansvc.txt 2>&1') -PassThru -NoNewWindow
for ($i = 0; $i -lt 120; $i++) {
  $now = ProcSet
  foreach ($pid2 in $now.Keys) {
    if (-not $before.ContainsKey($pid2) -and $pids -notcontains $pid2) {
      $pids += $pid2
      $pc = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $pid2) -ErrorAction SilentlyContinue
      Log ('  NEW PROC sample=' + $i + ' pid=' + $pid2 + ' name=' + $now[$pid2] + ' cmd=' + (One $pc.CommandLine))
    }
  }
  Start-Sleep -Milliseconds 100
}
Log ('  net start result: ' + (One (Get-Content 'X:\ns_wlansvc.txt' -Raw -ErrorAction SilentlyContinue)).Trim())
Log ('  wlansvc ' + (SvcState 'wlansvc') + ' ; new procs total=' + $pids.Count)

Sec '4_FRESH_NAME_VIA_REG_COPY'
# reg copy CAN create a new key; reg restore could not. Test the name theory both ways.
$NEW = 'wlansvcb'
& cmd.exe /c ('reg delete ' + $SVCHHKD + '\' + $NEW + ' /f 2>&1') | Out-Null
$c = & cmd.exe /c ('reg copy ' + $SVCHHKD + '\wlansvc ' + $SVCHHKD + '\' + $NEW + ' /s /f /ka 2>&1') | Out-String
Log ('  reg copy wlansvc -> ' + $NEW + ' => ' + (One $c).Trim())
[void](Dump-Key ($SVC + '\' + $NEW) 100)
Log ('  ' + $NEW + ' ' + (SvcState $NEW) + ' ; net start => ' + (NetStart $NEW))
# membership test with SCALAR semantics (array -imatch returns a filtered array!)
$cur = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))
$hasNew = @($cur | Where-Object { $_ -imatch ('^' + $NEW + '$') }).Count -gt 0
Log ('  ' + $NEW + ' in group list = ' + $hasNew)
if (-not $hasNew) {
  $add = $cur + $NEW
  Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value $add -Type MultiString
  Log ('  appended; new count=' + @((Get-Item -LiteralPath $SVCH).GetValue($GRP)).Count)
  Log ('  retry ' + $NEW + ' ' + (SvcState $NEW) + ' ; net start => ' + (NetStart $NEW))
}
Log ('  svchost now: ' + ((@(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" | ForEach-Object { ('{0}:[{1}]' -f $_.ProcessId, (One $_.CommandLine).Trim()) })) -join ' ;; '))

Sec '5_RESTORE_AND_FINAL'
& cmd.exe /c ('reg delete ' + $SVCHHKD + '\' + $NEW + ' /f 2>&1') | Out-Null
$r2 = & cmd.exe /c ('reg restore ' + $SVCHHK + ' X:\svchost_key.hiv 2>&1') | Out-String
Log ('  reg restore SVCHOST => ' + (One $r2).Trim())
$gl2 = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))
Log ('  group list final count=' + $gl2.Count + ' members=' + ($gl2 -join ','))
[void](Dump-Key ($SVC + '\wlansvc') 100)
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc', $NEW)) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log 'PROBE9_DONE'
