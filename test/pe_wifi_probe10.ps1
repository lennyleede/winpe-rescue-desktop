# probe10: probe9 proved services.exe never spawns svchost for wlansvc (12s of 100ms sampling,
# only net/cmd/net1 appeared). So the refusal happens inside services.exe BEFORE CreateProcess.
# Remaining name/config-bound candidate that no probe has touched: ServiceSidType=1 makes the
# SCM derive a per-service SID and build the service token -- that step sits exactly between
# "read config" and "CreateProcess". probe9 also never ran the fresh-name test (unquoted paths
# broke reg save; reg copy rejected /ka).
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { Write-Output $m }
function Sec([string]$n)  { Log ''; Log ('===== ' + $n + ' =====') }
function One([string]$s)  { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c)  { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }

function ProcSet {
  $h = @{}
  foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $h[[string]$p.ProcessId] = $p.Name }
  return $h
}
function Watch-Start([string]$svc, [int]$samples) {
  # Start the service out-of-band and sample the process table at 100ms. The question is
  # whether svchost is EVER created for this service name.
  $before = ProcSet
  $newp   = New-Object System.Collections.Generic.List[string]
  $f      = 'X:\ns_' + $svc + '.txt'
  del $f -ErrorAction SilentlyContinue
  $null = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('net start ' + $svc + ' > ' + $f + ' 2>&1') -PassThru -NoNewWindow
  for ($i = 0; $i -lt $samples; $i++) {
    $now = ProcSet
    foreach ($id in $now.Keys) {
      if (-not $before.ContainsKey($id)) {
        $known = $false
        foreach ($k in $newp) { if ($k.StartsWith($id + ':')) { $known = $true; break } }
        if (-not $known) {
          $pc = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $id) -ErrorAction SilentlyContinue
          $newp.Add($id + ':' + $now[$id] + ':' + (One $pc.CommandLine).Trim())
        }
      }
    }
    Start-Sleep -Milliseconds 100
  }
  $txt = One (Get-Content $f -Raw -ErrorAction SilentlyContinue)
  if ($txt.Length -gt 220) { $txt = $txt.Substring(0, 220) }
  $svcs = @($newp | Where-Object { $_ -imatch ':svchost\.exe:' })
  return [pscustomobject]@{ Svc = $svc; Net = $txt.Trim(); NewProcs = ($newp -join ' | '); SvchostSpawn = ($svcs.Count -gt 0); Detail = ($svcs -join ' | ') }
}
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}
$SVCH   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVCHHK = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SVCHHKD = 'HKLM\SYSTEM\CurrentControlSet\Services'
$GRP    = 'LocalSystemNetworkRestricted'
$ORIG   = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))

Sec '0_BASELINE'
Log ('  group list original (' + $ORIG.Count + '): ' + ($ORIG -join ','))
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  ' + $n + ' ' + (SvcState $n)) }
$sk = Get-Item -LiteralPath ($SVC + '\wlansvc')
Log ('  wlansvc ServiceSidType=' + $sk.GetValue('ServiceSidType') + ' Type=' + $sk.GetValue('Type') + ' ObjectName=' + $sk.GetValue('ObjectName'))
$dk = Get-Item -LiteralPath ($SVC + '\dot3svc')
Log ('  dot3svc ServiceSidType=' + $dk.GetValue('ServiceSidType') + ' Type=' + $dk.GetValue('Type') + ' ObjectName=' + $dk.GetValue('ObjectName'))

Sec '1_CONTROL_DOT3SVC_STARTS'
# Control for the watcher: dot3svc uses the same group, same svchost, same ServiceSidType.
$r = Watch-Start 'dot3svc' 100
Log ('  net: ' + $r.Net)
Log ('  svchost spawned = ' + $r.SvchostSpawn + ' ; ' + (SvcState 'dot3svc'))
Log ('  all new procs: ' + $r.NewProcs)

if ($LookOnly) { Sec 'LOOKONLY_STOP'; exit 0 }

Sec '2_SERVICE_SID_TYPE_SWEEP'
# 0 = SERVICE_SID_TYPE_NONE (no per-service SID, no restricted token) -- the one variable
# every previous probe left untouched.
foreach ($v in @(0, 3)) {
  Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ServiceSidType' -Value $v -Type DWord
  $r = Watch-Start 'wlansvc' 80
  Log ('  sidtype=' + $v + ' : svchost spawned = ' + $r.SvchostSpawn + ' ; ' + (SvcState 'wlansvc'))
  Log ('    net: ' + $r.Net)
  if ($r.SvchostSpawn) { Log ('    SPAWN DETAIL: ' + $r.Detail) }
}
Remove-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ServiceSidType' -ErrorAction SilentlyContinue
$r = Watch-Start 'wlansvc' 80
Log ('  sidtype=ABSENT : svchost spawned = ' + $r.SvchostSpawn + ' ; ' + (SvcState 'wlansvc'))
Log ('    net: ' + $r.Net)
if ($r.SvchostSpawn) { Log ('    SPAWN DETAIL: ' + $r.Detail) }
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ServiceSidType' -Value 1 -Type DWord

Sec '3_STARTNET_FORENSICS'
# Was wlansvc already start-attempted at boot? A poisoned in-memory SERVICE_RECORD would explain
# a refusal that ignores every registry change.
Log ('  startnet.cmd = ' + (Test-Path 'X:\Windows\System32\startnet.cmd'))
$t = One (Get-Content 'X:\Windows\System32\startnet.cmd' -Raw -ErrorAction SilentlyContinue)
Log ('    content(400): ' + $t.Substring(0, [Math]::Min(400, $t.Length)))
foreach ($pat in @('X:\Windows\System32\startnet.cmd', 'X:\Desktop\*.*', 'X:\Startup*', 'X:\*.log', 'X:\*.txt')) {
  foreach ($f in @(Get-ChildItem $pat -File -EA SilentlyContinue | Select-Object -First 40)) {
    $c = ''
    try { $c = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
    if ($c -imatch 'wlansvc') {
      foreach ($line in ($c -split "\r?\n")) { if ($line -imatch 'wlansvc') { Log ('    ' + $f.Name + ' :: ' + (One $line).Trim()) } }
    }
  }
}
Log ('  X: top-level: ' + ((@(Get-ChildItem X:\ -EA SilentlyContinue | ForEach-Object { $_.Name })) -join ','))

Sec '4_FRESH_NAME_REG_COPY'
# reg copy with quoted paths and NO /ka (reg copy rejects it). A brand-new service name that the
# SCM never saw at boot, carrying the exact bytes of the failing wlansvc key.
foreach ($NEW in @('wlansvcb', 'wlansvcc')) {
  $src = 'wlansvc'
  if ($NEW -eq 'wlansvcc') { $src = 'dot3svc' }
  Cmd ('reg delete "' + $SVCHHKD + '\' + $NEW + '" /f') | Out-Null
  Log ('  reg copy ' + $src + ' -> ' + $NEW + ' => ' + (Cmd ('reg copy "' + $SVCHHKD + '\' + $src + '" "' + $SVCHHKD + '\' + $NEW + '" /s /f')))
  $k = Get-Item -LiteralPath ($SVC + '\' + $NEW) -ErrorAction SilentlyContinue
  if (-not $k) { Log ('    KEY NOT CREATED'); continue }
  Log ('    Type=' + $k.GetValue('Type') + ' ImagePath=' + (One $k.GetValue('ImagePath')).Trim())
  Log ('    ' + $NEW + ' before group edit: ' + (SvcState $NEW) + ' ; net => ' + (Cmd ('net start ' + $NEW)))
  if (@($ORIG + $NEW | Where-Object { $_ -imatch ('^' + $NEW + '$') }).Count -eq 0) { }
  $cur = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))
  if (@($cur | Where-Object { $_ -imatch ('^' + $NEW + '$') }).Count -eq 0) {
    Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value ($cur + $NEW) -Type MultiString
    Log ('    appended to group list; count now ' + @((Get-Item -LiteralPath $SVCH).GetValue($GRP)).Count)
  }
  $r = Watch-Start $NEW 80
  Log ('    ' + $NEW + ' : ' + (SvcState $NEW) + ' ; svchost spawned = ' + $r.SvchostSpawn)
  Log ('      net: ' + $r.Net)
  Log ('      new procs: ' + $r.NewProcs)
}

Sec '5_CLEANUP_AND_FINAL'
foreach ($NEW in @('wlansvcb', 'wlansvcc')) {
  Cmd ('reg delete "' + $SVCHHKD + '\' + $NEW + '" /f') | Out-Null
}
Set-ItemProperty -LiteralPath $SVCH -Name $GRP -Value $ORIG -Type MultiString
Log ('  group list restored (' + @((Get-Item -LiteralPath $SVCH).GetValue($GRP)).Count + '): ' + ((Get-Item -LiteralPath $SVCH).GetValue($GRP) -join ','))
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc', 'wlansvcb', 'wlansvcc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
$kw = Get-Item -LiteralPath ($SVC + '\wlansvc')
Log ('  wlansvc ServiceSidType=' + $kw.GetValue('ServiceSidType') + ' ImagePath=' + (One $kw.GetValue('ImagePath')).Trim())
Log 'PROBE10_DONE'
