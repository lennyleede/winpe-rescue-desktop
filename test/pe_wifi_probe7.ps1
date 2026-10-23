# test/pe_wifi_probe7.ps1 -- runs INSIDE a live PE.
# probe6 (X:\pw6.txt) result: wlansvc fails with the SAME "System error 6 / The handle is invalid" for every
# registry shape we tried (Type 16/32, -p vs -s, trimmed privileges, DependOnService=RpcSs,Ndisuio, and even
# running dot3svc.dll inside the wlansvc slot), while dot3svc itself is Running in that very group.
# Two things must be settled before any of that means anything:
#   (1) METHODOLOGY CONTROL -- does the PE's SCM re-read service config at start time at all? If it latched
#       the config at boot, every one of probe6's edits was a no-op and the "identical error" is meaningless.
#       Test: point ImagePath at a nonexistent exe; a re-reading SCM must fail with 193/2, a caching SCM
#       repeats error 6. Also rename DisplayName and start it by the new name.
#   (2) KEY STRUCTURE vs DLL -- replace our hand-written wlansvc key with a byte-for-byte clone of the
#       working dot3svc key (reg save -> reg restore). If the clone starts, wifi-inject must CLONE a real
#       service key instead of writing values one by one.
# Everything is on the ephemeral ramdisk; the wlansvc key is saved to X:\wlansvc_key.hiv first and restored
# at the end, and the image on the stick is not touched. ASCII output only.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' | ') -replace '\s{2,}', ' ' }
$SVC    = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$PAR    = Join-Path $SVC 'Parameters'
$D3     = 'HKLM:\SYSTEM\CurrentControlSet\Services\dot3svc'
$WCM    = 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc'
$KEYBAK = 'X:\wlansvc_key.hiv'
$D3BAK  = 'X:\dot3svc_key.hiv'

function Dump-Key([string]$k) {
  if (-not (Test-Path $k)) { Write-Output ('  (key missing) ' + $k); return }
  $ki = Get-Item $k
  foreach ($vn in $ki.GetValueNames()) {
    $nm = if ($vn) { $vn } else { '(default)' }
    $raw = $ki.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $disp = if ($raw -is [array]) { ($raw | ForEach-Object { if ($_ -is [byte]) { ('{0:X2}' -f $_) } else { [string]$_ } }) -join ',' } else { [string]$raw }
    if ($disp.Length -gt 200) { $disp = $disp.Substring(0, 200) + '...' }
    Write-Output ('    ' + $nm + ' [' + $ki.GetValueKind($vn) + '] = ' + (One $disp))
  }
  foreach ($sk in @(Get-ChildItem $k -EA SilentlyContinue)) { Write-Output ('    subkey: ' + $sk.PSChildName) }
}
function Try-Start([string]$tag, [string]$target) {
  if (-not $target) { $target = 'wlansvc' }
  $o = & cmd.exe /c "net start `"$target`" 2>&1" | Out-String
  Write-Output ('  ' + $tag + ': net start rc=' + $LASTEXITCODE + ' out=' + (One $o))
  Start-Sleep -Seconds 2
  foreach ($n in @('wlansvc','dot3svc')) {
    $q = @(Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue)
    if ($q.Count) { Write-Output ('      ' + $n + ' State=' + $q[0].State + ' pid=' + $q[0].ProcessId + ' sspec=' + $q[0].ServiceSpecificExitCode) }
  }
  foreach ($pr in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    if ($pr.CommandLine -match 'LocalSystemNetworkRestricted') { Write-Output ('      svchost pid=' + $pr.ProcessId + ' cmd=' + (One $pr.CommandLine)) }
  }
  & cmd.exe /c "net stop wlansvc 2>&1" | Out-Null
}
function Snap-Backup() {
  & cmd.exe /c "reg save HKLM\SYSTEM\CurrentControlSet\Services\wlansvc $KEYBAK /y 2>&1" | Out-String | ForEach-Object { Write-Output ('  reg save wlansvc => ' + (One $_)) }
  & cmd.exe /c "reg save HKLM\SYSTEM\CurrentControlSet\Services\dot3svc $D3BAK /y 2>&1" | Out-String | ForEach-Object { Write-Output ('  reg save dot3svc => ' + (One $_)) }
  Write-Output ('  backup sizes: wlansvc=' + $(if (Test-Path $KEYBAK) { (Get-Item $KEYBAK).Length } else { 'FAILED' }) +
                ' dot3svc=' + $(if (Test-Path $D3BAK) { (Get-Item $D3BAK).Length } else { 'FAILED' }))
}

Sec '0_WHO_AND_CONTROL_SET'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' build=' + [Environment]::OSVersion.Version.Build + ' sysroot=' + $env:SystemRoot)
$who = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Write-Output ('  elevated=' + $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Write-Output ('  CurrentControlSet default = ' + (Get-ItemProperty 'HKLM:\SYSTEM' -Name CurrentControlSet -EA SilentlyContinue).CurrentControlSet +
              ' | select = ' + (Get-ItemProperty 'HKLM:\SYSTEM' -Name Select -EA SilentlyContinue).Select)
foreach ($cs in @(Get-ChildItem 'HKLM:\SYSTEM' -EA SilentlyContinue | Where-Object { $_.PSChildName -match '^ControlSet' })) {
  Write-Output ('  ' + $cs.PSChildName + ' has wlansvc=' + (Test-Path (Join-Path $cs.Name 'Services\wlansvc')) +
                ' dot3svc=' + (Test-Path (Join-Path $cs.Name 'Services\dot3svc')))
}

Sec '1_BASELINE_KEYS'
Write-Output '  wlansvc:';  Dump-Key $SVC;  Dump-Key $PAR
Write-Output '  dot3svc:';  Dump-Key $D3;  Dump-Key (Join-Path $D3 'Parameters')
Snap-Backup

Sec '2_SCM_RELOAD_CONTROL'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  $origImg = (Get-Item $SVC).GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames')
  $origDn  = (Get-Item $SVC).GetValue('DisplayName', $null, 'DoNotExpandEnvironmentNames')
  # control A: an image path that cannot exist. A config-reading SCM reports 193/2/3; a caching SCM repeats 6.
  Set-ItemProperty $SVC -Name ImagePath -Value '%SystemRoot%\System32\probe7_nosuch.exe' -Type ExpandString -Force
  Write-Output ('  ImagePath now = ' + (Get-Item $SVC).GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames'))
  Try-Start 'CTRL_bad_imagepath' 'wlansvc'
  # control B: rename the display name and start THAT name. net.exe resolves display names live.
  Set-ItemProperty $SVC -Name DisplayName -Value 'PROBE7_RENAMED_WLAN' -Type String -Force
  Try-Start 'CTRL_renamed_display' 'PROBE7_RENAMED_WLAN'
  Set-ItemProperty $SVC -Name ImagePath -Value $origImg -Type ExpandString -Force
  Set-ItemProperty $SVC -Name DisplayName -Value $origDn -Type String -Force
  Write-Output ('  restored ImagePath = ' + (Get-Item $SVC).GetValue('ImagePath', $null, 'DoNotExpandEnvironmentNames'))
}

Sec '3_DOT3DLL_UNDER_WLANSVC_NAME'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  $od  = (Get-Item $PAR).GetValue('ServiceDll', $null, 'DoNotExpandEnvironmentNames')
  $om  = (Get-Item $PAR).GetValue('ServiceMain', $null, 'DoNotExpandEnvironmentNames')
  Set-ItemProperty $PAR -Name ServiceDll -Value '%SystemRoot%\System32\dot3svc.dll' -Type ExpandString -Force
  Set-ItemProperty $PAR -Name ServiceMain -Value 'Dot3SvcMain' -Type String -Force
  Try-Start 'S_dot3dll' 'wlansvc'
  Set-ItemProperty $PAR -Name ServiceDll -Value $od -Type ExpandString -Force
  Set-ItemProperty $PAR -Name ServiceMain -Value $om -Type String -Force
  # and the mirror image: wlansvc.dll running under the wcmsvc name is NOT tried (different account/group),
  # but wcmsvc itself is retried here to compare its error against wlansvc's.
  $ow = & cmd.exe /c "net start wcmsvc 2>&1" | Out-String
  Write-Output ('  ctrl_wcmsvc: net start wcmsvc rc=' + $LASTEXITCODE + ' out=' + (One $ow))
  & cmd.exe /c "net stop wcmsvc 2>&1" | Out-Null
}

Sec '4_DOT3_EXTRA_VALUES'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  # dot3svc carries FailureActions + StateFlags that our hand-written key never set.
  $fa = (Get-Item $D3).GetValue('FailureActions', $null, 'DoNotExpandEnvironmentNames')
  $sf = (Get-Item $D3).GetValue('StateFlags', $null, 'DoNotExpandEnvironmentNames')
  Write-Output ('  dot3svc FailureActions bytes=' + $(if ($fa) { $fa.Length } else { 'none' }) + ' StateFlags=' + $sf)
  if ($fa) { Set-ItemProperty $SVC -Name FailureActions -Value $fa -Type Binary -Force }
  if ($null -ne $sf) { Set-ItemProperty $SVC -Name StateFlags -Value $sf -Type DWord -Force }
  Try-Start 'S_dot3_extras' 'wlansvc'
}

Sec '5_WHOLESALE_DOT3_KEY_CLONE'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  Write-Output '  -- replacing Services\wlansvc with a byte-for-byte copy of the WORKING dot3svc key'
  $r = & cmd.exe /c "reg restore HKLM\SYSTEM\CurrentControlSet\Services\wlansvc $D3BAK 2>&1" | Out-String
  Write-Output ('  reg restore => rc=' + $LASTEXITCODE + ' out=' + (One $r))
  Write-Output '  resulting wlansvc key:'; Dump-Key $SVC
  Write-Output '  resulting wlansvc Parameters:'; Dump-Key $PAR
  Try-Start 'S_pure_dot3_clone' 'wlansvc'
  Write-Output '  -- now the same cloned key but pointed at wlansvc.dll'
  $p2 = Join-Path $SVC 'Parameters'
  if (-not (Test-Path $p2)) { New-Item $p2 -Force | Out-Null }
  Set-ItemProperty $p2 -Name ServiceDll -Value '%SystemRoot%\System32\wlansvc.dll' -Type ExpandString -Force
  Set-ItemProperty $p2 -Name ServiceMain -Value 'WlanSvcMain' -Type String -Force
  Set-ItemProperty $p2 -Name ServiceDllUnloadOnStop -Value 1 -Type DWord -Force
  Try-Start 'S_cloned_key_wlansvcdll' 'wlansvc'
}

Sec '6_RESTORE_OWN_KEY'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  $r = & cmd.exe /c "reg restore HKLM\SYSTEM\CurrentControlSet\Services\wlansvc $KEYBAK 2>&1" | Out-String
  Write-Output ('  reg restore wlansvc from backup => rc=' + $LASTEXITCODE + ' out=' + (One $r))
  Write-Output '  restored key:'; Dump-Key $SVC; Dump-Key $PAR
}

Sec '7_KEY_ACLS'
foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\dot3svc',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\RpcSs',
                 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters')) {
  if (-not (Test-Path $k)) { Write-Output ('  (missing) ' + $k); continue }
  try {
    $acl = Get-Acl -LiteralPath $k
    Write-Output ('  ' + (Split-Path $k -Leaf).PadRight(12) + ' Owner=' + (One $acl.Owner))
    foreach ($a in $acl.Access) {
      Write-Output ('        ' + (One ($a.IdentityReference + ' | ' + $a.AccessControlType + ' | ' + $a.RegistryRights + ' | inherit=' + $a.IsInherited)))
    }
  } catch { Write-Output ('  ' + $k + ' Get-Acl failed: ' + (One $_.Exception.Message)) }
}

Sec '8_SVCHOST_DEBUG_MODE'
if ($LookOnly) { Write-Output '  skipped (-LookOnly)' } else {
  # -d makes svchost print its own progress/errors instead of dying quietly inside services.exe.
  # It calls DebugBreak(), so with no debugger present the process dies -- that is fine here; we want the
  # text it printed before that. Kill it after a few seconds either way.
  $outF = 'X:\pw6_svchost_d.txt'; $errF = 'X:\pw6_svchost_d.err'
  Remove-Item $outF, $errF -Force -EA SilentlyContinue
  $pi = Start-Process -FilePath 'X:\windows\System32\svchost.exe' `
        -ArgumentList '-k','LocalSystemNetworkRestricted','-d' -PassThru -NoNewWindow `
        -RedirectStandardOutput $outF -RedirectStandardError $errF
  if (-not $pi.WaitForExit(8000)) { try { $null = $pi.Kill(); Write-Output '  svchost -d still alive after 8s, killed' } catch {} }
  Write-Output ('  exited=' + $pi.HasExited + ' exitcode=' + $(try { $pi.ExitCode } catch { 'n/a' }))
  Write-Output ('  stdout=' + (One $(if (Test-Path $outF) { Get-Content $outF -Raw } else { '' })))
  Write-Output ('  stderr=' + (One $(if (Test-Path $errF) { Get-Content $errF -Raw } else { '' })))
}

Sec '9_FINAL_STATE'
foreach ($n in @('wlansvc','wcmsvc','dot3svc','RpcSs','Ndisuio')) {
  $q = @(Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue)
  if ($q.Count) { Write-Output ('  ' + $n.PadRight(10) + ' State=' + $q[0].State + ' pid=' + $q[0].ProcessId + ' path=' + (One $q[0].PathName)) }
  else { Write-Output ('  ' + $n.PadRight(10) + ' (not in SCM database)') }
}
Write-Output ('  backups kept: ' + $KEYBAK + ' ' + $D3BAK)

Sec 'DONE'
Write-Output '  probe7 complete'
