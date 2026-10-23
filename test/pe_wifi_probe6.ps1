# test/pe_wifi_probe6.ps1 -- runs INSIDE a live PE.
# probe5 (X:\pw5.txt) gave three hard facts and two measurement failures:
#   facts   : the injected stack is wlansvc.dll 10.0.19041.7725 while the image's ndis.sys / dot3svc.dll /
#             netsh.exe / wlanutil.dll are 10.0.26100.1 (mixed generation in one image);
#             wlansvc.dll references 4 contracts + 3 DLLs the image does not publish, whereas dot3svc.dll --
#             which starts fine in the SAME svchost group -- has 0 failures out of 44;
#             exports are correct: WlanSvcMain / Dot3SvcMain / WcmSvcMain are all present.
#   failures: QueryServiceStatusEx returned win32=122 (buffer) and a service key created at runtime was
#             invisible to the SCM (win32=1060), so probe5 never got the exit code and its A/B harness no-op'd.
# This version measures with what provably works in PE (CIM Win32_Service + "net start" text) and then runs a
# single-variable sweep over the shapes wlansvc could be missing. Every value is snapshotted and restored.
# Nothing here touches the ISO or the U: data partition -- only the ephemeral ramdisk registry.
# ASCII output only.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' | ') -replace '\s{2,}', ' ' }
$svcNames = @('wlansvc','wcmsvc','dot3svc','RpcSs','RpcEpMapper','Ndisuio','nativewifip','nsi','netprofm','Dhcp','LanmanWorkstation')

function Dump-Svc([string[]]$names) {
  foreach ($n in $names) {
    $q = @(Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue)
    if ($q.Count -eq 0) { Write-Output ('  ' + $n.PadRight(16) + ' (not in SCM database)'); continue }
    $s = $q[0]
    Write-Output ('  ' + $n.PadRight(16) + ' State=' + (One $s.State) + ' Status=' + (One $s.Status) +
                  ' StartMode=' + (One $s.StartMode) + ' pid=' + $s.ProcessId +
                  ' sspec=' + $s.ServiceSpecificExitCode + ' path=' + (One $s.PathName))
  }
}

Sec '0_WHO'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' build=' + [Environment]::OSVersion.Version.Build + ' sysroot=' + $env:SystemRoot)
$who = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
Write-Output ('  elevated=' + $who.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Sec '1_BASELINE_CIM'
Dump-Svc $svcNames

Sec '2_NET_START_AS_IS'
  $o = & cmd.exe /c "net start wlansvc 2>&1" | Out-String
Write-Output ('  net start wlansvc rc=' + $LASTEXITCODE + ' out=' + (One $o))
Start-Sleep -Seconds 2
Dump-Svc @('wlansvc')
  $o2 = & cmd.exe /c "net stop wlansvc 2>&1" | Out-String
Write-Output ('  net stop => ' + (One $o2))
Write-Output '  -- running services right now (net start list)'
  $o3 = & cmd.exe /c "net start 2>&1" | Out-String
Write-Output ('   ' + (One $o3))

Sec '3_SVCHOST_PROCESSES'
foreach ($pr in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
  Write-Output ('  pid=' + $pr.ProcessId + ' cmd=' + (One $pr.CommandLine))
}

# ---------- sweep machinery ----------
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$PARAMS = Join-Path $SVC 'Parameters'
function Get-Val([string]$k, [string]$n) {
  if (-not (Test-Path $k)) { return $null }
  $ki = Get-Item $k
  if ($ki.GetValueNames() -notcontains $n) { return $null }
  return $ki.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
}
function Set-Val([string]$k, [string]$n, $v, [string]$t) { Set-ItemProperty -Path $k -Name $n -Value $v -Type $t -Force -EA Stop }
function Try-Step([string]$tag, [string]$desc) {
  Write-Output ('  --- ' + $tag + ': ' + $desc)
    $o = & cmd.exe /c "net start wlansvc 2>&1" | Out-String
  Write-Output ('      net start rc=' + $LASTEXITCODE + ' out=' + (One $o))
  Start-Sleep -Seconds 2
  Dump-Svc @('wlansvc','dot3svc')
  foreach ($pr in @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue)) {
    if ($pr.CommandLine -match '(?i)LocalSystemNetworkRestricted|wlansvc') { Write-Output ('      svchost pid=' + $pr.ProcessId + ' cmd=' + (One $pr.CommandLine)) }
  }
    $o2 = & cmd.exe /c "net stop wlansvc 2>&1" | Out-String
  Write-Output ('      net stop out=' + (One $o2))
}

Sec '4_SNAPSHOT_ORIGINAL_KEYS'
$orig = @{}
foreach ($spec in @(@($SVC,'Type'), @($SVC,'Start'), @($SVC,'DependOnService'), @($SVC,'RequiredPrivileges'),
                   @($SVC,'ObjectName'), @($SVC,'ImagePath'), @($SVC,'Group'), @($SVC,'ServiceSidType'),
                   @($PARAMS,'ServiceDll'), @($PARAMS,'ServiceMain'), @($PARAMS,'ServiceDllUnloadOnStop'))) {
  $k = $spec[0]; $n = $spec[1]
  $v = Get-Val $k $n
  $orig[$k + '\' + $n] = $v
  $disp = if ($v -is [array]) { $v -join ',' } else { [string]$v }
  Write-Output ('  saved ' + $k.Substring($k.LastIndexOf('\') + 1) + '\' + $n.PadRight(20) + ' = ' + (One $disp))
}

if ($LookOnly) {
  Sec '5_SWEEP_SKIPPED'
  Write-Output '  -LookOnly: no registry surgery on this machine'
} else {
  Sec '5_SWEEP_SINGLE_VARIABLE'
  # S1: host real Windows uses Type=16 (SERVICE_WIN32_SHARE_PROCESS) for wlansvc; our key says 32 (OWN_PROCESS).
  Set-Val $SVC 'Type' 16 DWord
  Try-Step 'S1_type16' 'wlansvc Type 32 -> 16 (share process, matches a real Windows 10)'
  Set-Val $SVC 'Type' 32 DWord

  # S2: modern per-service svchost shape (the form Windows 10/11 uses for OWN_PROCESS svchost services).
  Set-Val $SVC 'ImagePath' '%SystemRoot%\System32\svchost.exe -k LocalSystemNetworkRestricted -s wlansvc' ExpandString
  Try-Step 'S2_dash_s' 'ImagePath with "-s wlansvc" so svchost starts ONLY wlansvc in its own process'
  Set-Val $SVC 'ImagePath' $orig[$SVC + '\ImagePath'] ExpandString

  # S3: same group, share process, and the -s form together (closest to a stock Win11 wlansvc).
  Set-Val $SVC 'Type' 16 DWord
  Set-Val $SVC 'ImagePath' '%SystemRoot%\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s wlansvc' ExpandString
  Try-Step 'S3_share_plus_s' 'Type=16 plus -k group -p -s wlansvc'
  Set-Val $SVC 'Type' 32 DWord
  Set-Val $SVC 'ImagePath' $orig[$SVC + '\ImagePath'] ExpandString

  # S4: privilege set trimmed to exactly what the working dot3svc declares.
  Set-Val $SVC 'RequiredPrivileges' @('SeChangeNotifyPrivilege','SeImpersonatePrivilege','SeAuditPrivilege','SeTcbPrivilege') MultiString
  Try-Step 'S4_privs_dot3_like' 'RequiredPrivileges = the 4 that dot3svc uses (drops SeDebug/SeLoadDriver)'
  Set-Val $SVC 'RequiredPrivileges' $orig[$SVC + '\RequiredPrivileges'] MultiString

  # S5: dependencies as a real Windows has them, restricted to what can actually be RUNNING in this image.
  Set-Val $SVC 'DependOnService' @('RpcSs','Ndisuio') MultiString
  Try-Step 'S5_deps' 'DependOnService = RpcSs,Ndisuio (Ndisuio is the one dot3svc also needs)'
  Set-Val $SVC 'DependOnService' $orig[$SVC + '\DependOnService'] MultiString

  # S6: the decisive partition -- keep the wlansvc NAME (the SCM already knows it) but run dot3svc.dll in it.
  #     starts  => SCM/svchost/group/privileges are all fine and the fault is inside wlansvc.dll's own init.
  #     fails   => the plumbing around the DLL is what is broken.
  Set-Val $PARAMS 'ServiceDll' '%SystemRoot%\System32\dot3svc.dll' ExpandString
  Set-Val $PARAMS 'ServiceMain' 'Dot3SvcMain' String
  Try-Step 'S6_dll_swap_dot3' 'wlansvc name + dot3svc.dll/Dot3SvcMain (plumbing-only control)'
  Set-Val $PARAMS 'ServiceDll' $orig[$PARAMS + '\ServiceDll'] ExpandString
  Set-Val $PARAMS 'ServiceMain' $orig[$PARAMS + '\ServiceMain'] String

  # S7: wcmsvc as-is -- does the OTHER borrowed 19041 service start? Same skew question, different DLL.
    $o7 = & cmd.exe /c "net start wcmsvc 2>&1" | Out-String
  Write-Output ('  --- S7_wcmsvc_as_is: net start wcmsvc rc=' + $LASTEXITCODE + ' out=' + (One $o7))
  Dump-Svc @('wcmsvc')

  Sec '6_RESTORE_AND_VERIFY'
  Set-Val $SVC 'Type' $orig[$SVC + '\Type'] DWord
  Set-Val $SVC 'ImagePath' $orig[$SVC + '\ImagePath'] ExpandString
  Set-Val $SVC 'RequiredPrivileges' $orig[$SVC + '\RequiredPrivileges'] MultiString
  Set-Val $SVC 'DependOnService' $orig[$SVC + '\DependOnService'] MultiString
  Set-Val $PARAMS 'ServiceDll' $orig[$PARAMS + '\ServiceDll'] ExpandString
  Set-Val $PARAMS 'ServiceMain' $orig[$PARAMS + '\ServiceMain'] String
  foreach ($spec in @(@($SVC,'Type'), @($SVC,'ImagePath'), @($SVC,'RequiredPrivileges'), @($SVC,'DependOnService'),
                      @($PARAMS,'ServiceDll'), @($PARAMS,'ServiceMain'))) {
    $k = $spec[0]; $n = $spec[1]
    $now = Get-Val $k $n
    $was = $orig[$k + '\' + $n]
    $same = if ($now -is [array] -and $was -is [array]) { (Compare-Object $now $was -EA SilentlyContinue).Count -eq 0 }
            elseif ($null -eq $now -or $null -eq $was) { ($null -eq $now) -and ($null -eq $was) }
            else { ([string]$now) -eq ([string]$was) }
    Write-Output ('  ' + $(if ($same) { 'RESTORED ' } else { 'MISMATCH!' }) + ' ' + $n + ' = ' + (One $(if ($now -is [array]) { $now -join ',' } else { [string]$now })))
  }
}

Sec '7_NWIFI_DRIVER_REALITY'
# WiFi needs the NativeWiFi filter to bind. The image has 26100 ndis.sys and a borrowed 19041 nwifi.sys;
# if NDIS refuses it, no service shape can save WiFi -- and that decides task #17 (26100 material vs 19041).
$nw = Join-Path $env:SystemRoot 'System32\drivers\nwifi.sys'
Write-Output ('  nwifi.sys ' + $(if (Test-Path -LiteralPath $nw) { 'present v=' + (One (Get-Item -LiteralPath $nw).VersionInfo.FileVersion) + ' size=' + (Get-Item -LiteralPath $nw).Length } else { 'ABSENT' }))
foreach ($d in @('ndis','Ndisuio','nativewifip')) {
  $q = @(Get-CimInstance Win32_SystemDriver -Filter "Name='$d'" -EA SilentlyContinue)
  if ($q.Count) { Write-Output ('  systemdriver ' + $d.PadRight(13) + ' State=' + $q[0].State + ' StartMode=' + $q[0].StartMode + ' path=' + (One $q[0].PathName)) }
  else { Write-Output ('  systemdriver ' + $d.PadRight(13) + ' (not listed)') }
}
if (-not $LookOnly) {
  $o = & drvload.exe $nw 2>&1 | Out-String
  Write-Output ('  drvload nwifi.sys rc=' + $LASTEXITCODE + ' out=' + (One $o))
  $q = @(Get-CimInstance Win32_SystemDriver -Filter "Name='nativewifip'" -EA SilentlyContinue)
  if ($q.Count) { Write-Output ('  after drvload nativewifip State=' + $q[0].State) }
}
foreach ($d in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.DeviceID -match '(?i)VEN_8086&DEV_7A70|wireless|Wi-Fi' } | Select-Object -First 5)) {
  Write-Output ('  devnode ' + (One ($d.Name + ' | ' + $d.DeviceID + ' | class=' + $d.ClassGuid + ' | code=' + $d.ConfigManagerErrorCode)))
}

Sec '8_SVCHOST_EX_SHAPES'
# What does this image's svchost actually accept? Its own usage strings settle the -p / -s question.
$sv = Join-Path $env:SystemRoot 'System32\svchost.exe'
if (Test-Path -LiteralPath $sv) {
  $bytes = [IO.File]::ReadAllBytes($sv)
  $a = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
  $u = [Text.Encoding]::Unicode.GetString($bytes)
  foreach ($pat in @('-k ','-s ','-p ','-m ','-d ','-w ','-ws ')) {
    $hitA = $a.Contains($pat); $hitU = $u.Contains($pat)
    Write-Output ('  svchost flag "' + $pat.Trim() + '" ansi=' + $hitA + ' unicode=' + $hitU)
  }
  $msgs = @()
  foreach ($mm in @([regex]::Matches($u, '[A-Za-z0-9 ,;:().\-/%]{12,150}'))) {
    $v = $mm.Value.Trim()
    if ($v -match '(?i)(service|group|DLL|entry|parameter|usage)') { $msgs += $v }
  }
  Write-Output ('  -- svchost strings mentioning service/group/entry point (' + $msgs.Count + ')')
  foreach ($m in ($msgs | Select-Object -Unique -First 22)) { Write-Output ('     ' + (One $m)) }
}

Sec '9_WLANSVC_EVENTS_AND_LOGS'
foreach ($p in @('X:\windows\System32\winevt\Logs', 'X:\windows\System32\LogFiles\WMI', 'X:\ProgramData\Microsoft\Network\Downloader')) {
  Write-Output ('  ' + $(if (Test-Path -LiteralPath $p) { 'OK    ' } else { 'ABSENT' }) + ' ' + $p +
                ' files=' + @(Get-ChildItem $p -File -EA SilentlyContinue).Count)
}
foreach ($ch in @('System','Application','Microsoft-Windows-WLAN-AutoConfig%4Operational')) {
  $ev = @(Get-WinEvent -ListLog $ch -EA SilentlyContinue)
  if ($ev.Count) { Write-Output ('  log channel ' + $ch + ' exists, records=' + $ev[0].RecordCount) } else { Write-Output ('  log channel ' + $ch + ' not registered') }
}

Sec 'DONE'
Write-Output '  probe6 complete'
