# v7 镜像自检: wlansvc 是否真的能起来 (由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wifi_v7.ps1)
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$PSX = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$W   = 'X:\Windows\System32\wifi.exe'
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$SVCHOST = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'

function Run([string]$tag, [string[]]$argv2) {
  $o = (& $W @argv2 2>&1 | Out-String)
  foreach ($ln in (($o -split "`r?`n") | Where-Object { $_.Trim() })) { L ('  [' + $tag + '] ' + $ln.Trim()) }
  return $o
}

L '===== 0. 注入的文件在不在 ====='
foreach ($f in @('wlanapi.dll','wlansvc.dll','wlanmsm.dll','wlanext.exe','wcmsvc.dll','dmcmnutils.dll','mdmregistration.dll','wci.dll','netshell.dll','drivers\nwifi.sys','drivers\ndisuio.sys','wifi.exe')) {
  $p = 'X:\Windows\System32\' + $f
  L ('  ' + $f + ' = ' + $(if (Test-Path $p) { (Get-Item $p).Length } else { 'MISSING' }))
}

L '===== 1. 烘焙进镜像的 wlansvc 键 ====='
if (Test-Path $SVC) {
  $kv = Get-ItemProperty $SVC
  foreach ($n in @('Type','Start','ErrorControl','Group','ImagePath','ObjectName','ServiceSidType','DependOnService','RequiredPrivileges')) {
    L ('  ' + $n + ' = ' + (@($kv.$n) -join ';'))
  }
  $pv = Get-ItemProperty ($SVC + '\Parameters') -EA SilentlyContinue
  L ('  Parameters.ServiceDll = ' + $pv.ServiceDll)
  L ('  Parameters.ServiceMain = ' + $pv.ServiceMain)
  L ('  Parameters.ServiceDllUnloadOnStop = ' + $pv.ServiceDllUnloadOnStop)
} else { L '  wlansvc 键不存在(注入没生效?)' }
L ('  wcmsvc 键存在 = ' + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc'))
L ('  nativewifip 键存在 = ' + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\nativewifip'))
L ('  nwifi 残留键 = ' + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\nwifi'))
L ('  PEWLan 残留组 = ' + [bool](Get-ItemProperty $SVCHOST -Name PEWLan -EA SilentlyContinue))
foreach ($g in @('LocalSystemNetworkRestricted','LocalServiceNetworkRestricted')) {
  L ('  组 ' + $g + ' = ' + (@((Get-ItemProperty $SVCHOST -Name $g -EA SilentlyContinue).$g) -join ','))
}

L '===== 2. 用 wifi.exe 起服务 ====='
Run 'start-wcmsvc' @('svc','start','wcmsvc')
Run 'start-wlansvc' @('svc','start','wlansvc')
Start-Sleep -Seconds 4
Run 'info-wlansvc' @('svc','info','wlansvc')
Run 'info-wcmsvc' @('svc','info','wcmsvc')

L '===== 3. WMI 侧状态 + svchost 里加载了没 ====='
foreach ($n in @('wlansvc','wcmsvc')) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { L ('  ' + $n + ' State=' + $q.State + ' PID=' + $q.ProcessId + ' StartMode=' + $q.StartMode + ' ExitCode=' + $q.ExitCode) }
  else { L ('  ' + $n + ' WMI 查不到') }
}
$hit = @()
foreach ($p in @(Get-Process svchost -EA SilentlyContinue)) {
  try {
    foreach ($m in $p.Modules) { if ($m.ModuleName -match '^(wlansvc|wcmsvc)\.dll$') { $hit += ($p.Id.ToString() + ':' + $m.ModuleName) } }
  } catch { }
}
L ('  加载了 wlansvc/wcmsvc 的 svchost: ' + $(if ($hit.Count) { $hit -join ', ' } else { '无' }))

L '===== 4. wlanapi 能不能打开句柄(最关键) ====='
Run 'status' @('status')
Run 'deps' @('deps','wlansvc')

L '===== 5. 事件日志(取最近的 Service Control Manager) ====='
foreach ($lg in @('System')) {
  try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $lg; ProviderName = 'Service Control Manager' } -MaxEvents 15 -EA Stop)
    L ('  SCM 事件 ' + $ev.Count + ' 条')
    foreach ($e in $ev) { L ('   [' + $e.LevelDisplayName + ' ' + $e.Id + '] ' + (($e.Message -split "`r?`n")[0])) }
  } catch { L ('  Get-WinEvent 不可用: ' + $_.Exception.Message) }
}

L '===== 结论 ====='
$w = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue
L ('  wlansvc 最终状态 = ' + $(if ($w) { $w.State } else { 'unknown' }) + ' / 接口枚举见上面 [status]')

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
