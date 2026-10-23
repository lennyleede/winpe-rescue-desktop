# PE 侧诊断 v3: 问 WMI/SCM 本身 "wlansvc 依赖谁, 谁没起来" (不依赖自己写的 QueryServiceConfig)
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wifidiag3.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$W = 'X:\wifi.exe'

try {
  Invoke-WebRequest -UseBasicParsing -Uri 'http://172.31.32.1:8000/file/wifi.exe' -OutFile $W
  L ('A. DL wifi.exe OK ' + (Get-Item $W).Length)
} catch { L ('A. DL 失败: ' + $_.Exception.Message) }
function Run([string]$tag, [string[]]$args2) {
  $o = (& $W @args2 2>&1 | Out-String)
  L ('--- ' + $tag + ' ---')
  foreach ($line in ($o -split "`r?`n")) { if ($line.Trim()) { L ('  ' + $line.Trim()) } }
}

L '===== B. WMI: 谁依赖 wlansvc (DependentSystem=wlansvc => Antecedent 是前置) ====='
try {
  $assoc = @(Get-CimInstance -Query "SELECT * FROM Win32_SystemDependentService" -EA Stop |
        Where-Object { $_.DependentSystem -match 'wlansvc|WCMSVC|dot3svc' })
  L ('  关联条目=' + $assoc.Count)
  foreach ($a in $assoc) {
    $dn = ($a.DependentSystem -split '"')[-2]
    $an = ($a.AntecedentSystem -split '"')[-2]
    $q = Get-CimInstance Win32_Service -Filter "Name='$an'" -EA SilentlyContinue
    $st = $(if ($q) { $q.State + '/exit=' + $q.ExitCode + '/pid=' + $q.ProcessId } else { 'SCM 里查不到这个服务' })
    L ('  ' + $dn + '  依赖 ->  ' + $an + '  [' + $st + ']')
  }
} catch { L ('  WQL 失败: ' + $_.Exception.Message) }

L '===== C. WMI: 反向 (wlansvc 是谁的前置) ====='
try {
  $rev = @(Get-CimInstance -Query "ASSOCIATORS OF {Win32_Service.Name='wlansvc'} WHERE ResultClass=Win32_Service" -EA Stop)
  foreach ($r in $rev) { L ('  ' + $r.Name + ' state=' + $r.State) }
} catch { L ('  ASSOCIATORS 失败: ' + $_.Exception.Message) }

L '===== D. 注册表里 wlansvc 现在的值 (X: 是易失的, 这是上一轮热修后的状态) ====='
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$p = Get-ItemProperty $k -EA SilentlyContinue
foreach ($n in @('Type', 'Start', 'ErrorControl', 'Imagepath', 'ObjectName', 'Group', 'DependOnService', 'ServiceSidType', 'RequiredPrivileges')) {
  $v = $p.$n
  if ($v -is [Array]) { $v = $v -join ';' }
  L ('  ' + $n + ' = ' + $v)
}
L ('  Parameters\ServiceDll = ' + ((Get-ItemProperty ($k + '\Parameters') -EA SilentlyContinue).ServiceDll))
L ('  文件 X:\Windows\System32\wlansvc.dll 存在=' + (Test-Path 'X:\Windows\System32\wlansvc.dll'))
L ('  文件 X:\Windows\System32\wlanapi.dll 存在=' + (Test-Path 'X:\Windows\System32\wlanapi.dll'))
L ('  文件 X:\Windows\System32\drivers\nwifi.sys 存在=' + (Test-Path 'X:\Windows\System32\drivers\nwifi.sys'))

L '===== E. SCM 缓存里的配置 (这次带 sechost 回退) ====='
foreach ($s in @('wlansvc', 'dot3svc', 'Dhcp')) { Run "svc info $s" @('svc', 'info', $s) }
Run 'deps wlansvc' @('deps', 'wlansvc')
Run 'svc start wlansvc' @('svc', 'start', 'wlansvc')
Start-Sleep -Seconds 2
Run 'svc info wlansvc 之后' @('svc', 'info', 'wlansvc')
Run 'status' @('status')

L ('===== 诊断 v3 完毕 =====')
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
