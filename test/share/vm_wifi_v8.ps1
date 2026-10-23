# v8 诊断: wlansvc "StartService 成功但立刻退出" 的真正原因
# 在 PE 控制台粘一条命令即可(结果自动 POST 回主机):
#   X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri http://172.31.32.1:8000/file/vm_wifi_v8.ps1 -OutFile X:\w8.ps1; & X:\w8.ps1"
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$H = 'http://172.31.32.1:8000'
$W2 = 'X:\w2.exe'

function Run([string]$tag, [string[]]$args2) {
  $o = (& $W2 @args2 2>&1 | Out-String)
  foreach ($ln in (($o -split "`r?`n") | Where-Object { $_.Trim() -ne '' })) { L ('  [' + $tag + '] ' + $ln.Trim()) }
}

L '===== 0. 取新版 wifi.exe (svc watch / dllload / regq) ====='
try {
  Invoke-WebRequest -UseBasicParsing -Uri ($H + '/file/wifi.exe') -OutFile $W2 -ErrorAction Stop
  L ('  OK ' + (Get-Item $W2).Length + ' 字节')
} catch {
  L ('  下载失败: ' + $_.Exception.Message)
  try { Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($H + '/result') -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null } catch { }
  exit 1
}

L '===== 1. 注册表里真正烘焙进去的值(类型错就是秒退的常见原因) ====='
foreach ($v in @('Type', 'Start', 'ErrorControl', 'Group', 'ImagePath', 'ObjectName', 'ServiceSidType', 'DependOnService', 'RequiredPrivileges')) {
  Run ('reg-' + $v) @('regq', 'SYSTEM\CurrentControlSet\Services\wlansvc', $v)
}
foreach ($v in @('ServiceDll', 'ServiceMain', 'ServiceDllUnloadOnStop')) {
  Run ('reg-' + $v) @('regq', 'SYSTEM\CurrentControlSet\Services\wlansvc\Parameters', $v)
}
L '  --- wcmsvc ---'
foreach ($v in @('Type', 'Start', 'ObjectName', 'DependOnService', 'RequiredPrivileges')) {
  Run ('creg-' + $v) @('regq', 'SYSTEM\CurrentControlSet\Services\wcmsvc', $v)
}
Run ('creg-dll') @('regq', 'SYSTEM\CurrentControlSet\Services\wcmsvc\Parameters', 'ServiceDll')
Run ('creg-main') @('regq', 'SYSTEM\CurrentControlSet\Services\wcmsvc\Parameters', 'ServiceMain')

L '===== 2. DLL 能不能载入 + ServiceMain 导出在不在 ====='
Run ('dll-wlansvc') @('dllload', 'X:\Windows\System32\wlansvc.dll', 'WlanSvcMain')
Run ('dll-wcmsvc') @('dllload', 'X:\Windows\System32\wcmsvc.dll', 'WcmSvcMain')
Run ('dll-wlanmsm') @('dllload', 'X:\Windows\System32\wlanmsm.dll')
Run ('dll-wlanutil') @('dllload', 'X:\Windows\System32\wlanutil.dll')
Run ('dll-wci') @('dllload', 'X:\Windows\System32\wci.dll')
Run ('dll-dmc') @('dllload', 'X:\Windows\System32\dmcmnutils.dll')

L '===== 3. 边启动边采样(抓过渡态和 Win32ExitCode) ====='
Run ('watch-wlansvc') @('svc', 'watch', 'wlansvc', '8000', 'start')
L '  --- wcmsvc ---'
Run ('watch-wcmsvc') @('svc', 'watch', 'wcmsvc', '5000', 'start')

L '===== 4. 依赖链 + wlanapi 句柄 ====='
Run ('deps-wlansvc') @('deps', 'wlansvc')
Run ('status') @('status')

L '===== 5. svchost 侧: 有没有进程加载过 wlansvc.dll ====='
$hit = @()
foreach ($p in @(Get-Process svchost -EA SilentlyContinue)) {
  try { foreach ($m in $p.Modules) { if ($m.ModuleName -match '^(wlansvc|wcmsvc|wlanmsm)\.dll$') { $hit += ($p.Id.ToString() + ':' + $m.ModuleName) } } } catch { }
}
L ('  ' + $(if ($hit.Count) { $hit -join ', ' } else { '无进程加载 wlansvc/wcmsvc/wlanmsm' }))
foreach ($n in @('wlansvc', 'wcmsvc')) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { L ('  ' + $n + ' WMI State=' + $q.State + ' PID=' + $q.ProcessId + ' ExitCode=0x' + ('{0:X8}' -f [uint32]($q.ExitCode -band 0xFFFFFFFF))) }
}

L '===== 6. 网络适配器侧(有没有 miniport 可绑) ====='
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue)) {
  L ('  ' + $a.Name + ' | GUID=' + $a.GUID + ' | NetEnabled=' + $a.NetEnabled + ' | PNPDeviceID=' + $a.PNPDeviceID)
}

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($H + '/result') -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
