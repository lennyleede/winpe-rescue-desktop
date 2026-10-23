# PE 侧热修第 2 轮: 把 wlansvc 的真实依赖链补齐 (nativewifip/Ndisuio/wcmsvc + 伴随 DLL), 看它能不能起来
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wififix2.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$SVCHOST = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'

L '===== A. 从主机取缺失的伴随 DLL ====='
foreach ($f in @('wcmsvc.dll','dmcmnutils.dll','mdmregistration.dll','wci.dll','netshell.dll')) {
  $dst = 'X:\Windows\System32\' + $f
  try {
    Invoke-WebRequest -UseBasicParsing -Uri ('http://172.31.32.1:8000/file/' + $f) -OutFile $dst
    L ('  DL ' + $f + ' OK ' + (Get-Item $dst).Length)
  } catch { L ('  DL ' + $f + ' 失败: ' + $_.Exception.Message) }
}

L '===== B. PE 里 svchost 组 (正确位置: SOFTWARE\...\SVCHOST) ====='
$groups = @((Get-Item $SVCHOST -EA SilentlyContinue).GetValueNames())
L ('  组数=' + $groups.Count + ' 列表=' + (($groups | Sort-Object) -join ','))

L '===== C. 补齐依赖服务键 ====='
function Ensure-DriverSvc([string]$name, [string]$img, [string]$grp) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $name
  if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
  Set-ItemProperty $k -Name Type -Value 1 -Type DWord
  Set-ItemProperty $k -Name Start -Value 3 -Type DWord
  Set-ItemProperty $k -Name ErrorControl -Value 1 -Type DWord
  Set-ItemProperty $k -Name ImagePath -Value $img -Type ExpandString
  Set-ItemProperty $k -Name Group -Value $grp -Type String
  L ('  ' + $name + ' -> ' + $img + ' (file=' + (Test-Path ('X:\Windows\' + ($img -replace 'system32', 'System32'))) + ')')
}
Ensure-DriverSvc 'nativewifip' 'system32\DRIVERS\nwifi.sys' 'NDIS'
Ensure-DriverSvc 'Ndisuio' 'system32\drivers\ndisuio.sys' 'NDIS'
L ('  nsi 服务键存在=' + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\nsi'))

# wcmsvc: 独立 svchost 组 PEWCm
$wc = 'HKLM:\SYSTEM\CurrentControlSet\Services\wcmsvc'
if (-not (Test-Path $wc)) { New-Item $wc -Force | Out-Null }
if (-not ($groups -contains 'PEWCm')) { New-ItemProperty $SVCHOST -Name PEWCm -Value '%SystemRoot%\System32\wcmsvc.dll' -PropertyType MultiString -Force | Out-Null }
Set-ItemProperty $wc -Name Type -Value 32 -Type DWord
Set-ItemProperty $wc -Name Start -Value 3 -Type DWord
Set-ItemProperty $wc -Name ErrorControl -Value 1 -Type DWord
Set-ItemProperty $wc -Name ImagePath -Value '%SystemRoot%\System32\svchost.exe -k PEWCm -p' -Type ExpandString
Set-ItemProperty $wc -Name ObjectName -Value 'LocalService' -Type String
Set-ItemProperty $wc -Name Group -Value 'TDI' -Type String
Set-ItemProperty $wc -Name ServiceSidType -Value 1 -Type DWord
Set-ItemProperty $wc -Name DependOnService -Value @('RpcSs') -Type MultiString
if (-not (Test-Path ($wc + '\Parameters'))) { New-Item ($wc + '\Parameters') -Force | Out-Null }
Set-ItemProperty ($wc + '\Parameters') -Name ServiceDll -Value '%SystemRoot%\System32\wcmsvc.dll' -Type ExpandString
L '  wcmsvc 键已写'

L '===== D. wlansvc 配置对齐主机, 依赖先只留 RpcSs ====='
if (-not ($groups -contains 'PEWLan')) { New-ItemProperty $SVCHOST -Name PEWLan -Value '%SystemRoot%\System32\wlansvc.dll' -PropertyType MultiString -Force | Out-Null }
else {
  $cur = @((Get-ItemProperty $SVCHOST -Name PEWLan).PEWLan)
  if ($cur -notcontains '%SystemRoot%\System32\wlansvc.dll') {
    Set-ItemProperty $SVCHOST -Name PEWLan -Value ($cur + '%SystemRoot%\System32\wlansvc.dll') -Type MultiString
  }
}
Set-ItemProperty $SVC -Name Type -Value 32 -Type DWord
Set-ItemProperty $SVC -Name Start -Value 3 -Type DWord
Set-ItemProperty $SVC -Name ErrorControl -Value 1 -Type DWord
Set-ItemProperty $SVC -Name ImagePath -Value '%SystemRoot%\System32\svchost.exe -k PEWLan -p' -Type ExpandString
Set-ItemProperty $SVC -Name ObjectName -Value 'LocalSystem' -Type String
Set-ItemProperty $SVC -Name Group -Value 'TDI' -Type String
Set-ItemProperty $SVC -Name ServiceSidType -Value 1 -Type DWord
Set-ItemProperty $SVC -Name RequiredPrivileges -Value @('SeChangeNotifyPrivilege','SeImpersonatePrivilege','SeAuditPrivilege','SeTcbPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege') -Type MultiString
Set-ItemProperty $SVC -Name DependOnService -Value @('RpcSs') -Type MultiString
L ('  PEWLan=' + ((Get-ItemProperty $SVCHOST -Name PEWLan).PEWLan -join ';'))
L ('  wlansvc ImagePath=' + (Get-ItemProperty $SVC).ImagePath)

function Start-Svc([string]$n) {
  $r = (& net.exe start $n 2>&1 | Out-String)
  $line = (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)).Trim()
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  L ('  net start ' + $n + ' => ' + ($line -replace '\s+', ' ') + '  [state=' + $(if ($q) { $q.State + ' pid=' + $q.ProcessId } else { '查不到' }) + ']')
  return $(if ($q) { $q.State -eq 'Running' } else { $false })
}

L '===== E. 逐个起服务 ====='
$wcOk = Start-Svc 'wcmsvc'
$wlOk = Start-Svc 'wlansvc'

if (-not $wlOk) {
  L '===== F. 换成完整依赖再试一次 (真机上 nativewifip 会因插着无线网卡而 running) ====='
  Set-ItemProperty $SVC -Name DependOnService -Value @('nativewifip','RpcSs','Ndisuio') -Type MultiString
  $wlOk = Start-Svc 'wlansvc'
  Set-ItemProperty $SVC -Name DependOnService -Value @('RpcSs') -Type MultiString
}

L '===== G. wlansvc.dll 到底加载了没 ====='
$found = $false
foreach ($p in @(Get-Process svchost -EA SilentlyContinue)) {
  try { foreach ($m in $p.Modules) { if ($m.ModuleName -match '^(wlansvc|wcmsvc)\.dll$') { $found = $true; L ('  ' + $p.ProcessName + ' pid=' + $p.Id + ' 加载 ' + $m.ModuleName) } } } catch {}
}
if (-not $found) { L '  没有 svchost 进程加载 wlansvc.dll/wcmsvc.dll' }

L '===== H. 事件日志里 SCM/SideBySide 的报错 ====='
foreach ($lg in @('System','Application')) {
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $lg } -MaxEvents 40 -EA SilentlyContinue |
        Where-Object { $_.ProviderName -match 'Service Control Manager|SideBySide|Application Error|MemoryDiagnostics' })
  L ('  ' + $lg + ' 相关事件 ' + $ev.Count + ' 条')
  foreach ($e in ($ev | Select-Object -First 8)) { L ('   [' + $e.ProviderName + ' ' + $e.Id + '] ' + (($e.Message -split "`n")[0])) }
}

L ('===== 结论: wlansvc 启动 ' + $(if ($wlOk) { '成功' } else { '仍失败' }) + ' / wcmsvc ' + $(if ($wcOk) { '成功' } else { '失败' }))

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
