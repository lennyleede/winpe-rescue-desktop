# PE 侧热修: 找出让 wlansvc 在 WinPE 里真正起来的最小配置 (运行时改注册表, 只影响本机内存盘)
# 由主机经 frp 隧道下发: test\host_wififix.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
$SCH = 'HKLM:\SYSTEM\CurrentControlSet\Services\svchost'

L '===== A. 依赖文件是否存在 ====='
foreach ($f in @('drivers\nativewifip.sys','drivers\Ndisuio.sys','drivers\nwifi.sys','nsi.dll','wcmsvc.dll','wlanapi.dll','wlansvc.dll','wlancfg.dll','wlanmsm.dll','fwpuclnt.dll','wci.dll','msvcp_win.dll','rpcrt4.dll','secur32.dll','wkscli.dll','srvcli.dll')) {
  $p = Join-Path $env:SystemRoot ('System32\' + $f)
  L ('  ' + $f.PadRight(26) + $(if (Test-Path $p) { 'YES' } else { 'NO' }))
}

L '===== B. PE 现有 svchost 组 (挑一个能挂 wlansvc.dll 的) ====='
$groups = (Get-Item $SCH -EA SilentlyContinue).GetValueNames()
L ('  组列表: ' + ($groups -join ', '))

L '===== C. 当前 wlansvc 键 ====='
foreach ($n in (Get-Item $SVC).GetValueNames()) {
  L ('  ' + $n + ' = ' + ((Get-ItemProperty $SVC -Name $n).$n -join ';'))
}

function Set-Group($group) {
  $cur = @((Get-ItemProperty $SCH -Name $group).$group)
  if ($cur -notcontains '%SystemRoot%\System32\wlansvc.dll') {
    $new = $cur + '%SystemRoot%\System32\wlansvc.dll'
    Set-ItemProperty $SCH -Name $group -Value $new -Type MultiString
  }
  Set-ItemProperty $SVC -Name ImagePath -Value ("%SystemRoot%\System32\svchost.exe -k " + $group + " -p") -Type ExpandString
  Set-ItemProperty $SVC -Name Type -Value 32 -Type DWord
  Set-ItemProperty $SVC -Name ServiceSidType -Value 1 -Type DWord
  Set-ItemProperty $SVC -Name ObjectName -Value 'LocalSystem' -Type String
  Set-ItemProperty $SVC -Name Group -Value 'TDI' -Type String
  Set-ItemProperty $SVC -Name RequiredPrivileges -Value @('SeChangeNotifyPrivilege','SeImpersonatePrivilege','SeAuditPrivilege','SeTcbPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege') -Type MultiString
  Set-ItemProperty $SVC -Name DependOnService -Value @('RpcSs') -Type MultiString
}
function Try-Start([string]$tag) {
  $ns = (& net.exe start wlansvc 2>&1 | Out-String)
  $q = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue
  L ('  [' + $tag + '] net start => ' + (($ns -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' / '))
  L ('  [' + $tag + '] state=' + $q.State + ' pid=' + $q.ProcessId)
  if ($q.State -eq 'Running') {
    foreach ($p in @(Get-Process -Id $q.ProcessId -EA SilentlyContinue)) {
      try { foreach ($m in $p.Modules) { if ($m.ModuleName -match 'wlan') { L ('    模块 ' + $m.ModuleName) } } } catch {}
    }
  }
  return ($q.State -eq 'Running')
}

L '===== D. 尝试 1: LocalServiceNetworkRestricted + 依赖 RpcSs ====='
$ok = $false
if ($groups -contains 'LocalServiceNetworkRestricted') {
  Set-Group 'LocalServiceNetworkRestricted'
  $ok = Try-Start 'LSNR'
} else { L '  PE 无该组' }

if (-not $ok) {
  L '===== E. 尝试 2: 去掉依赖 ====='
  Remove-ItemProperty $SVC -Name DependOnService -EA SilentlyContinue
  $ok = Try-Start 'no-dep'
}
if (-not $ok) {
  L '===== F. 尝试 3: LocalSystemNetworkRestricted (对照主机真实配置) ====='
  if ($groups -contains 'LocalSystemNetworkRestricted') {
    Set-Group 'LocalSystemNetworkRestricted'
    Remove-ItemProperty $SVC -Name DependOnService -EA SilentlyContinue
    $ok = Try-Start 'LSYSNR'
  } else { L '  PE 无该组' }
}
if (-not $ok) {
  L '===== G. 尝试 4: netsvcs + 依赖 RpcSs ====='
  if ($groups -contains 'netsvcs') {
    Set-Group 'netsvcs'
    Set-ItemProperty $SVC -Name DependOnService -Value @('RpcSs') -Type MultiString
    $ok = Try-Start 'netsvcs'
  } else { L '  PE 无该组' }
}

L '===== H. 收尾: 现在的服务状态与 boot 日志 ====='
L ('  wlansvc 最终 state=' + (Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue).State)
L ('  接口: ' + ((Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' -EA SilentlyContinue | ForEach-Object { $_.Name + '/' + $_.ServiceName }) -join ', '))
L ('  结论: ' + $(if ($ok) { 'wlansvc 在 PE 里可以启动' } else { 'wlansvc 在 PE 里仍起不来' }))

try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
