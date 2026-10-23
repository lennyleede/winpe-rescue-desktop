# PE 侧热修 v4: 按真实 Windows 的语义改 svchost 组 (组值是"服务名"列表, 不是 DLL 路径)
# 由主机经隧道下发: test\host_wifiprobe.ps1 -Payload vm_wififix4.ps1
$ErrorActionPreference = 'Continue'
$log = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $log.Add($m); Write-Host $m }
$W = 'X:\wifi.exe'
$SVCHOST = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'

try {
  Invoke-WebRequest -UseBasicParsing -Uri 'http://172.31.32.1:8000/file/wifi.exe' -OutFile $W
  L ('A. DL wifi.exe OK ' + (Get-Item $W).Length)
} catch { L ('A. DL 失败: ' + $_.Exception.Message) }
function Run([string]$tag, [string[]]$args2) {
  $o = (& $W @args2 2>&1 | Out-String)
  L ('--- ' + $tag + ' ---')
  foreach ($line in ($o -split "`r?`n")) { if ($line.Trim()) { L ('  ' + $line.Trim()) } }
}

L '===== B. PE 里的相关 svchost 组现在装了什么 ====='
foreach ($g in @('LocalSystemNetworkRestricted', 'LocalServiceNetworkRestricted', 'PEWLan')) {
  $v = @(('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST' | Get-Item).GetValue($g))
  L ('  ' + $g + ' 条数=' + $v.Count + ' 含wlansvc=' + ($v -contains 'wlansvc') + ' 样例=' + (($v | Select-Object -First 4) -join '|'))
}

L '===== C. 把 wlansvc 塞进标准组 LocalSystemNetworkRestricted (真机就在这里) ====='
$cur = @((Get-Item $SVCHOST).GetValue('LocalSystemNetworkRestricted'))
if ($cur.Count -eq 0) { L '  PE 没有这个组, 中止' } else {
  if ($cur -notcontains 'wlansvc') {
    $new = $cur + 'wlansvc'
    Set-ItemProperty $SVCHOST -Name LocalSystemNetworkRestricted -Value $new -Type MultiString
    L ('  组已追加 wlansvc, 新条数=' + (@((Get-Item $SVCHOST).GetValue('LocalSystemNetworkRestricted')).Count))
  } else { L '  组里已有 wlansvc' }
  Set-ItemProperty $SVC -Name ImagePath -Value '%SystemRoot%\System32\svchost.exe -k LocalSystemNetworkRestricted -p' -Type ExpandString
  Set-ItemProperty $SVC -Name Group -Value 'TDI' -Type String
  Set-ItemProperty $SVC -Name Type -Value 32 -Type DWord
  Set-ItemProperty $SVC -Name ObjectName -Value 'LocalSystem' -Type String
  Set-ItemProperty $SVC -Name ServiceSidType -Value 1 -Type DWord
  Set-ItemProperty $SVC -Name DependOnService -Value @('RpcSs') -Type MultiString
  Set-ItemProperty $SVC -Name RequiredPrivileges -Value @('SeChangeNotifyPrivilege','SeImpersonatePrivilege','SeAuditPrivilege','SeTcbPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege') -Type MultiString
  L ('  ImagePath=' + ((Get-ItemProperty $SVC).ImagePath))
  # PEWLan 里那条 DLL 路径是错的语义, 顺手清掉, 免得 svchost 再被它误导
  $pe = @((Get-Item $SVCHOST).GetValue('PEWLan'))
  L ('  PEWLan 目前=' + ($pe -join '|'))
}

L '===== D. 起服务并轮询 ====='
Run 'svc start wlansvc' @('svc', 'start', 'wlansvc')
$ok = $false
for ($i = 1; $i -le 15; $i++) {
  Start-Sleep -Seconds 2
  $q = Get-CimInstance Win32_Service -Filter "Name='wlansvc'" -EA SilentlyContinue
  L ('  t=' + ($i * 2) + 's state=' + $(if ($q) { $q.State } else { '?' }) + ' exit=' + $(if ($q) { $q.ExitCode } else { '?' }) + ' pid=' + $(if ($q) { $q.ProcessId } else { '?' }))
  if ($q -and $q.State -eq 'Running') { $ok = $true; break }
  if ($q -and $q.State -eq 'Stopped') { break }
}

L '===== E. 有没有 svchost 真加载了 wlansvc.dll ====='
$found = $false
foreach ($p in @(Get-Process svchost -EA SilentlyContinue)) {
  try { foreach ($m in $p.Modules) { if ($m.ModuleName -match '^(wlansvc|wcmsvc)\.dll$') { $found = $true; L ('  pid=' + $p.Id + ' 加载 ' + $m.ModuleName) } } } catch {}
}
if (-not $found) { L '  没有 svchost 加载 wlansvc.dll' }
$cmd = @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue | Where-Object { $_.CommandLine -match 'LocalSystemNetworkRestricted' })
foreach ($c in $cmd) { L ('  svchost pid=' + $c.ProcessId + ' cmd=' + $c.CommandLine) }

L '===== F. wlanapi 视角 ====='
Run 'status' @('status')

L ('===== 结论: wlansvc ' + $(if ($ok) { 'RUNNING' } else { '仍未起来' }) + ' =====')
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri 'http://172.31.32.1:8000/result' -Body ([Text.Encoding]::UTF8.GetBytes(($log -join "`r`n"))) | Out-Null
  Write-Host 'RESULT-POSTED'
} catch { Write-Host ('RESULT-POST-FAIL ' + $_.Exception.Message) }
