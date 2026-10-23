# PE 侧防火墙放行实验(两阶段, 带时间戳, 用主机 ping_watch.txt 的时间线归因)
#   阶段 B: 防火墙保持开启, 用 COM(HNetCfg.FwPolicy2) 加"允许 TCP 22 入站 + 允许 ICMP echo request"
#   阶段 A: 若 B 没用, 把三个 profile 的 EnableFirewall 置 0 并重启 MpsSvc
# 下发: 主机跑 host_serve.ps1 -Script vm_fw_fix.ps1, PE 里粘一条命令, 结果自动 POST 回主机
param(
  [string]$HostIp = '',
  [int]$Port = 8000,
  [int]$Observe = 30,
  [string]$Only = '',
  [switch]$ShowOnly
)
$ErrorActionPreference = 'Continue'
if (-not $HostIp) {
  $own = @(& ipconfig 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '192\.168\.100\.' }
  if ($own.Count -gt 0) { $HostIp = '192.168.100.1' } else { $HostIp = '192.168.0.106' }
}
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Stamp { (Get-Date -Format 'HH:mm:ss') }
function RegVal($path, $name) {
  try {
    $v = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
    if ($null -eq $v) { return '(absent)' }
    return [string]$v
  } catch { return 'ERR ' + $_.Exception.Message }
}
function NetStat($pats) {
  $r = @()
  foreach ($ln in @(& netstat.exe -s 2>&1 | ForEach-Object { $_.ToString() })) {
    foreach ($p in $pats) { if ($ln -match $p) { $r += (($ln -replace '\s+', ' ').Trim()) } }
  }
  $r
}
$WATCH = @('Packets Received', 'Received Packets Delivered', 'Segments Received', 'Passive Opens', 'Current Connections', 'Echo', '接收', '发送', '连接')

Add ('===== vm_fw_fix ' + (Stamp) + '  Only=' + $Only + '  Observe=' + $Observe + 's =====')
Add ''
Add '### 0. 起点状态'
$fp = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
foreach ($prof in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
  Add ('  ' + $prof + ' EnableFirewall=' + (RegVal ($fp + '\' + $prof) 'EnableFirewall'))
}
$bt = 'HKLM:\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\BootTime'
$bti = Get-Item $bt -ErrorAction SilentlyContinue
if ($bti) { Add ('  BFE\Parameters\Policy\BootTime 值 = ' + (($bti.GetValueNames()) -join ',')) } else { Add '  BFE\Parameters\Policy\BootTime 键不存在' }
foreach ($s in @('BFE', 'MpsSvc')) {
  Add ('  ' + $s + ' ' + ((@(Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue | ForEach-Object { 'State=' + $_.State + ' StartMode=' + $_.StartMode })) -join ' '))
}
Add ('  计数起点: ' + ((NetStat $WATCH) -join ' | '))

Add ''
if ($Only -eq 'A' -or $ShowOnly) {
  Add '### B 跳过 (-Only A 或 -ShowOnly)'
} else {
  Add ('### 1. 阶段 B: 保持防火墙开启, 加允许规则(观察窗 ' + $Observe + ' 秒)')
  try {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    Add ('  FwPolicy2 可用, 现有规则数=' + $fw.Rules.Count)
    Add ('  FirewallEnabled Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
    $r1 = New-Object -ComObject HNetCfg.FwRule
    $r1.Name = 'PE allow TCP 22'
    $r1.Protocol = 6
    $r1.LocalPorts = '22'
    $r1.Action = 1
    $r1.Direction = 1
    $r1.Enabled = $true
    $r1.Profiles = 7
    Add ('  加规则1(放行 入站 TCP 22): ReturnValue=' + $fw.Rules.Add($r1))
    $r2 = New-Object -ComObject HNetCfg.FwRule
    $r2.Name = 'PE allow ICMPv4 echo'
    $r2.Protocol = 1
    $r2.Action = 1
    $r2.Direction = 1
    $r2.Enabled = $true
    $r2.Profiles = 7
    $r2.IcmpTypesAndCodes = '8:0'
    Add ('  加规则2(放行 入站 ICMP echo request): ReturnValue=' + $fw.Rules.Add($r2))
    Add ('  规则数现在=' + $fw.Rules.Count)
  } catch { Add ('  阶段 B 失败: ' + $_.Exception.Message) }
  Add ('  [' + (Stamp) + '] 进入观察窗, 主机请保持 ping')
  Start-Sleep ([int]$Observe)
  Add ('  [' + (Stamp) + '] 观察后计数: ' + ((NetStat $WATCH) -join ' | '))
}

Add ''
if ($Only -eq 'B' -or $ShowOnly) {
  Add '### 2 跳过 (-Only B 或 -ShowOnly)'
} else {
  Add ('### 2. 阶段 A: 三个 profile EnableFirewall=0 并重启 MpsSvc(观察窗 ' + $Observe + ' 秒)')
  foreach ($prof in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
    $p = $fp + '\' + $prof
    if (-not (Test-Path $p)) { Add ('  ' + $prof + ' 键不存在, 跳过'); continue }
    try {
      Set-ItemProperty -Path $p -Name 'EnableFirewall' -Value 0 -Type DWord -ErrorAction Stop
      Add ('  ' + $prof + ' EnableFirewall -> ' + (RegVal $p 'EnableFirewall'))
    } catch { Add ('  ' + $prof + ' 写失败: ' + $_.Exception.Message) }
  }
  $o = @((& net.exe stop MpsSvc 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '\S' })
  Add ('  net stop MpsSvc -> ' + ($o -join ' | '))
  Start-Sleep 2
  $o = @((& net.exe start MpsSvc 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '\S' })
  Add ('  net start MpsSvc -> ' + ($o -join ' | '))
  Add ('  [' + (Stamp) + '] 进入观察窗')
  Start-Sleep ([int]$Observe)
  Add ('  [' + (Stamp) + '] 观察后计数: ' + ((NetStat $WATCH) -join ' | '))
  Add ('  MpsSvc ' + ((@(Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue | ForEach-Object { 'State=' + $_.State })) -join ' '))
}

Add ''
Add ('### 3. 结束 ' + (Stamp))
$text = ($L -join "`r`n")
try { [IO.File]::WriteAllText('X:\fw_fix.txt', $text, (New-Object Text.UTF8Encoding($true))) } catch { Add ('写 X:\fw_fix.txt 失败: ' + $_.Exception.Message) }
$body = [Text.Encoding]::UTF8.GetBytes($text)
try {
  (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
  Add ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功')
} catch {
  Add ('POST 失败: ' + $_.Exception.Message)
  Add ('手查: type X:\fw_fix.txt')
}
