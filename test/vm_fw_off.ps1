# PE 侧: 验证"运行时用 COM(HNetCfg.FwPolicy2) 把防火墙关掉"是否真的生效
#   为什么不用注册表: 上一轮阶段 A 已证明注册表 EnableFirewall=0 + net stop MpsSvc(被拒 2191) 是空跑
#   为什么先删规则: 上一轮阶段 B 加的两条允许规则还在, 不删掉就无法证明"是关掉防火墙放行的, 不是规则放行的"
# 下发: 主机跑 host_serve.ps1 -Script vm_fw_off.ps1, PE 里粘一条命令, 结果自动 POST 回主机
# 归因: 主机侧同时跑 test\ping_watch.ps1 -OutFile ping_watch3.txt, 用时间戳对齐
param(
  [string]$HostIp = '',
  [int]$Port = 8000,
  [int]$Observe = 30,
  [switch]$ShowOnly,
  [switch]$KeepRules
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
$RULES = @('PE allow TCP 22', 'PE allow ICMPv4 echo')
# 注: FwPolicy2 的 IsRulePresent 在 PowerShell 的 COM 适配器上取不到(找不到方法), 所以用 Rules 集合枚举
function HasRule($obj, $nm) {
  try { return (@($obj.Rules | Where-Object { $_.Name -eq $nm }).Count -gt 0) } catch { return $null }
}

Add ('===== vm_fw_off ' + (Stamp) + '  ShowOnly=' + $ShowOnly + '  KeepRules=' + $KeepRules + '  Observe=' + $Observe + 's =====')
Add ''
Add '### 0. 起点状态'
$fp = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
foreach ($prof in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
  Add ('  ' + $prof + ' EnableFirewall(注册表)=' + (RegVal ($fp + '\' + $prof) 'EnableFirewall'))
}
$fw = $null
try {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  Add ('  FwPolicy2 可用, 规则数=' + $fw.Rules.Count)
  Add ('  FirewallEnabled(运行时策略) Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
  foreach ($nm in $RULES) {
    Add ('    规则 "' + $nm + '" 存在=' + (HasRule $fw $nm))
  }
} catch { Add ('  FwPolicy2 不可用: ' + $_.Exception.Message) }
foreach ($s in @('BFE', 'MpsSvc')) {
  Add ('  ' + $s + ' ' + ((@(Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction SilentlyContinue | ForEach-Object { 'State=' + $_.State + ' StartMode=' + $_.StartMode })) -join ' '))
}
Add ('  计数起点: ' + ((NetStat $WATCH) -join ' | '))

if ($ShowOnly) {
  Add ''
  Add '### -ShowOnly: 只读, 不删规则、不改策略'
} else {
  Add ''
  if ($KeepRules) {
    Add '### 1. 跳过删规则 (-KeepRules)'
  } else {
    Add '### 1. 删掉阶段 B 那两条允许规则(让入站重新被拦, 这样第 3 步才是干净的对照)'
    if ($fw) {
      foreach ($nm in $RULES) {
        $how = ''
        try {
          $fw.Rules.Remove($nm)
          $how = 'Rules.Remove'
        } catch {
          Add ('  Rules.Remove("' + $nm + '") 失败: ' + $_.Exception.Message + ' -> 改用把规则置为未启用')
          try {
            foreach ($r in @($fw.Rules | Where-Object { $_.Name -eq $nm })) { $r.Enabled = $false }
            $how = 'Enabled=$false'
          } catch { Add ('  退化方案也失败: ' + $_.Exception.Message) }
        }
        if ($how) { Add ('  处理 "' + $nm + '" 走的是 ' + $how + ' -> 现在存在=' + (HasRule $fw $nm) + ' 规则数=' + $fw.Rules.Count) }
      }
    } else { Add '  没有 FwPolicy2 句柄, 跳过' }
  }
  Add ('  [' + (Stamp) + '] 基线观察窗开始(预期主机 ping 不通)')
  Start-Sleep ([int]$Observe)
  Add ('  [' + (Stamp) + '] 基线窗结束 计数: ' + ((NetStat $WATCH) -join ' | '))

  Add ''
  Add '### 2. 用 COM 把三个 profile 的 FirewallEnabled 置 False(不重启服务)'
  if ($fw) {
    foreach ($pp in @(@('Domain', 1), @('Private', 2), @('Public', 4))) {
      $lbl = [string]$pp[0]
      $id = [int]$pp[1]
      $done = $false
      try {
        $fw.FirewallEnabled($id) = $false
        Add ('  ' + $lbl + '(' + $id + '): 赋值语法完成, 读回=' + $fw.FirewallEnabled($id))
        $done = $true
      } catch { Add ('  ' + $lbl + '(' + $id + '): 赋值语法失败: ' + $_.Exception.Message) }
      if (-not $done) {
        try {
          $null = $fw.GetType().InvokeMember('FirewallEnabled', 'SetProperty', $null, $fw, @($id, $false))
          Add ('  ' + $lbl + '(' + $id + '): InvokeMember SetProperty 调用完成, 读回=' + $fw.FirewallEnabled($id))
        } catch { Add ('  ' + $lbl + '(' + $id + '): InvokeMember 也失败: ' + $_.Exception.Message) }
      }
    }
    Add ('  注册表 EnableFirewall 现在: Domain=' + (RegVal ($fp + '\DomainProfile') 'EnableFirewall') + ' Standard=' + (RegVal ($fp + '\StandardProfile') 'EnableFirewall') + ' Public=' + (RegVal ($fp + '\PublicProfile') 'EnableFirewall'))
  } else { Add '  没有 FwPolicy2 句柄, 这步做不了' }

  Add ''
  Add ('### 3. 验证窗(观察 ' + $Observe + ' 秒, 主机请保持 ping; 通了就证明关防火墙这条运行时路可行)')
  Add ('  [' + (Stamp) + '] 进入验证窗')
  Start-Sleep ([int]$Observe)
  Add ('  [' + (Stamp) + '] 验证窗结束 计数: ' + ((NetStat $WATCH) -join ' | '))
  if ($fw) {
    Add ('  读回 FirewallEnabled Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
  }
  Add ('  MpsSvc ' + ((@(Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue | ForEach-Object { 'State=' + $_.State })) -join ' '))
}

Add ''
Add ('### 4. 结束 ' + (Stamp))
$text = ($L -join "`r`n")
if ($ShowOnly) {
  try { [IO.File]::WriteAllText((Join-Path (Get-Location) 'fw_off_selftest.txt'), $text, (New-Object Text.UTF8Encoding($true))); Add '已写 fw_off_selftest.txt' } catch { Add ('写自测文件失败: ' + $_.Exception.Message) }
} else {
  try { [IO.File]::WriteAllText('X:\fw_off.txt', $text, (New-Object Text.UTF8Encoding($true))) } catch { Add ('写 X:\fw_off.txt 失败: ' + $_.Exception.Message) }
  $body = [Text.Encoding]::UTF8.GetBytes($text)
  try {
    (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
    Add ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功')
  } catch {
    Add ('POST 失败: ' + $_.Exception.Message)
    Add '手查: type X:\fw_off.txt'
  }
}
