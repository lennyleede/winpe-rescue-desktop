# 探明 PowerShell 里写 FwPolicy2.FirewallEnabled 的可行语法(宿主机三个 profile 现在都是 False, 所以写 False 是无操作, 不改状态)
#   A: $fw.FirewallEnabled(1) = $false   (参数化属性直接赋值, 先过 check_ps 的语法关)
#   B: GetType().InvokeMember(..., 'SetProperty', ...)  (上一轮已证 E_ACCESSDENIED = 走到了 COM)
#   C: 旧接口 HNetCfg.FwPolicy / FwProfile 有没有更简单的可写属性
param([switch]$NoAssign)
$ErrorActionPreference = 'Continue'
$fw = New-Object -ComObject HNetCfg.FwPolicy2
Write-Host ('A/B 前置: FwPolicy2 OK, Domain 当前=' + $fw.FirewallEnabled(1))
if (-not $NoAssign) {
  try {
    $fw.FirewallEnabled(1) = $false
    Write-Host ('A 参数化属性赋值 执行完成, 读回=' + $fw.FirewallEnabled(1))
  } catch {
    Write-Host ('A 失败: ' + $_.Exception.Message)
  }
} else { Write-Host 'A 跳过 (-NoAssign)' }
try {
  $null = $fw.GetType().InvokeMember('FirewallEnabled', 'SetProperty', $null, $fw, @(1, $false))
  Write-Host ('B InvokeMember 执行完成, 读回=' + $fw.FirewallEnabled(1))
} catch {
  Write-Host ('B 失败: ' + $_.Exception.Message)
}
Write-Host '--- C. 旧接口 ---'
foreach ($cf in @('HNetCfg.FwPolicy', 'HNetCfg.FwProfile', 'HNetCfg.FwPolicy2')) {
  try {
    $o = New-Object -ComObject $cf
    $names = @($o | Get-Member -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Firewall|Enable|Profile' } | ForEach-Object { $_.Name + '[' + $_.MemberType + ']' })
    Write-Host ($cf + ' OK 相关成员: ' + (($names | Select-Object -First 20) -join ', '))
  } catch { Write-Host ($cf + ' 不可用: ' + $_.Exception.Message) }
}
Write-Host 'PROBE2 DONE'
