# 只验证一件事: PowerShell 能不能绑定 FwPolicy2 的参数化属性 setter(set_FirewallEnabled)
#   做法: 读当前值 -> 用同一个值写回 -> 再读 -> 比较。绝不改动主机现有防火墙开关状态。
#   用途: 交付 PE 脚本前先证明调用写法能跑通, 不让用户当第一个测试者
param([switch]$DryRun)
$ErrorActionPreference = 'Continue'
$adm = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ('isAdmin=' + $adm)
try {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  Write-Host ('FwPolicy2 OK rules=' + $fw.Rules.Count)
} catch { Write-Host ('FwPolicy2 不可用: ' + $_.Exception.Message); exit 1 }
$mm = @($fw | Get-Member | Where-Object { $_.Name -like '*FirewallEnabled*' })
foreach ($m in $mm) { Write-Host ('成员: ' + $m.Name + '  类型=' + $m.MemberType + '  定义=' + $m.Definition) }
foreach ($pp in @(@('Domain', 1), @('Private', 2), @('Public', 4))) {
  $lbl = [string]$pp[0]; $id = [int]$pp[1]
  $before = $null
  try { $before = $fw.FirewallEnabled($id) } catch { Write-Host ($lbl + ' get 失败: ' + $_.Exception.Message); continue }
  Write-Host ($lbl + '(' + $id + ') get=' + $before)
  try {
    $fw.set_FirewallEnabled($id, $before)
    $after = $fw.FirewallEnabled($id)
    Write-Host ($lbl + ' set 同值回写 OK, 读回=' + $after + '  未改变=' + ($after -eq $before))
  } catch {
    Write-Host ($lbl + ' set_FirewallEnabled 失败: ' + $_.Exception.Message)
    try {
      $null = $fw.GetType().InvokeMember('FirewallEnabled', 'SetProperty', $null, $fw, @($id, $before))
      Write-Host ($lbl + ' InvokeMember SetProperty OK, 读回=' + ($fw.FirewallEnabled($id)))
    } catch { Write-Host ($lbl + ' InvokeMember 也失败: ' + $_.Exception.Message) }
  }
}
Write-Host 'PROBE DONE'
