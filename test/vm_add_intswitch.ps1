# 兜底方案: 给 VM 再加一块 Internal 交换机网卡, 专走 主机<->PE, 完全绕开物理网卡/路由器
#   主机侧(管理员, 只读预检):  powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_add_intswitch.ps1
#   主机侧(动手):            加 -Fix
#   之后 PE 里(重启 VM 后):   netsh interface show interface   看清名字, 再
#                     netsh interface ip set address name="Ethernet 2" static 192.168.100.2 255.255.255.0
#   然后主机:  ssh Administrator@192.168.100.2
param([switch]$Fix, [string]$VmName = 'WinPE-Test', [string]$SwitchName = 'PE-INT',
      [string]$NicName = 'PE-INT', [string]$HostIp = '192.168.100.1', [string]$PeIp = '192.168.100.2',
      [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_intswitch_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Output $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }

Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Add ('vm=' + $VmName + ' switch=' + $SwitchName + ' host=' + $HostIp + ' pe=' + $PeIp)
if (-not $Fix) { Add 'DRY-RUN (只读)。动手请加 -Fix' }

$vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if (-not $vm) { Add ('找不到 VM ' + $VmName); Flush; return }
Add ('vm state=' + $vm.State)
foreach ($a in @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue)) {
  Add ('现有网卡: ' + $a.Name + ' -> ' + $a.SwitchName + ' mac=' + $a.MacAddress)
}
$sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if ($sw) { Add ('交换机已存在: ' + $sw.Name + ' type=' + $sw.SwitchType) } else { Add ('将创建 Internal 交换机 ' + $SwitchName) }

if (-not $Fix) { Add '未做改动。确认无误后加 -Fix'; Flush; return }

if (-not $sw) {
  try { $sw = New-VMSwitch -Name $SwitchName -SwitchType Internal; Add ('created switch ' + $SwitchName) }
  catch { Add ('New-VMSwitch 失败: ' + $_.Exception.Message); Flush; return }
}
$hvNic = Get-NetAdapter -Name ('vEthernet (' + $SwitchName + ')') -ErrorAction SilentlyContinue
if (-not $hvNic) { Add '找不到主机侧 vEthernet (PE-INT)' } else {
  $have = Get-NetIPAddress -InterfaceIndex $hvNic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $HostIp }
  if ($have) { Add ('主机侧已有 ' + $HostIp) }
  else {
    try { New-NetIPAddress -InterfaceIndex $hvNic.ifIndex -IPAddress $HostIp -PrefixLength 24 | Out-Null; Add ('主机侧配好 ' + $HostIp + '/24') }
    catch { Add ('New-NetIPAddress 失败: ' + $_.Exception.Message) }
  }
}
$existing = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue | Where-Object { $_.SwitchName -eq $SwitchName })
if ($existing.Count -gt 0) { Add ('VM 已在 ' + $SwitchName + ' 上: ' + $existing[0].Name) }
else {
  try { Add-VMNetworkAdapter -VMName $VmName -Name $NicName -SwitchName $SwitchName | Out-Null; Add ('已给 VM 加网卡 ' + $NicName + ' -> ' + $SwitchName) }
  catch { Add ('Add-VMNetworkAdapter 失败: ' + $_.Exception.Message) }
}
Add ''
Add '下一步(必须重启 PE, WinPE 不热插拔):'
Add ('  Restart-VM -Name ' + $VmName + ' -Force')
Add '  PE 起来后在 cmd 里:'
Add '    netsh interface show interface'
Add ('    netsh interface ip set address name="Ethernet 2" static ' + $PeIp + ' 255.255.255.0')
Add ('    (名字以 netsh 输出为准, 新那块通常叫 Ethernet 2)'  )
Add ('主机侧验证: ping ' + $PeIp + '  然后  ssh Administrator@' + $PeIp)
Flush
