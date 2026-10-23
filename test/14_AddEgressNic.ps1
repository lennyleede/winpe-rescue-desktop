# 给 WinPE-Test 加第二块网卡(Default Switch), 让 PE 有出公网的路 —— 向日葵/frpc 需要
#   为什么: 现有 PE-INT 是 Internal 交换机, 按定义没有上行, PE 拿不到网关/DNS, 所以 sunlogin 连不上服务器。
#   约定: 第一块(静态 MAC 00-15-5D-4E-10-99)继续接 PE-INT, 固定 192.168.100.2/24 且不配网关;
#         第二块接 Default Switch(现 172.17.x.1 NAT), 由 DHCP 自动拿地址和默认路由 => 能出公网。
#   重要: 配地址那条粘贴命令不能再按 IPEnabled=TRUE 广播, 必须按 MAC 只点第一块, 否则两块都会被盖成 192.168.100.2。
# 用法(管理员 PowerShell):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\14_AddEgressNic.ps1 -SelfTest    # 只看计划, 不改任何东西
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\14_AddEgressNic.ps1              # 真加(需要管理员)
param(
  [string]$VmName = 'WinPE-Test',
  [string]$EgressSwitch = 'Default Switch',
  [string]$PeIntMac = '00-15-5D-4E-10-99',
  [string]$PeIntIP = '192.168.100.2',
  [switch]$SelfTest,
  [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
function Say($s) { Write-Host $s }
$PeIntMacWmi = $PeIntMac.Replace('-', ':')
try { Import-Module Hyper-V -ErrorAction Stop } catch { Say ('!! 载入 Hyper-V 模块失败: ' + $_.Exception.Message); exit 1 }

$vm = $null
$err = ''
try { $vm = Get-VM -Name $VmName -ErrorAction Stop } catch { $err = $_.Exception.Message }
if (-not $vm) {
  Say ('!! 拿不到虚拟机 ' + $VmName + ' 的信息: ' + $err)
  if ($err -match '权限|Access|denied') { Say '   这一步要管理员: 请在"以管理员身份运行"的 PowerShell 里执行本脚本(-SelfTest 也要, 因为读 VM 配置本身就要权限)' }
  exit 1
}
Say ('[0] VM=' + $vm.Name + ' 状态=' + $vm.State)

$sw = Get-VMSwitch -Name $EgressSwitch -ErrorAction SilentlyContinue
if (-not $sw) { Say ('!! 找不到交换机 ' + $EgressSwitch + '; 现有: ' + ((Get-VMSwitch | ForEach-Object { $_.Name + '(' + $_.SwitchType + ')' }) -join ', ')); exit 1 }
Say ('[0] 出口交换机=' + $sw.Name + ' 类型=' + $sw.SwitchType)

$wasRunning = ($vm.State -eq 'Running')
$adapters = @(Get-VMNetworkAdapter -VMName $VmName)
Say ('[1] 现有网卡 ' + $adapters.Count + ' 块:')
foreach ($a in $adapters) { Say ('    ' + $a.Name + '  MAC=' + $a.MacAddress + '  Switch=' + $a.SwitchName) }

$already = @($adapters | Where-Object { $_.SwitchName -eq $EgressSwitch })
if ($already.Count -gt 0) { Say ('[2] 已经接了 ' + $EgressSwitch + ' (' + $already[0].Name + '), 不重复加') }
elseif ($SelfTest) { Say ('[2] SelfTest: 计划执行 Add-VMNetworkAdapter -VMName ' + $VmName + ' -SwitchName "' + $EgressSwitch + '" -Name EGRESS') }
else {
  if ($vm.State -ne 'Off') { Say ('[2] 先关掉运行(PE 没有集成服务, 这等于直接断电): Stop-VM -Name ' + $VmName + ' -Force'); Stop-VM -Name $VmName -Force }
  $new = Add-VMNetworkAdapter -VMName $VmName -SwitchName $EgressSwitch -Name 'EGRESS'
  Say ('[2] 已加第二块网卡: EGRESS MAC=' + $new.MacAddress)
}

$lines = @(Get-VMNetworkAdapter -VMName $VmName | ForEach-Object { '    ' + $_.Name + ' MAC=' + $_.MacAddress + ' Switch=' + $_.SwitchName })
Say ('[3] 网卡清单:'); foreach ($l in $lines) { Say $l }

Say ''
Say '[4] 配地址: 不用在 PE 控制台粘了, 主机侧一条命令自动完成(不需要管理员):'
Say '    powershell -NoProfile -ExecutionPolicy Bypass -File test\pe_bootstrap.ps1'
Say ('    它从主机邻居表里找到 PE 的出口地址(出口网卡的 DNS 就是 ' + $EgressSwitch + ' 的网关), 远程把 ' + $PeIntIP + ' 配到 PE-INT 那块上。')
Say '    实在要手工粘(比如 ssh 也进不去时), MAC 必须写成冒号格式 —— PE 的 WMI 里是冒号, Hyper-V 显示的是横杠,'
Say ('    用横杠过滤会一条都不匹配而且静默无输出(踩过): ' + $PeIntMacWmi)
Say ('    X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MacAddress -eq ''' + $PeIntMacWmi + ''' } | Invoke-CimMethod -MethodName EnableStatic -Arguments @{IPAddress=@(''' + $PeIntIP + ''');SubnetMask=@(''255.255.255.0'')} | ForEach-Object { ''ReturnValue='' + $_.ReturnValue }"')
Say '    (出口那块 wpeinit 已经自己 DHCP 好了, 不用再动它; 实在没拿到地址再补 EnableDHCP)'
Say ''
Say '[5] 之后主机侧一条命令回传验收(只读):'
Say '    powershell -NoProfile -ExecutionPolicy Bypass -File test\host_pe_exec.ps1 -Payload vm_net_audit.ps1'
Say '    期望: L1~L4 全 True(sunlogin.oray.com 可解析 + 443 可达), 第 D 节能看到 SunloginSOS 的 ESTABLISHED 外网连接'
Say ''
Say '[6] 开机:'
if ($SelfTest) {
  Say ('    SelfTest: 跳过 Start-VM (真跑时会执行 Start-VM -Name ' + $VmName + ', 除非加 -NoStart)')
} elseif ($NoStart) {
  Say ('    -NoStart 已指定, 没开机。要自己起: Start-VM -Name ' + $VmName)
} else {
  $st = (Get-VM -Name $VmName).State
  if ($st -eq 'Running') { Say '    VM 已在运行, 不动它(注意: 网卡是热加的, PE 不一定认得, 建议 Restart-VM 走一遍完整开机)' }
  else { Start-VM -Name $VmName; Say ('    已 Start-VM ' + $VmName + ' —— 等桌面出来后, 主机侧跑 test\pe_bootstrap.ps1 配地址(见 [4])') }
}
Say ''
Say ('SelfTest=' + [bool]$SelfTest + $(if ($SelfTest) { '  没改任何东西' } else { '  网卡已就位' }))
Say '提醒: 当前 v8 镜像里没有 pe_host_ed25519, 每次开机会现生成主机密钥, 所以重启后主机侧仍会报'
Say '      REMOTE HOST IDENTIFICATION HAS CHANGED。重构建(#20)带上固定密钥就好了; 这期间每次重启后补一次:'
Say '    powershell -NoProfile -ExecutionPolicy Bypass -File test\trust_pe_host.ps1'
