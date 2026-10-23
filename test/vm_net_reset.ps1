# 宿主机 Hyper-V 网络收敛: 删掉 PE-EXT 交换机和它的孤儿管理主机网卡, 把 PE 统一挂到一个 Internal 交换机 PE-INT
#   为什么要换成 Internal: PE-EXT(物理网卡)和 Default Switch(NAT/HNS)两条路都验证过"主机发起的包进不去 PE",
#   Internal 交换机只有主机 vNIC 和 VM vNIC 两个端口, 不碰物理网卡、不碰路由器、不碰 HNS, 是唯一能定性的最小环境
#   只读预检:  powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_net_reset.ps1
#   动手:      加 -Fix                (管理员窗口)
#   动手并等 PE 起来复测: 加 -Fix -Wait 300
param(
  [switch]$Fix,
  [switch]$Wlan,
  [string]$VmName = 'WinPE-Test',
  [string]$SwitchName = 'PE-INT',
  [string]$HostIP = '192.168.100.1',
  [string]$PeIP = '192.168.100.2',
  [string]$PeMac = '00-15-5D-4E-10-99',
  [string]$DropExt = 'PE-EXT',
  [switch]$Scrub,
  [int]$Wait = 0,
  [string]$OutFile = ''
)
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_net_reset_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function Props($obj, $tag) {
  if (-not $obj) { return }
  foreach ($pi in @($obj.PSObject.Properties | Where-Object { $_.Name -match 'Flow|Veth|IpSec|IPsec|Strict|Protect|Filter|Guard|Spoof|Acl|Bandwidth' })) {
    Add ('   [' + $tag + '] ' + $pi.Name + ' = ' + $pi.Value)
  }
}
function Test-Pe($ip, $tag) {
  if (-not $ip) { Add ('[' + $tag + '] 没有可测的地址'); return $false }
  Add ('[' + $tag + ' ' + $ip + ']')
  Add ('  neighbor: ' + (((Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State + '/' + $_.LinkLayerAddress }) -join ' , ')))
  $p = ((& ping -n 3 -w 700 $ip 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  ping: ' + $p)
  $ok = ($p -match 'TTL=')
  $c = New-Object Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect($ip, 22, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne(3000) -and $c.Connected) {
      $s = $c.GetStream(); $b = New-Object byte[] 96
      try { $n = $s.Read($b, 0, 96); Add ('  tcp22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim()) } catch { Add '  tcp22 OPEN, banner 读不到' }
      $ok = $true
    } else { Add '  tcp22: SYN 无回应' }
  } catch { Add ('  tcp22 ERR ' + $_.Exception.Message) } finally { $c.Close() }
  Add ('  => ' + $(if ($ok) { '通了' } else { '不通' }))
  $ok
}

$L.Clear()
Add ('===== vm_net_reset ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) + ' Fix=' + $Fix + ' =====')
if (-not $Fix) { Add 'DRY-RUN(只读)。动手加 -Fix' }
Add ''
Add '===== 1. 现状 ====='
foreach ($sw in @(Get-VMSwitch -ErrorAction SilentlyContinue)) {
  Add ('switch=' + $sw.Name + ' type=' + $sw.SwitchType + ' uplink=' + $sw.NetAdapterInterfaceDescription + ' allowMgmt=' + $sw.AllowManagementOS)
  Props $sw $sw.Name
}
Add ('  管理主机 vNIC: ' + (((@(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name + '@' + $_.SwitchName + '(' + $_.MacAddress + ')' })) -join ' , '))
Add ('  孤儿/禁用网卡的 PnP 状态: ' + (((@(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'OK' -and $_.FriendlyName -like 'vEthernet*' } | ForEach-Object { $_.FriendlyName + '=' + $_.Status })) -join ' , ')))
foreach ($n in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
  Add ('netadapter=' + $n.Name + ' status=' + $n.Status + ' mac=' + $n.MacAddress + ' desc=' + $n.InterfaceDescription + ' hidden=' + $n.Hidden)
}
Add ('  host ipv4: ' + (((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength + '@' + $_.InterfaceAlias })) -join ' , '))
$cands = @()
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) {
    Add ('vm=' + $v.Name + ' state=' + $v.State + ' nic=' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress + ' ips=' + (($a.IPAddresses) -join '|'))
    if ($a.IPAddresses) { $cands += @($a.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) }
    if ($v.Name -eq $VmName) { Props $a $v.Name }
    Add ('   AclList=' + (($a.AclList) -join ';') + '  ExtendedAclList=' + (($a.ExtendedAclList) -join ';') + '  (两个都空 = 端口没有 ACL)')
  }
}
# 交换机上查不到 IP 时, 用 ARP 邻居兜底找 PE
if ($cands.Count -eq 0) {
  $cands = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like 'vEthernet*' -and ($_.IPAddress -like '172.26.*' -or $_.IPAddress -like '192.168.100.*') -and $_.State -ne 'Unreachable' -and $_.IPAddress -notmatch '\.(0|255|1)$' } | ForEach-Object { $_.IPAddress })
}
$peer = @($cands | Select-Object -Unique)[0]
if ($peer) { $null = Test-Pe $peer 'before' } else { Add '[before] 没找到 PE 地址' }

if (-not $Fix) {
  Add ''
  Add '===== 2. -Fix 将会执行的动作 ====='
  Add ('  a. 交换机 ' + $DropExt + ' 上次日志已确认不存在, 只补一步: -Scrub 时用 Remove-NetAdapter 删掉残留的 vEthernet (PE-EXT) 2 设备')
  Add ('  b. New-VMSwitch -Name ' + $SwitchName + ' -SwitchType Internal')
  Add ('  c. Add-VMNetworkAdapter -ManagementOS -Name ' + $SwitchName + ' -SwitchName ' + $SwitchName + '  然后配 ' + $HostIP + '/24')
  Add ('  d. Connect-VMNetworkAdapter -VMName ' + $VmName + ' -SwitchName ' + $SwitchName + ' (VM 没开就 Start-VM)')
  Add ('  e. PE 侧需要手工设静态地址 ' + $PeIP + '/24 (脚本会把命令打印出来), 之后主机复测 ping + tcp22')
  Add ('  f. Default Switch 本体不动: 上面有 Container NIC(WSL/Docker) 依赖它')
  Add ('  g. -Wlan 才会 Enable-NetAdapter WLAN (默认保持禁用, 免得又出现两个 192.168.0/24)')
  Flush
  return
}

Add ''
Add ('===== 2. 拆掉 ' + $DropExt + ' =====')
try {
  $orph = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object { $_.SwitchName -eq $DropExt })
  if ($orph.Count -eq 0) { Add '  没有属于该交换机的管理主机 vNIC' }
  foreach ($o in $orph) {
    Add ('  删除管理主机 vNIC: ' + $o.Name + ' mac=' + $o.MacAddress)
    try { Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $o.Id } | Remove-VMNetworkAdapter -ErrorAction Stop } catch {
      Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $o.Id } | Remove-VMNetworkAdapter
    }
  }
} catch { Add ('  管理主机 vNIC 清理失败: ' + $_.Exception.Message) }
try {
  if (Get-VMSwitch -Name $DropExt -ErrorAction SilentlyContinue) {
    Remove-VMSwitch -Name $DropExt -Force -ErrorAction Stop
    Add ('  Remove-VMSwitch ' + $DropExt + ' 完成')
  } else { Add ('  交换机 ' + $DropExt + ' 不存在') }
} catch { Add ('  Remove-VMSwitch 失败: ' + $_.Exception.Message) }

if ($Scrub) {
  Add ''
  Add '===== 2b. 禁用残留的 vEthernet 网卡设备 (-Scrub 才会做) ====='
  foreach ($n in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'vEthernet (' + $DropExt + ')*' -or ($_.Name -eq 'vEthernet (Default Switch)' -and $_.Status -ne 'Up') })) {
    Add ('  目标: ' + $n.Name + ' status=' + $n.Status + ' desc=' + $n.InterfaceDescription)
    if (@(Get-NetIPAddress -InterfaceAlias $n.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).Count -gt 0) { Add '   上面还有 IP, 跳过'; continue }
    try { Disable-NetAdapter -Name $n.Name -Confirm:$false -ErrorAction Stop; Add '   已禁用' } catch { Add ('   Disable-NetAdapter: ' + $_.Exception.Message) }
    Add '   注意: 本机 NetAdapter 模块没有 Remove-NetAdapter, Win32_NetworkAdapter 也没有删除方法 —— 彻底消失要靠重启宿主机; 重启后还在就去设备管理器(查看→显示隐藏的设备→网络适配器→卸载设备)'
  }
} else { Add '  (没加 -Scrub: ncpa.cpl 里残留的 vEthernet (PE-EXT) 2 / vEthernet (Default Switch) 保持原样)' }

Add ''
Add ('===== 3. 建 Internal 交换机 ' + $SwitchName + ' =====')
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
  try { New-VMSwitch -Name $SwitchName -SwitchType Internal -ErrorAction Stop | Out-Null; Add ('  New-VMSwitch ' + $SwitchName + ' 完成') } catch { Add ('  New-VMSwitch 失败: ' + $_.Exception.Message) }
} else { Add ('  交换机 ' + $SwitchName + ' 已存在') }
$alias = 'vEthernet (' + $SwitchName + ')'
$ha = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $alias }
if (-not $ha) {
  try { Add-VMNetworkAdapter -ManagementOS -Name $SwitchName -SwitchName $SwitchName -ErrorAction Stop | Out-Null; Add ('  已建管理主机 vNIC ' + $alias) } catch { Add ('  Add-VMNetworkAdapter 失败: ' + $_.Exception.Message) }
  Start-Sleep 3
  $ha = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $alias }
} else { Add ('  管理主机 vNIC 已存在: ' + $alias + ' status=' + $ha.Status) }
if ($ha) {
  $have = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue
  if ($have -and ($have.IPAddress -eq $HostIP)) { Add ('  主机侧 ' + $HostIP + ' 已就位') }
  else {
    if ($have) { try { Remove-NetIPAddress -InterfaceAlias $alias -IPAddress $have.IPAddress -Confirm:$false -ErrorAction Stop | Out-Null } catch { Add ('   换地址前删除失败: ' + $_.Exception.Message) } }
    try { New-NetIPAddress -InterfaceAlias $alias -IPAddress $HostIP -PrefixLength 24 -ErrorAction Stop | Out-Null; Add ('  主机侧已配 ' + $HostIP + '/24') } catch { Add ('  New-NetIPAddress 失败: ' + $_.Exception.Message) }
  }
}

Add ''
Add ('===== 4. 把 ' + $VmName + ' 的网卡接到 ' + $SwitchName + ' =====')
$ad = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue)
if ($ad.Count -eq 0) { Add ('  找不到 VM ' + $VmName) }
foreach ($a in $ad) {
  try {
    Connect-VMNetworkAdapter -VMName $VmName -Name $a.Name -SwitchName $SwitchName -ErrorAction Stop
    Add ('  已接: nic=' + $a.Name + ' mac=' + $a.MacAddress + ' -> ' + $SwitchName)
  } catch { Add ('  Connect-VMNetworkAdapter 失败: ' + $_.Exception.Message) }
}
$vmst = (Get-VM -Name $VmName -ErrorAction SilentlyContinue).State
if ($vmst -ne 'Running') {
  Add ('  VM 当前 ' + $vmst + ', 正在启动并等 45 秒')
  try { Start-VM -Name $VmName -ErrorAction Stop } catch { Add ('   Start-VM 失败: ' + $_.Exception.Message) }
  Start-Sleep 45
}
if ($Wlan) {
  try { Enable-NetAdapter -Name WLAN -ErrorAction Stop; Add '  WLAN 已启用' } catch { Add ('  启用 WLAN 失败: ' + $_.Exception.Message) }
} else { Add '  (未动 WLAN。要恢复 WiFi 就再加 -Wlan)' }

Add ''
Add '===== 5. PE 侧要做的一步(在 PE 的命令行里整行粘贴) ====='
Add '  其实不用手工粘: 主机侧跑 test\pe_bootstrap.ps1 会自动找到 PE 的出口地址并把静态配好(下面这条是进不去时才用)'
Add ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MacAddress -eq ''' + $PeMac.Replace('-', ':') + ''' } | Invoke-CimMethod -MethodName EnableStatic -Arguments @{IPAddress=@(''' + $PeIP + ''');SubnetMask=@(''255.255.255.0'')} | ForEach-Object { ''ReturnValue='' + $_.ReturnValue }"')
Add ('  注意 MAC 格式: PE 的 WMI 里是冒号分隔(' + $PeMac.Replace('-', ':') + '), Hyper-V 显示的是横杠(' + $PeMac + '); 用横杠过滤会一条都不匹配且静默无输出')
Add ('  按 MAC 只点 PE-INT 那块(静态 MAC ' + $PeMac + '); 一旦 VM 加了第二块网卡走 Default Switch 出公网, ' +
     '老的 -Filter IPEnabled=TRUE 写法会把两块都盖成 ' + $PeIP + ' 从而断掉出口, 所以别再广播配')
Add ('  (老写法, 只有一块网卡时才可用): (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter ''IPEnabled=TRUE'') | Invoke-CimMethod -MethodName EnableStatic -Arguments @{IPAddress=@(''' + $PeIP + ''');SubnetMask=@(''255.255.255.0'')}')
Add ('  备选(先 netsh interface ipv4 show interfaces 看网卡名, 再设): netsh interface ip set address name="以太网" static ' + $PeIP + ' 255.255.255.0')
Add '  注意: PE 里没有 Get-NetAdapter/Get-NetTCPConnection 的 provider(报 Invalid namespace), 只能用 Win32_NetworkAdapterConfiguration 或 netsh'
Add '  (静态地址不要配网关和 DNS, Internal 交换机只有主机和 PE 两端)'
Add ''
Add ('  顺带: 主机侧起了 HTTP 服务后, PE 可以用 iwr http://' + $HostIP + ':8000/v.ps1 拉脚本了')

if ($Wait -le 0) {
  Add ''
  Add '未复测。加 -Fix -Wait 300 让脚本自动等 PE 上线并复测。'
  Flush
  return
}
Add ''
Add ('===== 6. 等 PE ' + $PeIP + ' 上线(最多 ' + $Wait + ' 秒) =====')
$mine = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue)
if ($mine.Count -eq 0) {
  Add ('  主机侧 ' + $alias + ' 上没有 IP(应为 ' + $HostIP + '/24) —— 交换机/管理主机 vNIC 没建成, 不能开始 ping 等待')
  Add '  注意: 主机没有 192.168.100.1 时, ping 192.168.100.2 会走默认路由掉到公网上(表现为"来自 xx 的回复: TTL 传输中过期"), 那不是 PE'
  Flush
  Add ('WROTE ' + $OutFile)
  return
}
Add ('  主机侧已就位: ' + (($mine | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }) -join ','))
$dl = (Get-Date).AddSeconds($Wait)
$round = 0
$ok = $false
while ((Get-Date) -lt $dl) {
  $round++
  $p = ((& ping -n 1 -w 500 $PeIP 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  #' + $round + ' ping: ' + $p)
  if ($p -match 'TTL=') { $ok = $true; break }
  Start-Sleep 3
}
Flush
if ($ok) { $null = Test-Pe $PeIP 'after' ; Add ('  现在可以:  ssh Administrator@' + $PeIP) }
else { Add ('  等不到 ' + $PeIP + ' —— Internal 交换机连直通都不通, 说明 Hyper-V 虚拟交换机本身坏了(下一步: 重启 VMMS 服务 + 禁用/启用物理网卡, 还是不行就重启宿主机)') }
Add ''
Add '===== 收尾现状 ====='
foreach ($sw in @(Get-VMSwitch -ErrorAction SilentlyContinue)) { Add ('switch=' + $sw.Name + ' type=' + $sw.SwitchType + ' uplink=' + $sw.NetAdapterInterfaceDescription + ' allowMgmt=' + $sw.AllowManagementOS) }
foreach ($n in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) { Add ('netadapter=' + $n.Name + ' status=' + $n.Status + ' desc=' + $n.InterfaceDescription) }
Add ('  host ipv4: ' + (((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress + '@' + $_.InterfaceAlias })) -join ' , '))
Flush
Add ('WROTE ' + $OutFile)
