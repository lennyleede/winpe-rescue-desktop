# 每次重启 PE 后跑这一条就够了: 自动找到 PE 的出口网卡地址 -> 远程把 PE-INT 的 192.168.100.2 配回去 -> 验证两条路都通
#   为什么需要: PE 的 X: 是内存盘, 每次开机 PE-INT(Internal 交换机, 没有 DHCP) 只会拿到 169.254.x 的 APIPA,
#             整套工具链(host_pe_exec / host_serve)默认走 192.168.100.2, 所以要先补回来。
#   怎么找到 PE: 出口网卡接 Default Switch, 它的 DNS 服务器就是主机的 172.17.32.1, 一直在跟主机说话,
#             所以主机的 ARP/邻居表里必然有它的地址 —— 不用人肉看 HTA 状态栏。
#   注意: PE 的 WMI 里 MAC 是冒号格式(00:15:5D:4E:10:99), 不是 Hyper-V 显示的横杠格式; 用横杠过滤会一条都不匹配, 且静默无输出。
#   不需要管理员(读邻居表 + ssh 都是普通权限)。
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\pe_bootstrap.ps1 -SelfTest
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\pe_bootstrap.ps1
param(
  [string]$PeIntMac = '00:15:5D:4E:10:99',
  [string]$PeIntIP = '192.168.100.2',
  [string]$PeIntMask = '255.255.255.0',
  [string]$EgressPattern = '172.17.*',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Tcp22($ip) {
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($ip, 22, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(1200) -and $c.Connected
    $c.Close()
    return $ok
  } catch { return $false }
}

Write-Host '[1] 从主机邻居表里找 PE 的出口地址(Default Switch 网段)...'
$ifIdx = @(Get-NetAdapter | Where-Object { $_.Name -like '*Default Switch*' } | ForEach-Object { $_.ifIndex })
if ($ifIdx.Count -eq 0) { Write-Host '  !! 主机上没有 vEthernet (Default Switch) 这块网卡'; exit 1 }
$cand = @()
foreach ($i in $ifIdx) {
  # 注意: 主机上 Get-NetNeighbor 的 HardwareAddress 经常是空的, 不能拿它当过滤条件(踩过, 会筛出 0 个)
  $cand += @(Get-NetNeighbor -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like $EgressPattern -and $_.IPAddress -ne '172.17.32.1' -and $_.IPAddress -notlike '*.255' -and $_.ConnectionState -ne 'Unreachable' })
}
$cand = @($cand | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
Write-Host ('  候选 ' + $cand.Count + ' 个: ' + ($cand -join ', '))
if ($SelfTest) {
  Write-Host '  SelfTest: 只列候选 + 探 22 端口, 不下发任何配置'
  foreach ($n in $cand) { Write-Host ('    ' + $n + ' tcp22=' + (Tcp22 $n)) }
  Write-Host ('  将要执行的命令: test\host_pe_exec.ps1 -Ip <上面 tcp22=True 的那个> -Cmd "EnableStatic ' + $PeIntIP + '/' + $PeIntMask + ' 到 MAC=' + $PeIntMac + ' 的网卡"')
  exit 0
}
$cmd = '$c = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MacAddress -eq ''' + $PeIntMac + ''' }; ' +
  'if (-not $c) { ''MAC 没匹配上, 现有 MAC: '' + ((Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MacAddress } | ForEach-Object { $_.MacAddress }) -join '',''); exit 1 }; ' +
  '$x = Invoke-CimMethod -InputObject $c -MethodName EnableStatic -Arguments @{IPAddress=@(''' + $PeIntIP + ''');SubnetMask=@(''' + $PeIntMask + ''')}; ' +
  '''EnableStatic ReturnValue='' + $x.ReturnValue; ' +
  'Start-Sleep -Seconds 3; ' +
  '''现在 IP='' + ((Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.MacAddress -eq ''' + $PeIntMac + ''' }).IPAddress -join '','')'

# 22 端口开着的候选可能不止一个(邻居表里还有别的 VM), 挨个试到 EnableStatic 成功为止
$pe = ''
$done = $false
foreach ($n in $cand) {
  if (-not (Tcp22 $n)) { continue }
  Write-Host ('[2] 试 ' + $n + ' ...')
  $out = ''
  try { $out = (& (Join-Path $root 'host_pe_exec.ps1') -Ip $n -Cmd $cmd -TimeoutSec 90 6>&1 | Out-String) } catch { $out = $_.Exception.Message }
  # 远程 powershell 的 progress 记录会以 CLIXML 形式混进 stderr, 从那儿截断, 只看有用输出
  $ls = @($out -split "`r?`n")
  $cut = -1
  for ($k = 0; $k -lt $ls.Count; $k++) { if ($ls[$k] -match 'CLIXML|^<Objs ') { $cut = $k; break } }
  if ($cut -ge 0) { $ls = @($ls[0..($cut - 1)]) }
  foreach ($l in $ls) { Write-Host ('    | ' + $l) }
  if ($out -match 'ReturnValue=0' -or $out -match ([regex]::Escape($PeIntIP))) { $pe = $n; $done = $true; break }
}
if (-not $done) { Write-Host '  !! 所有候选都没配上(PE 不在? ssh 进不去? MAC 变了?)'; exit 1 }
Write-Host ('[3] 用的出口地址 = ' + $pe)

Write-Host ('[4] 验证 ' + $PeIntIP + ':22 ...')
$ok = $false
for ($i = 0; $i -lt 8; $i++) { if (Tcp22 $PeIntIP) { $ok = $true; break }; Start-Sleep -Seconds 2 }
Write-Host ('  ' + $PeIntIP + ' tcp22=' + $ok)
if ($ok) {
  Write-Host '  => 工具链恢复, 接下来照常: test\host_pe_exec.ps1 -Payload vm_net_audit.ps1'
} else {
  Write-Host '  => 静态地址没生效, 把上面 [2] 的输出贴回来(尤其看是不是 MAC 没匹配上)'
  exit 2
}
