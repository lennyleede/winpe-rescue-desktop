# 宿主机侧: 确认发往 PE 的包到底从哪块网卡出去、邻居状态、vSwitch 绑定
# powershell -NoProfile -ExecutionPolicy Bypass -File test\host_route_probe.ps1 -Peer 192.168.0.108
param([string]$Peer = '192.168.0.108')
$ErrorActionPreference = 'Continue'
function Sec($t) { Write-Output "`n===== $t =====" }

Sec 'host IPv4'
Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } |
  Sort-Object InterfaceMetric |
  ForEach-Object { Write-Output ("{0,-28} {1,-16} metric={2} ifIdx={3}" -f $_.InterfaceAlias, $_.IPAddress, $_.InterfaceMetric, $_.ifIndex) }

Sec 'routes on 192.168.0/24 + default'
Get-NetRoute | Where-Object { $_.DestinationPrefix -match '^0\.0\.0\.0|^192\.168\.0\.' } |
  Sort-Object RouteMetric |
  ForEach-Object { Write-Output ("{0,-18} via {1,-15} if={2,-26} ifMetric={3} routeMetric={4}" -f $_.DestinationPrefix, $_.NextHop, $_.InterfaceAlias, $_.InterfaceMetric, $_.RouteMetric) }

Sec 'Find-NetRoute (which source/egress does the host pick for PE)'
try {
  Find-NetRoute -RemoteIPAddress $Peer -ErrorAction Stop |
    Select-Object -First 4 |
    ForEach-Object { Write-Output ("src={0}  out={1}" -f $_.IPAddress, $_.InterfaceAlias) }
} catch { Write-Output ('Find-NetRoute 失败: ' + $_.Exception.Message) }

Sec 'neighbor'
Get-NetNeighbor -IPAddress $Peer -ErrorAction SilentlyContinue |
  ForEach-Object { Write-Output ("{0,-28} {1,-14} {2}" -f $_.InterfaceAlias, $_.IPAddress, $_.State) }

Sec 'TCP 22 banner'
$cli = New-Object Net.Sockets.TcpClient
$cli.ReceiveTimeout = 4000
$ar = $cli.BeginConnect($Peer, 22, $null, $null)
if ($ar.AsyncWaitHandle.WaitOne(4000) -and $cli.Connected) {
  $st = $cli.GetStream()
  $buf = New-Object byte[] 96
  try { $n = $st.Read($buf, 0, 96); Write-Output ('BANNER: ' + ([Text.Encoding]::ASCII.GetString($buf, 0, $n)).Trim()) }
  catch { Write-Output '连上了但读不到 banner' }
} else { Write-Output 'SYN 无回应 (filtered / 丢包)' }
$cli.Close()

Sec 'vSwitch 与网卡绑定'
Get-VMSwitch | ForEach-Object { Write-Output ('switch ' + $_.Name + ' kind=' + $_.SwitchType + ' adapters=' + ((Get-VMNetworkAdapter -SwitchName $_.Name -Name * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName) -join ',')) }
Get-NetAdapter | Where-Object { $_.InterfaceDescription -like 'Hyper-V Virtual Ethernet*' } |
  ForEach-Object { Write-Output ('vnic ' + $_.Name + '  desc=' + $_.InterfaceDescription + '  status=' + $_.Status + '  mac=' + $_.MacAddress) }

Sec '防火墙 profile (按网卡)'
Get-NetFirewallProfile | ForEach-Object { Write-Output ($_.Name + ' Enabled=' + $_.Enabled + ' DefaultInbound=' + $_.DefaultInboundAction) }
Get-NetConnectionProfile | ForEach-Object { Write-Output ('profile ' + $_.Name + ' on ' + $_.InterfaceAlias + ' => ' + $_.NetworkCategory) }
