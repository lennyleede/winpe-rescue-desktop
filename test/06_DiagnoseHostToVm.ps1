# 诊断 主机->VM 连接 (普通权限即可)
$VMName = 'WinPE-Test'
$VMIP   = '172.31.38.211'

Write-Host '=== 1. VM 当前 IP (KVP) ==='
try {
  $m = Get-VMNetworkConfiguration -ErrorAction Stop | Where-Object { $_.IPAddresses } | Select-Object -First 3
  if ($m) { $m | ForEach-Object { Write-Host ("  {0} -> {1}" -f $_.Id, ($_.IPAddresses -join ',')) } }
  else { Write-Host '  KVP 无 IP 记录' }
} catch { Write-Host "  KVP 读取失败: $($_.Exception.Message)" }

Write-Host '=== 2. VM 状态 ==='
Get-VM -Name $VMName -ErrorAction SilentlyContinue | Select-Object Name, State | Format-Table -AutoSize | Out-String | Write-Host

Write-Host '=== 3. 主机路由表 (172.31) ==='
$rt = Get-NetRoute -DestinationPrefix '172.31.*' -ErrorAction SilentlyContinue
if ($rt) { $rt | Select-Object InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize | Out-String | Write-Host }
else { Write-Host '  无匹配路由' }

Write-Host '=== 4. ICMP ping VM ==='
$p = Test-Connection -ComputerName $VMIP -Count 2 -Quiet -ErrorAction SilentlyContinue
Write-Host ("  ping {0}: {1}" -f $VMIP, $(if ($p) { 'OK' } else { 'FAIL (NAT 下 ICMP 失败属正常)' }))

Write-Host '=== 5. TCP 端口探测 ==='
foreach ($port in 22, 135, 445, 80) {
  $c = New-Object System.Net.Sockets.TcpClient
  $ok = try { $ar = $c.BeginConnect($VMIP, $port, $null, $null); $ar.AsyncWaitHandle.WaitOne(3000) -and $c.Connected } catch { $false }
  $c.Close()
  Write-Host ("  端口 {0}: {1}" -f $port, $(if ($ok) { 'OPEN' } else { 'CLOSED' }))
}

Write-Host '=== 6. Hyper-V NAT 相关服务 ==='
Get-Service vmcompute, vmms, hns, MNICap -ErrorAction SilentlyContinue | Select-Object Name, Status | Format-Table -AutoSize | Out-String | Write-Host

Write-Host '=== 7. Default Switch 与主机 vEthernet ==='
Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue | Select-Object Name, SwitchType | Format-Table -AutoSize | Out-String | Write-Host
Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress | Format-Table -AutoSize | Out-String | Write-Host

Write-Host 'DONE'
