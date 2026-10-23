# ASCII only, no admin needed: did our VM's MAC ever show up in the host's neighbor table?
# HNS writes a neighbour entry when its DHCP server hands out a lease, so a hit == the PE booted
# far enough to run wpeinit; a miss == it never got to the network stack at all.
$macs = @{ 'WinPE10-Test(static 00155D10E10A)' = '00155D10E10A' }
$all = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)
Write-Host ('IPv4 邻居条目总数 = ' + $all.Count)
foreach ($k in $macs.Keys) {
  $want = $macs[$k]
  $hit = @($all | Where-Object { (($_.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpper()) -eq $want })
  Write-Host ($k + ' -> ' + $(if ($hit.Count) { ($hit | ForEach-Object { $_.IPAddress + '(' + $_.PolicyStore + '/' + $_.ConnectionState + ') ' }) -join '' } else { 'NOT SEEN' }))
}
Write-Host '--- 172.17.* 的邻居(最多 20 条) ---'
foreach ($e in @($all | Where-Object { $_.IPAddress -like '172.17.*' } | Select-Object -First 20)) {
  Write-Host ('  ' + $e.IPAddress + '  ' + $e.LinkLayerAddress + '  ' + $e.PolicyStore + '  ' + $e.ConnectionState)
}
Write-Host '--- 有没有 192.168.100.x(PE-INT 静态段) ---'
foreach ($e in @($all | Where-Object { $_.IPAddress -like '192.168.100.*' } | Select-Object -First 10)) {
  Write-Host ('  ' + $e.IPAddress + '  ' + $e.LinkLayerAddress)
}
Write-Host '--- 宿主接口 ---'
foreach ($i in @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -like '172.17.*' -or $_.IPAddress -like '192.168.100.*' })) {
  Write-Host ('  ' + $i.InterfaceAlias + ' = ' + $i.IPAddress + '/' + $i.PrefixLength)
}
