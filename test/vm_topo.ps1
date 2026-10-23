# Read-only Hyper-V network topology dump (needs admin). Result file is read back by the agent.
# Run in an ELEVATED PowerShell:
#   powershell -NoProfile -ExecutionPolicy Bypass -File "D:\QoderProject\...\winpe\test\vm_topo.ps1"
param([string]$OutFile = '', [string]$Peer = '192.168.0.108')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_topo.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $L.Add([string]$s) }
function Blk($t) { Add ''; Add ('===== ' + $t + ' =====') }

Blk 'elevation'
Add ('user=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name)
Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

Blk 'Get-VMSwitch'
foreach ($s in @(Get-VMSwitch -ErrorAction SilentlyContinue)) {
  Add ('switch name=' + $s.Name + '  type=' + $s.SwitchType + '  allowMgmtOS=' + $s.AllowManagementOS + '  uplink=' + $s.NetAdapterInterfaceDescription)
}

Blk 'Get-VM'
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  Add ('vm=' + $v.Name + '  state=' + $v.State + '  gen=' + $v.Generation + '  uptime=' + $v.Uptime)
}

Blk 'VM network adapters (which switch each VM NIC hangs on)'
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) {
    Add ('vm=' + $v.Name + '  nic=' + $a.Name + '  switch=' + $a.SwitchName + '  mac=' + $a.MacAddress +
         '  connected=' + $a.Connected + '  legacy=' + $a.IsLegacy + '  macSpoof=' + $a.MacAddressSpoofing +
         '  dhcpGuard=' + $a.DhcpGuard + '  routerGuard=' + $a.RouterGuard +
         '  dynMac=' + $a.DynamicMacAddressing + '  staticMac=' + $a.StaticMacAddress +
         '  ips=' + (($a.IPAddresses) -join ','))
  }
}

Blk 'PE-EXT switch detail'
foreach ($p in @('Name','Id','SwitchType','NetAdapterInterfaceDescription','AllowManagementOS','EnableEmbeddedTeaming','AdaptiveIPs','IovEnabled','Enumeration')) {
  $vals = @(Get-VMSwitch -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties[$p] } | ForEach-Object { $_.Value })
  Add ($p + ' = ' + ($vals -join ' | '))
}

Blk 'Management OS (host side) vNICs'
foreach ($a in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)) {
  Add ('hostvnic=' + $a.Name + '  switch=' + $a.SwitchName + '  mac=' + $a.MacAddress)
}

Blk 'physical adapters'
foreach ($n in @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)) {
  Add ('phys ' + $n.Name + '  id=' + $n.InterfaceDescription + '  status=' + $n.Status + '  mac=' + $n.MacAddress + '  link=' + $n.LinkSpeed)
}

Blk 'neighbor for PE'
Get-NetNeighbor -IPAddress $Peer -ErrorAction SilentlyContinue | ForEach-Object { Add ($_.InterfaceAlias + '  ' + $_.IPAddress + '  ' + $_.State + '  ' + $_.LinkLayerAddress) }

Blk 'does host->PE traffic hit the physical wire? (adapter statistics delta across 10 pings)'
$wired = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -eq '802.3' -and $_.Status -eq 'Up' } | Select-Object -First 1
if ($wired) {
  $pName = $wired.Name
  $hName = 'vEthernet (PE-EXT) 2'
  $p0 = Get-NetAdapterStatistics -Name $pName -ErrorAction SilentlyContinue
  $h0 = Get-NetAdapterStatistics -Name $hName -ErrorAction SilentlyContinue
  $pr = ((& ping -n 10 -w 500 $Peer 2>&1 | ForEach-Object { $_.ToString() }) -join ' / ') -replace '\s+', ' '
  $p1 = Get-NetAdapterStatistics -Name $pName -ErrorAction SilentlyContinue
  $h1 = Get-NetAdapterStatistics -Name $hName -ErrorAction SilentlyContinue
  Add ('ping out : ' + $pr)
  Add ('phys ' + $pName + '  txDelta=' + ($p1.TransmittedBytes - $p0.TransmittedBytes) + '  rxDelta=' + ($p1.ReceivedBytes - $p0.ReceivedBytes))
  Add ('vnic ' + $hName + '  txDelta=' + ($h1.TransmittedBytes - $h0.TransmittedBytes) + '  rxDelta=' + ($h1.ReceivedBytes - $h0.ReceivedBytes))
  Add 'txDelta>0 on phys = 包被送到线上, 由路由器回折(同端口被丢); txDelta=0 而 vnic>0 = 交换机内部转发, 问题在 PE 侧'
} else { Add 'no wired adapter found' }

Blk 'tcp 22 from host'
$c = New-Object Net.Sockets.TcpClient
$ar = $c.BeginConnect($Peer, 22, $null, $null)
if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) { Add 'tcp 22: OPEN' } else { Add 'tcp 22: SYN no answer' }
$c.Close()

Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8
Write-Output ('WROTE ' + $OutFile)
