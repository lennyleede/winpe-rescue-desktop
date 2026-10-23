# 干掉 PE-EXT 上那块借用了无线网卡 MAC、还带着 192.168.0.100/24 的空壳 host 网卡
#   只读预检: powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_kill_ghost_nic.ps1
#   动手:    加 -Fix
param([switch]$Fix, [string]$Peer = '192.168.0.108', [string]$GhostMac = 'D83BBF3671F3', [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_ghost_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Output $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function Retest($tag) {
  Add ('[retest ' + $tag + ']')
  Add ('  ipconfig on host: ' + (((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.0.*' } | ForEach-Object { $_.IPAddress + '@' + $_.InterfaceAlias }) -join ' , ')))
  Add ('  neighbor: ' + (((Get-NetNeighbor -IPAddress $Peer -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State }) -join ' , ')))
  $p = ((& ping -n 4 -w 800 $Peer 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  ping: ' + $p)
  $c = New-Object Net.Sockets.TcpClient
  $ar = $c.BeginConnect($Peer, 22, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
    $s = $c.GetStream(); $b = New-Object byte[] 96
    try { $n = $s.Read($b, 0, 96); Add ('  tcp22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim()) } catch { Add '  tcp22 OPEN, 读不到 banner' }
  } else { Add '  tcp22: SYN 无回应' }
  $c.Close()
  $script:RetestOk = ($p -match 'TTL=')
  Add ('  => ' + $(if ($script:RetestOk) { '通了' } else { '还是不通' }))
}

Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not $Fix) { Add 'DRY-RUN (只读)。动手请加 -Fix' }

Add ''
Add '===== 现状 ====='
foreach ($a in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)) { Add ('hostvnic ' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress) }
foreach ($n in @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'vEthernet*' -or $_.Status -ne 'Up' })) {
  Add ('nic ' + $n.Name + ' | ' + $n.InterfaceDescription + ' | ' + $n.Status + ' | ' + $n.MacAddress)
}
foreach ($i in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.*' })) {
  Add ('ip ' + $i.InterfaceAlias + ' = ' + $i.IPAddress + '/' + $i.PrefixLength + ' ifIdx=' + $i.ifIndex)
}
$null = Retest 'before'
if (-not $Fix) { Add '未做改动。确认无误后加 -Fix'; Flush; return }

Add ''
Add '===== 摘掉 192.168.0.100 这个重复子网地址 ====='
$dup = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.0.*' -and $_.InterfaceAlias -like 'vEthernet*' })
foreach ($d in $dup) {
  try { Remove-NetIPAddress -InterfaceIndex $d.ifIndex -IPAddress $d.IPAddress -Confirm:$false -ErrorAction Stop; Add ('removed ' + $d.IPAddress + ' on ' + $d.InterfaceAlias) }
  catch { Add ('remove ip 失败: ' + $_.Exception.Message) }
}
if ($dup.Count -eq 0) { Add '没有挂在 vEthernet 上的 192.168.0.x' }

Add ''
Add '===== 删除借用无线 MAC(' + $GhostMac + ') 的空壳 host 网卡 ====='
$ghost = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object { $_.MacAddress -eq $GhostMac })
if ($ghost.Count -eq 0) { Add '没找到该 MAC 的 host 网卡(可能已被 Set-VMSwitch 清掉)' }
foreach ($g in $ghost) {
  try { Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $g.Id } | Remove-VMNetworkAdapter -ErrorAction Stop; Add ('removed ' + $g.Name + ' mac=' + $g.MacAddress + ' id=' + $g.Id) }
  catch { Add ('remove 失败: ' + $_.Exception.Message) }
}
Start-Sleep 5

Add ''
Add '===== 复测 ====='
$null = Retest 'after'
if (-not $script:RetestOk) {
  Add ''
  Add '还是不通的话, PE 侧要重启一次拿干净链路(刚才端口被断开重接过):'
  Add '  Restart-VM -Name WinPE-Test -Force'
  Add '起来后 ipconfig 看新地址, 再跑一次本脚本(不带 -Fix)复测。'
} else {
  Add ''
  Add '通了。直接: ssh Administrator@' + $Peer
}
Add ''
Add ('无线恢复: Enable-NetAdapter -Name WLAN   (需要重新插无线时)')
Flush
