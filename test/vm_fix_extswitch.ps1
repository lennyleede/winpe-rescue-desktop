# 修复主机<->PE 单向不通。分两步, 每步后立刻复测, 全程写 test\vm_fix_log.txt
#   步骤A: 拆掉重复子网 —— WLAN 现在没有载波却仍挂着 192.168.0.100/24, 先把无线口禁用
#   步骤B: 清理 PE-EXT 上残留的 management-OS 空壳网卡 + 重新绑定 + 刷新 VM 端口
# 只读预检:  powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_fix_extswitch.ps1
# 动手:     加 -Fix            (管理员窗口)
# 只跑A:    加 -Fix -SkipB     只跑B: 加 -Fix -SkipA
param([switch]$Fix, [switch]$SkipA, [switch]$SkipB, [string]$VmName = 'WinPE-Test',
      [string]$Peer = '192.168.0.108', [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_fix_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Output $s }
function Blk($t) { Add ''; Add ('===== ' + $t + ' ====='); Write-Output '' }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function Retest($tag) {
  Add ('[retest ' + $tag + ']')
  Add ('  neighbor: ' + (((Get-NetNeighbor -IPAddress $Peer -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State }) -join ' , ')))
  $p = ((& ping -n 3 -w 800 $Peer 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  ping: ' + $p)
  $c = New-Object Net.Sockets.TcpClient
  $ar = $c.BeginConnect($Peer, 22, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
    $s = $c.GetStream(); $b = New-Object byte[] 96
    try { $n = $s.Read($b, 0, 96); Add ('  tcp22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim()) } catch { Add '  tcp22 OPEN, 读不到 banner' }
  } else { Add '  tcp22: SYN 仍无回应' }
  $c.Close()
  $script:RetestOk = ($p -match 'TTL=')
  Add ("  => " + $(if ($script:RetestOk) { '通了' } else { '还是不通' }))
}

Blk 'elevation + 现状'
Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not $Fix) { Add 'DRY-RUN (只读, 不改任何东西)。动手请加 -Fix' }
foreach ($s in @(Get-VMSwitch -ErrorAction SilentlyContinue)) { Add ('switch ' + $s.Name + ' type=' + $s.SwitchType + ' uplink=' + $s.NetAdapterInterfaceDescription + ' allowMgmtOS=' + $s.AllowManagementOS) }
foreach ($a in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)) { Add ('hostvnic ' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress) }
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) {
    Add ('vm=' + $v.Name + ' state=' + $v.State + ' nic=' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress +
         ' macSpoof=' + $a.MacAddressSpoofing + ' dhcpGuard=' + $a.DhcpGuard + ' routerGuard=' + $a.RouterGuard)
  }
}
Get-NetAdapter | ForEach-Object { Add ('nic ' + $_.Name + ' | ' + $_.InterfaceDescription + ' | ' + $_.Status + ' | ' + $_.MacAddress + ' | ' + $_.PhysicalMediaType) }
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.0.*' } |
  ForEach-Object { Add ('ip ' + $_.InterfaceAlias + ' = ' + $_.IPAddress + '/' + $_.PrefixLength + ' metric=' + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue).InterfaceMetric) }
$null = Retest 'before'
if (-not $Fix) { Add ''; Add '未做任何改动。确认输出后: ... -Fix'; Flush; return }

$physWired = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -eq '802.3' } | Select-Object -First 1
$physWlan  = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -like '*802.11*' } | Select-Object -First 1
$ext = @(Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.SwitchType -eq 'External' }) | Select-Object -First 1

if (-not $SkipA) {
  Blk '步骤A: 禁用无线网卡, 消掉重复的 192.168.0.0/24'
  if ($physWlan) {
    try { Disable-NetAdapter -Name $physWlan.Name -Confirm:$false -ErrorAction Stop; Add ('disabled ' + $physWlan.Name + ' (要恢复: Enable-NetAdapter -Name ' + $physWlan.Name + ')') }
    catch { Add ('禁用失败: ' + $_.Exception.Message) }
    Start-Sleep 6
  } else { Add '没找到无线网卡' }
  Retest 'A'
  if ($script:RetestOk) { Add '步骤A 就解决了, 不动交换机。'; Flush; return }
}

if (-not $SkipB) {
  Blk '步骤B1: 删除 external switch 上的空壳 host vNIC'
  $mgmt = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)
  $wiredMac = ($physWired.MacAddress -replace '-', '')
  $orphans = @($mgmt | Where-Object { $_.SwitchName -eq $ext.Name -and $_.MacAddress -ne $wiredMac })
  if ($orphans.Count -eq 0) { Add '没有空壳(或都是有效绑定)' }
  foreach ($o in $orphans) {
    try { Remove-VMNetworkAdapter -InputObject $o; Add ('removed name=' + $o.Name + ' mac=' + $o.MacAddress) } catch { Add ('remove 失败: ' + $_.Exception.Message) }
  }
  Start-Sleep 4

  Blk '步骤B2: 把 external switch 重新绑到有线网卡'
  try { Set-VMSwitch -Name $ext.Name -NetAdapterName $physWired.Name -AllowManagementOS $true; Add ('Set-VMSwitch ' + $ext.Name + ' -> ' + $physWired.Name) }
  catch { Add ('Set-VMSwitch 失败: ' + $_.Exception.Message) }
  Start-Sleep 6

  Blk '步骤B3: 刷新 VM 端口(断开再接回) + 开 macSpoofing'
  $n = @(Get-VMNetworkAdapter -VMName $VmName -ErrorAction SilentlyContinue) | Select-Object -First 1
  if ($n) {
    try { Set-VMNetworkAdapter -VMName $VmName -Name $n.Name -MacAddressSpoofing On; Add ('macSpoof=On on ' + $n.Name) } catch { Add ('macSpoof 设置失败: ' + $_.Exception.Message) }
    try { Disconnect-VMNetworkAdapter -VMName $VmName -Name $n.Name; Add ('disconnected ' + $n.Name) } catch { Add ('disconnect 失败: ' + $_.Exception.Message) }
    Start-Sleep 3
    try { Connect-VMNetworkAdapter -VMName $VmName -Name $n.Name -SwitchName $ext.Name; Add ('reconnected -> ' + $ext.Name) } catch { Add ('connect 失败: ' + $_.Exception.Message) }
  } else { Add ('找不到 ' + $VmName + ' 的网卡') }
  Start-Sleep 6
  $null = Retest 'B'
}

Blk '收尾'
Add '如果还不通: PE 侧需要重启一次 VM(拿新链路), 然后重跑本脚本的 -Fix -SkipA 只复测。'
Add ('无线网卡恢复命令: Enable-NetAdapter -Name ' + $(if ($physWlan) { $physWlan.Name } else { 'WLAN' }))
Flush
