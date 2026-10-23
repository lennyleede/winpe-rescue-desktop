# 把 PE-EXT 恢复成干净状态(宿主网卡回到交换机上, 只留一个 192.168.0.x), 重启 PE, 自动找回 pe-sshd 的地址并复测
#   只读预检: powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_restore_ext_and_reboot.ps1
#   动手:    加 -Fix            (管理员窗口)
param([switch]$Fix, [string]$VmName = 'WinPE-Test', [string]$SwitchName = 'PE-EXT', [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_restore_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function State($tag) {
  Add ('--- state: ' + $tag + ' ---')
  foreach ($a in @(Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue)) { Add ('  hostvnic ' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress) }
  foreach ($n in @(Get-NetAdapter -ErrorAction SilentlyContinue)) { Add ('  nic ' + $n.Name + ' | ' + $n.InterfaceDescription + ' | ' + $n.Status + ' | ' + $n.MacAddress) }
  foreach ($i in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.*' })) { Add ('  ip ' + $i.InterfaceAlias + ' = ' + $i.IPAddress + '/' + $i.PrefixLength) }
  foreach ($s in @(Get-VMSwitch -ErrorAction SilentlyContinue)) { Add ('  switch ' + $s.Name + ' type=' + $s.SwitchType + ' uplink=' + $s.NetAdapterInterfaceDescription + ' allowMgmtOS=' + $s.AllowManagementOS) }
  foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
    foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) { Add ('  vm ' + $v.Name + ' state=' + $v.State + ' nic=' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress + ' macSpoof=' + $a.MacAddressSpoofing) }
  }
}
function Retest($tag, $ip) {
  Add ('[retest ' + $tag + ' ' + $ip + ']')
  Add ('  neighbor: ' + (((Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State }) -join ' , ')))
  $p = ((& ping -n 4 -w 800 $ip 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  ping: ' + $p)
  $c = New-Object Net.Sockets.TcpClient
  $ar = $c.BeginConnect($ip, 22, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
    $s = $c.GetStream(); $b = New-Object byte[] 96
    try { $n = $s.Read($b, 0, 96); Add ('  tcp22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim()) } catch { Add '  tcp22 OPEN, 读不到 banner' }
  } else { Add '  tcp22: SYN 无回应' }
  $c.Close()
  $script:RetestOk = ($p -match 'TTL=')
  Add ('  => ' + $(if ($script:RetestOk) { '通了' } else { '还是不通' }))
}
function FindPe() {
  $o = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'find_pe.ps1') -SubnetList '192.168.0' -Exclude '192.168.0.107' 2>&1 | ForEach-Object { $_.ToString() }
  $pe = @($o | Select-String 'pe-sshd')
  foreach ($x in $o) { Add ('  scan: ' + $x) }
  if ($pe.Count -gt 0) { return (($pe[0].ToString() -replace '.*?(\d+\.\d+\.\d+\.\d+):22.*', '$1')) }
  return ''
}

Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not $Fix) { Add 'DRY-RUN (只读, 不改任何东西)。动手请加 -Fix' }
State 'now'
if (-not $Fix) { Add ''; Add '未做改动。确认输出后加 -Fix'; Flush; return }

$wired = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -eq '802.3' } | Select-Object -First 1
Add ''
Add ('===== 1) 把 external 交换机重新绑回有线网卡并恢复宿主共享 (' + $wired.Name + ') =====')
try { Set-VMSwitch -Name $SwitchName -NetAdapterName $wired.Name -AllowManagementOS $true; Add 'Set-VMSwitch 完成' } catch { Add ('Set-VMSwitch 失败: ' + $_.Exception.Message) }
Start-Sleep 12
State 'after rebind'
$hasIp = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '192.168.0.*' }).Count
if ($hasIp -eq 0) {
  Add '主机上已经没有 192.168.0.x, 试着续租一次'
  Add (((& ipconfig /renew 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' ')
  Start-Sleep 6
  State 'after renew'
}
Add ('  主机联网自检: ' + (((& ping -n 2 -w 800 223.5.5.5 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '))

Add ''
Add ('===== 2) 重启 ' + $VmName + ' 拿干净链路 =====')
try { Restart-VM -Name $VmName -Force -ErrorAction Stop; Add 'Restart-VM 已发出' } catch { Add ('Restart-VM 失败: ' + $_.Exception.Message) }
Add '等 PE 起来(wpeinit + pe-sshd + 桌面), 45 秒'
Start-Sleep 45

Add ''
Add '===== 3) 找回 pe-sshd 的地址 ====='
$found = ''
for ($r = 1; $r -le 8; $r++) {
  Add ('第 ' + $r + ' 轮扫描:')
  $found = FindPe
  if ($found) { break }
  Start-Sleep 15
}
if (-not $found) { Add '没扫到 pe-sshd 在听 22 (PE 可能没起来或没拿到地址)'; Flush; return }
Add ('找到 PE: ' + $found)
Retest 'pe' $found
if ($script:RetestOk) {
  Add ''
  Add ('  现在可以:  ssh Administrator@' + $found + '     (救援盘默认空密码直接进)')
}
Add ''
Add ('无线恢复命令: Enable-NetAdapter -Name WLAN')
Flush
