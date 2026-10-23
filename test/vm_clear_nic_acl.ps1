# 清掉 VM 网卡上的 Port ACL(IPSec 过滤器) —— 它会让主机发往 VM 的包在 vSwitch 端口被丢弃, 而 VM 出站正常
#   只读预检: powershell -NoProfile -ExecutionPolicy Bypass -File test\vm_clear_nic_acl.ps1
#   动手:    加 -Fix            (管理员窗口)
param([switch]$Fix, [string]$VmName = 'WinPE-Test', [string]$Peer = '172.26.18.238', [switch]$Reboot, [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'vm_acl_log.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function Retest($tag, $ip) {
  Add ('[retest ' + $tag + ' ' + $ip + ']')
  Add ('  neighbor: ' + (((Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '=' + $_.State + '/' + $_.LinkLayerAddress }) -join ' , ')))
  $p = ((& ping -n 4 -w 800 $ip 2>&1 | ForEach-Object { $_.ToString() }) -join ' ') -replace '\s+', ' '
  Add ('  ping: ' + $p)
  $c = New-Object Net.Sockets.TcpClient
  $ar = $c.BeginConnect($ip, 22, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) {
    $s = $c.GetStream(); $b = New-Object byte[] 96
    try { $n = $s.Read($b, 0, 96); Add ('  tcp22 BANNER: ' + ([Text.Encoding]::ASCII.GetString($b, 0, $n)).Trim()) } catch { Add '  tcp22 OPEN, 读不到 banner' }
  } else { Add '  tcp22: SYN 无回应' }
  $c.Close()
  Add ('  => ' + $(if ($p -match 'TTL=') { '通了' } else { '还是不通' }))
  ($p -match 'TTL=')
}

Add ('isAdmin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
if (-not $Fix) { Add 'DRY-RUN (只读)。动手请加 -Fix' }
Add ''
Add '===== 现状 ====='
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) {
    Add ('vm=' + $v.Name + ' state=' + $v.State + ' nic=' + $a.Name + ' switch=' + $a.SwitchName + ' mac=' + $a.MacAddress)
    foreach ($p in @('IpSecConfigurationStatus','DynamicMacAddressing','StaticMacAddress','MacAddressSpoofing','DhcpGuard','RouterGuard','IovWeight','VMQWeight')) {
      Add ('   ' + $p + ' = ' + $a.$p)
    }
  }
}
Add ('  host ips: ' + (((Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress + '@' + $_.InterfaceAlias }) -join ' , ')))
if ($Peer) { $null = Retest 'before' $Peer }
if (-not $Fix) { Add ''; Add '未做改动。确认输出后加 -Fix'; Flush; return }

Add ''
Add '===== 清 ACL / 关掉 IPSec 过滤 ====='
foreach ($v in @(Get-VM -ErrorAction SilentlyContinue)) {
  foreach ($a in @(Get-VMNetworkAdapter -VMName $v.Name -ErrorAction SilentlyContinue)) {
    try { Set-VMNetworkAdapter -VMName $v.Name -Name $a.Name -IpSec NoFiltering; Add ('  ' + $v.Name + '/' + $a.Name + ' -> IpSec NoFiltering') }
    catch { Add ('  ' + $v.Name + '/' + $a.Name + ' NoFiltering 失败: ' + $_.Exception.Message) }
    try { Get-VMNetworkAdapterAcl -AdapterName $a.Name -VMName $v.Name -ErrorAction SilentlyContinue | ForEach-Object { Add ('   残留 ACL: ' + $_.Action + ' ' + $_.Direction + ' ' + $_.RemoteIPAddress) } } catch { }
  }
}
if ($Reboot) {
  Add ''
  Add ('===== 重启 ' + $VmName + ' =====')
  try { Restart-VM -Name $VmName -Force; Add '  已重启, 等 50 秒' } catch { Add ('  Restart-VM 失败: ' + $_.Exception.Message) }
  Start-Sleep 50
  Add ('  扫描 pe-sshd:')
  $o = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'find_pe.ps1') -SubnetList '192.168.0,172.26' -Exclude '192.168.0.107' 2>&1 | ForEach-Object { $_.ToString() }
  foreach ($x in $o) { Add ('   ' + $x) }
  $pe = @($o | Select-String 'pe-sshd')
  if ($pe.Count -gt 0) {
    $ip = (($pe[0].ToString() -replace '.*?(\d+\.\d+\.\d+\.\d+):22.*', '$1'))
    Add ('  找到 PE: ' + $ip)
    if (Retest 'after-reboot' $ip) { Add ('  现在可以:  ssh Administrator@' + $ip) }
  } else { Add '  没扫到 pe-sshd' }
} else {
  Add ''
  if ($Peer) { $null = Retest 'after' $Peer }
  Add '提示: 加 -Reboot 可以顺手重启 PE 并自动找回地址复测。'
}
Flush
