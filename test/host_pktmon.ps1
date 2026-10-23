# 用 pktmon 抓"主机发起 -> PE"的包在数据路径哪个组件被丢: 组件级计数器 + 丢包原因 + 包级 ETL 文本
#   管理员窗口: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_pktmon.ps1
param(
  [string]$PeIP = '192.168.100.2',
  [string]$HostIP = '192.168.100.1',
  [int]$PePort = 22,
  [string]$OutFile = '',
  [string]$EtlFile = '',
  [string]$TxtFile = '',
  [switch]$DryRun
)
$ErrorActionPreference = 'Continue'
$tag = 'pktmon_result.txt'
if ($DryRun) { $tag = 'pktmon_dryrun.txt' }
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot $tag }
if (-not $EtlFile) { $EtlFile = Join-Path $PSScriptRoot 'pktmon.etl' }
if (-not $TxtFile) { $TxtFile = Join-Path $PSScriptRoot 'pktmon_pkt.txt' }
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Flush { Set-Content -Path $OutFile -Value ($L -join "`r`n") -Encoding UTF8 }
function Run($exe, $args2) {
  if ($DryRun) { return @('WOULD RUN: ' + $exe + ' ' + ($args2 -join ' ')) }
  $o = @()
  try { $o = @(& $exe $args2 2>&1 | ForEach-Object { $_.ToString() }) } catch { $o = @('EXCEPTION ' + $_.Exception.Message) }
  $o
}

Add ('===== host_pktmon ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' =====')
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Add ('isAdmin=' + $isAdmin + '  DryRun=' + $DryRun)
if (-not $isAdmin -and -not $DryRun) { Add '需要管理员权限(pktmon 要驱动), 请在管理员 PowerShell 里重跑'; Flush; return }
Add ('host iface ip check: ' + (((Get-NetIPAddress -InterfaceAlias 'vEthernet (PE-INT)' -AddressFamily IPv4 -ErrorAction SilentlyContinue) | ForEach-Object { $_.IPAddress }) -join ','))

Add ''
Add '===== 1. 清筛选器并只留 PE-INT 相关的包 ====='
foreach ($x in @(Run pktmon @('filter', 'remove'))) { Add ('  ' + $x) }
foreach ($x in @(Run pktmon @('filter', 'add', 'peint', '-i', $HostIP, $PeIP))) { Add ('  ' + $x) }
foreach ($x in @(Run pktmon @('filter', 'add', 'arp', '-d', 'ARP'))) { Add ('  ' + $x) }
foreach ($x in @(Run pktmon @('filter', 'list'))) { Add ('  ' + $x) }

Add ''
Add '===== 1b. 流量前的计数器基线(和第 3 节对比才知道这轮丢了多少) ====='
foreach ($x in @(Run pktmon @('counters', '--type', 'all'))) { Add ('  ' + ($x -replace '\s+', ' ')) }
foreach ($x in @(Run pktmon @('status'))) { Add ('  status: ' + ($x -replace '\s+', ' ')) }

Add ''
Add ('===== 2. 开始捕获 + 制造流量(4 个 ping + 1 次 tcp' + $PePort + ') =====')
foreach ($x in @(Run pktmon @('start', '--capture', '--pkt-size', '128', '-f', $EtlFile))) { Add ('  ' + $x) }
Start-Sleep 2
foreach ($x in @((& ping -n 4 -w 800 -S $HostIP $PeIP 2>&1 | ForEach-Object { $_.ToString() }))) { Add ('  ping| ' + ($x -replace '\s+', ' ')) }
$c = New-Object System.Net.Sockets.TcpClient
try {
  $ar = $c.BeginConnect($PeIP, $PePort, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) { Add '  tcp SYN|ACK 收到了' } else { Add '  tcp SYN 无回应' }
} catch { Add ('  tcp ERR ' + $_.Exception.Message) } finally { $c.Close() }
Start-Sleep 2
foreach ($x in @(Run pktmon @('stop'))) { Add ('  ' + $x) }

Add ''
Add '===== 3. 组件计数器(含丢包原因) ====='
foreach ($x in @(Run pktmon @('counters', '--type', 'all', '--drop-reason'))) { Add ('  ' + ($x -replace '\s+', ' ')) }

Add ''
Add '===== 4. 组件清单(把组件 ID 对上网卡) ====='
foreach ($x in @(Run pktmon @('list'))) { Add ('  ' + ($x -replace '\s+', ' ')) }

Add ''
Add '===== 5. 包级明细 ====='
if (Test-Path $EtlFile) {
  foreach ($x in @(Run pktmon @('etl2txt', $EtlFile, '-o', $TxtFile))) { Add ('  ' + $x) }
  if (Test-Path $TxtFile) {
    $t = @(Get-Content $TxtFile -ErrorAction SilentlyContinue)
    Add ('  etl2txt 行数=' + $t.Count)
    $keep = @($t | Select-String -Pattern ('192\.168\.100|ARP|ICMP|DROP|Drop|drop|' + $PePort) -Context 1, 2 | Select-Object -First 120)
    foreach ($k in $keep) { Add ('  > ' + (($k.Line -replace '\s+', ' ').Trim())) ; foreach ($p in @($k.Context.PostContext)) { Add ('    ' + (($p -replace '\s+', ' ').Trim())) } }
  } else { Add '  etl2txt 没产出文件' }
} else { Add '  没有 etl 文件, 捕获可能没起来' }
Add ''
Add ('明细全文在: ' + $TxtFile)
Add ''
Add '===== 6. 收尾(清筛选器, 别留会话) ====='
foreach ($x in @(Run pktmon @('filter', 'remove'))) { Add ('  ' + $x) }
foreach ($x in @(Run pktmon @('unload'))) { Add ('  unload: ' + ($x -replace '\s+', ' ')) }
Flush
Add ('WROTE ' + $OutFile)
