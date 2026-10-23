# PE 侧防火墙栈探针: 判定"主机发来的 IP 包在客户机里被谁吃了"
# 下发: 主机跑 host_serve.ps1 -Script vm_fw_probe.ps1, PE 里粘一条命令即可(结果自动 POST 回主机)
param([string]$HostIp = '', [int]$Port = 8000, [int]$SampleSeconds = 60, [switch]$SkipStart)
$ErrorActionPreference = 'Continue'
if (-not $HostIp) {
  $own = @(& ipconfig 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '192\.168\.100\.' }
  if ($own.Count -gt 0) { $HostIp = '192.168.100.1' } else { $HostIp = '192.168.0.106' }
}
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $L.Add([string]$s) }
function Fmt($obj, $names) {
  if (-not $obj) { return '(none)' }
  $p = @()
  foreach ($k in $names) { $p += ($k + '=' + [string]$obj.$k) }
  ($p -join ' ')
}
function RegVal($path, $name) {
  try {
    $v = (Get-ItemProperty -Path $path -ErrorAction SilentlyContinue).$name
    if ($null -eq $v) { return '(absent)' }
    if ($v -is [Array]) { return (@($v) -join '/') }
    return [string]$v
  } catch { return 'ERR ' + $_.Exception.Message }
}

Add '### A. 防火墙相关服务键是否存在(注册表为准)'
$svcBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\'
foreach ($n in @('BFE', 'MpsSvc', 'mpsdrv', 'RpcSs', 'Dnscache', 'SharedAccess')) {
  $p = $svcBase + $n
  $exists = (Test-Path $p)
  Add ('  ' + $n + ' key=' + $exists)
  if ($exists) {
    Add ('     Start=' + (RegVal $p 'Start') + ' Type=' + (RegVal $p 'Type') + ' ImagePath=' + (RegVal $p 'ImagePath') + ' ObjectName=' + (RegVal $p 'ObjectName') + ' DependOnService=' + (RegVal $p 'DependOnService'))
  }
}

Add ''
Add '### B. mpsdrv 的开机期过滤器(boot-time filters, 服务没起也会生效)'
Add ('  mpsdrv\BootTimeFilters      = ' + (RegVal ($svcBase + 'mpsdrv') 'BootTimeFilters'))
Add ('  mpsdrv\Parameters 子键       = ' + ((@(Get-ChildItem ($svcBase + 'mpsdrv\Parameters') -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })) -join ','))
Add ('  BFE\Parameters\Policy 子键   = ' + ((@(Get-ChildItem ($svcBase + 'BFE\Parameters\Policy') -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })) -join ','))
Add ('  MpsSvc\Parameters\Service    = ' + ((@(Get-ChildItem ($svcBase + 'MpsSvc\Parameters') -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })) -join ','))
$fp = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
foreach ($prof in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
  Add ('  ' + $prof + ' EnableFirewall=' + (RegVal ($fp + '\' + $prof) 'EnableFirewall') + ' (键存在=' + (Test-Path ($fp + '\' + $prof)) + ')')
}

Add ''
Add '### C. 驱动/内核组件状态(Win32_SystemDriver)'
try {
  $drv = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Where-Object { $_.Name -match 'mps|fwp|bfe|netvsc|ndis|vmswitch' })
  if ($drv.Count -eq 0) { Add '  (没匹配到)' } else { foreach ($d in $drv) { Add ('  ' + (Fmt $d @('Name', 'State', 'StartMode', 'PathName'))) } }
} catch { Add ('  Win32_SystemDriver 不可用: ' + $_.Exception.Message) }

Add ''
Add '### D. 防火墙相关文件在不在'
foreach ($f in @('bfe.dll', 'mpssvc.dll', 'fwpkclnt.sys', 'wfp.h', 'FirewallPolicySnapIn.dll')) {
  $p = 'X:\Windows\System32\' + $f
  Add ('  ' + $f + ' = ' + (Test-Path $p))
}

Add ''
Add '### E. 试着把 BFE / MpsSvc 起来(起来后开机期过滤器会被交互策略替换)'
foreach ($s in @('BFE', 'MpsSvc')) {
  if ($SkipStart) { Add ('  (net start ' + $s + ' 跳过, -SkipStart)') }
  else {
    $o = @((& net.exe start $s 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '\S' })
    Add ('  net start ' + $s + ' -> ' + ($o -join ' | '))
  }
  try {
    $st = @(Get-CimInstance Win32_Service -Filter "Name='$s'" -ErrorAction Stop | ForEach-Object { Fmt $_ @('Name', 'State', 'StartMode', 'StartName', 'ExitCode') })
    if ($st.Count -gt 0) { Add ('     ' + ($st -join ' ')) } else { Add '     (WMI 里没有这个服务)' }
  } catch { Add ('     WMI 查询失败: ' + $_.Exception.Message) }
}

Add ''
Add ('### F. netstat -s 协议栈计数增量(这段时间主机要持续 ping 192.168.100.2)')
Add ('  意义: 只有 IPv4/ICMP 的 Received 涨了, 才说明包真进了客户机 TCP/IP 栈; 不涨=网卡/驱动层就没交给栈')
function Snap {
  $h = @{}
  $sect = '(top)'
  foreach ($ln in @(& netstat.exe -s 2>&1 | ForEach-Object { $_.ToString() })) {
    $t = $ln.Trim()
    if ($t -notmatch '\S') { continue }
    $m = [regex]::Match($t, '^(.*?)\s*=\s*(\d+)\s*$')
    if ($m.Success) { $h[($sect + ' / ' + $m.Groups[1].Value.Trim())] = [int64]$m.Groups[2].Value; continue }
    $sect = $t
  }
  $h
}
try {
  $a = Snap
  Add ('  采集到字段数=' + $a.Keys.Count + '  采样窗口=' + $SampleSeconds + 's')
  if ($a.Keys.Count -lt 5) { Add '  (netstat -s 好像没输出计数, 下面直接看原文)' }
  Start-Sleep ([int]$SampleSeconds)
  $b = Snap
  Add '  -- 有变化的计数 --'
  $changed = @($b.Keys | Where-Object { $a.ContainsKey($_) -and ([int64]$b[$_] -ne [int64]$a[$_]) } | Sort-Object)
  if ($changed.Count -eq 0) { Add '    (无: 这段时间协议栈既没收到也没发出任何被统计的包)' }
  foreach ($k in $changed) { Add ('    ' + $k + '  ' + $a[$k] + ' -> ' + $b[$k]) }
  Add '  -- 全量快照(第二次) --'
  foreach ($k in @($b.Keys | Sort-Object)) { Add ('    ' + $k + ' = ' + $b[$k]) }
} catch { Add ('  netstat -s 不可用: ' + $_.Exception.Message) }

$text = ($L -join "`r`n")
$text | Out-Host
try { [IO.File]::WriteAllText('X:\fw_probe.txt', $text, (New-Object Text.UTF8Encoding($true))) } catch { ('写 X:\fw_probe.txt 失败: ' + $_.Exception.Message) | Out-Host }
$body = [Text.Encoding]::UTF8.GetBytes($text)
try {
  (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
  ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功') | Out-Host
} catch {
  ('POST 失败: ' + $_.Exception.Message) | Out-Host
  ('手查: type X:\fw_probe.txt') | Out-Host
}
