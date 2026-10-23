# 冷启动验收探针(只读): 证明"离线注册表 + 开机脚本"这两条防火墙关闭路线在真镜像里各自是什么状态
#   重要: 本脚本绝不写 FirewallEnabled、不停服务 —— 写了就分不清是镜像的功劳还是探针的功劳
#   主机侧配套: 同时跑 test\ping_watch.ps1(看 REPLY)与 test\probe_pe_tcp.ps1 / ssh_diag.ps1 看入站
# 下发: test\host_pe_exec.ps1 -Payload vm_coldboot_accept.ps1   (或 host_serve 走 /file/)
param(
  [string]$HostIp = '192.168.100.1',
  [int]$Port = 8000,
  [int]$Win = 15,
  [string]$OutFile = 'X:\coldboot_accept.txt',
  [switch]$ShowOnly,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Stamp { (Get-Date -Format 'HH:mm:ss') }
function RegVal($path, $name) {
  try { return [string]((Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name) }
  catch { return ('读不到(' + $_.Exception.Message.split("`r`n")[0] + ')') }
}
function Svc($nm) {
  try {
    $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $nm + '''') -ErrorAction Stop
    if (-not $s) { return 'NO-SUCH-SERVICE' }
    return ('State=' + $s.State + ' StartMode=' + $s.StartMode + ' ExitCode=0x' + ('{0:X8}' -f [int]$s.ExitCode))
  } catch { return '查询失败: ' + $_.Exception.Message }
}
function NetStat($pats) {
  $r = @()
  foreach ($ln in @(& netstat.exe -s 2>&1 | ForEach-Object { $_.ToString() })) {
    foreach ($p in $pats) { if ($ln -match $p) { $r += (($ln -replace '\s+', ' ').Trim()) } }
  }
  $r
}
function Tail($f, $n) {
  if (-not (Test-Path $f)) { Add ('  ' + $f + ' 不存在'); return }
  $ls = @(& Get-Content -Path $f -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -Last $n)
  Add ('  -- ' + $f + ' 末 ' + $ls.Count + ' 行 --')
  foreach ($x in $ls) { Add ('    ' + $x) }
}

if ($SelfTest) {
  Add ('===== vm_coldboot_accept SELFTEST(干跑, 不落 X:) ' + (Stamp) + ' =====')
  $OutFile = 'coldboot_accept_selftest.txt'
} else {
  Add ('===== vm_coldboot_accept ' + (Stamp) + '  只读验收  窗口=' + $Win + 's =====')
}
Add ''
Add '### 0. 本机身份与网络(证明是从新 ISO 起来的 PE)'
Add ('  COMPUTERNAME=' + $env:COMPUTERNAME + '  Build=' + (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).BuildNumber)
# 自证新起: X: 是内存盘, 只要 LastBoot 早于 ISO 打包时间, 后面所有"痕迹"都是上一轮留下的, 不能算验收
$lb = (Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).LastBootUpTime
Add ('  LastBoot=' + $lb + '   现在=' + (Get-Date))
if ($lb -and ((Get-Date) - $lb).TotalHours -gt 1) {
  Add ('  !! 开机到现在 ' + [int]((Get-Date) - $lb).TotalMinutes + ' 分钟 —— 这不是刚冷启动的会话, X:\ 里的痕迹可能是上一轮测试留下的, 本次结论作废')
}
$own = @(& ipconfig 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '192\.168\.100\.' }
foreach ($o in $own) { Add ('  ' + $o.Trim()) }
if ($own.Count -eq 0) { Add '  !! 没有 192.168.100.x 地址: 主机侧 SSH/ping 都无从谈起(先跑那条 EnableStatic)' }

Add ''
Add '### 1. 镜像里到底有没有开机脚本(证明 build.ps1 的复制清单生效)'
Add ('  X:\Windows\System32\fw_off.ps1 存在=' + (Test-Path 'X:\Windows\System32\fw_off.ps1') +
  '  大小=' + ((Get-Item 'X:\Windows\System32\fw_off.ps1' -ErrorAction SilentlyContinue).Length))

Add ''
Add '### 2. 离线注册表那条路(烘进 boot.wim 的值, 开机即生效)'
Add ('  MpsSvc Start       = ' + (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc' 'Start') + '   (期望 4=Disabled)')
foreach ($pp in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
  Add ('  ' + $pp + ' EnableFirewall = ' + (RegVal ('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' + $pp) 'EnableFirewall') + '   (期望 0)')
}
Add ('  MpsSvc ' + (Svc 'MpsSvc'))
Add ('  BFE    ' + (Svc 'BFE'))

Add ''
Add '### 3. 运行时策略的真值(FwPolicy2 只读)'
$fw = $null
try {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  Add ('  FwPolicy2 OK 规则数=' + $fw.Rules.Count + '  Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
} catch { Add ('  FwPolicy2 不可用: ' + $_.Exception.Message + '  (MpsSvc 被禁用时这是预期表现)') }

Add ''
Add ('### 4. 开机脚本留下的痕迹(证明 [1b] 段真跑过)')
$bootLog = 'X:\boot.log'
if (Test-Path $bootLog) {
  # startnet.cmd 是 GBK 写的, 它 echo 进 boot.log 的中文用 -Encoding Default 在 PE 里会变码符, 显式按 936 解
  $bl = @()
  try {
    $bl = @([Text.Encoding]::GetEncoding(936).GetString([IO.File]::ReadAllBytes($bootLog)) -split "`r`n")
  } catch {
    $bl = @(& Get-Content -Path $bootLog -Encoding Default -ErrorAction SilentlyContinue | ForEach-Object { $_.ToString() })
  }
  $hits = @($bl | Where-Object { $_ -match '\[1b\]|fw_off' })
  Add ('  -- boot.log 里 [1b]/fw_off 相关 ' + $hits.Count + ' 行 --')
  foreach ($h in $hits) { Add ('    ' + $h.Trim()) }
  if ($hits.Count -eq 0) { Add '    !! 一行都没有: startnet 的 [1b] 段可能没进镜像或没执行到' }
} else { Add '  X:\boot.log 不存在' }
Tail 'X:\fw_off.log' 12
Tail 'X:\status.txt' 10

Add ''
Add ('### 5. 入站连通性观察窗 ' + $Win + ' 秒(这段时间主机侧请持续 ping 与探 22 端口)')
$WATCH = @('Echo Requests Received', 'Echo Replies Sent', 'Segments Received', 'Passive Opens')
Add ('  [' + (Stamp) + '] 前: ' + ((NetStat $WATCH) -join ' | '))
Start-Sleep ([int]$Win)
Add ('  [' + (Stamp) + '] 后: ' + ((NetStat $WATCH) -join ' | '))
Add '  说明: 防火墙关着 -> 主机的 ping 会让 Echo Replies Sent 增长、TCP SYN 会让 Passive Opens 增长'

Add ''
Add '### 6. 判定'
$startVal = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\MpsSvc' 'Start'
$svcLine = Svc 'MpsSvc'
$allFalse = $false
if ($fw) { $allFalse = (-not $fw.FirewallEnabled(1)) -and (-not $fw.FirewallEnabled(2)) -and (-not $fw.FirewallEnabled(4)) }
if ($startVal -eq '4' -and $svcLine -match 'State=Stopped') {
  Add '  离线注册表生效: MpsSvc 开机就是 Stopped/Disabled —— 防火墙这条服务被彻底禁掉了'
} elseif ($allFalse) {
  Add '  离线注册表没到位(MpsSvc 仍在跑), 但三个 profile 都读到 False -> 是开机脚本 fw_off.ps1 兜住的'
} elseif ($fw) {
  Add '  !! 两条路都没到位: MpsSvc 在跑且 profile 有 True -> 主机侧应表现为 ping/TCP 全 TIMEOUT'
} else {
  Add '  FwPolicy2 读不到且 MpsSvc 状态异常, 按上面第 2/5 节的原始数据人工判定'
}
Add ('  [' + (Stamp) + '] 结束')

$text = ($L -join "`r`n")
try { [IO.File]::WriteAllText($OutFile, $text, (New-Object Text.UTF8Encoding($true))) } catch { Add ('写 ' + $OutFile + ' 失败: ' + $_.Exception.Message) }
if (-not $ShowOnly -and -not $SelfTest) {
  $body = [Text.Encoding]::UTF8.GetBytes($text)
  try {
    (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
    Add ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功')
  } catch {
    Add ('POST 失败: ' + $_.Exception.Message)
    Add ('手查: type ' + $OutFile)
  }
}
