# PE 侧往返测试: 先把防火墙重新打开(主机应变不通) -> 再调用"要烘进镜像的那个 fw_off.ps1"关掉(主机应变通)
#   目的: 验证镜像脚本本体(overlay\Scripts\fw_off.ps1)在 PE 里真能用, 而不是只验证我的实验脚本
#   归因: 主机侧同时跑 test\ping_watch.ps1 -OutFile ping_watch4.txt, 用时间戳对齐
# 下发: 主机 host_serve.ps1 -Script vm_fw_roundtrip.ps1, 另外 fw_off.ps1 放 test\share\ 走 /file/
param(
  [string]$HostIp = '',
  [int]$Port = 8000,
  [int]$Gap = 20,
  [string]$FwOffPath = 'X:\fwo.ps1',
  [switch]$ShowOnly
)
$ErrorActionPreference = 'Continue'
if (-not $HostIp) {
  $own = @(& ipconfig 2>&1 | ForEach-Object { $_.ToString() }) | Where-Object { $_ -match '192\.168\.100\.' }
  if ($own.Count -gt 0) { $HostIp = '192.168.100.1' } else { $HostIp = '192.168.0.106' }
}
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Host $s }
function Stamp { (Get-Date -Format 'HH:mm:ss') }
function NetStat($pats) {
  $r = @()
  foreach ($ln in @(& netstat.exe -s 2>&1 | ForEach-Object { $_.ToString() })) {
    foreach ($p in $pats) { if ($ln -match $p) { $r += (($ln -replace '\s+', ' ').Trim()) } }
  }
  $r
}
function SetFw($obj, $id, $val) {
  try {
    $obj.FirewallEnabled($id) = $val
    return ('赋值 OK 读回=' + $obj.FirewallEnabled($id))
  } catch { return ('赋值失败: ' + $_.Exception.Message) }
}
$WATCH = @('Packets Received', 'Received Packets Delivered', 'Passive Opens', 'Echo Requests Received', 'Echo Replies Sent', 'Segments Received')

Add ('===== vm_fw_roundtrip ' + (Stamp) + '  ShowOnly=' + $ShowOnly + '  Gap=' + $Gap + 's  镜像脚本=' + $FwOffPath + ' =====')
Add ''
Add '### 0. 起点'
if (-not (Test-Path $FwOffPath)) {
  try {
    (New-Object Net.WebClient).DownloadFile('http://' + $HostIp + ':' + $Port + '/file/fw_off.ps1', $FwOffPath)
    Add ('  自动取镜像脚本本体: http://' + $HostIp + ':' + $Port + '/file/fw_off.ps1 -> ' + $FwOffPath)
  } catch { Add ('  自动取 ' + $FwOffPath + ' 失败: ' + $_.Exception.Message) }
}
Add ('  脚本文件存在=' + (Test-Path $FwOffPath) + '  大小=' + ((Get-Item $FwOffPath -ErrorAction SilentlyContinue).Length))
$fw = $null
try {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  Add ('  FwPolicy2 OK 规则数=' + $fw.Rules.Count + ' 当前 Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
} catch { Add ('  FwPolicy2 不可用: ' + $_.Exception.Message) }

if ($ShowOnly) {
  Add ''
  Add '### -ShowOnly: 只读, 不重开防火墙、不调用镜像脚本'
} elseif (-not $fw) {
  Add '  没有 FwPolicy2, 后面的对照做不了'
} else {
  Add ''
  Add ('### 1. 把防火墙重新打开(写 True), 制造"应当被拦"的状态')
  foreach ($id in @(1, 2, 4)) { Add ('  profile ' + $id + ' -> ' + (SetFw $fw $id $true)) }
  Add ('  [' + (Stamp) + '] 等 ' + $Gap + ' 秒, 主机侧预期: 全部 REQUEST / tcp22 TIMEOUT')
  Start-Sleep ([int]$Gap)
  Add ('  [' + (Stamp) + '] 打开后计数: ' + ((NetStat $WATCH) -join ' | '))

  Add ''
  Add '### 2. 调用镜像里那个脚本本体(fw_off.ps1), 完全按 startnet 的用法'
  if (-not (Test-Path $FwOffPath)) {
    Add ('  ' + $FwOffPath + ' 不存在, 这步跳过')
  } else {
    $ps = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $out = @(& $ps -NoProfile -ExecutionPolicy Bypass -File $FwOffPath -LogFile 'X:\fw_off.log' -StatusFile 'X:\status.txt' 2>&1 | ForEach-Object { $_.ToString() })
    foreach ($o in $out) { Add ('  | ' + $o) }
    Add ('  调用返回码=' + $LASTEXITCODE)
    Add ('  调用后读回 Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
  }

  Add ''
  Add ('### 3. 等 ' + $Gap + ' 秒, 主机侧预期: 恢复 REPLY + SSH banner')
  Add ('  [' + (Stamp) + '] 进入恢复窗')
  Start-Sleep ([int]$Gap)
  Add ('  [' + (Stamp) + '] 恢复后计数: ' + ((NetStat $WATCH) -join ' | '))
  if ($fw.FirewallEnabled(1) -or $fw.FirewallEnabled(2) -or $fw.FirewallEnabled(4)) {
    Add '  !! 镜像脚本没关掉, 用已验证的写法强制关闭(免得 VM 失联), 上面日志保留失败证据'
    foreach ($id in @(1, 2, 4)) { Add ('  兜底 profile ' + $id + ' -> ' + (SetFw $fw $id $false)) }
  } else {
    Add '  三个 profile 都是 False, 说明确实是镜像脚本关掉的(不需要兜底)'
  }
  Add ''
  Add '### 3b. 镜像脚本留下的文件(证明开机时会写什么)'
  foreach ($f in @('X:\fw_off.log', 'X:\status.txt')) {
    if (Test-Path $f) {
      $tail = @(& Get-Content -Path $f -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -Last 6)
      Add ('  -- ' + $f + ' 末 ' + $tail.Count + ' 行 --')
      foreach ($ln in $tail) { Add ('    ' + $ln) }
    } else { Add ('  ' + $f + ' 不存在') }
  }
}

Add ''
Add ('### 4. 结束 ' + (Stamp))
$text = ($L -join "`r`n")
if ($ShowOnly) {
  try { [IO.File]::WriteAllText('fw_roundtrip_selftest.txt', $text, (New-Object Text.UTF8Encoding($true))); Add '已写 fw_roundtrip_selftest.txt' } catch { Add ('写自测文件失败: ' + $_.Exception.Message) }
} else {
  try { [IO.File]::WriteAllText('X:\fw_rt.txt', $text, (New-Object Text.UTF8Encoding($true))) } catch { Add ('写 X:\fw_rt.txt 失败: ' + $_.Exception.Message) }
  $body = [Text.Encoding]::UTF8.GetBytes($text)
  try {
    (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $body) | Out-Null
    Add ('POST -> http://' + $HostIp + ':' + $Port + '/result 成功')
  } catch {
    Add ('POST 失败: ' + $_.Exception.Message)
    Add '手查: type X:\fw_rt.txt'
  }
}
