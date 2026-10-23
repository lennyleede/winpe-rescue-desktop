# ============================================================
# 33_HtaTypingDebug.ps1 —— 诊断"桌面 frp 面板里打字没反应"(只走 SSH, 普通权限即可)
#   第一阶段(起采样器 + 立即取证):  powershell -NoProfile -ExecutionPolicy Bypass -File test\33_HtaTypingDebug.ps1
#   第二阶段(120 秒后取回 X:\fg.log): ... -Phase fetch
# 判读:
#   - "mshta UI 线程不响应" 反复出现  => HTA 的 refresh() 每 3 秒同步查 WMI 把界面占满, 按键被丢
#   - "前台切换 -> pid=...(不是 mshta)" => 焦点被别的程序抢走, 字打到别处去了
#   - 两者都没有 + 手动 frpStat 能改值 => 界面本身没问题, 得往键盘输入链路(Hyper-V 控制台)查
# ============================================================
param(
  [string]$IP = '',
  [string]$User = 'Administrator',
  [ValidateSet('start', 'probe', 'focus', 'ctf', 'fetch', 'dom', 'ie8')] [string]$Phase = 'start'
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path $PSScriptRoot -Parent
$Out  = Join-Path $PSScriptRoot ('vm10_htadbg_' + $Phase + '.txt')
$Rows = New-Object System.Collections.ArrayList
function L($m) {
  Write-Host $m
  [void]$Rows.Add([string]$m)
  try { Set-Content -LiteralPath $Out -Value ($Rows -join "`r`n") -Encoding UTF8 } catch { }
}
if (-not $IP) {
  $f = Join-Path $PSScriptRoot 'vm_ip.txt'
  if (-not (Test-Path $f)) { L 'ERROR: 没给 -IP 也没有 test\vm_ip.txt'; exit 1 }
  $IP = (Get-Content $f).Trim()
}
$keySrc = Join-Path $Root 'overlay\Scripts\ssh_login_key'
if (-not (Test-Path -LiteralPath $keySrc)) { L ('ERROR: 登录私钥不在 ' + $keySrc); exit 1 }
$keyTmp = Join-Path $env:TEMP ('winpe10_dbg_key_' + $PID)
if (Test-Path -LiteralPath $keyTmp) { Remove-Item -LiteralPath $keyTmp -Force }
Copy-Item -LiteralPath $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r ("${env:USERNAME}:R") | Out-Null
$sshBin = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshBin)) { $sshBin = 'ssh' }
$sshOpts = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
             '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR', ($User + '@' + $IP))
function Invoke-Pe([string]$label, [string]$cmd) {
  L ('---------- ' + $label + ' ----------')
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $t0 = Get-Date
  $o = & $sshBin @sshOpts $cmd 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  $txt = @($o | ForEach-Object { "$_" })
  L ('  (rc=' + $rc + ' 用时=' + [int]((Get-Date).Subtract($t0).TotalSeconds) + 's 行数=' + $txt.Count + ')')
  $txt | Select-Object -First 120 | ForEach-Object { L ('  ' + $_) }
  return $txt
}
function Invoke-PePs([string]$label, [string]$ps) {
  $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
  return (Invoke-Pe $label ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64))
}
function Invoke-PeFile([string]$label, [string]$Path) {
  # 整段载荷 base64 后再包一层 -EncodedCommand 会把 cmd 的 8191 字符上限撑爆(实测 "The command line is too long"),
  # 所以分块写进 X:\rc.b64, 最后一块再解码成 X:\rc.ps1 并执行。每块 1800 字符 -> 命令行约 4100, 有余量。
  $txt = [System.IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
  $b64p = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($txt))
  & $sshBin @sshOpts 'del X:\rc.b64 2>nul & echo READY' | Out-Null
  for ($i = 0; $i -lt $b64p.Length; $i += 1800) {
    $len = [Math]::Min(1800, $b64p.Length - $i)
    $chunk = $b64p.Substring($i, $len)
    $inner = '[IO.File]::AppendAllText(''X:\rc.b64'',''' + $chunk + ''')'
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    $o = & $sshBin @sshOpts ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64) 2>&1
    if ($LASTEXITCODE -ne 0) { L ('  !! 分块写入失败(第 ' + [int]($i / 1800 + 1) + ' 块): ' + (($o | ForEach-Object { "$_" }) -join ' ')); return @() }
  }
  $run = ('$b=[IO.File]::ReadAllText(''X:\rc.b64'');' +
          '$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));' +
          '[IO.File]::WriteAllBytes(''X:\rc.ps1'',[byte[]](0xEF,0xBB,0xBF)+[Text.Encoding]::UTF8.GetBytes($s));' +
          'Remove-Item X:\rc.b64 -Force -EA SilentlyContinue;' +
          '& X:\rc.ps1')
  # 这段是 PowerShell 语句, 必须也走 -EncodedCommand(pe-sshd 是交给 cmd.exe 执行的)
  $br = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($run))
  return (Invoke-Pe $label ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $br))
}

function Send-PeBytes([string]$LocalPath, [string]$RemotePath) {
  # pe-sshd 是自研的, 没有 sftp/scp 子系统, 所以文件用 base64 分块写进 X:\up.b64 再解码落盘
  if (-not (Test-Path -LiteralPath $LocalPath)) { L ('  !! 本地文件不存在: ' + $LocalPath); return $false }
  $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
  $b64p = [Convert]::ToBase64String($bytes)
  & $sshBin @sshOpts 'del X:\up.b64 2>nul & echo READY' | Out-Null
  for ($i = 0; $i -lt $b64p.Length; $i += 1800) {
    $len = [Math]::Min(1800, $b64p.Length - $i)
    $inner = '[IO.File]::AppendAllText(''X:\up.b64'',''' + $b64p.Substring($i, $len) + ''')'
    $b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    $o = & $sshBin @sshOpts ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b) 2>&1
    if ($LASTEXITCODE -ne 0) { L ('  !! 上传分块失败(第 ' + [int]($i / 1800 + 1) + ' 块): ' + (($o | ForEach-Object { "$_" }) -join ' ')); return $false }
  }
  $run = ('$b=[IO.File]::ReadAllText(''X:\up.b64'');' +
          '[IO.File]::WriteAllBytes(''' + $RemotePath + ''',[Convert]::FromBase64String($b));' +
          'Remove-Item X:\up.b64 -Force -EA SilentlyContinue;' +
          '(Get-Item ''' + $RemotePath + ''').Length')
  $br = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($run))
  $r = Invoke-Pe ('  上传 -> ' + $RemotePath) ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $br)
  return (($r | ForEach-Object { "$_" }) -join ' ')
}

L ('===== HtaTypingDebug phase=' + $Phase + ' ' + (Get-Date -Format 'HH:mm:ss') + ' 目标=' + $User + '@' + $IP + ' =====')
if ($Phase -eq 'ie8') {
  # 降级后的验收: 镜像里的 Desktop.hta 是不是 IE=8, 以及真鼠标点框 + 真按键能不能打进 frp 输入框
  Invoke-PeFile 'IE8. 面板端到端自测(真鼠标 + SendKeys)' (Join-Path $PSScriptRoot 'pe10_ie8verify.ps1') | Out-Null
} elseif ($Phase -eq 'start') {
  Invoke-PeFile 'A. 现场取证 + 起 120 秒采样器' (Join-Path $PSScriptRoot 'pe10_htadbg.ps1') | Out-Null
  L ''
  L '>>> 采样器已经在 PE 里跑 120 秒: 请现在到 VM 控制台的 frp 输入框里连续打字(中英文都试), 再点几下输入框切换焦点。'
  L ('    之后取结果: powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot '33_HtaTypingDebug.ps1') + '" -Phase fetch')
} elseif ($Phase -eq 'ctf') {
  # 赌一把根因: IE9+ 文档模式的文本框要用 TSF(文本服务框架), 而 PE 镜像里没有 ctfmon.exe 这个宿主进程。
  # 这里只是把宿主的 ctfmon 临时推进运行中的内存盘 X:(不动镜像), 启动后重跑同一套文档模式对照。
  $hostCtf = 'C:\Windows\System32\ctfmon.exe'
  if (-not (Test-Path $hostCtf)) { L ('!! 宿主没有 ' + $hostCtf); exit 1 }
  L ('  宿主 ctfmon = ' + (Get-Item $hostCtf).Length + ' 字节, 版本 ' + (Get-Item $hostCtf).VersionInfo.ProductVersion)
  Send-PeBytes $hostCtf 'X:\Windows\System32\ctfmon.exe' | Out-Null
  Invoke-PePs '  落盘确认' '(Get-Item X:\Windows\System32\ctfmon.exe -EA SilentlyContinue).Length' | Out-Null
  Invoke-PePs '  在控制台会话里启动 ctfmon' 'try{ Start-Process -FilePath X:\Windows\System32\ctfmon.exe -EA Stop | Out-Null; "started" }catch{ "FAIL " + $_.Exception.Message }; Start-Sleep -Seconds 2; @(Get-Process ctfmon -EA SilentlyContinue | ForEach-Object { "ctfmon pid=" + $_.Id }) -join " "' | Out-Null
  Invoke-PeFile '  重跑文档模式对照(带 ctfmon)' (Join-Path $PSScriptRoot 'pe10_focusprobe.ps1') | Out-Null
  Invoke-PePs '  收尾: 关掉 ctfmon' '@(Get-Process ctfmon -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -EA SilentlyContinue }); "killed"' | Out-Null
} elseif ($Phase -eq 'focus') {
  # 三变体对照: 最简 HTA 的输入框到底能不能拿到焦点(隔离是页面问题还是 PE 缺文本输入服务)
  Invoke-PeFile 'F. 输入框焦点三变体对照' (Join-Path $PSScriptRoot 'pe10_focusprobe.ps1') | Out-Null
} elseif ($Phase -eq 'probe') {
  # 全程自动: 在 PE 里造一份带按键日志的 frp 面板副本, 真鼠标点输入框 + 真按键输字, 结果直接回传
  Invoke-PeFile 'P. 键盘/鼠标链路主动探针(不需要人碰键盘)' (Join-Path $PSScriptRoot 'pe10_kbprobe.ps1') | Out-Null
} elseif ($Phase -eq 'dom') {
  Invoke-PeFile 'C. HTA DOM 探针(读活动元素/输入框值, 代填并调 saveFrp)' (Join-Path $PSScriptRoot 'pe10_dom.ps1') | Out-Null
} else {
  Invoke-Pe 'B. 采样结果 X:\fg.log' 'type X:\fg.log' | Out-Null
  Invoke-PePs 'B2. 行数与关键计数' '$l=@(Get-Content X:\fg.log -EA SilentlyContinue); "总行数=" + $l.Count; "前台切换次数=" + @($l | Where-Object { $_ -match "前台切换" }).Count; "mshta 不响应次数=" + @($l | Where-Object { $_ -match "不响应" }).Count; "按键次数=" + @($l | Where-Object { $_ -match "按键 vk=" }).Count; "--- 按键行(最多 40 条) ---"; @($l | Where-Object { $_ -match "按键 vk=" }) | Select-Object -First 40; "--- 最后 15 行 ---"; $l | Select-Object -Last 15' | Out-Null
  Invoke-Pe 'B3. 最小测试窗口自己的按键日志 X:\kbtest.log' 'type X:\kbtest.log' | Out-Null
  Invoke-Pe 'B4. 面板副本日志 X:\dsktest.log' 'type X:\dsktest.log' | Out-Null
}
Remove-Item -LiteralPath $keyTmp -Force -EA SilentlyContinue
L ('结果文件 = ' + $Out)
