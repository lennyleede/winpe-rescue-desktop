# WinPE 第十二轮: sshd 的最后一组实验 (两个新线索)
#   假设1 路径写死: 第十一轮 wevtutil 报 resourceFileName = X:\windows\system32\openssh\ssh-agent.exe
#          -> inbox 版 OpenSSH 内部按 %windir%\System32\OpenSSH 找同伴组件, 我们放在 X:\OpenSSH 跑,
#             privsep 子进程可能因此初始化失败。把整套复制到 X:\Windows\System32\OpenSSH 再从那里跑一次。
#   假设2 子进程死因未知: 用 WMI 的 ProcessStartTrace/ProcessStopTrace 抓子的 pid/父 pid 和
#          ExitStatus (0xC0000142=DLL 初始化失败, 3=路径找不到), 一锤定音。
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }
$env:ProgramData = 'X:\ProgramData'
$SRC = 'X:\OpenSSH'
$DST = 'X:\Windows\System32\OpenSSH'

# ---------- R. 补发第十一轮结果 (那轮只是 POST 被主机的 accept 循环堵住了, 文件还在内存盘) ----------
if (Test-Path 'X:\verify11.txt') {
  try {
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result11") -InFile X:\verify11.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
    Write-Host '>>> verify11 已补发'
  } catch { Write-Host ('>>> verify11 补发失败: ' + $_.Exception.Message) }
} else { Write-Host '>>> X:\verify11.txt 不存在 (VM 重启过?), 第十一轮只能看屏幕' }

function Try-Login($tag, $dir = $SRC) {
  $r = & (Join-Path $dir 'ssh.exe') -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  $ok = if ($r -match 'LOGIN_OK') { 'LOGIN_OK !!' } else { (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '') }
  AL ('L_' + $tag) $ok
}
function Stop-Sshd { Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 2 }

# ---------- 0. 环境自检 ----------
foreach ($f in 'conhost.exe', 'csrss.exe', 'wininit.exe', 'user32.dll') {
  AL ('P_' + $f) (@(Get-ChildItem "X:\Windows\System32\$f" -ErrorAction SilentlyContinue | ForEach-Object { $_.Length }) -join ',')
}
AL 'P_sessions' ((Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'csrss|winlogon|services|smss' } |
  ForEach-Object { $_.ProcessName + ':' + $_.Id + ':S' + $_.SessionId }) -join ' ')
try { AL 'P_cim' ((Get-CimInstance Win32_OperatingSystem).Version) } catch { AL 'P_cim' ('WMI 不可用: ' + $_.Exception.Message) }

# ---------- 1. 复制到 System32\OpenSSH ----------
try {
  if (-not (Test-Path $DST)) { New-Item -ItemType Directory -Path $DST -Force | Out-Null }
  Copy-Item "$SRC\*" $DST -Recurse -Force
  AL 'C_copy' (@(Get-ChildItem $DST -File).Count.ToString() + ' 个文件已复制到 ' + $DST)
  $cfg2 = @((Get-Content "$SRC\sshd_config") | ForEach-Object { $_ -replace [regex]::Escape($SRC), $DST })
  Set-Content -Path "$DST\sshd_config" -Value $cfg2 -Encoding ASCII
  AL 'C_cfg' ((Get-Content "$DST\sshd_config" | Where-Object { $_ -match 'HostKey|AuthorizedKeysFile|Subsystem' }) -join ' ; ')
} catch { AL 'C_copy_err' ('失败: ' + $_.Exception.Message) }

# ---------- 2. 挂 WMI 进程事件, 从 System32 路径起 sshd 并登录 ----------
$null = Unregister-Event -SourceIdentifier sstart -ErrorAction SilentlyContinue
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
$hasEvt = $true
try {
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstart -ErrorAction Stop
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstop -ErrorAction Stop
} catch { $hasEvt = $false; AL 'E_reg' ('事件订阅不可用: ' + $_.Exception.Message) }
if ($hasEvt) { AL 'E_reg' '已订阅 sshd.exe 的 start/stop trace' }

Stop-Sshd
$null = Start-Process -FilePath "$DST\sshd.exe" -ArgumentList '-f', "$DST\sshd_config", '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\c_sys32.txt' -RedirectStandardOutput 'X:\c_sys32o.txt'
Start-Sleep 3
AL 'S_parent_procs' ((Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" |
  ForEach-Object { 'pid=' + $_.ProcessId + ' ppid=' + $_.ParentProcessId + ' sid=' + $_.SessionId + ' cmd=' + $_.CommandLine }) -join ' ;; ')
Try-Login 'sys32' -dir $DST
Start-Sleep 3
if ($hasEvt) {
  $st = @(Get-Event -SourceIdentifier sstart -ErrorAction SilentlyContinue)
  $sp = @(Get-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue)
  AL 'E_start' (($st | ForEach-Object { 'pid=' + $_.SourceEventArgs.NewEvent.ProcessID + ' ppid=' + $_.SourceEventArgs.NewEvent.ParentProcessID }) -join ' ;; ')
  AL 'E_stop' (($sp | ForEach-Object { 'pid=' + $_.SourceEventArgs.NewEvent.ProcessID + ' ppid=' + $_.SourceEventArgs.NewEvent.ParentProcessID +
    ' ExitStatus=0x' + ('{0:X8}' -f [int64]$_.SourceEventArgs.NewEvent.ExitStatus) }) -join ' ;; ')
  if ($st.Count -eq 0) { AL 'E_note' '没捕获到第二个 sshd 进程 -> privsep 子进程根本没被 CreateProcess 出来' }
}
AL 'S_srv_tail' (((Get-Content 'X:\c_sys32.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 6) -join ' || ')
$null = Unregister-Event -SourceIdentifier sstart -ErrorAction SilentlyContinue
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
Stop-Sshd

# ---------- 3. 对照组: 老路径 X:\OpenSSH 同样抓一次事件 ----------
if ($hasEvt) {
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstart -ErrorAction SilentlyContinue
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstop -ErrorAction SilentlyContinue
  $null = Start-Process -FilePath "$SRC\sshd.exe" -ArgumentList '-f', "$SRC\sshd_config", '-d', '-e' -NoNewWindow `
        -PassThru -RedirectStandardError 'X:\c_src.txt' -RedirectStandardOutput 'X:\c_srco.txt'
  Start-Sleep 3
  Try-Login 'srcpath'
  Start-Sleep 3
  $st2 = @(Get-Event -SourceIdentifier sstart -ErrorAction SilentlyContinue)
  $sp2 = @(Get-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue)
  AL 'O_start' (($st2 | ForEach-Object { 'pid=' + $_.SourceEventArgs.NewEvent.ProcessID + ' ppid=' + $_.SourceEventArgs.NewEvent.ParentProcessID }) -join ' ;; ')
  AL 'O_stop' (($sp2 | ForEach-Object { 'pid=' + $_.SourceEventArgs.NewEvent.ProcessID +
    ' ExitStatus=0x' + ('{0:X8}' -f [int64]$_.SourceEventArgs.NewEvent.ExitStatus) }) -join ' ;; ')
  $null = Unregister-Event -SourceIdentifier sstart -ErrorAction SilentlyContinue
  $null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
}
Stop-Sshd

# ---------- 4. 收尾: 恢复生产 sshd ----------
Start-Process -FilePath "$SRC\sshd.exe" -ArgumentList '-f', "$SRC\sshd_config", '-E', 'X:\sshd.log' -WindowStyle Hidden
Start-Sleep 2
AL 'D_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify12.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify12.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host ('>>> 回传失败: ' + $_.Exception.Message) }
