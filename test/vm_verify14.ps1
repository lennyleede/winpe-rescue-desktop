# WinPE 第十四轮: 真正测一次 System32 路径假设 (第十三轮被脚本 bug 挡住)
#   关键教训: host key 的权限检查不受 StrictModes 控制, 必须让私钥文件只有 SYSTEM/Administrators 能读。
#   做法: 在 X:\Windows\System32\OpenSSH 里用 ssh-keygen 现生成一个 host key(它自带严格 DACL),
#         用一份只指向它的 config 起 sshd, 看 privsep 子进程还会不会 0xC0000142。
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }
$env:ProgramData = 'X:\ProgramData'
$Root = 'X:\OpenSSH'
$Dst = 'X:\Windows\System32\OpenSSH'
$Key = "$Dst\ssh_host_t14_key"
$Cfg = "$Dst\sshd_t14.config"

function Try-Login($tag, $bin = $Root) {
  $r = & (Join-Path $bin 'ssh.exe') -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  $ok = if ($r -match 'LOGIN_OK') { 'LOGIN_OK !!' } else { (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '') }
  AL ('L_' + $tag) $ok
}
function Stop-Sshd { Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 2 }

# ---------- 1. 准备: 目录 + 现生成的 host key + 专用 config ----------
if (-not (Test-Path "$Dst\sshd.exe")) {
  New-Item -ItemType Directory -Path $Dst -Force | Out-Null
  Copy-Item "$Root\*" $Dst -Recurse -Force
  AL 'A_recopy' 'X:\Windows\System32\OpenSSH 不存在, 已重新复制整套'
}
Remove-Item "$Key*" -Force -ErrorAction SilentlyContinue
$kg = & "$Dst\ssh-keygen.exe" -t rsa -b 3072 -N '""' -f $Key -q 2>&1 | Out-String
AL 'A_keygen' ((($kg -split "`n" | Where-Object { $_.Trim() }) | Select-Object -First 2) -join ' / ')
AL 'A_key_exists' $(if (Test-Path $Key) { 'YES' } else { 'NO' })
AL 'A_key_acl' ((Get-Acl $Key -ErrorAction SilentlyContinue).AccessToString -replace "`r`n", ' / ')
$akCopy = "$Dst\administrators_authorized_keys"
Copy-Item "$Root\administrators_authorized_keys" $akCopy -Force -ErrorAction SilentlyContinue
AL 'A_ak_acl' ((Get-Acl $akCopy -ErrorAction SilentlyContinue).AccessToString -replace "`r`n", ' / ')
# 注意: PowerShell 里逗号比 + 结合更紧, 数组里的 'HostKey ' + $Key 必须加括号, 否则会被拆成两个元素
@(
  'Port 22', 'ListenAddress 0.0.0.0', ('HostKey ' + $Key),
  ('AuthorizedKeysFile ' + $akCopy),
  'PermitRootLogin yes', 'PasswordAuthentication no', 'PubkeyAuthentication yes',
  'StrictModes no', 'LogLevel DEBUG3', 'PidFile X:\sshd_t14.pid',
  ('Subsystem sftp ' + "$Dst\sftp-server.exe")
) | Set-Content -Path $Cfg -Encoding ASCII
AL 'A_cfg' ((Get-Content $Cfg) -join ' ; ')

# ---------- 2. sshd -t 只看配置和 host key 是否被接受 ----------
AL 'B_t' ((& "$Dst\sshd.exe" -t -f $Cfg 2>&1 | Out-String).Trim())

# ---------- 3. 从 System32 起, 登录, 抓子进程退出码 ----------
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
$hasEvt = $true
try {
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstop -ErrorAction Stop
} catch { $hasEvt = $false; AL 'C_reg' ('事件订阅不可用: ' + $_.Exception.Message) }
Stop-Sshd
$null = Start-Process -FilePath "$Dst\sshd.exe" -ArgumentList '-f', $Cfg, '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\e_dst.txt' -RedirectStandardOutput 'X:\e_dstout.txt'
Start-Sleep 3
AL 'C_listening' (@(netstat -an 2>$null | Select-String ':22\s' | ForEach-Object { $_.ToString().Trim() }) -join ' ; ')
Try-Login 'sys32_t14' -bin $Dst
Start-Sleep 2
if ($hasEvt) {
  AL 'C_stop' ((@(Get-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue) | ForEach-Object {
    'pid=' + $_.SourceEventArgs.NewEvent.ProcessID + ' ExitStatus=0x' + ('{0:X8}' -f [int64]$_.SourceEventArgs.NewEvent.ExitStatus) }) -join ' ;; ')
}
AL 'C_srv_tail' (((Get-Content 'X:\e_dst.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 6) -join ' || ')
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
Stop-Sshd

# ---------- 4. 对照组: 同样的 config 但用 X:\OpenSSH 里的二进制跑 ----------
$cfg4 = (Get-Content $Cfg) -replace [regex]::Escape($Dst), $Root
Set-Content -Path 'X:\sshd_t14_src.config' -Value $cfg4 -Encoding ASCII
$null = Start-Process -FilePath "$Root\sshd.exe" -ArgumentList '-f', 'X:\sshd_t14_src.config', '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\e_src.txt' -RedirectStandardOutput 'X:\e_srcout.txt'
Start-Sleep 3
Try-Login 'root_t14' -bin $Root
AL 'D_srv_tail' (((Get-Content 'X:\e_src.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 4) -join ' || ')
Stop-Sshd

# ---------- 5. 收尾 ----------
Start-Process -FilePath "$Root\sshd.exe" -ArgumentList '-f', "$Root\sshd_config", '-E', 'X:\sshd.log' -WindowStyle Hidden
Start-Sleep 2
AL 'E_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify14.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify14.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host ('>>> 回传失败: ' + $_.Exception.Message) }
