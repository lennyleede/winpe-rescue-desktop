# WinPE 第十三轮: 把第十二轮被"host key 权限太松"挡掉的 System32 假设真正测一次
#   第十二轮的硬证据: privsep 子进程 ExitStatus=0xC0000142 (STATUS_DLL_INIT_FAILED)
#   第十二轮没测成的原因: 复制到 System32\OpenSSH 后 host key 继承了宽 ACL,
#            sshd 报 "Permissions ... are too open ... no hostkeys available -- exiting" -> Connection refused
#   本轮: 1) 对齐 ACL + StrictModes no  2) 从 System32 路径真跑一次  3) 顺手抓子的命令行
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }
$env:ProgramData = 'X:\ProgramData'
$SRC = 'X:\OpenSSH'
$DST = 'X:\Windows\System32\OpenSSH'

function Try-Login($tag, $dir = $SRC) {
  $r = & (Join-Path $dir 'ssh.exe') -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  $ok = if ($r -match 'LOGIN_OK') { 'LOGIN_OK !!' } else { (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '') }
  AL ('L_' + $tag) $ok
}
function Stop-Sshd { Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 2 }

# ---------- 1. 补齐前置: StrictModes no + host key/config 的 ACL 与源目录一致 ----------
if (-not (Test-Path "$DST\sshd.exe")) { AL 'X_abort' "$DST 不存在, 第十二轮的复制没留下来(VM 重启过?)"; $text = $out -join "`r`n"; Set-Content X:\verify13.txt $text -Encoding UTF8; Write-Host $text; exit }
try {
  $cfg = @(Get-Content "$DST\sshd_config")
  $cfg = @($cfg | ForEach-Object { if ($_ -match '^\s*StrictModes') { 'StrictModes no' } else { $_ } })
  if (-not ($cfg -match '^StrictModes')) { $cfg = @('StrictModes no') + $cfg }
  Set-Content -Path "$DST\sshd_config" -Value $cfg -Encoding ASCII
  AL 'A_strictmodes' 'ok'
} catch { AL 'A_strictmodes' ('失败: ' + $_.Exception.Message) }
$fixed = @()
foreach ($f in (Get-ChildItem $DST -File | Where-Object { $_.Name -match '^ssh_host_.*_key$|sshd_config|administrators_authorized_keys' })) {
  $src = Join-Path $SRC $f.Name
  if (Test-Path $src) {
    try { Get-Acl $src | Set-Acl $f.FullName -ErrorAction Stop; $fixed += $f.Name } catch { $fixed += ($f.Name + '!失败') }
  }
}
AL 'A_acl' ('已对齐 ' + $fixed.Count + ' 个: ' + ($fixed -join ','))
AL 'A_acl_after' ((Get-Acl "$DST\ssh_host_rsa_key").AccessToString -replace "`r`n", ' / ')

# ---------- 2. sshd -t 配置自检(不 fork), 两个路径各一次 ----------
AL 'B_t_dst' ((& "$DST\sshd.exe" -t -f "$DST\sshd_config" 2>&1 | Out-String).Trim())
AL 'B_t_src' ((& "$SRC\sshd.exe" -t -f "$SRC\sshd_config" 2>&1 | Out-String).Trim())

# ---------- 3. 从 System32 路径起, 登录并抓子进程退出码 ----------
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
$hasEvt = $true
try {
  Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStopTrace WHERE ProcessName='sshd.exe'" -SourceIdentifier sstop -ErrorAction Stop
} catch { $hasEvt = $false; AL 'C_reg' ('事件订阅不可用: ' + $_.Exception.Message) }
Stop-Sshd
$null = Start-Process -FilePath "$DST\sshd.exe" -ArgumentList '-f', "$DST\sshd_config", '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\d_dst.txt' -RedirectStandardOutput 'X:\d_dstout.txt'
Start-Sleep 3
Try-Login 'sys32_fixed' -dir $DST
Start-Sleep 2
if ($hasEvt) {
  AL 'C_stop' ((@(Get-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue) | ForEach-Object {
    'pid=' + $_.SourceEventArgs.NewEvent.ProcessID + ' ExitStatus=0x' + ('{0:X8}' -f [int64]$_.SourceEventArgs.NewEvent.ExitStatus) }) -join ' ;; ')
}
AL 'C_srv_tail' (((Get-Content 'X:\d_dst.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 5) -join ' || ')
$null = Unregister-Event -SourceIdentifier sstop -ErrorAction SilentlyContinue
Stop-Sshd

# ---------- 4. 用老路径复现, 同时轮询 WMI 抢子进程的 CommandLine ----------
$null = Start-Process -FilePath "$SRC\sshd.exe" -ArgumentList '-f', "$SRC\sshd_config", '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\d_src.txt' -RedirectStandardOutput 'X:\_d_srcout.txt'
Start-Sleep 3
$cli = New-Object System.Collections.Generic.HashSet[string]
$ssh = Start-Process -FilePath "$SRC\ssh.exe" -ArgumentList '-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=X:\kh','-o','BatchMode=yes','-i','X:\tk','Administrator@127.0.0.1','echo LOGIN_OK' -NoNewWindow -PassThru
for ($i = 0; $i -lt 400; $i++) {
  foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='sshd.exe'" -ErrorAction SilentlyContinue)) {
    [void]$cli.Add('pid=' + $p.ProcessId + ' ppid=' + $p.ParentProcessId + ' :: ' + $p.CommandLine)
  }
  if ($ssh.HasExited) { break }
}
Try-Login 'src_again'
AL 'D_child_cmdlines' (($cli | Out-String).Trim())
Stop-Sshd

# ---------- 5. 收尾 ----------
Start-Process -FilePath "$SRC\sshd.exe" -ArgumentList '-f', "$SRC\sshd_config", '-E', 'X:\sshd.log' -WindowStyle Hidden
Start-Sleep 2
AL 'E_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify13.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify13.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host ('>>> 回传失败: ' + $_.Exception.Message) }
