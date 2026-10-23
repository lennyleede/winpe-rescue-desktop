# WinPE 第六轮: 判定 sshd 子进程启动失败的原因, 测三个修复方案
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

# ---------- A. 父 sshd 能否自己 spawn 一个 sshd 子进程 ----------
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
$null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
      -NoNewWindow -PassThru -RedirectStandardError 'X:\spawn_srv.txt' -RedirectStandardOutput 'X:\spawn_out.txt'
Start-Sleep 2
$before = @(Get-Process sshd -ErrorAction SilentlyContinue).Count
$cli = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
AL 'A_ssh_result' (($cli -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '')
AL 'A_sshd_proc_before' $before.ToString()
AL 'A_sshd_procs_now' (@(Get-Process sshd -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ',')
AL 'A_srv_log' (((Get-Content 'X:\spawn_srv.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 4) -join ' || ')

# ---------- B. 从主机下载缺失 DLL 到 PE 的 System32, 再重试 ----------
$made = @()
foreach ($d in 'comctl32.dll','msdmo.dll','pdh.dll') {
  $dst = "X:\Windows\System32\$d"
  if (Test-Path $dst) { $made += ($d + ' 已存在'); continue }
  try {
    Invoke-WebRequest -UseBasicParsing -Uri ("http://" + $H + ":8000/file/" + $d) -OutFile $dst -TimeoutSec 60 -ErrorAction Stop
    $made += ($d + ' 下载成功 ' + [math]::Round((Get-Item $dst).Length / 1KB) + 'KB')
  } catch { $made += ($d + ' 下载失败: ' + $_.Exception.Message) }
}
AL 'B_copied' ($made -join ' ; ')
AL 'B_now_present' ((@('comctl32.dll','msdmo.dll','pdh.dll') | ForEach-Object { $_ + '=' + (Test-Path "X:\Windows\System32\$_") }) -join ' ')

# B2: 只补 DLL(未改 Winsock) 后重试 sshd
function Ssh-Try($tag) {
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  $null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
        -NoNewWindow -PassThru -RedirectStandardError "X:\t_$tag.txt" -RedirectStandardOutput "X:\t_${tag}o.txt"
  Start-Sleep 3
  $r = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  AL ("B2_ssh_" + $tag) (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '')
  AL ("B2_srv_" + $tag) (((Get-Content "X:\t_$tag.txt" -ErrorAction SilentlyContinue) | Select-Object -Last 3) -join ' || ')
}
Ssh-Try 'dllonly'

# ---------- C. 关掉 Winsock 后台承诺 (WinPE 常见坑) ----------
try {
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters' -Name 'DisableBGPromise' -Value 1 -Type DWord -Force -ErrorAction Stop
  AL 'C_bgpromise' 'DisableBGPromise=1 已写入'
} catch { AL 'C_bgpromise' ('写注册表失败: ' + $_.Exception.Message) }
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Ssh-Try 'bgpromise'

# ---------- D. 向日葵: 补 DLL 后能否起来 ----------
Get-Process Sunlogin* -ErrorAction SilentlyContinue | Stop-Process -Force
$sp = Start-Process -FilePath 'X:\Sunlogin\SunloginSOS.exe' -WorkingDirectory 'X:\Sunlogin' -PassThru
Start-Sleep 6
$alive = Get-Process -Id $sp.Id -ErrorAction SilentlyContinue
AL 'D_sunlogin_after_fix' $(if ($alive) { '存活 6 秒仍运行 (缺 DLL 已解决)' } else { '仍退出 exit=' + $sp.ExitCode })

# ---------- E. 收尾: 恢复正式 sshd ----------
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-E','X:\sshd_prod.log' -WindowStyle Hidden
Start-Sleep 3
AL 'E_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify6.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify6.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 已回传'
} catch { Write-Host '>>> 回传失败' }
