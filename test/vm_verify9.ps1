# WinPE 第九轮: 抓 privsep 子进程的生死 + 文件 ACL, 并实测 OpenSSH 7.7.2 是否能登录
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }
$env:ProgramData = 'X:\ProgramData'

# ---------- 0. 先把上一轮的本地结果补传 ----------
try {
  if (Test-Path 'X:\verify7.txt') {
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") `
      -InFile 'X:\verify7.txt' -ContentType 'text/plain; charset=utf-8' -TimeoutSec 30 | Out-Null
    AL '0_prev7_repost' 'OK'
  } else { AL '0_prev7_repost' 'X:\verify7.txt 不存在' }
} catch { AL '0_prev7_repost' ('失败: ' + $_.Exception.Message) }

# ---------- 1. 受限令牌子进程能否读到这些文件(ACL) ----------
foreach ($f in 'X:\OpenSSH\sshd.exe', 'X:\OpenSSH\sshd_config', 'X:\Windows\System32\ntdll.dll', 'X:\Windows\System32\kernel32.dll') {
  try {
    $acl = Get-Acl $f
    $rules = @($acl.Access | ForEach-Object { ('{0} {1} {2}' -f $_.IdentityReference.Value, $_.AccessControlType, $_.FileSystemRights) })
    AL ('ACL_' + (Split-Path $f -Leaf)) (('Owner=' + $acl.Owner + '; ') + ($rules -join ' | '))
  } catch { AL ('ACL_' + (Split-Path $f -Leaf)) ('失败: ' + $_.Exception.Message) }
}

# ---------- 通用: 启动 sshd, 发起一次连接, 全程高频采样进程与错误弹窗 ----------
function Watch-Conn($tag, $dir, $cfg, $port) {
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  $null = Start-Process -FilePath (Join-Path $dir 'sshd.exe') -ArgumentList '-f', $cfg, '-d', '-e' -NoNewWindow `
        -PassThru -RedirectStandardError ("X:\w_{0}.txt" -f $tag) -RedirectStandardOutput ("X:\wo_{0}.txt" -f $tag)
  Start-Sleep 3
  $null = Start-Process -FilePath (Join-Path $dir 'ssh.exe') -ArgumentList '-p', $port,
        '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=X:\kh', '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10', '-i', 'X:\tk', 'Administrator@127.0.0.1', 'echo LOGIN_OK' -NoNewWindow `
        -PassThru -RedirectStandardOutput ("X:\c_{0}.txt" -f $tag) -RedirectStandardError ("X:\ce_{0}.txt" -f $tag)
  $seen = @{}
  $dlg = New-Object System.Collections.Generic.List[string]
  $t0 = Get-Date
  while (((Get-Date) - $t0).TotalMilliseconds -lt 15000) {
    $ms = [int]((Get-Date) - $t0).TotalMilliseconds
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
      if ($p.Name -ne 'sshd' -and $p.Name -ne 'werfault') { continue }
      $key = ('{0}:{1}' -f $p.Name, $p.Id)
      if (-not $seen.ContainsKey($key)) { $seen[$key] = @{ first = $ms; last = $ms } }
      else { $seen[$key].last = $ms }
      if ($p.Name -eq 'werfault') { try { if ($p.MainWindowTitle) { $dlg.Add($p.MainWindowTitle) } } catch { } }
    }
    Start-Sleep -Milliseconds 25
  }
  AL ('W_' + $tag + '_procs') (($seen.Keys | Sort-Object | ForEach-Object {
        ('{0} +{1}ms..+{2}ms' -f $_, $seen[$_].first, $seen[$_].last) }) -join ' ; ')
  AL ('W_' + $tag + '_dialog') $(if ($dlg.Count) { ($dlg | Select-Object -Unique) -join ' / ' } else { '无弹窗' })
  $co = (Get-Content ("X:\c_{0}.txt" -f $tag) -ErrorAction SilentlyContinue) -join ' '
  $ce = (Get-Content ("X:\ce_{0}.txt" -f $tag) -ErrorAction SilentlyContinue) -join ' '
  AL ('W_' + $tag + '_client') ('out=' + $co + ' err=' + $ce)
  AL ('W_' + $tag + '_srv_tail') (((Get-Content ("X:\w_{0}.txt" -f $tag) -ErrorAction SilentlyContinue) | Select-Object -Last 5) -join ' || ')
}

# ---------- 2. 现用 9.5p2 的行为 ----------
Watch-Conn 'v95' 'X:\OpenSSH' 'X:\OpenSSH\sshd_config' 22

# ---------- 3. 换 OpenSSH 7.7.2 实测 ----------
try {
  if (-not (Test-Path 'X:\OpenSSH-Win64\sshd.exe')) {
    Invoke-WebRequest -UseBasicParsing -Uri ("http://" + $H + ":8000/file/sshd77.zip") -OutFile 'X:\sshd77.zip' -TimeoutSec 120
    AL '3_zip' ('下载 ' + [math]::Round((Get-Item 'X:\sshd77.zip').Length/1KB) + 'KB')
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory('X:\sshd77.zip', 'X:\')
  }
  AL '3_extract' (((Get-ChildItem 'X:\OpenSSH-Win64' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ','))
  $cfg77 = @(
    'Port 2222', 'ListenAddress 0.0.0.0',
    'HostKey X:\OpenSSH\ssh_host_rsa_key',
    'AuthorizedKeysFile X:\OpenSSH\administrators_authorized_keys',
    'PasswordAuthentication no', 'PubkeyAuthentication yes', 'StrictModes no', 'LogLevel DEBUG3',
    'Subsystem sftp X:\OpenSSH-Win64\sftp-server.exe'
  )
  Set-Content -Path 'X:\sshd77.config' -Value $cfg77 -Encoding ASCII
  AL '3_version' ((& X:\OpenSSH-Win64\sshd.exe -V 2>&1 | Out-String).Trim())
  Watch-Conn 'v77' 'X:\OpenSSH-Win64' 'X:\sshd77.config' 2222
} catch { AL '3_77' ('失败: ' + $_.Exception.Message) }

# ---------- 4. 收尾: 恢复生产 sshd ----------
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f', 'X:\OpenSSH\sshd_config', '-E', 'X:\sshd.log' -WindowStyle Hidden
Start-Sleep 3
AL '4_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify9.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify9.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host '>>> 回传失败' }
