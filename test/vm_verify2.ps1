# WinPE 第二轮定向诊断: SSH 登录失败 / 向日葵退出 / wlansvc 未注册
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v -join ' '))) }

# ================= A. SSH =================
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
AL 'A0_sshd_killed' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'STILL-ALIVE' } else { 'OK' })

# A1: 前台调试模式, stderr 落盘
$p = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
     -NoNewWindow -PassThru -RedirectStandardError 'X:\sshd_dbg.txt' -RedirectStandardOutput 'X:\sshd_out.txt'
Start-Sleep 3
AL 'A1_debug_sshd_alive' $(if (-not $p.HasExited) { 'YES pid=' + $p.Id } else { 'NO exit=' + $p.ExitCode })
AL 'A1_listen22' (@(netstat -an 2>$null | Select-String ':22\s' | ForEach-Object { $_.ToString().Trim() }) -join ' ; ')

# A2: 用回环连接触发一次, 抓服务端日志
$pub = (Get-Content X:\tk.pub -ErrorAction SilentlyContinue)
if (-not $pub) { & X:\OpenSSH\ssh-keygen.exe -t ed25519 -N '""' -f X:\tk -q 2>&1 | Out-Null; $pub = Get-Content X:\tk.pub }
$ak = 'X:\OpenSSH\administrators_authorized_keys'
if (-not ((Get-Content $ak -Raw) -match [regex]::Escape(($pub | Out-String).Trim()))) { Add-Content $ak (($pub | Out-String).Trim()) }
AL 'A2_authkeys' ((Get-Content $ak).Count.ToString() + ' 行; 权限=' + (Get-Acl $ak -ErrorAction SilentlyContinue).AccessToString.Replace("`r`n", ' / '))
AL 'A2_hostkeys' (@(Get-ChildItem X:\OpenSSH\ssh_host_*_key -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ',')

$r1 = & X:\OpenSSH\ssh.exe -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\known_hosts -i X:\tk admin@127.0.0.1 'echo LOOPBACK_OK' 2>&1 | Out-String
AL 'A3_client_tail' ((($r1 -split "`n") | Where-Object { $_.Trim() } | Select-Object -Last 12) -join ' // ')
Start-Sleep 2
AL 'A4_server_dbg_tail' (((Get-Content X:\sshd_dbg.txt -ErrorAction SilentlyContinue) | Select-Object -Last 25) -join ' // ')
AL 'A5_dbg_sshd_after_conn' $(if (-not $p.HasExited) { 'STILL-RUNNING(可多连接)' } else { 'EXITED code=' + $p.ExitCode })

# A6: 正式(无 -d)方式重启, 再连两次验证可重复登录
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-E','X:\sshd_prod.log' -WindowStyle Hidden
Start-Sleep 3
AL 'A6_prod_alive' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })
$c1 = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\known_hosts -i X:\tk admin@127.0.0.1 'whoami' 2>&1 | Out-String
Start-Sleep 2
$c2 = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\known_hosts -i X:\tk admin@127.0.0.1 'ver' 2>&1 | Out-String
AL 'A7_conn1' (($c1.Trim() -replace '\s+', ' '))
AL 'A8_conn2' (($c2.Trim() -replace '\s+', ' '))
AL 'A9_prod_log' (((Get-Content X:\sshd_prod.log -ErrorAction SilentlyContinue) | Select-Object -Last 15) -join ' // ')

# ================= B. 向日葵 =================
Get-Process Sunlogin* -ErrorAction SilentlyContinue | Stop-Process -Force
$sp = Start-Process -FilePath 'X:\Sunlogin\SunloginSOS.exe' -WorkingDirectory 'X:\Sunlogin' -PassThru
Start-Sleep 6
$alive = Get-Process -Id $sp.Id -ErrorAction SilentlyContinue
AL 'B1_sunlogin_alive_6s' $(if ($alive) { 'YES' } else { 'NO exit=' + $sp.ExitCode })
AL 'B2_sunlogin_procs' (@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like '*unlogin*' } | ForEach-Object { $_.ProcessName + ':' + $_.Id }) -join ',')
# 它留下的文件/日志
$new = @(Get-ChildItem X:\Sunlogin -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } | ForEach-Object { $_.Name })
AL 'B3_sunlogin_newfiles' $(if ($new) { $new -join ',' } else { '无新文件' })
$t = @(Get-ChildItem 'X:\Users','X:\ProgramData','X:\Windows\Temp','X:\' -Recurse -Depth 3 -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*[Ss]unlogin*' } | Select-Object -First 15 -ExpandProperty FullName)
AL 'B4_sunlogin_traces' $(if ($t) { $t -join ' | ' } else { '无' })
# 依赖 DLL 是否齐
$need = @('ucrtbase.dll','vcruntime140.dll','msvcp140.dll','ws2_32.dll','wininet.dll','winhttp.dll','crypt32.dll','user32.dll','advapi32.dll','shell32.dll','gdi32.dll','ole32.dll','setupapi.dll','wtsapi32.dll','secur32.dll')
$miss = @()
foreach ($d in $need) { if (-not ((Test-Path "X:\Windows\System32\$d") -or (Test-Path "X:\Sunlogin\$d"))) { $miss += $d } }
AL 'B5_missing_dlls' $(if ($miss) { ($miss -join ',') } else { '无缺失(常规依赖)' })

# ================= C. wlansvc =================
$paths = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc','HKLM:\SYSTEM\ControlSet001\Services\wlansvc'
foreach ($k in $paths) {
  if (Test-Path $k) {
    $o = Get-ItemProperty $k
    AL ('C1_' + $k) ('Start=' + $o.Start + ' Type=' + $o.Type + ' Image=' + $o.ImagePath + ' Dll=' + (Get-ItemProperty "$k\Parameters" -ErrorAction SilentlyContinue).ServiceDll)
  } else { AL ('C1_' + $k) 'KEY-NOT-FOUND' }
}
AL 'C2_activecontrolset' ((Get-ItemProperty 'HKLM:\SYSTEM\Select' -ErrorAction SilentlyContinue).Current)
AL 'C3_svc_count' (@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue).Count.ToString())
AL 'C4_lanish_services' (@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match 'lan|WLAN|Dot3|msms|ndis|rpcss' } | ForEach-Object { $_.PSChildName }) -join ',')
AL 'C5_svchost_group' ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\svchost' -ErrorAction SilentlyContinue).PEWLan -join '|')
$ns = & net start wlansvc 2>&1 | Out-String
AL 'C6_net_start' ($ns.Trim() -replace '\s+', ' ')
AL 'C7_rpcss' (@(Get-Process -Id (Get-CimInstance Win32_Service -Filter "Name='RpcSs'" -ErrorAction SilentlyContinue).ProcessId -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName }) -join ',')
$mod = @(Get-Process -Name svchost -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Modules | Where-Object { $_.ModuleName -match 'wlansvc|dot3api|wlan' } | ForEach-Object { $_.ModuleName } } catch {} } | Sort-Object -Unique)
AL 'C8_loaded_wlan_modules' $(if ($mod) { $mod -join ',' } else { '无 svchost 加载 wlansvc.dll' })

# ================= 回传 =================
$text = $out -join "`r`n"
Set-Content -Path X:\verify2.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify2.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 20 | Out-Null
  Write-Host '>>> 已回传'
} catch { Write-Host '>>> 回传失败, 请截图 X:\verify2.txt' }
