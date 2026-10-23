# WinPE 第八轮: v6 ISO 回归验证(缺 DLL / wlansvc 注册 / 远程通道改为向日葵+frp+救援终端)
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
AL 'A0_identity' ($id.Name + ' SID=' + $id.User.Value)

# ---------- A. 向日葵运行依赖是否已进 ISO ----------
foreach ($d in 'comctl32.dll', 'msdmo.dll', 'pdh.dll') {
  $p = "X:\Windows\System32\$d"
  if (Test-Path $p) {
    $v = (Get-Item $p).VersionInfo
    AL ('A_dll_' + $d) ('OK ' + [math]::Round((Get-Item $p).Length/1KB) + 'KB v' + $v.FileVersion)
  } else { AL ('A_dll_' + $d) 'MISSING' }
}

# ---------- B. 向日葵是否存活 ----------
$p0 = @(Get-Process -Name SunloginSOS -ErrorAction SilentlyContinue)
AL 'B_sunlogin_procs' (@($p0 | ForEach-Object { $_.Id }) -join ',')
if ($p0.Count -eq 0) {
  Start-Process -FilePath 'X:\Sunlogin\SunloginSOS.exe' -WorkingDirectory 'X:\Sunlogin' -WindowStyle Hidden
  Start-Sleep 8
  $p1 = @(Get-Process -Name SunloginSOS -ErrorAction SilentlyContinue)
  AL 'B_after_launch' $(if ($p1.Count) { '存活 (' + $p1.Count + ' 进程)' } else { '仍未运行' })
} else { AL 'B_after_launch' '已在运行(开机自启生效)' }

# ---------- C. wlansvc 是否被 SCM 识别 ----------
$svc = @([System.ServiceProcess.ServiceController]::GetServices() | ForEach-Object { $_.ServiceName })
AL 'C_scm_count' $svc.Count
AL 'C_scm_wlan' $(if ($svc -contains 'wlansvc') { 'PRESENT' } else { 'ABSENT' })
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
if (Test-Path $k) {
  $o = Get-ItemProperty $k
  AL 'C_reg' ('ErrorControl=' + $o.ErrorControl + ' Start=' + $o.Start + ' Type=' + $o.Type +
     ' ServiceSidType=' + $o.ServiceSidType + ' Group=' + $o.Group + ' 值名含Error? ' + [bool]($o.PSObject.Properties.Name -contains 'Error'))
} else { AL 'C_reg' '键不存在' }
# net start 可能因服务挂起而长时间阻塞, 用子进程 + 45 秒限时
$pi = Start-Process -FilePath 'net.exe' -ArgumentList 'start', 'wlansvc' -NoNewWindow -PassThru `
      -RedirectStandardOutput 'X:\ns_out.txt' -RedirectStandardError 'X:\ns_err.txt'
if ($pi.WaitForExit(45000)) {
  AL 'C_net_start' (('@out ' + ((Get-Content 'X:\ns_out.txt' -ErrorAction SilentlyContinue) -join ' / ')) +
     ' @err ' + ((Get-Content 'X:\ns_err.txt' -ErrorAction SilentlyContinue) -join ' / '))
  AL 'C_net_exit' $pi.ExitCode
} else { AL 'C_net_start' '45 秒无返回(服务挂起), 放弃等待' }
$w = @([System.ServiceProcess.ServiceController]::GetServices() | Where-Object { $_.ServiceName -eq 'wlansvc' })
AL 'C_svc_status' $(if ($w.Count) { $w[0].Status } else { 'not-listed' })

# ---------- D. startnet / boot.log ----------
$sn = (Get-Content 'X:\Windows\System32\startnet.cmd' -ErrorAction SilentlyContinue)
AL 'D_startnet_sshd_line' (($sn | Where-Object { $_ -match 'sshd\.exe' }) -join '')
AL 'D_boot_log' (((Get-Content 'X:\boot.log' -ErrorAction SilentlyContinue) | Select-Object -Last 20) -join ' || ')
AL 'D_sshd_log' (((Get-Content 'X:\sshd.log' -ErrorAction SilentlyContinue) | Select-Object -Last 8) -join ' || ')

# ---------- E. 远程通道现状 (v6 起 sshd 不再自启: WinPE privsep 子进程 0xC0000142) ----------
AL 'E_listen22' $(if (((& netstat -an | Select-String ':22\s' | Out-String).Trim())) { '还在监听 22 (不该)' } else { '未监听 22 (符合预期)' })
AL 'E_startnet_marker' (($sn | Where-Object { $_ -match 'sshd autostart removed' }) -join '')
# 出站通道是救援终端/向日葵/frp 的命脉, 必须可用
$up = $null
try { $up = (Invoke-WebRequest -UseBasicParsing -Uri ("http://" + $H + ":8001/agent") -TimeoutSec 15).RawContentLength } catch { $up = '失败: ' + $_.Exception.Message }
AL 'E_outbound_http' ('GET :8001/agent -> ' + $up + ' 字节')
AL 'E_sunlogin_proc' (@(Get-Process -Name SunloginSOS -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ',')

# ---------- F. frp 与桌面文件位置 ----------
foreach ($d in 'X:\Desktop\Frp', 'X:\Frp', 'X:\Desktop', 'X:\Sunlogin', 'X:\Wlan') {
  if (Test-Path $d) { AL ('F_' + $d) (((Get-ChildItem $d -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ', ')) }
}
AL 'F_frp_exe' $(if (Get-ChildItem X:\ -Recurse -Filter 'frp*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1) { 'FOUND' } else { 'none' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify8.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify8.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host '>>> 回传失败' }
