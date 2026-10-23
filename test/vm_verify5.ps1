# WinPE 第五轮: 抓 sshd 完整崩溃日志 + 用 CreateService 验证运行时注册服务
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

# ---------- A. sshd 完整日志 ----------
AL 'A0_sshd_version' ((& X:\OpenSSH\sshd.exe -V 2>&1 | Out-String) -replace '\s+', ' ')
AL 'A1_test_config' ((& X:\OpenSSH\sshd.exe -t -f X:\OpenSSH\sshd_config 2>&1 | Out-String) -replace '\s+', ' ')
AL 'A2_shellhost' $(if (Test-Path X:\OpenSSH\ssh-shellhost.exe) { 'PRESENT' } else { 'MISSING' })
AL 'A3_config_content' ((Get-Content X:\OpenSSH\sshd_config) -join ' | ')

Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
$null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
      -NoNewWindow -PassThru -RedirectStandardError 'X:\full_srv.txt' -RedirectStandardOutput 'X:\full_srv_out.txt'
Start-Sleep 3
$cli = & X:\OpenSSH\ssh.exe -vvv -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
Start-Sleep 2
AL 'A4_server_FULL' ((Get-Content 'X:\full_srv.txt' -ErrorAction SilentlyContinue) -join ' || ')
AL 'A5_server_stdout' ((Get-Content 'X:\full_srv_out.txt' -ErrorAction SilentlyContinue) -join ' || ')
$cl = ($cli -split "`n" | Where-Object { $_.Trim() })
AL 'A6_client_tail20' ((($cl | Select-Object -Last 20)) -join ' || ')
AL 'A7_client_lines' $cl.Count.ToString()

# ---------- B. 事件日志里有没有 sshd 的报错 ----------
try {
  $ev = @(Get-WinEvent -LogName 'Application' -MaxEvents 40 -ErrorAction Stop | Where-Object { $_.Provider -match 'OpenSSH|SideBySide|Application Error|\.NET Runtime' } | ForEach-Object { $_.Provider + ':' + $_.Id + ':' + ($_.Message -replace '\s+', ' ') })
  AL 'B_events' $(if ($ev) { ($ev | Select-Object -First 6) -join ' ||| ' } else { '无相关事件' })
} catch { AL 'B_events' ('Get-WinEvent 不可用: ' + $_.Exception.Message) }

# ---------- C. CreateService 运行时注册 ----------
try {
  $sig = @'
using System;
using System.Runtime.InteropServices;
public static class ScmApi {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start, uint errctl, string image, string group, IntPtr tag, string deps, string svcStart, string password);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern uint StartServiceW(IntPtr svc, uint argc, IntPtr argv);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DeleteService(IntPtr svc);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool QueryServiceStatus(IntPtr svc, out SERVICE_STATUS st);
  [StructLayout(LayoutKind.Sequential)] public struct SERVICE_STATUS { public uint state, exit, wait, checkpoint, waitHint, win32Exit, svcExit; }
}
'@
  Add-Type -TypeDefinition $sig -ErrorAction Stop
  $scm = [ScmApi]::OpenSCManagerW('', '', 0x000F003F)
  if ($scm -eq [IntPtr]::Zero) { AL 'C_OpenSCManager' ('失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  else {
    AL 'C_OpenSCManager' 'OK'
    $img = 'X:\Windows\System32\svchost.exe -k netsvcs'
    $h = [ScmApi]::CreateServiceW($scm, 'wlansvcX', 'WLAN Test X', 0x000F01FF, 32, 3, 1, $img, 'NDIS', [IntPtr]::Zero, $null, 'LocalService', $null)
    if ($h -eq [IntPtr]::Zero) { AL 'C_CreateService' ('失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    else {
      AL 'C_CreateService' 'OK (SCM 接受运行时新建服务)'
      $st = New-Object ScmApi+SERVICE_STATUS
      [void][ScmApi]::QueryServiceStatus($h, [ref]$st)
      AL 'C_state_before' $st.state
      $r = [ScmApi]::StartServiceW($h, 0, [IntPtr]::Zero)
      AL 'C_StartService' ('ret=' + $r + ' err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
      Start-Sleep 3
      [void][ScmApi]::QueryServiceStatus($h, [ref]$st)
      AL 'C_state_after' $st.state
      [void][ScmApi]::DeleteService($h)
      [void][ScmApi]::CloseServiceHandle($h)
    }
    [void][ScmApi]::CloseServiceHandle($scm)
  }
} catch { AL 'C_pinvoke' ('失败: ' + $_.Exception.Message) }

# ---------- D. 顺手把 wlansvc 的注册表值补全(供下次构建参考) ----------
try {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
  New-ItemProperty -Path $k -Name ErrorControl -Value 1 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $k -Name ServiceSidType -Value 0 -PropertyType DWord -Force | Out-Null
  New-ItemProperty -Path $k -Name Group -Value 'NDIS' -PropertyType String -Force | Out-Null
  New-ItemProperty -Path $k -Name RequiredPrivileges -Value @('SeChangeNotifyPrivilege','SeCreateGlobalPrivilege','SeImpersonatePrivilege','SeIncreaseBasePriorityPrivilege','SeTcbPrivilege') -PropertyType MultiString -Force | Out-Null
  Remove-ItemProperty -Path $k -Name Error -ErrorAction SilentlyContinue
  AL 'D_reg_fixed' ((Get-Item $k).GetValueNames() -join ',')
} catch { AL 'D_reg_fixed' ('失败: ' + $_.Exception.Message) }

# ---------- E. 恢复正式 sshd ----------
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-E','X:\sshd_prod.log' -WindowStyle Hidden
Start-Sleep 3
AL 'E_sshd_restarted' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'RUNNING' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify5.txt -Value $text -Encoding UTF8
Write-Host ('结果 ' + $text.Length + ' 字节, 回传中...')
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify5.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 已回传'
} catch { Write-Host '>>> 回传失败, 请截图 X:\verify5.txt' }
