# WinPE 第十一轮: 按 install-sshd.ps1 的真实要求补两件事再测 sshd
#   A. wevtutil im openssh-events.man (ETW 提供方未注册)
#   B. 服务键补 RequiredPrivileges(SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/...) 再以服务启动
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }
$env:ProgramData = 'X:\ProgramData'

function Try-Login($tag, $dir = 'X:\OpenSSH', $cfg = 'X:\OpenSSH\sshd_config', $log = $null) {
  $r = & (Join-Path $dir 'ssh.exe') -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  $ok = if ($r -match 'LOGIN_OK') { 'LOGIN_OK !!' } else { (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '') }
  AL ('L_' + $tag) $ok
  if ($log) { AL ('G_' + $tag) (((Get-Content $log -ErrorAction SilentlyContinue) | Select-Object -Last 5) -join ' || ') }
}

function Stop-Sshd { Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 2 }

# ---------- A0. 登录前置自检 (VM 若重启过, X:\tk 就没了, 会让所有 Try-Login 误判成 sshd 的问题) ----------
if (-not (Test-Path 'X:\tk')) {
  & 'X:\OpenSSH\ssh-keygen.exe' -t ed25519 -N '""' -f X:\tk -q 2>&1 | Out-Null
  AL 'A0_key' 'X:\tk 缺失, 已重新生成'
} else { AL 'A0_key' 'X:\tk 存在' }
$pub = (Get-Content X:\tk.pub -ErrorAction SilentlyContinue | Out-String).Trim()
$ak = 'X:\OpenSSH\administrators_authorized_keys'
if ($pub) {
  $cur = @(Get-Content $ak -ErrorAction SilentlyContinue)
  if (-not ($cur -contains $pub)) { Add-Content -Path $ak -Value $pub -Encoding ASCII; AL 'A0_authkeys' '已追加 pubkey' }
  else { AL 'A0_authkeys' 'pubkey 已在' }
} else { AL 'A0_authkeys' '无 pubkey, 登录测试将不可信' }
AL 'A0_ak_lines' (@(Get-Content $ak -ErrorAction SilentlyContinue).Count.ToString() + ' 行')

# PE 里未必有 wevtutil.exe, 先探测再调用, 避免 CommandNotFoundException 打断整轮
$hasWevt = [bool](Get-Command wevtutil.exe -ErrorAction SilentlyContinue)
AL 'Z_wevtutil' $(if ($hasWevt) { (Get-Command wevtutil.exe).Source } else { 'PE 内没有 wevtutil.exe -> A/C 的 ETW 前置无法测' })
function Reg-Man($m) {
  if (-not $hasWevt) { return 'wevtutil 缺失' }
  ((& wevtutil im $m 2>&1 | Out-String).Trim())
}

# ---------- A. ETW 提供方 ----------
$man = @('X:\OpenSSH\openssh-events.man', 'X:\OpenSSH-Win64\openssh-events.man') | Where-Object { Test-Path $_ } | Select-Object -First 1
AL 'A_manifest' $(if ($man) { $man } else { 'PE 内没有 openssh-events.man' })
if ($man) { AL 'A_wevtutil_im' (Reg-Man $man) }
if ($hasWevt) { AL 'A_channels' ((& wevtutil el 2>&1 | Select-String -Pattern 'Application|OpenSSH' | Out-String).Trim()) }
Stop-Sshd
$null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f', 'X:\OpenSSH\sshd_config', '-d', '-e' -NoNewWindow `
      -PassThru -RedirectStandardError 'X:\a_etw.txt' -RedirectStandardOutput 'X:\a_etwo.txt'
Start-Sleep 3
Try-Login 'etw'
AL 'A_srv_tail' (((Get-Content 'X:\a_etw.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 5) -join ' || ')
Stop-Sshd

# ---------- B. 服务 + RequiredPrivileges ----------
try {
  $sig = @'
using System;
using System.Runtime.InteropServices;
public static class Scm3 {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access, uint type, uint start, uint errctl, string image, string group, IntPtr tag, string deps, string svcStart, string password);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool CloseServiceHandle(IntPtr h);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern uint StartServiceW(IntPtr svc, uint argc, IntPtr argv);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool DeleteService(IntPtr svc);
}
'@
  Add-Type -TypeDefinition $sig -ErrorAction Stop
  $nu = [NullString]::Value
  $scm = [Scm3]::OpenSCManagerW($nu, $nu, 0x000F003F)
  $img = 'X:\OpenSSH\sshd.exe -f X:\OpenSSH\sshd_config -E X:\svc2.log'
  # 上一轮可能残留 sshdTest(且没设权限), 一律先删注册表键再新建, 保证测的是本轮的 ImagePath+RequiredPrivileges
  if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\sshdTest') {
    Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\sshdTest' -Recurse -Force -ErrorAction SilentlyContinue
    AL 'B_predelete' '已删除残留 sshdTest 键'
    Start-Sleep 2
  }
  $h = [Scm3]::CreateServiceW($scm, 'sshdTest', 'sshd Test', 0x000F01FF, 16, 3, 1, $img, $nu, [IntPtr]::Zero, $nu, 'LocalSystem', $nu)
  if ($h -eq [IntPtr]::Zero) {
    $e1 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    # 1073=ERROR_SERVICE_EXISTS (上一轮残留): 直接打开已有服务再补权限
    if ($e1 -eq 1073) {
      $h = [Scm3]::OpenServiceW($scm, 'sshdTest', 0x000F01FF)
      AL 'B_CreateService' ('已存在, OpenService ret=' + ($h -ne [IntPtr]::Zero) + ' err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
      if ($h -ne [IntPtr]::Zero) { AL 'B_image' ('当前 ImagePath=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\sshdTest').ImagePath) }
    } else {
      AL 'B_CreateService' ('失败 err=' + $e1)
    }
  } else { AL 'B_CreateService' 'OK' }
  if ($h -ne [IntPtr]::Zero) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshdTest'
    $privs = @('SeChangeNotifyPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeTcbPrivilege',
               'SeBackupPrivilege', 'SeRestorePrivilege', 'SeImpersonatePrivilege',
               'SeCreateTokenPrivilege', 'SeIncreaseQuotaPrivilege', 'SeSecurityPrivilege')
    New-ItemProperty -Path $k -Name RequiredPrivileges -Value $privs -PropertyType MultiString -Force | Out-Null
    New-ItemProperty -Path $k -Name ServiceSidType -Value 0 -PropertyType DWord -Force | Out-Null
    AL 'B_privs' ((Get-ItemProperty $k).RequiredPrivileges -join ',')
    $r = [Scm3]::StartServiceW($h, 0, [IntPtr]::Zero)
    AL 'B_Start' ('ret=' + $r + ' err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    Start-Sleep 5
    AL 'B_procs' (@(Get-Process sshd -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ',')
    Try-Login 'svcpriv' -log 'X:\svc2.log'
    [void][Scm3]::DeleteService($h)
    [void][Scm3]::CloseServiceHandle($h)
  }
  [void][Scm3]::CloseServiceHandle($scm)
} catch { AL 'B_err' ('失败: ' + $_.Exception.Message) }
Stop-Sshd

# ---------- C. 服务方式 + 已注册 ETW + 7.7.2 二进制 ----------
try {
  if (Test-Path 'X:\OpenSSH-Win64\sshd.exe') {
    $cfg77 = @(
      'Port 22', 'ListenAddress 0.0.0.0',
      'HostKey X:\OpenSSH\ssh_host_rsa_key',
      'AuthorizedKeysFile X:\OpenSSH\administrators_authorized_keys',
      'PasswordAuthentication no', 'PubkeyAuthentication yes', 'StrictModes no', 'LogLevel DEBUG3',
      'Subsystem sftp X:\OpenSSH-Win64\sftp-server.exe'
    )
    Set-Content -Path 'X:\sshd77p22.config' -Value $cfg77 -Encoding ASCII
    $m77 = 'X:\OpenSSH-Win64\openssh-events.man'
    if (Test-Path $m77) { AL 'C_wevtutil_im77' (Reg-Man $m77) }
    $null = Start-Process -FilePath 'X:\OpenSSH-Win64\sshd.exe' -ArgumentList '-f', 'X:\sshd77p22.config', '-d', '-e' -NoNewWindow `
          -PassThru -RedirectStandardError 'X:\c77.txt' -RedirectStandardOutput 'X:\c77o.txt'
    Start-Sleep 3
    Try-Login 'v77etw' -dir 'X:\OpenSSH-Win64'
    AL 'C_srv_tail' (((Get-Content 'X:\c77.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 6) -join ' || ')
    Stop-Sshd
  } else { AL 'C_skip' 'X:\OpenSSH-Win64 不存在(上一轮未解出)' }
} catch { AL 'C_err' ('失败: ' + $_.Exception.Message) }

# ---------- D. 收尾 ----------
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f', 'X:\OpenSSH\sshd_config', '-E', 'X:\sshd.log' -WindowStyle Hidden
Start-Sleep 3
AL 'D_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify11.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify11.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host '>>> 回传失败' }
