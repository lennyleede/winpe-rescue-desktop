# WinPE 第七轮: 定位 sshd privsep 子进程早退 (ProgramData 假设 / 令牌权限 / 服务方式 / 最小配置)
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

function Ssh-Try($tag, $cfg = 'X:\OpenSSH\sshd_config', $port = 22) {
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  $null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f', $cfg, '-d', '-e' `
        -NoNewWindow -PassThru -RedirectStandardError "X:\p_$tag.txt" -RedirectStandardOutput "X:\po_$tag.txt"
  Start-Sleep 3
  $r = & X:\OpenSSH\ssh.exe -p $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
        -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  AL ('S_' + $tag) ((($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join ''))
  $log = (Get-Content "X:\p_$tag.txt" -ErrorAction SilentlyContinue)
  AL ('D_' + $tag) (($log | Select-Object -Last 6) -join ' || ')
  AL ('E_' + $tag) ('lines=' + @($log).Count + ' exit=' + (@(Get-Process sshd -ErrorAction SilentlyContinue).Count))
}

# ---------- A. 环境变量现状 ----------
$vars = 'ProgramData', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'TEMP', 'TMP', 'SystemDrive', 'windir', 'PUBLIC'
foreach ($v in $vars) { AL ('A_getenv_' + $v) ([Environment]::GetEnvironmentVariable($v)) }
foreach ($v in $vars) { AL ('A_proc_' + $v) (Get-Item "Env:$v" -ErrorAction SilentlyContinue).Value }

# ---------- B. 令牌权限(私有化子进程需要 SeCreateTokenPrivilege) ----------
try {
  $sigTok = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class Tk {
  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr p, uint acc, out IntPtr tok);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr info, uint len, out uint ret);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LookupPrivilegeNameW(string sys, IntPtr luid, StringBuilder name, ref uint cch);
}
'@
  Add-Type -TypeDefinition $sigTok -ErrorAction Stop
  $tok = [IntPtr]::Zero
  if (-not [Tk]::OpenProcessToken([Tk]::GetCurrentProcess(), 0x0008, [ref]$tok)) {
    AL 'B_token' ('OpenProcessToken 失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  } else {
    $rl = 0
    [void][Tk]::GetTokenInformation($tok, 3, [IntPtr]::Zero, 0, [ref]$rl)
    $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($rl)
    if ([Tk]::GetTokenInformation($tok, 3, $buf, $rl, [ref]$rl)) {
      $count = [Runtime.InteropServices.Marshal]::ReadInt32($buf)
      $names = New-Object System.Collections.Generic.List[string]
      for ($i = 0; $i -lt $count; $i++) {
        $p = $buf + 4 + $i * 12
        $attr = [Runtime.InteropServices.Marshal]::ReadInt32($p + 8)
        $sb = New-Object System.Text.StringBuilder 260
        $cch = [uint32]260
        if ([Tk]::LookupPrivilegeNameW($null, $p, $sb, [ref]$cch)) {
          $names.Add($sb.ToString() + $(if ($attr -band 2) { '=on' } else { '=off' }))
        }
      }
      AL 'B_privileges' ($names -join ', ')
    } else { AL 'B_privileges' ('GetTokenInformation 失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
  }
} catch { AL 'B_token' ('异常: ' + $_.Exception.Message) }

# ---------- C. 配置文件自检 ----------
AL 'C_sshd_t' ((& X:\OpenSSH\sshd.exe -t -f X:\OpenSSH\sshd_config 2>&1 | Out-String))
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$grp = try { (@($id.Groups | ForEach-Object { try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value } }) -join ';') } catch { 'N/A' }
AL 'C_id' ('user=' + $id.Name + ' groups=' + $grp)

# ---------- D. 补 ProgramData 后重试 ----------
New-Item -ItemType Directory -Force -Path 'X:\ProgramData\ssh\logs' -ErrorAction SilentlyContinue | Out-Null
[Environment]::SetEnvironmentVariable('ProgramData', 'X:\ProgramData', 'Process')
$env:ProgramData = 'X:\ProgramData'
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = 'X:\Users\Local'; New-Item -ItemType Directory -Force -Path $env:LOCALAPPDATA | Out-Null }
if (-not $env:APPDATA) { $env:APPDATA = 'X:\Users\Roaming'; New-Item -ItemType Directory -Force -Path $env:APPDATA | Out-Null }
if (-not $env:USERPROFILE) { $env:USERPROFILE = 'X:\Users\Default'; New-Item -ItemType Directory -Force -Path $env:USERPROFILE | Out-Null }
AL 'D_set' ('ProgramData=' + $env:ProgramData + ' APPDATA=' + $env:APPDATA + ' USERPROFILE=' + $env:USERPROFILE)
Ssh-Try 'withpd'
try {
  $envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  AL 'D_machine_before' (Get-ItemProperty $envKey).ProgramData
  Set-ItemProperty $envKey -Name ProgramData -Value 'X:\ProgramData' -Type ExpandString -Force
  AL 'D_machine_after' (Get-ItemProperty $envKey).ProgramData
} catch { AL 'D_machine_env' ('失败: ' + $_.Exception.Message) }

# ---------- E. 最小配置(另一端口, DEBUG3) ----------
$min = @(
  'Port 2222',
  'ListenAddress 0.0.0.0',
  'HostKey X:\OpenSSH\ssh_host_rsa_key',
  'AuthorizedKeysFile X:\OpenSSH\administrators_authorized_keys',
  'PasswordAuthentication no',
  'PubkeyAuthentication yes',
  'StrictModes no',
  'LogLevel DEBUG3'
)
Set-Content -Path 'X:\sshd_min.config' -Value $min -Encoding ASCII
AL 'E_min_written' ((Get-Content 'X:\sshd_min.config') -join ' | ')
Ssh-Try 'min' 'X:\sshd_min.config' 2222
$dbg = (Get-Content 'X:\p_min.txt' -ErrorAction SilentlyContinue)
AL 'E_min_around_kill' (($dbg | Select-String -Pattern 'child|privsep|monitor|error|Unable|failed|pipe|socket' | Select-Object -Last 12) -join ' || ')

# ---------- F. 服务方式启动 sshd ----------
try {
  $sig = @'
using System;
using System.Runtime.InteropServices;
public static class Scm2 {
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
  $nu = [NullString]::Value
  $scm = [Scm2]::OpenSCManagerW($nu, $nu, 0x000F003F)
  if ($scm -eq [IntPtr]::Zero) {
    AL 'F_OpenSCManager' ('失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  } else {
    AL 'F_OpenSCManager' 'OK'
    Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep 2
    Remove-Item 'X:\svc.log' -Force -ErrorAction SilentlyContinue
    $svcCfg = @($min | ForEach-Object { $_ -replace '^Port 2222$', 'Port 22' })
    Set-Content -Path 'X:\sshd_svc.config' -Value $svcCfg -Encoding ASCII
    $h = [Scm2]::CreateServiceW($scm, 'sshdTest', 'sshd Test', 0x000F01FF, 16, 3, 1, 'X:\OpenSSH\sshd.exe -f X:\sshd_svc.config -E X:\svc.log', $nu, [IntPtr]::Zero, $nu, 'LocalSystem', $nu)
    if ($h -eq [IntPtr]::Zero) {
      AL 'F_CreateService' ('失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    } else {
      AL 'F_CreateService' 'OK'
      $r = [Scm2]::StartServiceW($h, 0, [IntPtr]::Zero)
      AL 'F_Start' ('ret=' + $r + ' err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
      Start-Sleep 4
      $st = New-Object Scm2+SERVICE_STATUS
      [void][Scm2]::QueryServiceStatus($h, [ref]$st)
      AL 'F_state' ('state=' + $st.state + ' win32exit=' + $st.win32Exit)
      AL 'F_procs' (@(Get-Process sshd -ErrorAction SilentlyContinue | ForEach-Object { $_.Id }) -join ',')
      $rc = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes `
             -o ConnectTimeout=10 -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
      AL 'F_ssh_as_service' (($rc -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1) -join '')
      AL 'F_service_log_tail' (((Get-Content 'X:\svc.log' -ErrorAction SilentlyContinue) | Select-Object -Last 8) -join ' || ')
      AL 'F_service_log_err' (((Get-Content 'X:\svc.log' -ErrorAction SilentlyContinue) | Select-String -Pattern 'error|Unable|fail|denied|priv|monitor|child' | Select-Object -Last 12) -join ' || ')
      [void][Scm2]::DeleteService($h)
      [void][Scm2]::CloseServiceHandle($h)
    }
    [void][Scm2]::CloseServiceHandle($scm)
  }
} catch { AL 'F_pinvoke' ('失败: ' + $_.Exception.Message) }

# ---------- G. 收尾 ----------
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f', 'X:\OpenSSH\sshd_config', '-E', 'X:\sshd_prod.log' -WindowStyle Hidden
Start-Sleep 3
AL 'G_sshd_running' $(if (Get-Process sshd -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' })

$text = $out -join "`r`n"
Set-Content -Path X:\verify7.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify7.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host '>>> 回传失败' }
