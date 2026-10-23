# WinPE 第四轮: 定位向日葵缺失 DLL / 试修 sshd / 试修 wlansvc / 回传 System32 清单
$ErrorActionPreference = 'Continue'
$H = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function AL($k, $v) { $out.Add(("[{0}] {1}" -f $k, ($v | Out-String).Trim())) }
trap { AL 'TRAP' ($_.Exception.Message + ' @line' + $_.InvocationInfo.ScriptLineNumber); continue }

# ============ A. 账号 / SAM ============
try {
  $sidAdm = ([Security.Principal.NTAccount]'Administrator').Translate([Security.Principal.SecurityIdentifier]).Value
  AL 'A_translate_Administrator' $sidAdm
} catch { AL 'A_translate_Administrator' ('失败: ' + $_.Exception.Message) }
try {
  $sid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-21-0-0-0-500'
  AL 'A_translate_rid500' ($sid.Translate([Security.Principal.NTAccount]).Value)
} catch { AL 'A_translate_rid500' ('失败: ' + $_.Exception.Message) }
AL 'A_SAM_hive' $(if (Test-Path 'X:\Windows\System32\config\SAM') { 'EXISTS' } else { 'ABSENT(WinPE 无本地账号库)' })
AL 'A_ProgramData_ssh' $(if (Test-Path 'X:\ProgramData\ssh') { 'EXISTS' } else { 'ABSENT' })

# ============ B. 向日葵缺失 DLL 精确判定 ============
$need = @('ADVAPI32.dll','COMCTL32.dll','COMDLG32.dll','CRYPT32.dll','dbghelp.dll','GDI32.dll','gdiplus.dll','HID.DLL',
'IMM32.dll','IPHLPAPI.DLL','KERNEL32.DLL','msdmo.dll','MSIMG32.dll','NETAPI32.dll','ole32.dll','OLEAUT32.dll','pdh.dll',
'POWRPROF.dll','PSAPI.DLL','Secur32.dll','SensApi.dll','SETUPAPI.dll','SHELL32.dll','SHLWAPI.dll','USER32.dll',
'USERENV.dll','VERSION.dll','WININET.dll','WINMM.dll','WINSPOOL.DRV','WS2_32.dll','WTSAPI32.dll')
$miss = @()
foreach ($d in $need) {
  if (-not ((Test-Path "X:\Sunlogin\$d") -or (Test-Path "X:\Windows\System32\$d") -or (Test-Path "X:\Windows\System32\downlevel\$d"))) { $miss += $d }
}
AL 'B_sunlogin_missing' $(if ($miss) { ($miss -join ',') } else { '全部存在(那 0xC0000135 另有原因)' })
# 主机里这些 DLL 的大小, 便于确认能否直接拷进 PE
$hostMiss = @()
foreach ($d in $miss) { if (Test-Path "C:\Windows\System32\$d") { $hostMiss += $d } else { $hostMiss += ($d + '(主机也没有)') } }
AL 'B_host_has' ($hostMiss -join ',')
# 把缺的 DLL 从主机拷过来的话 PE 里 X: 是可写的吗
try { Set-Content X:\wtest.txt 'x' -ErrorAction Stop; AL 'B_X_writable' 'YES'; Remove-Item X:\wtest.txt -Force } catch { AL 'B_X_writable' ('NO: ' + $_.Exception.Message) }

# ============ C. 试修 sshd ============
# C1: app-local VC 运行库
foreach ($d in 'vcruntime140.dll','vcruntime140_1.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_codecvt_ids.dll','concrt140.dll','ucrtbase.dll') {
  foreach ($srcDir in 'X:\Sunlogin','X:\Windows\System32','C:\Windows\System32') {
    $srcPath = Join-Path $srcDir $d
    if (Test-Path $srcPath) { Copy-Item $srcPath "X:\OpenSSH\$d" -Force -ErrorAction SilentlyContinue; break }
  }
}
AL 'C1_applocal_vc' (@(Get-ChildItem X:\OpenSSH\msvcp*.dll,X:\OpenSSH\vcruntime*.dll,X:\OpenSSH\ucrtbase.dll -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ',')
# C2: ProgramData\ssh 目录 + 配置
New-Item -ItemType Directory -Force -Path 'X:\ProgramData\ssh\logs' | Out-Null
Copy-Item X:\OpenSSH\sshd_config 'X:\ProgramData\ssh\sshd_config' -Force
Copy-Item X:\OpenSSH\administrators_authorized_keys 'X:\ProgramData\ssh\administrators_authorized_keys' -Force
Copy-Item X:\OpenSSH\ssh_host_*_key 'X:\ProgramData\ssh\' -Force -ErrorAction SilentlyContinue
AL 'C2_pd_ssh' (@(Get-ChildItem X:\ProgramData\ssh -File | ForEach-Object { $_.Name }) -join ',')

function Retry-Ssh($tag) {
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
  Start-Sleep 2
  $null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-d','-e' `
        -NoNewWindow -PassThru -RedirectStandardError "X:\s_$tag.txt" -RedirectStandardOutput "X:\so_$tag.txt"
  Start-Sleep 3
  $r = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes -o ConnectTimeout=10 `
        -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
  $tail = ($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' // '
  AL ("C_ssh_" + $tag) ($tail -replace '\s+', ' ')
  $dbg = @(Get-Content "X:\s_$tag.txt" -ErrorAction SilentlyContinue)
  AL ("C_dbg_" + $tag) ((($dbg | Select-Object -Last 6) -join ' // ') + '  [总' + $dbg.Count + '行]')
  Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
}
Retry-Ssh 'vcfix'
# C3: 用 ProgramData 里的配置再试一次
$null = Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\ProgramData\ssh\sshd_config','-d','-e' -PassThru -NoNewWindow -RedirectStandardError 'X:\s_pd.txt' -RedirectStandardOutput 'X:\so_pd.txt'
Start-Sleep 3
$rp = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=X:\kh -o BatchMode=yes -i X:\tk Administrator@127.0.0.1 'echo LOGIN_OK' 2>&1 | Out-String
AL 'C_ssh_pdconfig' (($rp -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' // ')
AL 'C_dbg_pdconfig' (((Get-Content 'X:\s_pd.txt' -ErrorAction SilentlyContinue) | Select-Object -Last 6) -join ' // ')
Get-Process sshd -ErrorAction SilentlyContinue | Stop-Process -Force
# C4: 恢复正式 sshd
Start-Process -FilePath 'X:\OpenSSH\sshd.exe' -ArgumentList '-f','X:\OpenSSH\sshd_config','-E','X:\sshd_prod.log' -WindowStyle Hidden

# ============ D. 试修 wlansvc: 运行时 CreateService ============
$dot = @((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\dot3svc').GetValueNames())
$wlan = @((Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc').GetValueNames())
AL 'D_dot3svc_values' ($dot -join ',')
AL 'D_wlansvc_values' ($wlan -join ',')
AL 'D_value_diff' ((Compare-Object $dot $wlan | ForEach-Object { $_.SideIndicator + $_.InputObject }) -join ' ')
try {
  Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
  $sig = @'
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr OpenSCManager(string machine, string database, int access);
[DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr CreateService(IntPtr scm, string name, string display, int access, int type, int start, int err, string image, string group, int tag, string deps, string svcStart, string password);
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool CloseServiceHandle(IntPtr h);
'@
  Add-Type -MemberDefinition $sig -Namespace 'Win32' -Name 'Scm' -ErrorAction Stop
  $scm = [Win32.Scm]::OpenSCManager($null, $null, 0x0002)
  if ($scm -eq [IntPtr]::Zero) { AL 'D_CreateService' ('OpenSCManager 失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
  else {
    $h = [Win32.Scm]::CreateService($scm, 'wlansvc2', 'WLAN Test', 0xF01FF, 32, 3, 1, 'X:\Windows\System32\svchost.exe -k PEWLan', $null, [IntPtr]::Zero, $null, 'LocalService', $null)
    if ($h -eq [IntPtr]::Zero) { AL 'D_CreateService' ('CreateService 失败 err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    else {
      AL 'D_CreateService' '创建成功 -> SCM 接受新服务'
      [void][Win32.Scm]::CloseServiceHandle($h)
      try { $c = [System.ServiceProcess.ServiceController]::new('wlansvc2'); AL 'D_scm_sees_new' ('YES state=' + $c.Status) } catch { AL 'D_scm_sees_new' 'NO' }
    }
    [void][Win32.Scm]::CloseServiceHandle($scm)
  }
} catch { AL 'D_CreateService' ('Add-Type/P/Invoke 失败: ' + $_.Exception.Message) }

# ============ E. System32 清单回传 ============
$s32 = @(Get-ChildItem 'X:\Windows\System32' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$dl  = @(Get-ChildItem 'X:\Windows\System32\downlevel' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
AL 'E_sys32_count' $s32.Count.ToString()
AL 'E_downlevel_count' $dl.Count.ToString()
AL 'E_FILELIST' ($s32 -join ',')
AL 'E_FILELIST_DOWNLEVEL' ($dl -join ',')
AL 'E_apiset_count' (@($dl | Where-Object { $_ -like 'api-ms*' -or $_ -like 'ext-ms*' }).Count.ToString())

$text = $out -join "`r`n"
Set-Content -Path X:\verify4.txt -Value $text -Encoding UTF8
Write-Host ('结果 ' + $text.Length + ' 字节, 正在回传...')
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $H + ":8000/result") -InFile X:\verify4.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 40 | Out-Null
  Write-Host '>>> 已回传'
} catch { Write-Host '>>> 回传失败, 请把 X:\verify4.txt 截图' }
