# 在 WinPE 内部运行的全量自检脚本: 结果写 X:\verify_out.txt 并 POST 回主机
$ErrorActionPreference = 'Continue'
$Host_ = '172.31.32.1'
$out = New-Object System.Collections.Generic.List[string]
function Add-Line($k, $v) { $out.Add(("[{0}] {1}" -f $k, $v)) }

Add-Line 'TIME' (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Add-Line 'IDENTITY' ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Add-Line 'COMPUTER' $env:COMPUTERNAME
Add-Line 'PSVER' $PSVersionTable.PSVersion.ToString()
Add-Line 'CLRVER' ([Environment]::Version.ToString())

# --- 进程 (tasklist 缺失, 用 Get-Process) ---
$procs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName })
foreach ($p in 'sshd','mshta','SunloginSOS','svchost','services','explorer') {
  Add-Line ('PROC_' + $p) $(if ($procs -contains $p) { 'RUNNING' } else { 'NOT-RUNNING' })
}
Add-Line 'PROC_ALL' (($procs | Sort-Object -Unique) -join ',')

# --- 22 端口监听 (netstat 兜底 + Get-NetTCPConnection) ---
$ns = @(netstat -an 2>$null | Select-String ':22\s')
Add-Line 'NETSTAT22' $(if ($ns) { ($ns -join ' | ') } else { 'NO-LISTENER-ON-22' })
try {
  $t = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction Stop
  Add-Line 'NETTCP22' ('OK ' + (($t | ForEach-Object { $_.LocalAddress + ':' + $_.OwningProcess }) -join ','))
} catch { Add-Line 'NETTCP22' ('unavailable: ' + $_.Exception.Message) }

# --- wlansvc 服务状态 (sc 缺失, 用 WMI) ---
try {
  $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='wlansvc'" -ErrorAction Stop
  Add-Line 'WLANSVC' ('State=' + $s.State + ' StartMode=' + $s.StartMode + ' Path=' + $s.PathName)
} catch { Add-Line 'WLANSVC' ('WMI查询失败: ' + $_.Exception.Message) }
try {
  $svc = Get-Service wlansvc -ErrorAction Stop
  Add-Line 'WLANSVC_PS' ($svc.Status.ToString())
} catch { Add-Line 'WLANSVC_PS' 'Get-Service 不可用' }
# 无线硬件/驱动线索
foreach ($f in 'System32\wlansvc.dll','System32\wlancfg.dll','System32\drivers\nwifi.sys','System32\drivers\ndis.sys','System32\dot3svc.dll') {
  Add-Line ('FILE_' + (Split-Path $f -Leaf)) $(if (Test-Path "X:\Windows\$f") { 'PRESENT' } else { 'MISSING' })
}
try {
  $w = @(netsh wlan show interfaces 2>&1 | Out-String)
  Add-Line 'NETSH_WLAN' ($w -join ' ')
} catch { Add-Line 'NETSH_WLAN' 'netsh 不可用' }
try {
  $ad = @(Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop | ForEach-Object { $_.Name + '=' + $_.NetConnectionStatus })
  Add-Line 'ADAPTERS' ($ad -join ' | ')
} catch { Add-Line 'ADAPTERS' ('失败: ' + $_.Exception.Message) }

# --- 注入的文件 ---
foreach ($d in 'X:\Frp','X:\Sunlogin','X:\Desktop','X:\OpenSSH','X:\Desktop\Frp') {
  if (Test-Path $d) {
    $files = @(Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue)
    Add-Line ('DIR_' + $d) ($files.Count.ToString() + ' 文件, ' + [math]::Round((($files | Measure-Object Length -Sum).Sum / 1MB), 1) + ' MB')
    Add-Line ('DIRLIST_' + $d) ((($files | ForEach-Object { $_.Name }) | Select-Object -First 25) -join ',')
  } else { Add-Line ('DIR_' + $d) 'MISSING' }
}

# --- 组件与字体 ---
foreach ($f in 'System32\mshta.exe','System32\wbem\wmiprvse.exe','System32\WindowsPowerShell\v1.0\powershell.exe','System32\en-US\wmiprvse.exe.mui') {
  Add-Line ('COMP_' + (Split-Path $f -Leaf)) $(if (Test-Path "X:\Windows\$f") { 'OK' } else { 'NO' })
}
$fonts = @(Get-ChildItem X:\Windows\Fonts -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
Add-Line 'FONT_COUNT' ($fonts.Count.ToString())
Add-Line 'FONT_ZH' $(if ($fonts -match 'msyh|simhei|simsun|DengXian') { ('中文字体: ' + (($fonts -match 'msyh|simhei|simsun|DengXian') -join ',')) } else { '无中文字体(中文会显示为方块)' })
Add-Line 'DOT3_RNDIS_PPPoE' $(if ((Test-Path 'X:\Windows\System32\dot3svc.dll') -and (Test-Path 'X:\Windows\System32\raspppoe.dll')) { 'OK' } else { '部分缺失' })

# --- 磁盘 ---
try {
  $ld = @(Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | ForEach-Object { $_.DeviceID + ' ' + [math]::Round($_.Size/1MB) + 'MB' })
  Add-Line 'DISKS' ($ld -join ' | ')
} catch { Add-Line 'DISKS' ('失败: ' + $_.Exception.Message) }

# --- 日志尾部 ---
foreach ($lg in 'X:\boot.log','X:\sshd.log') {
  if (Test-Path $lg) { Add-Line ('LOG_' + (Split-Path $lg -Leaf)) (((Get-Content $lg -ErrorAction SilentlyContinue) | Select-Object -Last 15) -join ' // ') }
  else { Add-Line ('LOG_' + (Split-Path $lg -Leaf)) 'NO-LOG' }
}

# --- SSH 认证链回环测试 ---
try {
  if (-not (Test-Path X:\tk)) {
    & X:\OpenSSH\ssh-keygen.exe -t ed25519 -N '""' -f X:\tk -q 2>&1 | Out-Null
  }
  if (Test-Path X:\tk.pub) {
    $pub = (Get-Content X:\tk.pub -Raw).Trim()
    Add-Line 'SSH_KEYGEN' ('OK ' + $pub.Substring(0, [Math]::Min(30, $pub.Length)) + '...')
    Add-Content X:\OpenSSH\administrators_authorized_keys $pub
    $r = & X:\OpenSSH\ssh.exe -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -i X:\tk admin@127.0.0.1 'echo LOOPBACK_OK && whoami' 2>&1 | Out-String
    Add-Line 'SSH_LOOPBACK' ($r.Trim() -replace '\s+', ' ')
  } else { Add-Line 'SSH_KEYGEN' 'FAILED (无 X:\tk.pub)' ; Add-Line 'SSH_LOOPBACK' 'SKIPPED' }
} catch { Add-Line 'SSH_LOOPBACK' ('异常: ' + $_.Exception.Message) }

$text = $out -join "`r`n"
Set-Content -Path X:\verify_out.txt -Value $text -Encoding UTF8
Write-Host $text
try {
  Invoke-WebRequest -UseBasicParsing -Method Post -Uri ("http://" + $Host_ + ":8000/result") -InFile X:\verify_out.txt -ContentType 'text/plain; charset=utf-8' -TimeoutSec 20 | Out-Null
  Write-Host '>>> 结果已回传主机'
} catch { Write-Host ('>>> 回传失败: ' + $_.Exception.Message + '  (请把 X:\verify_out.txt 内容截图给我)') }
