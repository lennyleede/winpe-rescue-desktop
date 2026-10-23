# ============================================================
# pe_report.ps1 —— 在 WinPE 里跑一次, 把 ssh/frp/向日葵/网络的自检结果写成一份报告
# 报告优先落到 U 盘(可移动盘)根目录, 找不到可移动盘就只留 X:\pe_report.txt(X: 是内存盘, 关机即失)。
# 桌面 "自检报告" 图标会调用它; 命令行手动跑:
#   X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -EP Bypass -File X:\Windows\System32\pe_report.ps1
# ============================================================
param([switch]$NoPause, [switch]$NoUsb)
$ErrorActionPreference = 'Continue'
$lines = New-Object System.Collections.ArrayList
function Add2($s) { [void]$lines.Add([string]$s) }
function Sec($t) { Add2 ''; Add2 ('===== ' + $t + ' =====') }
function TryRun($name, $sb) {
  Sec $name
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Stop'   # 否则 Get-Content 之类的非终止错误不会进 catch
  try { & $sb | Out-String -Width 200 | ForEach-Object { Add2 $_.TrimEnd() } }
  catch { Add2 ('  失败: ' + $_.Exception.Message) }
  finally { $ErrorActionPreference = $old }
}

Add2 ('WinPE 自检报告  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

Sec '基本环境'
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
Add2 ('  计算机名 : ' + $cs.Name)
Add2 ('  制造商/型号 : ' + $cs.Manufacturer + ' / ' + $cs.Model)
Add2 ('  系统版本 : ' + $os.Version + ' build ' + $os.BuildNumber)
Add2 ('  内存     : ' + [Math]::Round($os.TotalVisibleMemorySize/1MB, 1) + ' GB')
Add2 ('  启动介质 : ' + $env:SystemDrive + ' (X: 是内存盘, 数据关机即丢)')

TryRun '网卡与IP (ipconfig /all)' { & ipconfig.exe /all }

Sec '网卡清单 (WMI)'
foreach ($a in (Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE')) {
  Add2 ('  ' + $a.Name + ' | ' + $a.NetConnectionID + ' | 介质=' + $a.PhysicalMediaType + ' | 状态=' + $a.NetConnectionStatus + ' | MAC=' + $a.MACAddress)
}

Sec '监听端口 (netstat -an)'
$ns = (& netstat.exe -an) -join "`n"
foreach ($l in (($ns -split "`n") | Where-Object { $_ -match 'LISTENING' })) { Add2 ('  ' + $l.Trim()) }
Add2 ('  :22 在监听 = ' + [bool]($ns -match 'LISTENING' -and $ns -match ':22\s'))

Sec '进程 (SSH / 向日葵 / frpc)'
foreach ($p in 'pe-sshd','SunloginSOS','SunloginClient','frpc','mshta') {
  $q = @(Get-CimInstance Win32_Process -Filter "Name LIKE '$p%'" -ErrorAction SilentlyContinue)
  Add2 ('  ' + $p + ' : ' + $(if ($q.Count) { '运行中 x' + $q.Count } else { '未运行' }))
}

TryRun 'frpc 配置摘要' {
  $f = 'X:\Desktop\Frp\frpc.toml'
  if (-not (Test-Path $f)) { '  没有 ' + $f; return }
  Get-Content $f | Where-Object { $_ -match 'serverAddr|serverPort|token|remotePort|localPort|name' }
}
TryRun 'frpc 日志尾部' {
  if (-not (Test-Path 'X:\frpc.log')) { '  还没有 X:\frpc.log (frpc 未启动)' }
  else { Get-Content 'X:\frpc.log' -Tail 15 }
}

TryRun 'SSH 服务端日志尾部' {
  if (-not (Test-Path 'X:\sshd.log')) { '  还没有 X:\sshd.log' } else { Get-Content 'X:\sshd.log' -Tail 15 }
}

TryRun '启动日志尾部 (X:\boot.log)' { Get-Content 'X:\boot.log' -Tail 25 }

Sec '出站连通性'
foreach ($t in @('http://www.baidu.com','http://detectportal.firefox.com/canonical.html','https://api.github.com')) {
  try {
    $r = Invoke-WebRequest -Uri $t -UseBasicParsing -TimeoutSec 8
    Add2 ('  OK   ' + $t + ' -> HTTP ' + [int]$r.StatusCode)
  } catch { Add2 ('  FAIL ' + $t + ' -> ' + $_.Exception.Message) }
}
Sec 'DNS'
try {
  $d = Resolve-DnsName -Name 'www.baidu.com' -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 2
  Add2 ('  解析到: ' + (($d | ForEach-Object { $_.IPAddress }) -join ', '))
} catch {
  foreach ($n in 'www.baidu.com','api.github.com') {
    try {
      $ips = @([Net.Dns]::GetHostAddresses($n) | ForEach-Object { $_.IPAddressToString })
      Add2 ('  ' + $n + ' -> ' + ($ips -join ', '))
    } catch { Add2 ('  ' + $n + ' 解析失败: ' + $_.Exception.Message) }
  }
}

Sec '磁盘 (Get-CimInstance Win32_LogicalDisk)'
foreach ($d in (Get-CimInstance Win32_LogicalDisk)) {
  Add2 ('  ' + $d.DeviceID + ' 剩余 ' + [Math]::Round($d.FreeSpace/1GB,1) + 'GB / 共 ' + [Math]::Round($d.Size/1GB,1) + 'GB')
}

Sec '结论速览'
Add2 ('  联网: 见上面"出站连通性"; 全 FAIL 就是没到外网(网线/WiFi/USB 共享网络)' )
Add2 ('  SSH : 监听端口里应有 0.0.0.0:22; 有则从另一台机器 ssh Administrator@<本机IP>')
Add2 ('  frp : 桌面 FRP 面板填服务器 -> 保存配置 -> 启动 frpc; 这里看进程与日志')
Add2 ('  向日葵: SunloginSOS 进程在跑即正常, 识别码在它自己弹出的窗口里')

$text = $lines -join "`r`n"
$utf8bom = New-Object Text.UTF8Encoding($true)   # 记事本打开要认得出中文
$saved = @()
try { [IO.File]::WriteAllText('X:\pe_report.txt', $text, $utf8bom); $saved = @('X:\pe_report.txt') }
catch { Write-Host ('  写 X:\pe_report.txt 失败: ' + $_.Exception.Message) }

# 落一份到 U 盘(可移动盘), 关机后还能在别的机器上读; -NoUsb 供宿主机干跑时跳过
if (-not $NoUsb) {
try {
  $usb = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2')
  if (-not $usb.Count) { $usb = @(Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | ForEach-Object { [PSCustomObject]@{ DeviceID = ($_.DriveLetter + ':') } }) }
  foreach ($u in $usb) {
    try {
      $p = Join-Path ($u.DeviceID + '\') ('WinPE自检_' + (Get-Date -Format 'MMdd-HHmmss') + '.txt')
      [IO.File]::WriteAllText($p, $text, $utf8bom)
      $saved += $p
      break
    } catch { Write-Host ('  写 U 盘失败: ' + $_.Exception.Message) }
  }
} catch {}
}

Write-Host $text
Write-Host ''
if ($saved.Count) { Write-Host ('报告已保存: ' + ($saved -join '   ')) -ForegroundColor Green }
else { Write-Host '没有可写的保存位置, 只有屏幕输出' -ForegroundColor Yellow }
if (-not $NoPause) { Read-Host '按回车关闭本窗口' }
