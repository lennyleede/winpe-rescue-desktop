# ============================================================
# 32_RecheckWinPe10.ps1 —— 只走 SSH 的 Win10 PE 复查(普通权限就能跑, 不用管理员)
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\32_RecheckWinPe10.ps1 [-IP 172.17.40.212]
# 为什么需要它:
#   - 30 脚本里的截图在这台宿主机上永远失败: root\virtualization\v2 里根本没有
#     Msvm_VideoHeadService 这个类(19044 的 Hyper-V 没开放 GetScreenImage), 报"无效类"。
#   - 所以"HTA 桌面/向日葵窗口到底画出来没有"改成在 PE 里 EnumWindows 拿顶层窗口标题 —— 这是
#     比看截图更硬的证据(进程活着不等于窗口画出来了)。
#   - 另外补两项: PE 出站联网(救援场景的真需求)、以及 30 里两处写坏的命令(cmd 用 & 串 if exist
#     只回了第一个标记; Win32_Service 的 ExitCode 是 uint32, [int] 转换在 wlansvc 上抛异常)。
# ============================================================
param(
  [string]$IP = '',
  [string]$User = 'Administrator',
  [switch]$SkipNet
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path $PSScriptRoot -Parent
$Out  = Join-Path $PSScriptRoot 'vm10_recheck.txt'
$Rows = New-Object System.Collections.ArrayList
function L($m) {
  Write-Host $m
  [void]$Rows.Add([string]$m)
  try { Set-Content -LiteralPath $Out -Value ($Rows -join "`r`n") -Encoding UTF8 } catch { }
}
if (-not $IP) {
  $f = Join-Path $PSScriptRoot 'vm_ip.txt'
  if (-not (Test-Path $f)) { L 'ERROR: 没给 -IP 也没有 test\vm_ip.txt'; exit 1 }
  $IP = (Get-Content $f).Trim()
}
L ('===== Win10 PE 复查(SSH-only) ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' 目标=' + $User + '@' + $IP + ' =====')

$keySrc = Join-Path $Root 'overlay\Scripts\ssh_login_key'
if (-not (Test-Path -LiteralPath $keySrc)) { L ('ERROR: 登录私钥不在 ' + $keySrc); exit 1 }
$keyTmp = Join-Path $env:TEMP ('winpe10_recheck_key_' + $PID)
if (Test-Path -LiteralPath $keyTmp) { Remove-Item -LiteralPath $keyTmp -Force }
Copy-Item -LiteralPath $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r ("${env:USERNAME}:R") | Out-Null
$sshBin = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshBin)) { $sshBin = 'ssh' }
# 注意不能加 -o BatchMode=yes: pe-sshd 走的是 "none" 认证(空密码), BatchMode 下客户端直接放弃 -> rc=255
$sshOpts = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
             '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=10', '-o', 'LogLevel=ERROR', ($User + '@' + $IP))
function Invoke-Pe([string]$label, [string]$cmd) {
  L ('---------- ' + $label + ' ----------')
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $t0 = Get-Date
  $o = & $sshBin @sshOpts $cmd 2>&1
  $script:SshRc = $LASTEXITCODE
  $sec = [int]((Get-Date).Subtract($t0).TotalSeconds)
  $ErrorActionPreference = $prev
  $txt = @($o | ForEach-Object { "$_" })
  L ('  (rc=' + $script:SshRc + ' 用时=' + $sec + 's 行数=' + $txt.Count + ')')
  $txt | Select-Object -First 80 | ForEach-Object { L ('  ' + $_) }
  if ($txt.Count -gt 80) { L ('  ...(还有 ' + ($txt.Count - 80) + ' 行未打印)') }
  return $txt
}
function Invoke-PePs([string]$label, [string]$ps) {
  $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
  return (Invoke-Pe $label ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64))
}
# 复杂载荷(带 here-string / 多行)一律走文件: 本地读 -> base64 -> PE 里解码写成 X:\rc.ps1 再跑。
# 这样彻底避开 cmd -> ssh -> powershell 三层引号互咬。
function Invoke-PeFile([string]$label, [string]$Path, [string]$Extra) {
  if (-not (Test-Path -LiteralPath $Path)) { L ('---------- ' + $label + ' ----------'); L ('  ERROR: 载荷文件不存在 ' + $Path); return @() }
  # 分块下发: 整段 base64 再包一层 -EncodedCommand 会超过 cmd 的 8191 字符上限("The command line is too long")
  $txt = [System.IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
  $b64p = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($txt))
  & $sshBin @sshOpts 'del X:\rc.b64 2>nul & echo READY' | Out-Null
  for ($i = 0; $i -lt $b64p.Length; $i += 1800) {
    $len = [Math]::Min(1800, $b64p.Length - $i)
    $inner = '[IO.File]::AppendAllText(''X:\rc.b64'',''' + $b64p.Substring($i, $len) + ''')'
    $b = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    $o = & $sshBin @sshOpts ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b) 2>&1
    if ($LASTEXITCODE -ne 0) { L ('  !! 分块写入失败(第 ' + [int]($i / 1800 + 1) + ' 块): ' + (($o | ForEach-Object { "$_" }) -join ' ')); return @() }
  }
  $run = ('$b=[IO.File]::ReadAllText(''X:\rc.b64'');' +
          '$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));' +
          '[IO.File]::WriteAllBytes(''X:\rc.ps1'',[byte[]](0xEF,0xBB,0xBF)+[Text.Encoding]::UTF8.GetBytes($s));' +
          'Remove-Item X:\rc.b64 -Force -EA SilentlyContinue;' +
          '& X:\rc.ps1' + $(if ($Extra) { ' ' + $Extra } else { '' }))
  # 这段是 PowerShell 语句, 同样要 -EncodedCommand(pe-sshd 把命令行交给 cmd.exe)
  $br = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($run))
  return (Invoke-Pe $label ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $br))
}

L ''
L '=== A. 身份(必须 product=WinPE10_Desktop_v1 且 OS=19041) ==='
$gate = Invoke-Pe 'A1 BUILD_TAG' 'type X:\BUILD_TAG.txt'
$gt = (@($gate) -join "`n")
if ($gt -notmatch 'WinPE10_Desktop_v1') { L 'ABORT: 连上的这台不是 Win10 分支镜像, 后面的结论都不要信'; exit 1 }
Invoke-PePs 'A2 OS / PowerShell' '[Environment]::OSVersion.Version.ToString(); $PSVersionTable.PSVersion.ToString(); $env:COMPUTERNAME; (Get-Date).ToString()' | Out-Null

L ''
L '=== B. 开机自启的原始记录 ==='
Invoke-Pe 'B1 status.txt' 'type X:\status.txt' | Out-Null
Invoke-PePs 'B2 boot.log 里 [1a]-[5] 的步骤行' 'if(Test-Path X:\boot.log){ (Get-Content X:\boot.log) | Where-Object { $_ -match ''^\[(1a|1b|2|3|4|5)\]'' } }else{ ''BOOT_LOG_MISSING'' }' | Out-Null
Invoke-PePs 'B3 fw_off.log 末 12 行' 'if(Test-Path X:\fw_off.log){ Get-Content X:\fw_off.log | Select-Object -Last 12 }else{ ''FW_OFF_LOG_MISSING'' }' | Out-Null
Invoke-PePs 'B4 sshd.log 末 8 行 + 监听' 'if(Test-Path X:\sshd.log){ Get-Content X:\sshd.log -Encoding UTF8 | Select-Object -Last 8 }; & netstat.exe -an | Select-String ''LISTENING''' | Out-Null

L ''
L '=== C. 桌面证据: 顶层窗口(进程活着不等于界面画出来了) ==='
# 载荷是文件(里面有 here-string, 不能内联): 见 test\pe10_windows.ps1
Invoke-PeFile 'C1 可见窗口(主窗口句柄/标题 + EnumWindows 全量)' (Join-Path $PSScriptRoot 'pe10_windows.ps1') | Out-Null
Invoke-PePs 'C2 mshta/向日葵 进程与启动时间' 'foreach($n in @("mshta","SunloginSOS","pe-sshd","frpc","WallpaperHost","winpeshl")){ $p=@(Get-Process -Name $n -EA SilentlyContinue); "{0} = {1} {2}" -f $n, $p.Count, (($p | ForEach-Object { "pid" + $_.Id + "@" + $_.StartTime.ToString("HH:mm:ss") }) -join " ") }' | Out-Null
Invoke-PePs 'C3 桌面 HTA 与 frp/向日葵素材在不在' 'foreach($p in @("X:\Desktop\Desktop.hta","X:\Desktop\wallpaper.jpg","X:\Desktop\Frp\frpc.exe","X:\Desktop\Frp\frpc.toml","X:\Sunlogin\SunloginSOS.exe","X:\SSH\pe-sshd.exe","X:\SSH\authorized_keys","X:\Windows\System32\mshta.exe","X:\Windows\System32\wbem\wmiprvse.exe","X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe","X:\Windows\Microsoft.NET\Framework64\v4.0.30319","X:\Windows\System32\dot3api.dll","X:\Windows\System32\netdrv_index.txt","X:\Windows\System32\niccheck.cmd","X:\Windows\System32\niccheck.ps1","X:\Windows\System32\netdrvfix.cmd")){ "{0} {1}" -f $(if(Test-Path $p){"YES "}else{"NO  "}), $p }' | Out-Null
Invoke-PePs 'C4 frpc 配置文件仍是模板(没被写死进镜像)' 'if(Test-Path X:\Desktop\Frp\frpc.toml){ Get-Content X:\Desktop\Frp\frpc.toml } else { "FRPC_TOML_MISSING" }' | Out-Null

L ''
L '=== D. 服务状态(ExitCode 是 uint32, 别再 [int] 转换) ==='
Invoke-PePs 'D1 关键服务' 'foreach($n in @("wlansvc","dot3svc","WcmSvc","Winmgmt","MpsSvc","BFE","LanmanServer","SamSS","Sens")){ $s=Get-CimInstance Win32_Service -Filter "Name=''$n''" -EA SilentlyContinue; if($s){ $ec=if($s.ExitCode -is [uint32]){$s.ExitCode}else{[uint32]$s.ExitCode}; "{0,-14} {1,-10} start={2,-8} exit=0x{3:X8}" -f $n,$s.State,$s.StartMode,$ec } else { "{0,-14} ABSENT" -f $n } }' | Out-Null

L ''
L '=== E. 联网(救援场景真正要的) ==='
Invoke-PePs 'E1 网卡与 IP' 'Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue | Where-Object { $_.IPEnabled } | ForEach-Object { "{0} | mac={1} | ip={2} | gw={3} | dhcp={4} | dns={5}" -f $_.Description, $_.MacAddress, ($_.IPAddress -join ","), ($_.DefaultIPGateway -join ","), $_.DHCPEnabled, ($_.DNSServerSearchOrder -join ",") }' | Out-Null
Invoke-Pe 'E2 netstat 路由/接口(有没有默认路由)' 'netstat.exe -rn' | Out-Null
if (-not $SkipNet) {
  Invoke-PePs 'E3 PE 出站 HTTP(百度 + 一个 IP 兜底)' 'foreach($u in @("http://www.baidu.com/","http://1.1.1.1/")){ try { $r = Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 8 -EA Stop; "OK  {0} -> {1} {2}B" -f $u, $r.StatusCode, $r.RawContentLength } catch { "FAIL {0} -> {1}" -f $u, $_.Exception.Message } }' | Out-Null
  Invoke-PePs 'E4 DNS 解析' 'try { (Resolve-DnsName -Name www.baidu.com -EA Stop | Select-Object -First 2 | ForEach-Object { $_.IPAddress }) -join "," } catch { try { ([System.Net.Dns]::GetHostAddresses("www.baidu.com") | ForEach-Object { $_.IPAddressToString }) -join "," } catch { "DNS_FAIL " + $_.Exception.Message } }' | Out-Null
}

L ''
L '=== F. 有线网卡自动识别(BUILD_TAG 的 netdrv 索引 + netdrvfix 结论) ==='
Invoke-PePs 'F1 设备里有没有 code28/未知的网卡' 'Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.Name -match ''(Ethernet|Network|Controller|NIC|Realtek|Intel|Killer|Broadcom|Aquantia)'' } | ForEach-Object { "{0,-58} cfg={1} status={2}" -f $_.Name, $_.ConfigManagerErrorCode, $_.Status }' | Out-Null
Invoke-Pe 'F2 netdrvfix.log' 'type X:\netdrvfix.log' | Out-Null
Invoke-Pe 'F3 niccheck.cmd(镜像内自检工具)' 'X:\Windows\System32\niccheck.cmd' | Out-Null

L ''
L '=== G. 安全边界: 登录私钥绝不能进镜像 ==='
Invoke-Pe 'G1 私钥检查' 'if exist X:\SSH\ssh_login_key (echo PRIVATE_KEY_LEAK) else (echo NO_PRIVATE_KEY_IN_IMAGE_OK) & if exist X:\Windows\System32\ssh_login_key (echo PRIVATE_KEY_LEAK2) else (echo CLEAN2)' | Out-Null
Invoke-PePs 'G2 X 根与 SSH 目录清单' 'Get-ChildItem X:\ -Force -EA SilentlyContinue | ForEach-Object { $_.Mode + " " + $_.Name }; "--- X:\SSH ---"; Get-ChildItem X:\SSH -Force -EA SilentlyContinue | ForEach-Object { $_.Length.ToString() + " " + $_.Name }' | Out-Null
Invoke-PePs 'G3 内存盘容量与已用' 'Get-PSDrive -PSProvider FileSystem | ForEach-Object { "{0} used={1:N0} free={2:N0}" -f $_.Name, $_.Used, $_.Free }' | Out-Null

Remove-Item -LiteralPath $keyTmp -Force -EA SilentlyContinue
L ''
L '===== 复查结束 ====='
L ('结果文件 = ' + $Out)
