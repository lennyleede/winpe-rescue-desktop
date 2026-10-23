# 主机侧: 补测 wifiaudit 里因 PE 的 cmd PATH 不含 powershell/findstr 而失败的项 (走隧道)
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_wifiaudit2.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$tmp  = Join-Path $proj 'build\wifiaudit2'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -EA SilentlyContinue

$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=15')
$PS = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

function Enc([string]$ps) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps)) }
function RunSsh($tag, $cmd, $waitSec) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $a = @('-n','-i',$key,'-p','6000') + $common + @('Administrator@127.0.0.1', $cmd)
  $pi = Start-Process -FilePath 'C:\Windows\System32\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; Write-Host ('[' + $tag + '] TIMEOUT ' + $waitSec + 's') -ForegroundColor Yellow }
  $txt = (Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue)
  Write-Host ('[' + $tag + '] ' + (($txt -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)))
  return $txt
}

# 1) 全盘找镜像里所有 wlan/wifi 相关文件 (PE 自带 vs 我们注入的, 看有没有 26100 版可用)
$ps_find = @'
$hits = Get-ChildItem ($env:SystemRoot + '\System32') -Recurse -Filter '*wlan*' -EA SilentlyContinue |
        ForEach-Object { $_.FullName + '  ' + $_.VersionInfo.FileVersion }
Write-Host '--- System32 递归 wlan*'
$hits | ForEach-Object { Write-Host $_ }
Write-Host '--- System32 递归 wifi*'
Get-ChildItem ($env:SystemRoot + '\System32') -Recurse -Filter '*wifi*' -EA SilentlyContinue |
  ForEach-Object { Write-Host ($_.FullName + '  ' + $_.VersionInfo.FileVersion) }
Write-Host '--- WinSxS FileMaps 里 wlan 相关组件包'
Get-ChildItem ($env:SystemRoot + '\WinSxS\FileMaps') -Filter '*wlan*' -EA SilentlyContinue | Select-Object -First 20 |
  ForEach-Object { Write-Host $_.Name }
Write-Host ('WinSxS 目录存在=' + (Test-Path ($env:SystemRoot + '\WinSxS')))
'@

# 2) 服务枚举换成 Win32_Service (ServiceController 需要额外程序集, PE 里没加载)
$ps_svc = @'
Add-Type -AssemblyName System.ServiceProcess -EA SilentlyContinue
Write-Host ('System.ServiceProcess 加载=' + ($?) )
foreach ($n in @('wlansvc','dot3svc','RpcSs','mpssvc','BFE','Dnscache')) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  if ($q) { Write-Host ($n.PadRight(10) + 'state=' + $q.State + ' startmode=' + $q.StartMode + ' path=' + $q.PathName) }
  else    { Write-Host ($n.PadRight(10) + 'SCM 里没有') }
}
Write-Host '--- 注册表里 wlansvc 键'
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc'
if (Test-Path $k) { Get-ItemProperty $k | Format-List Start, Type, ErrorControl, ImagePath, Group, ServiceSidType | Out-String -Width 200 }
else { Write-Host '  无' }
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\wlansvc\Parameters' -EA SilentlyContinue).ServiceDll
Write-Host '--- SVCHOST 组 PEWLan'
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue) | Out-Null
(Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST' -EA SilentlyContinue).GetValue('PEWLan', $null, 'DoNotExpandEnvironmentNames')
'@

# 3) 有线/USB 网卡这条保底路: 镜像里已有哪些 USB 网卡驱动 (已知 Class=Net 清单)
$ps_usb = @'
Write-Host '--- 已内置的 USB/有线网卡 INF (保底通道)'
foreach ($i in @('netrndis.inf','rndiscmp.inf','usbnet.inf','netax88179_178a.inf','rtux64w10.inf','netrtl8153','wnetvsc.inf','netvsc')) {
  $p = Join-Path ($env:SystemRoot + '\INF') $i
  if (Test-Path $p) { Write-Host ($i.PadRight(26) + 'YES') } else { Write-Host ($i.PadRight(26) + 'NO') }
}
Write-Host '--- RNDIS/远程网络服务是否在'
foreach ($n in @('RasMan','TapiSrv')) {
  $q = Get-CimInstance Win32_Service -Filter "Name='$n'" -EA SilentlyContinue
  Write-Host ($n.PadRight(9) + $(if ($q) { 'state=' + $q.State } else { 'SCM 里没有' }))
}
Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' | ForEach-Object { Write-Host ('NA: ' + $_.Name + ' mac=' + $_.MACAddress) }
'@

$cases = @(
  @{ t='5_find'; c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_find)); w=240 },
  @{ t='6_svc';  c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_svc));  w=150 },
  @{ t='7_usb';  c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_usb));  w=150 }
)
$out = [ordered]@{}
foreach ($c in $cases) { $out[$c.t] = RunSsh $c.t $c.c $c.w }
$sb = New-Object Text.StringBuilder
foreach ($k in $out.Keys) { [void]$sb.AppendLine('=== ' + $k); [void]$sb.AppendLine(($out[$k] -join "`r`n")) }
$rep = Join-Path $root 'wifiaudit3_result.txt'
Set-Content -Path $rep -Value $sb.ToString() -Encoding UTF8
Write-Host ('报告: ' + $rep) -ForegroundColor Green
