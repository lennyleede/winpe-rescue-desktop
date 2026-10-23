# 主机侧: 经 frps 的 6000 隧道在 PE 里做只读体检, 回答"镜像里到底有没有无线网卡驱动 / WiFi 客户端组件"
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_wifiaudit.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$tmp  = Join-Path $proj 'build\wifiaudit'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -EA SilentlyContinue

$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=15')

# PE 侧 PowerShell 负载统一走 -EncodedCommand, 免得 cmd/ssh/PS 三层引号互相咬
function Enc([string]$ps) {
  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
}
function RunSsh($tag, $cmd, $waitSec) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $a = @('-n','-i',$key,'-p','6000') + $common + @('Administrator@127.0.0.1', $cmd)
  $pi = Start-Process -FilePath 'C:\Windows\System32\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; Write-Host ('[' + $tag + '] TIMEOUT ' + $waitSec + 's 已强杀') -ForegroundColor Yellow }
  $txt = (Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue)
  $first = (($txt -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
  Write-Host ('[' + $tag + '] ' + $first)
  return $txt
}

$ps_drv = @'
Get-WindowsDriver -Online | Where-Object { $_.Class -eq 'Net' -or $_.Class -eq 'System' } | ForEach-Object { $_.InfFileName + ' | ' + $_.Class + ' | ' + $_.Description + ' | ' + $_.DriverVersion }
'@

$ps_dll = @'
foreach ($f in @('wlanapi.dll','wlansvc.dll','wlancfg.dll','wlanmsm.dll','wlanext.exe','wlanhook.dll','mswsock.dll','dot3api.dll','dot3cfg.dll','wdi.dll','wifi.dll','ndisapi.dll')) {
  $p = Join-Path ($env:SystemRoot + '\System32') $f
  Write-Host ($f.PadRight(16) + (Test-Path $p))
}
Write-Host ('nwifi.sys   ' + (Test-Path ($env:SystemRoot + '\System32\drivers\nwifi.sys')))
Write-Host ('vwifibus.sys' + (Test-Path ($env:SystemRoot + '\System32\drivers\vwifibus.sys')))
'@

$ps_svc = @'
foreach ($n in @('wlansvc','dot3svc','RpcSs','nsiproxy')) {
  $s = New-Object System.ServiceProcess.ServiceController($n)
  Write-Host ($n.PadRight(12) + 'exists=' + ($s.ServiceName -eq $n) + ' starttype=' + $s.StartType + ' status=' + $s.Status)
  if ($n -eq 'wlansvc' -and $s.Status -ne 'Running') {
    try { $s.Start(); Start-Sleep 4; $s.Refresh(); Write-Host ('  尝试启动后 status=' + $s.Status) }
    catch { Write-Host ('  启动失败: ' + $_.Exception.Message) }
  }
}
'@

$ps_net = @'
Write-Host ('PSVersion=' + $PSVersionTable.PSVersion.ToString())
Get-NetAdapter -EA SilentlyContinue | ForEach-Object { Write-Host ('Get-NetAdapter: ' + $_.Name + ' ' + $_.Status + ' ' + $_.InterfaceGuid) }
Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' | ForEach-Object { Write-Host ('Win32_NA: ' + $_.Name + ' | GUID=' + $_.GUID + ' | MAC=' + $_.MACAddress + ' | ' + $_.NetConnectionID) }
$w = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_NetworkAdapterConfiguration -EA SilentlyContinue
Write-Host ('NAConfig 行数=' + (@($w).Count))
'@

$cases = @(
  @{ t='01_ver';       c='ver & cd'; w=45 },
  @{ t='02_wlanfiles'; c='cmd /c dir /b X:\Windows\System32\wlan*.* & cmd /c dir /b X:\Windows\System32\drivers\nwifi.sys'; w=45 },
  @{ t='03_inflist';   c='dir /b X:\Windows\INF\*.inf'; w=60 },
  @{ t='04_infnwifi';  c='findstr /i /m nwifi X:\Windows\INF\*.inf'; w=90 },
  @{ t='05_dismdrv';   c=('powershell -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_drv)); w=180 },
  @{ t='06_dlls';      c=('powershell -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_dll)); w=90 },
  @{ t='07_svc';       c=('powershell -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_svc)); w=120 },
  @{ t='08_net';       c=('powershell -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_net)); w=90 },
  @{ t='09_bootlog';   c='more +0 X:\boot.log'; w=45 }
)

$out = [ordered]@{}
foreach ($c in $cases) { $out[$c.t] = RunSsh $c.t $c.c $c.w }

$sb = New-Object Text.StringBuilder
foreach ($k in $out.Keys) {
  [void]$sb.AppendLine('=== ' + $k)
  [void]$sb.AppendLine(($out[$k] -join "`r`n"))
  [void]$sb.AppendLine('')
}
$rep = Join-Path $root 'wifiaudit_result.txt'
Set-Content -Path $rep -Value $sb.ToString() -Encoding UTF8
Write-Host ('报告: ' + $rep) -ForegroundColor Green
