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

# 1) 镜像里 WiFi 客户端栈文件的真实情况 (存在 + 版本)
$ps_dll = @'
$dir = $env:SystemRoot + '\System32'
foreach ($f in @('wlanapi.dll','wlansvc.dll','wlancfg.dll','wlanutil.dll','wlanmsm.dll','wlanext.exe','dot3api.dll','dot3cfg.dll','dot3svc.dll','mswsock.dll','wdi.dll','wifi.dll','ndisimplatform.dll','bfe.dll','mpssvc.dll')) {
  $p = Join-Path $dir $f
  if (Test-Path $p) {
    $v = (Get-Item $p).VersionInfo.FileVersion
    Write-Host ($f.PadRight(22) + 'YES ' + $v)
  } else { Write-Host ($f.PadRight(22) + 'NO') }
}
foreach ($d in @('nwifi.sys','vwifibus.sys','vwififlt.sys','ndis.sys')) {
  $p = Join-Path ($dir + '\drivers') $d
  Write-Host ($d.PadRight(22) + $(if (Test-Path $p) { 'YES' } else { 'NO' }))
}
'@

# 2) INF 里有没有任何引用 nwifi/WLAN  miniport 的驱动包
$ps_inf = @'
$hits = Get-ChildItem ($env:SystemRoot + '\INF\*.inf') | ForEach-Object {
  $t = Get-Content $_.FullName -Raw -EA SilentlyContinue
  if ($t -and ($t -match 'nwifi' -or $t -match 'ms_wlan' -or $t -match 'IWL_wifi' -or $t -match 'Wireless')) { $_.Name }
}
Write-Host ('引用无线的 INF: ' + $(if ($hits) { $hits -join ', ' } else { '无' }))
$net = Get-ChildItem ($env:SystemRoot + '\INF\*.inf') | Where-Object { (Get-Content $_.FullName -Raw -EA SilentlyContinue) -match 'Class\s*=\s*Net' }
Write-Host ('Class=Net 的 INF 个数: ' + @($net).Count)
Write-Host ('NET INF: ' + (($net | ForEach-Object { $_.Name }) -join ', '))
'@

# 3) wlansvc 能否被 SCM 拉起 (svchost 组 PEWLan 是否有效)
$ps_svc = @'
foreach ($n in @('wlansvc','dot3svc','RpcSs','mpssvc','BFE')) {
  $s = New-Object System.ServiceProcess.ServiceController($n)
  Write-Host ($n.PadRight(10) + 'starttype=' + $s.StartType + ' status=' + $s.Status)
}
$w = New-Object System.ServiceProcess.ServiceController('wlansvc')
if ($w.Status -ne 'Running') {
  try { $w.Start(); Start-Sleep 5; $w.Refresh(); Write-Host ('wlansvc 尝试启动后: ' + $w.Status) }
  catch { Write-Host ('wlansvc 启动异常: ' + $_.Exception.Message) }
}
Get-Process svchost -EA SilentlyContinue | ForEach-Object { Write-Host ('svchost pid=' + $_.Id) }
'@

# 4) 网络栈能不能枚举适配器 (CIM/NetAdapter 在 PE 里的可用性)
$ps_net = @'
try { Get-NetAdapter | ForEach-Object { Write-Host ('Get-NetAdapter OK: ' + $_.Name + ' ' + $_.Status) } }
catch { Write-Host ('Get-NetAdapter 不可用: ' + $_.Exception.Message) }
Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' -EA SilentlyContinue | ForEach-Object { Write-Host ('Win32_NA: ' + $_.Name + ' guid=' + $_.GUID) }
'@

$cases = @(
  @{ t='1_dlls';   c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_dll)); w=120 },
  @{ t='2_inf';    c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_inf)); w=180 },
  @{ t='3_svc';    c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_svc)); w=120 },
  @{ t='4_net';    c=($PS + ' -NoProfile -EP Bypass -EncodedCommand ' + (Enc $ps_net)); w=120 }
)
$out = [ordered]@{}
foreach ($c in $cases) { $out[$c.t] = RunSsh $c.t $c.c $c.w }
$sb = New-Object Text.StringBuilder
foreach ($k in $out.Keys) { [void]$sb.AppendLine('=== ' + $k); [void]$sb.AppendLine(($out[$k] -join "`r`n")) }
$rep = Join-Path $root 'wifiaudit2_result.txt'
Set-Content -Path $rep -Value $sb.ToString() -Encoding UTF8
Write-Host ('报告: ' + $rep) -ForegroundColor Green
