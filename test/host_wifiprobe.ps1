# 主机侧: 经隧道让 PE 下载并执行 test\share 里的某个脚本, 结果同时回显到本机
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_wifiprobe.ps1 [-Payload vm_wifiprobe.ps1]
param([string]$Payload = 'vm_wifiprobe.ps1')
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$tmp  = Join-Path $proj 'build\wifiprobe'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh = Join-Path $tmp 'kh'
$PSX = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$cmd = $PSX + ' -NoProfile -EP Bypass -C "iwr -UseB http://172.31.32.1:8000/file/' + $Payload + ' -OutFile X:\w1.ps1; ' + $PSX + ' -NoProfile -EP Bypass -File X:\w1.ps1"'

$a = @('-n','-i',$key,'-p','6000','-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=15','Administrator@127.0.0.1',$cmd)
$o = Join-Path $tmp 'probe.out'; $e = Join-Path $tmp 'probe.err'
Remove-Item $o,$e -Force -EA SilentlyContinue
$pi = Start-Process -FilePath 'C:\Windows\System32\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
if (-not $pi.WaitForExit(240000)) { try { $pi.Kill() } catch {}; Write-Host 'TIMEOUT 240s 已强杀' -ForegroundColor Yellow }
$txt = (Get-Content $o -Raw -EA SilentlyContinue) + "`r`n" + (Get-Content $e -Raw -EA SilentlyContinue)
Write-Host $txt
Set-Content -Path (Join-Path $root ('wifiprobe_' + ($Payload -replace '\.ps1$','') + '.txt')) -Value $txt -Encoding UTF8
Write-Host ('已存 test\wifiprobe_' + ($Payload -replace '\.ps1$','') + '.txt') -ForegroundColor Green
