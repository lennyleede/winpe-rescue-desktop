# 主机侧: 经 frps 的 6000 端口打进 PE 里的 pe-sshd(PE 侧 frpc 已把它的 22 映射过来)
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\host_via_tunnel.ps1
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$tmp  = Join-Path $proj 'build\tunnel_host'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -EA SilentlyContinue

Write-Host ('6000 监听: ' + ((& netstat.exe -an | Select-String ':6000\s.*LISTENING' | Out-String).Trim()))
$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=15','-o','BatchMode=yes')
function RunSsh($tag, $a, $waitSec) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $pi = Start-Process -FilePath 'C:\Windows\System32\OpenSSH\ssh.exe' -ArgumentList $a -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
  if (-not $pi.WaitForExit($waitSec * 1000)) { try { $pi.Kill() } catch {}; return 'TIMEOUT ' + $waitSec + 's 已强杀' }
  return ((Get-Content $o -Raw -EA SilentlyContinue) + "`n" + (Get-Content $e -Raw -EA SilentlyContinue))
}
Write-Host '--- 隧道公钥登录, 在 PE 里执行命令 ---'
$k = RunSsh 'h_key' (@('-n','-p','6000') + $common + @('Administrator@127.0.0.1','echo TUNNEL_TO_PE_OK && cd && ver')) 40
Write-Host $k
Write-Host '--- 隧道空密码/无凭证登录 ---'
$n = RunSsh 'h_anon' (@('-n','-p','6000','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo TUNNEL_TO_PE_ANON_OK && cd')) 40
Write-Host $n
Write-Host '--- 隧道里开交互 shell(喂 ipconfig 再 exit) ---'
$inFile = Join-Path $tmp 'in'
Set-Content -Path $inFile -Value "ipconfig`r`nexit`r`n" -Encoding ASCII -NoNewline
$s = RunSsh 'h_shell' (@('-p','6000') + $common + @('Administrator@127.0.0.1')) $inFile 40
Write-Host $s

$v1 = if ($k -match 'TUNNEL_TO_PE_OK') { '经隧道公钥登录 PE 通过' } else { '经隧道公钥登录 PE 失败' }
$v2 = if ($n -match 'TUNNEL_TO_PE_ANON_OK') { '经隧道空密码登录 PE 通过' } else { '经隧道空密码登录 PE 失败' }
$v3 = if ($s -match '172\.31\.') { '隧道交互 shell 里看到 PE 的 IP' } else { '隧道交互 shell 未取到 ipconfig' }
$verdict = $v1 + ' / ' + $v2 + ' / ' + $v3
Write-Host ('判定: ' + $verdict)
Set-Content -Path (Join-Path $root 'tunnel_to_pe_result.txt') -Value (
  'key=' + ($k -replace '\s+',' ') + "`r`n" + 'anon=' + ($n -replace '\s+',' ') + "`r`n" +
  'shell=' + ($s -replace '\s+',' ') + "`r`n" + 'verdict=' + $verdict) -Encoding UTF8
