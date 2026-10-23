# 本机先跑一遍 pe-sshd: 编译产物先在宿主机 127.0.0.1 上验证协议栈, 再进 PE
# 用 2222 端口, 不碰宿主机自己的 OpenSSH
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Split-Path -Parent $root
$exe  = Join-Path $proj 'overlay\SSH\pe-sshd.exe'
if (-not (Test-Path $exe)) { throw "先跑 sshserver\build.ps1 生成 $exe" }
$tmp  = Join-Path $proj 'build\sshtest'
foreach ($old in @(Get-Process -Name 'pe-sshd' -ErrorAction SilentlyContinue)) { $old.Kill(); $old.WaitForExit(3000) | Out-Null }
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -ErrorAction SilentlyContinue

$logf = Join-Path $tmp 'sshd.log'
$p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
  '-addr', '127.0.0.1:2222',
  '-hostkey', (Join-Path $tmp 'host_ed25519'),
  '-authkeys', (Join-Path $proj 'test\share\authorized_keys'),
  '-shell', 'C:\Windows\System32\cmd.exe',
  '-log', $logf
)
Start-Sleep 3
Write-Host ('进程: pid=' + $p.Id + ' 存活=' + (-not $p.HasExited))
Write-Host ('监听: ' + ((& netstat.exe -an | Select-String ':2222\s' | Out-String).Trim()))
Write-Host '--- 用私钥登录并执行命令 ---'
$ErrorActionPreference = 'Continue'   # ssh 的 stderr 提示不是错误, 别让 Stop 把脚本打断
# 宿主机上的私钥文件 ACL 太宽, OpenSSH 客户端会拒绝使用, 拷一份到临时目录收紧
$key = Join-Path $tmp 'login_key'
Copy-Item (Join-Path $proj 'overlay\Scripts\ssh_login_key') $key -Force
& icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
$kh  = Join-Path $tmp 'kh'
$sshExe = 'C:\Windows\System32\OpenSSH\ssh.exe'
function RunSsh($tag, $a, $inFile) {
  $o = Join-Path $tmp ($tag + '.out'); $e = Join-Path $tmp ($tag + '.err')
  $sp = @{ FilePath = $sshExe; ArgumentList = $a; NoNewWindow = $true; PassThru = $true;
           RedirectStandardOutput = $o; RedirectStandardError = $e }
  if ($inFile) { $sp['RedirectStandardInput'] = $inFile }
  $pi = Start-Process @sp
  if (-not $pi.WaitForExit(25000)) { try { $pi.Kill() } catch {}; return "TIMEOUT(25s) 已强杀" }
  # 不加 -Encoding: ssh/cmd 的输出按本机代码页(936)读才不会把中文打乱
  return ((Get-Content $o -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content $e -Raw -ErrorAction SilentlyContinue))
}

$kh = Join-Path $tmp 'kh'
$common = @('-o','StrictHostKeyChecking=no',"-oUserKnownHostsFile=$kh",'-o','ConnectTimeout=10','-o','BatchMode=yes')
$report = New-Object System.Collections.Generic.List[string]
$report.Add('process=pid ' + $p.Id + ' alive=' + (-not $p.HasExited))
$report.Add('listen=' + ((& netstat.exe -an | Select-String ':2222\s' | Out-String).Trim()))

Write-Host '--- 私钥登录并执行命令 ---'
$out = RunSsh 'key' (@('-n','-p','2222','-i',$key) + $common + @('tester@127.0.0.1','echo LOCAL_SSH_OK && whoami'))
Write-Host $out

Write-Host '--- 空密码/无凭证登录(救援盘默认; 客户端首发的 none 请求即被接受) ---'
$anon = RunSsh 'anon' (@('-n','-p','2222','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo EMPTY_PW_OK && whoami'))
Write-Host $anon

Write-Host '--- 交互式 shell(救援时就是 ssh IP 不带命令,  stdin 喂几行再 exit) ---'
$inFile = Join-Path $tmp 'shell_in'
Set-Content -Path $inFile -Value "echo INTERACTIVE_OK`r`nwhoami`r`ncd`r`nexit`r`n" -Encoding ASCII -NoNewline
$shell = RunSsh 'shell' (@('-p','2222','-i',$key) + $common + @('tester@127.0.0.1')) $inFile
Write-Host $shell

Write-Host '--- 锁起来(-empty=false -pass 口令): 无凭证必须被拒, 公钥仍可用 ---'
$p2 = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
  '-addr','127.0.0.1:2223','-hostkey',(Join-Path $tmp 'host_ed25519_2'),
  '-authkeys',(Join-Path $proj 'test\share\authorized_keys'),
  '-empty=false','-pass','test123','-shell','C:\Windows\System32\cmd.exe',
  '-log',(Join-Path $tmp 'sshd_locked.log'))
Start-Sleep 3
$bad = RunSsh 'locked_anon' (@('-n','-p','2223','-o','IdentityAgent=none','-o','IdentitiesOnly=yes') + $common + @('rescue@127.0.0.1','echo SHOULD_NOT_HAPPEN'))
Write-Host $bad
$bykey = RunSsh 'locked_key' (@('-n','-p','2223','-i',$key) + $common + @('tester@127.0.0.1','echo KEY_STILL_WORKS'))
Write-Host $bykey

Write-Host '--- 服务端日志 ---'
Get-Content $logf -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -Last 15
Stop-Process -Id $p.Id,$p2.Id -Force -ErrorAction SilentlyContinue

$verdict = ('私钥登录 ' + $(if ($out -match 'LOCAL_SSH_OK') { '通过' } else { '失败' }) +
            ' / 空密码登录 ' + $(if ($anon -match 'EMPTY_PW_OK') { '通过' } else { '失败' }) +
            ' / 交互shell ' + $(if ($shell -match 'INTERACTIVE_OK') { '通过' } else { '失败' }) +
            ' / 锁定后无凭证 ' + $(if ($bad -match 'SHOULD_NOT_HAPPEN') { '被放行(有问题!)' } else { '已拒绝' }) +
            ' / 锁定后公钥 ' + $(if ($bykey -match 'KEY_STILL_WORKS') { '仍可用' } else { '失败' }))
Write-Host ('判定: ' + $verdict)
$report.Add('key_login_output=' + ($out -replace '\s+', ' '))
$report.Add('empty_pw_output=' + ($anon -replace '\s+', ' '))
$report.Add('interactive_shell_output=' + ($shell -replace '\s+', ' '))
$report.Add('locked_noauth_output=' + ($bad -replace '\s+', ' '))
$report.Add('locked_key_output=' + ($bykey -replace '\s+', ' '))
$report.Add('server_log=' + (((Get-Content $logf -Encoding UTF8 -ErrorAction SilentlyContinue) | Select-Object -Last 20) -join ' || '))
$report.Add('verdict=' + $verdict)
Set-Content -Path (Join-Path $root 'smoke_result.txt') -Value ($report -join "`r`n") -Encoding UTF8

