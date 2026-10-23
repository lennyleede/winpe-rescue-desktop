# 交付前自检: 让宿主机上的 pe-sshd 用 overlay\SSH\pe_host_ed25519 起一次, 证明
#   1) Go 端能解析这把 ssh-keygen 生成的密钥(不会退化成"每次开机重新生成")
#   2) 对外的指纹与 .pub 一致
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\hostkey_stability_check.ps1
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$exe = Join-Path $proj 'overlay\SSH\pe-sshd.exe'
$hk = Join-Path $proj 'overlay\SSH\pe_host_ed25519'
$pub = Join-Path $proj 'overlay\SSH\pe_host_ed25519.pub'
foreach ($f in @($exe, $hk, $pub)) { if (-not (Test-Path $f)) { throw ('缺少 ' + $f) } }
$tmp = Join-Path $proj 'build\hostkey_check'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
Remove-Item (Join-Path $tmp '*') -Force -ErrorAction SilentlyContinue
foreach ($p in @(Get-Process -Name 'pe-sshd' -ErrorAction SilentlyContinue)) { try { $p.Kill(); $p.WaitForExit(2000) | Out-Null } catch {} }

$want = (& C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f $pub)
Write-Host ('[1] .pub 期望指纹 : ' + ($want -replace '\s+', ' ').Trim())

$logf = Join-Path $tmp 'sshd.log'
$p = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -ArgumentList @(
  '-addr', '127.0.0.1:2223', '-hostkey', $hk,
  '-authkeys', (Join-Path $proj 'overlay\SSH\authorized_keys'),
  '-shell', 'C:\Windows\System32\cmd.exe', '-log', $logf)
Start-Sleep 2
Write-Host ('[2] 进程存活       : ' + (-not $p.HasExited))
$log = ''
if (Test-Path $logf) {
  # pe-sshd 一直开着这个日志句柄, ReadAllText 会撞"另一个程序正在使用此文件", 用 FileShare.ReadWrite 打开
  try {
    $fs = [IO.File]::Open($logf, 'Open', 'Read', 'ReadWrite')
    $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
    $log = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
  } catch { Write-Host ('  读日志失败: ' + $_.Exception.Message) }
}
Write-Host ('[3] 日志是否重新生成: ' + ($log -match '已生成主机密钥') + '  (False=用的是烘进去的那把)')
& C:\Windows\System32\OpenSSH\ssh-keyscan.exe -p 2223 -t ed25519 127.0.0.1 2>$null | Out-File (Join-Path $tmp 'scan.txt') -Encoding ascii
$line = @(Get-Content (Join-Path $tmp 'scan.txt') | Where-Object { $_ -and ($_ -notmatch '^#') })
$got = '(拿不到)'
if ($line.Count -gt 0) {
  [IO.File]::WriteAllBytes((Join-Path $tmp 'got.pub'), ([Text.Encoding]::ASCII.GetBytes(($line[0] -replace '^127\.0\.0\.1 ', '') + "`n")))
  $got = (& C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f (Join-Path $tmp 'got.pub'))
  $got = ($got -replace '\s+', ' ').Trim()
}
Write-Host ('[4] 服务端对外指纹 : ' + $got)
# ssh-keyscan 拿到的行没有注释字段, 两边整行比对会因为 comment 不同而假失败, 只比 SHA256 串
$fpWant = ([regex]::Match($want, 'SHA256:\S+')).Value
$fpGot = ([regex]::Match($got, 'SHA256:\S+')).Value
$regen = ($log -match '已生成主机密钥')
Write-Host ('[5] 判定           : ' + $(if ($fpGot -ne '' -and $fpGot -eq $fpWant -and -not $regen) { '一致且未重新生成 -> 这把密钥可作为固定主机密钥进镜像' } else { '不一致或仍在重新生成 -> 不能进镜像, 查上面差异 (want=' + $fpWant + ' got=' + $fpGot + ' regen=' + $regen + ')' }))
try { $p.Kill(); $p.WaitForExit(2000) | Out-Null } catch {}
Write-Host ('--- sshd.log ---')
Write-Host $log
