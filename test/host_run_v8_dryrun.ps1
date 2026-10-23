# 在宿主机上把 vm_wifi_v8.ps1 的 X: 换成 C: 跑一遍(只读 + 已经在运行的服务), 端到端验证脚本本身
# 会真的向 :8000/result POST, 所以能同时验证结果回传链路
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$src = Join-Path $Root 'share\vm_wifi_v8.ps1'
$tmp = Join-Path $env:TEMP 'vm_wifi_v8_host.ps1'
$t = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
$t = $t.Replace('X:\Windows\System32', "$env:SystemRoot\System32")
$t = $t.Replace("'X:\w2.exe'", "'" + (Join-Path $env:TEMP 'w2.exe') + "'")
[IO.File]::WriteAllText($tmp, $t, (New-Object Text.UTF8Encoding($true)))
Write-Host ('宿主版: ' + $tmp)
& powershell -NoProfile -ExecutionPolicy Bypass -File $tmp
