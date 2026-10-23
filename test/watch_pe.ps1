# 盯一会儿: PE 什么时候回到网络上, 顺便报出它的新 IP(不用人守着 ping)
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\watch_pe.ps1
#   改轮数/间隔: -Rounds 30 -IntervalSec 15
param(
  [string]$SubnetList = '192.168.0,172.31.38',
  [string]$Exclude = '192.168.0.107',
  [int]$Rounds = 20,
  [int]$IntervalSec = 20
)
$ErrorActionPreference = 'Stop'
$proj = Split-Path -Parent $PSScriptRoot
$scan = Join-Path $PSScriptRoot 'find_pe.ps1'
$out  = Join-Path $proj 'build\pe_watch.txt'
Write-Host "每 $IntervalSec 秒扫一轮, 共 $Rounds 轮; 排除 [$Exclude]; 结果追加到 $out"
for ($i = 1; $i -le $Rounds; $i++) {
  $r = & $scan -SubnetList $SubnetList -Exclude $Exclude -Concurrency 128 -BannerMs 1200 2>&1 |
        Where-Object { $_ -match 'OPEN|没扫到' }
  $line = (Get-Date -Format 'HH:mm:ss') + '  ' + (($r | Out-String).Trim() -replace '\s+', ' ')
  Write-Host ("[$i/$Rounds] " + $line)
  Add-Content -Path $out -Value $line -Encoding UTF8
  # 只有真拿到 SSH banner 才算 PE 回来了; 端口开着但没 banner 的野设备不算
  if ($line -match 'SSH-2\.0') { Write-Host '发现 SSH 服务端, 停止观察' -ForegroundColor Green; break }
  if ($i -lt $Rounds) { Start-Sleep $IntervalSec }
}
