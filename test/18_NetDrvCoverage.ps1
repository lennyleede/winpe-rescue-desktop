# ============================================================
# 18_NetDrvCoverage.ps1 —— 段感知(section-aware)的网卡驱动覆盖率度量器
#
# 为什么需要它(2026-10-08 VMware 实测定罪):
#   17_ 用正则扫 INF 全文收集 PCI\VEN_x&DEV_y, 不看 [Manufacturer] 的 target-OS 装饰,
#   于是把"只写在低档段里的 ID"也算成可用命中。例: e1q63x64.inf 的装饰是
#   `Intel, NTamd64.6.2, NTamd64.6.2.1, NTamd64.6.3`, 在 10.0 的 PE 上安装器只读
#   [Intel.NTamd64.6.3] —— 而那一节是空的, DEV_10D3 只存在于低档 [Intel.NTamd64.6.2]。
#   结果: drvload rc=0 "Successfully loaded", 设备仍然 code18, 物理网卡 0 块。
#   所以"索引里有多少 ID"这个指标是虚高的, 必须按"当前 PE 真正会读哪一节"来算。
#
# 解析器本体在 test\NetDrvLib.ps1(18_/19_ 共用), 本脚本只负责出报告。
#
# 普通权限运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\18_NetDrvCoverage.ps1
#   ... -SelfTest        只跑内置断言, 不写任何文件
#   ... -WriteIndex      把段感知索引写到 build\netdrv_index_sectionaware.txt (默认不写!)
#   ... -OutReport <p>   换报告输出路径
#   ... -DrvDir <p>      量别的驱动池, 例如 D:\winpe_build\hotpe_net\Lan
# ============================================================
param(
  [string]$DrvDir   = '',
  [string]$OutReport = '',
  [string]$OutIndex  = '',
  [string]$Arch     = 'NTamd64',
  [string]$OsVer    = '10.0',
  [int]$Build       = 26100,
  [int]$ProductType = 1,        # 1=VER_NT_WORKSTATION(客户端/PE 按客户端算), 3=Server
  [switch]$SelfTest,
  [switch]$WriteIndex
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $DrvDir)    { $DrvDir     = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $OutReport) { $OutReport  = Join-Path $Root 'build\netdrv_coverage.txt' }
if (-not $OutIndex)  { $OutIndex   = Join-Path $Root 'build\netdrv_index_sectionaware.txt' }
if (-not (Test-Path $DrvDir)) { Write-Host "驱动目录不存在: $DrvDir" -ForegroundColor Red; exit 1 }

. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')
# 不过滤 Class: overlay 池本来就是 15_ 挑过的 Net 集, 保持与旧版 18_ 完全同一口径
$pool = Get-NetDrvPool -DrvDir $DrvDir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName @()
$rows   = @($pool.Rows)
$idxMap = $pool.Idx

# ---------- 报告 ----------
$dead    = @($rows | Where-Object { $_.Dead })
$partial = @($rows | Where-Object { -not $_.Dead -and $_.Shadow -gt 0 })
$idxLines = @()
foreach ($k in ($idxMap.Keys | Sort-Object)) { foreach ($p in ($idxMap[$k].Keys | Sort-Object)) { $idxLines += ($k + "`t" + $p) } }

$rep = @()
$rep += '==== WinPE 网卡驱动覆盖率(段感知) ===='
$rep += ('生成时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$rep += ('驱动目录 : ' + $DrvDir)
$rep += ('目标系统 : ' + $Arch + ' / ' + $OsVer + '.' + $Build + '  ProductType=' + $ProductType)
$rep += ('扫描 INF : ' + $rows.Count + ' 个')
$rep += ('可绑 PCI 网卡ID : ' + $idxMap.Count + ' 种 / 索引行 ' + $idxLines.Count + ' 条')
$rep += ('可绑 USB 网卡ID : ' + (@($rows | ForEach-Object { $_.Ids } | Where-Object { $_ -match '^USB\\VID_' } | Sort-Object -Unique)).Count + ' 个 (netdrvfix 目前只处理 PCI)')
$rep += ('本 PE 上绑不了任何设备的包(死包) : ' + $dead.Count + ' 个')
$rep += ('有可绑 ID 但仍有一批 ID 只存在于低档段的包 : ' + $partial.Count + ' 个')
$rep += ''
$rep += '---- 死包(装进库也不会绑任何设备, 需要换更新版本) ----'
if (-not $dead) { $rep += '  (无)' }
foreach ($r in $dead) { $rep += ('  {0,-18} Class={1,-10} DriverVer={2,-22} 生效段={3}' -f $r.Pkg, $r.Cls, $r.DriverVer, $r.Sec) }
$rep += ''
$rep += '---- 部分够不到(生效段有 ID, 但另有 ID 只在低档段) ----'
if (-not $partial) { $rep += '  (无)' }
foreach ($r in $partial) {
  $rep += ('  {0,-18} 可绑 {1} 个 / 够不到 {2} 个  [{3}]' -f $r.Pkg, $r.N, $r.Shadow, ($r.ShadowIds -join ' '))
}
$rep += ''
$rep += '---- 每个包生效段一览 ----'
foreach ($r in ($rows | Sort-Object Pkg)) {
  $rep += ('  {0,-18} PCI={1,-4} USB={2,-4} 够不到={3,-4} {4}' -f $r.Pkg, $r.N, $r.NU, $r.Shadow, $r.Sec)
}

if ($SelfTest) {
  Write-Host '==== 18_ 内置断言 ====' -ForegroundColor Cyan
  $fail = 0
  function Assert-Has([string]$id, [bool]$expect, [string]$why) {
    $k = Get-BaseId $id
    $got = $idxMap.ContainsKey($k)
    $mark = if ($got -eq $expect) { 'OK  ' } else { 'FAIL' }
    if ($got -ne $expect) { $script:fail++ }
    Write-Host ("  [{0}] {1} 期望可绑={2} 实际={3}  ({4})" -f $mark, $k, $expect, $got, $why)
  }
  # 断言基线随驱动库演进: 2026-10-08 20_/35_ 之后, VMware 两条路(e1000e/vmxnet3)都该是可绑状态。
  # 如果哪天有人把包删了/换了旧版本, 这几条会把问题当场拦下来。
  Assert-Has 'PCI\VEN_10EC&DEV_8136' $true  '实机已验证 rt640x64 能绑'
  Assert-Has 'PCI\VEN_8086&DEV_10D3' $true  'VMware e1000e: 导入宿主机 net1ic64(2018, 段 [Intel.NTamd64.10.0.1]) 后应可绑'
  Assert-Has 'PCI\VEN_15AD&DEV_07B0' $true  'VMware vmxnet3: 15_/20_ 从 Lan\VmWare 收进包里后应可绑(原先被 serverPrefixes 黑名单漏掉)'
  Assert-Has 'PCI\VEN_10EC&DEV_8125' $true  'RTL8125 2.5G (2019+ 主流)'
  Assert-Has 'PCI\VEN_8086&DEV_15B8' $true  'I219-V (近10年笔记本最常见)'
  Assert-Has 'PCI\VEN_8086&DEV_15F3' $true  'I226-V'
  if ($idxMap.Count -lt 600) { $fail++; Write-Host ('  [FAIL] 可绑 ID ' + $idxMap.Count + ' < 600(驱动库被砍回了精简集?)') -ForegroundColor Red }
  else { Write-Host ('  [OK  ] 可绑 ID ' + $idxMap.Count + ' >= 600(导入+去重后的量级)') }
  Write-Host ('  死包 ' + $dead.Count + ' 个 / 可绑 ID ' + $idxMap.Count + ' 种')
  if ($fail) { Write-Host "  !! 断言失败 $fail 条" -ForegroundColor Red; exit 1 }
  Write-Host '  全部断言通过' -ForegroundColor Green
  exit 0
}

$rep | ForEach-Object { Write-Host $_ }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutReport) | Out-Null
Set-Content -LiteralPath $OutReport -Value $rep -Encoding UTF8
Write-Host ('报告已写: ' + $OutReport) -ForegroundColor Green
if ($WriteIndex) {
  Set-Content -LiteralPath $OutIndex -Value $idxLines -Encoding ASCII
  Write-Host ('段感知索引已写: ' + $OutIndex + ' (' + $idxLines.Count + ' 行)') -ForegroundColor Green
} else {
  Write-Host ('(未写索引; 确认报告没问题后加 -WriteIndex, 输出到 ' + $OutIndex + ')') -ForegroundColor Yellow
}
