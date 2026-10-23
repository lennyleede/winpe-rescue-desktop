# ============================================================
# 29_DedupeNetDrv.ps1 —— 给 overlay\Drivers\Net 里"同一个 INF 文件名有多份"的包去重
#
# 为什么会有一堆重名(2026-10-08 20_ -Apply 的副作用):
#   Copy-Item 是把厂商发布目录整份拷进来的(保 15_/20_ 的"包不能拆"原则), 而 Intel PROSet 这类
#   驱动包会同时发 W11 / WS2022 / WS2025 / NDIS64 / NDIS65 好几份"同名不同内容"的 INF。
#   实测: 208 个 INF 只有 143 个不同文件名, 54 个名字重复(最多 3 份)。
#   危害: ①DISM /Add-Driver 会把它们当不同包全塞进 DriverStore(PnP 只挑一个, 其余纯占体积)
#         ②16_ 的 DISM 时间变长 ③18_/17_ 的"死包"统计被老版本污染(死包 14 -> 19)
#
# 本脚本做的事(默认只出计划, 不动盘):
#   1) 用 NetDrvLib 段感知口径扫 overlay, 按文件名分组
#   2) 组内排序: 可绑 ID 多 > DriverVer 新 > 体积小 > 目录名不像服务器/Universal 变体
#   3) 贪心保留: 第一份必留; 后面的只有当它还能提供"当前留着的那份提供不了的可绑 ID"时才留
#      => 保证去重前后"可绑基址 ID 总数"一个都不掉(脚本末尾硬校验)
#   4) -Apply 才把该丢的包目录移到 overlay\Drivers\Net_dropped(可 -Undo 原样移回)
#
# 普通权限运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\29_DedupeNetDrv.ps1            # 只看计划
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\29_DedupeNetDrv.ps1 -SelfTest   # 内置断言, 不写盘
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\29_DedupeNetDrv.ps1 -Apply      # 真去重
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\29_DedupeNetDrv.ps1 -Undo       # 回滚
# ============================================================
param(
  [string]$DrvDir = '',
  [string]$Out    = '',
  [switch]$Apply,
  [switch]$Undo,
  [switch]$SelfTest,
  [string]$Arch = 'NTamd64',
  [string]$OsVer = '10.0',
  [int]$Build = 26100,
  [int]$ProductType = 1
)
$ErrorActionPreference = 'Stop'
$Root  = Split-Path -Parent $PSScriptRoot
if (-not $DrvDir) { $DrvDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $Out)    { $Out    = Join-Path $Root 'build\dedupe_netdrv.txt' }
$Stash = Join-Path $Root 'overlay\Drivers\Net_dropped'
. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')

function Get-StashName([string]$dir, [hashtable]$used) {
  # 移动单位可能重名(比如好几个 Universal/ 子目录), 加序号保证 Net_dropped 里不撞车
  $leaf = (Split-Path -Leaf $dir) -replace '[^\w.\-]', '_'
  $name = $leaf; $i = 1
  while ($used.ContainsKey($name)) { $i++; $name = ($leaf + '_' + $i) }
  $used[$name] = 1
  return $name
}
function Get-TopLeaf([string]$dir) {
  # 该包目录相对 DrvDir 的第一段, 报告里用它看"来自哪个导入目录"
  $rel = $dir.Substring($script:DrvDir.Length).TrimStart('\', '/')
  return (($rel -split '[\\/]')[0])
}
function Get-PtHint($row) {
  # 从生效段名里读 ProductType 限定: NTamd64.10.0.1 -> 1(工作站), .3 -> 服务器; 没写 -> -1(通用)
  $pts = @()
  foreach ($s in $row.Secs) {
    $i = $s.IndexOf('.')
    if ($i -lt 0) { continue }
    $parts = $s.Substring($i + 1) -split '\.'
    if ($parts.Count -ge 4) {
      $v = 0; if ([int]::TryParse($parts[3], [ref]$v)) { $pts += $v }
    }
  }
  if ($pts.Count -eq 0) { return -1 }
  if ($pts -contains $ProductType) { return $ProductType }
  return ($pts | Sort-Object)[0]
}
function Get-NamePenalty([string]$d) {
  # 同名多份时, 目录名带服务器/变体字样的当"次选"处理(只在同分时候打破平局, 不看内容就不用它)
  $n = 0
  foreach ($kw in @('WS20', 'Server', 'Ws20', 'Universal', 'Win8', 'Win7', 'Legacy')) { if ($d -match $kw) { $n++ } }
  return $n
}

$Manifest = Join-Path $Root 'build\dedupe_manifest.txt'

# ---------- 回滚(按 manifest 逐条挪回原目录) ----------
if ($Undo) {
  if (-not (Test-Path $Manifest)) { Write-Host '  没有 build\dedupe_manifest.txt, 说明没执行过 -Apply, 不需要回滚'; exit 0 }
  $n = 0; $miss = 0
  foreach ($line in @(Get-Content $Manifest -Encoding UTF8 | Where-Object { $_ })) {
    $c = $line -split "`t"
    if ($c.Count -lt 3) { continue }
    $stash = Join-Path $Stash $c[0]        # Net_dropped 里的名字(目录或 .lost 文件)
    $orig  = $c[1]                        # 原来的完整路径
    $kind  = $c[2]                        # dir / inf
    if (-not (Test-Path $stash)) { $miss++; continue }
    if (Test-Path $orig) { Write-Host ('  !! 原位置已被占用, 跳过 ' + $orig) -ForegroundColor Yellow; $miss++; continue }
    if ($kind -eq 'dir') {
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $orig) | Out-Null
      Move-Item -LiteralPath $stash -Destination $orig -Force
    } else {
      Move-Item -LiteralPath $stash -Destination $orig -Force
    }
    $n++
  }
  if (@(Get-ChildItem $Stash -Recurse -EA SilentlyContinue).Count -eq 0) { Remove-Item $Stash -Recurse -Force -EA SilentlyContinue }
  Write-Host ('  已回滚 ' + $n + ' 项' + $(if ($miss) { ' / 有 ' + $miss + ' 项没找到或位置被占' } else { '' }) + ', manifest 保留在 ' + $Manifest) -ForegroundColor Green
  exit 0
}

if (-not (Test-Path $DrvDir)) { Write-Host "驱动目录不存在: $DrvDir" -ForegroundColor Red; exit 1 }
Write-Host ('  扫描(段感知, 需要 1-2 分钟): ' + $DrvDir) -ForegroundColor Cyan
$pool = Get-NetDrvPool -DrvDir $DrvDir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName @()
$rows = @($pool.Rows)

# ---------- 分组 + 排序 ----------
$groups = @($rows | Group-Object PkgLower | Where-Object { $_.Count -gt 1 } | Sort-Object Name)
$keepIds = @{}          # 当前保留集合已经覆盖的可绑基址 ID
function Add-Ids($r, [hashtable]$into) { foreach ($id in $r.PciIds) { $k = Get-BaseId $id; if ($k -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$') { $into[$k] = 1 } } }

$drop = @()
$keptDup = @()
$dropReason = @{}
foreach ($g in $groups) {
  $scored = @()
  foreach ($r in $g.Group) {
    $pt = Get-PtHint $r
    $ptGood = if ($pt -eq $ProductType -or $pt -eq -1) { 1 } else { 0 }
    $scored += [pscustomobject]@{
      Row = $r
      # 分数高者先留: 可绑ID数(权重最高) > DriverVer 新 > 能匹配客户端 PT > 体积小 > 目录名干净
      # 每段都零填充成定宽, 否则字符串排序会在位数不同的时候排错(比如 8 vs 79)
      Key = ('{0:d6}|{1:d20}|{2}|{3:d8}|{4:d3}' -f $r.N, $r.VerDate.Ticks, $ptGood, ([int]($r.MB * 100)), (99 - (Get-NamePenalty $r.Dir)))
    }
  }
  $ordered = @($scored | Sort-Object -Property Key -Descending)
  $first = $true
  foreach ($o in $ordered) {
    $r = $o.Row
    if ($first) { Add-Ids $r $keepIds; $keptDup += $r; $first = $false; continue }
    $extra = @($r.PciIds | ForEach-Object { Get-BaseId $_ } | Where-Object { $_ -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$' -and -not $keepIds.ContainsKey($_) })
    if ($extra.Count -gt 0) { Add-Ids $r $keepIds; $keptDup += $r }
    else { $drop += $r; $dropReason[$r.InfPath] = ('同名 ' + $g.Count + ' 份中较弱的一份, 它的 ' + $r.N + ' 个可绑 ID 全被留下的那份盖住') }
  }
}

# 组内"全是不管有线 USB 都绑不到的死包"时, 连第一份也一起丢(丢了也不掉覆盖率)
$deadKept = @($keptDup | Where-Object { $_.N -eq 0 -and $_.NU -eq 0 })
foreach ($r in $deadKept) {
  $drop += $r
  $dropReason[$r.InfPath] = '同名组里每一份在本 PE 上都绑不到任何设备(死包), 一起丢'
}
$keptDup = @($keptDup | Where-Object { $_.N -gt 0 -or $_.NU -gt 0 })

# ---------- 计算移动单位(整目录 vs 只挪 INF) ----------
$moves = @()
$byDir = @{}
foreach ($r in $drop) {
  $d = $r.Dir
  if (-not $byDir.ContainsKey($d)) { $byDir[$d] = @() }
  $byDir[$d] += $r
}
$dropPaths = @{}
foreach ($r in $drop) { $dropPaths[$r.InfPath] = 1 }
foreach ($d in $byDir.Keys) {
  $all = @($rows | Where-Object { $_.Dir -eq $d })
  $dropHere = $byDir[$d]
  $moves += [pscustomobject]@{
    Dir     = $d
    Whole   = ($all.Count -eq $dropHere.Count)
    TopLeaf = (Get-TopLeaf $d)
    Infs    = ($dropHere | ForEach-Object { $_.Pkg }) -join ','
    MB      = [math]::Round(($dropHere | Measure-Object -Property MB -Sum).Sum, 2)
  }
}

# ---------- 校验: 保留集合的可绑 ID 必须等于去重前 ----------
$keepIds2 = @{}
foreach ($r in $rows) { if (-not $dropPaths.ContainsKey($r.InfPath)) { Add-Ids $r $keepIds2 } }

# ---------- 报告 ----------
$beforeIds = $pool.Idx.Count
$afterIds  = $keepIds2.Count
$sizeMB = [math]::Round(($rows | Measure-Object -Property MB -Sum).Sum, 1)
$rep = @()
$rep += '==== overlay\Drivers\Net 同名驱动包去重计划 ===='
$rep += ('生成时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + $(if ($Apply) { '   [已执行 -Apply]' } else { '   [仅计划, 未动盘]' }))
$rep += ('扫描     : ' + $rows.Count + ' 个 INF / ' + (@($rows | ForEach-Object { $_.PkgLower } | Sort-Object -Unique)).Count + ' 个不同文件名 / ' + ('{0:N1} MB(按包目录累加)' -f $sizeMB))
$rep += ('重复文件名: ' + $groups.Count + ' 个 / 拟丢弃 ' + $drop.Count + ' 份 / 移动单位 ' + $moves.Count + ' 个目录')
$rep += ('可绑基址 ID: 去重前 ' + $beforeIds + ' -> 保留集合 ' + $afterIds + $(if ($afterIds -eq $beforeIds) { '  (一个不掉)' } else { '  !! 少了 ' + ($beforeIds - $afterIds) + ' 个' }))
$rep += ''
$rep += '---- A. 拟丢弃(同名多份里较弱的那几份) ----'
if (-not $drop) { $rep += '  (无)' }
foreach ($m in ($moves | Sort-Object -Property @{ Expression = { $_.TopLeaf } })) {
  $rep += ('  {0}' -f $m.TopLeaf)
  $rep += ('     单位: {0}  方式: {1}  丢的 INF: {2}' -f $m.Dir, $(if ($m.Whole) { '整目录移到 Net_dropped' } else { '该目录还有留下的包, 只挪 INF' }), $m.Infs)
}
$rep += ''
$rep += '---- B. 重复名里保留下来的那一份 ----'
foreach ($r in ($keptDup | Sort-Object PkgLower)) {
  $rep += ('  {0,-18} N={1,-4} {2,-24} {3}' -f $r.PkgLower, $r.N, $r.DriverVer, (Split-Path -Leaf $r.Dir))
}
$rep += ''
$rep += '---- C. 校验 ----'
$rep += ('  可绑 ID 一个不掉: ' + $(if ($afterIds -eq $beforeIds) { 'OK' } else { 'FAIL(差 ' + ($beforeIds - $afterIds) + ')' }))
$rep += ('  丢弃的份里有活包(N>0)的: ' + (@($drop | Where-Object { $_.N -gt 0 }).Count) + ' 份(允许: 它们的 ID 已被覆盖)')

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Set-Content -LiteralPath $Out -Value $rep -Encoding UTF8

if ($SelfTest) {
  Write-Host '==== 29_ 内置断言(不写盘) ====' -ForegroundColor Cyan
  $fail = 0
  function Assert([bool]$c, [string]$msg) {
    if ($c) { Write-Host ('  [OK  ] ' + $msg) } else { Write-Host ('  [FAIL] ' + $msg) -ForegroundColor Red; $script:fail++ }
  }
  Assert ($rows.Count -ge 100) ('扫到 INF ' + $rows.Count + ' 个(>=100, 说明 20_ 已导入)')
  Assert ($groups.Count -gt 0) ('发现重复文件名 ' + $groups.Count + ' 个')
  Assert ($afterIds -eq $beforeIds) ('去重后可绑 ID 不掉: ' + $beforeIds + ' -> ' + $afterIds)
  Assert ($drop.Count -lt $rows.Count) ('只丢 ' + $drop.Count + ' 份, 远少于总数 ' + $rows.Count)
  foreach ($g in $groups) {
    $live = @($g.Group | Where-Object { $_.N -gt 0 -or $_.NU -gt 0 })
    if ($live.Count -eq 0) { continue }                       # 整组都是死包: 全丢是允许的
    $k = @($drop | Where-Object { $_.PkgLower -eq $g.Name }).Count
    if ($k -ge $g.Count) { Assert $false ('组 ' + $g.Name + ' 把所有活包份都丢了') }
  }
  Write-Host ('  计划/报告已写: ' + $Out)
  if ($fail) { Write-Host "  !! 断言失败 $fail 条" -ForegroundColor Red; exit 1 }
  Write-Host ('  全部断言通过 / 拟丢弃 ' + $drop.Count + ' 份, ' + $moves.Count + ' 个移动单位') -ForegroundColor Green
  exit 0
}

$rep | ForEach-Object { Write-Host $_ }
Write-Host ('报告已写: ' + $Out) -ForegroundColor Green
if (-not $Apply) { Write-Host '  这是计划。确认没问题后加 -Apply 才真的移动文件(可用 -Undo 回滚)' -ForegroundColor Yellow; exit 0 }

Write-Host '[Apply] 开始移动 ...' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $Stash | Out-Null
$used = @{}
$moved = 0
$man = @()
foreach ($m in $moves) {
  if ($m.Whole) {
    $tag = Get-StashName $m.Dir $used
    $dst = Join-Path $Stash $tag
    Move-Item -LiteralPath $m.Dir -Destination $dst -Force
    $moved++
    $man += ($tag + "`t" + $m.Dir + "`tdir")
    Write-Host ('  整目录 -> Net_dropped\' + $tag + '  [' + $m.Infs + ']')
  } else {
    # 同目录里还有要留的包: 只把要丢的 INF 单独挪走(它的 cat/sys 留在原地当死文件, 不影响留下的包)
    $leaf = Split-Path -Leaf $m.Dir
    foreach ($r in (@($drop | Where-Object { $_.Dir -eq $m.Dir }))) {
      $tag = Get-StashName ($leaf + '__' + $r.Pkg + '.lost') $used
      Move-Item -LiteralPath $r.InfPath -Destination (Join-Path $Stash $tag) -Force
      $moved++
      $man += ($tag + "`t" + $r.InfPath + "`tinf")
      Write-Host ('  只挪 INF -> ' + $tag)
    }
  }
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Manifest) | Out-Null
Set-Content -LiteralPath $Manifest -Value $man -Encoding UTF8
$after = Get-NetDrvPool -DrvDir $DrvDir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName @()
$tail = @('',
  ('移动单位执行数: ' + $moves.Count + ' / 挪走文件 ' + $moved),
  ('复扫: INF ' + $after.Rows.Count + ' 个 / 不同文件名 ' + (@($after.Rows | ForEach-Object { $_.PkgLower } | Sort-Object -Unique)).Count + ' 个 / 可绑 ID ' + $after.Idx.Count + ' 种 / 死包 ' + (@($after.Rows | Where-Object { $_.Dead }).Count) + ' 个 / ' + ('{0:N1} MB' -f ((Get-ChildItem $DrvDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB)))
)
Add-Content -LiteralPath $Out -Value ($tail -join "`r`n") -Encoding UTF8
$tail | ForEach-Object { Write-Host $_ }
if ($after.Idx.Count -lt $beforeIds) {
  Write-Host ('  !! 可绑 ID 掉了 ' + ($beforeIds - $after.Idx.Count) + ' 个 -> 立刻 -Undo 回滚再查') -ForegroundColor Red
  exit 1
}
Write-Host ('  去重完成, 可绑 ID ' + $beforeIds + ' -> ' + $after.Idx.Count + ' (不掉即正确)') -ForegroundColor Green
