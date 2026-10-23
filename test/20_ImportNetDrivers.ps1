# ============================================================
# 20_ImportNetDrivers.ps1 —— 第二步(换驱动来源)的执行器: 默认只出计划, -Apply 才动文件
#
# 选包口径(2026-10-08 与用户确认):
#   - 驱动越全越好, 不在乎体积, 服务器/万兆也收 -> 默认不加任何"精简"过滤
#   - 只看有线: Wifi=True 的包(802.11/蓝牙/WWAN)不选, 留给 WiFi 阶段(-IncludeWifi 可强开)
#   - 只认"本 PE 生效段里绑得出设备"的包(库 NetDrvLib 的段感知判定), 死包不再引进来
#   - 同名 INF 在池里有多个年份版本时只留 DriverVer 最新的一份
#   - 候选必须能带来至少一个"现镜像索引里没有"的 PCI 硬件ID
# 死包处理: 同一顶层目录里如果混着活包(且共用 nicco26.dll 这类共享 DLL), 整目录不能移,
#           段感知索引本来就不会登记死包 -> netdrvfix 查不到它, 留着无害;
#           只有"整个目录全为死包"才列入可移出清单(-Apply 时移到 overlay\Drivers\Net_dead)。
#
# 跑法(普通权限):
#   预览: powershell -NoProfile -ExecutionPolicy Bypass -File test\20_ImportNetDrivers.ps1
#   执行: ... -Apply
#   自检: ... -SelfTest        (只断言, 不写文件)
# ============================================================
param(
  [string]$OverlayDir = '',
  [string[]]$PoolDirs = @('D:\winpe_build\hotpe_net\Lan'),
  [switch]$NoHost,
  [switch]$IncludeWifi,
  [switch]$Apply,
  [switch]$Undo,
  [switch]$SelfTest,
  [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OverlayDir) { $OverlayDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $Out)        { $Out        = Join-Path $Root 'build\import_plan.txt' }
$StashDir  = Join-Path $Root 'overlay\Drivers\Net_dead'
$HostDs    = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'

. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')

function New-Pool2([string]$dir, [string]$label, [string[]]$cls) {
  if (-not (Test-Path $dir)) { Write-Host ('  跳过 ' + $label + ': 不存在 ' + $dir) -ForegroundColor Yellow; return $null }
  Write-Host ('  扫描 ' + $label + ' ...') -ForegroundColor Cyan
  $pp = Get-NetDrvPool -DrvDir $dir -ClassName $cls
  $pp.Label = $label
  return $pp
}
function Short-Label([string]$label, [string]$dir) {
  # 目录名用: 源池相对路径压成合法文件夹名
  $leaf = (Split-Path -Leaf $dir)
  return ((('imp_' + $leaf) -replace '[^\w.\-]', '_'))
}

# ---------- 回退: 删掉导入目录, 把移出的死包目录放回原处 ----------
if ($Undo) {
  $imp = @(Get-ChildItem $OverlayDir -Directory -Filter 'Lan_Imp_*' -EA SilentlyContinue)
  foreach ($d in $imp) { Remove-Item $d.FullName -Recurse -Force }
  $back = 0
  if (Test-Path $StashDir) {
    foreach ($d in @(Get-ChildItem $StashDir -Directory -EA SilentlyContinue)) {
      $dst = Join-Path $OverlayDir $d.Name
      if (Test-Path $dst) { Write-Host ('  !! ' + $dst + ' 已存在, 不覆盖(请手工核对)') -ForegroundColor Yellow; continue }
      Move-Item -LiteralPath $d.FullName -Destination $dst -Force
      $back++
    }
    if (-not @(Get-ChildItem $StashDir -Directory -EA SilentlyContinue)) { Remove-Item $StashDir -Force -EA SilentlyContinue }
  }
  Write-Host ('  回退完成: 删除导入目录 ' + $imp.Count + ' 个 / 放回死包目录 ' + $back + ' 个') -ForegroundColor Green
  exit 0
}

$ov = New-Pool2 $OverlayDir 'overlay(现镜像)' @()
$poolList = @()
foreach ($d in $PoolDirs) { $pp = New-Pool2 $d ('源池:' + (Split-Path -Leaf $d)) @(); if ($pp) { $poolList += $pp } }
if (-not $NoHost -and (Test-Path $HostDs)) {
  $hh = New-Pool2 $HostDs '宿主机DriverStore' @('Net')
  if ($hh) { $poolList += $hh }
}
$pools = $poolList

# ---------- 候选: 同名只留最新版 ----------
$ovNames = @($ov.Rows | ForEach-Object { $_.PkgLower })
$byName = @{}
foreach ($p in $pools) {
  foreach ($r in $p.Rows) {
    if (-not $IncludeWifi -and $r.Wifi) { continue }
    if ($r.Dead) { continue }
    if ($r.Cls -notmatch 'Net') { continue }
    if ($r.PciIds.Count -eq 0) { continue }                 # 只按 PCI 选包, USB 网卡留给第三步
    if ($ovNames -contains $r.PkgLower) { continue }         # 现镜像已有同名包 -> 不重复拷(升级另列)
    $k = $r.PkgLower
    if (-not $byName.ContainsKey($k)) { $byName[$k] = [pscustomobject]@{ Row = $r; Pool = $p.Label; Root = $p.Dir } }
    elseif ($r.VerDate -gt $byName[$k].Row.VerDate) { $byName[$k] = [pscustomobject]@{ Row = $r; Pool = $p.Label; Root = $p.Dir } }
  }
}
# 再筛"能带来新 ID", 并排序
$cands = @()
foreach ($k in $byName.Keys) {
  $it = $byName[$k]
  $new = @($it.Row.PciIds | ForEach-Object { Get-BaseId $_ } | Where-Object {
            $_ -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$' -and -not $ov.Idx.ContainsKey($_) } | Sort-Object -Unique)
  if ($new.Count -eq 0) { continue }
  # 目标目录名: 很多厂商子目录都叫 NDIS68/W11, 直接用叶子会撞车并把不同包的 DLL 互相覆盖,
  # 所以把"池根目录名 + 相对路径"整个压平
  $rel = $it.Row.Dir
  if ($rel.StartsWith($it.Root)) { $rel = $rel.Substring($it.Root.Length) }
  $flat = ((Split-Path -Leaf $it.Root) + '__' + $rel) -replace '[^\w.\-]', '_'
  $cands += [pscustomobject]@{
    Pkg = $it.Row.Pkg; PkgLower = $it.Row.PkgLower; Pool = $it.Pool; Dir = $it.Row.Dir
    Dst = ('Lan_Imp_' + $flat)
    MB = $it.Row.MB; DriverVer = $it.Row.DriverVer; VerDate = $it.Row.VerDate
    New = $new; N = $new.Count; Sec = $it.Row.Sec
  }
}
$cands = @($cands | Sort-Object -Property @{ Expression = { $_.N }; Descending = $true }, @{ Expression = { $_.VerDate }; Descending = $true })
$allNewIds  = @($cands | ForEach-Object { $_.New } | Sort-Object -Unique)
$covAfter   = @($ov.Idx.Keys + $allNewIds | Sort-Object -Unique)
$mbAfter    = [math]::Round((($cands | Measure-Object MB -Sum).Sum), 1)

# ---------- 同名包"有更老板本"清单(升级候选, 默认不动) ----------
$upgrades = @()
foreach ($o in $ov.Rows) {
  $best = $null
  foreach ($p in $pools) {
    foreach ($r in @($p.Rows | Where-Object { $_.PkgLower -eq $o.PkgLower })) {
      if ($r.VerDate -gt $o.VerDate -and -not $r.Dead) {
        if ($null -eq $best -or $r.VerDate -gt $best.VerDate) { $best = $r }
      }
    }
  }
  if ($best) {
    $gain = @($best.PciIds | ForEach-Object { Get-BaseId $_ } | Where-Object { $_ -match '^PCI\\VEN_[0-9A-F]{4}&DEV_' -and -not $ov.Idx.ContainsKey($_) } | Sort-Object -Unique)
    $upgrades += [pscustomobject]@{ Pkg = $o.Pkg; Now = $o.DriverVer; Newer = $best.DriverVer; Src = $best.Dir; Gain = $gain.Count }
  }
}
$upgrades = @($upgrades | Sort-Object -Property @{ Expression = { $_.Gain }; Descending = $true })

# ---------- 死包 / 可整目录移出的死包 ----------
$deadOv = @($ov.Rows | Where-Object { $_.Dead })
$ovTop  = @{}
foreach ($r in $ov.Rows) {
  $rel = $r.Dir.Substring($OverlayDir.Length).Trim('\')
  $top = if ($rel) { ($rel -split '\\')[0] } else { '.' }
  if (-not $ovTop.ContainsKey($top)) { $ovTop[$top] = @() }
  $ovTop[$top] += $r
}
$deadDirs = @()
foreach ($t in ($ovTop.Keys | Sort-Object)) {
  $items = @($ovTop[$t])
  $d = @($items | Where-Object { $_.Dead })
  if ($d.Count -eq $items.Count -and $d.Count -gt 0) {
    $deadDirs += [pscustomobject]@{ Top = $t; Nf = $items.Count; Shadow = (@($items | ForEach-Object { $_.ShadowIds } | Sort-Object -Unique)).Count }
  }
}

# ---------- 计划报告 ----------
$rep = @()
$rep += '==== 网卡驱动补包计划(段感知, 只出计划; -Apply 才写文件) ===='
$rep += ('生成时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$rep += ('现镜像   : ' + $ov.Dir + '  (' + $ov.Rows.Count + ' INF / 可绑 ' + $ov.Idx.Count + ' 种)')
foreach ($p in $pools) { $rep += ('来源池   : ' + $p.Dir + '  (' + $p.Rows.Count + ' INF / 可绑 ' + $p.Idx.Count + ' 种)') }
$rep += ('口径     : 只要有线' + $(if ($IncludeWifi) { '(已放开无线)' } else { '' }) + ' / 服务器万兆都收 / 同名只留最新版 / 死包不再引入')
$rep += ''
$rep += ('汇总: 补 ' + $cands.Count + ' 个包 (' + $mbAfter + ' MB) -> 可绑 ID ' + $ov.Idx.Count + ' 种 涨到 ' + $covAfter.Count + ' 种 (+' + $allNewIds.Count + ')')
$rep += ''
$rep += '---- A 要补进来的包(按新增ID数降序) ----'
foreach ($c in $cands) {
  $rep += ('  +{0,-4} ID  {1,-28} {2,-24} {3,7:N2} MB  [{4}]' -f $c.N, $c.Pkg, $c.DriverVer, $c.MB, $c.Pool)
  $rep += ('        源: ' + $c.Dir)
  $rep += ('        目标: ' + (Join-Path $OverlayDir $c.Dst))
  $rep += ('        生效段: ' + $c.Sec)
  $show = $c.New; if ($show.Count -gt 10) { $show = @($show[0..9]) + ('…共' + $c.New.Count) }
  $rep += ('        新增: ' + ($show -join ' '))
}
$rep += ''
$rep += '---- B 现镜像死包(生效段绑不出任何设备; 段感知索引不会再登记它们) ----'
if (-not $deadOv) { $rep += '  (无)' }
foreach ($r in ($deadOv | Sort-Object Pkg)) { $rep += ('  {0,-18} {1,-24} 生效段={2}' -f $r.Pkg, $r.DriverVer, $r.Sec) }
$rep += ''
$rep += '---- C 可整目录移出的死包目录(目录里全部 INF 都是死包, 才敢移) ----'
if (-not $deadDirs) { $rep += '  (无)' }
foreach ($d in $deadDirs) { $rep += ('  {0,-46} INF={1}  够不到的ID={2}' -f $d.Top, $d.Nf, $d.Shadow) }
$rep += ''
$rep += '---- D 同名包有更老板本(升级候选; 默认不动, 免得碰坏实机已验证的包) ----'
if (-not $upgrades) { $rep += '  (无)' }
foreach ($u in $upgrades) { $rep += ('  {0,-18} 现={1,-24} 新={2,-24} 多绑 {3} 个ID' -f $u.Pkg, $u.Now, $u.Newer, $u.Gain) }

if ($SelfTest) {
  Write-Host '==== 20_ 内置断言 ====' -ForegroundColor Cyan
  $f = 0
  function A([bool]$c, [string]$w) { if ($c) { Write-Host ('  [OK  ] ' + $w) } else { Write-Host ('  [FAIL] ' + $w) -ForegroundColor Red; $script:f++ } }
  A ($cands.Count -ge 20) ('候选包 ' + $cands.Count + ' >= 20')
  A ($covAfter.Count -ge 600) ('补完后可绑 ID ' + $covAfter.Count + ' >= 600')
  A ($deadOv.Count -eq 14) ('死包 14 个 (与 18_ 一致)')
  A (@($cands | Where-Object { $_.Pool -match 'DriverStore' -and $_.Pkg -match '1ic64' }).Count -ge 1) 'net1ic64(能绑 82574L) 在候选里'
  A (@($cands | Where-Object { $_.Pkg -match '(?i)vmxnet' }).Count -ge 1) 'vmxnet3 在候选里'
  A (@($cands | Where-Object { $_.PkgLower -in $ovNames }).Count -eq 0) '没有和现镜像重名的包'
  A (@($cands | ForEach-Object { $_.PkgLower } | Sort-Object -Unique).Count -eq $cands.Count) '候选包之间也没有重名(不会互相覆盖)'
  A (@($cands | Where-Object { Test-Path (Join-Path $OverlayDir $_.Dst) }).Count -eq 0) '目标目录全是新目录(不会覆盖现镜像文件)'
  A (@($cands | ForEach-Object { $_.Dir } | Where-Object { -not (Test-Path $_) }).Count -eq 0) '所有候选源目录都存在'
  if ($f) { Write-Host ('  !! 断言失败 ' + $f + ' 条') -ForegroundColor Red; exit 1 }
  Write-Host '  全部断言通过' -ForegroundColor Green
  exit 0
}

$rep | ForEach-Object { Write-Host $_ }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Set-Content -LiteralPath $Out -Value $rep -Encoding UTF8
Write-Host ('计划已写: ' + $Out) -ForegroundColor Green
if (-not $Apply) { Write-Host '  (这是预览; 确认无误后加 -Apply 才会真的拷贝)' -ForegroundColor Yellow; exit 0 }

# ---------- 真执行 ----------
Write-Host '==== -Apply: 开始拷贝 ====' -ForegroundColor Cyan
$manifest = @()
foreach ($c in $cands) {
  $dstDir  = Join-Path $OverlayDir $c.Dst
  if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Force -Path $dstDir | Out-Null }
  Copy-Item -Path (Join-Path $c.Dir '*') -Destination $dstDir -Force -Recurse
  $got = @(Get-ChildItem $dstDir -Filter '*.inf' -EA SilentlyContinue)
  if ($got.Count -eq 0) { Write-Host ('  !! 拷完找不到 INF: ' + $c.Pkg) -ForegroundColor Red; exit 1 }
  $manifest += ("{0}`t{1}`t{2}`t{3}" -f $c.Pkg, $c.Pool, $c.Dir, $dstDir)
  Write-Host ('  + ' + $c.Pkg + '  ->  ' + $dstDir)
}
foreach ($d in $deadDirs) {
  $src = Join-Path $OverlayDir $d.Top
  $dst = Join-Path $StashDir $d.Top
  if (-not (Test-Path $StashDir)) { New-Item -ItemType Directory -Force -Path $StashDir | Out-Null }
  Move-Item -LiteralPath $src -Destination $dst -Force
  Write-Host ('  移出死包目录 ' + $d.Top + ' -> ' + $dst)
}
Set-Content -LiteralPath (Join-Path $Root 'build\import_manifest.txt') -Value $manifest -Encoding UTF8
Write-Host ('  清单已写: build\import_manifest.txt') -ForegroundColor Green

$ov2 = Get-NetDrvPool -DrvDir $OverlayDir -ClassName @()
Write-Host ('  复核: overlay 现在有 INF ' + $ov2.Rows.Count + ' 个 / 可绑 ID ' + $ov2.Idx.Count + ' 种 (原 ' + $ov.Idx.Count + ')') -ForegroundColor Green
Write-Host '  下一步: 让 17_ 用段感知重生成 netdrv_index.txt, 再管理员跑 16_/build.ps1 出盘' -ForegroundColor Yellow
