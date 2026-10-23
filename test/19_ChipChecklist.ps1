# ============================================================
# 19_ChipChecklist.ps1 —— 把"覆盖近10年主流网卡"变成两张可执行的表
#
#   表1 芯片对照: 一颗一颗问 "overlay 里能绑吗? 源池(hotpe_net Lan / 宿主机 DriverStore)里能绑吗?
#                  用的是哪个包、哪一年的版本?" —— 分清三种情况:
#                    已覆盖 / 能从现成的池里补 / 全池都只有低档段(只能另找新驱动)
#   表2 可补包清单: 源池里"能绑、且带来 overlay 索引没有的 ID"的包, 按新增 ID 数排序,
#                  附源目录和体积 —— 第二步真正要拷进 overlay\Drivers\Net 的就是这张表。
#
#   解析口径与 18_ 完全一致(共用 test\NetDrvLib.ps1): 只看本 PE(NTamd64/10.0.26100)
#   安装器真正会读的那个 model support 段, 低档段的 ID 记为"够不到"。
#
# 普通权限运行(只读, 不写驱动目录):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\19_ChipChecklist.ps1
#   ... -SelfTest            只跑断言
#   ... -NoHost              跳过宿主机 DriverStore(省时)
#   ... -Out <路径>          换报告输出
# ============================================================
param(
  [string]$OverlayDir = '',
  [string[]]$PoolDirs = @('D:\winpe_build\hotpe_net\Lan'),
  [switch]$NoHost,
  [string]$Out      = '',
  [string]$Arch     = 'NTamd64',
  [string]$OsVer    = '10.0',
  [int]$Build       = 26100,
  [int]$ProductType = 1,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OverlayDir) { $OverlayDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $Out)        { $Out        = Join-Path $Root 'build\chip_checklist.txt' }
$HostDs = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'

. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')

function New-Pool([string]$dir, [string]$label, [string[]]$cls) {
  if (-not (Test-Path $dir)) { Write-Host ('  跳过 ' + $label + ': 目录不存在 ' + $dir) -ForegroundColor Yellow; return $null }
  Write-Host ('  扫描 ' + $label + ' ...') -ForegroundColor Cyan
  $p = Get-NetDrvPool -DrvDir $dir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName $cls
  $p.Label = $label
  # 基础ID -> 能绑它的包行(取 DriverVer 最新的那个作为代表)
  $m = @{}
  foreach ($r in $p.Rows) {
    foreach ($id in $r.PciIds) {
      $k = Get-BaseId $id
      if ($k -notmatch '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$') { continue }
      if (-not $m.ContainsKey($k)) { $m[$k] = @() }
      $m[$k] += $r
    }
  }
  $p.Bind = $m
  return $p
}

$ov = New-Pool $OverlayDir 'overlay(现镜像)' @()
# 坑(2026-10-08 踩过): 局部变量名不能和参数同名 —— PowerShell 变量大小写不敏感,
# 而参数 [string[]]$PoolDirs 是强类型数组, 往里塞 hashtable 会被静默转成字符串。
$poolList = @()
foreach ($d in $PoolDirs) { $pp = New-Pool $d ('源池:' + (Split-Path -Leaf $d)) @(); if ($pp) { $poolList += $pp } }
if (-not $NoHost -and (Test-Path $HostDs)) {
  $hh = New-Pool $HostDs '宿主机DriverStore' @('Net')
  if ($hh) { $poolList += $hh }
}
$pools = $poolList

# ---------- 表1: 芯片对照 ----------
# 只列我有把握的 ID; 万一记错, 判定行会显示"所有池都没声明这个ID(待核)", 不会伪装成缺口
$chips = @(
  @{ n = 'Realtek RTL8111E/8168 千兆';      id = 'PCI\VEN_10EC&DEV_8168' }
  @{ n = 'Realtek RTL8111E FastEthernet';   id = 'PCI\VEN_10EC&DEV_8136' }
  @{ n = 'Realtek RTL8111H/G 系';           id = 'PCI\VEN_10EC&DEV_3000' }
  @{ n = 'Realtek RTL8125 2.5G';            id = 'PCI\VEN_10EC&DEV_8125' }
  @{ n = 'Realtek RTL8125 变体(BG)';        id = 'PCI\VEN_10EC&DEV_8129' }
  @{ n = 'Realtek RTL8126 5G';              id = 'PCI\VEN_10EC&DEV_8127' }
  @{ n = 'Realtek RTL8118/8125 系';         id = 'PCI\VEN_10EC&DEV_4300' }
  @{ n = 'Intel 82574L (VMware e1000e)';    id = 'PCI\VEN_8086&DEV_10D3' }
  @{ n = 'Intel I217-LM';                   id = 'PCI\VEN_8086&DEV_153A' }
  @{ n = 'Intel I218-LM';                   id = 'PCI\VEN_8086&DEV_1559' }
  @{ n = 'Intel I219-LM';                   id = 'PCI\VEN_8086&DEV_15B7' }
  @{ n = 'Intel I219-V';                    id = 'PCI\VEN_8086&DEV_15B8' }
  @{ n = 'Intel I211-AT';                   id = 'PCI\VEN_8086&DEV_157B' }
  @{ n = 'Intel I350 千兆服务器';           id = 'PCI\VEN_8086&DEV_1521' }
  @{ n = 'Intel I225-V 2.5G';               id = 'PCI\VEN_8086&DEV_15F3' }
  @{ n = 'Intel I225-LM 2.5G';              id = 'PCI\VEN_8086&DEV_15F2' }
  @{ n = 'Intel I226-V 2.5G';               id = 'PCI\VEN_8086&DEV_5503' }
  @{ n = 'Intel I226-LM 2.5G';              id = 'PCI\VEN_8086&DEV_125C' }
  @{ n = 'Broadcom BCM5720 千兆';           id = 'PCI\VEN_14E4&DEV_1600' }
  @{ n = 'Broadcom BCM5723';                id = 'PCI\VEN_14E4&DEV_165D' }
  @{ n = 'Broadcom BCM5719 四口';           id = 'PCI\VEN_14E4&DEV_168A' }
  @{ n = 'Broadcom BCM57810 万兆';          id = 'PCI\VEN_14E4&DEV_1680' }
  @{ n = 'Qualcomm Atheros Killer E2400';   id = 'PCI\VEN_1969&DEV_E0B1' }
  @{ n = 'Qualcomm Atheros Killer E2500';   id = 'PCI\VEN_1969&DEV_E0C8' }
  @{ n = 'Aquantia/Marvell AQC107 万兆';    id = 'PCI\VEN_1D6A&DEV_07B1' }
  @{ n = 'VMware vmxnet3 半虚拟化';         id = 'PCI\VEN_15AD&DEV_07B0' }
  @{ n = 'Intel PRO/1000 (VMware 模拟)';    id = 'PCI\VEN_8086&DEV_100F' }
  @{ n = 'AMD PCnet (VMware vlance)';       id = 'PCI\VEN_1022&DEV_2000' }
)

$rep = @()
$rep += '==== 近10年主流有线网卡 芯片对照(段感知) ===='
$rep += ('生成时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$rep += ('目标系统 : ' + $Arch + ' / ' + $OsVer + '.' + $Build + '  ProductType=' + $ProductType)
$rep += ('现镜像池 : ' + $ov.Dir + '  (' + $ov.Rows.Count + ' INF / 可绑 ' + $ov.Idx.Count + ' 种)')
foreach ($p in $pools) { $rep += ('对照池   : ' + $p.Dir + '  (' + $p.Rows.Count + ' INF / 可绑 ' + $p.Idx.Count + ' 种)') }
$rep += ''
$rep += '---- 表1 芯片对照 ----'
$cnt = @{ have = 0; importable = 0; onlyold = 0; unknown = 0 }
foreach ($c in $chips) {
  $k = $c.id
  $inOv = $ov.Bind.ContainsKey($k)
  $best = $null
  foreach ($p in $pools) {
    if ($p.Bind.ContainsKey($k)) {
      $cand = @($p.Bind[$k] | Sort-Object -Property @{ Expression = { $_.VerDate } })[-1]
      if ($null -eq $best -or $cand.VerDate -gt $best.Row.VerDate) { $best = [pscustomobject]@{ Pool = $p.Label; Row = $cand } }
    }
  }
  $declaredSomewhere = ($ov.Decl.ContainsKey($k))
  foreach ($p in $pools) { if ($p.Decl.ContainsKey($k)) { $declaredSomewhere = $true } }
  $verdict = ''
  if ($inOv)        { $verdict = '已覆盖';            $cnt.have++ }
  elseif ($best)    { $verdict = '可补(池里有能绑的)'; $cnt.importable++ }
  elseif ($declaredSomewhere) { $verdict = '全池只有低档段(得另找新驱动)'; $cnt.onlyold++ }
  else              { $verdict = '所有池都没声明这个ID(待核)'; $cnt.unknown++ }
  $ovTxt = '(无)'
  if ($inOv) {
    $r = @($ov.Bind[$k] | Sort-Object -Property @{ Expression = { $_.VerDate } })[-1]
    $ovTxt = ($r.Pkg + ' ' + $r.DriverVer)
  } elseif ($ov.Decl.ContainsKey($k)) { $ovTxt = '(只有低档段, 够不到)' }
  $bTxt = '(池里没有)'
  if ($best) { $bTxt = ($best.Pool + ' -> ' + $best.Row.Pkg + ' ' + $best.Row.DriverVer + ' / ' + $best.Row.MB + 'MB') }
  $rep += ('  {0,-30} {1}' -f $c.n, $c.id)
  $rep += ('      现镜像: {0,-46} 最好来源: {1}' -f $ovTxt, $bTxt)
  $rep += ('      => ' + $verdict)
  if ($verdict -like '*待核*') {
    # 待核的两种可能: ①这块芯片确实没人带驱动 ②我表里的 PCI ID 记错了(比 ① 常见得多)。
    # 把同一厂商在池子里声明过的 DEV 全列出来, 一眼就能看出是哪种。
    $m = [regex]::Match($k, '^PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})$')
    if ($m.Success) {
      $ven = $m.Groups[1].Value
      $devs = @()
      $allKeys = @($ov.Decl.Keys)
      foreach ($p in $pools) { $allKeys += @($p.Decl.Keys) }
      foreach ($kk in $allKeys) {
        $mm = [regex]::Match($kk, '^PCI\\VEN_' + $ven + '&DEV_([0-9A-F]{4})$')
        if ($mm.Success) { $devs += $mm.Groups[1].Value }
      }
      $devs = @($devs | Sort-Object -Unique)
      $show = if ($devs.Count -gt 40) { @($devs[0..39]) + ('…共' + $devs.Count) } else { $devs }
      $rep += ('      同厂商(VEN_' + $ven + ')池里声明过的 DEV(超过 40 个会截断): ' + ($show -join ' '))
      $rep += ('      (DEV_' + $m.Groups[2].Value + ' 判定用的是全量声明表, 不是上面这截列表 —— 三个池子加起来都没写过这个 ID, 所以要么是这块芯片真没人带驱动, 要么是我表里的 PCI ID 记错了; 拿实机的 pci 硬件ID 对一下再定)')
    }
  }
}
$rep += ''
$rep += ('  小结: 已覆盖 ' + $cnt.have + ' / 可补 ' + $cnt.importable + ' / 只有低档段 ' + $cnt.onlyold + ' / 待核 ' + $cnt.unknown)

# ---------- 表2: 可补包清单 ----------
$rep += ''
$rep += '---- 表2 可补包(池里能绑、且带来现镜像没有的硬件ID) ----'
$adds = @()
foreach ($p in $pools) {
  foreach ($r in $p.Rows) {
    $newIds = @()
    foreach ($id in $r.PciIds) {
      $k = Get-BaseId $id
      if ($k -notmatch '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$') { continue }
      if (-not $ov.Idx.ContainsKey($k)) { $newIds += $k }
    }
    $newIds = @($newIds | Sort-Object -Unique)
    if ($newIds.Count -eq 0) { continue }
    if ($r.Cls -notmatch 'Net') { continue }
    $adds += [pscustomobject]@{ Pool = $p.Label; Pkg = $r.Pkg; Key = ($p.Label + '|' + $r.PkgLower); Dir = $r.Dir; MB = $r.MB; DriverVer = $r.DriverVer; VerDate = $r.VerDate; New = $newIds.Count; Ids = $newIds; Wifi = $r.Wifi }
  }
}
# 同一个 INF 名在池里常有 5~8 个年份版本(22x/23x/24x...), 去重只留 DriverVer 最新的那份
$adds2 = @()
foreach ($g in ($adds | Group-Object Key)) {
  $adds2 += @($g.Group | Sort-Object -Property @{ Expression = { $_.VerDate } })[-1]
}
$adds = @($adds2 | Sort-Object -Property @{ Expression = { $_.Wifi } }, @{ Expression = { $_.New }; Descending = $true }, @{ Expression = { $_.VerDate }; Descending = $true })
if (-not $adds) { $rep += '  (无: 池里的可绑 ID 现镜像全都有了)' }
$rep += ('  (同一 INF 名的多个年份版本已只留最新; 无线包排在最后)')
foreach ($a in $adds) {
  $tag = if ($a.Wifi) { '无线' } else { '有线' }
  $rep += ('  {0} +{1,-4} ID  {2,-26} {3,-20} {4,7:N1} MB  [{5}]' -f $tag, $a.New, $a.Pkg, $a.DriverVer, $a.MB, $a.Pool)
  $rep += ('        源目录: ' + $a.Dir)
  $show = $a.Ids; if ($show.Count -gt 12) { $show = @($show[0..11]) + ('…共' + $a.Ids.Count + '个') }
  $rep += ('        新增ID: ' + ($show -join ' '))
}
$totNew      = @($adds | ForEach-Object { $_.Ids } | Sort-Object -Unique)
$totNewWired = @($adds | Where-Object { -not $_.Wifi } | ForEach-Object { $_.Ids } | Sort-Object -Unique)
$nWired      = @($adds | Where-Object { -not $_.Wifi }).Count
$nWifi       = @($adds | Where-Object { $_.Wifi }).Count
$mbWired     = [math]::Round((($adds | Where-Object { -not $_.Wifi } | Measure-Object MB -Sum).Sum), 1)
$rep += ''
$rep += ('  小结: 候选补包 ' + $adds.Count + ' 个(有线 ' + $nWired + ' / 无线 ' + $nWifi + ') / 能新增硬件ID ' + $totNew.Count + ' 种(其中有线 ' + $totNewWired.Count + ' 种)')
$ovMbReal = [math]::Round(((Get-ChildItem $OverlayDir -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum) / 1MB, 1)
$rep += ('  全导入有线包的体积约 ' + $mbWired + ' MB; 现镜像驱动目录 ' + $ovMbReal + ' MB / ' + $ov.Idx.Count + ' 种可绑 ID / ' + @($ov.Rows).Count + ' 个 INF')
$rep += ('  参考: 只挑"新增ID 最多的有线包"能覆盖大部分缺口, 具体取舍在 20_ImportNetDrivers.ps1 里做贪心覆盖')

# ---------- 表3: 现镜像里的死包 & 能被池替换的 ----------
$rep += ''
$rep += '---- 表3 现镜像死包(该删/该换) ----'
$deadOv = @($ov.Rows | Where-Object { $_.Dead })
if (-not $deadOv) { $rep += '  (无)' }
foreach ($r in ($deadOv | Sort-Object Pkg)) {
  $repl = ''
  $sd = @($r.ShadowIds | ForEach-Object { Get-BaseId $_ } | Sort-Object -Unique)
  $fixable = @($sd | Where-Object { $id = $_; @($pools | Where-Object { $_.Bind.ContainsKey($id) }).Count -gt 0 })
  if ($sd.Count) { $repl = '  (它够不到的 ' + $sd.Count + ' 个ID里, 池里能绑的有 ' + $fixable.Count + ' 个)' }
  $rep += ('  {0,-18} DriverVer={1,-22} 生效段={2}{3}' -f $r.Pkg, $r.DriverVer, $r.Sec, $repl)
}

if ($SelfTest) {
  Write-Host '==== 19_ 内置断言 ====' -ForegroundColor Cyan
  $fail = 0
  function A([bool]$cond, [string]$what) {
    if ($cond) { Write-Host ('  [OK  ] ' + $what) } else { Write-Host ('  [FAIL] ' + $what) -ForegroundColor Red; $script:fail++ }
  }
  # 断言基线: 2026-10-08 20_(导入)+35_(同名去重)之后, overlay 已经把 VMware 两条路和其它池里的有线缺口收进来了,
  # 所以这里改成"确认它们现在可绑", 而不是像导入前那样确认"缺"。
  A ($ov.Idx.Count -ge 600) ('overlay 可绑 ID ' + $ov.Idx.Count + ' >= 600(导入+去重后的量级)')
  A ($ov.Bind.ContainsKey('PCI\VEN_10EC&DEV_8136')) 'overlay 能绑 RTL8136'
  A ($ov.Bind.ContainsKey('PCI\VEN_8086&DEV_10D3')) 'overlay 现在能绑 82574L(VMware e1000e) —— 导入宿主机 net1ic64 之后'
  A ($ov.Bind.ContainsKey('PCI\VEN_15AD&DEV_07B0')) 'overlay 现在能绑 vmxnet3(VMware 半虚拟化)'
  A ($pools.Count -ge 1) '至少扫到一个对照池'
  A (@($pools[0].Rows).Count -gt 100) ('源池 INF 数 ' + @($pools[0].Rows).Count + ' > 100')
  A (@($adds | Where-Object { -not $_.Wifi }).Count -le 25) ('导入后剩下的有线可补包 ' + @($adds | Where-Object { -not $_.Wifi }).Count + ' 个 <= 25(缺口基本收完)')
  A (@($ov.Rows | Where-Object { $_.Dead }).Count -le 12) ('overlay 死包 ' + @($ov.Rows | Where-Object { $_.Dead }).Count + ' 个 <= 12(去重把老版本死包挪走了)')
  if ($fail) { Write-Host ("  !! 断言失败 $fail 条") -ForegroundColor Red; exit 1 }
  Write-Host '  全部断言通过' -ForegroundColor Green
  exit 0
}

$rep | ForEach-Object { Write-Host $_ }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Set-Content -LiteralPath $Out -Value $rep -Encoding UTF8
Write-Host ('报告已写: ' + $Out) -ForegroundColor Green
