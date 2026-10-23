# ============================================================
# 17_MakeNetDrvIndex.ps1 —— 生成"硬件ID -> 驱动包"索引, 供镜像内 netdrvfix 查表。
#
#   为什么要在构建期生成: PE 里去解析 200+ 个 UTF-16 INF 太慢, 宿主机上算一次只要几十秒;
#   算出来的索引(每行 "硬件ID<TAB>包名.inf", ID 形如 PCI\VEN_xxxx&DEV_yyyy 或 USB\VID_xxxx&PID_yyyy)
#   拷进 System32, 运行时只做一次查表。
#
#   2026-10-08 改造: 改用 test\NetDrvLib.ps1 的"段感知"判定(和 18_/19_/20_ 同一口径)。
#   旧版是正则扫 INF 全文, 会把只写在低档段的 ID 也算命中 —— VMware e1000e 那次就是
#   索引说有 e1q63x64 可用、drvload 也 rc=0, 但生效段 [Intel.NTamd64.6.3] 是空的, 设备永远绑不上。
#   现在只登记"本 PE 真正会读的那个 Models 段"里的 ID, 宁少勿假。
#
# 普通权限运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\17_MakeNetDrvIndex.ps1 -SelfTest   # 只对比新旧, 不写文件
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\17_MakeNetDrvIndex.ps1             # 正式写 overlay\Scripts\netdrv_index.txt
#   ... -DrvDir <p> -Out <p> -OsVer 10.0 -Build 26100
#   ... -MaxPerId 3      每个硬件ID只登记最新的 3 个包(0 = 全部登记, 会让开机 netdrvfix 反复 drvload 同一芯片)
#   ... -NoUsb           只出 PCI\VEN 行(2026-10-08 第三步起默认带上 USB\VID, USB 网卡也能自愈)
#
#   2026-10-08 v3: 同一个脚本也用来出**存储**索引 —— netdrvfix 3.0 查两份表, 本脚本被调两次:
#     -DrvDir overlay\Drivers\Net     -Out overlay\Scripts\netdrv_index.txt     (143 INF -> 831 ID)
#     -DrvDir overlay\Drivers\Storage -Out overlay\Scripts\stodrv_index.txt     (7 INF  -> 21 ID, Intel VMD/AHCI/VROC)
#   口径不用改: 类不敏感(Class 只用来挑生效段), SCSIAdapter / HDC / DiskDrive 走的是同一套段感知规则。
#   注意 &CC_ 的归一在 NetDrvLib.ps1 的 Get-BaseId 里, Intel 存储 INF 整片都写 &CC_0106,
#   少了那一刀 21 个 ID 会只剩 9 个(2026-10-08 定罪, 详见 docs\存储驱动与远程救援方案_20261008.md 第 9.1 节)。
# ============================================================
param(
  [string]$DrvDir = '',
  [string]$Out    = '',
  [string]$Arch     = 'NTamd64',
  [string]$OsVer    = '10.0',
  [int]$Build       = 26100,
  [int]$ProductType = 1,
  [int]$MaxPerId  = 3,        # 每个硬件ID最多登记几个驱动包(留最新; 0 = 不截断)
  [switch]$NoUsb,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $DrvDir) { $DrvDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $Out)    { $Out    = Join-Path $Root 'overlay\Scripts\netdrv_index.txt' }
if (-not (Test-Path $DrvDir)) { Write-Host "驱动目录不存在: $DrvDir (先跑 test\15_CollectNetDrivers.ps1 / test\20_ImportNetDrivers.ps1)" -ForegroundColor Red; exit 1 }

. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')
Write-Host ('  段感知扫描 ' + $DrvDir + ' ...') -ForegroundColor Cyan
$pool = Get-NetDrvPool -DrvDir $DrvDir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName @()

$lines = @()
# ---------- 每个硬件ID 只留"最新 MaxPerId 个包" ----------
#   为什么要截: 驱动库里同一个芯片常被 5-6 份不同 NDIS 档的包同时声明(e1d.inf / e1d62x64.inf / ... / e1d68x64.inf),
#   20_ 导入后最狠的一个 ID 挂了 37 个包。netdrvfix 是"挨个试"的, 开机时对一块网卡敲 37 次要几分钟,
#   而且重复装载同一个芯片也没意义。留最新 3 份: 1 份正的 + 2 份备份(签名/兼容被拒时还有退路)。
function Build-IndexLines([string[]]$keys, $byId, [int]$cap) {
  $out = @(); $capped = 0; $maxRaw = 0; $full = 0
  foreach ($k in ($keys | Sort-Object)) {
    $cand = @($byId[$k] | Sort-Object -Property @{ Expression = { $_.VerDate }; Descending = $true },
                                              @{ Expression = { $_.N }; Descending = $true },
                                              @{ Expression = { $_.PkgLower } } |
                    ForEach-Object { $_.PkgLower } | Select-Object -Unique)
    $full += $cand.Count
    if ($cand.Count -gt $maxRaw) { $maxRaw = $cand.Count }
    if ($cand.Count -gt $cap) { $capped++ }
    $take = if ($cap -gt 0) { $cap } else { $cand.Count }
    foreach ($pkg in @($cand | Select-Object -First $take)) { $out += ($k + "`t" + $pkg) }
  }
  return @{ Lines = $out; Capped = $capped; MaxRaw = $maxRaw; Full = $full }
}
$rowsById = @{}; $rowsByUsb = @{}
foreach ($r in $pool.Rows) {
  foreach ($id in $r.PciIds) {
    $k = Get-BaseId $id
    if (-not (Test-PciBaseId $k)) { continue }
    if (-not $rowsById.ContainsKey($k)) { $rowsById[$k] = @() }
    $rowsById[$k] += $r
  }
  foreach ($id in $r.UsbIds) {
    $k = Get-UsbBaseId $id
    if (-not (Test-UsbBaseId $k)) { continue }
    if (-not $rowsByUsb.ContainsKey($k)) { $rowsByUsb[$k] = @() }
    $rowsByUsb[$k] += $r
  }
}
$pci = Build-IndexLines @($pool.Idx.Keys) $rowsById $MaxPerId
$usb = @{ Lines = @(); Capped = 0; MaxRaw = 0; Full = 0 }
if (-not $NoUsb) { $usb = Build-IndexLines @($pool.UsbIdx.Keys) $rowsByUsb $MaxPerId }
$lines = @($pci.Lines) + @($usb.Lines)
$deadN = @($pool.Rows | Where-Object { $_.Dead }).Count
Write-Host ('  INF ' + $pool.Rows.Count + ' 个 / 可绑 PCI ' + $pool.Idx.Count + ' 种 + USB ' + $pool.UsbIdx.Count + ' 种 / 索引行 ' + $lines.Count + ' 条 (PCI ' + $pci.Lines.Count + ' + USB ' + $usb.Lines.Count + ') / 死包 ' + $deadN + ' 个')
Write-Host ('  每ID候选包上限 ' + $MaxPerId + ' 个: 全量要给 ' + ($pci.Full + $usb.Full) + ' 行 -> 截后 ' + $lines.Count + ' 行 (被截的ID ' + ($pci.Capped + $usb.Capped) + ' 个, 单ID最多 ' + [math]::Max($pci.MaxRaw, $usb.MaxRaw) + ' 个候选)')

# ---------- 与"旧口径(全文正则)"对比, 看假命中有多少 ----------
$naive = @{}
foreach ($r in $pool.Rows) {
  $txt = ''
  try { $txt = Get-InfText $r.InfPath } catch { continue }
  foreach ($m in [regex]::Matches($txt, 'PCI\\(VEN_[0-9A-Fa-f]{4})&(DEV_[0-9A-Fa-f]{4})')) {
    $key = 'PCI\' + $m.Groups[1].Value.ToUpper() + '&' + $m.Groups[2].Value.ToUpper()
    if (-not $naive.ContainsKey($key)) { $naive[$key] = @{} }
    $naive[$key][$r.PkgLower] = 1
  }
}
$naiveLines = 0; foreach ($k in $naive.Keys) { $naiveLines += $naive[$k].Keys.Count }
$fake = @($naive.Keys | Where-Object { -not $pool.Idx.ContainsKey($_) } | Sort-Object)
Write-Host ('  旧口径(全文正则): ID ' + $naive.Count + ' 种 / 行 ' + $naiveLines + ' 条 -> 段感知后去掉的假命中 ID ' + $fake.Count + ' 种')
if ($fake.Count) {
  $show = if ($fake.Count -gt 12) { @($fake[0..11]) + ('…共' + $fake.Count) } else { $fake }
  Write-Host ('    例: ' + ($show -join ' '))
}
$cur = @()
if (Test-Path $Out) { $cur = @(Get-Content -LiteralPath $Out -EA SilentlyContinue) }
Write-Host ('  USB 网卡ID ' + $pool.UsbIdx.Count + ' 种 -> ' + $usb.Lines.Count + ' 行' + $(if ($NoUsb) { ' (被 -NoUsb 关掉了, 索引只含 PCI)' }) + ' / 现索引文件 ' + $cur.Count + ' 行 -> 新索引 ' + $lines.Count + ' 行')
if ($SelfTest) { Write-Host '  -SelfTest: 没写文件'; exit 0 }

if ($lines.Count -eq 0) { Write-Host '  !! 一条索引都没生成, 不覆盖旧文件' -ForegroundColor Red; exit 1 }
Copy-Item -LiteralPath $Out ($Out + '.bak') -Force -EA SilentlyContinue
Set-Content -LiteralPath $Out -Value $lines -Encoding ASCII
Write-Host ('  已写 ' + $Out + '  (' + [math]::Round((Get-Item $Out).Length / 1KB, 1) + ' KB, 旧版备份为 ' + (Split-Path -Leaf $Out) + '.bak)') -ForegroundColor Green
