# -*- coding: utf-8 -*-
# ============================================================
# test\38_CollectWlanDrivers.ps1 —— 收"精选档"无线网卡驱动池: D:\winpe_build\hotpe_net\Wlan -> overlay\Drivers\Wlan
#
#   为什么必须"新老各一档"(2026-10-09 用 build\scratch\wlan_coverage.ps1 算出来的, 快照在
#   build\scratch\wlan_coverage.txt 的 D 段):
#     * AX211(PCI DEV_51F1) 只在 4 个 2021 年后的 Intel 目录里; BE200(DEV_272B) 只在 23x 两个目录里;
#     * 老卡(3165/3166/24FD) 只在 <=2022 的目录里; 单个目录永远盖不全 => 每厂商取"新档", 关键家族补"老档"。
#     * 宿主机自己这块 Intel Wireless-AC 9260 = PCI\VEN_8086&DEV_2526, service Netwtw08, 靠新档覆盖。
#   体积口径(以 -SelfTest 打印的实测算为准, 这一档源约 345MB, DISM 进 boot.wim 后 ISO 约 +150MB):
#   boot.wim 是整份解进内存的 ramdisk, 救援机内存不明, 所以不走"全量 1568MB", 见记忆 winpe-wlan-driver-pool。
#
#   普通权限即可(只读源 + 写本仓库):
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\38_CollectWlanDrivers.ps1 -DryRun
#     ... 去掉 -DryRun 正式收; 收完跑 test\17_MakeNetDrvIndex.ps1 -DrvDir overlay\Drivers\Wlan 出索引
#     ... -SelfTest 只验证清单里每个源目录都存在、INF 数与体积能算出来, 不写文件
# ============================================================
param(
  [string]$Source = 'D:\winpe_build\hotpe_net\Wlan',
  [string]$Dst    = '',
  [switch]$DryRun,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Dst) { $Dst = Join-Path $Root 'overlay\Drivers\Wlan' }

# 目标目录名 -> 源里的相对路径。左边就是要写进 overlay\Drivers\Wlan 的目录名(别用 8.3 短名、别带空格)
$Tier = [ordered]@{
  'Wlan_Intel_23x_20240310'    = 'Intel/23x/20240310'          # Netwtw04+08+6e: AC 9260/9462, AX201/AX210/AX211, BE200
  'Wlan_Intel_21x_20200416'    = 'Intel/21x/20200416'          # 老档 Netwtw04/06/08: 3165/3166/24FD/9260 那一批
  'Wlan_Realtek_20250516'      = 'Realtek/20250516'            # 10 个 INF: RTL8821CE ~ RTL8852/BE 全家
  'Wlan_MediaTek_w11_20250312' = 'mediatek/w11/20250312'       # MT7921/MT7925 (Ax210 同级竞品)
  'Wlan_QCA_20250321'          = 'QualcommAtheros/11/20250321' # qcwlan64 (WCN3990/QCA685x)
  'Wlan_QCA_20160218'          = 'QualcommAtheros/20160218'    # athw10x 老档(AR9xxx/KB242), 23 个 ID 只要 4.6MB
  'Wlan_Broadcom_20161121'     = 'Broadcom/20161121'           # bcmwl63: 80 个 ID, 性价比最高的博通档
  'Wlan_Ralink_20150518'       = 'Ralink/20150518'             # netr28x (RT3xxx/MT76xx), 30 个 ID 3.5MB
  'Wlan_UsbRealtek_20250325'   = 'Usb/Realtek/20250325'        # USB WiFi 适配器 = 板载卡救不活时的保底
}

if (-not (Test-Path $Source)) { Write-Host "源目录不存在: $Source" -ForegroundColor Red; exit 1 }

$plan = @()
foreach ($k in $Tier.Keys) {
  $srcDir = Join-Path $Source (($Tier[$k] -replace '/', '\'))
  $infs = @(Get-ChildItem $srcDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue)
  $bytes = 0L
  if ($infs.Count -gt 0) {
    $bytes = (@(Get-ChildItem $srcDir -Recurse -File -EA SilentlyContinue) | Measure-Object Length -Sum).Sum
  }
  $plan += [pscustomobject]@{
    Name = $k; Src = $srcDir; Inf = $infs.Count; MB = [math]::Round($bytes / 1MB, 1)
  }
}

Write-Host ('=== 计划: ' + $Dst + ' ===') -ForegroundColor Cyan
$miss = @($plan | Where-Object { $_.Inf -eq 0 })
foreach ($p in $plan) {
  $tag = if ($p.Inf -eq 0) { '!! 源目录里没有 INF' } else { 'ok' }
  Write-Host ('  {0,-26} inf={1,-3} {2,7} MB  [{3}]  <= {4}' -f $p.Name, $p.Inf, $p.MB, $tag, $Tier[$p.Name])
}
Write-Host ('  合计 inf=' + (($plan | Measure-Object Inf -Sum).Sum) + '  源体积=' +
            [math]::Round((($plan | Measure-Object MB -Sum).Sum), 1) + ' MB')

if ($SelfTest) {
  if ($miss.Count -gt 0) { Write-Host 'SELFTEST FAIL: 清单里有目录取不到 INF' -ForegroundColor Red; exit 1 }
  Write-Host 'SELFTEST OK (' + $plan.Count + ' 个目录全部有 INF)' -ForegroundColor Green
  exit 0
}
if ($DryRun) { Write-Host 'DryRun: 未拷贝任何文件'; exit 0 }
if ($miss.Count -gt 0) {
  Write-Host ('!! ' + (($miss | ForEach-Object { $_.Name }) -join ',') + ' 取不到 INF, 先核对源路径') -ForegroundColor Red
  exit 1
}

New-Item -ItemType Directory -Force -Path $Dst | Out-Null
$total = 0L
foreach ($p in $plan) {
  $to = Join-Path $Dst $p.Name
  # /R:1 /W:1 是硬要求: robocopy 默认重试 100 万次 x 30 秒, 卡住时完全看不出动静
  & robocopy $p.Src $to /E /NFL /NDL /NJH /NJS /R:1 /W:1 /XJ | Out-Null
  $rc = $LASTEXITCODE
  if ($rc -ge 8) { Write-Host ('  !! ' + $p.Name + ' robocopy rc=' + $rc) -ForegroundColor Red; exit 1 }
  $bytes = (@(Get-ChildItem $to -Recurse -File -EA SilentlyContinue) | Measure-Object Length -Sum).Sum
  $total += $bytes
  Write-Host ('  ' + $p.Name + ' rc=' + $rc + ' 落地 ' + [math]::Round($bytes / 1MB, 1) + ' MB / inf=' +
              (@(Get-ChildItem $to -Recurse -Filter '*.inf' -File -EA SilentlyContinue)).Count)
}
Write-Host ('=== 完成: overlay\Drivers\Wlan = ' + [math]::Round($total / 1MB, 1) + ' MB ===') -ForegroundColor Green
Write-Host '下一步: powershell -NoProfile -ExecutionPolicy Bypass -File test\17_MakeNetDrvIndex.ps1 -DrvDir overlay\Drivers\Wlan -Out overlay\Scripts\wlandrv_index.txt'
