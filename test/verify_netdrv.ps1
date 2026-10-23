# ============================================================
# verify_netdrv.ps1 —— 驱动池验收器(一条命令给一个结论): -Profile net 验收有线池, -Profile wlan 验收无线池
#
#   它只干一件事: 把 overlay\Drivers\Net(驱动库) 和 overlay\Scripts\netdrv_index.txt
#   (开机 netdrvfix 查的表)放在一起对, 回答四个问题:
#     1) 驱动库现在有多大?(INF 数 / 重名 / 体积 / 死包)
#     2) 近10年主流有线芯片 + VMware 两条路是不是都"本 PE 真能绑"?(段感知口径)
#     3) 发布的索引是不是新鲜、自洽?(ID 全在库里、包名全在库里、每 ID <=3 个包、行数对得上)
#     4) 索引引用的包, 驱动库里是否还留着"真能绑到设备的那一份"(老版本被 29_ 挪走不算问题, 全被挪走才是)?
#   全过 -> 打印 GATE PASS, 可以去跑 test\16_InjectNetDrivers.ps1 出 ISO; 任一失败 -> GATE FAIL + 原因。
#
#   2026-10-09 加 -Profile wlan: 无线池(overlay\Drivers\Wlan, 精选档 9 目录/23 INF/360MB)走的是
#   同一套段感知口径和同一份索引自洽检查, 只有两处不一样, 都按 -Profile 切:
#     1) 体积/包数阈值(无线池只有 23 个 INF, 拿有线的 >=120 去卡等于永远红);
#     2) "必测芯片"清单换成 WiFi 芯片(含 2016 老卡 3165、2022+ 的 AX211、Wi-Fi 7 的 BE200,
#        以及 INF 里型号行写成 DEV_7961 的 MT7921 —— 这个 ID 当初差点被我当缺口)。
#
# 普通权限运行(约 1 分钟, 全程只读, 不写任何驱动文件):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\verify_netdrv.ps1
#   ... -Profile wlan            验收无线池 + wlandrv_index.txt
#   ... -Index <p>   换索引文件路径   ... -DrvDir <p>  换驱动目录
# ============================================================
param(
  [ValidateSet('net', 'wlan')][string]$Profile = 'net',
  [string]$DrvDir  = '',
  [string]$Index   = '',
  [string]$Out     = '',
  [string]$Arch     = 'NTamd64',
  [string]$OsVer    = '10.0',
  [int]$Build       = 26100,
  [int]$ProductType = 1,
  [int]$MaxPerId    = 3      # 和 17_ 的默认值保持一致
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $DrvDir) { $DrvDir = Join-Path $Root $(if ($Profile -eq 'wlan') { 'overlay\Drivers\Wlan' } else { 'overlay\Drivers\Net' }) }
if (-not $Index)  { $Index  = Join-Path $Root $(if ($Profile -eq 'wlan') { 'overlay\Scripts\wlandrv_index.txt' } else { 'overlay\Scripts\netdrv_index.txt' }) }
if (-not $Out)    { $Out    = Join-Path $Root $(if ($Profile -eq 'wlan') { 'build\wlandrv_gate.txt' } else { 'build\netdrv_gate.txt' }) }
. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')

$fail = @()
$note = @()
function Chk([bool]$ok, [string]$msg) {
  if ($ok) { Write-Host ('  [OK  ] ' + $msg) }
  else { Write-Host ('  [FAIL] ' + $msg) -ForegroundColor Red; $script:fail += $msg }
}

Write-Host ('==== 网卡驱动验收: ' + $DrvDir + ' ====') -ForegroundColor Cyan
Write-Host '  段感知扫描中(1 分钟以内) ...' -ForegroundColor DarkGray
$pool = Get-NetDrvPool -DrvDir $DrvDir -Arch $Arch -OsVer $OsVer -Build $Build -ProductType $ProductType -ClassName @()
$rows = @($pool.Rows)

# ---------- 1. 驱动库自身 ----------
$names  = @($rows | ForEach-Object { $_.PkgLower } | Sort-Object -Unique)
$dupCnt = $rows.Count - $names.Count
$files  = @(Get-ChildItem $DrvDir -Recurse -File -EA SilentlyContinue)
$mb     = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB, 1)
$dead   = @($rows | Where-Object { $_.Dead })
$usbIds = @($pool.UsbIdx.Keys)
$wiredN = @($rows | Where-Object { -not $_.Wifi }).Count
$wifiN  = @($rows | Where-Object { $_.Wifi }).Count
Write-Host '---- 1) 驱动库 ----' -ForegroundColor Cyan
if ($Profile -eq 'wlan') {
  Chk ($rows.Count -ge 18)                    ('INF ' + $rows.Count + ' 个(精选档 9 目录收进来应有 23 个上下)')
  Chk ($dupCnt -le 2)                         ('同名多份 ' + $dupCnt + ' 份(2 个以内是不同厂商的同名包)')
  Chk ($dead.Count -le 2)                     ('死包 ' + $dead.Count + ' 个(<=2; 生效段为空的包只会让 netdrvfix 白跑一轮 drvload)')
  Chk ($wifiN -ge 15)                         ('无线 Net 包 ' + $wifiN + ' 个(其余是包里的 BT/虚拟网卡 INF, 不算缺口)')
  $note += ('  体积 ' + $mb + ' MB / 文件 ' + $files.Count + ' 个 / 无线包 ' + $wifiN + ' 个 / 非无线 ' + $wiredN + ' 个')
  $note += ('  可绑 USB 无线ID ' + $usbIds.Count + ' 个 —— Usb/Realtek 档就是"板载卡救不活"时的保底')
} else {
  Chk ($rows.Count -ge 120)                  ('INF ' + $rows.Count + ' 个(精简集 64 个 -> 导入后应 >=120)')
  Chk ($dupCnt -le 2)                         ('同名多份的残留 ' + $dupCnt + ' 份(29_ 去重后应 <=2, 留的是"老版本还多绑了 ID"的那种)')
  Chk ($dead.Count -le 12)                    ('死包 ' + $dead.Count + ' 个(<=12; 只剩 Intel 6.2/6.3 档老包, 同芯片由更新档覆盖)')
  Chk ($wiredN -ge 100)                       ('有线 Net 包 ' + $wiredN + ' 个')
  $note += ('  体积 ' + $mb + ' MB / 文件 ' + $files.Count + ' 个 / 无线包 ' + $wifiN + ' 个(本步不收, 看到不算缺口)')
  $note += ('  可绑 USB 网卡ID ' + $usbIds.Count + ' 个 —— 索引里已带 USB\VID 行, netdrvfix v2 会一并处理')
}

# ---------- 2. 芯片覆盖 ----------
$miss = @()
if ($Profile -eq 'wlan') {
  Write-Host '---- 2) 关键 WiFi 芯片(本 PE 生效段里真能绑) ----' -ForegroundColor Cyan
  # 每一档都要有代表: 2016 老卡 / 2018-2020 主力 / 2021+ CNVi / Wi-Fi 7, 外加 MT7921 这种
  # "INF 型号行写的 ID 和市场名不一样"的坑(DEV_7961 才是 MT7921)。
  $must = @(
    @{ id = 'PCI\VEN_8086&DEV_2526'; n = 'Intel Wireless-AC 9260 (本机 ThinkPad, 实机验收第一台)' },
    @{ id = 'PCI\VEN_8086&DEV_3165'; n = 'Intel Wireless-AC 3165 (2016 老卡, 只有 21x 老档里有)' },
    @{ id = 'PCI\VEN_8086&DEV_51F1'; n = 'Intel AX211/AX411 (2022+ 轻薄本 CNVi)' },
    @{ id = 'PCI\VEN_8086&DEV_43F0'; n = 'Intel AX201 家族 (10-11 代 CNVi)' },
    @{ id = 'PCI\VEN_8086&DEV_272B'; n = 'Intel BE200 (Wi-Fi 7, 只在 23x 新档里)' },
    @{ id = 'PCI\VEN_10EC&DEV_8821'; n = 'Realtek RTL8821CE' },
    @{ id = 'PCI\VEN_10EC&DEV_8852'; n = 'Realtek RTL8852BE' },
    @{ id = 'PCI\VEN_10EC&DEV_B822'; n = 'Realtek RTL8822 家族' },
    @{ id = 'PCI\VEN_14C3&DEV_7961'; n = 'MediaTek MT7921 (INF 里型号行就是 DEV_7961&SUBSYS)' },
    @{ id = 'PCI\VEN_14C3&DEV_7922'; n = 'MediaTek MT7922 / RZ616' },
    @{ id = 'PCI\VEN_168C&DEV_0036'; n = 'QualcommAtheros athw10x 老档' },
    @{ id = 'PCI\VEN_17CB&DEV_1107'; n = 'QCA qcwlan64 (WCN3990/QCA685x 新档)' },
    @{ id = 'PCI\VEN_14E4&DEV_43A0'; n = 'Broadcom BCM43A0 (bcmwl63)' },
    @{ id = 'PCI\VEN_1814&DEV_7650'; n = 'Ralink netr28x MT7650/76x0' }
  )
} else {
Write-Host '---- 2) 关键芯片(本 PE 生效段里真能绑) ----' -ForegroundColor Cyan
$must = @(
  @{ id = 'PCI\VEN_10EC&DEV_8168'; n = 'Realtek RTL8111/8168 千兆' },
  @{ id = 'PCI\VEN_10EC&DEV_8136'; n = 'Realtek FastEthernet 8136' },
  @{ id = 'PCI\VEN_10EC&DEV_3000'; n = 'Realtek RTL8111H/G' },
  @{ id = 'PCI\VEN_10EC&DEV_8125'; n = 'Realtek RTL8125 2.5G' },
  @{ id = 'PCI\VEN_10EC&DEV_8127'; n = 'Realtek RTL8126 5G' },
  @{ id = 'PCI\VEN_8086&DEV_15B8'; n = 'Intel I219-V' },
  @{ id = 'PCI\VEN_8086&DEV_15B7'; n = 'Intel I219-LM' },
  @{ id = 'PCI\VEN_8086&DEV_15F3'; n = 'Intel I225-V 2.5G' },
  @{ id = 'PCI\VEN_8086&DEV_5503'; n = 'Intel I226-V 2.5G' },
  @{ id = 'PCI\VEN_8086&DEV_157B'; n = 'Intel I211-AT' },
  @{ id = 'PCI\VEN_8086&DEV_10D3'; n = 'Intel 82574L(VMware e1000e)' },
  @{ id = 'PCI\VEN_15AD&DEV_07B0'; n = 'VMware vmxnet3 半虚拟化' },
  @{ id = 'PCI\VEN_14E4&DEV_1600'; n = 'Broadcom BCM5720' },
  @{ id = 'PCI\VEN_1969&DEV_E0B1'; n = 'Killer E2400' },
  @{ id = 'PCI\VEN_1D6A&DEV_07B1'; n = 'Aquantia AQC107 万兆' }
)
}
foreach ($m in $must) {
  $ok = $pool.Idx.ContainsKey($m.id)
  if (-not $ok) { $miss += ($m.id + ' ' + $m.n) }
}
Chk ($miss.Count -eq 0) ('必测 ' + $must.Count + ' 款芯片可绑 ' + ($must.Count - $miss.Count) + '/' + $must.Count +
  $(if ($miss) { ' —— 缺: ' + ($miss -join ' | ') } elseif ($Profile -eq 'wlan') { ' 全齐(2016 老卡到 Wi-Fi 7)' } else { ' 全齐(含 VMware e1000e/vmxnet3)' }))
if ($Profile -eq 'wlan') {
  Chk ($pool.Idx.Count -ge 140) ('可绑 PCI 无线ID ' + $pool.Idx.Count + ' 种(精选档 9 目录应 >=140)')
  Chk ($pool.UsbIdx.Count -ge 150) ('可绑 USB 无线ID ' + $pool.UsbIdx.Count + ' 种(Usb/Realtek 档应 >=150)')
  # 缺口要说清是哪一种: Decl 里有 = 包声明了但只在低档段(本 PE 绑不上, 换档才有用);
  # Decl 里也没有 = 池子里根本没这块芯片的 INF(只能现场 pe_getdriver)。
  $shadowOnly = @($miss | Where-Object { $pool.Decl.ContainsKey(($_ -split '\s+')[0]) })
  if ($shadowOnly.Count) { $note += ('  其中"只在低档段声明过"的 ' + $shadowOnly.Count + ' 款: ' + (($shadowOnly | ForEach-Object { ($_ -split '\s+')[0] }) -join ' ') + ' —— 换更新/更老的档才有生效段') }
  $note += ('  USB 无线ID ' + $pool.UsbIdx.Count + ' 种 —— netdrvfix v3.1 把无线并进网卡那一轮, USB WiFi 适配器同样能自愈')
} else {
Chk ($pool.Idx.Count -ge 600) ('可绑 PCI 网卡ID ' + $pool.Idx.Count + ' 种(导入前 367, 现在应 >=600)')
# USB 转网线是"板上网卡怎么都起不来"时的保底通道, 只报数不强求(驱动库里有没有得看 19_ 的清单)
$usbMust = @(
  @{ id = 'USB\VID_0BDA&PID_8153'; n = 'Realtek RTL8153' },
  @{ id = 'USB\VID_0B95&PID_1790'; n = 'ASIX AX88179' },
  @{ id = 'USB\VID_0424&PID_9E00'; n = 'SMSC LAN95xx' }
)
$usbMiss = @($usbMust | Where-Object { -not $pool.UsbIdx.ContainsKey($_.id) })
$note += ('  常见 USB 转网线可绑 ' + ($usbMust.Count - $usbMiss.Count) + '/' + $usbMust.Count + $(if ($usbMiss) { ' —— 库里没有: ' + (($usbMiss | ForEach-Object { $_.id + '(' + $_.n + ')' }) -join ' ') } else { ' 全在(USB 网卡也能自愈)' }))
}

# ---------- 3. 索引新鲜且自洽 ----------
Write-Host ('---- 3) 发布给镜像的索引 ' + [IO.Path]::GetFileName($Index) + ' ----') -ForegroundColor Cyan
if (-not (Test-Path $Index)) {
  Chk $false ('索引文件不存在: ' + $Index + ' —— 跑 test\17_MakeNetDrvIndex.ps1 生成')
} else {
  $lines = @(Get-Content -LiteralPath $Index -EA SilentlyContinue | Where-Object { $_ })
  $idxIds = @{}; $idxPkgs = @{}; $perId = @{}; $bad = 0
  foreach ($l in $lines) {
    $p = $l -split "`t"
    if ($p.Count -lt 2) { $bad++; continue }
    $k = $p[0].Trim().ToUpper(); $g = $p[1].Trim().ToLower()
    $idxIds[$k] = 1; $idxPkgs[$g] = 1
    $perId[$k] = 1 + $(if ($perId.ContainsKey($k)) { $perId[$k] } else { 0 })
  }
  $pciKeys = @($idxIds.Keys | Where-Object { $_ -match '^PCI\\VEN_' })
  $usbKeys = @($idxIds.Keys | Where-Object { $_ -match '^USB\\VID_' })
  $otherKeys = @($idxIds.Keys | Where-Object { $_ -notmatch '^(PCI\\VEN_|USB\\VID_)' })
  $orphanPci  = @($pciKeys | Where-Object { -not $pool.Idx.ContainsKey($_) })
  $orphanUsb  = @($usbKeys | Where-Object { -not $pool.UsbIdx.ContainsKey($_) })
  $orphanIds  = @($orphanPci + $orphanUsb + $otherKeys)
  $orphanPkgs = @($idxPkgs.Keys | Where-Object { $names -notcontains $_ })
  $overCap    = @($perId.Keys | Where-Object { $perId[$_] -gt $MaxPerId })
  Chk ($bad -eq 0)                 ('索引行格式 ' + $lines.Count + ' 条全部是 "ID<TAB>包名.inf"')
  Chk ($orphanIds.Count -eq 0)     ('索引里的 ID 都在驱动库的生效段里(孤儿 ID ' + $orphanIds.Count + ' 个' + $(if ($orphanIds) { ': ' + (($orphanIds | Sort-Object) -join ' ') } else { '' }) + ')')
  Chk ($orphanPkgs.Count -eq 0)    ('索引里的包名都还在驱动库里(找不到 INF 的 ' + $orphanPkgs.Count + ' 个' + $(if ($orphanPkgs) { ': ' + (($orphanPkgs | Sort-Object) -join ' ') } else { '' }) + ')')
  Chk ($overCap.Count -eq 0)       ('每个 ID 最多 ' + $MaxPerId + ' 个候选包(超的 ' + $overCap.Count + ' 个)')
  Chk ($pciKeys.Count -eq $pool.Idx.Count) ('索引覆盖 PCI ' + $pciKeys.Count + ' 种 == 驱动库 ' + $pool.Idx.Count + ' 种(一个不落)')
  Chk ($usbKeys.Count -eq $pool.UsbIdx.Count) ('索引覆盖 USB ' + $usbKeys.Count + ' 种 == 驱动库 ' + $pool.UsbIdx.Count + ' 种(第三步要带上 USB 网卡)')
  $missingIds = @(@($pool.Idx.Keys | Where-Object { -not $idxIds.ContainsKey($_) }) + @($pool.UsbIdx.Keys | Where-Object { -not $idxIds.ContainsKey($_) }))
  if ($missingIds.Count) { Chk $false ('驱动库有但索引没有的 ID: ' + (($missingIds | Sort-Object | Select-Object -First 20) -join ' ')) }
  # 索引引用的包名, 在库里必须"至少留着一份真能绑到设备的"(PCI 或 USB 生效段非空)。
  # 注意不能拿 Net_dropped/Net_dead 里有没有同名文件来判断 —— 29_ 去重挪走的正是"同名老版本",
  # 名字当然还会在挪走目录里出现, 那不是问题; 问题是索引指过去之后库里那份是死的。
  $liveByName = @{}
  foreach ($r in $rows) { if ($r.N -gt 0 -or $r.NU -gt 0) { $liveByName[$r.PkgLower] = 1 } }
  $deadRef = @($idxPkgs.Keys | Where-Object { -not $liveByName.ContainsKey($_) })
  Chk ($deadRef.Count -eq 0) ('索引引用的包在库里都有"能绑到设备的那一份"(引用了绑不到东西的 ' + $deadRef.Count + ' 个' + $(if ($deadRef) { ': ' + (($deadRef | Sort-Object) -join ' ') } else { '' }) + ')')
  $note += ('  索引: ' + $Index + '  ' + $lines.Count + ' 行 / PCI ' + $pciKeys.Count + ' + USB ' + $usbKeys.Count + ' 种 ID')
  if (Test-Path ($Index + '.bak')) { $note += ('  上一版备份: netdrv_index.txt.bak (' + @(Get-Content ($Index + '.bak') -EA SilentlyContinue | Where-Object { $_ }).Count + ' 行)') }
}

# ---------- 4. 结论 ----------
Write-Host '---- 4) 结论 ----' -ForegroundColor Cyan
foreach ($n in $note) { Write-Host $n -ForegroundColor DarkGray }
if ($fail.Count -eq 0) {
  Write-Host ('  GATE PASS —— 驱动库与索引自洽(netdrvfix v3.1 的查表前提成立)') -ForegroundColor Green
  if ($Profile -eq 'wlan') {
    Write-Host ('  可以出盘了: 管理员 PowerShell 跑  powershell -NoProfile -ExecutionPolicy Bypass -File patch_wifi.ps1') -ForegroundColor Green
  } else {
    Write-Host ('  可以出盘了: 管理员 PowerShell 跑  powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1') -ForegroundColor Green
  }
} else {
  Write-Host ('  GATE FAIL —— ' + $fail.Count + ' 项没过:') -ForegroundColor Red
  foreach ($f in $fail) { Write-Host ('    * ' + $f) -ForegroundColor Red }
}
$rep = @()
$rep += ('==== ' + $(if ($Profile -eq 'wlan') { '无线' } else { '有线网卡' }) + '驱动池验收 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ====')
$rep += ('结果: ' + $(if ($fail.Count -eq 0) { 'GATE PASS' } else { 'GATE FAIL (' + $fail.Count + ' 项)' }))
$rep += ('驱动库: ' + $DrvDir + ' —— INF ' + $rows.Count + ' / 唯一文件名 ' + $names.Count + ' / 同名残留 ' + $dupCnt + ' / 死包 ' + $dead.Count + ' / ' + $mb + ' MB')
if ($dead.Count) { $rep += ('死包清单: ' + (($dead | ForEach-Object { $_.Pkg + '(' + $_.Dir + ')' }) -join ' | ')) }
$rep += ('可绑: PCI ' + $pool.Idx.Count + ' 种 / USB ' + $pool.UsbIdx.Count + ' 种(索引已同时带两类行)')
$rep += ('必测芯片缺口: ' + $(if ($miss.Count) { ($miss -join ' | ') } else { '无(' + $must.Count + '/' + $must.Count + ')' }))
foreach ($n in $note) { $rep += $n }
if ($fail.Count) { $rep += '未通过项:'; foreach ($f in $fail) { $rep += ('  - ' + $f) } }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Set-Content -LiteralPath $Out -Value $rep -Encoding UTF8
Write-Host ('  详情已写: ' + $Out)
if ($fail.Count) { exit 1 }
exit 0
