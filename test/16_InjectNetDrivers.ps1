# 管理员 PowerShell 运行: 把 overlay\Drivers\Net(万能有线网卡) + overlay\Drivers\Storage(Intel VMD/AHCI/VROC 存储)
#   注入"现成的 boot.wim", 然后直接出 ISO
#   —— 走这条路不用重跑 20 分钟的 copype/组件构建, boot.wim 里 v8 的全部内容(桌面/pe-sshd/固定主机密钥/关防火墙)都还在。
#   网卡驱动从哪来: powershell -NoProfile -ExecutionPolicy Bypass -File test\15_CollectNetDrivers.ps1 -DryRun / (去掉 -DryRun 正式产出)
#   存储驱动从哪来: test\19_ChipChecklist.ps1 挑芯片 -> test\20_ImportNetDrivers.ps1 那套目录, 或直接放好 overlay\Drivers\Storage\<pkg>\*.inf
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1 -SelfTest   # 只查前置条件, 不动盘
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1 -SkipIso    # 只注入, 不出 ISO
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1 -SkipStorage # 只动网卡(回到 v2 的行为)
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\16_InjectNetDrivers.ps1 -IsoTag 1008b   # ISO 叫 WinPE_Desktop_v8_1008b.iso, 不覆盖上一版
param(
  [string]$DrvDir = '',
  [string]$StoDir = '',
  [string]$IsoTag = '',
  [switch]$SkipIso,
  [switch]$SkipStorage,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root    = Split-Path -Parent $PSScriptRoot
. (Join-Path $Root 'test\DismReport.ps1')   # Get-DismPkgReport: 逐包读 DISM 日志, 不让 6/7 冒充成功
$Build   = Join-Path $Root 'build'
$Wim     = Join-Path $Build 'WinPE_amd64\media\sources\boot.wim'
$Mount   = Join-Path $Build 'mount_drv'
$Log     = Join-Path $Build 'scratch\dism_add_netdrv.log'
$LogSto  = Join-Path $Build 'scratch\dism_add_stodrv.log'
$ADK     = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe'
if (-not (Test-Path $ADK)) { $ADK = 'Dism.exe' }
if (-not $DrvDir) { $DrvDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $StoDir) { $StoDir = Join-Path $Root 'overlay\Drivers\Storage' }
# 存储池是"锦上添花"的那一半: 目录没了就跳过, 不能把网卡注入也一起堵死
if (-not $SkipStorage -and -not (Test-Path $StoDir)) {
  Write-Host ('  存储驱动目录不存在, 本次只注入网卡: ' + $StoDir) -ForegroundColor Yellow
  $SkipStorage = $true
}

function Get-FrCount { @(Get-ChildItem (Join-Path $Mount 'Windows\System32\DriverStore\FileRepository') -Directory -EA SilentlyContinue).Count }

if ($SelfTest) {
  Write-Host '=== SelfTest: 只检查前置条件, 不挂载不写盘 ===' -ForegroundColor Cyan
  $bad = 0
  $need = @(@{ n = '网卡驱动目录'; v = $DrvDir }, @{ n = 'boot.wim'; v = $Wim }, @{ n = 'DISM'; v = $ADK })
  if (-not $SkipStorage) { $need += @{ n = '存储驱动目录'; v = $StoDir } }
  foreach ($p in $need) {
    $ok = ($p.v -eq 'Dism.exe') -or (Test-Path $p.v)
    if ($ok) { Write-Host ('  OK   ' + $p.n + ': ' + $p.v) } else { Write-Host ('  !!   ' + $p.n + ' 不存在: ' + $p.v) -ForegroundColor Red; $bad++ }
  }
  $nInf = @(Get-ChildItem $DrvDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
  $list = Join-Path $DrvDir 'inf-list.txt'
  Write-Host ('  网卡 INF: ' + $nInf + ' 个' + $(if (Test-Path $list) { ' (有 inf-list.txt)' } else { ' (无 inf-list.txt, 说明不是 15_ 脚本产出的)' }) + $(if ($nInf -gt 30) { ' -> 数量正常' } else { ' -> 数量偏少, 先跑 test\15_CollectNetDrivers.ps1' }))
  if ($nInf -eq 0) { $bad++ }
  if (-not $SkipStorage) {
    $nSto = @(Get-ChildItem $StoDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
    Write-Host ('  存储 INF: ' + $nSto + ' 个 (' + ((@(Get-ChildItem $StoDir -Directory -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ', ') + ')'))
    if ($nSto -eq 0) { Write-Host '  !! 存储目录是空的' -ForegroundColor Red; $bad++ }
    $need2 = @{ 'iaStorVD.inf' = 'VMD(11-14 代开 VMD 的机器靠它)'; 'iaAHCIC.inf' = 'AHCI/HDC(6-10 代 + 300/400 系 RAID, 看不见 SATA 盘的那一类)' }
    foreach ($k in $need2.Keys) {
      $hit = @(Get-ChildItem $StoDir -Recurse -Filter $k -File -EA SilentlyContinue)
      if ($hit.Count -eq 0) { Write-Host ('  !! 缺 ' + $k + ' -- ' + $need2[$k]) -ForegroundColor Red; $bad++ }
    }
    # 包齐全性门禁提前到 SelfTest: DISM 对"inf 声明的文件不在目录里"只会回一句泛泛的 Error,
    # 而且其余包照样装成功 —— 等到那时才发现就得重来一遍 Commit(10-08 的 iaAHCIC 就是这么漏的)。
    $vsto = Join-Path $Root 'test\verify_stodrv.ps1'
    if (Test-Path $vsto) {
      $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      $vr = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $vsto -DrvDir $StoDir -Quiet 2>&1)
      $vrc = $LASTEXITCODE
      $ErrorActionPreference = $prevEap
      $vLine = (@($vr | Where-Object { $_ -match 'RESULT|FAILURES|COVERAGE total' } | ForEach-Object { "$_" }) -join ' | ')
      Write-Host ('  存储包门禁: ' + $vLine + $(if ($vrc -ne 0) { ' -- 先补齐包再注入' } else { '' }))
      if ($vrc -ne 0) { $bad++ }
    }
    $idxSrc = Join-Path $Root 'overlay\Scripts\stodrv_index.txt'
    Write-Host ('  存储索引: ' + $(if (Test-Path $idxSrc) { '已有旧版, 本次会重算覆盖 ' + $idxSrc } else { '还没有, 本次由 17_ 现算' }))
  } else {
    Write-Host '  本次跳过存储注入(-SkipStorage): 只动网卡, VMD 机器的硬盘照旧看不见' -ForegroundColor Yellow
  }
  if (Test-Path $Wim) { Write-Host ('  boot.wim: ' + (Get-Item $Wim).LastWriteTime + '  ' + ('{0:N0} MB' -f ((Get-Item $Wim).Length / 1MB))) }
  # 顺手自证"逐包解析器"可用: 拿 10-08 那份真日志(7 个包、iaAHCIC 被拒)当样本, 要求 ok+失败 == found
  $histLog = Join-Path $Build 'scratch\dism_add_stodrv.log'
  if (Test-Path $histLog) {
    $hr = Get-DismPkgReport -LogPath $histLog
    Write-Host ('  逐包解析自测: 旧日志 found ' + $hr.found + ' / ok ' + $hr.ok + ' / failed ' + @($hr.failed).Count + ' -> ' + $(if ($hr.found -gt 0 -and ($hr.ok + @($hr.failed).Count) -eq $hr.found) { '一致' } else { '不一致' }))
    if ($hr.found -gt 0 -and ($hr.ok + @($hr.failed).Count) -ne $hr.found) { Write-Host '  !! DISM 逐包解析器和 found 对不上, 部分失败会被漏掉' -ForegroundColor Red; $bad++ }
  }
  Write-Host ('  需要管理员权限, 全程约 5-10 分钟(Commit 最慢)')
  Write-Host ('  计划: 挂载 -> /Add-Driver(网卡) -> /Add-Driver(存储) -> 装 niccheck+netdrvfix v3+两份索引+rescue/storageprobe+BUILD_TAG -> /Unmount-Wim /Commit -> pack_iso.ps1' + $(if ($SkipIso) { '(本次不出 ISO)' } else { '' }))
  if ($bad -eq 0) { Write-Host 'SelfTest OK' -ForegroundColor Green; exit 0 } else { Write-Host "SelfTest 未通过 ($bad 项)" -ForegroundColor Red; exit 1 }
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host '请以管理员 PowerShell 运行本脚本' -ForegroundColor Red; exit 1
}
foreach ($p in @($DrvDir, $Wim)) { if (-not (Test-Path $p)) { Write-Host "缺少 $p (先跑 test\15_CollectNetDrivers.ps1 / build.ps1)" -ForegroundColor Red; exit 1 } }

Write-Host '[1/5] 挂载 boot.wim (1-3 分钟) ...' -ForegroundColor Cyan
if (Test-Path $Mount) { Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
& $ADK /Mount-Wim /WimFile:$Wim /Index:1 /MountDir:$Mount | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $Mount 'Windows\System32'))) {
  Write-Host ('  挂载失败 rc=' + $LASTEXITCODE + ', 清理挂载会话后重试一次') -ForegroundColor Yellow
  & $ADK /Cleanup-Mountpoints | Out-Null
  & $ADK /Mount-Wim /WimFile:$Wim /Index:1 /MountDir:$Mount | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Host '  还是挂不上, 中止(boot.wim 未改动)' -ForegroundColor Red; exit 1 }
}

# ---------- 一轮 DISM /Add-Driver: 返回 (rc, DriverStore 目录增量, 逐包结果) ----------
#   为什么要单独成函数: 网卡池(143 个 inf)和存储池(7 个 inf)是同一条命令、同一套判据,
#   只是"涨了几个目录"的期望值不同。
#   判据是"增量 + rc + 逐包结果"三条: 10-08 那次存储池 7 个包只进了 6 个(iaAHCIC 缺文件),
#   增量 6>0、脚本就当成功了 —— 光看增量会漏掉"部分失败", 所以必须读日志里那行 Installing k of N。
function Add-DrvPool([string]$label, [string]$dir, [string]$log) {
  $b = Get-FrCount
  New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
  # DISM 只要往 stderr 吐一个字, EAP=Stop 就会把它变成终止错误 -> 这段降 Continue, 结果一律看 $LASTEXITCODE
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $ADK /Image:$Mount /Add-Driver /Driver:$dir /Recurse /ForceUnsigned *>&1 | Out-File -FilePath $log -Encoding UTF8
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prevEap
  $a = Get-FrCount
  $n = @(Get-ChildItem $dir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
  Write-Host ('  ' + $label + ': inf ' + $n + ' 个 / DISM rc=' + $rc + ' / DriverStore 目录 ' + $b + ' -> ' + $a)
  $rep = Get-DismPkgReport -LogPath $log
  if ($rep.present) {
    Write-Host ('  ' + $label + ': DISM 逐包 ok ' + $rep.ok + ' / 失败 ' + @($rep.failed).Count + ' / 找到 ' + $rep.found) -ForegroundColor $(if (@($rep.failed).Count) { 'Red' } else { 'Gray' })
    foreach ($f in @($rep.failed)) { Write-Host ('    !! ' + $f) -ForegroundColor Red }
  }
  return @{ rc = $rc; delta = ($a - $b); n = $n; before = $b; after = $a; log = $log; rep = $rep; nfailed = @($rep.failed).Count }
}

Write-Host '[2/5] 注入网卡驱动 ...' -ForegroundColor Cyan
$net = Add-DrvPool '网卡池' $DrvDir $Log
if ($net.delta -lt 10) {
  if ($net.rc -eq 0) {
    Write-Host '  驱动包数量没涨: 这个 boot.wim 应该已经注入过了(DISM rc=0), 重复跑是安全的(已存在的包会被跳过)' -ForegroundColor Yellow
  } else {
    Write-Host '  !! 没注入进去(DISM rc!=0), 日志末尾:' -ForegroundColor Red
    Get-Content $net.log -Tail 25 | ForEach-Object { Write-Host ('    ' + $_) }
  }
}
if ($net.delta -eq 0 -and $net.rc -ne 0) {
  # 一个都没进去还提交/打包就是白等十分钟, 直接丢弃挂载还原 boot.wim
  Write-Host '  中止: 网卡驱动一个都没注入成功, 提交和打包都没有意义 -> /Unmount-Wim /Discard 还原 boot.wim' -ForegroundColor Red
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $ADK /Unmount-Wim /MountDir:$Mount /Discard | Out-Null
  $ErrorActionPreference = $prevEap
  Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue
  exit 1
}

if ($SkipStorage) {
  Write-Host '[2b] 跳过存储驱动注入(-SkipStorage) ...' -ForegroundColor Yellow
  $sto = @{ rc = 0; delta = 0; n = 0; before = $net.after; after = $net.after; log = ''; nfailed = 0; failed = @() }
} else {
  Write-Host '[2b] 注入存储驱动(Intel VMD / AHCI / VROC, 看不见硬盘的那一类) ...' -ForegroundColor Cyan
  $sto = Add-DrvPool '存储池' $StoDir $LogSto
  # 存储池只有 7 个包, 增量 >=1 才算进去了; 全零且 rc!=0 不用中止 —— 网卡已经进去了, 这半是加分项
  if ($sto.delta -eq 0 -and $sto.rc -ne 0) {
    Write-Host '  !! 存储驱动没进去(boot.wim 大约已有这几个包, 或 DISM 拒了), 日志末尾:' -ForegroundColor Red
    Get-Content $sto.log -Tail 20 | ForEach-Object { Write-Host ('    ' + $_) }
    Write-Host '  继续出 ISO: 网卡自愈照旧可用, 只是 VMD 机器还得现场敲 netdrvfix/pe_getdriver' -ForegroundColor Yellow
  }
  # 部分失败必须点名: 10-08 的 iaAHCIC 就是"6/7 成功 + rc=2 + 增量>0"混过去的,
  # 后果是 AHCI/HDC 那一批机器(6-10 代 + 300/400 系 RAID)开 VMD/RAID 时照样看不见盘。
  if ($sto.nfailed -gt 0) {
    Write-Host ('  !! 存储池有 ' + $sto.nfailed + ' 个包被 DISM 拒绝, ISO 里不会有它们的芯片支持:') -ForegroundColor Red
    foreach ($f in @($sto.rep.failed)) { Write-Host ('    !! ' + $f) -ForegroundColor Red }
    Write-Host '     先跑 test\verify_stodrv.ps1(它会检查 [SourceDisksFiles] 声明的文件是否齐全), 补齐后重跑本脚本' -ForegroundColor Yellow
  }
}
if ($net.nfailed -gt 0) {
  Write-Host ('  !! 网卡池有 ' + $net.nfailed + ' 个包被 DISM 拒绝(其余照常生效):') -ForegroundColor Yellow
  foreach ($f in @($net.rep.failed)) { Write-Host ('    !! ' + $f) -ForegroundColor Yellow }
}

Write-Host '[3/5] 装 niccheck / netdrvfix v3 / 取证工具 + 写镜像版本标记 ...' -ForegroundColor Cyan
# 现场排查靠敲长命令粘贴是不现实的(实机反馈: "这个命令太长了"), 所以把自检做进镜像: PE 命令行敲 `niccheck`
# 一次吐出 ISO版本/驱动包数/缺驱动设备的硬件ID/网卡/IP/SSH 状态。BUILD_TAG.txt 则用来证明"烧进去的到底是哪一版"。
$Sys32 = Join-Path $Mount 'Windows\System32'
# startnet.cmd 也要一起更新: 它是 [1a] 自动跑 netdrvfix 的接线点, 而 16_ 不重跑 build.ps1,
# 不拷的话镜像里还是旧 startnet(开机不会自愈, 只能手敲 netdrvfix —— 10-06 13:14 那版就是这样)
# rescue / storageprobe / pe_getdriver 是救援另外三条腿: 取证据、看盘、现场下驱动 —— 一并进 System32, 现场只敲一个词。
foreach ($f in @('niccheck.ps1', 'niccheck.cmd', 'netdrvfix.ps1', 'netdrvfix.cmd', 'startnet.cmd',
                 'rescue.ps1', 'rescue.cmd', 'storageprobe.ps1', 'storageprobe.cmd', 'pe_getdriver.ps1', 'pe_getdriver.cmd')) {
  $src = Join-Path $Root ('overlay\Scripts\' + $f)
  if (-not (Test-Path $src)) { Write-Host "  !! 缺少 $src, 镜像里就没有 $f" -ForegroundColor Red; continue }
  Copy-Item $src (Join-Path $Sys32 $f) -Force
  Write-Host ('  已复制 ' + $f)
}
# 硬件ID->驱动包 索引: PE 里解析几百个 UTF-16 INF 太慢, 构建期算一次拷进去给 netdrvfix 查表
#   网卡索引 netdrv_index.txt + 存储索引 stodrv_index.txt, 都由 17_ 的同一套"段感知"口径生成
$IdxFile  = Join-Path $Root 'overlay\Scripts\netdrv_index.txt'
$StoIdxF  = Join-Path $Root 'overlay\Scripts\stodrv_index.txt'
& (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1') -DrvDir $DrvDir -Out $IdxFile
$StoIdxF = Join-Path $Root 'overlay\Scripts\stodrv_index.txt'
if (Test-Path $IdxFile) { Copy-Item $IdxFile $Sys32 -Force; Write-Host ('  已装 netdrv_index.txt (' + [math]::Round((Get-Item $IdxFile).Length / 1KB, 1) + ' KB)') }
else { Write-Host '  !! 网卡索引没生成, netdrvfix 在镜像里会直接退出' -ForegroundColor Red }
if (-not $SkipStorage) {
  & (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1') -DrvDir $StoDir -Out $StoIdxF
  if (Test-Path $StoIdxF) { Copy-Item $StoIdxF $Sys32 -Force; Write-Host ('  已装 stodrv_index.txt (' + [math]::Round((Get-Item $StoIdxF).Length / 1KB, 1) + ' KB)') }
  else { Write-Host '  !! 存储索引没生成: 镜像里 netdrvfix 会打 WARN 并只做网卡那一半' -ForegroundColor Yellow }
}
function Count-IdxIds([string]$file) {
  $p = 0; $u = 0
  if (-not (Test-Path $file)) { return @{ Pci = $p; Usb = $u } }
  $seen = @{}
  foreach ($l in @(Get-Content -LiteralPath $file -EA SilentlyContinue)) {
    $t = ($l -split "`t")[0].Trim().ToUpper()
    if (-not $t -or $seen.ContainsKey($t)) { continue }
    $seen[$t] = 1
    if ($t -like 'PCI\VEN_*') { $p++ } elseif ($t -like 'USB\VID_*') { $u++ }
  }
  return @{ Pci = $p; Usb = $u }
}
$netInf = @(Get-ChildItem $DrvDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
$stoInf = $(if ($SkipStorage) { 0 } else { @(Get-ChildItem $StoDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count })
$idn = Count-IdxIds $IdxFile
$ids = Count-IdxIds $StoIdxF
$fixVer = 'unknown'
$nfSrc = Join-Path $Root 'overlay\Scripts\netdrvfix.ps1'
if (Test-Path $nfSrc) { $m = [regex]::Match((Get-Content $nfSrc -Raw -EA SilentlyContinue), 'netdrvfix/\d+\.\d+'); if ($m.Success) { $fixVer = $m.Value } }
# BUILD_TAG 是现场唯一能看到的"这版 ISO 里到底有什么", 所以被 DISM 拒绝的包要直接写进去,
# 免得又出现"日志显示 7 个包, 镜像里其实只有 6 个"这种事。
$stoRej = ''
$netRej = ''
if (-not $SkipStorage) {
  $rj = @($sto.rep.failed | ForEach-Object { (($_ -split '::')[0]).Trim() })
  $stoRej = $(if ($rj.Count) { ' / REJECTED ' + (($rj | Select-Object -First 6) -join ' ') } else { ' / all accepted' })
}
$rjN = @($net.rep.failed | ForEach-Object { (($_ -split '::')[0]).Trim() })
if ($rjN.Count) { $netRej = ' / REJECTED ' + (($rjN | Select-Object -First 6) -join ' ') }
$tag = @(
  ('build   = ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
  ('netdrv  = inf ' + $netInf + ' / DriverStore ' + $net.before + '->' + $net.after + ' / index ids ' + $idn.Pci + ' PCI + ' + $idn.Usb + ' USB' + $netRej),
  ('stodrv  = ' + $(if ($SkipStorage) { 'skipped (-SkipStorage)' } else { 'inf ' + $stoInf + ' / DriverStore ' + $sto.before + '->' + $sto.after + ' / index ids ' + $ids.Pci + ' PCI (Intel VMD/AHCI/VROC)' + $stoRej })),
  ('tools   = niccheck / ' + $fixVer + '  (runs at boot: startnet [1a]; code18=pnputil remove+scan, code28=drvload/add-driver; NIC round first, storage round second)'),
  ('rescue  = rescue / storageprobe / pe_getdriver in System32 (verdict: disks a->b + sysdisk=ok|missing in status.txt)'),
  ('logs    = X:\netdrvfix.log X:\niccheck.txt X:\status.txt -> also copied to USB:\winpe_logs'),
  ('product = WinPE_Desktop_v8 (drivers patched by 16_InjectNetDrivers.ps1)')
) -join "`r`n"
Set-Content -Path (Join-Path $Mount 'BUILD_TAG.txt') -Value $tag -Encoding ASCII -NoNewline
Write-Host ('  已写 X:\BUILD_TAG.txt: ' + (($tag -split "`r`n")[0] + ' / ' + ($tag -split "`r`n")[1] + ' / ' + ($tag -split "`r`n")[2]))

Write-Host '[4/5] 卸载并提交进 boot.wim (最慢的一步, 3-6 分钟) ...' -ForegroundColor Cyan
$committed = $false
foreach ($try in 1..2) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  & $ADK /Unmount-Wim /MountDir:$Mount /Commit | Out-Null
  if ($LASTEXITCODE -eq 0) { $committed = $true; break }
  Write-Host ('  Commit 失败 rc=' + $LASTEXITCODE + ' (第 ' + $try + ' 次), 清理挂载会话后重试' ) -ForegroundColor Yellow
  & $ADK /Cleanup-Mountpoints | Out-Null
  Start-Sleep -Seconds 3
}
if (-not $committed) {
  Write-Host '  !! 提交失败: 驱动没进 boot.wim。可以先手工收尾再重跑本脚本:' -ForegroundColor Red
  Write-Host ('     "' + $ADK + '" /Unmount-Wim /MountDir:' + $Mount + ' /Discard') -ForegroundColor Yellow
  exit 1
}
Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('  boot.wim: ' + (Get-Item $Wim).LastWriteTime + '  ' + ('{0:N0} MB' -f ((Get-Item $Wim).Length / 1MB))) -ForegroundColor Green

if ($SkipIso) { Write-Host '  -SkipIso: 到此为止, 没出 ISO'; exit 0 }
Write-Host '[5/5] 打包 ISO ...' -ForegroundColor Cyan
& (Join-Path $Root 'test\pack_iso.ps1') -Tag $IsoTag
Write-Host ('  下一步: 用 -IsoTag 出的那个新 ISO 拷进 U 盘(Ventoy 直接拷)。开机自动跑 netdrvfix v3: 先网卡后存储, ' +
  'code18 用 pnputil remove-device+scan-devices, code28 用 drvload/pnputil /add-driver, ' +
  '判据 = 设备 problem code 归零 + 物理网卡数 + 盘数(disks a->b) + 固定盘上有没有 \Windows(sysdisk=ok)。 ' +
  '验收办法: BIOS 保持 VMD 开启, 启动这版 ISO, 不要手敲任何命令, 直接看 X:\status.txt 里的 stor=/disks=/sysdisk=; ' +
  '现场再敲 niccheck / storageprobe / rescue, 日志会自动拷到 U 盘的 winpe_logs 目录') -ForegroundColor Cyan
