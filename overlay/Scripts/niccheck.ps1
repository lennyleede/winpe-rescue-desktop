# ============================================================
# niccheck.ps1 (v3, 2026-10-08) —— PE 现场自检: 在 PE 命令行里敲 `niccheck` 就行
#
#   v2 改了三件事:
#     1) NETDRV 计数不再用写死的驱动名前缀白名单(老口径会把 yt640 之类漏掉),
#        改成拿开机查的 netdrv_index.txt 里的包名去 DriverStore 里对, 对不上就是真缺;
#     2) 缺驱动的设备按 problem code 说人话: 18 = 装一半没装完(netdrvfix 会 remove-device + 重扫),
#        28 = 压根没驱动(netdrvfix 会 drvload / pnputil /add-driver), 并标出这块卡在不在索引里;
#     3) 结果自动回传: 除了写 X:\niccheck.txt(UTF-8, 能从 ssh 里 type), 还把日志拷到 U 盘 winpe_logs\,
#        网卡没起来、ssh 不通的时候把 U 盘插别的电脑就能拿到日志(末行 VERDICT 是纯 ASCII, 拍照也能读)。
#
#   v3 把"看不见硬盘"这半边也纳入自检(12 代 i5 实机: BIOS 开 VMD 时 NVMe 和 SATA 都藏在 iaStorVD 后面):
#     4) STODRV  = stodrv_index.txt 里那些存储驱动包到底进没进 DriverStore(烘没烘进镜像一目了然);
#     5) DISKS / SYSDISK = 几块物理盘、固定盘上有没有 \Windows —— 救援的硬判据, 比"驱动装了几个"有用;
#     6) VERDICT 追加 disks=/sysdisk=, ACTION 会区分"控制器没绑(敲 netdrvfix)"和"芯片压根不在索引(敲 storageprobe/pe_getdriver)"。
#
#   只用 WinPE 里确实存在的工具: Get-CimInstance / Get-Disk / netstat / Select-String (PE 没有 findstr/Get-NetAdapter)
#   宿主机试跑: powershell -NoProfile -ExecutionPolicy Bypass -File overlay\Scripts\niccheck.ps1 -NoFile -NoCopy
# ============================================================
param(
  [switch]$NoFile,
  [switch]$NoCopy,
  [string]$IdxPath = '',
  [string]$StoIdxPath = '',
  [string]$FrPath  = '',
  [string]$CopyTo  = ''      # 强制回传目标卷, 例如 E:
)
$ErrorActionPreference = 'Continue'
$sysRoot = $env:SystemRoot
$volRoot = Split-Path $sysRoot -Parent          # PE 里通常是 X:\
$fr      = if ($FrPath)  { $FrPath }  else { Join-Path $sysRoot 'System32\DriverStore\FileRepository' }
$idxFile = if ($IdxPath) { $IdxPath } else { Join-Path $sysRoot 'System32\netdrv_index.txt' }
$stoFile = if ($StoIdxPath) { $StoIdxPath } else { Join-Path $sysRoot 'System32\stodrv_index.txt' }
$lines   = @()
function O([string]$s) { $script:lines += $s; Write-Host $s }
function A([string]$s) { $script:lines += $s; Write-Host (($s) -replace '[^\x20-\x7E]', '?') }   # 纯 ASCII 行: 拍照也能读

# 1) 我烧进去的是哪一版? (没有这行说明镜像比 niccheck 还早)
$tag = Join-Path $volRoot 'BUILD_TAG.txt'
if (Test-Path $tag) { O ('ISO    = ' + ((Get-Content $tag -Raw) -replace '\s+', ' ')) }
else { O 'ISO    = 这个镜像里没有 BUILD_TAG.txt, 说明是加 niccheck 之前出的盘' }

# 2) 万能网卡驱动在不在 —— 口径: 拿 netdrvfix 查的那张表里的包名, 去 DriverStore 里一个个对
$d = @(Get-ChildItem $fr -Directory -EA SilentlyContinue)
$toks = @{}
foreach ($x in $d) {
  $n = $x.Name.ToLower()
  $m = [regex]::Match($n, '^(.+?)[_.]inf')      # rt640x64.inf_amd64_xxx -> rt640x64.inf
  if ($m.Success) { $toks[$m.Groups[1].Value + '.inf'] = 1 }
}
$pkgs = @(); $keys = @{}
if (Test-Path $idxFile) {
  foreach ($l in @(Get-Content -LiteralPath $idxFile -EA SilentlyContinue)) {
    $p = $l -split "`t"
    if ($p.Count -lt 2) { continue }
    $keys[$p[0].Trim().ToUpper()] = 1
    $g = $p[1].Trim().ToLower()
    if ($g -and ($pkgs -notcontains $g)) { $pkgs += $g }
  }
}
$present = @($pkgs | Where-Object { $toks.ContainsKey($_) })
$absent  = @($pkgs | Where-Object { -not $toks.ContainsKey($_) })
$usbKeyN = @($keys.Keys | Where-Object { $_ -like 'USB\VID_*' }).Count
O ('NETDRV = 索引里的网卡驱动包在库里 ' + $present.Count + '/' + $pkgs.Count + ' 个 (驱动库共 ' + $d.Count + ' 个目录, 其中带 .inf 的 ' + $toks.Count + ' 种)')
O ('        索引覆盖硬件ID ' + $keys.Count + ' 种 (PCI ' + (@($keys.Keys | Where-Object { $_ -like 'PCI\VEN_*' }).Count) + ' + USB ' + $usbKeyN + ') —— 索引文件 ' + (Split-Path -Leaf $idxFile))
if ($absent.Count -gt 0) {
  $show = @($absent | Select-Object -First 8)
  O ('        !! 索引指向但库里找不到: ' + ($show -join ' ') + $(if ($absent.Count -gt 8) { ' …共 ' + $absent.Count + ' 个' } else { '' }))
}
if ($pkgs.Count -eq 0) { O '        !! 索引是空的/不存在, 这个镜像的 netdrvfix 帮不上忙(比第二步的出盘还早)' }

# 2b) 存储驱动(VMD/AHCI/VROC)在不在 —— "看不见硬盘"和"看不见网卡"是救援现场的两条命门, 一条命令要都答完
$spkgs = @(); $skeys = @{}
if (Test-Path $stoFile) {
  foreach ($l in @(Get-Content -LiteralPath $stoFile -EA SilentlyContinue)) {
    $p = $l -split "`t"
    if ($p.Count -lt 2) { continue }
    $skeys[$p[0].Trim().ToUpper()] = 1
    $g = $p[1].Trim().ToLower()
    if ($g -and ($spkgs -notcontains $g)) { $spkgs += $g }
  }
  $spresent = @($spkgs | Where-Object { $toks.ContainsKey($_) })
  $sabsent  = @($spkgs | Where-Object { -not $toks.ContainsKey($_) })
  O ('STODRV = 索引里的存储驱动包在库里 ' + $spresent.Count + '/' + $spkgs.Count + ' 个, 覆盖硬件ID ' + $skeys.Count + ' 种 (Intel VMD/AHCI/VROC) —— 索引文件 ' + (Split-Path -Leaf $stoFile))
  if ($sabsent.Count -gt 0) { O ('        !! 索引指向但库里找不到: ' + (($sabsent | Select-Object -First 8) -join ' ')) }
} else {
  O ('STODRV = 没有 ' + (Split-Path -Leaf $stoFile) + ' —— 这个镜像还没烘存储驱动, 开 VMD 的机器看不见硬盘时只能现场下载(pe_getdriver)')
}

# 2c) 盘到底有没有 —— 救援能不能往下走就看这两行(固定盘上的 \Windows = 客户的系统盘)
$dk = @(); $dkErr = $false
try { $dk = @(Get-Disk -EA SilentlyContinue) } catch { $dkErr = $true }
if ($dkErr) {
  $w = @(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue)
  O ('DISKS    = Get-Disk 用不了, WMI 认出 ' + $w.Count + ' 块物理盘')
  $dkN = $w.Count
} else {
  $dkN = $dk.Count
  O ('DISKS    = ' + $dkN + ' 块物理盘')
  foreach ($x in $dk) { O ('           #' + $x.Number + ' ' + $x.FriendlyName + '  bus=' + $x.BusType + '  ' + [math]::Round($x.Size / 1GB, 0) + 'GB  style=' + $x.PartitionStyle + '  health=' + $x.HealthStatus) }
}
$sysHits = @()
$sysLetter = $volRoot.Substring(0, 1).ToUpper()
foreach ($v in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)) {
  if ([int]$v.DriveType -ne 3) { continue }                  # 只认固定盘: X: 内存盘里也有 \Windows
  $lv = "$($v.DeviceID)".TrimEnd('\')
  if ($lv.Substring(0, 1).ToUpper() -eq $sysLetter) { continue }
  if (Test-Path (Join-Path $lv 'Windows')) { $sysHits += $lv }
}
A ('SYSDISK  = ' + $(if ($sysHits.Count -gt 0) { 'ok (' + ($sysHits -join ',') + ' has \Windows)' } else { 'missing (no fixed drive holds \Windows -- offline repair is impossible)' }))

# 3) 有没有设备还缺驱动 —— 这行直接给出"还缺哪块卡"的 VEN/DEV 与 problem code
$devs = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.ConfigManagerErrorCode -gt 0 })
$badNet = @($devs | Where-Object { $up = "$($_.DeviceID)".ToUpper(); $up -like 'PCI\VEN_*' -or $up -like 'USB\VID_*' })
$codeMean = @{ 18 = '驱动装一半没完成(netdrvfix 走 remove-device+scan)'; 28 = '没找到驱动(netdrvfix 走 drvload)'; 10 = '驱动起来了但启动失败'; 3 = '驱动/系统配置有问题'; 31 = '驱动加载失败'; 37 = '设备硬件故障' }
if ($devs.Count -eq 0) { O 'PROBLEMDRV = 无 (所有设备都拿到驱动了)' }
else {
  O ('PROBLEMDRV = ' + $devs.Count + ' 个设备缺驱动/启动失败, 其中网卡类 ' + $badNet.Count + ' 个:')
  foreach ($b in ($devs | Select-Object -First 14)) {
    $mm = $codeMean[[int]$b.ConfigManagerErrorCode]
    if (-not $mm) { $mm = 'code ' + $b.ConfigManagerErrorCode }
    O ('           code' + $b.ConfigManagerErrorCode + '  ' + $b.DeviceID + '  | ' + $b.Name + '  —— ' + $mm)
  }
  if ($devs.Count -gt 14) { O ('           ... 还有 ' + ($devs.Count - 14) + ' 个') }
}
# 只有"这块卡确实在两份索引之一里"才提示修, 否则声卡/显卡也会触发误报
#   归一口径和 netdrvfix / 17_ 一致: 剥 &SUBSYS/&REV/&MI/&CC(Intel 存储包的 INF 都写 &CC_0106)
$unbound = @(); $unboundSto = @(); $notidx = @()
foreach ($b in $badNet) {
  $parts = ("$b.DeviceID").ToUpper() -split '\\'
  $hw = if ($parts.Count -ge 2) { $parts[0] + '\' + $parts[1] } else { $parts[0] }
  $kk = ((($hw -split '&SUBSYS|&REV|&MI|&CC')[0]).TrimEnd('&')).TrimEnd('\')
  if ($keys.ContainsKey($kk)) { $unbound += $kk }
  elseif ($skeys.ContainsKey($kk) -and $kk -like 'PCI\VEN_*') { $unboundSto += $kk }
  else { $notidx += $kk }
}
$unbound = @($unbound | Select-Object -Unique)
$unboundSto = @($unboundSto | Select-Object -Unique)
$notidx  = @($notidx  | Select-Object -Unique)
if ($unbound.Count -gt 0) {
  O ('HINT     = 有网卡没绑上驱动 (' + ($unbound -join ', ') + ') —— 敲 netdrvfix 回车, 日志 X:\netdrvfix.log')
} elseif ($unboundSto.Count -gt 0) {
  O ('HINT     = 有存储控制器没绑上驱动 (' + ($unboundSto -join ', ') + ') —— 敲 netdrvfix 回车(v3 第二轮专管这个), 硬盘多半就是因此看不见')
} elseif ($badNet.Count -gt 0) {
  O ('HINT     = 有带问题的设备(' + ($notidx -join ', ') + ')不在网卡/存储索引里, 多半是声卡/显卡/读卡器; 真要这块芯片的驱动就敲 pe_getdriver')
}

# 4) 上一次 netdrvfix 干了什么 (开机 startnet 已经自动跑过一次)
$st = Join-Path $volRoot 'status.txt'
$fixLine = ''
if (Test-Path $st) {
  $f = @(Get-Content -LiteralPath $st -EA SilentlyContinue | Select-String -Pattern 'netdrvfix=' -SimpleMatch)
  if ($f.Count -gt 0) { $fixLine = "$($f[-1])" }
}
$lg = Join-Path $volRoot 'netdrvfix.log'
$ver = 'v1(只会 drvload, 老镜像)'
if (Test-Path $lg) {
  $lgTxt = @(Get-Content -LiteralPath $lg -EA SilentlyContinue)
  if (@($lgTxt | Select-String -Pattern 'netdrvfix/2.0' -SimpleMatch).Count -gt 0) { $ver = 'v2(按 problem code 分流 + pnputil 兜底)' }
  if (@($lgTxt | Select-String -Pattern 'netdrvfix/3.0' -SimpleMatch).Count -gt 0) { $ver = 'v3(网卡一轮 + 存储一轮, 判据含 disks/sysdisk)' }
  # 3.1/3.2 起不能再靠"数固定字符串"认版本(2026-10-12: overlay 已到 netdrvfix/3.2, 上面两条都不命中,
  # 这行读数会退回 v1 = 把新盘说成老镜像)。改成: 抓日志里最后一个 netdrvfix/x.y 原样报出来, 命中 3.x 就算 v3。
  $lgVer = ''
  foreach ($t in @($lgTxt)) { if (("$t" -match 'netdrvfix/(\d+\.\d+)')) { $lgVer = 'netdrvfix/' + $matches[1] } }
  if ($lgVer -match '/3\.') { $ver = 'v3(网卡一轮 + 存储一轮, 判据含 disks/sysdisk)' }
  elseif ($lgVer -match '/2\.') { $ver = 'v2(按 problem code 分流 + pnputil 兜底)' }
  if ($lgVer) { $ver = $ver + ' ' + $lgVer }
}
if ($fixLine) { O ('FIX      = ' + ($fixLine -replace '\s+', ' ') + '   [netdrvfix ' + $ver + ']') }
else { O ('FIX      = status.txt 里没有 netdrvfix= 这行(开机那次可能没跑成)  [netdrvfix ' + $ver + ']') }
if (Test-Path $lg) {
  $tail = @(Get-Content -LiteralPath $lg -EA SilentlyContinue) | Select-Object -Last 12
  O ('FIXLOG   = 最后 ' + $tail.Count + ' 行 (' + $lg + '):')
  foreach ($t in $tail) { A ('           ' + $t) }
} else { O 'FIXLOG   = 还没有 X:\netdrvfix.log (netdrvfix 没跑过)' }

# 5) 系统认到的物理网卡与 IP
$ad = @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.PhysicalAdapter })
O ('ADAPTER  = ' + $ad.Count + ' 块物理网卡')
foreach ($a in $ad) { O ('           ' + $a.Name + '  NetConnectionStatus=' + $a.NetConnectionStatus + '  (' + $a.NetConnectionID + ')') }
$ip = @(Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue | Where-Object { $_.IPEnabled })
if ($ip.Count -eq 0) { O 'IP       = 没有已启用 TCP/IP 的适配器 (驱动没上 或 没拿到地址)' }
else {
  foreach ($i in $ip) {
    # 两个网关属性都试: DefaultGateway_IPAddress 在部分 PE 上是空的, DefaultIPGateway 才有值
    $gw = @($i.DefaultGateway_IPAddress) + @($i.DefaultIPGateway) | Where-Object { "$_" } | Select-Object -First 1
    O ('IP       = ' + ($i.IPAddress -join ',') + '  gw=' + $gw)
  }
}

# 6) SSH 服务端在不在听 22
$ls = @(netstat -ano -p TCP 2>$null | Select-String ':22 ')
A ('SSH22    = ' + $(if ($ls.Count -gt 0) { 'LISTENING' } else { 'NOT listening (pe-sshd did not start)' }))

# 7) 一句话结论(纯 ASCII, 屏摄也能读) —— 网卡与硬盘两条命门一起报
$verdict = 'NIC_UP'
if ($ad.Count -eq 0) { $verdict = 'NO_ADAPTER' }
elseif ($ip.Count -eq 0) { $verdict = 'ADAPTER_NO_IP' }
if ($unbound.Count -gt 0) { $verdict = 'NEED_NETDRVFIX' }
$sysTok = $(if ($sysHits.Count -gt 0) { 'ok' } else { 'missing' })
A ('VERDICT  = ' + $verdict + '  devs_problem=' + $badNet.Count + '  adapters=' + $ad.Count + '  tcpip=' + $ip.Count + '  ssh22=' + $(if ($ls.Count -gt 0) { 'up' } else { 'down' }) + '  disks=' + $dkN + '  sysdisk=' + $sysTok)
if ($verdict -eq 'NEED_NETDRVFIX') { A 'ACTION   = type: netdrvfix   (then re-run niccheck)' }
elseif ($verdict -eq 'ADAPTER_NO_IP') { A 'ACTION   = check cable/switch, type: ipconfig /renew' }
elseif ($verdict -eq 'NO_ADAPTER') { A 'ACTION   = type: netdrvfix ; if it stays NO_ADAPTER the chip is not in the pool, photograph X:\netdrvfix.log' }
if ($sysTok -eq 'missing') {
  if ($unboundSto.Count -gt 0) { A 'ACTION   = disks missing because a storage controller is unbound: type: netdrvfix' }
  else { A 'ACTION   = no fixed drive holds \Windows: type: storageprobe (is the chip in the index at all?), then pe_getdriver to fetch a driver over the network' }
} else { A ('ACTION   = client OS volume is visible on ' + ($sysHits -join ',') + ': type: rescue to pull hives/dumps/events') }

if (-not $NoFile) { try { Set-Content -LiteralPath (Join-Path $volRoot 'niccheck.txt') -Value ($lines -join "`r`n") -Encoding UTF8 } catch { } }

# 8) 回传: 把日志拷到 U 盘(网卡没起来、ssh 不通时唯一能把日志带走的办法)
function Get-UsbLetters {
  $set = @{}
  foreach ($dd in @(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue | Where-Object { "$($_.InterfaceType)".ToUpper() -eq 'USB' })) {
    $q1 = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $dd.DeviceID + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
    foreach ($p in @(Get-CimInstance -Query $q1 -EA SilentlyContinue)) {
      $q2 = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $p.DeviceID + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"
      foreach ($ld in @(Get-CimInstance -Query $q2 -EA SilentlyContinue)) {
        $lv = "$($ld.DeviceID)".TrimEnd('\')        # Win32 有时给 'G:' 有时给 'G:\' —— 不归一这行就永远匹配不上, U 盘回传会静默失效
        if ($lv -match '^[A-Za-z]:$') { $set[$lv.Substring(0, 1).ToUpper()] = 1 }
      }
    }
  }
  foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue | Where-Object { $_.DriveType -eq 2 })) {
    $lv = "$($ld.DeviceID)".TrimEnd('\')
    if ($lv -match '^[A-Za-z]:$') { $set[$lv.Substring(0, 1).ToUpper()] = 1 }
  }
  $sysLetter = $volRoot.Substring(0, 1).ToUpper()
  return @($set.Keys | Where-Object { $_ -ne $sysLetter } | Sort-Object)
}
if (-not $NoCopy) {
  $cands = @()
  if ($CopyTo) { $cands = @(($CopyTo -replace '[:\\]', '').ToUpper()) } else { $cands = @(Get-UsbLetters) }
  if (-not (Test-Path (Join-Path $volRoot 'niccheck.txt'))) { try { Set-Content -LiteralPath (Join-Path $volRoot 'niccheck.txt') -Value ($lines -join "`r`n") -Encoding UTF8 -EA Stop } catch { } }
  $files = @((Join-Path $volRoot 'niccheck.txt'), $lg, $st, (Join-Path $volRoot 'boot.log')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
  $copied = ''
  foreach ($lv in $cands) {
    $dir = $lv + ':\winpe_logs'
    try {
      if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir -EA Stop | Out-Null }
      foreach ($f in $files) { Copy-Item -LiteralPath $f -Destination $dir -Force -EA Stop }
      $copied = $dir
      break
    } catch { }
  }
  if ($copied) { A ('LOGCOPY  = ' + $copied + ' <- niccheck.txt, netdrvfix.log, status.txt, boot.log') }
  else { A 'LOGCOPY  = no writable USB volume (plug in the boot stick, or run: niccheck -CopyTo E:)' }
}
