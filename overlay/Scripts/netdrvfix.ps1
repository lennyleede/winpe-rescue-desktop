# ============================================================
# netdrvfix.ps1 (v3.1, 2026-10-09) —— 开机后把"驱动在库里、设备却没起来"的网卡(有线+无线)**和存储控制器**一起修好
#
#   为什么不能只靠 drvload(2026-10-08 VMware e1000e 实机定案):
#     problem code 18 = CM_PROB_REINSTALL("Reinstall the drivers for this device"),
#     官方语义是"这块卡的驱动装到一半没装完" —— PE 里表现为 PNPClass 还是 Unknown、物理网卡 0 块。
#     微软 Drvload 文档: "If the driver .inf file requires a reboot, Windows PE will ignore the request",
#     而且它照样返回 rc=0(实测同时打印了 Unable to load ... Error 0x80078103) —— 所以 v1 拿 $LASTEXITCODE
#     当成功判据是错的。code 18 的正解是设备管理器那套"卸载设备 + 扫描硬件改动":
#     pnputil /remove-device <实例ID> 再 pnputil /scan-devices; 重扫后通常变成 code 28, 那时才轮到 drvload。
#     problem code 28 = CM_PROB_FAILED_INSTALL(真·没驱动): drvload <inf>, 不行再 pnputil /add-driver <inf> /install。
#
#   v2 的规则:
#     1) 按 problem code 分流(18 -> 摘 devnode 重扫; 28/其它 -> drvload -> pnputil 入库+装), 每台设备动作有上限;
#     2) 成功判据 = 复查该设备 problem code 是否归零 + 物理网卡数 + 有没有 IP, 不看命令返回码;
#     3) 某块卡一旦归零就不再对它重复试;
#     4) 日志 X:\netdrvfix.log 正文只用 ASCII/英文(PE 控制台会把中文打成 ?, 现场要靠拍照); 中文解释看 niccheck;
#     5) X:\status.txt 写 netdrvfix=ok / partial(装上但没地址) / noop(本来就没得修) / fail;
#     6) 没网也能回传: 自动把 netdrvfix.log / status.txt / niccheck.txt 拷到 U 盘的 winpe_logs\;
#     7) 查表同时支持 PCI\VEN_* 与 USB\VID_*(USB 转网线是板载卡起不来时的保底通道)。
#
#   v3 加的正是"硬盘看不见"这条命门(2026-10-08 12 代 i5 实机定案):
#     BIOS 开 Intel VMD 时, NVMe 和 SATA **都**挂在 VMD 控制器下(DEV_467F code28), PE 只枚举出启动 U 盘,
#     手工 drvload iaStorVD.inf 后盘数 1->3、D:\Windows 出现。v3 就是把这套动作并进开机自愈:
#       a) 查表用两份索引: netdrv_index.txt(网卡) + stodrv_index.txt(存储, 缺了只 WARN 不 ABORT —— 老镜像照样能跑);
#       b) 顺序 = 先网卡后存储(网卡先起来才有 SSH/frp/下载通道; 存储不依赖网络, 放后面不影响救援);
#       c) 存储这轮只碰 PCI\VEN_ 键, 绝不因为某个 USB\VID 恰好撞进索引就去 /remove-device 启动 U 盘;
#       d) 判据加两条硬证据: Get-Disk 台数 before->after、固定盘上有没有 \Windows(sysdisk=ok|missing) ——
#          drvload 返回码永远不能当判据(见上), 而"盘回来了没有"才是救援要的答复。
#
#   v3.1 加的是第三份表 —— 无线网卡(2026-10-09):
#     WiFi 芯片和有线芯片在 PnP 层面是同一回事(code 28 = 没驱动, drvload 那条 INF 就绑上了),
#     所以不新写一套流程, 只把 overlay\Drivers\Wlan 生成的 wlandrv_index.txt 并进"网卡那一轮":
#       a) 查表现在三份: netdrv_index.txt(有线) + wlandrv_index.txt(无线) + stodrv_index.txt(存储),
#          两份网卡表合并成候选包列表, 同一个 ID 谁在前不影响(包名去重);
#       b) 无线表缺了同样只 WARN 不 ABORT(老镜像里没有这个文件, 不能因此把自愈整个关掉);
#       c) 绑上驱动 != 能上网: WiFi 还要 wlansvc + 配置文件, 所以判据里单列 wifi=bound/none,
#          并在"网起来了但没地址"时给出 `wlan.cmd` 这条下一步(有线不会走到这里, 别浪费时间)。
#
#   v3.2 加的是 WiFi 的"绑定层"(2026-10-12 实机 192.168.0.102 定案, 任务 #38/#41):
#     那张盘的 WiFi 芯片 code 0、WDI 框架 Running, 但 wlansvc 仍然没有接口可管 —— 因为
#     miniport 后面该挂的 nativewifip / vwififlt / vwifibus 一个都没挂上:
#       读数: 适配器 class 键的 Linkage\FilterList 整条不存在(wifi_entries=0) + devnode UpperFilters 为空;
#       而且**离线烘进 Control\Network 的组件记录不会让 PnP 去绑**(烘记录 != 会绑, 这条否定了
#       "照抄 WinRE 两棵树就等价于微软做法"的期待), 剩下的只有开机后把 netcfg 的活儿自己补上。
#     实测有效的两个钩子(所以 v3.2 就照这个做, 顺序也照实测):
#       1) netcfg -v -l <netnwifi.inf> -c s -i MS_NativeWifiP   -> FilterList +1, nativewifip Running
#          netcfg -v -l <netvwififlt.inf> -c s -i ms_vwifi      -> FilterList +1, vwififlt Running
#          INF 用镜像内固定路径($sysRoot\INF), 不依赖 DISM 每次分配的 oem### 编号(实机两条都验过);
#       2) devnode 写 UpperFilters=[vwifibus](保留既有条目) + pnputil /restart-device -> vwifibus Running。
#     判据独立成 wbind=ok|partial|fail|noop, 只看"两个 WiFi 过滤器在不在 + vwifibus 挂没挂 + 三个服务跑没跑",
#     不看 netcfg 的返回码。-SkipWlanBind 可以关掉这一段(现场想单独看驱动层时用)。
#
#   PE 命令行用法: netdrvfix          (startnet.cmd 开机自动跑一次, 现场也可以手动再敲一次)
#   宿主机改完先自检(不碰任何真设备):
#     powershell -NoProfile -ExecutionPolicy Bypass -File overlay\Scripts\netdrvfix.ps1 -SelfTest
#     ... -DryRun -IdxPath overlay\Scripts\netdrv_index.txt -StoIdxPath overlay\Scripts\stodrv_index.txt -LogPath %TEMP%\nd.log
#     ... -DryRun -Simulate "PCI\VEN_8086&DEV_467F&SUBSYS_00000000&REV_00\3&1357b3c0&0&A0" -SimCode 28   # 网卡芯片
#     ... -DryRun -Simulate "PCI\VEN_8086&DEV_09AB&REV_00\..." -SimCode 28                              # VMD 子控制器
#   只用 WinPE 里确实存在的工具: pnputil.exe / drvload.exe / Get-CimInstance / Get-Disk / ipconfig
# ============================================================
param(
  [switch]$DryRun,
  [switch]$SelfTest,
  [switch]$NoCopy,
  [switch]$SkipStorage,
  [switch]$SkipWlanBind,
  [string]$IdxPath    = '',
  [string]$StoIdxPath = '',
  [string]$WlIdxPath  = '',
  [string]$FrPath     = '',
  [string]$LogPath    = '',
  [string]$StatusPath = '',
  [string]$CopyTo     = '',      # 强制回传目标卷, 例如 E:
  [string]$Simulate   = '',      # 假设备实例ID(自动按 DryRun 处理, 用来验证查表与分流)
  [int]$SimCode       = 28       # 假设备的 problem code
)
$ErrorActionPreference = 'Continue'
$VER     = 'netdrvfix/3.2'
$sysRoot = $env:SystemRoot
$volRoot = Split-Path $sysRoot -Parent
$fr   = if ($FrPath)     { $FrPath }     else { Join-Path $sysRoot 'System32\DriverStore\FileRepository' }
$idx  = if ($IdxPath)    { $IdxPath }    else { Join-Path $sysRoot 'System32\netdrv_index.txt' }
$sidx = if ($StoIdxPath) { $StoIdxPath } else { Join-Path $sysRoot 'System32\stodrv_index.txt' }
$widx = if ($WlIdxPath)  { $WlIdxPath }  else { Join-Path $sysRoot 'System32\wlandrv_index.txt' }
$log  = if ($LogPath)    { $LogPath }    else { Join-Path $volRoot 'netdrvfix.log' }
$stat = if ($StatusPath) { $StatusPath } else { Join-Path $volRoot 'status.txt' }
function Resolve-Tool([string]$name) {
  $p = Join-Path $sysRoot ('System32\' + $name)
  if (Test-Path -LiteralPath $p -EA SilentlyContinue) { return $p }
  return $name                      # 拿不到绝对路径就交给 PATH
}
$drv  = Resolve-Tool 'drvload.exe'
$pnpu = Resolve-Tool 'pnputil.exe'

# ---------- 日志: 正文一律压成 ASCII, PE 控制台/GBK 里才不会变 ? ----------
function W([string]$m) {
  $a = ("$m") -replace '[^\x20-\x7E]', '?'
  $line = (Get-Date -Format 'HH:mm:ss') + '  ' + $a
  Write-Host $line
  try { Add-Content -LiteralPath $log -Value $line -Encoding ASCII -EA SilentlyContinue } catch { }
}
function Cut([string]$s) {
  $t = ("$s") -replace '\s+', ' '
  if ($t.Length -gt 170) { return ($t.Substring(0, 170) + '...') }
  return $t
}

# ---------- 纯函数: 实例ID -> 查表用的基础硬件ID ----------
#   PCI\VEN_8086&DEV_10D3&SUBSYS_075015AD&REV_00\3&11583659&0&B8  ->  PCI\VEN_8086&DEV_10D3
#   USB\VID_0BDA&PID_8153&REV_0100\5&1A2B3C4D&0&2                 ->  USB\VID_0BDA&PID_8153
#   USB\VID_1BCF&PID_2C1E&MI_00\7&111&0                           ->  USB\VID_1BCF&PID_2C1E
#   INF 侧还常写 PCI\VEN_8086&DEV_9D03&CC_0106(按类别码限定, Intel 存储包整片都这样),
#   而设备枚举出来的实例ID里没有 CC 段 —— 两边都剥掉 &CC_ 才对得上(索引生成端同口径)。
function Get-Key([string]$devid) {
  $parts = ("$devid").ToUpper() -split '\\'
  $hw = if ($parts.Count -ge 2) { $parts[0] + '\' + $parts[1] } else { $parts[0] }
  return ((($hw -split '&SUBSYS|&REV|&MI|&CC')[0]).TrimEnd('\')).TrimEnd('&')
}
function Test-NicKey([string]$k) {
  return ($k -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$' -or $k -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}$')
}
# ---------- 纯函数: 这块卡归哪一轮管 ----------
#   'net'  = 网卡索引(有线或无线)里有(先修, 关系到 SSH/frp/下载通道)
#   'stor' = 只有存储索引里有, 且是 PCI 板载控制器 —— v3 硬规则: 存储这轮绝不碰 USB\VID 键,
#            免得某个 USB\VID 撞进索引后去 /remove-device 正在读日志的启动 U 盘。
#   ''     = 三份索引都没有 -> SKIP
#   第 4 个参数是 v3.1 的无线表; 调用方没传($null)时行为和 v3.0 完全一致。
function Get-DevClass([string]$k, $netMap, $stoMap, $wlanMap) {
  if ($netMap.ContainsKey($k)) { return 'net' }
  if ($wlanMap -and $wlanMap.ContainsKey($k)) { return 'net' }
  if (-not $SkipStorage -and $k -like 'PCI\VEN_*' -and $stoMap.ContainsKey($k)) { return 'stor' }
  return ''
}
# ---------- 纯函数: 合并两份网卡表(有线 + 无线) ----------
#   同一个 ID 在两份里都有时(Realtek 的 combo 芯片两边都登记过)候选包取并集、保持顺序、去重。
#   不动原表: 返回新哈希, SelfTest 才能拿同一份 fixture 反复比。
function Merge-Index($a, $b) {
  $m = @{}
  foreach ($k in @($a.Keys)) { $m[$k.ToUpper()] = @($a[$k]) }
  foreach ($k in @($b.Keys)) {
    $kk = "$k".ToUpper()
    if (-not $m.ContainsKey($kk)) { $m[$kk] = @($b[$k]); continue }
    foreach ($g in @($b[$k])) { if ($m[$kk] -notcontains $g) { $m[$kk] += $g } }
  }
  return $m
}

# ---------- 纯函数: problem code + 候选包 -> 动作序列 ----------
#   'rescan'          = pnputil /remove-device <ID> 然后 pnputil /scan-devices
#   'drvload:<pkg>'   = drvload <该包的 inf>
#   'addinf:<pkg>'    = pnputil /add-driver <inf> /install 然后 /scan-devices
function Get-ActionSeq([int]$code, [string[]]$pkgs) {
  $seq = @()
  if ($code -eq 18) { $seq += 'rescan' }                        # CM_PROB_REINSTALL: 先摘 devnode 让 PnP 重来
  foreach ($p in @($pkgs)) { if ($p) { $seq += ('drvload:' + $p) } }
  if (@($pkgs).Count -gt 0) { $seq += ('addinf:' + @($pkgs)[0]) }
  $seq += 'rescan'                                              # 收尾: 装完常停在 18, 重扫一次才真起来
  return $seq
}

# ---------- 纯函数: 状态口径 ----------
function Get-StatusToken([int]$badN, [int]$boundN, $ips) {
  if ($badN -le 0) { return 'noop' }
  if ($boundN -le 0) { return 'fail' }
  if (@($ips).Count -gt 0) { return 'ok' }
  return 'partial'
}
# ---------- 纯函数: 存储侧口径(v3) ----------
#   判据是"能不能看见客户的 \Windows", 不是"我装了几个驱动":
#     ok      = 固定盘上有 \Windows(健康机器开机就这样)
#     noop    = 盘没回来, 但也没有任何"索引里有驱动却报错"的存储设备 -> 芯片不在这 21 个 ID 里, 重复敲没用
#     partial = 绑上了驱动 / 盘数涨了, 但还没看见 \Windows(常见于 BitLocker 未解锁、或分区没挂载 —— 救援照样能取到盘)
#     fail    = 有可修的设备, 驱动没绑上, 盘也没回来
function Get-StoToken([int]$badN, [int]$boundN, [string]$sdTok, [int]$dk0, [int]$dk1) {
  if ($sdTok -eq 'ok') { return 'ok' }
  if ($badN -le 0) { return 'noop' }
  if ($boundN -gt 0 -or $dk1 -gt $dk0) { return 'partial' }
  return 'fail'
}

# ---------- 纯函数: WiFi 绑定层(v3.2, 2026-10-12 实机定案) ----------
#   "驱动 code 0" 不等于 "wlansvc 有接口可管": 无线 miniport 后面还要挂
#     nativewifip(原生 WiFi provider) + vwififlt/vwifibus(虚拟 WiFi 过滤栈),
#   它们分别来自 适配器 class 键的 Linkage\FilterList 和 devnode 的 UpperFilters。
#   实机 192.168.0.102(那张已对齐盘)开机读数: boot_upper=none、wifi_entries=0、FilterList 整条不存在,
#   而**烘进 Control\Network 的组件记录并不会让 PnP 去绑** —— 两个钩子都要在开机后补:
#     钩子1  netcfg -v -l <inf> -c s -i MS_NativeWifiP / ms_vwifi  => FilterList 出条目、对应服务 Running
#            (实测 oem### 和镜像内固定名 X:\Windows\INF\netnwifi.inf 都能吃, 所以配方不依赖 DISM 的编号)
#     钩子2  devnode 写 UpperFilters=[vwifibus] + pnputil /restart-device => vwifibus Running
#   判据口径就按 2026-10-12 的三个量具改: "值不存在"必须数成 0(FlOf 那坑正好掩盖过这次的核心发现)。
#   这里只放"怎么决定", 真正的 reg/netcfg/pnputil 调用在下面"正式运行"段的 WLAN-BIND 那一步。
# 两个 WiFi 过滤器在 FilterList 里的两种形态都要认(宿主机正对照实测), 组件 GUID 就是 wifi-inject 烘进
# Control\Network 的那两棵树: E475CF9A...=ms_nativewifip / 5CBF81BF...=ms_vwifi。
$FL_ALIAS = @{ 'nativewifip' = @('nativewifip', 'E475CF9A'); 'vwififlt' = @('vwififlt', '5CBF81BF'); 'vwifibus' = @('vwifibus') }
function Test-FlEntry($arr, [string]$name) {
  # 一个过滤器在 FilterList 里有两种形态, 只认一种就会把"已经绑上"读成"没绑"(2026-10-12 宿主机正对照抓到):
  #   WinPE / netcfg 刚装完  -> 裸名 'nativewifip' / 'vwififlt'
  #   完整 Windows 实测      -> 绑定实例 '{<adapter GUID>}-{<component GUID>}-000N', 13 条全是这个形状
  # 组件 GUID 就是烘进 Control\Network 的那两棵树(ms_nativewifip / ms_vwifi), 所以两种都算命中。
  $pats = @("$name")
  if ($FL_ALIAS.ContainsKey("$name".ToLower())) { $pats = @($FL_ALIAS["$name".ToLower()]) }
  foreach ($x in @($arr)) {
    $v = ("$x").Trim()
    if (-not $v) { continue }
    # 子串匹配(-match 默认不区分大小写): 绑定实例是 '{adapter}-{component}-000N', GUID 在中间, 不是前缀也不是后缀
    foreach ($p in $pats) { if ($v -match [regex]::Escape($p)) { return $true } }
  }
  return $false
}
# FilterList 里到底有几个"WiFi 的"过滤器 —— 现场要读的是这个数, 不是条目总数
function Count-WlanFilter($fl) {
  $n = 0
  foreach ($x in @($fl)) {
    $v = ("$x").Trim()
    if (-not $v) { continue }
    if ($v -match '(?i)nativewifip|E475CF9A' -or $v -match '(?i)^vwififlt$|5CBF81BF') { $n++ }
  }
  return $n
}
# UpperFilters 合并: 已存在的条目必须原样保留(别的厂商可能挂了东西), 大小写不敏感去重,
# 传入 $null / @($null) / '' 都当成"没有" —— 这是 FlOf 那次数出 1 的直接修正。
function Merge-UpperFilters($cur, [string]$add) {
  $list = @()
  foreach ($x in @($cur)) {
    $v = ("$x").Trim()
    if (-not $v) { continue }
    if (-not (Test-FlEntry $list $v)) { $list += $v }
  }
  if (-not (Test-FlEntry $list $add)) { $list += $add }
  return $list
}
# 动作顺序是定过的: 两条 netcfg 先补 FilterList, 最后才动 UpperFilters + 重启设备,
# 因为 /restart-device 会让 PnP 重绑一次 —— 前面补的东西要在那一刻全部就位。
function Get-WlanBindPlan($fl, $upper, [string]$infNwifi, [string]$infVwifi) {
  $acts = @()
  if (-not (Test-FlEntry $fl 'nativewifip') -and $infNwifi) { $acts += ('netcfg:nwifi:' + $infNwifi) }
  if (-not (Test-FlEntry $fl 'vwififlt')     -and $infVwifi) { $acts += ('netcfg:vwifi:' + $infVwifi) }
  if (-not (Test-FlEntry $upper 'vwifibus')) { $acts += 'upperfilters:vwifibus'; $acts += 'restart-device' }
  return $acts
}
# 绑定层结论(和 net/stor 一样四态, 但判据来自绑定而不是 problem code):
#   ok      = 两个 WiFi 过滤器都在 + vwifibus 挂了 + 三个服务都在跑 -> wlansvc 有接口可管
#   partial = 补上了一部分(常见: netcfg 成功但 restart-device 还没来得及生效)
#   fail    = 一块驱动健康的 WiFi 芯片, 补完还是什么都没有
#   noop    = 这台机器没有可用无线芯片(驱动都没绑上, 或压根没 WiFi)
# WDI 宿主要不要 start: 只有"键在但没在跑"才是这一步的对象; 读不到服务=这张盘早于 #40 的烘焙(重出盘才行),
# 已经在跑的不要去动它。判据只看复读后的状态, 不看 net start 的返回码(PE 里 net 的输出不可靠)。
function Test-WdiHostNeeded([string]$st) { return ($st -ne '' -and $st -ne 'Running') }
function Get-WlanBindToken([int]$wlanN, [int]$flWifi, [bool]$upperOk, [int]$svcUp) {
  if ($wlanN -le 0) { return 'noop' }
  if ($flWifi -ge 2 -and $upperOk -and $svcUp -ge 3) { return 'ok' }
  if ($flWifi -gt 0 -or $upperOk -or $svcUp -gt 0) { return 'partial' }
  return 'fail'
}

# ---------- 查表文件: "ID<TAB>包名.inf" 一行一条, 同一 ID 最多 3 条 ----------
function Parse-Index([string]$file) {
  $m = @{}
  foreach ($l in @(Get-Content -LiteralPath $file -EA SilentlyContinue)) {
    $p = $l -split "`t"
    if ($p.Count -lt 2) { continue }
    $k = $p[0].Trim().ToUpper()
    $g = $p[1].Trim().ToLower()
    if (-not $k -or -not $g) { continue }
    if (-not $m.ContainsKey($k)) { $m[$k] = @() }
    if ($m[$k] -notcontains $g) { $m[$k] += $g }
  }
  return $m
}

# ---------- 在镜像的 DriverStore 里把包名解析成 inf 全路径 ----------
#   同一个包名在库里可能有**两份**(存储池就是: iaStorVD.inf 20.2.13 与 20.2.4 是两个 FileRepository 目录),
#   索引按包名去重后只剩一行, 只取第一个目录就可能挑到旧版 —— 而新旧版覆盖的芯片不一样
#   (11 代的 DEV_9A0B 只在 20.2.4 里, 12 代的 DEV_467F 两版都有)。
#   所以 Resolve-InfList 把同名包的每一份都交出来, 按 DriverVer 新→旧排, 动作循环里挨个试。
function Get-InfVerDate([string]$path) {
  try {
    $b = [IO.File]::ReadAllBytes($path)
    $txt = ''
    if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { $txt = [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
    elseif ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $txt = [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
    else { $txt = [Text.Encoding]::Default.GetString($b) }
    $m = [regex]::Match($txt, '(?im)^\s*DriverVer\s*=\s*([^\r\n]+)')
    if (-not $m.Success) { return [datetime]::MinValue }
    $p = ($m.Groups[1].Value -split ',')[0].Trim()
    foreach ($fmt in @('MM/dd/yyyy', 'M/d/yyyy', 'dd/MM/yyyy', 'yyyy-MM-dd')) {
      $dtp = [datetime]::MinValue
      if ([datetime]::TryParseExact($p, $fmt, [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$dtp)) { return $dtp }
    }
  } catch { }
  return [datetime]::MinValue
}
$script:infCache = @{}
function Resolve-InfList([string]$pkg) {
  $k = $pkg.ToLower()
  if ($script:infCache.ContainsKey($k)) { return $script:infCache[$k] }
  $hits = @()
  # 镜像里目录名是 包名.inf_amd64_<hash>; 构建期池里 29b_ 把 .inf_ 改成了 _inf_,
  # 所以只按 "以 包名_ 开头" 匹配目录, 再用同名文件精确校验(顺带挡掉 8.3 短名的假命中)。
  $dirs = @(Get-ChildItem -LiteralPath $script:fr -Directory -EA SilentlyContinue |
            Where-Object { $_.Name.ToLower().StartsWith($k + '_') } | Sort-Object Name)
  foreach ($d in $dirs) {
    $f = @(Get-ChildItem -LiteralPath $d.FullName -File -EA SilentlyContinue | Where-Object { $_.Name.ToLower() -eq $k })
    if ($f.Count -gt 0) { $hits += $f[0].FullName }
  }
  $hits = @($hits | Sort-Object { (Get-InfVerDate $_) } -Descending)
  $script:infCache[$k] = $hits
  return $hits
}
function Resolve-Inf([string]$pkg) {
  $l = @(Resolve-InfList $pkg)
  if ($l.Count -eq 0) { return $null }
  return $l[0]
}

# ---------- 设备快照: 原样 DeviceID -> code/Name (只留 PCI\VEN 与 USB\VID 两族) ----------
function Get-NetDevs {
  $h = @{}
  foreach ($d in @(Get-CimInstance -ClassName Win32_PnPEntity -Property DeviceID, ConfigManagerErrorCode, Name -EA SilentlyContinue)) {
    $idv = "$($d.DeviceID)"
    if (-not $idv) { continue }
    $up = $idv.ToUpper()
    if ($up -notlike 'PCI\VEN_*' -and $up -notlike 'USB\VID_*') { continue }
    $h[$idv] = @{ code = [int]$d.ConfigManagerErrorCode; name = "$($d.Name)" }
  }
  return $h
}
# 读某台设备现在的 problem code; -1 = devnode 不在(摘掉后还没重扫回来)。
# 同硬件ID 换了实例号(USB 重枚举常见)时认成同一台, 并把新实例ID通过 .id 传回去。
function Get-DevCode([string]$curId, [string]$key, $snap) {
  if ($snap.ContainsKey($curId)) { return @{ code = [int]$snap[$curId].code; id = $curId } }
  $same = @($snap.Keys | Where-Object { (Get-Key $_) -eq $key })
  if ($same.Count -eq 0) { return @{ code = -1; id = $curId } }
  $pick = @($same | Sort-Object { [int]$snap[$_].code })[0]
  return @{ code = [int]$snap[$pick].code; id = $pick }
}
function Get-AdapterCount { @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.PhysicalAdapter }).Count }
# ---------- v3 存储判据: 盘台数 + 固定盘上有没有 \Windows ----------
#   救援要的是"看得见客户的系统盘", 这两条比 problem code 更硬:
#   iaStorVD 实机证明里 disks 1->3 与 DEV_467F code 归零是同时发生的。
function Get-DiskCount {
  try { return @(Get-Disk -EA SilentlyContinue).Count } catch { return -1 }
}
function Get-SysDisk {
  # 'ok' = 有本地固定盘上摆着 \Windows; 'missing' = 没有(装不了离线修复, rescue 也取不到 hive)
  # 只认 DriveType=3(固定盘): X:  ramdisk 里也有 \Windows, 把它算进来等于永远自欺欺人。
  $hits = @()
  $sysLetter = $volRoot.Substring(0, 1).ToUpper()
  foreach ($v in @(Get-CimInstance Win32_LogicalDisk -Property DeviceID, DriveType -EA SilentlyContinue)) {
    if ([int]$v.DriveType -ne 3) { continue }
    $lv = "$($v.DeviceID)".TrimEnd('\')            # 不同版本可能是 'C:' 也可能是 'C:\'
    if ($lv -notmatch '^[A-Za-z]:$') { continue }
    if ($lv.Substring(0, 1).ToUpper() -eq $sysLetter) { continue }
    try { if (Test-Path -LiteralPath (Join-Path $lv 'Windows') -EA SilentlyContinue) { $hits += $lv.Substring(0, 1) } } catch { }
  }
  return @{ tok = $(if ($hits.Count -gt 0) { 'ok' } else { 'missing' }); letters = (@($hits | Sort-Object)) }
}
function Get-MyIp {
  try { $cfg = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -EA Stop | Where-Object { $_.IPEnabled }) } catch { return @() }
  $r = @()
  foreach ($c in $cfg) { foreach ($a in @($c.IPAddress)) { if ("$a" -and "$a" -notmatch '^169\.254|^fe80') { $r += "$a" } } }
  return @($r | Select-Object -Unique)
}
function Run-Cmd([string]$exe, $argv) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $out = ''
  try { $out = (& $exe @argv 2>&1 | Out-String) } catch { $out = 'EXCEPTION ' + $_.Exception.Message }
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return @{ rc = $rc; txt = (Cut $out) }
}

# ============================================================
# -SelfTest: 只测纯逻辑 + 假驱动库/假索引; 不装驱动、不动设备
# ============================================================
if ($SelfTest) {
  $tmp = Join-Path $env:TEMP ('netdrvfix_selftest_' + (Get-Date -Format 'HHmmss'))
  $tfr = Join-Path $tmp 'FileRepository'
  New-Item -ItemType Directory -Force -Path $tfr | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $tfr 'rt640x64.inf_amd64_aaa111') | Out-Null
  Set-Content -LiteralPath (Join-Path $tfr 'rt640x64.inf_amd64_aaa111\rt640x64.inf') -Value '[Version]' -Encoding ASCII
  New-Item -ItemType Directory -Force -Path (Join-Path $tfr 'rtl8153a.inf_amd64_bbb222') | Out-Null
  Set-Content -LiteralPath (Join-Path $tfr 'rtl8153a.inf_amd64_bbb222\rtl8153a.inf') -Value '[Version]' -Encoding ASCII
  # v3: 存储包也要有 fixture(和网卡同一套 Resolve-Inf / 动作序列)
  New-Item -ItemType Directory -Force -Path (Join-Path $tfr 'iastorvd.inf_amd64_ccc333') | Out-Null
  Set-Content -LiteralPath (Join-Path $tfr 'iastorvd.inf_amd64_ccc333\iastorvd.inf') -Value '[Version]' -Encoding ASCII
  # v3.1: 无线包也要能在同一个 FileRepository 里被解析出来(和有线走同一条 Resolve-Inf 通路)
  New-Item -ItemType Directory -Force -Path (Join-Path $tfr 'netwtw08.inf_amd64_ddd444') | Out-Null
  Set-Content -LiteralPath (Join-Path $tfr 'netwtw08.inf_amd64_ddd444\netwtw08.inf') -Value '[Version]' -Encoding ASCII
  # 库里同名包的旧版(镜像里 iaStorVD 20.2.4 与 20.2.13 就是这种), DriverVer 更旧 -> 排序必须把新的排在第一个
  New-Item -ItemType Directory -Force -Path (Join-Path $tfr 'iastorvd.inf_amd64_aaa000old') | Out-Null
  Set-Content -LiteralPath (Join-Path $tfr 'iastorvd.inf_amd64_aaa000old\iastorvd.inf') -Value '[Version]' -Encoding ASCII
  $oldInf = Join-Path $tfr 'iastorvd.inf_amd64_aaa000old\iastorvd.inf'
  $newInf = Join-Path $tfr 'iastorvd.inf_amd64_ccc333\iastorvd.inf'
  Set-Content -LiteralPath $oldInf -Value ('[Version]' + "`r`n" + 'DriverVer=12/06/2024,20.2.4.1019') -Encoding ASCII
  Set-Content -LiteralPath $newInf -Value ('[Version]' + "`r`n" + 'DriverVer=04/02/2026,20.2.13.1038') -Encoding ASCII
  $tidx = Join-Path $tmp 'netdrv_index.txt'
  @(
    ('PCI\VEN_10EC&DEV_8136' + "`t" + 'rt640x64.inf'),
    ('USB\VID_0BDA&PID_8153' + "`t" + 'rtl8153a.inf'),
    ('PCI\VEN_8086&DEV_10D3' + "`t" + 'nosuchpkg.inf'),
    'this-line-has-no-tab',
    ''
  ) | Set-Content -LiteralPath $tidx -Encoding ASCII
  $tsidx = Join-Path $tmp 'stodrv_index.txt'
  @(
    ('PCI\VEN_8086&DEV_467F' + "`t" + 'iastorvd.inf'),
    ('PCI\VEN_8086&DEV_09AB' + "`t" + 'iastorvd.inf'),
    ('USB\VID_13FE&PID_6300' + "`t" + 'iastorvd.inf'),   # 故意放个 USB 键: v3 规定存储轮不碰 USB\VID
    ''
  ) | Set-Content -LiteralPath $tsidx -Encoding ASCII
  $twidx = Join-Path $tmp 'wlandrv_index.txt'
  @(
    ('PCI\VEN_8086&DEV_2526' + "`t" + 'netwtw08.inf'),      # 用户 ThinkPad 那块 AC 9260
    ('PCI\VEN_8086&DEV_51F1' + "`t" + 'netwtw08.inf'),      # AX211: 同一个包在两份表里都可能出现
    ('PCI\VEN_8086&DEV_51F1' + "`t" + 'netwtw6e.inf'),
    ('USB\VID_0BDA&PID_8153' + "`t" + 'rtwlanu.inf'),        # 与有线表撞键: 合并后应去重不重复 drvload
    ''
  ) | Set-Content -LiteralPath $twidx -Encoding ASCII
  $script:fr = $tfr; $idx = $tidx; $sidx = $tsidx; $widx = $twidx; $log = Join-Path $tmp 'netdrvfix.log'; $stat = Join-Path $tmp 'status.txt'

  $script:stFail = 0
  function Tst([bool]$ok, [string]$what) {
    if ($ok) { W ('  [OK  ] ' + $what) } else { W ('  [FAIL] ' + $what); $script:stFail++ }
  }
  W ('==== netdrvfix SelfTest (' + $VER + ') on ' + $env:COMPUTERNAME + ' ====')
  $k1 = Get-Key 'PCI\VEN_8086&DEV_10D3&SUBSYS_075015AD&REV_00\3&11583659&0&B8'
  Tst ($k1 -eq 'PCI\VEN_8086&DEV_10D3') ('Get-Key PCI  drops SUBSYS/REV/instance -> ' + $k1)
  $k2 = Get-Key 'USB\VID_0BDA&PID_8153&REV_0100\5&1A2B3C4D&0&2'
  Tst ($k2 -eq 'USB\VID_0BDA&PID_8153') ('Get-Key USB  drops REV/instance        -> ' + $k2)
  $k3 = Get-Key 'USB\VID_1BCF&PID_2C1E&MI_00\7&111&0'
  Tst ($k3 -eq 'USB\VID_1BCF&PID_2C1E') ('Get-Key USB  composite drops MI_00     -> ' + $k3)
  $k4 = Get-Key 'PCI\VEN_10EC&DEV_8136\4&4B3A2C1&0&B8'
  Tst ($k4 -eq 'PCI\VEN_10EC&DEV_8136') ('Get-Key PCI  without REV still works   -> ' + $k4)
  $k5 = Get-Key 'PCI\VEN_8086&DEV_9D03&CC_0106&REV_02\3&1822831&0&A0'
  Tst ($k5 -eq 'PCI\VEN_8086&DEV_9D03') ('Get-Key strips &CC_ (Intel stor INFs)  -> ' + $k5)
  Tst ((Get-Key 'ROOT\KDNIC\0000') -eq 'ROOT\KDNIC') ('Get-Key ROOT devnode stays put           -> ' + (Get-Key 'ROOT\KDNIC\0000'))
  Tst ((Test-NicKey 'PCI\VEN_10EC&DEV_8136') -and (Test-NicKey 'USB\VID_0BDA&PID_8153') -and (-not (Test-NicKey 'ROOT\KDNIC')) -and (-not (Test-NicKey 'PCI\VEN_10EC&DEV_XXXX'))) ('Test-NicKey accepts only well-formed IDs')

  $map = Parse-Index $tidx
  Tst ($map.Count -eq 3) ('Parse-Index drops the tab-less line    -> ' + $map.Count + ' IDs')
  Tst ((@($map['PCI\VEN_10EC&DEV_8136']).Count -eq 1) -and (@($map['PCI\VEN_10EC&DEV_8136'])[0] -eq 'rt640x64.inf')) ('Parse-Index PCI  row -> package list')
  Tst (@($map['USB\VID_0BDA&PID_8153'])[0] -eq 'rtl8153a.inf') ('Parse-Index USB  row -> package list')

  Tst ((Resolve-Inf 'rt640x64.inf') -eq (Join-Path $tfr 'rt640x64.inf_amd64_aaa111\rt640x64.inf')) ('Resolve-Inf finds the inf in FileRepository')
  Tst ((Resolve-Inf 'rtl8153a.inf') -eq (Join-Path $tfr 'rtl8153a.inf_amd64_bbb222\rtl8153a.inf')) ('Resolve-Inf finds a USB  nic package')
  Tst ($null -eq (Resolve-Inf 'nosuchpkg.inf')) ('Resolve-Inf returns null for a missing pkg')
  Tst ((Resolve-Inf 'iastorvd.inf') -eq $newInf) ('Resolve-Inf picks the NEWEST of two same-name copies')
  # 同名包两份(镜像里 iaStorVD 20.2.4 / 20.2.13 就是这种): 动作循环靠 Resolve-InfList 挨个试,
  # 少了这份就是"只试了一份就放弃"。用目录名比对, 免得 TEMP 的 8.3 短名把字符串比较搞花。
  $rl = @(Resolve-InfList 'iastorvd.inf')
  Tst ($rl.Count -eq 2) ('Resolve-InfList returns EVERY same-name copy     -> ' + $rl.Count)
  Tst ((Split-Path -Leaf (Split-Path -Parent $rl[0])) -eq 'iastorvd.inf_amd64_ccc333') ('...sorted newest DriverVer first (20.2.13 before 20.2.4)')
  Tst ((@($rl | ForEach-Object { (Split-Path -Leaf (Split-Path -Parent $_)) }) -join ',') -match 'aaa000old') ('...and the older copy is still in the list (drvload fallback)')
  Tst ((Resolve-InfList 'nosuchpkg.inf').Count -eq 0) ('Resolve-InfList is empty for a missing pkg')

  # ---------- v3: 两轮分工(先网卡后存储) + 存储轮不碰 USB\VID ----------
  $nm = Parse-Index $tidx
  $sm = Parse-Index $tsidx
  Tst ($nm.Count -eq 3 -and $sm.Count -eq 3) ('Parse-Index reads both index files        -> net ' + $nm.Count + ' / stor ' + $sm.Count)
  Tst ((Get-DevClass 'PCI\VEN_10EC&DEV_8136' $nm $sm) -eq 'net') ('NIC chip              -> net round')
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_467F' $nm $sm) -eq 'stor') ('VMD controller        -> stor round')
  Tst ((Get-DevClass 'USB\VID_13FE&PID_6300' $nm $sm) -eq '') ('USB key in stor index -> nobody (boot stick guard)')
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_15B8' $nm $sm) -eq '') ('unknown chip          -> SKIP')
  $script:SkipStorage = $true
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_467F' $nm $sm) -eq '') ('-SkipStorage disables the stor round')
  $script:SkipStorage = $false
  $emptyMap = Parse-Index (Join-Path $tmp 'no_such_index_file.txt')
  Tst ($emptyMap.Count -eq 0) ('missing stor index parses to empty (WARN, not ABORT)')

  # ---------- v3.1: 第三份表(无线)并进网卡那一轮 ----------
  $wm = Parse-Index $twidx
  Tst ($wm.Count -eq 3) ('Parse-Index reads the wifi index -> ' + $wm.Count + ' IDs')
  $merged = Merge-Index $nm $wm
  Tst ($merged.Count -eq ($nm.Count + 2)) ('Merge-Index adds only the new IDs -> ' + $merged.Count + ' (net ' + $nm.Count + ' + wifi 2)')
  Tst ((@($merged['USB\VID_0BDA&PID_8153']) -join ',') -eq 'rtl8153a.inf,rtwlanu.inf') ('Shared key keeps both packages, deduped, wired first')
  Tst ((@($merged['PCI\VEN_8086&DEV_51F1']).Count -eq 2) -and (@($merged['PCI\VEN_8086&DEV_51F1'])[0] -eq 'netwtw08.inf')) ('AX211 -> 2 candidate pkgs newest-first from the index')
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_2526' $nm $sm $wm) -eq 'net') ('AC 9260 (wifi-only key) -> net round')
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_2725' $nm $sm $wm) -eq '') ('wifi chip outside the pool -> SKIP')
  Tst ((Get-DevClass 'PCI\VEN_8086&DEV_2526' $nm $sm) -eq '') ('without the 4th arg v3.0 behaviour is unchanged (old image, no wifi index)')
  Tst ((Resolve-Inf 'netwtw08.inf') -eq (Join-Path $tfr 'netwtw08.inf_amd64_ddd444\netwtw08.inf')) ('Resolve-Inf finds a wifi package in the same FileRepository')

  # ---------- v3.2: WiFi 绑定层的判据(实机 10-12 的两个钩子) ----------
  # 量具本身先自证: "值不存在"必须数成 0 —— FlOf 用 @($null) 把不存在数成 1, 正好掩盖了这次的核心发现。
  Tst ((Test-FlEntry $null 'vwifibus') -eq $false)  ('Test-FlEntry: absent value is NOT an entry')
  Tst ((Test-FlEntry @($null) 'vwifibus') -eq $false) ('Test-FlEntry: @($null) still counts as nothing')
  Tst ((Test-FlEntry @('VWIFIBUS') 'vwifibus') -eq $true) ('Test-FlEntry: case-insensitive match')
  Tst ((Count-WlanFilter $null) -eq 0 -and (Count-WlanFilter @()) -eq 0) ('Count-WlanFilter: absent/empty -> 0')
  Tst ((Count-WlanFilter @('vwififlt', 'nativewifip')) -eq 2) ('Count-WlanFilter: both wifi filters -> 2')
  Tst ((Count-WlanFilter @('vwififlt', 'RsNdisFilt', 'NdisWans')) -eq 1) ('Count-WlanFilter: only wifi entries count -> 1')
  Tst ((Count-WlanFilter @('l2tp', 'NdisWans')) -eq 0) ('Count-WlanFilter: unrelated filters -> 0')
  # 宿主机正对照(build\scratch\t_p107_host_fl.ps1, 2026-10-12: 那块 AC 9260 的 class 实例有 13 条 FilterList,
  # 形状是 '{<adapter GUID>}-{<component GUID>}-000N' 而不是裸名)。第一版判据只认裸名, 把这台健康机器读成
  # wifi_entries=0 —— 这就是 FlOf 那一坑的第二个版本, 所以两种形态都必须认, 而且拿真机器读数当固定样本。
  $hostFl = @('{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{430BDADD-BAB0-41AB-A369-94B67FA5BE0A}-0000',
              '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{3BFD7820-D65C-4C1B-9FEA-983A019639EA}-0000',
              '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{5CBF81BF-5055-47CD-9055-A76B2B4E3698}-0000',
              '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{430BDADD-BAB0-41AB-A369-94B67FA5BE0A}-0002',
              '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{E475CF9A-60CD-4439-A75F-0079CE0E18A1}-0000',
              '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{B5F4D659-7DAA-4565-8E41-BE220ED60542}-0000')
  Tst ((Count-WlanFilter $hostFl) -eq 2) ('Count-WlanFilter: host GUID-shaped bindings count  -> ' + (Count-WlanFilter $hostFl) + '/2')
  Tst ((Test-FlEntry $hostFl 'nativewifip') -and (Test-FlEntry $hostFl 'vwififlt')) ('Test-FlEntry: ms_nativewifip + ms_vwifi GUIDs recognised')
  Tst (@(Get-WlanBindPlan $hostFl @('vwifibus') 'a.inf' 'b.inf').Count -eq 0) ('plan: a healthy host reads as already bound (no busywork)')
  Tst ((Count-WlanFilter @('nativewifip', '{7D8A89C0-8A54-42A5-8F24-E3618458C29F}-{5CBF81BF-5055-47CD-9055-A76B2B4E3698}-0000')) -eq 2) ('Count-WlanFilter: mixed PE-name and host-GUID forms both count')
  $u1 = @(Merge-UpperFilters $null 'vwifibus')
  Tst (($u1.Count -eq 1) -and ($u1[0] -eq 'vwifibus')) ('Merge-UpperFilters: absent -> [vwifibus]        -> ' + ($u1 -join ','))
  $u2 = @(Merge-UpperFilters @('vwifibus') 'vwifibus')
  Tst ($u2.Count -eq 1) ('Merge-UpperFilters: already there stays single      -> ' + ($u2 -join ','))
  $u3 = @(Merge-UpperFilters @('SomeVendorFilter', '') 'vwifibus')
  Tst (($u3.Count -eq 2) -and ($u3[0] -eq 'SomeVendorFilter') -and ($u3[1] -eq 'vwifibus')) ('Merge-UpperFilters: keeps existing entries, drops blanks -> ' + ($u3 -join ','))
  $u4 = @(Merge-UpperFilters @('VWIFIBUS') 'vwifibus')
  Tst ($u4.Count -eq 1) ('Merge-UpperFilters: case-insensitive dedup         -> ' + ($u4 -join ','))
  # 动作序列: 空绑定 + 两份 INF 都在 -> 4 步, 且 restart-device 必须最后(重绑发生在那一刻)
  $p0 = @(Get-WlanBindPlan @() @() 'X:\Windows\INF\netnwifi.inf' 'X:\Windows\INF\netvwififlt.inf')
  Tst ($p0.Count -eq 4) ('plan: nothing bound -> 4 actions                   -> ' + $p0.Count)
  Tst ((@($p0)[0] -like 'netcfg:nwifi:*') -and (@($p0)[-1] -eq 'restart-device') -and (@($p0)[-2] -eq 'upperfilters:vwifibus')) ('plan: netcfg first, devnode restart last')
  Tst (@(@(Get-WlanBindPlan @('nativewifip', 'vwififlt') @('vwifibus') 'a.inf' 'b.inf')).Count -eq 0) ('plan: already bound -> no busywork')
  $p2 = @(Get-WlanBindPlan @('nativewifip') @('vwifibus') 'a.inf' 'b.inf')
  Tst (($p2.Count -eq 1) -and (@($p2)[0] -like 'netcfg:vwifi:*')) ('plan: missing only vwififlt -> one netcfg    -> ' + ($p2 -join ' | '))
  $p3 = @(Get-WlanBindPlan @() @() '' '')
  Tst ($p3.Count -eq 2) ('plan: no INF in the image -> only the devnode pair')
  # 结论口径
  Tst ((Get-WlanBindToken 0 2 $true 3) -eq 'noop')     ('bind: no wifi chip                -> noop')
  Tst ((Get-WlanBindToken 1 2 $true 3) -eq 'ok')       ('bind: 2 filters + vwifibus + 3 up -> ok')
  Tst ((Get-WlanBindToken 1 2 $true 0) -eq 'partial')  ('bind: filters bound, services down-> partial')
  Tst ((Get-WlanBindToken 1 1 $false 1) -eq 'partial') ('bind: half of it                    -> partial')
  Tst ((Get-WlanBindToken 1 0 $false 0) -eq 'fail')    ('bind: nothing happened              -> fail')
  # WDI 宿主: 只有"键在但不是 Running"才该去 start; 读不到服务(absent)只能重出盘, 启动它没有意义
  Tst ((Test-WdiHostNeeded 'Stopped') -and (Test-WdiHostNeeded 'StartPending')) ('wdi: Stopped/StartPending -> start it')
  Tst (-not (Test-WdiHostNeeded 'Running'))            ('wdi: Running -> leave alone')
  Tst (-not (Test-WdiHostNeeded ''))                   ('wdi: absent(key not baked) -> do not try to start')

  # ---------- v3: 盘的判据 ----------
  $dc = Get-DiskCount
  Tst ($dc -ge 0 -or $dc -eq -1) ('Get-DiskCount returns a number (-1 = Get-Disk missing) -> ' + $dc)
  $sd = Get-SysDisk
  Tst ($sd.tok -eq 'ok' -or $sd.tok -eq 'missing') ('Get-SysDisk returns ok|missing           -> ' + $sd.tok + ' (' + ($sd.letters -join ',') + ')')
  Tst ((Join-Path 'D:' 'Windows') -eq 'D:\Windows') ('Join-Path on a "D:" letter gives D:\Windows (never D::\Windows)')

  $s18 = @(Get-ActionSeq 18 @('rt640x64.inf', 'x2.inf'))
  Tst (@($s18)[0] -eq 'rescan') ('code18 starts with remove-device+scan     -> ' + ($s18 -join ' | '))
  Tst (($s18 -contains 'drvload:rt640x64.inf') -and (@($s18)[-1] -eq 'rescan')) ('code18 sequence ends with a final rescan')
  $s28 = @(Get-ActionSeq 28 @('rt640x64.inf'))
  Tst (@($s28)[0] -eq 'drvload:rt640x64.inf') ('code28 starts with drvload                -> ' + ($s28 -join ' | '))
  Tst ($s28 -contains 'addinf:rt640x64.inf') ('code28 falls back to pnputil /add-driver')
  $s0 = @(Get-ActionSeq 28 @())
  Tst ((@($s0).Count -eq 1) -and (@($s0)[0] -eq 'rescan')) ('no candidate pkg -> one rescan, no busywork')

  Tst ((Get-StatusToken 0 0 @('1.2.3.4')) -eq 'noop')   ('nothing broken        -> noop')
  Tst ((Get-StatusToken 2 0 @()) -eq 'fail')             ('repaired nothing      -> fail')
  Tst ((Get-StatusToken 2 1 @('10.0.0.5')) -eq 'ok')     ('driver up + IP        -> ok')
  Tst ((Get-StatusToken 2 1 @()) -eq 'partial')          ('driver up, no address -> partial')
  Tst ((Get-StoToken 0 0 'ok' 3 3) -eq 'ok')              ('stor: sysdisk visible            -> ok')
  Tst ((Get-StoToken 0 0 'missing' 1 1) -eq 'noop')       ('stor: nothing to fix, no disk    -> noop')
  Tst ((Get-StoToken 1 1 'missing' 1 3) -eq 'partial')    ('stor: bound + disks grew, no Win -> partial')
  Tst ((Get-StoToken 1 0 'missing' 1 1) -eq 'fail')       ('stor: nothing bound, no disk     -> fail')

  # 顺带把真索引读一遍: netdrvfix.ps1 就住在 overlay\Scripts, 和 netdrv_index.txt 同一目录
  $here = if ($PSScriptRoot) { $PSScriptRoot }
          elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
          else { (Get-Location).Path }
  $realIdx = ''
  foreach ($cand in @((Join-Path $here 'netdrv_index.txt'), (Join-Path (Split-Path -Parent $here) 'overlay\Scripts\netdrv_index.txt'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $realIdx = $cand; break }
  }
  if (-not $realIdx) { $realIdx = $tidx }
  $rm = Parse-Index $realIdx
  $rp = @($rm.Keys | Where-Object { $_ -like 'PCI\VEN_*' }).Count
  $ru = @($rm.Keys | Where-Object { $_ -like 'USB\VID_*' }).Count
  W ('  shipped index ' + $realIdx + ' -> ' + $rm.Count + ' IDs (PCI ' + $rp + ' / USB ' + $ru + ')')
  Tst ($rm.Count -gt 100) ('shipped index parses (>100 IDs)')
  # 存储索引: 和网卡索引同一个目录, 小文件(21 行), 读一遍确认没写坏
  $realSto = ''
  foreach ($cand in @((Join-Path $here 'stodrv_index.txt'), (Join-Path (Split-Path -Parent $here) 'overlay\Scripts\stodrv_index.txt'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $realSto = $cand; break }
  }
  if ($realSto) {
    $rsm = Parse-Index $realSto
    W ('  shipped stor index ' + $realSto + ' -> ' + $rsm.Count + ' IDs')
    Tst ($rsm.Count -ge 10) ('shipped storage index parses (>=10 IDs, Intel VMD/AHCI/VROC)')
    Tst ($rsm.ContainsKey('PCI\VEN_8086&DEV_467F')) ('12th-gen VMD DEV_467F is indexed (the real-machine proof)')
  } else {
    W '  shipped stor index not found next to the script (StoDir not indexed yet) -- storage round will be skipped'
  }
  # v3.1 无线索引: 构建期由 wifi-inject 调 17_ 生成并放进镜像 System32
  $realWlan = ''
  foreach ($cand in @((Join-Path $here 'wlandrv_index.txt'), (Join-Path (Split-Path -Parent $here) 'overlay\Scripts\wlandrv_index.txt'))) {
    if ($cand -and (Test-Path -LiteralPath $cand)) { $realWlan = $cand; break }
  }
  if ($realWlan) {
    $rwm = Parse-Index $realWlan
    $rwp = @($rwm.Keys | Where-Object { $_ -like 'PCI\VEN_*' }).Count
    $rwu = @($rwm.Keys | Where-Object { $_ -like 'USB\VID_*' }).Count
    W ('  shipped wifi index ' + $realWlan + ' -> ' + $rwm.Count + ' IDs (PCI ' + $rwp + ' / USB ' + $rwu + ')')
    Tst ($rwm.Count -ge 100) ('shipped wifi index parses (>=100 IDs) -> ' + $rwm.Count)
    Tst ($rwm.ContainsKey('PCI\VEN_8086&DEV_51F1')) ('Intel AX211 DEV_51F1 is indexed (the 2022+ laptop chip)')
    Tst ($rwm.ContainsKey('PCI\VEN_8086&DEV_2526')) ('Intel AC 9260 DEV_2526 is indexed (the bench ThinkPad card)')
  } else {
    W '  shipped wifi index not found next to the script -- wifi chips stay unhealed on this ISO (v3.0 behaviour)'
  }

  $sn = @{ 'PCI\VEN_10EC&DEV_8136\4&1&0&B8' = @{ code = 28; name = 'x' } }
  Tst ((Get-DevCode 'PCI\VEN_10EC&DEV_8136\4&1&0&B8' 'PCI\VEN_10EC&DEV_8136' $sn).code -eq 28) ('Get-DevCode reads a known devnode')
  Tst ((Get-DevCode 'PCI\VEN_10EC&DEV_8136\4&2&0&B8' 'PCI\VEN_10EC&DEV_8136' $sn).id -eq 'PCI\VEN_10EC&DEV_8136\4&1&0&B8') ('Get-DevCode follows a renumbered instance')
  Tst ((Get-DevCode 'PCI\VEN_8086&DEV_15B8\4&9&0&A0' 'PCI\VEN_8086&DEV_15B8' $sn).code -eq -1) ('Get-DevCode reports -1 when devnode is gone')

  W ('==== SelfTest ' + $(if ($script:stFail -eq 0) { 'PASS' } else { 'FAIL (' + $script:stFail + ' checks)' }) + ' ====')
  W ('   scratch dir: ' + $tmp + ' (safe to delete)')
  exit $(if ($script:stFail -eq 0) { 0 } else { 1 })
}

# ============================================================
# 正式运行
# ============================================================
W ('==== ' + $VER + ' begin ==== host=' + $env:COMPUTERNAME + ' time=' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($DryRun) { W 'MODE = DryRun (plan only, no device is touched)' }
if ($Simulate) { $DryRun = $true; W ('MODE = Simulate ' + (Cut $Simulate) + ' code=' + $SimCode + ' (treated as DryRun)') }
foreach ($p in @(@{ n = 'driver index'; v = $idx }, @{ n = 'driver store'; v = $fr })) {
  if (-not (Test-Path -LiteralPath $p.v)) { W ('ABORT = missing ' + $p.n + ': ' + $p.v + ' (this ISO predates netdrvfix v2)'); exit 1 }
}
$drvOk = (Test-Path -LiteralPath $drv -EA SilentlyContinue) -or [bool](Get-Command $drv -EA SilentlyContinue)
$pnpOk = (Test-Path -LiteralPath $pnpu -EA SilentlyContinue) -or [bool](Get-Command $pnpu -EA SilentlyContinue)
if (-not $drvOk) { W ('WARN = drvload missing: ' + $drv) }
if (-not $pnpOk) { W ('WARN = pnputil missing: ' + $pnpu + ' -- code18 devices cannot be repaired without it') }

$map = Parse-Index $idx
$pciN = @($map.Keys | Where-Object { $_ -like 'PCI\VEN_*' }).Count
$usbN = @($map.Keys | Where-Object { $_ -like 'USB\VID_*' }).Count
W ('INDEX = ' + $map.Count + ' hardware IDs (PCI ' + $pciN + ' / USB ' + $usbN + ')')
# v3.1 无线索引: 和有线同一轮、同一套动作, 只是文件是构建期由 wifi-inject 生成的第三份。
# 缺了同样只 WARN(26100 之前的镜像里根本没有这个文件)。
$wmap = @{}
if (Test-Path -LiteralPath $widx) {
  $wmap = Parse-Index $widx
  $wpci = @($wmap.Keys | Where-Object { $_ -like 'PCI\VEN_*' }).Count
  $wusb = @($wmap.Keys | Where-Object { $_ -like 'USB\VID_*' }).Count
  W ('WLANIDX = ' + $wmap.Count + ' wifi hardware IDs (PCI ' + $wpci + ' / USB ' + $wusb + ') from ' + $widx)
} else {
  W ('WARN = wifi index missing: ' + $widx + ' -- wired NICs still self-heal, wifi chips will be reported as SKIP (this ISO predates v3.1)')
}
# 两份网卡表合并成一张查表用的候选包表(无线键只出现在这里, 归 'net' 轮)
$netAll = Merge-Index $map $wmap
# 存储索引(21 行 Intel VMD/AHCI/VROC): 老镜像里没有这个文件 —— 只 WARN, 绝不能 ABORT,
# 否则 v3 脚本装进 v2 镜像就等于把开机自愈整个关掉。
$smap = @{}
if ($SkipStorage) { W 'STORIDX = skipped (-SkipStorage)' }
elseif (Test-Path -LiteralPath $sidx) {
  $smap = Parse-Index $sidx
  W ('STORIDX = ' + $smap.Count + ' storage hardware IDs from ' + $sidx)
} else {
  W ('WARN = storage index missing: ' + $sidx + ' -- NIC self-heal still runs, disks stay as the ISO left them (this ISO predates v3)')
}

# WMI 探测: startnet 的 [6] 还没跑, Winmgmt 可能没起来, 而枚举设备全靠它
function Test-Wmi {
  try { $null = @(Get-CimInstance -ClassName Win32_PnPEntity -EA Stop | Select-Object -First 1); return $true } catch { return $false }
}
if (-not (Test-Wmi)) {
  if ($DryRun) { W 'WMI not ready (DryRun: not starting winmgmt)' }
  else {
    W 'WMI not ready, net start Winmgmt ...'
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; & net start Winmgmt 2>&1 | Out-Null; $ErrorActionPreference = $prev
    for ($i = 0; $i -lt 10 -and -not (Test-Wmi); $i++) { Start-Sleep -Seconds 2 }
    W ('WMI ' + $(if (Test-Wmi) { 'ready' } else { 'STILL DOWN - cannot enumerate devices' }))
    if (-not (Test-Wmi)) {
      try { Add-Content -LiteralPath $stat -Value 'netdrvfix=fail reason=wmi-down' -Encoding ASCII -EA SilentlyContinue } catch { }
      exit 1
    }
  }
}

$snap = Get-NetDevs
$ad0 = Get-AdapterCount
$dk0 = Get-DiskCount
$sd0 = Get-SysDisk
W ('DEVS = ' + $snap.Count + ' PCI/USB devnodes / adapters before = ' + $ad0 + ' / disks before = ' + $dk0 + ' / sysdisk before = ' + $sd0.tok + $(if ($sd0.letters.Count) { ' (' + ($sd0.letters -join ',') + ')' } else { '' }))

# 要修的设备: problem code > 0, 且硬件ID在两份索引之一里(声卡/显卡不算)
#   排序 = 网卡在前、存储在后的稳定序(先修远程通道, 再救硬盘 —— 现场最怕的是"连不上", 其次是"看不见盘")
$todo = @()
function New-Todo($idv, $codev, $namev, $kindv) {
  $key = Get-Key $idv
  $src = if ($kindv -eq 'stor') { $smap } else { $netAll }
  $pkgs = @()
  if ($src.ContainsKey($key)) { $pkgs = @($src[$key]) }
  return [pscustomobject]@{ DeviceID = $idv; ConfigManagerErrorCode = $codev; Name = $namev; Key = $key; Kind = $kindv; Pkgs = $pkgs; Wlan = [bool]$wmap.ContainsKey($key) }
}
if ($Simulate) {
  $sk = Get-Key $Simulate
  $kind = 'net'
  if (-not $netAll.ContainsKey($sk)) {
    if ($sk -like 'PCI\VEN_*' -and $smap.ContainsKey($sk)) { $kind = 'stor' }
    else { W ('ABORT = simulated key ' + $sk + ' is in neither index (try a chip that is in netdrv_index.txt / wlandrv_index.txt / stodrv_index.txt)'); exit 1 }
  }
  $todo = @((New-Todo $Simulate $SimCode '(simulated)' $kind))
} else {
  $netList = @(); $stoList = @()
  foreach ($id in @($snap.Keys | Sort-Object)) {
    $d = $snap[$id]
    if ($d.code -le 0) { continue }
    $key = Get-Key $id
    $cl = Get-DevClass $key $map $smap $wmap
    if ($cl -eq 'net') { $netList += ,(New-Todo $id $d.code $d.name 'net') }
    elseif ($cl -eq 'stor') { $stoList += ,(New-Todo $id $d.code $d.name 'stor') }
    else {
      W ('SKIP = code' + $d.code + ' ' + $id + ' [' + (Cut $d.name) + '] key ' + $key + ' is not in the driver index')
    }
  }
  $todo = @($netList) + @($stoList)
}
$badNet = @(@($todo | Where-Object { $_.Kind -eq 'net' })).Count
$badSto = @(@($todo | Where-Object { $_.Kind -eq 'stor' })).Count
$badWlan = @(@($todo | Where-Object { $_.Wlan })).Count
$badN = @($todo).Count
foreach ($t in $todo) { W ('TODO = [' + $t.Kind + '] code' + $t.ConfigManagerErrorCode + '  ' + $t.DeviceID + '  key=' + $t.Key + '  [' + (Cut $t.Name) + ']') }

$bound = 0; $boundNet = 0; $boundSto = 0; $boundWlan = 0; $remain = @()
foreach ($t in $todo) {
  $cur = $t.DeviceID
  $key = $t.Key
  $pkgs = @($t.Pkgs)
  $code = [int]$t.ConfigManagerErrorCode
  W ('---- [' + $t.Kind + $(if ($t.Wlan) { ':wlan' } else { '' }) + '] ' + $key + ' (' + $pkgs.Count + ' candidate pkg, code ' + $code + ') ----')
  foreach ($act in (Get-ActionSeq $code $pkgs)) {
    if ($DryRun) {
      if ($act -like 'drvload:*' -or $act -like 'addinf:*') {
        $pk = $act.Substring($act.IndexOf(':') + 1)
        $infs = @(Resolve-InfList $pk)
        if ($infs.Count -gt 0) {
          # 同名包在库里可能有两版(iaStorVD 就是), 挨个试 -> 这里把几份都列出来, 现场一眼看得懂
          foreach ($inf in $infs) { W ('  [DryRun] would run: ' + (($act -split ':')[0]) + ' ' + $inf) }
        } else { W ('  [DryRun] ' + (($act -split ':')[0]) + ' SKIP: package ' + $pk + ' is not in ' + $fr) }
      } else {
        W ('  [DryRun] would run: pnputil /remove-device "' + $cur + '" && pnputil /scan-devices')
      }
      continue
    }
    if ($act -eq 'rescan') {
      $r = Run-Cmd $pnpu @('/remove-device', $cur)
      W ('  pnputil /remove-device "' + $cur + '" rc=' + $r.rc + ' out=' + $r.txt)
      Start-Sleep -Milliseconds 600
      $s = Run-Cmd $pnpu @('/scan-devices')
      W ('  pnputil /scan-devices rc=' + $s.rc + ' out=' + $s.txt)
      Start-Sleep -Seconds 2
    }
    elseif ($act -like 'drvload:*') {
      $pk = $act.Substring(8)
      $infs = @(Resolve-InfList $pk)
      if ($infs.Count -eq 0) { W ('  drvload SKIP = package not in store: ' + $pk); continue }
      # 同名包可能有几版(覆盖的芯片不完全一样), 一份试完没归零就换下一份
      foreach ($inf in $infs) {
        $r = Run-Cmd $drv @($inf)
        W ('  drvload ' + $inf + ' rc=' + $r.rc + ' out=' + $r.txt + '   (rc is not the verdict)')
        Start-Sleep -Seconds 2
        $v = Get-DevCode $cur $key (Get-NetDevs)
        $cur = $v.id; $code = $v.code
        if ($code -eq 0) { W ('  -> bound with ' + (Split-Path -Leaf $inf) + ' (code 0)'); break }
        if (@($infs).Count -gt 1) { W ('  -> code now ' + $code + ', will try the next copy of ' + $pk) }
      }
    }
    elseif ($act -like 'addinf:*') {
      $pk = $act.Substring(7)
      $infs = @(Resolve-InfList $pk)
      if ($infs.Count -eq 0) { W ('  add-driver SKIP = package not in store: ' + $pk); continue }
      $inf = @($infs)[0]          # /add-driver 入库只要一份就够(挑 DriverVer 最新的)
      $r = Run-Cmd $pnpu @('/add-driver', $inf, '/install')
      W ('  pnputil /add-driver ' + $inf + ' /install rc=' + $r.rc + ' out=' + $r.txt)
      $s = Run-Cmd $pnpu @('/scan-devices')
      W ('  pnputil /scan-devices rc=' + $s.rc + ' out=' + $s.txt)
      Start-Sleep -Seconds 2
    }
    # 复查: 只有 problem code 归零才算这块卡绑上了驱动
    $v = Get-DevCode $cur $key (Get-NetDevs)
    $cur = $v.id; $code = $v.code
    W ('  -> code now ' + $code + ' (devnode ' + $cur + ')')
    if ($code -eq 0) { break }
    if ($code -eq -1) { W '  -> devnode not back yet, one more rescan will fix the id lookup' }
  }
  if ($DryRun) { $code = [int]$t.ConfigManagerErrorCode }
  else {
    for ($i = 0; $i -lt 3 -and $code -ne 0; $i++) {
      Start-Sleep -Seconds 2
      $v = Get-DevCode $cur $key (Get-NetDevs)
      $cur = $v.id; $code = $v.code
    }
  }
  if ($code -eq 0) {
    $bound++; if ($t.Kind -eq 'net') { $boundNet++ } else { $boundSto++ }
    if ($t.Wlan) { $boundWlan++ }
    W ('  RESULT = code 0, driver bound (' + $key + ')')
  }
  else { $remain += ($t.Kind + $(if ($t.Wlan) { ':wlan' } else { '' }) + ':' + $key + '=code' + $code); W ('  RESULT = still code ' + $code + ' (' + $key + ') -- this chip needs a different driver') }
}

# ============================================================
# v3.2 WiFi 绑定层: 驱动 code 0 之后, 把 nativewifip / vwififlt / vwifibus 挂到这块卡上
# ============================================================
#   为什么要这一步(2026-10-12 实机 192.168.0.102, 见文件头 v3.2):
#     离线烘 Control\Network 的组件记录**不会让 PnP 去绑** —— 开机读数 wifi_entries=0 / 没有 FilterList /
#     devnode UpperFilters 为空, 于是整栈服务 Stopped, wlansvc 拿着句柄却没有接口可管。
#     实机证明只有两个钩子有效, 这里就是把它们做成开机动作(顺序照实测: 两条 netcfg 在前,
#     因为 UpperFilters 的效果要到 /restart-device 那一刻才落地)。
#   判据不看返回码, 只看复读: FilterList 里的 WiFi 条目数 + devnode 的 vwifibus + 三个服务在跑没有。
$netcfg = Resolve-Tool 'netcfg.exe'
function Get-WlanDevNodes {
  # 只看"驱动已经绑上(code 0)且无线索引认得"的 devnode: 绑定层对没驱动的卡没有意义, 对有线卡更没意义
  $sn = Get-NetDevs
  $r = @()
  foreach ($id in @($sn.Keys | Sort-Object)) {
    if ([int]$sn[$id].code -ne 0) { continue }
    if ($wmap.ContainsKey((Get-Key $id))) { $r += $id }
  }
  return $r
}
function Get-AdapterClassKey([string]$devId) {
  # 适配器 class 实例 = devnode 的 Driver 值('{classGUID}\NNNN'), 这是 probe93 实测可用的映射;
  # (宿主机正对照: Network 类里的 Linkage\PnpInstanceID **是空的**, 靠它匹配永远读不到 FilterList —— 别走这条路)
  $dk = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $devId
  $drvName = '' + (Get-ItemProperty -LiteralPath $dk -EA SilentlyContinue).Driver
  if (-not $drvName) { return '' }
  return ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\' + $drvName)
}
function Get-FlForDevice([string]$devId) {
  $out = @()
  $ck = Get-AdapterClassKey $devId
  if (-not $ck) { return $out }
  $j = Get-ItemProperty -LiteralPath ($ck + '\Linkage') -Name 'FilterList' -EA SilentlyContinue
  if ($null -eq $j) { return $out }
  $v = @($j.PSObject.Properties['FilterList'].Value)
  foreach ($x in $v) { $t = ("$x").Trim(); if ($t) { $out += $t } }
  return $out
}
function Get-UpperForDevice([string]$devId) {
  $p = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $devId
  $out = @()
  foreach ($x in @((Get-ItemProperty -LiteralPath $p -EA SilentlyContinue).UpperFilters)) {
    $v = ("$x").Trim(); if ($v) { $out += $v }
  }
  return $out
}
function Set-UpperForDevice([string]$devId, $list) {
  # 单元素也必须显式 -Type MultiString: 否则 reg provider 按 String 写, PnP 读不到过滤器名
  try {
    Set-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Enum\' + $devId) -Name 'UpperFilters' `
      -Value ([string[]]@($list)) -Type MultiString -EA Stop
    return $true
  } catch { W ('  WARN = cannot write UpperFilters on ' + $devId + ': ' + $_.Exception.Message); return $false }
}
function Resolve-WlanInf([string]$pkg) {
  # 镜像内固定路径优先(实机证明 X:\Windows\INF\netnwifi.inf 这条 netcfg 吃得下, 而且不依赖 DISM 的 oem### 编号)
  $p1 = Join-Path $sysRoot ('INF\' + $pkg)
  if (Test-Path -LiteralPath $p1 -EA SilentlyContinue) { return $p1 }
  $l = @(Resolve-InfList $pkg)
  if (@($l).Count -gt 0) { return @($l)[0] }
  return ''
}
function Get-SvcState([string]$name) {
  # 顺序有讲究: 宿主机正对照实测 Win32_Service 对 nativewifip/vwififlt/vwifibus 这类驱动服务返回 0 行,
  # 而 Get-Service 给的是 Running —— 先 CIM 会把"在跑的服务"读成 absent(和 FlOf 同一类错误)。
  try { $g = Get-Service -Name $name -EA Stop; if ($g) { return ('' + $g.Status) } } catch { }
  try {
    $s = @(Get-CimInstance Win32_Service -Filter ('Name="' + $name + '"') -EA Stop | Select-Object -First 1)
    if (@($s).Count -gt 0) { return ('' + $s[0].State) }
  } catch { }
  return ''
}
function Get-WlanBindReadout($devs) {  # 绑定层的"复读": WiFi 过滤器条目数取几块卡里最好的那个, vwifibus 只要有一块挂上就算, 服务数单独报
  $fl = 0; $up = $false
  foreach ($d in @($devs)) {
    $c = Count-WlanFilter (Get-FlForDevice $d)
    if ($c -gt $fl) { $fl = $c }
    if (Test-FlEntry (Get-UpperForDevice $d) 'vwifibus') { $up = $true }
  }
  $svc = @(); $up3 = 0
  foreach ($n in @('nativewifip', 'vwififlt', 'vwifibus')) {
    $st = Get-SvcState $n
    $svc += ($n + '=' + $(if ($st) { $st } else { 'absent' }))
    if ($st -eq 'Running') { $up3++ }
  }
  return @{ fl = $fl; up = $up; svcUp = $up3; svcTxt = ($svc -join ' ') }
}

# WDI 用户态宿主(任务 #40 烘进去的两个键)在真机是"由 WDI 框架按需拉起"的, 而 PE 里没有那个触发者:
# 两个键的 Start=3(手动), 开机 SCM 不会自己动它们 —— 所以这里显式 start 一次。
# 判据只看复读后的状态, 不看 net start 的返回码(PE 里 net 的输出不可靠)。
#   absent  = 服务键不在(这张盘早于 #40 的烘焙, 只能重出盘)
#   Stopped = 键在但没人起 —— 就是我们这一步要处理的
function Test-WdiHostNeeded([string]$st) { return ($st -ne '' -and $st -ne 'Running') }
function Start-WdiHosts {
  $txt = @(); $up = 0
  foreach ($n in @('WdiServiceHost', 'wdisystemhost')) {
    $st = Get-SvcState $n
    if (-not $st) { $txt += ($n + '=absent'); continue }
    if ((Test-WdiHostNeeded $st) -and -not $DryRun) {
      try { Start-Service -Name $n -EA Stop } catch { W ('  Start-Service ' + $n + ' failed: ' + (Cut $_.Exception.Message)) }
      Start-Sleep -Seconds 1
      $st = Get-SvcState $n
      if (Test-WdiHostNeeded $st) {
        $r = Run-Cmd 'net.exe' @('start', $n)
        W ('  net start ' + $n + ' rc=' + $r.rc + ' out=' + $r.txt)
        Start-Sleep -Seconds 2
        $st = Get-SvcState $n
      }
    }
    if ($st -eq 'Running') { $up++ }
    $txt += ($n + '=' + $st)
  }
  return @{ up = $up; txt = ($txt -join ' ') }
}

$wbTok = 'noop'; $wbFl = 0; $wbUp = $false; $wbSvc = 0; $wbDev = 0; $wbSvcTxt = 'skipped'
if ($SkipWlanBind) {
  W 'WLAN-BIND = skipped (-SkipWlanBind)'
} elseif (@($wmap.Keys).Count -eq 0) {
  W 'WLAN-BIND = noop (no wifi index on this ISO, v3.1 and older behaviour)'
} else {
  $wdevs = @(Get-WlanDevNodes)
  $wbDev = @($wdevs).Count
  if ($wbDev -eq 0) {
    W 'WLAN-BIND = noop (no wifi devnode has a working driver: fix the driver first, this step only binds filters)'
  } else {
    $infN = Resolve-WlanInf 'netnwifi.inf'
    $infV = Resolve-WlanInf 'netvwififlt.inf'
    $ncOk = (Test-Path -LiteralPath $netcfg -EA SilentlyContinue) -or [bool](Get-Command $netcfg -EA SilentlyContinue)
    W ('WLAN-BIND = ' + $wbDev + ' wifi devnode(s) with code 0 / netcfg=' + $(if ($ncOk) { 'present' } else { 'MISSING' }) +
       ' inf_nwifi=' + $(if ($infN) { (Cut $infN) } else { 'absent' }) + ' inf_vwifi=' + $(if ($infV) { (Cut $infV) } else { 'absent' }))
    $doneCmps = @(); $didRestart = @()
    foreach ($d in $wdevs) {
      $fl0 = @(Get-FlForDevice $d)
      $up0 = @(Get-UpperForDevice $d)
      W ('  before ' + (Cut $d) + ' cls=[' + (Cut (Get-AdapterClassKey $d)) + '] wifi_entries=' + (Count-WlanFilter $fl0) +
         ' filter_entries=' + @($fl0).Count + ' upper=[' + ($up0 -join ';') + ']')
      $plan = @(Get-WlanBindPlan $fl0 $up0 $(if ($ncOk) { $infN } else { '' }) $(if ($ncOk) { $infV } else { '' }))
      if (@($plan).Count -eq 0) { W '  plan = none (already bound)'; continue }
      foreach ($a in $plan) {
        # netcfg 装的是"这一类(NetService)的组件绑定", 是全机动作而不是每块卡一次:
        # 两块 WiFi 芯片时第二次的 -c s 只会白跑(还可能把第一次的结果重写), 所以每个组件只装一次。
        if ($a -like 'netcfg:*') {
          $cmpId = if ($a -like 'netcfg:nwifi:*') { 'MS_NativeWifiP' } else { 'ms_vwifi' }
          if ($doneCmps -contains $cmpId) { W ('  skip netcfg ' + $cmpId + ' (already installed for this class this run)'); continue }
          $doneCmps += $cmpId
        }
        if ($DryRun) { W ('  [DryRun] would run: ' + $a); continue }
        if ($a -like 'netcfg:nwifi:*') {
          $ip = $a.Substring(($a.IndexOf(':', 8) + 1))
          $r = Run-Cmd $netcfg @('-v', '-l', $ip, '-c', 's', '-i', 'MS_NativeWifiP')
          W ('  netcfg MS_NativeWifiP rc=' + $r.rc + ' out=' + $r.txt + '   (rc is not the verdict)')
        } elseif ($a -like 'netcfg:vwifi:*') {
          $ip = $a.Substring(($a.IndexOf(':', 8) + 1))
          $r = Run-Cmd $netcfg @('-v', '-l', $ip, '-c', 's', '-i', 'ms_vwifi')
          W ('  netcfg ms_vwifi rc=' + $r.rc + ' out=' + $r.txt + '   (rc is not the verdict)')
        } elseif ($a -eq 'upperfilters:vwifibus') {
          $newU = @(Merge-UpperFilters (Get-UpperForDevice $d) 'vwifibus')
          if (Set-UpperForDevice $d $newU) { W ('  wrote UpperFilters=[' + ($newU -join ';') + '] on ' + (Cut $d)) }
        } elseif ($a -eq 'restart-device') {
          $r = Run-Cmd $pnpu @('/restart-device', $d)
          W ('  pnputil /restart-device "' + $d + '" rc=' + $r.rc + ' out=' + $r.txt)
          $didRestart += $d
          Start-Sleep -Seconds 3
        }
      }
    }
    # netcfg 装完组件后, 已经挂着 vwifibus 的卡不会再走上面那条 restart(计划里没有它这一步),
    # 但新写进 FilterList 的绑定要到设备重绑那一刻才全部落地 —— 实机 10-12 的顺序是"netcfg -> 服务当场 Running",
    # 所以这一步是保险而不是主判据: 只在真跑了 netcfg、且这块卡本轮没被 restart 过时补一次。
    if ((-not $DryRun) -and (@($doneCmps).Count -gt 0)) {
      foreach ($d in $wdevs) {
        if ($didRestart -contains $d) { continue }
        $r = Run-Cmd $pnpu @('/restart-device', $d)
        W ('  pnputil /restart-device (after netcfg) "' + $d + '" rc=' + $r.rc + ' out=' + $r.txt)
        Start-Sleep -Seconds 3
      }
    }
    if ($DryRun) {
      $ro = Get-WlanBindReadout $wdevs
      $wbFl = $ro.fl; $wbUp = [bool]$ro.up; $wbSvc = $ro.svcUp; $wbSvcTxt = $ro.svcTxt
      $wbTok = Get-WlanBindToken $wbDev $wbFl $wbUp $wbSvc
      W ('  [DryRun] this machine reads wifi_entries=' + $wbFl + ' vwifibus=' + $wbUp + ' services[' + $wbSvcTxt + '] -> ' + $wbTok + ' (the plan above is what would run here)')
    } else {
      for ($i = 0; $i -lt 3; $i++) {
        $ro = Get-WlanBindReadout $wdevs
        if ((Get-WlanBindToken $wbDev $ro.fl $ro.up $ro.svcUp) -eq 'ok') { break }
        Start-Sleep -Seconds 2
      }
      $wbFl = $ro.fl; $wbUp = [bool]$ro.up; $wbSvc = $ro.svcUp; $wbSvcTxt = $ro.svcTxt
      $wbTok = Get-WlanBindToken $wbDev $wbFl $wbUp $wbSvc
      W ('  after  wifi_entries=' + $wbFl + ' vwifibus=' + $wbUp + ' services[' + $wbSvcTxt + '] -> ' + $wbTok)
    }
  }
}

# WDI 用户态宿主: 绑定层做到位之后, 把两个手动启动的 WDI 宿主拉一次(键是 #40 烘的, 触发者 PE 没有)
$wdiUp = -1; $wdiTxt = 'skipped'
if ($SkipWlanBind) { W 'WDI-HOST = skipped (-SkipWlanBind)' }
elseif ($wbDev -eq 0) { W 'WDI-HOST = noop (no bound wifi chip: nothing needs the WDI hosts)' }
else {
  $h = Start-WdiHosts
  $wdiUp = $h.up; $wdiTxt = $h.txt
  W ('WDI-HOST = ' + $wdiUp + '/2 ' + $wdiTxt + $(if ($DryRun) { '  (DryRun: read only, nothing was started)' } else { '' }))
}

# 复查: 物理网卡数 / IP —— 这才是"网卡起来了"的判据
$ad1 = Get-AdapterCount
W ('ADAPTERS = ' + $ad1 + ' (before ' + $ad0 + ')')
$ips = Get-MyIp
if (-not $DryRun) {
  for ($i = 0; $i -lt 8 -and @($ips).Count -eq 0; $i++) { Start-Sleep -Seconds 2; $ips = Get-MyIp }
  if (@($ips).Count -eq 0 -and $ad1 -gt 0) {
    W 'adapter is up but has no address, ipconfig /renew ...'
    $r = Run-Cmd 'ipconfig.exe' @('/renew')
    W ('  ipconfig /renew rc=' + $r.rc + ' out=' + $r.txt)
    Start-Sleep -Seconds 4
    for ($i = 0; $i -lt 5 -and @($ips).Count -eq 0; $i++) { $ips = Get-MyIp; if (@($ips).Count -eq 0) { Start-Sleep -Seconds 2 } }
  }
}
if (@($ips).Count -gt 0) { W ('IP = ' + ($ips -join ',')) } else { W 'IP = none' }

# 复查: 盘回来了没有 —— 救援的硬判据(12 代 i5 实机: drvload iaStorVD 之后 disks 1->3, D:\Windows 才出现)
$dk1 = Get-DiskCount
$sd1 = Get-SysDisk
if ($DryRun) { $sd1 = $sd0 }
W ('DISKS = ' + $dk1 + ' (before ' + $dk0 + ') / SYSDISK = ' + $sd1.tok + $(if ($sd1.letters.Count) { ' (' + ($sd1.letters -join ',') + ': has \Windows)' } else { ' (no fixed drive holds \Windows)' }))
$stoTok = Get-StoToken $badSto $boundSto $sd1.tok $dk0 $dk1
W ('STOR = ' + $stoTok + '  (broken ' + $badSto + ' / bound ' + $boundSto + ')')
W ('WLAN = ' + $(if ($boundWlan -gt 0) { 'bound' } elseif ($badWlan -gt 0) { 'fail' } else { 'noop' }) +
   '  (broken ' + $badWlan + ' / bound ' + $boundWlan + '; a bound wifi chip still needs `wlan` to join an AP)')
# v3.2: 绑定层单独一行 —— "驱动绑上了"和"wlansvc 有接口可管"是两件事, 现场必须一眼看出卡在哪一层
W ('WLAN-BIND = ' + $wbTok + ' (devnodes ' + $wbDev + ' / wifi_filter_entries ' + $wbFl + ' / vwifibus=' + $wbUp +
   ' / services_running ' + $wbSvc + '/3 ' + $wbSvcTxt + ')')

$tok = Get-StatusToken $badNet $boundNet $ips
$ipTxt = if (@($ips).Count -gt 0) { ($ips -join ',') } else { 'none' }
$line = ('netdrvfix=' + $tok + ' bound=' + $bound + ' adapters=' + $ad1 + ' ip=' + $ipTxt +
         ' stor=' + $stoTok + ' disks=' + $dk0 + '->' + $dk1 + ' sysdisk=' + $sd1.tok +
         ' wifi=' + $boundWlan + '/' + $badWlan + ' wbind=' + $wbTok + ' wfl=' + $wbFl +
         ' wupper=' + $(if ($wbUp) { 1 } else { 0 }) + ' wsvc=' + $wbSvc + '/3' +
         ' wdihost=' + $(if ($wdiUp -lt 0) { 'na' } else { "$wdiUp/2" }))
if ($remain.Count -gt 0) { $line += ' remain=' + ($remain -join ';') }
W ('REMAIN = ' + $(if ($remain.Count -gt 0) { ($remain -join ' ') } else { 'none' }))
if ($DryRun) {
  W ('PLAN   = would write to ' + $stat + ': ' + $line)
  W '==== netdrvfix end (DryRun) ===='
  exit 0
}
W ('STATUS = ' + $line)
try { Add-Content -LiteralPath $stat -Value $line -Encoding ASCII -EA Stop } catch { W 'WARN = cannot write status.txt' }
if ($tok -eq 'fail') { W 'NEXT = type `niccheck`, then read X:\niccheck.txt -- the chip that stayed broken is in REMAIN' }
elseif ($tok -eq 'partial') { W 'NEXT = driver is up but DHCP answered nothing: reseat the cable / try another switch port, then `ipconfig /renew`' }
elseif ($tok -eq 'ok') { W 'NEXT = ssh / sunlogin should work now' }
if ($stoTok -eq 'fail') { W 'NEXT(stor) = the storage chip is in REMAIN: type `rescue` anyway (it still works on whatever is visible), and check X:\stodrv_index.txt coverage' }
elseif ($stoTok -eq 'noop' -and $sd1.tok -eq 'missing') { W 'NEXT(stor) = no \Windows on a fixed disk and no broken storage devnode: the disk itself is invisible (RAID BIOS / broken cable / a chip this ISO has no driver for) -- type `storageprobe`' }
elseif ($stoTok -eq 'partial') { W 'NEXT(stor) = driver bound but \Windows still not visible: the volume may be BitLocker-locked or unmounted -- type `storageprobe`' }
elseif ($stoTok -eq 'ok') { W 'NEXT(stor) = the client OS partition is visible: type `rescue` to pull hives / dumps / event log' }
# v3.1: 无线这条腿单独给一句话 —— 驱动绑上 != 能上网(WiFi 还要 wlansvc + 配置文件),
#       现场最容易在这里以为"修好了却没有连接"。
if ($boundWlan -gt 0 -and @($ips).Count -eq 0) {
  W 'NEXT(wlan) = the wifi chip has its driver now, but there is no address: type `wlan` (it starts wcmsvc/wlansvc, then scan and connect; a profile in X:\Desktop\Wlan\wifi.conf is applied automatically)'
} elseif ($badWlan -gt 0 -and $boundWlan -eq 0) {
  W 'NEXT(wlan) = the wifi chip is in wlandrv_index.txt but stayed broken: collect the vendor package on a working PC (pe_getdriver), drop it into overlay\Drivers\Wlan and rebuild -- drvload in the field cannot fix a package that is not in the DriverStore'
}
# v3.2: 绑定层的下一步单独说 —— 这一层的症状是"驱动好好的, wlansvc 却看不到接口"
if ($wbTok -eq 'fail') {
  W 'NEXT(wbind) = netcfg put no WiFi filter behind the adapter: read the netcfg lines above (rc + text), then check X:\Windows\INF\netnwifi.inf and netvwififlt.inf exist (wifi-inject A3) -- if they are missing this ISO predates the vWiFi bake'
} elseif ($wbTok -eq 'partial') {
  W 'NEXT(wbind) = half bound (see wifi_entries / vwifibus / services above): run `netdrvfix` once more -- the class binding sometimes lands only after the device restart settles -- then `wlan`'
} elseif ($wbTok -eq 'ok') {
  W 'NEXT(wbind) = nativewifip + vwififlt + vwifibus are behind the adapter, so wlansvc has an interface to manage now: type `wlan` to scan and connect'
}
if ($wdiUp -eq 0 -and $wbDev -gt 0) {
  W 'NEXT(wdi) = neither WDI user-mode host runs: absent means this ISO predates the 2026-10-12 bake (task #40) -- rebuild; Stopped means SCM refused, read the net start line above'
} elseif ($wdiUp -lt 2 -and $wbDev -gt 0) {
  # 2026-10-12 probe108 定案: System32\wdi.dll 是 Windows Diagnostic Infrastructure(诊断框架),
  # 与无线的 WDI 驱动安装框架(wdiwifi.sys)只是撞名。这两个宿主**不在 WiFi 关键路径上**,
  # 它们不 Running 不是 wlansvc 早退的原因 —— 这一行只作镜像完整性提示, 别再据此追 wlansvc。
  W 'NEXT(wdi) = WDI diagnostic hosts not both Running -- NOTE(probe108): wdi.dll is the diagnostic framework, NOT the wifi driver-installation WDI; this does not block wlansvc. Chase wlansvc on its own early-exit line instead.'
}
# 2026-10-12: the two netcfg component records (ms_vwifi / ms_nativewifip under Control\Network\{4d36e974-...})
# are what put vwififlt + nativewifip into a WiFi adapter's Linkage\FilterList. wifi-inject bakes them offline
# now, so a disc that predates that bake can have a perfectly bound wifi chip and STILL give wlansvc no
# interface to manage. Say it here in one line -- otherwise the field reads "driver ok, no wifi" and chases
# drvload forever. Read-only, never throws: the judgement is a log line, not a repair.
$wcomp = 0
try {
  $ncr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
  foreach ($cg in @(@('{5CBF81BF-5055-47CD-9055-A76B2B4E3698}', 'ms_vwifi'),
                    @('{E475CF9A-60CD-4439-A75F-0079CE0E18A1}', 'ms_nativewifip'))) {
    $cidv = '' + (Get-ItemProperty -LiteralPath (Join-Path $ncr $cg[0]) -EA SilentlyContinue).ComponentId
    if ($cidv -eq $cg[1]) { $wcomp++ }
  }
} catch { }
W ('WLAN-COMP = ' + $wcomp + '/2 (netcfg component records: ms_vwifi + ms_nativewifip)')
if ($wcomp -ne 2 -and $wbTok -ne 'ok') {
  W 'NEXT(wlan) = this disc predates the 2026-10-12 component-record bake: even a bound wifi chip has no WiFi filter behind it, so wlansvc sees no interface -- burn a new ISO and check the wifi-inject evidence line reads comp_vwifi=1 comp_nwifi=1'
}

# ---------- 回传通道: 没网的时候把日志拷到启动 U 盘 ----------
function Get-UsbLetters {
  $set = @{}
  foreach ($d in @(Get-CimInstance Win32_DiskDrive -EA SilentlyContinue | Where-Object { "$($_.InterfaceType)".ToUpper() -eq 'USB' })) {
    $q1 = "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $d.DeviceID + "'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
    foreach ($p in @(Get-CimInstance -Query $q1 -EA SilentlyContinue)) {
      $q2 = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $p.DeviceID + "'} WHERE AssocClass=Win32_LogicalDiskToPartition"
      foreach ($ld in @(Get-CimInstance -Query $q2 -EA SilentlyContinue)) {
        $lv = "$($ld.DeviceID)".TrimEnd('\')
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
function Copy-Out {
  if ($NoCopy) { W 'LOGCOPY = skipped (-NoCopy)'; return }
  $cands = @()
  if ($CopyTo) { $cands = @((($CopyTo -replace '[:\\]', '')).ToUpper()) } else { $cands = @(Get-UsbLetters) }
  if ($cands.Count -eq 0) { W 'LOGCOPY = no USB volume found (plug in the boot USB stick and run netdrvfix again, or just type niccheck)'; return }
  $files = @($log, $stat, (Join-Path $volRoot 'niccheck.txt')) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
  foreach ($lv in $cands) {
    $dir = $lv + ':\winpe_logs'
    try {
      if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir -EA Stop | Out-Null }
      foreach ($f in $files) { Copy-Item -LiteralPath $f -Destination $dir -Force -EA Stop }
      $names = @($files | ForEach-Object { Split-Path -Leaf $_ } | Sort-Object -Unique)
      W ('LOGCOPY = ' + $dir + ' <- ' + ($names -join ', '))
      W ('LOGCOPY = read ' + $dir + ' from any PC that can mount this USB stick')
      return
    } catch { W ('LOGCOPY = ' + $lv + ': not writable (' + (Cut $_.Exception.Message) + ')') }
  }
  W 'LOGCOPY = every candidate volume refused -- photograph the screen instead'
}
Copy-Out
W '==== netdrvfix end ===='
if ($tok -eq 'fail') { exit 1 } else { exit 0 }
