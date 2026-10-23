# ============================================================
# wifi-inject.ps1 —— 把 WiFi 客户端栈(wlansvc / wcmsvc / wlanapi)注入已挂载的 WinPE 镜像
# 被 build.ps1 (全新构建) 和 patch_wifi.ps1 (只补 WiFi 的快速通道) 共用。
# 需要管理员权限 (reg load + dism), 由调用方保证。
#   powershell -NoProfile -ExecutionPolicy Bypass -File wifi-inject.ps1 -Mount <挂载点> [-DriverDir <驱动目录>]
#   自检(不需要管理员, 不碰真镜像): 同上 + -SelfTest
# ============================================================
param(
  [Parameter(Mandatory = $true)][string]$Mount,
  [string]$Overlay   = '',
  [string]$DriverDir = '',
  [switch]$NoDrivers,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
if (-not $Overlay) { $Overlay = Join-Path $Root 'overlay' }
$pe32   = Join-Path $Mount 'Windows\System32'
$host32 = 'C:\Windows\System32'
$DismExe = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe'

# ---------- 通用工具 ----------
# PS 5.1 的坑: $ErrorActionPreference='Stop' 时, 原生命令(reg.exe)只要往 stderr 写一个字就抛终止错误
# —— `reg unload` 未加载的配置单元、`reg query` 不存在的键 都会这样炸(2>$null 也拦不住)。
# 所以所有 reg.exe 都走这里: 局部降为 Continue, 并把输出收成一行的字符串供打印。
function Invoke-Reg([string[]]$ra) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $q = @($ra | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } })
    # 让 cmd 在 shell 层就把 reg.exe 的 stderr 并进 stdout: PS 就不会把每行 stderr 变成 ErrorRecord
    # (EAP=SilentlyContinue 虽然也不抛, 但会把 stderr 文字一起丢掉, 诊断信息就没了)
    $o = & cmd.exe /c ('reg.exe ' + ($q -join ' ') + ' 2>&1') | Out-String
  } finally { $ErrorActionPreference = $prev }
  return (($o -replace "`r?`n", ' ') -replace '\s{2,}', ' ').Trim()
}

# 挂载镜像里的文件常被标只读/ACL 拒绝直接覆盖, 先清属性删掉再复制
function Copy-IntoPe([string]$src, [string]$dst) {
  $dstDir = Split-Path $dst
  if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Force -Path $dstDir -ErrorAction Stop | Out-Null }
  if (Test-Path $dst) {
    # 出错要能被外层 try/catch 收到: 这一段跑在 EAP=Continue 下, 必须显式 Stop
    $it = Get-Item $dst -Force -ErrorAction Stop
    if ($it.Attributes -band [IO.FileAttributes]::ReadOnly) { $it.Attributes = 'Normal' }
    Remove-Item $dst -Force -ErrorAction Stop
  }
  Copy-Item $src $dst -Force -ErrorAction Stop
}

$files = @(
  'wlanapi.dll', 'wlansvc.dll', 'wlancfg.dll', 'wlanmsm.dll', 'wlanext.exe',
  'wlansec.dll', 'wlanutil.dll', 'wlansvcpal.dll', 'wlanhlp.dll',
  'wcmsvc.dll', 'dmcmnutils.dll', 'mdmregistration.dll', 'wci.dll', 'netshell.dll',
  # 2026-10-10 build\scratch\t_wdi_imports_host.ps1 逐个解析导入表得到的三个"延迟导入"缺口:
  # wlansvc.dll 的 delay 表里有 deviceassociation.dll / IpNatHlpClient.dll, wlanapi.dll 的有 WFDSConMgr.dll,
  # 而 PE 镜像(ADK 基础包)里没有它们。延迟导入不在 LoadLibrary 时解析, 所以缺了不会让服务起不来
  # (probe82/probe86 已证 wlansvc 能跑到 ServiceMain), 但一旦跑到那条代码路径就是 STATUS_DLL_NOT_FOUND ——
  # wcmsvc 那份 dump 的 R13=0xC0000135 就是这类失败的活样本。三个文件都小(61KB/32KB/72KB),
  # 且它们的**静态**导入在 PE 里全部可满足(同一脚本 phase 2 实测 PE-LACKS-STATIC=none), 借进来是净赚。
  'deviceassociation.dll', 'IpNatHlpClient.dll', 'WFDSConMgr.dll',
  # 2026-10-11 probe99 实机定案: PE 里 wcmsvc 一直报 1067(ERROR_DEPENDENCY_SERVICES_DO_NOT_EXIST 的兄弟码
  # "服务没有正常启动", win32=0x42B), 根因是它启动时要按 Services\wcmsvc\Csps\* 里的 Dll 值逐个加载 CSP,
  # 而镜像里既没有 wcmcsp.dll 也没有那三棵子键 —— 现场把两样都补上(文件 246,272B + 13 个值)之后
  # wcmsvc 当场 state=4 RUNNING、loaded=35、exit=0x0。这是本项目第一次把某个服务从红洗成绿, 所以两半都必须烘。
  'wcmcsp.dll',
  'drivers\nwifi.sys', 'drivers\ndisuio.sys'
)

# ---------- A4. L2Schemas: wlansvc 启动期必读的 XML Schema ----------
# 2026-10-12 12 代实机(AX211)定案。证据链:
#   probe155 进程内调 WlanSvcMain, 在 START_PENDING(t≈95ms)抓到第一手异常
#     p0=!-neg0xFFFFFFFF800C0006  (ERROR_INTERNET_UNRECOGNIZED_SCHEME),
#     栈里连着 14 层 msxml6 帧, 栈上明文是
#     [X:\windows\L2Schemas\WLAN_profile_v1.xsd] + [http://www.microsoft.com/networking/WLAN/profile/v1]。
#   也就是说 wlansvc 让 MSXML6 按命名空间去找本地 schema, 镜像里根本没有这个目录文件(PE 只有
#   LAN_policy_v1/LAN_profile_v1/OneX_v1 三份), 于是 MSXML 退化成"把命名空间当 URL 解析" -> 离线环境
#   没有 http scheme handler -> 0x800C0006 -> wlansvc 抛 C++ 对象并自退(t231ms 报 STOPPED)。
#   活体把这 7 个文件拷进 X:\Windows\L2Schemas 之后: wlansvc Start() -> Running(t+2/5/9/14 全 Running),
#   WlanOpenHandle rc=0, WlanEnumInterfaces n=1, WlanGetAvailableNetworkList rc=0 n=5(p159/p160)。
# 素材来自宿主机 C:\Windows\L2Schemas, 已按字节数固化进 overlay\L2Schemas(不依赖构建机版本)。
$l2xsds = @(
  'WLAN_profile_v1.xsd', 'WLAN_profile_v2.xsd', 'WLAN_profile_v3.xsd', 'WLAN_policy_v1.xsd',
  'WLANAP_profile_v1.xsd', 'WFD_profile_v1.xsd', 'WFD_LEGACY_profile_v1.xsd'
)

# ---------- A1. nwifi.sys 的配对目录文件(catalog) ----------
# nwifi.sys 是微软 inbox 驱动: PE 段没有内嵌 Authenticode(data dir[4] 全 0), 只能靠 CatRoot 里
# "覆盖它的那份 .cat"验签。镜像里没有这份 .cat => 代码完整性直接拦下:
#   NtLoadDriver 0xC0000428 / SCM error 577 ERROR_DRIVER_BLOCKED
#   => nativewifip 起不来 => wlansvc 初始化找不到 WiFi 对象, 150ms 内以 specific=0x800C0006 自杀。
# 2026-10-09 在活 PE 里把 overlay\Cats 这份 .cat 拷进 {F750E6C3-...} 存储, 同一台机器不重启再试,
# 拦下码立刻从 577 变成 31(ERROR_GEN_FAILURE = 这台测试机根本没有 802.11 设备), 即签名这道墙已拆掉。
# 名字必须保持原样(带 ~arch~version), CatRoot 的索引按文件名+哈希找, 改名就失效。
$CatStoreGuid = '{F750E6C3-38EE-11D1-85E5-00C04FC295EE}'
function Copy-NwifiCatalogs {
  $catSrc = Join-Path $Root 'overlay\Cats'
  $store  = Join-Path $Mount ('Windows\System32\CatRoot\' + $CatStoreGuid)
  if (-not (Test-Path $catSrc)) { Write-Host "    overlay\Cats 不存在, 跳过"; return 0 }
  $cats = @(Get-ChildItem $catSrc -Filter *.cat -File -EA SilentlyContinue)
  if ($cats.Count -eq 0) { Write-Host '    overlay\Cats 里没有 .cat, 跳过'; return 0 }
  if (-not (Test-Path $store)) {
    New-Item -ItemType Directory -Force -Path $store -ErrorAction Stop | Out-Null
    Write-Host ('    已创建 CatRoot 存储目录 ' + $CatStoreGuid)
  }
  $bad = 0
  foreach ($c in $cats) {
    $dst = Join-Path $store $c.Name
    if (Test-Path $dst) {
      $d = Get-Item $dst
      if ($d.Length -eq $c.Length) {
        Write-Host ('    ' + $c.Name + ' 已在镜像内(同尺寸 ' + [int]($c.Length/1KB) + 'KB), 不覆盖')
        continue
      }
    }
    try {
      Copy-IntoPe $c.FullName $dst
      Write-Host ('    已注入 ' + $c.Name + ' (' + [int]((Get-Item $dst).Length/1KB) + 'KB)')
    } catch {
      $bad++
      Write-Host ('    !! ' + $c.Name + ' 注入失败: ' + $_.Exception.Message) -ForegroundColor Red
    }
  }
  Write-Host ('    CatRoot\' + ($CatStoreGuid -replace '[{}]','').Substring(0,8) + ' 现有 .cat 数 = ' +
             (@(Get-ChildItem $store -Filter *.cat -File -EA SilentlyContinue)).Count)
  return $bad
}

# ---------- A4. L2Schemas 的 WLAN/WFD schema 文件 ----------
# 为什么单独一步而不塞进 $files: $files 全落 System32, 而这些文件必须待在 %Windows%\L2Schemas
# (wlansvc/MSXML6 拼的就是这个绝对路径), 而且 $files 的"已存在就不覆盖"分支对它们是错的 ——
# 缺文件才是本次的根因, 半截/旧文件同样致命, 所以这里按 overlay 的字节数强制对齐。
# 源优先级: overlay\L2Schemas(仓库里固化, 构建机不是 Win11 也能出盘) -> 宿主机 C:\Windows\L2Schemas(兜底)。
function Copy-L2Schemas {
  $srcOv = Join-Path $Root 'overlay\L2Schemas'
  $srcHost = 'C:\Windows\L2Schemas'
  $dstDir = Join-Path (Split-Path $pe32 -Parent) 'L2Schemas'
  $bad = 0; $put = @(); $miss = @()
  foreach ($n in $l2xsds) {
    $src = ''; $want = -1
    $o = Join-Path $srcOv $n
    $h = Join-Path $srcHost $n
    if (Test-Path $o) {
      $src = $o; $want = (Get-Item $o).Length
    } elseif (Test-Path $h) {
      $src = $h; $want = (Get-Item $h).Length
      Write-Host ('    ' + $n + ' overlay 里没有, 用宿主机兜底(' + $want + 'B) —— 建议把它补进 overlay\L2Schemas') -ForegroundColor Yellow
    } else {
      $miss += $n; $bad++; continue
    }
    $dst = Join-Path $dstDir $n
    try {
      # 同尺寸就不动(镜像里只读文件多, 无谓重写会白白触发 Copy-IntoPe 的删+拷)
      if ((Test-Path $dst) -and (Get-Item $dst).Length -eq $want) {
        $put += ('{0}({1}B 已在)' -f $n, $want); continue
      }
      Copy-IntoPe $src $dst
      $got = (Get-Item $dst).Length
      if ($got -ne $want) { Write-Host ('    !! ' + $n + ' 落地尺寸 ' + $got + ' != ' + $want) -ForegroundColor Red; $bad++; continue }
      $put += ('{0}({1}B)' -f $n, $got)
    } catch {
      $bad++
      Write-Host ('    !! ' + $n + ' 注入失败: ' + $_.Exception.Message) -ForegroundColor Red
    }
  }
  Write-Host ('    已放 ' + $put.Count + '/' + $l2xsds.Count + ': ' + ($put -join ' '))
  if ($miss.Count) { Write-Host ('    !! 素材缺失(既不在 overlay 也不在宿主机): ' + ($miss -join ',')) -ForegroundColor Red }
  Write-Host ('    镜像 ' + ($dstDir -replace [Regex]::Escape($Mount), '%MOUNT%') + ' 现有 .xsd 数 = ' +
             (@(Get-ChildItem $dstDir -Filter *.xsd -File -EA SilentlyContinue)).Count)
  return $bad
}

# ---------- A2. 无线网卡驱动索引(开机 netdrvfix 查的第三份表) ----------
# 2026-10-09 决定: 无线驱动池打进 ISO(精选档 9 目录 / 23 INF / 360MB), 与有线池同一套路
#   —— DISM 进 DriverStore, 开机由 netdrvfix 按"硬件ID -> 包名"表 drvload。
#   所以光把包塞进镜像不够: 表里没有那个 ID, netdrvfix 直接 SKIP, 360MB 白占 RAM。
# 生成放这里而不是 build.ps1: patch_wifi.ps1(只补 WiFi 的快速通道)只调本脚本,
#   两条出盘路径必须都带上这张表, 否则快速通道出的 ISO 会"有驱动没索引"。
function Install-WlanIndex {
  $out  = Join-Path $Overlay 'Scripts\wlandrv_index.txt'
  $pool = Join-Path $Overlay 'Drivers\Wlan'
  $mk   = Join-Path $Root 'test\17_MakeNetDrvIndex.ps1'
  $nInf = @(Get-ChildItem $pool -Recurse -Filter *.inf -File -EA SilentlyContinue).Count
  if ($SelfTest) {
    Write-Host ('    (自检) 跳过索引重算, 池内 ' + $nInf + ' 个 inf, 直接用现成的 ' + [IO.Path]::GetFileName($out))
  } elseif ($nInf -eq 0) {
    Write-Host '    池内没有 inf(overlay\Drivers\Wlan 为空), 不生成索引' -ForegroundColor Yellow
    return 0
  } elseif (-not (Test-Path $mk)) {
    Write-Host ('    !! 找不到索引生成器 ' + $mk) -ForegroundColor Red
    return 1
  } else {
    Write-Host ('    重算 wlandrv_index.txt: ' + $nInf + ' 个 inf, 段感知口径约 1 分钟 ...')
    $t0 = Get-Date
    try {
      & $mk -DrvDir $pool -Out $out 2>&1 | ForEach-Object { Write-Host ('      ' + $_) }
    } catch {
      Write-Host ('      !! 17_ 抛错: ' + $_.Exception.Message) -ForegroundColor Red
    }
    $it = Get-Item $out -EA SilentlyContinue
    if (-not $it -or $it.LastWriteTime -lt $t0) {
      Write-Host '    !! 索引没有更新(生成失败), 镜像里会用上一版或干脆没有这张表' -ForegroundColor Red
      if (-not (Test-Path $out)) { return 1 }
    }
  }
  if (-not (Test-Path $out)) {
    Write-Host ('    没有 ' + $out + ' —— 无线网卡开机不会自愈(只依赖镜像内置驱动)') -ForegroundColor Yellow
    return 0
  }
  $rows = @(Get-Content $out -EA SilentlyContinue | Where-Object { $_ -match "`t" })
  $pci  = @($rows | Where-Object { $_ -match '^PCI\\VEN_' }).Count
  $usb  = @($rows | Where-Object { $_ -match '^USB\\VID_' }).Count
  try {
    Copy-IntoPe $out (Join-Path $pe32 'wlandrv_index.txt')
  } catch {
    Write-Host ('    !! wlandrv_index.txt 复制失败: ' + $_.Exception.Message) -ForegroundColor Red
    return 1
  }
  Write-Host ('    已装 wlandrv_index.txt -> X:\Windows\System32 (' +
              [math]::Round((Get-Item $out).Length / 1KB, 1) + ' KB / 行 ' + $rows.Count +
              ' = PCI ' + $pci + ' + USB ' + $usb + ' / 池内 inf ' + $nInf + ')')
  if ($nInf -gt 0 -and $rows.Count -lt 20) {
    Write-Host '    !! 池里有 inf 但索引几乎没有: 段感知把整片判成"本 PE 绑不上", 先查 17_ 的输出再出盘' -ForegroundColor Red
    return 1
  }
  return 0
}

# ---------- WiFi 三件证据(纯读, 不写任何东西) ----------
# WiFi 这半条腿要同时满足三件事才算接上, 少任何一件开机都只是"没有 WiFi"而不会报错:
#   1) 覆盖 nwifi.sys 的 .cat 进了 CatRoot  ——  缺了 => nativewifip 被代码完整性拦下 => wlansvc 自杀(10-09 定案)
#   2) wlandrv_index.txt 进了 System32     ——  缺了 => netdrvfix 查不到硬件ID, 360MB 驱动池白占 RAM
#   3) 驱动池真的落了 DriverStore          ——  只有逐包比对能证明(/Recurse 会"进 22 拒 1"仍 rc=0)
# 判据故意写成英文 ASCII: 现场要靠截图/ssh 回传读这一行, 中文在 PE 侧会变成 ??。
# 抽成函数而不是直接写在收尾: -SelfTest 用假挂载点也要跑得到同一段代码(收尾在 SelfTest 的 exit 之后,
# 不抽出来的话这段逻辑就只能等用户那台管理员机器上第一次执行 —— 那是不允许的)。
# ---------- A3. 原生 WiFi 过滤栈(vwifibus / vwififlt / vwifimp / nwifi) ----------
# 2026-10-09 现场(probe33~40)定案: 无线网卡的 INF 用 Include=netvwifibus.inf + Needs=VWiFiBus.*
# 引这四个微软包, ADK 的 WinPE 组件里一个都没有, 所以设备永远停在 code 37 / 0xC00000BB,
# setupapi 反复报 "Needed section [VWiFiBus] not found, might exist in missing included INF"。
# 开机后再补的全部路子都实测死了(pnputil /add-driver=0xE000020F, drvload inf=0xE000022F,
# drvload sys=0x80070002, SetupCopyOEMInf=0xE000020F, 手写过滤键+restart-device 无效,
# NtLoadDriver 当时也全返回 0x80000002 —— 2026-10-10 更正: 那是我们自己的传参 bug(它收
# PUNICODE_STRING)。probe79 正确传参后内核给的真答案是六个目标全 0xC0000061, 结论不变。)
# 根因是 PE 不跑 catroot2/CryptSvc: 运行时无法用 catalog 数据库证明微软 INF 有签名, 而
# %windir%\INF 的索引在开机时已经定死。=> 只能离线烘: INF 进 Windows\INF + DriverStore,
# .sys 进 System32\drivers, .cat 进 CatRoot, 服务键进 SYSTEM 配置单元(services.exe 开机才认)。
# 素材由 test\20_MakeVWifiPool.ps1 从宿主机 C:\Windows 收集到 overlay\VWiFi。
$vwifiInfs = @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')
$vwifiSyss = @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys')
# 2026-10-10 新增(probe79/81 定案): WDI = Windows 无线驱动框架。现代无线 miniport 注册的入口是
#   ndis.sys 的 NdisMRegisterWdiMiniportDriver, 而 ndis 只做转发, 实现者在 wdiwifi.sys 的导出
#   Wdi_NdisMRegisterWdiMiniportDriver 里。镜像没有 wdiwifi => 驱动 DriverEntry 直接 0xC00000BB
#   => PnP 报 code37(CM_PROB_FAILED_DRIVER_ENTRY) + Services\Netwtw14\Enum\INITSTARTFAILED=1。
#   probe81 实测: D:/X: 上 48 个无线包里 35 个是 WDI, 声明 7A70 的 6 个 INF 全是 WDI, 没有经典包可绕。
#   NdisImPlatform = IM 过滤/内部虚拟 miniport 宿主(离线参考机与 vwififlt/nwifi 同时在册), 一起烘。
#   这两个没有可分发的微软 INF, 所以只走 .sys + 服务键 + 覆盖 .cat(Package04 覆盖 wdiwifi,
#   Package05112 覆盖 NdisImPlatform —— 由 20_MakeVWifiPool 的 crypt32 反查自动收进 overlay\Cats)。
$wdiSyss = @('wdiwifi.sys', 'NdisImPlatform.sys')
function Inject-VWifiFiles {
  $src = Join-Path $Root 'overlay\VWiFi'
  $infDst = Join-Path $Mount 'Windows\INF'
  $fail = @()
  if (-not (Test-Path $src)) {
    Write-Host "    !! overlay\VWiFi 不存在 —— 先跑 test\20_MakeVWifiPool.ps1" -ForegroundColor Red
    return @{ inf = 0; sys = 0; fail = @('NO_POOL') }
  }
  $nInf = 0; $nSys = 0
  foreach ($i in $vwifiInfs) {
    $s = Join-Path $src $i
    if (-not (Test-Path $s)) { $fail += ('pool缺inf:' + $i); continue }
    try { Copy-IntoPe $s (Join-Path $infDst $i); $nInf++ }
    catch { $fail += ($i + ':' + $_.Exception.Message) }
  }
  foreach ($y in ($vwifiSyss + $wdiSyss)) {
    $s = Join-Path $src $y
    $d = Join-Path $pe32 ('drivers\' + $y)
    if (-not (Test-Path $s)) { $fail += ('pool缺sys:' + $y); continue }
    # 比 SHA256 而不是比尺寸: 镜像里可能有上一轮手工塞进去的同尺寸不同版本文件
    # (实测活 PE 的 vwififlt.sys=19041.1202, 宿主机=19041.3636, 两者都是 77824 字节)。
    # CatRoot 里那份 .cat 只覆盖宿主机这一版, 留着旧的会被代码完整性判成"无目录文件"。
    $hs = (Get-FileHash -Algorithm SHA256 $s).Hash
    if ((Test-Path $d) -and (Get-Item $d).Length -lt 5MB) {
      $hd = try { (Get-FileHash -Algorithm SHA256 $d).Hash } catch { '' }
      if ($hd -eq $hs) { $nSys++; Write-Host ('      ' + $y + ' 已是宿主机版本, 保留'); continue }
      Write-Host ('      ' + $y + ' 版本不符, 覆盖为宿主机版本')
    }
    try { Copy-IntoPe $s $d; $nSys++ }
    catch { $fail += ($y + ':' + $_.Exception.Message) }
  }
  Write-Host ('    INF -> Windows\INF: ' + $nInf + '/' + $vwifiInfs.Count +
              ',  .sys -> System32\drivers: ' + $nSys + '/' + ($vwifiSyss.Count + $wdiSyss.Count) +
              ' (含 WDI 框架 ' + $wdiSyss.Count + ' 个)')
  if ($fail.Count) { Write-Host ('    !! ' + ($fail -join ' | ')) -ForegroundColor Red }
  return @{ inf = $nInf; sys = $nSys; fail = $fail }
}

# ---------- 一轮 DISM /Add-Driver(B 段与 B2 段共用) ----------
# 为什么长得跟"普通 DISM 命令"不一样, 两条都是拿实机报错换来的:
#  1) 绝对不要给 /Add-Driver 传 /Log —— 2026-10-09 17:12 那次出盘, 无线池(23 inf)和四个微软 vWiFi 包
#     全部 rc=87 而且我们的日志文件一个都没生成。宿主机 C:\Windows\Logs\DISM\dism.log 里那两行是根因:
#       "DISM Driver Manager: /log was not recognized by the driver manager provider (hr:0x80070057)"
#       "CDriverManager::Internal_DoAddDriverPackage(hr:0x80070057)"
#     /Log 只在部分提供程序有效, 驱动管理器在解析参数阶段就把整条命令拒了 => DriverStore 一个包没进。
#  2) 不要用 | Out-Null —— 那样 DISM 自己打印的错误文字被吞掉, 屏幕上只剩 rc=87, 现场无从判断。
#     正确做法照抄 test\16_InjectNetDrivers.ps1 里跑了 143+7 个包的那行: *>&1 收进文件,
#     "Installing k of N - xxx.inf: ..." 那行英文也正好是 Get-DismPkgReport 的解析对象。
#  3) EAP=Stop 时原生命令往 stderr 吐一个字就变终止错误, 所以这一段局部降为 Continue, 结果只看 $LASTEXITCODE。
function Invoke-DismAddDriver {
  param([string]$Driver, [string]$LogPath, [switch]$Recurse)
  if (-not (Get-Command Get-DismPkgReport -EA SilentlyContinue)) { . (Join-Path $Root 'test\DismReport.ps1') }
  New-Item -ItemType Directory -Force -Path (Split-Path $LogPath) | Out-Null
  if (Test-Path $LogPath) { Remove-Item $LogPath -Force }
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    if ($Recurse) {
      & $DismExe /Image:$Mount /Add-Driver /Driver:$Driver /Recurse /ForceUnsigned *>&1 | Out-File -FilePath $LogPath -Encoding UTF8
    } else {
      & $DismExe /Image:$Mount /Add-Driver /Driver:$Driver /ForceUnsigned *>&1 | Out-File -FilePath $LogPath -Encoding UTF8
    }
    $rc = $LASTEXITCODE
  } finally { $ErrorActionPreference = $prev }
  $rep = Get-DismPkgReport -LogPath $LogPath
  # rc!=0 时必须把 DISM 的原话带出来, 否则用户回贴的日志里只有数字, 又要重新猜
  if ($rc -ne 0) {
    Write-Host ('    DISM rc=' + $rc + ' 的输出尾巴(' + (Split-Path $LogPath -Leaf) + '):') -ForegroundColor Red
    @((Get-Content $LogPath -EA SilentlyContinue | Where-Object { "$_".Trim() -ne '' }) | Select-Object -Last 8) |
      ForEach-Object { Write-Host ('      ' + ($_ -replace '\s+', ' ')) -ForegroundColor Red }
    # DISM 那句 "check for log files in the <windir>\inf folder of the target image" 是真话:
    # 被拒的确切原因写在挂载点 Windows\INF\setupapi.offline.log 里, 而 patch_wifi 失败路径会 /Discard
    # 把整个挂载点连日志一起丢掉 —— 所以现在就把它捞到 build\scratch\salvage 并打出 error 行。
    if (Test-Path (Join-Path $Mount 'Windows\INF')) {
      @(& (Join-Path $Root 'test\Salvage-SetupapiLog.ps1') -Mount $Mount 2>&1 | ForEach-Object { "$_" }) |
        ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
    }
  }
  return @{ rc = $rc; rep = $rep }
}

# 尝试用 DISM 把这四个微软包写进镜像的 DriverStore 索引(这样 PnP 解析 Include=netvwifibus.inf 就有第二条路)。
# 逐包单独调用而不是 /Recurse 一次: /Recurse 会"进 N-1 拒 1"照样 rc=0(iaAHCIC 与无线池的教训)。
# 实测结果(2026-10-09 17:39 与 18:17 两轮一致): 只有 netvwifibus.inf 被拒 rc=13, 另外三个 successfully installed。
# 原因见 Get-WlanEvidence 里那段: 四个 INF 都没有 [SourceDisks*], 但只有 bus 那份写了 CopyFiles+[DestinationDirs],
# 于是只有它需要"定位文件源"并失败。所以这一段是"能进多少进多少 + 留证据", 返回值不参与出盘判据
# (判据看 cat/index/池 driverstore/vwifi_inf/vwifi_sys/vwifi_svc)。
function Add-VWifiDriverStore {
  $src = Join-Path $Root 'overlay\VWiFi'
  if (-not (Test-Path $DismExe)) { Write-Host "    !! 找不到 DISM: $DismExe" -ForegroundColor Red; return 0 }
  if (-not (Test-Path $src))     { Write-Host '    !! overlay\VWiFi 不存在, 跳过' -ForegroundColor Red; return 0 }
  . (Join-Path $Root 'test\DismReport.ps1')
  $ok = 0; $logBad = 0; $rcBad = 0; $badNames = @(); $okNames = @()
  foreach ($i in $vwifiInfs) {
    $inf = Join-Path $src $i
    if (-not (Test-Path $inf)) { Write-Host ('    缺 ' + $i) -ForegroundColor Yellow; continue }
    $tag = ($i -replace '[^A-Za-z0-9]', '')
    $drvLog = Join-Path $Root ('build\scratch\dism_add_vwifi_' + $tag + '_' + (Get-Date -Format 'HHmmss') + '.log')
    $r = Invoke-DismAddDriver -Driver $inf -LogPath $drvLog
    $rc = $r.rc; $rep = $r.rep
    $ran = $rep.present
    if (-not $ran) { $logBad++ }
    if ($rc -ne 0) { $rcBad++ }
    Write-Host ('    Add-Driver ' + $i + ' rc=' + $rc + ' 日志=' + $(if ($ran) { '有' } else { '!!无(这一步其实没执行)' }) + ' 进包=' + $rep.ok)
    if ($ran) { Write-Host (Format-DismPkgReport -Label ('vwifi:' + ($i -replace '\.inf$', '')) -Rep $rep) }
    if (($rc -eq 0) -and (@($rep.failed).Count -eq 0)) { $ok++; $okNames += $i } else { $badNames += $i }
    # 单个 INF 的调用形态偶尔不打 "Installing k of N" 那行(它本来是给 /Recurse 批量写的)。
    # 这种情况不算失败: 最终结论由收尾 Get-WlanEvidence 直接查挂载点 FileRepository 定, 这里只说明一句。
    if ($rc -eq 0 -and $ran -and $rep.ok -eq 0 -and @($rep.failed).Count -eq 0) {
      Write-Host ('    (rc=0 但日志里没有逐包行 —— 以收尾的 FileRepository 证据为准: ' + $i + ')') -ForegroundColor DarkGray
    }
  }
  if ($logBad) { Write-Host ('    !! ' + $logBad + ' 次 DISM 调用没留下日志 —— 那才是"这一步没执行"(EAP 或 DISM 路径问题)') -ForegroundColor Red }
  # 唯一"设计上就进不去"的是 netvwifibus.inf(它带 CopyFiles 却没有 [SourceDisks*] -> rc=13)。
  # 另外三个是纯 AddReg/Ndi 服务安装 INF, 没有文件要拷, 实测 rc=0 successfully installed —— 它们红了才是真红。
  $unexpected = @($badNames | Where-Object { $_ -ne 'netvwifibus.inf' })
  if ($unexpected.Count -gt 0) {
    Write-Host ('    !! vWiFi 暂存意外失败: ' + ($unexpected -join ', ') +
                ' —— 这三个不带 CopyFiles, 本该 rc=0, overlay\VWiFi 里的 INF 可能被改过或不是宿主机原件') -ForegroundColor Red
  }
  if (@($badNames | Where-Object { $_ -eq 'netvwifibus.inf' }).Count -eq 1) {
    Write-Host ('    vWiFi 包 DriverStore 暂存: ' + $ok + '/4 —— 唯 netvwifibus.inf 被 DISM 拒 rc=13, 符合预期' +
                '(它是四个里唯一写 CopyFiles+[DestinationDirs] 的, 而四个都没有 [SourceDisks*])') -ForegroundColor Yellow
    Write-Host '    这块盘能不能连 WiFi 由 vwifi_inf/vwifi_sys/vwifi_svc + 实机 setupapi 日志判定, 不由这一项判定' -ForegroundColor Yellow
  }
  Write-Host ('    (参考) vwifi_dism=' + $ok + '/4 成功: ' + $(if ($okNames.Count) { $okNames -join ',' } else { '-' }) +
              ' | 失败: ' + $(if ($badNames.Count) { $badNames -join ',' } else { '-' })) -ForegroundColor DarkGray
  return $ok
}


function Get-WlanEvidence {
  param([string]$Pe32, [string]$PoolDir, [int]$SvcCount = -1, [int]$DismOk = -1, [int]$WdiSvcCount = -1)
  $wfr   = Join-Path $Pe32 'DriverStore\FileRepository'
  $wbase = @(Get-ChildItem $PoolDir -Recurse -Filter *.inf -File -EA SilentlyContinue |
             ForEach-Object { $_.Name.ToLower() } | Sort-Object -Unique)
  $wds = 0
  if (Test-Path $wfr) {
    $wd = @(Get-ChildItem $wfr -Directory -EA SilentlyContinue | ForEach-Object { $_.Name.ToLower() })
    foreach ($b in $wbase) { if (@($wd | Where-Object { $_.StartsWith($b + '_') }).Count -gt 0) { $wds++ } }
  }
  $widxRows = @(Get-Content (Join-Path $Pe32 'wlandrv_index.txt') -EA SilentlyContinue | Where-Object { $_ -match "`t" }).Count
  $wcatN = 0
  $wcatWdi = 0
  $wstore = Join-Path $Pe32 ('CatRoot\' + $CatStoreGuid)
  if (Test-Path $wstore) {
    $wcatN = @(Get-ChildItem -LiteralPath $wstore -Filter 'Microsoft-Windows-Client-Desktop-Required-Package04*.cat' -File -EA SilentlyContinue).Count
    # Package05112 覆盖 NdisImPlatform.sys(2026-10-10 crypt32 反查), 缺了它这个驱动会被 CI 判 577
    $wcatWdi = @(Get-ChildItem -LiteralPath $wstore -Filter 'Microsoft-Windows-Client-Desktop-Required-Package05112*.cat' -File -EA SilentlyContinue).Count
  }
  $wbad = @()
  if ($wcatN -eq 0)     { $wbad += 'NO_CAT' }
  if ($widxRows -lt 20) { $wbad += 'NO_INDEX' }
  # netrtwlane02 是记录在案的唯一缺口(池里没有 rtlCoInst.dll/.dat), 所以允许比池内包数少 1
  if ($wbase.Count -gt 0 -and $wds -lt ($wbase.Count - 1)) { $wbad += 'PKG_SHORT' }

  # --- vWiFi 过滤栈: 文件在不在 + DISM 有没有真的把它们装进 DriverStore + 服务键写没写 ---
  $winfDir = Join-Path (Split-Path $Pe32 -Parent) 'INF'
  $vInfN = 0; foreach ($i in $vwifiInfs) { if (Test-Path (Join-Path $winfDir $i)) { $vInfN++ } }
  $vSysN = 0; foreach ($y in $vwifiSyss) { if (Test-Path (Join-Path $Pe32 ('drivers\' + $y))) { $vSysN++ } }
  $wdiSysN = 0; foreach ($y in $wdiSyss) { if (Test-Path (Join-Path $Pe32 ('drivers\' + $y))) { $wdiSysN++ } }
  $vDsN = 0
  if (Test-Path $wfr) {
    foreach ($i in $vwifiInfs) {
      $b = $i.ToLower()
      $hit = @(Get-ChildItem $wfr -Directory -EA SilentlyContinue | Where-Object { $_.Name.ToLower().StartsWith($b + '_') })
      if ($hit.Count -gt 0) { $vDsN++ }
    }
  }
  if ($vInfN -lt 4) { $wbad += 'VWIFI_INF' }
  if ($vSysN -lt 4) { $wbad += 'VWIFI_SYS' }
  # wcmsvc 的 CSP 文件(2026-10-11 probe99 实机: 没有 wcmcsp.dll 时 wcmsvc 每次启动都 1067 自退,
  # 补文件 + Services\wcmsvc\Csps 三棵子键之后当场 RUNNING)。键的形状由 Get-SvcShapeEvidence 的 C_CSP 管,
  # 这里只管文件在不在 System32 —— 两半缺一半都是同一个 1067, 但修法完全不同, 所以拆成两个 flag。
  $cspDll = Test-Path (Join-Path $Pe32 'wcmcsp.dll')
  if (-not $cspDll) { $wbad += 'CSP_DLL' }
  # WDI 框架(2026-10-10): 没有 wdiwifi.sys, 任何 WDI miniport 的 DriverEntry 都是 0xC00000BB => code37,
  # 前面的 vWiFi 过滤栈烘得再全也白搭; NdisImPlatform 缺覆盖它的 .cat 同样会被代码完整性拦下。
  if ($wdiSysN -lt $wdiSyss.Count) { $wbad += 'WDI_SYS' }
  if ($WdiSvcCount -ge 0 -and $WdiSvcCount -lt $wdiSyss.Count) { $wbad += 'WDI_SVC' }
  if ($wcatWdi -eq 0) { $wbad += 'WDI_CAT' }
# vwifi_store / vwifi_dism 只作参考, 不亮红旗(2026-10-09 18:17 出盘实测逐个点名):
#   四个包 DISM 只拒一个 —— netvwififlt/netvwifimp/netnwifi 都 rc=0 successfully installed,
#   唯独 netvwifibus.inf 回 rc=13 "数据无效"。差别在 INF 形状: 只有它写了
#   `CopyFiles = VWiFiBus.CopyFilesInternal` + [DestinationDirs](要把 vwifibus.sys 拷进 drivers),
#   而四个微软 inbox 服务安装 INF 全都没有 [SourceDisksNames]/[SourceDisksFiles] —— 没有 CopyFiles
#   的那三个不需要定位文件源, 所以 DISM 收得下; 需要定位源的那个必然收不下。宿主机 FileRepository
#   里这四个目录也只有 INF(netvwifimp 多一个 .PNF), 印证它们本来就不是可分发的驱动包。
#   => 结论: bus 包进不了 DriverStore 是这条路不存在, 不是我们的素材缺。开机时网卡 INF 的
#      Include=netvwifibus.inf 能不能靠"Windows\INF 里有这份 INF + System32\drivers 里有 .sys +
#      服务键已写"解析成功, 只有实机 setupapi 日志能定论(现场读数见 test\share\probe41.ps1)。
#   vwifi_store 统计的是 FileRepository 目录名, DISM 中止时可能留下半截目录, 所以它不能当判据;
#   vwifi_dism 统计的是真正的 rc=0 且逐包行报 successfully installed 的个数。
  if ($SvcCount -ge 0 -and $SvcCount -lt 3) { $wbad += 'VWIFI_SVC' }
  # L2Schemas(2026-10-12 12 代实机 probe155/158/159/160 定案): wlansvc 在 START_PENDING 里让 MSXML6 按
  # 命名空间 http://www.microsoft.com/networking/WLAN/profile/v1 去取 %Windows%\L2Schemas\WLAN_profile_v1.xsd,
  # 镜像里只有 LAN_*/OneX_* 三份 -> MSXML 退化成解析 URL -> 离线没有 http handler -> 异常参数
  # 0x800C0006(ERROR_INTERNET_UNRECOGNIZED_SCHEME) -> wlansvc 自退。把这 7 份 .xsd 放进目录之后当场
  # Running, 并且 WlanEnumInterfaces n=1 / WlanGetAvailableNetworkList rc=0 n=5。
  # 判据只看"文件在不在", 不看内容: 半截 .xsd 会以同样的方式炸, 而字节对齐由 Copy-L2Schemas 负责。
  $l2Dir = Join-Path (Split-Path $Pe32 -Parent) 'L2Schemas'
  $l2N = 0; $l2Miss = @()
  foreach ($n in $l2xsds) { if (Test-Path (Join-Path $l2Dir $n)) { $l2N++ } else { $l2Miss += $n } }
  if ($l2N -lt $l2xsds.Count) { $wbad += 'L2_XSD' }
  $wline = ('VERDICT wlan: cat=' + $wcatN + ' index_rows=' + $widxRows + ' driverstore=' + $wds + '/' + $wbase.Count +
            ' pool_inf=' + (@(Get-ChildItem $PoolDir -Recurse -Filter *.inf -File -EA SilentlyContinue).Count) +
            ' vwifi_inf=' + $vInfN + '/4 vwifi_sys=' + $vSysN + '/4 vwifi_store=' + $vDsN + '/4' +
            $(if ($DismOk -ge 0) { ' vwifi_dism=' + $DismOk + '/4' } else { '' }) +
            $(if ($SvcCount -ge 0) { ' vwifi_svc=' + $SvcCount + '/3' } else { '' }) +
            ' wdi_sys=' + $wdiSysN + '/' + $wdiSyss.Count +
            $(if ($WdiSvcCount -ge 0) { ' wdi_svc=' + $WdiSvcCount + '/' + $wdiSyss.Count } else { '' }) +
            ' wdi_cat=' + $wcatWdi + '/1' +
            ' csp_dll=' + $(if ($cspDll) { '1' } else { '0' }) +
            ' l2_xsd=' + $l2N + '/' + $l2xsds.Count + $(if ($l2Miss.Count) { '(' + ($l2Miss -join ',') + ')' } else { '' }) +
            ' flags=' + $(if ($wbad.Count) { ($wbad -join ',') } else { 'none' }))
  return @{ line = $wline; flags = $wbad; ds = $wds; pkgs = $wbase.Count; rows = $widxRows; cat = $wcatN;
            vinf = $vInfN; vsys = $vSysN; vds = $vDsN; dism = $DismOk; wdisys = $wdiSysN; wdicat = $wcatWdi;
            csp = $(if ($cspDll) { 1 } else { 0 }); l2 = $l2N; l2miss = ($l2Miss -join ',') }
}

# ---------- 证据行的落地 ----------
# 为什么要单独写文件: 控制台按窗口宽度(默认 120)折行, 而这条证据行 2026-10-10 加了 wdi_sys/wdi_svc/
# wdi_cat 之后有 ~170 字符, 在门禁的管道里必然被劈成两截 —— 判据会因为"排版"而不是"事实"变红。
# 所以自检里每行证据同时: (1) 原样(不折行)追加进 build\scratch\wlan_verify_selftest.txt(ASCII),
# (2) 打屏给人看。门禁只读文件。
$script:EvFile = ''
function Write-Ev([string]$label, [string]$line) {
  Write-Host ('  证据行(' + $label + ') = ' + $line)
  if ($script:EvFile) {
    try { Add-Content -LiteralPath $script:EvFile -Value $line -Encoding ASCII }
    catch { Write-Host ('    !! 证据文件写不进去: ' + $_.Exception.Message) -ForegroundColor Red }
  }
}

# ---------- A0+A. 文件 ----------
function Copy-WlanFiles {
  Write-Host '  [wifi-inject] A0. 同步启动脚本与 WiFi 配置模板 ...' -ForegroundColor Cyan
  foreach ($f in @('startnet.cmd', 'wlan.cmd')) {
    $src = Join-Path $Overlay ('Scripts\' + $f)
    if (-not (Test-Path $src)) { Write-Host "    !! 缺 $src" -ForegroundColor Yellow; continue }
    try { Copy-IntoPe $src (Join-Path $pe32 $f); Write-Host ('    ' + $f) }
    catch { Write-Host ('    !! ' + $f + ' 复制失败: ' + $_.Exception.Message) -ForegroundColor Red }
  }
  # A0b. 把 overlay\Scripts 的开机脚本与索引一起带进镜像。
  # 为什么放在 wifi-inject 而不是只放 build.ps1: patch_wifi.ps1(只补 WiFi 的快速通道)不调 build.ps1 的 4b,
  # 于是 2026-10-09 出的盘里 netdrvfix 还是 3.0(overlay 里已经是 3.1), 现场看到的行为和仓库不一致。
  # 两条出盘路径共用这一段, 就不会再有"改了 overlay 但快速通道没带上"的窗口。
  # 白名单 + 显式黑名单: 私钥(ssh_login_key)和 authorized_keys 一类永远不进镜像。
  $syncList = @(
    'netdrvfix.ps1', 'netdrvfix.cmd', 'niccheck.ps1', 'niccheck.cmd', 'onsite.ps1', 'onsite.cmd',
    'rescue.ps1', 'rescue.cmd', 'pe_getdriver.ps1', 'pe_getdriver.cmd', 'storageprobe.ps1', 'storageprobe.cmd',
    'pe_report.ps1', 'fw_off.ps1', 'netdrv_index.txt', 'stodrv_index.txt'
  )
  $syncBlack = @('ssh_login_key', 'administrators_authorized_keys', 'sshd_config')
  $synced = @(); $syncMiss = @(); $syncBad = @()
  foreach ($f in $syncList) {
    if ($syncBlack -contains ($f -replace '\.[a-z]+$', '')) { Write-Host "    !! 黑名单文件 $f 不同步" -ForegroundColor Red; continue }
    $src = Join-Path $Overlay ('Scripts\' + $f)
    if (-not (Test-Path $src)) { $syncMiss += $f; continue }
    try {
      Copy-IntoPe $src (Join-Path $pe32 $f)
      $synced += ('{0}({1})' -f $f, [int]((Get-Item (Join-Path $pe32 $f)).Length / 1KB))
    } catch { $syncBad += ($f + ': ' + $_.Exception.Message) }
  }
  Write-Host ('    同步开机脚本/索引 ' + $synced.Count + '/' + $syncList.Count + ' 个: ' + ($synced -join ' '))
  if ($syncMiss.Count) { Write-Host ('    overlay 里没有(跳过): ' + ($syncMiss -join ',')) -ForegroundColor Yellow }
  if ($syncBad.Count)  { Write-Host ('    !! 同步失败: ' + ($syncBad -join ' | ')) -ForegroundColor Red }
  # 版本自证: netdrvfix.ps1 头部那行版本号必须和 overlay 一致, 否则现场跑的仍是旧的
  $ovNd = Join-Path $Overlay 'Scripts\netdrvfix.ps1'
  $peNd = Join-Path $pe32 'netdrvfix.ps1'
  if ((Test-Path $ovNd) -and (Test-Path $peNd)) {
    $a = (Get-Item $ovNd).Length; $b = (Get-Item $peNd).Length
    Write-Host ('    netdrvfix.ps1 镜像/overlay 尺寸一致 = ' + ($a -eq $b) + ' (' + $b + '/' + $a + ')')
  }
  $wlanSrc = Join-Path $Overlay 'Desktop\Wlan'
  if (Test-Path $wlanSrc) {
    $dstDir = Join-Path $Mount 'Desktop\Wlan'
    New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
    foreach ($i in @(Get-ChildItem $wlanSrc -File)) {
      try { Copy-IntoPe $i.FullName (Join-Path $dstDir $i.Name); Write-Host ('    Desktop\Wlan\' + $i.Name) }
      catch { Write-Host ('    !! Desktop\Wlan\' + $i.Name + ' 复制失败: ' + $_.Exception.Message) -ForegroundColor Red }
    }
  }

  Write-Host '  [wifi-inject] A. 复制 WiFi 栈文件 ...' -ForegroundColor Cyan
  # PE 镜像里没有这些文件(ADK 无 WinPE WiFi 组件包, 微软官方也不支持 WinPE 跑 WiFi), 只能从主机 System32 借。
  # 已经存在的(PE 自带或上一轮已注入)一律不覆盖: 主机是 Win10 21H2(10.0.19044), 镜像是 ADK 26100,
  # 版本混用比缺文件更容易出问题。
  $copied = @(); $already = @(); $noHost = @(); $failed = @()
  foreach ($t in $files) {
    $src = Join-Path $host32 $t
    $dst = Join-Path $pe32 $t
    if (-not (Test-Path $src)) { $noHost += $t; continue }
    if (Test-Path $dst) { $already += ('{0}({1})' -f $t, [int]((Get-Item $dst).Length / 1KB)); continue }
    try {
      Copy-IntoPe $src $dst
      $copied += ('{0}({1})' -f $t, [int]((Get-Item $dst).Length / 1KB))
    } catch { $failed += ('{0}: {1}' -f $t, $_.Exception.Message) }
  }
  Write-Host ('    新复制 ' + $copied.Count + ' 个: ' + ($copied -join ' '))
  if ($already.Count) { Write-Host ('    PE 已存在(保留不覆盖) ' + $already.Count + ' 个: ' + ($already -join ' ')) }
  if ($noHost.Count)   { Write-Host ('    主机缺少(跳过): ' + ($noHost -join ',')) -ForegroundColor Yellow }
  if ($failed.Count)   { Write-Host ('    !! 失败: ' + ($failed -join ' | ')) -ForegroundColor Red }

  # 自研 WiFi 命令行工具(PE 内没有 netsh wlan 插件, 连接管理只能直调 wlanapi)
  $wifiExe = Join-Path $Overlay 'Tools\wifi.exe'
  if (Test-Path $wifiExe) {
    try {
      Copy-IntoPe $wifiExe (Join-Path $pe32 'wifi.exe')
      Write-Host ('    wifi.exe 版本 ' + (Get-Item $wifiExe).LastWriteTime + ' (' + (Get-Item $wifiExe).Length + ' bytes)')
    } catch { Write-Host ('    !! wifi.exe 复制失败: ' + $_.Exception.Message) -ForegroundColor Red }
  } else {
    Write-Host "    !! 缺 $wifiEx`n       先执行: powershell -NoProfile -ExecutionPolicy Bypass -File wifitool\build.ps1" -ForegroundColor Yellow
  }

  Write-Host '  [wifi-inject] A1. 注入覆盖 nwifi.sys 的 .cat(CatRoot) ...' -ForegroundColor Cyan
  $catFail = Copy-NwifiCatalogs
  Write-Host '  [wifi-inject] A2. 生成并注入无线网卡索引 wlandrv_index.txt ...' -ForegroundColor Cyan
  $idxFail = Install-WlanIndex
  Write-Host '  [wifi-inject] A3. 注入原生 WiFi 过滤栈 + WDI 框架(4 INF -> Windows\INF, 6 .sys -> drivers) ...' -ForegroundColor Cyan
  $vf = Inject-VWifiFiles
  $script:VWifiFiles = $vf
  Write-Host '  [wifi-inject] A4. 注入 L2Schemas 的 WLAN/WFD schema(缺 wlansvc 直接 0x800C0006 自退) ...' -ForegroundColor Cyan
  $xsdFail = Copy-L2Schemas
  return ($failed.Count + $catFail + $idxFail + @($vf.fail).Count + $syncBad.Count + $xsdFail)
}

# ---------- C. 注册表(与 hive 路径无关, 自检时指向 HKCU 临时键) ----------
# NetClass: SYSTEM\ControlSet001\Control\Network\{4d36e974-...}(netcfg 的 NetService 组件类)。
#   自检传 HKCU 假根, 真机传 HKLM:\PE_SYS2\...; 传空串就当这层不写(旧调用点兼容)。
function Write-WlanServiceKeys([string]$SVCHOST, [string]$SVCROOT, [string]$PeSystem32, [string]$NetClass = '') {
  # SVCHOST 组的 MULTI_SZ 值是"服务名列表"而不是 DLL 路径; svchost -k <组> 靠它找要加载的 DLL
  # 真实路径跑在 EAP=Continue 下(reg.exe 那段降过级), 这里所有写操作显式 Stop, 否则半截失败会被静默吞掉
  function Add-ToGroup([string]$group, [string]$svcName) {
    # @() 必须包住整条流水线: 组值只有一个成员时管道会塌成 string, 下一行 "$cur + $svcName" 就从
    # "追加元素"变成"字符串拼接", 写出 dot3svcwlansvc 这种不存在的成员名, 而且完全不报错。
    # (2026-10-10 由 build/scratch/t_p84_dryrun.ps1 的 HKCU 干跑复现)
    $cur = @(@((Get-ItemProperty $SVCHOST -Name $group -EA SilentlyContinue).$group) | Where-Object { $_ })
    if ($cur -notcontains $svcName) { $cur = @($cur) + @($svcName) }
    Set-ItemProperty $SVCHOST -Name $group -Value $cur -Type MultiString -Force -ErrorAction Stop
    Write-Host ("    组 $group = " + (@($cur) -join ','))
  }
  function Remove-GroupVal([string]$group) {
    if (Get-ItemProperty $SVCHOST -Name $group -EA SilentlyContinue) {
      Remove-ItemProperty $SVCHOST -Name $group -Force -ErrorAction Stop
      Write-Host "    删除遗留组值 $group"
    }
  }
  # 把某个服务名从 svchost 组里摘掉(其它成员必须原样保留)。用 @() 收值, 理由和 Add-ToGroup 一样:
  # 单成员时管道会塌成 string, 那时 -ne 比较和回写都会变成"整串字符"级别的操作。
  function Remove-FromGroup([string]$group, [string]$svcName) {
    $cur = @(@((Get-ItemProperty $SVCHOST -Name $group -EA SilentlyContinue).$group) | Where-Object { $_ })
    if ($cur -notcontains $svcName) {
      Write-Host ('    组 ' + $group + ' 里没有 ' + $svcName + ' (现状: ' + (@($cur) -join ',') + ')')
      return
    }
    $rest = @($cur | Where-Object { $_ -ne $svcName })
    if ($rest.Count -eq 0) {
      Remove-ItemProperty $SVCHOST -Name $group -Force -ErrorAction Stop
      Write-Host ('    组 ' + $group + ' 只剩 ' + $svcName + ', 整个值已删除')
    } else {
      Set-ItemProperty $SVCHOST -Name $group -Value $rest -Type MultiString -Force -ErrorAction Stop
      Write-Host ('    组 ' + $group + ' 已摘掉 ' + $svcName + ' -> ' + (@($rest) -join ','))
    }
  }
  function New-SvcKey([string]$name) {
    $k = Join-Path $SVCROOT $name
    if (-not (Test-Path $k)) { New-Item $k -Force -ErrorAction Stop | Out-Null }
    return $k
  }
  function Set-V([string]$k, [string]$n, $v, [string]$t) {
    Set-ItemProperty -Path $k -Name $n -Value $v -Type $t -Force -ErrorAction Stop
  }
  function Remove-V([string]$k, [string]$n) {
    if (Test-Path $k) {
      if (Get-ItemProperty $k -Name $n -EA SilentlyContinue) { Remove-ItemProperty $k -Name $n -Force -ErrorAction Stop }
    }
  }

  # 清掉早期版本里错误的自定义组(把 DLL 路径当服务名写进去, svchost 解析不了)
  Remove-GroupVal 'PEWLan'
  Remove-GroupVal 'PEWCm'
  if (Test-Path (Join-Path $SVCROOT 'nwifi')) {
    Remove-Item (Join-Path $SVCROOT 'nwifi') -Recurse -Force -ErrorAction Stop
    Write-Host '    删除错误的 nwifi 服务键'
  }

  # --- wlansvc: 形状改抄官方 WinRE(2026-10-12 build\scratch\p100_winre_reg\WR_svc_wlansvc.reg 逐值实测) ---
  #   Type=32(0x20 SHARE_PROCESS) + ImagePath = %SystemRoot%\system32\svchost.exe -k WlansvcGroup(没有 -p)
  #   SOFTWARE\...\CurrentVersion\Svchost: WlansvcGroup=[wlansvc] + 子键 CoInitializeSecurityParam=1
  #   DependOnService = nativewifip, RpcSs, Ndisuio ; Group=TDI ; ObjectName=LocalSystem ; ServiceSidType=1
  #   RequiredPrivileges 6 个 ; Parameters\ServiceMain=WlanSvcMain
  # 为什么换: 之前那版(Type=16 + -k LocalSystemNetworkRestricted -p)是照"宿主机(完整 Windows)"抄的,
  # 而 probe95 把 wlansvc 的两类失败分成了"WDI 用户态宿主"与"服务环境" —— 官方 WinRE 是同一个 WinPE 内核里
  # 真能把 wlansvc 跑到 RUNNING 的那一个, 它的 svchost 形状才是我们要对标的对象。宿主机只是"能跑"的证据,
  # 不是"在 PE 里能跑"的证据。
  # -p 的语义是 phase2 初始化(独占进程那条路), WinRE 不带它: 组名 WlansvcGroup 里只有 wlansvc 一个成员,
  # 所以共享进程路径照样给它开一个专属 svchost, 而 SCM 走的是"按组找宿主 + 组内服务全量启动"那条代码分支。
  # 保留的两处有意偏离(打印在形状结论里, 出问题时先看这两条):
  #   1) Start=3(手动) —— 参考机/WinRE 是 2(自启)。PE 里开机时序紧张, 由 startnet 的 wifi.exe svc start 拉起,
  #      免得 wlansvc 与 netdrvfix 抢设备; 代价是"没人调它就不会自己起", 这是我们想要的可控。
  #   2) DisplayName 用字面量 'WLAN AutoConfig (PE)' —— 参考机是资源串 @wlansvc.dll,-257, 字面量在 PE 的
  #      services.msc/控制台里更好读, 且不影响 SCM 语义。
  # 依赖列表按"键真的写了没有"动态生成(见下面 $wantNwifi/$wantNdisuio), 因为 nativewifip/Ndisuio 是
  # Type=1 内核驱动: 镜像里没有对应 .sys 时服务键不会写, 那时把它们写成硬依赖 = 必然 1068。
  $wantNwifi   = Test-Path (Join-Path $PeSystem32 'drivers\nwifi.sys')
  $wantNdisuio = Test-Path (Join-Path $PeSystem32 'drivers\ndisuio.sys')
  $wDeps = @()
  if ($wantNwifi) { $wDeps += 'nativewifip' }
  $wDeps += 'RpcSs'
  if ($wantNdisuio) { $wDeps += 'Ndisuio' }
  $w = New-SvcKey 'wlansvc'
  Set-V $w 'Type' 32 DWord
  Set-V $w 'Start' 3 DWord           # 手动: 由 startnet 里的 wifi.exe svc start 拉起(WinRE 是 2 自启, PE 不抢开机时序)
  Set-V $w 'ErrorControl' 1 DWord    # SCM 只枚举带此值名的服务键, 写成 Error 会被静默忽略
  Set-V $w 'Group' 'TDI' String
  Set-V $w 'ImagePath' '%SystemRoot%\System32\svchost.exe -k WlansvcGroup' ExpandString
  Set-V $w 'ObjectName' 'LocalSystem' String
  Set-V $w 'DisplayName' 'WLAN AutoConfig (PE)' String
  Set-V $w 'Description' '@%SystemRoot%\System32\wlansvc.dll,-258' ExpandString
  Set-V $w 'ServiceSidType' 1 DWord
  Set-V $w 'RequiredPrivileges' @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege', 'SeAuditPrivilege',
    'SeTcbPrivilege', 'SeDebugPrivilege', 'SeLoadDriverPrivilege') MultiString
  Set-V $w 'DependOnService' $wDeps MultiString
  $wp = Join-Path $w 'Parameters'
  if (-not (Test-Path $wp)) { New-Item $wp -Force -ErrorAction Stop | Out-Null }
  Set-V $wp 'ServiceDll' '%SystemRoot%\System32\wlansvc.dll' ExpandString
  Set-V $wp 'ServiceDllUnloadOnStop' 1 DWord
  Set-V $wp 'ServiceMain' 'WlanSvcMain' String
  Write-Host ('    wlansvc 键已写 (Type=0x20 -k WlansvcGroup 无 -p deps=' + ($wDeps -join ';') + ' ServiceMain=WlanSvcMain)')

  # --- wcmsvc: wlansvc 的 DLL 导入它, 顺带补齐; 起不来不影响 wlansvc(不作硬依赖) ---
  # 参考机实测(q56_host): Type=16 Start=2 Group=TDI ObjectName='NT Authority\LocalService'
  #                        RequiredPrivileges 只有 SeChangeNotify+SeImpersonate, DependOnService=RpcSs,NSI
  # ObjectName 这一条是本次最重要的修正: SCM 认的特殊账户名是 'LocalSystem' 和 'NT Authority\LocalService'
  # 这种全名, 之前写的裸 'LocalService' 不是这台机器上的账户名, 依赖一旦满足就会在登录那步失败(1069)。
  # RequiredPrivileges 从 4 个减到 2 个: 多写的 SeAudit/SeTcb 不在 LocalService 的令牌里, SCM 会忽略,
  # 但抄参考机能让"PE 与真机只差一处"这种事不再多一个候选解释。
  # DependOnService 仍只写 RpcSs: 参考机多一个 NSI, 而 probe86 实测 PE 里 Nsi 确实在跑(state=4 hostpid=1664),
  # 所以加不加都不影响能不能起来; 少一个依赖 = 少一种 1068, 现场调试时不想再多一个变量。
  $c = New-SvcKey 'wcmsvc'
  Set-V $c 'Type' 16 DWord
  Set-V $c 'Start' 3 DWord
  Set-V $c 'ErrorControl' 1 DWord
  Set-V $c 'Group' 'TDI' String
  Set-V $c 'ImagePath' '%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p' ExpandString
  Set-V $c 'ObjectName' 'NT Authority\LocalService' String
  Set-V $c 'DisplayName' 'Windows Connection Manager (PE)' String
  Set-V $c 'ServiceSidType' 1 DWord
  Set-V $c 'RequiredPrivileges' @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege') MultiString
  Set-V $c 'DependOnService' @('RpcSs') MultiString
  $cp = Join-Path $c 'Parameters'
  if (-not (Test-Path $cp)) { New-Item $cp -Force -ErrorAction Stop | Out-Null }
  Set-V $cp 'ServiceDll' '%SystemRoot%\System32\wcmsvc.dll' ExpandString
  Set-V $cp 'ServiceDllUnloadOnStop' 1 DWord
  Set-V $cp 'ServiceMain' 'WcmSvcMain' String
  Write-Host '    wcmsvc 键已写 (ServiceMain=WcmSvcMain)'

  # --- wcmsvc\Csps: 连接管理器按这张表逐个加载 CSP(2026-10-11 probe99 实机定案) ---
  # 证据: PE 里这张表整棵树都不存在, System32 里也没有 wcmcsp.dll, wcmsvc 每次都在启动阶段自退
  #   (win32=0x42B / 1067); 现场把 wcmcsp.dll(246,272B) 拷进 System32 + 把这三棵子键按宿主机值表写出来之后,
  #   wcmsvc 当场 state=4 RUNNING、模块 35 个、退出码 0x0 —— 同一个开机、同一次 SCM, 没有重启。
  # 值表来自 build\scratch\p97_stage\values99.tsv(宿主机 reg.exe 只读导出, 值是 UTF-16LE 的 base64,
  #   这里已经解成字面量)。cspethernet 没有 MediaService(宿主机就没有), 所以按 - 处理并显式删遗留值。
  # 为什么"文件不在就整棵不写": 指向一个不存在的 DLL 的 CSP 记录, 就是 wcmsvc 现在这个 1067 的形状;
  #   少一条记录 = 少一个加载目标, 让判据亮 C_CSP 红灯比留下半套形状更有用。
  $script:WcmCspCount = 0
  $cspDllInPe = Test-Path (Join-Path $PeSystem32 'wcmcsp.dll')
  if (-not $cspDllInPe) {
    Write-Host '    !! 镜像 System32 里没有 wcmcsp.dll(A 段没借到), 跳过 Csps 表 —— 判据会亮 C_CSP/CSP_DLL' -ForegroundColor Red
  } else {
    $csps = Join-Path $c 'Csps'
    if (-not (Test-Path $csps)) { New-Item $csps -Force -ErrorAction Stop | Out-Null }
    foreach ($d in @(
        @{ n = 'cspethernet'; ini = 'EthernetCspInit'; de = 'EthernetCspDeInit'; media = '';       mt = 1 },
        @{ n = 'cspwlan';     ini = 'WlanCspInit';     de = 'WlanCspDeInit';     media = 'wlansvc'; mt = 2 },
        @{ n = 'cspwwan';     ini = 'WwanCspInit';     de = 'WwanCspDeInit';     media = 'wwansvc'; mt = 3 })) {
      $k = Join-Path $csps $d.n
      if (-not (Test-Path $k)) { New-Item $k -Force -ErrorAction Stop | Out-Null }
      Set-V $k 'Dll' 'wcmcsp.dll' String
      Set-V $k 'InitFunction' $d.ini String
      Set-V $k 'DeinitFunction' $d.de String
      if ($d.media) { Set-V $k 'MediaService' $d.media String } else { Remove-V $k 'MediaService' }
      Set-V $k 'WcmMediaType' $d.mt DWord
      $script:WcmCspCount++
      Write-Host ('    Csps\' + $d.n + ' 已写 (Dll=wcmcsp.dll Init=' + $d.ini + ' Deinit=' + $d.de +
                  ' MediaService=' + $(if ($d.media) { $d.media } else { '-' }) + ' WcmMediaType=' + $d.mt + ')')
    }
    Write-Host ('    wcmsvc CSP 表写入数 = ' + $script:WcmCspCount + '/3')
  }

  # --- svchost 组(2026-10-12 换路线): wlansvc 从 LocalSystemNetworkRestricted 挪进自己的 WlansvcGroup ---
  # 官方 WinRE(WR_sw_sethost.reg) 就是这两条:
  #   Svchost: "WlansvcGroup"=multi:"wlansvc"
  #   Svchost\WlansvcGroup: CoInitializeSecurityParam=dword:1
  # 少了组值, svchost 拿到 -k WlansvcGroup 会"进程起来但一个服务都不加载"(服务停在 START_PENDING 然后自己退);
  # CoInitializeSecurityParam=1 是这套 COM 初始化时序的开关, WinRE 有, 我们照抄。
  Add-ToGroup 'WlansvcGroup' 'wlansvc'
  $wg = Join-Path $SVCHOST 'WlansvcGroup'
  if (-not (Test-Path $wg)) { New-Item $wg -Force -ErrorAction Stop | Out-Null }
  Set-V $wg 'CoInitializeSecurityParam' 1 DWord
  # 同一次构建里从旧形状迁过来时, LocalSystemNetworkRestricted 里还留着上一版的 wlansvc —— 必须摘掉:
  # 同一个服务出现在两个组里, svchost 会按它拿到的那个 -k 组加载, 而 SCM 侧的"共享宿主"记账会指向另一份,
  # 现场表现是"服务起不来 / 起来了又自己停"这类没有信息量的现象(2026-10 上半年我们一直在这种坑里绕圈)。
  Remove-FromGroup 'LocalSystemNetworkRestricted' 'wlansvc'
  Add-ToGroup 'LocalServiceNetworkRestricted' 'wcmsvc'

  # --- 原生 WiFi 驱动服务键: 有无线网卡设备时由 PnP 自动加载 ---
  # 值表逐条对齐宿主机 nativewifip 键(2026-10-09 probe25 读 C:\Windows 的参考形状):
  # Ndis*Version/DriverVersion 与 DefaultFilterSettings 缺了会不会导致加载失败? 实测无差(活 PE 里
  # 补齐后 nativewifip 仍是 dos=31), 但把它们写全能让离线镜像不依赖"某一轮构建碰巧留下了这些值"。
  if ($wantNwifi) {
    $n = New-SvcKey 'nativewifip'
    Set-V $n 'Type' 1 DWord
    Set-V $n 'Start' 3 DWord
    Set-V $n 'ErrorControl' 1 DWord
    Set-V $n 'ImagePath' 'system32\DRIVERS\nwifi.sys' ExpandString
    Set-V $n 'Group' 'NDIS' String
    Set-V $n 'DisplayName' '@%SystemRoot%\System32\drivers\nwifi.sys,-101' ExpandString
    Set-V $n 'NdisMajorVersion' 6 DWord
    Set-V $n 'NdisMinorVersion' 84 DWord          # 0x54 = NDIS 6.54, 与宿主机/镜像内现值一致
    Set-V $n 'DriverMajorVersion' 1 DWord
    Set-V $n 'DriverMinorVersion' 0 DWord
    $np = Join-Path $n 'Parameters'
    if (-not (Test-Path $np)) { New-Item $np -Force -ErrorAction Stop | Out-Null }
    Set-V $np 'DefaultFilterSettings' 1 DWord
    Write-Host '    nativewifip 驱动键已写 (含 Ndis*Version + Parameters\DefaultFilterSettings)'
  } else { Write-Host '    镜像内无 nwifi.sys, 跳过 nativewifip' -ForegroundColor Yellow }
  if ($wantNdisuio) {
    $nd = New-SvcKey 'Ndisuio'
    Set-V $nd 'Type' 1 DWord
    Set-V $nd 'Start' 3 DWord
    Set-V $nd 'ErrorControl' 1 DWord
    Set-V $nd 'ImagePath' 'system32\drivers\ndisuio.sys' ExpandString
    # Group 从 'PNP' 改成 'NDIS': 官方 WinRE 的 Ndisuio 就是 NDIS 组(WR_svc_ndisuio.reg), 而它现在是
    # wlansvc 的硬依赖 —— 组决定它由谁在什么时候带起来, 少一个与参考机的差 = 少一个候选解释。
    Set-V $nd 'Group' 'NDIS' String
    Set-V $nd 'DisplayName' 'NDIS Usermode I/O Protocol' String
    # Ndisuio 是 wlansvc 的硬依赖(WinRE 与宿主机都是), 缺 Ndis*Version / Parameters 时 NDIS 侧的注册形状
    # 和参考机不一致; 值抄宿主机(build\scratch\_host_wlan_ref3.txt: 6/30 + 0/0 + 空 Parameters)。
    Set-V $nd 'NdisMajorVersion' 6 DWord
    Set-V $nd 'NdisMinorVersion' 30 DWord
    Set-V $nd 'DriverMajorVersion' 0 DWord
    Set-V $nd 'DriverMinorVersion' 0 DWord
    $ndp = Join-Path $nd 'Parameters'
    if (-not (Test-Path $ndp)) { New-Item $ndp -Force -ErrorAction Stop | Out-Null }
    Write-Host '    Ndisuio 驱动键已写 (Group=NDIS, Ndis 6.30, 含空 Parameters —— 与参考机同形)'
  }

  # --- 原生 WiFi 过滤栈的三个驱动键(2026-10-09 probe33~40 的结论: 这三个键必须在"开机时就存在") ---
  # services.exe 在开机瞬间把 Services 子键读成它自己的服务数据库, 之后再往 hive 里加键, SCM 也看不见
  # (活 PE 里手写过的 vwifibus 键: reg query 值齐全, OpenServiceW 却是 1060)。PnP 起过滤驱动走的是
  # 同一份数据库, 所以离线镜像里就必须有这些键。
  # 值表逐条抄自宿主机(2026-10-09 实测 C:\Windows 的 CurrentControlSet\Services):
  #   vwifibus  Type=1 Start=3 ImagePath=\SystemRoot\System32\drivers\vwifibus.sys  (无 Group)
  #   vwififlt  Type=1 Start=1 Group=NDIS ImagePath=System32\drivers\vwififlt.sys  Ndis 6.50
  #   vwifimp   Type=1 Start=3 Group=NDIS ImagePath=\SystemRoot\System32\drivers\vwifimp.sys  Ndis 6.40
  # 不抄的两项: vwifibus/vwifimp 的 Owners(多值) 与 vwifimp 的 Tag —— 那是 PnP/DISM 自己算出来的
  # 运行期数据(宿主机上 Owners=oem57.inf;netwtw08.inf;netvwifibus.inf 是装过网卡之后才有的), 写死反而误导。
  $vwifiSvcs = 0
  $vw = @(
    @{ n='vwifibus'; sys='vwifibus.sys'; img='\SystemRoot\System32\drivers\vwifibus.sys'; start=3; group='';     dn='@%SystemRoot%\System32\drivers\vwifibus.sys,-257'; ds='@%SystemRoot%\System32\drivers\vwifibus.sys,-258'; ndmin=0;  dmaj=0; dmin=0 },
    @{ n='vwififlt'; sys='vwififlt.sys'; img='System32\drivers\vwififlt.sys';              start=1; group='NDIS'; dn='@%SystemRoot%\System32\drivers\vwififlt.sys,-259'; ds='@%SystemRoot%\System32\drivers\vwififlt.sys,-260'; ndmin=50; dmaj=1; dmin=0 },
    @{ n='vwifimp';  sys='vwifimp.sys';  img='\SystemRoot\System32\drivers\vwifimp.sys';   start=3; group='NDIS'; dn='@%SystemRoot%\System32\drivers\vwifimp.sys,-261'; ds='';                                    ndmin=40; dmaj=1; dmin=1 }
  )
  foreach ($t in $vw) {
    $sysName = $t.sys
    if (-not (Test-Path (Join-Path $PeSystem32 ('drivers\' + $sysName)))) {
      Write-Host ('    镜像里没有 ' + $sysName + ', 跳过 ' + $t.n + ' 键') -ForegroundColor Yellow
      continue
    }
    $k = New-SvcKey $t.n
    Set-V $k 'Type' 1 DWord
    Set-V $k 'Start' $t.start DWord
    Set-V $k 'ErrorControl' 1 DWord
    Set-V $k 'ImagePath' $t.img ExpandString
    Set-V $k 'DisplayName' $t.dn ExpandString
    if ($t.ds) { Set-V $k 'Description' $t.ds ExpandString } else { Remove-V $k 'Description' }
    if ($t.group) { Set-V $k 'Group' $t.group String } else { Remove-V $k 'Group' }
    if ($t.ndmin -ne 0) {
      Set-V $k 'NdisMajorVersion' 6 DWord
      Set-V $k 'NdisMinorVersion' $t.ndmin DWord
      Set-V $k 'DriverMajorVersion' $t.dmaj DWord
      Set-V $k 'DriverMinorVersion' $t.dmin DWord
    }
    $vwifiSvcs++
    Write-Host ('    ' + $t.n + ' 驱动键已写 (Start=' + $t.start + ' Group=' + $(if ($t.group) { $t.group } else { '-' }) + ')')
  }
  $script:WwifiSvcCount = $vwifiSvcs
  Write-Host ('    vWiFi 服务键写入数 = ' + $vwifiSvcs + '/3')

  # --- WDI 框架 + IM 平台宿主(2026-10-10, probe79/81 定案后新增) ---
  # 值表逐条抄自离线参考机 D:\Windows 的 ControlSet001\Services(probe78 §6 全量导出):
  #   wdiwifi         Type=1 Start=3 ErrorControl=1 ImagePath=system32\DRIVERS\wdiwifi.sys
  #                   Parameters: ForceLogsInMiniDump=1, WppRecorder_TraceGuid={21ba7b61-...}
  #   NdisImPlatform  Type=1 Start=3 ErrorControl=1 ImagePath=System32\drivers\NdisImPlatform.sys
  #                   Parameters: AdapterFilterAllowList=ms_netmon;MS_NdisCap, 另三个名单为空
  # 两个键都**不写 Group**(参考机也没有): Group 会把驱动排进开机 GroupOrderList 的批次, 而它们该由
  # NDIS 在 miniport 调 NdisMRegisterWdiMiniportDriver / 注册内部虚拟适配器时按服务名动态加载。
  # 空名单照样写出来(而不是省略), 是为了让离线镜像与参考机的键形状一致 —— 少一个值名这种事,
  # 将来只有实机能证伪, 现场调试时不想再多一个变量。
  $wdiSvcs = 0
  $wdiDefs = @(
    @{ n = 'wdiwifi'; sys = 'wdiwifi.sys'; img = 'system32\DRIVERS\wdiwifi.sys'; start = 3;
       dn = 'WDI Driver Framework'; ds = '';
       pr = @( @{ k = 'ForceLogsInMiniDump';   v = 1; t = 'DWord' },
               @{ k = 'WppRecorder_TraceGuid'; v = '{21ba7b61-05f8-41f1-9048-c09493dcfe38}'; t = 'String' } ) },
    @{ n = 'NdisImPlatform'; sys = 'NdisImPlatform.sys'; img = 'System32\drivers\NdisImPlatform.sys'; start = 3;
       dn = '@%SystemRoot%\System32\drivers\ndisimplatform.sys,-501';
       ds = '@%SystemRoot%\System32\drivers\ndisimplatform.sys,-501';
       pr = @( @{ k = 'AdapterFilterAllowList';          v = @('ms_netmon', 'MS_NdisCap'); t = 'MultiString' },
               @{ k = 'AdapterProtocolAllowList';        v = ''; t = 'MultiString' },
               @{ k = 'VirtualMiniportFilterBlockList';  v = ''; t = 'MultiString' },
               @{ k = 'VirtualMiniportProtocolBlockList'; v = ''; t = 'MultiString' } ) }
  )
  foreach ($t in $wdiDefs) {
    if (-not (Test-Path (Join-Path $PeSystem32 ('drivers\' + $t.sys)))) {
      Write-Host ('    镜像里没有 ' + $t.sys + ', 跳过 ' + $t.n + ' 键(先跑 test\20_MakeVWifiPool.ps1)') -ForegroundColor Yellow
      continue
    }
    $k = New-SvcKey $t.n
    Set-V $k 'Type' 1 DWord
    Set-V $k 'Start' $t.start DWord
    Set-V $k 'ErrorControl' 1 DWord
    Set-V $k 'ImagePath' $t.img ExpandString
    Set-V $k 'DisplayName' $t.dn String
    if ($t.ds) { Set-V $k 'Description' $t.ds String } else { Remove-V $k 'Description' }
    Remove-V $k 'Group'
    Remove-V $k 'DependOnService'
    $kp = Join-Path $k 'Parameters'
    if (-not (Test-Path $kp)) { New-Item $kp -Force -ErrorAction Stop | Out-Null }
    foreach ($p in $t.pr) { Set-V $kp $p.k $p.v $p.t }
    $wdiSvcs++
    Write-Host ('    ' + $t.n + ' 驱动键已写 (Start=' + $t.start + ' 无 Group, Parameters=' +
                (($t.pr | ForEach-Object { $_.k }) -join ',') + ')')
  }
  $script:WdiSvcCount = $wdiSvcs
  Write-Host ('    WDI 服务键写入数 = ' + $wdiSvcs + '/' + $wdiDefs.Count)

  # --- WDI 用户态宿主: WdiServiceHost + wdisystemhost(2026-10-12 probe94 具名的缺口) ---
  # 证据: 实机 OpenService('WdiServiceHost') => 1060 ERROR_SERVICE_DOES_NOT_EXIST, P94 的 ROW-FINAL 打的是
  #   <key absent>; 而同一个探针对 X:\Windows\System32\wdi.dll(118,784B, ADK 自带) 给的是
  #   LoadLibraryEx OK + GetProcAddress(ServiceMain) OK —— 文件层没缺, 缺的是"让这份 DLL 作为服务跑起来"的
  #   SCM 记录。内核侧的 WDI 框架(wdiwifi.sys)上一轮已经烘通并 Running。
  # ★口径修正(2026-10-12 probe108): 这份 System32\wdi.dll 的字符串是 clientcore\base\diagnosis\pdi\wdi\
  #   framework\..., 导出 WdipETWRegister/CWdiHandler::WdipLaunchUserHost, 读 Control\WDI\Config 与
  #   Control\WDI\DiagnosticModules(30 个 GUID), 写 System32\WDI\LogFiles\WdiContextLog.etl —— 它是
  #   Windows Diagnostic Infrastructure(诊断框架), 与无线的 driver-installation WDI(wdiwifi.sys) 只是撞名。
  #   所以这两个宿主**不在 WiFi 关键路径上**, 本段只是把镜像补全, 不要再拿它们的 1052 当 wlansvc 的线索;
  #   wlansvc 自退(0x800C0006)当下的候选见 probe109: 运行时晚绑定模块缺失(宿主 82 个 / PE 38 个)。
  # 形状抄宿主机只读实测(build\scratch\p106_host_wdisvc.txt 第 1/16 行 + _host_wlan_ref3.txt 第 1 节):
  #   两者都是 Type=32 Start=3 ErrorControl=1 ServiceSidType=1,
  #   Parameters{ServiceDll=…\wdi.dll, ServiceMain=ServiceMain, ServiceDllUnloadOnStop=1};
  #   WdiServiceHost = ObjectName 'NT AUTHORITY\LocalService' + -k LocalService -p +
  #                    RequiredPrivileges SeChangeNotify/SeImpersonate(参考机还列了第三条 SeSystemProfile,
  #                    但 2026-10-11 probe104 实机证明: PE 的 LSA 里没有这条特权 -> SCM 起服务回 1297
  #                    ERROR_NO_SUCH_PRIVILEGE, 服务直接起不来。所以按 PE 实测裁剪, 不照抄参考机);
  #   wdisystemhost  = ObjectName LocalSystem + -k LocalSystemNetworkRestricted -p
  #                    (它的特权表没在参考机里读全 => 干脆不写, 交给 SCM 给默认值, 别猜)。
  #   FailureActions / Security(SACL) / 资源化的 DisplayName 都刻意不抄 —— 与 P2 同一口径(无人值守救援盘
  #   不该有自动重启动作, SD 不是功能, 而 -502/-503 这种字符串资源在 PE 里本来就没有本地化需求)。
  # 为什么只能离线烘: services.exe 开机瞬间把 Services 子键读成它自己的服务数据库, 之后新建的键它看不见
  #   (vwifibus 那一课: reg query 值齐全, OpenServiceW 仍 1060), 所以活体探针永远验不了这一项, 必须重启才算。
  $script:WdiHostCount = 0
  foreach ($h in @(
      @{ n = 'WdiServiceHost'; obj = 'NT AUTHORITY\LocalService'; grp = 'LocalService';
         priv = @('SeChangeNotifyPrivilege', 'SeImpersonatePrivilege') },
      @{ n = 'wdisystemhost';  obj = 'LocalSystem';               grp = 'LocalSystemNetworkRestricted';
         priv = @() })) {
    $k = New-SvcKey $h.n
    Set-V $k 'Type' 32 DWord
    Set-V $k 'Start' 3 DWord
    Set-V $k 'ErrorControl' 1 DWord
    Set-V $k 'ObjectName' $h.obj String
    Set-V $k 'ServiceSidType' 1 DWord
    Set-V $k 'ImagePath' ('%SystemRoot%\System32\svchost.exe -k ' + $h.grp + ' -p') ExpandString
    if (@($h.priv).Count) { Set-V $k 'RequiredPrivileges' $h.priv MultiString } else { Remove-V $k 'RequiredPrivileges' }
    $kp = Join-Path $k 'Parameters'
    if (-not (Test-Path $kp)) { New-Item $kp -Force -ErrorAction Stop | Out-Null }
    Set-V $kp 'ServiceDll' '%SystemRoot%\System32\wdi.dll' ExpandString
    Set-V $kp 'ServiceMain' 'ServiceMain' String
    Set-V $kp 'ServiceDllUnloadOnStop' 1 DWord
    # svchost 组: 键写了但组值里没有它 => svchost 拿着 -k <组> 起来却不会加载这份 DLL,
    # 表现和"没有这个服务"几乎一样(2026-10-12 之前 WlansvcGroup 缺值就是这么坑的), 所以键与组一起算一项。
    Add-ToGroup $h.grp $h.n
    $script:WdiHostCount++
    Write-Host ('    ' + $h.n + ' 键已写 (Type=32 Start=3 acct=[' + $h.obj + '] -k ' + $h.grp +
                ' -p privs=' + $(if (@($h.priv).Count) { (@($h.priv) -join ',') } else { 'SCM 默认' }) +
                ' dll=wdi.dll!ServiceMain)')
  }
  Write-Host ('    WDI 宿主服务键写入数 = ' + $script:WdiHostCount + '/2')

  # --- P0: 无线栈的两个 netcfg 组件实例记录(2026-10-12 的决定性差量, 逐值抄自官方 WinRE) ---
  # 证据链: build\scratch\p100_reg_diff.txt 里 `TREE ctl_network :: keys A=66 B=60 only-A=6`, 那 6 行
  #   全是这两棵树(Control\Network\{4d36e974-...}\{GUID} 各自的 Ndi 与 Ndi\Interfaces), 也就是说
  #   WinRE 与我们的镜像在整张 NetService 组件表上**只差 WiFi 这两个组件**; 宿主机(host_component_records.txt
  #   §3/§4) 的同两条记录与 WinRE 逐值一致, GUID 也是同一对 —— 它们是 netcfg 从 INF 算出来的常量,
  #   不是每台机器随机生成(probe90 用同一对 GUID 在活 PE 里建键, 组件表当场从 2 变 4)。
  # 为什么必须离线烘: 组件记录是网卡实例 Linkage\FilterList 的来源, 而 FilterList 只在开机 PnP 枚举那一次
  #   生成; "运行时补组件/补 WDI" 已定案不可行(任务 #22), 所以缺这两棵树 = 无线 miniport 后面永远挂不上
  #   vwififlt / nativewifip = wlansvc 起来也没有可管理的 WiFi 接口。
  $script:WifiCompWritten = 0
  if ($NetClass) {
    $compDefs = @(
      @{ guid = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'; cid = 'ms_vwifi';
         inf = 'netvwififlt.inf'; sec = 'Install';         fmt = 'vwifi,vchannel';
         res = '@%windir%\System32\drivers\vwififlt.sys,-105';
         help = '@%windir%\System32\drivers\vwififlt.sys,-106'; svc = '' },
      @{ guid = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'; cid = 'ms_nativewifip';
         inf = 'netnwifi.inf';    sec = 'MS_NWIFI.Install'; fmt = 'wlan';
         res = '@%windir%\System32\drivers\nwifi.sys,-101';
         help = '';                                         svc = 'NativeWifiP' }
    )
    # InstallTimeStamp / Ndi\TimeStamp 是 SYSTEMTIME(WinRE 里那两位 = 2015-12-04, 即 WinRE 镜像的装机日期);
    # Ndi 子键那份只有 15 字节(微软自己就少写一个字节)。原样抄: netcfg 只拿它排"装过的先后", 不参与任何判定,
    # 而自造"今天的日期"会让两代镜像的字节永远对不上, 现场 diff 时凭空多一列噪声。
    $ts16 = @(0xdd, 0x07, 0x0c, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    $ts15 = @($ts16[0..14])
    if (-not (Test-Path $NetClass)) { New-Item $NetClass -Force -ErrorAction Stop | Out-Null }
    # 组件记录里的 InfPath 必须真的在镜像的 Windows\INF 里, 否则 netcfg 开机解析它会报错;
    # 缺 INF 时宁可不写这条记录, 让判据亮 COMP_* 红灯(A3/Inject-VWifiFiles 那条路自己会报文件缺失)。
    $infDir = Join-Path (Split-Path $PeSystem32 -Parent) 'INF'
    foreach ($cd in $compDefs) {
      if (-not (Test-Path (Join-Path $infDir $cd.inf))) {
        Write-Host ('    镜像 INF 目录里没有 ' + $cd.inf + ', 跳过组件记录 ' + $cd.cid + ' —— 判据会亮 COMP_* 红灯') -ForegroundColor Yellow
        continue
      }
      $ck = Join-Path $NetClass $cd.guid
      New-Item $ck -Force -ErrorAction Stop | Out-Null
      Set-V $ck 'InstallTimeStamp' $ts16 Binary
      Set-V $ck 'Characteristics' 0x00040028 DWord
      Set-V $ck 'ComponentId' $cd.cid String
      Set-V $ck 'Description' $cd.res String
      Set-V $ck 'InfPath' $cd.inf String
      Set-V $ck 'InfSection' $cd.sec String
      Set-V $ck 'LocDescription' $cd.res String
      $cn = Join-Path $ck 'Ndi'
      New-Item $cn -Force -ErrorAction Stop | Out-Null
      Set-V $cn 'TimeStamp' $ts15 Binary
      if ($cd.help) { Set-V $cn 'HelpText' $cd.help String } else { Remove-V $cn 'HelpText' }
      # Ndi\Service 只有 ms_nativewifip 有(宿主机和 WinRE 两边实测 ms_vwifi 都没有这一条);
      # 之前 probe90 给 ms_vwifi 写了 Service=vwififlt, 那是我们自己猜的, 现在按权威参照删掉。
      if ($cd.svc) { Set-V $cn 'Service' $cd.svc String } else { Remove-V $cn 'Service' }
      $ci = Join-Path $cn 'Interfaces'
      New-Item $ci -Force -ErrorAction Stop | Out-Null
      Set-V $ci 'LowerRange' 'nolower' String
      Set-V $ci 'UpperRange' 'noupper' String
      Set-V $ci 'FilterMediaTypes' $cd.fmt String
      $script:WifiCompWritten++
      Write-Host ('    组件记录 ' + $cd.cid + ' ' + $cd.guid + ' 已烘 (InfPath=' + $cd.inf + ' InfSection=' +
                  $cd.sec + ' Ndi\Service=' + $(if ($cd.svc) { $cd.svc } else { '-' }) +
                  ' FilterMediaTypes=' + $cd.fmt + ')')
    }
    Write-Host ('    WiFi 组件记录写入数 = ' + $script:WifiCompWritten + '/2')
  } else {
    Write-Host '    !! 调用方没传 NetClass(Control\Network 的 NetService 类键), 组件记录这层没烘 —— 出盘前必须补' -ForegroundColor Red
  }
  # 写完立刻从同一份配置单元读回来判形状(参考机读数 = build\scratch\q56_host.txt):
  # 这几个值错了, 现场只会出现"服务起不来/起来了又自己停了"这种没有信息量的现象, 不该留到实机去比对。
  $script:SvcShape = Get-SvcShapeEvidence $SVCROOT $SVCHOST $NetClass
  Write-Host ('    ' + $script:SvcShape.line)
  if (@($script:SvcShape.flags).Count) {
    Write-Host ('    !! 服务键形状与参考机不符: ' + ($script:SvcShape.flags -join ',') +
                ' —— 现场会表现成 1068/1069/服务自己停, 不要出盘') -ForegroundColor Red
  }
  return $vwifiSvcs
}

# 机器可读的服务键形状结论: 每个 flag 都对应一个"错了就会在服务启动上栽跟头"的值。
# SVCHOST / NetClass 传空串时对应的检查整组跳过(打印 '-' 而不是 0, 免得"没检查"看起来像"检查没过")。
function Get-SvcShapeEvidence([string]$SVCROOT, [string]$SVCHOST = '', [string]$NetClass = '') {
  $wl = Get-ItemProperty (Join-Path $SVCROOT 'wlansvc') -EA SilentlyContinue
  $wc = Get-ItemProperty (Join-Path $SVCROOT 'wcmsvc') -EA SilentlyContinue
  $wP = Get-ItemProperty (Join-Path $SVCROOT 'wlansvc\Parameters') -EA SilentlyContinue
  $cP = Get-ItemProperty (Join-Path $SVCROOT 'wcmsvc\Parameters') -EA SilentlyContinue
  $bad = @()
  # 打印用的中间量, 默认 '-' = 没检查/键不存在; 每个都要能在反向自检里被点亮
  $wKgrp = '-'; $wP2 = '-'; $sGrp = '-'; $sCiso = '-'; $sLsnr = '-'
  $compV = '-'; $compN = '-'
  # 10-11/10-12 新增三项(CSP 表 / 两个 WDI 宿主键): '-' = 这一层根本没检查(调用方没给 SVCROOT 之外的路径时同理)
  $cCsp = '-'; $wdiH = '-'; $wdiS = '-'
  if ($null -eq $wl) { $bad += 'W_ABSENT' }
  if ($null -eq $wc) { $bad += 'C_ABSENT' }
  if ($null -ne $wl) {
    # Type 必须是 32(0x20 SHARE_PROCESS): 官方 WinRE 的 wlansvc 就是 32 + -k WlansvcGroup(不带 -p),
    # 组里只有 wlansvc 一个成员, 所以"共享进程"这条路照样给它开一个专属 svchost, 但走的是组加载分支。
    if ([int]$wl.Type -ne 32) { $bad += 'W_TYPE' }
    if ('' + $wl.ObjectName -ne 'LocalSystem') { $bad += 'W_OBJ' }
    if ('' + $wl.Group -ne 'TDI') { $bad += 'W_GROUP' }
    if (@($wl.RequiredPrivileges).Count -ne 6) { $bad += 'W_PRIV' }
    # ImagePath: -k 后面必须是 WlansvcGroup, 而且不能带 -p(那是"独占进程"的 phase2 开关, WinRE 没有)
    $imgTxt = '' + $wl.ImagePath
    $mg = [regex]::Match($imgTxt, '-k\s+(\S+)')
    if ($mg.Success) { $wKgrp = $mg.Groups[1].Value }
    if ($imgTxt -match '\s-p(\s|$)') { $wP2 = '1' } else { $wP2 = '0' }
    if ($wKgrp -ne 'WlansvcGroup') { $bad += 'W_IMG' }
    if ($wP2 -ne '0') { $bad += 'W_IMGP' }
    # 依赖按"这两个驱动键真的写了没有"来算(与上面 $wantNwifi/$wantNdisuio 同一套判据),
    # 镜像里没 .sys 时依赖列表就不该有它们 —— 少写/多写都会亮 W_DEPS, 因为现场差别是 1068。
    $exp = @()
    if (Test-Path (Join-Path $SVCROOT 'nativewifip')) { $exp += 'nativewifip' }
    $exp += 'RpcSs'
    if (Test-Path (Join-Path $SVCROOT 'Ndisuio')) { $exp += 'Ndisuio' }
    if ((@($wl.DependOnService) -join ';') -ne ($exp -join ';')) { $bad += 'W_DEPS' }
    if ('' + $wP.ServiceMain -ne 'WlanSvcMain') { $bad += 'W_MAIN' }
    if ('' + $wP.ServiceDll -notmatch 'wlansvc\.dll$') { $bad += 'W_DLL' }
  }
  if ($null -ne $wc) {
    if ([int]$wc.Type -ne 16) { $bad += 'C_TYPE' }
    # SCM 认的特殊账户名是全名('NT Authority\LocalService'), 裸 'LocalService' 在这台机器上不是账户名,
    # 依赖一旦满足就会在登录那步失败(1069)。这是本次修正里最要紧的一条。
    if ('' + $wc.ObjectName -ne 'NT Authority\LocalService') { $bad += 'C_OBJ' }
    if ('' + $wc.Group -ne 'TDI') { $bad += 'C_GROUP' }
    if (@($wc.RequiredPrivileges).Count -ne 2) { $bad += 'C_PRIV' }
    if ((@($wc.DependOnService) -join ';') -ne 'RpcSs') { $bad += 'C_DEPS' }
    if ('' + $cP.ServiceMain -ne 'WcmSvcMain') { $bad += 'C_MAIN' }
    if ('' + $cP.ServiceDll -notmatch 'wcmsvc\.dll$') { $bad += 'C_DLL' }
  }
  # wcmsvc 的 CSP 表(2026-10-11 probe99 实机: 补齐之前每次 1067 自退, 补齐之后当场 state=4 RUNNING)。
  # 判"三条记录都在 + 各自的 Dll/InitFunction/WcmMediaType 非空", 不判具体函数名 —— 函数名由写入点保证,
  # 而"少一条"或"Dll 不是 wcmcsp.dll"才是现场会看到的 1067。
  $cspN = 0
  foreach ($cn in @('cspethernet', 'cspwlan', 'cspwwan')) {
    $cv = Get-ItemProperty (Join-Path $SVCROOT ('wcmsvc\Csps\' + $cn)) -EA SilentlyContinue
    if ($null -ne $cv -and ('' + $cv.Dll -eq 'wcmcsp.dll') -and ('' + $cv.InitFunction) -and
        ([int]$cv.WcmMediaType -ge 1)) { $cspN++ }
  }
  $cCsp = '' + $cspN + '/3'
  if ($cspN -ne 3) { $bad += 'C_CSP' }
  # WDI 用户态宿主(2026-10-12 probe94: 实机 OpenService=1060, 而 wdi.dll 本身能 LoadLibrary + 拿到 ServiceMain)。
  # 一条记录算两项: SCM 侧的键形状(共享进程 + -k 组名 + wdi.dll!ServiceMain)与 svchost 侧的组成员。
  # 组里少名字的后果和键不存在几乎一样 —— svchost 拿着 -k <组> 起来却不去加载这份 DLL, 所以必须一起判。
  $shAll = $null
  if ($SVCHOST) { $shAll = Get-ItemProperty $SVCHOST -EA SilentlyContinue }
  foreach ($h in @(@{ n = 'WdiServiceHost'; g = 'LocalService'; fl = 'S_WDIH'; tag = 'wdi_host' },
                   @{ n = 'wdisystemhost';  g = 'LocalSystemNetworkRestricted'; fl = 'S_WDISH'; tag = 'wdi_shost' })) {
    $hk = Join-Path $SVCROOT $h.n
    $hv = Get-ItemProperty $hk -EA SilentlyContinue
    $hp = Get-ItemProperty (Join-Path $hk 'Parameters') -EA SilentlyContinue
    $okh = 0
    if ($null -ne $hv) {
      $okh = 1
      if ('' + $hv.ImagePath -notmatch ('-k\s+' + $h.g + '(\s|$)')) { $okh = 0 }
      if ('' + $hp.ServiceDll -notmatch 'wdi\.dll$') { $okh = 0 }
      if ('' + $hp.ServiceMain -ne 'ServiceMain') { $okh = 0 }
      if ([int]$hv.Type -ne 32) { $okh = 0 }
      if ($null -ne $shAll) {
        $gname = $h.g
        $gv = @(@($shAll.$gname) | Where-Object { $_ })
        if ($gv -notcontains $h.n) { $okh = 0 }
      }
    }
    if ($h.tag -eq 'wdi_host') { $wdiH = '' + $okh } else { $wdiS = '' + $okh }
    if ($okh -ne 1) { $bad += $h.fl }
  }
  # svchost 组这一层(WinRE 的 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost):
  #   缺 WlansvcGroup=[wlansvc] => svchost 拿着 -k WlansvcGroup 起来, 但一个服务都不加载, wlansvc 停在
  #   START_PENDING 之后自己退; 留着 LocalSystemNetworkRestricted 里的 wlansvc => 同一个服务在两个组里,
  #   SCM 的宿主记账和 svchost 实际加载的服务集合对不上。两条都是"服务起不来"级, 所以都进判据。
  if ($SVCHOST) {
    $sh = Get-ItemProperty $SVCHOST -EA SilentlyContinue
    $sgv = @(@($sh.WlansvcGroup) | Where-Object { $_ })
    $sGrp = (@($sgv) -join ';')
    if ($sGrp -eq '') { $sGrp = '(empty)' }
    if (($sGrp -join ';') -ne 'wlansvc') { $bad += 'S_GROUP' }
    $sc = Get-ItemProperty (Join-Path $SVCHOST 'WlansvcGroup') -EA SilentlyContinue
    $sCiso = $(if ($null -ne $sc) { '' + $sc.CoInitializeSecurityParam } else { '-' })
    if ($null -eq $sc -or [int]$sc.CoInitializeSecurityParam -ne 1) { $bad += 'S_CISO' }
    $lnr = @(@($sh.LocalSystemNetworkRestricted) | Where-Object { $_ })
    $sLsnr = $(if ($lnr -contains 'wlansvc') { '1' } else { '0' })
    if ($lnr -contains 'wlansvc') { $bad += 'S_LSNR' }
  }
  # netcfg 组件记录这一层(2026-10-12 决定性差量): 只看"键在不在 + ComponentId 对不对",
  # 值表其余部分由写入点保证(自检里同一棵树刚被逐值读过)。
  if ($NetClass) {
    $compDefs2 = @(
      @{ g = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'; cid = 'ms_vwifi';       fl = 'COMP_VWIFI' },
      @{ g = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'; cid = 'ms_nativewifip'; fl = 'COMP_NWIFI' }
    )
    foreach ($cd in $compDefs2) {
      $ok = 0
      $ck = Join-Path $NetClass $cd.g
      $cp2 = Get-ItemProperty $ck -EA SilentlyContinue
      $cim = Get-ItemProperty (Join-Path $ck 'Ndi\Interfaces') -EA SilentlyContinue
      if (($null -ne $cp2) -and ('' + $cp2.ComponentId -eq $cd.cid) -and ($null -ne $cim) -and
          ('' + $cim.FilterMediaTypes) -and ('' + (Get-ItemProperty (Join-Path $ck 'Ndi') -EA SilentlyContinue).TimeStamp)) {
        $ok = 1
      }
      if ($cd.fl -eq 'COMP_VWIFI') { $compV = '' + $ok } else { $compN = '' + $ok }
      if ($ok -ne 1) { $bad += $cd.fl }
    }
  }
  $line = ('VERDICT svc-shape: w_type=' + $(if ($null -ne $wl) { $wl.Type } else { '-' }) +
           ' w_obj=[' + $(if ($null -ne $wl) { $wl.ObjectName } else { '-' }) + ']' +
           ' w_group=' + $(if ($null -ne $wl) { $wl.Group } else { '-' }) +
           # 键不存在时 @($null.x).Count 会给出 1, 那是 PowerShell 的假读数而不是"有一个特权", 所以按 '-' 打
           ' w_priv=' + $(if ($null -ne $wl) { @($wl.RequiredPrivileges).Count } else { '-' }) +
           ' w_deps=' + $(if ($null -ne $wl) { (@($wl.DependOnService) -join '+') } else { '-' }) +
           ' w_main=' + $(if ($null -ne $wP) { $wP.ServiceMain } else { '-' }) +
           ' c_type=' + $(if ($null -ne $wc) { $wc.Type } else { '-' }) +
           ' c_obj=[' + $(if ($null -ne $wc) { $wc.ObjectName } else { '-' }) + ']' +
           ' c_group=' + $(if ($null -ne $wc) { $wc.Group } else { '-' }) +
           ' c_priv=' + $(if ($null -ne $wc) { @($wc.RequiredPrivileges).Count } else { '-' }) +
           ' c_deps=' + $(if ($null -ne $wc) { (@($wc.DependOnService) -join '+') } else { '-' }) +
           ' c_main=' + $(if ($null -ne $cP) { $cP.ServiceMain } else { '-' }) +
           # 2026-10-12 新增(WinRE 对标): -k 组名 / 是否带 -p / svchost 组值 / CoInitializeSecurityParam /
           # LocalSystemNetworkRestricted 里是否还留着 wlansvc / 两个 netcfg 组件记录
           ' w_kgrp=' + $wKgrp +
           ' w_phaser=' + $wP2 +
           ' s_grp=[' + $sGrp + ']' +
           ' s_ciso=' + $sCiso +
           ' s_lsnr=' + $sLsnr +
           ' comp_vwifi=' + $compV +
           ' comp_nwifi=' + $compN +
           # 2026-10-11/10-12 新增: wcmsvc 的 CSP 表条数 / 两个 WDI 宿主服务键(键形状 + 组成员一起判)
           ' c_csp=' + $cCsp +
           ' wdi_host=' + $wdiH +
           ' wdi_shost=' + $wdiS +
           ' flags=' + $(if ($bad.Count) { ($bad -join ',') } else { 'none' }))
  return @{ line = $line; flags = @($bad) }
}

if ($SelfTest) {
  # 自检: 用临时目录当"挂载点", 验证只读/已存在文件处理和注册表写入, 全程不需管理员
  $tmp = Join-Path $env:TEMP ('peinject_selftest_' + (Get-Date -Format 'HHmmss'))
  $Mount = $tmp                      # 让脚本里所有路径都指向假挂载点
  $pe32  = Join-Path $Mount 'Windows\System32'
  $t32   = $pe32
  New-Item -ItemType Directory -Force -Path (Join-Path $t32 'drivers') | Out-Null
  # 已存在且只读的 startnet.cmd: 验证 Copy-IntoPe 能清只读并覆盖(这是我们必须要换的文件)
  'old contents' | Set-Content (Join-Path $t32 'startnet.cmd') -Encoding ASCII
  Set-ItemProperty (Join-Path $t32 'startnet.cmd') -Name IsReadOnly -Value $true
  # 已存在的 wlanapi.dll 与只读的 wlanutil.dll: 验证"PE 已存在就不覆盖"分支(上一轮就是这里炸的)
  'fake' | Set-Content (Join-Path $t32 'wlanutil.dll') -Encoding ASCII
  Set-ItemProperty (Join-Path $t32 'wlanutil.dll') -Name IsReadOnly -Value $true
  'fake' | Set-Content (Join-Path $t32 'wlanapi.dll') -Encoding ASCII
  Set-Content -Path (Join-Path $t32 'drivers\nwifi.sys') -Value 'fake'
  # ndisuio.sys 也摆一个假的: wlansvc 的 DependOnService 是"按驱动键真写了没有"动态生成的,
  # 自检必须把 WinRE 那三个依赖(nativewifip/RpcSs/Ndisuio)的形状全走一遍, 否则门禁钉的那行绿的
  # 就只是"少一个依赖"的半成品形状。
  Set-Content -Path (Join-Path $t32 'drivers\ndisuio.sys') -Value 'fake'
  # 证据行落盘(门禁只读这个文件, 不读会被窗口宽度折行的控制台输出)。每轮开头清空,
  # 免得上一轮的绿行冒充本轮结论; 目录不存在时后面 Add-Content 会失败并显式报红, 不静默。
  $script:EvScratch = Join-Path $Root 'build\scratch'
  New-Item -ItemType Directory -Force -Path $script:EvScratch | Out-Null
  $script:EvFile = Join-Path $script:EvScratch 'wlan_verify_selftest.txt'
  Set-Content -LiteralPath $script:EvFile -Value ('# wifi-inject -SelfTest ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding ASCII
  Write-Host ('===== SELFTEST 假挂载点: ' + $tmp + ' =====') -ForegroundColor Magenta
  Write-Host '----- 第 1 轮(缺文件/只读文件) -----' -ForegroundColor Magenta
  $nf = Copy-WlanFiles
  $chk = @('wlanapi.dll','wlanmsm.dll','wlanext.exe','wcmsvc.dll','wci.dll','netshell.dll','wlansvc.dll','wifi.exe','wlan.cmd')
  foreach ($f in $chk) { Write-Host ('  存在? ' + $f + ' = ' + (Test-Path (Join-Path $t32 $f))) }
  $snLen = (Get-Item (Join-Path $t32 'startnet.cmd')).Length
  $ovLen = (Get-Item (Join-Path $Overlay 'Scripts\startnet.cmd')).Length
  Write-Host ('  只读的 startnet.cmd 已被覆盖 = ' + ($snLen -eq $ovLen) + ' (镜像 ' + $snLen + ' / overlay ' + $ovLen + ')')
  if ($snLen -ne $ovLen) { Write-Host '!! 只读文件覆盖失败' -ForegroundColor Red; exit 1 }
  Write-Host ('  wlanutil.dll 仍是假文件(未被覆盖) = ' + ((Get-Item (Join-Path $t32 'wlanutil.dll')).Length -lt 100))
  # A1: 覆盖 nwifi.sys 的 .cat 必须落在 CatRoot 的 WinNT 存储目录里(名字保持原样)
  $fakeStore = Join-Path $Mount ('Windows\System32\CatRoot\' + $CatStoreGuid)
  $gotCats = @(Get-ChildItem $fakeStore -Filter *.cat -File -EA SilentlyContinue)
  Write-Host ('  CatRoot 存储里有 .cat = ' + $gotCats.Count + ' 个: ' + (($gotCats | ForEach-Object { $_.Name }) -join ','))
  if ($gotCats.Count -eq 0) { Write-Host '!! 没有 .cat 进 CatRoot —— WiFi 会被代码完整性拦下, 不要出盘' -ForegroundColor Red; exit 1 }
  # A2: 无线索引必须跟着进镜像(池子 360MB 进 DriverStore 却没有这张表 = 开机查不到 ID)
  $wli = Join-Path $t32 'wlandrv_index.txt'
  $wlRows = @(Get-Content $wli -EA SilentlyContinue | Where-Object { $_ -match "`t" })
  Write-Host ('  wlandrv_index.txt 已进镜像 = ' + (Test-Path $wli) + ' / 行 ' + $wlRows.Count)
  if ($wlRows.Count -lt 20) { Write-Host '!! 无线索引没进 System32, netdrvfix 不会自愈无线网卡 —— 不要出盘' -ForegroundColor Red; exit 1 }
  # 收尾那行证据(VERDICT wlan)真正的执行点在 SelfTest 的 exit 之后, 所以把它抽成 Get-WlanEvidence 在这里两条分支都跑:
  # 不这么做的后果是"判据本身"要等用户那台管理员机器上第一次执行 —— 万一函数写错, 现场只会看到一行看不懂的 red。
  $weE = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan')
  Write-Ev 'DriverStore 为空' $weE.line
  # 2026-10-17: 宿主机 servicing 后 Package04 出现两条修订线(7663 覆盖 vwifi 三件套, 7807 覆盖
  # nwifi/wdiwifi), CatRoot 里 Package04*.cat 合法地变成 2 根 —— 判据语义是"至少一根", 不是"恰好一根"。
  if ($weE.cat -lt 1 -or $weE.rows -lt 20) { Write-Host '!! 证据函数没认出已经注入的 .cat / 索引' -ForegroundColor Red; exit 1 }
  if (@($weE.flags) -notcontains 'PKG_SHORT') { Write-Host '!! 空 DriverStore 必须亮 PKG_SHORT —— 红灯分支失效' -ForegroundColor Red; exit 1 }
  # 再摆出"除了 netrtwlane02 全都进了 DriverStore"的样子, 确认绿灯分支也亮(允许少 1 包正是那个已知缺口)
  $wbaseS = @(Get-ChildItem (Join-Path $Overlay 'Drivers\Wlan') -Recurse -Filter *.inf -File -EA SilentlyContinue |
              ForEach-Object { $_.Name.ToLower() } | Sort-Object -Unique)
  $fds = Join-Path $t32 'DriverStore\FileRepository'
  New-Item -ItemType Directory -Force -Path $fds | Out-Null
  foreach ($b in @($wbaseS | Where-Object { $_ -ne 'netrtwlane02.inf' })) {
    New-Item -ItemType Directory -Force -Path (Join-Path $fds ($b + '_amd64_selftest')) | Out-Null
  }
  # vWiFi 四个包在自检里不可能真跑 DISM(要管理员+真镜像), 所以照同样的形状伪造目录名,
  # 只验证"证据函数认不认得 DISM 装完之后的样子"; vwifi_svc 同理传 3, 真值在下面 HKCU 那轮里实测。
  foreach ($b in $vwifiInfs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $fds ($b.ToLower() + '_amd64_selftest')) | Out-Null
  }
  $weG = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -WdiSvcCount 2
  Write-Ev '只缺 netrtwlane02(全绿)' $weG.line
  if ($weG.flags.Count -ne 0 -or $weG.ds -ne ($wbaseS.Count - 1)) {
    Write-Host '!! 已知缺口(netrtwlane02)之外不该亮红灯, 或者包数没对上 —— 绿灯分支失效' -ForegroundColor Red; exit 1
  }
  if ($weG.vinf -ne 4 -or $weG.vsys -ne 4 -or $weG.vds -ne 4) {
    Write-Host ('!! vWiFi 证据不对: inf=' + $weG.vinf + ' sys=' + $weG.vsys + ' ds=' + $weG.vds) -ForegroundColor Red; exit 1
  }
  # WDI 框架(2026-10-10): 素材齐(6 个 .sys + 两份 .cat + 两个键)时必须是 wdi_sys=2/2 wdi_cat=1 wdi_svc=2/2
  if ($weG.wdisys -ne 2 -or $weG.wdicat -ne 1 -or ($weG.line -notmatch 'wdi_svc=2/2')) {
    Write-Host ('!! WDI 证据不对: ' + $weG.line) -ForegroundColor Red; exit 1
  }
  # 反向判据: 抽掉 wdiwifi.sys 必须亮 WDI_SYS(少了它, 无线 miniport 的 DriverEntry 就是 0xC00000BB)
  $wdiBak = Join-Path $t32 'drivers\wdiwifi.sys'
  if (Test-Path $wdiBak) {
    Remove-Item $wdiBak -Force
    $weWD = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -WdiSvcCount 1
    Write-Ev '抽掉 wdiwifi.sys(应红)' $weWD.line
    if (@($weWD.flags) -notcontains 'WDI_SYS' -or @($weWD.flags) -notcontains 'WDI_SVC') {
      Write-Host '!! 抽掉 WDI 框架却没亮 WDI_SYS/WDI_SVC —— 这条红旗是装饰' -ForegroundColor Red; exit 1
    }
    Copy-IntoPe (Join-Path $Root 'overlay\VWiFi\wdiwifi.sys') $wdiBak
  } else {
    Write-Host '!! overlay\VWiFi 里没有 wdiwifi.sys —— 先跑 test\20_MakeVWifiPool.ps1, 自检无法验证 WDI 分支' -ForegroundColor Red; exit 1
  }
  # 反向判据: 抽掉 wcmcsp.dll 必须亮 CSP_DLL(2026-10-11 probe99: 没有这个文件时 wcmsvc 每次启动都 1067 自退,
  # 而 Csps 那三棵子键的形状由 C_CSP 单独管 —— 两半的修法不同, 所以红旗也分开, 一个红一个查)。
  $cspBak = Join-Path $t32 'wcmcsp.dll'
  if (Test-Path $cspBak) {
    $cspLenBak = (Get-Item $cspBak).Length
    Remove-Item $cspBak -Force
    $weCsp = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -WdiSvcCount 2
    Write-Ev '抽掉 wcmcsp.dll(应红)' $weCsp.line
    if (@($weCsp.flags) -notcontains 'CSP_DLL' -or $weCsp.csp -ne 0) {
      Write-Host ('!! 抽掉 wcmcsp.dll 却没亮 CSP_DLL(csp=' + $weCsp.csp + ' flags=' + ($weCsp.flags -join ',') +
                  ') —— 这条红旗是装饰') -ForegroundColor Red; exit 1
    }
    Copy-IntoPe (Join-Path $env:SystemRoot 'System32\wcmcsp.dll') $cspBak
    if ((Get-Item $cspBak).Length -ne $cspLenBak) {
      Write-Host '!! wcmcsp.dll 复原后尺寸变了, 后面的自检读数不可信' -ForegroundColor Red; exit 1
    }
  } else {
    Write-Host '!! 假挂载点里没有 wcmcsp.dll(A 段没从宿主机借到) —— 自检无法验证 CSP 分支, 先查上面 A 段的失败列表' -ForegroundColor Red; exit 1
  }
  # A4 判据: L2Schemas 的 7 份 .xsd 必须全进假挂载点, 而且抽掉任意一份必须亮 L2_XSD。
  # 实机背景(2026-10-12, 12 代 AX211): 缺 WLAN_profile_v1.xsd 时 wlansvc 在 START_PENDING 里让 MSXML6
  # 按命名空间去解析 URL, 顶出 0x800C0006 自退; 现场把这 7 份拷进 X:\Windows\L2Schemas 之后当场 Running,
  # 并且 WlanEnumInterfaces n=1 / WlanGetAvailableNetworkList rc=0 n=5。所以这一步是"文件级"的必修项。
  $l2DirSt = Join-Path $Mount 'Windows\L2Schemas'
  $l2Have = @(Get-ChildItem $l2DirSt -Filter *.xsd -File -EA SilentlyContinue | ForEach-Object { $_.Name })
  $l2Want = @($l2xsds | Where-Object { $l2Have -notcontains $_ })
  $l2Tiny = @($l2Have | Where-Object { (Get-Item (Join-Path $l2DirSt $_)).Length -lt 500 })
  Write-Host ('  L2Schemas 进镜像 = ' + $l2Have.Count + '/' + $l2xsds.Count +
              $(if ($l2Want.Count) { ' 缺: ' + ($l2Want -join ',') } else { '' }))
  if ($l2Want.Count) { Write-Host '!! schema 不齐 —— wlansvc 会以 0x800C0006 自退, 不要出盘' -ForegroundColor Red; exit 1 }
  if ($l2Tiny.Count) { Write-Host ('!! 疑似占位(小于 500B): ' + ($l2Tiny -join ',')) -ForegroundColor Red; exit 1 }
  $xsdBak = Join-Path $l2DirSt 'WLAN_profile_v1.xsd'
  $xsdLenBak = (Get-Item $xsdBak).Length
  Remove-Item $xsdBak -Force
  $weXsd = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -WdiSvcCount 2
  Write-Ev '抽掉 WLAN_profile_v1.xsd(应红)' $weXsd.line
  if (@($weXsd.flags) -notcontains 'L2_XSD' -or $weXsd.l2 -ne ($l2xsds.Count - 1)) {
    Write-Host ('!! 抽掉 schema 却没亮 L2_XSD(l2=' + $weXsd.l2 + ' flags=' + ($weXsd.flags -join ',') +
                ') —— 这条红旗是装饰') -ForegroundColor Red; exit 1
  }
  Copy-IntoPe (Join-Path $Root 'overlay\L2Schemas\WLAN_profile_v1.xsd') $xsdBak
  if ((Get-Item $xsdBak).Length -ne $xsdLenBak) {
    Write-Host '!! WLAN_profile_v1.xsd 复原后尺寸变了, 后面的自检读数不可信' -ForegroundColor Red; exit 1
  }
  $weX2 = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -WdiSvcCount 2
  Write-Ev 'schema 复原(应绿)' $weX2.line
  if ($weX2.l2 -ne $l2xsds.Count -or @($weX2.flags).Count -ne 0) {
    Write-Host ('!! schema 复原后不该还有红旗: ' + $weX2.line) -ForegroundColor Red; exit 1
  }
  # 真机上 DISM 只会成功 3/4(netvwifibus.inf 必拒 rc=13), 这个缺口绝不能变成红旗 —— 用 -DismOk 3 复现该形状
  $weG3 = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3 -DismOk 3
  Write-Ev 'DISM 成功 3/4' $weG3.line
  if ($weG3.line -notmatch 'vwifi_dism=3/4' -or $weG3.flags.Count -ne 0) {
    Write-Host '!! vwifi_dism 读数没出现在证据行里, 或者 3/4 被误判成缺陷' -ForegroundColor Red; exit 1
  }
  # 反向: 少一个 vwifi INF 时必须亮 VWIFI_INF(判据本身不能只会亮绿灯)
  $bakInf = Join-Path $t32 '..\INF\netvwifibus.inf'
  if (Test-Path $bakInf) {
    Remove-Item $bakInf -Force
    $weR = Get-WlanEvidence -Pe32 $t32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount 3
    Write-Ev '删掉 netvwifibus.inf(应红)' $weR.line
    if (@($weR.flags) -notcontains 'VWIFI_INF') { Write-Host '!! 删掉 vWiFi INF 却没亮 VWIFI_INF' -ForegroundColor Red; exit 1 }
  }
  Write-Host '----- 第 2 轮(幂等: 全部 PE 已存在, 应 0 失败) -----' -ForegroundColor Magenta
  $nf2 = Copy-WlanFiles
  Write-Host '----- 回归: EAP=Stop 时调用会往 stderr 报错的 reg.exe, 不应抛终止错误 -----' -ForegroundColor Magenta
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Stop'
  try {
    Write-Host ('  reg unload 未加载的键 => ' + (Invoke-Reg @('unload', 'HKLM\SELFTEST_NO_SUCH_HIVE')))
    Write-Host ('  reg query 不存在的键 => ' + (Invoke-Reg @('query', 'HKCU\SELFTEST_NO_SUCH_KEY')))
    Write-Host '  PASS(上一轮就是在这里抛的)'
  } catch {
    $ErrorActionPreference = $prevEap
    Write-Host ('!! FAIL: Invoke-Reg 仍会被 stderr 打断 => ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
  }
  $ErrorActionPreference = $prevEap
  Write-Host '----- 注册表写入(HKCU 临时键) -----' -ForegroundColor Magenta
  $sc = 'HKCU:\Software\_peinject_selftest'
  Remove-Item $sc -Recurse -Force -EA SilentlyContinue
  New-Item (Join-Path $sc 'SVCHOST') -Force | Out-Null
  New-Item (Join-Path $sc 'SVCROOT') -Force | Out-Null
  Set-ItemProperty (Join-Path $sc 'SVCHOST') -Name PEWLan -Value @('x.dll') -Type MultiString
  # LocalSystemNetworkRestricted 里预先塞一个 wlansvc(上一版烘焙出来的形状就是这样): 用来证明
  # Remove-FromGroup 会把 wlansvc 摘掉、而 hidserv/Netman 这些别的成员原样保留。
  Set-ItemProperty (Join-Path $sc 'SVCHOST') -Name LocalSystemNetworkRestricted -Value @('hidserv', 'wlansvc', 'Netman') -Type MultiString
  New-Item (Join-Path $sc 'SVCROOT\nwifi') -Force | Out-Null
  New-Item (Join-Path $sc 'SVCROOT\wlansvc') -Force | Out-Null
  Set-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc') -Name ObjectName -Value 'LocalService' -Type String
  Set-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc') -Name Group -Value 'NDIS' -Type String
  Set-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc') -Name Type -Value 16 -Type DWord -Force
  Set-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc') -Name ImagePath -Value 'x\svchost.exe -k LocalSystemNetworkRestricted -p' -Type ExpandString -Force
  # 假 NetService 组件类: 先把 ms_vwifi 那棵树摆成"ComponentId 是错的"样子, 烘完必须被逐值改成 WinRE 的形状。
  $netc = Join-Path $sc ('NET\{4d36e974-e325-11ce-bfc1-08002be10318}')
  New-Item $netc -Force | Out-Null
  $bogus = Join-Path $netc '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'
  New-Item $bogus -Force | Out-Null
  Set-ItemProperty $bogus -Name ComponentId -Value 'ms_something_else' -Type String -Force
  Set-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc') -Name DependOnService -Value @('RpcSs') -Type MultiString -Force
  $vwRet = Write-WlanServiceKeys (Join-Path $sc 'SVCHOST') (Join-Path $sc 'SVCROOT') $t32 $netc
  # 服务键形状: 自检直接判红, 不留给实机去比对(口径与参考机 q56_host.txt 一致)
  $shLine = ''
  $shFlags = @()
  if ($script:SvcShape -is [hashtable]) { $shLine = $script:SvcShape.line; $shFlags = @($script:SvcShape.flags) }
  Write-Ev '服务键形状' $(if ($shLine) { $shLine } else { 'VERDICT svc-shape: flags=SHAPE_NOT_SET' })
  if (-not $shLine -or @($shFlags).Count) {
    $shTxt = if (@($shFlags).Count) { ($shFlags -join ',') } else { '自检没拿到结论' }
    Write-Host ('!! 服务键形状不对(' + $shTxt + '), 不要出盘') -ForegroundColor Red
    exit 1
  }
  Write-Host ('  服务键形状 flags=none (wlansvc 与官方 WinRE 同形: Type=32 -k WlansvcGroup 无 -p deps=nativewifip+RpcSs+Ndisuio' +
              ' main=WlanSvcMain; svchost WlansvcGroup=[wlansvc]+CoInitializeSecurityParam=1; 组件记录 2/2)')
  # 反向判据: 形状结论必须能对"故意写错的键"亮红 —— 这条断言保的是判据本身(否则它永远是绿灯)。
  $rs = Join-Path $sc 'REVROOT'
  New-Item (Join-Path $rs 'wcmsvc') -Force | Out-Null
  Set-ItemProperty (Join-Path $rs 'wcmsvc') -Name Type -Value 32 -Type DWord -Force
  Set-ItemProperty (Join-Path $rs 'wcmsvc') -Name ObjectName -Value 'LocalService' -Type String -Force
  $rv = Get-SvcShapeEvidence $rs
  Write-Ev '服务键形状(反向: 只写了一个错键)' $rv.line
  $rvMiss = @()
  foreach ($needFlag in @('W_ABSENT', 'C_TYPE', 'C_OBJ', 'C_GROUP', 'C_PRIV', 'C_DEPS', 'C_MAIN', 'C_DLL',
                          # 2026-10-11/10-12 新增三层: CSP 表 + 两个 WDI 宿主键(这个反向桩里只放了一个错键,
                          # 所以这三项都必须一起红 —— 判据不会因为"键完全不存在"而看不见)。
                          'C_CSP', 'S_WDIH', 'S_WDISH')) {
    if ($rv.flags -notcontains $needFlag) { $rvMiss += $needFlag }
  }
  if (@($rvMiss).Count) {
    Write-Host ('!! 反向判据失效, 这些 flag 没亮起来: ' + ($rvMiss -join ',')) -ForegroundColor Red
    exit 1
  }
  Write-Host ('  反向判据 PASS: 错键亮红 ' + ($rv.flags -join ','))
  # 反向判据 2(2026-10-12 跟着 WinRE 形状新增的那几条 flag): 每条都要能被"故意写错"点亮。
  # 这一组保的不是烘焙结果, 而是判据本身 —— 一条永远不会红的判据等于没有判据。
  $r2 = Join-Path $sc 'REV2'
  $r2svc = Join-Path $r2 'SVC'
  $r2sh  = Join-Path $r2 'SH'
  $r2net = Join-Path $r2 ('NET\{4d36e974-e325-11ce-bfc1-08002be10318}')
  New-Item $r2svc -Force | Out-Null
  New-Item $r2sh  -Force | Out-Null
  New-Item $r2net -Force | Out-Null
  # wlansvc: 故意保持"上一版(宿主机/早期)的形状" —— Type=16、-k LocalSystemNetworkRestricted、带 -p、
  # 依赖只有 RpcSs(而 nativewifip/Ndisuio 两个驱动键都摆在旁边, 所以"应有的依赖"是三个)。
  $r2w = Join-Path $r2svc 'wlansvc'
  New-Item $r2w -Force | Out-Null
  New-Item (Join-Path $r2w 'Parameters') -Force | Out-Null
  Set-ItemProperty $r2w -Name Type -Value 16 -Type DWord -Force
  Set-ItemProperty $r2w -Name ObjectName -Value 'LocalSystem' -Type String -Force
  Set-ItemProperty $r2w -Name Group -Value 'TDI' -Type String -Force
  Set-ItemProperty $r2w -Name RequiredPrivileges -Value @('a', 'b', 'c', 'd', 'e', 'f') -Type MultiString -Force
  Set-ItemProperty $r2w -Name ImagePath -Value 'svchost.exe -k LocalSystemNetworkRestricted -p' -Type ExpandString -Force
  Set-ItemProperty $r2w -Name DependOnService -Value @('RpcSs') -Type MultiString -Force
  Set-ItemProperty (Join-Path $r2w 'Parameters') -Name ServiceDll -Value 'x\wlansvc.dll' -Type ExpandString -Force
  Set-ItemProperty (Join-Path $r2w 'Parameters') -Name ServiceMain -Value 'WlanSvcMain' -Type String -Force
  foreach ($dv in @('nativewifip', 'Ndisuio')) { New-Item (Join-Path $r2svc $dv) -Force | Out-Null }
  $r2c = Join-Path $r2svc 'wcmsvc'
  New-Item $r2c -Force | Out-Null
  New-Item (Join-Path $r2c 'Parameters') -Force | Out-Null
  Set-ItemProperty $r2c -Name Type -Value 16 -Type DWord -Force
  Set-ItemProperty $r2c -Name ObjectName -Value 'NT Authority\LocalService' -Type String -Force
  Set-ItemProperty $r2c -Name Group -Value 'TDI' -Type String -Force
  Set-ItemProperty $r2c -Name RequiredPrivileges -Value @('a', 'b') -Type MultiString -Force
  Set-ItemProperty $r2c -Name DependOnService -Value @('RpcSs') -Type MultiString -Force
  Set-ItemProperty (Join-Path $r2c 'Parameters') -Name ServiceDll -Value 'x\wcmsvc.dll' -Type ExpandString -Force
  Set-ItemProperty (Join-Path $r2c 'Parameters') -Name ServiceMain -Value 'WcmSvcMain' -Type String -Force
  # svchost: 没有 WlansvcGroup 值(子键也没有), 而 LocalSystemNetworkRestricted 里还留着 wlansvc
  Set-ItemProperty $r2sh -Name LocalSystemNetworkRestricted -Value @('wlansvc', 'Netman') -Type MultiString -Force
  # 组件记录: ms_vwifi 的 ComponentId 是错的, ms_nativewifip 整棵树不存在
  New-Item (Join-Path $r2net '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}') -Force | Out-Null
  Set-ItemProperty (Join-Path $r2net '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}') -Name ComponentId -Value 'ms_wrong' -Type String -Force
  $rv2 = Get-SvcShapeEvidence $r2svc $r2sh $r2net
  Write-Ev '服务键形状(反向 2: WinRE 形状那几条各自写错)' $rv2.line
  $rv2Miss = @()
  foreach ($needFlag2 in @('W_TYPE', 'W_IMG', 'W_IMGP', 'W_DEPS', 'S_GROUP', 'S_CISO', 'S_LSNR', 'COMP_VWIFI', 'COMP_NWIFI')) {
    if ($rv2.flags -notcontains $needFlag2) { $rv2Miss += $needFlag2 }
  }
  if (@($rv2Miss).Count) {
    Write-Host ('!! 反向判据 2 失效, 这些新 flag 没亮起来: ' + ($rv2Miss -join ',')) -ForegroundColor Red
    exit 1
  }
  Write-Host ('  反向判据 2 PASS: 新 flag 全点亮 ' + ($rv2.flags -join ','))
  # 摘组分支的读数: wlansvc 必须从 LocalSystemNetworkRestricted 里消失, 而别的成员一个都不能少。
  # 注意成员表尾巴上那个 wdisystemhost 是我们自己刚加进去的(2026-10-12), 顺序 = 原顺序 + 新成员,
  # 所以期望值必须带上它 —— 否则"摘组正确"会被误报成"多摘/少摘"。
  $lnrAfter = @(@((Get-ItemProperty (Join-Path $sc 'SVCHOST') -EA SilentlyContinue).LocalSystemNetworkRestricted) | Where-Object { $_ })
  Write-Host ('  LocalSystemNetworkRestricted 摘完 = ' + (@($lnrAfter) -join ',') + ' (期望 hidserv,Netman,wdisystemhost)')
  if ((@($lnrAfter) -join ',') -ne 'hidserv,Netman,wdisystemhost') {
    Write-Host '!! 摘组分支不对: 应该只摘掉 wlansvc, 保留 hidserv/Netman(加上本轮写的 wdisystemhost) —— 不要出盘' -ForegroundColor Red
    exit 1
  }
  # 本轮新增两层的逐值回读: CSP 表(缺 = wcmsvc 1067)与两个 WDI 宿主键(缺 = 实机 OpenService=1060)。
  # 判据看的是 SVCROOT 里的真键, 不是计数器 —— 计数器只能证明"代码走到过那行"。
  foreach ($cn in @('cspethernet', 'cspwlan', 'cspwwan')) {
    $ck = Join-Path $sc ('SVCROOT\wcmsvc\Csps\' + $cn)
    $cv = Get-ItemProperty $ck -EA SilentlyContinue
    Write-Host ('  Csps\' + $cn + ' 存在=' + (Test-Path $ck) + ' Dll=' + $cv.Dll + ' Init=' + $cv.InitFunction +
                ' Deinit=' + $cv.DeinitFunction + ' MediaService=' + $(if ($cv.MediaService) { $cv.MediaService } else { '-' }) +
                ' WcmMediaType=' + $cv.WcmMediaType)
  }
  foreach ($hn in @('WdiServiceHost', 'wdisystemhost')) {
    $hk = Join-Path $sc ('SVCROOT\' + $hn)
    $hv = Get-ItemProperty $hk -EA SilentlyContinue
    $hp = Get-ItemProperty (Join-Path $hk 'Parameters') -EA SilentlyContinue
    Write-Host ('  ' + $hn + ' 存在=' + (Test-Path $hk) + ' Type=' + $hv.Type + ' Start=' + $hv.Start +
                ' acct=[' + $hv.ObjectName + '] ImagePath=[' + $hv.ImagePath + ']' +
                ' dll=' + $hp.ServiceDll + ' main=' + $hp.ServiceMain)
  }
  # svchost 组与组件记录逐值回读(出问题时最先看这几行, 它们比控制台里那些被折行的中文更可信)
  Write-Host ('  SVCHOST\WlansvcGroup = ' + (@(@((Get-ItemProperty (Join-Path $sc 'SVCHOST') -EA SilentlyContinue).WlansvcGroup)) -join ';'))
  Write-Host ('  SVCHOST\WlansvcGroup\CoInitializeSecurityParam = ' +
              (Get-ItemProperty (Join-Path $sc 'SVCHOST\WlansvcGroup') -EA SilentlyContinue).CoInitializeSecurityParam)
  foreach ($cd in @(@{ g = '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}'; n = 'ms_vwifi' },
                    @{ g = '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}'; n = 'ms_nativewifip' })) {
    $ckk = Join-Path $netc $cd.g
    $ckv = Get-ItemProperty $ckk -EA SilentlyContinue
    $cnv = Get-ItemProperty (Join-Path $ckk 'Ndi') -EA SilentlyContinue
    $civ = Get-ItemProperty (Join-Path $ckk 'Ndi\Interfaces') -EA SilentlyContinue
    Write-Host ('  组件 ' + $cd.n + ' ' + $cd.g + ' 存在=' + (Test-Path $ckk) +
                ' ComponentId=' + $ckv.ComponentId + ' InfPath=' + $ckv.InfPath + ' InfSection=' + $ckv.InfSection +
                ' Characteristics=0x' + ('{0:x8}' -f [int]$ckv.Characteristics) +
                ' InstallTimeStamp字节数=' + @($ckv.InstallTimeStamp).Count +
                ' Ndi\Service=' + $(if ($cnv.Service) { $cnv.Service } else { '-' }) +
                ' Ndi\TimeStamp字节数=' + @($cnv.TimeStamp).Count +
                ' Ndi\Interfaces\FilterMediaTypes=' + $civ.FilterMediaTypes +
                ' LowerRange=' + $civ.LowerRange + ' UpperRange=' + $civ.UpperRange)
  }
  $compLine = ('VERDICT comp-records: written=' + $script:WifiCompWritten + '/2' +
               ' ts=' + $(if ((@($((Get-ItemProperty (Join-Path $netc '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}') -EA SilentlyContinue).InstallTimeStamp)).Count -eq 16) -and
                              (@($((Get-ItemProperty (Join-Path $netc '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}') -EA SilentlyContinue).InstallTimeStamp)).Count -eq 16)) { '16+16' } else { 'BAD' }) +
               ' flags=' + $(if ($script:WifiCompWritten -eq 2) { 'none' } else { 'COMP_WRITE_SHORT' }))
  Write-Ev '组件记录写入' $compLine
  if ($script:WifiCompWritten -ne 2) {
    Write-Host '!! WiFi 组件记录没写满 2 条(缺了它网卡不会挂 vwififlt/nativewifip filter) —— 不要出盘' -ForegroundColor Red
    exit 1
  }
  # WDI 两个键要单独回读: 它们的判据不是"计数器说写了", 而是"注册表里真能查到 Type/Start/ImagePath
  # 和 Parameters 子键" —— 现场调试时唯一能证伪 WDI 的就是这四项(实机 setupapi/设备状态见任务 #20)。
  foreach ($n in @('wdiwifi', 'NdisImPlatform')) {
    $kk = Join-Path $sc ('SVCROOT\' + $n)
    $kp = Get-ItemProperty $kk -EA SilentlyContinue
    Write-Host ('  ' + $n + ' 键存在 = ' + (Test-Path $kk) + ' / Type=' + $kp.Type + ' Start=' + $kp.Start +
                ' Group=' + $(if ($null -eq $kp.Group) { '-' } else { $kp.Group }) +
                ' ImagePath=' + $kp.ImagePath +
                ' / Parameters 存在 = ' + (Test-Path (Join-Path $kk 'Parameters')))
  }
  foreach ($n in @('vwifibus', 'vwififlt', 'vwifimp')) {
    $kk = Join-Path $sc ('SVCROOT\' + $n)
    Write-Host ('  ' + $n + ' 键存在 = ' + (Test-Path $kk) + ' / Start=' + (Get-ItemProperty $kk -EA SilentlyContinue).Start +
                ' / Group=' + (Get-ItemProperty $kk -EA SilentlyContinue).Group +
                ' / ImagePath=' + (Get-ItemProperty $kk -EA SilentlyContinue).ImagePath)
  }
  # 机器可读的服务键结论(门禁读文件, 不读中文行): 3 个 vWiFi 键 + 2 个 WDI 键都必须在真实注册表里查到
  $skN = 0; foreach ($n in @('vwifibus', 'vwififlt', 'vwifimp', 'wdiwifi', 'NdisImPlatform')) {
    if (Test-Path (Join-Path $sc ('SVCROOT\' + $n))) { $skN++ }
  }
  $skLine = ('VERDICT svc-keys: vwifi=' + $vwRet + '/3 wdi=' + $script:WdiSvcCount + '/2 readback=' + $skN + '/5' +
             ' flags=' + $(if ($vwRet -eq 3 -and $script:WdiSvcCount -eq 2 -and $skN -eq 5) { 'none' } else { 'SVC_KEYS_SHORT' }))
  Write-Ev '服务键回读' $skLine
  if ($skN -ne 5) { Write-Host '!! 服务键没写全(3 个 vWiFi + 2 个 WDI), 开机 services.exe 不认 —— 不要出盘' -ForegroundColor Red; exit 1 }
  foreach ($n in @('Type','Start','ErrorControl','Group','ImagePath','ObjectName','ServiceSidType','DependOnService','RequiredPrivileges')) {
    Write-Host ('  wlansvc\' + $n + ' = ' + (@((Get-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc')).$n) -join ';'))
  }
  foreach ($n in @('ServiceDll','ServiceMain','ServiceDllUnloadOnStop')) {
    Write-Host ('  wlansvc\Parameters\' + $n + ' = ' + (Get-ItemProperty (Join-Path $sc 'SVCROOT\wlansvc\Parameters')).$n)
  }
  foreach ($n in @('ImagePath','ObjectName','ServiceMain')) {
    $v = if ($n -eq 'ServiceMain') { (Get-ItemProperty (Join-Path $sc 'SVCROOT\wcmsvc\Parameters') -EA SilentlyContinue).ServiceMain } else { (Get-ItemProperty (Join-Path $sc 'SVCROOT\wcmsvc')).$n }
    Write-Host ('  wcmsvc\' + $n + ' = ' + $v)
  }
  Write-Host ('  PEWLan 已删 = ' + (-not (Get-ItemProperty (Join-Path $sc 'SVCHOST') -Name PEWLan -EA SilentlyContinue)))
  Write-Host ('  nwifi 已删 = ' + (-not (Test-Path (Join-Path $sc 'SVCROOT\nwifi'))))
  Write-Host ('  重复运行幂等 = ' + (Test-Path (Join-Path $sc 'SVCROOT\wlansvc')))
  Write-Host ('  nativewifip = ' + (Test-Path (Join-Path $sc 'SVCROOT\nativewifip')) + ' / Ndisuio = ' + (Test-Path (Join-Path $sc 'SVCROOT\Ndisuio')))
  foreach ($n in @('Type','Start','ErrorControl','Group','ImagePath','NdisMajorVersion','NdisMinorVersion','DriverMajorVersion','DriverMinorVersion','DisplayName')) {
    Write-Host ('  nativewifip\' + $n + ' = ' + (Get-ItemProperty (Join-Path $sc 'SVCROOT\nativewifip') -EA SilentlyContinue).$n)
  }
  Write-Host ('  nativewifip\Parameters\DefaultFilterSettings = ' +
              (Get-ItemProperty (Join-Path $sc 'SVCROOT\nativewifip\Parameters') -EA SilentlyContinue).DefaultFilterSettings)
  Write-Host '----- reg.exe 回读值类型(REG_EXPAND_SZ / REG_MULTI_SZ 必须对) -----'
  $scRaw = $sc -replace '^HKCU:', 'HKCU'
  foreach ($sub in @('\SVCROOT\wlansvc', '\SVCROOT\wlansvc\Parameters', '\SVCROOT\wcmsvc\Parameters', '\SVCHOST')) {
    foreach ($ln in ((& reg.exe query ($scRaw + $sub) 2>&1 | Out-String) -split "`r?`n")) { if ($ln.Trim()) { Write-Host ('  ' + $ln.Trim()) } }
  }
  Remove-Item $sc -Recurse -Force -EA SilentlyContinue
  Remove-Item $tmp -Recurse -Force -EA SilentlyContinue
  Write-Host ('===== SELFTEST 结束: 第1轮失败数=' + $nf + ' 第2轮失败数=' + $nf2 + ' =====') -ForegroundColor Magenta
  if ($nf2 -ne 0) { Write-Host '!! 幂等运行仍有失败, 不要拿去构建' -ForegroundColor Red; exit 1 }
  exit 0
}

if (-not (Test-Path $pe32)) {
  Write-Host "挂载点无效(没有 $pe32): $Mount" -ForegroundColor Red; throw "wifi-inject: 挂载点无效 $Mount"
}
# 下面 DISM/reg 这类原生命令的提示文字走 stderr, 在 EAP=Stop 下会被当成终止错误(上面 Invoke-Reg 注释里已实测),
# 所以这一段降为 Continue, 全部靠 $LASTEXITCODE / 显式判断来出错
$ErrorActionPreference = 'Continue'
$fileFail = Copy-WlanFiles

Write-Host '  [wifi-inject] B. 注入无线网卡驱动(可选) ...' -ForegroundColor Cyan
$drvDirs = @()
# 无线网卡驱动池: 与以太网池同一套路(DISM 进镜像 => DriverStore\FileRepository, 开机由 netdrvfix 按索引 drvload)。
# 目录名 Wlan 为主, 兼容早期的 wifi 写法。
foreach ($dn in @('Drivers\Wlan', 'Drivers\wifi')) {
  $dd = Join-Path $Overlay $dn
  if (Test-Path $dd) { $drvDirs += $dd }
}
if ($DriverDir -and (Test-Path $DriverDir)) { $drvDirs += $DriverDir }
if ($NoDrivers) {
  Write-Host '    指定 -NoDrivers, 跳过'
} elseif (-not (Test-Path $DismExe)) {
  Write-Host "    !! 找不到 DISM: $DismExe" -ForegroundColor Yellow
} elseif ($drvDirs.Count -eq 0) {
  Write-Host "    无驱动目录(overlay\Drivers\wifi 不存在), 只依赖镜像内置的通用 ndis 驱动"
  Write-Host '    目标机是 WiFi-only 时请在目标机上跑 harvest_wifi_drivers.ps1, 把产物放到 overlay\Drivers\wifi'
} else {
  # 逐包结果必须看得见(2026-10-08 的 iaAHCIC 教训): /Recurse 是"进 N-1 拒 1"照样 rc=0、
  # DriverStore 目录数照样涨, 只看 rc 就会把拒掉的那个包当成功。DismReport 把那行英文日志读成结论。
  . (Join-Path $Root 'test\DismReport.ps1')
  foreach ($d in $drvDirs) {
    $n = @(Get-ChildItem $d -Recurse -Filter *.inf -EA SilentlyContinue).Count
    if ($n -eq 0) { Write-Host "    $d 里没有 inf, 跳过" -ForegroundColor Yellow; continue }
    $drvLog = Join-Path $Root ('build\scratch\dism_add_wlan_' + (Get-Date -Format 'HHmmss') + '.log')
    $rB = Invoke-DismAddDriver -Driver $d -LogPath $drvLog -Recurse
    $rc = $rB.rc; $rep = $rB.rep
    Write-Host ('    Add-Driver ' + $d + ' rc=' + $rc + ' inf=' + $n)
    Write-Host (Format-DismPkgReport -Label 'wlan' -Rep $rep)
    if (@($rep.failed).Count -gt 0) {
      Write-Host ('    !! 被 DISM 拒掉的包 ' + (@($rep.failed).Count) + ' 个, 这些芯片开机时不会在 DriverStore 里找到:') -ForegroundColor Red
      Write-Host ('       已知缺口: netrtwlane02(RTL8821CE/8812AE/8188EE 一档) 缺 rtlCoInst.dll/.dat,') -ForegroundColor Yellow
      Write-Host ('       盘里 4 个 Realtek 档都没这两个文件 => 只能现场 pe_getdriver 或插 USB 网卡。') -ForegroundColor Yellow
    }
    if ($rc -ne 0 -and $rep.ok -eq 0) { Write-Host '    !! 这个目录一个包都没进去' -ForegroundColor Red }
  }
}

Write-Host '  [wifi-inject] B2. DISM 离线装原生 WiFi 过滤栈四个包(进 DriverStore 索引) ...' -ForegroundColor Cyan
$vwifiDs = 0
if ($NoDrivers) {
  Write-Host '    指定 -NoDrivers, 跳过(注意: 跳过 = Include=netvwifibus.inf 仍然解析不了)' -ForegroundColor Yellow
} else {
  $vwifiDs = Add-VWifiDriverStore
  Write-Host ('    vWiFi 包成功进 DriverStore: ' + $vwifiDs + '/4')
}

Write-Host '  [wifi-inject] C. 离线注册表: wlansvc / wcmsvc / 驱动服务键 ...' -ForegroundColor Cyan
$vwifiSvc = 0
$SYS_HIVE = Join-Path $pe32 'Config\SOFTWARE'
$NT_HIVE  = Join-Path $pe32 'Config\SYSTEM'
$mp = 'HKLM\PE_SYS'; $ms = 'HKLM\PE_SYS2'
foreach ($h in @($mp, $ms)) { [void](Invoke-Reg @('unload', $h)) }   # 清上一轮可能残留的加载
Write-Host ('    reg load SOFTWARE: ' + (Invoke-Reg @('load', $mp, $SYS_HIVE)))
if (-not (Test-Path 'HKLM:\PE_SYS')) {
  Write-Host '    !! 加载 SOFTWARE 配置单元失败(需要管理员权限; 也可能是上一个进程还占着挂载点)' -ForegroundColor Red
  throw 'wifi-inject: reg load SOFTWARE 失败(需管理员)'
}
$regErr = ''
try {
  Write-Host ('    reg load SYSTEM: ' + (Invoke-Reg @('load', $ms, $NT_HIVE)))
  if (-not (Test-Path 'HKLM:\PE_SYS2')) {
    Write-Host '    !! 加载 SYSTEM 配置单元失败(需要管理员权限)' -ForegroundColor Red
    throw 'wifi-inject: reg load SYSTEM 失败(需管理员)'
  }
  # NetClass 用 ControlSet001(离线 hive 没有 CurrentControlSet, 与上面 Services 的写法同一口径)
  $vwifiSvc = Write-WlanServiceKeys 'HKLM:\PE_SYS\Microsoft\Windows NT\CurrentVersion\SVCHOST' 'HKLM:\PE_SYS2\ControlSet001\Services' $pe32 'HKLM:\PE_SYS2\ControlSet001\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}'
  Write-Host '    注册表配置完成'
} catch {
  $regErr = $_.Exception.Message
  Write-Host ('    !! 注册表写入异常: ' + $regErr) -ForegroundColor Red
  Write-Host ('       位置: 行' + $_.InvocationInfo.ScriptLineNumber + ' => ' + ($_.InvocationInfo.Line -replace '\s+', ' ').Trim()) -ForegroundColor Red
} finally {
  foreach ($h in @($mp, $ms)) {
    $r = Invoke-Reg @('unload', $h)
    if ($r -notmatch '成功|SUCCESS') {
      [GC]::Collect(); [GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 800
      Write-Host ('    重试卸载 ' + $h + ': ' + (Invoke-Reg @('unload', $h)))
    }
  }
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}
# 子脚本里的 exit 不会让父脚本(patch_wifi/build.ps1)的 catch 触发, 必须 throw 才能传出去
if ($regErr) { throw ('wifi-inject: 注册表写入失败 => ' + $regErr) }
$ErrorActionPreference = 'Stop'
if ($fileFail -gt 0) { Write-Host '  !! 有 WiFi 文件没复制成功, 见上面的失败列表' -ForegroundColor Red }

# ---------- 收尾: 一行 ASCII 证据(逻辑见 Get-WlanEvidence) ----------
$we = Get-WlanEvidence -Pe32 $pe32 -PoolDir (Join-Path $Overlay 'Drivers\Wlan') -SvcCount $vwifiSvc -DismOk $vwifiDs -WdiSvcCount $script:WdiSvcCount
Write-Host $we.line -ForegroundColor $(if ($we.flags.Count) { 'Red' } else { 'Green' })
if ($we.flags.Count) {
  Write-Host ('  !! ' + ($we.flags -join ',') + ' —— 这一项不齐就别出盘, 开机一定连不上 WiFi') -ForegroundColor Red
  Write-Host '     NO_CAT: overlay\Cats 或 Copy-NwifiCatalogs 出问题; NO_INDEX: 见 A2 输出; PKG_SHORT: 见上面被 DISM 拒掉的包'
  Write-Host '     VWIFI_INF/VWIFI_SYS: overlay\VWiFi 缺文件 -> 跑 test\20_MakeVWifiPool.ps1'
  Write-Host '     VWIFI_SVC: 服务键没写进 SYSTEM 配置单元 -> services.exe 开机不认识 vwifibus/vwififlt/vwifimp'
  Write-Host '     WDI_SYS/WDI_SVC/WDI_CAT: wdiwifi.sys + NdisImPlatform.sys 这套 WDI 框架不齐 ——'
  Write-Host '     缺 wdiwifi => 无线 miniport 的 DriverEntry 里 NdisMRegisterWdiMiniportDriver 无目标 => 0xC00000BB'
  Write-Host '     => 设备停在 code 37(CM_PROB_FAILED_DRIVER_ENTRY), Enum\INITSTARTFAILED=1, 永远连不上 WiFi'
  Write-Host '     三个都要齐: .sys 进 System32\drivers, 服务键进 SYSTEM 配置单元, 覆盖它们的 .cat 进 CatRoot'
}
# vwifi_store / vwifi_dism 不是判据, 只是读数(口径见 Get-WlanEvidence 里那段注释):
#   vwifi_dism 是 DISM 真成功的包数, 实测恒为 3/4 —— 四个微软 inbox 服务安装 INF 都没有 [SourceDisks*],
#   其中只有 netvwifibus.inf 写了 CopyFiles+[DestinationDirs], 所以只有它必然 rc=13。
#   vwifi_store 数的是 FileRepository 目录名, DISM 中止时可能留下半截目录, 所以它可能比 vwifi_dism 虚高。
# 真正决定开机能否解析 Include=netvwifibus.inf 的是 X:\Windows\INF 里有没有这四个 INF + 服务键 + .sys,
# 这一条只能实机看 setupapi 日志, 现场读数用 test\share\probe41.ps1。
if ($we.vds -ne $we.dism) { Write-Host ('  参考: vwifi_store=' + $we.vds + '/4 与 vwifi_dism=' + $we.dism + '/4 不一致 —— FileRepository 里有 DISM 中止留下的半截目录') -ForegroundColor DarkGray }
try {
  New-Item -ItemType Directory -Force -Path (Join-Path $Root 'build\scratch') | Out-Null
  # 两行都落盘: 第一行是文件/目录/.cat 的证据, 第二行是服务键形状(出盘后想复核"烘进去的键对不对形",
  # 不必重新挂载, 读这个文件即可; 自检那条路径写的是 wlan_verify_selftest.txt)
  $vLines = @($we.line)
  if ($script:SvcShape -is [hashtable]) { $vLines += $script:SvcShape.line }
  Set-Content -LiteralPath (Join-Path $Root 'build\scratch\wlan_verify.txt') -Value $vLines -Encoding ASCII
  if ($script:SvcShape -is [hashtable] -and @($script:SvcShape.flags).Count) {
    Write-Host ('  !! ' + (($script:SvcShape.flags) -join ',') + ' —— 服务键形状与官方 WinRE 不一致, 现场会表现为 1068/1069/服务自己停') -ForegroundColor Red
    # 新加的几条各对应一个"看得见的后果", 现场只有一行 red 时按这张表定位
    Write-Host '     W_TYPE/W_IMG/W_IMGP: wlansvc 不是 WinRE 那套(Type=32 + -k WlansvcGroup, 不带 -p) —— SCM 走的宿主分支不对'
    Write-Host '     W_DEPS: 依赖表与"实际写了的驱动键"不匹配 —— 多写=开机 1068, 少写=驱动没加载就起服务'
    Write-Host '     S_GROUP/S_CISO: SOFTWARE 的 Svchost\WlansvcGroup 缺失或没有 CoInitializeSecurityParam=1 ——'
    Write-Host '       svchost 拿着 -k WlansvcGroup 起来却一个服务都不加载, wlansvc 停在 START_PENDING 后自己退'
    Write-Host '     S_LSNR: wlansvc 还留在 LocalSystemNetworkRestricted 里(同一个服务在两个组, 宿主记账和实际加载对不上)'
    Write-Host '     COMP_VWIFI/COMP_NWIFI: Control\Network\{4d36e974-...} 里 ms_vwifi / ms_nativewifip 组件记录不齐 ——'
    Write-Host '       网卡实例不会有 Linkage\FilterList, 无线 miniport 后面挂不上 vwififlt/nativewifip, wlansvc 没有可管的接口'
    Write-Host '       (注意: 记录齐也只代表"能绑", 10-12 实机证明开机仍要 netcfg 走一遍才生成 FilterList —— 见 netdrvfix 的 WLAN-BIND)'
    Write-Host '     C_CSP: Services\wcmsvc\Csps 三棵子键不齐/值不对 —— wcmsvc 每次启动都 1067 自退(10-11 probe99 实测),'
    Write-Host '       配套的 System32\wcmcsp.dll 由 CSP_DLL 单独管(两半修法不同: 一个是借文件, 一个是写注册表)'
    Write-Host '     S_WDIH/S_WDISH: WdiServiceHost / wdisystemhost 的 SCM 键或 svchost 组成员缺其一 ——'
    Write-Host '       实机读数 OpenService=1060 而 wdi.dll 能 LoadLibrary+拿 ServiceMain, 即"文件在、宿主记录没有";'
    Write-Host '       svchost 组里少名字的后果和键不存在一样(进程起来却不加载这份 DLL), 所以键与组一起算一项'
  }
} catch { }
