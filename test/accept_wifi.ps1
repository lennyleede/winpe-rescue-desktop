# ============================================================
# test\accept_wifi.ps1 —— WiFi 离线烘焙的"一条命令验收": 推 + 跑探针(2 个, 加 -Bind 是 3 个), 结果全部自动回传到本机文件
#
#   为什么要有这个总入口(2026-10-10): 用户上机一次的成本 = 重启 + 进 PE + 记 IP + 敲命令。
#   以前要分两条命令(push probe42 / push probe86), 少跑一条就少一半结论。现在一条:
#     1) probe42_wdi.ps1  = 只读的设备/驱动层读数(WDI .sys、.cat、开机键、PnP code、nativewifip)
#     2) probe86_...ps1   = 服务层: 依赖闭包 + wlansvc/wcmsvc 怎么结束 + 这张盘是不是新盘(P86 DISC)
#   两段的原始输出都按 ASCII 落到 build\scratch\wifi_accept_<时间戳>.txt, 末尾再打一行 WIFI ACCEPT 结论,
#   所以我读完就能判断"是不是这张盘、WDI 有没有进去、wlansvc 现在还报什么"。
#
#   只读 vs 改动: probe42 纯读; probe86 会在 RAMDISK 上建 X:\pe_dumps、写 WER LocalDumps 键、
#   并 start/stop wcmsvc+wlansvc —— 全在内存盘上, 重启即消失, 不动镜像里的服务记录。
#
#   2026-10-12 加第三段 `-Bind`(默认不开): 12:25 那张盘量到 comp=2/2、服务形状全对齐, 但 SCM 仍然拒起
#   wlansvc(1068), 闭包里唯一没起来的是 nativewifip(win32=31), 同时 `upper=-`/`vwifibus_node=no`
#   ⇒ 问题从"服务层"挪到了"设备栈的 filter 绑定层"。probe93 是这一层唯一的仪器: 它先用 netcfg 的
#   受支持安装路径(MS_NativeWifiP / ms_vwifi)逐 rung 重装组件并每步复量, 然后重启无线 devnode、
#   起 wlansvc、`netsh wlan show interfaces`。它只在 X: 上动手(RAMDISK), 重启即复原, 且永不碰有线网卡 devnode。
#   probe93 现在有一段"第 0 节": 在阶梯动手之前先把这张盘的开机态绑定读数打出来 ——
#   boot_upper=无线 devnode 的 UpperFilters 里有没有 vwifibus, boot_filter_hits=网卡 Linkage\FilterList
#   里 ms_vwifi(5CBF81BF)/ms_nativewifip(E475CF9A) 两条在不在。这两个数就是"离线烘组件记录够不够"的判据,
#   结论行会原样带出来(本机正例对照: build\scratch\t_p103_boot_section.ps1 -> Upper=[vwifibus] hits=2)。
#
#   2026-10-12 加 probe161 这一段(默认开, `-NoL2` 才关): wlansvc 自退 0x800C0006 的根因已经定案并烘好 ——
#   PE 的 %Windows%\L2Schemas 里没有 WLAN_profile_v1.xsd, MSXML6 退化成"把命名空间当 URL 解析"。
#   当时是往 RAMDRIVE 里现场拷 7 个 .xsd 才让它 RUNNING 的(p158/159/160), 而 X: 每次开机都从 boot.wim
#   重建, 所以"活体绿了"对盘本身什么都不能证明。probe161 读的是**开机态的镜像文件**:
#     L2 = 7 份 schema 在不在 + 字节数对不对(wifi-inject A4 的落地判据)
#     CSP = wcmcsp.dll(probe99 的 wcmsvc 1067 修法) + wcmsvc 状态
#     STACK/API = wlansvc 开机状态, 停着才 Start()(只在内存盘上动手), 然后 WlanOpenHandle/EnumInterfaces/
#                 WlanGetAvailableNetworkList —— 出到网络(availability n>0)才算这条链真的能用
#     BIND = 抄 X:\status.txt 里 netdrvfix 开机那行的 wbind/wfl/wupper/wsvc/wdihost
#   结论行因此多三个读数 l2= / avail= / p161=, 并且 l2 不是 7/7 时整条验收直接判 1(旧盘 / A4 没落地)。
#
#   用法(实机插 LAN, 开机后进 PE 拿到 IP 再跑):
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\accept_wifi.ps1
#     要连绑定层一起量/一起试: ... -Bind   (这一段最慢, 阶梯 + 每次 Enum 全遍历, 几分钟是正常的)
#     通道走 frp 隧道时: ... -Target administrator@203.0.113.10 -Port 8022
#   退出码: 0 = 探针都跑完且读数落在"新盘 + 服务键已对齐 + wdi 参数键 2/2 + L2Schemas 7/7 烘进镜像且
#           WlanGetAvailableNetworkList 出到网络"(-Bind 时还要有 P93 VERDICT);
#           1 = 任一环节没成 / 还是旧盘 / 绑定段没出结论 / schema 没烘上
# ============================================================
param(
  [string]$Target = 'administrator@192.168.0.107',
  [int]$Port = 22,
  [string]$OutFile = '',
  [switch]$Bind,
  [switch]$NoL2
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not $OutFile) {
  $OutFile = Join-Path $Root ('build\scratch\wifi_accept_' + (Get-Date -Format 'MMddHHmm') + '.txt')
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile -Parent) | Out-Null

function PushRun([string]$localPath, [string]$remotePath, [string]$staging, [string]$remoteArgs = '') {
  # 每次都是独立的子 powershell, 免得一个探针把会话变量搞脏; 输出原样收回字符串数组
  # $remoteArgs 只用来传纯 ASCII 开关(2026-10-12: -Bind 要给 probe93 带 -Apply)。
  # 名字刻意不叫 $args —— 那是 PowerShell 的自动变量, 拿来当参数会把调用方的散装参数吞掉。
  #
  # 为什么写成数组而不是把 -RunArgs 直接摊在命令行上(build\scratch\t_p104*_ 实测):
  #   `-RunArgs $remoteArgs` 在 $remoteArgs='' 时会被 PowerShell 当成"没给值", 子进程直接报
  #   "缺少参数 RunArgs" —— 那是 probe42/probe86 两条老路径, 等于整条验收命令废掉;
  #   而值本身带减号('-Apply')摊开时又容易被当参数名。所以只在非空时才拼 -RunArgs, 参数走数组展开,
  #   实测 '-Apply' / '' / '-Apply -Only x' 三种都能原样绑定。
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'test\host_push_run.ps1',
         '-Local', $localPath, '-RemotePath', $remotePath, '-StagingB64', $staging,
         '-Target', $Target, '-Port', $Port, '-Run')
  if ($remoteArgs) { $a += @('-RunArgs', $remoteArgs) }
  $o = @(& powershell @a 2>&1)
  return @($o | ForEach-Object { "$_" })
}

$all = @()
$all += ('# wifi accept ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' target=' + $Target + ' port=' + $Port)
$stages = 2
if (-not $NoL2) { $stages = 3 }
if ($Bind) { $stages = $stages + 1 }
Write-Output ('===== [1/' + $stages + '] probe42_wdi (只读: WDI 文件/键/设备 code) =====')
$p42 = PushRun 'test\share\probe42_wdi.ps1' 'X:\p42w.ps1' 'X:\p42w.b64'
$all += '---- P42 ----'
$all += $p42
$p42 | Where-Object { $_ -match '^(P42|ABORT|LOCAL|  REMOTE)' } | ForEach-Object { Write-Output $_ }

Write-Output ('===== [2/' + $stages + '] probe86 (依赖闭包 + wlansvc 结局 + 是不是新盘) =====')
$p86 = PushRun 'test\share\probe86_wer_arm_and_trigger.ps1' 'X:\p86.ps1' 'X:\p86.b64'
$all += '---- P86 ----'
$all += $p86
$p86 | Where-Object { $_ -match '^(P86|  CLOSURE nodes|ABORT|  REMOTE)' } | ForEach-Object { Write-Output $_ }

$p161 = @()
$sN = 2
if (-not $NoL2) {
  $sN = 3
  Write-Output ('===== [' + $sN + '/' + $stages + '] probe161 (开机态: L2Schemas 烘焙 + wcmcsp + wlansvc + wlanapi 能不能出网络) =====')
  $p161 = PushRun 'test\share\probe161_l2_bake.ps1' 'X:\p161.ps1' 'X:\p161.b64'
  $all += '---- P161 ----'
  $all += $p161
  $p161 | Where-Object { $_ -match '^P161' } | ForEach-Object { Write-Output $_ }
}

$p93 = @()
if ($Bind) {
  Write-Output ('===== [' + ($sN + 1) + '/' + $stages + '] probe93 -Bind (绑定层: netcfg 受支持重装 + 重启无线 devnode + 起 wlansvc) =====')
  $p93 = PushRun 'test\share\probe93_netcfg_bind.ps1' 'X:\p93.ps1' 'X:\p93.b64' '-Apply'
  $all += '---- P93 ----'
  $all += $p93
  $p93 | Where-Object { $_ -match '^(P93|\s+P93 (TAG|SHAPE|BOOT|STACK|BASE|AFTER|PROGRESS|VERDICT|READING|NET-START|NETSH|WLANSVC|DEV))' } | ForEach-Object { Write-Output $_ }
}

Set-Content -LiteralPath $OutFile -Value ($all -replace '[^\x20-\x7E]', '?') -Encoding ASCII
Write-Output ('RAW LOG = ' + $OutFile)

# ---- 结论行: 三个"能不能算验收"的读数, 全部从探针原文里取, 不靠人眼比对 ----
$txt42 = ($p42 -join "`n")
$txt86 = ($p86 -join "`n")
$ran42 = ($txt42 -match 'P42 VERDICT')
$ran86 = ($txt86 -match 'P86 END')
$paramKey = '-'
if ($txt42 -match 'wdi_paramkey=(\d+/\d+)') { $paramKey = $matches[1] }
# wifi_nodes=<无线节点数>/<其中 code 0 的个数>: probe42 里 devcodes 会把有线网卡也算进去(同一个 ClassGuid),
# 2026-10-10 21:38 那次就是 devcodes=0,0 但无线卡其实 AX211 code=0/Netwtw14 Running —— 看 wifi_nodes 才准。
$wifiNodes = '0/0'
if ($txt42 -match 'wifi_nodes=(\d+/\d+)') { $wifiNodes = $matches[1] }
# P86 DISC 的 verdict 三档(2026-10-10 夜新加): NOT-the-baked-disc / baked-disc-OLD-keys / baked-disc+aligned。
# 分不开就会把"驱动层已修好但服务键还是旧形状"的 wlansvc 读数当成对齐后的结论(15:21 那张盘正是这种)。
$discVerdict = 'no-line'
if ($txt86 -match 'verdict=([A-Za-z+-]+)') { $discVerdict = $matches[1] }
$baked = ($discVerdict -like 'baked-disc*')
$fixed = ($discVerdict -eq 'baked-disc+aligned')
$wlKind = 'none'; $wlHr = ''; $wcKind = 'none'; $wcErr = '-'
if ($txt86 -match '(?m)^P86 SVC wlansvc .*\bkind=([a-z-]+)')        { $wlKind = $matches[1] }
if ($txt86 -match '(?m)^P86 SVC wlansvc .*win32=(0x[0-9A-Fa-f]+)')  { $wlHr = $matches[1] }
if ($txt86 -match '(?m)^P86 SVC wcmsvc .*kind=([a-z-]+)')           { $wcKind = $matches[1] }
if ($txt86 -match '(?m)^P86 SVC wcmsvc start=\w+/err=(\d+)')        { $wcErr = $matches[1] }
# 2026-10-12 起 DISC 行还带两个新读数: comp=<netcfg 组件记录 2/2>(ms_vwifi/ms_nativewifip 在不在活注册表里),
# 以及 FIX 行的 missing=<哪几项没对齐>。把它们抄进结论行, 免得"没对齐"只藏在原始日志的中间某行里。
$compN = '-'
if ($txt86 -match '(?m)^P86 DISC .* comp=(\d/2)') { $compN = $matches[1] }
$fixMissing = 'none'
if ($txt86 -match '(?m)^P86 DISC FIX .*?missing=(\S+)') { $fixMissing = $matches[1] }
# P161(2026-10-12): 开机态的 L2Schemas 烘焙读数。l2 不满 7/7 就是"这张盘没带 schema"或"A4 没落地",
# 这时候 wlansvc 再报什么都是旧结论, 不能算验收; avail=<rc>/<n> 里 n>0 才是"客户端真能拿到网络列表"。
$txt161 = ($p161 -join "`n")
$ran161 = ($txt161 -match 'P161 VERDICT')
$l2Frac = 'no-line'
if ($txt161 -match '(?m)^P161 VERDICT l2=(\d+/\d+)') { $l2Frac = $matches[1] }
$cspN = '-'
if ($txt161 -match '(?m)^P161 VERDICT .* csp=(\d)') { $cspN = $matches[1] }
$wlBoot = '-'
if ($txt161 -match '(?m)^P161 VERDICT .* wlansvc=([A-Za-z]+)->([A-Za-z]+)') { $wlBoot = $matches[1] + '->' + $matches[2] }
$availN = '-'; $availRc = '-'
if ($txt161 -match '(?m)^P161 VERDICT .* avail=(\S+)/(\S+)') { $availRc = $matches[1]; $availN = $matches[2] }
$p161V = 'no-line'
if ($txt161 -match '(?m)^P161 VERDICT .* verdict=(\S+)') { $p161V = $matches[1] }
# 算"在新盘上量到了"的条件: 两个探针都跑完 + 这张盘是"WDI 已烘 + 服务键已对齐" + wdi 参数键 2/2。
# -NoL2 时不卡 schema 那一项(留给只查绑定层的老用法), 默认必须 7/7。
$okRun = ($ran42 -and $ran86 -and $fixed -and ($paramKey -eq '2/2'))
if (-not $NoL2) { $okRun = ($okRun -and $ran161 -and ($l2Frac -eq '7/7')) }
# -Bind 时把 probe93 的结论也抄进同一行: 2026-10-12 之后 wlansvc 卡的是"设备栈的 filter 绑定", 不是服务键形状,
# 所以真正决定下一步的是 netcfg 重装组件之后 nativewifip/vwififlt 有没有 Running、有没有长出 vwifimp 子设备。
$bindOutcome = 'not-run'; $bindStack = '-'; $bindVwifimp = '-'; $bindWl = '-'
$bindBootUpper = '-'; $bindBootFl = '-'
$txt93 = ($p93 -join "`n")
if ($Bind) {
  if ($txt93 -match '(?m)^P93 VERDICT outcome=([a-z0-9-]+)') { $bindOutcome = $matches[1] }
  # 四个读数一律从 VERDICT 那一行取(锚到行首), 不锚就会先命中中间某级 AFTER/DEVICES 的同名字段。
  if ($txt93 -match '(?m)^P93 VERDICT.* stack=(\S+)')        { $bindStack = $matches[1] }
  if ($txt93 -match '(?m)^P93 VERDICT.* vwifimp_nodes=(\d+)') { $bindVwifimp = $matches[1] }
  if ($txt93 -match '(?m)^P93 VERDICT.* wlansvc=([A-Za-z]+)') { $bindWl = $matches[1] }
  # boot_upper / boot_filter_hits = 这张盘"开机时"到底有没有把 WiFi filter 挂上(devnode UpperFilters、
  # FilterList 里 ms_vwifi/ms_nativewifip 两条)。这两个数是绑定层根因的分叉点, 所以进结论行。
  if ($txt93 -match '(?m)^P93 VERDICT.* boot_upper=(\S+)')   { $bindBootUpper = $matches[1] }
  if ($txt93 -match '(?m)^P93 VERDICT.* boot_filter_hits=(\d+)') { $bindBootFl = $matches[1] }
  # 带了 -Bind 却没量到 P93 结论 = 这一趟的绑定层没结论, 等于白跑一次上机, 所以也算没验收。
  $okRun = ($okRun -and ($txt93 -match 'P93 VERDICT'))
}
Write-Output ('WIFI ACCEPT probes=' + [int]$ran42 + [int]$ran86 + $(if ($NoL2) { '' } else { [int]$ran161 }) +
  ' disc=' + $discVerdict +
  ' wdi_paramkey=' + $paramKey + ' wifi_nodes=' + $wifiNodes + ' comp=' + $compN +
  ' fix_missing=' + $fixMissing +
  ' l2=' + $l2Frac + ' csp=' + $cspN + ' boot=' + $wlBoot + ' avail=' + $availRc + '/' + $availN + ' p161=' + $p161V +
  ' wlansvc=' + $wlKind + ' ' + $wlHr + ' wcmsvc=' + $wcKind + '/' + $wcErr +
  ' bind=' + $bindOutcome + ' bind_stack=' + $bindStack + ' bind_vwifimp=' + $bindVwifimp +
  ' bind_wlansvc=' + $bindWl + ' boot_upper=' + $bindBootUpper + ' boot_filter_hits=' + $bindBootFl +
  ' verdict=' + $(if ($okRun) { 'ALIGNED-DISC-MEASURED' } else { 'NOT-MEASURED-ON-ALIGNED-DISC' }))
if (-not $NoL2 -and $l2Frac -ne '7/7') {
  Write-Output ('  => L2Schemas 只有 ' + $l2Frac + ': 这张盘没带 wlansvc 必读的 WLAN/WFD schema,')
  Write-Output ('     wlansvc 一定会回到 0x800C0006 自退(probe155 定案的根因)。确认烧的是 A4 之后出的 ISO:')
  Write-Output '     X:\BUILD_TAG.txt 的 wifi_patch 时间戳要晚于 overlay\L2Schemas 的提交, 再看 patch_wifi 屏幕上 A4 那行 "已放 7/7"'
} elseif ($availN -match '^\d+$' -and [int]$availN -gt 0) {
  Write-Output ('  => WiFi 栈在服务客户端了: WlanGetAvailableNetworkList rc=' + $availRc + ' networks=' + $availN +
    '(宿主机正对照 12~15)。下一步才是拿 DHCP/IP 与外网, 用 wifi.cmd / wlan.cmd。')
}
if ($discVerdict -eq 'baked-disc-OLD-keys') {
  Write-Output ('  => 驱动层是新的(WDI 已烘), 但服务层还没对齐(缺项见上面 fix_missing=' + $fixMissing + '):')
  Write-Output '     2026-10-12 的对齐=wlansvc Type=0x20 + -k WlansvcGroup(无 -p) + deps 含 nativewifip/RpcSs/Ndisuio'
  Write-Output '     + SOFTWARE\Svchost\WlansvcGroup + 两条 netcfg 组件记录(comp 必须 2/2)。'
  Write-Output '     这一轮的 wlansvc 读数是"旧服务层"的结论, 不能当作对齐后的验收 —— 出 patch_wifi 的新盘再跑一次。'
} elseif ($discVerdict -eq 'NOT-the-baked-disc') {
  Write-Output '  => 这张盘连 WDI 都没有: 确认烧的是 patch_wifi 之后新生成的 ISO(看 X:\BUILD_TAG.txt 的 wifi_patch/wlandrv 行)'
}
if ($okRun -and $wlKind -eq 'returned-error') {
  Write-Output ('  => 驱动层齐 + 服务键形状对齐 + L2Schemas ' + $l2Frac + ' 在场, wlansvc 仍自返 ' + $wlHr + ' ——')
  Write-Output '     崩溃取证、键形状、schema 三条都排除了, 这是 10-12 定案之后的新问题, 拿 P161 STACK 的 start=/poll= 和 P86 CLOSURE 对比 p159/p160 的活体读数'
}
if ($okRun -and $wlKind -eq 'faulted') {
  Write-Output '  => wlansvc 这次起了崩且带了自己的 dump: 按 P86 头部说明把 dump 拉回本机用 t_p85_dryrun.ps1 解'
}
if ($ran86 -and $wcKind -eq 'refused-by-scm') {
  Write-Output ('  => wcmsvc 仍被 SCM 拒(err=' + $wcErr + '): 读 P86 CLOSURE, 找第一个不是 state=4 的节点(闭包已走到第二层)')
}
if ($okRun -and ($wifiNodes -match '/0$') -and ($wlKind -eq 'returned-error')) {
  Write-Output '  => 没有任何无线 PnP 节点是 code 0: 这台机器的卡没被池里的包绑上(或 radio 被关), 那是 netdrvfix/code28 那条线'
}
if ($Bind -and $bindOutcome -eq 'not-run') {
  Write-Output '  => -Bind 开了却没拿到 P93 VERDICT: 看上面 ---- P93 ---- 的最后几行(探针多半在 netcfg 之前就被 ABORT 了)'
} elseif ($Bind -and ($bindVwifimp -ne '0') -and $bindVwifimp -ne '-') {
  Write-Output ('  => 绑定层突破了: probe93 之后 vwifimp_nodes=' + $bindVwifimp + ' wlansvc=' + $bindWl +
    ' —— 打 P93 PROGRESS 的那一级 netcfg 命令就是要固化进镜像/开机路径的那一步')
} elseif ($Bind) {
  Write-Output ('  => netcfg 受支持重装后仍没长 vwifimp 子设备(stack=' + $bindStack + ' wlansvc=' + $bindWl + '):')
  Write-Output ('     开机态绑定读数 boot_upper=' + $bindBootUpper + ' boot_filter_hits=' + $bindBootFl +
    ' —— 0/none 就是这张盘开机时根本没挂 filter, 差在 P93 每一级的 rc,')
  Write-Output '     对照 build\scratch\p93_apply_1011.txt 看哪一级和这次不一样(那两份日志曾经把 nativewifip/vwififlt 装到 Running)'
}
if ($okRun) { exit 0 } else { exit 1 }
