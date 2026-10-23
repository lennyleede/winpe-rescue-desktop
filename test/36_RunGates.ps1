# ============================================================
# test\36_RunGates.ps1 —— 出盘前的一条命令门禁总闸(普通权限, 只读+写 scratch 临时文件)。
#
#   为什么要总闸: 这个项目的坑几乎都是"单项看起来过了"——10-08 的 iaAHCIC 就是 DriverStore 增量>0
#   让构建脚本报了成功, 而 DISM 其实拒了 1 个包。把每项检查串成一条命令、每项只打一行 VERDICT,
#   我就能自己读完判断, 不需要用户在控制台逐条核对。
#   2026-10-09 补了 WiFi 那一半: 5b 无线池验收 / 5c 无线索引新鲜 / 5d 无线包完整(只准 netrtwlane02 红)
#   / 7b wifi-inject 自检里加了"索引必须进 System32"。
#
#   用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\36_RunGates.ps1
#         ...(改门禁时想看细节可加 -Verbose 打印每项原始尾巴)
#   输出刻意全 ASCII: 我要通过 ssh/管道读它, 中文在 PE 侧和管道里会变成 ??。
# ============================================================
param([switch]$Verbose2)
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$fails = 0
function Line([string]$name, [int]$rc, [string]$tail) {
  Write-Output (('GATE {0,-26} rc={1} {2}' -f $name, $rc, $tail))
  if ($rc -ne 0) { $script:fails++ }
}
function Grab($arr, [string]$pat) { (@($arr | ForEach-Object { "$_" } | Where-Object { $_ -match $pat }) -join ' | ') }

# 1) 语法: 改动链路上的脚本(WiFi 两个是 2026-10-09 加 .cat 注入时补进来的)
foreach ($f in @('build.ps1', 'test\16_InjectNetDrivers.ps1', 'test\verify_stodrv.ps1', 'test\verify_netdrv.ps1', 'test\DismReport.ps1', 'test\Update-WlanTag.ps1', 'test\WlanEvidenceFlags.ps1', 'test\iso_target.ps1', 'test\accept_wifi.ps1', 'test\20_MakeVWifiPool.ps1', 'test\Salvage-SetupapiLog.ps1', 'overlay\Scripts\netdrvfix.ps1', 'overlay\Scripts\niccheck.ps1', 'wifi-inject.ps1', 'patch_wifi.ps1', 'test\share\probe42_wdi.ps1', 'test\share\probe86_wer_arm_and_trigger.ps1', 'test\share\probe93_netcfg_bind.ps1', 'test\share\probe161_l2_bake.ps1', 'test\host_push_run.ps1', 'test\verify_runargs_binding.ps1')) {
  $o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\check_syntax.ps1' -Files $f 2>&1)
  Line ('syntax ' + [IO.Path]::GetFileName($f)) $(if ((Grab $o 'SYNTAX-OK') -ne '') { 0 } else { 1 }) $(if ((Grab $o 'SYNTAX-OK') -eq '') { (Grab $o '.') })
}

# 1c) 静态查禁: 探针脚本必须纯 ASCII —— 它们整份输出就是日志, 中文在 PE 控制台和 ssh 管道里会变成一屏 ??。
#     (overlay\Scripts\netdrvfix.ps1 / niccheck.ps1 不在这一闸里: 它们的中文只在注释里, 由 UTF-8 BOM 保证
#      PowerShell 5.1 解析正确, 而且从不 Write-Output 中文; 把它们放进来只会让门禁常年红。)
#     probe93 现在挂在 accept_wifi -Bind 上, 所以它必须在这一闸里。
#     probe161(2026-10-12, L2Schemas 烘焙的开机复验探针)挂在 accept_wifi 的第 3 段, 同理必须在闸里。
#     判据用 _check_ascii.ps1 的 ASCII 行"NON-ASCII (excluding BOM) = 0"。
foreach ($f in @('test\share\probe42_wdi.ps1', 'test\share\probe86_wer_arm_and_trigger.ps1',
                 'test\share\probe93_netcfg_bind.ps1', 'test\share\probe161_l2_bake.ps1')) {
  $o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\_check_ascii.ps1' -Target $f 2>&1)
  $bad = ''
  foreach ($l in $o) { if (("$l" -match 'NON-ASCII \(excluding BOM\) = (\d+)')) { $bad = $matches[1] } }
  Line ('ascii ' + [IO.Path]::GetFileName($f)) $(if ($bad -eq '0') { 0 } else { 1 }) ('non-ascii=' + $bad)
}

# 1c2) L2Schemas 三份口径必须一致(2026-10-12): wifi-inject 的 $l2xsds(烘什么) / overlay\L2Schemas(素材尺寸) /
#      probe161 里硬编码的 名字|字节数(开机复验判据)。任何一处漂移都会让开机读数说谎 ——
#      尺寸写小 => 半截 .xsd 被判绿; 名字写错 => 一张好盘被判 L2-NOT-BAKED。所以拿真机 API 之外的静态一致性当闸。
#      这台宿主机 wlansvc 是 Running 的正对照, 顺带把 Add-Type 那三行 wlanapi 声明也验一次。
$o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'build\scratch\t_p161_ctl_host.ps1' 2>&1)
Line 'l2 bake vs probe161 agree' $(if ($LASTEXITCODE -eq 0) { 0 } else { 1 }) ((Grab $o 'T161 CTL (PASS|FAIL).*') -replace '\s+', ' ')

# 1d) PushRun 拼参数回归: -RunArgs 空值会被 PowerShell 丢掉 => 子进程 "缺少参数 RunArgs",
#     三段验收全废; '-Apply' 这种带减号的值又可能被当参数名。语法检查抓不到, 只能跑。
$o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\verify_runargs_binding.ps1' 2>&1)
Line 'runargs binding' $(if ($LASTEXITCODE -eq 0) { 0 } else { 1 }) (Grab $o 'VERDICT runargs|case\[')

# 1b) 静态查禁: /Add-Driver 一律不许带 /Log。
#     2026-10-09 17:12 那次出盘就是这么坏的 —— 宿主机 dism.log 原话
#     "DISM Driver Manager: /log was not recognized by the driver manager provider (hr:0x80070057)",
#     驱动管理器在参数解析阶段把整条命令拒了: 无线池 23 个包 + 四个 vWiFi 包全部没进 DriverStore,
#     而脚本用 | Out-Null 把 DISM 的错误文字吞掉, 屏幕上只剩 rc=87。日志一律交给 PowerShell 重定向。
$badLog = @()
$scanDirs = @($Root, (Join-Path $Root 'test'), (Join-Path $Root 'overlay\Scripts'))
foreach ($d in $scanDirs) {
  foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter *.ps1 -File -EA SilentlyContinue)) {
    if ($f.Name -eq '36_RunGates.ps1') { continue }      # 本文件里那条正则自己就是"同时含两个串"的行
    foreach ($ln in @(Get-Content -LiteralPath $f.FullName -EA SilentlyContinue)) {
      $t = ("$ln").Trim()
      if ($t.StartsWith('#')) { continue }               # 注释里的教训文字不算违规
      if ($t -match '/Add-Driver' -and $t -match '/Log') { $badLog += ($f.Name + ' => ' + ($t -replace '\s+', ' ')) }
    }
  }
}
Line 'no /Log on Add-Driver' $(if ($badLog.Count) { 1 } else { 0 }) $(if ($badLog.Count) { (@($badLog | Select-Object -First 2) -join ' || ') } else { 'scanned=' + $scanDirs.Count + ' dirs, clean' })

# 2) 存储包门禁: 签名 + [SourceDisksFiles] 齐全 + 关键 ID 覆盖
$o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\verify_stodrv.ps1' 2>&1)
Line 'verify_stodrv' $LASTEXITCODE (Grab $o 'RESULT|FAILURES =|WARNINGS =|COVERAGE total')

# 3) 存储索引重算必须与入库版本逐字节相同(否则 netdrvfix 查表口径就变了)
& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\17_MakeNetDrvIndex.ps1' -DrvDir 'overlay\Drivers\Storage' -Out 'build\scratch\sto_idx_now.txt' 2>&1 | Out-Null
$a = (Get-Content 'overlay\Scripts\stodrv_index.txt' -Raw -EA SilentlyContinue) -replace "`r`n", "`n"
$b = (Get-Content 'build\scratch\sto_idx_now.txt' -Raw -EA SilentlyContinue) -replace "`r`n", "`n"
Line 'stodrv_index stable' $(if ($a -and $a -eq $b) { 0 } else { 1 }) ('rows=' + @($b -split "`n" | Where-Object { $_ -match 'VEN_' }).Count)

# 4) 镜像内自愈脚本的纯逻辑自测(含同名双包 Resolve-InfList、STOR 四态、三份随包索引 net/wlan/sto,
#    以及 v3.2 绑定层判据 —— 里面钉了一条宿主机正对照: 健康机器那 13 条 GUID 形状的 FilterList 必须读成 2)
$o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'overlay\Scripts\netdrvfix.ps1' -SelfTest 2>&1)
Line 'netdrvfix -SelfTest' $LASTEXITCODE (Grab $o 'SelfTest (PASS|FAIL)|DEV_467F|host GUID-shaped')

# 4b) v3.2 绑定层的"活代码路径"必须在宿主机真跑一次 DryRun(只读: 不写注册表、不动设备、不写 status.txt)。
#     为什么要单独一条: 语法检查抓不到"两行被拼成一行"这种损坏(2026-10-12 插入绑定段时就把
#     `$ad1 = Get-AdapterCount` 和下一行的 W(...) 拼成了 Get-AdapterCountW —— 解析通过、运行时才炸,
#     现场表现是 status.txt 里 adapters= 空一格)。SelfTest 走的是纯函数, 碰不到这些调用点,
#     所以这里拿真机器把 Get-NetDevs / Get-AdapterClassKey / Get-SvcState 全过一遍。
#     判据: 必须出现 WLAN-BIND 行(noop/ok/partial/fail 都算跑到了)、ADAPTERS 必须是数字、
#     且整段输出里不能有 PowerShell 的运行期错误字样。
$ndOut = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'overlay\Scripts\netdrvfix.ps1' -DryRun `
             -IdxPath 'overlay\Scripts\netdrv_index.txt' -WlIdxPath 'overlay\Scripts\wlandrv_index.txt' `
             -StoIdxPath 'overlay\Scripts\stodrv_index.txt' -LogPath 'build\scratch\gate_netdrvfix_dryrun.log' `
             -SkipStorage 2>&1)
$ndTxt = (($ndOut | ForEach-Object { "$_" }) -join "`n")
$ndTok = 'none'
foreach ($l in $ndOut) { if (("$l" -match 'WLAN-BIND = (\w+)')) { $ndTok = $matches[1] } }
$ndErr = @($ndTxt -split "`n" | Where-Object { $_ -match 'is not recognized|Cannot process|Exception calling|ObjectNotFound|ParseError' }).Count
$ndAdOk = ($ndTxt -match 'ADAPTERS = \d')
Line 'netdrvfix dryrun path' $(if (($ndTok -ne 'none') -and $ndAdOk -and $ndErr -eq 0) { 0 } else { 1 }) ('wbind=' + $ndTok + ' adapters_line=' + [bool]$ndAdOk + ' runtime_err=' + $ndErr)

# 5) 网卡池门禁
& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\verify_netdrv.ps1' 2>&1 | Out-Null
Line 'verify_netdrv' $LASTEXITCODE ''

# 5b) 无线池门禁(2026-10-09 精选档): 同一套段感知口径, 只把必测清单换成 WiFi 芯片
& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\verify_netdrv.ps1' -Profile wlan 2>&1 | Out-Null
Line 'verify_netdrv(wlan)' $LASTEXITCODE ''

# 5c) 无线索引重算必须与入库版本逐字节相同(netdrvfix v3.1 查的第三份表; 口径变了查表就对不上)
& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\17_MakeNetDrvIndex.ps1' -DrvDir 'overlay\Drivers\Wlan' -Out 'build\scratch\wlan_idx_now.txt' 2>&1 | Out-Null
$aw = (Get-Content 'overlay\Scripts\wlandrv_index.txt' -Raw -EA SilentlyContinue) -replace "`r`n", "`n"
$bw = (Get-Content 'build\scratch\wlan_idx_now.txt' -Raw -EA SilentlyContinue) -replace "`r`n", "`n"
Line 'wlandrv_index stable' $(if ($aw -and $aw -eq $bw) { 0 } else { 1 }) ('rows=' + @($bw -split "`n" | Where-Object { $_ -match 'VEN_|VID_' }).Count)

# 5d) 无线包完整性门禁([SourceDisksFiles] 声明的文件必须齐, 否则 DISM "进 22 拒 1" 还报成功 —— iaAHCIC 教训)。
#     唯一被认可的缺口: netrtwlane02 声明的 rtlCoInst.dll/.dat 池里根本没有(唯一副本是 2016 年的 USB/Realtek
#     老包, 混进来会让 2025 版 .cat 哈希对不上)。这一款 7 个 ID(10EC DEV_8179/818B/8753/8812/8813/8821/B723)
#     DISM 会拒, 现场靠 pe_getdriver 或 USB 网卡补。除此以外的任何 FAIL 都是红。
$ow2 = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\verify_stodrv.ps1' -DrvDir 'overlay\Drivers\Wlan' -ExpectIds 'PCI\VEN_8086&DEV_2526,PCI\VEN_14C3&DEV_7961' -Quiet 2>&1)
$wfail = @($ow2 | ForEach-Object { "$_" } | Where-Object { $_ -match '^\s*FAIL:' })
$wbad  = @($wfail | Where-Object { $_ -notmatch 'netrtwlane02' })
$wmiss = @($ow2 | ForEach-Object { "$_" } | Where-Object { $_ -match 'EXPECT .* = MISSING' })
Line 'wlan pkgs complete' $(if (($wbad.Count -eq 0) -and ($wmiss.Count -eq 0)) { 0 } else { 1 }) ('fail=' + $wfail.Count + ' unexpected=' + $wbad.Count + ' mustid_missing=' + $wmiss.Count)

# 6) 注入脚本前置条件(存储池 7 个包、iaAHCIC 在场、逐包解析器自证)
$o = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\16_InjectNetDrivers.ps1' -SelfTest 2>&1)
Line '16_ -SelfTest' $LASTEXITCODE (Grab $o 'SelfTest (OK|FAIL)')

# 7b) WiFi 注入自检(假挂载点, 不需要管理员): 退出码必须 0, 且日志里出现那根 .cat 的名字
#     (判据全用 ASCII —— 子进程 Write-Host 的中文在管道里编码不稳, 不能拿中文行当判据)
#     2026-10-10 改读文件: 证据行加了 wdi_sys/wdi_svc/wdi_cat 之后有 ~170 字符, 控制台必按窗口宽度
#     (默认 120)折行, 在管道里会被劈成两截 —— 判据会因为"排版"而不是"事实"变红。wifi-inject 现在把
#     每行证据原样追加进 build\scratch\wlan_verify_selftest.txt(ASCII, 每轮开头清空), 门禁只读它;
#     这里先删一次, 保证"文件是本轮生成的"(自检真跑过就一定会重建)。
$evf = Join-Path $Root 'build\scratch\wlan_verify_selftest.txt'
Remove-Item $evf -Force -EA SilentlyContinue
$wtmp = Join-Path $env:TEMP ('gate_wifi_inject_' + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Force -Path $wtmp | Out-Null
$ow = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'wifi-inject.ps1' -Mount (Join-Path $wtmp 'mount') -SelfTest 2>&1)
$wrc = $LASTEXITCODE
$oe = @(Get-Content $evf -EA SilentlyContinue)
$wcats = (Grab $ow 'Client-Desktop-Required-Package04')
$widxl = (Grab $ow 'wlandrv_index\.txt')
$wver  = (Grab $oe 'VERDICT wlan: .*flags=none')
# vWiFi 过滤栈 + WDI 框架(2026-10-09/10 现场定案: 只能离线烘)的判据本身也要有红灯分支, 所以逐条当门禁:
#   全绿行(4 INF + 4 .sys + DriverStore + 3 键 + 2 个 WDI .sys + 2 个 WDI 键 + 覆盖 wdiwifi 的 .cat)
#   / 删掉 netvwifibus.inf 必须亮 VWIFI_INF / 抽掉 wdiwifi.sys 必须亮 WDI_SYS+WDI_SVC / 服务键真写进 hive
$wvGrn = (Grab $oe 'vwifi_inf=4/4 vwifi_sys=4/4 vwifi_store=4/4 vwifi_svc=3/3 wdi_sys=2/2 wdi_svc=2/2 wdi_cat=1/1 csp_dll=1 l2_xsd=7/7 flags=none')
$wvRed = (Grab $oe 'vwifi_inf=3/4 .*flags=VWIFI_INF')
$wdRed = (Grab $oe 'wdi_sys=1/2 wdi_svc=1/2 .*flags=WDI_SYS,WDI_SVC')
# 2026-10-11 probe99 实机: 没有 wcmcsp.dll 时 wcmsvc 每次启动都 1067 自退(补上文件+CSP 表当场 RUNNING)。
# 这条红旗分支必须能被点亮, 否则"wcmcsp 借到了没有"就没人管。
$wcRed = (Grab $oe 'csp_dll=0 l2_xsd=7/7 flags=CSP_DLL')
# 2026-10-12 probe158/159/160 实机定案: PE 的 L2Schemas 只有 LAN/OneX 三个 xsd, wlansvc 向 MSXML6 要
# WLAN_profile_v1.xsd 拿不到, 就把命名空间当 URL 解析 -> 0x800C0006(ERROR_INTERNET_UNRECOGNIZED_SCHEME)
# 自退。把这 7 个 WLAN/WFD schema 烘进 overlay\L2Schemas 后 Start() 当场 RUNNING 且 WlanOpenHandle rc=0、
# 可用网络 n=5。所以 xsd 数量必须当门禁判据: 全绿行($wvGrn)已要求 7/7, 这里再要求抽掉
# WLAN_profile_v1.xsd 的分支必须亮 L2_XSD —— 少一个 schema 就少一个红灯, 别让它悄悄通过。
$wl2Red = (Grab $oe 'l2_xsd=6/7\(WLAN_profile_v1\.xsd\) flags=L2_XSD')
$wskg  = (Grab $oe 'VERDICT svc-keys: vwifi=3/3 wdi=2/2 readback=5/5 flags=none')
#     服务键形状(2026-10-12 起对标官方 WinRE build\scratch\p100_winre_reg, 不再是宿主机 q56_host.txt):
# wlansvc 必须 Type=32 + -k WlansvcGroup 且不带 -p、依赖按实际写了的驱动键算出
# nativewifip+RpcSs+Ndisuio、SOFTWARE 的 Svchost WlansvcGroup=[wlansvc]+CoInitializeSecurityParam=1、
# LocalSystemNetworkRestricted 里不再留 wlansvc、两个 netcfg 组件记录在场; wcmsvc 仍要 Type=16 +
# 账户名全名 'NT Authority\LocalService'(裸 'LocalService' 不是这台机器上的账户名, 依赖满足后会在登录那步 1069)。
# 2026-10-12 追加三项(都来自实机读数, 不是推测): c_csp=3/3(wcmsvc 的 CSP 表, 缺 = 实机 1067 自退)、
# wdi_host=1 / wdi_shost=1(WdiServiceHost + wdisystemhost: 键形状 + svchost 组成员一起判, 缺 = 实机 OpenService=1060)。
# 三条反向分支(只写一个错键 / 把 WinRE 形状那几条各自写错 / 组件记录写入数)必须都亮红 —— 判据自己也要被证明会红。
# 反向桩里新增的三项在两条分支都必须点亮(桩里根本没写这些键), 所以 flags 的串里带 C_CSP,S_WDIH,S_WDISH。
$wshp  = (Grab $oe 'VERDICT svc-shape: w_type=32 w_obj=\[LocalSystem\] w_group=TDI w_priv=6 w_deps=nativewifip\+RpcSs\+Ndisuio w_main=WlanSvcMain c_type=16 c_obj=\[NT Authority\\LocalService\] c_group=TDI c_priv=2 c_deps=RpcSs c_main=WcmSvcMain w_kgrp=WlansvcGroup w_phaser=0 s_grp=\[wlansvc\] s_ciso=1 s_lsnr=0 comp_vwifi=1 comp_nwifi=1 c_csp=3/3 wdi_host=1 wdi_shost=1 flags=none')
$wshpR = (Grab $oe 'VERDICT svc-shape: .*flags=W_ABSENT,C_TYPE,C_OBJ,C_GROUP,C_PRIV,C_DEPS,C_MAIN,C_DLL,C_CSP,S_WDIH,S_WDISH')
$wshpR2 = (Grab $oe 'VERDICT svc-shape: .*flags=W_TYPE,W_IMG,W_IMGP,W_DEPS,C_CSP,S_WDIH,S_WDISH,S_GROUP,S_CISO,S_LSNR,COMP_VWIFI,COMP_NWIFI')
$wcmp  = (Grab $oe 'VERDICT comp-records: written=2/2 ts=16\+16 flags=none')
$wvSvc = (Grab $ow 'vwifibus')
Remove-Item $wtmp -Recurse -Force -EA SilentlyContinue
Line 'wifi-inject -SelfTest' $(if (($wrc -eq 0) -and ($wcats -ne '') -and ($widxl -ne '') -and ($wver -ne '') -and ($wvGrn -ne '') -and ($wvRed -ne '') -and ($wdRed -ne '') -and ($wcRed -ne '') -and ($wl2Red -ne '') -and ($wskg -ne '') -and ($wshp -ne '') -and ($wshpR -ne '') -and ($wshpR2 -ne '') -and ($wcmp -ne '')) { 0 } else { 1 }) ('rc=' + $wrc + ' cat=' + [bool]($wcats -ne '') + ' idx=' + [bool]($widxl -ne '') + ' verdict=' + [bool]($wver -ne '') + ' green=' + [bool]($wvGrn -ne '') + ' vwifi_red=' + [bool]($wvRed -ne '') + ' wdi_red=' + [bool]($wdRed -ne '') + ' csp_red=' + [bool]($wcRed -ne '') + ' l2_red=' + [bool]($wl2Red -ne '') + ' svc_keys=' + [bool]($wskg -ne '') + ' svc_shape=' + [bool]($wshp -ne '') + ' svc_shape_red=' + [bool]($wshpR -ne '') + ' svc_shape_red2=' + [bool]($wshpR2 -ne '') + ' comp=' + [bool]($wcmp -ne '') + ' ev_lines=' + $oe.Count + ' marker=' + [bool]($wvSvc -ne ''))

# 7c) vWiFi + WDI 素材池: 从宿主机 C:\Windows 收集 4 个微软 INF + 6 个 .sys(4 个 vWiFi 栈 + wdiwifi
#     和 NdisImPlatform 两个 WDI 框架驱动) + 覆盖它们的 .cat。
#     2026-10-17: 宿主机 servicing 后 nwifi/wdiwifi 的覆盖包升到 Package04~...10.0.19041.7807,
#     与 vwifi 三件套的 ...7663 不再是同一根 -> 池子正确状态是 3 根 .cat(旧断言 cats=2 已过期)。
#     这一步是"离线烘"的前提 —— overlay\VWiFi 空着的话 wifi-inject 只会一路红灯。
$op = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\20_MakeVWifiPool.ps1' 2>&1)
$poolV = (Grab $op 'VERDICT vwifi_pool: .*flags=none')
$poolW = (Grab $op 'VERDICT vwifi_pool: inf=4/4 sys=6/6 cats=3 flags=none')
Line 'vwifi pool ready' $(if ($LASTEXITCODE -eq 0 -and $poolV -ne '' -and $poolW -ne '') { 0 } else { 1 }) ((Grab $op 'VERDICT vwifi_pool.*') -replace '\s+', ' ')

# 7d) 取证辅助脚本: 它是在 DISM 失败路径里被调用的, 所以"没有日志可捞"时必须安静返回 0,
#     不能抛异常 —— 否则一次驱动包失败会把整个注入带崩(2026-10-09 的教训: 半截出错也要看得见结论)。
$svM = Join-Path $env:TEMP ('gate_salvage_mount_' + (Get-Date -Format 'HHmmss'))
$svO = Join-Path $env:TEMP ('gate_salvage_out_' + (Get-Date -Format 'HHmmss'))
$sv  = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\Salvage-SetupapiLog.ps1' -Mount $svM -OutDir $svO 2>&1)
Line 'salvage degrades' $(if (($LASTEXITCODE -eq 0) -and ((Grab $sv 'SALVAGED |NO-SETUPAPI-LOG') -ne '')) { 0 } else { 1 }) ('rc=' + $LASTEXITCODE + ' ' + ((Grab $sv 'SALVAGED |NO-SETUPAPI-LOG') -replace '\s+', ' '))
Remove-Item $svM, $svO -Recurse -Force -EA SilentlyContinue

# 7) DISM 逐包解析器: "7 个包拒 1 个"必须认出 iaAHCIC, 网卡那份 143 全过。
#    6-of-7 用的是冻结样本 test\fixtures\dism_6of7_sample.log(按 2026-10-08 真实输出的行形状复原;
#    build\scratch 里的原始日志会被下一轮成功构建覆盖, 不能当固定样本)。
. (Join-Path $Root 'test\DismReport.ps1')
$fx = Join-Path $Root 'test\fixtures\dism_6of7_sample.log'
if (Test-Path $fx) {
  $hr = Get-DismPkgReport -LogPath $fx
  $good = ($hr.found -eq 7 -and $hr.ok -eq 6 -and @($hr.failed).Count -eq 1 -and (@($hr.failed) -join ' ') -match 'iaAHCIC')
  Line 'DismReport vs 6-of-7 fixture' $(if ($good) { 0 } else { 1 }) ('found=' + $hr.found + ' ok=' + $hr.ok + ' failed=' + @($hr.failed).Count)
} else {
  Line 'DismReport vs 6-of-7 fixture' 1 'fixture missing'
}
$hist = Join-Path $Root 'build\scratch\dism_add_stodrv.log'
if (Test-Path $hist) {
  $hl = Get-DismPkgReport -LogPath $hist
  $goodL = ($hl.found -gt 0 -and ($hl.ok + @($hl.failed).Count) -eq $hl.found)
  Line 'DismReport vs live sto log' $(if ($goodL) { 0 } else { 1 }) ('found=' + $hl.found + ' ok=' + $hl.ok + ' failed=' + @($hl.failed).Count)
} else {
  Line 'DismReport vs live sto log' 0 'no sample log yet (first build), skipped'
}
$histN = Join-Path $Root 'build\scratch\dism_add_netdrv.log'
if (Test-Path $histN) {
  $hn = Get-DismPkgReport -LogPath $histN
  $goodN = ($hn.found -gt 0 -and ($hn.ok + @($hn.failed).Count) -eq $hn.found)
  Line 'DismReport vs net log' $(if ($goodN) { 0 } else { 1 }) ('found=' + $hn.found + ' ok=' + $hn.ok + ' failed=' + @($hn.failed).Count)
} else {
  Line 'DismReport vs net log' 0 'no net sample log yet, skipped'
}

# 8) BUILD_TAG 的 wlandrv 行更新器: patch_wifi 在"必须管理员才跑到"的那段里调它, 所以这里用临时目录
#    把三种输入(已有 wlandrv 行 / 没有该行 / 文件根本不存在)在普通权限下全过一遍。
$tt = Join-Path $env:TEMP ('wlantag_' + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Force -Path $tt | Out-Null
$evTxt = 'cat=1 index_rows=395 driverstore=20/21 pool_inf=23 flags=none'
$tagCases = @()
$fA = Join-Path $tt 'tagA.txt'
@('build   = 2026-10-08 22:00:00', 'netdrv  = inf 143', 'stodrv  = inf 7', 'wlandrv = OLD STALE LINE', 'tools   = niccheck', 'product = WinPE_Desktop_v8') | Set-Content $fA -Encoding ASCII
$tagCases += @{ n = 'A:has-old-line'; f = $fA; want = 7; stale = $true }
$fB = Join-Path $tt 'tagB.txt'
@('build   = 2026-10-08 22:00:00', 'stodrv  = inf 7', 'product = WinPE_Desktop_v8') | Set-Content $fB -Encoding ASCII
$tagCases += @{ n = 'B:no-line'; f = $fB; want = 5; stale = $false }
$fC = Join-Path $tt 'tagC_missing.txt'
$tagCases += @{ n = 'C:no-file'; f = $fC; want = 3; stale = $false }
$tagBad = @()
foreach ($c in $tagCases) {
  $o8 = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\Update-WlanTag.ps1' -TagFile $c.f -Evidence $evTxt 2>&1)
  $rc8 = $LASTEXITCODE
  $back = @(Get-Content $c.f -EA SilentlyContinue)
  $nTag = @($back | Where-Object { $_ -match '^wlandrv = ' }).Count
  $nPat = @($back | Where-Object { $_ -match '^wifi_patch = ' }).Count
  $hasEv = (@($back | Where-Object { $_ -match ('^wlandrv = ' + [regex]::Escape($evTxt)) }).Count -eq 1)
  $noStale = $(if ($c.stale) { (@($back | Where-Object { $_ -match 'OLD STALE' }).Count -eq 0) } else { $true })
  $ok8 = (($rc8 -eq 0) -and ($nTag -eq 1) -and ($nPat -eq 1) -and $hasEv -and $noStale -and ($back.Count -eq $c.want))
  if (-not $ok8) { $tagBad += ($c.n + '(rc=' + $rc8 + ' tag=' + $nTag + ' pat=' + $nPat + ' ev=' + [bool]$hasEv + ' lines=' + $back.Count + '/' + $c.want + ')') }
}
Remove-Item $tt -Recurse -Force -EA SilentlyContinue
Line 'Update-WlanTag 3 cases' $(if ($tagBad.Count -eq 0) { 0 } else { 1 }) (@($tagBad) -join ' ')

# 8b) 同一个更新器的 tools 行同步(2026-10-12 新加): 14:25 那张盘的 BUILD_TAG 里 `tools = niccheck / netdrvfix/3.0`,
#     而那时 overlay\Scripts\netdrvfix.ps1 已经是 3.2 —— 那行是完整构建(16_)写的, 快速通道 patch_wifi 不碰,
#     于是"盘里到底是哪个开机脚本"当场不可知(现场 wdihost= 读空正是旧 3.2 之前那份文件的缺陷)。
#     两条都要断言: 给了 -Netdrvfix 必须只替换版本号(后面那句解释原样留着); 没给时一个字都不许动。
$tt2 = Join-Path $env:TEMP ('wlantag2_' + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Force -Path $tt2 | Out-Null
$ndFake = Join-Path $tt2 'netdrvfix.ps1'
("`$VER     = 'netdrvfix/3.2'") | Set-Content $ndFake -Encoding ASCII
$toolsLineOld = 'tools   = niccheck / netdrvfix/3.0  (runs at boot: startnet [1a]; code18=pnputil remove+scan, code28=drvload/add-driver)'
$fD = Join-Path $tt2 'tagD.txt'
@('build   = 2026-10-12 14:25:40', 'netdrv  = inf 143', 'stodrv  = inf 7', $toolsLineOld, 'product = WinPE_Desktop_v8') | Set-Content $fD -Encoding ASCII
$oD = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\Update-WlanTag.ps1' -TagFile $fD -Evidence $evTxt -Netdrvfix $ndFake 2>&1)
$rcD = $LASTEXITCODE
$backD = @(Get-Content $fD -EA SilentlyContinue)
$toolsNew = (@($backD | Where-Object { $_ -match '^tools\s*= niccheck / netdrvfix/3\.2  \(runs at boot: startnet \[1a\]; code18=pnputil remove\+scan, code28=drvload/add-driver\)$' }).Count -eq 1)
$syncRep = (@($oD | ForEach-Object { "$_" } | Where-Object { $_ -match 'TAG tools' } | Select-Object -First 1) -match 'asked=netdrvfix/3\.2 done=1')
# 反例: 不给 -Netdrvfix(= 完整构建那条路径的调用方式)时 tools 行必须原样
$fE = Join-Path $tt2 'tagE.txt'
@('build   = 2026-10-12 14:25:40', 'stodrv  = inf 7', $toolsLineOld, 'product = WinPE_Desktop_v8') | Set-Content $fE -Encoding ASCII
$oE = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'test\Update-WlanTag.ps1' -TagFile $fE -Evidence $evTxt 2>&1)
$keepE = (@(Get-Content $fE -EA SilentlyContinue | Where-Object { $_ -eq $toolsLineOld }).Count -eq 1)
$tagDbad = @()
if ($rcD -ne 0) { $tagDbad += 'rc=' + $rcD }
if (-not $toolsNew) { $tagDbad += 'tools_not_bumped' }
if (-not $syncRep) { $tagDbad += 'no_report' }
if (-not $keepE) { $tagDbad += 'E:touched_without_param' }
Remove-Item $tt2 -Recurse -Force -EA SilentlyContinue
Line 'Update-WlanTag tools sync' $(if ($tagDbad.Count -eq 0) { 0 } else { 1 }) (@($tagDbad) -join ' ')

# 8c) niccheck 第 4 段的"版本阶梯"行为闸(黑盒跑对照脚本)。
#     以前它靠数固定字符串认版本: 日志里有 'netdrvfix/2.0' => v2、有 'netdrvfix/3.0' => v3。
#     netdrvfix 升到 3.2 之后两条都不命中 => 一张 3.2 的盘在现场被念成 "v1(只会 drvload, 老镜像)",
#     而 tools 行的 BUILD_TAG 又是另一套(见上面 8/8b)——现场读到的是"这台机器到底跑了哪个脚本"的假信息。
#     现在改成抓日志里最后一个 netdrvfix/x.y 原样报出来 + 按主版本归类, 四种日志(3.2/3.0/2.0/无)都要对上。
#     对照本体: build\scratch\t_niccheck_verfix_host.ps1(只用 $env:TEMP 临时目录, 不碰镜像、不碰 C: 系统区)。
#     注意它有个自己踩过的坑: 不能在父进程改 $env:SystemRoot 再起子 powershell(PS 加载器要用真 SystemRoot,
#     指到临时目录只会回 8009001d, 于是 FIX 行为空 => 误判成"没修好"), 改在子进程内部的 wrapper 里改。
$nvo = @(& powershell -NoProfile -ExecutionPolicy Bypass -File 'build\scratch\t_niccheck_verfix_host.ps1' 2>&1)
$rcNv = $LASTEXITCODE
$nvTail = "$((@($nvo | ForEach-Object { "$_" }) | Select-Object -Last 1))"
Line 'niccheck ver ladder 4 cases' $(if (($rcNv -eq 0) -and ($nvTail -match 'NICVER PASS')) { 0 } else { 1 }) ('rc=' + $rcNv + ' ' + ($nvTail -replace '\s+', ' ') + ' || ' + (((@($nvo | ForEach-Object { "$_" }) | Where-Object { $_ -match '^NICVER \S+ ->'}) | ForEach-Object { ($_ -replace '^NICVER ', '') -replace '\s+', ' ' }) -join ' ~ '))

# 9b) 出盘总闸的"证据齐不齐"判据本身。2026-10-10 之前的写法是 $ev -match 'flags=none',
#     而 wifi-inject 现在写两行证据(wlan + svc-shape): "-match" 只要任意一段绿就为真,
#     于是"形状红 + 文件绿"会报成"WiFi 判据齐"并烧出一张 1068/1069 的盘。五种输入都要有对应红灯:
#       两行全绿 -> ok=1 / 形状行红 -> ok=0 且 bad 里有 svc-shape / 只有旧单行 -> ok=0(NO_SHAPE_LINE)
#       / 空文本 -> ok=0(NO_VERDICT_LINE) / 文件行红 -> ok=0(wlan:NO_CAT)
$evGreen = 'VERDICT wlan: cat=1 index_rows=395 wdi_sys=2/2 wdi_svc=2/2 wdi_cat=1/1 flags=none' + "`r`n" +
           'VERDICT svc-shape: w_type=32 w_obj=[LocalSystem] w_deps=nativewifip+RpcSs+Ndisuio c_type=16 c_obj=[NT Authority\LocalService] w_kgrp=WlansvcGroup w_phaser=0 s_grp=[wlansvc] s_ciso=1 s_lsnr=0 comp_vwifi=1 comp_nwifi=1 flags=none'
$evShapeRed = 'VERDICT wlan: cat=1 index_rows=395 wdi_sys=2/2 flags=none' + "`r`n" +
              'VERDICT svc-shape: w_type=16 c_obj=[LocalService] c_group= s_grp=[(empty)] s_lsnr=1 comp_vwifi=0 comp_nwifi=0 flags=W_TYPE,C_OBJ,C_GROUP,S_GROUP,S_LSNR,COMP_VWIFI,COMP_NWIFI'
$evOldOnly = 'VERDICT wlan: cat=1 index_rows=395 wdi_sys=2/2 flags=none'
$evWlanRed = 'VERDICT wlan: cat=0 index_rows=395 flags=NO_CAT' + "`r`n" + 'VERDICT svc-shape: w_type=32 flags=none'
$flCases = @(@{ n = 'green'; ev = $evGreen; want = 1 }, @{ n = 'shape_red'; ev = $evShapeRed; want = 0 },
             @{ n = 'old_single_line'; ev = $evOldOnly; want = 0 }, @{ n = 'empty'; ev = ''; want = 0 },
             @{ n = 'wlan_red'; ev = $evWlanRed; want = 0 })
$flBad = @()
foreach ($c in $flCases) {
  # 用 & 在当前进程里调, 和 patch_wifi 的真实调用方式一致: 走 `powershell -File` 时命令行会把空串参数
  # 整个丢掉, Mandatory 报的是"缺少参数"而不是判据结论, 空证据那条用例就测成了"绑定失败"。
  $o9 = @(& (Join-Path $Root 'test\WlanEvidenceFlags.ps1') -Evidence $c.ev 2>&1)
  $rc9 = $LASTEXITCODE
  $t9 = (($o9 | ForEach-Object { "$_" }) -join ' ')
  $got = 0; if ($t9 -match 'ok=1') { $got = 1 }
  $wantBad = ''
  if ($c.n -eq 'shape_red') { $wantBad = 'svc-shape:W_TYPE,C_OBJ,C_GROUP,S_GROUP,S_LSNR,COMP_VWIFI,COMP_NWIFI' }
  if ($c.n -eq 'old_single_line') { $wantBad = 'NO_SHAPE_LINE' }
  if ($c.n -eq 'empty') { $wantBad = 'NO_VERDICT_LINE,NO_SHAPE_LINE' }
  if ($c.n -eq 'wlan_red') { $wantBad = 'wlan:NO_CAT' }
  $badHit = ($wantBad -eq '') -or ($t9 -match [regex]::Escape($wantBad))
  if (($got -ne $c.want) -or ($rc9 -ne $(if ($c.want -eq 1) { 0 } else { 1 })) -or (-not $badHit)) {
    $flBad += ($c.n + '(got=' + $got + ' rc=' + $rc9 + ' ' + $t9 + ')')
  }
}
Line 'WlanEvidenceFlags 5 cases' $(if ($flBad.Count -eq 0) { 0 } else { 1 }) (@($flBad) -join ' ')

# 10) iso_target.ps1 必须只回绝对路径: patch_wifi/build 是在 Push-Location <Oscdimg 目录> 之后才把它给的
#     名字交给 oscdimg.exe, 相对名会被解析到 Oscdimg 目录里去 -> Error 3, 而那时注入已经 commit 进 boot.wim
#     (2026-10-10 22:30 的 -OutIso .\dist\...iso 就是这个形状)。这里同时守"占用改名"那条老功能没被改坏。
$itScript = Join-Path $Root 'test\iso_target.ps1'
$itTemp = Join-Path $env:TEMP ('isotarget_' + (Get-Date -Format 'HHmmss'))
New-Item -ItemType Directory -Force -Path $itTemp | Out-Null
$itBad = @()
# A: 空闲的绝对路径 -> 原样返回, 且不落任何文件
$itA = Join-Path $itTemp 'free.iso'
$oIT = @(& $itScript -Base $itA | Select-Object -Last 1)
$itR = ('' + $oIT)
if ($LASTEXITCODE -ne 0 -or $itR -ne $itA -or (Test-Path $itA)) { $itBad += ('A(rc=' + $LASTEXITCODE + ' out=' + $itR + ')') }
# B: 相对路径 + 当前目录不是项目根(正是 oscdimg 那一步的处境) -> 仍按项目根展开, 绝不落到临时目录里
Push-Location $itTemp
try {
  $oIT2 = @(& $itScript -Base 'dist\gate_b.iso' | Select-Object -Last 1)
} finally { Pop-Location }
$itR2 = ('' + $oIT2)
$itWant2 = Join-Path $Root 'dist\gate_b.iso'
if (-not [IO.Path]::IsPathRooted($itR2)) { $itBad += ('B not rooted: ' + $itR2) }
elseif ($itR2 -ne $itWant2 -or $itR2 -like ($itTemp + '*')) { $itBad += ('B anchored wrong: ' + $itR2) }
if (Test-Path $itWant2) { $itBad += 'B created a file' }
# C: 名字被独占(虚拟机光驱正在用) -> 换成同目录下带时间戳的新名字, 依然绝对
$itC = Join-Path $itTemp 'busy.iso'
Set-Content -LiteralPath $itC -Value 'x' -Encoding ASCII
$itLock = [IO.File]::Open($itC, 'Open', 'ReadWrite', 'None')
try {
  $oIT3 = @(& $itScript -Base $itC | Select-Object -Last 1)
  $itR3 = ('' + $oIT3)
  if (-not [IO.Path]::IsPathRooted($itR3)) { $itBad += ('C not rooted: ' + $itR3) }
  elseif ($itR3 -eq $itC) { $itBad += 'C returned the locked name' }
  elseif ((Split-Path $itR3 -Parent) -ne $itTemp) { $itBad += ('C changed the dir: ' + $itR3) }
  elseif ([IO.Path]::GetFileNameWithoutExtension($itR3) -notmatch '^busy_\d{4}-\d{6}$') { $itBad += ('C bad stamp: ' + $itR3) }
} finally { $itLock.Dispose() }
Remove-Item $itTemp -Recurse -Force -EA SilentlyContinue
Line 'iso_target absolute 3 cases' $(if ($itBad.Count -eq 0) { 0 } else { 1 }) (@($itBad) -join ' ')

# 11) Desktop.hta 面板门禁(2026-10-13, WiFi 图形面板随 frp 面板同闸):
#     a. 语法闸: 用 cscript 的 JScript(与 PE mshta 同一引擎)对整段 <script> 做 new Function 只解析。
#        语法错在 PE 里是弹窗, 用户没法贴回来; 在这里是一行 GATE。顺带核 CRLF(LONE_LF>0=文件被写坏)。
#     b. 解析闸: 面板读 wifi.exe 输出(UTF-8, Go printf 左对齐补空格)的 parseWifiTxt 拿 Go 格式样本正对照。
#        为什么单独闸: readWifi 走 ADODB utf-8 而不是 FSO ANSI(FSO 读会把 UTF-8 当 GBK 解坏), 回归看不见。
$o = @(& cscript //nologo //E:JScript 'build\scratch\t_hta_syntax_gate.js' 2>&1)
$sgRc = $LASTEXITCODE
Line 'hta js syntax+crlf' $(if ($sgRc -eq 0 -and ((Grab $o 'LONE_LF=0') -ne '')) { 0 } else { 1 }) (Grab $o 'HTASYNTAX|LONE_LF')
$o = @(& cscript //nologo //E:JScript 'build\scratch\t_hta_wifi_parse.js' 2>&1)
Line 'hta wifi parse' $LASTEXITCODE (Grab $o 'HTAPARSE')
#     c. i18n 闸(v11): I18N 表可被 JScript 解析且 zh/en 键集一一对应; 每个 T("key")/k="key" 引用在两表都有值。
#        缺键在 PE 里=整句掉回中文, 靠眼睛看不出来, 必须闸。
$o = @(& cscript //nologo //E:JScript 'build\scratch\t_hta_i18n_gate.js' 2>&1)
Line 'hta i18n parity' $LASTEXITCODE (Grab $o 'I18NGATE')

Write-Output $(if ($fails -eq 0) { 'ALL GATES GREEN' } else { ('GATES FAILED = ' + $fails) })
if ($fails -eq 0) { exit 0 } else { exit 1 }

