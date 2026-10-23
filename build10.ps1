# ============================================================
# WinPE 定制 ISO 构建 —— Win10 分支 (孪生于 build.ps1 / v8)
#   基镜像: Windows 10 LTSC 2021 (10.0.19044) 光盘里的 sources\boot.wim
#   现有 ADK 是 10.1.26100.9457(其 winpe.wim 属 Win11 世代), 所以本脚本不用 copype 的基镜像,
#   只借用 ADK 的 DISM / oscdimg / Media 引导文件树。
#   功能与 v8 一摸一样: pe-sshd 自启 + 向日葵 SOS 自启 + frp 桌面手动 + HTA 桌面 +
#                      开机 netdrvfix 自动认网卡 + 防火墙关闭 + niccheck/BUILD_TAG 自检。
# 以管理员 PowerShell 运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File build10.ps1
# 产物: .\dist\WinPE10_Desktop_v1.iso (被占用时自动改带时间戳的新名)
# 注意: 本文件是 build.ps1 的孪生分支, 改完 overlay 注入逻辑请同步检查两边。
# ============================================================
param(
  [string]$BaseWim = 'D:\winpe10_probe\boot.wim',
  [string]$SourceIso = 'D:\迅雷下载\zh-cn_windows_10_enterprise_ltsc_2021_x64_dvd_033b7312.iso',
  [ValidateSet('auto','1','2')][string]$BaseIndex = 'auto',
  [string]$Product = 'WinPE10_Desktop_v1',
  [string]$PeRoot10 = 'D:\adk10pe',   # 解包(未安装)的 10.1.19041.x WinPE add-on 根目录
  [string]$WorkRoot = 'D:\pe10_work', # DISM 挂载点根目录, 必须是纯 ASCII 路径(原因见下方 0a)
  [switch]$KeepProbe,           # 保留普查用的临时挂载点(默认用完删)
  [switch]$CensusOnly,          # 只做基镜像普查, 打印结论就收工(不组建媒体/不出 ISO)
  [switch]$OcTrial,             # 只试装本机 ADK(26100) 的 WinPE 组件包, 结果自动落盘, 改动全 /Discard
  [switch]$SelfTest             # 只做静态自检(普通权限可跑), 不动任何镜像
)
$ErrorActionPreference = 'Stop'
$Root    = $PSScriptRoot
$Build   = Join-Path $Root 'build10'
# 挂载点必须在纯 ASCII 路径下(见下面的 WorkRootIsAscii 检查), 所以不把 Work 放在本项目目录里。
$Work    = $WorkRoot
$Media   = Join-Path $Work 'media'
$Mount   = Join-Path $Work 'mount'
$Probe   = Join-Path $Work 'probe'
$Overlay = Join-Path $Root 'overlay'
$Dist    = Join-Path $Root 'dist'
$LogPath = Join-Path $Build ('build10_' + (Get-Date -Format 'MMdd-HHmmss') + '.log')

function WorkRootIsAscii([string]$p) {
  # WinPE-NetFX 的 lodctr 高级安装器只能处理 ASCII 路径: 2026-10-06 实测挂在
  # D:\QoderProject\国内版\生成winpe\build10\octrial 上时
  # CntrtextInstallPerfDll(...\_DataPerfCounters_d.ini) returns 1815 ->
  # 0x80073713(ERROR_ADVANCED_INSTALLER_FAILED, DISM 回 14099), 并且这个挂载点
  # 从此 CBS_E_IMAGE_UNSERVICEABLE(0x800f0830), 后面每个包都跟着失败。
  return ($p -match '^[\x20-\x7E]+$')
}
$ADK     = 'C:\Program Files (x86)\Windows Kits\10'
$PeTools = "$ADK\Assessment and Deployment Kit\Windows Preinstallation Environment"
$DismExe = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe"
$Oscdimg = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"

New-Item -ItemType Directory -Force -Path $Build,$Dist | Out-Null
function Say($m) {
  Write-Host $m
  # 写日志失败绝不能反过来打断构建: 2026-10-07 就是 $Log 被 fw-offline 的 $global:LOG 拼脏,
  # Add-Content 在 EAP=Stop 下抛终止错误, 让跑了四十分钟的构建死在 [8/8] 提交前一行。
  try { Add-Content -LiteralPath $LogPath -Value ((Get-Date -Format 'HH:mm:ss ') + $m) -Encoding UTF8 -ErrorAction Stop } catch { }
}
function Find-BadArg($argList) {
  # PowerShell 里逗号比 + 结合更紧: @('/Image:' + $M, '/Add-Package') 会被解析成
  # '/Image:' + ($M,'/Add-Package') -> 整个命令行塌成 1 个参数, DISM 只报晦涩的 1639。
  # 合法的 DISM 参数里不可能出现"空格+斜杠"(路径不可能含 " /"), 所以见到就是拼错了。
  return @($argList | Where-Object { "$_" -match ' /' })
}
function DismRun($argList, $label) {
  $badArg = Find-BadArg $argList
  if ($badArg.Count -gt 0) {
    Say ('ERROR: 参数拼装错误(逗号吃掉了 + 后面的元素, 请把拼接整体加括号): ' + ($badArg -join ' || '))
    return -9999
  }
  # DISM/原生程序往 stderr 写字就会在 EAP=Stop 下变成终止错误(2026-10-05 构建就是在这儿炸的), 统一降 EAP
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $DismExe @argList 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  $script:LastDismText = (($o | ForEach-Object { "$_" }) -join "`n")
  Say ("  " + $label + " rc=" + $rc)
  ($o | Where-Object { "$_" -match '错误|Error|error|成功|complete' } | Select-Object -Last 6) | ForEach-Object { Say ("      " + $_) }
  return $rc
}
function DismPoisoned {
  # 一次事务失败后 CBS 会把挂载点判死(CBS_E_IMAGE_UNSERVICEABLE), 之后每个包都返回 0x800f0830,
  # 真正的失败原因被埋在第一个非零 rc 里 —— 所以调用方要用 DismFailCode 拿第一个真实错误码。
  return ($script:LastDismText -match '0x800f0830|no longer serviceable|不可再服务')
}
function DismFailCode($rc) {
  # 0x800f081e = 包与映像不匹配; 14099/0x3713 = 高级安装器失败(基本是挂载点路径或依赖问题)
  if ($rc -eq -2146498512) { return '0x800f0830(挂载点已被上一次失败判死)' }
  if ($rc -eq -2146498530) { return '0x800f081e(包与映像不同世代)' }
  if ($rc -eq 14099)        { return '14099=0x3713 ERROR_ADVANCED_INSTALLER_FAILED(看 dism.log 里第一条 CSI 错误)' }
  return ('rc=' + $rc)
}

function Save-DismTail([string]$name) {
  # 高级安装器失败只会回 14099, 真正原因在 dism.log 的 CSI 行里; 顺手截回来, 免得再去翻 C:\Windows\Logs
  $dl = Join-Path $env:windir 'Logs\DISM\dism.log'
  $out = @()
  if (Test-Path $dl) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = @(Get-Content $dl -Tail 4000 -EA SilentlyContinue |
      Where-Object { $_ -match ', Error |\(F\)|CntrtextInstallPerfDll|nserviceable' -and
                     $_ -notmatch 'Failed to load the provider' } | Select-Object -Last 40)
    $ErrorActionPreference = $prev
  }
  $p = Join-Path $Build $name
  Set-Content -Path $p -Value ($out -join "`r`n") -Encoding UTF8
  return $p
}

if (-not (WorkRootIsAscii $Work)) {
  Say ('ERROR: 挂载点根目录 -WorkRoot 必须是纯 ASCII, 当前 = ' + $Work)
  Say '       WinPE-NetFX 的 lodctr 安装器在含中文/非 ASCII 的挂载路径上必失败(14099 -> 0x80073713), 见 WorkRootIsAscii 注释'
  exit 1
}

# ---------- 0. 前置检查 ----------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin -and -not $SelfTest) { Say 'ERROR: 请以管理员身份运行'; exit 1 }
foreach ($p in @($DismExe, "$Oscdimg\oscdimg.exe", "$Oscdimg\etfsboot.com", "$PeTools\amd64\Media\bootmgr")) {
  if (-not (Test-Path $p)) { Say ("缺少 ADK 组件: " + $p); exit 1 }
}
foreach ($p in @((Join-Path $Overlay 'SSH\pe-sshd.exe'), (Join-Path $Overlay 'Desktop\Desktop.hta'), (Join-Path $Overlay 'Drivers\Net'))) {
  if (-not (Test-Path $p)) { Say ("缺少 overlay 素材: " + $p); exit 1 }
}
$env:WinPERoot   = $PeTools
$env:OSCDImgRoot = $Oscdimg
$env:DISMRoot    = Split-Path $DismExe
$env:Path       += ";$Oscdimg;$(Split-Path $DismExe);$PeTools"
Say ("日志: " + $LogPath)

# ---------- 0b. Win10(19041) 世代的 WinPE 源(基镜像 / 组件包 / 引导文件树) ----------
# 组件包的版本必须与 WinPE 映像的版本一致: 26100 的 cab 装进 19041 映像会被 DISM 以
# 0x800f081e 整体拒绝(2026-10-06 -OcTrial 实测, 12 个包全灭)。所以从解包出来的
# 10.1.19041.x WinPE add-on 里同时取 winpe.wim + WinPE_OCs + Media, 三者同世代。
# DISM / oscdimg 继续用本机 26100 的(新版部署工具可以给旧版映像做服务, 官方允许)。
$Pe10 = @{ Wim = $null; Oc = $null; Media = $null }
if (Test-Path $PeRoot10) {
  $cWim = @(Get-ChildItem $PeRoot10 -Recurse -Filter 'winpe.wim' -File -EA SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\amd64\\' } | Sort-Object { $_.FullName.Length })
  $cOc  = @(Get-ChildItem $PeRoot10 -Recurse -Directory -Filter 'WinPE_OCs' -EA SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\amd64\\' } |
            Where-Object { @(Get-ChildItem (Join-Path $_.FullName '*.cab') -File -EA SilentlyContinue).Count -gt 5 })
  $cMed = @(Get-ChildItem $PeRoot10 -Recurse -Directory -Filter 'Media' -EA SilentlyContinue |
            Where-Object { $_.FullName -match '(?i)\\amd64\\' -and (Test-Path (Join-Path $_.FullName 'bootmgr')) })
  if ($cWim.Count -gt 0) { $Pe10.Wim = $cWim[0].FullName }
  if ($cOc.Count  -gt 0) { $Pe10.Oc   = $cOc[0].FullName }
  if ($cMed.Count -gt 0) { $Pe10.Media = $cMed[0].FullName }
}
Say ('  19041 WinPE 源(' + $PeRoot10 + '): winpe.wim=' + $(if ($Pe10.Wim) { '有' } else { '无' }) +
     ' / WinPE_OCs=' + $(if ($Pe10.Oc) { '有' } else { '无' }) +
     ' / Media=' + $(if ($Pe10.Media) { '有' } else { '无' }))
if (-not $Pe10.Oc) { Say '  (没找到 19041 组件包 -> 会退回 26100 的 cab, 那必然 0x800f081e, 见 component_trial.txt)' }

if ($SelfTest) {
  Say '===== SELFTEST(只读, 不动任何镜像) ====='
  $bad = @()
  # (1) 参数拆词: 上次 25 号探测脚本就是栽在这里(逗号比 + 结合更紧 -> /WimFile: 变成空值, DISM rc=87)
  $fake = 'X:\nope\none.wim'
  $arr  = @('/Mount-Wim', ('/WimFile:' + $fake), ('/Index:' + 1), ('/MountDir:' + 'X:\mount'), '/ReadOnly')
  Say ('  [1] 参数数组 count=' + $arr.Count + ' | ' + ($arr -join ' , '))
  if ($arr.Count -ne 5 -or $arr[1] -ne ('/WimFile:' + $fake)) { $bad += '参数拆词' }
  # (2) 素材齐不齐
  $must = @(
    (Join-Path $Overlay 'SSH\pe-sshd.exe'), (Join-Path $Overlay 'SSH\pe_host_ed25519'),
    (Join-Path $Overlay 'Desktop\Desktop.hta'), (Join-Path $Overlay 'Sunlogin'),
    (Join-Path $Overlay 'Drivers\Net'), (Join-Path $Root 'wifi-inject.ps1'),
    (Join-Path $Root 'fw-offline.ps1'), (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1'),
    (Join-Path $Root 'test\iso_target.ps1'), $BaseWim
  )
  foreach ($f in @('startnet.cmd','wlan.cmd','pe_report.ps1','fw_off.ps1','niccheck.ps1','niccheck.cmd','netdrvfix.ps1','netdrvfix.cmd')) {
    $must += (Join-Path $Overlay ('Scripts\' + $f))
  }
  foreach ($m in $must) {
    $ok = Test-Path $m
    Say ('  [2] ' + $(if ($ok) { 'OK      ' } else { 'MISSING ' }) + $m)
    if (-not $ok) { $bad += ('缺素材 ' + (Split-Path $m -Leaf)) }
  }
  # (3) 驱动与索引规模
  $ni = @(Get-ChildItem (Join-Path $Overlay 'Drivers\Net') -Recurse -Filter '*.inf' -EA SilentlyContinue).Count
  Say ('  [3] 有线网卡 inf = ' + $ni)
  if ($ni -lt 40) { $bad += ('inf 太少(' + $ni + ')') }
  # (4) 主机密钥指纹(必须与 v8 那把一致, 否则宿主机 known_hosts 要重新信任)
  $pub = Join-Path $Overlay 'SSH\pe_host_ed25519.pub'
  if (Test-Path $pub) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $fp = (& C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f $pub) -join ' '
    $ErrorActionPreference = $prev
    Say ('  [4] ' + $fp)
  }
  # (5) 产物名与 v8 不撞车
  Say ('  [5] 产物 = dist\' + $Product + '.iso (v8 用的是 dist\WinPE_Desktop_v8*.iso)')
  if ($Product -like 'WinPE_Desktop_v8*') { $bad += '产物名与 v8 冲突' }
  # (6) 权限
  Say ('  [6] isAdmin=' + $IsAdmin + $(if ($IsAdmin) { '' } else { ' (SelfTest 允许非管理员; 正式构建必须管理员)' }))
  # (7) 参数拼装守卫: 2026-10-06 的 1639 就是 @('/Image:' + $M, '/Add-Package') 塌成 1 个参数造成的
  $badShape  = @('/Image:' + 'D:\m', '/Add-Package')
  $goodShape = @(('/Image:' + 'D:\m'), '/Add-Package')
  Say ('  [7] 塌参数示例 count=' + $badShape.Count + '(应为 1) / 正确示例 count=' + $goodShape.Count + '(应为 2)')
  if ($badShape.Count -ne 1 -or $goodShape.Count -ne 2) { $bad += 'PowerShell 拆词规则与预期不符' }
  if ((Find-BadArg $badShape).Count -eq 0)   { $bad += 'Find-BadArg 没拦住塌参数' }
  if ((Find-BadArg $goodShape).Count -ne 0)  { $bad += 'Find-BadArg 误杀正确参数' }
  $offend = @()
  $lineNo = 0
  foreach ($ln in (Get-Content -Path $PSCommandPath -Encoding UTF8)) {
    $lineNo++
    if ($ln -match "DismRun @\('[^']*'\s*\+") { $offend += ('第 ' + $lineNo + ' 行') }
  }
  Say ('  [7] 源码里未加括号的 DismRun 拼接 = ' + (@($offend) -join ', ') + $(if ($offend.Count -eq 0) { ' (无)' } else { '' }))
  if ($offend.Count -gt 0) { $bad += ('DismRun 参数没加括号: ' + ($offend -join ', ')) }
  # (8) 挂载点路径必须纯 ASCII: NetFX 的 lodctr 高级安装器只认 ASCII 路径(2026-10-06 实测 14099)
  Say ('  [8] WorkRoot = ' + $Work + ' 纯ASCII=' + (WorkRootIsAscii $Work) + ' | mount=' + $Mount + ' probe=' + $Probe + ' media=' + $Media)
  if (-not (WorkRootIsAscii $Work)) { $bad += '挂载点路径含非 ASCII 字符' }
  # (9) 组件包来源: 26100 的 cab 装 19041 映像必 0x800f081e, 所以必须命中 19041 的 WinPE_OCs
  $need5 = @('WinPE-WMI.cab','WinPE-NetFX.cab','WinPE-Scripting.cab','WinPE-PowerShell.cab','WinPE-HTA.cab')
  if ($Pe10.Oc) {
    $OcCnt = @(Get-ChildItem $Pe10.Oc -Filter '*.cab' -File -EA SilentlyContinue).Count
    $miss5 = @($need5 | Where-Object { -not (Test-Path (Join-Path $Pe10.Oc $_)) })
    Say ('  [9] 19041 WinPE_OCs cab=' + $OcCnt + ' 关键包缺失=' + $miss5.Count + (@($miss5 | ForEach-Object { ' ' + $_ }) -join ''))
    if ($OcCnt -lt 20 -or $miss5.Count -gt 0) { $bad += '19041 组件包不全(先跑 test\26_ExtractAdk10Pe.ps1)' }
  } else {
    Say '  [9] 没有 19041 WinPE_OCs -> 会退回本机 26100 cab, 必 0x800f081e'
    $bad += '缺少 19041 组件包'
  }
  if ($bad.Count -eq 0) { Say 'SELFTEST OK' } else { Say ('SELFTEST FAIL: ' + ($bad -join '; ')); exit 1 }
  exit 0
}

# ---------- 1. 取 Win10 基镜像 ----------
Say '[1/8] 准备 Win10 基镜像 boot.wim ...'
if ($Pe10.Wim) {
  # 组件包与基镜像同世代才不会 0x800f081e, 所以有 19041 的 winpe.wim 就优先用它;
  # 但绝不直接在 D:\adk10pe 里挂载 —— DISM /Commit 会改写解包出来的原件。
  $workCopy = 'D:\winpe10_probe\winpe10_base.wim'
  $srcLen = (Get-Item $Pe10.Wim).Length
  if (-not ((Test-Path $workCopy) -and (Get-Item $workCopy).Length -eq $srcLen)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $workCopy) | Out-Null
    Copy-Item $Pe10.Wim $workCopy -Force
    Say ('  winpe.wim 复制成工作副本: ' + $workCopy + ' (' + ('{0:N0}' -f $srcLen) + ' B), 原件保持不动')
  }
  $BaseWim = $workCopy
  Say ('  基镜像改用 19041 add-on 的 winpe.wim: ' + $Pe10.Wim)
}
if (-not (Test-Path $BaseWim)) {
  if (-not (Test-Path $SourceIso)) { Say ("找不到 ISO: " + $SourceIso); exit 1 }
  Say ("  从 ISO 复制 sources\boot.wim -> " + $BaseWim)
  $mounted = $false
  try {
    Mount-DiskImage -ImagePath $SourceIso | Out-Null
    Start-Sleep -Seconds 3
    $drv = ((Get-DiskImage -ImagePath $SourceIso | Get-Volume).DriveLetter + ':\')
    $mounted = $true
    New-Item -ItemType Directory -Force -Path (Split-Path $BaseWim) | Out-Null
    $t0 = Get-Date
    Copy-Item ($drv + 'sources\boot.wim') $BaseWim -Force
    Say ("  复制 " + ('{0:N0}' -f (Get-Item $BaseWim).Length) + " B, 用时 " + [int]((Get-Date)-$t0).TotalSeconds + " 秒")
  } finally {
    if ($mounted) { Dismount-DiskImage -ImagePath $SourceIso | Out-Null }
  }
} else {
  Say ("  用已有本地副本: " + $BaseWim + " (" + ('{0:N0}' -f (Get-Item $BaseWim).Length) + " B)")
}
# 从 ISO 拷出的文件带只读属性, /Mount-Wim 读写挂载会报 0xC1510111 "WIM open failed with access denied"
# (2026-10-06 OC 试装就卡在这儿; 普查用 /ReadOnly 所以没暴露)
if ((Get-Item $BaseWim).IsReadOnly) {
  Set-ItemProperty -Path $BaseWim -Name IsReadOnly -Value $false
  Say '  已清除基镜像副本的只读属性(否则读写挂载被拒)'
}

# ---------- 2. 选基镜像索引 + 能力普查 ----------
Say '[2/8] 普查基镜像索引(1=WinPE, 2=Windows Setup), 选组件最全的那个 ...'
if (Test-Path $Probe) { DismRun @('/Unmount-Wim', ('/MountDir:' + $Probe), '/Discard') '清理旧普查点' | Out-Null; Remove-Item $Probe -Recurse -Force -EA SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Probe | Out-Null
function Probe-Index([int]$idx) {
  $d = Join-Path $Probe ("i" + $idx)
  if (Test-Path $d) { Remove-Item $d -Recurse -Force -EA SilentlyContinue }
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  $rc = DismRun @('/Mount-Wim', ('/WimFile:' + $BaseWim), ('/Index:' + $idx), ('/MountDir:' + $d), '/ReadOnly') ('挂载 index ' + $idx)
  if ($rc -ne 0) { return $null }
  $s = Join-Path $d 'Windows\System32'
  $need = [ordered]@{
    'wpeutil'      = (Test-Path (Join-Path $s 'wpeutil.exe'))
    'powershell'   = (Test-Path (Join-Path $s 'WindowsPowerShell\v1.0\powershell.exe'))
    'mshta'        = (Test-Path (Join-Path $s 'mshta.exe'))
    'wbem'         = (Test-Path (Join-Path $s 'wbem\WmiPrvSE.exe'))
    'netfx'        = (Test-Path (Join-Path $d 'Windows\Microsoft.NET\Framework64\v4.0.30319'))
    'mshtml'       = (Test-Path (Join-Path $s 'mshtml.dll'))
    'urlmon'       = (Test-Path (Join-Path $s 'urlmon.dll'))
    'ieframe'      = (Test-Path (Join-Path $s 'ieframe.dll'))
    'jscript'      = (Test-Path (Join-Path $s 'jscript.dll'))
    'dot3api'      = (Test-Path (Join-Path $s 'dot3api.dll'))
    'wlansvc_dll'  = (Test-Path (Join-Path $s 'wlansvc.dll'))
    'driverstore'  = (Test-Path (Join-Path $s 'DriverStore\FileRepository'))
    'font_msyh'    = (Test-Path (Join-Path $d 'Windows\Fonts\msyh.ttc'))
    'font_simsun'  = (Test-Path (Join-Path $d 'Windows\Fonts\simsun.ttc'))
    'ntdll'        = (Get-Item (Join-Path $s 'ntdll.dll') -EA SilentlyContinue).VersionInfo.FileVersion
  }
  $score = (@($need.GetEnumerator() | Where-Object { $_.Value -eq $true }).Count)
  DismRun @('/Unmount-Wim', ('/MountDir:' + $d), '/Discard') ('释放普查点 i' + $idx) | Out-Null
  return [pscustomobject]@{ Index = $idx; Flags = $need; Score = $score }
}
$probes = @()
foreach ($i in @(1,2)) {
  $pr = Probe-Index $i
  if ($pr) {
    Say ("  index " + $pr.Index + " 命中 " + $pr.Score + " 项, ntdll=" + $pr.Flags['ntdll'])
    foreach ($k in $pr.Flags.Keys) { Say ("      {0,-13} {1}" -f $k, $pr.Flags[$k]) }
    $probes += $pr
  } else { Say ("  index " + $i + " 挂载失败, 跳过") }
}
if ($probes.Count -eq 0) { Say 'ERROR: 两个索引都挂不上, 没法继续'; exit 1 }
if ($BaseIndex -eq 'auto') {
  $chosen = ($probes | Sort-Object Score -Descending | Select-Object -First 1)
} else {
  $chosen = ($probes | Where-Object { $_.Index -eq [int]$BaseIndex } | Select-Object -First 1)
  if (-not $chosen) { Say ("ERROR: 指定的索引 " + $BaseIndex + " 不可用"); exit 1 }
}
Say ("  选定基镜像 index = " + $chosen.Index + " (得分 " + $chosen.Score + ")")
# 缺件清单(下面第 3/5 步据此决定要不要补)
$miss = @($chosen.Flags.GetEnumerator() | Where-Object { $_.Value -eq $false -or -not $_.Value } | ForEach-Object { $_.Key })
Say ("  缺失项: " + (($miss | Sort-Object) -join ', '))
$NeedHta     = -not $chosen.Flags['mshta']
$NeedPs      = -not $chosen.Flags['powershell']
$NeedWmi     = -not $chosen.Flags['wbem']
$NeedNetfx   = -not $chosen.Flags['netfx']
if (($NeedPs -or $NeedNetfx) -and -not $Pe10.Oc) {
  Say '  !! 基镜像缺 PowerShell/.NET 且没找到同世代(19041)组件包'
  Say ('     -> 用 -PeRoot10 指向解包出来的 WinPE add-on(默认 ' + $PeRoot10 + '), 否则 HTA 桌面/niccheck/fw_off 跑不起来')
}
if (-not $KeepProbe) { Remove-Item $Probe -Recurse -Force -EA SilentlyContinue }
if ($CensusOnly) {
  Say ('CENSUS ONLY 结束: 选定 index ' + $chosen.Index + ' / mshta=' + $chosen.Flags['mshta'] +
       ' powershell=' + $chosen.Flags['powershell'] + ' wbem=' + $chosen.Flags['wbem'] +
       ' netfx=' + $chosen.Flags['netfx'] + ' 字体=' + $chosen.Flags['font_msyh'] + '/' + $chosen.Flags['font_simsun'])
  Say ('  缺失: ' + (($miss | Sort-Object) -join ', '))
  exit 0
}

# ---------- 2b. OC TRIAL: 19041 组件包能不能装进 19041 基镜像(顺带自证失败原因) ----------
# 全程在 <WorkRoot>\octrial 上做, 结尾 /Discard, 不碰基镜像文件、不出 ISO。
# 两个坑已经踩过: 1) 挂载点路径含中文 -> NetFX 的 lodctr 安装器失败并把挂载点判死;
# 2) 一旦判死, 后面每个包都是 0x800f0830, 看不出谁是真的元凶 -> 所以这里显式记住第一个非零 rc。
if ($OcTrial) {
  $lblTri = '试装 ' + $(if ($Pe10.Oc) { '19041' } else { '26100(本机 ADK)' }) + ' 组件包'
  Say ('===== OC TRIAL(' + $lblTri + ', 结尾全部丢弃) =====')
  $Oc = $(if ($Pe10.Oc) { $Pe10.Oc } else { "$PeTools\amd64\WinPE_OCs" })
  # 候选基镜像一次全试完, 免得再排一轮:
  #   A = 解包出来的 19041 winpe.wim(正统 WinPE 基, 和组件包同版本)
  #   B = LTSC 2021 光盘的 boot.wim(Setup 映像, 自带中文字体与驱动库)
  $targets = @()
  $winpeCopy = 'D:\winpe10_probe\winpe10_base.wim'
  $ltscCopy = 'D:\winpe10_probe\boot.wim'
  if (Test-Path $winpeCopy) { $targets += @{ Name = 'A_winpe.wim'; Wim = $winpeCopy; Index = 1 } }
  if (Test-Path $ltscCopy)  { $targets += @{ Name = 'B_boot.wim'; Wim = $ltscCopy;  Index = $chosen.Index } }
  if ($targets.Count -eq 0) { Say 'ERROR: 两个候选基镜像都不存在, 没法试装'; exit 1 }
  $trialPkgs = @('WinPE-WMI.cab','en-us\WinPE-WMI_en-us.cab','WinPE-NetFX.cab','en-us\WinPE-NetFX_en-us.cab',
                 'WinPE-Scripting.cab','en-us\WinPE-Scripting_en-us.cab','WinPE-PowerShell.cab','en-us\WinPE-PowerShell_en-us.cab',
                 'WinPE-HTA.cab','en-us\WinPE-HTA_en-us.cab','WinPE-StorageWMI.cab','WinPE-Dot3Svc.cab')
  $trialChecks = [ordered]@{
    'powershell'     = 'WindowsPowerShell\v1.0\powershell.exe'
    'mshta'          = 'mshta.exe'
    'mshtml'         = 'mshtml.dll'
    'ieframe'        = 'ieframe.dll'
    'netfx(mscoree)' = 'mscoree.dll'
    'wbem(WmiPrvSE)' = 'wbem\WmiPrvSE.exe'
    'dot3api'        = 'dot3api.dll'
  }
  function Invoke-TrialOne($tg, [int]$n) {
    $mdir = Join-Path $Work ('octrial' + $n)
    $rows = @('### ' + $tg.Name + ' | ' + $tg.Wim + ' index=' + $tg.Index + ' | mount=' + $mdir)
    if (Test-Path $mdir) { DismRun @('/Unmount-Wim', ('/MountDir:' + $mdir), '/Discard') '释放残留' | Out-Null; Remove-Item $mdir -Recurse -Force -EA SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $mdir | Out-Null
    $rc = DismRun @('/Mount-Wim', ('/WimFile:' + $tg.Wim), ('/Index:' + $tg.Index), ('/MountDir:' + $mdir)) ('读写挂载 ' + $tg.Name)
    if ($rc -ne 0 -or -not (Test-Path ($mdir + '\Windows\System32'))) {
      $rows += ('MOUNT FAIL rc=' + $rc + ' | ' + (DismFailCode $rc))
      return @{ Rows = $rows; Ok = $false; Fail = ('挂载失败 rc=' + $rc) }
    }
    $firstFail = $null
    foreach ($pkg in $trialPkgs) {
      $cab = Join-Path $Oc $pkg
      if (-not (Test-Path $cab)) { $rows += ($pkg + ' | cab 不在本机'); continue }
      $r = DismRun @(('/Image:' + $mdir), '/Add-Package', ('/PackagePath:' + $cab), '/Quiet') ($tg.Name + ' Add-Package ' + $pkg)
      $rows += ($pkg + ' | rc=' + $r + $(if ($r -ne 0) { ' | ' + (DismFailCode $r) } else { '' }))
      if ($r -ne 0 -and -not $firstFail) { $firstFail = ($pkg + ' -> ' + (DismFailCode $r)) }
      if ($r -ne 0 -and (DismPoisoned)) {
        Say ('  ' + $tg.Name + ': 挂载点被判死(CBS_E_IMAGE_UNSERVICEABLE), 元凶 = ' + $firstFail + ', 剩下的包再试也只是 0x800f0830')
        $rows += ('STOP: 第一个真实失败 = ' + $firstFail)
        break
      }
    }
    $s = Join-Path $mdir 'Windows\System32'
    $okPs = $false
    foreach ($k in $trialChecks.Keys) {
      $found = Test-Path (Join-Path $s ($trialChecks[$k]))
      $rows += ('check ' + $k + ' | ' + $found)
      if ($k -eq 'powershell') { $okPs = $found }
    }
    DismRun @('/Unmount-Wim', ('/MountDir:' + $mdir), '/Discard') ($tg.Name + ' 释放(discard)') | Out-Null
    Remove-Item $mdir -Recurse -Force -EA SilentlyContinue
    return @{ Rows = $rows; Ok = $okPs; Fail = $firstFail }
  }
  $allRows = @('ocs = ' + $Oc); $verdicts = @(); $n = 0
  foreach ($tg in $targets) {
    $n++
    $res = Invoke-TrialOne $tg $n
    $allRows += $res.Rows
    $verdicts += ($tg.Name + ' PowerShell=' + $res.Ok + $(if ($res.Fail) { ' 首个失败=' + $res.Fail } else { '' }))
    Say ('  ' + $tg.Name + ' -> PowerShell 装得上 = ' + $res.Ok)
  }
  $tailPath = Save-DismTail 'component_trial_dismtail.txt'
  $outFile = Join-Path $Build 'component_trial.txt'
  Set-Content -Path $outFile -Value ($allRows -join "`r`n") -Encoding UTF8
  Say ('  明细: ' + $outFile)
  Say ('  DISM 错误摘录: ' + $tailPath)
  $verdicts | ForEach-Object { Say ('  结论: ' + $_) }
  if (@($verdicts | Where-Object { $_ -like '*PowerShell=True*' }).Count -eq 0) {
    Say '  两个候选基镜像都装不上 -> 看 component_trial_dismtail.txt 的 CSI 行定位'
  } else {
    Say '  有候选能装上 -> 正式构建用 -BaseWim 指到那个(不指定就按脚本默认: 有 winpe.wim 优先 winpe.wim)'
  }
  exit 0
}

# ---------- 3. 组媒体目录(不跑 copype, 用 Win10 基镜像替换 boot.wim) ----------
Say '[3/8] 组装可启动媒体目录 ...'
if (Test-Path $Mount) { DismRun @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '释放残留挂载' | Out-Null }
DismRun @('/Cleanup-Mountpoints') '清理 DISM 会话' | Out-Null
if (Test-Path $Work) {
  if ($Work -match '^[A-Za-z]:\\?$') { Say ('ERROR: -WorkRoot 不能是盘根目录: ' + $Work); exit 1 }
  Say ('  清空工作目录 ' + $Work + ' (下面只应有 DISM 挂载点与媒体目录)')
  Remove-Item $Work -Recurse -Force -EA SilentlyContinue
}
New-Item -ItemType Directory -Force -Path ($Work + '\mount') | Out-Null
New-Item -ItemType Directory -Force -Path ($Media + '\sources') | Out-Null
# 第 3 步导出的目标 boot.wim(v8 里 copype 会自己建 media\sources\boot.wim, 本分支不走 copype 必须自己定义)
$Wim = Join-Path $Media 'sources\boot.wim'
$MedSrc = $(if ($Pe10.Media) { $Pe10.Media } else { ($PeTools + '\amd64\Media') })
Say ('  复制引导文件树(bootmgr/EFI/字体等) 来源 = ' + $MedSrc)
if ($Pe10.Media) {
  # 19041 add-on 的 bootmgfw.efi/bootmgr 是零售版微软签名 -> 目标机可保持 Secure Boot 开启;
  # v8 用的是 28000 预览版引导, 微软不签, 必须关 Secure Boot
  foreach ($bf in @('EFI\Microsoft\Boot\bootmgfw.efi', 'bootmgr.efi', 'Boot\bootmgfw.efi')) {
    $bp = Join-Path $MedSrc $bf
    if (Test-Path $bp) {
      $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      $sig = Get-AuthenticodeSignature $bp
      $ErrorActionPreference = $prev
      Say ('    ' + $bf + ' 签名: ' + $sig.Status + ' / ' + $sig.SignerCertificate.Subject)
    }
  }
}
Copy-Item ($MedSrc + '\*') ($Media + '\') -Recurse -Force
# ---------- 3b. 引导扇区镜像(efisys / etfsboot) ----------
# v8 用的是本机 ADK 的 efisys_noprompt.bin, 里面装的是 28000 预览版 bootmgfw.efi, 微软没给正式签名
# -> 目标机/虚拟机必须关 Secure Boot。Win10 分支应尽量换成 19041 正式版那一份, 这样 Secure Boot 可以开着。
$BootBin = Join-Path $Build 'bootbin'
New-Item -ItemType Directory -Force -Path $BootBin | Out-Null
$binNote = '本机 ADK Oscdimg(26100 世代, 预览版引导, 无正式签名 -> 需关 Secure Boot)'
$efi10 = @(Get-ChildItem $PeRoot10 -Recurse -Filter 'efisys_noprompt.bin' -File -EA SilentlyContinue)
if ($efi10.Count -gt 0) {
  Copy-Item $efi10[0].FullName (Join-Path $BootBin 'efisys_noprompt.bin') -Force
  $binNote = '19041 add-on 的 efisys_noprompt.bin: ' + $efi10[0].FullName
  Say ('  [3b] ' + $binNote)
} elseif (Test-Path $SourceIso) {
  Say ('  [3b] 从光盘取 19041 正式版引导镜像: ' + $SourceIso)
  $mounted10 = $false
  try {
    Mount-DiskImage -ImagePath $SourceIso | Out-Null
    Start-Sleep -Seconds 3
    $drv10 = ((Get-DiskImage -ImagePath $SourceIso | Get-Volume).DriveLetter + ':\')
    $mounted10 = $true
    foreach ($rel in @('efi\microsoft\boot\efisys_noprompt.bin', 'boot\etfsboot.com')) {
      $rp = $drv10 + $rel
      if (Test-Path $rp) {
        $leaf = Split-Path $rp -Leaf
        Copy-Item $rp (Join-Path $BootBin $leaf) -Force
        Set-ItemProperty -Path (Join-Path $BootBin $leaf) -Name IsReadOnly -Value $false
        Say ('    取到 ' + $leaf)
      }
    }
  } catch { Say ('    !! 光盘引导镜像获取失败: ' + $_.Exception.Message) }
  finally { if ($mounted10) { Dismount-DiskImage -ImagePath $SourceIso | Out-Null } }
  if (Test-Path (Join-Path $BootBin 'efisys_noprompt.bin')) { $binNote = 'LTSC 2021 光盘(19041 正式版签名, Secure Boot 可保持开启)' }
}
foreach ($need in @('efisys_noprompt.bin', 'etfsboot.com')) {
  $dst = Join-Path $BootBin $need
  if (Test-Path $dst) { continue }
  $alt = Join-Path $Oscdimg $need
  if (Test-Path $alt) { Copy-Item $alt $dst -Force; Say ('    用本机 ADK 的 ' + $need + ' 顶上'); continue }
  if ($need -eq 'efisys_noprompt.bin' -and (Test-Path (Join-Path $Oscdimg 'efisys.bin'))) {
    Copy-Item (Join-Path $Oscdimg 'efisys.bin') $dst -Force
    Say '    本机 ADK 没有 noprompt 版, 用 efisys.bin(开机会有 "Press any key" 提示)'
    continue
  }
  Say ('  !! ' + $need + ' 哪都没找到, 没法做可引导 ISO'); exit 1
}
Say ('  [3b] 引导镜像来源 = ' + $binNote)

Say ('  导出基镜像 index ' + $chosen.Index + ' -> boot.wim (几分钟) ...')
$rc = DismRun @('/Export-Image', ('/SourceImageFile:' + $BaseWim), ('/SourceIndex:' + $chosen.Index), ('/DestinationImageFile:' + $Wim), '/Compress:max') 'Export-Image'
if ($rc -ne 0 -or -not (Test-Path $Wim)) { Say 'ERROR: 导出基镜像失败'; exit 1 }
Say ("  boot.wim = " + ('{0:N0}' -f (Get-Item $Wim).Length) + " B")

# ---------- 4. 挂载 ----------
Say '[4/8] 挂载 boot.wim ...'
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
$rc = DismRun @('/Mount-Wim', ('/WimFile:' + $Wim), '/Index:1', ('/MountDir:' + $Mount)) '挂载'
if ($rc -ne 0 -or -not (Test-Path ($Mount + '\Windows\System32'))) { Say 'ERROR: 挂载失败'; exit 1 }

# ---------- 5. 组件补全(Win10 基缺什么补什么) ----------
Say '[5/8] 组件普查与补全 ...'
$S32 = Join-Path $Mount 'Windows\System32'
$ocResults = @()
# 5a. 官方组件包优先(必须与基镜像同世代, 否则 DISM 0x800f081e 整体拒绝)
$Oc = $(if ($Pe10.Oc) { $Pe10.Oc } else { "$PeTools\amd64\WinPE_OCs" })
Say ('  组件包来源 = ' + $Oc + $(if ($Pe10.Oc) { ' (19041, 与基镜像同世代)' } else { ' (本机 26100 -> 装 19041 映像必失败)' }))
# 清单照 build.ps1(v8), 保证功能对齐; 缺的 cab 只记录不中止
$ocPkgs = @(
  'WinPE-WMI.cab','en-us\WinPE-WMI_en-us.cab',
  'WinPE-NetFX.cab','en-us\WinPE-NetFX_en-us.cab',
  'WinPE-Scripting.cab','en-us\WinPE-Scripting_en-us.cab',
  'WinPE-PowerShell.cab','en-us\WinPE-PowerShell_en-us.cab',
  'WinPE-StorageWMI.cab','en-us\WinPE-StorageWMI_en-us.cab',
  'WinPE-HTA.cab','en-us\WinPE-HTA_en-us.cab',
  'WinPE-DismCmdlets.cab','en-us\WinPE-DismCmdlets_en-us.cab',
  'WinPE-SecureBootCmdlets.cab',
  'WinPE-Dot3Svc.cab','en-us\WinPE-Dot3Svc_en-us.cab',
  'WinPE-RNDIS.cab','en-us\WinPE-RNDIS_en-us.cab',
  'WinPE-PPPoE.cab','en-us\WinPE-PPPoE_en-us.cab',
  'WinPE-EnhancedStorage.cab','en-us\WinPE-EnhancedStorage_en-us.cab',
  'WinPE-SecureStartup.cab','en-us\WinPE-SecureStartup_en-us.cab',
  'WinPE-FontSupport-ZH-CN.cab'
)
$ocFirstFail = $null
foreach ($pkg in $ocPkgs) {
  $cab = Join-Path $Oc $pkg
  if (-not (Test-Path $cab)) { Say ("  缺少 " + $pkg); $ocResults += ($pkg + ' | cab 不在本机'); continue }
  $r = DismRun @(('/Image:' + $Mount), '/Add-Package', ('/PackagePath:' + $cab), '/Quiet') ('Add-Package ' + $pkg)
  $ocResults += ($pkg + ' rc=' + $r + $(if ($r -ne 0) { ' | ' + (DismFailCode $r) } else { '' }))
  if ($r -ne 0 -and -not $ocFirstFail) { $ocFirstFail = ($pkg + ' -> ' + (DismFailCode $r)) }
  if ($r -ne 0 -and (DismPoisoned)) {
    # 挂载点被 CBS 判死, 继续装只会全是 0x800f0830; 这一步不能救, 直接停下来报元凶
    $t = Save-DismTail 'component_dismtail.txt'
    Set-Content -Path (Join-Path $Build 'component_actions.txt') -Value ($ocResults -join "`r`n") -Encoding UTF8
    Say ('ERROR: 挂载点被判死, 元凶 = ' + $ocFirstFail)
    Say ('       DISM 错误摘录: ' + $t)
    DismRun @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '释放(丢弃报废的挂载点)' | Out-Null
    exit 1
  }
}
# 5b. 装完复检, 仍然缺的才从本机(19044, 与 19041 同族)手搬兜底
if (-not (Test-Path (Join-Path $S32 'mshta.exe'))) {
  # mshta.exe 是薄壳, 真正干活的是 mshtml/ieframe/urlmon/jscript
  $depsOk = (Test-Path (Join-Path $S32 'mshtml.dll')) -and (Test-Path (Join-Path $S32 'urlmon.dll'))
  Say ("  官方 HTA 包没给 mshta.exe(依赖齐=" + $depsOk + ") -> 从本机 System32 搬")
  foreach ($f in @('mshta.exe')) {
    $src = "C:\Windows\System32\$f"
    if (Test-Path $src) { Copy-Item $src (Join-Path $S32 $f) -Force; $ocResults += ("graft " + $f) }
    else { Say ("  !! 本机没有 " + $f) }
  }
  foreach ($f in @('ieframe.dll','jscript9.dll','dxtrans.dll','mshtml.dll','urlmon.dll','jscript.dll')) {
    if (-not (Test-Path (Join-Path $S32 $f))) {
      $src = "C:\Windows\System32\$f"
      if (Test-Path $src) { Copy-Item $src (Join-Path $S32 $f) -Force; $ocResults += ("graft " + $f); Say ("  补 " + $f) }
    } else { $ocResults += ("present " + $f) }
  }
}
if ((-not (Test-Path (Join-Path ($Mount + '\Windows\Fonts') 'msyh.ttc'))) -or (-not (Test-Path (Join-Path ($Mount + '\Windows\Fonts') 'simsun.ttc')))) {
  # HTA 桌面的中文全靠字体文件, 缺了就是一方框; 本机与基镜像同为 1904x, 直接搬
  Say '  官方字体包没给中文字体, 从本机补 ...'
  New-Item -ItemType Directory -Force -Path ($Mount + '\Windows\Fonts') | Out-Null
  foreach ($f in @('msyh.ttc','msyhbd.ttc','msyhl.ttc','simhei.ttf','simsun.ttc','simfang.ttf','simkai.ttf','simsum.ttc','arial.ttf','tahoma.ttf','segoeui.ttf','msgothic.ttc','meiryo.ttc')) {
    $src = "C:\Windows\Fonts\$f"; $dst = Join-Path ($Mount + '\Windows\Fonts') $f
    if ((Test-Path $src) -and -not (Test-Path $dst)) { Copy-Item $src $dst -Force; $ocResults += ('font ' + $f) }
  }
  Say ('  字体补充条目 = ' + (@($ocResults | Where-Object { $_ -like 'font *' }).Count))
}
# 5c. 复检: 组件装完到底有没有 PowerShell / HTA
$gotPs = Test-Path (Join-Path $S32 'WindowsPowerShell\v1.0\powershell.exe')
$gotHta = Test-Path (Join-Path $S32 'mshta.exe')
$gotNet = Test-Path (Join-Path $S32 'mscoree.dll')
$ocResults += ('final powershell = ' + $gotPs)
$ocResults += ('final mshta      = ' + $gotHta)
$ocResults += ('final netfx      = ' + $gotNet)
Say ('  复检: powershell=' + $gotPs + ' mshta=' + $gotHta + ' netfx=' + $gotNet)
if (-not $gotPs) {
  Say '  !! 仍然没有 PowerShell: niccheck/netdrvfix/fw_off/pe_report 会退化成不可用, 请把 -PeRoot10 指到解包出来的 19041 WinPE add-on'
}
Set-Content -Path (Join-Path $Build 'component_actions.txt') -Value ($ocResults -join "`r`n") -Encoding UTF8
Say ("  组件动作记录: build10\component_actions.txt (" + $ocResults.Count + " 条)")

# ---------- 6. overlay(与 build.ps1 同一套素材, 保证功能一致) ----------
Say '[6/8] 注入 overlay: SSH/桌面/向日葵/WiFi 栈/网卡驱动/脚本 ...'
# 6a. OpenSSH 客户端(服务端用自研 pe-sshd: Win32-OpenSSH 的 privsep 子进程在 PE 里 0xC0000142)
New-Item -ItemType Directory -Force -Path ($Mount + '\OpenSSH') | Out-Null
Copy-Item 'C:\Windows\System32\OpenSSH\*' ($Mount + '\OpenSSH') -Force
Copy-Item 'C:\Windows\System32\libcrypto-3-x64.dll' $S32 -Force -EA SilentlyContinue
Copy-Item 'C:\Windows\System32\libcrypto.dll' $S32 -Force -EA SilentlyContinue
# 6b. pe-sshd + 固定主机密钥(X: 是内存盘, 没预置密钥会导致每次开机指纹变化 -> known_hosts 拒连)
New-Item -ItemType Directory -Force -Path ($Mount + '\SSH') | Out-Null
$HostKey = "$Overlay\SSH\pe_host_ed25519"
if (-not (Test-Path $HostKey)) {
  Say '  overlay\SSH\pe_host_ed25519 不存在, 生成一把(与 v8 共用同一把, 别换)'
  & C:\Windows\System32\OpenSSH\ssh-keygen.exe -q -t ed25519 -f $HostKey -N '' -C 'pe-sshd@winpe'
}
if (Test-Path $HostKey) { Say ('  固定主机密钥: ' + ((& C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f "$HostKey.pub") -join ' ')) }
Copy-Item "$Overlay\SSH\*" ($Mount + '\SSH\') -Force
if (Test-Path ($Mount + '\SSH\ssh_login_key')) { Remove-Item ($Mount + '\SSH\ssh_login_key') -Force }   # 私钥绝不进镜像
# 6c. 脚本
foreach ($f in @('startnet.cmd','wlan.cmd','pe_report.ps1','fw_off.ps1','niccheck.ps1','niccheck.cmd','netdrvfix.ps1','netdrvfix.cmd')) {
  Copy-Item "$Overlay\Scripts\$f" $S32 -Force
}
# 6d. 桌面 / 向日葵
Copy-Item "$Overlay\Desktop" ($Mount + '\Desktop') -Recurse -Force
New-Item -ItemType Directory -Force -Path ($Mount + '\Sunlogin') | Out-Null
Copy-Item "$Overlay\Sunlogin\*" ($Mount + '\Sunlogin\') -Force
# 6e. 向日葵运行依赖(本机 19044 的 dll 装进同版本基镜像 = 版本一致)
foreach ($t in @('comctl32.dll','msdmo.dll','pdh.dll')) {
  $src = "C:\Windows\System32\$t"; $dst = Join-Path $S32 $t
  if (-not (Test-Path $src)) { Say ("  主机无 " + $t); continue }
  if (Test-Path $dst) { Say ("  PE 已有 " + $t); continue }
  Copy-Item $src $dst -Force; Say ("  已复制 " + $t)
}
# 6f. WiFi 栈 + 服务注册(wifi-inject.ps1 灌的 dll 全来自本机 19044, 在 Win10 基上是同版本)
# 注意: 这里失败不再中止整轮构建 —— WiFi 栈是 Hyper-V 里根本验不了的附属能力(见 winpe-vm-wifi-limit),
# 而 [5/8] 的 26 个组件包已经花了二十几分钟, 不该因为 WiFi 白跑一遍。失败只记警告, 开机 wlan.cmd 仍会显式报错。
$WifiOk = 'unknown'
try {
  & (Join-Path $Root 'wifi-inject.ps1') -Mount $Mount -Overlay $Overlay
  $WifiOk = 'injected'
} catch {
  $WifiOk = 'FAILED: ' + $_.Exception.Message
  Say ('  !! wifi-inject 失败, 继续出盘(有线/netdrvfix 不受影响): ' + $_.Exception.Message)
}
Add-Content -Path (Join-Path $Build 'component_actions.txt') -Value ('wifi-inject final = ' + $WifiOk) -Encoding UTF8
# 6g. PowerShell 模块扩容(本机与基镜像同世代, /XO 只增不覆盖)
# robocopy 不给 /R /W 时默认"重试 100 万次、每次等 30 秒"(≈347 天), 往 WIM 挂载点写文件被
# 防病毒/筛选器挡一下就是无限假死, 而且输出进了 Out-Null 什么都看不见
# —— 2026-10-07 正式构建就卡死在第二个 robocopy(全局模块 5 个目录只落了 2 个, 进程 CPU 不再涨)。
# 所以这里强制 /R:1 /W:1(失败一次就跳过) + /XJ(不跟 junction) + /LOG(留证据)。
$RbCommon = @('/E', '/XO', '/XJ', '/R:1', '/W:1', '/MT:8', '/NFL', '/NDL', '/NJH')
function Copy-PeModules([string]$src, [string]$dst, [string]$logName) {
  if (-not (Test-Path $src)) { Say ("  源不存在, 跳过: " + $src); return }
  $log = Join-Path $Build $logName
  $n0 = @(Get-ChildItem $dst -Recurse -File -EA SilentlyContinue).Count
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & robocopy $src $dst @RbCommon ('/LOG:' + $log) | Out-Null
  $rc = $LASTEXITCODE
  $n1 = @(Get-ChildItem $dst -Recurse -File -EA SilentlyContinue).Count
  $ErrorActionPreference = $prev
  Say ('  robocopy ' + (Split-Path $src -Leaf) + ' -> PE: code=' + $rc + ' 文件 ' + $n0 + ' -> ' + $n1 + ' (明细 build10\' + $logName + ')')
  if ($rc -ge 16) { Say '    !! robocopy 严重错误(被杀或参数错), 该目录未拷全; PE 只用 System32 模块, 不影响功能' }
}
Say '  复制 PowerShell 模块(可能较慢) ...'
Copy-PeModules 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules' ($Mount + '\Windows\System32\WindowsPowerShell\v1.0\Modules') 'robocopy_psmodules.log'
Copy-PeModules 'C:\Program Files\WindowsPowerShell\Modules' ($Mount + '\Program Files\WindowsPowerShell\Modules') 'robocopy_psmodules_global.log'
# 6h. winpeshl.ini 由 startnet.cmd 接管
Remove-Item ($S32 + '\winpeshl.ini') -EA SilentlyContinue

# ---------- 6i. 万能有线网卡驱动 + 硬件ID 索引 ----------
Say '[6i] 注入有线网卡驱动 (overlay\Drivers\Net) ...'
$NetDrv = Join-Path $Overlay 'Drivers\Net'
$frDir  = Join-Path $S32 'DriverStore\FileRepository'
$before = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
$after  = $before
$nInf   = 0
$prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& $DismExe ('/Image:' + $Mount) '/Add-Driver' ('/Driver:' + $NetDrv) '/Recurse' '/ForceUnsigned' *>&1 | Out-File -FilePath (Join-Path $Build 'dism_add_netdrv.log') -Encoding UTF8
$drvRc = $LASTEXITCODE
$ErrorActionPreference = $prevEap
$after = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
$nInf  = @(Get-ChildItem $NetDrv -Recurse -Filter '*.inf' -EA SilentlyContinue).Count
Say ('  inf ' + $nInf + ' 个 / DISM rc=' + $drvRc + ' / DriverStore ' + $before + ' -> ' + $after)
if (($after - $before) -lt 10) { Say '  !! 只多出不到 10 个驱动包, 请查 build10\dism_add_netdrv.log' }
$IdxFile = Join-Path $Overlay 'Scripts\netdrv_index.txt'
& (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1') -DrvDir $NetDrv -Out $IdxFile
if (Test-Path $IdxFile) {
  Copy-Item $IdxFile $S32 -Force
  Say ('  已装 netdrv_index.txt (' + [math]::Round((Get-Item $IdxFile).Length / 1KB, 1) + ' KB)')
} else { Say '  !! 没生成索引, 镜像里的 netdrvfix 会直接报错退出' }

# 6j. 镜像内版本标记(niccheck 会打印; 与 v8 区分就靠这里 + 文件名)
# BUILD_TAG.txt 是 -Encoding ASCII 写的(基镜像是 en-us PE, 控制台代码页 437), 这里必须全 ASCII,
# 否则中文会变成一串问号, 救援时读不清。
$bootbinTag = $(if ($binNote -match '19041') { '19041 retail signed (Secure Boot should stay ON)' } else { 'ADK 26100 preview boot (Secure Boot OFF)' })
$tagText = @(
  ('build   = ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
  ('base    = Windows 10 ' + $chosen.Flags['ntdll'] + ' (boot.wim index ' + $chosen.Index + ')'),
  ('product = ' + $Product),
  ('netdrv  = inf ' + $nInf + ' / DriverStore ' + $before + '->' + $after),
  ('tools   = niccheck / netdrvfix  (netdrvfix auto-runs at boot: startnet [1a])'),
  ('bootbin = ' + $bootbinTag),
  ('wifi    = ' + $WifiOk),
  ('hta     = ' + $(if (Test-Path (Join-Path $S32 'mshta.exe')) { 'yes' } else { 'NO - desktop will not start' })),
  ('powershell = ' + $(if (Test-Path (Join-Path $S32 'WindowsPowerShell\v1.0\powershell.exe')) { 'yes' } else { 'NO' }))
) -join "`r`n"
Set-Content -Path ($Mount + '\BUILD_TAG.txt') -Value $tagText -Encoding ASCII -NoNewline
Say ('  已写 X:\BUILD_TAG.txt / product=' + $Product)

# ---------- 7. 离线注册表: 执行策略 + 关防火墙 ----------
Say '[7/8] 离线注册表(执行策略 / 关闭防火墙) ...'
$mp = 'HKLM\PE10_SYS'
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
reg load $mp ($S32 + '\Config\SOFTWARE') 2>$null | Out-Null
if (-not (Test-Path 'HKLM:\PE10_SYS')) { $ErrorActionPreference = 'Stop'; Say 'ERROR: 注册表加载失败'; exit 1 }
try {
  reg add "$mp\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f | Out-Null
  reg add "$mp\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 1 /f | Out-Null
  Say '  执行策略已写'
} finally {
  reg unload $mp 2>$null | Out-Null
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  $ErrorActionPreference = $prev
}
try {
  & (Join-Path $Root 'fw-offline.ps1') -Mount $Mount
} catch { Say ('  !! 防火墙离线关闭失败: ' + $_.Exception.Message + ' (开机 fw_off.ps1 兜底)') }

# ---------- 8. 提交 + 出 ISO ----------
Say '[8/8] 卸载 boot.wim 并生成 ISO ...'
function Test-RegHiveLoaded([string]$key) {
  $p = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
  $null = & reg.exe query $key 2>$null
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $p
  return ($rc -eq 0)
}
foreach ($round in 1..2) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  foreach ($hk in @('PE10_SYS','PE_FW','PE_SYS','PE_SYS2')) {
    $key = 'HKLM\' + $hk
    if (Test-RegHiveLoaded $key) {
      $p = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
      $null = & reg.exe unload $key 2>$null
      $ErrorActionPreference = $p
      Say ('  残留配置单元 ' + $key + ' 已尝试卸载')
    }
  }
}
$rc = DismRun @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Commit') '提交'
if ($rc -ne 0) { Say 'ERROR: 提交失败(检查是否有进程占用 mount)'; exit 1 }

$Iso = & (Join-Path $Root 'test\iso_target.ps1') -Base (Join-Path $Dist ($Product + '.iso')) | Select-Object -Last 1
if (-not $Iso) { Say 'ERROR: 目标 ISO 被占用且无法改名'; exit 1 }
if (Test-Path $Iso) { Remove-Item $Iso -Force }
$EfiBin = 'efisys_noprompt.bin'
if (-not (Test-Path (Join-Path $BootBin $EfiBin))) { $EfiBin = 'efisys.bin' }
Push-Location $BootBin
try {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & "$Oscdimg\oscdimg.exe" -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,b' + $EfiBin) $Media $Iso 2>&1 | Select-Object -Last 4 | ForEach-Object { Say ('  oscdimg: ' + $_) }
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
} finally { Pop-Location }
if ($rc -ne 0 -or -not (Test-Path $Iso)) { Say 'ERROR: oscdimg 失败'; exit 1 }

$bootEntries = 0; $etLba = -1; $catLba = -1; $sectorLen = 2048
$fs = [IO.File]::OpenRead($Iso)
try {
  $br = New-Object System.IO.BinaryReader($fs)
  $total = [int][Math]::Floor($fs.Length / $sectorLen)
  $sig = [Text.Encoding]::ASCII.GetBytes('EL TORITO SPECIFICATION')
  for ($s = 0; $s -lt [Math]::Min(64, $total); $s++) {
    $sec = $br.ReadBytes($sectorLen)
    if ($sec.Length -lt $sectorLen) { break }
    $ok = $true
    for ($k = 0; $k -lt $sig.Length; $k++) { if ($sec[7 + $k] -ne $sig[$k]) { $ok = $false; break } }
    if ($ok) { $etLba = $s; $catLba = [BitConverter]::ToInt32($sec, 71); break }
  }
  if ($catLba -gt 0 -and $catLba -lt $total) {
    $fs.Position = [int64]$catLba * $sectorLen
    $cat = $br.ReadBytes($sectorLen)
    for ($o = 0x20; $o + 32 -le $cat.Length; $o += 32) {
      if ($cat[$o] -ne 0x88) { continue }
      $lba = [BitConverter]::ToInt32($cat, $o + 8)
      if ($lba -gt 0 -and $lba -lt $total) { $bootEntries++ }
    }
  }
} finally { $fs.Close() }
if ($bootEntries -lt 2) { Say ('ERROR: ISO 引导记录异常 ET-VD=' + $etLba + ' catalog=' + $catLba + ' 可引导项=' + $bootEntries); exit 1 }
Say ('  El Torito 校验通过 (引导目录 LBA ' + $catLba + ', 可引导项 ' + $bootEntries + ', EFI ' + $EfiBin + ')')
Say ''
Say ('完成! 产物: ' + $Iso)
Say ('大小: ' + ('{0:N1} MB' -f ((Get-Item $Iso).Length/1MB)))
Say ('基镜像: Windows 10 index ' + $chosen.Index + ' / ntdll ' + $chosen.Flags['ntdll'])
Say ('缺失项(构建开始时普查): ' + (($miss | Sort-Object) -join ', '))
Say ('引导镜像来源: ' + $binNote)
if ($binNote -match '19041') { Say '  -> 目标是拿到 19041 正式版签名引导, Secure Boot 或许可以保持开启(交付前实机确认)' }
else { Say '  -> 仍是本机 ADK 的预览版引导(未签名), Secure Boot 需关闭, 与 v8 相同' }
Say '与 v8 的区分看文件名和 X:\BUILD_TAG.txt 的 product 行'
