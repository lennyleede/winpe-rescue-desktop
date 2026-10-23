# ============================================================
# WinPE 定制 ISO 构建 v8 (HTA桌面+frp手动面板 / SSH自启 / 向日葵自启 / WiFi栈注入)
# 以管理员 PowerShell 运行:
#   powershell -ExecutionPolicy Bypass -File build.ps1
# 产物: .\dist\WinPE_Desktop_v8.iso   (不触碰 D:\winpe_build)
# 只想补 WiFi(不重跑 copype/组件): .\patch_wifi.ps1
# ============================================================
$ErrorActionPreference = 'Stop'
$Root    = $PSScriptRoot
$Build   = Join-Path $Root 'build'
$Media   = Join-Path $Build 'WinPE_amd64'
$Mount   = Join-Path $Build 'mount'
$Overlay = Join-Path $Root 'overlay'
$Dist    = Join-Path $Root 'dist'
$ADK     = 'C:\Program Files (x86)\Windows Kits\10'
$PeTools = "$ADK\Assessment and Deployment Kit\Windows Preinstallation Environment"
$DismExe = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe"
$Oscdimg = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"
# Get-DismPkgReport: 把 DISM /Add-Driver 日志读成"逐包 ok/失败"(/Recurse 的部分失败只有这里能看出来)
. (Join-Path $Root 'test\DismReport.ps1')

# ---------- 0. 管理员检查 ----------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请以管理员身份运行' -ForegroundColor Red; exit 1
}
foreach ($p in @($DismExe, "$Oscdimg\oscdimg.exe", "$PeTools\copype.cmd")) {
  if (-not (Test-Path $p)) { Write-Host "缺少 ADK 组件: $p" -ForegroundColor Red; exit 1 }
}
# copype/oscdimg 依赖这些环境变量 (Deployment and Imaging Tools 环境里才有)
$env:WinPERoot   = $PeTools
$env:OSCDImgRoot = $Oscdimg
$env:DISMRoot    = Split-Path $DismExe
$env:Path       += ";$Oscdimg;$(Split-Path $DismExe);$PeTools"

# ---------- 1. copype ----------
Write-Host '[1/6] copype amd64 ...' -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $Build,$Dist | Out-Null
# 先释放残留挂载, 否则 boot.wim 被占用删不掉
if (Test-Path $Mount) {
  & $DismExe /Unmount-Wim /MountDir:$Mount /Discard 2>$null | Out-Null
  Start-Sleep -Seconds 2
  Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue
}
# 也检查 DISM 镜像会话残留
& $DismExe /Cleanup-Mountpoints 2>$null | Out-Null
if (Test-Path $Media) { Remove-Item $Media -Recurse -Force -ErrorAction Stop }
& "$PeTools\Copype.cmd" amd64 $Media | Out-Null
if (-not (Test-Path "$Media\media\sources\boot.wim")) { Write-Host 'copype 失败' -ForegroundColor Red; exit 1 }

# ---------- 2. 挂载 ----------
Write-Host '[2/6] 挂载 boot.wim ...' -ForegroundColor Cyan
if (Test-Path $Mount) { & $DismExe /Unmount-Wim /MountDir:$Mount /Discard 2>$null | Out-Null; Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
$Wim = "$Media\media\sources\boot.wim"
& $DismExe /Mount-Wim /WimFile:$Wim /Index:1 /MountDir:$Mount
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$Mount\Windows\System32")) { Write-Host '挂载失败' -ForegroundColor Red; exit 1 }

# ---------- 3. 可选组件 ----------
Write-Host '[3/6] 注入 WinPE 组件 ...' -ForegroundColor Cyan
$Oc = "$PeTools\amd64\WinPE_OCs"
$pkgs = @(
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
foreach ($pkg in $pkgs) {
  $cab = Join-Path $Oc $pkg
  if (Test-Path $cab) {
    & $DismExe /Image:$Mount /Add-Package /PackagePath:$cab /Quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "  警告: $pkg 添加失败(可能已内置), 继续" -ForegroundColor Yellow }
  } else { Write-Host "  缺少 $pkg, 跳过" -ForegroundColor Yellow }
}

# ---------- 4. overlay 与主机工具 ----------
Write-Host '[4/6] 复制 OpenSSH / 桌面 / 向日葵 / frp / WiFi 栈 / PowerShell 模块 ...' -ForegroundColor Cyan

# 4a. OpenSSH 客户端 + libcrypto 依赖 (服务端不用它: privsep 子进程在 PE 里 0xC0000142)
$SshDst = "$Mount\OpenSSH"
New-Item -ItemType Directory -Force -Path $SshDst | Out-Null
Copy-Item 'C:\Windows\System32\OpenSSH\*' $SshDst -Force
Copy-Item 'C:\Windows\System32\libcrypto-3-x64.dll' "$Mount\Windows\System32\" -Force -ErrorAction SilentlyContinue
Copy-Item 'C:\Windows\System32\libcrypto.dll' "$Mount\Windows\System32\" -Force -ErrorAction SilentlyContinue

# 4a2. 自研 SSH 服务端 (Go 静态编译, 无 DLL/无 Windows 认证依赖) —— 先跑 sshserver\build.ps1
$PeSsh = "$Overlay\SSH\pe-sshd.exe"
if (-not (Test-Path $PeSsh)) {
  Write-Host "缺少 $PeSsh`n  请先执行: powershell -NoProfile -ExecutionPolicy Bypass -File sshserver\build.ps1" -ForegroundColor Red
  exit 1
}
New-Item -ItemType Directory -Force -Path "$Mount\SSH" | Out-Null
# 4a3. 固定主机密钥: X: 是内存盘, pe-sshd 找不到 pe_host_ed25519 就每次开机重新生成一把,
#      主机侧 known_hosts 于是每重启一次就报 REMOTE HOST IDENTIFICATION HAS CHANGED 直接拒连
#      (2026-10-05 实测定罪: 这就是"SSH 突然连不上"的原因, 与防火墙无关)。镜像里预置一把即可稳定。
$HostKey = "$Overlay\SSH\pe_host_ed25519"
if (-not (Test-Path $HostKey)) {
  Write-Host '  overlay\SSH\pe_host_ed25519 不存在, 现场生成一把(此后所有构建都用它, 别再换)' -ForegroundColor Yellow
  & C:\Windows\System32\OpenSSH\ssh-keygen.exe -q -t ed25519 -f $HostKey -N '' -C 'pe-sshd@winpe'
  if (-not (Test-Path $HostKey)) { Write-Host '  !! 主机密钥生成失败, SSH 指纹会每次开机变化' -ForegroundColor Yellow }
}
if (Test-Path $HostKey) {
  $fp = (& C:\Windows\System32\OpenSSH\ssh-keygen.exe -l -f "$HostKey.pub") -join ' '
  Write-Host ("  固定主机密钥: " + $fp)
}
Copy-Item "$Overlay\SSH\*" "$Mount\SSH\" -Force
if (Test-Path "$Mount\SSH\ssh_login_key") { Remove-Item "$Mount\SSH\ssh_login_key" -Force }   # 私钥绝不进镜像

# 4b. 脚本 (不含私钥! ssh_login_key 保留在宿主机)
#     sshd_config/administrators_authorized_keys 是 Win32-OpenSSH 服务端的旧配套, 服务端已换 pe-sshd
#     pe_getdriver.ps1 = 现场"索引里没有这块芯片"时的外网下载通道(实机验过: PE 自己 Invoke-WebRequest 拉 catalog cab -> expand -> pnputil)
foreach ($f in @('startnet.cmd','wlan.cmd','pe_report.ps1','fw_off.ps1','niccheck.ps1','niccheck.cmd','netdrvfix.ps1','netdrvfix.cmd','storageprobe.ps1','storageprobe.cmd','rescue.ps1','rescue.cmd','pe_getdriver.ps1','pe_getdriver.cmd','bootfix.ps1','bootfix.cmd','filefix.ps1','filefix.cmd','drvfix.ps1','drvfix.cmd','letterfix.ps1','letterfix.cmd','gptfix.ps1','gptfix.cmd','gptdump.ps1','gptdump.cmd')) {
  Copy-Item "$Overlay\Scripts\$f" "$Mount\Windows\System32\" -Force
}

# 4c. 桌面 (HTA + Frp + Wlan 模板)
Copy-Item "$Overlay\Desktop" "$Mount\Desktop" -Recurse -Force

# 4d. 向日葵 SOS
New-Item -ItemType Directory -Force -Path "$Mount\Sunlogin" | Out-Null
Copy-Item "$Overlay\Sunlogin\*" "$Mount\Sunlogin\" -Force

# 4e. WiFi 栈 + 自研工具 + 服务注册表 (与 patch_wifi.ps1 共用 wifi-inject.ps1)
#     comctl32/msdmo/pdh 是向日葵 SOS 的运行依赖, PE 镜像里没有, 缺则 0xC0000135 直接起不来(已实机验证)
foreach ($t in @('comctl32.dll','msdmo.dll','pdh.dll')) {
  $src = "C:\Windows\System32\$t"
  $dst = Join-Path "$Mount\Windows\System32" $t
  if (-not (Test-Path $src)) { Write-Host "  主机无 $t, 跳过" -ForegroundColor Yellow; continue }
  if (Test-Path $dst) { Write-Host "  PE 已有 $t"; continue }
  try { Copy-Item $src $dst -Force -ErrorAction Stop; Write-Host "  已复制 $t" }
  catch { Write-Host "  !! $t 复制失败: $($_.Exception.Message)" -ForegroundColor Yellow }
}
try {
  & (Join-Path $Root 'wifi-inject.ps1') -Mount $Mount -Overlay $Overlay
} catch {
  # 别让半截改动留在挂载点里, 也不要带着脏镜像继续做 ISO
  & $DismExe /Unmount-Wim /MountDir:$Mount /Discard | Out-Null
  Write-Host "wifi-inject 失败: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

# 4f. PowerShell 模块扩容 ("全量" 尽力): 复制主机模块目录 (合并, /XO 不覆盖 PE 自带)
Write-Host '  复制 PowerShell 模块 (可能较慢) ...' -ForegroundColor Cyan
robocopy 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules' "$Mount\Windows\System32\WindowsPowerShell\v1.0\Modules" /E /XO /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { Write-Host "  PS 模块复制警告 code=$LASTEXITCODE" -ForegroundColor Yellow }
robocopy 'C:\Program Files\WindowsPowerShell\Modules' "$Mount\Program Files\WindowsPowerShell\Modules" /E /XO /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { Write-Host "  PS 全局模块复制警告 code=$LASTEXITCODE" -ForegroundColor Yellow }

# 4g. winpeshl.ini 确认禁用 (由 startnet.cmd 接管)
Remove-Item "$Mount\Windows\System32\winpeshl.ini" -ErrorAction SilentlyContinue

# ---------- 4h. 万能有线网卡驱动 ----------
# 实机教训(2026-10-05): 3 代 i5 台机(板载 82579V)在 PE 里一块网卡都认不出来 —— 基础 WinPE 的驱动集
# 比完整 Windows 小得多, 而"给别人的电脑做运维"要求镜像自带各家网卡驱动。
# 驱动由 test\15_CollectNetDrivers.ps1 从 D:\winpe_build\hotpe_net\Lan 精简产出(同名 INF 取最新 DriverVer,
# 剔服务器/虚拟网卡, 按 INF 文本引用挑文件), 这里整目录递归注入即可。
Write-Host '[4h/6] 注入有线网卡驱动 (overlay\Drivers\Net) ...' -ForegroundColor Cyan
$NetDrv = Join-Path $Overlay 'Drivers\Net'
$frDir  = "$Mount\Windows\System32\DriverStore\FileRepository"
$before = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
$after  = $before
$nInf   = 0
$netFailedTxt = 'not injected'
if (Test-Path $NetDrv) {
  $drvLog = Join-Path $Build 'scratch\dism_add_netdrv.log'
  New-Item -ItemType Directory -Force -Path (Split-Path $drvLog) | Out-Null
  # DISM 只要往 stderr 吐一个字, EAP=Stop 就会把它变成终止错误(和 [6/6] 那次白扔注入同一个坑), 所以这段降 Continue
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $DismExe /Image:$Mount /Add-Driver /Driver:$NetDrv /Recurse /ForceUnsigned *>&1 | Out-File -FilePath $drvLog -Encoding UTF8
  $drvRc = $LASTEXITCODE
  $ErrorActionPreference = $prevEap
  $after = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
  $nInf = @(Get-ChildItem $NetDrv -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
  Write-Host ('  inf ' + $nInf + ' 个 / DISM rc=' + $drvRc + ' / DriverStore ' + $before + ' -> ' + $after + '  (日志 ' + $drvLog + ')')
  $netRep = Get-DismPkgReport -LogPath $drvLog
  if ($netRep.present) {
    Write-Host ('  逐包: ok ' + $netRep.ok + ' / 失败 ' + @($netRep.failed).Count + ' / 找到 ' + $netRep.found)
    foreach ($x in @($netRep.failed)) { Write-Host ('    !! ' + $x) -ForegroundColor Yellow }
    $netFailedTxt = $(if (@($netRep.failed).Count) { 'REJECTED ' + ((@($netRep.failed) | ForEach-Object { (($_ -split '::')[0]).Trim() } | Select-Object -First 6) -join ' ') } else { 'all accepted' })
  }
  if (($after - $before) -lt 10) {
    Write-Host '  !! 只多出不到 10 个驱动包, 实机大概率仍认不出网卡, 请把日志末尾贴回来:' -ForegroundColor Red
    Get-Content $drvLog -Tail 20 | ForEach-Object { Write-Host ('    ' + $_) }
  }
} else {
  Write-Host '  没有 overlay\Drivers\Net, 跳过注入 (先跑 test\15_CollectNetDrivers.ps1)' -ForegroundColor Yellow
}

# ---------- 4i. Intel 存储驱动(VMD / AHCI / VROC): 开 VMD 的 11-14 代机器"看不见硬盘"的那一半 ----------
# 实机教训(2026-10-08, 12 代 i5): BIOS 开 VMD 时 NVMe 和 SATA **都**藏在 VMD 控制器(PCI\VEN_8086&DEV_467F)后面,
# 基础 WinPE 没有 iaStorVD -> 开机只枚举出启动 U 盘(disks=1), 离线修复/取日志全是空谈。
# 手工 drvload iaStorVD.inf 后 disks 1->3、D:\Windows 出现, 所以把这几个包烘进镜像, 让开机自愈(netdrvfix v3)直接做到。
Write-Host '[4i/6] 注入存储驱动 (overlay\Drivers\Storage) ...' -ForegroundColor Cyan
$StoDrv = Join-Path $Overlay 'Drivers\Storage'
$stoBefore = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
$stoAfter  = $stoBefore
$stoNInf   = 0
$stoRc     = 'skip'
$stoFailedTxt = 'not injected'
if (Test-Path $StoDrv) {
  $stoLog = Join-Path $Build 'scratch\dism_add_stodrv.log'
  New-Item -ItemType Directory -Force -Path (Split-Path $stoLog) | Out-Null
  $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $DismExe /Image:$Mount /Add-Driver /Driver:$StoDrv /Recurse /ForceUnsigned *>&1 | Out-File -FilePath $stoLog -Encoding UTF8
  $stoRc = $LASTEXITCODE
  $ErrorActionPreference = $prevEap
  $stoAfter = @(Get-ChildItem $frDir -Directory -EA SilentlyContinue).Count
  $stoNInf = @(Get-ChildItem $StoDrv -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
  Write-Host ('  inf ' + $stoNInf + ' 个 / DISM rc=' + $stoRc + ' / DriverStore ' + $stoBefore + ' -> ' + $stoAfter + '  (日志 ' + $stoLog + ')')
  # 部分失败必须点名: /Recurse 是"进 6 个拒 1 个"也照样把 DriverStore 涨上去, 只看增量等于没检查。
  # (2026-10-08 iaAHCIC: 包缺 RstMwService.exe / RstMwEventLogMsg.dll, DISM 拒了, 当时构建脚本报了成功)
  $stoRep = Get-DismPkgReport -LogPath $stoLog
  $stoFailedTxt = 'no per-package lines in log'
  if ($stoRep.present) {
    Write-Host ('  逐包: ok ' + $stoRep.ok + ' / 失败 ' + @($stoRep.failed).Count + ' / 找到 ' + $stoRep.found) -ForegroundColor $(if (@($stoRep.failed).Count) { 'Red' } else { 'Gray' })
    foreach ($x in @($stoRep.failed)) { Write-Host ('    !! ' + $x) -ForegroundColor Red }
    if (@($stoRep.failed).Count) {
      Write-Host '    先跑 test\verify_stodrv.ps1(它会检查 [SourceDisksFiles] 声明的文件是否齐全), 补齐后重跑本脚本' -ForegroundColor Yellow
      $stoFailedTxt = 'REJECTED ' + ((@($stoRep.failed) | ForEach-Object { (($_ -split '::')[0]).Trim() }) -join ' ')
    } else { $stoFailedTxt = 'all accepted' }
  }
  # 存储池就 7 个包, 增量 >=1 即正常; 一个都没涨且 rc!=0 才报警(不中止: 网卡那一半已经进去了)
  if (($stoAfter - $stoBefore) -eq 0 -and $stoRc -ne 0) {
    Write-Host '  !! 存储驱动没进去, VMD 机器仍会看不见硬盘, 日志末尾:' -ForegroundColor Red
    Get-Content $stoLog -Tail 20 | ForEach-Object { Write-Host ('    ' + $_) }
  }
} else {
  Write-Host '  没有 overlay\Drivers\Storage, 跳过注入 (VMD 机器要靠现场 netdrvfix/pe_getdriver)' -ForegroundColor Yellow
}

# 4h2. 镜像版本标记: X:\BUILD_TAG.txt —— niccheck 会打印它。
#      实机排查时最怕"烧的是旧 ISO 却以为是新的"(10-06 就因为这个多绕了一轮: pack_iso 遇默认名被占用会
#      悄悄改成带时间戳的新文件名), 所以把构建时间+驱动数量写进镜像根目录, 开机一条命令就能自证。
# wlandrv 这一行由 4e 的 wifi-inject 落下的两件东西组成: 索引行数 + 覆盖 nwifi.sys 的 .cat。
# 少了 .cat, nativewifip 会被代码完整性拦下(577), WiFi 整条栈起不来 —— 所以它必须写进自证标记。
$wlanInfN  = @(Get-ChildItem (Join-Path $Overlay 'Drivers\Wlan') -Recurse -Filter *.inf -File -EA SilentlyContinue).Count
$wlanIdxN  = @(Get-Content (Join-Path $Mount 'Windows\System32\wlandrv_index.txt') -EA SilentlyContinue | Where-Object { $_ -match "`t" }).Count
$wlanCatN  = @(Get-ChildItem -LiteralPath (Join-Path $Mount 'Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}') -Filter 'Microsoft-Windows-Client-Desktop-Required-Package04*.cat' -EA SilentlyContinue).Count
# "池里有 23 个 inf" 不等于 "镜像里有 23 包": DISM /Recurse 会进 22 拒 1 还报 rc=0(iaAHCIC 教训)。
# 所以这里按包名去镜像的 DriverStore 里逐个认, 把真的落了几包写进自证标记。
# 已知只少 1 包: netrtwlane02(rtlCoInst.dll/.dat 池里没有) —— 少了它不算 WiFi 不完整, 少第二包才算。
$wlanDsN = 0
$wlanPkgN = 0
$wlanFr  = Join-Path $Mount 'Windows\System32\DriverStore\FileRepository'
if (Test-Path $wlanFr) {
  $wlDirs = @(Get-ChildItem $wlanFr -Directory -EA SilentlyContinue | ForEach-Object { $_.Name.ToLower() })
  $wlBase = @(Get-ChildItem (Join-Path $Overlay 'Drivers\Wlan') -Recurse -Filter *.inf -File -EA SilentlyContinue |
              ForEach-Object { $_.Name.ToLower() } | Sort-Object -Unique)
  $wlanPkgN = @($wlBase).Count
  foreach ($b in $wlBase) { if (@($wlDirs | Where-Object { $_.StartsWith($b + '_') }).Count -gt 0) { $wlanDsN++ } }
}
$wlanTagTxt = ('inf ' + $wlanInfN + ' / DriverStore ' + $wlanDsN + '/' + $wlanPkgN + ' pkgs / index rows ' + $wlanIdxN +
               ' / nwifi .cat ' + $wlanCatN +
               $(if ($wlanCatN -eq 0 -or $wlanIdxN -lt 20 -or ($wlanPkgN -gt 0 -and $wlanDsN -lt ($wlanPkgN - 1))) { '  !! WiFi 不完整, 看 wifi-inject 末尾 VERDICT wlan 行' } else { '' }))
$tagText = @(
  ('build   = ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
  ('netdrv  = inf ' + $nInf + ' / DriverStore ' + $before + '->' + $after + ' / ' + $netFailedTxt),
  ('stodrv  = inf ' + $stoNInf + ' / DriverStore ' + $stoBefore + '->' + $stoAfter + ' / rc ' + $stoRc + ' / ' + $stoFailedTxt + ' (Intel VMD/AHCI/VROC)'),
  ('wlandrv = ' + $wlanTagTxt),
  ('tools   = niccheck / netdrvfix / storageprobe / rescue  (netdrvfix v3.1 auto-runs at boot: startnet [1a], NIC round (wired+wlan) first then storage; verdict = problem code + adapters + disks + sysdisk)'),
  ('product = WinPE_Desktop_v8')
) -join "`r`n"
Set-Content -Path "$Mount\BUILD_TAG.txt" -Value $tagText -Encoding ASCII -NoNewline
Write-Host ('  已写 X:\BUILD_TAG.txt: ' + ($tagText -split "`r`n")[0])

# 4h3. 硬件ID -> 驱动包 索引: 镜像里的 netdrvfix 靠它查表(PE 里解析几百个 UTF-16 INF 太慢, 构建期算好)
#      两份: netdrv_index.txt(网卡) + stodrv_index.txt(存储); 同一套段感知口径(17_ + NetDrvLib)
$IdxFile = Join-Path $Overlay 'Scripts\netdrv_index.txt'
& (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1') -DrvDir $NetDrv -Out $IdxFile
if (Test-Path $IdxFile) {
  Copy-Item $IdxFile "$Mount\Windows\System32\" -Force
  Write-Host ('  已装 netdrv_index.txt (' + [math]::Round((Get-Item $IdxFile).Length / 1KB, 1) + ' KB) -> X:\Windows\System32')
} else {
  Write-Host '  !! 没生成索引, 镜像里的 netdrvfix 会直接报错退出' -ForegroundColor Red
}
$StoIdxFile = Join-Path $Overlay 'Scripts\stodrv_index.txt'
if (Test-Path $StoDrv) {
  & (Join-Path $Root 'test\17_MakeNetDrvIndex.ps1') -DrvDir $StoDrv -Out $StoIdxFile
  if (Test-Path $StoIdxFile) {
    Copy-Item $StoIdxFile "$Mount\Windows\System32\" -Force
    Write-Host ('  已装 stodrv_index.txt (' + [math]::Round((Get-Item $StoIdxFile).Length / 1KB, 1) + ' KB) -> X:\Windows\System32')
  } else {
    Write-Host '  !! 没生成存储索引: 镜像里的 netdrvfix 会打 WARN, 只做网卡那一半' -ForegroundColor Yellow
  }
}

# ---------- 5. 注册表: PowerShell 执行策略 (wlansvc/wcmsvc 服务键已由 4e 的 wifi-inject.ps1 写入) ----------
Write-Host '[5/6] 离线注册表配置 (执行策略) ...' -ForegroundColor Cyan
$SYS_HIVE = "$Mount\Windows\System32\Config\SOFTWARE"
$mp = 'HKLM\PE_SYS'
$ErrorActionPreference = 'Continue'   # reg 的 stderr 不应中断构建
reg load $mp $SYS_HIVE 2>$null | Out-Null
if (-not (Test-Path 'HKLM:\PE_SYS')) { $ErrorActionPreference='Stop'; Write-Host '注册表加载失败, 中止' -ForegroundColor Red; exit 1 }
try {
  # PowerShell 绕过执行策略
  reg add "$mp\Policies\Microsoft\Windows\PowerShell" /v ExecutionPolicy /t REG_SZ /d Bypass /f | Out-Null
  reg add "$mp\Policies\Microsoft\Windows\PowerShell" /v EnableScripts /t REG_DWORD /d 1 /f | Out-Null
  Write-Host '  注册表配置完成'
} finally {
  reg unload $mp 2>$null | Out-Null
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  $ErrorActionPreference = 'Stop'
}

# ---------- 5b. 离线关闭防火墙 (MpsSvc Start=4 + 三 profile EnableFirewall=0) ----------
# 依据: v8 PE 实测 - 零允许规则下运行时写 FirewallEnabled=False 约 4 秒主机即可直连(见 test\vm_result_002256_1.txt)
# 双保险: X:\Windows\System32\fw_off.ps1 由 startnet 的 [1b] 段再兜一次, 两条谁生效都行
Write-Host '[5b/6] 离线注册表: 关闭 WinPE 防火墙 ...' -ForegroundColor Cyan
try {
  & (Join-Path $Root 'fw-offline.ps1') -Mount $Mount
} catch {
  Write-Host "  !! 防火墙离线关闭失败: $($_.Exception.Message) (开机脚本 fw_off.ps1 仍会兜底)" -ForegroundColor Yellow
}

# ---------- 6. 卸载 + 生成 ISO ----------
Write-Host '[6/6] 卸载 boot.wim 并生成 ISO ...' -ForegroundColor Cyan
# 临时配置单元没退干净会把 /Unmount-Wim 顶成"错误 32 另一个程序正在使用此文件"(2026-10-05 就这么失败过一次),
# 所以先回收句柄再把可能残留的 HKLM\PE_* 卸掉, 两轮。
# PS 5.1 坑: $ErrorActionPreference='Stop' 下, reg.exe 只要往 stderr 写一个字就抛终止错误 —— 而"键不存在"
# 这个最好的结果恰恰是靠 stderr 报的(2026-10-05 构建就在 [6/6] 这里炸掉, 白扔一次注入)。所以探测必须降 EAP。
function Test-RegHiveLoaded([string]$key) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  $null = & reg.exe query $key 2>$null
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return ($rc -eq 0)
}
foreach ($round in 1..2) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  foreach ($hk in @('PE_FW', 'PE_SYS', 'PE_SYS2')) {
    $key = 'HKLM\' + $hk
    if (Test-RegHiveLoaded $key) {
      $prev = $ErrorActionPreference
      $ErrorActionPreference = 'SilentlyContinue'
      $null = & reg.exe unload $key 2>$null
      $rc = $LASTEXITCODE
      $ErrorActionPreference = $prev
      Write-Host ('  残留配置单元 ' + $key + ' 已尝试卸载 (rc=' + $rc + ')') -ForegroundColor Yellow
    }
  }
}
& $DismExe /Unmount-Wim /MountDir:$Mount /Commit
if ($LASTEXITCODE -ne 0) { Write-Host '卸载失败 (若有进程占用 mount 目录请先关闭; 再查 reg query HKLM\PE_FW 是否还挂着)' -ForegroundColor Red; exit 1 }

# efisys_noprompt.bin: 去掉 "Press any key to boot from CD/DVD" 提示, 无人值守启动必需
# 正在从旧 ISO 启动的虚拟机会独占该文件, iso_target.ps1 负责换成写得进去的名字
$Iso = & (Join-Path $Root 'test\iso_target.ps1') -Base (Join-Path $Dist 'WinPE_Desktop_v8.iso') | Select-Object -Last 1
if (-not $Iso) { Write-Host '目标 ISO 被占用且无法改名' -ForegroundColor Red; exit 1 }
if (Test-Path $Iso) { Remove-Item $Iso -Force }
$EfiBin = if (Test-Path "$Oscdimg\efisys_noprompt.bin") { 'efisys_noprompt.bin' } else { 'efisys.bin' }
# 注意: bootdata 串里的路径若含空格(oscdimg 会解析失败导致 ISO 无引导记录)，
# 须先切到 Oscdimg 目录用相对文件名
Push-Location $Oscdimg
try {
  # 每个引导镜像前必须有 b 前缀(b<file>), 少一个字母 oscdimg 直接报 "invalid bootdata parameter"
  & "$Oscdimg\oscdimg.exe" -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,b' + $EfiBin) "$Media\media" $Iso
  $rc = $LASTEXITCODE
} finally { Pop-Location }
if ($rc -ne 0 -or -not (Test-Path $Iso)) { Write-Host 'oscdimg 失败' -ForegroundColor Red; exit 1 }

# 校验 El Torito: 前 64 扇区找 El Torito 卷描述符(偏移7起为标识串), 其偏移71 = 引导目录 LBA;
# 引导目录里逐 32 字节槽找 bootInfo=0x88 且引导记录 LBA 合法的条目(oscdimg 不写 0x55AA 校验项)
$etLba = -1; $catLba = -1; $bootEntries = 0
$sectorLen = 2048
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
if ($bootEntries -lt 2) {
  Write-Host ('ISO 引导记录异常: ET-VD LBA={0} catalog LBA={1} 可引导项={2}，ISO 不可引导!' -f $etLba, $catLba, $bootEntries) -ForegroundColor Red
  exit 1
}
Write-Host ('  El Torito 校验通过 (引导目录 LBA {0}, 可引导项 {1} 个, EFI 加载器 {2})' -f $catLba, $bootEntries, $EfiBin)

Write-Host "`n完成! 产物: $Iso" -ForegroundColor Green
Write-Host ('大小: {0:N1} MB' -f ((Get-Item $Iso).Length/1MB)) -ForegroundColor Green
Write-Host '提示: 本 ISO 用预览版 ADK 的 bootx64.efi, 未获微软 UEFI 签名 -> 目标机/虚拟机需关闭 Secure Boot(实机验证过 Gen2 开 Secure Boot 会报 "The boot loader failed")' -ForegroundColor Yellow
