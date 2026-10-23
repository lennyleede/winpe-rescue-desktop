# ============================================================
# patch_wifi.ps1 —— 只补 WiFi 栈的快速通道 (不跑 copype/组件注入, 约 3 分钟)
# 在已经构建过的 build\WinPE_amd64\media\sources\boot.wim 上重新挂载 -> wifi-inject -> 出 ISO。
# 以管理员 PowerShell 运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File patch_wifi.ps1
#   可选: -DriverDir D:\wifi_drv  -OutIso ...\WinPE_Desktop_v7.iso
#         -Force = WiFi 证据不齐时仍然提交并出 ISO(默认不出, 见 [3/4] 的拦截)
# ============================================================
param(
  [string]$DriverDir = '',
  [string]$OutIso    = '',
  [switch]$NoDrivers,
  [switch]$Force
)
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
if (-not $OutIso) { $OutIso = Join-Path $Dist 'WinPE_Desktop_v8.iso' }
# 相对名按项目根展开成绝对名: 第 [4/4] 步是在 Push-Location <Oscdimg 目录> 之后才把 $OutIso 交给 oscdimg.exe
# (bootdata 的 .bin 只能用相对文件名), 相对的输出路径会变成 "<Oscdimg>\dist\X.iso" -> Error 3(2026-10-10 22:30)。
if (-not [IO.Path]::IsPathRooted($OutIso)) { $OutIso = [IO.Path]::GetFullPath((Join-Path $Root $OutIso)) }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请以管理员身份运行' -ForegroundColor Red; exit 1
}
$Wim = "$Media\media\sources\boot.wim"
if (-not (Test-Path $Wim)) { Write-Host "缺 $Wim`n  请先完整跑一次 build.ps1" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Dist)) { New-Item -ItemType Directory -Force -Path $Dist | Out-Null }

Write-Host '[1/4] 挂载 boot.wim ...' -ForegroundColor Cyan
# boot.wim 若被残留挂载会话占用, 先清理
if (Test-Path $Mount) {
  & $DismExe /Unmount-Wim /MountDir:$Mount /Discard 2>$null | Out-Null
  Start-Sleep -Seconds 2
  Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue
}
& $DismExe /Cleanup-Mountpoints 2>$null | Out-Null
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
& $DismExe /Mount-Wim /WimFile:$Wim /Index:1 /MountDir:$Mount
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$Mount\Windows\System32")) { Write-Host '挂载失败(虚拟机若在跑请先关机)' -ForegroundColor Red; exit 1 }

Write-Host '[2/4] 注入 WiFi 栈 ...' -ForegroundColor Cyan
# 本次证据必须来自本次: 先删掉上一轮的 wlan_verify.txt, wifi-inject 收尾会重写它
Remove-Item (Join-Path $Root 'build\scratch\wlan_verify.txt') -Force -EA SilentlyContinue
$injOk = $false
try {
  $a = @{ Mount = $Mount; Overlay = $Overlay }
  if ($DriverDir) { $a.DriverDir = $DriverDir }
  if ($NoDrivers) { $a.NoDrivers = $true }
  & (Join-Path $Root 'wifi-inject.ps1') @a
  $injOk = $true
} catch {
  # 上一轮失败时只打了"注入失败"没打原因, 这里必须把异常原文和出错行号带出来
  Write-Host ('  !! wifi-inject 异常: ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host ('     出错位置: ' + $_.InvocationInfo.ScriptName + ' 行' + $_.InvocationInfo.ScriptLineNumber +
    ' => ' + (($_.InvocationInfo.Line -replace '\s+', ' ').Trim())) -ForegroundColor Red
  if ($_.Exception.ErrorRecord -and $_.Exception.ErrorRecord.PositionMessage) {
    Write-Host ('     ' + ($_.Exception.ErrorRecord.PositionMessage -replace "`r?`n", ' | ')) -ForegroundColor Red
  }
} finally {
  if ($injOk) {
    # X:\BUILD_TAG.txt 是现场唯一能自证"这张盘里有什么"的东西(niccheck 开机就打印它)。
    # 逻辑抽到 test\Update-WlanTag.ps1: 那段代码要在这台机器需要管理员才能跑到,
    # 不抽出来就没人验过 —— 现在由 test\36_RunGates.ps1 用临时目录在普通权限下过三种输入。
    $ev = ''
    $evFile = Join-Path $Root 'build\scratch\wlan_verify.txt'
    if (Test-Path $evFile) { $ev = ((Get-Content $evFile -Raw -EA SilentlyContinue) -replace '\s+', ' ').Trim() }
    # 判"能不能出盘"不许用 $ev -match 'flags=none': wifi-inject 现在写两行证据(wlan + svc-shape),
    # "-match" 只要有一段绿就为真, 形状行亮了 W_TYPE/C_OBJ 也会报"齐"。逻辑抽在 test\WlanEvidenceFlags.ps1,
    # 由门禁在普通权限下覆盖 5 种输入(全绿/形状红/只有旧单行/空/文件行红)。
    $evCheck = @(& (Join-Path $Root 'test\WlanEvidenceFlags.ps1') -Evidence $ev 2>&1)
    $evTail = (($evCheck | ForEach-Object { "$_" }) -join ' ')
    $evOk = ($evTail -match 'ok=1')
    # -Netdrvfix: 把 tools 行里的 netdrvfix/x.y 同步成 overlay 里真正烘进镜像的那个版本(2026-10-12 的教训:
    # 14:25 那张盘 tools 写 3.0 而 overlay 已是 3.2, 现场 wdihost= 读空时没人知道盘里是哪个脚本)。
    # 参数走哈希表(和上面 wifi-inject 那次调用同一写法): PS 5.1 里反引号续行 + 带减号的参数名是坑。
    $tagArgs = @{ TagFile = (Join-Path $Mount 'BUILD_TAG.txt'); Evidence = $ev }
    $ndSrc = Join-Path $Overlay 'Scripts\netdrvfix.ps1'
    if (Test-Path $ndSrc) { $tagArgs['Netdrvfix'] = $ndSrc }
    $tagOut = @(& (Join-Path $Root 'test\Update-WlanTag.ps1') @tagArgs 2>&1)
    foreach ($l in @($tagOut | ForEach-Object { "$_" })) { Write-Host ('  ' + $l) }
    if ((@($tagOut | Where-Object { "$_" -match 'TAG UPDATE = OK' }).Count) -eq 0) {
      Write-Host '  !! BUILD_TAG 没更新成功(注入本身已完成, 仍会提交出盘) —— 现场读到的 wlandrv 行可能是旧的' -ForegroundColor Yellow
    } elseif ($evOk) {
      Write-Host '  WiFi 判据齐: nwifi/wdiwifi 的 .cat 进 CatRoot / 无线索引进 System32 / vWiFi 四 INF+四 .sys+三服务键 / WDI 两 .sys+两服务键(wdiwifi+NdisImPlatform) / 服务层形状=官方 WinRE(wlansvc Type 0x20 + -k WlansvcGroup 无 -p, deps=nativewifip+RpcSs+Ndisuio, SOFTWARE\Svchost\WlansvcGroup 带 CoInitializeSecurityParam=1, LocalSystemNetworkRestricted 里不再留 wlansvc, Control\Network 的 ms_vwifi+ms_nativewifip 组件记录 2/2; wcmsvc 仍是全名 NT Authority\LocalService)' -ForegroundColor Green
    } else {
      Write-Host ('  !! WiFi 证据不齐, 见上面 flags= —— 这块盘连不上 WiFi (' + $evTail + ')') -ForegroundColor Red
    }
    # 证据不齐就不要出盘(2026-10-09 的教训): 上一次 flags=PKG_SHORT 照样提交并出了 ISO,
    # 结果拿那张盘去实机只会重复 code37, 白烧一次上机机会。要绕过请显式加 -Force。
    # 注意 vwifi_store / vwifi_dism 不在此列: 那四个是微软 inbox 服务安装 INF, 没有 [SourceDisks*],
    # 其中只有 netvwifibus.inf 写了 CopyFiles+[DestinationDirs] -> 它必被 DISM 拒 rc=13, 另外三个 rc=0。
    # 所以 vwifi_dism=3/4 是常态而不是缺陷, 它是读数不是判据(详见 wifi-inject.ps1 的 Get-WlanEvidence)。
    if (-not $evOk -and -not $Force) {
      Write-Host '[3/4] 证据不齐, 丢弃挂载点改动, 不出 ISO(确认要带缺陷出盘请加 -Force) ...' -ForegroundColor Yellow
      Write-Host ('     本次证据: ' + $ev) -ForegroundColor Yellow
      Write-Host ('     判据读数: ' + $evTail) -ForegroundColor Yellow
      # /Discard 会把挂载点里的东西全删掉, 包括 DISM 让我们去看的 setupapi.offline.log —— 先捞出来
      @(& (Join-Path $Root 'test\Salvage-SetupapiLog.ps1') -Mount $Mount 2>&1 | ForEach-Object { "$_" }) |
        ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
      & $DismExe /Unmount-Wim /MountDir:$Mount /Discard | Out-Null
      Write-Host 'boot.wim 保持原样, 未生成 ISO' -ForegroundColor Red
      exit 1
    }
    Write-Host '[3/4] 卸载并提交 ...' -ForegroundColor Cyan
    & $DismExe /Unmount-Wim /MountDir:$Mount /Commit
    if ($LASTEXITCODE -ne 0) { Write-Host '卸载失败(有进程占用 mount 目录)' -ForegroundColor Red; exit 1 }
  } else {
    # 注入中途出错就不要把半截状态提交进 boot.wim
    Write-Host '[3/4] 注入失败, 丢弃挂载点改动 ...' -ForegroundColor Yellow
    @(& (Join-Path $Root 'test\Salvage-SetupapiLog.ps1') -Mount $Mount 2>&1 | ForEach-Object { "$_" }) |
      ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor DarkGray }
    & $DismExe /Unmount-Wim /MountDir:$Mount /Discard | Out-Null
    Write-Host 'boot.wim 保持原样, 未生成 ISO' -ForegroundColor Red
    exit 1
  }
}

Write-Host '[4/4] 生成 ISO ...' -ForegroundColor Cyan
# 虚拟机会独占它正在启动的 ISO(删不掉也覆盖不了), 由 iso_target.ps1 换成写得进去的名字,
# 否则注入已经提交进 boot.wim 却在最后一步白跑
$OutIso = & (Join-Path $Root 'test\iso_target.ps1') -Base $OutIso | Select-Object -Last 1
if (-not $OutIso) { Write-Host '目标 ISO 被占用且无法改名' -ForegroundColor Red; exit 1 }
# 目录不存在的话 oscdimg 只会给一句 Error 3, 而那时注入已经提交进 boot.wim 了 —— 提前判, 别把 3 分钟的活变成
# 一个看不懂的失败(2026-10-10 22:30 的 oscdimg Error 3 就是这个形状, 只是原因是相对路径)
$IsoDir = Split-Path -Parent $OutIso
if (-not (Test-Path $IsoDir)) {
  Write-Host ('  ISO 目录不存在: ' + $IsoDir) -ForegroundColor Red
  Write-Host ('  给一个写得进去的名字, 例如: ' + (Join-Path $Dist ('WinPE_Desktop_v8_' + (Get-Date -Format 'MMdd-HHmmss') + '.iso'))) -ForegroundColor Yellow
  exit 1
}
if (Test-Path $OutIso) { Remove-Item $OutIso -Force }
$EfiBin = if (Test-Path "$Oscdimg\efisys_noprompt.bin") { 'efisys_noprompt.bin' } else { 'efisys.bin' }
# oscdimg 的 bootdata 串里带空格路径会解析失败(出来的 ISO 无引导记录), 所以切到 Oscdimg 目录用相对文件名
Push-Location $Oscdimg
try {
  & "$Oscdimg\oscdimg.exe" -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,b' + $EfiBin) "$Media\media" $OutIso
  $rc = $LASTEXITCODE
} finally { Pop-Location }
if ($rc -ne 0 -or -not (Test-Path $OutIso)) {
  Write-Host 'oscdimg 失败' -ForegroundColor Red
  # 注入在第 [3/4] 步已经 /Commit 进 boot.wim 了, 出盘失败不该把 3 分钟的活一起作废: 直接用 pack_iso 只打包
  Write-Host ('  boot.wim 已提交, 不必重跑注入 —— 只打包 ISO 请运行:') -ForegroundColor Yellow
  Write-Host ('    powershell -NoProfile -ExecutionPolicy Bypass -File "{0}" -Tag {1}' -f `
              (Join-Path $Root 'test\pack_iso.ps1'), (Get-Date -Format 'MMdd-HHmmss')) -ForegroundColor Yellow
  exit 1
}

# El Torito 校验: 前 64 扇区找卷描述符(偏移7起为标识串), 偏移71 = 引导目录 LBA;
# 引导目录内逐 32 字节槽找 bootInfo=0x88 且引导记录 LBA 合法的条目(oscdimg 不写 0x55AA)
$etLba = -1; $catLba = -1; $bootEntries = 0; $sectorLen = 2048
$fs = [IO.File]::OpenRead($OutIso)
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
  Write-Host ('ISO 引导记录异常: ET-VD LBA={0} catalog LBA={1} 可引导项={2}' -f $etLba, $catLba, $bootEntries) -ForegroundColor Red
  exit 1
}
Write-Host ('  El Torito 校验通过 (引导目录 LBA {0}, 可引导项 {1} 个, EFI 加载器 {2})' -f $catLba, $bootEntries, $EfiBin)
Write-Host ('完成! 产物: ' + $OutIso + '  大小: {0:N1} MB' -f ((Get-Item $OutIso).Length / 1MB)) -ForegroundColor Green
