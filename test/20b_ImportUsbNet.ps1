# ============================================================
# 20b_ImportUsbNet.ps1 —— 把宿主机 DriverStore 里"USB 转网线"的包补进 overlay\Drivers\Net
#
#   为什么需要它(2026-10-08): 20_ 的入选口径是"必须带来现索引里没有的 **PCI** 硬件ID",
#   于是宿主机 DriverStore 里几个只有 USB\VID 的有线网卡包被整体漏掉了 —— 而 USB 转网线恰恰是
#   板载卡在 PE 里起不来时的保底通道(任务 #11「USB 保底联网」)。verify_netdrv 新加的 USB 口径
#   把缺口照出来了: AX88179/178A(0B95:1790/178A, 市面上最常见的 USB3 千兆转接)、
#   SMSC/Genesys LAN95xx/LAN78xx(0424:9500/9505/9530/9730/7800/780A)、微软 usbnet(045E Surface 扩展坞)。
#   池子里已经有的 RTL8152/8153/8156(rtump64x64/rtux64w10)、ax88178/ax88772/ax88772b、net7500 不重复导。
#
#   只做拷贝, 不改任何既有目录; 拷完请重新跑 test\17_MakeNetDrvIndex.ps1 与 test\verify_netdrv.ps1。
#   无线(802.11/WWAN)一律不收: WiFi 阶段再单独处理。
#
# 跑法(普通权限):
#   预览: powershell -NoProfile -ExecutionPolicy Bypass -File test\20b_ImportUsbNet.ps1
#   执行: ... -Apply
#   自检: ... -SelfTest     (只看宿主机有没有这些包, 不写文件)
# ============================================================
param(
  [string[]]$InfNames = @('netax88179_178a.inf', 'net9500-x64-n650f.inf', 'net7800-x64-n650f.inf', 'usbnet.inf'),
  [string]$DsPath     = '',
  [string]$OverlayDir = '',
  [string]$Out        = '',
  [int]$MaxKB         = 8192,        # 单个包超过 8MB 的一定是 WiFi/多功能大包, 不收
  [switch]$Apply,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $DsPath)     { $DsPath     = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository' }
if (-not $OverlayDir) { $OverlayDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not $Out)        { $Out        = Join-Path $Root 'build\import_usbb_net.txt' }
. (Join-Path $PSScriptRoot 'NetDrvLib.ps1')
if (-not (Test-Path $DsPath)) { Write-Host ('  !! 宿主机驱动库不存在: ' + $DsPath) -ForegroundColor Red; exit 1 }

# 现池子里已有的 inf 名(小写), 同名就不导
$have = @{}
Get-ChildItem $OverlayDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue | ForEach-Object { $have[$_.Name.ToLower()] = $_.Directory.Name }

$rows = @()
$allDirs = @(Get-ChildItem $DsPath -Directory -EA SilentlyContinue)
foreach ($name in $InfNames) {
  $base = ($name -replace '\.inf$', '')
  $dirs = @($allDirs | Where-Object { $_.Name.ToLower().StartsWith($base.ToLower() + '.inf_') } | Sort-Object Name)
  if ($dirs.Count -eq 0) { $dirs = @($allDirs | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $name) } | Sort-Object Name) }
  if ($dirs.Count -eq 0) { $rows += [pscustomobject]@{ Inf = $name; Dst = '-'; KB = 0; Act = '宿主机没有这个包'; Ids = 0; Class = ''; SrcPath = '' }; continue }
  $src = $dirs[-1]
  $kb  = [math]::Round(((Get-ChildItem -LiteralPath $src.FullName -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum) / 1KB, 0)
  if ($kb -gt $MaxKB) { $rows += [pscustomobject]@{ Inf = $name; Dst = '-'; KB = $kb; Act = '太大(' + $kb + 'KB), 疑似多功能包, 跳过'; Ids = 0; Class = ''; SrcPath = '' }; continue }
  $infPath = Join-Path $src.FullName $name
  if (-not (Test-Path $infPath)) {
    # 目录里 inf 可能同名也可能大小写不同, 兜底找同名文件
    $alt = @(Get-ChildItem -LiteralPath $src.FullName -File -Filter '*.inf' -EA SilentlyContinue | Where-Object { $_.Name.ToLower() -eq $name.ToLower() })
    if ($alt.Count -eq 0) { $rows += [pscustomobject]@{ Inf = $name; Dst = '-'; KB = $kb; Act = '目录里找不到同名 inf'; Ids = 0; Class = ''; SrcPath = '' }; continue }
    $infPath = $alt[0].FullName
  }
  $txt = Get-InfText $infPath
  $cls = ''
  $secs = Parse-Sections $txt
  if ($secs.ContainsKey('Version')) { foreach ($l in $secs['Version']) { if ($l -match '^Class\s*=\s*(.+)$') { $cls = $Matches[1].Trim().Trim('"', '%').Trim() } } }
  $isWifi = ($txt -match '(?i)Wireless|Wi-Fi|\b802\.11\b|WLAN|Bluetooth|Mobile Broadband|WWAN|Virtual\s?NIC')
  $vids = @([regex]::Matches($txt, 'USB\\VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}') | ForEach-Object { $_.Value.ToUpper() } | Sort-Object -Unique)
  $dstName = 'Lan_Imp_HostUsb_' + ($base -replace '[^\w.\-]', '_')
  $act = '要拷 -> ' + $dstName
  if ($cls -ne 'Net') { $act = 'Class=' + $cls + '(不是 Net), 跳过' }
  elseif ($isWifi)    { $act = '看着是无线包, 跳过(WiFi 阶段再收)' }
  elseif ($have.ContainsKey($name.ToLower())) { $act = '池子里已有 ' + $have[$name.ToLower()] + ', 跳过' }
  elseif ($vids.Count -eq 0) { $act = '没有 USB\VID, 不值得导' }
  $rows += [pscustomobject]@{ Inf = $name; Dst = $dstName; KB = $kb; Act = $act; Ids = $vids.Count; Class = $cls; SrcPath = $src.FullName }
}

Write-Host ('==== 宿主机 USB 转网线补包 (' + $DsPath + ') ====') -ForegroundColor Cyan
foreach ($r in $rows) {
  Write-Host ('  ' + $r.Inf.PadRight(26) + (' ' + $r.KB + 'KB').PadLeft(10) + (' usbID=' + $r.Ids).PadLeft(9) + '  ' + $r.Act)
}
$todo = @($rows | Where-Object { $_.Act -like '要拷*' })
Write-Host ('  合计可补 ' + $todo.Count + ' 个包 / ' + (($todo | Measure-Object -Property KB -Sum).Sum) + ' KB')

if ($SelfTest) { Write-Host '  -SelfTest: 没写文件'; exit 0 }
if (-not $Apply) { Write-Host '  这是预览。要真拷请加 -Apply' -ForegroundColor Yellow; exit 0 }
if ($todo.Count -eq 0) { Write-Host '  没有要拷的包, 什么都没动' -ForegroundColor Yellow; exit 0 }

$log = @()
foreach ($r in $todo) {
  $dst = Join-Path $OverlayDir $r.Dst
  if (Test-Path $dst) { Write-Host ('  !! 目标已存在, 跳过: ' + $dst) -ForegroundColor Yellow; continue }
  Copy-Item -LiteralPath $r.SrcPath -Destination $dst -Recurse -Force
  $n = @(Get-ChildItem $dst -File -EA SilentlyContinue).Count
  Write-Host ('  已拷 ' + $r.Dst + ' (' + $n + ' 个文件)') -ForegroundColor Green
  $log += ('COPIED ' + $r.Inf + ' <- ' + $r.SrcPath + ' -> ' + $dst)
}
$log += ('TIME ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$log += 'NEXT: 1) powershell -NoProfile -ExecutionPolicy Bypass -File test\17_MakeNetDrvIndex.ps1'
$log += 'NEXT: 2) powershell -NoProfile -ExecutionPolicy Bypass -File test\verify_netdrv.ps1'
$log += 'NEXT: 3) 管理员跑 test\16_InjectNetDrivers.ps1 出盘'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Set-Content -LiteralPath $Out -Value $log -Encoding UTF8
Write-Host ('  清单已写: ' + $Out)
