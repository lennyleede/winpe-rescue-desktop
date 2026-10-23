# ============================================================
# test\Update-WlanTag.ps1 —— 把 X:\BUILD_TAG.txt 的 wlandrv 行换成本次注入的证据, 并盖 wifi_patch 时间戳
#
#   为什么单独成文件: 这段"改文本标记"的逻辑以前抄在 patch_wifi.ps1 里, 而 patch_wifi 需要管理员才能跑到
#   (它挂载 boot.wim)。等于没人验过它就交给用户执行。抽出来之后 test\36_RunGates.ps1 可以用临时目录
#   在普通权限下把三种输入都过一遍: 有 wlandrv 行 / 没有 wlandrv 行 / BUILD_TAG 压根不存在。
#
#   只动 wlandrv / wifi_patch 两行, 外加(仅当调用方给了 -Netdrvfix 时)tools 行里的 netdrvfix/x.y 这一个词:
#   netdrv/stodrv 那两行是上一次完整构建留下的证据, 快速通道不配改动它们,
#   但必须让现场看得见"WiFi 这半条腿是这次补的"(10-06 因为烧错 ISO 白绕一轮, 靠的就是这行自证)。
#   tools 行为什么也要跟着改(2026-10-12): 14:25 那张盘的 BUILD_TAG 写着 `tools = niccheck / netdrvfix/3.0`,
#   而那时 overlay 里已经是 3.2 了 —— 因为那行是 test\16_InjectNetDrivers.ps1(完整构建)写的, 快速通道 patch_wifi
#   不碰它。现场读 X:\status.txt 里 netdrvfix 的开机行为判据(wdihost= 那一段)就是那个旧文件留下的缺陷,
#   但标记说的是 3.0 => "盘里到底是哪个脚本"当场不可知。现在只替换版本号这一个词, 后面那句解释原样保留。
#
#   用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\Update-WlanTag.ps1 -TagFile <path> -Evidence 'cat=1 ...'
#         [-Netdrvfix <overlay\Scripts\netdrvfix.ps1 的路径>]   # 给了才会同步 tools 行的版本号
#   退出码: 0 = 已写好; 1 = 写失败(调用方自己决定要不要继续出盘)
# ============================================================
param(
  [Parameter(Mandatory = $true)][string]$TagFile,
  [Parameter(Mandatory = $true)][string]$Evidence,
  [string]$PatchMarker = 'patch_wifi.ps1',
  [string]$Netdrvfix = ''
)
$ErrorActionPreference = 'Stop'
try {
  $ev = ($Evidence -replace '\s+', ' ').Trim()
  if ($ev -match '^VERDICT wlan:\s*') { $ev = ($ev -replace '^VERDICT wlan:\s*', '') }
  if (-not $ev) { $ev = 'flags=NO_VERDICT_LINE (wifi-inject 没跑到收尾)' }

  # 与 test\16_InjectNetDrivers.ps1 同一个取法: 只认 overlay 脚本头部那行 netdrvfix/x.y
  $toolsVer = ''
  if ($Netdrvfix -and (Test-Path -LiteralPath $Netdrvfix)) {
    $m9 = [regex]::Match((Get-Content $Netdrvfix -Raw -EA SilentlyContinue), 'netdrvfix/\d+\.\d+')
    if ($m9.Success) { $toolsVer = $m9.Value }
  }

  $lines = @()
  if (Test-Path -LiteralPath $TagFile) { $lines = @(Get-Content -LiteralPath $TagFile -EA SilentlyContinue) }
  if ($lines.Count -eq 0) { $lines = @('product = WinPE_Desktop_v8') }
  $now = ('{0} ({1})' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PatchMarker)

  $ins = @()
  $doneTag = $false; $donePat = $false; $doneTools = $false
  foreach ($l0 in @($lines | Where-Object { $_ -notmatch '^(wlandrv|wifi_patch)\s*=' })) {
    $l = $l0
    # 只改"已经有版本号"的 tools 行; 没有这个词的(旧格式/门禁 fixture)一律原样保留, 不凭空造。
    if ($toolsVer -and ($l -match '^tools\s*=') -and ($l -match 'netdrvfix/\d+\.\d+')) {
      $l = ($l -replace 'netdrvfix/\d+\.\d+', $toolsVer)
      $doneTools = $true
    }
    $ins += $l
    if (-not $donePat -and $l -match '^build\s*=') { $ins += ('wifi_patch = ' + $now); $donePat = $true }
    if (-not $doneTag -and $l -match '^stodrv\s*=') { $ins += ('wlandrv = ' + $ev); $doneTag = $true }
  }
  if (-not $donePat) { $ins += ('wifi_patch = ' + $now) }
  if (-not $doneTag) { $ins += ('wlandrv = ' + $ev) }

  # 挂载点里的文件常带只读属性(PE 镜像解出来的东西), 不清掉 Set-Content 会直接拒写
  $ti = Get-Item -LiteralPath $TagFile -Force -EA SilentlyContinue
  if ($ti -and ($ti.Attributes -band [IO.FileAttributes]::ReadOnly)) { $ti.Attributes = 'Normal' }
  Set-Content -LiteralPath $TagFile -Value ($ins -join "`r`n") -Encoding ASCII

  $back = @(Get-Content -LiteralPath $TagFile -EA SilentlyContinue)
  $okTag = (@($back | Where-Object { $_ -match '^wlandrv = ' }).Count -eq 1)
  $okPat = (@($back | Where-Object { $_ -match '^wifi_patch = ' }).Count -eq 1)
  Write-Output ('TAG wlandrv = ' + $ev)
  # tools 行的同步结果必须打出来: 现场/niccheck 判据读的是这行, 而它只在给了 -Netdrvfix 且那行本来就有版本号时才动。
  $tl = (@($back | Where-Object { $_ -match '^tools\s*=' }) | Select-Object -First 1)
  Write-Output ('TAG tools   = ' + $(if ($tl) { (($tl -replace '\s+', ' ').Trim()) } else { '<none>' }) +
    ' sync=' + $(if ($toolsVer) { 'asked=' + $toolsVer + ' done=' + [int]$doneTools } else { 'off' }))
  Write-Output ('TAG lines   = ' + $back.Count + ' / wlandrv=' + [int]$okTag + ' wifi_patch=' + [int]$okPat)
  if (-not ($okTag -and $okPat)) { Write-Output 'TAG UPDATE = BAD'; exit 1 }
  Write-Output 'TAG UPDATE = OK'
  exit 0
} catch {
  Write-Output ('TAG UPDATE = THREW ' + $_.Exception.Message)
  exit 1
}
