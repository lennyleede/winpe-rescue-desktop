# ============================================================
# test\WlanEvidenceFlags.ps1 —— 把 wifi-inject 的证据文本(可能多行)判成"这次能不能出盘"的一个开关
#
#   为什么要单独成文件: 2026-10-10 之前 patch_wifi.ps1 里判的是
#       $ev -match 'flags=none'
#   在**单行**证据上没问题, 但 wifi-inject 现在往 build\scratch\wlan_verify.txt 写两行
#   (第一行 VERDICT wlan: 文件/.cat/DriverStore, 第二行 VERDICT svc-shape: 服务键形状)。
#   "-match" 是对整段文本的"存在即真": 只要第一行绿, 第二行红(W_TYPE,C_OBJ...)照样报"WiFi 判据齐",
#   烧出来的盘开机就是 1068/1069/服务自己停 —— 正是这次要防的那类缺陷。
#   所以判据改成"每一条 VERDICT 行都必须 flags=none, 且必须有 svc-shape 行(缺行=旧证据, 不算绿)"。
#
#   这段逻辑只有 patch_wifi 会跑到, 而 patch_wifi 要挂载 boot.wim = 管理员; 抽出来之后
#   test\36_RunGates.ps1 能在普通权限下把 5 种输入都过一遍: 两行全绿 / 形状行红 / 只有旧的单行(缺形状行)
#   / 空文本 / 文件行红。除第一种外必须全部 ok=0。
#
#   用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\WlanEvidenceFlags.ps1 -Evidence (Get-Content <file> -Raw)
#   退出码: 0 = ok=1; 1 = 有红或缺行
#   输出: EVIDENCE FLAGS ok=<0|1> lines=<n> shape=<yes|no> bad=<逗号列表|none>   (刻意全 ASCII, 走管道)
#
#   AllowEmptyString 是必须的: patch_wifi 里 $ev 在"wifi-inject 没跑到收尾 / wlan_verify.txt 被删"时就是空串,
#   Mandatory 单独用会让 PowerShell 抛"缺参数", 调用方只能看见异常而看不见结论 —— 空证据必须判成红(NO_VERDICT_LINE)。
# ============================================================
param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Evidence)
$ErrorActionPreference = 'Stop'
$ev = ($Evidence -replace "`r", ' ' -replace "`n", ' ' -replace '\s+', ' ').Trim()
$bad = @()
$segs = @()
if ($ev) { $segs = @([regex]::Split($ev, '(?=VERDICT\s)') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($segs.Count -eq 0) { $bad += 'NO_VERDICT_LINE' }
$shapeSeen = $false
foreach ($sg in $segs) {
  $lbl = 'wlan'
  if ($sg -match '^VERDICT\s+([A-Za-z0-9_-]+)') { $lbl = $matches[1] }
  if ($lbl -like '*svc-shape*') { $shapeSeen = $true }
  $mm = [regex]::Match($sg, 'flags=([A-Za-z0-9_~,]*)')
  if (-not $mm.Success) { $bad += ($lbl + ':NO_FLAGS'); continue }
  $fl = $mm.Groups[1].Value
  if ($fl -ne 'none') { $bad += ($lbl + ':' + $fl) }
}
if (-not $shapeSeen) { $bad += 'NO_SHAPE_LINE' }
$ok = (@($bad).Count -eq 0)
$tail = 'EVIDENCE FLAGS ok=' + $(if ($ok) { 1 } else { 0 }) + ' lines=' + $segs.Count +
        ' shape=' + $(if ($shapeSeen) { 'yes' } else { 'no' }) +
        ' bad=' + $(if ($ok) { 'none' } else { ($bad -join ',') })
Write-Output $tail
if ($ok) { exit 0 } else { exit 1 }
