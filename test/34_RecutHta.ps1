# ============================================================
# 34_RecutHta.ps1 —— 只换镜像里的 Desktop.hta 并重新出盘(不重跑 40 分钟的 build10)
#   背景: frp 面板"打字没反应"的根因已定案 —— PE 里 docMode>=9 的 mshta 页面拿不到输入框
#         焦点(实测 test\pe10_focusprobe.ps1: IE7/IE8 能打字, IE9/IE10/edge 全废, 与 ctfmon 无关)。
#         Desktop.hta 已改成 IE=8 文档模式 + IE8 能解析的 CSS, 现在要把它塞回成品镜像。
#   前提: build10 的成果还在 D:\pe10_work 里(media\sources\boot.wim 已提交, index 1)。
#   需要管理员:
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\34_RecutHta.ps1
#   先看一眼不干活(普通权限可跑):
#     同上 -DryRun
# ============================================================
param(
  [string]$Work    = 'D:\pe10_work',
  [string]$Product = 'WinPE10_Desktop_v1',
  [int]$Index      = 1,
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$Root    = Split-Path $PSScriptRoot -Parent
$Build   = Join-Path $Root 'build10'
$Dist    = Join-Path $Root 'dist'
$BootBin = Join-Path $Build 'bootbin'
$ADK     = 'C:\Program Files (x86)\Windows Kits\10'
$DismExe = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe"
$Oscdimg = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
$Mount   = Join-Path $Work 'mount'
$Media   = Join-Path $Work 'media'
$Wim     = Join-Path $Media 'sources\boot.wim'
$Hta     = Join-Path $Root 'overlay\Desktop\Desktop.hta'
$LogPath = Join-Path $Build ('recut_' + (Get-Date -Format 'MMdd-HHmmss') + '.log')
$rows    = New-Object System.Collections.ArrayList

function Say($m) {
  Write-Host $m
  [void]$rows.Add([string]$m)
  try { Add-Content -LiteralPath $LogPath -Value ((Get-Date -Format 'HH:mm:ss ') + $m) -Encoding UTF8 -ErrorAction Stop } catch { }
}
function Flush-Rows {
  try { Set-Content -LiteralPath (Join-Path $Build 'recut_result.txt') -Value ($rows -join "`r`n") -Encoding UTF8 } catch { }
}
function Dism($argList, $label) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $DismExe @argList 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  Say ($label + ' rc=' + $rc)
  ($o | Where-Object { "$_" -match '错误|Error|成功|complete|warning' } | Select-Object -Last 5) | ForEach-Object { Say ('    ' + $_) }
  return $rc
}

New-Item -ItemType Directory -Force -Path $Build | Out-Null
Say ('===== 只换 Desktop.hta 重出盘 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' DryRun=' + $DryRun + ' =====')

foreach ($p in @($DismExe, $Oscdimg, $Wim, $Hta, (Join-Path $BootBin 'efisys_noprompt.bin'), (Join-Path $BootBin 'etfsboot.com'))) {
  if (-not (Test-Path $p)) { Say ('缺少: ' + $p); Flush-Rows; exit 1 }
}
$srcTxt = [IO.File]::ReadAllText($Hta, [Text.Encoding]::UTF8)
$metaLine = (@($srcTxt -split "`r?`n") | Where-Object { $_ -match 'x-ua-compatible' } | Select-Object -First 1)
Say ('待注入的 Desktop.hta = ' + (Get-Item $Hta).Length + ' B')
Say ('  meta: ' + $metaLine.Trim())
if ($metaLine -notmatch 'IE=8' -or $srcTxt -notmatch 'v10-ie8') {
  Say 'ERROR: overlay 里这份 Desktop.hta 不是 IE8 版, 先确认改动'; Flush-Rows; exit 1
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ('isAdmin = ' + $IsAdmin)
if (-not $IsAdmin) { Say 'ERROR: 挂载/提交/出盘需要管理员 PowerShell'; Flush-Rows; exit 1 }
if ($DryRun) { Say 'DryRun: 检查通过, 没有动任何镜像'; Flush-Rows; exit 0 }

# ---------- 1. 清掉残留挂载记录, 再读写挂载 ----------
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$mounted = & $DismExe '/Get-MountedWimInfo' 2>&1
if (("$mounted" -match [regex]::Escape($Mount))) {
  Say '挂载点上有残留记录, 先 /Unmount-Wim /Discard'
  [void](Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '  丢弃残留挂载')
}
$ErrorActionPreference = $prev
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
$rc = Dism @('/Mount-Wim', ('/WimFile:' + $Wim), ('/Index:' + $Index), ('/MountDir:' + $Mount)) 'Mount-Wim(读写)'
if ($rc -ne 0) { Say 'ERROR: 挂载失败, 见上面 DISM 输出'; Flush-Rows; exit 1 }

$marker = Join-Path $Mount 'BUILD_TAG.txt'
if (-not (Test-Path $marker)) {
  Say '!! 挂载点里没有 BUILD_TAG.txt —— 这不是 build10 的成品镜像, 已停手(未提交)'
  [void](Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '  丢弃挂载')
  Flush-Rows; exit 1
}
Say ('挂载点原标记: ' + ((Get-Content $marker -Encoding ASCII) -join ' / '))

# ---------- 2. 换文件 + 更新镜像内标记 ----------
$dst = Join-Path $Mount 'Desktop\Desktop.hta'
if (-not (Test-Path (Split-Path $dst -Parent))) {
  Say ('!! 镜像里没有 ' + (Split-Path $dst -Parent) + ', 已停手(未提交)')
  [void](Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '  丢弃挂载')
  Flush-Rows; exit 1
}
Copy-Item -LiteralPath $Hta -Destination $dst -Force
$dstTxt = [IO.File]::ReadAllText($dst, [Text.Encoding]::UTF8)
Say ('  写入 ' + $dst + ' = ' + (Get-Item $dst).Length + ' B, IE=8 meta=' + ($dstTxt -match 'content="IE=8"') + ', 版本标记=' + ($dstTxt -match 'v10-ie8'))
if ((Get-Item $dst).Length -ne (Get-Item $Hta).Length) {
  Say '!! 落盘字节数与源文件不一致, 已停手(未提交)'
  [void](Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Discard') '  丢弃挂载')
  Flush-Rows; exit 1
}
try {
  $t = @(Get-Content -LiteralPath $marker -Encoding ASCII) | ForEach-Object {
    if ($_ -match '^hta\s*=') { 'hta     = panel v10-ie8 (recut ' + (Get-Date -Format 'yyyy-MM-dd HH:mm') + ')' } else { $_ }
  }
  Set-Content -LiteralPath $marker -Value ($t -join "`r`n") -Encoding ASCII -NoNewline
  Say '  BUILD_TAG.txt 的 hta 行已更新(纯 ASCII)'
} catch { Say ('  (BUILD_TAG 更新跳过: ' + $_.Exception.Message + ')') }

# ---------- 3. 提交 ----------
foreach ($hk in @('PE10_SYS', 'PE_FW', 'PE_SYS', 'PE_SYS2')) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & reg.exe query ('HKLM\' + $hk) 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) { [void](reg.exe unload ('HKLM\' + $hk) 2>&1); Say ('  残留配置单元 HKLM\' + $hk + ' 已卸载') }
  $ErrorActionPreference = $prev
}
$wimBefore = (Get-Item $Wim).Length
$rc = Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Commit') 'Unmount-Wim /Commit'
if ($rc -ne 0) {
  Say '  5 秒后重试一次(常见原因是文件被占用)'
  Start-Sleep -Seconds 5
  $rc = Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Commit') '重试 Unmount-Wim /Commit'
  if ($rc -ne 0) { Say 'ERROR: 提交失败, 镜像未改动'; Flush-Rows; exit 1 }
}
Say ('boot.wim ' + ('{0:N0}' -f $wimBefore) + ' -> ' + ('{0:N0}' -f (Get-Item $Wim).Length) + ' B')

# ---------- 4. 出 ISO ----------
$Iso = & (Join-Path $Root 'test\iso_target.ps1') -Base (Join-Path $Dist ($Product + '.iso')) | Select-Object -Last 1
if (-not $Iso) { Say 'ERROR: 目标 ISO 名字拿不到'; Flush-Rows; exit 1 }
if (Test-Path $Iso) { Remove-Item $Iso -Force }
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
Push-Location $BootBin
& $Oscdimg -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,befisys_noprompt.bin') $Media $Iso 2>&1 | Select-Object -Last 4 | ForEach-Object { Say ('  oscdimg: ' + $_) }
$rc = $LASTEXITCODE
Pop-Location
$ErrorActionPreference = $prev
Say ('oscdimg rc=' + $rc)
if ($rc -ne 0 -or -not (Test-Path $Iso)) { Say 'ERROR: oscdimg 失败'; Flush-Rows; exit 1 }
Say ('完成! 产物: ' + $Iso + ' (' + ('{0:N1} MB' -f ((Get-Item $Iso).Length / 1MB)) + ')')
Say '下一步(普通权限即可, 会自动建 VM 开机并跑面板自测):'
Say ('  powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'test\30_BootAndVerifyWinPe10.ps1') + '" -Iso "' + $Iso + '"')
Say ('  然后: powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'test\33_HtaTypingDebug.ps1') + '" -Phase ie8')
Flush-Rows
