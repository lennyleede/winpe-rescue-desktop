# ============================================================
# pack_iso.ps1 —— 只打包 ISO(oscdimg + El Torito 引导校验), 不重新挂载/注入。
# 适用场景: boot.wim 已经注入完成, 但 ISO 步骤失败, 或目标 ISO 正被 Hyper-V 虚拟机
# 光驱占用(占用时无法删除也无法覆盖 —— 这时换个新文件名就能立刻出盘)。
# 普通权限即可运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\pack_iso.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\pack_iso.ps1 -Tag v7b
# ============================================================
param(
  [string]$Tag = '',          # 追加到文件名后缀, 默认自动按时间生成
  [switch]$Force              # 允许覆盖已存在且未被占用的同名 ISO
)
$ErrorActionPreference = 'Stop'
$Root    = Split-Path -Parent $PSScriptRoot
$Media   = Join-Path $Root 'build\WinPE_amd64'
$Src     = Join-Path $Media 'media'
$Dist    = Join-Path $Root 'dist'
$Wim     = Join-Path $Src 'sources\boot.wim'
$Oscdimg = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg'

if (-not (Test-Path $Wim)) { Write-Host "没有 $Wim, 请先跑 build.ps1 或 patch_wifi.ps1" -ForegroundColor Red; exit 1 }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

function Test-FileFree([string]$p) {
  if (-not (Test-Path $p)) { return $true }
  try { $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None'); $fs.Close(); return $true }
  catch { return $false }
}

# 目标文件名: 优先 WinPE_Desktop_v8[.Tag].iso; 被占用就换带时间戳的新名字
$base = 'WinPE_Desktop_v8'
if ($Tag) { $base = $base + '_' + $Tag }
$target = Join-Path $Dist ($base + '.iso')
if (-not (Test-FileFree $target)) {
  $stamp = Get-Date -Format 'MMdd-HHmmss'
  $target = Join-Path $Dist ($base + '_' + $stamp + '.iso')
  Write-Host '  注意: 默认目标 ISO 正被别的进程(通常是运行中的虚拟机光驱)占用, 本次改用带时间戳的新文件名' -ForegroundColor Yellow
  if (-not (Test-FileFree $target)) { Write-Host "新文件名也被占用: $target" -ForegroundColor Red; exit 1 }
} elseif ((Test-Path $target) -and -not $Force) {
  Write-Host ('  目标已存在且会被覆盖: ' + $target + '  (想保留旧文件请加 -Tag xxx)') -ForegroundColor Yellow
}

# boot.wim 比现有 ISO 新 => 那个 ISO 是旧的, 提醒一句
$existing = Get-ChildItem $Dist -Filter '*.iso' | Sort-Object LastWriteTime | Select-Object -Last 1
if ($existing -and $existing.LastWriteTime -lt (Get-Item $Wim).LastWriteTime) {
  $msg = '  提示: 目前最新的 ISO {0} ({1}) 比 boot.wim ({2}) 旧, 旧 ISO 不含最后一次注入, 本次打包才有' -f `
    $existing.Name, $existing.LastWriteTime, (Get-Item $Wim).LastWriteTime
  Write-Host $msg -ForegroundColor Yellow
}

$EfiBin = if (Test-Path "$Oscdimg\efisys_noprompt.bin") { 'efisys_noprompt.bin' } else { 'efisys.bin' }
Write-Host ('[1/2] oscdimg 打包 -> ' + $target) -ForegroundColor Cyan
# bootdata 串里带空格路径会让 oscdimg 解析失败, 所以切到 Oscdimg 目录用相对文件名
Push-Location $Oscdimg
try {
  & "$Oscdimg\oscdimg.exe" -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,b' + $EfiBin) $Src $target
  $rc = $LASTEXITCODE
} finally { Pop-Location }
if ($rc -ne 0 -or -not (Test-Path $target)) { Write-Host "oscdimg 失败 (rc=$rc)" -ForegroundColor Red; exit 1 }
Write-Host ('  已生成 {0}  大小 {1:N1} MB' -f (Split-Path $target -Leaf), ((Get-Item $target).Length/1MB)) -ForegroundColor Green

Write-Host '[2/2] El Torito 引导校验 ...' -ForegroundColor Cyan
& (Join-Path $Root 'test\check_isoboot.ps1') -Iso $target
Write-Host ('下一步(管理员, 需要关机/换盘): powershell -NoProfile -ExecutionPolicy Bypass -File "{0}" -SkipBuild' -f (Join-Path $Root 'test\10_RebuildAndSwap.ps1'))
