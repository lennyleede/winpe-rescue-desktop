param([string]$DrvDir = '', [switch]$Apply)
# ============================================================
# 29b_FixInfDirNames.ps1 —— 把"目录名里带 .inf_"的导入包目录改名为 "_inf_"
#
#   为什么要改: 20_ 从宿主机 DriverStore 导入时, 目录名保留了 FileRepository 的写法
#   (net1ic64.inf_amd64_5f033e...), 这个长名的 8.3 短名会被切成 LAN_IM~1.INF —— 扩展名正好是 .INF。
#   而 Get-ChildItem -Filter '*.inf' 是走短名匹配的, 于是这些**目录**被当成 INF 捞进每一次扫描:
#   16_ 的 SelfTest 报"驱动 INF 162 个"(真数 139), 15_/16_/18_/17_ 的计数全部虚高 23 个。
#   轻则统计不准, 重则 DISM 枚举时对着一堆"看起来像 inf"的目录做无谓判断。改成 _inf_ 之后短名不再带 .INF。
#
#   默认只列计划; 加 -Apply 才改名(只动 overlay, 不动镜像/不删文件)。
# ============================================================
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $DrvDir) { $DrvDir = Join-Path $Root 'overlay\Drivers\Net' }
if (-not (Test-Path $DrvDir)) { Write-Host "目录不存在: $DrvDir" -ForegroundColor Red; exit 1 }

$bad = @(Get-ChildItem $DrvDir -Directory -Recurse | Where-Object { $_.Name -match '\.inf_' })
Write-Host ('驱动目录: ' + $DrvDir)
Write-Host ('名字里带 ".inf_" 的目录: ' + $bad.Count + ' 个')
$n = 0
foreach ($d in ($bad | Sort-Object FullName)) {
  $new = $d.Name -replace '\.inf_', '_inf_'
  Write-Host ('  ' + $d.Name)
  Write-Host ('    -> ' + $new)
  if ($Apply) {
    if (Test-Path (Join-Path $d.Parent.FullName $new)) { Write-Host '    !! 目标名已存在, 跳过' -ForegroundColor Yellow; continue }
    Rename-Item -LiteralPath $d.FullName -NewName $new
    $n++
  }
}
# 顺手验证: 改名后还应该有 0 个"目录"被 -Filter '*.inf' 捞到
$stillDirs = @(Get-ChildItem $DrvDir -Recurse -Filter '*.inf' | Where-Object { $_.PSIsContainer })
Write-Host ('  复查: 被 -Filter *.inf 捞到的目录还剩 ' + $stillDirs.Count + ' 个(应为 0)')
if ($Apply) { Write-Host ('  已改名 ' + $n + ' 个目录') -ForegroundColor Green }
else { Write-Host '  这是计划, 没动盘。加 -Apply 执行' -ForegroundColor Yellow }
