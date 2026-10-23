# 诊断 dist 里 ISO 的占用情况 + boot.wim 是否比最新 ISO 更新(说明 ISO 是旧的需重打包)
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root 'dist'
$Wim  = Join-Path $Root 'build\WinPE_amd64\media\sources\boot.wim'

Write-Host '--- boot.wim ---'
if (Test-Path $Wim) { Get-Item $Wim | ForEach-Object { Write-Host ('{0:N1} MB  {1}' -f ($_.Length/1MB), $_.LastWriteTime) } }
else { Write-Host "不存在: $Wim" }

Write-Host '--- dist ISO (按时间) ---'
$isos = Get-ChildItem $Dist -Filter '*.iso' | Sort-Object LastWriteTime
foreach ($i in $isos) {
  $w = '可独占打开(未被占用)'
  try { $fs = [IO.File]::Open($i.FullName, 'Open', 'ReadWrite', 'None'); $fs.Close() }
  catch { $w = '被占用: ' + $_.Exception.GetType().Name }
  Write-Host ('{0}  {1:N0} MB  {2}  [{3}]' -f $i.Name, ($i.Length/1MB), $i.LastWriteTime, $w)
}

Write-Host '--- 谁在持有 ISO: Hyper-V 光驱路径 ---'
try {
  Get-VM | ForEach-Object {
    $v = $_
    Get-VMDvdDrive -VMName $v.Name -EA SilentlyContinue | ForEach-Object {
      Write-Host ('{0} 世 {1} 控制器{2}位置{3} => {4}' -f $v.Name, $v.State, $_.ControllerNumber, $_.ControllerLocation, $_.Path)
    }
  }
} catch { Write-Host ('看不到 Hyper-V(需管理员): ' + $_.Exception.Message) }

Write-Host '--- 残留挂载点 ---'
$m = Join-Path $Root 'build\mount'
if (Test-Path $m) { Write-Host ('mount 目录存在, 子项数: ' + (Get-ChildItem $m -Force -EA SilentlyContinue).Count) } else { Write-Host '无 mount 目录(干净)' }
