# 把生成的壁纸 PNG 压成 JPEG 放进 overlay\Desktop (PE 里 HTA 直接当背景)
param(
  [string]$Src = '',
  [string]$Dst = '',
  [int]$Quality = 78
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Src) {
  $Src = (Get-ChildItem (Join-Path $root 'vibe_images') -Filter 'winpe_wallpaper*.png' |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Dst) { $Dst = Join-Path $root 'overlay\Desktop\wallpaper.jpg' }
if (-not (Test-Path $Src)) { Write-Host "找不到 $Src" -ForegroundColor Red; exit 1 }

Add-Type -AssemblyName System.Drawing
$img = [Drawing.Image]::FromFile($Src)
try {
  $codec = [Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() |
           Where-Object { $_.MimeType -eq 'image/jpeg' } | Select-Object -First 1
  $ep = New-Object Drawing.Imaging.EncoderParameters(1)
  $ep.Param[0] = New-Object Drawing.Imaging.EncoderParameter([Drawing.Imaging.Encoder]::Quality, [long]$Quality)
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dst) | Out-Null
  $img.Save($Dst, $codec, $ep)
} finally { $img.Dispose() }

$srcMB = [Math]::Round((Get-Item $Src).Length/1MB, 2)
$dstMB = [Math]::Round((Get-Item $Dst).Length/1MB, 2)
Write-Host ("{0} ({1} MB) -> {2} ({3} MB) 质量{4}" -f $Src, $srcMB, $Dst, $dstMB, $Quality) -ForegroundColor Green
