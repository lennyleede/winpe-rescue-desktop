# 用本机 mshta 真渲染 Desktop.hta 并截屏(HTA 的 IE 引擎与 PE 里同一套, 能看出兼容问题)
# 普通权限即可; 只在 build\ 下产图, 不碰镜像。窗口会全屏 4 秒后自动关掉。
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\hta_shot.ps1
param(
  [string]$Hta = '',
  [int]$Wait = 5,
  [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Hta) { $Hta = Join-Path $Root 'overlay\Desktop\Desktop.hta' }
if (-not $Out) { $Out = Join-Path $Root 'build\hta_mshta.png' }
if (-not (Test-Path $Hta)) { Write-Host "找不到 $Hta" -ForegroundColor Red; exit 1 }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null

$p = Start-Process mshta.exe -ArgumentList ('"' + $Hta + '"') -PassThru
Start-Sleep -Seconds $Wait
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
# 不声明 DPI 感知的话, VirtualScreen 会返回缩放后的假分辨率, 截出来的图缺底部一条
Add-Type 'using System.Runtime.InteropServices; public static class Dpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); [DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h); }'
[void][Dpi]::SetProcessDPIAware()
# 2026-10-13: IDE 会抢前台导致截到自己, 拍之前把 mshta 主窗口顶到最前
try { $p.Refresh(); if ($p.MainWindowHandle -ne [IntPtr]::Zero) { [void][Dpi]::SetForegroundWindow($p.MainWindowHandle); Start-Sleep -Milliseconds 700 } } catch {}
$b = [Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object Drawing.Bitmap($b.Width, $b.Height)
$g = [Drawing.Graphics]::FromImage($bmp)
try {
  $g.CopyFromScreen($b.Location, [Drawing.Point]::Empty, $b.Size)
  $bmp.Save($Out, [Drawing.Imaging.ImageFormat]::Png)
} finally {
  $g.Dispose(); $bmp.Dispose()
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
Write-Host ('截图: ' + $Out + ' (' + [Math]::Round((Get-Item $Out).Length/1KB,1) + ' KB, ' + $b.Width + 'x' + $b.Height + ')') -ForegroundColor Green
Write-Host 'mshta 已关闭; 图里若出现大段空白/没有圆角卡片, 说明 PE 的 IE 引擎模式不对, 需要退回保守 CSS'
