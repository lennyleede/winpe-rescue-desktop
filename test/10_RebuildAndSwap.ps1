# 管理员 PowerShell 运行: 重新构建 ISO -> 换到测试 VM 的光驱 -> 关闭 Secure Boot -> 重启 VM
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File 10_RebuildAndSwap.ps1 [-Iso <path>]
param(
  [string]$VMName = 'WinPE-Test',
  [string]$Iso = '',
  [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# ISO 名可能带时间戳(build.ps1/patch_wifi.ps1 遇到被占用的旧 ISO 会换名), 所以默认取 dist 里
# 最新且比 boot.wim 新的那个 —— 比 boot.wim 旧的 ISO 不含最后一次注入, 拿去启动等于白测
function Get-FreshIso {
  $dist = Join-Path $root 'dist'
  $wim  = Join-Path $root 'build\WinPE_amd64\media\sources\boot.wim'
  $isos = Get-ChildItem $dist -Filter '*.iso' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending
  if (-not $isos) { return '' }
  if (Test-Path $wim) {
    $fresh = $isos | Where-Object { $_.LastWriteTime -ge (Get-Item $wim).LastWriteTime } | Select-Object -First 1
    if ($fresh) { return $fresh.FullName }
    Write-Host ('  !! dist 里没有任何 ISO 比 boot.wim 新(最新 ' + $isos[0].Name + ' ' + $isos[0].LastWriteTime +
      ' / boot.wim ' + (Get-Item $wim).LastWriteTime + ') —— 最后一次注入没打进 ISO, 请先跑 pack_iso.ps1') -ForegroundColor Red
  }
  return $isos[0].FullName
}

if (-not $Iso) { $Iso = Get-FreshIso }
if ($Iso -and $Iso -notmatch '^[A-Za-z]:') { $Iso = Join-Path $PWD $Iso }
if (-not $Iso) { Write-Host 'dist 里没有 ISO, 请先跑 build.ps1 或 patch_wifi.ps1' -ForegroundColor Red; exit 1 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host '请以管理员 PowerShell 运行本脚本' -ForegroundColor Red; exit 1
}

if (-not $SkipBuild) {
  Write-Host '=== 构建 (copype/DISM/oscdimg, 约 10-20 分钟) ===' -ForegroundColor Cyan
  & (Join-Path $root 'build.ps1')
  if ($LASTEXITCODE -ne 0) { Write-Host '构建失败, 中止' -ForegroundColor Red; exit 1 }
  # 构建脚本遇到被占用的目标会自动改名, 这里重新取一次
  if (-not (Test-Path $Iso)) { $Iso = Get-FreshIso }
}
if (-not $Iso -or -not (Test-Path $Iso)) { Write-Host "找不到要启动的 ISO: $Iso" -ForegroundColor Red; exit 1 }

Write-Host '=== 换 ISO 并重启 VM ===' -ForegroundColor Cyan
if (-not (Get-VM -Name $VMName -ErrorAction SilentlyContinue)) { Write-Host "找不到 VM $VMName" -ForegroundColor Red; exit 1 }
Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
$dvd = Get-VMDvdDrive -VMName $VMName
Set-VMDvdDrive -VMName $VMName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $Iso
Start-VM -Name $VMName
Write-Host ('已启动 {0}, ISO: {1}' -f $VMName, $Iso) -ForegroundColor Green
Write-Host '等 60-90 秒进入桌面/命令行后, 在 VM 控制台粘贴本轮验证命令即可'
