# iso_target.ps1 —— 给 build.ps1 / patch_wifi.ps1 用一个"写得进去"的 ISO 路径。
# Hyper-V 虚拟机正在从某个 ISO 启动时会独占该文件(无法删除也无法覆盖), 这时换带时间戳的新名字,
# 免得注入已经提交进 boot.wim 却在最后一步出盘失败。
# 用法(只打印路径): $Iso = & test\iso_target.ps1 -Base dist\WinPE_Desktop_v7.iso
param([Parameter(Mandatory = $true)][string]$Base)
$ErrorActionPreference = 'Continue'

# 返回的路径必须是绝对的 —— build.ps1 / patch_wifi.ps1 在 Push-Location <Oscdimg 目录> 之后才把这个名字交给
# oscdimg.exe(bootdata 的 .bin 只能给相对文件名, 带空格的路径 oscdimg 解析不了), 于是相对名会被解析成
# "C:\Program Files (x86)\...\Oscdimg\dist\X.iso" -> Error 3 系统找不到路径。2026-10-10 22:30 出盘就红在
# 这一步: 注入已经 /Commit 进 boot.wim, 只差 ISO 没写出来。
# 相对路径一律按项目根(本脚本上一级)解析, 用户在哪个目录敲结果都一样, 绝不会落到 Oscdimg 目录里。
function FullPath([string]$p) {
  if ([IO.Path]::IsPathRooted($p)) { return [IO.Path]::GetFullPath($p) }
  return [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $PSScriptRoot) $p))
}
$Base = FullPath $Base

function Test-Free([string]$p) {
  if (-not (Test-Path $p)) { return $true }
  try { $fs = [IO.File]::Open($p, 'Open', 'ReadWrite', 'None'); $fs.Close(); return $true }
  catch { return $false }
}

if (Test-Free $Base) { Write-Output $Base; exit 0 }
$dir  = Split-Path $Base -Parent
$name = [IO.Path]::GetFileNameWithoutExtension($Base)
$alt  = FullPath (Join-Path $dir ($name + '_' + (Get-Date -Format 'MMdd-HHmmss') + '.iso'))
if (-not (Test-Free $alt)) { Write-Host '目标 ISO 与备选名都被占用' -ForegroundColor Red; exit 1 }
Write-Host ('目标 ISO 正被占用(通常是虚拟机光驱), 改用: ' + (Split-Path $alt -Leaf)) -ForegroundColor Yellow
Write-Output $alt
