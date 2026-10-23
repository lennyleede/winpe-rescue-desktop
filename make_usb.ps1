# ============================================================
# make_usb.ps1 —— 把 build\WinPE_amd64\media 写成 UEFI+Legacy 双引导的救援 U 盘(实机测试用)
# 底层用 ADK 自带的 MakeWinPEMedia.cmd /UFD(会 diskpart 清掉整盘重建 FAT32 引导分区)。
#
# 先看有哪些可移动盘(普通权限, 不写任何东西):
#   powershell -NoProfile -ExecutionPolicy Bypass -File make_usb.ps1 -List
# 真正写入(管理员, 会清空 U 盘):
#   powershell -NoProfile -ExecutionPolicy Bypass -File make_usb.ps1 -Drive E:
# ============================================================
param(
  [string]$Drive = '',
  [switch]$List
)
$ErrorActionPreference = 'Stop'
$Root  = $PSScriptRoot
$Src   = Join-Path $Root 'build\WinPE_amd64'
$ADKPE = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\MakeWinPEMedia.cmd'

function Show-Removable {
  $disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2')
  if (-not $disks.Count) { Write-Host '  现在没有插任何可移动 U 盘(或系统没把它识别为 Removable)' -ForegroundColor Yellow; return }
  Write-Host '  可移动盘:' -ForegroundColor Cyan
  foreach ($d in $disks) {
    Write-Host ('    {0}  {1}  容量 {2:N1} GB / 剩余 {3:N1} GB' -f $d.DeviceID, $d.VolumeName,
      ($d.Size/1GB), ($d.FreeSpace/1GB))
  }
}

Show-Removable
if ($List) { exit 0 }
if (-not $Drive) { Write-Host '缺少 -Drive, 例如 -Drive E:  (先看上面的 -List 输出)' -ForegroundColor Red; exit 1 }
$Drive = $Drive.TrimEnd('\').ToUpper()
if ($Drive -notmatch '^[A-Z]:$') { Write-Host "盘符写法不对: $Drive (应为 E: 这种)" -ForegroundColor Red; exit 1 }
if ($Drive -in @('C:', (Split-Path $env:SystemRoot -Qualifier).ToUpper())) {
  Write-Host "$Drive 是系统盘, 拒绝" -ForegroundColor Red; exit 1
}
if (-not (Test-Path "$Src\media")) { Write-Host "找不到 $Src\media, 先跑 build.ps1" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $ADKPE)) { Write-Host "找不到 ADK 的 MakeWinPEMedia.cmd: $ADKPE" -ForegroundColor Red; exit 1 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请以管理员 PowerShell 运行' -ForegroundColor Red; exit 1
}

Write-Host ''
Write-Host ("!! 即将清空并格式化整个 {0} 盘, 上面所有数据都会没了" -f $Drive) -ForegroundColor Red
$ans = Read-Host ("确认请输入盘符(只输字母, 例如 {0}): " -f $Drive[0])
if ($ans.Trim().ToUpper() -ne $Drive[0]) { Write-Host '已取消, 什么都没做' -ForegroundColor Yellow; exit 0 }

Write-Host ('[1/2] MakeWinPEMedia /UFD -> ' + $Drive) -ForegroundColor Cyan
& $ADKPE /UFD /f $Src $Drive
$rc = $LASTEXITCODE
if ($rc -ne 0) { Write-Host "MakeWinPEMedia 失败 (code=$rc), 常见原因: U 盘被占用/写保护/盘符不对" -ForegroundColor Red; exit 1 }

Write-Host '[2/2] 校验引导文件是否真的进去了 ...' -ForegroundColor Cyan
$need = @('sources\boot.wim','efi\boot\bootx64.efi','boot\bcd','bootmgr')
$miss = @()
foreach ($n in $need) { if (-not (Test-Path (Join-Path ($Drive + '\') $n))) { $miss += $n } }
if ($miss.Count) { Write-Host ('缺文件: ' + ($miss -join ', ') + '  (UEFI 启动可能失败)') -ForegroundColor Red; exit 1 }
$wim = Get-Item (Join-Path ($Drive + '\') 'sources\boot.wim')
Write-Host ('完成! U 盘已可引导 (boot.wim ' + [Math]::Round($wim.Length/1MB,1) + ' MB, ' + $wim.LastWriteTime + ')') -ForegroundColor Green
Write-Host '下一步: 目标机 BIOS 里关闭 Secure Boot, 从这块 U 盘(UEFI 项)启动' -ForegroundColor Yellow
