# 管理员 PowerShell 运行: 把"已经注入完但 /Unmount-Wim 报错 32"的那次构建救回来, 不必重跑 20 分钟
#   背景: 2026-10-05 的构建在 [5b] 把四个防火墙值都写对了, 但 HKLM\PE_FW 没卸掉, 于是
#         [6/6] dism /Unmount-Wim /Commit 报"错误 32 另一个程序正在使用此文件", 构建中止。
#         mount 目录里的注入内容还在, 只要现在把残留配置单元清掉再 Commit 就能出 boot.wim。
#   用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\13_RescueCommit.ps1
param(
  [switch]$CheckOnly      # 只看状态, 不动任何盘
)
$ErrorActionPreference = 'Continue'
$Root  = Split-Path -Parent $PSScriptRoot
$Mount = Join-Path $Root 'build\mount'
$Wim   = Join-Path $Root 'build\WinPE_amd64\media\sources\boot.wim'
$DismExe = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe'
if (-not (Test-Path $DismExe)) { $DismExe = 'Dism.exe' }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host '请以管理员 PowerShell 运行本脚本' -ForegroundColor Red; exit 1
}

Write-Host '=== 1. 清理残留的临时配置单元(错误 32 的元凶) ===' -ForegroundColor Cyan
foreach ($round in 1..2) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  foreach ($hk in @('PE_FW', 'PE_SYS', 'PE_SYS2')) {
    & reg.exe query ('HKLM\' + $hk) > $null 2>&1
    if ($LASTEXITCODE -eq 0) {
      & reg.exe unload ('HKLM\' + $hk) > $null 2>&1
      Write-Host ('  HKLM\' + $hk + ' 原本挂着, 已尝试卸载 (rc=' + $LASTEXITCODE + ')') -ForegroundColor Yellow
      & reg.exe query ('HKLM\' + $hk) > $null 2>&1
      if ($LASTEXITCODE -ne 0) { Write-Host ('  确认 HKLM\' + $hk + ' 已不在') -ForegroundColor Green }
      else { Write-Host ('  !! HKLM\' + $hk + ' 仍卸不掉, 请关闭其它管理员 PowerShell/窗口后再试') -ForegroundColor Red }
    } else { Write-Host ('  HKLM\' + $hk + ' 没有残留') }
  }
}

Write-Host '=== 2. DISM 挂载会话状态 ===' -ForegroundColor Cyan
& $DismExe /Get-MountedImageInfo
if (-not (Test-Path $Mount)) { Write-Host ('  mount 目录不存在: ' + $Mount) -ForegroundColor Red; exit 1 }
if ($CheckOnly) { Write-Host '  -CheckOnly: 到此为止, 没有提交'; exit 0 }

Write-Host '=== 3. 提交挂载内容进 boot.wim (可能要几分钟) ===' -ForegroundColor Cyan
$before = if (Test-Path $Wim) { (Get-Item $Wim).LastWriteTime } else { [datetime]0 }
& $DismExe /Unmount-Wim ('/MountDir:' + $Mount) /Commit
$rc = $LASTEXITCODE
if ($rc -eq 0 -and (Test-Path $Wim) -and (Get-Item $Wim).LastWriteTime -gt $before) {
  Write-Host ('  提交成功: boot.wim ' + (Get-Item $Wim).LastWriteTime + '  ' + ('{0:N0} MB' -f ((Get-Item $Wim).Length / 1MB))) -ForegroundColor Green
  Write-Host '=== 4. 下一步 ===' -ForegroundColor Cyan
  Write-Host ('  (普通权限, 1-2 分钟出 ISO) powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'test\pack_iso.ps1') + '"')
  Write-Host ('  (管理员, 换 VM 光驱并启动)  powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'test\10_RebuildAndSwap.ps1') + '" -SkipBuild')
  exit 0
}

Write-Host ('  提交没成功 (rc=' + $rc + '), boot.wim 时间戳没变 -> 这次注入保不住了') -ForegroundColor Red
Write-Host '  补救: 直接重跑管理员构建即可, build.ps1 的 [1/6] 会自己 /Discard + /Cleanup-Mountpoints 再 copype:' -ForegroundColor Yellow
Write-Host ('    powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $Root 'test\10_RebuildAndSwap.ps1') + '"')
