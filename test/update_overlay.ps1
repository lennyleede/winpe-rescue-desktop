# ============================================================
# update_overlay.ps1 —— 只把 overlay 里的文件层(桌面/脚本/SSH/向日葵)重新灌进 boot.wim 并出 ISO
# 用途: 改了 Desktop.hta / wallpaper.jpg / startnet.cmd / wlan.cmd / SSH / Sunlogin 这类
#       "纯文件"内容时, 不用重跑 copype+组件+WiFi 注入(全程约 3-5 分钟)。
# 需要管理员(挂载 boot.wim):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\update_overlay.ps1
# 先干跑看计划(普通权限, 不写任何东西):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\update_overlay.ps1 -SelfTest
# ============================================================
param(
  [string]$Tag = '',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$Root    = $PSScriptRoot | Split-Path -Parent
$Media   = Join-Path $Root 'build\WinPE_amd64'
$Mount   = Join-Path $Root 'build\mount'
$Overlay = Join-Path $Root 'overlay'
$Dist    = Join-Path $Root 'dist'
$Wim     = Join-Path $Media 'media\sources\boot.wim'
$ADK     = 'C:\Program Files (x86)\Windows Kits\10'
$DismExe = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe"

# 要覆盖的内容: overlay 路径 -> 镜像内路径
$Jobs = @(
  @{ Src = "$Overlay\Desktop";              Dst = "$Mount\Desktop";              Mode = 'replace' }
  @{ Src = "$Overlay\Scripts\startnet.cmd"; Dst = "$Mount\Windows\System32\startnet.cmd"; Mode = 'file' }
  @{ Src = "$Overlay\Scripts\wlan.cmd";     Dst = "$Mount\Windows\System32\wlan.cmd";     Mode = 'file' }
  @{ Src = "$Overlay\Scripts\pe_report.ps1"; Dst = "$Mount\Windows\System32\pe_report.ps1"; Mode = 'file' }
  # wifi.exe 是 overlay\Desktop\Desktop.hta WiFi 面板的后端(面板每 8 秒轮询它), 改了 wifitool 就要跟着出盘。
  # 正式全量链里由 wifi-inject.ps1 A2 拷它, 但 update_overlay 不跑 wifi-inject, 所以这里必须自己带上,
  # 否则会出现"面板是新的、wifi.exe 还是旧盘里的"的错代(2026-10-13 的 1206/CONNECTED 修复就差点被吞掉)。
  @{ Src = "$Overlay\Tools\wifi.exe";        Dst = "$Mount\Windows\System32\wifi.exe";     Mode = 'file' }
  # 救援修复四件套(bootfix/filefix/drvfix/letterfix): 2026-10-14 远程救援演练的产品化产物。
  # ps1 带 UTF-8 BOM, cmd 必须无 BOM(纯 ASCII, cmd.exe 按 ANSI 解析首行)。
  @{ Src = "$Overlay\Scripts\bootfix.ps1";   Dst = "$Mount\Windows\System32\bootfix.ps1";   Mode = 'file' }
  @{ Src = "$Overlay\Scripts\bootfix.cmd";   Dst = "$Mount\Windows\System32\bootfix.cmd";   Mode = 'file' }
  @{ Src = "$Overlay\Scripts\filefix.ps1";   Dst = "$Mount\Windows\System32\filefix.ps1";   Mode = 'file' }
  @{ Src = "$Overlay\Scripts\filefix.cmd";   Dst = "$Mount\Windows\System32\filefix.cmd";   Mode = 'file' }
  @{ Src = "$Overlay\Scripts\drvfix.ps1";    Dst = "$Mount\Windows\System32\drvfix.ps1";    Mode = 'file' }
  @{ Src = "$Overlay\Scripts\drvfix.cmd";    Dst = "$Mount\Windows\System32\drvfix.cmd";    Mode = 'file' }
  @{ Src = "$Overlay\Scripts\letterfix.ps1"; Dst = "$Mount\Windows\System32\letterfix.ps1"; Mode = 'file' }
  @{ Src = "$Overlay\Scripts\letterfix.cmd"; Dst = "$Mount\Windows\System32\letterfix.cmd"; Mode = 'file' }
  # 分区表两件(4B 演练产品化): gptfix 是面板"分区表"磁贴(盘内重建/盘外 dump 还原), gptdump 是救援规程
  # 的盘外字节备份器(产物文件名 = gptfix -DumpDir 的输入格式)。
  @{ Src = "$Overlay\Scripts\gptfix.ps1";    Dst = "$Mount\Windows\System32\gptfix.ps1";    Mode = 'file' }
  @{ Src = "$Overlay\Scripts\gptfix.cmd";    Dst = "$Mount\Windows\System32\gptfix.cmd";    Mode = 'file' }
  @{ Src = "$Overlay\Scripts\gptdump.ps1";   Dst = "$Mount\Windows\System32\gptdump.ps1";   Mode = 'file' }
  @{ Src = "$Overlay\Scripts\gptdump.cmd";   Dst = "$Mount\Windows\System32\gptdump.cmd";   Mode = 'file' }
  @{ Src = "$Overlay\SSH";                  Dst = "$Mount\SSH";                  Mode = 'merge' }
  @{ Src = "$Overlay\Sunlogin";             Dst = "$Mount\Sunlogin";             Mode = 'merge' }
)

Write-Host '=== 计划 ===' -ForegroundColor Cyan
foreach ($j in $Jobs) {
  $mark = if (Test-Path $j.Src) { 'OK ' } else { '缺失!' }
  Write-Host ('  {0} {1}  ->  {2}  [{3}]' -f $mark, $j.Src, $j.Dst, $j.Mode)
}
foreach ($j in $Jobs) { if (-not (Test-Path $j.Src)) { Write-Host ('overlay 缺文件: ' + $j.Src) -ForegroundColor Red; exit 1 } }

if ($SelfTest) {
  Write-Host ('  镜像 wim: ' + $(if (Test-Path $Wim) { '存在 ' + (Get-Item $Wim).LastWriteTime } else { '不存在, 需先跑一次 build.ps1' }))
  Write-Host ('  产物 ISO: ' + (Join-Path $Dist 'WinPE_Desktop_v8*.iso') + ' (由 pack_iso.ps1 决定最终名字)')
  Write-Host '  磁盘上的桌面文件: '
  Get-ChildItem "$Overlay\Desktop" -File | ForEach-Object { Write-Host ('    ' + $_.Name + '  ' + [Math]::Round($_.Length/1KB, 1) + ' KB  ' + $_.LastWriteTime) }
  Write-Host 'SelfTest 完成, 未做任何改动 (正式执行请去掉 -SelfTest, 并用管理员 PowerShell)' -ForegroundColor Green
  if (-not (Test-Path $Wim)) { exit 1 }
  exit 0
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请以管理员 PowerShell 运行' -ForegroundColor Red; exit 1
}
foreach ($p in @($DismExe, $Wim)) { if (-not (Test-Path $p)) { Write-Host "缺少 $p" -ForegroundColor Red; exit 1 } }
$env:Path += ";$(Split-Path $DismExe)"

Write-Host '[1/3] 挂载 boot.wim ...' -ForegroundColor Cyan
if (Test-Path $Mount) {
  & $DismExe /Unmount-Wim /MountDir:$Mount /Discard 2>$null | Out-Null
  Start-Sleep -Seconds 2
  Remove-Item $Mount -Recurse -Force -ErrorAction SilentlyContinue
}
& $DismExe /Cleanup-Mountpoints 2>$null | Out-Null
New-Item -ItemType Directory -Force -Path $Mount | Out-Null
& $DismExe /Mount-Wim /WimFile:$Wim /Index:1 /MountDir:$Mount
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$Mount\Windows\System32")) {
  Write-Host '挂载失败(测试虚拟机若在跑请先 Stop-VM)' -ForegroundColor Red; exit 1
}

$done = $false
try {
  Write-Host '[2/3] 覆盖文件层 ...' -ForegroundColor Cyan
  foreach ($j in $Jobs) {
    if ($j.Mode -eq 'replace') {
      if (Test-Path $j.Dst) { Remove-Item $j.Dst -Recurse -Force }
      Copy-Item $j.Src $j.Dst -Recurse -Force
    } elseif ($j.Mode -eq 'merge') {
      New-Item -ItemType Directory -Force -Path $j.Dst | Out-Null
      Copy-Item (Join-Path $j.Src '*') $j.Dst -Force
    } else {
      Copy-Item $j.Src $j.Dst -Force
    }
    Write-Host ('    ' + $j.Dst)
  }
  # 私钥绝不进镜像(和 build.ps1 同一道保险)
  foreach ($k in @("$Mount\SSH\ssh_login_key", "$Mount\Desktop\ssh_login_key")) {
    if (Test-Path $k) { Remove-Item $k -Force; Write-Host ("    已剔除私钥 " + $k) -ForegroundColor Yellow }
  }
  # 桌面文件清单回读, 免得"改了没进去"
  Get-ChildItem "$Mount\Desktop" -File | ForEach-Object {
    Write-Host ('    镜像内: ' + $_.Name + ' ' + [Math]::Round($_.Length/1KB, 1) + ' KB')
  }
  $done = $true
} finally {
  if ($done) {
    Write-Host '[3/3] 卸载并提交 ...' -ForegroundColor Cyan
    & $DismExe /Unmount-Wim /MountDir:$Mount /Commit
    if ($LASTEXITCODE -ne 0) { Write-Host '卸载失败(有进程占用 mount 目录)' -ForegroundColor Red; exit 1 }
  } else {
    Write-Host '出错, 丢弃挂载点改动, boot.wim 保持原样' -ForegroundColor Red
    & $DismExe /Unmount-Wim /MountDir:$Mount /Discard | Out-Null
    exit 1
  }
}

# 出 ISO 交给 pack_iso.ps1(它负责目标被虚拟机光驱占用时换名 + El Torito 引导校验)
& (Join-Path $Root 'test\pack_iso.ps1') -Force
