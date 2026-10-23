# ============================================================
# harvest_wifi_drivers.ps1 —— 在【目标机器】上导出它的无线网卡驱动, 供救援盘镜像内置
# WinPE 官方不支持 WiFi, ADK 也没有 WiFi 组件包; 无线能不能连最终取决于"这块网卡的厂商驱动在不在镜像里"。
# 所以给每台要救的机器(或每种网卡型号)采一次驱动, 放进 overlay\Drivers\wifi 再构建即可。
#
# 在目标机上以管理员 PowerShell 运行(可U盘带走本脚本):
#   powershell -NoProfile -ExecutionPolicy Bypass -File harvest_wifi_drivers.ps1
#   powershell ... -File harvest_wifi_drivers.ps1 -AllNet      # 连所有有线/无线网卡驱动一起导出
# 产物目录默认 %USERPROFILE%\Desktop\wifi_drivers
# ============================================================
param(
  [string]$Out      = (Join-Path $env:USERPROFILE 'Desktop\wifi_drivers'),
  [switch]$AllNet,
  [switch]$AllThirdParty
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
Write-Host ('导出目录: ' + $Out) -ForegroundColor Cyan

function Export-One([string]$infName, [string]$dest) {
  # 先试 DISM cmdlet(能处理系统内置驱动), 再退回 pnputil(只认 oem*.inf)
  try {
    Export-WindowsDriver -Online -Driver $infName -Destination $dest -EA Stop | Out-Null
    return 'Export-WindowsDriver'
  } catch { Write-Host ('  Export-WindowsDriver ' + $infName + ' 失败: ' + $_.Exception.Message) }
  try {
    $r = (& pnputil.exe /export-driver $infName $dest 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) { return 'pnputil' }
    Write-Host ('  pnputil ' + $infName + ' 失败: ' + (($r -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)).Trim())
  } catch { Write-Host ('  pnputil ' + $infName + ' 异常: ' + $_.Exception.Message) }
  return ''
}

$targets = @()
if ($AllThirdParty) {
  Write-Host '===== 模式: 导出全部第三方驱动 =====' -ForegroundColor Cyan
  $r = (& pnputil.exe /export-driver '*' $Out 2>&1 | Out-String)
  Write-Host (($r -split "`n" | Where-Object { $_ -match 'Driver|Published|成功|已导出' } | Select-Object -First 20) -join "`n")
} else {
  Write-Host '===== 网卡清单 =====' -ForegroundColor Cyan
  $adapters = @(Get-NetAdapter -Physical -EA SilentlyContinue)
  if ($adapters.Count -eq 0) {
    Write-Host '  Get-NetAdapter 不可用, 用 WMI 兜底' -ForegroundColor Yellow
    $adapters = @(Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' -EA SilentlyContinue |
      Select-Object @{n='Name';e={$_.Name}}, @{n='PhysicalMediaType';e={$_.PhysicalMediaType}}, @{n='PnPDeviceID';e={$_.PNPDeviceID}})
  }
  foreach ($a in $adapters) { Write-Host ('  ' + $a.Name + ' | media=' + $a.PhysicalMediaType + ' | ' + $a.PnPDeviceID) }
  if ($AllNet) {
    $sel = $adapters
    Write-Host '===== 模式: 所有网卡(-AllNet) =====' -ForegroundColor Cyan
  } else {
    $sel = @($adapters | Where-Object { "$($_.PhysicalMediaType)" -like '802.11*' })
    Write-Host '===== 模式: 仅无线网卡 =====' -ForegroundColor Cyan
  }
  if ($sel.Count -eq 0) {
    Write-Host '  这台机器没有识别到 802.11 无线网卡(可能只有有线/USB 网卡)。' -ForegroundColor Yellow
    Write-Host '  救援盘里已内置 RNDIS/usbnet 等 USB 网卡驱动: 手机 USB 共享网络(设置里开"USB 网络共享")插上就能联网, 这是最稳的兜底。' -ForegroundColor Yellow
  }
  foreach ($a in $sel) {
    $inf = ''
    try {
      $inf = (Get-CimInstance Win32_PnPSignedDriver -Filter "DeviceID='$($a.PnPDeviceID)'" -EA Stop |
        Select-Object -First 1).InfName
    } catch { Write-Host ('  查 ' + $a.Name + ' 的 INF 失败: ' + $_.Exception.Message) }
    if (-not $inf) { Write-Host ('  ' + $a.Name + ' 没查到 INF, 跳过') -ForegroundColor Yellow; continue }
    Write-Host ('  ' + $a.Name + ' -> ' + $inf)
    $how = Export-One $inf $Out
    if ($how) { Write-Host ('    已用 ' + $how + ' 导出') }
  }
}

$infs = @(Get-ChildItem $Out -Recurse -Filter *.inf -EA SilentlyContinue)
Write-Host ('===== 结果: ' + $infs.Count + ' 个 inf 在 ' + $Out + ' =====') -ForegroundColor Green
foreach ($f in $infs) { Write-Host ('  ' + $f.FullName) }
Write-Host '下一步: 把这个文件夹整个拷到构建机的 overlay\Drivers\wifi, 然后跑 patch_wifi.ps1 (或 build.ps1)' -ForegroundColor Yellow
