# ============================================================
# 04: 用纯英文路径 ISO 重建 VM + 全量诊断 (管理员运行)
#   powershell -NoProfile -ExecutionPolicy Bypass -File 04_RebuildVmClean.ps1
# ============================================================
param(
  [string]$IsoSrc = 'D:\QoderProject\国内版\生成winpe\dist\WinPE_Desktop_v5_fix.iso',
  [string]$IsoDst = 'D:\winpe_test\WinPE_v5.iso',
  [string]$VMName = 'WinPE-Test',
  [int]$TimeoutSec = 300,
  [switch]$NoSecureBoot
)
$ErrorActionPreference = 'Stop'
$ResultFile = Join-Path $PSScriptRoot 'vm_ip.txt'
Remove-Item $ResultFile -ErrorAction SilentlyContinue
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请在管理员 PowerShell 中运行' -ForegroundColor Red; exit 1
}
Import-Module Hyper-V

# ---------- 1. 复制 ISO 到英文路径 ----------
Write-Host "[1] 复制 ISO 到 $IsoDst ..."
New-Item -ItemType Directory -Force -Path (Split-Path $IsoDst) | Out-Null
if (-not (Test-Path $IsoDst) -or (Get-Item $IsoDst).Length -ne (Get-Item $IsoSrc).Length) {
  Copy-Item $IsoSrc $IsoDst -Force
}
Write-Host ('    大小: {0:N1} MB' -f ((Get-Item $IsoDst).Length/1MB))

# ---------- 2. 删除并重建 VM ----------
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
  Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue; Start-Sleep 2
  Remove-VM -Name $VMName -Force
}
$switch = 'Default Switch'
$vmPath = 'D:\winpe_test\vm'
New-Item -ItemType Directory -Force -Path $vmPath | Out-Null
Write-Host "[2] 重建 VM (Gen2, 2048MB, 2vCPU, DVD=$IsoDst)"
New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 2GB -SwitchName $switch -Path $vmPath | Out-Null
Set-VM -VMName $VMName -ProcessorCount 2 -AutomaticStopAction TurnOff | Out-Null
# New-VM 无硬盘时不会创建 DVD 驱动器，必须显式添加
try { Get-VMDvdDrive -VMName $VMName -ErrorAction Stop | Out-Null } catch { }
if (-not (Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue)) {
  Write-Host '    VM 无 DVD 驱动器，显式添加 SCSI DVD (0:1)'
  Add-VMDvdDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 1 | Out-Null
}
Set-VMDvdDrive -VMName $VMName -Path $IsoDst
# 静态 MAC，便于 ARP 精确匹配
$staticMac = '00-15-5D-4E-10-99'
Set-VMNetworkAdapter -VMName $VMName -StaticMacAddress $staticMac | Out-Null

# ---------- 3. 引导固件诊断 ----------
$dvd = Get-VMDvdDrive -VMName $VMName
if (-not $dvd -or -not $dvd.Path) { Write-Host 'ERROR: DVD 挂载失败' -ForegroundColor Red; exit 1 }
Write-Host ("[3] DVD 挂载确认: {0} (Controller {1}:{2})" -f $dvd.Path, $dvd.ControllerType, $dvd.ControllerNumber)
$fw = Get-VMFirmware -VMName $VMName
Write-Host '    当前引导顺序:'
$devs = @($fw.BootOrder | ForEach-Object { $_.Device })
$n = 0; foreach ($d in $devs) { $n++; Write-Host ("      {0}. {1}  Id={2}" -f $n, $d.GetType().Name, $d.Id) }
$dvdDev = $devs | Where-Object { $_.Id -eq $dvd.Id }
if ($dvdDev) {
  $newOrder = @($dvdDev) + @($devs | Where-Object { $_.Id -ne $dvd.Id })
  Set-VMFirmware -VMName $VMName -BootOrder $newOrder
  Write-Host '    -> 已将 DVD 置顶'
} else {
  Write-Host '    -> 警告: DVD 不在 BootOrder 设备列表!' -ForegroundColor Yellow
  Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
}
Write-Host '    设置后引导顺序:'
$n = 0; foreach ($d in (Get-VMFirmware -VMName $VMName).BootOrder | ForEach-Object { $_.Device }) { $n++; Write-Host ("      {0}. {1}" -f $n, $d.GetType().Name) }
$vmMac = ((Get-VMNetworkAdapter -VMName $VMName).MacAddress).ToUpper()
Write-Host "    VM MAC: $vmMac"
if ($NoSecureBoot) {
  Stop-VM -VMName $VMName -TurnOff -Force -ErrorAction SilentlyContinue; Start-Sleep 2
  Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
  Write-Host '    -> SecureBoot 已关闭 (验证 dbx 吊销假设)' -ForegroundColor Yellow
}

# ---------- 4. 启动并探测 ----------
Start-VM -VMName $VMName
Write-Host "[4] 已启动。请打开 VM 控制台，若出现'按任意键从CD引导'请立即按键。等待最长 ${TimeoutSec}s ..." -ForegroundColor Yellow

function Test-Port22([string]$ip) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $r = $c.BeginConnect($ip, 22, $null, $null); $ok = $r.AsyncWaitHandle.WaitOne(300); if ($ok -and $c.Connected) { return $true } return $false }
  catch { return $false } finally { $c.Close() }
}
$foundIP = $null
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not $foundIP) {
  Start-Sleep 5
  $cands = @()
  $cands += @( (Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue).IPAddresses ) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
  $cands += @( Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.MACAddress -and (($_.MACAddress -replace '[^0-9A-Fa-f]','').ToUpper()) -eq $vmMac } |
               Select-Object -ExpandProperty IPAddress )
  foreach ($ip in ($cands | Where-Object { $_ } | Select-Object -Unique)) {
    Write-Host "    候选: $ip"
    if (Test-Port22 $ip) { $foundIP = $ip; break }
  }
}

if ($foundIP) {
  Write-Host "`n成功! WinPE sshd 可达: $foundIP" -ForegroundColor Green
  Set-Content -Path $ResultFile -Value $foundIP
} else {
  Write-Host "`n超时。抓取 Hyper-V Worker 最近错误日志辅助定位:" -ForegroundColor Red
  Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-Worker-Admin' -MaxEvents 15 -ErrorAction SilentlyContinue |
    Where-Object { $_.LevelDisplayName -in @('错误','Warning','Error','Warning') } |
    Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}} |
    Format-List
  Write-Host '请把以上输出与 VM 控制台画面一起贴给我。'
}
