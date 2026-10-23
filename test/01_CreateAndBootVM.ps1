# ============================================================
# WinPE ISO Hyper-V 冒烟测试 - 步骤1：创建并启动 VM（需管理员）
# 在管理员 PowerShell 中运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File 01_CreateAndBootVM.ps1
# 完成后 VM 保持运行，IP 写入 test\vm_ip.txt，随后用 SSH 验证脚本检查。
# ============================================================
param(
  [string]$Iso = 'D:\QoderProject\国内版\生成winpe\dist\WinPE_Desktop_v5.iso',
  [string]$VMName = 'WinPE-Test',
  [int]$RAMMB = 2048,
  [int]$TimeoutSec = 240,
  [switch]$NoSecureBoot
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
$ResultFile = Join-Path $PSScriptRoot 'vm_ip.txt'
Remove-Item $ResultFile -ErrorAction SilentlyContinue

# ---------- 前置检查 ----------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请在【管理员】PowerShell 中运行本脚本' -ForegroundColor Red; exit 1
}
if (-not (Test-Path $Iso)) { Write-Host "ERROR: 未找到 ISO: $Iso" -ForegroundColor Red; exit 1 }
Import-Module Hyper-V
Write-Host ('[0] ISO: {0}  ({1:N1} MB)' -f (Split-Path $Iso -Leaf), ((Get-Item $Iso).Length/1MB))

# ---------- 清理旧测试 VM ----------
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
  Write-Host "[1] 已存在 $VMName，先删除重建"
  Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
  Start-Sleep 2
  Remove-VM -Name $VMName -Force
}

# ---------- 选择交换机: 优先 Default Switch ----------
$switch = Get-VMSwitch | Where-Object { $_.Name -eq 'Default Switch' }
if (-not $switch) { $switch = Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' } | Select-Object -First 1 }
if (-not $switch) { Write-Host 'ERROR: 找不到可用虚拟交换机' -ForegroundColor Red; exit 1 }
Write-Host "[2] 使用交换机: $($switch.Name) [$($switch.SwitchType)]"

# ---------- 创建 VM (Generation 2, UEFI 从 ISO 启动) ----------
$vmPath = Join-Path $PSScriptRoot 'vm'
New-Item -ItemType Directory -Force -Path $vmPath | Out-Null
Write-Host "[3] 创建 VM: $VMName, ${RAMMB}MB, 2 vCPU, Gen2"
New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($RAMMB*1MB) -SwitchName $switch.Name -Path $vmPath | Out-Null
Set-VM -VMName $VMName -ProcessorCount 2 -AutomaticStopAction TurnOff | Out-Null
# 不挂硬盘，仅 DVD 引导，避免写盘
Set-VMDvdDrive -VMName $VMName -Path $Iso
# 启动顺序: DVD 优先; SecureBoot 默认开(微软签名 winpe 可通过)，失败可用 -NoSecureBoot 重试
$dvd = Get-VMDvdDrive -VMName $VMName
Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd -EnableSecureBoot $(if ($NoSecureBoot) {'Off'} else {'On'})
Write-Host ("[4] SecureBoot = " + $(if ($NoSecureBoot) {'Off'} else {'On'}))

# ---------- 启动并探测 IP ----------
Start-VM -VMName $VMName
Write-Host "[5] VM 已启动，等待网络 (最长 ${TimeoutSec}s) ..."
$hostIP = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1)
$prefixLen = 0
if ($hostIP) {
  $prefixLen = $hostIP.PrefixLength
  Write-Host ("    宿主 Default Switch 地址: {0}/{1}" -f $hostIP.IPAddress, $prefixLen)
}

function Test-Port22([string]$ip) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $r = $c.BeginConnect($ip, 22, $null, $null); $ok = $r.AsyncWaitHandle.WaitOne(300); if ($ok -and $c.Connected) { return $true } return $false }
  catch { return $false } finally { $c.Close() }
}

$foundIP = $null
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not $foundIP) {
  Start-Sleep 5
  # 途径A: KVP 上报的 IP
  $ips = (Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue).IPAddresses
  $v4 = @($ips) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
  if ($v4.Count -gt 0 -and (Test-Port22 $v4[0])) { $foundIP = $v4[0]; break }
  # 途径B: 扫描 Default Switch 子网 22 端口
  if ($hostIP) {
    $p = $hostIP.IPAddress.Split('.') | ForEach-Object { [int64]$_ }
    $ipInt = ($p[0] -shl 24) + ($p[1] -shl 16) + ($p[2] -shl 8) + $p[3]
    $hostBits = 32 - $prefixLen
    $mask = -bnot (([int64]1 -shl $hostBits) - 1)
    $netStart = $ipInt -band $mask
    $total = [int64]1 -shl $hostBits
    for ($i = 1; $i -lt $total; $i++) {
      $addr = $netStart + $i
      $ipStr = '{0}.{1}.{2}.{3}' -f (($addr -shr 24) -band 255), (($addr -shr 16) -band 255), (($addr -shr 8) -band 255), ($addr -band 255)
      if ($ipStr -eq $hostIP.IPAddress) { continue }
      if (Test-Port22 $ipStr) { $foundIP = $ipStr; break }
    }
  }
  Write-Host '    等待中...'
}

if ($foundIP) {
  Write-Host "`n成功! WinPE 已启动且 sshd 端口 22 可达: $foundIP" -ForegroundColor Green
  Set-Content -Path $ResultFile -Value $foundIP
  Write-Host @"
接下来请勿关闭本窗口/VM，在普通 PowerShell 运行验证脚本:
  powershell -NoProfile -ExecutionPolicy Bypass -File '$PSScriptRoot\02_VerifyViaSSH.ps1'
或直接把本窗口输出粘贴给我。
"@ -ForegroundColor Cyan
} else {
  Write-Host "`n超时: 未能发现开放 22 端口的 VM IP。请把以上输出贴给我分析。" -ForegroundColor Red
  Write-Host '可尝试: .\01_CreateAndBootVM.ps1 -NoSecureBoot' -ForegroundColor Yellow
}
Get-VM -Name $VMName | Format-List Name, State, Status, Uptime
