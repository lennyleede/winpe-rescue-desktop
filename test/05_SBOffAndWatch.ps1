# ============================================================
# 05: 现有 WinPE-Test 关闭 SecureBoot 重启 + 探测 (管理员)
#   .\05_SBOffAndWatch.ps1                     -> 关 SecureBoot 重启当前 ISO
#   .\05_SBOffAndWatch.ps1 -Iso 'D:\winpe_build\WinPE_SSH_Sunlogin.iso'
#                                              -> 顺便换旧 ISO 做对照实验
# ============================================================
param(
  [string]$VMName = 'WinPE-Test',
  [string]$Iso,
  [int]$TimeoutSec = 300
)
$ErrorActionPreference = 'Stop'
$ResultFile = Join-Path $PSScriptRoot 'vm_ip.txt'
Remove-Item $ResultFile -ErrorAction SilentlyContinue
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请在管理员 PowerShell 中运行' -ForegroundColor Red; exit 1
}
Import-Module Hyper-V
Stop-VM -VMName $VMName -TurnOff -Force -ErrorAction SilentlyContinue
Start-Sleep 2
if ($Iso) {
  if (-not (Test-Path $Iso)) { Write-Host "ISO 不存在: $Iso" -ForegroundColor Red; exit 1 }
  Set-VMDvdDrive -VMName $VMName -Path $Iso
  Write-Host "已换 DVD: $Iso"
}
$sb = (Get-VMFirmware -VMName $VMName).EnableSecureBoot
Write-Host "SecureBoot 当前: $sb"
if ($sb -ne 'Off') { Set-VMFirmware -VMName $VMName -EnableSecureBoot Off; Write-Host '-> 已关闭 SecureBoot' }
$vmMac = ((Get-VMNetworkAdapter -VMName $VMName).MacAddress).ToUpper()
Write-Host "VM MAC: $vmMac  (若为 000000000000 则改扫邻居表)"
Start-VM -VMName $VMName
Write-Host "[watch] 已启动。请盯 VM 控制台：出现'按任意键从CD引导'立刻按键。最长 ${TimeoutSec}s ..." -ForegroundColor Yellow

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
  $neigh = @( Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.MACAddress } )
  if ($vmMac -and $vmMac -ne '000000000000') {
    $cands += @($neigh | Where-Object { ($_.MACAddress -replace '[^0-9A-Fa-f]','').ToUpper() -eq $vmMac } | Select-Object -ExpandProperty IPAddress)
  } else {
    # MAC 未知: 只测 default switch 网段里非宿主的邻居 (数量有限)
    $hostIP = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1)
    $cands += @($neigh | Where-Object { $_.IPAddress -like ($hostIP.IPAddress.Split('.')[0..1] -join '.') + '.*' -and $_.IPAddress -ne $hostIP.IPAddress } | Select-Object -ExpandProperty IPAddress)
  }
  foreach ($ip in ($cands | Where-Object { $_ } | Select-Object -Unique)) {
    Write-Host "    候选: $ip"
    if (Test-Port22 $ip) { $foundIP = $ip; break }
  }
}
if ($foundIP) {
  Write-Host "`n成功! WinPE sshd 可达: $foundIP" -ForegroundColor Green
  Set-Content -Path $ResultFile -Value $foundIP
} else {
  Write-Host "`n超时未探测到。请描述 VM 控制台当前画面。" -ForegroundColor Red
}
