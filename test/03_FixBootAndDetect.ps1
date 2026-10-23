# ============================================================
# 修复 WinPE-Test 引导顺序(DVD 首位) + 重启 + 探测 sshd IP
# 管理员 PowerShell 运行:
#   powershell -NoProfile -ExecutionPolicy Bypass -File 03_FixBootAndDetect.ps1
# ============================================================
param(
  [string]$Iso = 'D:\QoderProject\国内版\生成winpe\dist\WinPE_Desktop_v5.iso',
  [string]$VMName = 'WinPE-Test',
  [int]$TimeoutSec = 240
)
$ErrorActionPreference = 'Stop'
$ResultFile = Join-Path $PSScriptRoot 'vm_ip.txt'
Remove-Item $ResultFile -ErrorAction SilentlyContinue
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'ERROR: 请在管理员 PowerShell 中运行' -ForegroundColor Red; exit 1
}
Import-Module Hyper-V

# ---------- 1. 诊断信息 ----------
$dvd = Get-VMDvdDrive -VMName $VMName
Write-Host ("[1] DVD 控制器: {0}:{1}  当前挂载: {2}" -f $dvd.ControllerType, $dvd.ControllerNumber, $(if ($dvd.Path) { $dvd.Path } else { '<空>' }))
if (-not $dvd.Path -or -not (Test-Path $dvd.Path)) {
  Write-Host "    重新挂载 ISO: $Iso"
  Set-VMDvdDrive -VMName $VMName -Path $Iso
  $dvd = Get-VMDvdDrive -VMName $VMName
}
$fw = Get-VMFirmware -VMName $VMName
Write-Host '[2] 修复前引导顺序:'
$devs = @($fw.BootOrder | ForEach-Object { $_.Device })
$i = 0; foreach ($d in $devs) { $i++; Write-Host ("    {0}. {1}  Id={2}" -f $i, $d.GetType().Name, $d.Id) }

# ---------- 2. 把 DVD 提到首位 ----------
Stop-VM -VMName $VMName -TurnOff -Force -ErrorAction SilentlyContinue
Start-Sleep 2
$dvdDev = $devs | Where-Object { $_.Id -eq $dvd.Id }
if (-not $dvdDev) {
  Write-Host '[3] DVD 不在引导设备列表(异常)，尝试 -FirstBootDevice 强制设置'
  Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd
} else {
  $newOrder = @($dvdDev) + @($devs | Where-Object { $_.Id -ne $dvd.Id })
  Write-Host '[3] 设置引导顺序: DVD 置顶'
  Set-VMFirmware -VMName $VMName -BootOrder $newOrder
}
$fw2 = Get-VMFirmware -VMName $VMName
Write-Host '[4] 修复后引导顺序:'
$j = 0; foreach ($d in ($fw2.BootOrder | ForEach-Object { $_.Device })) { $j++; Write-Host ("    {0}. {1}" -f $j, $d.GetType().Name) }

# ---------- 3. 启动并探测 ----------
Start-VM -VMName $VMName
Write-Host "[5] 已重启，等待网络(最长 ${TimeoutSec}s)。请打开 VM 控制台观察：若出现\"按任意键从 CD 引导\"提示，请按键。" -ForegroundColor Yellow
$hostIP = (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1)
$prefixLen = if ($hostIP) { $hostIP.PrefixLength } else { 0 }

function Test-Port22([string]$ip) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $r = $c.BeginConnect($ip, 22, $null, $null); $ok = $r.AsyncWaitHandle.WaitOne(300); if ($ok -and $c.Connected) { return $true } return $false }
  catch { return $false } finally { $c.Close() }
}

$vmMac = (Get-VMNetworkAdapter -VMName $VMName).MacAddress
Write-Host "    VM MAC: $vmMac"
$foundIP = $null
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not $foundIP) {
  Start-Sleep 5
  $cands = @()
  # 途径A: KVP 上报的 IP
  $cands += @( (Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue).IPAddresses ) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
  # 途径B: 按 VM 网卡 MAC 精确匹配 ARP 邻居
  $cands += @( Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Where-Object { $_.MACAddress -and ($_.MACAddress -replace '[^0-9A-Fa-f]','') -eq $vmMac } |
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
  Write-Host "`n超时: 未发现 22 端口。请描述/截图 VM 控制台当前画面贴给我。" -ForegroundColor Red
}
