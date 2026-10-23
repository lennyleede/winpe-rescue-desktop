# ============================================================
# WinPE Hyper-V 冒烟测试 - 步骤2：SSH 进入 WinPE 验证功能（普通权限即可）
#   powershell -NoProfile -ExecutionPolicy Bypass -File 02_VerifyViaSSH.ps1
#   或 02_VerifyViaSSH.ps1 -IP 172.17.x.x
# ============================================================
param(
  [string]$IP,
  [string]$User = 'Administrator'
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path $PSScriptRoot -Parent
if (-not $IP) {
  $ipFile = Join-Path $PSScriptRoot 'vm_ip.txt'
  if (-not (Test-Path $ipFile)) { Write-Host 'ERROR: 未找到 vm_ip.txt，请先运行 01 脚本或用 -IP 指定' -ForegroundColor Red; exit 1 }
  $IP = (Get-Content $ipFile).Trim()
}
Write-Host "目标 WinPE: $IP"

# 私钥放临时目录并收紧 ACL（客户端要求）
$keySrc = Join-Path $Root 'overlay\Scripts\ssh_login_key'
$keyTmp = Join-Path $env:TEMP 'winpe_test_key'
Copy-Item $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r "${env:USERNAME}:R" | Out-Null

$sshOpts = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
             '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR', "$User@$IP")

function Invoke-Pe([string]$label, [string]$cmd) {
  Write-Host "`n========== $label ==========" -ForegroundColor Cyan
  & ssh @sshOpts $cmd 2>&1 | ForEach-Object { $_.ToString() }
}

Invoke-Pe '0. 基本连通/whoami' 'whoami & echo CONN_OK'
Invoke-Pe '1. boot.log 启动序列' 'type X:\boot.log'
Invoke-Pe '2. 进程表(sshd/mshta/Sunlogin)' 'tasklist'
Invoke-Pe '3. 网络配置' 'ipconfig'
Invoke-Pe '4. wlansvc 状态' 'sc query wlansvc'
Invoke-Pe '5. Desktop/Frp/Sunlogin 目录' 'dir X:\Desktop & dir X:\Desktop\Frp & dir X:\Sunlogin'
Invoke-Pe '6. sshd.log 尾部' 'more +1 X:\sshd.log' 
Invoke-Pe '7. PowerShell 可用性' 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "$PSVersionTable.PSVersion; (Get-Service wlansvc -ErrorAction SilentlyContinue).Status; Get-Process mshta,sshd,SunloginSOS -ErrorAction SilentlyContinue | Select Name,Id | Format-Table -AutoSize | Out-String"'
Invoke-Pe '8. 已包组件(WMI/HTA 存在性)' 'if exist X:\Windows\System32\mshta.exe (echo HTA_OK) else (echo HTA_MISSING) & if exist X:\Windows\System32\wbem\wmiprvse.exe (echo WMI_OK) else (echo WMI_MISSING) & if exist X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (echo PS_OK) else (echo PS_MISSING)'

Write-Host "`n验证完毕。测试 VM 可保留，如需删除请管理员运行: Remove-VM -Name WinPE-Test -Force" -ForegroundColor Green
