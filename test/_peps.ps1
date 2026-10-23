param(
  [Parameter(Mandatory = $true)][string]$Code,
  [string]$IP = '172.17.40.212',
  [string]$User = 'Administrator'
)
# ASCII only. 在 PE 里执行一段 PowerShell(走 -EncodedCommand, 因为 pe-sshd 把命令交给 cmd.exe), 把结果打到本会话。
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\_peps.ps1 -Code "Get-Item X:\dsktest.hta | Select Length,LastWriteTime"
$ErrorActionPreference = 'Continue'
$Root = Split-Path $PSScriptRoot -Parent
$keySrc = Join-Path $Root 'overlay\Scripts\ssh_login_key'
if (-not (Test-Path -LiteralPath $keySrc)) { Write-Output ('NO_KEY: ' + $keySrc); exit 1 }
$keyTmp = Join-Path $env:TEMP ('winpe10_peps_key_' + $PID)
if (Test-Path -LiteralPath $keyTmp) { Remove-Item -LiteralPath $keyTmp -Force }
Copy-Item -LiteralPath $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r ("${env:USERNAME}:R") | Out-Null
$sshBin = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshBin)) { $sshBin = 'ssh' }
$opts = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
          '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR', ($User + '@' + $IP))
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Code))
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& $sshBin @opts ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64) 2>&1 | ForEach-Object { "$_" }
Write-Output ('(rc=' + $LASTEXITCODE + ')')
$ErrorActionPreference = $prev
Remove-Item -LiteralPath $keyTmp -Force -EA SilentlyContinue
