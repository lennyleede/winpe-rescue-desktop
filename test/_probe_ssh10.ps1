param([string]$IP = '172.17.45.120')
# ASCII only. Ask a PE over SSH who it is: BUILD_TAG + version + NIC count.
$keySrc = 'D:\QoderProject\国内版\生成winpe\overlay\Scripts\ssh_login_key'
if (-not (Test-Path -LiteralPath $keySrc)) { Write-Host "NO_KEY: $keySrc"; exit 1 }
# A fixed temp name got stuck once (read-only ACL + access denied), so use a per-process name.
$keyTmp = Join-Path $env:TEMP ('winpe10_probe_key_' + $PID)
if (Test-Path -LiteralPath $keyTmp) { Remove-Item -LiteralPath $keyTmp -Force }
Copy-Item -LiteralPath $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r ("${env:USERNAME}:R") | Out-Null
$ssh = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $ssh)) { $ssh = 'ssh' }
$sshArgs = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
             '-o', 'ConnectTimeout=8', '-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR',
             'Administrator@' + $IP)
foreach ($c in @('type X:\BUILD_TAG.txt', 'ver', 'echo ---- & dir X:\Windows\System32\niccheck.ps1 X:\Windows\System32\netdrvfix.cmd 2>&1', 'echo CONN_OK')) {
  Write-Host ('===== ' + $c + ' =====')
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & $ssh @sshArgs $c 2>&1 | ForEach-Object { "$_" } | Select-Object -First 45
  Write-Host ('(rc=' + $LASTEXITCODE + ')')
  $ErrorActionPreference = $prev
}
