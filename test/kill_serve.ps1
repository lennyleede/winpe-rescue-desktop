# 停掉本机在跑的 test\host_serve.ps1 / host_cmd.ps1 微型服务(按命令行匹配, 不动其它 powershell)
param([string]$Match = 'host_serve.ps1|host_cmd.ps1')
$me = $PID
$procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.ProcessId -ne $me -and $_.CommandLine -match $Match }
if (-not $procs) { Write-Host 'NO-PROCESS'; exit 0 }
foreach ($p in $procs) {
  Write-Host ('STOP ' + $p.ProcessId + ' :: ' + $p.CommandLine)
  Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
}
