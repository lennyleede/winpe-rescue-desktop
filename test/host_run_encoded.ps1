# Run a local PS script inside a REMOTE PowerShell via -EncodedCommand (single round trip).
# Why: the VM's Windows sshd default shell is PowerShell and has no cmd-style staging like PE;
# base64 of UTF-16LE survives Git Bash (no literal $ on the command line) and 32K CreateProcess
# limits. Script text must be ASCII-safe in its OUTPUT (stdout comes back as-is).
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_run_encoded.ps1 -Local build\scratch\t_x.ps1
param(
  [Parameter(Mandatory)][string]$Local,
  [string]$Target = 'administrator@192.168.0.100',
  [int]$Port = 22
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Local)) { Write-Host "找不到 $Local" -ForegroundColor Red; exit 1 }
$text = Get-Content -LiteralPath $Local -Raw
$text = $text -replace "`uFEFF", ''
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text))
if ($b64.Length -gt 26000) { Write-Host ('脚本太长: base64=' + $b64.Length + ' (上限约 26000)') -ForegroundColor Red; exit 1 }
$cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64
& ssh -p $Port $Target $cmd
exit $LASTEXITCODE
