# Run a local ASCII PS script inside the VM's Windows over ssh by piping it to stdin
# (powershell -Command -). Chosen over -EncodedCommand because the base64 round trip got
# one character mangled in transit (CLIXML/encoding noise); an ASCII script through stdin
# is byte-stable under cp936. Output comes back on stdout as-is.
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_run_stdin.ps1 -Local build\scratch\t_x.ps1
param(
  [Parameter(Mandatory)][string]$Local,
  [string]$Target = 'administrator@192.168.0.100',
  [int]$Port = 22
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Local)) { Write-Host "not found: $Local" -ForegroundColor Red; exit 1 }
$text = Get-Content -LiteralPath $Local -Raw
if ($text -match '[^\x00-\x7F]') { Write-Host 'script is not pure ASCII, refuse (use bom_fix first)' -ForegroundColor Red; exit 1 }
$guard = "`$ProgressPreference='SilentlyContinue'; `$ErrorActionPreference='Continue'; `$OutputEncoding=[Console]::OutputEncoding=[Text.Encoding]::ASCII"
# -Command - : read the script from stdin; prefix a guard line first (progress noise off,
# stdout pinned to ASCII so KEY=value evidence lines survive the ssh hop unmangled).
($guard + "`r`n" + $text) | & ssh -o StrictHostKeyChecking=accept-new -p $Port $Target 'powershell -NoProfile -ExecutionPolicy Bypass -Command -'
exit $LASTEXITCODE
