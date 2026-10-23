# ASCII only. Elevate once, run 30_BootAndVerifyWinPe10.ps1, drop a mark file when it exits.
$Root = 'D:\QoderProject\国内版\生成winpe'
$Script = Join-Path $Root 'test\30_BootAndVerifyWinPe10.ps1'
$Log  = Join-Path $Root 'test\vm10_console.log'
$Mark = Join-Path $Root 'test\vm10_run.mark'
Remove-Item -LiteralPath $Mark -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $Log) { Remove-Item -LiteralPath $Log -Force }
$inner = '/c powershell -NoProfile -ExecutionPolicy Bypass -File "' + $Script + '" > "' + $Log + '" 2>&1 & (echo done) > "' + $Mark + '"'
Write-Host 'UAC: click Yes once. The run takes up to ~20 min (two boot rounds).'
Start-Process cmd -Verb RunAs -ArgumentList $inner
Start-Sleep 3
Write-Host ('launched. log=' + $Log + ' mark=' + $Mark)
