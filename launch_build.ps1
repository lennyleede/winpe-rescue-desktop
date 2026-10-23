$Root = 'D:\QoderProject\国内版\生成winpe'
$log  = Join-Path $Root 'build\build_out.log'
$mark = Join-Path $Root 'build\BUILD_DONE.mark'
Remove-Item $mark -ErrorAction SilentlyContinue
Write-Host "启动管理员构建进程，请在弹出的 UAC 窗口点击[是] ..."
$cmdLine = '/c powershell -NoProfile -ExecutionPolicy Bypass -File "' + $Root + '\build.ps1" > "' + $log + '" 2>&1 & (echo finished) > "' + $mark + '"'
Start-Process cmd -Verb RunAs -Wait -ArgumentList $cmdLine
if (Test-Path $mark) { Write-Host 'BUILD_FINISHED' } else { Write-Host 'BUILD_MARK_MISSING (UAC 可能被取消)' }
