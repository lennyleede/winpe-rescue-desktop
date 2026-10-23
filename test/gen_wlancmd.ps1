# 重新生成 overlay\Scripts\wlan.cmd (GBK + CRLF): PE 无 sc/netsh-wlan, 改用注册表 + net start
$lines = @(
  '@echo off',
  'rem ===== WLAN 尽力而为脚本 (WinPE 官方不支持 WiFi; 服务由构建时离线注入注册表) =====',
  'rem PE 内没有 sc.exe, 用注册表判断服务是否已注入, 用 net start 拉起',
  'set SVCOK=',
  'reg query "HKLM\SYSTEM\CurrentControlSet\Services\wlansvc" /v ErrorControl >nul 2>&1',
  'if errorlevel 1 (',
  '  echo [wlan] wlansvc 未注册或缺 ErrorControl, 跳过 (构建时注册表注入未生效?)',
  '  if /i "%1"=="silent" exit /b 1',
  '  goto :manual_help',
  ')',
  'net start wlansvc',
  'ping -n 5 127.0.0.1 >nul',
  'if /i "%1"=="silent" exit /b 0',
  '',
  ':manual_help',
  'echo ============ WiFi 手动连接 ============',
  'echo PE 未内置无线网络客户端 API (缺 wlanapi.dll/wlanext.exe), 命令行可能不可用:',
  'echo   netsh wlan show interfaces',
  'echo 若上面报 "函数未实现", 说明该 WinPE 组件缺失, 只能走有线/USB 网卡或换用带 WiFi 组件的 PE.',
  'echo.',
  'echo 连接步骤:',
  'echo   1. 编辑 X:\Desktop\Wlan\profile.xml 填入 SSID 与密码',
  'echo   2. netsh wlan add profile filename="X:\Desktop\Wlan\profile.xml"',
  'echo   3. netsh wlan connect name=PEWIFI',
  'echo   4. ipconfig 确认获取地址',
  'echo.',
  'set GO=',
  'set /p GO=现在按模板 profile.xml 尝试连接？(y/N)',
  'if /i "%GO%"=="y" (',
  '  netsh wlan add profile filename="X:\Desktop\Wlan\profile.xml"',
  '  netsh wlan connect name=PEWIFI',
  ')',
  'pause',
  ''
)
$target = Join-Path $PSScriptRoot '..\overlay\Scripts\wlan.cmd'
$text = ($lines -join "`r`n")
[IO.File]::WriteAllBytes($target, [Text.Encoding]::GetEncoding(936).GetBytes($text))
'written: ' + $target + ' (' + (Get-Item $target).Length + ' bytes, GBK+CRLF)'
