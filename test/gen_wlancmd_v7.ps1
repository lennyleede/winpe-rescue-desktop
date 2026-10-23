# 生成 overlay\Scripts\wlan.cmd v7 (GBK + CRLF): 用镜像注入的 wlansvc + 自研 wifi.exe
# PE 里没有 netsh 的 wlan 插件也没有 sc.exe, 服务启停与连接全部走 wifi.exe
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Proj = Split-Path -Parent $Root
$Target = Join-Path $Proj 'overlay\Scripts\wlan.cmd'
$Bak = Join-Path $Proj 'overlay\Scripts\wlan.cmd.bak16'
if (Test-Path $Target) { Copy-Item $Target $Bak -Force }

$text = @'
@echo off
rem ===== WLAN v7: 镜像内注入的 wlansvc/wcmsvc + 自研 wifi.exe (直调 wlanapi) =====
rem 能不能连上取决于这块无线网卡的厂商驱动在不在镜像里(harvest_wifi_drivers.ps1 采集 -> overlay\Drivers\wifi)
rem 没有 WiFi 也能联网: 手机开"USB 网络共享"插 USB, 或插 USB/有线网卡(RNDIS/usbnet 驱动已在镜像内)
set WIFI=X:\Windows\System32\wifi.exe
set CONF=X:\Desktop\Wlan\wifi.conf
if not exist "%WIFI%" goto :no_tool

echo [wlan] ===== 启动 WiFi 相关服务 =====
"%WIFI%" svc start wcmsvc
"%WIFI%" svc start wlansvc
ping -n 4 127.0.0.1 >nul
"%WIFI%" svc info wlansvc
"%WIFI%" status

if /i "%1"=="silent" goto :auto
if /i "%1"=="auto" goto :auto
goto :menu

:auto
rem 开机自动连: 把 X:\Desktop\Wlan\wifi.conf 写成两行 SSID=xxx / KEY=xxx
if not exist "%CONF%" goto :eof
set SSID=
set KEY=
for /f "usebackq tokens=1,* delims==" %%a in ("%CONF%") do (
  if /i "%%a"=="SSID" set SSID=%%b
  if /i "%%a"=="KEY" set KEY=%%b
)
if not defined SSID goto :eof
echo [wlan] 自动连接 %SSID%
"%WIFI%" connect "%SSID%" "%KEY%"
ipconfig /renew * >nul 2>&1
goto :eof

:menu
echo.
echo ============ WiFi 操作 ============
echo   1  扫描热点
echo   2  连接(输入 SSID 与密码)
echo   3  断开当前连接
echo   4  查看无线接口状态
echo   5  wlansvc 依赖链诊断
echo   6  按 wifi.conf 里的配置连接
echo   0  退出
set OP=
set /p OP=选择: 
if "%OP%"=="1" goto :do_scan
if "%OP%"=="2" goto :do_connect
if "%OP%"=="3" goto :do_drop
if "%OP%"=="4" goto :do_status
if "%OP%"=="5" goto :do_deps
if "%OP%"=="6" goto :auto
if "%OP%"=="0" goto :eof
goto :menu

:do_scan
"%WIFI%" scan
goto :menu

:do_connect
set S=
set /p S=SSID: 
set K=
set /p K=密码(开放网络直接回车): 
"%WIFI%" connect "%S%" "%K%"
ipconfig /renew * >nul 2>&1
goto :menu

:do_drop
"%WIFI%" disconnect
goto :menu

:do_status
"%WIFI%" status
goto :menu

:do_deps
"%WIFI%" deps wlansvc
goto :menu

:no_tool
echo [wlan] 镜像里没有 wifi.exe, WiFi 客户端不可用。
echo [wlan] 兜底: 手机开"USB 网络共享"插 USB, 或插 USB/有线网卡(镜像已带 RNDIS/usbnet 驱动)。
if /i "%1"=="silent" exit /b 1
pause
'@

$gbk = [Text.Encoding]::GetEncoding(936)
$bytes = $gbk.GetBytes($text.Replace("`r`n", "`n").Replace("`n", "`r`n"))
if ($bytes[$bytes.Length - 2] -ne 13 -or $bytes[$bytes.Length - 1] -ne 10) { $bytes = $bytes + [byte[]](13, 10) }
[IO.File]::WriteAllBytes($Target, $bytes)

$check = [IO.File]::ReadAllBytes($Target)
$crlf = 0; $loneLf = 0
for ($i = 0; $i -lt $check.Length; $i++) {
  if ($check[$i] -eq 10) { if ($i -gt 0 -and $check[$i - 1] -eq 13) { $crlf++ } else { $loneLf++ } }
}
Write-Host ('字节数={0} CRLF={1} 裸LF={2}' -f $check.Length, $crlf, $loneLf)
if ($loneLf -ne 0) { Write-Host '!! 存在裸 LF, 编码不合格' -ForegroundColor Red; exit 1 }
Write-Host ('GBK 回读首行: ' + ($gbk.GetString($check) -split "`r`n")[0])
if (Test-Path $Bak) { Write-Host "备份: $Bak" }
