@echo off
rem ===== frps 服务端手动启动（在 PE 内提供 frp 服务） =====
cd /d X:\Desktop\Frp
echo.
echo  将在本机 7000 端口启动 frps（配置见 frps.toml）。
echo.
set GO=
set /p GO=确认启动 frps？(y/N)
if /i not "%GO%"=="y" exit /b
frps.exe -c frps.toml
pause
