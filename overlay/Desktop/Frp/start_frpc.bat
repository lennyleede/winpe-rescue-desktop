@echo off
rem ===== frpc 客户端手动启动 =====
cd /d X:\Desktop\Frp
echo.
echo  请先确认 frpc.toml 中的 serverAddr 已填写为你的 frp 服务器地址。
echo  未配置可先编辑：notepad X:\Desktop\Frp\frpc.toml
echo.
set EDIT=
set /p EDIT=现在用记事本编辑 frpc.toml 吗？(y/N)
if /i "%EDIT%"=="y" start /wait notepad.exe X:\Desktop\Frp\frpc.toml
echo 启动 frpc（Ctrl+C 或关闭本窗口停止）...
frpc.exe -c frpc.toml
pause
