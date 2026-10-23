@echo off
rem ===== startnet v8 =====
rem 开机自启: wpeinit -> pe-sshd(SSH 服务端) -> 向日葵 SOS -> wifi(尽力) -> HTA 桌面
rem frpc 不再自启: 桌面起来后在 "FRP frp 穿透" 面板里填服务器并手动启动
set LOG=X:\boot.log
set STATUS=X:\status.txt
echo ==== startnet v8 begin ==== > %LOG%
echo # startnet autostart record > %STATUS%
wpeinit.exe >> %LOG% 2>&1
echo [1] wpeinit err=%errorlevel% >> %LOG%
ping -n 4 127.0.0.1 >nul
ipconfig /all >> %LOG% 2>&1
rem ---------- [1a] NIC self-heal: WinPE PnP often leaves the adapter unbound (code 18/28) ----------
rem drvload is the documented WinPE fallback. netdrvfix reads X:\Windows\System32\netdrv_index.txt
rem (generated at image build time) and loads the matching package from the DriverStore.
rem Log: X:\netdrvfix.log   ASCII only here: this file is stored as GBK for cmd.exe.
if exist "X:\Windows\System32\netdrvfix.cmd" (
  call X:\Windows\System32\netdrvfix.cmd >> %LOG% 2>&1
  echo [1a] netdrvfix attempted >> %LOG%
  echo netdrvfix=attempted >> %STATUS%
  ping -n 6 127.0.0.1 >nul
  ipconfig >> %LOG% 2>&1
) else (
  echo [1a] netdrvfix.cmd NOT found >> %LOG%
  echo netdrvfix=missing >> %STATUS%
)

rem ---------- [1b] 防火墙: 彻底关闭 ----------
rem 离线注册表已把 MpsSvc 设为禁用(fw-offline.ps1); 这里再用 COM 把三个 profile 置 False 兜一层。
rem 实测: 零允许规则下写 FirewallEnabled=False 约 4 秒, 主机即可 ping 通并拿到 SSH banner。
if exist "X:\Windows\System32\fw_off.ps1" (
  X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\fw_off.ps1 >> %LOG% 2>&1
) else (
  echo [1b] fw_off.ps1 NOT found >> %LOG%
)
echo [1b] fw_off attempted (详情 X:\fw_off.log, 结论 X:\status.txt 里 fw_off=) >> %LOG%

rem ---------- [2] SSH 服务端: 自研 pe-sshd ----------
rem Win32-OpenSSH 的 sshd 在 WinPE 里 privsep 子进程必然 0xC0000142(实测十余次验证),
rem 所以服务端换成 Go 静态编译的 pe-sshd(单文件, 无 DLL/无 Windows 认证依赖), X:\OpenSSH 只放客户端。
rem 默认(救援场景可直接登): -empty=true, 空密码/无凭证也能登录, 同时接受 X:\SSH\authorized_keys 里的公钥;
rem 首次运行在 X: 内存盘生成主机密钥。
rem 要收紧: 在本行 start 参数里追加  -empty=false -pass 你的口令   之后只有该口令或公钥持有人能登录。
set SSHDIR=X:\SSH
if exist "%SSHDIR%\pe-sshd.exe" (
  start "" /b "%SSHDIR%\pe-sshd.exe" -addr 0.0.0.0:22 -hostkey %SSHDIR%\pe_host_ed25519 -authkeys %SSHDIR%\authorized_keys -log X:\sshd.log
  echo [2] pe-sshd started >> %LOG%
  echo pe-sshd.exe=started >> %STATUS%
) else (
  echo [2] pe-sshd NOT found >> %LOG%
  echo pe-sshd.exe=missing >> %STATUS%
)

rem ---------- [3] frp 客户端: 不自启(用户要求) ----------
rem frpc.exe/frpc.toml 仍在 X:\Desktop\Frp, 桌面面板保存配置后手动启动, 日志 X:\frpc.log。
rem 不在这里启动的原因: 救援现场服务器地址/令牌每次都可能不同, 自启会用错配置反复重连。
if exist "X:\Desktop\Frp\frpc.exe" (
  echo [3] frpc present, autostart disabled - start it from the desktop FRP panel >> %LOG%
  echo frpc.exe=manual >> %STATUS%
) else (
  echo [3] frpc NOT found >> %LOG%
  echo frpc.exe=missing >> %STATUS%
)

rem ---------- [4] 向日葵 SOS ----------
if exist "X:\Sunlogin\SunloginSOS.exe" (
  pushd X:\Sunlogin
  start "" X:\Sunlogin\SunloginSOS.exe
  popd
  echo [4] sunlogin launched >> %LOG%
  echo sunloginsos.exe=started >> %STATUS%
) else (
  echo [4] sunlogin NOT found >> %LOG%
  echo sunloginsos.exe=missing >> %STATUS%
)

rem ---------- [5] WiFi: 有 wlan.conf 时自动连(没驱动/没网卡就跳过) ----------
call X:\Windows\System32\wlan.cmd silent >> %LOG% 2>&1
echo [5] wlan done err=%errorlevel% >> %LOG%

rem ---------- [6] WMI 服务: 桌面状态灯和 pe_report.ps1 都要用 ----------
rem WinPE 里 Winmgmt 默认不自启; 起不来也不要紧, 桌面会退回读 X:\status.txt 和 boot.log 显示状态。
net start Winmgmt >> %LOG% 2>&1
if errorlevel 1 (
  sc config Winmgmt start= auto >> %LOG% 2>&1
  sc start Winmgmt >> %LOG% 2>&1
)
ping -n 5 127.0.0.1 >nul
echo [6] winmgmt tried >> %LOG%

rem ---------- [7] 桌面 ----------
if exist "X:\Desktop\Desktop.hta" (
  start "WinPEDesktop" X:\Windows\System32\mshta.exe X:\Desktop\Desktop.hta
  echo [7] desktop launched >> %LOG%
  ping -n 8 127.0.0.1 >nul
  if exist "X:\Windows\System32\mshta.exe" exit /b 0
)
echo [7] fallback to cmd >> %LOG%
cmd.exe
