# 生成 startnet.cmd v7 (GBK + CRLF)
# 改动: [3] 去掉 findstr(PE 里没有这个命令, 之前是碰巧没报错); [5] WiFi 交给 wlan.cmd v7(wifi.exe)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Proj = Split-Path -Parent $Root
$Target = Join-Path $Proj 'overlay\Scripts\startnet.cmd'
$Bak = Join-Path $Proj 'overlay\Scripts\startnet.cmd.bak16'
Copy-Item $Target $Bak -Force

$text = @'
@echo off
rem ===== startnet v7: SSH(pe-sshd) + frp + Sunlogin + WiFi(wifi.exe) + Desktop HTA =====
set LOG=X:\boot.log
set PSX=X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
echo ==== startnet v7 begin ==== > %LOG%
wpeinit.exe >> %LOG% 2>&1
echo [1] wpeinit err=%errorlevel% >> %LOG%
ping -n 4 127.0.0.1 >nul
ipconfig /all >> %LOG% 2>&1

rem ---------- [2] SSH 服务端: 自研 pe-sshd ----------
rem Win32-OpenSSH 的 sshd 在 WinPE 里 privsep 子进程必然 0xC0000142(实机十四轮验证),
rem 所以服务端换成 Go 静态编译的 pe-sshd(与 frpc 同类型, 无 DLL/无 Windows 认证依赖), X:\OpenSSH 只留客户端。
rem 认证默认(救援盘优先可达): 空密码/无凭证就能登录, 名单内公钥也认; 主机密钥首次开机自动生成在 X: 内存盘。
rem 想收紧: 给下面 start 行的参数追加  -empty=false -pass 你的口令   之后只有该口令或名单公钥能连进来。
set SSHDIR=X:\SSH
if exist "%SSHDIR%\pe-sshd.exe" (
  start "" /b "%SSHDIR%\pe-sshd.exe" -addr 0.0.0.0:22 -hostkey %SSHDIR%\pe_host_ed25519 -authkeys %SSHDIR%\authorized_keys -log X:\sshd.log
  echo [2] pe-sshd started >> %LOG%
) else (
  echo [2] pe-sshd NOT found >> %LOG%
)

rem ---------- [3] frp 客户端(出站穿透, 无需入站规则) ----------
rem PE 里没有 findstr, 用 PowerShell 判断 frpc.toml 是否还是占位符; 只有明确返回 1 才跳过(宁可多试不误跳过)
if not exist "X:\Desktop\Frp\frpc.exe" (
  echo [3] frpc NOT found >> %LOG%
  goto :step4
)
"%PSX%" -NoProfile -EP Bypass -Command "exit ([int]((Get-Content -Raw 'X:\Desktop\Frp\frpc.toml') -match 'your-frp-server'))"
if %errorlevel%==1 (
  echo [3] frpc serverAddr 未配置, 跳过自启 >> %LOG%
  goto :step4
)
pushd X:\Desktop\Frp
start "" /b frpc.exe -c frpc.toml
popd
echo [3] frpc started >> %LOG%

rem ---------- [4] 向日葵 SOS ----------
:step4
if exist "X:\Sunlogin\SunloginSOS.exe" (
  pushd X:\Sunlogin
  start "" X:\Sunlogin\SunloginSOS.exe
  popd
  echo [4] sunlogin launched >> %LOG%
) else (
  echo [4] sunlogin NOT found >> %LOG%
)

rem ---------- [5] WiFi: 起 wlansvc 并按 wifi.conf 自动连(尽力而为) ----------
call X:\Windows\System32\wlan.cmd silent >> %LOG% 2>&1
echo [5] wlan done err=%errorlevel% >> %LOG%

rem ---------- [6] 桌面 ----------
if exist "X:\Desktop\Desktop.hta" (
  start "WinPEDesktop" X:\Windows\System32\mshta.exe X:\Desktop\Desktop.hta
  echo [6] desktop launched >> %LOG%
  ping -n 8 127.0.0.1 >nul
  if exist "X:\Windows\System32\mshta.exe" exit /b 0
)
echo [6] fallback to cmd >> %LOG%
cmd.exe
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
Write-Host "备份: $Bak"
