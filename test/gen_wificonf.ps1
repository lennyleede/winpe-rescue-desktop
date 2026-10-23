# 生成 overlay\Desktop\Wlan\wifi.conf (GBK + CRLF): wlan.cmd 开机自动连接用的模板
# 行首 ; 的会被 for /f 当注释跳过
$ErrorActionPreference = 'Stop'
$Proj = Split-Path -Parent $PSScriptRoot
$Target = Join-Path $Proj 'overlay\Desktop\Wlan\wifi.conf'
$text = @'
; ===== WiFi 开机自动连接配置 =====
; 填好下面两行(等号后不要加空格/引号), 重启进 PE 就会自动连接并 ipconfig /renew
; 密码里有 & " % ^ 等特殊字符时别用自动连接, 点桌面的 "WiFi 连接" 图标手输
; 前提: 这块无线网卡的驱动在镜像里(不连就先看 X:\boot.log 里 [5] 的输出)
SSID=
KEY=
'@
$gbk = [Text.Encoding]::GetEncoding(936)
$bytes = $gbk.GetBytes($text.Replace("`r`n", "`n").Replace("`n", "`r`n"))
if ($bytes[$bytes.Length - 2] -ne 13 -or $bytes[$bytes.Length - 1] -ne 10) { $bytes = $bytes + [byte[]](13, 10) }
[IO.File]::WriteAllBytes($Target, $bytes)
$lone = 0
for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -eq 10 -and ($i -eq 0 -or $bytes[$i - 1] -ne 13)) { $lone++ } }
Write-Host ('written: ' + $Target + ' bytes=' + $bytes.Length + ' loneLF=' + $lone)
