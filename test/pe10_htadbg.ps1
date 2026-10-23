# pe10_htadbg.ps1 —— 在 WinPE 里跑(由 33_HtaTypingDebug.ps1 下发)。取证 frp 面板"打字没反应"。
# 只做只读检查 + 起一个 120 秒的采样器进程, 不写注册表、不改镜像里的任何文件。
$ErrorActionPreference = 'Continue'
function T { (Get-Date).ToString('HH:mm:ss.fff') }
Write-Output ('===== frp 面板打字无响应 取证 ' + (T) + ' =====')

$htaImg = 'X:\Desktop\Desktop.hta'
if (Test-Path $htaImg) {
  $h = (Get-FileHash -Path $htaImg -Algorithm SHA256 -EA SilentlyContinue).Hash
  $i = Get-Item $htaImg
  Write-Output ('镜像里的 Desktop.hta: size=' + $i.Length + ' sha256=' + $h + ' mtime=' + $i.LastWriteTime)
} else { Write-Output '!! 镜像里没有 X:\Desktop\Desktop.hta' }
Write-Output ('mshta 版本 = ' + (Get-Item X:\Windows\System32\mshta.exe -EA SilentlyContinue).VersionInfo.ProductVersion)
Write-Output ('ie 引擎版本 = ' + $(try { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -EA Stop).svcVersion } catch { '读不到' }))

$ms = @(Get-Process -Name mshta -EA SilentlyContinue)
Write-Output ('mshta 进程数 = ' + $ms.Count)
foreach ($p in $ms) {
  Write-Output ('  pid=' + $p.Id + ' 主窗口=0x' + ('{0:X}' -f [int64]$p.MainWindowHandle) + ' 标题="' + $p.MainWindowTitle +
                '" Responding=' + $p.Responding + ' 启动=' + $p.StartTime.ToString('HH:mm:ss') + ' 内存=' + [int]($p.WorkingSet64 / 1MB) + 'MB')
}
$wf = @(Get-Process -Name WerFault -EA SilentlyContinue)
Write-Output ('WerFault 个数 = ' + $wf.Count)

# WMI 每 3 秒同步查一次是 HTA 界面卡死的最常见原因, 量一下在 PE 里到底多慢
Write-Output '--- WMI 同步查询耗时(HTA 的 refresh 每 3 秒就这么调两次) ---'
$loc = New-Object -ComObject WbemScripting.SWbemLocator
$svc = $loc.ConnectServer('127.0.0.1', 'root\cimv2')
foreach ($q in @('SELECT Name FROM Win32_Process', 'SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True')) {
  $t0 = Get-Date
  $rows = $svc.ExecQuery($q)
  $n = $rows.Count
  Write-Output ('  ' + [int]((Get-Date).Subtract($t0).TotalMilliseconds) + ' ms  ' + $q + ' -> ' + $n + ' 行')
}

# 采样器: 120 秒, 每 250ms 记一次 前台窗口属主 + mshta 是否响应(Responding=false 就是 UI 线程被占着,
# 这段时间里的按键会被系统丢掉 -> 表现就是"打字没反应")
$sampler = @'
$ErrorActionPreference = "Continue"
Add-Type -Namespace F -Name G -MemberDefinition "[DllImport(""user32.dll"")] public static extern IntPtr GetForegroundWindow();
[DllImport(""user32.dll"")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport(""user32.dll"")] public static extern short GetAsyncKeyState(int vk);"
$out = "X:\fg.log"
$lines = @()
$lastFg = ""
# 扫键: 把 A-Z 0-9 Backspace Space . , - @ / 的虚拟键码轮一遍, 只要某次采样相对上次"由松变按"就算一次按键。
# 这是为了分清楚: 按键到底有没有送达这个 VM 会话(Hyper-V 控制台键盘链路), 还是送达了但输入框不吃。
$vks = @()
foreach ($c in ([char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')) { $vks += [int]$c }
foreach ($c in ([char[]]" .,-@/")) { $vks += [int]$c }
$vks += 8; $vks += 9; $vks += 13; $vks += 27; $vks += 45; $vks += 46
$down = @{}
foreach ($v in $vks) { $down[[int]$v] = $false }
$keys = 0
$dl = (Get-Date).AddSeconds(120)
$round = 0
while ((Get-Date) -lt $dl) {
  $round++
  $hwnd = [F.G]::GetForegroundWindow()
  $p = [uint32]0
  [void][F.G]::GetWindowThreadProcessId($hwnd, [ref]$p)
  $nm = ""
  if ($p -gt 0) { $nm = (Get-Process -Id ([int]$p) -EA SilentlyContinue).ProcessName }
  $ms = @(Get-Process -Name mshta -EA SilentlyContinue)
  $resp = if ($ms.Count) { ($ms | ForEach-Object { $_.Responding }) -join "/" } else { "no-mshta" }
  $cur = "fg pid=" + $p + "(" + $nm + ") hwnd=0x" + ("{0:X}" -f [int64]$hwnd)
  if ($cur -ne $lastFg) { $lines += ((Get-Date).ToString("HH:mm:ss.fff") + " 前台切换 -> " + $cur + "  mshta.Responding=" + $resp); $lastFg = $cur }
  if ($resp -match "False") { $lines += ((Get-Date).ToString("HH:mm:ss.fff") + " mshta UI 线程不响应 Responding=" + $resp) }
  foreach ($v in $vks) {
    $st = [F.G]::GetAsyncKeyState($v)
    $now = (([int]$st -band 0x8000) -ne 0)
    if ($now -and -not $down[[int]$v]) {
      $down[[int]$v] = $true
      $keys++
      $ch = ""
      if ($v -ge 65 -and $v -le 90) { $ch = [string][char]$v } elseif ($v -ge 48 -and $v -le 57) { $ch = [string][char]$v }
      $lines += ((Get-Date).ToString("HH:mm:ss.fff") + " 按键 vk=" + $v + " [" + $ch + "] 前台=" + $nm + " 累计=" + $keys)
    } elseif (-not $now) { $down[[int]$v] = $false }
  }
  if ($round % 40 -eq 0) { [IO.File]::WriteAllLines($out, $lines) }
  Start-Sleep -Milliseconds 120
}
$lines += ("结束: 共采到按键 " + $keys + " 次, 采样 " + $round + " 轮")
[IO.File]::WriteAllLines($out, $lines)
'@
[IO.File]::WriteAllText('X:\fgs.ps1', $sampler, [Text.Encoding]::UTF8)
try {
  Start-Process -FilePath 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','X:\fgs.ps1' -WindowStyle Hidden | Out-Null
  Write-Output '采样器已启动(X:\fg.log, 120 秒) —— 这期间请到 frp 面板里连续打字'
} catch { Write-Output ('采样器启动失败: ' + $_.Exception.Message) }

# 再起一个自带记时日志的最小 HTA: 它把每一次 keydown/keyup 和当时的 value 写进 X:\kbtest.log。
# 这是"输入框吃不吃字"的 A/B 对照 —— 同一个 mshta 引擎、同样一个 input, 只是没有 3 秒定时器和别的层。
$kb = @'
<!DOCTYPE html><html><head>
<meta http-equiv="x-ua-compatible" content="ie=edge" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<HTA:APPLICATION ID="kbtest" APPLICATIONNAME="kbtest" BORDER="dialog" SCROLL="no" CONTEXTMENU="no" />
<title>键盘链路测试</title></head>
<body style="font-family:'Microsoft YaHei',sans-serif; background:#0b1626; color:#eaf4ff; padding:14px">
<h3 style="margin:0 0 8px 0">键盘链路测试(与救援桌面同一个 mshta 引擎)</h3>
<div style="font-size:13px;margin-bottom:8px">在下面这个框里连续打字, 中英文、数字、退格都试:</div>
<input id="t1" type="text" style="width:96%;font-size:16px;padding:6px" onfocus="log('focus t1')"
       onkeydown="log('keydown key=['+event.key+'] code='+event.keyCode)"
       onkeyup="log('keyup value=['+this.value+'] active='+(document.activeElement ? document.activeElement.id : '?'))" />
<div id="st" style="font-size:12px;margin-top:10px;color:#9dc4ee">等待按键...</div>
<script>
var fso = new ActiveXObject('Scripting.FileSystemObject');
var kbuf = [];
function log(s){
  // PE 里 OpenTextFile(路径, 8=追加, true) 建不出新文件, 一律走 2=覆盖 + 内存缓冲
  try { kbuf.push(new Date().toLocaleTimeString() + '  ' + s); var f = fso.OpenTextFile('X:\\kbtest.log', 2, true); f.WriteLine(kbuf.join('\r\n')); f.Close(); } catch(e){}
  document.getElementById('st').innerText = s;
}
log('kbtest 启动');
</script>
</body></html>
'@
[IO.File]::WriteAllBytes('X:\kbtest.hta', [byte[]](0xEF,0xBB,0xBF) + [Text.Encoding]::UTF8.GetBytes($kb))
try {
  Start-Process -FilePath 'X:\Windows\System32\mshta.exe' -ArgumentList 'X:\kbtest.hta' | Out-Null
  Write-Output '已另开一个最小测试窗口 X:\kbtest.hta(它自己把每次按键写进 X:\kbtest.log) —— 请在里面也打字'
} catch { Write-Output ('测试窗口启动失败: ' + $_.Exception.Message) }
Write-Output ('===== 取证结束 ' + (T) + ' =====')
