# pe10_ie8verify.ps1 —— 在 WinPE 里跑(由 33_HtaTypingDebug.ps1 -Phase ie8 下发)。
# 端到端验证降级后的桌面面板: 真鼠标点 #addr + 真按键 SendKeys, 结果写 X:\hta_selftest.log 回传。
# 只用镜像里那份 X:\Desktop\Desktop.hta 的原文, 改出来的副本落在 X:\Desktop\selftest.hta。
$ErrorActionPreference = 'Continue'
function T { (Get-Date).ToString('HH:mm:ss') }

Write-Output ('===== IE8 面板自测 ' + (T) + ' =====')
$src = 'X:\Desktop\Desktop.hta'
if (-not (Test-Path $src)) { Write-Output "!! 没有 $src"; exit 1 }
$raw = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
Write-Output ('Desktop.hta 字节=' + (Get-Item $src).Length + ' 行数=' + ($raw -split "`n").Count)

# 1) 镜像里的那份确实降到了 IE=8, 且带版本标记
$metaLine = (@($raw -split "`r?`n") | Where-Object { $_ -match 'x-ua-compatible' }) -join ' | '
Write-Output ('META: ' + $metaLine)
Write-Output ('MARKER v10-ie8 = ' + ($(if ($raw -match 'v10-ie8') { 'yes' } else { 'NO(镜像还是旧的)' })))
Write-Output ('DOCMode8 meta = ' + ($(if ($metaLine -match 'IE=8') { 'yes' } else { 'NO' })))

# 2) 注入自测脚本(改应用名避免 SINGLEINSTANCE 抢已有窗口)
$inject = @'

/* ---- 自测注入(由 pe10_ie8verify.ps1 加, 不进镜像) ---- */
var ST = new ActiveXObject("Scripting.FileSystemObject");
function stAsc(s){ var o="", i, c; s = "" + s;
  for (i = 0; i < s.length; i++) { c = s.charCodeAt(i); o += (c >= 32 && c <= 126) ? s.charAt(i) : "?"; } return o; }
var stBuf = [];
function stFlush(){ try { var f = ST.OpenTextFile("X:\\hta_selftest.log", 2, true); f.WriteLine(stAsc(stBuf.join("\r\n"))); f.Close(); } catch(e){} }
function stRect(){
  var e = document.getElementById("addr");
  var r = e.getBoundingClientRect();
  // IE8 的 getBoundingClientRect 只有 left/top/right/bottom, 没有 width/height(那是 IE9+), 直接用会 NaN
  var cx = Math.round((r.left + r.right) / 2) + (window.screenLeft || 0);
  var cy = Math.round((r.top + r.bottom) / 2) + (window.screenTop || 0);
  var f = ST.OpenTextFile("X:\\hta_selftest.rect.txt", 2, true); f.WriteLine(cx + " " + cy); f.Close();
  stBuf.push("rect addr = " + cx + "," + cy + " winOrigin=" + (window.screenLeft || 0) + "," + (window.screenTop || 0));
}
setTimeout(function(){
  document.onmousedown = function(){
    try { var t = event.srcElement;
      stBuf.push("mousedown -> " + (t.id ? ("#" + t.id) : t.tagName) + " client=" + event.clientX + "," + event.clientY +
                 " screen=" + (event.clientX + (window.screenLeft || 0)) + "," + (event.clientY + (window.screenTop || 0)));
    } catch(e){ stBuf.push("mousedown 读不到 srcElement"); }
    stFlush();
  };
  stBuf.push("docMode=" + document.documentMode + "  ua=" + navigator.appVersion);
  stBuf.push("css rgba/gradient in IE8 mode: btn bg = " + document.getElementById("addr").currentStyle.backgroundColor);
  openFrp();
  setTimeout(stRect, 1200);
  setTimeout(function(){
    var e = document.getElementById("addr");
    e.value = ""; e.focus();
    stBuf.push("focus() -> active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "null"));
    stFlush();
  }, 2600);
  // 4.2s 先把焦点丢掉, 这样 5.5s 外部真鼠标点击之后 active 是不是 addr 才有意义
  setTimeout(function(){
    try { document.getElementById("addr").blur(); } catch(b1){}
    try { document.getElementById("addr").value = ""; } catch(b2){}
    stBuf.push("blurred -> active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "null"));
    stFlush();
  }, 4200);
  // 5.5s 时外部 PowerShell 用真鼠标点 addr; 这里只看它有没有把焦点拿到
  setTimeout(function(){
    stBuf.push("after real click -> active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "null"));
    stFlush();
  }, 7200);
  setTimeout(function(){
    var e = document.getElementById("addr");
    try { new ActiveXObject("WScript.Shell").SendKeys("frp.example.com"); } catch(ek){ stBuf.push("SendKeys err " + ek.message); }
  }, 8000);
  setTimeout(function(){
    var v = document.getElementById("addr").value;
    stBuf.push("addr value = [" + v + "]");
    stBuf.push("TYPING = " + (v == "frp.example.com" ? "PASS" : "FAIL"));
    stBuf.push("panel version = " + document.getElementById("sub").innerHTML);
    stFlush();
    try { window.close(); } catch(e){}
  }, 11500);
}, 1500);
'@
$st = $raw -replace 'ID="WinPEDesktop"', 'ID="WinPEDesktopST"' -replace 'APPLICATIONNAME="WinPE Rescue Desktop"', 'APPLICATIONNAME="WinPE Rescue Desktop ST"'
$st = $st -replace '</script>', ($inject + '</script>')
if ($st -notmatch 'WinPEDesktopST') { Write-Output '!! 注入失败(没找到锚点), 不自测'; exit 1 }
[IO.File]::WriteAllBytes('X:\Desktop\selftest.hta', [byte[]](0xEF,0xBB,0xBF) + [Text.Encoding]::UTF8.GetBytes($st))
Remove-Item X:\hta_selftest.log, X:\hta_selftest.rect.txt -Force -EA SilentlyContinue
Write-Output ('selftest.hta = ' + (Get-Item 'X:\Desktop\selftest.hta').Length + ' 字节')

# 3) 起窗口, 中途用真鼠标点输入框(证明不是只靠 focus())
Add-Type -Namespace H -Name M -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern void mouse_event(int flags, int dx, int dy, int data, int extra);' -EA SilentlyContinue
# 开机自启的真面板也是 mshta 窗口, 它会压在自测窗口下面把点击吃掉 -> 先关掉, 测完再拉回来
$old = @(Get-Process mshta -EA SilentlyContinue)
if ($old.Count) { $old | ForEach-Object { Stop-Process -Id $_.Id -Force -EA SilentlyContinue }; Start-Sleep -Seconds 2; Write-Output ('  先关掉已有的 mshta 窗口 ' + $old.Count + ' 个') }
$p = Start-Process -FilePath X:\Windows\System32\mshta.exe -ArgumentList 'X:\Desktop\selftest.hta' -PassThru
Start-Sleep -Seconds 5
$rp = 'X:\hta_selftest.rect.txt'
if (Test-Path $rp) {
  $xy = ((Get-Content $rp -EA SilentlyContinue) -join '').Trim() -split '\s+'
  if ($xy.Count -ge 2 -and $xy[0] -match '^\d+$') {
    Write-Output ('  真鼠标点击 ' + $xy[0] + ',' + $xy[1] + ' (两下)')
    foreach ($round in 1..2) {
      [H.M]::SetCursorPos([int]$xy[0], [int]$xy[1]) | Out-Null
      Start-Sleep -Milliseconds 250
      [H.M]::mouse_event(0x0002, 0, 0, 0, 0); [H.M]::mouse_event(0x0004, 0, 0, 0, 0)
      Start-Sleep -Milliseconds 500
    }
  } else { Write-Output '  !! rect 文件内容异常: ' $xy }
} else { Write-Output '  !! 没有 rect 文件(页面可能根本没起来)' }
Start-Sleep -Seconds 8
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }

Write-Output '---------- X:\hta_selftest.log ----------'
if (Test-Path 'X:\hta_selftest.log') { Get-Content 'X:\hta_selftest.log' } else { Write-Output '(空 —— 页面没跑起来或脚本被语法挡住)' }
Write-Output '---------- 收尾 ----------'
Remove-Item X:\Desktop\selftest.hta -Force -EA SilentlyContinue
try { Start-Process -FilePath X:\Windows\System32\mshta.exe -ArgumentList 'X:\Desktop\Desktop.hta' | Out-Null; Write-Output '  已把真桌面面板重新拉起' } catch { Write-Output ('  !! 重新拉起面板失败: ' + $_.Exception.Message) }
Write-Output ('done ' + (T))
