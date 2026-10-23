# pe10_focusprobe.ps1 —— 在 WinPE 里跑(由 33_HtaTypingDebug.ps1 -Phase focus 下发)。
# 已确认: 真实 Desktop.hta 的输入框拿不到焦点 —— 真鼠标 down/up 都命中输入框, focusin 却落到 HTML,
#   el.focus() 后 activeElement 仍是 null, 按键全落在文档上 => 用户看到的"打字没反应"。
# 前几轮的坑: (1) IE7/8 文档模式下 getBoundingClientRect 没有 width, 算出来的点击点飘了;
#             (2) 页面上的 CSS 能力探测一句抛异常就把后面的定时器全带走了。
# 这一轮判定不依赖鼠标坐标: 页面每 2 秒自己 el.focus() 一次并记录 activeElement, PS 负责置前 + 真按键。
# 变体: CTRL(无 x-ua-compatible, HTA 默认) / IE8 / IE9 / IE10 / EDGE, 只换文档模式, 页面结构完全相同。
$ErrorActionPreference = 'Continue'
function T { (Get-Date).ToString('HH:mm:ss.fff') }

Add-Type -Namespace K -Name K3 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
[DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
[DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
'@

function VkOf([string]$ch) {
  $code = [int][char]$ch.ToUpper()[0]
  if ($code -ge 65 -and $code -le 90) { return $code }
  if ($code -ge 48 -and $code -le 57) { return $code }
  if ($ch -eq '.') { return 190 }
  if ($ch -eq '-') { return 189 }
  if ($ch -eq ' ') { return 32 }
  return $null
}
function Type-Str([string]$s) {
  foreach ($ch in $s.ToCharArray()) {
    $vk = VkOf ([string]$ch)
    if ($null -eq $vk) { continue }
    [K.K3]::keybd_event([byte]$vk, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 45
    [K.K3]::keybd_event([byte]$vk, 0, 2, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 45
  }
}
function Fg-Who {
  $fh = [K.K3]::GetForegroundWindow()
  $fp = [uint32]0
  [void][K.K3]::GetWindowThreadProcessId($fh, [ref]$fp)
  $nm = (Get-Process -Id ([int]$fp) -EA SilentlyContinue).ProcessName
  return '0x' + ('{0:X}' -f [int64]$fh) + '(' + $nm + '/' + $fp + ')'
}

# 落盘文本一律过 asc(): PE 里 FSO 写含中文的字符串会抛异常(实测建出 0 字节文件)
function Hta-Text {
@'
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>fp</title>
<style>body{background:#0b1626;color:#eaf4ff;font-family:"Segoe UI",sans-serif;padding:16px;margin:0}
input{font-size:18px;width:220px;padding:5px;color:#000;background:#fff}</style>
</head>
<body>
<h3>MODE_TAG</h3>
<input id="t1" type="text" />
<script>
var pk = null, buf = [];
try { pk = new ActiveXObject("Scripting.FileSystemObject"); } catch(e) { buf.push("NO FSO"); }
function asc(s){
  s = (s === null || s === undefined) ? "?" : ("" + s);
  var o = "";
  for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); o += (c >= 32 && c <= 126) ? s.charAt(i) : "?"; }
  return o;
}
function dump(name, txt){ try { var f = pk.OpenTextFile(name, 2, true); f.WriteLine(asc(txt)); f.Close(); return true; } catch(e) { return false; } }
function klog(s, tag){
  try { buf.push(new Date().toLocaleTimeString() + " [" + asc(tag) + "] " + asc(s)); dump("X:\\fp_LOG.log", buf.join("\r\n")); } catch(e) {}
}
function actv(){ try { return document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "null"; } catch(e){ return "err"; } }
function nameOf(t){ try { return t ? (t.id ? ("#" + t.id) : t.tagName) : "?"; } catch(e){ return "ex"; } }
klog("script parsing ok", "boot");
document.onkeydown = function(){ try { klog("keyCode=" + event.keyCode + " target=" + nameOf(event.srcElement) + " active=" + actv(), "doc-key"); } catch(e){} };
document.onmousedown = function(){ try { klog("down on " + nameOf(event.srcElement) + " client=" + event.clientX + "," + event.clientY, "mouse"); } catch(e){} };
document.onfocusin = function(){ try { klog("in -> " + nameOf(event.srcElement), "focusin"); } catch(e){} };
var el1 = document.getElementById("t1");
if (el1) {
  el1.onfocus = function(){ klog("t1 focus event", "foc"); };
  el1.onkeydown = function(){ klog("t1 keydown keyCode=" + event.keyCode, "el-key"); };
  el1.onkeyup = function(){ klog("t1 keyup value=[" + asc(el1.value) + "]", "el-key"); };
} else { klog("NO #t1 element!", "boot"); }
function tryFocus(n){
  if (!el1) return;
  var before = actv();
  try { el1.focus(); } catch(e) { klog("focus() threw: " + asc(e && e.message), "jsf"); }
  klog("#" + n + " focus -> active=" + actv() + " (before=" + before + ") value=[" + asc(el1.value) + "]", "jsf");
}
var lastV = "";
function poll(){ var s = "t1=[" + asc(el1 ? el1.value : "NOEL") + "] active=" + actv(); if (s != lastV) { klog(s, "poll"); lastV = s; } }
setInterval(poll, 400);
setTimeout(function(){ tryFocus(1); }, 2000);
setTimeout(function(){ tryFocus(2); }, 4000);
setTimeout(function(){ tryFocus(3); }, 6000);
setTimeout(function(){ tryFocus(4); }, 8000);
setTimeout(function(){
  var info = "docMode=" + document.documentMode + " compat=" + document.compatMode + " active=" + actv();
  try { info += " origin=" + (window.screenLeft || 0) + "," + (window.screenTop || 0); } catch(e){}
  klog(info, "mode");
  var c = null;
  try {
    var r = el1.getBoundingClientRect();
    var w = (r.width && !isNaN(r.width)) ? r.width : (r.right - r.left);
    var hh = (r.height && !isNaN(r.height)) ? r.height : (r.bottom - r.top);
    var ox = (window.screenLeft || 0), oy = (window.screenTop || 0);
    c = { x: Math.round(r.left + w / 2) + ox, y: Math.round(r.top + hh / 2) + oy };
    dump("X:\\fp_LOG.rect.txt", c.x + " " + c.y);
    klog("t1 center=" + c.x + "," + c.y + " (w=" + w + " h=" + hh + " left=" + r.left + " top=" + r.top + ")", "rect");
  } catch(e) { klog("rect threw " + asc(e && e.message), "rect"); }
  var caps = [];
  try {
    var d = document.createElement("div"), cs = d.style;
    cs.backgroundImage = "linear-gradient(135deg,#2b7fd4,#1e5f8f)"; caps.push("gradient=" + !!cs.backgroundImage);
    cs.borderRadius = "9px"; caps.push("radius=" + !!cs.borderRadius);
    cs.backgroundColor = "rgba(8,16,30,0.58)"; caps.push("rgba=" + !!cs.backgroundColor);
    cs.boxShadow = "0 2px 8px rgba(0,0,0,.45)"; caps.push("shadow=" + !!cs.boxShadow);
  } catch(e) { caps.push("css探测异常"); }
  klog(caps.join(" "), "css");
}, 1200);
klog("script parsed to end", "boot");
</script>
</body></html>
'@
}

$Head = '<HTA:APPLICATION ID="fpID" APPLICATIONNAME="fpID" BORDER="dialog" SCROLL="no" CONTEXTMENU="no" SINGLEINSTANCE="no" />'
$variants = @(
  @{ Name='CTRL'; Tag='V1 HTA默认(无x-ua-compatible)'; Meta='' },
  @{ Name='IE8';  Tag='V2 IE=8';  Meta='<meta http-equiv="x-ua-compatible" content="IE=8" />' },
  @{ Name='IE9';  Tag='V3 IE=9';  Meta='<meta http-equiv="x-ua-compatible" content="IE=9" />' },
  @{ Name='IE10'; Tag='V4 IE=10'; Meta='<meta http-equiv="x-ua-compatible" content="IE=10" />' },
  @{ Name='EDGE'; Tag='V5 IE=edge'; Meta='<meta http-equiv="x-ua-compatible" content="ie=edge" />' }
)

$known = @(Get-Process -Name mshta -EA SilentlyContinue | ForEach-Object { $_.Id })
$verdict = @()
foreach ($v in $variants) {
  $file = 'X:\fp' + $v.Name + '.hta'
  $lf = 'X:\fp' + $v.Name + '.log'; $rf = 'X:\fp' + $v.Name + '.rect.txt'
  Write-Output ('##### ' + $v.Tag + ' -> ' + $file)
  $body = (Hta-Text).Replace('MODE_TAG', $v.Tag).Replace('fp_LOG', 'fp' + $v.Name)
  $html = '<!DOCTYPE html><html><head>' + "`r`n" + $Head.Replace('fpID', 'fp' + $v.Name) + "`r`n" + $v.Meta + "`r`n" + $body
  [IO.File]::WriteAllBytes($file, [byte[]](0xEF,0xBB,0xBF) + [Text.Encoding]::UTF8.GetBytes($html))
  foreach ($f in @($lf, $rf)) { if (Test-Path $f) { Remove-Item $f -Force -EA SilentlyContinue } }
  Start-Process -FilePath 'X:\Windows\System32\mshta.exe' -ArgumentList ('"' + $file + '"') | Out-Null
  $p = $null
  for ($k = 0; $k -lt 20; $k++) {
    Start-Sleep -Milliseconds 300
    $np = @(Get-Process -Name mshta -EA SilentlyContinue | Where-Object { $known -notcontains $_.Id -and $_.MainWindowHandle -ne 0 })
    if ($np.Count) { $p = $np[0]; break }
  }
  if (-not $p) { Write-Output '  !! 没起新 mshta 窗口'; $verdict += ($v.Name + ' 起不来'); continue }
  $h = $p.MainWindowHandle
  [void][K.K3]::BringWindowToTop($h)
  [void][K.K3]::SetForegroundWindow($h)
  Write-Output ('  pid=' + $p.Id + ' 置前 -> 前台=' + (Fg-Who))
  Start-Sleep -Milliseconds 700
  Write-Output '  [阶段1] 真按键 qrs (页面 2s 时会自己 focus t1)'
  Type-Str 'qrs'
  Start-Sleep -Milliseconds 1600
  Write-Output '  [阶段2] 真按键 tuv (对应页面 4s 的 focus)'
  Type-Str 'tuv'
  Start-Sleep -Milliseconds 1600
  Write-Output '  [阶段3] 真鼠标点 t1 中心 + 真按键 wxy'
  if (Test-Path $rf) {
    $xy = ((Get-Content $rf | Select-Object -First 1) -split '\s+')
    if ($xy.Count -ge 2 -and $xy[0] -match '^-?\d+$' -and $xy[1] -match '^-?\d+$') {
      [void][K.K3]::SetCursorPos([int]$xy[0], [int]$xy[1])
      Start-Sleep -Milliseconds 250
      [K.K3]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 90
      [K.K3]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 500
      Write-Output ('    点击 ' + $xy[0] + ',' + $xy[1] + ' 后按键 wxy')
      Type-Str 'wxy'
    } else { Write-Output ('    !! 坐标不合法: ' + ($xy -join ',')) }
  } else { Write-Output '    !! 没有 rect 文件' }
  Start-Sleep -Milliseconds 2500
  Write-Output '  ---- 日志 ----'
  $txt = ''
  if (Test-Path $lf) { $txt = (Get-Content $lf -Raw); ($txt -split '\r?\n') | Where-Object { $_ -ne '' } | ForEach-Object { Write-Output ('   ' + $_) } }
  else { Write-Output '   (无日志文件)' }
  $jsf = ($txt -match 'active=t1')
  $elkey = ($txt -match 't1 keydown')
  $eat = ($txt -match 't1=\[(qrs|tuv|wxy|q|t|w)')
  Write-Output ('  判定: focus()能拿到t1=' + $jsf + ' 元素收到按键=' + $elkey + ' 字符进框=' + $eat)
  $verdict += ($v.Name + '  focus=' + $jsf + ' keydown=' + $elkey + ' 吃字=' + $eat)
  try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch { }
  $known += $p.Id
  Start-Sleep -Milliseconds 600
}
Write-Output ''
Write-Output '===== 汇总 ====='
$verdict | ForEach-Object { Write-Output ('  ' + $_) }
Write-Output ('===== 结束 ' + (T) + ' =====')
