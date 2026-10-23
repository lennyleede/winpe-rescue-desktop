# pe10_kbprobe.ps1 —— 在 WinPE 里跑(由 33_HtaTypingDebug.ps1 -Phase probe 下发)。
# 目的: 不打扰人的情况下判定 frp 面板"打字没反应"到底卡在哪一环 ——
#   复制一份真实 Desktop.hta, 给四个输入框挂 keydown/keyup/focus 日志, 再从本机
#   用 SetForegroundWindow + SetCursorPos/mouse_event(真点击) + keybd_event(真按键)
#   把字符串打进去。日志会告诉我们是哪一段断的:
#     没有 focusin -> addr        => 鼠标点不到输入框(遮挡/层级问题)
#     有 keydown 但 value 一直空  => 输入框不吃字(文档模式/引擎问题)
#     keydown+value 正常增长      => HTA 输入没问题, 症结在宿主->VM 的键盘链路
$ErrorActionPreference = 'Continue'
function T { (Get-Date).ToString('HH:mm:ss.fff') }
Write-Output ('===== 键盘链路主动探针 ' + (T) + ' =====')

$src = 'X:\Desktop\Desktop.hta'
$dst = 'X:\dsktest.hta'
$logf = 'X:\dsktest.log'
$rectf = 'X:\dsktest.rect.txt'
if (-not (Test-Path $src)) { Write-Output '!! 镜像里没有 X:\Desktop\Desktop.hta'; exit }

$probe = @'
<script>
var pk = new ActiveXObject("Scripting.FileSystemObject");
var kbuf = [];
// 实测: PE 里 TextStream.WriteLine 写含中文的字符串会抛(日志文件被建出来但是 0 字节),
// 纯 ASCII 的 rect 文件写得很好。所以这里一律先消毒成 ASCII 再落盘。
function asc(s){
  s = (s === null || s === undefined) ? "?" : (s + "");
  var o = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 32 && c <= 126) o += s.charAt(i); else if (c == 9) o += " "; else o += "?";
  }
  return o;
}
function dump(name, txt){
  try { var f = pk.OpenTextFile(name, 2, true); f.WriteLine(asc(txt)); f.Close(); return true; } catch(e) { return false; }
}
function klog(s, tag){
  try {
    kbuf.push(new Date().toLocaleTimeString() + "  [" + asc(tag || "log") + "]  " + asc(s));
    if (!dump("X:\\dsktest.log", kbuf.join("\r\n"))) kbuf.push("DUMP_FAIL last=" + asc(s));
  } catch(e) {
    dump("X:\\dsktest.err.txt", "klog threw: " + asc(e && e.message ? e.message : e));
  }
}
function wire(id){
  var el = document.getElementById(id);
  if (!el) { klog("NO ELEMENT #" + id, "wire"); return; }
  el.onkeydown = function(){ klog(id + " keydown keyCode=" + event.keyCode + " key=[" + asc(event.key) + "]", "kbd"); };
  el.onkeyup   = function(){ klog(id + " keyup value=[" + asc(el.value) + "] active=" + (document.activeElement ? document.activeElement.id : "?"), "kbd"); };
  el.onfocus   = function(){ klog(id + " focus", "foc"); };
  el.onblur    = function(){ klog(id + " blur", "foc"); };
  el.onchange  = function(){ klog(id + " change value=[" + asc(el.value) + "]", "chg"); };
}
document.onfocusin = function(){
  try { var t = event.srcElement; klog("-> " + (t.id ? ("#" + t.id) : t.tagName), "focusin"); } catch(e){ klog("unreadable: " + (e && e.message), "focusin"); }
};
// 页面级按键记录: 用来分"键根本没进这个窗口"和"键进了窗口但没落到输入框"
document.onkeydown = function(){
  try { var t = event.srcElement; klog("keyCode=" + event.keyCode + " target=" + (t ? (t.id ? ("#" + t.id) : t.tagName) : "?") +
       " active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "?"), "doc-key"); } catch(e){}
};
document.onmousedown = function(){
  try { var t = event.srcElement; klog("down on " + (t ? (t.id ? ("#" + t.id) : t.tagName) : "?") + " clientXY=" + event.clientX + "," + event.clientY +
       " screenXY=" + event.screenX + "," + event.screenY, "mouse"); } catch(e){}
};
document.onmouseup = function(){
  try { var t = event.srcElement; klog("up on " + (t ? (t.id ? ("#" + t.id) : t.tagName) : "?"), "mouse"); } catch(e){}
};
function jsFocusTest(){
  var el = document.getElementById("addr");
  if (!el) { klog("no #addr to focus", "jsf"); return; }
  try { el.focus(); } catch(e){ klog("focus() threw: " + (e && e.message), "jsf"); }
  klog("jsFocus done active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "?") +
       " value=[" + asc(el.value) + "]", "jsf");
}
setTimeout(jsFocusTest, 12000);
function rectOf(id){
  var el = document.getElementById(id);
  if (!el) { klog("NO ELEMENT #" + id, "rect"); return; }
  var r = el.getBoundingClientRect();
  var ox = (window.screenLeft || 0), oy = (window.screenTop || 0);
  var cx = Math.round(r.left + r.width / 2) + ox;
  var cy = Math.round(r.top + r.height / 2) + oy;
  dump("X:\\dsktest.rect.txt", cx + " " + cy);
  klog("#" + id + " left=" + Math.round(r.left) + " top=" + Math.round(r.top) + " w=" + Math.round(r.width) +
       " h=" + Math.round(r.height) + " winOrigin=" + ox + "," + oy + " -> clickPoint " + cx + "," + cy, "rect");
}
function go(){
  klog("probe script alive", "boot");
  try { openFrp(); klog("frp panel display=" + document.getElementById("frp").style.display, "boot"); }
  catch(e){ klog("openFrp threw: " + (e && e.message ? e.message : e), "boot"); }
  var ids = ["addr", "sport", "token", "rport"];
  for (var i = 0; i < ids.length; i++) wire(ids[i]);
  rectOf("addr");
  klog("ready active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "?") +
       " body=" + document.body.clientWidth + "x" + document.body.clientHeight +
       " docMode=" + document.documentMode, "boot");
}
setTimeout(go, 1200);
var lastVals = "";
function pollVals(){
  var ids = ["addr", "sport", "token", "rport"], s = "";
  for (var i = 0; i < ids.length; i++) { var e = document.getElementById(ids[i]); s += ids[i] + "=[" + asc(e ? e.value : "NONE") + "] "; }
  s += "active=" + (document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : "?");
  if (s != lastVals) { klog(s, "vals"); lastVals = s; }
}
setInterval(pollVals, 1000);
</script>
'@

$txt = [IO.File]::ReadAllText($src, [Text.Encoding]::UTF8)
Write-Output ('原 Desktop.hta 字符数 = ' + $txt.Length)
$patched = $txt.Replace('ID="WinPEDesktop"', 'ID="WinPEDesktopProbe"').Replace('SINGLEINSTANCE="yes"', 'SINGLEINSTANCE="no"')
if ($patched.IndexOf('</body>') -ge 0) { $patched = $patched.Replace('</body>', $probe + '</body>') } else { $patched = $patched + $probe }
if ($patched.IndexOf('WinPEDesktopProbe') -lt 0) { Write-Output '!! 注入失败: 没找到要替换的标记, 放弃' ; exit }
[IO.File]::WriteAllBytes($dst, [byte[]](0xEF,0xBB,0xBF) + [Text.Encoding]::UTF8.GetBytes($patched))
foreach ($f in @($logf, $rectf, 'X:\dsktest.err.txt')) { if (Test-Path $f) { Remove-Item $f -Force } }
Write-Output ('已写出探针副本 ' + $dst + '(' + (Get-Item $dst).Length + ' 字节), 日志=' + $logf)

$before = @(Get-Process -Name mshta -EA SilentlyContinue | ForEach-Object { $_.Id })
try { Start-Process -FilePath 'X:\Windows\System32\mshta.exe' -ArgumentList $dst | Out-Null }
catch { Write-Output ('!! mshta 启动失败: ' + $_.Exception.Message); exit }
Start-Sleep -Seconds 5
$new = @(Get-Process -Name mshta -EA SilentlyContinue | Where-Object { $before -notcontains $_.Id })
if (-not $new.Count) { Write-Output '!! 没看到新的 mshta 进程(SINGLEINSTANCE 把副本并到原窗口了?), 放弃'; exit }
$p = $new[0]
Write-Output ('探针 mshta pid=' + $p.Id + ' 主窗口=0x' + ('{0:X}' -f [int64]$p.MainWindowHandle) + ' Responding=' + $p.Responding)
if ($p.MainWindowHandle -eq 0) { Write-Output '!! 探针窗口句柄为 0, 无法置前, 放弃'; exit }
$h = $p.MainWindowHandle

Add-Type -Namespace K -Name K2 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
[DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, UIntPtr extra);
[DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
[DllImport("user32.dll")] public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);
'@

function Fg-Who {
  $fh = [K.K2]::GetForegroundWindow()
  $fp = [uint32]0
  [void][K.K2]::GetWindowThreadProcessId($fh, [ref]$fp)
  $nm = (Get-Process -Id ([int]$fp) -EA SilentlyContinue).ProcessName
  return '0x' + ('{0:X}' -f [int64]$fh) + '(' + $nm + '/' + $fp + ')'
}
function VkOf([string]$ch) {
  $code = [int][char]$ch.ToUpper()[0]
  if ($code -ge 65 -and $code -le 90) { return $code }
  if ($code -ge 48 -and $code -le 57) { return $code }
  if ($code -ge 97 -and $code -le 122) { return ($code - 32) }
  if ($ch -eq '.') { return 190 }
  if ($ch -eq '-') { return 189 }
  if ($ch -eq ' ') { return 32 }
  return $null
}
function Type-Str([string]$s) {
  foreach ($ch in $s.ToCharArray()) {
    $vk = VkOf ([string]$ch)
    if ($null -eq $vk) { Write-Output ('  (跳过无法映射的字符 ' + $ch + ')'); continue }
    [K.K2]::keybd_event([byte]$vk, 0, 0, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 45
    [K.K2]::keybd_event([byte]$vk, 0, 2, [UIntPtr]::Zero)
    Start-Sleep -Milliseconds 45
  }
}

Write-Output ('--- 1) 把探针窗口置前(页面已在 1.2s 时自己打开 frp 面板并算好坐标) ---')
[void][K.K2]::BringWindowToTop($h)
[void][K.K2]::SetForegroundWindow($h)
Start-Sleep -Milliseconds 800
Write-Output ('  现在前台 = ' + (Fg-Who))

Write-Output '--- 2) 真鼠标点 #addr 两次(第一次可能只用来激活窗口), 坐标见 X:\dsktest.rect.txt ---'
if (Test-Path $rectf) {
  $rc = (Get-Content $rectf -EA SilentlyContinue | Select-Object -First 1)
  $xy = ($rc -split '\s+')
  Write-Output ('  目标坐标 = ' + $rc)
  for ($n = 1; $n -le 2; $n++) {
    [void][K.K2]::SetCursorPos([int]$xy[0], [int]$xy[1])
    Start-Sleep -Milliseconds 250
    [K.K2]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero)   # LEFTDOWN
    Start-Sleep -Milliseconds 90
    [K.K2]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero)   # LEFTUP
    Start-Sleep -Milliseconds 700
    Write-Output ('  第 ' + $n + ' 次点击完成, 前台 = ' + (Fg-Who))
  }
} else { Write-Output '  !! 没有 rect 文件, 跳过点击' }

Write-Output '--- 3) 点击之后真按键 abc (测"点完能不能打字") ---'
Type-Str 'abc'
Start-Sleep -Milliseconds 800

Write-Output '--- 4) 页面会在第 12 秒自己调用 addr.focus(), 等到那时再按键 def123 (测"焦点真在框里时吃不吃字") ---'
Start-Sleep -Milliseconds 4500
Write-Output ('  按键前前台 = ' + (Fg-Who))
Type-Str 'def123'
Start-Sleep -Milliseconds 800

Write-Output '--- 5) 用方向键/Tab 再试一次, 然后连续退格 ---'
[K.K2]::keybd_event(9, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 60
[K.K2]::keybd_event(9, 0, 2, [UIntPtr]::Zero); Start-Sleep -Milliseconds 400
Type-Str '7000'
foreach ($i in 1..3) { [K.K2]::keybd_event(8, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 60; [K.K2]::keybd_event(8, 0, 2, [UIntPtr]::Zero); Start-Sleep -Milliseconds 60 }
Start-Sleep -Milliseconds 1200

Write-Output ('--- 探针按键结束 ' + (T) + ' ---')
Write-Output ''
Write-Output '===== X:\dsktest.log ====='
if (Test-Path $logf) { Get-Content $logf | ForEach-Object { Write-Output ('  ' + $_) } } else { Write-Output '  (日志文件根本没被创建 —— 探针脚本没跑起来)' }
Write-Output '===== X:\dsktest.err.txt(写日志本身失败的现场) ====='
if (Test-Path 'X:\dsktest.err.txt') { Get-Content 'X:\dsktest.err.txt' | ForEach-Object { Write-Output ('  ' + $_) } } else { Write-Output '  (无)' }
Write-Output '============================'

try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue; Write-Output '已关掉探针窗口(不影响真实桌面 HTA)' } catch { }
$okI = @(Get-Process -Name mshta -EA SilentlyContinue | Where-Object { $before -contains $_.Id -and $_.MainWindowHandle -ne 0 })
Write-Output ('真实桌面 mshta(有窗口)还在 = ' + $okI.Count)
Write-Output ('===== 探针结束 ' + (T) + ' =====')
