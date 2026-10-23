# 在真 mshta 引擎里跑一遍 Desktop.hta(整页原样加载, 只追加一段检查代码), 结果写 build\probe_desktop.txt
# 用途: 桌面状态灯依赖 wmi()/wql()/procNames()/ipList(), 出盘前先确认这些函数在 edge 模式 mshta 里真的能取到数据。
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\hta_desktop_probe.ps1
param([int]$TimeoutSec = 25)
$ErrorActionPreference = 'Stop'
$Root  = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root 'build'
$Src   = Join-Path $Root 'overlay\Desktop\Desktop.hta'
$Hta   = Join-Path $Build 'probe_desktop.hta'
$Out   = Join-Path $Build 'probe_desktop.txt'
if (Test-Path $Out) { Remove-Item $Out -Force }

$real = [IO.File]::ReadAllText($Src, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
if ($real -notmatch '(?i)</html>') { throw 'Desktop.hta 里没有 </html>, 无法插入检查脚本' }

# 检查脚本直接调用页面里真实的函数和真实的 DOM 元素
$check = @'
<script>
var R = [];
function push(s){ R.push(s); }
try {
  push('typeof GetObject = ' + (typeof GetObject));
  push('wmi() = ' + (wmi() === false ? 'FAILED(WMI 不可用)' : 'server=' + wmi().Server));
  var ps = procNames();
  push('procNames.__ok = ' + ps.__ok + ' (1=WMI 可用)');
  var cnt = 0, keys = [];
  for (var k in ps) if (k != '__ok') { cnt++; if (keys.length < 4) keys.push(k); }
  push('process rows = ' + cnt + ' sample = ' + keys.join(','));
  push('ssh=' + (ps['pe-sshd.exe'] ? 'y' : 'n') +
       ' sunlogin=' + (ps['sunlogin.exe'] || ps['sunloginsos.exe'] ? 'y' : 'n') +
       ' frpc=' + (ps['frpc.exe'] ? 'y' : 'n'));
  var ips = ipList();
  push('ipList = ' + (ips.length ? ips.join(',') : '(empty)') + ' | ipFromLog = ' + ipFromLog().join(','));
  // 诊断: 到底哪一步没拿到地址
  try {
    var s = wmi();
    var q1 = s.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration");
    var en = new Enumerator(q1), n = 0, det = [];
    for (; !en.atEnd(); en.moveNext()) {
      try {
        var o = en.item();
        push('#' + n + ' ipenabled=' + o.IPEnabled + ' type=' + (typeof o.IPAddress) +
             ' len=' + (function(){ try { return o.IPAddress.length; } catch(x){ return 'n/a'; } })() +
             ' vb=' + (function(){ try { return new VBArray(o.IPAddress).toArray().join('|'); } catch(x){ return 'noVB'; } })() +
             ' desc=' + o.Description);
      } catch (ix) { push('#' + n + ' item EXCEPTION ' + ix.message); }
      n++;
    }
    push('Win32_NetworkAdapterConfiguration rows=' + n);
    var q2 = null;
    try { q2 = s.ExecQuery("SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"); }
    catch (eq) { push('WHERE query EXCEPTION ' + eq.message); }
    if (q2) { var e2 = new Enumerator(q2), c = 0; for (; !e2.atEnd(); e2.moveNext()) c++; push('WHERE rows=' + c); }
  } catch (dz) { push('diag EXCEPTION ' + dz.message); }
  hostInfo();
  push('#host = ' + document.getElementById('host').innerHTML);
  refresh();
  push('#ip = ' + document.getElementById('ip').innerHTML);
  push('dots ssh/sun/frp/ip = ' + document.getElementById('d-ssh').className + ', ' +
       document.getElementById('d-sun').className + ', ' + document.getElementById('d-frp').className + ', ' +
       document.getElementById('d-ip').className);
} catch(e) { push('EXCEPTION ' + e.name + ': ' + e.message); }
try {
  var f = new ActiveXObject('Scripting.FileSystemObject').OpenTextFile('OUTPATH', 2, true);
  f.Write(R.join('\r\n')); f.Close();
} catch(e2) {}
window.close();
</script>
'@
$check = $check.Replace('OUTPATH', ($Out -replace '\\', '\\'))

$html = $real.Replace('</html>', $check + '</html>')
[IO.File]::WriteAllText($Hta, $html, (New-Object Text.UTF8Encoding($true)))

$p = Start-Process mshta.exe -ArgumentList ('"' + $Hta + '"') -PassThru
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not (Test-Path $Out)) { Start-Sleep -Milliseconds 400 }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $Out)) { Write-Host "探针没写出文件(HTA 可能没起来): $Out" -ForegroundColor Red; exit 1 }
Get-Content $Out -Encoding UTF8 | ForEach-Object { Write-Host $_ }
