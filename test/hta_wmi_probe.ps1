# 在真 mshta 引擎里探一次 WMI 可用性, 结果由 HTA 自己写回 build\probe_wmi.txt
# 用途: 桌面状态灯全靠 GetObject('winmgmts:...'), 出盘前先确认这个写法在 mshta 里到底能不能用。
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\hta_wmi_probe.ps1
param([int]$TimeoutSec = 20)
$ErrorActionPreference = 'Stop'
$Root  = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root 'build'
$Hta   = Join-Path $Build 'probe_wmi.hta'
$Out   = Join-Path $Build 'probe_wmi.txt'
if (Test-Path $Out) { Remove-Item $Out -Force }

$js = @'
var out=[];
function t(name, fn){ try{ var r=fn(); out.push('OK  '+name+' => '+r); }catch(e){ out.push('ERR '+name+' => '+e.name+': '+e.message); } }
var W = 'winmgmts:\\\\.\\root\\cimv2';
function loc(){ var l=new ActiveXObject('WbemScripting.SWbemLocator'); return l.ConnectServer('.', 'root/cimv2'); }
t('typeof GetObject', function(){ return typeof GetObject; });
t('SWbemLocator ConnectServer', function(){ var s=loc(); return 'server='+s.Server+' ns='+s.Security_.ImpersonationLevel; });
t('Win32_Process count', function(){ var s=loc(); var e=new Enumerator(s.ExecQuery('SELECT Name FROM Win32_Process')); var n=0; for(;!e.atEnd();e.moveNext())n++; return n; });
t('Win32_ComputerSystem', function(){ var s=loc(); var e=new Enumerator(s.ExecQuery('SELECT * FROM Win32_ComputerSystem')); var o=e.item(); return o.Name+' / '+o.Manufacturer+' / '+o.Model; });
t('Win32_OperatingSystem', function(){ var s=loc(); var e=new Enumerator(s.ExecQuery('SELECT * FROM Win32_OperatingSystem')); return e.item().Version; });
t('NetAdapterConfig', function(){ var s=loc(); var e=new Enumerator(s.ExecQuery('SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True')); var n=0,f=''; for(;!e.atEnd();e.moveNext()){n++; if(!f&&e.item().IPAddress)f=e.item().IPAddress[0];} return 'rows='+n+' first='+f; });
t('winmgmts: moniker', function(){ var s=GetObject('winmgmts:'); return 'namespace='+s.NameSpace; });
t('root/cimv2 moniker', function(){ var s=GetObject(W); return 'path='+s.Path_.Path; });
try{
  var fso=new ActiveXObject('Scripting.FileSystemObject');
  var f=fso.OpenTextFile(OUTPATH, 2, true); f.Write(out.join('\r\n')); f.Close();
}catch(e){}
window.close();
'@
$js = $js.Replace('OUTPATH', "'" + ($Out -replace '\\', '\\') + "'")

$html = '<!DOCTYPE html><html><head>' +
  '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />' +
  '<meta http-equiv="x-ua-compatible" content="ie=edge" />' +
  '<HTA:APPLICATION ID="W" BORDER="none" SCROLL="no" /></head><body><script>' +
  $js + '</script></body></html>'
[IO.File]::WriteAllText($Hta, $html, (New-Object Text.UTF8Encoding($true)))

$p = Start-Process mshta.exe -ArgumentList ('"' + $Hta + '"') -PassThru
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and -not (Test-Path $Out)) { Start-Sleep -Milliseconds 400 }
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $Out)) { Write-Host "探针没写出文件(HTA 可能没起来或被安全策略拦了): $Out" -ForegroundColor Red; exit 1 }
Get-Content $Out -Encoding UTF8 | ForEach-Object { Write-Host $_ }
