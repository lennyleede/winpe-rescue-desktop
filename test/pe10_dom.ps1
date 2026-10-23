# pe10_dom.ps1 —— 在 WinPE 里跑: 直接拿到救援桌面 HTA 的文档对象, 判断"输入框不吃字"卡在哪一层。
#   能拿到 Document => 面板本身是活的, 可以代填代点(顺带证明 保存配置/启动 这条链是好的)
#   拿不到        => mshta 没暴露 DOM, 只能从键盘送达/焦点链路查
$ErrorActionPreference = 'Continue'
function T { (Get-Date).ToString('HH:mm:ss.fff') }
Write-Output ('===== HTA DOM 探针 ' + (T) + ' =====')

$found = $null
try {
  $sh = New-Object -ComObject Shell.Application
  $i = 0
  foreach ($w in @($sh.Windows())) {
    $i++
    $title = ''; $url = ''; $hasDoc = $false
    try { $title = [string]$w.LocationName } catch { }
    try { $url = [string]$w.LocationURL } catch { }
    try { if ($w.Document) { $hasDoc = $true } } catch { }
    Write-Output ('  Shell窗口#' + $i + ' LocationName="' + $title + '" LocationURL=' + $url + ' 有Document=' + $hasDoc)
    if ($hasDoc -and -not $found) {
      try { if ($w.Document.getElementById('addr')) { $found = $w } } catch { }
    }
  }
  Write-Output ('  共 ' + $i + ' 个 Shell 窗口, 找到带 #addr 的文档 = ' + [bool]$found)
} catch {
  Write-Output ('  Shell.Application 不可用: ' + $_.Exception.Message)
}

if (-not $found) {
  Write-Output '结论: 拿不到 HTA 的 Document, 代填这条路不通。'
  exit 0
}

$doc = $found.Document
$win = $doc.parentWindow
Write-Output ('  document.title = "' + $doc.title + '"  readyState=' + $doc.readyState)
try { $ae = $doc.activeElement; Write-Output ('  当前活动元素 id=' + $ae.id + ' tagName=' + $ae.tagName + ' type=' + $ae.type) } catch { Write-Output '  activeElement 读不到' }
Write-Output ('  #frp 面板 display = ' + $doc.getElementById('frp').style.display)
foreach ($id in @('addr', 'sport', 'token', 'rport')) {
  $el = $doc.getElementById($id)
  Write-Output ('  #' + $id + ' 当前值="' + $el.value + '" disabled=' + $el.disabled + ' readOnly=' + $el.readOnly)
}
Write-Output ('  #frpstat = ' + $doc.getElementById('frpstat').innerText)

Write-Output '--- 代填并调用 saveFrp()(只动内存盘里的 X:\Desktop\Frp\frpc.toml, 不碰镜像) ---'
$doc.getElementById('addr').value = 'probe.example.com'
$doc.getElementById('sport').value = '7000'
$doc.getElementById('token').value = 'probe-token'
$doc.getElementById('rport').value = '6021'
try {
  [void]$win.execScript('saveFrp()', 'JScript')
  Write-Output '  saveFrp() 已调用'
} catch { Write-Output ('  saveFrp() 调用失败: ' + $_.Exception.Message) }
Start-Sleep 2
Write-Output ('  #addr 回读="' + $doc.getElementById('addr').value + '"  #frpstat=' + $doc.getElementById('frpstat').innerText)
$f = 'X:\Desktop\Frp\frpc.toml'
if (Test-Path $f) {
  $txt = Get-Content $f -Raw
  Write-Output ('  frpc.toml 现在的内容(前 400 字): ')
  Write-Output ('    ' + (($txt -split "`n" | Select-Object -First 12) -join ' | '))
  Write-Output ('  判定: 代填链路 ' + $(if ($txt -match 'probe\.example\.com') { '通(面板能保存配置)' } else { '不通(写了但不是我们填的值)'}))
} else { Write-Output '  !! X:\Desktop\Frp\frpc.toml 不存在' }
