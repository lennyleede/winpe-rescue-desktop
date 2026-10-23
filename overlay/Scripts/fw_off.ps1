# PE 开机兜底: 用 COM(HNetCfg.FwPolicy2) 把三个 profile 的防火墙置为关闭
#   与 fw-offline.ps1(离线把 MpsSvc 设为禁用 + 注册表 EnableFirewall=0) 是双保险, 谁生效都行
#   2026-10-05 在 v8 PE 里实测有效: 删掉全部允许规则后, 写 FirewallEnabled=False 约 4 秒主机即可 ping 通并拿到 SSH banner
#   由 startnet.cmd 的 [1b] 段调用; 结果写 X:\fw_off.log, 摘要一行写 X:\status.txt
param(
  [string]$LogFile = 'X:\fw_off.log',
  [string]$StatusFile = 'X:\status.txt',
  [switch]$SelfTest
)
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) {
  $t = (Get-Date -Format 'HH:mm:ss') + ' ' + ([string]$s)
  $L.Add($t)
  Write-Host $t
}
$verdict = 'unknown'
try {
  $fw = New-Object -ComObject HNetCfg.FwPolicy2
  Add ('FwPolicy2 OK 规则数=' + $fw.Rules.Count)
  Add ('写之前 Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
  $okCount = 0
  foreach ($id in @(1, 2, 4)) {
    if ($SelfTest) {
      Add ('SelfTest: 跳过写 profile ' + $id)
      continue
    }
    try {
      $fw.FirewallEnabled($id) = $false
      Add ('profile ' + $id + ' 赋值语法成功, 读回=' + $fw.FirewallEnabled($id))
      if ($fw.FirewallEnabled($id) -eq $false) { $okCount = $okCount + 1 }
    } catch {
      Add ('profile ' + $id + ' 赋值语法失败: ' + $_.Exception.Message)
      try {
        $null = $fw.GetType().InvokeMember('FirewallEnabled', 'SetProperty', $null, $fw, @($id, $false))
        Add ('profile ' + $id + ' InvokeMember 成功, 读回=' + $fw.FirewallEnabled($id))
        if ($fw.FirewallEnabled($id) -eq $false) { $okCount = $okCount + 1 }
      } catch {
        Add ('profile ' + $id + ' InvokeMember 也失败: ' + $_.Exception.Message)
      }
    }
  }
  Add ('写后 Domain=' + $fw.FirewallEnabled(1) + ' Private=' + $fw.FirewallEnabled(2) + ' Public=' + $fw.FirewallEnabled(4))
  if ($SelfTest) { $verdict = 'selftest' }
  elseif ($okCount -eq 3) { $verdict = 'off' }
  else { $verdict = 'partial(' + $okCount + '/3)' }
} catch {
  Add ('FwPolicy2 不可用: ' + $_.Exception.Message)
  # 2026-10-05 冷启动实测: 离线注册表已把 MpsSvc 设成 Start=4, 此时 COM 拿不到服务(0x800706D9),
  # 这不是故障 —— 防火墙根本没起来。必须报成成功, 否则 status.txt 里的 failed 会让人以为没关掉。
  $mps = @(Get-CimInstance Win32_Service -Filter "Name='MpsSvc'" -ErrorAction SilentlyContinue)
  $mpsNote = ''
  if ($mps.Count -eq 0) { $mpsNote = '服务键不存在' }
  elseif ($mps[0].State -eq 'Stopped') { $mpsNote = ('State=Stopped StartMode=' + $mps[0].StartMode) }
  if ($mpsNote) {
    Add ('' + $mpsNote + ' -> 离线注册表已经把防火墙禁掉了, 本脚本无事可做')
    $verdict = 'off-mpsvc-disabled'
  } else {
    $verdict = 'failed'
  }
}
foreach ($svc in @('MpsSvc', 'BFE')) {
  $o = @(Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction SilentlyContinue | ForEach-Object { 'State=' + $_.State + ' StartMode=' + $_.StartMode })
  if ($o.Count -gt 0) { Add ($svc + ' ' + ($o -join ' ')) } else { Add ($svc + ' 服务键不存在') }
}
$text = ($L -join "`r`n") + "`r`n"
try { [IO.File]::AppendAllText($LogFile, $text, (New-Object Text.UTF8Encoding($true))) } catch { Write-Host ('写 ' + $LogFile + ' 失败: ' + $_.Exception.Message) }
try { Add-Content -Path $StatusFile -Value ('fw_off=' + $verdict) -Encoding UTF8 } catch { Write-Host ('写 ' + $StatusFile + ' 失败: ' + $_.Exception.Message) }
Write-Host ('fw_off verdict=' + $verdict)
