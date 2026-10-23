# 在 startnet.cmd 的 [2] SSH 之前插入 [1b] 防火墙关闭段
# .cmd 必须按 GBK(936) + CRLF 字节级读写, 否则中文在 PE 控制台里是乱码
# 幂等: 文件里已经出现 fw_off.ps1 就跳过
$ErrorActionPreference = 'Stop'
$p = 'D:\QoderProject\国内版\生成winpe\overlay\Scripts\startnet.cmd'
$gbk = [Text.Encoding]::GetEncoding(936)
$t = $gbk.GetString([IO.File]::ReadAllBytes($p))
$anchor = 'rem ---------- [2] SSH'

if ($t.IndexOf('fw_off.ps1') -ge 0) { Write-Host 'SKIP: startnet.cmd 里已经有 fw_off.ps1 调用'; exit 0 }
if ($t.IndexOf($anchor) -lt 0) { Write-Host 'FAIL: 找不到 [2] SSH 锚点, 不动文件'; exit 1 }

$lines = @(
  'rem ---------- [1b] 防火墙: 彻底关闭 ----------',
  'rem 离线注册表已把 MpsSvc 设为禁用(fw-offline.ps1); 这里再用 COM 把三个 profile 置 False 兜一层。',
  'rem 实测: 零允许规则下写 FirewallEnabled=False 约 4 秒, 主机即可 ping 通并拿到 SSH banner。',
  'if exist "X:\Windows\System32\fw_off.ps1" (',
  '  X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\Windows\System32\fw_off.ps1 >> %LOG% 2>&1',
  ') else (',
  '  echo [1b] fw_off.ps1 NOT found >> %LOG%',
  ')',
  'echo [1b] fw_off attempted (详情 X:\fw_off.log, 结论 X:\status.txt 里 fw_off=) >> %LOG%',
  ''
)
$block = ($lines -join "`r`n") + "`r`n"
$t2 = $t.Replace($anchor, $block + $anchor)
[IO.File]::WriteAllBytes($p, $gbk.GetBytes($t2))

$b = [IO.File]::ReadAllBytes($p)
$cr = (@($b | Where-Object { $_ -eq 13 })).Count
$lf = (@($b | Where-Object { $_ -eq 10 })).Count
Write-Host ('PATCHED: 已插入 [1b] 段  CRLF=' + $cr + ' LF=' + $lf + ' 字节=' + $b.Length)
$chk = $gbk.GetString($b)
$pos = $chk.IndexOf('[1b]')
if ($pos -ge 0) { Write-Host ('回读片段: ' + (($chk.Substring($pos, 120) -replace "`r`n", ' / '))) } else { Write-Host '!! 回读没找到 [1b]' }
