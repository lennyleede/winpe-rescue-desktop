# PE 侧"救援终端" agent: 轮询主机 host_cmd.ps1 取命令, 执行后把输出 POST 回去
# 只需要 PE 能出站访问主机 (Hyper-V Default Switch 方向可用)
# 用法(在 WinPE 控制台里粘一条):
#   powershell -NoProfile -ExecutionPolicy Bypass -File X:\agent.ps1
param([string]$H = '172.31.32.1', [int]$Port = 8001, [int]$IntervalSec = 2)
$ErrorActionPreference = 'Continue'
$base = 'http://' + $H + ':' + $Port
# PE 里 powershell.exe 不在 System32 而在 System32\WindowsPowerShell\v1.0, 裸名字未必解析得到 -> 用 $PSHome 全路径
$PSExe = Join-Path $PSHome 'powershell.exe'
Write-Host ('救援终端 agent 已启动, 轮询 ' + $base + '/cmd (输入 EXIT 或 Ctrl+C 停止) 子shell=' + $PSExe)
while ($true) {
  $cmd = $null
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri ($base + '/cmd') -TimeoutSec 15
    $cmd = ($r.Content | Out-String).Trim()
  } catch {
    Write-Host ('取命令失败(主机没在听?): ' + $_.Exception.Message)
    Start-Sleep 10
    continue
  }
  if (-not $cmd) { Start-Sleep $IntervalSec; continue }
  if ($cmd -eq 'EXIT') { Write-Host '收到 EXIT, agent 退出'; break }
  Write-Host ('执行: ' + $cmd)
  # 放到子 powershell 里跑: 命令崩了/写了死循环也不会把 agent 一起带走
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
  $t0 = Get-Date
  $o = ''
  try {
    $o = & $PSExe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc 2>&1 | Out-String
  } catch { $o = 'agent 执行异常: ' + $_.Exception.Message }
  $report = ('===== ' + (Get-Date -Format 'HH:mm:ss') + '  ' + $cmd + "`r`n" +
             '(耗时 ' + [int]((Get-Date) - $t0).TotalSeconds + 's)' + "`r`n" + $o)
  Set-Content -Path X:\agent_out.txt -Value $report -Encoding UTF8
  try {
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($base + '/out') -InFile X:\agent_out.txt `
      -ContentType 'text/plain; charset=utf-8' -TimeoutSec 30 | Out-Null
  } catch { Write-Host ('回传失败: ' + $_.Exception.Message) }
}
