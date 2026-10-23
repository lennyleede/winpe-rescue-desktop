# 主机侧"救援终端"服务端 (测试用, 不进 ISO)
#   PE 里跑 vm_shellagent.ps1 -> 每 2 秒 GET /cmd 取命令, 执行后 POST /out 回传输出。
#   只需要 PE 能出站访问本机(已验证可行), 不需要主机能连进 PE(Hyper-V Default Switch 做不到)。
#   用法: 在普通 PowerShell 窗口里执行本脚本, 然后直接敲命令, 输出会打印回来。
#   注意: 监听 0.0.0.0 且任何能连到本机的人都能取命令, 只在本机测试时开着, 用完 Ctrl+C。
param([int]$Port = 8001, [int]$Seconds = 3600)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$logFile = Join-Path $root ('cmd_session_' + (Get-Date -Format 'HHmmss') + '.log')
$queue = New-Object System.Collections.Generic.Queue[string]
$agentBytes = [IO.File]::ReadAllBytes((Join-Path $root 'vm_shellagent.ps1'))
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
$listener.Start()
Write-Host "LISTENING :$Port  等待 PE 侧 vm_shellagent.ps1 上线 (GET /cmd)"
Write-Host '输入命令后回车即下发; :quit 退出, :pe 查看 PE 最近上线时间'
Write-Host ('PE 输出同时写入: ' + $logFile + '   (投递命令也可写 ' + (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'cmd_in.txt') + ')')
$deadline = (Get-Date).AddSeconds($Seconds)
$peSeen = $null
# stdin 被重定向时 Console.KeyAvailable 会抛 InvalidOperationException
$interactive = $false
try { $interactive = -not [Console]::IsInputRedirected } catch { }
if (-not $interactive) { Write-Host '非交互模式(标准输入被重定向), 只能观察 PE 的输出' }
# 也支持从文件投递命令: 往 test\cmd_in.txt 写一行, 下一轮循环就下发并清空该文件
$inFile = Join-Path $root 'cmd_in.txt'
while ((Get-Date) -lt $deadline) {
  if ((Test-Path $inFile) -and ((Get-Item $inFile).Length -gt 0)) {
    # 读-清空-入队 必须整体容错: 编辑器/脚本正占着这个文件时会抛 IOException, 不能让它把服务带崩;
    # 且要先清空再入队, 否则清空失败会导致同一条命令下一轮重复下发
    try {
      $lines = @(Get-Content $inFile -ErrorAction Stop)
      Set-Content -Path $inFile -Value '' -Encoding ASCII -ErrorAction Stop
      $trimChars = @([char]0xFEFF, ' ', "`t", "`r", "`n")
      foreach ($l in $lines) {
        $l2 = ('' + $l).Trim($trimChars)
        if ($l2) { $queue.Enqueue($l2); Write-Host ('QUEUED(文件): ' + $l2) }
      }
    } catch { Start-Sleep 2 }
  }
  if ($interactive -and [Console]::KeyAvailable) {
    $line = [Console]::ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) { $line = [Console]::In.ReadLine() }
    if ($line -eq ':quit') { break }
    if ($line -eq ':pe') { Write-Host ('PE 最近上报: ' + $peSeen); continue }
    $queue.Enqueue($line)
    Write-Host ('QUEUED: ' + $line)
  }
  if (-not $listener.Pending()) { Start-Sleep -Milliseconds 200; continue }
  $c = $listener.AcceptTcpClient()
  $s = $c.GetStream(); $s.ReadTimeout = 8000
  $buf = New-Object byte[] 8192
  $data = New-Object System.Collections.Generic.List[byte]
  try {
    while ($true) {
      $n = $s.Read($buf, 0, $buf.Length)
      if ($n -le 0) { break }
      for ($i = 0; $i -lt $n; $i++) { $data.Add($buf[$i]) }
      $txt = [Text.Encoding]::ASCII.GetString($data.ToArray())
      if ($txt -notmatch "`r`n`r`n") { continue }
      $headLen = $txt.IndexOf("`r`n`r`n") + 4
      $cl = 0
      if ($txt -match '(?i)Content-Length:\s*(\d+)') { $cl = [int]$Matches[1] }
      if ($data.Count -lt ($headLen + $cl)) { continue }
      $parts = $txt -split ' '
      $method = $parts[0]; $path = $parts[1]
      $remote = $c.Client.RemoteEndPoint.ToString()
      if ($method -eq 'GET' -and $path -like '/agent*') {
        # 让 PE 一条命令就能把 agent 自己拉下去: GET /agent -> vm_shellagent.ps1 原始字节
        $hd = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($agentBytes.Length)`r`nConnection: close`r`n`r`n")
        $s.Write($hd, 0, $hd.Length); $s.Write($agentBytes, 0, $agentBytes.Length)
        Write-Host ('SERVED agent -> ' + $remote)
      } elseif ($method -eq 'GET' -and $path -like '/cmd*') {
        $cmd = ''
        if ($queue.Count -gt 0) { $cmd = $queue.Dequeue() }
        $body = [Text.Encoding]::UTF8.GetBytes($cmd)
        $hd = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
        $s.Write($hd, 0, $hd.Length); $s.Write($body, 0, $body.Length)
        $peSeen = (Get-Date).ToString('HH:mm:ss') + ' from ' + $remote
        if ($cmd) { Write-Host ('SENT -> ' + $remote + ' : ' + $cmd) }
      } elseif ($method -eq 'POST') {
        $raw = $data.ToArray()
        $text = ''
        if ($cl -gt 0) { $text = [Text.Encoding]::UTF8.GetString($raw[($headLen)..($headLen + $cl - 1)]) }
        Add-Content -Path $logFile -Value $text -Encoding UTF8
        Write-Host ('<-- ' + $remote)
        Write-Host $text
      } else {
        $nf = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`nContent-Length: 3`r`nConnection: close`r`n`r`n404")
        $s.Write($nf, 0, $nf.Length)
      }
      break   # 一个请求处理完就断开, 否则会卡在 keep-alive 的 Read 上
    }
  } catch { Write-Host "连接结束: $($_.Exception.Message)" } finally { $c.Close() }
}
$listener.Stop()
Write-Host ('日志: ' + $logFile)
