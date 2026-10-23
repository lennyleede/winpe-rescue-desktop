# 主机侧微型 HTTP 服务: GET /v.ps1 下发脚本, POST /result 收回结果
# 用 TcpListener 实现 (无需管理员, 无需 urlacl)
param([string]$Script = 'vm_verify.ps1', [int]$Seconds = 900)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $root $Script
$resultBase = Join-Path $root 'vm_result'
$postCount = 0
$port = 8000

$bytes = [IO.File]::ReadAllBytes($script)
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $port)
$listener.Start()
Write-Host "SERVING http://172.31.32.1:$port/v.ps1  (脚本: $Script $($bytes.Length) 字节; 等待 WinPE 连接, 最多 $Seconds 秒)"

$deadline = (Get-Date).AddSeconds($Seconds)
$got = $false
while ((Get-Date) -lt $deadline) {
  if (-not $listener.Pending()) { Start-Sleep -Milliseconds 300; continue }
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

      $method = ($txt -split ' ')[0]
      $path = ($txt -split ' ')[1]
      $remote = $c.Client.RemoteEndPoint.ToString()
      Write-Host "$remote -> $method $path"
      if ($method -eq 'POST') {
        $body = $data.ToArray()[($headLen)..($headLen + $cl - 1)]
        $postCount++
        $resultFile = ('{0}_{1}_{2}.txt' -f $resultBase, (Get-Date -Format 'HHmmss'), $postCount)
        [IO.File]::WriteAllBytes($resultFile, $body)
        $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`nConnection: close`r`n`r`nOK")
        $s.Write($resp, 0, $resp.Length)
        Write-Host "RESULT-SAVED -> $resultFile ($cl 字节)"
        $got = $true
      } elseif ($path -like '/file/*') {
        # 只允许下载 share 目录下的裸文件名
        $name = [IO.Path]::GetFileName($path.Substring(6))
        $fp = Join-Path (Join-Path $root 'share') $name
        if ((Test-Path $fp) -and ((Split-Path -Parent $fp) -eq (Join-Path $root 'share'))) {
          $fb = [IO.File]::ReadAllBytes($fp)
          $hd = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Length: $($fb.Length)`r`nConnection: close`r`n`r`n")
          $s.Write($hd, 0, $hd.Length); $s.Write($fb, 0, $fb.Length)
          Write-Host ("SENT file " + $name + ' ' + $fb.Length + ' 字节')
        } else {
          $nf = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`nContent-Length: 3`r`nConnection: close`r`n`r`n404")
          $s.Write($nf, 0, $nf.Length); Write-Host ("404 " + $name)
        }
      } else {
        $head = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n")
        $s.Write($head, 0, $head.Length)
        $s.Write($bytes, 0, $bytes.Length)
        Write-Host ("SERVED " + $Script)
      }
      # 一个请求处理完就断开: 响应里已写 Connection: close, 若继续停在 Read 上,
      # keep-alive 的连接会把后面的 POST 结果堵到超时(第十一轮就是这么丢结果的)
      break
    }
  } catch { Write-Host "连接结束: $($_.Exception.Message)" } finally { $c.Close() }
}
$listener.Stop()
if ($got) { Write-Host 'DONE' } else { Write-Host "TIMEOUT: $Seconds 秒内无 POST 结果" }
