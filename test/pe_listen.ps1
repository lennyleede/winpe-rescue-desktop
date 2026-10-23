# PE 侧监听探针: 判断"主机发起的包到底有没有进 PE"
# 由 host_serve.ps1 下发, PE 里执行; 开始监听后先 POST READY, 期间允许主机来连, 结束时 POST 全过程记录
param([string]$HostIp = '192.168.0.106', [int]$Port = 8000, [int]$ListenPort = 9010, [int]$Seconds = 120, [string]$Drop = 'X:\pe_listen.txt')
$ErrorActionPreference = 'Continue'
$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $L.Add([string]$s) }
function Send($tag) {
  $txt = ($L -join "`r`n")
  try { [IO.File]::WriteAllText($Drop, ($tag + "`r`n" + $txt), (New-Object Text.UTF8Encoding($true))) } catch { }
  try {
    $b = [Text.Encoding]::UTF8.GetBytes($tag + "`r`n" + $txt)
    (New-Object Net.WebClient).UploadData('http://' + $HostIp + ':' + $Port + '/result', 'POST', $b) | Out-Null
  } catch { Add ('POST ' + $tag + ' 失败: ' + $_.Exception.Message) }
}

Add ("### 监听 " + $ListenPort)
$listener = $null
try {
  $listener = New-Object Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $ListenPort)
  $listener.Start()
  Add ('  已绑定: ' + $listener.LocalEndpoint)
} catch { Add ('  绑定失败: ' + $_.Exception.Message) }

Add ('### 本机 netstat 基线 ' + $ListenPort)
@(netstat -ano | Select-String (':' + $ListenPort)) | ForEach-Object { Add('  ' + ($_.ToString().Trim() -replace '\s+', ' ')) }
Send 'READY'

$deadline = (Get-Date).AddSeconds($Seconds)
$nextSnap = Get-Date
$accepts = 0
while ((Get-Date) -lt $deadline) {
  if ($listener -and $listener.Pending()) {
    $c = $listener.AcceptTcpClient()
    $accepts++
    Add ('  ' + (Get-Date -Format 'HH:mm:ss') + ' ACCEPT 来自 ' + $c.Client.RemoteEndPoint + ' => 说明主机的 SYN 进得来, 回程也能通')
    try {
      $s = $c.GetStream()
      $b = [Text.Encoding]::ASCII.GetBytes('PE-SAW-YOU ' + (Get-Date -Format 'HH:mm:ss') + "`r`n")
      $s.Write($b, 0, $b.Length); $s.Flush()
    } catch { Add ('  写回失败: ' + $_.Exception.Message) }
    $c.Close()
  }
  if ((Get-Date) -ge $nextSnap) {
    $nextSnap = (Get-Date).AddSeconds(5)
    $sn = @(netstat -ano | Select-String ($ListenPort.ToString()))
    if ($sn.Count -eq 0) { Add ('  ' + (Get-Date -Format 'HH:mm:ss') + ' netstat: 无 ' + $ListenPort + ' 相关条目') }
    else { $sn | ForEach-Object { Add ('  ' + (Get-Date -Format 'HH:mm:ss') + ' ' + ($_.ToString().Trim() -replace '\s+', ' ')) } }
  }
  Start-Sleep -Milliseconds 300
}
Add ('### 结束: 共接受 ' + $accepts + ' 条连接')
if ($listener) { $listener.Stop() }
Send 'FINAL'
$L | ForEach-Object { $_ } | Out-Host
