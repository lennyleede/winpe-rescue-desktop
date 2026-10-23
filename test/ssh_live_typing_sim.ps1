# 模拟真人在控制台里一段一段敲字: 先送"半行不回车"看有没有回显, 再送退格, 最后送裸 \r 看有没有执行
#   输入走真管道(重定向到文件会被 ssh 立刻当 EOF), 输出用异步读+超时轮询, 所以能按时间切片看
#   对照用法(同一个 PE, 老服务端在 22 / 新服务端在 2222):
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_live_typing_sim.ps1 -Port 22
#     powershell -NoProfile -ExecutionPolicy Bypass -File test\ssh_live_typing_sim.ps1 -Port 2222
param(
  [string]$Ip = '192.168.100.2',
  [string]$User = 'Administrator',
  [int]$Port = 2222,
  [int]$SettleMs = 3000
)
$ErrorActionPreference = 'Continue'
$proj = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path $proj 'build\ssh_live_sim'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$stamp = (Get-Date -Format 'HHmmss') + '_p' + $Port
$key = Join-Path $tmp 'login_key'
$src = Join-Path $proj 'overlay\Scripts\ssh_login_key'
if (Test-Path $src) {
  Copy-Item $src $key -Force
  & icacls.exe $key /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
}
$kh = Join-Path $tmp ('kh_' + $stamp)
$args_ = '-p ' + $Port + ' -tt -i "' + $key + '" -o StrictHostKeyChecking=no -o UserKnownHostsFile="' + $kh +
         '" -o ConnectTimeout=8 -o BatchMode=yes ' + $User + '@' + $Ip

$si = New-Object Diagnostics.ProcessStartInfo
$si.FileName = 'C:\Windows\System32\OpenSSH\ssh.exe'
$si.Arguments = $args_
$si.UseShellExecute = $false
$si.RedirectStandardInput = $true
$si.RedirectStandardOutput = $true
$si.RedirectStandardError = $true
$si.CreateNoWindow = $true
$p = [Diagnostics.Process]::Start($si)
$so = $p.StandardOutput.BaseStream
$se = $p.StandardError.BaseStream
$sin = $p.StandardInput
$sin.AutoFlush = $true
$out = New-Object Text.StringBuilder
$errb = New-Object Text.StringBuilder

function Drain($stream, $sbHolder, $state, $ms) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.ElapsedMilliseconds -lt $ms) {
    if (-not $state.task) {
      $state.buf = New-Object byte[] 4096
      $state.task = $stream.ReadAsync($state.buf, 0, $state.buf.Length)
    }
    $rem = [int]($ms - $sw.ElapsedMilliseconds)
    if ($rem -lt 50) { $rem = 50 }
    if ($state.task.Wait($rem)) {
      $n = 0
      try { $n = $state.task.Result } catch { $n = -1 }
      $state.task = $null
      if ($n -le 0) { return }
      $sbHolder.Append([Text.Encoding]::UTF8.GetString($state.buf, 0, $n)) | Out-Null
    } else { return }
  }
}
$soS = @{ task = $null; buf = $null }
$seS = @{ task = $null; buf = $null }
function Slice($tag, $ms) {
  Drain $so $out $soS $ms
  Drain $se $errb $seS 200
  $t = $out.ToString() + $errb.ToString()
  $line = ($t -replace '[\x00-\x08\x0b\x0c\x0e-\x1f]', '.' -replace '[\r\n]+', '~')
  if ($line.Length -gt 190) { $line = $line.Substring($line.Length - 190) }
  Write-Host ('  [' + $tag + '] 字节=' + $t.Length + ' 回显MARK=' + ($t -match 'MARK') + ' cmd打出该行=' + ($t -match 'X:\\>echo MARK') + ' 尾部: ...' + $line)
  return $t
}

Write-Host ('=== ' + $User + '@' + $Ip + ':' + $Port + ' 模拟手敲(输入分四段送) ===')
Start-Sleep 3
$t0 = Slice 't0 刚连上' 1500

$sin.Write('echo MARK'); Start-Sleep -Milliseconds $SettleMs
$t1 = Slice 't1 敲了 echo MARK 未回车' 1500

$sin.Write([string][char]0x08 + [string][char]0x08); Start-Sleep -Milliseconds 800
$t2 = Slice 't2 退两格' 1200

$sin.Write(' MARK'); Start-Sleep -Milliseconds 800
$t3 = Slice 't3 补成 echo MARK' 1200

$sin.Write("`r"); Start-Sleep -Milliseconds ($SettleMs + 1500)
$t4 = Slice 't4 按回车(裸 CR)' 1500

try { $sin.Write("`r"); $sin.Write('exit'); $sin.Write("`r") } catch { }
Start-Sleep -Milliseconds 800
Drain $so $out $soS 1500 | Out-Null
if (-not $p.WaitForExit(5000)) { try { $p.Kill() } catch { } }

$text = @($t0, $t1, $t2, $t3, $t4) -join "`r`n`r`n===== 下一切片 =====`r`n"
[IO.File]::WriteAllText((Join-Path $tmp ('sim_' + $stamp + '.txt')), $text, (New-Object Text.UTF8Encoding($true)))
Write-Host '=== 判定 ==='
$live = ($t1 -match 'MARK') -and ($t0 -notmatch 'MARK')
$traced = $t4 -match 'X:\\>echo M'
$dup = $t4 -match 'MARKMARK'
Write-Host ('  回车前就看到自己敲的字(实时回显) : ' + $live)
Write-Host ('  回车后 cmd 打出并执行了这一行     : ' + $traced)
Write-Host ('  退格重打没留残留字符(无 MARKMARK): ' + (-not $dup))
Write-Host ('  详细切片: build\ssh_live_sim\sim_' + $stamp + '.txt')
