param(
  [Parameter(Mandatory=$true)][string]$Local,
  [string]$RemotePath = 'X:\storageprobe.ps1',
  [string]$StagingB64  = 'X:\sp.b64',
  [int]$ChunkSize = 2000,
  [string]$Target = '',
  [int]$Port = 0,
  [switch]$Run,
  [switch]$ForceRun,
  [string]$RunArgs = ''
)
# Push a local file into a running WinPE over pe-sshd: chunked base64 via cmd 'echo >>' + certutil -decode.
# pe-sshd has no scp/sftp subsystem and cmd.exe chokes past ~8KB, so keep each command well under that.
# NOTE: PowerShell variable names are CASE-INSENSITIVE. '$b64' and a param named '$B64' are the SAME
# variable -- that aliasing silently put a 9.8KB base64 blob into every remote command and produced
# "The command line is too long." for every chunk. Keep staging-path names clearly distinct.
#
# REMOTE PATHS ARE NORMALIZED TO BACKSLASHES (2026-10-10): cmd.exe treats '/' as a SWITCH delimiter, so
# 'del X:/p43.ps1' deleted nothing while 'powershell -File X:/p43.ps1' ran happily -- certutil then
# refused with ERROR_FILE_EXISTS and we executed the PREVIOUS probe and read its output as if it were
# fresh. Every path handed to a cmd built-in (del / echo / certutil / for) goes through PePath below.
function PePath([string]$p) { ($p -replace '/', '\') }
$Key = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
# 默认走 frp 隧道(203.0.113.10:8022); 实机插 LAN 时用 -Target administrator@192.168.0.107 -Port 22,
# 这样同一条推送命令在两种通道下都能跑(2026-10-09 起 WiFi 验收走的是 LAN 直连)。
if (-not $Target) { $Target = 'administrator@203.0.113.10' }
if ($Port -le 0)  { $Port  = 8022 }

function Invoke-Pe {
  param([string]$Cmd)
  $a = @('-i', $Key, '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10',
         '-p', "$Port", $Target, $Cmd)
  & ssh.exe @a 2>&1 |
    Where-Object { $_ -notmatch 'post-quantum|vulnerable to|may need to be upgraded' }
}

if (-not (Test-Path -LiteralPath $Local)) { Write-Output "MISSING: $Local"; exit 1 }
$bytes = [IO.File]::ReadAllBytes($Local)
Write-Output ("LOCAL {0} bytes={1}" -f (Split-Path $Local -Leaf), $bytes.Length)

$dataB64 = [Convert]::ToBase64String($bytes)
Write-Output ("B64 length={0} chunks={1}" -f $dataB64.Length,
              [Math]::Ceiling($dataB64.Length / $ChunkSize))

$RemotePath = PePath $RemotePath
$StagingB64 = PePath $StagingB64
Invoke-Pe ('del /f /q ' + $StagingB64) | Out-Null
Invoke-Pe ('echo -----BEGIN CERTIFICATE----- > ' + $StagingB64)

$i = 0
$n = 0
while ($i -lt $dataB64.Length) {
  $take  = [Math]::Min($ChunkSize, $dataB64.Length - $i)
  $piece = $dataB64.Substring($i, $take)
  $cmd   = 'echo ' + $piece + '>>' + $StagingB64
  $out   = (Invoke-Pe $cmd | Out-String).Trim()
  $n++
  if ($out.Length -gt 0) {
    Write-Output ("  ABORT chunk {0} (cmdlen={1}): {2}" -f $n, $cmd.Length, $out)
    exit 2
  }
  $i += $take
  Write-Output ("  sent chunk {0} len={1} cmdlen={2} ({3}/{4})" -f $n, $piece.Length, $cmd.Length, $i, $dataB64.Length)
}
Invoke-Pe ('echo -----END CERTIFICATE----- >> ' + $StagingB64)

Write-Output 'DECODE:'
# certutil -decode refuses to overwrite an existing target (ERROR_FILE_EXISTS), so clear it first.
Invoke-Pe ('del /f /q ' + $RemotePath) | Out-Null
Invoke-Pe ('certutil -decode ' + $StagingB64 + ' ' + $RemotePath)
Write-Output 'SIZE (expect local bytes above):'
$szOut = @((Invoke-Pe ('for %F in (' + $RemotePath + ') do @echo %~zF') | Out-String) -split "`r?`n" |
          ForEach-Object { ($_ -replace '\s+', '').Trim() } | Where-Object { $_ -match '^\d+$' })
$remoteBytes = if ($szOut.Count) { [int]$szOut[0] } else { -1 }
Write-Output ("  REMOTE bytes=" + $remoteBytes + "  LOCAL bytes=" + $bytes.Length)
if ($Run -and $remoteBytes -ne $bytes.Length -and -not $ForceRun) {
  Write-Output 'ABORT: the remote file is not the file we just pushed (stale copy from an earlier run).' -ForegroundColor Red
  Write-Output '       Refusing to run it. Investigate the DECODE block above; -ForceRun overrides.' -ForegroundColor Red
  exit 3
}

if ($Run) {
  Write-Output 'RUN:'
  # -RunArgs 是给"同一个探针要带开关"的场合(2026-10-12: probe93 只在 -Apply 时才会跑 netcfg 阶梯)。
  # 它只是拼在 -File 后面, 所以内容必须是纯 ASCII 的开关串, 不能带引号嵌套。
  Invoke-Pe ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $RemotePath + $(if ($RunArgs) { ' ' + $RunArgs } else { '' }))
}
