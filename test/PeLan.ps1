param(
  [string]$Ip        = '192.168.0.107',
  [string]$User      = 'Administrator',
  [string]$Local     = '',
  [string]$Remote    = 'X:\p_probe.ps1',
  [string]$Cmd       = '',
  [switch]$Run,
  [int]$ChunkSize    = 1800
)
# PeLan.ps1 -- host-side helper to talk to a WinPE that is reachable directly on the LAN (no frp).
#   -Cmd '<text>'            run one short PowerShell line inline (keep the whole ssh command well under 6KB)
#   -Local <file> [-Run]     chunk-push a local script into the PE (pe-sshd has no scp/sftp; cmd.exe chokes past
#                            ~8KB, so base64 goes in through 'echo >>' and certutil -decode), then optionally run it.
# Everything here is ASCII: output gets read from a console and over ssh, non-ASCII turns into '??'.
$ErrorActionPreference = 'Stop'

$Root    = Split-Path $PSScriptRoot -Parent
$KeySrc  = Join-Path $Root 'overlay\Scripts\ssh_login_key'
if (-not (Test-Path -LiteralPath $KeySrc)) { Write-Output ('NO_KEY: ' + $KeySrc); exit 1 }
# ssh refuses a key that other users can read; the repo copy is wide-open, so take a private temp copy.
$KeyTmp = Join-Path $env:TEMP ('pelan_key_' + $PID)
if (Test-Path -LiteralPath $KeyTmp) { Remove-Item -LiteralPath $KeyTmp -Force }
Copy-Item -LiteralPath $KeySrc $KeyTmp -Force
& icacls $KeyTmp /inheritance:r /grant:r ($env:USERNAME + ':R') | Out-Null

$SshBin = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $SshBin)) { $SshBin = 'ssh' }
$Opts = @('-i', $KeyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
          '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR', ($User + '@' + $Ip))

function Invoke-Pe {
  param([string]$CmdLine)
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $SshBin @Opts $CmdLine 2>&1 | ForEach-Object { "$_" }
  $ErrorActionPreference = $prev
  return ($o -join "`r`n")
}

try {
  if ($Cmd) {
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Cmd))
    $line = 'X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64
    Write-Output ('INLINE cmdlen=' + $line.Length)
    Write-Output (Invoke-Pe $line)
    exit 0
  }

  if (-not $Local) { Write-Output 'nothing to do: pass -Cmd or -Local'; exit 1 }
  if (-not (Test-Path -LiteralPath $Local)) { Write-Output ('MISSING: ' + $Local); exit 1 }

  $bytes = [IO.File]::ReadAllBytes($Local)
  Write-Output ('LOCAL {0} bytes={1}' -f (Split-Path $Local -Leaf), $bytes.Length)
  $data = [Convert]::ToBase64String($bytes)
  $stg  = 'X:\p_probe.b64'

  Invoke-Pe ('del ' + $stg) | Out-Null
  Invoke-Pe ('echo -----BEGIN CERTIFICATE----- > ' + $stg)
  $i = 0; $n = 0
  while ($i -lt $data.Length) {
    $take  = [Math]::Min($ChunkSize, $data.Length - $i)
    $piece = $data.Substring($i, $take)
    $out   = (Invoke-Pe ('echo ' + $piece + '>>' + $stg)).Trim()
    $n++
    if ($out.Length -gt 0) { Write-Output ('  ABORT chunk ' + $n + ': ' + $out); exit 2 }
    $i += $take
  }
  Write-Output ('  pushed ' + $n + ' chunks (' + $data.Length + ' b64 chars)')
  Invoke-Pe ('echo -----END CERTIFICATE----- >> ' + $stg)

  Invoke-Pe ('del ' + $Remote) | Out-Null
  Write-Output ('DECODE: ' + (Invoke-Pe ('certutil -decode ' + $stg + ' ' + $Remote) -replace '\r?\n', ' '))
  Write-Output ('SIZE (expect ' + $bytes.Length + '): ' + (Invoke-Pe ('for %F in (' + $Remote + ') do @echo %~zF')))

  if ($Run) {
    Write-Output 'RUN:'
    Write-Output (Invoke-Pe ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + $Remote))
  }
} finally {
  Remove-Item -LiteralPath $KeyTmp -Force -EA SilentlyContinue
}
