param(
  [Parameter(Mandatory=$true)][string]$RemoteFile,   # e.g. X:\rescue.zip
  [Parameter(Mandatory=$true)][string]$LocalFile,    # host path to write
  [string]$Staging   = 'X:\pull.b64',
  [int]$ChunkLimitMB = 60,                            # refuse to pull absurdly big files over exec ssh
  # the LAN boot (192.168.0.x, port 22) and the frp relay (203.0.113.10, port 8022) are different
  # doors to the same PE; keep the relay as the default but let the caller aim at the LAN directly.
  [string]$Target    = '',
  [int]$Port         = 0,
  [switch]$KeepRemote
)
$ErrorActionPreference = 'Stop'

# Pull one file OUT of the rescue PE over the existing frp -> pe-sshd exec channel.
#
# pe-sshd has no sftp/scp subsystem, and INBOUND cmd.exe is capped around 8KB per command line --
# but that cap is on the COMMAND STRING, not on STDOUT. So the transfer is:
#   PE:  certutil -encode <file> X:\pull.b64          (base64, PEM-wrapped)
#   host: ssh ... type X:\pull.b64                    (one round trip, stdout streams back)
# Base64 is pure ASCII so it survives the shell, the tunnel and PowerShell's line splitting.
#
# NOTE on names: PowerShell variable names are case-insensitive, so never let a staging path and a
# data blob share a name (that bug produced "The command line is too long" on every chunk).

$Key    = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
if (-not $Target) { $Target = 'administrator@203.0.113.10' }
if ($Port -le 0)  { $Port   = 8022 }
$Port   = "$Port"
Write-Output ('TARGET ' + $Target + ' port ' + $Port)

function Invoke-Pe([string]$Cmd) {
  $a = @('-i', $Key, '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=15',
         '-o', 'ServerAliveInterval=15', '-p', $Port, $Target, $Cmd)
  # ssh.exe writes its post-quantum notice on STDERR. With ErrorActionPreference=Stop, `2>&1` turns
  # that harmless line into a terminating NativeCommandError, so relax it just for the native call.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & ssh.exe @a 2>&1 | Where-Object { $_ -notmatch 'post-quantum|vulnerable to|may need to be upgraded' }
  } finally { $ErrorActionPreference = $prev }
}

# pe-sshd hands the command string to 'cmd.exe /c "<string>"'. cmd then removes the FIRST and LAST
# quote, so a quoted path ("X:\a.zip") leaves stray quotes inside the argument list and certutil
# reports ERROR_FILE_NOT_FOUND for a file that demonstrably exists. Measured 2026-10-08: unquoted
# paths work, quoted ones do not. PE paths here never contain spaces, so refuse them loudly.
foreach ($p in @($RemoteFile, $Staging)) {
  if ($p -match '\s') { throw ('remote path must not contain spaces (pe-sshd + cmd /c quoting is broken): ' + $p) }
  if ($p -match '"') { throw ('remote path must not contain a double quote: ' + $p) }
}

# 1. size on the PE (cmd 'for %F' prints byte count; cheaper than shipping PowerShell to measure)
$sizeTxt = (Invoke-Pe ('for %F in (' + $RemoteFile + ') do @echo %~zF')) -join ''
$sizeTxt = ($sizeTxt -replace '[^0-9]', '')
if (-not $sizeTxt) { throw ('cannot stat remote file: ' + $RemoteFile) }
$remoteBytes = [int64]$sizeTxt
Write-Output ('REMOTE ' + $RemoteFile + ' = ' + $remoteBytes + ' bytes')
if ($remoteBytes -gt ($ChunkLimitMB * 1MB)) {
  throw ('too big for the exec channel (' + [math]::Round($remoteBytes/1MB) + 'MB > ' + $ChunkLimitMB + 'MB). Narrow the bundle or split it.')
}

# 2. encode on the PE (del first: certutil -encode fails with 0x80070050 if the target exists)
Invoke-Pe ('del ' + $Staging + ' 2>nul') | Out-Null
$enc = Invoke-Pe ('certutil -encode ' + $RemoteFile + ' ' + $Staging)
$encTxt = ($enc | Out-String)
if ($encTxt -notmatch 'completed successfully') {
  throw ('certutil -encode failed: ' + $encTxt.Trim())
}

# 3. stream the base64 back in one ssh call
Write-Output 'PULL: type X:\pull.b64 -> stdout'
$sw = [Diagnostics.Stopwatch]::StartNew()
$lines = Invoke-Pe ('type ' + $Staging)
$sw.Stop()
$joined = ($lines -join "`r`n")
Write-Output ('  got ' + $lines.Count + ' lines in ' + [math]::Round($sw.Elapsed.TotalSeconds, 1) + 's')

# 4. strip PEM armor, decode locally
$body = $joined -replace '(?m)^-----BEGIN CERTIFICATE-----\s*$', '' -replace '(?m)^-----END CERTIFICATE-----\s*$', ''
$body = ($body -replace '[^A-Za-z0-9+/=]', '')
$bytes = [Convert]::FromBase64String($body)
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LocalFile) | Out-Null
[IO.File]::WriteAllBytes($LocalFile, $bytes)
Write-Output ('WROTE ' + $LocalFile + ' bytes=' + $bytes.Length)

# 5. verify against the remote size
if ($bytes.Length -ne $remoteBytes) {
  Write-Output ('SIZE MISMATCH: local=' + $bytes.Length + ' remote=' + $remoteBytes)
  exit 2
}
Write-Output 'SIZE MATCH = ok'

if (-not $KeepRemote) {
  Invoke-Pe ('del ' + $Staging + ' 2>nul') | Out-Null
}
Write-Output 'PULL DONE'
