param([Parameter(Mandatory=$true)][string]$Cmd, [int]$TimeoutSec = 40)
# Run one command on the live rescue PE through frp -> pe-sshd and print its stdout.
# Kept as a -File script because Git Bash eats '$' inside inline powershell -Command.
$ErrorActionPreference = 'Continue'
$Key    = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
$Target = 'administrator@203.0.113.10'
$a = @('-i', $Key, '-o', 'StrictHostKeyChecking=no', '-o', ('ConnectTimeout=' + $TimeoutSec),
       '-o', 'BatchMode=yes', '-p', '8022', $Target, $Cmd)
& 'ssh.exe' @a 2>&1 | Where-Object { $_ -notmatch 'post-quantum|vulnerable to|may need to be upgraded|^\s*$' }
