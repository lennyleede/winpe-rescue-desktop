param([int]$Len = 100)
$Key  = Join-Path $env:USERPROFILE '.ssh\id_ed25519'
$Base = @('-i', $Key, '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-p', '8022', 'administrator@203.0.113.10')
$piece = ('A' * $Len)
$cmd = 'echo ' + $piece + '>>X:\t1.b64'
Write-Output ("cmdlen={0}" -f $cmd.Length)
$a = $Base + $cmd
$out = & ssh.exe @a 2>&1 | Where-Object { $_ -notmatch 'post-quantum|vulnerable to|may need' }
Write-Output ("write output=[{0}]" -f (($out | Out-String).Trim()))
$a2 = $Base + 'dir X:\t1.b64'
$o2 = & ssh.exe @a2 2>&1 | Where-Object { $_ -notmatch 'post-quantum|vulnerable to|may need' }
Write-Output 'dir after:'
$o2 | ForEach-Object { Write-Output ("  " + $_) }
