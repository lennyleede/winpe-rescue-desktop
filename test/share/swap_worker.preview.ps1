$ErrorActionPreference = 'Continue'
Start-Sleep 5
Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'" | ForEach-Object { $null = $_.Terminate() }
Start-Sleep 1
Move-Item 'X:\SSH\pe-sshd.new' 'X:\SSH\pe-sshd.exe' -Force
$fs = [IO.File]::Open('X:\swap.log', 'Append', 'Write', 'ReadWrite')
$sr = New-Object IO.StreamWriter($fs, (New-Object Text.UTF8Encoding($true)))
$sr.WriteLine((Get-Date -Format 'HH:mm:ss') + ' swapped exe=' + (Get-Item 'X:\SSH\pe-sshd.exe').Length)
$sr.Close(); $fs.Close()
Start-Process -FilePath 'X:\SSH\pe-sshd.exe' -WindowStyle Hidden -ArgumentList '-addr 0.0.0.0:22 -hostkey X:\SSH\pe_host_ed25519 -authkeys X:\SSH\authorized_keys -log X:\sshd.log'
Start-Sleep 3
$cnt = @(Get-CimInstance Win32_Process -Filter "Name='pe-sshd.exe'").Count
$fs2 = [IO.File]::Open('X:\sshd.log', 'Open', 'Read', 'ReadWrite')
$sr2 = New-Object IO.StreamReader($fs2, [Text.Encoding]::UTF8)
$txt = $sr2.ReadToEnd(); $sr2.Close(); $fs2.Close()
$tail = @(($txt -split "`r?`n" | Where-Object { $_ }) | Select-Object -Last 4) -join ' | '
$body = 'pe-sshd 进程数=' + $cnt + ' exe=' + (Get-Item 'X:\SSH\pe-sshd.exe').Length + ' 换于' + (Get-Date -Format 'HH:mm:ss') + ' | 日志尾: ' + $tail
try { (New-Object Net.WebClient).UploadString('http://192.168.100.1:8000/result', $body) } catch { }