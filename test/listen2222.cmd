@echo off
rem One-shot TCP listener on port 2222 inside WinPE.
rem Opens a background powershell window; keep it open while testing from host.
start "" powershell -NoProfile -ExecutionPolicy Bypass -Command "$l=New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any,2222);$l.Start();Write-Host 'LISTENING 2222';while($true){try{$c=$l.AcceptTcpClient();Write-Host 'CONNECT!';[void]$c.GetStream().Write([Text.Encoding]::ASCII.GetBytes('WINPE-LISTENER-OK'),0,18);$c.Close()}catch{Write-Host ('accept err: '+$_.Exception.Message)}}; $l.Stop()"
