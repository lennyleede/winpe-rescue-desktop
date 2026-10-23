# 以字节方式修改 startnet.cmd, 保持 GBK+CRLF 不被转码
$p = Join-Path $PSScriptRoot '..\overlay\Scripts\startnet.cmd'
$bytes = [IO.File]::ReadAllBytes($p)
$text = [Text.Encoding]::GetEncoding(936).GetString($bytes)
$new = $text.Replace(' -E X:\sshd.log -d', ' -E X:\sshd.log')
if ($new -eq $text) { 'NO CHANGE (old string not found)'; exit 1 }
[IO.File]::WriteAllBytes($p, [Text.Encoding]::GetEncoding(936).GetBytes($new))
'OK: -d removed from sshd launch line'
$text.Split("`r`n") | Where-Object { $_ -match 'sshd.exe' }
