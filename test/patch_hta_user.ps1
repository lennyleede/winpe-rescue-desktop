# 字节级替换(不改编码): HTA 里 SSH 登录用户名应为 PE 唯一内置账号 Administrator
param([switch]$DryRun)
$p = Join-Path $PSScriptRoot '..\overlay\Desktop\Desktop.hta'
$lat = [Text.Encoding]::GetEncoding(28591)
$t = $lat.GetString([IO.File]::ReadAllBytes($p))
$old = 'ssh -i ssh_login_key admin@'
$new = 'ssh -i ssh_login_key Administrator@'
$n = ([regex]::Matches($t, [regex]::Escape($old))).Count
'occurrences: ' + $n
if ($n -eq 0 -or $DryRun) { exit 0 }
[IO.File]::WriteAllBytes($p, $lat.GetBytes($t.Replace($old, $new)))
'patched: ' + $p
