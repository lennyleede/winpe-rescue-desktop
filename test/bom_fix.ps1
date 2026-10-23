param([Parameter(Mandatory)][string]$Target)
# 把脚本统一成 UTF-8 BOM + CRLF。必须显式按 UTF-8 读: PS5.1 的 Get-Content 对无 BOM 文件会按 GBK 读, 中文会被读坏
$p = (Resolve-Path $Target).Path
$txt = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$txt = $txt.TrimStart([char]0xFEFF) -replace "`r`n", "`n" -replace "`n", "`r`n"
[IO.File]::WriteAllText($p, $txt, (New-Object System.Text.UTF8Encoding($true)))
$b = [IO.File]::ReadAllBytes($p)
Write-Host ($p + ' bytes=' + $b.Length + ' bom=' + ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) + ' crlf=' + ([regex]::Matches($txt, "`r`n")).Count)
