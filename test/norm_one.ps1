# 规范化单个 .ps1: 去多余 BOM -> 恰好一个 UTF-8 BOM + CRLF
param([Parameter(Mandatory=$true)][string]$Path)
$bytes = [IO.File]::ReadAllBytes($Path)
$i = 0
while ($i + 2 -lt $bytes.Length -and $bytes[$i] -eq 0xEF -and $bytes[$i+1] -eq 0xBB -and $bytes[$i+2] -eq 0xBF) { $i += 3 }
$text = [Text.Encoding]::UTF8.GetString($bytes[$i..($bytes.Length-1)])
$text = ($text -replace "`r`n", "`n") -replace "`n", "`r`n"
[IO.File]::WriteAllText($Path, $text, (New-Object Text.UTF8Encoding $true))
Write-Output ("NORMALIZED {0} (stripped {1} BOM)" -f (Split-Path $Path -Leaf), (($i/3)))
