# 把 UTF-8 源文件转成 GBK(936)+CRLF 的 .cmd/.bat (zh-CN Windows 的 cmd.exe 按 GBK 解析)
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\to_gbk.ps1 -Target overlay\Scripts\startnet.cmd
param([Parameter(Mandatory)][string]$Target)
$ErrorActionPreference = 'Stop'
$p = (Resolve-Path $Target).Path
$bytes = [IO.File]::ReadAllBytes($p)
$i = 0
while ($i + 2 -lt $bytes.Length -and $bytes[$i] -eq 0xEF -and $bytes[$i+1] -eq 0xBB -and $bytes[$i+2] -eq 0xBF) { $i += 3 }
$txt = [Text.Encoding]::UTF8.GetString($bytes[$i..($bytes.Length-1)])
$txt = $txt.TrimEnd([char]0) -replace "`r`n", "`n" -replace "`n", "`r`n"
$gbk = [Text.Encoding]::GetEncoding(936)
[IO.File]::WriteAllBytes($p, $gbk.GetBytes($txt))

# 自检: 回读解码必须和原文一致, 且行尾是 CRLF、无 BOM
$b = [IO.File]::ReadAllBytes($p)
$back = $gbk.GetString($b) -replace "`r`n", "`n"
$plain = $txt -replace "`r`n", "`n"
if ($back -ne $plain) { Write-Host 'GBK 往返校验不一致' -ForegroundColor Red; exit 1 }
if ($b[0] -eq 0xEF -and $b[1] -eq 0xBB) { Write-Host '仍带 BOM' -ForegroundColor Red; exit 1 }
if (([regex]::Matches($txt, "`r`n")).Count -lt 3 -or ([regex]::Matches($txt, "`n")).Count -ne ([regex]::Matches($txt, "`r`n")).Count) {
  Write-Host 'CRLF 行数异常' -ForegroundColor Red; exit 1
}
Write-Host ('GBK-OK {0} bytes={1} crlf={2}' -f $p, $b.Length, ([regex]::Matches($txt, "`r`n")).Count) -ForegroundColor Green
