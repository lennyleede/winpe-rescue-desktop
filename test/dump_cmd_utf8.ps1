# 把 GBK(936) 编码的 .cmd/.bat 转成 UTF-8 视图文件, 方便用 Read 工具复查中文是否还是乱码
# 用法: test\dump_cmd_utf8.ps1 -Path <cmd文件> [-Out <视图文件>]
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$gbk = [Text.Encoding]::GetEncoding(936)
$bytes = [IO.File]::ReadAllBytes($Path)
$text = $gbk.GetString($bytes)
if (-not $Out) {
  $dir = Split-Path -Parent $Path
  $Out = Join-Path $Dir ('_' + (Split-Path -Leaf $Path) + '.utf8view.txt')
}
[IO.File]::WriteAllText($Out, $text, (New-Object Text.UTF8Encoding($true)))
$bomLead = ($bytes.Length -gt 2 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB)
$cr = (@($bytes | Where-Object { $_ -eq 13 })).Count
$lf = (@($bytes | Where-Object { $_ -eq 10 })).Count
Write-Host ('源字节=' + $bytes.Length + '  CRLF=' + $cr + '  LF=' + $lf + '  开头像BOM(不该有)=' + $bomLead)
Write-Host ('视图: ' + $Out)
