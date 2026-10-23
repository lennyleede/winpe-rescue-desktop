# 规范化 test\*.ps1 与 build\*.ps1 的编码: 恰好一个 UTF-8 BOM + CRLF
$targets = @('D:\QoderProject\国内版\生成winpe\test','D:\QoderProject\国内版\生成winpe')
foreach ($dir in $targets) {
  Get-ChildItem $dir -Filter *.ps1 -File -ErrorAction SilentlyContinue | ForEach-Object {
    $bytes = [IO.File]::ReadAllBytes($_.FullName)
    $i = 0
    while ($i + 2 -lt $bytes.Length -and $bytes[$i] -eq 0xEF -and $bytes[$i+1] -eq 0xBB -and $bytes[$i+2] -eq 0xBF) { $i += 3 }
    $text = [Text.Encoding]::UTF8.GetString($bytes[$i..($bytes.Length-1)])
    $text = $text -replace "`r`n", "`n"
    $text = $text -replace "`n", "`r`n"
    [IO.File]::WriteAllText($_.FullName, $text, (New-Object Text.UTF8Encoding $true))
    Write-Host ("NORMALIZED {0} (removed {1} stray BOM)" -f $_.Name, (($i/3)-1))
  }
}
