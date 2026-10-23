param([Parameter(Mandatory=$true)][string]$Target, [switch]$Gbk)
# Normalize a delivered script: exactly one UTF-8 BOM (or GBK, for cmd/bat) + CRLF. Idempotent.
$bytes = [System.IO.File]::ReadAllBytes($Target)
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
  $bytes = $bytes[3..($bytes.Length - 1)]
}
$text = [System.Text.Encoding]::UTF8.GetString($bytes)
$text = $text -replace "`r`n", "`n"
$text = $text -replace "`n", "`r`n"
if ($Gbk) {
  [System.IO.File]::WriteAllBytes($Target, [System.Text.Encoding]::GetEncoding(936).GetBytes($text))
  Write-Host ('GBK+CRLF written: ' + $Target)
} else {
  $bom = [byte[]](0xEF, 0xBB, 0xBF)
  $body = [System.Text.Encoding]::UTF8.GetBytes($text)
  $out = New-Object byte[] ($bom.Length + $body.Length)
  [Array]::Copy($bom, 0, $out, 0, $bom.Length)
  [Array]::Copy($body, 0, $out, $bom.Length, $body.Length)
  [System.IO.File]::WriteAllBytes($Target, $out)
  Write-Host ('UTF8-BOM+CRLF written: ' + $Target)
}
