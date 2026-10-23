param([Parameter(Mandatory=$true)][string]$Target)
# PE scripts must be ASCII-only (log files and console output in PE cannot render CJK).
$p = (Resolve-Path $Target).Path
$b = [System.IO.File]::ReadAllBytes($p)
$hits = @()
for ($i = 0; $i -lt $b.Length; $i++) { if ($b[$i] -gt 127) { $hits += $i } }
# strip the BOM from the count
$bom = ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
if ($bom) { $hits = @($hits | Where-Object { $_ -ge 3 }) }
Write-Host ('NON-ASCII (excluding BOM) = ' + $hits.Count)
if ($hits.Count) {
  $txt = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
  $lines = $txt -split "`r`n"
  $show = @()
  for ($ln = 0; $ln -lt $lines.Count; $ln++) {
    if ($lines[$ln] -match '[^\x20-\x7E]') { $show += ('  line ' + ($ln + 1) + ': ' + $lines[$ln]) }
  }
  foreach ($s in $show) { Write-Host $s }
} else { Write-Host 'ASCII: OK' }
