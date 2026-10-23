param([Parameter(Mandatory=$true)][string]$Inf, [switch]$Body)
# Dump the raw shape of an INF: sections and every PCI hardware id anywhere in the file.
# UTF-16LE aware (catalog driver INFs are UTF-16).
$full = (Resolve-Path -LiteralPath $Inf).Path
$text = [IO.File]::ReadAllText($full, [Text.Encoding]::Unicode)
if ($text -notmatch '\[') { $text = [IO.File]::ReadAllText($full) }   # ASCII fallback
Write-Output ("FILE  " + $full)
Write-Output ("LEN   " + $text.Length)
Write-Output '--- [Version] ---'
$m = [regex]::Match($text, '(?ms)^\[Version\].*?(?=^\[)')
if ($m.Success) { Write-Output $m.Value.Trim() }
Write-Output '--- sections ---'
[regex]::Matches($text, '(?m)^\[[^]]+\]') | ForEach-Object { Write-Output ('  ' + $_.Value) }
Write-Output '--- PCI ids (whole file) ---'
$ids = [regex]::Matches($text, '(?i)VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}') | ForEach-Object { $_.Value.ToUpper() } | Sort-Object -Unique
if ($ids.Count) { Write-Output ('  ' + ($ids -join ' ')) } else { Write-Output '  none' }
Write-Output '--- root-enumerated / select flags ---'
foreach ($p in @('ExcludeFromSelect', 'CLASS\s*=', 'CatalogFile', 'Provider')) {
  [regex]::Matches($text, ('(?im)^.*' + $p + '.*$')) | ForEach-Object { Write-Output ('  ' + $_.Value.Trim()) }
}
if ($Body) {
  Write-Output '--- body ---'
  ($text -split "`r?`n") | Select-Object -Skip 20 -First 90 | ForEach-Object { Write-Output ('  ' + $_) }
}
