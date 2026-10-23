param([Parameter(Mandatory=$true)][string]$Path)
# Peek at a .wer file the way rescue.ps1 will have to: these are UTF-16 with a binary preamble, so
# plain Get-Content gives mojibake. Dump the decodable key lines.
$b = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)
foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::ASCII)) {
  $t = $enc.GetString($b)
  $lines = @($t -split "[`r`n]+" | Where-Object { $_ -match '[ -~]{6,}' })
  Write-Output ('=== encoding ' + $enc.EncodingName + ' usable lines=' + $lines.Count)
  foreach ($l in ($lines | Select-Object -First 25)) { Write-Output ('  ' + ($l -replace '[^\x20-\x7E]', '?')) }
}
