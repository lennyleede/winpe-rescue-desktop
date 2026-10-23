param([Parameter(Mandatory=$true)][string]$Target)
# Repair the mangled Run() call sites: `Run ('exe ' + ( args))` -> `Run ('exe ' + (args))`.
# Doing it with one regex per line instead of hand-editing ten of them.
$p = (Resolve-Path -LiteralPath $Target).Path
$txt = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$out = New-Object Collections.Generic.List[string]
$fixed = 0
foreach ($line in ($txt -split "`r?`n")) {
  if ($line -match "^(.*?)Run \('([^']+)'\s*\+\s*\(\s*\((.*)\)\)\s*$") {
    $line = $matches[1] + 'Run (''' + $matches[2] + ' + (' + $matches[3] + '))'
    $fixed++
  }
  $out.Add($line)
}
$new = [string]::Join("`r`n", $out)
[IO.File]::WriteAllText($p, $new, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ('fixed lines = ' + $fixed)
foreach ($m in [regex]::Matches($new, "(?m)^.*Run \('.*$")) { Write-Host ('  ' + $m.Value.Trim()) }
