param([Parameter(Mandatory=$true)][string]$Target)
# One-off: rewrite `Run 'exe' ('args')` into `Run ('exe ' + ('args'))` now that Run() takes a single
# command line. Keeps the file UTF-8 BOM + CRLF per the project's script-encoding rule.
$p = (Resolve-Path -LiteralPath $Target).Path
$txt = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$new = [regex]::Replace($txt, "Run '([^']+)' \((.+)\)(\s*)$", {
  param($m)
  'Run (''' + $m.Groups[1].Value + ''' + (' + $m.Groups[2].Value + '))' + $m.Groups[3].Value
}, 'Multiline')
[IO.File]::WriteAllText($p, $new, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ('rewrote ' + $p)
Write-Host ('remaining two-arg Run sites = ' + ([regex]::Matches($new, "Run '[^']+' \(").Count))
