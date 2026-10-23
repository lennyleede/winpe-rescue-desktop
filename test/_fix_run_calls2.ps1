param([Parameter(Mandatory=$true)][string]$Target)
# Fix the rewrite: `Run ('exe' + (args))` glued the exe name to the arguments. Insert the space.
$p = (Resolve-Path -LiteralPath $Target).Path
$txt = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$new = [regex]::Replace($txt, "Run \('([^']+)'\s*\+", { param($m) "Run ('" + $m.Groups[1].Value + " ' + (" })
$new = $new -replace "Run \('([^']+)'\s*\('", "Run ('$1 ('"
[IO.File]::WriteAllText($p, $new, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ('sites now: ' + ([regex]::Matches($new, "Run \('")).Count)
foreach ($m in [regex]::Matches($new, "(?m)^.*Run \('.*$")) { Write-Host ('  ' + $m.Value.Trim()) }
