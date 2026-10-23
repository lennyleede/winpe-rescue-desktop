param([Parameter(Mandatory=$true)][string]$Target)
# Undo the earlier machine rewrite: `Run ('exe ' + ( (rest))` -> `Run 'exe' (rest)`.
# Run() takes (exe, args) again, because it now shells out through cmd.exe /c.
$p = (Resolve-Path -LiteralPath $Target).Path
$txt = [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8)
$out = New-Object Collections.Generic.List[string]
$n = 0
$bad = 0
foreach ($line in ($txt -split "`r?`n")) {
  if ($line -match "^(.*?)Run \('([^']+)'\s*\+\s*\(\s*\(\s*(.*?)\s*\)\s*\)\s*$") {
    $line = $matches[1] + 'Run ''' + $matches[2].TrimEnd() + ''' (' + $matches[3] + ')'
    $n++
  }
  if ($line -match 'Run ') {
    $o = ([regex]::Matches($line, '\(')).Count
    $c = ([regex]::Matches($line, '\)')).Count
    if ($o -ne $c) { $bad++; Write-Host ('UNBALANCED ' + $line) }
  }
  $out.Add($line)
}
$new = [string]::Join("`r`n", $out)
[IO.File]::WriteAllText($p, $new, (New-Object System.Text.UTF8Encoding($true)))
Write-Host ('rewrote ' + $n + ' call sites, unbalanced after rewrite = ' + $bad)
foreach ($m in [regex]::Matches($new, "(?m)^\s*\S.*Run .*$")) { Write-Host ('  ' + $m.Value.Trim()) }
