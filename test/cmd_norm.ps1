param([string]$Path = 'overlay\Scripts\storageprobe.cmd')
$t = [IO.File]::ReadAllText($Path)
$t = $t -replace "`r`n", "`n"
$t = $t -replace "`n", "`r`n"
[IO.File]::WriteAllText($Path, $t, [Text.Encoding]::ASCII)
$b = [IO.File]::ReadAllBytes($Path)
$cr = @($b | Where-Object { $_ -eq 13 }).Count
$lf = @($b | Where-Object { $_ -eq 10 }).Count
$hi = @($b | Where-Object { $_ -gt 127 }).Count
Write-Output ("{0}: bytes={1} CR={2} LF={3} nonascii={4}" -f $Path, $b.Length, $cr, $lf, $hi)
