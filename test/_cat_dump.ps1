param([string]$Query = 'Intel Rapid Storage Technology driver')
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent', $UA)
$html = $wc.DownloadString('https://www.catalog.update.microsoft.com/Search.aspx?q=' + [Uri]::EscapeDataString($Query))
$out = 'downloads\storage\raw\search_sample.html'
New-Item -ItemType Directory -Force -Path (Split-Path $out) | Out-Null
[IO.File]::WriteAllText($out, $html, [Text.Encoding]::UTF8)
Write-Output ('bytes=' + $html.Length + ' -> ' + $out)
# dump the first data row verbatim so we can see the real cell markup
$m = [regex]::Matches($html, '<tr.{0,4000}?</tr>', 'Singleline') | Where-Object { $_.Value -match 'goToDetails' } | Select-Object -First 2
foreach ($x in $m) { Write-Output '--- ROW ---'; Write-Output $x.Value }
