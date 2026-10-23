param(
  [Parameter(Mandatory=$true)][string]$Query,
  [string]$VersionFilter = '',
  [switch]$ListOnly
)
# Catalog paging probe: isql/200/Search.aspx?Query=...&PageSize=&SearchSku=&Language=0&UpdateID=0&Row=
# Row is the offset into the result set. Find out whether it works and how deep it goes.
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent', $UA)
foreach ($row in @(0, 25, 50, 100)) {
  $u = 'https://www.catalog.update.microsoft.com/isql/200/Search.aspx?Query=' + [Uri]::EscapeDataString($Query) +
       '&PageSize=&SearchSku=&Language=0&UpdateID=0&Row=' + $row
  try {
    $h = $wc.DownloadString($u)
    $vers = @([regex]::Matches($h, 'Driver Update \(([0-9.]+)\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
    $rows = ([regex]::Matches($h, 'goToDetails\("')).Count
    Write-Output ('Row=' + $row + ' rows=' + $rows + ' versions=' + (($vers | Select-Object -First 12) -join ' '))
  } catch {
    Write-Output ('Row=' + $row + ' ERROR ' + $_.Exception.Message)
  }
}
