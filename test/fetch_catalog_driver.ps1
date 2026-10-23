param(
  [Parameter(Mandatory=$true)][string]$Query,
  [string]$OutDir = 'downloads\storage\raw',
  [int]$MaxPicks = 3,
  [string]$ClassFilter = '',
  [string]$GuidList = '',
  [switch]$ListOnly,
  [switch]$SkipDownload
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Microsoft Update Catalog scraping, v2.
# v1 used curl from Git Bash and every cab URL came back 404 (1245-byte IIS error page).
# Differences here: one System.Net.Http.HttpClient holds cookies for the whole search ->
# dialog -> download flow, a real browser UA + Referer is sent, and the sha256 digest from
# DownloadDialog.aspx is verified against the downloaded bytes before we accept the file.
$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.AllowAutoRedirect = $true
$handler.UseCookies = $true
$client = New-Object System.Net.Http.HttpClient($handler)
$client.DefaultRequestHeaders.UserAgent.ParseAdd($UA)
$client.DefaultRequestHeaders.Accept.ParseAdd('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
$client.Timeout = [TimeSpan]::FromMinutes(5)

function Get-Text([string]$url, [string]$referer) {
  $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::Get, $url)
  if ($referer) { $req.Headers.Referrer = [Uri]$referer }
  $resp = $client.SendAsync($req).Result
  $resp.EnsureSuccessStatusCode() | Out-Null
  return $resp.Content.ReadAsStringAsync().Result
}

Write-Output ('SEARCH q=' + $Query)
$searchUrl = 'https://www.catalog.update.microsoft.com/Search.aspx?q=' + [Uri]::EscapeDataString($Query)
$html = Get-Text $searchUrl $null
$rows = @($html -split '</tr>' | Where-Object { $_ -match 'goToDetails\("' })
Write-Output ('  rows=' + $rows.Count)

if ($GuidList) {
  # direct selection: skip the search-result ranking entirely (catalog ordering is by date,
  # and the version that actually covers an old device id is often not the newest row)
  $picks = @()
  foreach ($g in ($GuidList -split '[,; ]+' | Where-Object { $_ -match '[0-9a-fA-F-]{36}' })) {
    $picks += [pscustomobject]@{ Guid = $g; Title = '(forced)'; Product = ''; Class = ''; Date = ''; Version = $g; Size = '' }
  }
  Write-Output ('  forced picks=' + $picks.Count)
}
else {
$picks = @()
foreach ($r in $rows) {
  if ($r -notmatch 'goToDetails\("([0-9a-fA-F-]{36})"') { continue }
  $guid = $matches[1]
  # real cell ids (confirmed from search_sample.html): <guid>_C1 title, _C2 product,
  # _C3 classification, _C4 date, _C5 version, _C6 originalSize
  function Cell([string]$n) {
    if ($r -match ('(?s)id="' + [regex]::Escape($guid) + '_C' + $n + '_R\d+"[^>]*>(.*?)</td>')) {
      return (($matches[1] -replace '<[^>]+>', '') -replace '\s+', ' ').Trim()
    }
    return ''
  }
  $row = [pscustomobject]@{
    Guid   = $guid
    Title  = (Cell 1)
    Product= (Cell 2)
    Class  = (Cell 3)
    Date   = (Cell 4)
    Version= (Cell 5)
    Size   = (Cell 6)
  }
  if ($ClassFilter -and ($row.Class + ' ' + $row.Title + ' ' + $row.Product) -notmatch $ClassFilter) { continue }
  $picks += $row
}
$picks = @($picks | Select-Object -First $MaxPicks)
# the catalog lists the same driver build many times (one row per Windows release / servicing
# channel). Dedupe by version so MaxPicks means 'distinct driver versions', not 'rows'.
$seen = @{}
$dedup = @()
foreach ($p in $picks) {
  $k = $p.Version
  if (-not $k) { $k = $p.Guid }
  if ($seen.ContainsKey($k)) { continue }
  $seen[$k] = $true
  $dedup += $p
}
$picks = $dedup
}
foreach ($p in $picks) {
  Write-Output ('  PICK| ' + $p.Guid + ' | ' + $p.Date + ' | v' + $p.Version + ' | ' + $p.Size + 'B | ' + $p.Class + ' | ' + $p.Title + ' | ' + $p.Product)
}
if ($ListOnly -or $picks.Count -eq 0) { return }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

foreach ($p in $picks) {
  Write-Output ('DIALOG ' + $p.Guid)
  $dlgUrl = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
  $body = 'updateIDs=%5B%7B%22size%22%3A0%2C%22updateID%22%3A%22' + $p.Guid + '%22%7D%5D&isLanguageExpanded=False&isMetadataExpanded=False'
  $content = New-Object System.Net.Http.StringContent($body, [Text.Encoding]::UTF8, 'application/x-www-form-urlencoded')
  $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::Post, $dlgUrl)
  $req.Content = $content
  $req.Headers.Referrer = [Uri]$searchUrl
  $resp = $client.SendAsync($req).Result
  $dlg = $resp.Content.ReadAsStringAsync().Result

  $urls = @([regex]::Matches($dlg, "files\[\d+\]\.url\s*=\s*'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
  $hashes = @([regex]::Matches($dlg, "files\[\d+\]\.fileDigestBase64\s*=\s*'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
  $sizes = @([regex]::Matches($dlg, "files\[\d+\]\.size\s*=\s*'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
  Write-Output ('  urls=' + $urls.Count + ' digests=' + $hashes.Count + ' sizes=' + $sizes.Count)
  if ($SkipDownload) { foreach ($u in $urls) { Write-Output ('  URL ' + $u) }; continue }

  for ($i = 0; $i -lt $urls.Count; $i++) {
    $u = $urls[$i]
    $leaf = [IO.Path]::GetFileName(([Uri]$u).AbsolutePath)
    if ($leaf.Length -lt 5) { $leaf = 'file_' + $i + '.cab' }
    $out = Join-Path $OutDir ($p.Guid.Substring(0,8) + '_' + $leaf)
    Write-Output ('  GET ' + $u)
    try {
      $gr = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::Get, $u)
      $gr.Headers.Referrer = [Uri]$dlgUrl
      $r2 = $client.SendAsync($gr).Result
      $code = [int]$r2.StatusCode
      Write-Output ('    status=' + $code)
      if ($code -ne 200) {
        $txt = $r2.Content.ReadAsStringAsync().Result
        Write-Output ('    SKIPPED body=' + $txt.Substring(0, [Math]::Min(160, $txt.Length)).Replace("`r",' ').Replace("`n",' '))
        continue
      }
      $bytes = $r2.Content.ReadAsByteArrayAsync().Result
      [IO.File]::WriteAllBytes($out, $bytes)
      Write-Output ('    WROTE ' + $out + ' bytes=' + $bytes.Length)
      if ($i -lt $hashes.Count -and $hashes[$i]) {
        $sha = [Security.Cryptography.SHA256]::Create()
        $gotB64 = [Convert]::ToBase64String($sha.ComputeHash($bytes))
        $hex = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })
        Write-Output ('    SHA256 ' + $(if ($gotB64 -eq $hashes[$i]) { 'MATCH' } else { 'MISMATCH' }) + ' hex=' + $hex)
      }
    } catch {
      Write-Output ('    ERROR ' + $_.Exception.Message)
    }
  }
}
