# Read-only helper for the B2 failure: pull the setupapi offline log out of the mounted image
# (patch_wifi /Discard deletes everything in the mount, so the reason for a rejected package
# would otherwise be destroyed together with the evidence).
param([string]$Mount, [string]$OutDir)
$ErrorActionPreference = 'Continue'
if (-not $Mount) { $Mount = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\mount' }
if (-not $OutDir) { $OutDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\scratch\salvage' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$n = 0
foreach ($pat in @('setupapi.offline.log', 'setupapi.offline.log.~tlt', 'WINNETLG.*', 'setupapi.dev.log')) {
  foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Mount 'Windows\INF') -Filter $pat -File -EA SilentlyContinue)) {
    $dst = Join-Path $OutDir ((Get-Date -Format 'HHmmss_') + $f.Name)
    try { Copy-Item -LiteralPath $f.FullName -Destination $dst -Force; $n++
      Write-Host ('  SALVAGED ' + $f.Name + ' -> ' + $dst + ' (' + $f.Length + 'B)') }
    catch { Write-Host ('  !! copy ' + $f.Name + ' failed: ' + $_.Exception.Message) }
  }
}
if ($n -eq 0) { Write-Host '  NO-SETUPAPI-LOG: nothing to salvage from <mount>\Windows\INF (DISM did not write there, or the mount is already gone)' }
# 顺手把最后一份 setupapi.offline.log 里的 Error/失败行打印出来(ASCII, 便于 ssh 回传)
$last = @(Get-ChildItem $OutDir -Filter 'setupapi.offline.log*' -File -EA SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1)
if ($last.Count -gt 0) {
  $p = $last[0].FullName
  Write-Host ('  ---- error/fail lines from ' + (Split-Path $p -Leaf) + ' ----')
  @(Get-Content -LiteralPath $p -Encoding Unicode -EA SilentlyContinue |
    Where-Object { $_ -match '(?i)error|fail|could not|not found|invalid|denied' } |
    Select-Object -Last 15) | ForEach-Object { Write-Host ('    ' + (($_ -replace '\s+', ' ').Trim())) }
}
