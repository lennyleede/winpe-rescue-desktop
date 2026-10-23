param([string[]]$Names = @('wcmsvc','wlansvc','nativewifip','Ndisuio','dot3svc'))
foreach ($n in $Names) {
  Write-Host ('===== ' + $n + ' =====')
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (-not (Test-Path $k)) { Write-Host '  (no key)'; continue }
  (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    $v = if ($_.Value -is [Array]) { $_.Value -join ';' } else { $_.Value }
    Write-Host ('  ' + $_.Name + ' = ' + $v)
  }
  foreach ($sub in (Get-ChildItem $k -EA SilentlyContinue)) {
    Write-Host ('  [' + $sub.PSChildName + ']')
    (Get-ItemProperty $sub.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $v = if ($_.Value -is [Array]) { $_.Value -join ';' } else { $_.Value }
      Write-Host ('    ' + $_.Name + ' = ' + $v)
    }
  }
}
