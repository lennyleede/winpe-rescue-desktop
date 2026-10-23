$ErrorActionPreference = 'Continue'
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$item = Get-Item $k
Write-Host ('values=' + ($item.GetValueNames().Count) + ' subkeys=' + ($item.GetSubKeyNames().Count -join ','))
foreach ($n in ($item.GetValueNames() | Sort-Object)) {
  $v = @($item.GetValue($n))
  foreach ($t in @('wlansvc', 'wcmsvc', 'dot3svc', 'WwanSvc')) {
    if ($v -contains $t) { Write-Host ($t + ' -> group ' + $n + ' (len=' + $v.Count + ')') }
  }
}
Write-Host '--- subkey detail (per-group ObjectName/RequiredPrivileges) ---'
foreach ($s in $item.GetSubKeyNames()) {
  if ($s -match 'LocalSystemNetworkRestricted|^PEWLan|LocalService$') {
    Write-Host ('[' + $s + ']')
    Get-ItemProperty (Join-Path $k $s) | ForEach-Object { $_.PSObject.Properties } |
      Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Write-Host ('   ' + $_.Name + ' = ' + ($_.Value -join ';')) }
  }
}
