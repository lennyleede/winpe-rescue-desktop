foreach ($f in @('D:\QoderProject\国内版\生成winpe\test\01_CreateAndBootVM.ps1', 'D:\QoderProject\国内版\生成winpe\test\02_VerifyViaSSH.ps1')) {
  $e = $null
  [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e) | Out-Null
  Write-Output ("$f -> errors: " + $e.Count)
  $e | ForEach-Object { Write-Output ("  " + $_.Message + " @line " + $_.Extent.StartLineNumber) }
}
