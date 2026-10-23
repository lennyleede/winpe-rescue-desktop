param([string[]]$Files)
$ErrorActionPreference = 'Stop'
foreach ($f in $Files) {
  $p = (Resolve-Path $f).Path
  $errs = $null
  [void][System.Management.Automation.PSParser]::Tokenize((Get-Content $p -Raw), [ref]$errs)
  if ($errs.Count) {
    Write-Host ("SYNTAX-FAIL " + $p) -ForegroundColor Red
    foreach ($e in $errs) { Write-Host ("  line " + $e.Token.StartLine + ": " + $e.Message) }
  } else {
    Write-Host ("SYNTAX-OK " + $p) -ForegroundColor Green
  }
}
