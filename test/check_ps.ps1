param([string]$Path = 'vm_verify7.ps1')
$b = [IO.File]::ReadAllBytes($Path)
'first6: ' + (($b[0..5] | ForEach-Object { $_.ToString('X2') }) -join ' ')
$t = [IO.File]::ReadAllText($Path)
$e = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($t, [ref]$null, [ref]$e)
if ($e.Count -gt 0) {
  'PARSE ERRORS: ' + $e.Count
  $e | ForEach-Object { ('  {0}: {1}' -f $_.Extent.StartLineNumber, $_.Message) }
} else { 'PARSE OK' }
