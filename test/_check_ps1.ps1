param([Parameter(Mandatory=$true)][string]$Target)
# Pre-handoff static check: BOM + parse + read-before-assign. ASCII only (this file must run anywhere).
$bytes = [System.IO.File]::ReadAllBytes($Target)
$hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
Write-Host ('BOM(UTF8) = ' + $hasBom + '   bytes = ' + $bytes.Length)
$src = [System.IO.File]::ReadAllText($Target, [System.Text.Encoding]::UTF8)
$errs = $null; $toks = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$toks, [ref]$errs)
if ($errs -and $errs.Count) {
  Write-Host ('PARSE ERRORS: ' + $errs.Count) -ForegroundColor Red
  foreach ($e in $errs) { Write-Host ('  line ' + $e.Extent.StartLineNumber + ': ' + $e.Message) }
} else { Write-Host 'PARSE: OK' -ForegroundColor Green }

# ALIAS COLLISIONS: in Windows PowerShell command-name resolution puts ALIASES ABOVE FUNCTIONS, so a
# helper named "rv" is Remove-Variable and one named "oh" is Out-Host -- both bit us in the field
# (probe code lost its log lines / a host dump threw positional-parameter errors mid-run).
$aliasNames = @{}
try {
  foreach ($al in @(Get-Alias -EA SilentlyContinue)) { $aliasNames[$al.Name.ToLower()] = $al.Definition }
} catch { }
$fnDecls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$collide = @()
foreach ($fd in $fnDecls) {
  $nm = $fd.Name.ToLower()
  if ($aliasNames.ContainsKey($nm)) { $collide += ($fd.Name + ' -> alias of ' + $aliasNames[$nm] + ' (line ' + $fd.Extent.StartLineNumber + ') -- the alias wins, your function is dead code') }
}
if ($collide.Count) {
  Write-Host ('ALIAS/NAME COLLISIONS: ' + $collide.Count) -ForegroundColor Red
  foreach ($c in $collide) { Write-Host ('  ' + $c) }
} else { Write-Host ('FUNCTION NAMES: OK (' + $fnDecls.Count + ' declared, none shadowed by an alias)') -ForegroundColor Green }

$assigned = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
  foreach ($t in $a.Left.FindAll({ param($x) $x -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
    [void]$assigned.Add($t.VariablePath.UserPath.ToLower())
  }
}
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
  [void]$assigned.Add($f.Variable.VariablePath.UserPath.ToLower())
}
if ($ast.ParamBlock) {
  foreach ($pp in $ast.ParamBlock.Parameters) { [void]$assigned.Add(($pp.Name -replace '^\$+', '').ToLower()) }
}
# scoped assignment ($script:x / $global:x) also counts as assigned somewhere
foreach ($t in $toks) {
  if ($t.Kind -eq [System.Management.Automation.Language.TokenKind]::Variable) {
    $u = $t.Text.Substring(1).ToLower()
    if ($u -match ':') { [void]$assigned.Add(($u -split ':',2)[1]) }
  }
}
$builtin = @('_', 'psitem', 'true', 'false', 'null', 'lastexitcode', 'error', 'host', 'executioncontext',
             'global', 'script', 'local', 'args', 'pwd', 'home', 'profile', 'input', 'matches', 'foreach', 'omnipsoptions',
             'psversiontable', 'isadmin', 'cspolicy')
$first = @{}
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
  $n = $v.VariablePath.UserPath.ToLower()
  if ($assigned.Contains($n) -or $builtin -contains $n) { continue }
  if (-not $first.ContainsKey($n)) { $first[$n] = $v.Extent.StartLineNumber }
}
if ($first.Count) {
  Write-Host 'SUSPECT: read but never assigned' -ForegroundColor Yellow
  foreach ($k in ($first.Keys | Sort-Object)) { Write-Host ('  $' + $k + '  first read at line ' + $first[$k]) }
} else { Write-Host 'VARIABLES: OK' -ForegroundColor Green }

$ln = 0
foreach ($line in ($src -split "`r?`n")) {
  $ln++
  if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=[^=]') {
    Write-Host ('  line ' + $ln + ' assignment without leading $? ' + $line.Trim()) -ForegroundColor Magenta
  }
}
$crlf = ([regex]::Matches($src, "`r`n")).Count
Write-Host ('CRLF lines = ' + $crlf + ' / total lines = ' + (($src -split "`n").Count))
