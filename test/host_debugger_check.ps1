# host_debugger_check.ps1 -- do we have a kernel minidump analyzer on the workstation, and if not,
# what is the shortest path to one? Run as the ordinary user; it only reads.
$ErrorActionPreference = 'Continue'
Write-Output 'DEBUGGER-CHECK'
$names = @('cdb.exe', 'windbg.exe', 'kd.exe')
$found = @()
foreach ($n in $names) {
  $c = Get-Command $n -ErrorAction SilentlyContinue
  if ($c) { $found += $c.Source }
  foreach ($root in @('C:\Program Files (x86)\Windows Kits\10\Debuggers\x64',
                      'C:\Program Files\Windows Kits\10\Debuggers\x64',
                      'C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64')) {
    $p = Join-Path $root $n
    if (Test-Path -LiteralPath $p) { $found += $p }
  }
}
Write-Output ('  analyzers found = ' + $(if ($found.Count) { $found -join ' ; ' } else { 'NONE' }))
$w = Get-Command winget -ErrorAction SilentlyContinue
Write-Output ('  winget = ' + $(if ($w) { $w.Source } else { 'ABSENT (use the SDK installer or choco)' }))
$choco = Get-Command choco -ErrorAction SilentlyContinue
Write-Output ('  choco = ' + $(if ($choco) { $choco.Source } else { 'ABSENT' }))
try {
  $r = Invoke-WebRequest -Uri 'https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/' -UseBasicParsing -TimeoutSec 10
  Write-Output ('  symbol server reachable = ok ' + $r.StatusCode)
} catch { Write-Output ('  symbol server reachable = FAIL ' + $_.Exception.Message.Substring(0, [Math]::Min(90, $_.Exception.Message.Length))) }
Write-Output 'INSTALL-OPTIONS (need admin -- run these yourself and paste any error)'
Write-Output '  A) winget install --id Microsoft.WinDbg -e --source msstore --accept-package-agreements --accept-source-agreements'
Write-Output '  B) winget install "Windows SDK for Windows Store Apps" is NOT what we want; use the classic SDK:'
Write-Output '     https://go.microsoft.com/fwlink/?linkid=2243961  (winsdksetup.exe) then select "Debugging Tools for Windows"'
Write-Output '  C) lightest: the standalone cdb package via the SDK above; no full Visual Studio needed.'
Write-Output 'END'
