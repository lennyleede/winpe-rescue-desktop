param([string]$Path = 'downloads\storage\extracted')
# List PCI device ids claimed by every INF under $Path (UTF-16 or ANSI), plus class + DriverVer.
# Needed because the shipped index builder only reads Class=Net; before baking storage drivers we
# must know exactly which VEN/DEV pairs each package covers.
function Read-InfText([string]$f) {
  $b = [IO.File]::ReadAllBytes($f)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
    return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
  }
  return [Text.Encoding]::UTF8.GetString($b)
}
$files = @([IO.Directory]::GetFiles($Path, '*.inf', 'AllDirectories'))
Write-Output ('INF files = ' + $files.Count)
foreach ($f in $files) {
  $t = Read-InfText $f
  $ids = @([regex]::Matches($t, '(?i)PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') |
    ForEach-Object { ('PCI\VEN_' + $_.Groups[1].Value.ToUpper() + '&DEV_' + $_.Groups[2].Value.ToUpper()) } |
    Sort-Object -Unique)
  $cls = ''
  if ($t -match '(?im)^\s*Class\s*=\s*(\S+)') { $cls = $matches[1] }
  $dv = ''
  if ($t -match '(?im)^\s*DriverVer\s*=\s*([^\r\n]+)') { $dv = $matches[1].Trim() }
  $short = @($ids | Where-Object { $_ -notmatch '&SUBSYS' })
  Write-Output ('--- ' + [IO.Path]::GetFileName($f))
  Write-Output ('    class=' + $cls + '  DriverVer=' + $dv + '  ids=' + $short.Count)
  Write-Output ('    ' + (($short | Select-Object -First 40) -join ' '))
}
