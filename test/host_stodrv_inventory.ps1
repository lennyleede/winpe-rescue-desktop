$ErrorActionPreference = 'Continue'
# What storage-class driver packages does the HOST have staged? Those can be copied straight into
# overlay\Drivers\Storage without any download (same trick used for the NIC packages).
$out = & pnputil.exe /enum-drivers 2>&1 | Out-String
$blocks = $out -split "(?=Published Name)"
$keep = @()
foreach ($b in $blocks) {
  if ($b -match '(?im)^\s*Class(?: Name)?\s*:\s*(SCSIAdapter|CD-ROM|DiskDrive|System|SoftwareComponent|USB|HDC|Media)') {
    $cls = $matches[1]
    $pub = if ($b -match '(?im)Published Name\s*:\s*(\S+)') { $matches[1] } else { '?' }
    $org = if ($b -match '(?im)Original Name\s*:\s*(\S+)') { $matches[1] } else { '?' }
    $prv = if ($b -match '(?im)Provider Name\s*:\s*(.+)') { $matches[1].Trim() } else { '?' }
    $ver = if ($b -match '(?im)Driver Version\s*:\s*(.+)') { $matches[1].Trim() } else { '?' }
    $path= if ($b -match '(?im)Driver Package (?:Path|Location)\s*:\s*(.+)') { $matches[1].Trim() } else { '?' }
    $keep += [pscustomobject]@{ Class=$cls; Published=$pub; Original=$org; Provider=$prv; Version=$ver; Path=$path }
  }
}
Write-Output ('STORAGE_CLASS_PACKAGES = ' + $keep.Count)
foreach ($k in $keep) {
  Write-Output ('  ' + $k.Class + ' | ' + $k.Published + ' | ' + $k.Original + ' | ' + $k.Provider + ' | ' + $k.Version)
  Write-Output ('      path=' + $k.Path)
}
Write-Output '--- FileRepository inf names (all) ---'
$fr = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
$names = @([IO.Directory]::GetDirectories($fr) | ForEach-Object { [IO.Path]::GetFileName($_) })
$stor = @($names | Where-Object { $_ -match '(?i)^(ia|stor|amd|nvme|vmd|raid|mega|nvd|sis|uli|pciide|iastor)' })
Write-Output ('  dirs=' + $names.Count + ' storage-ish=' + $stor.Count)
foreach ($s in $stor) { Write-Output ('    ' + $s) }
