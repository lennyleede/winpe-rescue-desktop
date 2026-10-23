Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $PSScriptRoot 'share\sshd77.zip'))
foreach ($name in 'OpenSSH-Win64/install-sshd.ps1') {
  $e = $z.GetEntry($name)
  $r = New-Object IO.StreamReader($e.Open())
  $t = $r.ReadToEnd(); $r.Close()
  ($t -split "`n" | Select-Object -Skip 28) -join "`n"
}
$z.Dispose()
