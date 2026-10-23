# pe_tool_inventory.ps1 -- what can this PE do on its own? Answers the Step 3 design question:
# which transport (curl / scp / ssh / Invoke-WebRequest) and which compressor (tar / .NET GZip)
# are actually present, so `rescue` does not promise a channel that does not exist.
# ASCII output only: PE logs are read through cmd/ssh in CP936.
$ErrorActionPreference = 'Continue'
function Have([string]$n) {
  $p = (Get-Command $n -ErrorAction SilentlyContinue)
  if ($p) { return $p.Source }
  foreach ($d in @("$env:SystemRoot\System32", "$env:SystemRoot\System32\WindowsPowerShell\v1.0", "$env:SystemRoot")) {
    $f = Join-Path $d $n
    if (Test-Path -LiteralPath $f) { return $f }
  }
  return 'ABSENT'
}
Write-Output 'TOOL-INVENTORY'
foreach ($t in @('curl.exe','tar.exe','scp.exe','ssh.exe','certutil.exe','manage-bde.exe','wevtutil.exe',
                 'pnputil.exe','dism.exe','msinfo32.exe','driverquery.exe','quser.exe','tasklist.exe',
                 'verifier.exe','sfc.exe','diantx.exe','cdb.exe','windbg.exe','gpedit.msc','notepad.exe')) {
  Write-Output ('  ' + $t + ' = ' + (Have $t))
}
Write-Output 'DOTNET-COMPRESS'
foreach ($asm in @('System.IO.Compression','System.IO.Compression.FileSystem')) {
  try { Add-Type -AssemblyName $asm -ErrorAction Stop; Write-Output ('  assembly ' + $asm + ' = loaded') }
  catch { Write-Output ('  assembly ' + $asm + ' = ' + $_.Exception.Message) }
}
$types = @('System.IO.Compression.GZipStream','System.IO.Compression.ZipFile','System.IO.Compression.DeflateStream')
foreach ($t in $types) {
  $typ = $null
  foreach ($asm in [AppDomain]::CurrentDomain.GetAssemblies()) {
    $typ = $asm.GetType($t)
    if ($typ) { break }
  }
  Write-Output ('  ' + $t + ' = ' + $(if ($typ) { 'ok' } else { 'ABSENT' }))
}
Write-Output ('PS-VERSION = ' + $PSVersionTable.PSVersion.ToString())
Write-Output 'FREE-SPACE'
foreach ($d in @('X:\','Y:\','Z:\')) {
  if (Test-Path -LiteralPath $d) {
    $di = New-Object IO.DriveInfo($d)
    Write-Output ('  ' + $d + ' free=' + [math]::Round($di.AvailableFreeSpace/1MB) + 'MB total=' + [math]::Round($di.TotalSize/1MB) + 'MB')
  } else { Write-Output ('  ' + $d + ' absent') }
}
Write-Output 'DUMPS'
foreach ($p in @('X:\Windows\Minidump','X:\Windows\MEMORY.DMP')) {
  Write-Output ('  ' + $p + ' = ' + $(if (Test-Path -LiteralPath $p) { 'present' } else { 'absent' }))
}
# the offline target system usually lives on D: or E: when X: is the ramdisk
foreach ($p in @('C:\Windows','D:\Windows','E:\Windows')) {
  Write-Output ('  ' + $p + ' = ' + $(if (Test-Path -LiteralPath $p) { 'present' } else { 'absent' }))
}
Write-Output 'NET'
try {
  $r = Invoke-WebRequest -Uri 'https://www.baidu.com' -UseBasicParsing -TimeoutSec 10
  Write-Output ('  egress = ok ' + $r.StatusCode)
} catch { Write-Output ('  egress = FAIL ' + $_.Exception.Message) }
Write-Output 'END-INVENTORY'
