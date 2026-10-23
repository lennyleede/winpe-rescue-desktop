param(
  [string]$Url = 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/driver/drvs/2026/04/b11fec46-8446-41c2-9319-c83718387121_3bf99fd1e54b010661a802adba3851fac78a8800.cab',
  [string]$Dir = 'X:\drv'
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# Prove the on-site path: PE downloads a driver cab from the public catalog itself, expands it,
# and stages it with pnputil. Nothing here touches a disk or a device -- staging is reversible
# (pnputil /delete-driver oemN.inf), so this is safe to run on a live rescue box.
function L([string]$s) { Write-Output ((Get-Date).ToString('HH:mm:ss') + '  ' + $s) }

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$leaf = [IO.Path]::GetFileName(([Uri]$Url).AbsolutePath)
$cab = Join-Path $Dir $leaf
L ('GET ' + $Url)
try {
  $r = Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $cab -TimeoutSec 120
  $fi = Get-Item -LiteralPath $cab
  L ('DOWNLOADED ' + $fi.Length + ' bytes')
} catch {
  L ('DOWNLOAD_FAILED ' + $_.Exception.Message)
  return
}
$sha = [Security.Cryptography.SHA256]::Create()
$hex = -join ($sha.ComputeHash((Get-Content -LiteralPath $cab -Encoding Byte -ReadCount 0)) | ForEach-Object { $_.ToString('x2') })
L ('SHA256 ' + $hex)

$xdir = Join-Path $Dir ($leaf + '.d')
New-Item -ItemType Directory -Force -Path $xdir | Out-Null
& expand.exe -F:* $cab $xdir 2>&1 | Out-Null
$infs = @([IO.Directory]::GetFiles($xdir, '*.inf'))
L ('EXTRACTED infs=' + $infs.Count + ' files=' + @([IO.Directory]::GetFiles($xdir)).Count)
foreach ($f in $infs) { L ('  INF ' + [IO.Path]::GetFileName($f) + ' ' + (Get-Item -LiteralPath $f).Length + 'B') }

foreach ($f in $infs) {
  L ('STAGE ' + [IO.Path]::GetFileName($f))
  $o = & pnputil.exe /add-driver $f 2>&1 | Out-String
  foreach ($ln in ($o -split "`r?`n")) { if ($ln.Trim().Length) { L ('  | ' + $ln.Trim()) } }
}
L 'NOW STAGED (storage-class only):'
$o2 = & pnputil.exe /enum-drivers 2>&1 | Out-String
$blocks = $o2 -split "(?=Published Name)"
foreach ($b in $blocks) {
  if ($b -notmatch '(?im)^\s*Class(?: Name)?\s*:\s*(SCSIAdapter|IDE|RAID|DiskDrive|System)') { continue }
  $pub = if ($b -match '(?im)Published Name\s*:\s*(\S+)') { $matches[1] } else { '?' }
  $org = if ($b -match '(?im)Original Name\s*:\s*(\S+)') { $matches[1] } else { '?' }
  $cls = if ($b -match '(?im)^\s*Class(?: Name)?\s*:\s*(\S+)') { $matches[1] } else { '?' }
  $ver = if ($b -match '(?im)Driver Version\s*:\s*(.+)') { $matches[1].Trim() } else { '?' }
  L ('  ' + $pub + ' | ' + $org + ' | ' + $cls + ' | ' + $ver)
}
L 'DONE (undo staging with: pnputil /delete-driver <oemN.inf>)'
