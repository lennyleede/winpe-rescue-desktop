# ============================================================
# peimports.ps1 -- read a PE file's import table without dumpbin.
# Why: wlansvc/wcmsvc now fail with 1053 (probe49) instead of 1068, i.e. svchost loads the service DLL
# but the service never reports RUNNING. The classic reason left standing is a static import that
# cannot be resolved in WinPE (a DLL the ADK image simply does not carry, or a VC runtime). LoadLibrary
# of the service DLL would then fail inside svchost with nothing in the event log -- PE has no System
# log -- so we read the imports out of the file bytes and check them against the image ourselves.
# Usage (host):  powershell -NoProfile -ExecutionPolicy Bypass -File test\share\peimports.ps1 -SelfHost
#               powershell ... -File test\share\peimports.ps1 -Target 'X:\Windows\System32\wlansvc.dll'
# ============================================================
param(
  [string]$Target = '',
  [switch]$SelfHost,
  [switch]$Json
)
$ErrorActionPreference = 'Stop'

function Get-PeImports([string]$Path) {
  if (-not (Test-Path $Path)) { throw ("missing file " + $Path) }
  $b = [System.IO.File]::ReadAllBytes($Path)
  if ($b.Length -lt 0x40) { throw 'too small' }
  $e_lfanew = [System.BitConverter]::ToInt32($b, 0x3C)
  if ([System.BitConverter]::ToInt16($b, $e_lfanew) -ne 0x5A4D -and $b[$e_lfanew] -ne 0x50) { }
  if ([System.BitConverter]::ToUInt32($b, $e_lfanew) -ne 0x00004550) { throw ('bad PE signature at 0x' + $e_lfanew.ToString('X')) }
  $coff = $e_lfanew + 4
  $numSections = [System.BitConverter]::ToUInt16($b, $coff + 2)
  $sizeOptional = [System.BitConverter]::ToUInt16($b, $coff + 16)
  $magic = [System.BitConverter]::ToUInt16($b, $coff + 20)
  $opt = $coff + 20
  $is32 = ($magic -eq 0x10b)
  $numRva = if ($is32) { 96 } else { 112 }
  # data directory 1 = import table
  $dd = $opt + $numRva
  $impRva = [System.BitConverter]::ToUInt32($b, $dd + 8)
  $impSize = [System.BitConverter]::ToUInt32($b, $dd + 12)
  $sec = $opt + $sizeOptional
  $sections = @()
  for ($i = 0; $i -lt $numSections; $i++) {
    $o = $sec + $i * 40
    # IMAGE_SECTION_HEADER: Name[8], VirtualSize@8, VirtualAddress@12, SizeOfRawData@16, PointerToRawData@20
    # (getting these two swapped turns every RVA translation into machine code -- that is what produced
    #  the "BAD_RVA_0x48000000" wall on the first run)
    $sections += [pscustomobject]@{
      va     = [System.BitConverter]::ToUInt32($b, $o + 12)
      vsz    = [System.BitConverter]::ToUInt32($b, $o + 8)
      rawsz  = [System.BitConverter]::ToUInt32($b, $o + 16)
      raw    = [System.BitConverter]::ToUInt32($b, $o + 20)
      name   = ([System.Text.Encoding]::ASCII.GetString($b, $o, 8) -replace '`0', '')
    }
  }
  function RvaToOff([uint32]$rva) {
    foreach ($s in $sections) {
      if ($rva -ge $s.va -and $rva -lt ($s.va + [Math]::Max($s.vsz, $s.rawsz))) {
        $o = [int]($s.raw + ($rva - $s.va))
        if ($o -ge 0 -and $o -lt $b.Length) { return $o }
        return -1
      }
    }
    return -1
  }
  $names = @()
  if ($impRva -eq 0 -or $impSize -eq 0) { return @{ names = @(); delay = @(); hasImports = $false } }
  $entrySize = if ($is32) { 20 } else { 20 }
  $p = RvaToOff $impRva
  for ($n = 0; $n -lt 400; $n++) {
    $o = $p + $n * $entrySize
    $origThunk = [System.BitConverter]::ToUInt32($b, $o + 0)
    $nameRva   = [System.BitConverter]::ToUInt32($b, $o + 12)
    $firstThunk= [System.BitConverter]::ToUInt32($b, $o + 16)
    if ($nameRva -eq 0 -and $origThunk -eq 0 -and $firstThunk -eq 0) { break }
    $no = RvaToOff $nameRva
    if ($no -lt 0) { $names += ('BAD_RVA_0x' + $nameRva.ToString('X')); continue }
    $sb = New-Object System.Text.StringBuilder
    for ($k = 0; $k -lt 260; $k++) {
      $c = $b[$no + $k]
      if ($c -eq 0) { break }
      [void]$sb.Append([char]$c)
    }
    $names += $sb.ToString()
  }
  # bound/delay imports live in directories 11 (bound) and 13 (delay); delay is what really matters
  $delayRva = 0; $delaySize = 0
  $dd2 = $opt + $numRva
  if ($dd2 + 12*8 -lt $b.Length) {
    $delayRva  = [System.BitConverter]::ToUInt32($b, $dd2 + 13*8)
    $delaySize = [System.BitConverter]::ToUInt32($b, $dd2 + 13*8 + 4)
  }
  $dl = @()
  if ($delayRva -ne 0 -and $delaySize -ne 0) {
    $dp = RvaToOff $delayRva
    # ImgDelayDescr: 5 DWORDs (v1, with attributes first in v2) -- treat the 2nd DWORD as the name RVA
    for ($n = 0; $n -lt 200; $n++) {
      $o = $dp + $n * 32
      $dName = [System.BitConverter]::ToUInt32($b, $o + 4)
      if ($dName -eq 0) { break }
      $no = RvaToOff $dName
      if ($no -lt 0) { $dl += ('BAD_DELAY_0x' + $dName.ToString('X')); continue }
      $sb = New-Object System.Text.StringBuilder
      for ($k = 0; $k -lt 260; $k++) { $c = $b[$no + $k]; if ($c -eq 0) { break }; [void]$sb.Append([char]$c) }
      $dl += $sb.ToString()
    }
  }
  return @{ names = $names; delay = $dl; hasImports = $true; is32 = $is32 }
}

# Export directory (data directory 0) -- the probe needs one answer: does the DLL actually export the entry
# point its registry key names? IMAGE_EXPORT_DIRECTORY:
#   +12 Name RVA, +20 NumberOfFunctions, +24 NumberOfNames, +28 AddressOfFunctions,
#   +32 AddressOfNames, +36 AddressOfNameOrdinals
function Get-PeExports([string]$Path) {
  $b = [System.IO.File]::ReadAllBytes($Path)
  $e_lfanew = [System.BitConverter]::ToInt32($b, 0x3C)
  if ([System.BitConverter]::ToUInt32($b, $e_lfanew) -ne 0x00004550) { throw 'bad PE signature' }
  $coff = $e_lfanew + 4
  $numSections = [System.BitConverter]::ToUInt16($b, $coff + 2)
  $sizeOptional = [System.BitConverter]::ToUInt16($b, $coff + 16)
  $opt = $coff + 20
  $is32 = ([System.BitConverter]::ToUInt16($b, $coff + 20) -eq 0x10b)
  $numRva = if ($is32) { 96 } else { 112 }
  $dd = $opt + $numRva
  $expRva = [System.BitConverter]::ToUInt32($b, $dd + 0)
  $expSize = [System.BitConverter]::ToUInt32($b, $dd + 4)
  $sec = $opt + $sizeOptional
  $sections = @()
  for ($i = 0; $i -lt $numSections; $i++) {
    $o = $sec + $i * 40
    $sections += [pscustomobject]@{
      va    = [System.BitConverter]::ToUInt32($b, $o + 12)
      vsz   = [System.BitConverter]::ToUInt32($b, $o + 8)
      rawsz = [System.BitConverter]::ToUInt32($b, $o + 16)
      raw   = [System.BitConverter]::ToUInt32($b, $o + 20)
    }
  }
  function XToOff([uint32]$rva) {
    foreach ($s in $sections) {
      if ($rva -ge $s.va -and $rva -lt ($s.va + [Math]::Max($s.vsz, $s.rawsz))) {
        $o = [int]($s.raw + ($rva - $s.va))
        if ($o -ge 0 -and $o -lt $b.Length) { return $o }
        return -1
      }
    }
    return -1
  }
  $out = @()
  if ($expRva -eq 0 -or $expSize -eq 0) { return $out }
  $eo = XToOff $expRva
  if ($eo -lt 0) { return $out }
  $nNames = [System.BitConverter]::ToUInt32($b, $eo + 24)
  $pNet = XToOff ([System.BitConverter]::ToUInt32($b, $eo + 32))
  if ($pNet -lt 0 -or $nNames -eq 0 -or $nNames -gt 20000) { return $out }
  for ($i = 0; $i -lt $nNames; $i++) {
    $no = XToOff ([System.BitConverter]::ToUInt32($b, $pNet + $i * 4))
    if ($no -lt 0) { continue }
    $sb = New-Object System.Text.StringBuilder
    for ($k = 0; $k -lt 300; $k++) { $c = $b[$no + $k]; if ($c -eq 0) { break }; [void]$sb.Append([char]$c) }
    $out += $sb.ToString()
  }
  return $out
}

$targets = @()
if ($SelfHost) {
  # The host's own keys are the authority for what the bake must write (build/scratch/t_host_svcparams.ps1):
  #   wlansvc -> WlanSvcMain, wcmsvc -> WcmSvcMain, dot3svc -> Dot3SvcMain, Dhcp -> (no ServiceMain value)
  $entry = @{ 'wlansvc.dll' = 'WlanSvcMain'; 'wcmsvc.dll' = 'WcmSvcMain'; 'dot3svc.dll' = 'Dot3SvcMain';
              'dhcpcore.dll' = ''; 'wlanapi.dll' = ''; 'msmmsvc.dll' = ''; 'fdPHost.dll' = '' }
  $targets = @('wlansvc.dll', 'wcmsvc.dll', 'wlanapi.dll', 'dot3svc.dll', 'dhcpcore.dll', 'msmmsvc.dll', 'fdPHost.dll')
  foreach ($t in $targets) {
    $p = Join-Path $env:WINDIR ("System32\" + $t)
    if (-not (Test-Path $p)) { Write-Host ($t + ' ABSENT on the host'); continue }
    try {
      $r = Get-PeImports $p
      Write-Host ('==== ' + $t + ' imports=' + @($r.names).Count + ' delay=' + @($r.delay).Count)
      Write-Host ('  STATIC: ' + ((@($r.names) | Sort-Object -Unique) -join ' '))
      if (@($r.delay).Count) { Write-Host ('  DELAY : ' + ((@($r.delay) | Sort-Object -Unique) -join ' ')) }
      $ex = @(Get-PeExports $p)
      $mains = @($ex | Where-Object { $_ -match '(?i)main$' } | Sort-Object -Unique)
      $want = $entry[$t]
      $hit = if ($want) { if ($ex -contains $want) { 'EXPORTED' } else { '*** NOT EXPORTED ***' } } else { 'n/a' }
      Write-Host ('  EXPORTS=' + $ex.Count + ' entry[' + $want + ']=' + $hit + ' *Main*=' + ($mains -join ','))
    } catch { Write-Host ('==== ' + $t + ' PARSE FAIL: ' + $_.Exception.Message) }
  }
} elseif ($Target) {
  $r = Get-PeImports $Target
  if ($Json) { ($r | ConvertTo-Json -Compress) } else {
    Write-Host ('==== ' + $Target)
    Write-Host ('  STATIC: ' + ((@($r.names) | Sort-Object -Unique) -join ' '))
    Write-Host ('  DELAY : ' + ((@($r.delay) | Sort-Object -Unique) -join ' '))
  }
} else {
  Write-Host 'give -SelfHost or -Target'
}
