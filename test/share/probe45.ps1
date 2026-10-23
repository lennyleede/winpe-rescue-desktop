# probe45 -- LIVE PE, READ-ONLY forensics on the target machine's own installed Windows.
# Situation (probe41..44 + X:\netdrvfix.log): the bake is complete, vwifibus loads, but the AX211
# (PCI\VEN_8086&DEV_7A70, service Netwtw14 / netwtw08) lands on code 37 = driver failed to load,
# for BOTH Intel packages in our pool, while the Realtek 8125 wired NIC went 18 -> 0 in the same run.
# PE keeps no setupapi/event-log text, so the cheapest way to learn "which driver actually works for
# this exact chip on this exact laptop" is to read the laptop's own Windows volume (D: here).
# Nothing is written: D: is only enumerated/read; the SYSTEM hive is reg-loaded under a temp key and
# unloaded in a finally block (that touches only the PE's own in-memory registry, X: is a ramdisk).
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }

$vol = ''
foreach ($c in 'D:\', 'E:\', 'C:\') {
  if (Test-Path ($c + 'Windows\System32\DriverStore\FileRepository')) { $vol = $c; break }
}
if (-not $vol) { O 'P45 NOFIND no Windows volume with DriverStore on D:/E:/C:'; O 'P45 END'; exit 0 }
O ('P45 VOLUME ' + $vol)
$fr = $vol + 'Windows\System32\DriverStore\FileRepository'
$nds = @(Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)netwtw|netwaw|iwm|Netwtw04|Netwtw08' })
O ('P45 PKGS ' + $nds.Count)
foreach ($d in $nds) {
  $inf = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.inf' -File -EA SilentlyContinue)
  foreach ($i in $inf) {
    $t = @(Get-Content -LiteralPath $i.FullName -Encoding Unicode -EA SilentlyContinue)
    $dv = @($t | Where-Object { "$_" -match '(?i)^\s*DriverVer' } | Select-Object -First 1)
    $cat = @($t | Where-Object { "$_" -match '(?i)^\s*CatalogFile' } | Select-Object -First 1)
    $ids = @($t | Where-Object { "$_" -match 'DEV_7A70|DEV_272B|DEV_51F1' }).Count
    $sysv = ''
    $sy = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.sys' -File -Recurse -EA SilentlyContinue)
    foreach ($s in $sy) { $sysv += ($s.Name + '=' + $s.VersionInfo.FileVersion + ' ') }
    O ('  PKG ' + $d.Name + ' inf=' + $i.Name + ' [' + (("$dv" -replace '\s+', ' ').Trim()) + '] [' + (("$cat" -replace '\s+', ' ').Trim()) + '] targetids=' + $ids)
    O ('      SYS ' + $sysv.Trim())
  }
}
O 'P45 ---- which installed oem inf matches DEV_7A70 ----'
$oi = @(Get-ChildItem ($vol + 'Windows\INF') -Filter 'oem*.inf' -File -EA SilentlyContinue)
O ('  OEMTOTAL ' + $oi.Count)
foreach ($f in $oi) {
  $t = @(Get-Content -LiteralPath $f.FullName -Encoding Unicode -EA SilentlyContinue)
  if (@($t | Where-Object { "$_" -match 'DEV_7A70' }).Count -gt 0) {
    $dv = @($t | Where-Object { "$_" -match '(?i)^\s*DriverVer' } | Select-Object -First 1)
    $sec = @($t | Where-Object { "$_" -match 'DEV_7A70' } | Select-Object -First 1)
    O ('  MATCH ' + $f.Name + ' [' + (("$dv" -replace '\s+', ' ').Trim()) + '] row=' + (("$sec" -replace '\s+', ' ').Trim()))
  }
}
O 'P45 ---- offline SYSTEM hive: the devnode + class key of the working install ----'
$hive = $vol + 'Windows\System32\config\SYSTEM'
$key = 'HKLM\P45OFF'
$loaded = $false
try {
  & reg.exe load $key ("$hive") 2>&1 | ForEach-Object { O ('  LOAD ' + (($_ -replace '\s+', ' ').Trim())) }
  if (@(& reg.exe query "$key" 2>&1).Count -gt 0 -and ("$(& reg.exe query "$key" 2>&1)") -notmatch 'ERROR') {
    $loaded = $true
    $cc = $key + '\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $subs = @(& reg.exe query "$cc" 2>&1 | ForEach-Object { ("$_").Trim() }) | Where-Object { $_ -match '\\\d{4}$' }
    foreach ($s in $subs) {
      $vals = @(& reg.exe query "$s" 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
      $txt = $vals -join '|'
      if ($txt -match '(?i)7A70|Wi-Fi|Wireless|AX211|netwtw') {
        $desc = @($vals | Where-Object { $_ -match 'DriverDesc' })
        $ip = @($vals | Where-Object { $_ -match 'InfPath' })
        $vv = @($vals | Where-Object { $_ -match 'DriverVersion' })
        $ii = @($vals | Where-Object { $_ -match 'IncludedInfs' })
        $svc = @($vals | Where-Object { $_ -match 'ActiveServer' })
        O ('  OFFCLASS ' + ($s -split '\\')[-1] + ' ' + (($desc + $ip + $vv + $ii) -join ' '))
      }
    }
    $en = $key + '\ControlSet001\Enum\PCI'
    $ven = @(& reg.exe query "$en" 2>&1 | ForEach-Object { ("$_").Trim() }) | Where-Object { $_ -match 'VEN_8086&DEV_7A70' }
    foreach ($v in $ven) {
      $insts = @(& reg.exe query "$v" 2>&1 | ForEach-Object { ("$_").Trim() }) | Where-Object { $_ -match ('^' + [regex]::Escape($v) + '\\') }
      foreach ($i2 in $insts) {
        $vals = @(& reg.exe query "$i2" /s 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
        $pick = @($vals | Where-Object { $_ -match 'Service|UpperFilters|LowerFilters|Driver\s|Class\s|ProblemCode' })
        O ('  OFFDEV ' + ($i2 -replace ('^' + [regex]::Escape($key)), '') + ' :: ' + ($pick -join ' ;; '))
      }
    }
    foreach ($n in 'Netwtw14', 'Netwtw08', 'Netwtw04', 'vwifibus', 'vwififlt', 'nativewifip', 'wlansvc') {
      $k2 = $key + '\ControlSet001\Services\' + $n
      $q = @(& reg.exe query "$k2" 2>&1 | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() })
      if ($q.Count -le 1) { O ('  OFFSVC ' + $n + ' absent') } else {
        $p2 = @($q | Where-Object { $_ -match '^\s*(Start|Type|Group|ImagePath|DependOnService|ErrorControl)\s' })
        O ('  OFFSVC ' + $n + ' :: ' + ($p2 -join ' ;; '))
      }
    }
  }
} catch { O ('  OFFERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
finally {
  if ($loaded) {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    & reg.exe unload $key 2>&1 | ForEach-Object { O ('  UNLOAD ' + (($_ -replace '\s+', ' ').Trim())) }
  }
  O ('  UNLOADCHECK ' + (@(& reg.exe query $key 2>&1 | ForEach-Object { "$_" })[0] -replace '\s+', ' '))
}
O 'P45 END'

