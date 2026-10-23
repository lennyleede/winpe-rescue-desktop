# probe51 -- LIVE PE, read-only. Output P51.
# probe50 nailed the concrete registry difference: the laptop's WORKING devnode has
#   UpperFilters REG_MULTI_SZ vwifibus
# while the live PE's devnode for the very same PCI ID has NO UpperFilters value at all. Intel's INF asks for
# that with (318/57 times)   Include = netvwifibus.inf / Needs = VWiFiBus.CopyFiles, VWiFiBus.PnPFilterRegistration.HW,
# and overlay\VWiFi\netvwifibus.inf (19041) really does contain both sections -- so the file content is not the
# problem; PnP is not resolving (or not completing) the Include at install time.
# Host-side shape check (build\scratch\q51a.ps1) says netvwifibus.inf is the one of the four with
#   [DestinationDirs]/[VWiFiBus.CopyFilesInternal] but no [SourceDisks*] -- the identical shape that makes
#   offline DISM return rc=13 ERROR_INVALID_DATA. Hypothesis for PE: at device install the CopyFiles step needs a
#   file source for vwifibus.sys; full Windows gets it from the WinSxS component store, WinPE has no vWiFi
#   component, so the Include install aborts before PnPFilterRegistration.HW is applied -> no UpperFilters ->
#   the miniport init returns 0xC00000BB (probe48) and everything downstream (nativewifip/vwififlt/wlansvc/1062)
#   stays dead. probe40 saw exactly this complaint at runtime ("missing included INF"), which is why the A3
#   bake put the four INFs into X:\Windows\INF -- this probe checks whether that is now enough.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output ('  ' + $s) }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function RQ([string]$key, [string[]]$extra) {
  $a = @('query', $key) + @($extra)
  return @(& reg.exe @a 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
}
function SecCount([string]$p, [string]$pat) {
  if (-not (Test-Path -LiteralPath $p)) { return 'NOFILE' }
  $t = @(Get-Content -LiteralPath $p -Encoding Unicode -EA SilentlyContinue)
  $b = @(Get-Content -LiteralPath $p -Encoding Byte -TotalCount 2 -EA SilentlyContinue)
  $bom = if ($b.Count -ge 2) { ('{0:x2}{1:x2}' -f $b[0], $b[1]) } else { '?' }
  $m = @($t | Where-Object { $_ -match $pat })
  return ('lines=' + $t.Count + ' bom=' + $bom + ' matches=' + $m.Count + ' :: ' +
          (($m | Select-Object -First 6 | ForEach-Object { ($_.Trim() -replace '\s+', ' ') }) -join ' | '))
}

HDR '1 the four baked vWiFi INFs as the running PE actually sees them'
foreach ($n in @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')) {
  $p = 'X:\Windows\INF\' + $n
  if (Test-Path -LiteralPath $p) {
    $i = Get-Item -LiteralPath $p
    O ($n + ' ' + $i.Length + 'B ' + $i.LastWriteTime)
    O ('   SourceDisks: ' + (SecCount $p '(?i)^\s*\[SourceDisks'))
    O ('   sections:    ' + (SecCount $p '(VWiFiBus|PnPFilterRegistration|CopyFiles)'))
  } else { O ($n + ' ABSENT from X:\Windows\INF') }
}

HDR '2 the installed Intel package in the PE: does it still ask for the include?'
$ois = @(Get-ChildItem 'X:\Windows\INF' -Filter 'oem*.inf' -File -EA SilentlyContinue)
O ('oem inf count=' + $ois.Count)
foreach ($f in $ois) {
  $t = @(Get-Content -LiteralPath $f.FullName -Encoding Unicode -TotalCount 400 -EA SilentlyContinue)
  if (@($t | Where-Object { $_ -match '(?i)netvwifibus' }).Count -gt 0) {
    $dv = @($t | Where-Object { $_ -match '(?i)^\s*DriverVer' })
    O ('MENTIONS_VWIFI ' + $f.Name + ' ' + $(if ($dv.Count) { $dv[0].Trim() } else { '' }))
  }
}
O ('oem183 Include/Needs: ' + (SecCount 'X:\Windows\INF\oem183.inf' '(?i)^\s*(Include|Needs)\s*=\s*.*vwifibus'))

HDR '3 live PE: does vwifibus know any owner (i.e. was its INF ever installed)?'
foreach ($n in @('vwifibus', 'vwififlt', 'vwifimp', 'nativewifip')) {
  $k = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $n
  O ($n + ' Owners: ' + ((RQ $k @('/v', 'Owners') | Where-Object { $_ -match 'REG_' }) -join ' ;; '))
  O ($n + ' Tag   : ' + ((RQ $k @('/v', 'Tag')    | Where-Object { $_ -match 'REG_' }) -join ' ;; '))
}
O ('Netwtw14 subkeys: ' + ((RQ 'HKLM\SYSTEM\CurrentControlSet\Services\Netwtw14' @('/s') | Where-Object { $_ -match '^HKEY' }) -join ' ;; '))

HDR '4 class-level view: which INFs are registered for the Net class?'
$cls = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
O ('class values: ' + ((RQ $cls @('/v', 'Properties') | Where-Object { $_ -match 'REG_' }) -join ' ;; '))
foreach ($l in @(RQ $cls @('') | Where-Object { $_ -match '^HKEY' })) { O ('CLASS-SUB ' + $l) }
$inst = $cls + '\0001'
foreach ($l in @(RQ $inst @('') | Where-Object { $_ -match 'REG_' })) { O ('INST0001 | ' + $l) }

HDR '5 DriverDatabase: what PnP will consult for this PCI ID'
foreach ($id in @('PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11', 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086',
                  'PCI\VEN_8086&DEV_7A70')) {
  $k = 'HKLM\SYSTEM\DriverDatabase\DeviceIds\' + $id
  $r = @(RQ $k @('/v', 'ConfigSize'))
  $o = @(RQ $k @('') | Where-Object { $_ -match 'REG_' })
  O ('DBID ' + $id + ' -> ' + $(if ($o.Count) { ($o -join ' ;; ') } else { 'ABSENT' }))
}
O ('DriverDatabase class key: ' + ((RQ 'HKLM\SYSTEM\DriverDatabase' @('') | Where-Object { $_ -match '^HKEY' }) -join ' ;; '))

HDR '6 setupapi.dev.log -- every line that mentions the vWiFi include machinery'
$slog = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path -LiteralPath $slog) {
  $lines = @(Get-Content -LiteralPath $slog -EA SilentlyContinue)
  O ('lines=' + $lines.Count)
  $pat = '(?i)(vwifibus|vwififlt|vwifimp|nwifi|included INF|PnPFilter|filter|UpperFilters|LowerFilters|not found|invalid data|0xe000|ERROR_|VWiFi)'
  $hits = @()
  for ($i = 0; $i -lt $lines.Count; $i++) { if ("$($lines[$i])" -match $pat) { $hits += $i } }
  O ('hits=' + $hits.Count)
  foreach ($j in ($hits | Select-Object -Last 120)) {
    O ('L' + $j + ' ' + ((" $($lines[$j])" -replace '\s+', ' ').Trim()))
  }
} else { O 'setupapi.dev.log ABSENT' }

HDR '7 the 7A70 install attempt in full (last section of the log)'
if (Test-Path -LiteralPath $slog) {
  $lines = @(Get-Content -LiteralPath $slog -EA SilentlyContinue)
  $startLine = -1
  for ($i = $lines.Count - 1; $i -ge 0; $i--) {
    if ("$($lines[$i])" -match 'DEV_7A70.*CopyList|^\s*\[Device Install.*DEV_7A70|DEV_7A70') { $startLine = $i; break }
  }
  $from = [Math]::Max(0, $startLine - 40)
  O ('window ' + $from + '..' + $lines.Count)
  for ($i = $from; $i -lt $lines.Count; $i++) {
    $t = (" $($lines[$i])" -replace '\s+', ' ').Trim()
    if ($t) { O ('T' + $i + ' ' + $t) }
  }
}
Write-Output 'P51 END'
