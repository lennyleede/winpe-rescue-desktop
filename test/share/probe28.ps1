$ErrorActionPreference = 'SilentlyContinue'
# probe28 -- is the AX211 physically exposed to the OS at all?
# The live PE enumerates no WiFi function, so ask the offline Windows on D: what it enumerated.
# ASCII output only; read-only on D: (no writes to the customer disk).
Write-Output '== P0. which drive holds the offline Windows =='
foreach ($v in @(Get-Volume -EA SilentlyContinue | Where-Object { $_.DriveLetter })) {
  Write-Output ('VOL|' + $v.DriveLetter + '|fs=' + $v.FileSystem + '|' + $v.SizeRemaining + '/' + $v.Size + '|win=' + (Test-Path ($v.DriveLetter + ':\Windows')))
}

Write-Output '== P1. PE-side PCI enum, second source (devnode registry) =='
$pk = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)
Write-Output ('REG_PCI_KEYS=' + $pk.Count)
foreach ($k in $pk) {
  if ($k.PSChildName -match 'VEN_8086&DEV_(43F0|51F1|51F0|272B|A3F0|34F0|3DF0|02B2|A0F1|24FD|2526|3165|3166|4DF[0-9])') {
    Write-Output ('REGHIT|' + $k.PSChildName)
  }
}
Write-Output ('REG_WLAN_CLASS_KEYS=' + @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-ce09-08c7e7d9e2b8}' -EA SilentlyContinue).Count)
Write-Output '== P2. ACPI/other bus nodes that could be CNVi =='
$e = @(Get-CimInstance Win32_PnPEntity)
foreach ($d in @($e | Where-Object { $_.PNPDeviceID -match '^ACPI\\' })) {
  if ($d.Name -match 'WiFi|Wireless|WLAN|CNV|Radio|Airplane|HID') { Write-Output ('ACPI|' + $d.PNPDeviceID + '|code=' + $d.ConfigManagerErrorCode + '|' + $d.Name) }
}
Write-Output ('ACPI_SCAN_DONE=' + @($e | Where-Object { $_.PNPDeviceID -match '^ACPI\\' }).Count)

Write-Output '== P3. offline Windows: staged oem INFs mentioning Intel WiFi =='
$oi = @(Get-ChildItem 'D:\Windows\INF' -Filter 'oem*.inf' -EA SilentlyContinue)
Write-Output ('OFFLINE_OEM_INF=' + $oi.Count)
foreach ($f in $oi) {
  $t = Get-Content -LiteralPath $f.FullName -Raw -EA SilentlyContinue
  if ($t -match 'DEV_43F0|DEV_51F1|AX211|netwtw|NetWifi|Class\s*=\s*Net') {
    $dv = ([regex]'(?i)DriverVer\s*=\s*([^,\r\n]+),\s*([0-9\.]+)').Match($t)
    Write-Output ('OFFINF|' + $f.Name + '|hit=' + $(if ($t -match 'DEV_43F0|DEV_51F1|AX211|netwtw') { 'wifi' } else { 'net' }) +
                  '|ver=' + $(if ($dv.Success) { $dv.Groups[2].Value } else { '?' }))
  }
}

Write-Output '== P4. offline Windows: setupapi devcon log around WiFi =='
$sal = 'D:\Windows\INF\setupapi.dev.log'
Write-Output ('SETUPAPI_BYTES=' + ((Get-Item $sal -EA SilentlyContinue).Length))
$m = @(Select-String -Path $sal -Pattern 'DEV_43F0|DEV_51F1|AX211|netwtw|Wi-Fi|WiFi|WLAN' -EA SilentlyContinue | Select-Object -First 40)
Write-Output ('SETUPAPI_HITS=' + $m.Count)
foreach ($x in $m) { Write-Output ('SAL|' + $x.LineNumber + '|' + $x.Line.ToString().Trim()) }

Write-Output '== P5. offline DriverStore WiFi packages =='
$fd = @(Get-ChildItem 'D:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw|rtwlane|mt79|Netwtw' })
foreach ($d in $fd) { Write-Output ('OFFDS|' + $d.Name) }
Write-Output ('OFFDS_TOTAL=' + $fd.Count)

Write-Output '== P6. offline SYSTEM hive: does it have a Net class key for WiFi? =='
Write-Output ('(needs reg load, skipped here; P3/P4 answer the same question)')
Write-Output 'PROBE28 END'
