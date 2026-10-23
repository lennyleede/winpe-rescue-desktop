$ErrorActionPreference = 'SilentlyContinue'
# probe27 -- live-PE WiFi census (ASCII only; read over ssh/console).
# Questions this answers, in order:
#   A) is the AX211 radio enumerated at all, and with what problem code?
#   B) did any WiFi driver package actually land in DriverStore?
#   C) is the nwifi .cat present, and does nativewifip / wlansvc come up now?
$ts = Get-Date -Format 'HH:mm:ss'
Write-Output ('PROBE27 ' + $ts + ' BUILD_TAG=' + ((Get-Content X:\BUILD_TAG.txt -EA SilentlyContinue | Select-String 'wifi_patch|wlandrv' | ForEach-Object { $_.Line.ToString().Trim() }) -join ' // '))

Write-Output '== A1. PCI devnodes =='
$all = @(Get-CimInstance Win32_PnPEntity)
Write-Output ('PNP_TOTAL=' + $all.Count)
$pci = @($all | Where-Object { $_.PNPDeviceID -like 'PCI\*' })
Write-Output ('PCI_TOTAL=' + $pci.Count)
foreach ($p in $pci) {
  Write-Output ('PCI|' + $p.PNPDeviceID + '|code=' + $p.ConfigManagerErrorCode + '|st=' + $p.Status + '|' + $p.Name)
}

Write-Output '== A2. anything that looks wireless / unbound =='
$pat = 'VEN_8086&DEV_(43F0|51F1|51F0|272B|A3F0|34F0|3DF0|02B2|A0F1|24FD|2526|08B1|3165|3166|4DF[0-9])'
$look = @($all | Where-Object { ($_.PNPDeviceID -match $pat) -or ($_.Name -match 'Wi-?Fi|Wireless|802\.11|Network controller|CNVi|AX[0-9]') })
Write-Output ('LOOK_N=' + $look.Count)
foreach ($d in $look) {
  Write-Output ('LOOK|' + $d.PNPDeviceID + '|code=' + $d.ConfigManagerErrorCode + '|st=' + $d.Status + '|man=' + $d.Manufacturer + '|' + $d.Name)
}
Write-Output '== A3. problem devices (code != 0) =='
$bad = @($all | Where-Object { $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne $null })
foreach ($d in $bad) { Write-Output ('BAD|' + $d.PNPDeviceID + '|code=' + $d.ConfigManagerErrorCode + '|' + $d.Name) }
Write-Output ('BAD_TOTAL=' + $bad.Count)

Write-Output '== B1. WiFi packages in DriverStore =='
$fr = 'X:\Windows\System32\DriverStore\FileRepository'
$dirs = @(Get-ChildItem $fr -Directory -EA SilentlyContinue)
Write-Output ('FILEREPO_TOTAL=' + $dirs.Count)
$wf = @($dirs | Where-Object { $_.Name -match 'netwtw|netrtwlane|rtwlane|rtwlan|netathr|iwmw|WlanU|mt79|mtk|bw200|bwc' })
foreach ($d in $wf) { Write-Output ('WIFIPKG|' + $d.Name) }
Write-Output ('WIFIPKG_TOTAL=' + $wf.Count)
Write-Output '== B2. staged oem inf + class Net drivers =='
Write-Output ('OEM_INF_N=' + @(Get-ChildItem 'X:\Windows\INF' -Filter 'oem*.inf' -EA SilentlyContinue).Count)
Write-Output '== B3. index file present =='
$ix = @(Get-Content 'X:\Windows\System32\wlandrv_index.txt' -EA SilentlyContinue)
Write-Output ('WLANIDX_ROWS=' + @($ix | Where-Object { $_ -match "`t" }).Count)
$hit = @($ix | Where-Object { $_ -match 'DEV_43F0|DEV_51F1' })
foreach ($h in $hit) { Write-Output ('IDX|' + ($h -replace "`t", ' -> ')) }

Write-Output '== C1. covering catalog present in CatRoot =='
$cats = Get-ChildItem 'X:\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}' -Filter '*.cat' -EA SilentlyContinue
Write-Output ('CATROOT_TOTAL=' + @($cats).Count)
foreach ($c in @($cats | Where-Object { $_.Name -like 'Microsoft-Windows-Client-Desktop-Required-Package04*' })) {
  Write-Output ('CAT|' + $c.Name + '|' + $c.Length)
}
Write-Output ('NWiFi_SYS=' + ((Get-Item 'X:\Windows\System32\drivers\nwifi.sys' -EA SilentlyContinue).Length))
Write-Output ('NWiFi_SHA=' + ((Get-FileHash 'X:\Windows\System32\drivers\nwifi.sys' -Algorithm SHA256 -EA SilentlyContinue).Hash))

Write-Output '== C2. services =='
foreach ($s in 'wlansvc', 'wcmsvc', 'mpsvc', 'nativewifip', 'dot3svc') {
  $sv = Get-Service $s -EA SilentlyContinue
  $k  = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  $start = (Get-ItemProperty $k -EA SilentlyContinue).Start
  $type  = (Get-ItemProperty $k -EA SilentlyContinue).Type
  $img   = (Get-ItemProperty $k -EA SilentlyContinue).ImagePath
  $deps  = (Get-ItemProperty $k -EA SilentlyContinue).DependOnService
  Write-Output ('SVC|' + $s + '|exists=' + [bool]$sv + '|state=' + $(if ($sv) { $sv.Status } else { '-' }) +
                '|start=' + $start + '|type=' + $type + '|img=' + $img + '|dep=' + (($deps | ForEach-Object { $_ }) -join ','))
}
Write-Output '== C3. WlanOpenHandle attempt (netsh) =='
Write-Output ('NETSH=' + (Test-Path 'X:\Windows\System32\netsh.exe'))
$ns = & netsh wlan show interfaces 2>&1
foreach ($l in @($ns)) { Write-Output ('NETSH|' + $l) }
Write-Output '== C4. network adapters visible =='
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
  Write-Output ('ADAPTER|' + $a.Name + '|guid=' + $a.GUID + '|netenabled=' + $a.NetEnabled + '|mac=' + $a.MACAddress)
}
Write-Output ('FREE_X=' + ((Get-PSDrive X).Free))
Write-Output 'PROBE27 END'
