# probe26: decide whether dos=31 on nativewifip is "no radio in this box" or "a radio is here but the image
# has no WiFi miniport for it".  Task #17 (wireless driver pool) has never run, so the image is expected to
# contain Ethernet-only drivers -- if a PCI 802.11 device is present and unbound, that is the whole story and
# the fix order is: catalog + WiFi miniport pool together, then verify wlansvc on real hardware.
$ErrorActionPreference = 'Continue'
function Log([string]$m) { [Console]::Out.WriteLine($m) }
function Sec([string]$n) { Log (''); Log ('===== ' + $n + ' =====') }

Sec 'S0_MACHINE_IDENTITY'
$cs = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
$bi = Get-CimInstance Win32_BIOS -EA SilentlyContinue
Log ('  model      : ' + $cs.Manufacturer + ' / ' + $cs.Model)
Log ('  bios       : ' + $bi.Manufacturer + ' / ' + ($bi.SMBIOSBIOSVersion))
Log ('  isVm       : ' + $cs.PCSystemType + ' hypervisor=' + $cs.HyperVesselSRequirementsDetected)
Log ('  boot media : ' + ((Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue).SystemDevice))

Sec 'S1_DEVICES_WITH_PROBLEM_CODES'
$bad = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
Log ('  count=' + $bad.Count)
foreach ($d in $bad) {
  Log ('    err={0,-3} class={1,-12} name={2}  id={3}' -f $d.ConfigManagerErrorCode, $d.PNPClass, $d.Name, $d.DeviceID)
}

Sec 'S2_ALL_NET_AND_PCI_DEVICES'
$net = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.PNPClass -eq 'Net' })
Log ('  class=Net count=' + $net.Count)
foreach ($d in $net) { Log ('    OK  name={0,-45} id={1}' -f $d.Name, $d.DeviceID) }
$pci = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.DeviceID -like 'PCI\*' })
Log ('  PCI devices count=' + $pci.Count)
foreach ($d in $pci) {
  $cls = ''
  if ($d.PNPClass) { $cls = $d.PNPClass }
  Log ('    {0,-14} err={1,-3} {2,-48} {3}' -f $cls, $d.ConfigManagerErrorCode, $d.Name, $d.DeviceID)
}

Sec 'S3_WIFI_HARDWARE_IDS_IN_THE_IMAGE'
# Every PCI id that looks like a WLAN controller, and whether any INF in the image mentions it.
$cats = 'VEN_8086&DEV_2723|VEN_8086&DEV_2725|VEN_8086&DEV_34E0|VEN_8086&DEV_43F0|VEN_8086&DEV_51F1|VEN_8086&DEV_8CF0|VEN_8086&DEV_A0F0|VEN_8086&DEV_02F0|VEN_8086&DEV_24FC|VEN_8086&DEV_272B|VEN_14E4|VEN_168C|VEN_1A6B|VEN_17CB|VEN_10EC&DEV_B723|VEN_10EC&DEV_C822|VEN_10EC&DEV_C852|VEN_02B0'
$hit = @($pci | Where-Object { $_.DeviceID -imatch $cats -or $_.Name -imatch '802\.11|[Ww]i-?[Ff]i|[Ww]ireless|Network controller' })
Log ('  WLAN-looking PCI/unknown devices = ' + $hit.Count)
foreach ($d in $hit) { Log ('    >>> {0} | class={1} | err={2} | id={3}' -f $d.Name, $d.PNPClass, $d.ConfigManagerErrorCode, $d.DeviceID) }

Sec 'S4_DOES_ANY_OEM_INF_CLAIM_THEM'
$infs = @(Get-ChildItem 'X:\Windows\INF' -Filter 'oem*.inf' -File -EA SilentlyContinue)
Log ('  staged OEM INF files in image = ' + $infs.Count)
$want = @{}
foreach ($d in $hit) {
  $id = ($d.DeviceID -split '\\')[0..1] -join '\'
  if ($d.DeviceID -like 'PCI\*') { $want[$d.DeviceID.ToUpper()] = $d.Name }
}
Log ('  ids to match = ' + (($want.Keys | Sort-Object) -join ' ; '))
if ($infs.Count -gt 0) {
  $txt = ($infs | ForEach-Object { (Get-Content $_.FullName -Raw -EA SilentlyContinue) }) -join "`r`n"
  $low = $txt.ToLower()
  foreach ($k in ($want.Keys | Sort-Object)) {
    $m = ($k -split '&') | ForEach-Object { $_.ToLower() }
    Log ('    {0,-40} present in staged INF text = {1}' -f $k, ($low.Contains($m[0] + '&' + $m[1])))
  }
  Log ('    staged INF text mentions nwifi/NativeWiFi = ' + ($low.Contains('nativewifi') -or $low.Contains('nwifi')))
}
# also: what NDIS thinks of the adapters that ARE bound -- a WiFi miniport would show IEEE80211 in its registry NDI
Sec 'S5_NDI_USAGE_MARKERS'
$clsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
if (Test-Path $clsKey) {
  foreach ($sub in (Get-ChildItem $clsKey -EA SilentlyContinue)) {
    $iv = (Get-ItemProperty $sub.PSPath -EA SilentlyContinue)
    Log ('    {0}  desc={1} component={2}' -f $sub.PSChildName, $iv.DriverDesc, $iv.ComponentId)
  }
} else { Log '  Net class key absent' }

Sec 'S6_SERVICES_AND_STATE_NOW'
foreach ($n in @('nativewifip', 'wlansvc', 'wcmsvc', 'dot3svc')) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -EA SilentlyContinue
  if ($s) { Log ('  ' + $n + ' : state=' + $s.State + ' start=' + $s.StartMode + ' pid=' + $s.ProcessId) }
  else    { Log ('  ' + $n + ' : not enumerated by Win32_Service') }
}
Log 'PROBE26_DONE'
