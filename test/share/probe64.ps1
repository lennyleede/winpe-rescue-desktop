# probe64 -- LIVE PE, READ ONLY. Structure of the NetCfg "filter component" store, so probe65 can copy it
# instead of guessing.
# probe63 gave the shape of the smoking gun:
#   offline  Control\Class\{4d36e972..}\0002\Linkage | FilterList = 12 instances, and the idiom is
#            {NetCfgInstanceId}-{component-guid}-000N  with components
#            {430BDADD..} x6, {3BFD7820..}, {5CBF81BF..}, {E475CF9A..}, {B5F4D659..}, {B70D6460..}
#   offline  Control\Class\{4d36e972..}\0001 (Realtek Ethernet) carries {430BDADD..}x4 + {3BFD7820} +
#            {B5F4D659} + {B70D6460} but NOT {5CBF81BF} / {E475CF9A}  => those two are WiFi-only, i.e.
#            almost certainly the vwififlt / nwifi (NativeWiFiP) mandatory filters.
#   PE       Control\Class\{4d36e972..}\0000 (Realtek) and \0001 (AX211) have a Linkage subkey but NO
#            FilterList at all, and neither Ethernet nor Wi-Fi connection key has any component instance.
# So the question probe65 needs answered is: what does a "{conn}-{component}-000N" key actually contain
# (that is where the filter's service name must live), and where does it sit in the tree.
$ErrorActionPreference = 'Continue'
function L([string]$s) { Write-Output $s }
function Clean([string]$s) { return (($s -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim() }
$NETCLASS = '{4d36e972-e325-11ce-bfc1-08002be10318}'
$SVSCLASS = '{4d36e974-e325-11ce-bfc1-08002be10318}'
$PE = 'HKLM:\SYSTEM\CurrentControlSet'
$OFF = 'HKLM:\R8OFF\ControlSet001'
$OFFWLAN = '{BD396AA3-3919-4606-9311-AA55795F5F57}'
$PEWIFI = '{FFCECF27-1B9D-43A7-903F-B1CB626C975D}'

function DumpAll([string]$path, [string]$tag, [int]$depth, [int]$maxDepth) {
  $gi = Get-Item -LiteralPath $path -EA SilentlyContinue
  if ($null -eq $gi) { L ('  ' + $tag + ' ABSENT ' + (Clean $path)); return }
  $pad = ''
  for ($i = 0; $i -lt $depth; $i++) { $pad = $pad + '  ' }
  foreach ($vn in @($gi.GetValueNames())) {
    $raw = $gi.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
    $v = ''
    if ($raw -is [array]) { $v = ($raw -join ';') } else { $v = '' + $raw }
    if ($v.Length -gt 300) { $v = $v.Substring(0, 300) + '...' }
    L ($pad + '  <' + $tag + '> ' + $vn + ' = ' + (Clean $v))
  }
  if ($depth -ge $maxDepth) { return }
  foreach ($sub in @(Get-ChildItem -LiteralPath $path -EA SilentlyContinue)) {
    L ($pad + '  KEY ' + $sub.PSChildName)
    DumpAll ($path + '\' + $sub.PSChildName) $tag ($depth + 1) $maxDepth
  }
}

if (-not (Test-Path -LiteralPath $OFF)) {
  $r = @(& reg.exe load HKLM\R8OFF 'D:\Windows\System32\config\SYSTEM' 2>&1 | ForEach-Object { (Clean ('' + $_)) })
  L ('LOAD ' + ($r -join '|'))
}

L '=A offline: children of the WLAN connection key (component instances live here?)'
DumpAll ($OFF + '\Control\Network\' + $NETCLASS + '\' + $OFFWLAN) 'OFFCONN' 0 2
L '=B offline: names of every child of Control\Network\{net} (class level)'
$cn = @(Get-ChildItem -LiteralPath ($OFF + '\Control\Network\' + $NETCLASS) -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
foreach ($n in $cn) { L ('  OFFNAME ' + $n) }
L ('  OFFNAME count=' + $cn.Count)
L '=C offline: one instance key in full (pick the first child that looks like conn-component)'
$inst = @($cn | Where-Object { $_ -match ('^\{' + 'BD396AA3') -and $_ -match '\-\d{4}$' })
if ($inst.Count -eq 0) { $inst = @($cn | Where-Object { $_ -match '-00\d\d$' }) }
if ($inst.Count -gt 0) {
  L ('  PICK ' + $inst[0])
  DumpAll ($OFF + '\Control\Network\' + $NETCLASS + '\' + $inst[0]) 'OFFINST' 0 2
} else { L '  no instance-shaped child under Control\Network\{net} -- components live elsewhere' }
L '=D offline: search Control\Network\{net}\{conn}\* for the 6 WiFi component GUIDs'
foreach ($g in '{430BDADD-BAB0-41AB-A369-94B67FA5BE0A}', '{3BFD7820-D65C-4C1B-9FEA-983A019639EA}',
             '{5CBF81BF-5055-47CD-9055-A76B2B4E3698}', '{E475CF9A-60CD-4439-A75F-0079CE0E18A1}',
             '{B5F4D659-7DAA-4565-8E41-BE220ED60542}', '{B70D6460-3635-4D42-B866-B8AB1A24454C}') {
  $hit = @($cn | Where-Object { $_ -match [regex]::Escape($g) })
  L ('  G ' + $g + ' class-level hits=' + $hit.Count + ' [' + (($hit | Select-Object -First 3) -join ' ') + ']')
}
L '=E offline: NetService class {4d36e974} children + slots'
DumpAll ($OFF + '\Control\Class\' + $SVSCLASS) 'OFFSVC' 0 1
L '=F offline: class slot 0002 Linkage + Ndi in full'
DumpAll ($OFF + '\Control\Class\' + $NETCLASS + '\0002\Linkage') 'OFFL2' 0 2
DumpAll ($OFF + '\Control\Class\' + $NETCLASS + '\0002\Ndi') 'OFFN2' 0 2
L '=G PE: connection key children + class slot 0001 Linkage/Ndi'
$pcn = @(Get-ChildItem -LiteralPath ($PE + '\Control\Network\' + $NETCLASS) -EA SilentlyContinue | ForEach-Object { $_.PSChildName })
L ('  PENAME count=' + $pcn.Count + ' [' + ($pcn -join ' ') + ']')
DumpAll ($PE + '\Control\Network\' + $NETCLASS + '\' + $PEWIFI) 'PECONN' 0 2
DumpAll ($PE + '\Control\Class\' + $NETCLASS + '\0001\Linkage') 'PEL1' 0 2
DumpAll ($PE + '\Control\Class\' + $NETCLASS + '\0001\Ndi') 'PEN1' 0 2
L '=H PE: NetService class + services that would be filters'
DumpAll ($PE + '\Control\Class\' + $SVSCLASS) 'PESVC' 0 1
L 'P64 END'
