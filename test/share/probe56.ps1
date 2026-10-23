# probe56 -- LIVE PE. Output ASCII, prefix-free lines.
# Job 1: dump the real VALUES of the WiFi service keys. probe55 listed subkeys but its line filter
#        ('^(HKEY|REG_|    )') never matched, because reg.exe indents value lines with spaces that were
#        collapsed by the whitespace normaliser before the filter ran. So we still do not know whether
#        Parameters\ServiceDll / ServiceMain survived the bake. Host reference (q56_host.ps1, a 19041 box
#        where WiFi works) has wlansvc\Parameters: ServiceDll=%SystemRoot%\System32\wlansvc.dll,
#        ServiceMain=WlanSvcMain, ServiceDllUnloadOnStop=1, plus Type=0x10 Start=2
#        DependOnService=nativewifip,RpcSs,Ndisuio,wcmsvc.
# Job 2: the decisive code-37 experiment. On the laptop's own Windows the AX211 devnode carries
#        UpperFilters=vwifibus because setupapi resolves "Include = netvwifibus.inf"; in our PE that
#        Include never resolves (probe51: "Needed section [VWiFiBus.CopyFiles] not found, might exist in
#        missing included INF"), so the devnode has no UpperFilters and the NdisMediumNative802_11
#        miniport dies with STATUS_NOT_SUPPORTED (0xC00000BB / code 37).
#        UpperFilters is just a registry value PnP writes -- so write it by hand on the ramdisk and
#        restart the device. If code 37 clears, the fix is an offline bake of that one value.
# Mutations: X: ramdisk only (disappears on reboot). The laptop's offline SYSTEM hive is reg-load'ed
# read-only and unload'ed in the last section. No C:/D: writes, no ISO writes.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function St([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'NOGET' } }
function RQA([string[]]$a) {
  return @(& reg.exe @a 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
}
function Vals([string]$label, [string]$key) {
  $t = @(RQA @('query', $key))
  if ($t.Count -eq 0) { O ('  ' + $label + ' EMPTYQUERY'); return $false }
  if ($t[0] -match 'ERROR') { O ('  ' + $label + ' ABSENT :: ' + $t[0]); return $false }
  O ('  ' + $label + ' KEY ' + ($t[0] -replace '^HKEY_LOCAL_MACHINE\\', ''))
  foreach ($l in ($t | Where-Object { $_ -match 'REG_' })) { O ('  ' + $label + ' | ' + $l) }
  return $true
}

HDR 'A volumes: locate an offline Windows\System32\config\SYSTEM'
$disks = @(Get-CimInstance Win32_LogicalDisk -EA SilentlyContinue)
$offRoot = ''
foreach ($d in $disks) {
  $p = $d.DeviceID + '\Windows\System32\config\SYSTEM'
  $has = $false
  try { $has = Test-Path -LiteralPath $p } catch { }
  O ('  VOL ' + $d.DeviceID + ' type=' + $d.DriveType + ' label=' + $(if ($d.VolumeName) { $d.VolumeName } else { '-' }) +
     ' size=' + $(if ($d.Size) { [Math]::Round($d.Size / 1GB, 1) } else { 0 }) + 'GB sys_hive=' + $has)
  if ((-not $has) -or $d.DeviceID -eq 'X:') { continue }
  if ($offRoot -eq '') { $offRoot = $d.DeviceID }
}
O ('  OFFROOT ' + $(if ($offRoot) { $offRoot } else { 'NONE' }))

$HK = 'HKLM\P56OFF'
$loaded = $false
$OFF = ''
if ($offRoot -ne '') {
  O ('  LOAD ' + ((RQA @('load', $HK, ($offRoot + '\Windows\System32\config\SYSTEM'))) -join ' | '))
  if (@(RQA @('query', $HK))[0] -match '^HKEY') { $loaded = $true; $OFF = $HK + '\ControlSet001' }
}

HDR 'B offline reference: which devnode carries UpperFilters'
if ($loaded) {
  $pci = @(RQA @('query', ($OFF + '\Enum\PCI')))
  $fams = @($pci | Where-Object { ($_ -match '^HKEY') -and ($_ -match 'VEN_8086&DEV_7A70') })
  O ('  B PCI_FAMILY ' + $fams.Count)
  foreach ($f in $fams) {
    $insts = @(RQA @('query', $f) | Where-Object { ($_ -match '^HKEY') -and ($_ -ne $f) })
    O ('  B FAMILY ' + ($f -replace '^HKEY_LOCAL_MACHINE\\', '') + ' instances=' + $insts.Count)
    foreach ($i in $insts) { Vals 'OFF-DEV' $i | Out-Null }
  }
  O ('  B vwifibus Owners :: ' + ((@(RQA @('query', ($OFF + '\Services\vwifibus'), '/v', 'Owners')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  B vwifibus Tag   :: ' + ((@(RQA @('query', ($OFF + '\Services\vwifibus'), '/v', 'Tag')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  B vwifimp  Owners :: ' + ((@(RQA @('query', ($OFF + '\Services\vwifimp'), '/v', 'Owners')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  B vwififlt Owners :: ' + ((@(RQA @('query', ($OFF + '\Services\vwififlt'), '/v', 'Owners')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  B nativewifip Owners :: ' + ((@(RQA @('query', ($OFF + '\Services\nativewifip'), '/v', 'Owners')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  B NdisImPlatform key :: ' + (@(RQA @('query', ($OFF + '\Services\NdisImPlatform')))[0]))
} else { O '  B SKIPPED no offline hive' }

HDR 'C live PE: the AX211 devnode as it stands now'
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
O ('  C COUNT ' + $ents.Count)
$PNP = ''
if ($ents.Count) { $PNP = "$($ents[0].PNPDeviceID)" }
O ('  C PNP ' + $PNP)
$devInst = ''
if ($PNP -ne '') {
  $parts = $PNP -split '\\'
  $upper = $parts[0]
  $inst = ''
  if ($parts.Count -gt 1) { $inst = $parts[1] }
  foreach ($bus in 'PCI', 'USB', 'ACPI', 'SD', 'ROOT', 'VM') {
    $k = 'HKLM\SYSTEM\CurrentControlSet\Enum\' + $bus + '\' + $upper
    if (@(RQA @('query', $k))[0] -match '^HKEY') {
      O ('  C BUSKEY ' + $k)
      if ($inst -ne '' -and @(RQA @('query', ($k + '\' + $inst)))[0] -match '^HKEY') {
        $devInst = $k + '\' + $inst
      }
      break
    }
  }
  if ($devInst -ne '') {
    $t = @(RQA @('query', $devInst))
    foreach ($l in $t) { if ($l -match 'REG_') { O ('  C PEVAL ' + $l) } }
  } else { O '  C INSTANCE KEY NOT FOUND' }
}

HDR 'D EXPERIMENT: UpperFilters=vwifibus on the devnode, then restart it'
if ($devInst -ne '') {
  O ('  D TARGET ' + $devInst)
  O ('  D ADD ' + ((RQA @('add', $devInst, '/v', 'UpperFilters', '/t', 'REG_MULTI_SZ', '/d', 'vwifibus', '/f')) -join ' | '))
  O ('  D READBACK ' + ((@(RQA @('query', $devInst, '/v', 'UpperFilters')) | Where-Object { $_ -match 'REG_' }) -join ' '))
  O ('  D RESTART ' + ((@(& pnputil.exe /restart-device $PNP 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })) -join ' | '))
  Start-Sleep -Seconds 12
  $d = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
  foreach ($x in $d) { O ('  D AFTER code=' + $x.ConfigManagerErrorCode + ' status=' + $x.Status + ' name=' + $x.Name) }
  $t = @(RQA @('query', $devInst))
  foreach ($l in $t) { if ($l -match 'REG_') { O ('  D PEVAL2 ' + $l) } }
  $kids = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
            Where-Object { ($_.PNPDeviceID -match '(?i)^ROOT\\VWIFIBUS') -or ($_.Name -match '(?i)virtual wireless|Microsoft Wi-Fi Direct') })
  O ('  D VWIFI_CHILDREN ' + $kids.Count)
  foreach ($k in $kids) { O ('  D KID ' + $k.Name + ' | ' + $k.PNPDeviceID + ' | code=' + $k.ConfigManagerErrorCode) }
} else { O '  D SKIPPED (no devnode instance key)' }

HDR 'E live PE WiFi service keys, full values'
foreach ($n in 'wlansvc', 'wlansvc\Parameters', 'wcmsvc', 'wcmsvc\Parameters', 'nativewifip',
                'nativewifip\Parameters', 'vwifibus', 'vwififlt', 'vwifimp', 'Ndisuio', 'dot3svc') {
  $k = 'HKLM\SYSTEM\CurrentControlSet\Services\' + $n
  $t = @(RQA @('query', $k))
  if ($t[0] -match 'ERROR') { O ('  E ' + $n + ' ABSENT'); continue }
  O ('  E ' + $n)
  foreach ($l in $t) { if ($l -match 'REG_') { O ('     | ' + $l) } }
}

HDR 'F wlansvc retry after the filter change'
O ('  F STARTCMD ' + ((RQA @('start', 'wlansvc')) -join ' | '))
Start-Sleep -Seconds 6
foreach ($n in 'wlansvc', 'wcmsvc', 'nativewifip', 'vwifibus', 'vwifimp', 'vwififlt', 'Ndisuio', 'Netman') {
  O ('  F STATE ' + $n + ' = ' + (St $n))
}
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class W56 {
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanOpenHandle(int ver, IntPtr res, out int newVer, out IntPtr handle);
  [DllImport("wlanapi.dll", SetLastError=true)]
  public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr res, out IntPtr list, out int count);
}
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [W56]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  F WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    O ('  F WLANENUM rc=' + [W56]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt) + ' ifaces=' + $cnt)
  }
} catch { O ('  F WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | Where-Object { $_.NetConnectionID })) {
  O ('  F ADAPT ' + $a.Name + ' idx=' + $a.Index + ' mac=' + $a.MACAddress)
}
if ($loaded) {
  [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  O ('  G UNLOAD ' + ((RQA @('unload', $HK)) -join ' | '))
  O ('  G UNLOADCHECK ' + (@(RQA @('query', $HK))[0]))
}
O 'P56 END'
