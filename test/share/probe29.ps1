param([switch]$Load, [string]$Inf = '')
$ErrorActionPreference = 'SilentlyContinue'
# probe29 -- the AX211 is present and unbound: PCI\VEN_8086&DEV_7A70 code=28 (plus its Bluetooth USB\VID_8087&PID_0033).
# The baked ISO has no WiFi package in DriverStore (wlandrv=0/21), so prove the CNVio2 driver path works using the
# driver already sitting on the offline Windows volume D:. Read-only unless -Load is given (drvload into the ramdisk PE).
Write-Output ('PROBE29 ' + (Get-Date -Format 'HH:mm:ss') + ' load=' + [bool]$Load + ' freeX=' + ((Get-PSDrive X).Free))

Write-Output '== N0. offline Windows volumes =='
foreach ($v in @(Get-Volume -EA SilentlyContinue | Where-Object { $_.DriveLetter })) {
  Write-Output ('VOL|' + $v.DriveLetter + '|win=' + (Test-Path ($v.DriveLetter + ':\Windows')))
}

Write-Output '== N1. Intel WiFi packages in the offline driver store =='
$cands = @()
foreach ($fr in 'D:\Windows\System32\DriverStore\FileRepository', 'C:\Windows\System32\DriverStore\FileRepository') {
  if (-not (Test-Path $fr)) { Write-Output ('SKIP|' + $fr); continue }
  foreach ($d in @(Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw|netwlan|rtwlane|mt792|Netwtw' })) {
    $sz   = @(Get-ChildItem $d.FullName -Recurse -File -EA SilentlyContinue)
    $infs = @($sz | Where-Object { $_.Extension -eq '.inf' })
    $catN = @($sz | Where-Object { $_.Extension -eq '.cat' }).Count
    foreach ($i in $infs) {
      $b = [IO.File]::ReadAllBytes($i.FullName)
      $t = $(if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($b) }
             elseif ($b.Length -ge 3 -and $b[0] -eq 0xEF) { [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
             else { [Text.Encoding]::UTF8.GetString($b) })
      $dv   = ([regex]'(?i)DriverVer\s*=\s*([^;\r\n]+)').Match($t)
      $has70 = ($t -match 'DEV_7A70')
      $svc  = ([regex]'(?i)^Class\s*=\s*Net').Match($t)
      Write-Output ('PKGCAND|' + $i.FullName + '|files=' + $sz.Count + '|cat=' + $catN +
                   '|ver=' + $(if ($dv.Success) { $dv.Groups[1].Value.Trim() } else { '?' }) +
                   '|declares_7A70=' + $has70 + '|MB=' + [Math]::Round(($sz | Measure-Object Length -Sum).Sum / 1MB, 1))
      if ($has70) { $cands += [pscustomobject]@{ Inf = $i.FullName; Ver = $(if ($dv.Success) { $dv.Groups[1].Value.Trim() } else { '0' }); Bytes = ($sz | Measure-Object Length -Sum).Sum } }
    }
  }
}
Write-Output ('PKGCAND_TOTAL=' + $cands.Count)
if (-not $Inf -and $cands.Count) { $Inf = ($cands | Sort-Object Ver -Descending | Select-Object -First 1).Inf }
Write-Output ('TARGET_INF=' + $Inf)
if ($Inf) { Write-Output ('TARGET_DIR_MB=' + [Math]::Round((@(Get-ChildItem (Split-Path $Inf) -Recurse -File) | Measure-Object Length -Sum).Sum / 1MB, 1)) }

Write-Output '== N2. devnode before =='
function Show-Node([string]$tag) {
  $d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match 'DEV_7A70|USB\\VID_8087&PID_0033|DEV_7AF0' })
  foreach ($x in $d) { Write-Output ($tag + '|dev|' + $x.PNPDeviceID + '|code=' + $x.ConfigManagerErrorCode + '|st=' + $x.Status + '|' + $x.Name) }
  $a = @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })
  Write-Output ($tag + '|adapters=' + $a.Count)
  foreach ($y in $a) { Write-Output ($tag + '|nic|' + $y.Name + '|guid=' + $y.GUID + '|id=' + $y.PNPDeviceID + '|enabled=' + $y.NetEnabled) }
  $np = @(Get-CimInstance Win32_NetworkProtocol -EA SilentlyContinue | Where-Object { $_.Name -match 'Native|802' })
  foreach ($p in $np) { Write-Output ($tag + '|nproto|' + $p.Name + '|' + $p.Status) }
  foreach ($s in 'nativewifip', 'wlansvc', 'wcmsvc') {
    $sv = Get-Service $s -EA SilentlyContinue
    Write-Output ($tag + '|svc|' + $s + '=' + $(if ($sv) { $sv.Status } else { 'absent' }))
  }
}
Show-Node 'BEFORE'

if (-not $Load) { Write-Output 'PROBE29 END (no load requested)'; exit 0 }
if (-not $Inf) { Write-Output 'NO TARGET INF, ABORT'; exit 1 }

Write-Output '== N3. drvload =='
$t0 = Get-Date
$out = & drvload $Inf 2>&1
Write-Output ('DRVLOAD_RC=' + $LASTEXITCODE + ' ms=' + [int]((Get-Date) - $t0).TotalMilliseconds)
foreach ($l in @($out)) { Write-Output ('DL|' + $l) }
Start-Sleep -Seconds 5
Show-Node 'AFTER'

Write-Output '== N4. try wlansvc + WlanOpenHandle =='
$sw = Get-Service wlansvc -EA SilentlyContinue
if ($sw -and $sw.Status -ne 'Running') {
  $rs = 'not-tried'
  try { $sw.Start(); $rs = 'Start() ok' } catch { $rs = 'Start() EX: ' + $_.Exception.Message }
  Write-Output ('WLANSVC_START=' + $rs)
  Write-Output ('SVCHOST_PROCS=' + @(Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" -EA SilentlyContinue).Count)
}
Start-Sleep -Seconds 3
$sw2 = Get-Service wlansvc -EA SilentlyContinue
Write-Output ('WLANSVC_NOW=' + $(if ($sw2) { $sw2.Status } else { 'absent' }))
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll",CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue
$ver = 0; $hk = [IntPtr]::Zero
$rh = & { try { [Wapi]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk) } catch { 'EX:' + $_.Exception.Message } }
Write-Output ('WlanOpenHandle=' + $rh + ' serverver=' + $ver)
if ($rh -eq 0) {
  $lst = [IntPtr]::Zero; $n = 0
  $re = [Wapi]::WlanEnumInterfaces($hk, [IntPtr]::Zero, [ref]$lst, [ref]$n)
  Write-Output ('WlanEnumInterfaces=' + $re + ' count=' + $n)
  if ($re -eq 0 -and $n -gt 0 -and $lst -ne [IntPtr]::Zero) {
    $p1 = $lst
    $g  = [Runtime.InteropServices.Marshal]::PtrToStructure($p1, [Type][Guid])
    $descPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($p1, 16)
    $state = [Runtime.InteropServices.Marshal]::ReadInt32($p1, 24)
    Write-Output ('IFACE1|guid=' + $g + '|state=' + $state + '|desc=' + [Runtime.InteropServices.Marshal]::PtrToStringUni($descPtr))
  }
}
Write-Output '== N5. event log tail (driver load errors) =='
foreach ($ev in @(Get-WinEvent -LogName System -MaxEvents 40 -EA SilentlyContinue | Where-Object { $_.LevelDisplayName -ne 'Information' -or $_.ProviderName -match 'ndis|Driver|PnP|Service' } | Select-Object -First 15)) {
  Write-Output ('EVT|' + $ev.TimeCreated.ToString('HH:mm:ss') + '|' + $ev.ProviderName + '|id=' + $ev.Id + '|' + ($ev.Message -replace '\s+', ' '))
}
Write-Output 'PROBE29 END'
