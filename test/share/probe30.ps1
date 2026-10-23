param([switch]$Retry)
$ErrorActionPreference = 'SilentlyContinue'
# probe30 -- drvload got the AX211 to code 37 (CM_PROB_FAILED_DRIVER_ENTRY) instead of 0.
# Find why: setupapi log tail, System event log (Kernel-PnP gives the real NTSTATUS),
# the INF's service definition + DependOnService, and what files actually landed in the image.
# -Retry also starts nativewifip (this is the CI/.cat fix being exercised for the first time on real
# hardware) and re-enables the devnode, then re-reads everything.
$node = 'PCI\VEN_8086&DEV_7A70&SUBSYS_00948086&REV_11\3&11583659&0&A3'
$infp = 'D:\Windows\System32\DriverStore\FileRepository\netwtw6e.inf_amd64_c3785d6f1e6d5b0e\Netwtw6e.INF'

Write-Output ('PROBE30 ' + (Get-Date -Format 'HH:mm:ss') + ' retry=' + [bool]$Retry)

Write-Output '== S1. devnode / service state now =='
$d = Get-CimInstance Win32_PnPEntity -Filter ("PNPDeviceID='" + $node + "'") -EA SilentlyContinue
Write-Output ('NODE|code=' + $d.ConfigManagerErrorCode + '|st=' + $d.Status + '|' + $d.Name)
foreach ($s in @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw|nativewifip|ioprof' })) {
  Write-Output ('SYSDRV|' + $s.Name + '|state=' + $s.State + '|startmode=' + $s.StartMode + '|path=' + $s.PathName)
}
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netwtw6e'
$kp = Get-ItemProperty $k -EA SilentlyContinue
Write-Output ('NETWTW6E_KEY=' + [bool]$kp + '|Start=' + $kp.Start + '|Type=' + $kp.Type + '|Group=' + $kp.Group +
              '|Depend=' + (($kp.DependOnService | ForEach-Object { $_ }) -join ',') + '|SvcDll=' + $kp.ServiceDll +
              '|ImagePath=' + $kp.ImagePath + '|ErrorControl=' + $kp.ErrorControl)
foreach ($sub in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -EA SilentlyContinue | Where-Object { $_.PSChildName -match 'netwtw|NonVol|iologenerate|Intc' })) {
  $p = Get-ItemProperty $sub.PSPath -EA SilentlyContinue
  Write-Output ('SVCKEY|' + $sub.PSChildName + '|Start=' + $p.Start + '|Type=' + $p.Type + '|Img=' + $p.ImagePath + '|Dep=' + (($p.DependOnService | ForEach-Object { $_ }) -join ','))
}

Write-Output '== S2. what landed in the image =='
foreach ($p in 'X:\Windows\System32\drivers\Netwtw6e.sys', 'X:\Windows\System32\DriverStore\FileRepository') {
  Write-Output ('PATH|' + $p + '=' + (Test-Path $p))
}
foreach ($dd in @(Get-ChildItem 'X:\Windows\System32\DriverStore\FileRepository' -Directory -EA SilentlyContinue | Where-Object { $_.Name -match 'netwtw' })) {
  $fs = @(Get-ChildItem $dd.FullName -Recurse -File -EA SilentlyContinue)
  Write-Output ('DSDIR|' + $dd.Name + '|files=' + $fs.Count)
  foreach ($f in ($fs | Sort-Object Length -Descending | Select-Object -First 12)) {
    Write-Output ('  FILE|' + $f.Name + '|' + $f.Length)
  }
}
Write-Output ('FREE_X=' + ((Get-PSDrive X).Free))

Write-Output '== S3. setupapi.dev.log tail (drvload install trace) =='
$sal = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path $sal) {
  $ln = @(Get-Content $sal -EA SilentlyContinue)
  Write-Output ('SETUPAPI_LINES=' + $ln.Count)
  foreach ($l in ($ln | Select-Object -Last 60)) { Write-Output ('SAL|' + $l) }
} else { Write-Output 'SETUPAPI=missing' }

Write-Output '== S4. INF service/dependency definition =='
if (Test-Path $infp) {
  $b = [IO.File]::ReadAllBytes($infp)
  $t = $(if ($b[0] -eq 0xFF -and $b[1] -eq 0xFE) { [Text.Encoding]::Unicode.GetString($b) } else { [Text.Encoding]::UTF8.GetString($b) })
  foreach ($l in ($t -split "`r?`n")) {
    if ($l -match '^\s*(AddService|DelService|CopyFiles|Include|EXCLUDE)' -or $l -match '\.sys|\.dat|ServiceType|StartType|LoadOrderGroup|Dependencies') {
      Write-Output ('INF|' + $l.Trim())
    }
  }
}

Write-Output '== S5. System event log (Kernel-PnP / Driver entry status) =='
$evs = @(Get-WinEvent -LogName System -MaxEvents 120 -EA SilentlyContinue)
Write-Output ('EVT_TOTAL=' + $evs.Count)
foreach ($e in ($evs | Select-Object -First 30)) {
  Write-Output ('EVT|' + $e.TimeCreated.ToString('HH:mm:ss') + '|' + $e.ProviderName + '|id=' + $e.Id + '|lvl=' + $e.LevelDisplayName + '|' + (($e.Message -replace '\s+', ' ') -replace '[^\x20-\x7E]', '?'))
}

if (-not $Retry) { Write-Output 'PROBE30 END (read-only pass)'; exit 0 }

Write-Output '== S6. start nativewifip (the .cat fix, first real-hardware test) =='
Add-Type -Language CSharp @'
using System;using System.Runtime.InteropServices;
public class Wapi {
  [DllImport("wlanapi.dll")] public static extern int WlanOpenHandle(int a, IntPtr b, out int c, out IntPtr d);
  [DllImport("wlanapi.dll",CharSet=CharSet.Unicode)] public static extern int WlanEnumInterfaces(IntPtr h, IntPtr r, out IntPtr list, out int cnt);
}
'@ -EA SilentlyContinue
$nw = Get-Service nativewifip -EA SilentlyContinue
Write-Output ('NATIVEWIFIP_BEFORE=' + $nw.Status)
try { $nw.Start(); Write-Output 'NATIVEWIFIP_START=Start() returned' } catch { Write-Output ('NATIVEWIFIP_START_EX=' + $_.Exception.Message) }
Start-Sleep -Seconds 2
Write-Output ('NATIVEWIFIP_NOW=' + (Get-Service nativewifip -EA SilentlyContinue).Status)

Write-Output '== S7. re-enable devnode (retry DriverEntry) =='
Write-Output ('PNPUTIL|' + ((& pnputil /enable-device $node 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 3
Write-Output ('PNPUTIL_SCAN|' + ((& pnputil /scan-devices 2>&1 | Out-String) -replace '\s+', ' '))
Start-Sleep -Seconds 4
$d2 = Get-CimInstance Win32_PnPEntity -Filter ("PNPDeviceID='" + $node + "'") -EA SilentlyContinue
Write-Output ('NODE2|code=' + $d2.ConfigManagerErrorCode + '|st=' + $d2.Status + '|' + $d2.Name)
foreach ($a in @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })) {
  Write-Output ('NIC2|' + $a.Name + '|enabled=' + $a.NetEnabled + '|guid=' + $a.GUID)
}
Write-Output ('WLANSVC2=' + (Get-Service wlansvc -EA SilentlyContinue).Status)
Write-Output ('NATIVEWIFIP2=' + (Get-Service nativewifip -EA SilentlyContinue).Status)
$ver = 0; $hk = [IntPtr]::Zero
$rh = & { try { [Wapi]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$hk) } catch { 'NO_TYPE' } }
Write-Output ('WlanOpenHandle2=' + $rh)
ipconfig /all | Select-String -Pattern 'adapter|description|IPv4|DHCP Enabled' | ForEach-Object { Write-Output ('IPC|' + $_.Line) }
Write-Output 'PROBE30 END'
