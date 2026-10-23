# probe42 -- LIVE PE experiment, ASCII only, output prefixed P42.
# Field fact this tests (probe41, 2026-10-09 18:5x, AX211 DEV_7A70):
#   files baked 4/4, service keys 8, DriverStore dirs 4/4, but the devnode has NO UpperFilters
#   and the device sits at code 37 (CM_PROB_FAILED_DRIVER_ENTRY), WlanOpenHandle rc=1062.
# Host reference (build\scratch\host_vwifi_layers.ps1, working Win10 machine):
#   [PnPFilterRegistration] is  HKR,,"UpperFilters",0x00010000,"vwifibus"   -> devnode-level ONLY.
#   The working AC 9260 devnode has Upper=vwifibus and **no LowerFilters at all**
#   (nativewifip is attached by wlansvc, not by a LowerFilters value), and no Control\Class key
#   carries a vwifi filter. So the whole thing hinges on one MULTI_SZ on the device instance key.
# Earlier handwritten attempt (memory) set Upper=vwifibus *and* Lower=nativewifip -> still code37.
# Hypothesis: the LowerFilters=nativewifip we added ourselves is what kept the stack from starting.
# Phase A reads the current shape, Phase B writes ONLY UpperFilters and restarts, Phase C re-reads.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function RV([string]$key, [string]$name) {
  $o = @(& reg.exe query $key /v $name 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|MULTI_SZ|DWORD)\s+(.*)$')) {
      return ($matches[2] -replace '\s+', ' ').Trim()
    }
  }
  return ''
}

$target = $null
foreach ($v in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)) {
  if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
    $inst = @(Get-ChildItem $v.PSPath -EA SilentlyContinue) | Select-Object -First 1
    if ($inst) {
      $target = @{
        name  = $v.PSChildName
        inst  = $inst.PSChildName
        path  = $inst.PSPath
        reg   = ('HKLM\SYSTEM\CurrentControlSet\Enum\PCI\' + $v.PSChildName + '\' + $inst.PSChildName)
        full  = ('PCI\' + $v.PSChildName + '\' + $inst.PSChildName)
      }
    }
  }
}
if (-not $target) { O 'P42 FATAL: AX211 (VEN_8086&DEV_7A70) not present under Enum\PCI'; O 'P42 END'; exit 0 }
O ('P42 DEV ' + $target.full)

function Dump([string]$phase) {
  O ('-- ' + $phase)
  O ('   code      = ' + @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
        Where-Object { $_.PNPDeviceID -eq $target.full } | ForEach-Object { $_.ConfigManagerErrorCode }))
  O ('   Service   = ' + (RV $target.reg 'Service'))
  O ('   Upper     = ' + (RV $target.reg 'UpperFilters'))
  O ('   Lower     = ' + (RV $target.reg 'LowerFilters'))
  O ('   Driver    = ' + (RV $target.reg 'Driver'))
  O ('   ClassGuid = ' + (RV $target.reg 'ClassGuid'))
}
Dump 'A baseline'
foreach ($n in 'vwifibus', 'vwififlt', 'nativewifip') {
  $e = ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n + '\Enum')
  $cnt = @(Get-ChildItem ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n) -EA SilentlyContinue |
           Where-Object { $_.PSChildName -eq 'Enum' }).Count
  O ('   SVCNODE ' + $n + ' EnumKeyExists=' + ($cnt -gt 0) + ' NextInstance=' + $(if ($cnt) { (RV ('HKLM\SYSTEM\CurrentControlSet\Services\' + $n + '\Enum') 'NextInstance') } else { '-' }))
}
$drv = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue |
         Where-Object { $_.Name -match 'vwifi|nativewifip|Netwtw' } |
         ForEach-Object { $_.Name + '=' + $_.State + '/' + $_.Started })
O ('   CIMDRIVERS ' + $(if ($drv.Count) { $drv -join ' ' } else { 'none' }))

O 'P42 ACTION: reg add UpperFilters=vwifibus (NO LowerFilters) + pnputil /restart-device'
& reg.exe add $target.reg /v UpperFilters /t REG_MULTI_SZ /d vwifibus /f 2>&1 | ForEach-Object { O ('   REG ' + ("$_" -replace '\s+', ' ')) }
Dump 'B after write, before restart'
& pnputil.exe /restart-device $target.full 2>&1 | ForEach-Object { O ('   PNPUTIL ' + ("$_" -replace '\s+', ' ')) }
Start-Sleep -Seconds 8
Dump 'C after restart'

O 'P42 ACTION: try wlansvc + WlanOpenHandle'
try {
  $s = Get-Service wlansvc -EA Stop
  O ('   SVCSTATE before = ' + $s.Status)
  if ("$($s.Status)" -ne 'Running') { $s.Start(); Start-Sleep -Seconds 5 }
  O ('   SVCSTATE after  = ' + (Get-Service wlansvc).Status)
} catch { O ('   SVCFAIL ' + $_.Exception.Message) }
try {
  Add-Type -Namespace P42 -Name P42W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [P42.P42W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('   WLANOPEN rc=' + $rc + ' newVer=' + $nv)
  if ($rc -eq 0 -and $h -ne [IntPtr]::Zero) { [void][P42.P42W]::WlanCloseHandle($h, [IntPtr]::Zero) }
} catch { O ('   WLANOPEN-FAIL ' + ($_.Exception.Message -replace '\s+', ' ')) }
$ad = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
        Where-Object { $_.Name -match '(?i)Wi-Fi|wireless|WLAN|Virtual WiFi' } |
        ForEach-Object { $_.Name + '|code=' + $_.ConfigManagerErrorCode })
O ('   DEVICES ' + $(if ($ad.Count) { $ad -join ' ;; ' } else { 'none' }))
Dump 'D final'
$lg = 'X:\Windows\INF\setupapi.dev.log'
if (Test-Path $lg) {
  $t = @(Get-Content -LiteralPath $lg -Encoding Unicode -EA SilentlyContinue)
  O ('   SETUPAPI_DEV lines=' + $t.Count)
  @($t | Where-Object { "$_" -match '(?i)vwifi|7A70|error|fail' } | Select-Object -Last 12) |
    ForEach-Object { O ('   LOG ' + (($_ -replace '\s+', ' ').Trim())) }
}
O 'P42 END'
