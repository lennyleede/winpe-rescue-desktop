# probe46 -- LIVE PE, the decisive experiment, output prefixed P46.
# probe45 read the laptop's own Windows volume: it runs netwtw6e **23.60.1.2 (2024-06-03)** and
# **23.150.0.4 (2025-06-12)**, both with Netwtw14/Netwtw16 + .cat. Our pool's copy is the OLDER
# 23.40.0.4 (2024-03-10), and netdrvfix tried netwtw08(2 pkg)+netwtw6e -> AX211 stayed code 37 while the
# Realtek wired NIC went 18 -> 0 in the same run. So test whether the machine's own known-good package
# loads in PE, and (importantly) whether a FRESH install of it makes PnP apply Include=netvwifibus.inf
# from our bake -- i.e. UpperFilters appears and WlanOpenHandle stops returning 1062.
# Mutations stay on X: (ramdisk). D: is only read.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function CodeNow {
  $c = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' } |
         ForEach-Object { $_.ConfigManagerErrorCode })
  if ($c.Count -eq 0) { return 'GONE' } else { return "$($c[0])" }
}
function DevReg() {
  foreach ($v in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -EA SilentlyContinue)) {
    if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
      $i = @(Get-ChildItem $v.PSPath -EA SilentlyContinue) | Select-Object -First 1
      if ($i) { return ('HKLM\SYSTEM\CurrentControlSet\Enum\PCI\' + $v.PSChildName + '\' + $i.PSChildName) }
    }
  }
  return ''
}
function RGV([string]$key, [string]$name) {
  $o = @(& reg.exe query $key /v $name 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|MULTI_SZ|DWORD|BINARY)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim())
    }
  }
  return ''
}
function Report([string]$phase) {
  $r = DevReg
  O ('  ' + $phase + ' code=' + @(CodeNow) + ' svc=' + (RGV $r 'Service') +
     ' upper=' + (RGV $r 'UpperFilters') + ' lower=' + (RGV $r 'LowerFilters') + ' drv=' + (RGV $r 'Driver'))
}
O '== 0 baseline =='
Report 'BASE'

$fr = 'D:\Windows\System32\DriverStore\FileRepository'
$pkgs = @(Get-ChildItem $fr -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)^netwtw6e\.inf_' })
O ('  CANDIDATES ' + $pkgs.Count)
foreach ($p in $pkgs) {
  $inf = @(Get-ChildItem -LiteralPath $p.FullName -Filter '*.inf' -File -EA SilentlyContinue) | Select-Object -First 1
  if (-not $inf) { O ('  SKIP ' + $p.Name + ' no inf'); continue }
  $dv = @((Get-Content -LiteralPath $inf.FullName -Encoding Unicode -EA SilentlyContinue) |
          Where-Object { "$_" -match '(?i)^\s*DriverVer' } | Select-Object -First 1)
  O ('  ---- try ' + $p.Name + ' [' + (("$dv" -replace '\s+', ' ').Trim()) + '] ----')
  & pnputil.exe /add-driver $inf.FullName /install 2>&1 |
    ForEach-Object { $l = (($_ -replace '\s+', ' ').Trim()); if ($l -ne '') { O ('  PNPUTIL ' + $l) } }
  Start-Sleep -Seconds 6
  Report 'AFTER_ADDDRIVER'
  if ("$(CodeNow)" -ne '0') {
    $r = DevReg
    if ($r -ne '') {
      $full = ($r -replace '^HKLM\\SYSTEM\\CurrentControlSet\\Enum\\', '')
      & pnputil.exe /restart-device $full 2>&1 | ForEach-Object { O ('  RESTART ' + (($_ -replace '\s+', ' ').Trim())) }
      Start-Sleep -Seconds 6
      Report 'AFTER_RESTART'
    }
  }
}
O '== service / wlan state =='
foreach ($n in 'vwifibus', 'vwififlt', 'nativewifip', 'wlansvc', 'wcmsvc') {
  $st = 'NOKEY'
  if (Test-Path ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $n)) { try { $st = "$((Get-Service $n).Status)" } catch { $st = 'ERR' } }
  O ('  SVC ' + $n + '=' + $st)
}
try {
  $w = Get-Service wlansvc -EA Stop
  if ("$($w.Status)" -ne 'Running') { $w.Start(); Start-Sleep -Seconds 4 }
  O ('  WLANSVC now=' + (Get-Service wlansvc).Status)
} catch { O ('  WLANSVC-FAIL ' + (($_.Exception.Message) -replace '\s+', ' ')) }
try {
  Add-Type -Namespace P46 -Name P46W -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list, out int count);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [P46.P46W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('  WLANOPEN rc=' + $rc + ' newVer=' + $nv)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    $rc2 = [P46.P46W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt)
    O ('  WLANENUM rc=' + $rc2 + ' ifaces=' + $cnt)
    [void][P46.P46W]::WlanCloseHandle($h, [IntPtr]::Zero)
  }
} catch { O ('  WLANAPI-FAIL ' + (($_.Exception.Message) -replace '\s+', ' ')) }
$ad = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
        Where-Object { $_.Name -match '(?i)Wi-Fi|wireless|Virtual WiFi' } |
        ForEach-Object { $_.Name + '|code=' + $_.ConfigManagerErrorCode })
O ('  DEVICES ' + ($ad -join ' ;; '))
$ip = @(Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue |
        Where-Object { $_.IPAddress } | ForEach-Object { $_.Description + '=' + ($_.IPAddress -join ',') })
O ('  IPS ' + ($ip -join ' ;; '))
O 'P46 END'
