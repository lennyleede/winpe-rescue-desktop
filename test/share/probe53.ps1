# probe53 -- LIVE PE, corrected version of probe52's start test.
# probe52 wasted itself on two of my own bugs: OpenSCManager($null,$null,...) came back err=123
# (ERROR_INVALID_NAME, the marshal sent an empty machine name), and '... = ' + "$(Get-Service $n).Status"
# stringified the ServiceController instead of its Status (PS needs "$((Get-Service $n).Status)").
# No P/Invoke needed for the number we want: (Get-Service x).Start() throws, and the innermost
# Win32Exception carries NativeError -- that is the Win32 code the SCM returned (31=GEN_FAILURE,
# 577=DRIVER_BLOCKED/signing, 1068=dependency, 1058=disabled, 193=bad image, 2/3=file or path missing).
# vwififlt's Start was already flipped 1 -> 3 by probe52 in this ramdisk session, so SCM will now accept it.
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output ('  ' + $s) }
function HDR([string]$s) { Write-Output ('== ' + $s + ' ==') }
function CodeNow {
  $c = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
         Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' } |
         ForEach-Object { $_.ConfigManagerErrorCode })
  if ($c.Count -eq 0) { return 'GONE' } else { return "$($c[0])" }
}
function ProbStatus {
  $d = @(Get-PnpDevice -EA SilentlyContinue | Where-Object { $_.InstanceId -like '*VEN_8086&DEV_7A70*' })
  if ($d.Count -eq 0) { return '-' }
  $v = (Get-PnpDeviceProperty -InstanceId $d[0].InstanceId -Key 'DEVPKEY_Device_ProblemStatus' -EA SilentlyContinue).Data
  if ($null -eq $v) { return '-' }
  return ($v.ToString() + ' 0x' + ('{0:X8}' -f [uint32]$v))
}
function St([string]$n) {
  try { $s = Get-Service $n -EA Stop; return "$($s.Status)" } catch { return 'NOGET' }
}
function StartOne([string]$n) {
  try {
    $s = Get-Service $n -EA Stop
    if ("$($s.Status)" -eq 'Running') { O ('START ' + $n + ' already Running'); return }
    $s.Start()
    Start-Sleep -Seconds 2
    O ('START ' + $n + ' ok state=' + (St $n))
  } catch {
    $ie = $_.Exception
    while ($ie.InnerException) { $ie = $ie.InnerException }
    $code = 'n/a'
    if ($ie -is [ComponentModel.Win32Exception]) { $code = $ie.NativeError }
    O ('START ' + $n + ' FAILED NativeError=' + $code + ' type=' + $ie.GetType().Name +
       ' msg=' + (($ie.Message) -replace '\s+', ' '))
  }
}
function ResolveImg([string]$img) {
  if (-not $img) { return '' }
  if ($img -match '^[A-Za-z]:\\') { return $img }
  if ($img -match '(?i)^(\\|%)?SystemRoot(\\|%)?\\(.*)$') { return ('X:\Windows\' + $matches[3]) }
  return ('X:\Windows\' + $img)
}
function ImgOf([string]$n) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  if (-not (Test-Path -LiteralPath $k)) { O ($n + ' KEY_ABSENT'); return }
  $p = Get-ItemProperty -LiteralPath $k -EA SilentlyContinue
  $img = "$($p.ImagePath)"
  $res = ResolveImg $img
  $fs = 'NOIMAGE'
  if ($res) { $fs = $(if (Test-Path -LiteralPath $res) { "$((Get-Item -LiteralPath $res).Length)B " +
      (Get-Item -LiteralPath $res).VersionInfo.ProductVersion } else { 'MISSING -> ' + $res }) }
  O ($n + ' Start=' + $p.Start + ' Group=' + ($p.Group -join ',') + ' Image=' + $img + ' resolved=' + $res +
     ' file=' + $fs + ' state=' + (St $n))
}

HDR '0 device before'
O ('code=' + (CodeNow) + ' status=' + (ProbStatus))

HDR '1 the chain: keys, images, files, states'
foreach ($n in @('ndis', 'ndisuio', 'vwifibus', 'vwififlt', 'vwifimp', 'nativewifip', 'Netwtw14', 'wlansvc', 'wcmsvc')) {
  ImgOf $n
}

HDR '2 start each one, with the real Win32 code'
foreach ($n in @('ndisuio', 'vwifibus', 'vwifimp', 'vwififlt', 'nativewifip')) { StartOne $n }

HDR '3 device read-back after those start attempts'
O ('code=' + (CodeNow) + ' status=' + (ProbStatus))
$ents = @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue |
          Where-Object { $_.PNPDeviceID -match 'VEN_8086&DEV_7A70' })
$PNP = if ($ents.Count) { "$($ents[0].PNPDeviceID)" } else { '' }
if ($PNP) {
  $r = @(& pnputil.exe /restart-device "$PNP" 2>&1 | ForEach-Object { (($_ -replace '\s+', ' ').Trim()) })
  O ('RESTART ' + ($r -join ' | '))
  Start-Sleep -Seconds 5
  O ('AFTER_RESTART code=' + (CodeNow) + ' status=' + (ProbStatus))
}
$enum = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
foreach ($v in @(Get-ChildItem -LiteralPath $enum -EA SilentlyContinue)) {
  if ($v.PSChildName -match 'VEN_8086&DEV_7A70') {
    foreach ($i in @(Get-ChildItem -LiteralPath $v.PSPath -EA SilentlyContinue)) {
      $p = Get-ItemProperty -LiteralPath $i.PSPath -EA SilentlyContinue
      O ('DEVNODE upper=' + ($p.UpperFilters -join ',') + ' lower=' + ($p.LowerFilters -join ',') +
         ' service=' + $p.Service + ' driver=' + $p.Driver + ' problem=' + $p.'Problemcode')
    }
  }
}
foreach ($n in @('vwifibus', 'vwififlt', 'nativewifip', 'Netwtw14')) { O ('STATE ' + $n + ' = ' + (St $n)) }

HDR '4 wlansvc and wlanapi'
StartOne 'wlansvc'
StartOne 'wcmsvc'
try {
  Add-Type -Namespace 'P53' -Name 'W' -MemberDefinition @'
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int ver, System.IntPtr res, out int newVer, out System.IntPtr handle);
[DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanEnumInterfaces(System.IntPtr handle, System.IntPtr res, out System.IntPtr list, out int count);
[DllImport("wlanapi.dll")]
public static extern int WlanCloseHandle(System.IntPtr handle, System.IntPtr res);
'@ -EA Stop
  $h = [IntPtr]::Zero; $nv = 0
  $rc = [P53.W]::WlanOpenHandle(1, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  O ('WLANOPEN rc=' + $rc)
  if ($rc -eq 0) {
    $list = [IntPtr]::Zero; $cnt = 0
    $rc2 = [P53.W]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list, [ref]$cnt)
    O ('WLANENUM rc=' + $rc2 + ' ifaces=' + $cnt)
    [void][P53.W]::WlanCloseHandle($h, [IntPtr]::Zero)
  }
} catch { O ('WLANAPI-ERR ' + (($_.Exception.Message) -replace '\s+', ' ')) }
Write-Output 'P53 END'
