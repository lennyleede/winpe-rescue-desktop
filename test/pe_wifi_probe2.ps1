# test/pe_wifi_probe2.ps1 -- runs INSIDE a live PE (pushed with test\host_push_run.ps1 -Run).
# Question: WHY does wlansvc fail with "System error 6" in this 26100 PE while dot3svc-shaped
# services start fine? Two decisive measurements, neither of which needs the driver:
#   (A) static import-table parse of every borrowed WiFi DLL -> which dependency file is absent
#   (B) LoadLibraryExW + GetLastError -> the loader's own verdict (126 missing module / 127 missing proc)
# Output: ASCII only. Read-only except: it starts dot3svc/wlansvc/wcmsvc (ramdisk, nothing persists).
$ErrorActionPreference = 'Continue'
function Sec([string]$t) { Write-Output ''; Write-Output ('===== ' + $t + ' =====') }
function One([string]$s) { ($s -replace "`r?`n", ' ') -replace '\s{2,}', ' ' }

$S32 = Join-Path $env:SystemRoot 'System32'

Sec '0_WHO'
Write-Output ('  computer=' + $env:COMPUTERNAME + ' build=' + [Environment]::OSVersion.Version.Build +
              ' sp=' + [Environment]::OSVersion.Version.ServicePack + ' user=' + [Environment]::UserName)
$bt = 'X:\BUILD_TAG.txt'
if (Test-Path $bt) { Write-Output ('  BUILD_TAG build = ' + ((Get-Content $bt -EA SilentlyContinue) | Where-Object { $_ -match '^\s*build' } | Select-Object -First 1)) }

# ---------- (A) PE import table ----------
# The helpers return SCALARS only. Handing arrays back through the PowerShell output stream is what
# made an earlier version report "imports=1  MISSING=System.Object[]": `return , $names` from a
# function nests the array inside another array, and @() around the call keeps that nesting.
$script:PeB = $null
$script:PeSecs = $null
$script:PeMissSec = 0

function Find-PeOffset([int]$rva, [int]$len) {
  foreach ($s in $script:PeSecs) {
    if ($rva -ge $s.VA -and ($rva + $len) -le ($s.VA + [Math]::Max($s.VS, $s.RawS))) {
      $off = $s.RawO + ($rva - $s.VA)
      if (($off + $len) -le $script:PeB.Length) { return $off }
    }
  }
  $script:PeMissSec++
  return -1
}

function Read-PeUInt32([int]$rva) {
  $off = Find-PeOffset $rva 4
  if ($off -lt 0) { return $null }
  return [BitConverter]::ToUInt32($script:PeB, $off)
}

function Read-PeCString([int]$rva) {
  $off = Find-PeOffset $rva 1
  if ($off -lt 0) { return '' }
  $s = ''
  for ($j = 0; $j -lt 260; $j++) {
    $o = $off + $j
    if ($o -ge $script:PeB.Length) { break }
    $ch = [char]$script:PeB[$o]
    if ([int]$ch -eq 0) { break }
    if ([int]$ch -lt 1) { break }
    $s += $ch
  }
  return $s
}

function Get-PeImports([string]$path) {
  $b = [IO.File]::ReadAllBytes($path)
  if ($b.Length -lt 0x100) { return @('!!TOO_SMALL') }
  if ([BitConverter]::ToUInt16($b, 0) -ne 0x5A4D) { return @('!!NOT_MZ') }
  $pe = [BitConverter]::ToInt32($b, 0x3C)
  if ([BitConverter]::ToUInt32($b, $pe) -ne 0x00004550) { return @('!!NOT_PE') }
  $sizeOpt = [BitConverter]::ToUInt16($b, $pe + 20)
  $opt     = $pe + 24
  $magic   = [BitConverter]::ToUInt16($b, $opt)
  $dirBase = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }   # data directory[0] = EXPORT
  $dirOff  = $dirBase + 8                                              # [1] = IMPORT (reading [0] once yielded "Wlansvc.dll" as its only import)
  $script:PeB = $b
  $nSec = [BitConverter]::ToUInt16($b, $pe + 6)
  $sec  = $opt + $sizeOpt
  $secs = @()
  for ($i = 0; $i -lt $nSec; $i++) {
    $o = $sec + $i * 40
    $secs += [pscustomobject]@{
      VA   = [int]   [BitConverter]::ToUInt32($b, $o + 12)
      VS   = [int]   [BitConverter]::ToUInt32($b, $o + 8)
      RawO = [int]   [BitConverter]::ToUInt32($b, $o + 20)
      RawS = [int]   [BitConverter]::ToUInt32($b, $o + 16)
    }
  }
  $script:PeSecs = $secs
  $script:PeMissSec = 0
  # the data-directory array sits in the OPTIONAL HEADER, which is addressed by raw file offset,
  # not by RVA -- so read it straight out of $b instead of through the section mapper.
  $impRva = [int]([BitConverter]::ToUInt32($b, $dirOff))
  $impCnt = [int]([BitConverter]::ToUInt32($b, $dirOff + 4))
  if ($impRva -eq 0) { return @('!!NO_IMPORT_DIR') }
  $names = @()
  $maxDesc = if ($impCnt -ge 20) { [Math]::Min(64, [int]($impCnt / 20)) } else { 64 }
  for ($k = 0; $k -lt $maxDesc; $k++) {
    $base = $impRva + $k * 20
    $nameRva = Read-PeUInt32 ($base + 12)
    if ($null -eq $nameRva) { break }
    $oft = Read-PeUInt32 $base
    $ft  = Read-PeUInt32 ($base + 16)
    if ($nameRva -eq 0 -and $oft -eq 0 -and $ft -eq 0) { break }        # terminating null descriptor
    $nm = Read-PeCString ([int]$nameRva)
    if ($nm) { $names += $nm }
  }
  if ($script:PeMissSec -gt 0) { $names += ('!!BADRVA' + $script:PeMissSec) }
  return $names
}

# Filename index of System32, built once. NOTE: never use Get-ChildItem -Filter for existence
# checks here -- -Filter also matches 8.3 short names and would call an absent DLL "present".
$s32Names = @{}
foreach ($fi in @(Get-ChildItem $S32 -File -EA SilentlyContinue)) { $s32Names[$fi.Name.ToUpper()] = 1 }
Write-Output ('(System32 has ' + $s32Names.Count + ' files on index)')

$StackFiles = @('wlansvc.dll','wlanapi.dll','wlancfg.dll','wlanmsm.dll','wlansec.dll','wlanext.exe',
                'wlanutil.dll','wlansvcpal.dll','wlanhlp.dll','wcmsvc.dll','dmcmnutils.dll',
                'mdmregistration.dll','wci.dll','netshell.dll','netsh.exe','dot3api.dll','dot3cfg.dll','dot3svc.dll')

Sec '1_IMPORTS_OF_STACK_MODULES'
foreach ($f in $StackFiles) {
  $p = Join-Path $S32 $f
  if (-not (Test-Path -LiteralPath $p)) { Write-Output ('  ' + $f + ' : ABSENT-IN-PE'); continue }
  $imp = @(Get-PeImports $p)
  if ($imp.Count -eq 1 -and $imp[0] -like '!!*') {
    Write-Output ('  ' + $f + ' : parse says ' + $imp[0]); continue
  }
  $note = @($imp | Where-Object { $_ -like '!!*' })
  $real = @($imp | Where-Object { $_ -notmatch '(?i)^(api-ms-win|ext-ms-win)-' -and $_ -notlike '!!*' })
  $apisetCount = $imp.Count - $real.Count
  $miss = @($real | Where-Object { -not $s32Names.ContainsKey($_.ToUpper()) })
  Write-Output ('  ' + $f.PadRight(20) + ' imports=' + $imp.Count + ' (apiset ' + $apisetCount + ') real=' + $real.Count + '  MISSING=' + $(if ($miss.Count) { ($miss -join ',') } else { 'none' }) + $(if ($note.Count) { '  note=' + ($note -join ',') } else { '' }))
  if ($miss.Count) { Write-Output ('      full list: ' + ($real -join ' ')) }
}

Sec '2_FILE_VERSIONS_IN_PE'
foreach ($f in @('wlansvc.dll','wlanapi.dll','wcmsvc.dll','wlancfg.dll','wlanmsm.dll','wlansec.dll','wlanutil.dll','netsh.exe','netshell.dll','dot3svc.dll','drivers\nwifi.sys','drivers\ndisuio.sys')) {
  $p = Join-Path $S32 $f
  if (Test-Path -LiteralPath $p) {
    $vi = (Get-Item -LiteralPath $p).VersionInfo
    Write-Output ('  ' + $f.PadRight(20) + ' ' + $vi.FileVersion)
  } else { Write-Output ('  ' + $f.PadRight(20) + ' ABSENT') }
}

Sec '3_LOADLIBRARY'
$src = @'
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode) ]
static extern IntPtr LoadLibraryExW(string dll, IntPtr hFile, uint flags);
[ System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true) ]
static extern int FreeLibrary(IntPtr m);
public static string Try(string path) {
  IntPtr h = LoadLibraryExW(path, IntPtr.Zero, 0x00000008); // LOAD_WITH_ALTERED_SEARCH_PATH
  if (h == IntPtr.Zero) {
    int e = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
    return "FAIL win32=" + e + " (0x" + e.ToString("X8") + ")";
  }
  FreeLibrary(h);
  return "LOAD-OK";
}
'@
# -MemberDefinition injects its text INSIDE a generated class and already emits the using
# directives, so a full "using ...; public class X { }" source here is a compile error.
try {
  $t = Add-Type -MemberDefinition $src -Name Ldr -Namespace P -Language CSharp -PassThru -EA Stop
  foreach ($f in @('rpcrt4.dll','dot3svc.dll','wlansvc.dll','wcmsvc.dll','wlanapi.dll','wlancfg.dll','wlanmsm.dll','wlansec.dll','wlanutil.dll','netshell.dll','dmcmnutils.dll','mdmregistration.dll','wci.dll')) {
    $p = Join-Path $S32 $f
    if (-not (Test-Path -LiteralPath $p)) { Write-Output ('  ' + $f.PadRight(20) + ' ABSENT'); continue }
    $r = ''
    try { $r = [P.Ldr]::Try($p) } catch { $r = 'threw: ' + $_.Exception.Message }
    Write-Output ('  ' + $f.PadRight(20) + ' ' + $r)
  }
} catch {
  Write-Output ('  Add-Type failed: ' + $_.Exception.Message)
}

Sec '3B_WLANSVC_DEP_BY_DEP'
# If the top-level load above fails with win32=126, the loader does not say WHICH module is missing.
# Loading every real import one by one does. Api-set contracts are listed but not probed (they are
# resolved virtually by ntdll, not from System32 files).
foreach ($m in @('wlansvc.dll','wcmsvc.dll')) {
  $mp = Join-Path $S32 $m
  if (-not (Test-Path -LiteralPath $mp)) { Write-Output ('  ' + $m + ' ABSENT'); continue }
  $imps = @(Get-PeImports $mp)
  $apis = @($imps | Where-Object { $_ -match '(?i)^(api-ms-win|ext-ms-win)-' })
  $reals = @($imps | Where-Object { $_ -notmatch '(?i)^(api-ms-win|ext-ms-win)-' -and $_ -notlike '!!*' })
  Write-Output ('  -- ' + $m + ': real=' + $reals.Count + ' apiset=' + $apis.Count)
  Write-Output ('     apiset list: ' + ($apis -join ' '))
  foreach ($d in $reals) {
    $dp = Join-Path $S32 $d
    $r = 'FILE-NOT-IN-SYSTEM32'
    if (Test-Path -LiteralPath $dp) { try { $r = [P.Ldr]::Try($dp) } catch { $r = 'threw: ' + $_.Exception.Message } }
    Write-Output ('     ' + $d.PadRight(24) + ' ' + $r)
  }
}

Sec '3C_APINET_CONTRACT_SAMPLE'
Write-Output '  -- does this PE know the contracts the WiFi stack asks for? ask the loader for one representative module per family'
foreach ($d in @('wimgapi.dll','twinapi.appcore.dll','microsoft-windows-kernelbase-emergencytrace-l1-2-0.dll','kernel.appcore.dll','ucrtbase.dll','msvcp_win.dll','devobj.dll','cfgmgr32.dll','wtsapi32.dll','srvcli.dll','netutils.dll','bcrypt.dll','ncrypt.dll','userenv.dll','profapi.dll','gpapi.dll','ipnathlp.dll','fwpuclnt.dll','rasapi32.dll','eappcfg.dll','eappprxy.dll','msclrjit.dll')) {
  $dp = Join-Path $S32 $d
  $r = 'ABSENT'
  if (Test-Path -LiteralPath $dp) { try { $r = [P.Ldr]::Try($dp) } catch { $r = 'threw' } }
  Write-Output ('  ' + $d.PadRight(56) + ' ' + $r)
}

Sec '4_SERVICE_KEYS_EXACT'
foreach ($s in @('wlansvc','wcmsvc','dot3svc','nativewifip','Ndisuio','RpcSs','nsi')) {
  $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $s
  if (-not (Test-Path $k)) { Write-Output ('  ' + $s + ' : NO KEY'); continue }
  $v = Get-ItemProperty $k
  $line = '  ' + $s.PadRight(12)
  $line += 'Type=' + $v.Type + ' Start=' + $v.Start + ' ErrCtl=' + $v.ErrorControl
  if ($v.Group) { $line += ' Group=' + ($v.Group -join ',') }
  if ($v.ImagePath) { $line += ' ImagePath=' + $v.ImagePath }
  if ($v.ObjectName) { $line += ' Obj=' + $v.ObjectName }
  if ($v.DependOnService) { $line += ' Deps=' + ($v.DependOnService -join ',') }
  Write-Output $line
  $pk = Join-Path $k 'Parameters'
  if (Test-Path $pk) {
    $pv = Get-ItemProperty $pk
    Write-Output ('      Parameters: ServiceDll=' + $pv.ServiceDll + ' ServiceMain=' + $pv.ServiceMain + ' UnloadOnStop=' + $pv.ServiceDllUnloadOnStop)
  }
  $sp = Join-Path $k 'Security'
  if (Test-Path $sp) { Write-Output '      has Security subkey' }
  $ti = Join-Path $k 'TriggerInfo'
  if (Test-Path $ti) { Write-Output '      has TriggerInfo subkey' }
}

Sec '5_SVCHOST_GROUPS'
$sh = 'HKLM:\SYSTEM\CurrentControlSet\Services\SVCHOST'
if (Test-Path $sh) {
  $shp = Get-Item $sh
  foreach ($n in $shp.GetValueNames()) {
    $lst = @($shp.GetValue($n)) | Where-Object { $_ }
    $flag = ''
    if ($lst -contains 'wlansvc') { $flag = '  <== wlansvc' }
    if ($lst -contains 'wcmsvc')  { $flag = $flag + '  <== wcmsvc' }
    if ($lst -contains 'dot3svc') { $flag = $flag + '  <== dot3svc' }
    Write-Output ('  ' + $n.PadRight(34) + ' n=' + $lst.Count + $flag)
    if ($flag -and $lst.Count -le 12) { Write-Output ('      ' + ($lst -join ',')) }
  }
} else { Write-Output '  NO SVCHOST KEY' }

Sec '6_NETSH_HELPER_REG'
$nk = 'HKLM:\SOFTWARE\Microsoft\Netsh'
if (Test-Path $nk) {
  $np = Get-Item $nk
  foreach ($n in $np.GetValueNames()) {
    if (-not $n) { continue }
    $dv = [string]$np.GetValue($n)
    $dp = [Environment]::ExpandEnvironmentVariables($dv)
    $exists = if ($dp) { Test-Path -LiteralPath $dp } else { $false }
    Write-Output ('  ' + $n.PadRight(16) + ' = ' + $dv + '  file=' + $(if ($exists) { 'OK' } elseif (-not $dp) { '(empty)' } else { 'MISSING' }))
  }
} else { Write-Output '  NO KEY (netsh has zero context helpers registered)' }

Sec '7_START_ATTEMPTS'
Write-Output '  -- control: dot3svc uses the same svchost shape and came with the ADK'
$cd = & net.exe start dot3svc 2>&1 | Out-String
Write-Output ('  net start dot3svc -> ' + (One $cd))
$cw = & net.exe start wlansvc 2>&1 | Out-String
Write-Output ('  net start wlansvc -> ' + (One $cw))
Start-Sleep -Seconds 2
foreach ($s in @('dot3svc','wlansvc','wcmsvc')) {
  $st = 'unknown'
  try { $q = Get-CimInstance Win32_Service -Filter "Name='$s'" -EA Stop; if ($q) { $st = $q.State + '/' + $q.StartMode + '/pid=' + $q.ProcessId } } catch { $st = 'query failed: ' + $_.Exception.Message }
  Write-Output ('  ' + $s.PadRight(9) + ' ' + $st)
}

Sec '8_RECENT_SYSTEM_EVENTS'
try {
  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-40) } -EA Stop |
          Where-Object { $_.LevelDisplayName -match 'Error|Warning' } | Select-Object -First 12)
  if (-not $ev.Count) { Write-Output '  (no error/warning entries in System log)' }
  foreach ($e in $ev) { Write-Output ('  ' + $e.TimeCreated.ToString('HH:mm:ss') + ' src=' + $e.ProviderName + ' id=' + $e.Id + ' | ' + (One $e.Message)) }
} catch { Write-Output ('  Get-WinEvent unavailable: ' + $_.Exception.Message) }

Sec '9_WIFI_DEVNODE'
foreach ($d in @(Get-CimInstance Win32_PnPEntity -Filter "PNClass='Net'" -EA SilentlyContinue)) {
  Write-Output ('  NET code=' + $d.ConfigManagerErrorCode + ' | ' + (One $d.Name) + ' | ' + $d.DeviceID)
}
foreach ($d in @(Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.DeviceID -match 'VEN_8086&DEV_7A70' })) {
  Write-Output ('  AX211 node: name=' + (One $d.Name) + ' class=' + $d.PNClass + ' code=' + $d.ConfigManagerErrorCode + ' status=' + $d.Status)
}

Sec '10_WLAN_ENUM_TRY'
try {
  $api = @'
[ System.Runtime.InteropServices.DllImport("wlanapi.dll") ]
public static extern int WlanOpenHandle(uint ver, IntPtr r, out uint outVer, out IntPtr handle);
public static string Open() {
  uint v; IntPtr h;
  int rc = WlanOpenHandle(2, IntPtr.Zero, out v, out h);
  return "WlanOpenHandle rc=0x" + rc.ToString("X8") + " outVer=" + v + " handle=" + h;
}
'@
  $wt = Add-Type -MemberDefinition $api -Name W -Namespace Q -Language CSharp -PassThru -EA Stop
  Write-Output ('  ' + [Q.W]::Open())
} catch { Write-Output ('  wlanapi call failed: ' + $_.Exception.Message) }

Sec 'DONE'
Write-Output '  probe2 complete'
