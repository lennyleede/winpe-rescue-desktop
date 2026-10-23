# probe11: probe10 invalidated probe9's "no svchost was created" reading -- the control proved
# a HEALTHY start (dot3svc) also spawns nothing, because that group's host (pid 1328) already
# exists at boot and services are injected into it. probe10 also proved the SCM service DB is
# FROZEN AT BOOT for new names (reg copy created wlansvcb/wlansvcc cleanly, both "service name
# is invalid"), so live experiments may only vary VALUES of existing services.
# Two experiments remain possible with value-only edits:
#  A) put the service in a svchost GROUP THAT HAS NO HOST PROCESS -> a new svchost MUST be
#     created; poll with Get-Process (ms-scale) instead of CIM (100ms-scale).
#  B) does the borrowed 19041 wlansvc.dll actually LoadLibrary in this 26100 image? Parse its
#     import table and load it in a CHILD process so a crash cannot eat this log.
param([switch]$LookOnly)
$ErrorActionPreference = 'Continue'

function Log([string]$m) { Write-Output $m }
function Sec([string]$n)  { Log ''; Log ('===== ' + $n + ' =====') }
function One([string]$s)  { ($s | Out-String) -replace '\s+', ' ' }
function Cmd([string]$c)  { (One (& cmd.exe /c ($c + ' 2>&1'))).Trim() }
function SvcState([string]$n) {
  $s = Get-CimInstance Win32_Service -Filter ('Name=''' + $n + '''') -ErrorAction SilentlyContinue
  if (-not $s) { return 'NOT-IN-SCM-DB' }
  return ('State=' + $s.State + ' pid=' + $s.ProcessId)
}
function SvchostPids {
  $h = @{}
  foreach ($p in @(Get-Process -Name 'svchost' -ErrorAction SilentlyContinue)) { $h[$p.Id] = 1 }
  return $h
}
function Watch-Spawn([string]$svc, [string]$group, [int]$iters) {
  # Returns: did ANY svchost appear, its pid, and whether it was still alive at the end.
  $before = SvchostPids
  $seen   = New-Object System.Collections.Generic.List[int]
  $f = 'X:\ns11_' + $svc + '.txt'
  del $f -ErrorAction SilentlyContinue
  $null = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('net start ' + $svc + ' > ' + $f + ' 2>&1') -PassThru -NoNewWindow
  for ($i = 0; $i -lt $iters; $i++) {
    foreach ($p in @(Get-Process -Name 'svchost' -ErrorAction SilentlyContinue)) {
      if (-not $before.ContainsKey($p.Id) -and -not $seen.Contains($p.Id)) { $seen.Add($p.Id) }
    }
  }
  $alive = @($seen | Where-Object { [bool](Get-Process -Id $_ -ErrorAction SilentlyContinue) })
  $txt = One (Get-Content $f -Raw -ErrorAction SilentlyContinue)
  if ($txt.Length -gt 200) { $txt = $txt.Substring(0, 200) }
  $cmds = ''
  foreach ($id in $alive) {
    $pc = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $id) -ErrorAction SilentlyContinue
    $cmds += ('[' + $id + ':' + (One $pc.CommandLine).Trim() + ']')
  }
  return [pscustomobject]@{ Svc = $svc; Spawned = $seen.Count; Pids = ($seen -join ','); Alive = ($alive -join ','); Cmds = $cmds; Net = $txt.Trim(); Iters = $iters }
}

$SVCH    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SVCHOST'
$SVC     = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$SVCHHKD = 'HKLM\SYSTEM\CurrentControlSet\Services'
$GRP     = 'LocalSystemNetworkRestricted'

Sec '0_BASELINE'
$cur = @((Get-Item -LiteralPath $SVCH).GetValue($GRP))
Log ('  group ' + $GRP + ' (' + $cur.Count + '): ' + ($cur -join ','))
Log ('  wlansvc ' + (SvcState 'wlansvc') + ' ; dot3svc ' + (SvcState 'dot3svc'))
Log ('  svchost pids now: ' + ((@(SvchostPids).Keys) -join ','))
Log ('  wlansvc ImagePath: ' + (One (Get-Item ($SVC + '\wlansvc')).GetValue('ImagePath')).Trim())

if ($LookOnly) { Sec 'LOOKONLY_STOP'; exit 0 }

Sec '1_EMPTY_GROUP_TEST_DOT3_CONTROL'
# dot3svc moved into a group that has NO running host: svchost MUST be created. This is the
# positive control for the whole technique -- if this shows Spawned=0, the method is blind.
$G1 = 'peDot3Grp'
Set-ItemProperty -LiteralPath $SVCH -Name $G1 -Value @('dot3svc') -Type MultiString
Cmd ('net stop dot3svc') | Out-Null
Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G1 + ' -p') -Type ExpandString
$r = Watch-Spawn 'dot3svc' $G1 3000
Log ('  CONTROL dot3svc in empty group: spawned=' + $r.Spawned + ' pids=' + $r.Pids + ' alive=' + $r.Alive + ' samples=' + $r.Iters)
Log ('    net: ' + $r.Net)
Log ('    cmds: ' + $r.Cmds)
Log ('    ' + (SvcState 'dot3svc'))

Sec '2_EMPTY_GROUP_TEST_WLANSVC'
$G2 = 'peWlanGrp'
Set-ItemProperty -LiteralPath $SVCH -Name $G2 -Value @('wlansvc') -Type MultiString
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G2 + ' -p') -Type ExpandString
$r = Watch-Spawn 'wlansvc' $G2 3000
Log ('  wlansvc in empty group: spawned=' + $r.Spawned + ' pids=' + $r.Pids + ' alive=' + $r.Alive + ' samples=' + $r.Iters)
Log ('    net: ' + $r.Net)
Log ('    cmds: ' + $r.Cmds)
Log ('    ' + (SvcState 'wlansvc'))
# Without -p (shared host) as a second shape.
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $G2) -Type ExpandString
$r = Watch-Spawn 'wlansvc' $G2 3000
Log ('  wlansvc shared-host shape: spawned=' + $r.Spawned + ' pids=' + $r.Pids + ' alive=' + $r.Alive)
Log ('    net: ' + $r.Net)

Sec '3_LOADLIBRARY_AND_IMPORTS'
# Write a child harness so a hard crash inside a bad DLL cannot take this log with it.
$child = @'
param([string]$Dll)
$src = @"
using System;
using System.Runtime.InteropServices;
public class LL11 {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
  public static string Load(string dll) {
    IntPtr h = LoadLibraryExW(dll, IntPtr.Zero, 0x00000100);
    int e = Marshal.GetLastWin32Error();
    if (h == IntPtr.Zero) { return "FAIL win32=" + e + " " + (new System.ComponentModel.Win32Exception(e)).Message; }
    return "OK handle=0x" + h.ToInt64().ToString("x");
  }
  public static string Main2(string dll, string fn) {
    string r = Load(dll);
    if (!r.StartsWith("OK")) return r + " (no GetProcAddress)";
    IntPtr h = LoadLibraryExW(dll, IntPtr.Zero, 0x00000100);
    IntPtr p = GetProcAddress(h, fn);
    return r + " proc " + fn + " = " + (p == IntPtr.Zero ? ("NULL win32=" + Marshal.GetLastWin32Error()) : "FOUND");
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
  static extern IntPtr GetProcAddress(IntPtr h, string n);
}
"@
Add-Type -TypeDefinition $src -ErrorAction Stop
Write-Output ('  ' + $Dll + ' => ' + [LL11]::Load($Dll))
'@
Set-Content -LiteralPath 'X:\ll11.ps1' -Value $child -Encoding ASCII

$dlls = @('wlansvc.dll', 'wlanapi.dll', 'wlanmsm.dll', 'wlansec.dll', 'wlansvcpal.dll', 'dot3svc.dll')
foreach ($d in $dlls) {
  $p = 'X:\windows\System32\' + $d
  if (-not (Test-Path $p)) { Log ('  ' + $d + ' : FILE ABSENT'); continue }
  $out = & cmd.exe /c ("X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\ll11.ps1 -Dll " + [char]34 + $p + [char]34 + " 2>&1") | Out-String
  Log ((One $out).Trim())
}

# Import table of wlansvc.dll -- which modules must resolve for svchost to load it.
function Get-Imports([string]$path) {
  $b = [IO.File]::ReadAllBytes($path)
  $pe = [int][BitConverter]::ToUInt32($b, 0x3C)
  $magic = [int][BitConverter]::ToUInt16($b, $pe + 24)
  $opt = $pe + 24
  $dirBase = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
  $impRva = [int][BitConverter]::ToUInt32($b, ($dirBase + 8))       # data dir[1] = IMPORT
  $nSec = [int][BitConverter]::ToUInt16($b, $pe + 6)
  $sizeOpt = [int][BitConverter]::ToUInt16($b, $pe + 20)
  $secStart = $pe + 24 + $sizeOpt
  $secs = @()
  for ($i = 0; $i -lt $nSec; $i++) {
    $o = $secStart + ($i * 40)
    $secs += [pscustomobject]@{
      VA = [int][BitConverter]::ToUInt32($b, $o + 12)
      VS = [int][BitConverter]::ToUInt32($b, $o + 8)
      RawO = [int][BitConverter]::ToUInt32($b, $o + 20)
      RawS = [int][BitConverter]::ToUInt32($b, $o + 16)
    }
  }
  $rva2off = { param([int]$r) foreach ($s in $secs) { if ($r -ge $s.VA -and ($r + 4) -le ($s.VA + [Math]::Max($s.VS, $s.RawS))) { return ($s.RawO + ($r - $s.VA)) } } return -1 }
  $res = New-Object System.Collections.Generic.List[string]
  $io = & $rva2off $impRva
  if ($io -lt 0) { return $res }
  for ($d = 0; $d -lt 200; $d++) {
    $e = $io + ($d * 20)
    $oft = [int][BitConverter]::ToUInt32($b, $e)
    $nameRva = [int][BitConverter]::ToUInt32($b, ($e + 12))
    $flt = [int][BitConverter]::ToUInt32($b, ($e + 16))
    if ($oft -eq 0 -and $nameRva -eq 0 -and $flt -eq 0) { break }
    $no = & $rva2off $nameRva
    if ($no -lt 0) { $res.Add('?badname-rva'); continue }
    $sb = New-Object Text.StringBuilder
    for ($j = 0; $j -lt 64; $j++) { $ch = $b[$no + $j]; if ($ch -eq 0) { break }; [void]$sb.Append([char]$ch) }
    $mod = $sb.ToString()
    # thunks -> imported function names
    $tn = 0
    $to = & $rva2off $flt
    if ($to -ge 0) {
      for ($k = 0; $k -lt 4000; $k++) {
        $tw = [int][BitConverter]::ToUInt32($b, ($to + $k * 8))
        $tl = [int][BitConverter]::ToUInt32($b, ($to + $k * 8 + 4))
        if ($tw -eq 0 -and $tl -eq 0) { break }
        $nameOff = & $rva2off ($tl -band 0x7FFFFFFF)
        if ($nameOff -lt 0) { $tn++; continue }
        if ($tl -band 0x80000000) { $tn++; continue }
        $tn++
      }
    }
    $res.Add($mod + '=' + $tn)
  }
  return $res
}
foreach ($d in @('wlansvc.dll', 'dot3svc.dll')) {
  $p = 'X:\windows\System32\' + $d
  if (-not (Test-Path $p)) { continue }
  $imps = Get-Imports $p
  Log ('  --- imports of ' + $d + ' (' + $imps.Count + ' modules)')
  $miss = @()
  foreach ($i in $imps) {
    $mn = ($i -split '=')[0]
    if ($mn -imatch '^api-ms-|^ext-ms-') { $miss += ('VIRTUAL ' + $i); continue }
    if (-not (Test-Path ('X:\windows\System32\' + $mn))) { $miss += ('NO FILE ' + $i) }
  }
  Log ('    ' + (($imps | Sort-Object) -join ' '))
  if ($miss.Count -gt 0) { Log ('    MISSING: ' + ($miss -join ' ; ')) } else { Log '    all non-api-set imports present as files' }
}

Sec '4_RESTORE_AND_FINAL'
Set-ItemProperty -LiteralPath ($SVC + '\wlansvc') -Name 'ImagePath' -Value ('%SystemRoot%\System32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString
Set-ItemProperty -LiteralPath ($SVC + '\dot3svc') -Name 'ImagePath' -Value ('%SystemRoot%\system32\svchost.exe -k ' + $GRP + ' -p') -Type ExpandString
foreach ($g in @($G1, $G2)) { Remove-ItemProperty -LiteralPath $SVCH -Name $g -ErrorAction SilentlyContinue }
$r = & cmd.exe /c ('net start dot3svc 2>&1') | Out-String
Log ('  dot3svc restarted in original group: ' + (One $r).Trim())
foreach ($n in @('wlansvc', 'dot3svc', 'wcmsvc')) { Log ('  final ' + $n + ' ' + (SvcState $n)) }
Log ('  final group list: ' + ((Get-Item -LiteralPath $SVCH).GetValue($GRP) -join ','))
Log ('  final wlansvc ImagePath: ' + (One (Get-Item ($SVC + '\wlansvc')).GetValue('ImagePath')).Trim())
Log 'PROBE11_DONE'
