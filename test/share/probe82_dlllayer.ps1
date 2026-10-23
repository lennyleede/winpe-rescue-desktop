# ============================================================
# probe82_dlllayer.ps1 -- the last layer that can explain 1053: can svchost actually load and enter
# the service DLL inside this PE?
#
# (Numbering: 51-81 were used by the earlier WiFi driver series, so the probe line continues at 82.)
#
# What probe49/50 already excluded, with live data (build/scratch/p49_push_1010.raw, p50_push_1010.raw):
#   * account/privilege pair  -- fixed through ChangeServiceConfigW/2W, 1068 went away, 1053 stayed;
#   * svchost -k group table   -- GRP wcmsvcs = wcmsvc / GRP wlansvcs = wlansvc, all four CHK=OK;
#   * SCM stuck in StartPending -- QSS state=1 STOPPED, checkpoint=0, waithint=2000;
#   * manual launch bypass     -- svchost -k/-s exits 0 even for the healthy CTRL=Dhcp, so it proves
#     nothing about the DLL.
# 1053 means: the SCM handed the child to svchost, and no SERVICE_RUNNING ever arrived. svchost can fail
# silently at exactly three points, and PE has no System event log to tell us which:
#   (1) the service key's Parameters\ServiceDll is absent or names a file that is not there;
#   (2) the DLL's STATIC imports cannot be resolved -- WinPE carries a subset of System32 and NO component
#       store, so a DLL like WLANMSM.DLL / OneX.DLL / MobileNetworking.dll may simply not exist, or an
#       ext-ms-* apiset may have no host DLL to land on;
#   (3) Parameters\ServiceMain does not name an export the DLL really has (svchost GetProcAddress fails).
# All three are answerable from the file bytes plus one LoadLibrary per import, which is what this probe
# does. dot3svc and Dhcp are the differential controls: their DLLs are the same kind of svchost-hosted
# network service, and whatever they import MUST be resolvable in this image.
#
# Host authority for the shapes we compare against (build/scratch/t_host_svcparams.ps1 + peimports.ps1):
#   wlansvc  ServiceDll=%SystemRoot%\System32\wlansvc.dll  ServiceMain=WlanSvcMain  (exports=7)
#   wcmsvc   ...wcmsvc.dll                                 ServiceMain=WcmSvcMain    (exports=5)
#   dot3svc  ...dot3svc.dll                                ServiceMain=Dot3SvcMain   (exports=4)
#   Dhcp     ...dhcpcore.dll                               (no ServiceMain -> default ServiceMain)
#   wlansvc.dll static imports that are real files: WLANMSM.DLL DNSAPI.dll dhcpcsvc6.DLL OneX.DLL
#       msvcp_win.dll RPCRT4.dll WS2_32.dll ntdll.dll;  delay: AUTHZ bcrypt CRYPT32 CRYPTSP
#       deviceassociation DEVOBJ dhcpcsvc DSROLE eappcfg EventAggregation IPHLPAPI IpNatHlpClient
#       NetSetupApi OLEAUT32 profapi SYSNTFY WMICLNT
#   wcmsvc.dll static real files: MobileNetworking.dll nlaapi.dll NSI.dll UMPDC.dll USERENV.dll
#       WINHTTP.dll WINNSI.DLL IPHLPAPI msvcp_win.dll RPCRT4.dll WS2_32.dll
#   dot3svc.dll static real files: dot3msm.dll msvcrt.dll RPCRT4.dll WINNSI.DLL WMICLNT.dll  <- control
#
# Writes: NONE (registry reads, file reads, LoadLibrary inside this process only -- FreeLibrary after).
# LoadLibrary of wlansvc.dll/wcmsvc.dll happens LAST, after every other line is already emitted, so a
# surprise in a DllMain cannot cost us the data.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe82_dlllayer.ps1 -RemotePath X:/p82.ps1 -StagingB64 X:/p82.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
#
# FIELD RESULT 2026-10-10 (build/scratch/p82_push_1010.txt) -- the DLL layer is CLEAN:
#   * the baked contract is present and correct in the image:
#       wlansvc\Parameters: ServiceDll=%SystemRoot%\System32\wlansvc.dll, ServiceMain=WlanSvcMain  -> EXPORTED
#       wcmsvc\Parameters : ...wcmsvc.dll, WcmSvcMain                                             -> EXPORTED
#     (dot3svc/Dhcp match too, and both of those services are Running in this PE)
#   * every STATIC import resolves: 20 real files + 73 api-ms-* names all LoadLibrary OK, in particular
#     WLANMSM.DLL, OneX.DLL, DNSAPI.dll, dhcpcsvc6.DLL, msvcp_win.dll, MobileNetworking.dll, nlaapi.dll,
#     NSI.dll, UMPDC.dll, WINHTTP.dll, WINNSI.DLL, USERENV.dll, IPHLPAPI -- nothing to bake for them;
#   * LoadLibrary("X:\Windows\System32\wlansvc.dll") itself SUCCEEDS and GetProcAddress('WlanSvcMain')
#     resolves, same for wcmsvc.dll/WcmSvcMain. svchost can load and enter both service DLLs.
#   * the only gaps are DELAY loads (they cannot stop the DLL from loading, they explode at the call):
#       wlansvc.dll: deviceassociation.dll IpNatHlpClient.dll ext-ms-win-devmgmt-policy
#                    ext-ms-win-networking-wlanstorage ext-ms-win-shell-embeddedmode ext-ms-win-wlan-grouppolicy
#       wcmsvc.dll : ext-ms-win-net-cmvpn ext-ms-win-networking-nlaapi
#     On the host those ext-ms names are backed by policymanager.dll / embeddedmodesvcapi.dll / wlgpclnt.dll /
#     cmintegrator.dll / nlaapi.dll (build/scratch/t_apiset_host.ps1); ext-ms-win-networking-wlanstorage does
#     not even resolve on this 19041 host, so it is a Win11-only mapping.
#   => 1053 is NOT a key-shape and NOT a static-import problem. Either ServiceMain returns without ever
#      reporting RUNNING, or the service host dies on one of those delay loads. probe83 separates the two.
#   NOTE: the VERDICT line came out blank because PowerShell names are case-INSENSITIVE: the parse loop's
#   $p overwrote the $P accumulator. Renamed to $VERD, and the per-service detail lines (which are the real
#   data) were unaffected.
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }

$S32 = 'X:\Windows\System32'
$REG = 'HKLM\SYSTEM\CurrentControlSet\Services'
# NOTE ON NAMING: PowerShell variables are case-INSENSITIVE, so a loop variable called $p silently
# overwrites an accumulator called $P -- that is exactly what blanked the P82 VERDICT line in the field
# run (build/scratch/p82_push_1010.txt). The accumulator therefore has a name nothing else can collide with.
$VERD = @{ tag = 'notag'; keys = @(); exps = @(); imp = @(); loads = @(); ctrl = ''; miss = @(); noentry = @() }

function RegGet([string]$key, [string]$name) {
  $o = @(& reg.exe query "$key" /v "$name" 2>&1 | ForEach-Object { "$_" })
  foreach ($l in $o) {
    if ($l -match ('^\s*' + [regex]::Escape($name) + '\s+REG_(SZ|EXPAND_SZ|DWORD|MULTI_SZ|NONE)\s+(.*)$')) {
      return (($matches[2] -replace '\s+', ' ').Trim() -replace '\\0', ';')
    }
  }
  return ''
}
function St([string]$n) { try { "$((Get-Service -Name $n -EA Stop).Status)" } catch { 'ABSENT' } }
function FileSig([string]$p) {
  try { $i = Get-Item $p -EA Stop; return ('' + [int]($i.Length / 1024) + 'KB ' + $i.LastWriteTime.ToString('yyyy-MM-dd')) }
  catch { return 'ABSENT' }
}
function ErrName([int]$e) {
  $m = @{ 5 = 'ACCESS_DENIED'; 8 = 'NOT_ENOUGH_MEMORY'; 87 = 'INVALID_PARAMETER'; 126 = 'MOD_NOT_FOUND';
          127 = 'PROC_NOT_FOUND'; 193 = 'NOT_A_WIN32_APP'; 577 = 'INVALID_SIGNATURE';
          1260 = 'DISABLED_BY_POLICY'; 1402 = 'INVALID_HANDLE' }
  if ($m.ContainsKey($e)) { return ('' + $e + '_' + $m[$e]) }
  return '' + $e
}
# %SystemRoot% inside the PE points at the ramdisk; expand both ways so a stray W:/C: cannot fool us.
function Expand2([string]$s) {
  $a = ''
  try { $a = [Environment]::ExpandEnvironmentVariables($s) } catch { $a = $s }
  $a = ($a -replace '(?i)^%SystemRoot%', $S32.Substring(0, $S32.Length - 9))
  return $a
}

# ---------- PE reader: imports + delay imports + exports from file bytes (proved on the host, same
# offsets as test/share/peimports.ps1; SizeOfRawData@16 and PointerToRawData@20 must not be swapped) ----
function Get-PeInfo([string]$Path) {
  $b = [System.IO.File]::ReadAllBytes($Path)
  if ($b.Length -lt 0x200) { throw 'file too small' }
  $lf = [System.BitConverter]::ToInt32($b, 0x3C)
  if ([System.BitConverter]::ToUInt32($b, $lf) -ne 0x00004550) { throw ('bad PE signature at 0x' + $lf.ToString('X')) }
  $coff = $lf + 4
  $nsec = [System.BitConverter]::ToUInt16($b, $coff + 2)
  $sizeOpt = [System.BitConverter]::ToUInt16($b, $coff + 16)
  $opt = $coff + 20
  $is32 = ([System.BitConverter]::ToUInt16($b, $opt) -eq 0x10b)
  $numRva = if ($is32) { 96 } else { 112 }
  $dd = $opt + $numRva
  $sections = @()
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $opt + $sizeOpt + $i * 40
    $sections += [pscustomobject]@{
      va    = [System.BitConverter]::ToUInt32($b, $o + 12)
      vsz   = [System.BitConverter]::ToUInt32($b, $o + 8)
      rawsz = [System.BitConverter]::ToUInt32($b, $o + 16)
      raw   = [System.BitConverter]::ToUInt32($b, $o + 20)
    }
  }
  function RvaToOff([uint32]$rva) {
    foreach ($s in $sections) {
      if ($rva -ge $s.va -and $rva -lt ($s.va + [Math]::Max($s.vsz, $s.rawsz))) {
        $o = [int]($s.raw + ($rva - $s.va))
        if ($o -ge 0 -and ($o + 4) -le $b.Length) { return $o }
        return -1
      }
    }
    return -1
  }
  function ZStr([int]$o) {
    if ($o -lt 0 -or $o -ge $b.Length) { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($k = 0; $k -lt 300; $k++) {
      $c = $b[$o + $k]
      if ($c -eq 0) { break }
      [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
  }
  $names = @(); $delay = @(); $exports = @()
  $impRva = [System.BitConverter]::ToUInt32($b, $dd + 8)
  $impSize = [System.BitConverter]::ToUInt32($b, $dd + 12)
  if ($impRva -ne 0 -and $impSize -ne 0) {
    $p = RvaToOff $impRva
    for ($n = 0; $n -lt 400; $n++) {
      $o = $p + $n * 20
      if (($o + 20) -gt $b.Length) { break }
      $orig = [System.BitConverter]::ToUInt32($b, $o + 0)
      $nameRva = [System.BitConverter]::ToUInt32($b, $o + 12)
      $first = [System.BitConverter]::ToUInt32($b, $o + 16)
      if ($orig -eq 0 -and $nameRva -eq 0 -and $first -eq 0) { break }
      $s = ZStr (RvaToOff $nameRva)
      if ($s) { $names += $s } else { $names += ('BAD_RVA_0x' + $nameRva.ToString('X')) }
    }
  }
  $delRva = [System.BitConverter]::ToUInt32($b, $dd + 13 * 8)
  $delSize = [System.BitConverter]::ToUInt32($b, $dd + 13 * 8 + 4)
  if ($delRva -ne 0 -and $delSize -ne 0) {
    $dp = RvaToOff $delRva
    for ($n = 0; $n -lt 200; $n++) {
      $o = $dp + $n * 32
      if (($o + 8) -gt $b.Length) { break }
      $dName = [System.BitConverter]::ToUInt32($b, $o + 4)   # ImgDelayDescr v2: attrs, then Name RVA
      if ($dName -eq 0) { break }
      $s = ZStr (RvaToOff $dName)
      if ($s) { $delay += $s }
    }
  }
  $expRva = [System.BitConverter]::ToUInt32($b, $dd + 0)
  $expSize = [System.BitConverter]::ToUInt32($b, $dd + 4)
  if ($expRva -ne 0 -and $expSize -ne 0) {
    $eo = RvaToOff $expRva
    $nNames = [System.BitConverter]::ToUInt32($b, $eo + 24)
    $pNet = RvaToOff ([System.BitConverter]::ToUInt32($b, $eo + 32))
    if ($eo -ge 0 -and $pNet -ge 0 -and $nNames -gt 0 -and $nNames -lt 20000) {
      for ($i = 0; $i -lt $nNames; $i++) {
        $s = ZStr (RvaToOff ([System.BitConverter]::ToUInt32($b, $pNet + $i * 4)))
        if ($s) { $exports += $s }
      }
    }
  }
  return @{ names = (@($names) | Sort-Object -Unique); delay = (@($delay) | Sort-Object -Unique);
            exports = $exports; is32 = $is32 }
}

# ---------- loader helpers ----------
if (-not ('P82.L' -as [type])) {
  Add-Type -Namespace P82 -Name L -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, int flags);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr h, string name);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeLibrary(IntPtr h);
public static int LastErr = 0;
public static IntPtr Last = IntPtr.Zero;
// Returns "OK=0x<handle>" or "NULL=<err>". flags 0 = normal search path (System32 is in it because this
// process runs from System32); 0x8 = LOAD_WITH_ALTERED_SEARCH_PATH for fully qualified paths.
// The handle lives in the static Last field: PowerShell must NOT try to turn the hex text back into an
// IntPtr -- [System.IntPtr]::Parse only has a (string) overload, so "Parse(hex, 'HexNumber')" throws and
// kills the probe (caught by build/scratch/t_p82_dryrun.ps1).
public static string Load(string path, int flags) {
  Last = LoadLibraryExW(path, IntPtr.Zero, flags);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (Last == IntPtr.Zero) { return "NULL=" + LastErr; }
  return "OK=0x" + Last.ToInt64().ToString("X");
}
public static string Entry(string name) {
  if (Last == IntPtr.Zero) { return "NOHANDLE"; }
  IntPtr p = GetProcAddress(Last, name);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (p == IntPtr.Zero) { return "NULL=" + LastErr; }
  return "OK=0x" + p.ToInt64().ToString("X");
}
public static bool Drop() {
  if (Last == IntPtr.Zero) { return false; }
  bool r = FreeLibrary(Last);
  LastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
  if (r) { Last = IntPtr.Zero; }
  return r;
}
'@ -EA Stop
}
# Load a bare import name the way the loader would: full path when System32 has the file, else by name
# (apiset/ext-ms names have no file to point at, so they must go through the search path / schema).
function LoadImp([string]$nm) {
  $full = Join-Path $S32 $nm
  if (Test-Path $full) {
    $r = [P82.L]::Load($full, 0x8)
    $e = 0; if ($r -match 'NULL=(\d+)') { $e = [int] $matches[1] }
    [void][P82.L]::Drop()          # do not accumulate a hundred loaded modules in the probe process
    return ($r + '/' + (ErrName $e))
  }
  $r = [P82.L]::Load($nm, 0)
  $e = 0; if ($r -match 'NULL=(\d+)') { $e = [int] $matches[1] }
  [void][P82.L]::Drop()
  return ($r + '/' + (ErrName $e))
}

O '== 0 the image, the DLLs and the control services =='
if (Test-Path 'X:\BUILD_TAG.txt') {
  $tl = @(Get-Content 'X:\BUILD_TAG.txt' -EA SilentlyContinue)
  $VERD.tag = (($tl | Select-Object -First 1) -replace '[^\x20-\x7E]', '?')
  foreach ($l in ($tl | Select-Object -First 4)) { O ('  TAG | ' + (ToAscii $l)) }
} else { O '  TAG | X:\BUILD_TAG.txt ABSENT' }
foreach ($f in @('svchost.exe', 'wlansvc.dll', 'wcmsvc.dll', 'dot3svc.dll', 'dhcpcore.dll', 'wlanapi.dll',
                 'WLANMSM.DLL', 'OneX.DLL', 'DNSAPI.dll', 'dhcpcsvc6.DLL', 'msvcp_win.dll',
                 'MobileNetworking.dll', 'nlaapi.dll', 'UMPDC.dll', 'WINHTTP.dll', 'WINNSI.DLL', 'NSI.dll',
                 'USERENV.dll', 'dot3msm.dll', 'WMICLNT.dll', 'eappcfg.dll', 'SYSNTFY.dll', 'DEVOBJ.dll',
                 'deviceassociation.dll', 'IpNatHlpClient.dll', 'NetSetupApi.dll', 'EventAggregation.dll',
                 'DSROLE.dll', 'AUTHZ.dll', 'CRYPTSP.dll', 'dhcpcsvc.dll', 'profapi.dll', 'OLEAUT32.dll')) {
  O ('  FILE ' + $f + ' = ' + (FileSig (Join-Path $S32 $f)))
}
# The controls: services of the same kind that DO run in this PE prove their own imports resolve.
foreach ($n in @('dot3svc', 'Dhcp', 'fdPHost', 'netprofm', 'NlaSvc', 'Dnscache', 'wlansvc', 'wcmsvc')) {
  O ('  STATE ' + $n + ' = ' + (St $n))
}
$VERD.ctrl = 'dot3svc=' + (St 'dot3svc') + ',Dhcp=' + (St 'Dhcp')

O '== 1 the svchost contract in the registry (ServiceDll / ServiceMain) =='
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $sdRaw = RegGet "$REG\$n\Parameters" 'ServiceDll'
  $sm = RegGet "$REG\$n\Parameters" 'ServiceMain'
  $sdExp = Expand2 $sdRaw
  $exists = if ($sdExp) { "$(Test-Path $sdExp)" } else { 'no-value' }
  $unload = RegGet "$REG\$n\Parameters" 'ServiceDllUnloadOnStop'
  O ('  KEY ' + $n + ' sdRaw=[' + (ToAscii $sdRaw) + '] sdExp=[' + (ToAscii $sdExp) + '] exists=' + $exists +
     ' ServiceMain=[' + $sm + '] unloadOnStop=[' + $unload + ']' +
     ' obj=[' + (ToAscii (RegGet "$REG\$n" 'ObjectName')) + '] img=[' + (ToAscii (RegGet "$REG\$n" 'ImagePath')) + ']')
  if (-not $sdRaw) { $VERD.noentry += "$n-noservicedll" }
  $VERD.keys += "$n sd=$exists sm=$(if ($sm) { $sm } else { 'default ServiceMain' })"
}

O '== 2 parse the DLLs the image really has: entry point + import count =='
$targets = @()
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $sd = Expand2 (RegGet "$REG\$n\Parameters" 'ServiceDll')
  if (-not $sd) { continue }
  $leaf = Split-Path $sd -Leaf
  if ($targets -notcontains $leaf) { $targets += $leaf }
}
$script:info = @{}
foreach ($leaf in $targets) {
  $dllPath = Join-Path $S32 $leaf
  if (-not (Test-Path $dllPath)) { O ('  DLL ' + $leaf + ' ABSENT -- nothing to parse'); $VERD.noentry += "$leaf-missing"; continue }
  try {
    $r = Get-PeInfo $dllPath
    $script:info[$leaf.ToLower()] = $r
    O ('  DLL ' + $leaf + ' arch=' + $(if ($r.is32) { 'x86' } else { 'x64' }) +
       ' static=' + @($r.names).Count + ' delay=' + @($r.delay).Count + ' exports=' + @($r.exports).Count)
    O ('    STATIC ' + ((@($r.names) | Sort-Object -Unique) -join ' '))
    if (@($r.delay).Count) { O ('    DELAY  ' + ((@($r.delay) | Sort-Object -Unique) -join ' ')) }
    $mains = @(@($r.exports) | Where-Object { "$_" -match '(?i)main$' } | Sort-Object -Unique)
    O ('    MAINEXPORTS ' + ($mains -join ','))
  } catch { O ('  DLL ' + $leaf + ' PARSE FAIL: ' + (ToAscii $_.Exception.Message)) }
}
# (3) is the entry point the key names actually exported?
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $sd = Expand2 (RegGet "$REG\$n\Parameters" 'ServiceDll')
  if (-not $sd) { continue }
  $leaf = (Split-Path $sd -Leaf).ToLower()
  $want = RegGet "$REG\$n\Parameters" 'ServiceMain'
  if (-not $want) { $want = 'ServiceMain' }
  if (-not $script:info.ContainsKey($leaf)) { O ('  ENTRY ' + $n + ' cannot check (no parsed ' + $leaf + ')'); continue }
  $ex = @($script:info[$leaf].exports)
  $hit = if ($ex -contains $want) { 'EXPORTED' } else { '*** NOT EXPORTED ***' }
  O ('  ENTRY ' + $n + ' wants [' + $want + '] in ' + $leaf + ' -> ' + $hit + ' (exports=' + $ex.Count + ')')
  $VERD.exps += "$n/$leaf=$hit"
  if ($hit -ne 'EXPORTED') { $VERD.noentry += "$n-$want" }
}

O '== 3 resolve every STATIC import: file present? loadable? (delay imports are only reported when bad) =='
$use = @{}
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $sd = Expand2 (RegGet "$REG\$n\Parameters" 'ServiceDll')
  if (-not $sd) { continue }
  $leaf = (Split-Path $sd -Leaf).ToLower()
  if (-not $script:info.ContainsKey($leaf)) { continue }
  foreach ($nm in @($script:info[$leaf].names)) {
    $k = "$nm".ToLower()
    if (-not $use.ContainsKey($k)) { $use[$k] = @() }
    if ($use[$k] -notcontains $leaf) { $use[$k] += $leaf }
  }
}
$failStatic = @{}
foreach ($k in (@($use.Keys) | Sort-Object)) {
  $nm = $k
  $isApi = ($nm -match '^(api-ms-|ext-ms-)')
  $present = if ($nm -match '^ext-ms-') { 'schema' } else { "$(Test-Path (Join-Path $S32 $nm))" }
  $ld = LoadImp $nm
  $bad = ($ld -match 'NULL=')
  $line = ('  IMP ' + $nm + ' present=' + $present + ' load=' + $ld + ' by=' + (($use[$k] | Sort-Object) -join '+'))
  if ($isApi -and -not $bad) { continue }                     # 51 apiset lines that pass say nothing
  if ($isApi) { O ('  APIS ' + $nm + ' load=' + $ld + ' by=' + (($use[$k] | Sort-Object) -join '+')) }
  else { O $line }
  if ($bad) {
    foreach ($l in $use[$k]) {
      if (-not $failStatic.ContainsKey($l)) { $failStatic[$l] = @() }
      $failStatic[$l] += ($nm + '(' + ($ld -replace 'NULL=', '') + ')')
    }
    $VERD.miss += ($nm + '(' + ($ld -replace 'NULL=', '') + ')' + '<' + (($use[$k] | Sort-Object) -join '+') + '>')
  }
}
$apiCount = @(@($use.Keys) | Where-Object { $_ -match '^(api-ms-|ext-ms-)' }).Count
$fileCount = (@($use.Keys).Count - $apiCount)
O ('  SUMMARY static names=' + @($use.Keys).Count + ' (apiset=' + $apiCount + ' files=' + $fileCount + ')')
# delay: not fatal at load time, but a missing one breaks the feature at runtime -- report failures only
foreach ($leaf in @($script:info.Keys)) {
  $dl = @($script:info[$leaf].delay)
  $badD = @()
  foreach ($nm in $dl) {
    $ld = LoadImp $nm
    if ($ld -match 'NULL=') { $badD += ($nm + '(' + ($ld -replace 'NULL=', '') + ')') }
  }
  O ('  DELAYFAIL ' + $leaf + ' total=' + $dl.Count + ' bad=' + $badD.Count + ' [' + ($badD -join ' ') + ']')
}

O '== 4 the decisive call: load the service DLL ourselves and ask for its entry point =='
# Last, so even a hostile DllMain cannot cost us the data above.
foreach ($n in @('wlansvc', 'wcmsvc', 'dot3svc', 'Dhcp')) {
  $sd = Expand2 (RegGet "$REG\$n\Parameters" 'ServiceDll')
  if (-not $sd) { O ('  LOAD ' + $n + ' no ServiceDll value'); continue }
  if (-not (Test-Path $sd)) { O ('  LOAD ' + $n + ' file not on disk: [' + (ToAscii $sd) + ']'); $VERD.loads += "$n=FILEABSENT"; continue }
  $want = RegGet "$REG\$n\Parameters" 'ServiceMain'
  if (-not $want) { $want = 'ServiceMain' }
  $r = [P82.L]::Load($sd, 0x8)
  $e = 0; if ($r -match 'NULL=(\d+)') { $e = [int] $matches[1] }
  $ent = 'skipped'
  if ($r -match '^OK=') { $ent = [P82.L]::Entry($want) }
  O ('  LOAD ' + $n + ' ' + $r + '/' + (ErrName $e) + ' entry[' + $want + ']=' + $ent + ' state=' + (St $n))
  $VERD.loads += "$n=" + $(if ($r -match '^OK=') { if ($ent -match '^OK=') { 'LOADED+ENTRY' } else { 'LOADED+ENTRY_FAIL:' + $ent } } else { 'LOAD_FAIL:' + (ErrName $e) })
  if ($r -match '^OK=') { [void][P82.L]::Drop() }
}

O '== 5 VERDICT =='
O ('P82 VERDICT tag=' + $VERD.tag + ' ctrl=' + $VERD.ctrl + ' keys=' + ($VERD.keys -join ';') +
   ' entry=' + ($VERD.exps -join ',') + ' loads=' + ($VERD.loads -join ',') +
   ' staticBad=' + (@($VERD.miss).Count) + ' noentry=' + (@($VERD.noentry).Count) + ':' + ($VERD.noentry -join ','))
if (@($VERD.miss).Count) {
  O ('P82 MISSING-IMPORTS ' + (@($VERD.miss) -join ' '))
  O 'P82 READING: a static import cannot be resolved in this image -> svchost fails LoadLibrary before ServiceMain can run and the SCM can only time out (1053). Every name above is a file to bake into System32 (with the .cat that covers it), or a service whose key must stop importing it.'
}
elseif (@($VERD.noentry).Count) {
  O 'P82 READING: imports all resolve but the ServiceDll/ServiceMain contract is broken (no Parameters key, file absent, or the entry point is not exported) -> fix the baked key, nothing else.'
}
elseif ($VERD.loads -match 'LOAD_FAIL') {
  O 'P82 READING: every named import loads on its own yet the DLL itself will not load -> the failure is one level deeper (a dependency of a dependency, or a signature/policy reject). Next probe: walk the failing DLL own imports only.'
}
elseif ($VERD.loads -match 'ENTRY_FAIL') {
  O 'P82 READING: the DLL loads but GetProcAddress of the configured ServiceMain fails -> the baked ServiceMain string is wrong for this DLL version.'
}
else {
  O ('P82 READING: nothing in the DLL layer can explain 1053 (all ' + @($use.Keys).Count + ' static imports load, both entry points resolve). The suspect is back on the SCM/svchost handshake: this ramdisk hive is still the probe47/48-mutated one, so reboot and re-run against the baked key shape before touching anything else.')
}
O 'P82 END'
