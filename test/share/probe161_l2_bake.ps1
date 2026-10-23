# ============================================================
# test\share\probe161_l2_bake.ps1 -- fresh-boot proof that the WiFi file-level bakes landed AND that
# wlansvc now serves clients on a disc nobody has patched at runtime.
#
# Why this probe exists (2026-10-12):
#   probe158/159/160 killed the wlansvc 0x800C0006 self-exit by copying the seven WLAN/WFD .xsd files into
#   X:\Windows\L2Schemas of a RUNNING PE. That X: drive is a RAMDRIVE rebuilt from boot.wim at every boot,
#   so a live copy proves nothing about the disc -- it only proves the mechanism. The bake went into
#   wifi-inject step A4 (Copy-L2Schemas, sources pinned in overlay\L2Schemas by byte size), and the same
#   boot that carries it also has to carry probe99's wcmsvc fix (wcmcsp.dll). This probe reads what came
#   OUT OF THE IMAGE and then walks the client-facing stack once:
#     TAG   -- X:\BUILD_TAG.txt lines, so an old ISO can never be read as the new one
#     L2     -- the 7 schema files: present + byte-exact (truncated .xsd fails MSXML the same way)
#     CSP    -- System32\wcmcsp.dll (the 1067 fix) and wcmsvc state
#     STACK  -- wlansvc state as booted; Start() it only when it is Stopped (RAM-only, never writes the image)
#     API    -- WlanOpenHandle / WlanEnumInterfaces / WlanGetAvailableNetworkList (the functional verdict)
#     BIND   -- the boot-time netdrvfix STATUS tail (wbind/wfl/wupper/wsvc/wdihost) from X:\status.txt
#
# Instrument rules learned the hard way (see build\scratch\t_p160_wlanapi_host.ps1):
#   * WlanScan and WlanGetNetworkBssList return 87 even on a healthy host -- retired, not used here.
#   * WLAN_INTERFACE_INFO state/description offsets do not match the documented layout in this mixed
#     19041/26100 build, so only count@+0 / index@+4 / items@+8 are trusted and no description is printed.
#   * WlanGetAvailableNetworkList rc=0 with n>0 is the only accepted "the stack works" reading.
#   * PE has no sc.exe -- services are driven through Get-Service / .Start().
#   * Output must stay ASCII: it is the log, and Chinese turns into ?? in the PE console and in ssh pipes.
#
# Usage (host side, PE already booted and reachable):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\host_push_run.ps1 -Local test\share\probe161_l2_bake.ps1 -RemotePath X:\p161.ps1 -StagingB64 X:\p161.b64 -Target administrator@192.168.0.102 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
$l2Want = @('WLAN_profile_v1.xsd|18947', 'WLAN_profile_v2.xsd|2335', 'WLAN_profile_v3.xsd|984',
            'WLAN_policy_v1.xsd|7627', 'WLANAP_profile_v1.xsd|7548', 'WFD_profile_v1.xsd|7983',
            'WFD_LEGACY_profile_v1.xsd|7914')
$l2Dir = 'X:\Windows\L2Schemas'

Write-Output 'P161 begin'

# ---------- 1) which disc is this ----------
$tag = ''
if (Test-Path 'X:\BUILD_TAG.txt') {
  $tl = @(Get-Content 'X:\BUILD_TAG.txt' -EA SilentlyContinue | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
  $tag = (($tl | Where-Object { $_ -match 'wifi_patch|wlandrv|netdrvfix' }) -join ' / ')
  if (-not $tag) { $tag = (($tl | Select-Object -First 3) -join ' / ') }
}
Write-Output ('P161 TAG ' + $(if ($tag) { $tag } else { '<no BUILD_TAG.txt>' }))

# ---------- 2) L2Schemas baked? ----------
$l2Ok = 0; $l2Miss = @(); $l2Size = @()
foreach ($e in $l2Want) {
  $p = $e.Split('|'); $n = $p[0]; $want = [int]$p[1]
  $f = Join-Path $l2Dir $n
  if (Test-Path $f) {
    $len = [int](Get-Item $f).Length
    if ($len -eq $want) { $l2Ok++; $l2Size += ($n + '=' + $len) }
    else { $l2Miss += ($n + ':' + $len + '!=' + $want); $l2Size += ($n + '=' + $len + '!' + $want) }
  } else { $l2Miss += $n }
}
Write-Output ('P161 L2 dir=' + $l2Dir + ' xsd_total=' +
  (@(Get-ChildItem $l2Dir -Filter *.xsd -File -EA SilentlyContinue)).Count +
  ' baked=' + $l2Ok + '/' + $l2Want.Count +
  $(if ($l2Miss.Count) { ' missing=' + ($l2Miss -join ',') } else { ' missing=none' }))
Write-Output ('P161 L2 SIZES ' + ($l2Size -join ' '))

# ---------- 3) wcmcsp.dll (probe99's 1067 fix) ----------
$cspFile = Test-Path 'X:\Windows\System32\wcmcsp.dll'
$cspLen = 0; if ($cspFile) { $cspLen = [int](Get-Item 'X:\Windows\System32\wcmcsp.dll').Length }
Write-Output ('P161 CSP wcmcsp=' + $(if ($cspFile) { $cspLen } else { 'absent' }))

# ---------- 3b) SCM's own status record (Get-Service hides the exit code) ----------
# dwWin32ExitCode is where wlansvc's 0x800C0006 used to show up, and it is also the only way to tell
# "wcmsvc is Stopped because nobody asked" apart from "wcmsvc started and died again" (1067/0x42B = the
# wcmcsp defect). SERVICE_STATUS_PROCESS in THIS build is 36 bytes, not the documented 32: the DWORD slots
# are [0]type [1]state [2]<inserted> [3]Win32ExitCode [4]Specific [5]CheckPoint [6]WaitHint [7]ProcessId
# [8]Flags, so state=offset 4, win32=offset 12, pid=offset 28. Every SCM call lives inside one C# method
# on purpose -- calling the P/Invokes straight from PowerShell produced a bogus OpenSCManagerW err=123
# (probe99 lesson), and $needed=36 with a 32-byte buffer silently reads nothing at all.
# WDI lesson in here: this block goes through Add-Type -TypeDefinition (a complete class with its own usings),
# NOT -MemberDefinition. -MemberDefinition injects the text INSIDE a generated class body, so a `using`
# directive there is CS1529 and the whole block would silently degrade to ScmQ='unavailable'.
$scmCode = @'
using System;
using System.Runtime.InteropServices;
public class S161Scm {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr OpenSCManager(string machine, string database, uint access);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr OpenService(IntPtr manager, string name, uint access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, byte[] buffer, uint size, out uint needed);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool CloseServiceHandle(IntPtr handle);
  public static string Q(string name) {
    IntPtr m = OpenSCManager(null, null, 0x00000001);
    if (m == IntPtr.Zero) { return "scmerr=" + Marshal.GetLastWin32Error(); }
    IntPtr s = OpenService(m, name, 0x00000004);
    if (s == IntPtr.Zero) { CloseServiceHandle(m); return name + "=operr" + Marshal.GetLastWin32Error(); }
    byte[] b = new byte[64];
    uint need = 0;
    string r;
    if (QueryServiceStatusEx(s, 0, b, 36, out need)) {
      int state = BitConverter.ToInt32(b, 4);
      uint wx = BitConverter.ToUInt32(b, 12);
      int pid = BitConverter.ToInt32(b, 28);
      r = name + ":state" + state + " win32=0x" + wx.ToString("X8") + " pid=" + pid;
    } else {
      r = name + ":qerr" + Marshal.GetLastWin32Error() + " need=" + need;
    }
    CloseServiceHandle(s);
    CloseServiceHandle(m);
    return r;
  }
}
'@
$script:scmOk = $false
try { Add-Type -TypeDefinition $scmCode -EA Stop; $script:scmOk = $true }
catch { Write-Output ('P161 SCM addtype err ' + $_.Exception.Message) }
function ScmQ([string]$n) {
  if (-not $script:scmOk) { return 'unavailable' }
  try { return [S161Scm]::Q($n) } catch { return ($n + ':exc') }
}

# ---------- 4) service states as booted, then start wlansvc if it is stopped ----------
function SvcState([string]$n) { try { return "$((Get-Service $n -EA Stop).Status)" } catch { return 'err' } }
function Trivy([string]$n) {
  try {
    $s = Get-Service $n -EA Stop
    if ($s.Status -ne 'Stopped') { return 'already-' + $s.Status }
    $s.Start()
    $s.WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
    return 'started'
  } catch { return ('fail ' + $_.Exception.Message) }
}
$wBefore = SvcState 'wlansvc'; $cBefore = SvcState 'wcmsvc'
$nsBefore = SvcState 'nativewifip'; $vbBefore = SvcState 'vwifibus'; $vfBefore = SvcState 'vwififlt'
Write-Output ('P161 STACK before wlansvc=' + $wBefore + ' wcmsvc=' + $cBefore +
  ' nativewifip=' + $nsBefore + ' vwifibus=' + $vbBefore + ' vwififlt=' + $vfBefore)
$wStart = 'not-needed'; $cStart = 'not-needed'
if ($wBefore -eq 'Stopped') { $wStart = Trivy 'wlansvc' }
if ($cBefore -eq 'Stopped') { $cStart = Trivy 'wcmsvc' }
Start-Sleep -Seconds 3
$wAfter = SvcState 'wlansvc'; $cAfter = SvcState 'wcmsvc'
$poll = @(); for ($i = 0; $i -lt 3; $i++) { $poll += ('t+' + (3 + $i * 4) + '=' + (SvcState 'wlansvc')); Start-Sleep -Seconds 4 }
Write-Output ('P161 STACK start wlansvc=' + $wStart + ' wcmsvc=' + $cStart +
  ' after wlansvc=' + $wAfter + ' wcmsvc=' + $cAfter + ' poll ' + ($poll -join ' '))
# WdiServiceHost / wdisystemhost ride along: #45's 1297 was "the baked RequiredPrivileges list names a
# privilege PE's LSA does not have", and the only way to see whether the trimmed list lets SCM accept them
# is to read their state on a fresh boot (state1 = stopped-but-known, operr1060 = key never made it in).
$scmLine = ((ScmQ 'wlansvc') + ' | ' + (ScmQ 'wcmsvc') + ' | ' + (ScmQ 'nativewifip') +
            ' | ' + (ScmQ 'WdiServiceHost') + ' | ' + (ScmQ 'wdisystemhost'))
Write-Output ('P161 SCM ' + $scmLine)
$cWin32 = '-'
if ($scmLine -match 'wcmsvc:state\d+ win32=(0x[0-9A-Fa-f]+)') { $cWin32 = $matches[1] }

# ---------- 5) the functional client API ----------
$openRc = -1; $enumRc = -1; $ifN = 0; $avRc = -1; $avN = -1
try {
  $dl = '[DllImport("wlanapi.dll")] public static extern int '
  $def = (($dl + 'WlanOpenHandle(uint a,IntPtr b,out uint c,out IntPtr d);') +
         ($dl + 'WlanEnumInterfaces(IntPtr h,IntPtr r,out IntPtr l);') +
         ($dl + 'WlanGetAvailableNetworkList(IntPtr h,IntPtr g,uint f,IntPtr r,out IntPtr l);'))
  Add-Type -Namespace P161x -Name Q -MemberDefinition $def -EA Stop
  $M = [System.Runtime.InteropServices.Marshal]
  $h = [IntPtr]::Zero; $nv = [uint32]0
  $openRc = [P161x.Q]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nv, [ref]$h)
  Write-Output ('P161 API open=' + $openRc + ' ver=' + $nv + ' h=' + ($h -ne [IntPtr]::Zero))
  if ($openRc -eq 0) {
    $ip = [IntPtr]::Zero
    $enumRc = [P161x.Q]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$ip)
    if ($enumRc -eq 0 -and $ip -ne [IntPtr]::Zero) { $ifN = $M::ReadInt32($ip) }
    Write-Output ('P161 API enum=' + $enumRc + ' ifaces=' + $ifN)
    if ($ifN -gt 0) {
      $it = [IntPtr]($ip.ToInt64() + 8)
      $an = [IntPtr]::Zero
      $avRc = [P161x.Q]::WlanGetAvailableNetworkList($h, $it, 2, [IntPtr]::Zero, [ref]$an)
      if ($avRc -eq 0 -and $an -ne [IntPtr]::Zero) { $avN = $M::ReadInt32($an) }
      Write-Output ('P161 API avail=' + $avRc + ' networks=' + $avN)
    }
  }
} catch { Write-Output ('P161 API err ' + $_.Exception.Message) }

# ---------- 6) boot-time binding verdict, straight from netdrvfix ----------
$bindLine = '<no status.txt>'
if (Test-Path 'X:\status.txt') {
  $bl = @(Get-Content 'X:\status.txt' -EA SilentlyContinue | ForEach-Object { "$_" } |
          Where-Object { $_ -match 'wbind|wifi=' })
  if ($bl.Count) { $bindLine = (($bl | Select-Object -Last 1) -replace '\s+', ' ').Trim() }
}
Write-Output ('P161 BIND ' + $bindLine)

# ---------- 7) verdict ----------
$baked = ($l2Ok -eq $l2Want.Count)
$running = ($wAfter -eq 'Running')
$vd = 'WIFI-STACK-OK'
if (-not $baked) { $vd = 'L2-NOT-BAKED (old ISO or Copy-L2Schemas failed: check A4 line and rebuild disc)' }
elseif ($avN -gt 0) {
  $vd = 'WIFI-STACK-OK'
  # wcmsvc is NOT a wlansvc dependency in our bake (the host lists it, we trimmed it), so the stack can serve
  # enumeration without it. Connect/health paths still want it, so "started then died again" gets its own
  # verdict word instead of a silent OK -- with the win32 code right there so the next round has a number.
  if ($cAfter -ne 'Running') { $vd = 'WIFI-STACK-OK-WCMSVC-' + $cAfter + '-' + $cWin32 }
}
elseif ($running -and $avN -lt 0) { $vd = 'RUNNING-BUT-NO-AVAIL-READING (wlansvc up, avail rc<0: check the API lines)' }
elseif ($running) { $vd = 'RUNNING-NO-ADAPTER (bind layer or radio; read BIND/STACK lines)' }
elseif ($openRc -eq 1062) { $vd = 'WLANSVC-DIED-AGAIN (see start= and poll=; the 0x800C0006 shape)' }
else { $vd = 'WLANSVC-NOT-RUNNING' }
Write-Output ('P161 VERDICT l2=' + $l2Ok + '/' + $l2Want.Count + ' csp=' + $(if ($cspFile) { 1 } else { 0 }) +
  ' wlansvc=' + $wBefore + '->' + $wAfter + ' wcmsvc=' + $cAfter + '/' + $cWin32 +
  ' open=' + $openRc + ' ifaces=' + $ifN +
  ' avail=' + $avRc + '/' + $avN + ' verdict=' + $vd)
Write-Output 'P161 end'
