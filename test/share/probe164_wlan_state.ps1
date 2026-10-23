# ============================================================
# test\share\probe164_wlan_state.ps1 -- what is the ONE wlan interface actually doing right now?
#
#   Why: probe161 on the 2026-10-12 14:25 disc proved the control plane is up
#     (WlanOpenHandle rc=0, ifaces=1, WlanGetAvailableNetworkList rc=0, 5-6 networks visible).
#     Still unknown on-site: the interface's OPERATIONAL state (not_ready / connected / disconnected /
#     associating ...) and whether the disc has any saved profile at all. That decides how the NEXT disc
#     is accepted: "can scan" (what we have) vs "can associate" (what a rescue operator needs).
#
#   Read-only. Nothing here connects, scans on demand, or writes to the image.
#
#   OPCODE-NUMBERING LESSON (measured on the build host's Intel Wireless-AC 9260, cross-checked with
#   netsh; harness = build\scratch\t_wlan_opcode_host.ps1). WLAN_INTF_OPCODE starts at
#   autoconf_start=0 and then autoconf_enabled=1, so the real numbering is:
#     1=autoconf_enabled  2=background_scan_enabled  3=media_streaming_mode  4=radio_state (772 bytes)
#     5=bss_type  6=interface_state  7=current_connection (rc=5023 while disconnected)  8=channel_number
#   The first draft asked opcode 3 (the number from memory) and the host answered 0, which the old state
#   table read as "not_ready" -- while `netsh wlan show interfaces` on that same machine said
#   "disconnected, radio on". Opcode 6 gives 4, and 4 = disconnected in the correct table:
#     0=not_ready 1=connected 2=ad_hoc_network_formed 3=disconnecting 4=disconnected
#     5=associating 6=discovering 7=authenticating 8=invalid
#   So: query opcode 6, translate with the table above. Never trust a remembered enum value.
#
#   MEMORY-LAYOUT LESSON (same host, harness = build\scratch\t_wlan_layout_host.ps1):
#   WlanEnumInterfaces has only 3 parameters (handle / reserved / out list pointer); the interface count
#   is the DWORD at offset 0 of the block it returns, the GUID starts at offset 8, and the Description
#   follows IMMEDIATELY (offset 24) -- the "state DWORD between GUID and Description" from the docs is
#   not there in this implementation (bytes 20..23 are the GUID tail). The profile list behaves the same
#   way: count at 0, a DWORD that is always 0 at 4, the first name right at offset 8.
#   Therefore: state comes from WlanQueryInterface, and descriptions/profile names come from scanning
#   for printable UTF-16 runs -- no hardcoded struct offsets.
#
#   Run in PE:  X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File X:\p164.ps1
#   Dry-run on the build host works too (it has a real adapter) -- that is the positive control.
#   ASCII only: PE's console codepage mangles anything else and the log has to survive a pull.
# ============================================================
$ErrorActionPreference = 'Continue'

$md = @'
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanOpenHandle(int clientVersion, IntPtr reserved, out int negotiated, out IntPtr handle);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanCloseHandle(IntPtr handle, IntPtr reserved);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr interfaceInfoList);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanQueryInterface(IntPtr handle, ref System.Guid guid, int opcode, IntPtr reserved,
                                            out int dataSize, out IntPtr data, out int valueType);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanGetProfileList(IntPtr handle, ref System.Guid guid, IntPtr reserved, out IntPtr profileInfoList);
[System.Runtime.InteropServices.DllImport("wlanapi.dll", SetLastError=true)]
public static extern int WlanFreeMemory(IntPtr pointer);
'@
try { Add-Type -MemberDefinition $md -Name 'W164' -Namespace 'P164' -ErrorAction Stop }
catch { Write-Output ('P164 ERR addtype ' + ($_.Exception.Message -replace '\s+', ' ')); exit 1 }
$M = [Runtime.InteropServices.Marshal]
$Q = [P164.W164]

# WLAN_INTERFACE_STATE names, verified against netsh on the host (see header)
$stateName = @{
  0 = 'not_ready'; 1 = 'connected'; 2 = 'ad_hoc_network_formed'; 3 = 'disconnecting'
  4 = 'disconnected'; 5 = 'associating'; 6 = 'discovering'; 7 = 'authenticating'; 8 = 'invalid'
}

# Longest printable UTF-16LE run (>=4 chars) inside a memory block -- used instead of guessing offsets.
function Get-PrintableRun([IntPtr]$p, [int]$maxChars) {
  $sb = New-Object System.Text.StringBuilder
  $best = ''
  $run = 0
  for ($i = 0; $i -lt $maxChars; $i++) {
    $c = $M::ReadInt16([IntPtr]($p.ToInt64() + ($i * 2)))
    if ($c -ge 32 -and $c -lt 127) { [void]$sb.Append([char]$c); $run++ }
    else {
      if ($run -ge 4 -and $sb.Length -gt $best.Length) { $best = $sb.ToString() }
      [void]$sb.Clear(); $run = 0
      if ($c -eq 0 -and $i -gt 40) { break }
    }
  }
  if ($run -ge 4 -and $sb.Length -gt $best.Length) { $best = $sb.ToString() }
  return $best
}

# Same idea but keep the FIRST $want runs (one per profile name) instead of the longest.
function Get-Runs([IntPtr]$p, [int]$maxChars, [int]$want) {
  $out = @()
  $sb = New-Object System.Text.StringBuilder
  $run = 0
  for ($i = 0; $i -lt $maxChars; $i++) {
    $c = $M::ReadInt16([IntPtr]($p.ToInt64() + ($i * 2)))
    if ($c -ge 32 -and $c -lt 127) { [void]$sb.Append([char]$c); $run++ }
    else {
      if ($sb.Length -ge 1) { $out += $sb.ToString() }
      [void]$sb.Clear(); $run = 0
      if (@($out).Count -ge $want) { break }
    }
  }
  return , @($out | Where-Object { $_ -and ("$_").Length -ge 1 })
}

$nego = 0; $h = [IntPtr]::Zero
$rc = $Q::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$nego, [ref]$h)
Write-Output ('P164 OPEN rc=' + $rc + ' ver=' + $nego)
if ($rc -ne 0) { exit 1 }
try {
  $arr = [IntPtr]::Zero
  $rc2 = $Q::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$arr)
  $cnt = -1
  if ($arr -ne [IntPtr]::Zero) { $cnt = $M::ReadInt32($arr) }
  Write-Output ('P164 ENUM rc=' + $rc2 + ' count=' + $cnt)
  if ($rc2 -eq 0 -and $arr -ne [IntPtr]::Zero -and $cnt -gt 0) {
    # entries start at block+8 (offset 0 = count, offset 4 = a DWORD this build leaves 0); GUID is first
    $entryBase = $arr.ToInt64() + 8
    $guidBytes = New-Object byte[] 16
    for ($j = 0; $j -lt 16; $j++) { $guidBytes[$j] = $M::ReadByte([IntPtr]($entryBase + $j)) }
    $guid = New-Object Guid (, $guidBytes)
    $descP = [IntPtr]($entryBase + 16)
    $desc = Get-PrintableRun $descP 600
    $dsz = 0; $dp = [IntPtr]::Zero; $vt = 0
    $gref = $guid
    $rc4 = $Q::WlanQueryInterface($h, [ref]$gref, 6, [IntPtr]::Zero, [ref]$dsz, [ref]$dp, [ref]$vt)
    $st = -1
    if ($rc4 -eq 0 -and $dp -ne [IntPtr]::Zero) { $st = $M::ReadInt32($dp) }
    $stTxt = $stateName[[int]$st]
    if (-not $stTxt) { $stTxt = 'unknown' }
    Write-Output ('P164 IF state=' + $st + '(' + $stTxt + ') qrc=' + $rc4 + ' qsize=' + $dsz +
                 ' guid=' + $guid.ToString() + ' desc=' + $desc)
    if ($dp -ne [IntPtr]::Zero) { $Q::WlanFreeMemory($dp) | Out-Null }

    # opcode 4 = radio_state (WLAN_RADIO_STATE, measured 772 bytes = count + 96 PHY slots). The field
    # spacing inside a slot has no on-site ground truth (netsh only prints a conclusion), so the first 5
    # DWORDs are dumped RAW: the host with "hardware on / software on" gives ints=5,0,1,1,1 and the disc
    # is compared against that reading instead of a guessed decode.
    $dszR = 0; $dpR = [IntPtr]::Zero; $vtR = 0
    $rcR = $Q::WlanQueryInterface($h, [ref]$gref, 4, [IntPtr]::Zero, [ref]$dszR, [ref]$dpR, [ref]$vtR)
    $rd = ''
    if ($rcR -eq 0 -and $dpR -ne [IntPtr]::Zero) {
      $lim = [int]($dszR / 4)
      if ($lim -gt 5) { $lim = 5 }
      $iv = @()
      # Loop variable must NOT be called $q: PowerShell names are CASE-INSENSITIVE, so $q would overwrite
      # the class handle $Q ([P164.W164]) with an Int32 and every later $Q::WlanFreeMemory would blow up.
      # Third time this class of bug bit ($v/$V, $b64/$B64) -- long names for loop locals.
      for ($qi = 0; $qi -lt $lim; $qi++) { $iv += $M::ReadInt32([IntPtr]($dpR.ToInt64() + ($qi * 4))) }
      $rd = ($iv -join ',')
    }
    Write-Output ('P164 RADIO rc=' + $rcR + ' size=' + $dszR + ' ints=' + $rd)
    if ($dpR -ne [IntPtr]::Zero) { $Q::WlanFreeMemory($dpR) | Out-Null }

    # opcodes 1/2 = autoconf_enabled / background_scan_enabled: rules out "policy switched it off"
    foreach ($ob in @(1, 2)) {
      $dso = 0; $dpo = [IntPtr]::Zero; $vto = 0
      $rcO = $Q::WlanQueryInterface($h, [ref]$gref, $ob, [IntPtr]::Zero, [ref]$dso, [ref]$dpo, [ref]$vto)
      $val = -1
      if ($rcO -eq 0 -and $dpo -ne [IntPtr]::Zero) { $val = $M::ReadInt32($dpo) }
      Write-Output ('P164 OP' + $ob + ' rc=' + $rcO + ' size=' + $dso + ' value=' + $val)
      if ($dpo -ne [IntPtr]::Zero) { $Q::WlanFreeMemory($dpo) | Out-Null }
    }

    # Saved profiles: >=1 = this disc has associated before (operator just re-picks it);
    # 0 = we have only proven "wlansvc can see and scan the adapter".
    $pi = [IntPtr]::Zero
    $rc3 = $Q::WlanGetProfileList($h, [ref]$gref, [IntPtr]::Zero, [ref]$pi)
    $pn = -1
    $pDw4 = 0
    $pDw8 = 0
    if ($rc3 -eq 0 -and $pi -ne [IntPtr]::Zero) {
      $pn = $M::ReadInt32($pi)
      if ($pn -gt 0) {
        $pDw4 = $M::ReadInt32([IntPtr]($pi.ToInt64() + 4))
        $pDw8 = $M::ReadInt32([IntPtr]($pi.ToInt64() + 8))
      }
      # dump the header raw as well: if those two DWORDs mean something else in this build,
      # the pulled log is enough to decide offline -- no second field trip.
      $hx = @()
      for ($j2 = 0; $j2 -lt 64; $j2++) { $hx += ('{0:x2}' -f $M::ReadByte([IntPtr]($pi.ToInt64() + $j2))) }
      Write-Output ('P164 PRF_HDR ' + ($hx -join ''))
    }
    Write-Output ('P164 PROFILES rc=' + $rc3 + ' count=' + $pn + ' dword4=' + $pDw4 + ' dword8=' + $pDw8)
    # names are scanned, not indexed (see the layout lesson in the header)
    if ($pn -gt 0) {
      $pBase = [IntPtr]($pi.ToInt64() + 8)
      $names = Get-Runs $pBase 4096 $pn
      $ki = 0
      foreach ($nm in @($names)) {
        Write-Output ('P164 PROFILE[' + $ki + '] name=' + $nm)
        $ki++
      }
      if ($ki -lt $pn) { Write-Output ('P164 PROFILE scanned=' + $ki + ' of ' + $pn + ' (non-ASCII SSID skipped)') }
    }
    if ($pi -ne [IntPtr]::Zero) { $Q::WlanFreeMemory($pi) | Out-Null }
  }
  Write-Output 'P164 end'
} finally { $Q::WlanCloseHandle($h, [IntPtr]::Zero) | Out-Null }
exit 0
