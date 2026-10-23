# ============================================================
# probe85_minidump.ps1 -- read the WER minidump probe84 produced and name the crash.
#
# WHY THIS PROBE EXISTS
# probe84 (build/scratch/p84_push_1010.txt, live PE 192.168.0.107) killed the double -s theory and
# replaced it with something much better: a crash dump.
#   record / launched shape                                   StartServiceW     what the SCM ended with
#   A  -k wlansvcs -p -s wlansvc   (this hive, probe47/48)    False err=1053    state=1 win32err=0  waithint=2000
#   B  -k LocalSystemNetworkRestricted -p   (the BAKE shape)  True  StartPending state=1 win32err=0x800C0006
#   C  B + " -s wlansvc"           (double -s on purpose)     True  StartPending state=1 win32err=0x800C0006
#   D  wcmsvc -k LocalServiceNetworkRestricted -p             True  StartPending state=1 win32err=1067
#   So B == C: the trailing "-s" changes nothing; what changes everything is the GROUP. With the hand-made
#   "wlansvcs" group the SCM never creates a process (1053). With a group the SCM accepts, a svchost IS
#   created and it dies inside ~100-200 ms -- and WER writes a dump into X:\pe_dumps.
#
# FORMAT GROUND TRUTH (this is the important part -- an earlier draft of this probe used the textbook
# offsets and they were WRONG for the dumps WER writes in this PE)
# Every statement below was verified byte-for-byte against the real crash dump pulled off the PE,
# build/scratch/drydumps/pe_svchost_1328.dmp (780,551 bytes), by build/scratch/t_p85_bytelayout2.ps1 and
# build/scratch/t_p85_threads3.ps1 (output kept as p85_bytelayout2.txt / p85_threads3.txt).
#   header: 'MDMP'@0 version@4 nStreams@8 dirRva@12 checksum@16 reserved@20 timestamp@24 flags(8)@28.
#   directory entry: type(4) size(4) rva(4) = 12 bytes. MiniDumpWriteDump files are flat: RVA == file
#   offset, so the byte[] can be indexed directly.
#   STREAM TYPES (the enum, NOT the guess the first draft used):
#     0 Unused  3 ThreadList  4 ModuleList  5 MemoryList  6 EXCEPTION  7 Verification  8 MiscInfo
#     9 Memory64List  10 CommentA  11 CommentW  12 HandleData  13 FunctionTable  14 UnloadedModules
#     15 ThreadNameList
#   In that PE dump the directory is [3,4,13,5,6,7,15,21,22,24] and the sizes tile the file exactly:
#     3 size 1348 = 4 + 28*48   4 size 4540 = 4 + 42*108   5 size 6100 = 4 + 381*16   6 size 168
#   The first draft read the exception from type 7 (it is Verification, 56 bytes) and the memory map from
#   type 14 (absent in a WER dump; type 5 MemoryList is the one that maps captured bytes). Both mistakes
#   produced garbage that merely looked structured, so the rules are now:
#     * exception  = stream 6, 168 bytes: tid(4) pad(4) + EXCEPTION_RECORD64[152]
#                  { code(4)@+8 flags(4)@+12 record(8)@+16 addr(8)@+24 nparams(4)@+32 pad(4)@+36
#                    params[15](8)@+40 } + ctxSize(4)@+160 ctxRva(4)@+164.
#                  The CONTEXT it points at is the AUTHORITATIVE faulting context. The thread list's own
#                  ctx pointer is a second, per-thread copy.
#     * memory map = stream 5 entries startVa(8) DataSize(4) Rva(4); stream 9 (Memory64List) if present.
#     * threads  = stream 3, count(4) then entries of (size-4)/count bytes. The documented MINIDUMP_THREAD
#                  is 40 bytes, but WER on this build writes 48 and the two 8-byte VAs are ordered
#                  Teb@+16 then Stack{ startVa(8)@+24 DataSize(4)@+32 Rva(4)@+36 } ctx{ size(4)@+40
#                  rva(4)@+44 }. Proof: for the faulting thread +24/+32/+36 decoded to
#                  VA 0x000000FCBA27DE38 / 8648 bytes / file rva 675939 and that region really exists in
#                  stream 5 and really contains Rsp; and 27 of 28 entries carry a stream-5-verified
#                  context rva at +44. This probe therefore does NOT trust one layout: it derives the
#                  stride from the stream size and picks the field offsets whose (start,size,rva) triple
#                  matches a captured memory region and whose ctx rva starts with a sane ContextFlags.
#     * x64 CONTEXT (winnt.h, verified on this dump): ContextFlags@0x30 (=0x0010004F) MxCsr@0x34 SegCs@0x38
#                  EFlags@0x44 (=0x206) Dr0..Dr7@0x48..0x70 Rax@0x78 Rcx@0x80 Rdx@0x88 Rbx@0x90 Rsp@0x98
#                  Rbp@0xA0 Rsi@0xA8 Rdi@0xB0 R8@0xB8 R9@0xC0 R10@0xC8 R11@0xD0 R12@0xD8 R13@0xE0
#                  R14@0xE8 R15@0xF0 Rip@0xF8, Xmm0/M128A@0x100, total 1232 bytes (= the ctxSize WER
#                  reports). Two independent confirmations: at 0x44 sits 0x206 (a real EFlags), and the
#                  8 bytes @0xF8 equal the exception record's own ExceptionAddress, while 0x100 is Xmm0
#                  garbage. Rsp@0x98 = 0x000000FCBA27F510 lands inside the faulting thread's captured
#                  stack -- that is the LAYOUTCHECK below, and if it ever says NO the register table has
#                  moved again and the numbers must not be believed.
#     * modules  = stream 4, count(4) then 108-byte entries base(8) size(4)@+8 checksum(4)@+12
#                  timestamp(4)@+16 nameRva(4)@+20 VS_FIXEDFILEINFO@+24 (dwSignature 0xFEEF04BD at +24,
#                  FileVersionMS@+32 FileVersionLS@+36). Names are MINIDUMP_STRING {ULONG Length-in-bytes;
#                  UTF-16} at the rva, text at rva+4.
#     * WER dumps also carry non-standard types 21/22/24; they are listed and ignored.
#
# WHAT THIS PRINTS (the four things that decide the next step)
#   (1) the exception CODE   0xC0000135 DLL_NOT_FOUND / 0xC0000139 ENTRYPOINT_NOT_FOUND / 0xC0000005 AV /
#       0xC0000409 failfast / 0xE06D7363 C++ throw / a small custom code = someone called RaiseException.
#   (2) the faulting ADDRESS and the module that owns it.
#   (3) the exception PARAMETERS: loader failures hand over a PUNICODE_STRING per parameter, so the NAME OF
#       THE MISSING DLL can be read straight out of the dump; when the parameter points into module .text
#       (image pages are not captured) the module+offset is still the next best thing.
#   (4) the faulting context's registers plus a scanned stack: every 8-byte word inside a loaded module is
#       a candidate return address -> a rough call chain without any symbols.
# Reference reading of the dump already pulled to the host: code 0x00000505 (a deliberate, noncontinuable
# RaiseException), ExceptionAddress KERNELBASE+0xCFC8A (the raise path itself), both parameters inside
# wcmsvc.dll, and R13 = 0xC0000135 STATUS_DLL_NOT_FOUND left over from the failed load -- i.e. that dump is
# the wcmsvc host, and it holds no wlansvc.dll/nwifi module at all. wlansvc's own failure (win32err
# 0x800C0006) has no dump yet, which is exactly what section 2 below re-arms and re-triggers for.
#
# Writes: WER LocalDumps DumpType/DumpCount (only when no exception stream exists) and the svchost start
#         that goes with it. Nothing else; the service records stay as probe84 left them. All on the
#         RAMDISK, gone on reboot.
# Push + run from the host (one command, result returns automatically):
#   powershell -NoProfile -ExecutionPolicy Bypass -File test/host_push_run.ps1 `
#     -Local test/share/probe85_minidump.ps1 -RemotePath X:/p85.ps1 -StagingB64 X:/p85.b64 `
#     -Target administrator@192.168.0.107 -Port 22 -Run
# ============================================================
$ErrorActionPreference = 'Continue'
function O([string]$s) { Write-Output $s }
function ToAscii([string]$x) { ($x -replace '[^\x20-\x7E]', '?') }
$script:B = $null          # the dump bytes, loaded per file
$script:MODS = @()         # @{name; base; size}
$script:MEM = @()          # @{start; size; rva}
$script:THREAD = $null     # the faulting thread, filled by ParseThreads
$script:GOTEXC = $false    # did ANY dump carry a real exception stream
$RPT = @{ code = ''; addr = ''; params = ''; stack = ''; names = ''; rearm = 'no'; dump = 'none'; tid = -1; ctxok = 'no' }

function ReadU16([int]$o) { [BitConverter]::ToUInt16($script:B, $o) }
function ReadU32([int]$o) { [BitConverter]::ToUInt32($script:B, $o) }
function ReadU64([int]$o) { [BitConverter]::ToUInt64($script:B, $o) }
# PS 5.1 throws when a UInt32 above Int32.MaxValue is cast to [int] ("Value was either too large or too
# small for an Int32"), and a module RVA or a size field can easily exceed 2 GB in the high words. Every
# integer read therefore goes through [int64].
function U32i([int]$o) { if ($o -lt 0 -or ($o + 4) -gt $script:B.Length) { return [int64](-1) }; return [int64](ReadU32 $o) }
function U64v([int]$o) { if ($o -lt 0 -or ($o + 8) -gt $script:B.Length) { return [uint64]0 }; return ReadU64 $o }
function Hex8($v) { try { '0x' + ('{0:X8}' -f [uint32] $v) } catch { '?(' + $v + ')' } }
function Hex16($v) { try { '0x' + ('{0:X16}' -f [uint64] $v) } catch { '?(' + $v + ')' } }
# MINIDUMP_STRING: ULONG Length in BYTES (NUL not counted) then UTF-16.
function MdString([int]$rva) {
  if ($rva -le 0 -or ($rva + 4) -gt $script:B.Length) { return '<bad rva ' + $rva + '>' }
  $len = U32i $rva
  if ($len -lt 0 -or $len -gt 4000 -or ($rva + 4 + $len) -gt $script:B.Length) { return '<bad len ' + $len + '>' }
  if ($len -eq 0) { return '' }
  return [System.Text.Encoding]::Unicode.GetString($script:B, $rva + 4, [int] $len)
}
function FindModule($addr) {
  $a = [uint64] $addr
  foreach ($m in $script:MODS) {
    if ($a -ge [uint64] $m.base -and ($a - [uint64] $m.base) -lt [uint64] $m.size) {
      return ($m.name + '+0x' + ('{0:X}' -f ($a - [uint64] $m.base)))
    }
  }
  return ''
}
# VA -> file offset, using the captured-memory map (stream 5, or stream 9 when the dump used Memory64List).
function VaToRva($va) {
  $a = [uint64] $va
  foreach ($r in $script:MEM) {
    $s = [uint64] $r.start
    if ($a -ge $s -and ($a - $s) -lt [uint64] $r.size) { return [int64]([int64] $r.rva + ($a - $s)) }
  }
  return -1
}
function RegionContaining($va) {
  $a = [uint64] $va
  foreach ($r in $script:MEM) {
    $s = [uint64] $r.start
    if ($a -ge $s -and ($a - $s) -lt [uint64] $r.size) { return $r }
  }
  return $null
}
# A PUNICODE_STRING passed as an exception parameter: Length(2) MaxLength(2) pad(4) Buffer(8).
function MdUniAt($va) {
  $r = VaToRva $va
  if ($r -lt 0 -or ($r + 16) -gt $script:B.Length) { return '' }
  $ri = [int] $r
  $len = [int](ReadU16 $ri)
  $buf = U64v ($ri + 8)
  if ($len -le 0 -or ($len % 2) -ne 0 -or $len -gt 1024) { return '' }
  $r2 = VaToRva $buf
  if ($r2 -lt 0 -or ($r2 + $len) -gt $script:B.Length) { return '' }
  return [System.Text.Encoding]::Unicode.GetString($script:B, [int] $r2, $len)
}

function ParseModules([int]$rva) {
  $n = U32i $rva
  if ($n -lt 0 -or $n -gt 4000) { O ('  MODULES bad count=' + $n); return }
  O ('  MODULES count=' + $n)
  $script:MODS = @()
  for ($i = 0; $i -lt $n; $i++) {
    $e = $rva + 4 + ($i * 108)
    if (($e + 108) -gt $script:B.Length) { O ('  MODULES truncated at ' + $i); break }
    $base = U64v $e
    $size = U32i ($e + 8)
    $nameRva = U32i ($e + 20)
    $vsSig = U32i ($e + 24)     # VS_FIXEDFILEINFO dwSignature must be 0xFEEF04BD
    $vms = U32i ($e + 32)
    $vls = U32i ($e + 36)
    $nm = MdString ([int] $nameRva)
    $leaf = $nm
    if ($leaf -match '[\\/]') { $leaf = ((@($leaf -split '[\\/]') | Where-Object { $_ }))[-1] }
    $script:MODS += @{ name = $leaf; base = $base; size = $size }
    $ver = 'n/a'
    if ($vsSig -eq 4276674237) {   # 0xFEEF04BD
      $ver = '' + [int64][math]::Floor($vms / 65536) + '.' + [int64]($vms % 65536) + '.' +
                   [int64][math]::Floor($vls / 65536) + '.' + [int64]($vls % 65536)
    }
    if ($i -lt 3 -or ($leaf -match '(?i)^wlansvc|^wlan|^vwif|^nwifi|^onex|^mcm\.|^dnsapi|^rpcrt|^ntdll|^svchost|^kernelbase|^wcmsvc|^policymanager|^embeddedmode|^wlgpclnt|^cmintegrator|^deviceassociation')) {
      O ('    MOD[' + $i + '] ' + (ToAscii $leaf) + ' base=' + (Hex16 $base) + ' size=0x' + ('{0:X}' -f $size) +
         ' ver=' + $ver + ' full=[' + (ToAscii $nm) + ']')
    }
  }
  $RPT.names = ((@($script:MODS | ForEach-Object { $_.name } | Sort-Object -Unique)) -join ',')
  O ('    all module names: ' + (ToAscii $RPT.names))
  foreach ($probe in @('wlansvc.dll', 'nwifi.dll', 'vwifibus.sys', 'policymanager.dll', 'wcmsvc.dll')) {
    $seen = $false
    foreach ($m in $script:MODS) { if ($m.name -match ('(?i)^' + [regex]::Escape($probe) + '$')) { $seen = $true } }
    O ('    PRESENT? ' + $probe + ' = ' + $(if ($seen) { 'yes' } else { 'no -- not loaded in this process' }))
  }
}

# Captured memory. stream 5 MemoryList  = count(4) + count * {startVa(8) DataSize(4) Rva(4)}.
#                  stream 9 Memory64List = count(8) + totalSize(8) + baseRva(8) then count * {startVa(8)
#                  DataSize(8)} with the bytes streamed contiguously from baseRva in entry order.
function ParseMemory([int]$rva5, [int]$rva9) {
  $script:MEM = @()
  if ($rva5 -gt 0) {
    $n = U32i $rva5
    if ($n -ge 0 -and $n -lt 200000) {
      for ($i = 0; $i -lt $n; $i++) {
        $e = $rva5 + 4 + ($i * 16)
        if (($e + 16) -gt $script:B.Length) { O ('  MEMORYLIST truncated at ' + $i); break }
        $sz = U32i ($e + 8)
        if ($sz -le 0) { continue }
        $script:MEM += @{ start = (U64v $e); size = $sz; rva = (U32i ($e + 12)) }
      }
      O ('  MEMORYLIST(stream 5) regions=' + $script:MEM.Count)
    } else { O ('  MEMORYLIST bad count=' + $n) }
  }
  if ($rva9 -gt 0 -and $script:MEM.Count -eq 0) {
    $n = [int64](U64v $rva9)
    $base = [int64](U64v ($rva9 + 16))
    O ('  MEMORY64LIST regions=' + $n + ' baseRva=' + $base)
    if ($n -ge 0 -and $n -lt 200000) {
      $cur = $base
      for ($i = 0; $i -lt $n; $i++) {
        $e = $rva9 + 24 + ($i * 16)
        if (($e + 16) -gt $script:B.Length) { break }
        $sz = [int64](U64v ($e + 8))
        $script:MEM += @{ start = (U64v $e); size = $sz; rva = $cur }
        $cur += $sz
      }
      O ('    mapped from stream 9: ' + $script:MEM.Count + ' regions')
    }
  }
  $tot = [int64] 0
  foreach ($r in $script:MEM) { $tot += [int64] $r.size }
  O ('    captured bytes total=' + $tot + ' of file ' + $script:B.Length)
}

# The thread list. Stride is derived from the stream, and the field layout is CHOSEN by verification
# rather than assumed, because WER on this build writes 48-byte entries that are not the documented
# 40-byte MINIDUMP_THREAD (see the header note). No return value: the caller reads $script:THREAD.
function ParseThreads([int]$rva, [int]$size, [int]$wantTid) {
  $script:THREAD = $null
  $n = U32i $rva
  if ($n -le 0 -or $n -gt 8000) { O ('  THREADS bad count=' + $n); return }
  $stride = [int64] (($size - 4) / $n)
  O ('  THREADS count=' + $n + ' streamSize=' + $size + ' stride=' + $stride)
  if ($stride -lt 24 -or $stride -gt 128) { O '  THREADS stride implausible, skipping'; return }
  $cands = @()
  if ($stride -ge 40) { $cands += @{ ss = 16; sd = 24; sr = 28; cs = 32; cr = 36; lbl = 'documented-40' } }
  if ($stride -ge 48) { $cands += @{ ss = 24; sd = 32; sr = 36; cs = 40; cr = 44; lbl = 'wer-48-teb-first' } }
  $best = $null; $bestScore = -1
  foreach ($cd in $cands) {
    $score = 0
    $sample = [int64][Math]::Min($n, 8)
    for ($i = 0; $i -lt $sample; $i++) {
      $e = $rva + 4 + ($i * $stride)
      if (($e + $stride) -gt $script:B.Length) { break }
      $st = U64v ($e + $cd.ss); $sz = U32i ($e + $cd.sd); $sr = U32i ($e + $cd.sr)
      $cr = U32i ($e + $cd.cr)
      if ($sz -gt 0 -and $sz -lt 0x800000 -and $sr -gt 0 -and ($sr + $sz) -le $script:B.Length) { $score += 2 }
      $cf = -1
      if ($cr -gt 0 -and ($cr + 0x34) -le $script:B.Length) { $cf = U32i ([int] ($cr + 0x30)) }
      if ($cf -ge 0 -and (($cf -band 0x00FF0000) -eq 0x00100000)) { $score += 3 }
    }
    O ('    layout ' + $cd.lbl + ' score=' + $score + ' of ' + ($sample * 5))
    if ($score -gt $bestScore) { $bestScore = $score; $best = $cd }
  }
  if ($null -eq $best -or $bestScore -le 0) { O '  THREADS no layout matched -- thread/stack scan unavailable'; return }
  O ('    USING layout ' + $best.lbl)
  for ($i = 0; $i -lt $n; $i++) {
    $e = $rva + 4 + ($i * $stride)
    if (($e + $stride) -gt $script:B.Length) { O ('  THREADS truncated at ' + $i); break }
    $tid = U32i $e
    $isWanted = ($tid -eq $wantTid) -or (($wantTid -lt 0) -and ($i -eq 0))
    if (-not $isWanted) { continue }
    $stackStart = U64v ($e + $best.ss)
    $stackSize = U32i ($e + $best.sd)
    $stackRva = U32i ($e + $best.sr)
    $ctxSize = U32i ($e + $best.cs)
    $ctxRva = U32i ($e + $best.cr)
    $cf = 'n/a'
    if ($ctxRva -gt 0 -and ($ctxRva + 0x34) -le $script:B.Length) { $cf = Hex8 (U32i ([int] ($ctxRva + 0x30))) }
    O ('    THREAD[' + $i + '] tid=' + $tid + ' stackVa=' + (Hex16 $stackStart) + ' size=' + $stackSize +
       ' fileRva=' + $stackRva + ' ctx size=' + $ctxSize + ' rva=' + $ctxRva + ' ContextFlags=' + $cf)
    $script:THREAD = @{ tid = $tid; stackStart = $stackStart; stackSize = $stackSize; stackRva = $stackRva;
                        ctxSize = $ctxSize; ctxRva = $ctxRva }
    return
  }
  if ($wantTid -ge 0) { O ('  THREADS tid ' + $wantTid + ' not found in the list') }
}

# Use the exception stream's CONTEXT (authoritative). $ctxFrom is a label saying where the rva came from.
function ParseContext([int]$ctxRva, [string]$ctxFrom) {
  if ($ctxRva -le 0 -or ($ctxRva + 0x108) -gt $script:B.Length) { O ('  CONTEXT rva out of range (' + $ctxRva + ')'); return }
  $c = [int] $ctxRva
  $flags = U32i ($c + 0x30)
  $eflags = U32i ($c + 0x44)
  $rax = U64v ($c + 0x78); $rcx = U64v ($c + 0x80); $rdx = U64v ($c + 0x88); $rbx = U64v ($c + 0x90)
  $rsp = U64v ($c + 0x98); $rbp = U64v ($c + 0xA0); $rsi = U64v ($c + 0xA8); $rdi = U64v ($c + 0xB0)
  $r8 = U64v ($c + 0xB8); $r9 = U64v ($c + 0xC0); $r12 = U64v ($c + 0xD8); $r13 = U64v ($c + 0xE0)
  $rip = U64v ($c + 0xF8)
  O ('  CONTEXT from ' + $ctxFrom + ' ContextFlags=' + (Hex8 $flags) + ' (x64 CONTEXT_ALL=0x10000F, +debug=0x10005F) EFlags=' + (Hex8 $eflags))
  O ('    Rax=' + (Hex16 $rax) + $(if ((FindModule $rax) -ne '') { ' [' + (FindModule $rax) + ']' } else { '' }) +
     ' Rbx=' + (Hex16 $rbx) + ' Rcx=' + (Hex16 $rcx) + ' Rdx=' + (Hex16 $rdx))
  O ('    Rsi=' + (Hex16 $rsi) + ' Rdi=' + (Hex16 $rdi) + ' Rbp=' + (Hex16 $rbp))
  O ('    R8=' + (Hex16 $r8) + ' R9=' + (Hex16 $r9) + '  [rcx/rdx/r8/r9 hold the arguments at the fault]')
  O ('    R12=' + (Hex16 $r12) + $(if ((FindModule $r12) -ne '') { ' [' + (FindModule $r12) + ']' } else { '' }) +
     ' R13=' + (Hex16 $r13) + $(if ((FindModule $r13) -ne '') { ' [' + (FindModule $r13) + ']' } else { '' }))
  if ((Hex16 $r13) -match 'C0000135$') { O '    R13 carries STATUS_DLL_NOT_FOUND -- a load failed on this path' }
  if ((Hex16 $r13) -match 'C0000139$') { O '    R13 carries STATUS_ENTRYPOINT_NOT_FOUND -- a DLL lacks an import' }
  O ('    Rsp=' + (Hex16 $rsp) + '  Rip=' + (Hex16 $rip) + ' owner=' + $(if ((FindModule $rip) -ne '') { FindModule $rip } else { 'not in any module' }))
  $rg = RegionContaining $rsp
  if ($null -ne $rg) {
    O ('    LAYOUTCHECK Rsp inside captured Stack=[' + (Hex16 $rg.start) + '..' + (Hex16 ([uint64] $rg.start + [uint64] $rg.size)) +
       '] = yes (x64 CONTEXT offsets confirmed: Rax@0x78 Rsp@0x98 Rip@0xF8)')
    $RPT.ctxok = 'yes'
  } else {
    O ('    LAYOUTCHECK Rsp ' + (Hex16 $rsp) + ' is not inside any captured region = NO -- treat the register lines above as raw bytes')
    $RPT.ctxok = 'no'
  }
  $script:RSP = $rsp
}

# Every 8-byte word from Rsp upward that points inside a loaded module is a candidate return address.
function ScanStack() {
  $RPT.stack = 'nostack'
  $rsp = [uint64] 0
  if ($script:RSP -ne $null) { $rsp = [uint64] $script:RSP }
  $rg = RegionContaining $rsp
  if ($null -eq $rg) {
    if ($script:THREAD -ne $null -and [int64] $script:THREAD.stackSize -gt 0 -and [int64] $script:THREAD.stackRva -gt 0) {
      $rg = @{ start = $script:THREAD.stackStart; size = $script:THREAD.stackSize; rva = $script:THREAD.stackRva }
      O '  STACK falling back to the thread-list descriptor'
    } else { O '  STACK no captured stack memory (DumpType too small)'; return }
  }
  $off = [int64] ($rsp - [uint64] $rg.start)
  if ($off -lt 0) { $off = 0 }
  $lim = [Math]::Min([int64] ([int64] $rg.size - $off), 8192)
  $base = [int64] $rg.rva + $off
  if (($base + $lim) -gt $script:B.Length) { $lim = [int64] ($script:B.Length - $base) }
  O ('  STACK region=' + (Hex16 $rg.start) + ' rspOff=0x' + ('{0:X}' -f $off) + ' scanning=' + $lim + ' bytes')
  $hits = @()
  $prev = ''
  for ($o = 0; $o -lt $lim; $o += 8) {
    $word = U64v ([int] ($base + $o))
    $who = FindModule $word
    if (($who -ne '') -and ($who -ne $prev)) {
      $hits += ('sp+0x' + ('{0:X}' -f $o) + ' ' + $who)
      $prev = $who
      if ($hits.Count -ge 24) { break }
    }
  }
  O ('  STACK candidateReturnAddresses=' + $hits.Count)
  foreach ($h in $hits) { O ('    ' + $h) }
  $RPT.stack = ($hits -join ' | ')
}

function ParseOneDump([string]$path) {
  $script:RSP = $null
  O ('---- ' + $path)
  $fi = Get-Item $path -EA SilentlyContinue
  if (-not $fi) { O '  absent'; return }
  O ('  bytes=' + $fi.Length + ' mtime=' + $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))
  $script:B = [System.IO.File]::ReadAllBytes($path)
  if ($script:B.Length -lt 64) { O '  too small'; return }
  $sig = [System.Text.Encoding]::ASCII.GetString($script:B, 0, 4)
  $ver = U32i 4
  $nStreams = U32i 8
  $dirRva = U32i 12
  $stamp = U32i 24
  $flags = U64v 28
  O ('  SIG=' + $sig + ' version=' + $ver + ' streams=' + $nStreams + ' dirRva=' + $dirRva +
     ' timestamp=' + ([DateTimeOffset]::FromUnixTimeSeconds($stamp).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')) +
     ' flags=' + (Hex16 $flags))
  if ($sig -ne 'MDMP') { O '  NOT A MINIDUMP'; return }
  $RPT.dump = (Split-Path $path -Leaf)
  $streams = @{}
  for ($i = 0; $i -lt $nStreams; $i++) {
    $e = [int] ($dirRva + ($i * 12))
    if (($e + 12) -gt $script:B.Length) { O ('  directory truncated at ' + $i); break }
    $t = [int](U32i $e)     # INT, not int64: a hashtable keyed by [long]4 does not answer ContainsKey(4),
                            # because Int32.Equals(object) refuses a boxed Int64. Reading the directory with
                            # 64-bit keys silently turned every "is stream N present" test into "absent".
    $sz = U32i ($e + 4)
    $rva = U32i ($e + 8)
    if (-not $streams.ContainsKey($t)) { $streams[$t] = @{ size = $sz; rva = $rva } }
    $tname = switch ($t) {
      0 { 'Unused' } 3 { 'ThreadList' } 4 { 'ModuleList' } 5 { 'MemoryList' } 6 { 'EXCEPTION' }
      7 { 'Verification' } 8 { 'MiscInfo' } 9 { 'Memory64List' } 10 { 'CommentA' } 11 { 'CommentW' }
      12 { 'HandleData' } 13 { 'FunctionTable' } 14 { 'UnloadedModules' } 15 { 'ThreadNameList' }
      16 { 'Token' } 17 { 'HdrPlus' } default { 'other/non-standard' } }
    O ('    STREAM ' + $t + ' ' + $tname + ' size=' + $sz + ' rva=' + $rva)
  }
  if ($streams.ContainsKey(8)) {
    $mi = [int] $streams[8].rva
    O ('  MISCINFO pid=' + (U32i ($mi + 8)) + ' flags=' + (Hex8 (U32i ($mi + 4))) + ' (MiscInfoStream carries the process id at +8)')
  }
  if ($streams.ContainsKey(4)) { ParseModules ([int] $streams[4].rva) } else { O '  NO ModuleList stream' }
  $r5 = -1; $r9 = -1
  if ($streams.ContainsKey(5)) { $r5 = [int] $streams[5].rva }
  if ($streams.ContainsKey(9)) { $r9 = [int] $streams[9].rva }
  ParseMemory $r5 $r9
  $tid = -1
  $ctxRva = -1
  $ctxFrom = 'none'
  if ($streams.ContainsKey(6)) {
    $x = [int] $streams[6].rva
    $xsz = [int] $streams[6].size
    $tid = [int] (U32i $x)
    $RPT.tid = $tid
    $codev = [uint32](U32i ($x + 8))
    $hexKey = '{0:X8}' -f $codev
    $names = @{ 'C0000005' = 'STATUS_ACCESS_VIOLATION'; 'C0000135' = 'STATUS_DLL_NOT_FOUND';
                'C0000139' = 'STATUS_ENTRYPOINT_NOT_FOUND'; 'C0000142' = 'STATUS_DLL_INIT_FAILED';
                'C0000409' = 'STATUS_STACK_BUFFER_OVERRUN (failfast)'; '80000003' = 'STATUS_BREAKPOINT';
                'E06D7363' = 'C++ exception (MSVC_EH)'; 'C0000374' = 'STATUS_HEAP_CORRUPTION';
                'C00000FD' = 'STATUS_STACK_OVERFLOW'; 'C000041D' = 'STATUS_FATAL_APC_UNWIND';
                '00000505' = 'a small user-defined code: someone called RaiseException on purpose' }
    $cn = 'unmapped'
    if ($names.ContainsKey($hexKey)) { $cn = $names[$hexKey] }
    $addrv = U64v ($x + 24)
    $np = [int] (U32i ($x + 32))
    $ctxSize = [int] (U32i ($x + 160))
    $ctxRva = [int] (U32i ($x + 164))
    if ($ctxSize -eq 1232) { $ctxFrom = 'exception stream 6 (authoritative)' }
    $RPT.code = '0x' + $hexKey
    $owner = FindModule $addrv
    $RPT.addr = (Hex16 $addrv) + '@' + $(if ($owner -ne '') { $owner } else { 'unmapped' })
    O ('  EXCEPTION stream6 size=' + $xsz + ' tid=' + $tid + ' code=0x' + $hexKey + ' (' + $cn + ')' +
       ' flags=' + (Hex8 (U32i ($x + 12))) + ' (1=NONCONTINUABLE 0x80=NESTED) addr=' + (Hex16 $addrv) +
       ' owner=' + $(if ($owner -ne '') { $owner } else { 'not in any module' }) +
       ' numberParameters=' + $np + ' ctxSize=' + $ctxSize + ' ctxRva=' + $ctxRva)
    $script:GOTEXC = $true
    $paramTxt = ''
    for ($p = 0; $p -lt [Math]::Min($np, 8); $p++) {
      $pv = U64v ($x + 40 + ($p * 8))
      $extra = ''
      $who = FindModule $pv
      if ($who -ne '') { $extra = ' module=' + $who }
      $uni = MdUniAt $pv
      if ($uni -ne '') { $extra = ' STRING=[' + (ToAscii $uni) + ']' }
      O ('    PARAM[' + $p + '] ' + (Hex16 $pv) + $extra +
         $(if ($extra -eq '') { $(if ($null -ne (RegionContaining $pv)) { ' [captured memory]' } else { ' [not captured]' }) } else { '' }))
      $paramTxt += ('[' + $p + ']' + (Hex16 $pv) + $extra + ' ')
    }
    $RPT.params = $paramTxt
  } else { O '  NO ExceptionStream (stream 6) in this dump' }
  if ($streams.ContainsKey(3)) {
    ParseThreads ([int] $streams[3].rva) ([int] $streams[3].size) $tid
  } else { O '  NO ThreadList stream' }
  if ($ctxRva -le 0 -and $null -ne $script:THREAD) { $ctxRva = [int] $script:THREAD.ctxRva; $ctxFrom = 'thread list' }
  if ($ctxRva -gt 0) { ParseContext $ctxRva $ctxFrom } else { O '  NO CONTEXT anywhere in this dump' }
  ScanStack
}

O '== 0 what is on disk, and what room is there =='
$dumps = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue | Sort-Object LastWriteTime)
O ('  pe_dumps files=' + $dumps.Count)
foreach ($dd in $dumps) { O ('    FILE ' + (ToAscii $dd.Name) + ' ' + [int]($dd.Length / 1024) + 'KB ' + $dd.LastWriteTime.ToString('HH:mm:ss')) }
$freeMB = -1
foreach ($x in @(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='X:'" -EA SilentlyContinue)) { $freeMB = [int]($x.FreeSpace / 1MB) }
O ('  X: free MB=' + $freeMB)
$wk = 'HKLM:\SYSTEM\Microsoft\Windows\Windows Error Reporting\LocalDumps\svchost.exe'
$wr = ''
foreach ($vn in @(try { @((Get-Item $wk -EA Stop).GetValueNames()) } catch { @() })) {
  $wr += ($vn + '=' + (Get-ItemProperty $wk -Name $vn).$vn + ' ')
}
O ('  WER LocalDumps svchost.exe: ' + (ToAscii $wr))
$wlImg = ''
$o = @(& reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\wlansvc' /v ImagePath 2>&1 | ForEach-Object { "$_" })
foreach ($l in $o) { if ($l -match 'REG_\S+\s+(.*)$') { $wlImg = ($matches[1] -replace '\s+', ' ').Trim() } }
$wlState = try { "$((Get-Service -Name wlansvc -EA Stop).Status)" } catch { 'ABSENT' }
O ('  wlansvc now: ImagePath=[' + (ToAscii $wlImg) + '] state=' + $wlState + ' (probe84 left the pristine bake shape)')

O '== 1 parse every dump present =='
foreach ($dd in $dumps) { ParseOneDump $dd.FullName }

O '== 2 re-arm and re-trigger, only if nothing carried an exception stream =='
if (-not $script:GOTEXC) {
  $newType = 1
  if ($freeMB -gt 400) { $newType = 2 }
  try {
    $k = 'HKLM:\SYSTEM\Microsoft\Windows\Windows Error Reporting'
    if (-not (Test-Path (Join-Path $k 'LocalDumps'))) { New-Item (Join-Path $k 'LocalDumps') -Force -EA Stop | Out-Null }
    if (-not (Test-Path $wk)) { New-Item $wk -Force -EA Stop | Out-Null }
    Set-ItemProperty $wk 'DumpFolder' 'X:\pe_dumps' -Type String -Force -EA Stop
    Set-ItemProperty $wk 'DumpCount' 1 -Type DWord -Force -EA Stop
    Set-ItemProperty $wk 'DumpType' $newType -Type DWord -Force -EA Stop
    $RPT.rearm = 'DumpType=' + $newType
    O ('  WER re-armed DumpType=' + $newType + ' DumpCount=1 (free MB=' + $freeMB + ')')
    Remove-Item 'X:\pe_dumps\*' -Force -EA SilentlyContinue
  } catch { O ('  re-arm failed: ' + (ToAscii $_.Exception.Message)) }
  try {
    Start-Service -Name wlansvc -EA SilentlyContinue
    for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Milliseconds 400 }
    O ('  after the re-trigger svc=' + $(try { "$((Get-Service -Name wlansvc -EA Stop).Status)" } catch { 'ABSENT' }))
  } catch { O ('  start failed: ' + (ToAscii $_.Exception.Message)) }
  $fresh = @(Get-ChildItem 'X:\pe_dumps' -File -EA SilentlyContinue | Sort-Object LastWriteTime)
  O ('  dumps after re-trigger=' + $fresh.Count)
  foreach ($dd in $fresh) { ParseOneDump $dd.FullName }
} else { O '  an existing dump already carries an exception stream -- nothing re-triggered' }

O '== 3 VERDICT =='
O ('P85 VERDICT dump=' + $RPT.dump + ' code=' + $RPT.code + ' addr=' + $RPT.addr + ' tid=' + $RPT.tid +
   ' ctxLayoutVerified=' + $RPT.ctxok + ' rearm=' + $RPT.rearm)
O ('P85 PARAMS ' + $RPT.params)
O ('P85 STACK ' + $RPT.stack)
O ('P85 MODULES ' + (ToAscii $RPT.names))
if ($RPT.code -eq '0xC0000135') {
  O 'P85 ROOT CAUSE: STATUS_DLL_NOT_FOUND -- the host process died on a DLL that is not in the image. The PARAM STRING line names it; that file (with the .cat covering it) is what the bake still has to add.'
} elseif ($RPT.code -eq '0xC0000139') {
  O 'P85 ROOT CAUSE: STATUS_ENTRYPOINT_NOT_FOUND -- a DLL is present but does not export something the service imports by name; PARAM module= says which one, and the MOD ver= lines show which copy is in the image.'
} elseif ($RPT.code -eq '0xC0000005') {
  O 'P85 ROOT CAUSE: access violation. addr owner = the code that ran; if it is wlansvc.dll itself this is a NULL function pointer, which is exactly what a failed delay-load leaves behind. The STACK chain plus Rcx/Rdx/R8/R9 (the arguments) localise it.'
} elseif ($RPT.code -eq '0xC0000409') {
  O 'P85 ROOT CAUSE: failfast / stack cookie -- svchost killed itself on purpose. The owner in addr= is the module that detected it.'
} elseif ($RPT.code -ne '') {
  O 'P85 READING: code not in the local table. A small code such as 0x505 means someone called RaiseException deliberately (flags bit 1 = noncontinuable); then the PARAMETERS and R12/R13 are the useful part -- R13 often still holds the NTSTATUS that made them raise.'
} else {
  O 'P85 READING: no exception stream even after the re-trigger -- WER is not capturing this crash. Fall back to the delay-load layer: bake the six missing backing files and re-test, since that is the only remaining known-bad input.'
}
if ($RPT.ctxok -ne 'yes') {
  O 'P85 CAUTION: LAYOUTCHECK did not confirm Rsp inside a captured stack region, so the register values may be misaligned. The dump itself (code/addr/params) does not depend on that check.'
}
O 'P85 END'
