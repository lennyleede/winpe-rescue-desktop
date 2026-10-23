# 主机侧: 解析 PE 导入表, 递归列出 SunloginSOS.exe / sshd.exe 的 DLL 依赖
param([string]$Target = 'D:\QoderProject\国内版\生成winpe\overlay\Sunlogin\SunloginSOS.exe',
       [string]$SearchDir = 'C:\Windows\System32',
       [string]$OutFile = '')

function Get-PeImports([string]$path) {
  $fs = [IO.File]::OpenRead($path); $br = New-Object IO.BinaryReader($fs)
  try {
    $fs.Position = 0x3C; $lfanew = $br.ReadInt32()
    $fs.Position = $lfanew + 6
    $nSec = $br.ReadUInt16()
    $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
    $sizeOpt = $br.ReadUInt16(); $null = $br.ReadUInt16()
    $opt = $lfanew + 24
    $fs.Position = $opt; $magic = $br.ReadUInt16()
    $ddOff = if ($magic -eq 0x20B) { 112 } else { 96 }
    # data directory index 1 = import table
    $fs.Position = $opt + $ddOff + 8;  $impRva = $br.ReadUInt32()
    $fs.Position = $opt + $ddOff + 12; $impSize = $br.ReadUInt32()
    if ($impRva -eq 0 -or $impSize -eq 0) { return @() }
    $secOff = $opt + $sizeOpt
    $secs = @()
    for ($i = 0; $i -lt $nSec; $i++) {
      $fs.Position = $secOff + $i * 40
      $null = $br.ReadBytes(8)
      $vsize = $br.ReadUInt32(); $va = $br.ReadUInt32(); $raw = $br.ReadUInt32(); $ptr = $br.ReadUInt32()
      $secs += [pscustomobject]@{ VA = $va; Span = [math]::Max($vsize, $raw); Ptr = $ptr }
    }
    function R2F($rva) {
      foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.Span)) { return $s.Ptr + ($rva - $s.VA) } }
      return -1
    }
    $impOff = R2F $impRva
    if ($impOff -lt 0) { return @() }
    $res = @(); $pos = $impOff
    for ($n = 0; $n -lt 200; $n++) {
      $fs.Position = $pos
      $oft = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
      $nameRva = $br.ReadUInt32(); $ft = $br.ReadUInt32()
      if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
      $noff = R2F $nameRva
      if ($noff -ge 0) {
        $fs.Position = $noff
        $b = New-Object System.Collections.Generic.List[byte]
        for ($k = 0; $k -lt 512; $k++) { $x = $br.ReadByte(); if ($x -eq 0) { break }; $b.Add($x) }
        $dll = [Text.Encoding]::ASCII.GetString($b.ToArray())
        # 该 DLL 的函数名列表 (判断是否真的需要)
        $funcOff = R2F $(if ($oft -ne 0) { $oft } else { $ft })
        $funcs = @()
        if ($funcOff -ge 0) {
          $tp = $funcOff
          for ($t = 0; $t -lt 4096; $t++) {
            $fs.Position = $tp
            $q = if ($magic -eq 0x20B) { $br.ReadUInt64() } else { [uint64]$br.ReadUInt32() }
            if ($q -eq 0) { break }
            $ordFlag = if ($magic -eq 0x20B) { 0x8000000000000000 } else { 0x80000000 }
            if (($q -band $ordFlag) -ne 0) { $funcs += ('#' + ($q -band 0xFFFF)) }
            else {
              $fo = R2F ([uint32]($q -band 0x7FFFFFFF))
              if ($fo -ge 0) {
                $fs.Position = $fo + 2
                $fb = New-Object System.Collections.Generic.List[byte]
                for ($k = 0; $k -lt 256; $k++) { $x = $br.ReadByte(); if ($x -eq 0) { break }; $fb.Add($x) }
                $funcs += [Text.Encoding]::ASCII.GetString($fb.ToArray())
              }
            }
            $tp += $(if ($magic -eq 0x20B) { 8 } else { 4 })
          }
        }
        $res += [pscustomobject]@{ Dll = $dll; Functions = $funcs }
      }
      $pos += 20
    }
    return $res
  } finally { $br.Close(); $fs.Close() }
}

$apisetPrefixes = @('api-ms-win','ext-ms-win','windows.','ntdll')
$script:allSys = New-Object System.Collections.Generic.HashSet[string]
$script:apiSets = New-Object System.Collections.Generic.HashSet[string]
$seen = @{}
$queue = New-Object System.Collections.Generic.Queue[object]
$queue.Enqueue([pscustomobject]@{ Path = $Target; Depth = 0; Via = '' })

while ($queue.Count -gt 0) {
  $item = $queue.Dequeue()
  if (-not (Test-Path $item.Path)) { Write-Host ("MISSING-FILE " + $item.Path); continue }
  $key = (Resolve-Path $item.Path).Path.ToLower()
  if ($seen.ContainsKey($key)) { continue }
  $seen[$key] = $true
  try { $imps = @(Get-PeImports $item.Path) } catch { Write-Host ("PARSE-FAIL " + $item.Path + ' : ' + $_.Exception.Message); continue }
  Write-Host ("{0}  [{1}]  <- {2}  导入 {3} 个" -f (Split-Path $item.Path -Leaf), (' ' * (2 - $item.Depth)) + 'd' + $item.Depth, $item.Via, $imps.Count)
  $dir = Split-Path $item.Path
  $sysDlls = @()
  foreach ($i in $imps) {
    $d = $i.Dll
    if ($d -match '^(api-ms-win|ext-ms-win|windows\.)') { $null = $script:apiSets.Add($d); continue }
    $appLocal = Join-Path $dir $d
    $sys = Join-Path $SearchDir $d
    $down = Join-Path (Join-Path $SearchDir 'downlevel') $d
    if (Test-Path $appLocal) {
      if ($item.Depth -lt 2) { $queue.Enqueue([pscustomobject]@{ Path = $appLocal; Depth = $item.Depth + 1; Via = (Split-Path $item.Path -Leaf) }) }
      else { Write-Host ('    (depth 截断) ' + $d) }
    }
    elseif ((Test-Path $sys) -or (Test-Path $down)) { $sysDlls += $d; $null = $script:allSys.Add($d.ToLower()) }
    else { Write-Host ("    NOT-FOUND: " + $d) }
  }
  if ($sysDlls) { Write-Host ('    系统 DLL 依赖: ' + (($sysDlls | Sort-Object -Unique) -join ', ')) }
}
Write-Host ''
Write-Host ('===== 汇总: 需要 ' + $seen.Count + ' 个模块; 系统 DLL 共 ' + $script:allSys.Count + ' 个; api-set 共 ' + $script:apiSets.Count + ' 个 =====')
if ($OutFile) {
  ($script:allSys | Sort-Object) | Set-Content $OutFile -Encoding UTF8
  Write-Host ('系统 DLL 依赖清单已存: ' + $OutFile)
}
