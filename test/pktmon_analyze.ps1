# 汇总 pktmon etl2txt 的包级明细: 每个包在哪些组件/方向出现过, 判定主机->VM 的帧到底送到哪一层
param([string]$InFile = '', [string]$OutFile = '')
$ErrorActionPreference = 'Continue'
if (-not $InFile) { $InFile = Join-Path $PSScriptRoot 'pktmon_pkt.txt' }
if (-not $OutFile) { $OutFile = Join-Path $PSScriptRoot 'pktmon_analyze.txt' }

$lines = @(Get-Content $InFile -Encoding Unicode)
if ($lines.Count -lt 3) { $lines = @(Get-Content $InFile -Encoding UTF8) }

$L = New-Object System.Collections.Generic.List[string]
function Add($s) { $s = [string]$s; $L.Add($s); Write-Output $s }

Add ('===== pktmon_analyze ' + (Get-Date -Format 'HH:mm:ss') + ' =====')
Add ('infile=' + $InFile + ' lines=' + $lines.Count)

# 事件行 + 紧随其后的包摘要行 配对
$evs = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt $lines.Count; $i++) {
  $ln = [string]$lines[$i]
  if ($ln -notmatch 'PktGroupId') { continue }
  $d = 'Tx'
  if ($ln -match '\bRx\b') { $d = 'Rx' }
  # 标签是中文且随代码页变乱码, 所以按分隔符切字段取位置: 0=PktGroupId 1=PktNumber 2=出现 3=方向 4=类型 5=组件 6=边缘 7=筛选器
  $f = @($ln -split '[，,]')
  $comp = ''
  $edge = ''
  if ($f.Count -gt 5) { $cm2 = [regex]::Match($f[5], '(\d+)'); if ($cm2.Success) { $comp = $cm2.Groups[1].Value } }
  if ($f.Count -gt 6) { $em2 = [regex]::Match($f[6], '(\d+)'); if ($em2.Success) { $edge = $em2.Groups[1].Value } }
  $sum = ''
  if ($i + 1 -lt $lines.Count) { $sum = ([string]$lines[$i + 1]).Trim() }
  if ($sum -notmatch 'length') { $sum = '' }
  $kind = 'other'
  if ($sum -match 'ARP') { $kind = 'arp' }
  elseif ($sum -match 'echo request') { $kind = 'icmp-req' }
  elseif ($sum -match 'echo reply') { $kind = 'icmp-reply' }
  elseif ($sum -match '192\.168\.100\.1\s*>\s*192\.168\.100\.2') { $kind = 'host>pe' }
  elseif ($sum -match '192\.168\.100\.2\s*>\s*192\.168\.100\.1') { $kind = 'pe>host' }
  $evs.Add([pscustomobject]@{ Kind = $kind; Dir = $d; Comp = $comp; Edge = $edge; Sum = $sum })
}

Add ('paired events=' + $evs.Count)
Add ''
Add '===== A. 每类包 x 方向 x 组件 的计数 ====='
foreach ($g in @($evs | Group-Object Kind, Dir, Comp | Sort-Object Name)) {
  Add ('  ' + ($g.Name -replace ', ', '  |  ') + '  x' + $g.Count)
}

Add ''
Add '===== B. 有没有任何"来自 PE"的帧 (192.168.100.2 作源 / echo reply / ARP reply) ====='
$frompe = @($evs | Where-Object { $_.Sum -match '192\.168\.100\.2\s*>\s*192\.168\.100\.1' -or $_.Sum -match 'echo reply' })
if ($frompe.Count -eq 0) { Add '  (无: 整个窗口 VM 一帧都没发出来/没回到主机)' }
else { $frompe | Select-Object -First 15 | ForEach-Object { Add ('  ' + $_.Dir + ' comp=' + $_.Comp + ' | ' + ($_.Sum -replace '\s+', ' ')) } }

Add ''
Add '===== C. 包摘要去重(每类只留一条) ====='
foreach ($k in @($evs | Select-Object -ExpandProperty Kind | Sort-Object -Unique)) {
  $one = ($evs | Where-Object { $_.Kind -eq $k } | Select-Object -First 1).Sum
  Add ('  ' + $k + ' -> ' + (($one -replace '\s+', ' ') -replace '^00-15-5D-\S+ ', ''))
}

Add ''
Add '===== D. VM 端点(component 153, WinPE-Test)上看到的方向计数 ====='
foreach ($g in @($evs | Where-Object { $_.Comp -eq '153' } | Group-Object Kind, Dir)) {
  Add ('  ' + ($g.Name -replace ', ', ' | ') + '  x' + $g.Count)
}
$any153 = @($evs | Where-Object { $_.Comp -eq '153' })
if ($any153.Count -eq 0) { Add '  (153 一次都没出现 —— 前面 A 表里的组件 ID 需要和 pktmon list 对齐再看)' }

$out = ($L -join "`r`n")
Set-Content -Path $OutFile -Value $out -Encoding UTF8
Add ('WROTE ' + $OutFile)
