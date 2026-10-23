# 从 D:\winpe_build\hotpe_net 里挑出"万能网卡驱动"精简集, 拷进 overlay\Drivers\Net 供 build.ps1 [4x] 注入 boot.wim
# 普通权限即可运行(源目录只读, 目标在本项目 D: 内)
# 用法:
#   预览体积/清单:  powershell -NoProfile -ExecutionPolicy Bypass -File test\15_CollectNetDrivers.ps1 -DryRun
#   正式产出:       powershell -NoProfile -ExecutionPolicy Bypass -File test\15_CollectNetDrivers.ps1
#   自检:           powershell -NoProfile -ExecutionPolicy Bypass -File test\15_CollectNetDrivers.ps1 -SelfTest
#   以后做 WiFi:    ... -File test\15_CollectNetDrivers.ps1 -Sections Lan,Wlan -IncludeWifi -OutName Net
param(
  [string]$Source  = 'D:\winpe_build\hotpe_net',
  [string[]]$Sections = @('Lan'),
  [string]$OutName = 'Net',
  [switch]$KeepServer,      # 默认剔除 40G/服务器/虚拟化网卡(救援场景用不到, 省体积)
  [switch]$IncludeWifi,     # 默认跳过无线 INF(WinPE 里没 wlansvc 时装了也不干活, 留给 WiFi 阶段)
  [switch]$DryRun,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$Out  = Join-Path $root ("overlay\Drivers\" + $OutName)

# 服务器/数据中心/虚拟网卡家族: 给"别人的电脑"做运维用不到, 且是大头
$serverPrefixes = @('i40e','ice','iavf','ixn','ixs','ixt','ixw','sxa','sxb','scea','sceb','v1q','v40e','vxn','vxs','vmxnet','netvsc','cnicdriver')

function Get-InfInfo([System.IO.FileInfo]$fi) {
  $path = $fi.FullName
  $txt = ''
  try { $txt = Get-Content -LiteralPath $path -Raw -ErrorAction Stop } catch { return $null }
  if (-not $txt) { return $null }
  # 架构: PE 是 amd64, 只收带 NTamd64/amd64 的包(x86 包 DISM 会直接报错)
  if ($txt -notmatch '(?i)NTamd64|\bamd64\b') { return $null }
  if ($txt -match '(?im)^\s*Class\s*=\s*(\S+)') { $cls = $Matches[1].Trim('"', ' ', '%') } else { $cls = '' }
  $dv = [datetime]::MinValue; $ver = '0.0'
  if ($txt -match '(?im)^\s*DriverVer\s*=\s*([^;\r\n]+)') {
    $parts = $Matches[1] -split ','
    foreach ($fmt in @('MM/dd/yyyy', 'dd/MM/yyyy', 'M/d/yyyy', 'd/M/yyyy')) {
      $parsed = [datetime]::MinValue
      if ([datetime]::TryParseExact($parts[0].Trim(), $fmt, [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$parsed)) { $dv = $parsed; break }
    }
    if ($parts.Count -gt 1) { $ver = $parts[1].Trim() }
  }
  # 无线网卡判定: *IfType=71(IEEE80211) 或 NdisPhysicalMedium802_11
  $wifi = ($txt -match '(?i)\*\s*IfType\s*=\s*71\b' -or $txt -match '(?i)NdisPhysicalMedium802_11')
  # 这个包到底要哪些文件由 [SourceDisksFiles] 段说了算 —— 整目录拷会把 Killer 那 146MB(WiFi 固件+Killer 助手 exe)一起背进来
  $files = New-Object System.Collections.Generic.List[string]
  if ($txt -match '(?sim)\[SourceDisksFiles\](.*?)(\r?\n\[|$)') {
    foreach ($line in ($Matches[1] -split "\r?\n")) {
      $l = $line.Trim()
      if (-not $l -or $l.StartsWith(';') -or $l -notmatch '=') { continue }
      $f = (($l -split '=')[0]).Trim().Trim('"')
      if ($f -and $f -notmatch '\$') { $files.Add($f) }
    }
  }
  # DriverVer 的版本号是字符串, 直接按串排会出 "1.5 > 1.40" 这种错; 能解析成 Version 就按数值排
  $vkey = [version]'0.0'
  [void][version]::TryParse($ver, [ref]$vkey)
  return [pscustomobject]@{
    Inf = $path; Name = $fi.Name; Base = [IO.Path]::GetFileNameWithoutExtension($fi.Name)
    Dir = $fi.Directory.FullName; Class = $cls; Date = $dv; Version = $ver; VKey = $vkey
    Devs = ([regex]::Matches($txt, '(?i)&DEV_[0-9A-Fa-f]{4}')).Count; Wifi = $wifi; Files = @($files)
  }
}

function Get-DirFileMap([string]$dir) {
  $map = @{}
  foreach ($it in @(Get-ChildItem $dir -Recurse -File -EA SilentlyContinue)) {
    $rel = $it.FullName.Substring($dir.Length + 1).TrimStart('\')
    $map[$rel.ToLower()] = $it.FullName
    if (-not $map.ContainsKey($it.Name.ToLower())) { $map[$it.Name.ToLower()] = $it.FullName }
  }
  return $map
}

function Resolve-DirPackage([string]$dir, $infsInDir, $map) {
  # 一个源目录 = 一个目标包(同目录的多个 INF 共用文件, 不重复拷)。
  # 只拷"被保留的 INF 文本点过名"的文件: 驱动包真正要什么文件由 [SourceDisksFiles](有的厂商根本不写)、
  # AddService 的服务名、%Strings% 里的 dll 名共同决定, 而这些名字都会原样出现在 INF 文本里 —— 按名字命中
  # 比整目录拷精准得多(Killer 那个目录 146MB 里大半是同包进来的 WiFi 固件和 Killer 助手 exe)。
  $text = ''
  foreach ($k in $infsInDir) { $text += (Get-Content -LiteralPath $k.Inf -Raw) }
  $lower = $text.ToLower()
  $keepRel = New-Object System.Collections.Generic.List[string]
  $own = @{}
  foreach ($k in $infsInDir) { $own[$k.Name.ToLower()] = 1 }
  foreach ($rel in ($map.Keys | Sort-Object { $_.Length })) {
    $src = $map[$rel]
    $name = [IO.Path]::GetFileName($rel)
    $ln = $name.ToLower()
    if ($own.ContainsKey($ln)) { $keepRel.Add($rel); continue }                       # 保留的 INF 本身
    if ($name -match '(?i)\.cat$' -and $lower.Contains($ln)) { $keepRel.Add($rel); continue }  # 签名目录
    $stem = [IO.Path]::GetFileNameWithoutExtension($rel)
    if ($stem.Length -lt 3) { continue }
    if ($lower -match ('(?i)(^|[^0-9a-z_])' + [regex]::Escape($stem) + '([^0-9a-z_]|$)')) {
      # 名字被 INF 提到过; 顺带按后缀排除非驱动杂物(安装包/文档/WiFi 固件)
      $ext = [IO.Path]::GetExtension($ln)
      if ($ext -notin @('.exe', '.msi', '.zip', '.pdf', '.txt', '.htm', '.html', '.lnk', '.png', '.jpg', '.gif', '.chm')) { $keepRel.Add($rel) }
    }
  }
  $dedup = @{}; $list = New-Object System.Collections.Generic.List[object]; $bytes = 0L
  foreach ($rel in $keepRel) {
    $src = $map[$rel]
    if ($dedup.ContainsKey($src)) { continue }
    $dedup[$src] = 1
    $len = (Get-Item -LiteralPath $src).Length
    $bytes += $len
    $list.Add([pscustomobject]@{ Rel = $rel; Src = $src; Size = $len })
  }
  $res = @{}
  $res['List'] = $list.ToArray()
  $res['Bytes'] = $bytes
  return $res
}

if ($SelfTest) {
  Write-Host '=== SelfTest: 只验证源目录和过滤规则能跑通, 不写任何文件 ===' -ForegroundColor Cyan
  if (-not (Test-Path $Source)) { Write-Host "源目录不存在: $Source" -ForegroundColor Red; exit 1 }
  $n = 0
  foreach ($s in $Sections) {
    $dir = Join-Path $Source $s
    if (-not (Test-Path $dir)) { Write-Host "  跳过不存在的分区: $dir" -ForegroundColor Yellow; continue }
    $c = @(Get-ChildItem $dir -Recurse -Filter '*.inf' -File -EA SilentlyContinue).Count
    Write-Host ("  {0}: {1} 个 INF" -f $s, $c)
    $n += $c
  }
  Write-Host ("  规则: 只留 Class=Net + NTamd64; 同名 INF 取最新 DriverVer; 剔服务器/虚拟 {0}; 跳无线 {1}" -f `
    $(if ($KeepServer) { '(关)' } else { '(开)' }), $(if ($IncludeWifi) { '(关)' } else { '(开)' }))
  $probe = @(Get-ChildItem (Join-Path $Source 'Lan') -Recurse -Filter '*.inf' -File | Select-Object -First 1)
  if ($probe) {
    $p = Get-InfInfo $probe[0]
    Write-Host ('  解析探针: ' + $probe[0].Name + ' -> Class=' + $p.Class + ' DriverVer=' + $p.Date.ToString('yyyy-MM-dd') + ' 包内文件 ' + $p.Files.Count + ' 个')
  }
  Write-Host ("SelfTest OK (共 {0} 个 INF 待解析)" -f $n) -ForegroundColor Green
  exit 0
}

Write-Host ('=== 1. 扫描 ' + $Source + ' ===') -ForegroundColor Cyan
$all = New-Object System.Collections.Generic.List[object]
$skip = @{ nonet = 0; x86 = 0; wifi = 0 }
foreach ($s in $Sections) {
  $dir = Join-Path $Source $s
  if (-not (Test-Path $dir)) { Write-Host "  !! 分区不存在: $dir" -ForegroundColor Red; continue }
  foreach ($fi in @(Get-ChildItem $dir -Recurse -Filter '*.inf' -File)) {
    $info = Get-InfInfo $fi
    if (-not $info) { $skip.x86++; continue }
    if ($info.Class -ne 'Net') { $skip.nonet++; continue }
    if ($info.Wifi -and -not $IncludeWifi) { $skip.wifi++; continue }
    $info | Add-Member -NotePropertyName Section -NotePropertyValue $s -Force
    $all.Add($info)
  }
}
Write-Host ('  Class=Net 且 x64 的 INF: ' + $all.Count + '  (非 Net ' + $skip.nonet + ' / x86或解析失败 ' + $skip.x86 + ' / 无线 ' + $skip.wifi + ')')

Write-Host '=== 2. 同名 INF 只留最新 DriverVer, 剔掉服务器/虚拟网卡家族 ===' -ForegroundColor Cyan
$keep = New-Object System.Collections.Generic.List[object]
foreach ($g in ($all | Group-Object { $_.Name })) {
  $best = $g.Group | Sort-Object Date, VKey, Version -Descending | Select-Object -First 1
  if (-not $KeepServer) {
    foreach ($p in $serverPrefixes) { if ($g.Name -like ($p + '*')) { $best = $null; break } }
  }
  if ($best) { $keep.Add($best) }
}
Write-Host ('  保留 ' + $keep.Count + ' 个驱动包')

Write-Host '=== 3. 按源目录归并驱动包, 只拷被 INF 引用的文件 ===' -ForegroundColor Cyan
$pkgs = New-Object System.Collections.Generic.List[object]
$totalBytes = 0L
foreach ($g in (@($keep | Group-Object Dir) | Sort-Object Name)) {
  $rel = $g.Name.Substring($Source.Length + 1) -replace '[\\/:*?"<>|]', '_'
  $r = Resolve-DirPackage $g.Name @($g.Group) (Get-DirFileMap $g.Name)
  $totalBytes += $r.Bytes
  $pkgs.Add([pscustomobject]@{ Dir = $g.Name; Rel = $rel; Infs = @($g.Group); List = $r.List; MB = ($r.Bytes / 1MB) })
}
Write-Host ('  源目录 ' + $pkgs.Count + ' 个 / INF ' + $keep.Count + ' 个, 合计 ' + ('{0:N1} MB' -f ($totalBytes / 1MB)))

if ($DryRun) {
  Write-Host '=== DryRun: 到此为止, 没有写文件 ===' -ForegroundColor Yellow
  $pkgs | Select-Object @{n = 'MB'; e = { '{0:N2}' -f $_.MB }}, @{n = 'INF数'; e = { $_.Infs.Count }},
    @{n = '文件数'; e = { $_.List.Count }}, @{n = 'INF'; e = { (($_.Infs | ForEach-Object { $_.Name }) -join ' ') }},
    @{n = '源目录'; e = { $_.Dir.Replace($Source + '\', '') }} |
    Sort-Object { [double]($_.MB -replace ',', '') } -Descending | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
  exit 0
}

Write-Host ('=== 4. 拷到 ' + $Out + ' ===') -ForegroundColor Cyan
if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$manifest = New-Object System.Collections.Generic.List[string]
$infs = New-Object System.Collections.Generic.List[string]
$manifest.Add("inf`tMB`tdriverver`tdev数`t源目录`t目标目录")
$empty = 0
foreach ($pk in $pkgs) {
  $dst = Join-Path $Out $pk.Rel
  New-Item -ItemType Directory -Path $dst -Force | Out-Null
  foreach ($it in $pk.List) {
    $to = Join-Path $dst ($it.Rel -replace '/', '\')
    $parent = Split-Path -Parent $to
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Copy-Item -LiteralPath $it.Src -Destination $to -Force
  }
  foreach ($k in $pk.Infs) {
    $infs.Add((Join-Path $pk.Rel $k.Name))
    $manifest.Add(($k.Name + "`t" + ('{0:N2}' -f $pk.MB) + "`t" + $k.Date.ToString('yyyy-MM-dd') + "`t" + $k.Devs + "`t" + ($pk.Dir -replace '^.*hotpe_net\\', '') + "`t" + $pk.Rel))
  }
  $bin = @($pk.List | Where-Object { $_.Rel -notmatch '(?i)\.(inf|cat)$' }).Count
  if ($bin -eq 0) { $empty++; Write-Host ('  !! ' + $pk.Rel + ' 一个二进制都没匹配上, DISM 会拒绝这个包') -ForegroundColor Yellow }
}
# build.ps1 只按这份清单逐个 /Add-Driver: 整目录 /Recurse 会把包里顺带拷进来的旧系统/x86 子 INF 也塞给 DISM, 那会报错
$infs | Set-Content -LiteralPath (Join-Path $Out 'inf-list.txt') -Encoding UTF8
$mfPath = Join-Path $root ("build\scratch\drivers_" + $OutName + "_manifest.txt")
New-Item -ItemType Directory -Path (Split-Path -Parent $mfPath) -Force | Out-Null
($manifest | Sort-Object) | Set-Content -LiteralPath $mfPath -Encoding UTF8

Write-Host ('  完成: ' + $pkgs.Count + ' 个包 / ' + $infs.Count + ' 个 INF / ' + ('{0:N1} MB' -f ((@(Get-ChildItem $Out -Recurse -File) | Measure-Object Length -Sum).Sum / 1MB))) -ForegroundColor Green
Write-Host ('  注入清单: ' + (Join-Path $Out 'inf-list.txt'))
Write-Host ('  明细清单: ' + $mfPath)
if ($empty -gt 0) { Write-Host ('  !! 有 ' + $empty + ' 个包没匹配到二进制, 见上面的告警') -ForegroundColor Yellow }
Write-Host '=== 5. 下一步 ===' -ForegroundColor Cyan
Write-Host '  管理员 PowerShell 重构建即可, build.ps1 的 [4x] 会把本目录注入 boot.wim:'
Write-Host ('    powershell -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $root 'test\10_RebuildAndSwap.ps1') + '"')
