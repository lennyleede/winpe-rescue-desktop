# ============================================================
# NetDrvLib.ps1 —— 段感知(section-aware)的网卡 INF 解析库, 给 18_/19_/20_ 共用。
#
# 为什么要有"段感知": 官方语法 (learn: INF Manufacturer Section)
#   NT[Architecture][.[OSMajor][.[OSMinor][.[ProductType][.[SuiteMask][.[BuildNumber]]]]]
# 安装器只会挑"不超过当前系统的最高档位"那一个 model support 段, 而且
#   "想把某个 OS 版本显式排除, 就写一个空的 Models 段"  —— 不向低档回落。
# 所以扫 INF 全文收集硬件 ID(老 17_ 的做法)是虚高的: 2026-10-08 VMware 实测就是
#   e1q63x64 生效段 [Intel.NTamd64.6.3] 全空, DEV_10D3 只在低档段里 -> drvload rc=0
#   但设备停在 code18, 物理网卡 0 块。
#
# 对外只有一个函数: Get-NetDrvPool(驱动目录) -> 每包的生效段/可绑ID/够不到ID + 全局索引
# 本库不写任何文件。
# ============================================================

if (-not (Get-Variable -Name NetDrvLibLoaded -Scope Global -EA SilentlyContinue)) { $global:NetDrvLibLoaded = $true }

# ---------- INF 文本读取(UTF-16LE 带 BOM 为主, 也兼容 ANSI/UTF-8) ----------
function Get-InfText([string]$path) {
  $b = [IO.File]::ReadAllBytes($path)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2) }
  if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($b, 3, $b.Length - 3) }
  return [Text.Encoding]::Default.GetString($b)
}

# ---------- 把 INF 拆成 段名 -> 行数组 (已并续行/去整行注释) ----------
function Parse-Sections([string]$txt) {
  $raw = $txt -replace "`r", ''
  $phys = $raw -split "`n"
  $joined = New-Object System.Collections.Generic.List[string]
  $buf = ''
  foreach ($l in $phys) {
    $t = $l.TrimEnd()
    if ($t -match '\\\s*$') { $buf += $t.Substring(0, $t.Length - 1); continue }
    if ($buf) { $joined.Add($buf + $t); $buf = '' } else { $joined.Add($t) }
  }
  if ($buf) { $joined.Add($buf) }

  $secs = @{}
  $cur = $null
  foreach ($l in $joined) {
    if ($l -match '^\s*\[([^\]]+)\]') {
      $cur = $Matches[1].Trim()
      if (-not $secs.ContainsKey($cur)) { $secs[$cur] = New-Object System.Collections.Generic.List[string] }
      continue
    }
    if (-not $cur) { continue }
    $t = $l.Trim()
    if (-not $t -or $t.StartsWith(';')) { continue }
    $secs[$cur].Add($t)
  }
  return $secs
}

# ---------- [Strings] 变量表(有些 INF 把 ID 写成 %VAR%) ----------
function Parse-Strings($secs) {
  $tbl = @{}
  foreach ($k in $secs.Keys) {
    if ($k -notmatch '^(Strings(\..*)?|Localizable.*)$') { continue }
    foreach ($l in $secs[$k]) {
      $m = [regex]::Match($l, '^([^=]+?)\s*=\s*(.*)$')
      if ($m.Success) {
        $v = $m.Groups[2].Value.Trim()
        if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) { $v = $v.Substring(1, $v.Length - 2) }
        $tbl[$m.Groups[1].Value.Trim().ToUpper()] = $v
      }
    }
  }
  return $tbl
}
function Resolve-Str([string]$s, $tbl) {
  if (-not $s) { return $s }
  $s = $s.Trim()
  $guard = 0
  while ($s -match '^%([^%]+)%$' -and $guard -lt 3) {
    $k = $Matches[1].ToUpper()
    if ($tbl.ContainsKey($k)) { $s = $tbl[$k] } else { break }
    $guard++
  }
  return $s
}

# ---------- 一档装饰 -> (架构, major, minor, ProductType, Suite, Build) ----------
#   NTamd64.10.0...17763  = amd64 / 10.0 / PT空 / Suite空 / 最低 build 17763
#   NTamd64.10.0.1..17763 = 同上但 ProductType=1(VER_NT_WORKSTATION)
#   NTamd64.6.2.1         = 6.2 + ProductType=1  (不是"6.2.1 版本"!)
function Split-Deco([string]$base, [string]$sec) {
  if ($sec -eq $base) { return @{ arch = ''; maj = -1; min = -1; pt = -1; suite = -1; build = -1 } }
  $parts = $sec.Substring($base.Length + 1) -split '\.'
  $arch = ''
  $nums = @()
  foreach ($p in $parts) {
    if (-not $arch) {
      if ($p -match '^(NT|NTamd64|NTia64|NTx86|NTarm|NTarm64)$') { $arch = $p; continue }
      return $null
    }
    $nums += $p
  }
  function N($i) { if ($i -lt $nums.Count) { $v = 0; if ([int]::TryParse($nums[$i], [ref]$v)) { return $v } }; return -1 }
  return @{ arch = $arch; maj = N(0); min = N(1); pt = N(2); suite = N(3); build = N(4) }
}

# 该档在当前系统上是否适用
function Test-Deco($info, [string]$arch, [int]$cMaj, [int]$cMin, [int]$cBuild, [int]$cPt) {
  if ($info.arch -ne $arch -and $info.arch -ne 'NT' -and $info.arch -ne '') { return $false }
  if ($info.maj -lt 0) { return $true }                       # 只写了 NTamd64, 不限版本
  $cur = $cMaj * 100 + $cMin; $dec = $info.maj * 100 + $info.min
  if ($cur -lt $dec) { return $false }
  if ($info.pt -ge 0 -and $info.pt -ne $cPt) { return $false } # 指定了 ProductType 就必须匹配
  if ($cur -eq $dec -and $info.build -ge 0 -and $cBuild -lt $info.build) { return $false }
  return $true
}

# 多档适用时的优先级: 版本高者优先; 同版本里限定更具体/下限 build 更高者优先
function Get-DecoSortKey($info) {
  $v = 0
  if ($info.maj -ge 0) { $v = $info.maj * 100 + [math]::Max(0, $info.min) }
  $spec = 0
  if ($info.pt -ge 0) { $spec += 2 }
  if ($info.suite -ge 0) { $spec += 1 }
  $b = if ($info.build -ge 0) { $info.build } else { 0 }
  return ($v * 1000000000 + $spec * 100000 + $b)
}

# ---------- 选出生效段 ----------
function Select-ModelSection($secs, [string]$base, [string[]]$decos, [string]$arch, [int]$cMaj, [int]$cMin, [int]$cBuild, [int]$cPt) {
  $cands = @()
  foreach ($d in $decos) {
    if ($d -eq $base) { continue }
    $sec = $base + '.' + $d
    if (-not $secs.ContainsKey($sec)) { continue }
    $info = Split-Deco $base $sec
    if ($null -eq $info) { continue }
    if (-not (Test-Deco $info $arch $cMaj $cMin $cBuild $cPt)) { continue }
    $cands += , @{ sec = $sec; key = (Get-DecoSortKey $info) }
  }
  if ($cands.Count -gt 0) {
    # 只有一个候选时 Sort-Object 会拆成单个 hashtable, 那时 [-1] 会被当成"取键 -1" -> $null
    $sorted = @($cands | Sort-Object -Property @{ Expression = { $_.key } })
    return $sorted[-1].sec
  }
  if ($secs.ContainsKey($base)) { return $base }               # 没有适用档 -> 用未装饰段
  return $null
}

# ---------- 从 model support 段里抽硬件 ID ----------
function Get-IdsFromSection($lines, $tbl) {
  $ids = @()
  foreach ($l in $lines) {
    $ci = $l.IndexOf(';')                       # 行尾注释: 截到第一个 ';' 之前
    $body = if ($ci -ge 0) { $l.Substring(0, $ci) } else { $l }
    $parts = $body -split ','
    if ($parts.Count -lt 2) { continue }
    $tail = $parts[1..($parts.Count - 1)] | ForEach-Object { Resolve-Str $_ $tbl }
    foreach ($t in $tail) {
      $tt = $t.Trim()
      if ($tt -match '^(PCI|USB|ACPI|ROOT|ISAPNP|HDAUDIO|REPLACED)\b') { $ids += $tt.ToUpper() }
    }
  }
  return ($ids | Where-Object { $_ } | Sort-Object -Unique)
}

# ---------- 归一: PCI\VEN_xxxx&DEV_yyyy[&SUBSYS_*|&REV_*|&CC_*] -> 基础 ID ----------
#   &CC_0106 是 INF 侧的"按类别码限定匹配"写法(Intel 存储包整片都这么写: iaAHCIC 30 个 ID、
#   iaStorB/iaStorT 各 7 个全带 &CC_)。设备实机枚举出来的 PnP 实例ID 里**没有** CC 段
#   (只有 &SUBSYS/&REV), 所以归一必须把 &CC_ 一起剥掉, 否则 Test-PciBaseId 判它不合法,
#   这批 ID 会整族静默消失 —— 2026-10-08 存储池 21 个 ID 只剩 9 个就是这个原因(不是"段不适用")。
function Get-BaseId([string]$id) { return (($id -split '&SUBSYS|&REV|&CC')[0]).ToUpper() }

# ---------- 归一: USB\VID_xxxx&PID_yyyy[&REV_*|&MI_*|&SUBSYS_*] -> 基础 ID ----------
#   USB 网卡(含复合设备的 function)在设备管理器里是 USB\VID_x&PID_y&REV_z 或 ...&MI_00,
#   INF 里一般只写到 VID&PID, 所以运行时查表也要按这个口径归一。
function Get-UsbBaseId([string]$id) { return (($id -split '&REV|&MI|&SUBSYS')[0]).ToUpper() }
function Test-PciBaseId([string]$k) { return ($k -match '^PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}$') }
function Test-UsbBaseId([string]$k) { return ($k -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}$') }

# ---------- 驱动包里的 .sys/.cat 体积(MB), 判断"补这个包要多大代价" ----------
function Get-PkgSizeMb([string]$infPath) {
  $dir = Split-Path -Parent $infPath
  $sum = 0
  try {
    $sum = (Get-ChildItem -LiteralPath $dir -File -EA SilentlyContinue |
            Where-Object { $_.Extension -in '.sys', '.cat', '.dll', '.inf', '.din', '.mui' } |
            Measure-Object Length -Sum).Sum
  } catch {}
  if (-not $sum) { $sum = 0 }
  return [math]::Round($sum / 1MB, 2)
}

# ---------- DriverVer 里的日期, 用于"同芯片取最新" ----------
function Get-DriverVerDate([string]$dv) {
  if (-not $dv) { return [datetime]::MinValue }
  $parts = $dv -split ','
  foreach ($fmt in @('MM/dd/yyyy', 'dd/MM/yyyy', 'M/d/yyyy', 'd/M/yyyy', 'yyyy/MM/dd', 'yyyy-MM-dd')) {
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParseExact($parts[0].Trim(), $fmt, [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$parsed)) { return $parsed }
  }
  return [datetime]::MinValue
}

# ============================================================
# Get-NetDrvPool: 扫一个驱动目录, 返回每包在本 PE 上的可绑情况 + 全局"ID -> 包"索引
#   .Rows  每包: Pkg Cls DriverVer VerDate MB Secs SecPath Dir Ids PciIds UsbIds ShadowIds Shadow N NU Dead
#   .Idx   @{ 'PCI\VEN_x&DEV_y' = @{ '包名.inf' = 1 } }   (只登记生效段里的 ID)
#   .UsbIdx @{ 'USB\VID_x&PID_y' = @{ '包名.inf' = 1 } }  (同一口径, USB 网卡)
#   .Decl  @{ 基础ID = @{池内声明过该 ID 的包名...} }      (含低档段: 用来区分"真缺"和"只有老段")
#   .AllPci 池内出现过的所有基础 PCI ID 集合
# ============================================================
function Get-NetDrvPool {
  param(
    [Parameter(Mandatory = $true)][string]$DrvDir,
    [string]$Arch = 'NTamd64',
    [string]$OsVer = '10.0',
    [int]$Build = 26100,
    [int]$ProductType = 1,      # 1=VER_NT_WORKSTATION(PE 按客户端算), 3=Server
    [string[]]$ClassName = @('Net')
  )
  $TargetOs = [version]$OsVer
  $cMaj = $TargetOs.Major; $cMin = $TargetOs.Minor
  # -File 必须加: -Filter '*.inf' 走 8.3 短名匹配, 名字里带 ".inf_xxx" 的**目录**也会被捞进来(29b_ 就是来治这个的)
  $infs = @(Get-ChildItem $DrvDir -Recurse -Filter '*.inf' -File -EA SilentlyContinue | Sort-Object FullName)
  $rows = @()
  foreach ($fi in $infs) {
    try { $txt = Get-InfText $fi.FullName } catch { continue }
    $secs = Parse-Sections $txt
    $tbl  = Parse-Strings $secs
    $cls = ''; $dver = ''
    if ($secs.ContainsKey('Version')) {
      foreach ($l in $secs['Version']) {
        if ($l -match '^Class\s*=\s*(.+)$')     { $cls = $Matches[1].Trim().Trim('"', '%').Trim() }
        if ($l -match '^DriverVer\s*=\s*(.+)$') { $dver = $Matches[1].Trim() }
      }
    }
    if ($ClassName -and $ClassName.Count -gt 0 -and $ClassName -notcontains $cls) { continue }

    $mfgName = @($secs.Keys | Where-Object { $_ -match '^(Manufacturer|Manufacturer\..*)$' })
    $chosen = @()          # 本 PE 上真正生效的 model support 段
    $bases  = @()
    foreach ($mk in $mfgName) {
      foreach ($l in $secs[$mk]) {
        $m = [regex]::Match($l, '^([^=]+?)\s*=\s*([^,]+?)\s*(?:,\s*(.*))?$')
        if (-not $m.Success) { continue }
        $base = $m.Groups[2].Value.Trim()
        $bases += $base
        $decoList = @($base)
        if ($m.Groups[3].Value) { $decoList = @($m.Groups[3].Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        $sel = Select-ModelSection $secs $base $decoList $Arch $cMaj $cMin $Build $ProductType
        if ($sel) { $chosen += $sel } else { $chosen += ('(无适用段)' + $base) }
      }
    }
    $bases = @($bases | Sort-Object -Unique)

    $liveRaw = @()
    foreach ($c in ($chosen | Where-Object { $secs.ContainsKey($_) })) { $liveRaw += Get-IdsFromSection $secs[$c] $tbl }
    $live    = @($liveRaw | Where-Object { $_ -match '^PCI\\VEN_' } | Sort-Object -Unique)
    $liveUsb = @($liveRaw | Where-Object { $_ -match '^USB\\VID_' } | Sort-Object -Unique)
    # 够不到的 ID = 同包其它档位段里有、生效段里没有
    $other = @()
    foreach ($k in $secs.Keys) {
      foreach ($b in $bases) {
        if ($k -eq $b -or $k.StartsWith($b + '.')) {
          if ($chosen -notcontains $k) { $other += Get-IdsFromSection $secs[$k] $tbl }
        }
      }
    }
    $otherPci = @($other | Where-Object { $_ -match '^PCI\\VEN_' } | Sort-Object -Unique)
    $shadow   = @($otherPci | Where-Object { $live -notcontains $_ })

    # 无线判定(信息用, 不影响 ID 统计): INF 里写了 802.11 设备描述/IfType=71 的都是 WiFi 或 WWAN,
    # 本次"万能有线网卡"阶段不往里塞, 但清单里要看得见, 免得把它们当有线缺口算。
    $isWifi = ($txt -match '(?i)Wireless|Wi-Fi|\b802\.11\b|WLAN|Bluetooth|Mobile Broadband|WWAN|Virtual\s?NIC') -or ($txt -match '(?i)\*IfType\s*=\s*71')

    $rows += [pscustomobject]@{
      Pkg       = $fi.Name
      PkgLower  = $fi.Name.ToLower()
      Dir       = (Split-Path -Parent $fi.FullName)
      InfPath   = $fi.FullName
      Cls       = $cls
      Wifi      = $isWifi
      DriverVer = $dver
      VerDate   = (Get-DriverVerDate $dver)
      MB        = (Get-PkgSizeMb $fi.FullName)
      Secs      = $chosen
      Sec       = ($chosen -join ' | ')
      N         = $live.Count
      NU        = $liveUsb.Count
      Shadow    = $shadow.Count
      Ids       = @($live + $liveUsb)
      PciIds    = $live
      UsbIds    = $liveUsb
      ShadowIds = $shadow
      AllPciRaw = @($live + $otherPci)          # 声明过(不分档位)的全部 PCI ID
      Dead      = ($live.Count -eq 0 -and $liveUsb.Count -eq 0)
    }
  }

  $idx = @{}; $decl = @{}; $usbIdx = @{}
  foreach ($r in $rows) {
    foreach ($id in $r.PciIds) {
      $k = Get-BaseId $id
      if (-not (Test-PciBaseId $k)) { continue }
      if (-not $idx.ContainsKey($k)) { $idx[$k] = @{} }
      $idx[$k][$r.PkgLower] = 1
    }
    foreach ($id in $r.UsbIds) {
      $k = Get-UsbBaseId $id
      if (-not (Test-UsbBaseId $k)) { continue }
      if (-not $usbIdx.ContainsKey($k)) { $usbIdx[$k] = @{} }
      $usbIdx[$k][$r.PkgLower] = 1
    }
    foreach ($id in $r.AllPciRaw) {
      $k = Get-BaseId $id
      if (-not (Test-PciBaseId $k)) { continue }
      if (-not $decl.ContainsKey($k)) { $decl[$k] = @{} }
      $decl[$k][$r.PkgLower] = 1
    }
  }
  return @{
    Dir    = $DrvDir
    Rows   = $rows
    Idx    = $idx          # 可绑索引(段感知)
    UsbIdx = $usbIdx       # 可绑 USB 网卡索引(段感知)
    Decl   = $decl         # 声明过的 ID(含低档段)
    AllPci = @($decl.Keys)
    AllUsb = @($usbIdx.Keys)
  }
}
