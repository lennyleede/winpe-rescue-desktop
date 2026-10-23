# ============================================================
# test\20_MakeVWifiPool.ps1 —— 在宿主机上准备 overlay\VWiFi(原生 WiFi 过滤栈素材)
#
# 为什么需要这一步(2026-10-09 现场结论, probe33~40):
#   PE 里 Intel/Realtek 无线网卡能被 drvload 装上, 但设备最终停在 code 37 / 0xC00000BB,
#   setupapi 每次都说 "Needed section [VWiFiBus] / [VWiFiBus.CopyFiles] /
#   [VWiFiBus.PnPFilterRegistration] not found, might exist in missing included INF" ——
#   因为 ADK 的 WinPE 组件包(33 个 cab)里根本没有原生 WiFi 栈, 而网卡的 INF 用
#   Include=netvwifibus.inf + Needs=VWiFiBus.* 去引用它。
#   所有"开机后再补"的路子都实测死了:
#     pnputil /add-driver  -> 0xE000020F "The third-party INF does not contain digital signature information"
#     drvload netvwifibus.inf -> 0xE000022F;  drvload vwifibus.sys -> 0x80070002
#     SetupCopyOEMInfW     -> 0xE000020F
#     手写 Upper/LowerFilters + pnputil /restart-device -> 仍是 code 37, setupapi 零新增行
#     NtLoadDriver         -> 见下面 2026-10-10 的更正
#   根因: PE 不跑 catroot2/CryptSvc, 运行时的 catalog 数据库建不起来, 所以任何"验微软 INF 签名"
#   的动作都判成"没有签名信息"; 而 %windir%\INF 的索引在开机时就定死了, 开机后再拷 INF 也解析不了。
#   => 只能离线烘进镜像: INF 进 Windows\INF + DriverStore, .sys 进 System32\drivers,
#      覆盖它们的 .cat 进 CatRoot, 服务键进 SYSTEM 配置单元(services.exe 开机才认)。
#
# 2026-10-10 更正 + 扩容(probe78/79/80/81, 证据 build\scratch\p7x_raw.txt / p8x_raw.txt):
#   1) 当年那条"NtLoadDriver 对这台 PE 的每个驱动都返回 0x80000002, 所以没有判别力"是**我们自己的
#      bug**: NtLoadDriver 收的是 PUNICODE_STRING, probe78 按字符串指针传参才会全部对齐错误。
#      probe79 用结构体正确传参后内核给的是真答案: 六个目标全 0xC0000061 PRIVILEGE_NOT_HELD
#      (即便 RtlAdjustPrivilege 报 OK —— 顺带纠正: SeLoadDriverPrivilege 的 LUID 低位是 10,
#       probe74 用的 19 其实是 SeShutdownPrivilege)。=> 运行时补驱动在这台 PE 确实不可行, 结论不变。
#   2) code 37 的主因不止 vWiFi 过滤栈: Netwtw14.sys 注册走的是 **WDI**(Windows 无线驱动框架)——
#      它从 ndis.sys 导入 NdisMRegisterWdiMiniportDriver, 而 ndis 只做转发, 实现者在 wdiwifi.sys。
#      probe81 扫了本机 D: 与镜像 X: 的全部 48 个无线包: 35 个 WDI, 唯一 CLASSIC 是 2013 年的
#      rtwlane_13; 声明 PCI\VEN_8086&DEV_7A70 的 6 个 INF 无一是经典 miniport。
#      => wdiwifi 不是"Intel 专属补丁", 而是整条 WiFi 腿的前提, 必须和 NdisImPlatform 一起烘进来。
#   3) 素材代次: 这台笔记本自己的 Windows(D:) 就是 19041 代(cmd.exe 10.0.19041.746,
#      wdiwifi 10.0.19041.2788 / NdisImPlatform 10.0.19041.546), 机上不存在 Win11 代副本;
#      宿主机 19041.7663 的 wdiwifi 由 Package04 目录覆盖(与 nwifi/vwififlt 同一份, 已实机证明
#      26100 PE 的代码完整性放行), NdisImPlatform 由 Package05112 覆盖 —— 下面的 crypt32 反查
#      会自动把它带进 overlay\Cats。
#
# 只读宿主机 C:\Windows, 只写本项目目录, 不需要管理员。
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\20_MakeVWifiPool.ps1 [-Dry]
# ============================================================
param(
  [string]$HostWin = 'C:\Windows',
  [string]$OutDir  = '',
  [string]$CatsDir = '',
  [switch]$Dry
)
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot | Split-Path -Parent          # ...\生成winpe
if (-not $OutDir)  { $OutDir  = Join-Path $Root 'overlay\VWiFi' }
if (-not $CatsDir) { $CatsDir = Join-Path $Root 'overlay\Cats' }

$infs = @('netvwifibus.inf', 'netvwififlt.inf', 'netvwifimp.inf', 'netnwifi.inf')
# 后两个 .sys 是 2026-10-10 加的 WDI 框架对: wdiwifi = NdisMRegisterWdiMiniportDriver 的真正实现者,
# NdisImPlatform = IM 过滤/内部虚拟 miniport 的宿主(nwifi/vwififlt 挂进协议栈要用)。
# 微软那边它们没有可分发的 INF 包(属于 OS 组件), 所以只烘 .sys + 服务键 + 覆盖 .cat 这一种形状。
$syss = @('vwifibus.sys', 'vwififlt.sys', 'vwifimp.sys', 'nwifi.sys', 'wdiwifi.sys', 'NdisImPlatform.sys')

function V([System.IO.FileInfo]$o) {
  $v = $o.VersionInfo
  return ($v.FileMajorPart.ToString() + '.' + $v.FileMinorPart + '.' + $v.FileBuildPart + '.' + $v.FilePrivatePart)
}

# ---------- 1. 找齐素材 ----------
$missing = @()
$items = @()
foreach ($i in $infs) {
  $p = Join-Path $HostWin ('INF\' + $i)
  if (-not (Test-Path $p)) { $missing += ('INF:' + $i); continue }
  $items += [pscustomobject]@{ Name = $i; Src = $p; Kind = 'inf' }
}
foreach ($s in $syss) {
  $p = Join-Path $HostWin ('System32\drivers\' + $s)
  if (-not (Test-Path $p)) { $missing += ('SYS:' + $s); continue }
  $items += [pscustomobject]@{ Name = $s; Src = $p; Kind = 'sys' }
}
Write-Host ('  素材: inf=' + (@($items | Where-Object { $_.Kind -eq 'inf' }).Count) + '/' + $infs.Count + '  sys=' +
           (@($items | Where-Object { $_.Kind -eq 'sys' }).Count) + '/' + $syss.Count)
foreach ($o in $items) {
  $fi = Get-Item $o.Src
  Write-Host ('    ' + ('{0,-16}' -f $o.Name) + ' ' + (V $fi) + '  ' + [int]($fi.Length / 1KB) + 'KB')
}
if ($missing.Count) { Write-Host ('  !! 宿主机缺: ' + ($missing -join ',')) -ForegroundColor Red }

# INF 没有 VersionInfo(全是 0.0.0.0), 版本和目录文件写在 [Version] 段里, 门禁要看的是这两行。
function InfMeta([string]$path) {
  $t = @(Get-Content $path -EA SilentlyContinue)
  $inVer = $false; $meta = @{}
  foreach ($l in $t) {
    if ($l -match '^\s*\[Version\]') { $inVer = $true; continue }
    if ($inVer) {
      if ($l -match '^\s*\[') { break }
      if ($l -match '^\s*(CatalogFile\w*)\s*=\s*(.+?)\s*$') { $meta[$matches[1]] = $matches[2] }
      if ($l -match '^\s*(DriverVer|Class|Provider)\s*=\s*(.+?)\s*$') { $meta[$matches[1]] = $matches[2] }
    }
  }
  return $meta
}
$infMeta = @{}
foreach ($o in @($items | Where-Object { $_.Kind -eq 'inf' })) {
  $m = InfMeta $o.Src
  $infMeta[$o.Name] = $m
  Write-Host ('    [Version] ' + ('{0,-16}' -f $o.Name) + ' ' + (($m.GetEnumerator() | Sort-Object Name | ForEach-Object { $_.Key + '=' + $_.Value }) -join ' '))
}

# ---------- 2. 覆盖这 4 个 .sys 的 .cat(crypt32 反查, 不扫字节) ----------
# 与 build\scratch\find_covering_catalog.ps1 同一套 API。扫 .cat 字节会假阴性(probe22 的教训)。
Add-Type -Language CSharp @'
using System;using System.Text;using System.Runtime.InteropServices;
public class CATQ20 {
  [DllImport("wintrust.dll", SetLastError=true)]
  public static extern bool CryptCATAdminAcquireContext2(out IntPtr h, ref Guid g, IntPtr a, IntPtr b, uint f);
  [DllImport("wintrust.dll", SetLastError=true)]
  public static extern bool CryptCATAdminReleaseContext(IntPtr h, uint f);
  [DllImport("wintrust.dll", SetLastError=true)]
  public static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hf, ref uint cb, byte[] pb, uint f);
  [DllImport("wintrust.dll", SetLastError=true)]
  public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr h, byte[] pb, uint cb, uint f, ref IntPtr prev);
  [DllImport("wintrust.dll", SetLastError=true)]
  public static extern bool CryptCATCatalogInfoFromContext(IntPtr ctx, byte[] info, uint f);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint fl, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  public static string Query(string path, Guid sub) {
    IntPtr admin;
    if (!CryptCATAdminAcquireContext2(out admin, ref sub, IntPtr.Zero, IntPtr.Zero, 0u)) return "ACQUIRE-FAIL " + Marshal.GetLastWin32Error();
    IntPtr hf = CreateFileW(path, 0x80000000u, 0x00000007u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
    if (hf == IntPtr.Zero || ((long)hf) == -1) { CryptCATAdminReleaseContext(admin, 0u); return "OPEN-FAIL " + Marshal.GetLastWin32Error(); }
    uint cb = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hf, ref cb, null, 0) || cb == 0) { CloseHandle(hf); CryptCATAdminReleaseContext(admin, 0u); return "CALC-FAIL"; }
    byte[] hash = new byte[cb]; uint cb2 = cb;
    if (!CryptCATAdminCalcHashFromFileHandle(hf, ref cb2, hash, 0)) { CloseHandle(hf); CryptCATAdminReleaseContext(admin, 0u); return "CALC2-FAIL"; }
    CloseHandle(hf);
    StringBuilder sb = new StringBuilder();
    IntPtr prev = IntPtr.Zero; int n = 0;
    while (true) {
      IntPtr ctx = CryptCATAdminEnumCatalogFromHash(admin, hash, (uint)hash.Length, 0u, ref prev);
      if (ctx == IntPtr.Zero) break;
      n++;
      byte[] info = new byte[4 + 2 * 260];
      BitConverter.GetBytes((uint)info.Length).CopyTo(info, 0);
      if (CryptCATCatalogInfoFromContext(ctx, info, 0u))
        sb.Append("|" + System.Text.Encoding.Unicode.GetString(info, 4, info.Length - 4).TrimEnd('\0'));
      if (n > 6) break;
    }
    CryptCATAdminReleaseContext(admin, 0u);
    if (n == 0) return "NO-CATALOG";
    return sb.ToString().TrimStart('|');
  }
}
'@
$stores = [ordered]@{
  'WinNTStore' = [Guid]'F750E6C3-38EE-11D1-85E5-00C04FC295EE'
  'DrvStore64' = [Guid]'45A8D7E8-57A7-45BB-A429-70F744020361'
  'Windows'    = [Guid]'C118A253-0BA4-4878-A1FF-8C7495C42F85'
}
$catNames = @()
$catRows = @()
foreach ($s in $syss) {
  $p = Join-Path $HostWin ('System32\drivers\' + $s)
  if (-not (Test-Path $p)) { continue }
  $row = ''
  foreach ($g in $stores.Keys) {
    $r = [CATQ20]::Query($p, $stores[$g])
    # 打日志只留猫名(全路径重复 7 遍没法读), 收集用 $catNames
    if ($r -notmatch 'FAIL' -and $r -ne 'NO-CATALOG') {
      $names = @(($r -split '\|' | ForEach-Object { ($_ -split '\\')[-1].Trim() }) | Where-Object { $_ } | Sort-Object -Unique)
      $row += (' ' + $g + '=' + ($names -join ','))
      foreach ($nm in $names) { if ($catNames -notcontains $nm) { $catNames += $nm } }
    } else {
      $row += (' ' + $g + '=' + $r)
    }
  }
  $catRows += ('  CATSRC|' + $s + $row)
}
foreach ($r in $catRows) { Write-Host $r }
Write-Host ('  覆盖 .sys 的 .cat: ' + ($catNames -join ', '))

# ---------- 3. 落到 overlay ----------
if ($Dry) {
  Write-Host '  (-Dry) 到此为止, 不写文件'
  exit 0
}
if ($missing.Count) { throw ('素材不齐, 先解决: ' + ($missing -join ',')) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $CatsDir | Out-Null
foreach ($o in $items) {
  $dst = Join-Path $OutDir $o.Name
  if (Test-Path $dst) { Remove-Item $dst -Force }
  Copy-Item $o.Src $dst -Force
}
$catCopied = @(); $catAbsent = @()
foreach ($c in $catNames) {
  $srcCat = Join-Path $HostWin ('System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\' + $c)
  if (-not (Test-Path $srcCat)) {
    $alt = @(Get-ChildItem (Join-Path $HostWin 'System32\CatRoot') -Recurse -Filter $c -File -EA SilentlyContinue)
    if ($alt.Count) { $srcCat = $alt[0].FullName } else { $catAbsent += $c; continue }
  }
  $dst = Join-Path $CatsDir $c
  if (-not (Test-Path $dst) -or (Get-Item $dst).Length -ne (Get-Item $srcCat).Length) { Copy-Item $srcCat $dst -Force }
  $catCopied += $c
}

# ---------- 4. manifest(给门禁当断言用) ----------
$lines = @('# overlay\VWiFi manifest —— 由 test\20_MakeVWifiPool.ps1 生成, 不要手改')
foreach ($o in @($items | Sort-Object Kind, Name)) {
  $fi = Get-Item (Join-Path $OutDir $o.Name)
  $h = (Get-FileHash -Algorithm SHA256 $fi.FullName).Hash.Substring(0, 16)
  $ver = (V $fi)
  if ($o.Kind -eq 'inf' -and $infMeta[$o.Name]) {
    $m = $infMeta[$o.Name]
    $ver = ('Cat=' + $(if ($m['CatalogFile']) { $m['CatalogFile'] } else { '-' }) +
            ' Ver=' + $(if ($m['DriverVer']) { $m['DriverVer'] } else { '-' }) +
            ' Class=' + $(if ($m['Class']) { $m['Class'] } else { '-' }))
  }
  $lines += ($o.Kind + '|' + $o.Name + '|' + $ver + '|' + $fi.Length + '|' + $h)
}
foreach ($c in $catCopied) {
  $fi = Get-Item (Join-Path $CatsDir $c)
  $lines += ('cat|' + $c + '|-|' + $fi.Length + '|' + (Get-FileHash -Algorithm SHA256 $fi.FullName).Hash.Substring(0, 16))
}
Set-Content -LiteralPath (Join-Path $OutDir 'vwifi_manifest.txt') -Value $lines -Encoding ASCII
Write-Host ('  已写 ' + $OutDir + ' (' + (@(Get-ChildItem $OutDir -File).Count) + ' 个文件) + ' +
           $CatsDir + ' (' + (@(Get-ChildItem $CatsDir -Filter *.cat -File).Count) + ' 个 .cat)')

$flags = @()
if ((@($items | Where-Object { $_.Kind -eq 'inf' }).Count) -lt $infs.Count) { $flags += 'INF_SHORT' }
if ((@($items | Where-Object { $_.Kind -eq 'sys' }).Count) -lt $syss.Count) { $flags += 'SYS_SHORT' }
if ($catAbsent.Count) { $flags += 'CAT_NOT_FOUND' }
if ($catNames.Count -eq 0) { $flags += 'NO_CAT_AT_ALL' }
Write-Host ('VERDICT vwifi_pool: inf=' + (@($items | Where-Object { $_.Kind -eq 'inf' }).Count) + '/' + $infs.Count +
           ' sys=' + (@($items | Where-Object { $_.Kind -eq 'sys' }).Count) + '/' + $syss.Count +
           ' cats=' + $catCopied.Count +
           ' flags=' + $(if ($flags.Count) { ($flags -join ',') } else { 'none' }))
