# ============================================================
# 解包(不安装)ADK WinPE add-on 的离线 layout, 供 build10.ps1 -PeRoot10 使用
#   为什么不能直接安装: 安装会把本机 26100 ADK 的 WinPE_OCs 覆盖成 19041 的,
#   v8(Win11 世代基镜像)以后重建就会全数 0x800f081e 失败。
# 普通权限即可运行(msiexec /a 只往 TARGETDIR 写文件)。
# 用法:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\26_ExtractAdk10Pe.ps1 -EnumerateOnly
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\26_ExtractAdk10Pe.ps1
# ============================================================
param(
  [string]$Installers = 'D:\adk10_layout\Installers',
  [string]$Out        = 'D:\adk10pe',
  [string]$Pattern    = '*x86 x64*',   # 只要 amd64 那个包; ARM/ARM64 的用通配过滤掉
  [switch]$EnumerateOnly,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host $m }

if ($SelfTest) {
  Say '===== SELFTEST: 只查 COM 能不能读 MSI 的 Media 表 ====='
  $msi = @(Get-ChildItem $Installers -Filter '*.msi' -EA SilentlyContinue)
  Say ('  MSI 数量 = ' + $msi.Count + ' (' + $Installers + ')')
  if ($msi.Count -eq 0) { Say '  (还没下完, 无 MSI 可试) SELFTEST OK'; exit 0 }
  foreach ($m in $msi) { Say ('  尝试枚举: ' + $m.Name) }
  exit 0
}

if (-not (Test-Path $Installers)) { Say ("ERROR: 找不到 " + $Installers); exit 1 }
$all = @(Get-ChildItem $Installers -Filter '*.msi' -File)
$msis = @($all | Where-Object { $_.Name -like $Pattern })
Say ('MSI 总数 ' + $all.Count + ' 个, 匹配 [' + $Pattern + '] 的 ' + $msis.Count + ' 个, cab ' + @(Get-ChildItem $Installers -Filter '*.cab' -File).Count + ' 个')
$msis | ForEach-Object { Say ('  待处理: ' + $_.Name) }
$all | Where-Object { $_.Name -notlike $Pattern } | ForEach-Object { Say ('  跳过(非 amd64): ' + $_.Name) }
if ($msis.Count -eq 0) { Say 'ERROR: 一个 MSI 都没有, layout 没下完'; exit 1 }

# ---------- 1. 枚举每个 MSI 引用的 cabinet(看看哪些大包还没落地) ----------
function Get-MsiCabs([string]$msiPath) {
  $wi = $null; $db = $null; $view = $null
  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $wi, @($msiPath, 0))
    # 实测(10.1.19041.5856 的 Windows PE x86 x64-x86_en-us.msi): Media 表只有
    # LastSequence / Cabinet 两列, 选 Disk / Options / Signature / Reference 任一都会抛
    # OpenView,Sql 让整条查询失败 -> 只取 Cabinet。
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `Cabinet` FROM `Media`'))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $rows = @()
    while ($true) {
      $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
      if ($null -eq $rec) { break }
      $f1 = $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @(1))
      $rows += [string]$f1
    }
    return $rows
  } catch {
    Say ('  !! Media 表读取失败: ' + $_.Exception.Message)
    return @()
  } finally {
    if ($view) { [Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null }
    if ($db)   { [Runtime.InteropServices.Marshal]::ReleaseComObject($db)   | Out-Null }
    if ($wi)   { [Runtime.InteropServices.Marshal]::ReleaseComObject($wi)   | Out-Null }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
  }
}
$allMissing = @()
$skipNames = @()
foreach ($m in $msis) {
  Say ('--- ' + $m.Name + ' ---')
  $rows = Get-MsiCabs $m.FullName
  Say ('  Media 行数 = ' + $rows.Count)
  $cabNames = @($rows | Where-Object { $_ -and $_ -ne '#' -and $_ -notmatch '^\s*$' } | Sort-Object -Unique)
  Say ('  引用 cab 数 = ' + $cabNames.Count)
  foreach ($c in $cabNames) {
    $here = Join-Path $Installers $c
    $sz = if (Test-Path $here) { ('{0,10:N0}' -f (Get-Item $here).Length) + ' B' } else { ('{0,10}' -f '-') }
    Say ('    cab ' + $c + ' 大小=' + $sz + ' 已在本地=' + (Test-Path $here))
  }
  $missing = @($cabNames | Where-Object { -not (Test-Path (Join-Path $Installers $_)) })
  Say ('  缺失 cab = ' + $missing.Count + (@($missing | ForEach-Object { ' ' + $_ }) -join ''))
  if ($missing.Count -gt 0) { $skipNames += $m.Name }
  $allMissing += $missing
}
if ($EnumerateOnly) { Say 'ENUMERATE ONLY 结束'; exit 0 }
$ready = @($msis | Where-Object { $_.Name -notin @($skipNames) })
$skipNames | ForEach-Object { Say ('  本轮跳过(cab 未下齐): ' + $_) }
if ($ready.Count -eq 0) {
  Say 'ERROR: 匹配的 MSI 都还有 cab 没下完, 稍后再跑。'
  exit 1
}
$msis = $ready

# ---------- 2.  administrative install 解包 ----------
New-Item -ItemType Directory -Force -Path $Out | Out-Null
foreach ($m in $msis) {
  Say ('--- 解包 ' + $m.Name + ' -> ' + $Out + ' ---')
  # msiexec 不往 stdout 写东西, 用 Start-Process -Wait 拿退出码最稳(EAP=Stop 下原生程序的 stderr 会变成终止错误)
  $p = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList @(
    '/a', ('"' + $m.FullName + '"'), '/qn',
    ('TARGETDIR="' + $Out + '"'), ('SourceDir="' + $Installers + '"')
  )
  Say ('  msiexec rc=' + $p.ExitCode)
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
    Say '  !! 解包失败(1603/1305 多半是同目录 cab 没下齐, 先用 -EnumerateOnly 看缺哪个)'
  }
}

# ---------- 3. 验收: build10 要的三样 ----------
Say '--- 解包结果验收 ---'
$wim = @(Get-ChildItem $Out -Recurse -Filter 'winpe.wim' -File -EA SilentlyContinue | Where-Object { $_.FullName -match '(?i)\\amd64\\' })
Say ('  winpe.wim(amd64) = ' + $wim.Count)
foreach ($w in $wim) { Say ('    ' + ('{0,12:N0}' -f $w.Length) + '  ' + $w.FullName) }
$oc = @(Get-ChildItem $Out -Recurse -Directory -Filter 'WinPE_OCs' -EA SilentlyContinue | Where-Object { $_.FullName -match '(?i)\\amd64\\' })
Say ('  WinPE_OCs(amd64) = ' + $oc.Count)
foreach ($d in $oc) {
  $cabs = @(Get-ChildItem $d.FullName -Filter '*.cab' -File -EA SilentlyContinue)
  Say ('    ' + $d.FullName + ' cab=' + $cabs.Count)
  $cabs | Sort-Object Name | ForEach-Object { Say ('      ' + ('{0,12:N0}' -f $_.Length) + '  ' + $_.Name) }
  $enu = Join-Path $d.FullName 'en-us'
  if (Test-Path $enu) {
    Say ('      en-us cab=' + @(Get-ChildItem $enu -Filter '*.cab' -File).Count)
  }
}
$med = @(Get-ChildItem $Out -Recurse -Directory -Filter 'Media' -EA SilentlyContinue | Where-Object { $_.FullName -match '(?i)\\amd64\\' -and (Test-Path (Join-Path $_.FullName 'bootmgr')) })
Say ('  Media(amd64, 含 bootmgr) = ' + $med.Count)
foreach ($d in $med) {
  Say ('    ' + $d.FullName)
  foreach ($bf in @('bootmgr', 'bootmgr.efi', 'EFI\Boot\bootx64.efi', 'EFI\Microsoft\Boot\bootmgfw.efi', 'EFI\Microsoft\Boot\efisys_noprompt.bin')) {
    $bp = Join-Path $d.FullName $bf
    if (Test-Path $bp) {
      $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      $sig = Get-AuthenticodeSignature $bp
      $ErrorActionPreference = $prev
      $who = ''
      if ($sig.SignerCertificate) { $who = $sig.SignerCertificate.Subject }
      Say ('      ' + $bf + ' 签名=' + $sig.Status + ' 签发者=' + $who)
    }
  }
}
Say '完成。build10.ps1 用 -PeRoot10 指向上面的输出目录即可。'
