# ============================================================
# 28_FinishWinPe10.ps1 —— 把已经做好的 Win10 PE 挂载点提交并出盘
# 用途: build10.ps1 跑到 [8/8] 之前被打断(日志变量被 fw-offline 的 $global:LOG 污染)时,
#       镜像里的成果(组件包/网卡驱动/overlay/BUILD_TAG)都还在 D:\pe10_work\mount 里,
#       这里只补最后两步: DISM /Unmount-Wim /Commit  +  oscdimg 出 ISO。
# 需要管理员:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\28_FinishWinPe10.ps1
# 先看一眼不干活(普通权限可跑):
#   同上 -DryRun
# ============================================================
param(
  [string]$Work    = 'D:\pe10_work',
  [string]$Product = 'WinPE10_Desktop_v1',
  [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$Root    = Split-Path $PSScriptRoot -Parent
$Build   = Join-Path $Root 'build10'
$Dist    = Join-Path $Root 'dist'
$BootBin = Join-Path $Build 'bootbin'
$ADK     = 'C:\Program Files (x86)\Windows Kits\10'
$DismExe = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\Dism.exe"
$Oscdimg = "$ADK\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
$Mount   = Join-Path $Work 'mount'
$Media   = Join-Path $Work 'media'
$Wim     = Join-Path $Media 'sources\boot.wim'
$LogPath = Join-Path $Build ('finish_' + (Get-Date -Format 'MMdd-HHmmss') + '.log')   # 名字刻意避开 $LOG
$rows    = New-Object System.Collections.ArrayList

function Say($m) {
  Write-Host $m
  [void]$rows.Add([string]$m)
  # 日志写失败绝不能反过来打断收尾: 这一步的成败只看 DISM/oscdimg 的返回码
  try { Add-Content -LiteralPath $LogPath -Value ((Get-Date -Format 'HH:mm:ss ') + $m) -Encoding UTF8 -ErrorAction Stop } catch { }
}
function Flush-Rows {
  try { Set-Content -LiteralPath (Join-Path $Build 'finish_result.txt') -Value ($rows -join "`r`n") -Encoding UTF8 } catch { }
}
function Dism($argList, $label) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $DismExe @argList 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  Say ($label + ' rc=' + $rc)
  ($o | Where-Object { "$_" -match '错误|Error|成功|complete' } | Select-Object -Last 5) | ForEach-Object { Say ('    ' + $_) }
  return $rc
}

New-Item -ItemType Directory -Force -Path $Build | Out-Null
Say ('===== 收尾开始 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' DryRun=' + $DryRun + ' =====')

# ---------- 前置检查 ----------
foreach ($p in @($DismExe, $Oscdimg, $Wim, $Mount, (Join-Path $BootBin 'efisys_noprompt.bin'), (Join-Path $BootBin 'etfsboot.com'))) {
  if (-not (Test-Path $p)) { Say ('缺少: ' + $p); Flush-Rows; exit 1 }
}
$marker = Join-Path $Mount 'BUILD_TAG.txt'
if (-not (Test-Path $marker)) {
  Say '!! 挂载点里没有 BUILD_TAG.txt —— 这个挂载点不是 build10 做好的成品, 不要提交'
  Flush-Rows; exit 1
}
Say ('挂载点标记: ' + ((Get-Content $marker -Encoding ASCII) -join ' / '))
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ('isAdmin = ' + $IsAdmin)
if (-not $IsAdmin -and -not $DryRun) { Say 'ERROR: 提交和出盘需要管理员'; Flush-Rows; exit 1 }
$wimBefore = (Get-Item $Wim).Length
Say ('提交前 boot.wim = ' + ('{0:N0}' -f $wimBefore) + ' B')
Say ('媒体目录顶层 = ' + ((@(Get-ChildItem $Media | ForEach-Object { $_.Name })) -join ', '))
if ($DryRun) { Say 'DryRun: 到此为止, 没有动任何镜像'; Flush-Rows; exit 0 }

# ---------- 0. 修掉 BUILD_TAG 里的非 ASCII 残字(基镜像是 en-us PE, 这文件按 ASCII 读) ----------
try {
  $t = @(Get-Content -LiteralPath $marker -Encoding ASCII)
  $t2 = $t | ForEach-Object {
    if ($_ -match '^bootbin = ') { 'bootbin = 19041 retail signed (Secure Boot should stay ON)' } else { $_ }
  }
  Set-Content -LiteralPath $marker -Value ($t2 -join "`r`n") -Encoding ASCII -NoNewline
  Say 'BUILD_TAG.txt 已规整成纯 ASCII'
} catch { Say ('  (BUILD_TAG 规整跳过: ' + $_.Exception.Message + ')') }

# ---------- 2. 清掉可能残留的离线注册表配置单元 ----------
foreach ($hk in @('PE10_SYS', 'PE_FW', 'PE_SYS', 'PE_SYS2')) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & reg.exe query ('HKLM\' + $hk) 2>&1 | Out-Null
  if ($LASTEXITCODE -eq 0) {
    $o = & reg.exe unload ('HKLM\' + $hk) 2>&1
    Say ('  残留配置单元 HKLM\' + $hk + ' 卸载: ' + (($o | ForEach-Object { "$_" }) -join ' '))
  }
  $ErrorActionPreference = $prev
}

# ---------- 2. 提交挂载点 ----------
$rc = Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Commit') 'Unmount-Wim /Commit'
if ($rc -ne 0) {
  Say '  5 秒后重试一次(常见原因是文件被占用)'
  Start-Sleep -Seconds 5
  $rc = Dism @('/Unmount-Wim', ('/MountDir:' + $Mount), '/Commit') '重试 Unmount-Wim /Commit'
  if ($rc -ne 0) { Say 'ERROR: 提交失败, 镜像未改动; 请关闭占用 D:\pe10_work\mount 的程序后重跑'; Flush-Rows; exit 1 }
}
$wimAfter = (Get-Item $Wim).Length
Say ('提交后 boot.wim = ' + ('{0:N0}' -f $wimAfter) + ' B (变化 ' + ('{0:N0}' -f ($wimAfter - $wimBefore)) + ' B)')
if ($wimAfter -le $wimBefore) { Say '!! 提交后体积没变大, 可能没真正写回, 请核对' }

# ---------- 3. 出 ISO ----------
$Iso = & (Join-Path $Root 'test\iso_target.ps1') -Base (Join-Path $Dist ($Product + '.iso')) | Select-Object -Last 1
if (-not $Iso) { Say 'ERROR: 目标 ISO 名字拿不到'; Flush-Rows; exit 1 }
if (Test-Path $Iso) { Remove-Item $Iso -Force }
$EfiBin = 'efisys_noprompt.bin'
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
Push-Location $BootBin
& $Oscdimg -m -o -u2 -udfver102 ('-bootdata:2#p0,e,betfsboot.com#pEF,e,b' + $EfiBin) $Media $Iso 2>&1 | Select-Object -Last 5 | ForEach-Object { Say ('  oscdimg: ' + $_) }
$rc = $LASTEXITCODE
Pop-Location
$ErrorActionPreference = $prev
Say ('oscdimg rc=' + $rc)
if ($rc -ne 0 -or -not (Test-Path $Iso)) { Say 'ERROR: oscdimg 失败'; Flush-Rows; exit 1 }

# ---------- 4. El Torito 自检 ----------
$bootEntries = 0; $etLba = -1; $catLba = -1; $sectorLen = 2048
$fs = [IO.File]::OpenRead($Iso)
try {
  $br = New-Object System.IO.BinaryReader($fs)
  $total = [int][Math]::Floor($fs.Length / $sectorLen)
  $sig = [Text.Encoding]::ASCII.GetBytes('EL TORITO SPECIFICATION')
  for ($s = 0; $s -lt [Math]::Min(64, $total); $s++) {
    $sec = $br.ReadBytes($sectorLen)
    if ($sec.Length -lt $sectorLen) { break }
    $ok = $true
    for ($k = 0; $k -lt $sig.Length; $k++) { if ($sec[7 + $k] -ne $sig[$k]) { $ok = $false; break } }
    if ($ok) { $etLba = $s; $catLba = [BitConverter]::ToInt32($sec, 71); break }
  }
  if ($catLba -gt 0 -and $catLba -lt $total) {
    $fs.Position = [int64]$catLba * $sectorLen
    $cat = $br.ReadBytes($sectorLen)
    for ($o = 0x20; $o + 32 -le $cat.Length; $o += 32) {
      if ($cat[$o] -ne 0x88) { continue }
      $lba = [BitConverter]::ToInt32($cat, $o + 8)
      if ($lba -gt 0 -and $lba -lt $total) { $bootEntries++ }
    }
  }
} finally { $fs.Close() }
Say ('El Torito: ET-VD=' + $etLba + ' catalog=' + $catLba + ' 可引导项=' + $bootEntries)
if ($bootEntries -lt 2) { Say 'ERROR: 引导记录不足两项(BIOS + EFI), 这个盘点不亮'; Flush-Rows; exit 1 }
Say ('完成! 产物: ' + $Iso)
Say ('大小: ' + ('{0:N1} MB' -f ((Get-Item $Iso).Length / 1MB)))
Flush-Rows
