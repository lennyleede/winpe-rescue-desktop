# 管理员运行：检查 LTSC 2021 ISO 里的 boot.wim(WinPE 19044) 有哪些能力
# powershell -NoProfile -ExecutionPolicy Bypass -File test\23_InspectWin10Iso.ps1
$ErrorActionPreference = 'Continue'
$Iso  = 'D:\迅雷下载\zh-cn_windows_10_enterprise_ltsc_2021_x64_dvd_033b7312.iso'
$Scr  = 'D:\winpe10_probe'
$Mnt  = Join-Path $Scr 'mount'
$Log  = Join-Path $Scr 'inspect.txt'
New-Item -ItemType Directory -Force -Path $Scr | Out-Null
Set-Content -Path $Log -Value ('inspect ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8
function Say($m) { Write-Host $m; Add-Content -Path $Log -Value $m -Encoding UTF8 }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Say ('isAdmin=' + $isAdmin)
if (-not $isAdmin) { Say 'ERROR: 需要管理员权限'; exit 1 }
if (-not (Test-Path $Iso)) { Say ('ERROR: 找不到 ISO ' + $Iso); exit 1 }

$mounted = $false
try {
  Say '=== [1] 挂载 ISO ==='
  Mount-DiskImage -ImagePath $Iso | Out-Null
  Start-Sleep -Seconds 3
  $di = Get-DiskImage -ImagePath $Iso
  $dl = ($di | Get-Volume).DriveLetter
  $drv = ($dl + ':\')
  Say ('  驱动器 ' + $drv)
  $mounted = $true

  Say '=== [2] boot.wim 索引信息 ==='
  $bw = ($drv + 'sources\boot.wim')
  Say ('  ' + $bw + ' 存在=' + (Test-Path $bw))
  & dism.exe /Get-WimInfo /WimFile:$bw | Out-File -FilePath (Join-Path $Scr 'wiminfo.txt') -Encoding UTF8
  Get-Content (Join-Path $Scr 'wiminfo.txt') | ForEach-Object { Say ('  ' + $_) }

  Say '=== [3] 挂载 index 1 (Windows Setup WinPE) ==='
  New-Item -ItemType Directory -Force -Path $Mnt | Out-Null
  & dism.exe /Mount-Wim /WimFile:$bw /Index:1 /MountDir:$Mnt | Out-Null
  if (-not (Test-Path ($Mnt + '\Windows\System32'))) { Say '  挂载失败, 中止'; exit 1 }
  Say ('  挂载 OK: ' + $Mnt)

  Say '=== [4] DISM 已装包列表 (含版本) ==='
  & dism.exe /Image:$Mnt /Get-Packages /Format:Table | Out-File -FilePath (Join-Path $Scr 'packages.txt') -Encoding UTF8
  Get-Content (Join-Path $Scr 'packages.txt') | ForEach-Object { Say ('  ' + $_) }

  Say '=== [5] 关键文件存在性 ==='
  $sys32 = $Mnt + '\Windows\System32'
  $checks = @(
    'mshta.exe','wbem\WmiPrvSE.exe','wbem\wmiprvsd.dll','WindowsPowerShell\v1.0\powershell.exe',
    'WindowsPowerShell\v1.0\powershell_ise.exe','shell32.dll','urlmon.dll','mshtml.dll','jscript9.dll',
    'ieframe.dll','dxtrans.dll','htafile.dll','netsetup.exe','wpeutil.exe','smss.exe','wininit.exe',
    'svchost.exe','mpssvc.dll','wlansvc.dll','wlanapi.dll','iphlpapi.dll','dnsapi.dll',
    'iphlpapi.dll','dnsapi.dll','mscoree.dll','mscoreei.dll','normalization.dll'
  )
  foreach ($c in $checks) {
    $p = Join-Path $sys32 $c
    $sz = ''
    if (Test-Path $p) { $sz = ('  {0,12:N0}  ' -f (Get-Item $p).Length) + $c } else { $sz =  '         MISSING  ' + $c }
    Say ('  ' + $sz)
  }

  Say '=== [6] .NET / WinSxS 线索 ==='
  foreach ($p in @(($Mnt + '\Windows\Microsoft.NET\Framework64'), ($Mnt + '\Windows\System32\mscoree.dll'), ($Mnt + '\Windows\System32\clr.dll'), ($Mnt + '\Windows\WinSxS'))) {
    Say ('  ' + $p + ' 存在=' + (Test-Path $p))
  }
  $winsxs = $Mnt + '\Windows\WinSxS'
  if (Test-Path $winsxs) {
    Say ('  WinSxS 目录数=' + @(Get-ChildItem $winsxs -Directory -EA SilentlyContinue).Count)
    foreach ($pat in @('*mshta*','*hta*','*WindowsForms*','*PresentationCore*','*MSHTML*','*Jscript*')) {
      $n = @(Get-ChildItem $winsxs -Directory -Filter $pat -EA SilentlyContinue).Count
      Say ('    filter ' + $pat + ' -> ' + $n)
    }
  }

  Say '=== [7] PE 版本 ==='
  $ver = Join-Path $sys32 'config\SOFTWARE'
  Say ('  System32 文件总数=' + @(Get-ChildItem $sys32 -Recurse -File -EA SilentlyContinue).Count)
  $cmd = Join-Path $sys32 'cmd.exe'
  if (Test-Path $cmd) { Say ('  cmd.exe 版本=' + (Get-Item $cmd).VersionInfo.FileVersion) }
  $dll = Join-Path $sys32 'ntdll.dll'
  if (Test-Path $dll) { Say ('  ntdll.dll 版本=' + (Get-Item $dll).VersionInfo.FileVersion) }

  Say '=== [8] 驱动商店里的网卡驱动 ==='
  $fr = Join-Path $sys32 'DriverStore\FileRepository'
  if (Test-Path $fr) {
    $all = @(Get-ChildItem $fr -Directory -EA SilentlyContinue)
    Say ('  FileRepository 包数=' + $all.Count)
    $net = @($all | Where-Object { $_.Name -match 'net|e1|rtl|bnx|ax|killer' })
    Say ('  名称含网卡特征的包=' + $net.Count)
    $net | Select-Object -First 15 | ForEach-Object { Say ('    ' + $_.Name) }
  } else { Say '  无 FileRepository' }

  Say '=== [9] winre/wim 其它索引 ==='
  foreach ($w in @(($drv + 'sources\install.wim'), ($drv + 'sources\install.esd'))) {
    if (Test-Path $w) { Say ('  found ' + $w + ' size=' + (Get-Item $w).Length) }
  }
} finally {
  if (Test-Path $Mnt) { & dism.exe /Unmount-Wim /MountDir:$Mnt /Discard | Out-Null; Say '  已卸载 mount(discard)' }
  if ($mounted) { Dismount-DiskImage -ImagePath $Iso | Out-Null; Say '  已弹出 ISO' }
}
Say ('=== 完成, 报告在 ' + $Log + ' ===')
