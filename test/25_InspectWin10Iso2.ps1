# 管理员运行：把 LTSC 2021 ISO 的 boot.wim 复制到本地后分别挂载 index 1 / index 2 做能力普查
# 上一版失败原因：/Mount-Wim 需要写回 WIM 元数据，只读 ISO 里挂不上 -> 这次先复制到本地
# powershell -NoProfile -ExecutionPolicy Bypass -File test\25_InspectWin10Iso2.ps1
$ErrorActionPreference = 'Continue'
$Iso   = 'D:\迅雷下载\zh-cn_windows_10_enterprise_ltsc_2021_x64_dvd_033b7312.iso'
$Scr   = 'D:\winpe10_probe'
$Local = Join-Path $Scr 'boot.wim'
$Log   = Join-Path $Scr 'inspect2.txt'
New-Item -ItemType Directory -Force -Path $Scr | Out-Null
Set-Content -Path $Log -Value ('inspect2 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8
function Say($m) { Write-Host $m; Add-Content -Path $Log -Value $m -Encoding UTF8 }
function Run($exe, $args_) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $exe @args_ 2>&1
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return ,@($rc, $o)
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Say 'ERROR: 需要管理员权限'; exit 1
}
if (-not (Test-Path $Iso)) { Say ('ERROR: 找不到 ' + $Iso); exit 1 }

# ---------- [1] 复制 boot.wim 出 ISO ----------
Say '=== [1] 从 ISO 复制 sources\boot.wim 到本地 ==='
$mounted = $false
try {
  Mount-DiskImage -ImagePath $Iso | Out-Null
  Start-Sleep -Seconds 3
  $drv = ((Get-DiskImage -ImagePath $Iso | Get-Volume).DriveLetter + ':\')
  Say ('  ' + $drv)
  $mounted = $true
  $srcWim = ($drv + 'sources\boot.wim')
  if ((Test-Path $Local) -and ((Get-Item $Local).Length -gt 100MB)) {
    Say ('  已有本地副本, 跳过复制: ' + ('{0:N0}' -f (Get-Item $Local).Length) + ' B')
  } else {
    if (Test-Path $Local) { Remove-Item $Local -Force }
    $t0 = Get-Date
    Copy-Item $srcWim $Local -Force
    Say ('  复制完成 ' + ('{0:N0}' -f (Get-Item $Local).Length) + ' B, 用时 ' + [int]((Get-Date)-$t0).TotalSeconds + ' 秒')
  }
  # 也看看 ISO 里还有哪些可能有用的东西
  foreach ($n in @('sources\install.wim','sources\install.esd','sources\winre.wim','sources\boot.wim')) {
    Say ('  ' + $n + ' 存在=' + (Test-Path ($drv + $n)))
  }
} finally {
  if ($mounted) { Dismount-DiskImage -ImagePath $Iso | Out-Null; Say '  已弹出 ISO' }
}
if (-not (Test-Path $Local)) { Say 'ERROR: boot.wim 没拿到'; exit 1 }

# ---------- [2..n] 逐个索引普查 ----------
$dism = 'dism.exe'   # 本机 10.0.19041.3636
foreach ($idx in @(1,2)) {
  $Mnt = Join-Path $Scr ("mount{0}" -f $idx)
  Say ('=== [' + ($idx + 1) + '] 挂载 index ' + $idx + ' ===')
  if (Test-Path $Mnt) { & dism.exe /Unmount-Wim ("/MountDir:" + $Mnt) /Discard 2>&1 | Out-Null; Remove-Item $Mnt -Recurse -Force -EA SilentlyContinue }
  New-Item -ItemType Directory -Force -Path $Mnt | Out-Null
  $o = & dism.exe /Mount-Wim ("/WimFile:" + $Local) ("/Index:" + $idx) ("/MountDir:" + $Mnt) 2>&1
  $rc = $LASTEXITCODE
  Say ('  dism rc=' + $rc)
  ($o | Select-Object -Last 12) | ForEach-Object { Say ('    ' + $_) }
  if (-not (Test-Path ($Mnt + '\Windows\System32'))) { Say '  挂载失败, 跳过该索引'; continue }

  Say '  --- 已装包 ---'
  $o2 = & dism.exe ("/Image:" + $Mnt) /Get-Packages /Format:Table 2>&1
  $pkgs = @($o2 | Select-String -Pattern 'Package' )
  Say ('    含 Package 的行数=' + $pkgs.Count)
  $pkgs | Select-Object -First 70 | ForEach-Object { Say ('    ' + $_.Line.Trim()) }
  foreach ($kw in @('PowerShell','HTA','WMI','NetFX','Scripting','Dot3','RNDIS','Font')) {
    $hit = @($pkgs | Where-Object { $_.Line -match ('(?i)' + $kw) })
    Say ('    关键字 ' + $kw + ' 命中=' + $hit.Count)
  }

  Say '  --- 关键文件 ---'
  $sys32 = $Mnt + '\Windows\System32'
  foreach ($c in @('wpeutil.exe','mshta.exe','WindowsPowerShell\v1.0\powershell.exe','wbem\WmiPrvSE.exe','wbem\wmiprvsd.dll','wbem\fastprox.dll',
                   'urlmon.dll','mshtml.dll','ieframe.dll','jscript.dll','jscript9.dll','dxtrans.dll','mscoree.dll','mscoreei.dll',
                   'Normaliz.dll','gdiplus.dll','comctl32.dll','wlanapi.dll','wlansvc.dll','mpssvc.dll','bfe.dll','winhttp.dll',
                   'wininet.dll','sspicli.dll','dnsapi.dll','iphlpapi.dll','netshell.dll','neightrace.exe','netstat.exe','tasklist.exe','sc.exe','findstr.exe')) {
    $p = Join-Path $sys32 $c
    if (Test-Path $p) { Say ('    OK      {0,12:N0}  {1}' -f (Get-Item $p).Length, $c) }
    else { Say ('    MISSING               ' + $c) }
  }

  Say '  --- 版本 / 规模 ---'
  Say ('    ntdll.dll = ' + (Get-Item (Join-Path $sys32 'ntdll.dll') -EA SilentlyContinue).VersionInfo.FileVersion)
  Say ('    System32 文件数 = ' + @(Get-ChildItem $sys32 -Recurse -File -EA SilentlyContinue).Count)
  foreach ($d in @('Microsoft.NET\Framework64\v4.0.30319', 'WinSxS', 'System32\en-US', 'System32\DriverStore', 'System32\LogFiles\WMI')) {
    Say ('    Windows\' + $d + ' 存在 = ' + (Test-Path ($Mnt + '\Windows\' + $d)))
  }
  Say ('    mshta* 匹配 = ' + (@(Get-ChildItem $sys32 -Filter 'mshta*' -EA SilentlyContinue | ForEach-Object { $_.Name }) -join ','))
  Say ('    wbem 文件数 = ' + @(Get-ChildItem (Join-Path $sys32 'wbem') -File -EA SilentlyContinue).Count)
  $fr = Join-Path $sys32 'DriverStore\FileRepository'
  if (Test-Path $fr) { Say ('    DriverStore 包数 = ' + @(Get-ChildItem $fr -Directory -EA SilentlyContinue).Count) }
  else { Say '    无 DriverStore\FileRepository' }
  $fnt = Join-Path $sys32 'zh-cn'
  Say ('    System32\zh-cn 存在 = ' + (Test-Path $fnt))
  foreach ($f in @('msyh.ttc','simhei.ttf','simsun.ttc','msgothic.ttc')) {
    $fp = Join-Path ($Mnt + '\Windows\Fonts') $f
    Say ('    Fonts\' + $f + ' = ' + (Test-Path $fp))
  }
  # 服务端/客户端 OpenSSH 是否自带
  foreach ($f in @('OpenSSH\sshd.exe','OpenSSH\ssh.exe')) {
    Say ('    ' + $f + ' = ' + (Test-Path (Join-Path $sys32 $f)))
  }
  # startnet / winpeshl
  foreach ($f in @('System32\startnet.cmd','System32\winpeshl.ini')) {
    $q = $Mnt + '\Windows\' + $f
    if (Test-Path $q) { Say ('    ' + $f + ' 内容: '); (Get-Content $q -EA SilentlyContinue | Select-Object -First 12) | ForEach-Object { Say ('      ' + $_) } }
    else { Say ('    ' + $f + ' = MISSING') }
  }

  $o3 = & dism.exe /Unmount-Wim ("/MountDir:" + $Mnt) /Discard 2>&1
  Say ('  卸载 rc=' + $LASTEXITCODE)
  ($o3 | Select-Object -Last 3) | ForEach-Object { Say ('    ' + $_) }
}
Say ('=== 完成, 报告: ' + $Log + ' ===')
