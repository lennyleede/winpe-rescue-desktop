# 探测：能否弄到真正的 Windows 10 (19041/19044) WinPE 基镜像与可选组件
# 普通权限运行: powershell -NoProfile -ExecutionPolicy Bypass -File test\20_ProbeWin10Base.ps1
$ErrorActionPreference = 'Continue'
$Out = Join-Path $PSScriptRoot 'probe_win10base.txt'
function Say($m) { Write-Output $m; Add-Content -Path $Out -Value $m -Encoding UTF8 }
Set-Content -Path $Out -Value ('probe ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8

Say '=== 1. 已安装的 Windows Kits / ADK ==='
foreach ($root in @('C:\Program Files (x86)\Windows Kits', 'C:\Program Files\Windows Kits', 'D:\Program Files\Windows Kits', 'D:\Windows Kits')) {
  if (Test-Path $root) {
    Get-ChildItem $root -Directory -EA SilentlyContinue | ForEach-Object {
      $v = 'n/a'
      $copype = Join-Path $_.FullName 'Assessment and Deployment Kit\Windows Preinstallation Environment\copype.cmd'
      if (Test-Path $copype) { $v = 'has copype' }
      Say ("  {0}  [{1}]" -f $_.FullName, $v)
    }
  } else { Say ("  (missing) " + $root) }
}

Say '=== 2. 注册表里的 ADK / Windows 10 安装信息 ==='
foreach ($k in @(
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
  if (Test-Path $k) {
    if ($k -like '*Installed Roots') {
      Get-ItemProperty $k | Get-Member -Type Property | ForEach-Object {
        $val = (Get-ItemProperty $k).($_.Name); Say ("  {0} = {1}" -f $_.Name, $val)
      }
    } else {
      Get-ChildItem $k -EA SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
        if ($p.DisplayName -match 'Assessment|Deployment Tools|ADK|Windows Preinstallation') {
          Say ("  {0} | {1} | {2}" -f $p.DisplayName, $p.DisplayVersion, $p.InstallLocation)
        }
      }
    }
  } else { Say ("  (missing) " + $k) }
}

Say '=== 3. 当前 ADK 的 WinPE 基镜像版本 ==='
$peRoot = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64'
foreach ($w in @((Join-Path $peRoot 'Media\sources\boot.wim'), (Join-Path $peRoot 'WinPE.wim'))) {
  if (Test-Path $w) {
    Say ("  " + $w + "  size=" + (Get-Item $w).Length)
    & dism.exe /Get-WimInfo /WimFile:$w 2>&1 | Select-String -Pattern 'Name|Version|Architecture|Index' | ForEach-Object { Say ('    ' + $_.Line.Trim()) }
  } else { Say ("  (missing) " + $w) }
}

Say '=== 4. WinPE_OCs 组件包版本(取 WinPE-WMI.cab 的内部版本) ==='
$oc = Join-Path $peRoot 'WinPE_OCs'
if (Test-Path $oc) {
  Get-ChildItem $oc -Filter 'WinPE-*.cab' | Select-Object -First 8 | ForEach-Object {
    Say ("  {0}  {1:N0} B  {2}" -f $_.Name, $_.Length, $_.LastWriteTime)
  }
  Say ("  total cab = " + @(Get-ChildItem $oc -Filter '*.cab' -Recurse).Count)
}

Say '=== 5. 本机 OS ==='
$os = Get-CimInstance Win32_OperatingSystem
Say ("  " + $os.Caption + " " + $os.Version + " build " + $os.BuildNumber)

Say '=== 6. ISO 挂载能力(只读测试, 不改动任何文件) ==='
$iso = 'D:\迅雷下载\zh-cn_windows_10_enterprise_ltsc_2021_x64_dvd_033b7312.iso'
if (Test-Path $iso) {
  Say ("  found " + $iso + " size=" + (Get-Item $iso).Length)
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Say ("  isAdmin=" + $isAdmin)
  if ($isAdmin) {
    try {
      Mount-DiskImage -ImagePath $iso -AccessTimeout 15 -EA Stop | Out-Null
      $d = (Get-DiskImage -ImagePath $iso | Get-Volume).DriveLetter
      Say ("  MOUNTED as " + $d + ":")
      Get-ChildItem ($d + ':\sources') -EA SilentlyContinue | Where-Object { $_.Length -gt 1MB -or $_.Name -like '*.wim' } | ForEach-Object { Say ("    " + $_.Name + " " + $_.Length) }
      $bw = ($d + ':\sources\boot.wim')
      if (Test-Path $bw) { & dism.exe /Get-WimInfo /WimFile:$bw 2>&1 | ForEach-Object { Say ('    ' + $_) } }
      Dismount-DiskImage -ImagePath $iso | Out-Null
      Say '  unmounted'
    } catch { Say ('  MOUNT FAILED: ' + $_.Exception.Message) }
  } else { Say '  skip mount (需要管理员)' }
} else { Say ("  (missing) " + $iso) }

Say '=== 7. 网络到 ADK 下载点 ==='
foreach ($u in @('https://go.microsoft.com/fwlink/?linkid=2166289', 'https://download.microsoft.com/download/')) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri $u -Method Head -TimeoutSec 15
    Say ("  OK " + $u + " -> " + $r.StatusCode)
  } catch { Say ("  FAIL " + $u + " -> " + $_.Exception.Message) }
}
Say '=== done ==='
