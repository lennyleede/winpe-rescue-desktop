# 只读探测: 本机 PE 基镜像版本 + Win10 ADK 素材是否可获得(不写系统目录)
$ErrorActionPreference = 'Continue'
function Ver($p) { if (Test-Path $p) { try { return (Get-Item $p).VersionInfo.FileVersion } catch { return '?' } } return '(missing)' }

Write-Output '=== 1. 基镜像版本 ==='
$adkWim = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\en-us\winpe.wim'
Write-Output ('  ADK winpe.wim: ' + $adkWim)
if (Test-Path $adkWim) {
  & dism.exe /Get-WimInfo /WimFile:$adkWim 2>&1 | Select-String -Pattern 'Index|Name|Arch|Version|Size' | ForEach-Object { Write-Output ('    ' + $_.Line.Trim()) }
}
$ourWim = 'D:\QoderProject\国内版\生成winpe\build\WinPE_amd64\media\sources\boot.wim'
Write-Output ('  本项目 boot.wim: ' + $ourWim + ' 存在=' + (Test-Path $ourWim))
if (Test-Path $ourWim) {
  & dism.exe /Get-WimInfo /WimFile:$ourWim 2>&1 | Select-String -Pattern 'Index|Name|Arch|Version|Size' | ForEach-Object { Write-Output ('    ' + $_.Line.Trim()) }
}
Write-Output ('  ADK bootmgr.efi  ' + (Ver 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\Media\bootmgr.efi'))
Write-Output ('  ADK bootsect?    ' + (Ver 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\amd64\Media\Boot\bootsect.exe'))
Write-Output ('  ADK bcdboot      ' + (Ver 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe'))

Write-Output '=== 2. 本机是否残留 Win10 版 ADK 素材(winpe.wim/WinPE_OCs) ==='
$hits = @()
foreach ($root in @('C:\Windows\Temp','C:\ProgramData','D:\winpe_build','D:\迅雷下载','D:\Program Files','D:\dev')) {
  if (-not (Test-Path $root)) { continue }
  $hits += Get-ChildItem $root -Recurse -Depth 3 -Include 'winpe.wim','WinPE-HTA.cab','adksetup.exe','WinPE.wim' -File -EA SilentlyContinue | Select-Object -First 20
}
if ($hits.Count -eq 0) { Write-Output '  (无)' } else { $hits | ForEach-Object { Write-Output ('  {0,15:N0} {1} {2}' -f $_.Length, $_.LastWriteTime, $_.FullName) } }
Write-Output ('  旧 adksetup.exe 版本: ' + (Ver 'D:\winpe_build\downloads\adksetup.exe'))

Write-Output '=== 3. 网络: Win10 ADK 下载点(TLS1.2) ==='
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
foreach ($u in @(
  'https://go.microsoft.com/fwlink/?linkid=2166289',
  'https://go.microsoft.com/fwlink/?linkid=2243689',
  'https://download.microsoft.com/download/8/5/f/85fabf0c-5ca6-4f57-9ab7-e874826c87af/adksetup.exe',
  'https://www.microsoft.com/en-us/download/details.aspx?id=57477')) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri $u -Method Head -MaximumRedirection 5 -TimeoutSec 25 -EA Stop
    Write-Output ('  OK   ' + $r.StatusCode + ' ' + $u + ' len=' + $r.Headers['Content-Length'] + ' type=' + $r.Headers['Content-Type'])
  } catch { Write-Output ('  FAIL ' + $u + ' -> ' + $_.Exception.Message) }
}
Write-Output '=== done ==='
