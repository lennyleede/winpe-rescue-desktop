# Non-admin pre-check for the WinPE10 acceptance run: proves the ISO on disk really is the
# newest injected boot.wim, that it is bootable, and that the host has room for the VM.
$ErrorActionPreference = 'Continue'
$Root = 'D:\QoderProject\国内版\生成winpe'
$Iso  = Join-Path $Root 'dist\WinPE10_Desktop_v1.iso'
$Wim  = 'D:\pe10_work\media\sources\boot.wim'
$Key  = Join-Path $Root 'overlay\Scripts\ssh_login_key'
function Say($s) { Write-Output $s }

if (Test-Path $Iso) {
  $i = Get-Item $Iso
  Say ('ISO   = ' + $i.FullName)
  Say ('        size=' + $i.Length + ' (' + ('{0:N1}' -f ($i.Length / 1MB)) + ' MB)  mtime=' + $i.LastWriteTime)
} else { Say ('ISO MISSING: ' + $Iso) }

foreach ($cand in @($Wim, (Join-Path $Root 'build10\boot.wim'), (Join-Path $Root 'build\boot10.wim'))) {
  if (Test-Path $cand) {
    $w = Get-Item $cand
    Say ('WIM   = ' + $w.FullName + '  size=' + $w.Length + '  mtime=' + $w.LastWriteTime)
    if (Test-Path $Iso) {
      if ($w.LastWriteTime -gt (Get-Item $Iso).LastWriteTime) {
        Say '        !! boot.wim 比 ISO 新 —— 最后一次注入没重新打包, 这张 ISO 不含最新内容'
      } else { Say '        OK: ISO 不早于 boot.wim' }
    }
    break
  }
}
if (-not (Test-Path $Wim)) { Say ('(工作挂载点不存在或不可读: ' + $Wim + ')') }

Say ('LOGINKEY = ' + $(if (Test-Path $Key) { 'present (host-only, must never be copied in)' } else { 'MISSING -> SSH 检查会直接失败' }))
$os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
if ($os) { Say ('HOSTMEM free=' + [int]($os.FreePhysicalMemory / 1024) + ' MB total=' + [int]($os.TotalVisibleMemorySize / 1024) + ' MB  (VM 需要 2048MB + 700MB 余量)') }
$dh = Get-PSDrive D -EA SilentlyContinue
if ($dh) { Say ('DISK D: free=' + [int]($dh.Free / 1GB) + ' GB') }
Say 'ISO 引导结构:'
& PowerShell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root 'test\check_isoboot.ps1') -Iso $Iso 2>&1 | ForEach-Object { Say ('  ' + $_) }
