# 编译 wifi.exe 并同步到 overlay\Tools 与 test\share
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File wifitool\build.ps1
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Proj = Split-Path -Parent $Root
$GoExe = Join-Path $Proj 'tools\go\bin\go.exe'
if (-not (Test-Path $GoExe)) {
  Write-Host "找不到 Go: 需要 tools\go\bin\go.exe" -ForegroundColor Red
  exit 1
}

$env:GOCACHE     = Join-Path $Proj 'build\gocache'
$env:GOMODCACHE  = Join-Path $Proj 'build\gomod'
$env:CGO_ENABLED = '0'
$env:GOOS        = 'windows'
$env:GOARCH      = 'amd64'
New-Item -ItemType Directory -Force -Path $env:GOCACHE, $env:GOMODCACHE | Out-Null

$Out = Join-Path $Proj 'overlay\Tools'
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Push-Location $Root
try {
  Write-Host '[1/2] go build (console, 静态) ...' -ForegroundColor Cyan
  & $GoExe build -trimpath -ldflags '-s -w' -o (Join-Path $Out 'wifi.exe') .
  if ($LASTEXITCODE -ne 0) { throw 'go build 失败' }
  $exe = Get-Item (Join-Path $Out 'wifi.exe')
  Write-Host ('  产物 wifi.exe {0:N0} KB' -f ($exe.Length / 1KB))

  Write-Host '[2/2] 同步 test\share\wifi.exe ...' -ForegroundColor Cyan
  if (Test-Path (Join-Path $Proj 'test\share')) {
    Copy-Item $exe.FullName (Join-Path $Proj 'test\share\wifi.exe') -Force
    Write-Host '  已同步 test\share\wifi.exe'
  }
  Write-Host ('完成: ' + $exe.FullName) -ForegroundColor Green
} finally {
  Pop-Location
}
