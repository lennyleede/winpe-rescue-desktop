# 编译 pe-sshd 并把产物放进 overlay\SSH
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File sshserver\build.ps1
$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Proj = Split-Path -Parent $Root
$GoExe = Join-Path $Proj 'tools\go\bin\go.exe'
if (-not (Test-Path $GoExe)) {
  Write-Host "找不到 Go: 先把 downloads\go1.21.13.windows-amd64.zip 解压到 $Proj\tools\ (得到 tools\go\bin\go.exe)" -ForegroundColor Red
  exit 1
}

$Cache = Join-Path $Proj 'build\gocache'
$Mod   = Join-Path $Proj 'build\gomod'
New-Item -ItemType Directory -Force -Path $Cache, $Mod | Out-Null

$env:GOPROXY     = 'https://goproxy.cn,direct'
$env:GOFLAGS     = '-mod=mod'
$env:GOCACHE     = $Cache
$env:GOMODCACHE  = $Mod
$env:CGO_ENABLED = '0'
$env:GOOS        = 'windows'
$env:GOARCH      = 'amd64'

$Out = Join-Path $Proj 'overlay\SSH'
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Push-Location $Root
try {
  Write-Host '[1/3] go mod tidy ...' -ForegroundColor Cyan
  & $GoExe mod tidy
  if ($LASTEXITCODE -ne 0) { throw 'go mod tidy 失败' }

  Write-Host '[2/3] go build -H=windowsgui ...' -ForegroundColor Cyan
  # -H=windowsgui: 无控制台窗口, 不在救援桌面背后闪黑框; 日志走 -log 文件
  & $GoExe build -trimpath -ldflags '-s -w -H=windowsgui' -o (Join-Path $Out 'pe-sshd.exe') .
  if ($LASTEXITCODE -ne 0) { throw 'go build 失败' }
  $exe = Get-Item (Join-Path $Out 'pe-sshd.exe')
  Write-Host ('  产物 pe-sshd.exe {0:N0} KB' -f ($exe.Length / 1KB))

  Write-Host '[3/3] 同步 authorized_keys ...' -ForegroundColor Cyan
  Copy-Item (Join-Path $Proj 'overlay\Scripts\administrators_authorized_keys') (Join-Path $Out 'authorized_keys') -Force
  # 私钥只留在宿主机, 不能进镜像
  if (-not (Test-Path (Join-Path $Proj 'overlay\Scripts\ssh_login_key.pub'))) { throw '缺少 ssh_login_key.pub' }
  $pub = (Get-Content (Join-Path $Proj 'overlay\Scripts\administrators_authorized_keys') -Raw).Trim()
  if ($pub -ne (Get-Content (Join-Path $Proj 'overlay\Scripts\ssh_login_key.pub') -Raw).Trim()) {
    Write-Host '  警告: authorized_keys 与 ssh_login_key.pub 不一致, 用 .pub 覆盖' -ForegroundColor Yellow
    Copy-Item (Join-Path $Proj 'overlay\Scripts\ssh_login_key.pub') (Join-Path $Out 'authorized_keys') -Force
  }
  Write-Host ('完成: ' + $exe.FullName) -ForegroundColor Green
  # 顺带同步给 Hyper-V 落地测试的下发目录, 免得 test\share 里一直留旧版 exe
  if (Test-Path (Join-Path $Proj 'test\share')) {
    Copy-Item (Join-Path $Out 'pe-sshd.exe') (Join-Path $Proj 'test\share\pe-sshd.exe') -Force
    Copy-Item (Join-Path $Out 'authorized_keys') (Join-Path $Proj 'test\share\authorized_keys') -Force
    Write-Host '  已同步 test\share\pe-sshd.exe / authorized_keys'
  }
} finally {
  Pop-Location
}
