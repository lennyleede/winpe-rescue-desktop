# ============================================================
# 2A-0 只读侦察: 宿主机 DriverStore 里有哪些 Net 类驱动包。
#   不动系统、不写 C:。输出 build\host_netdrivers.txt
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\scratch\recon_host_netdrivers.ps1
# ============================================================
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Ds   = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
$Out  = Join-Path $Root 'build\host_netdrivers.txt'
if (-not (Test-Path $Ds)) { Write-Host "没有 DriverStore: $Ds" -ForegroundColor Red; exit 1 }

$infs = @(Get-ChildItem -LiteralPath $Ds -Directory -EA SilentlyContinue |
          ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter '*.inf' -EA SilentlyContinue })
Write-Host ('  DriverStore 包目录里 INF 总数: ' + $infs.Count + '  开始筛 Class=Net ...') -ForegroundColor Cyan

$rows = @()
foreach ($fi in $infs) {
  $txt = ''
  try { $txt = Get-Content -LiteralPath $fi.FullName -Raw -EA Stop } catch { continue }
  $cm = [regex]::Match($txt, '(?im)^\s*Class\s*=\s*(\S+)')
  if ($cm.Success -ne 'True') { continue }
  $cls = $cm.Groups[1].Value.Trim()
  if ($cls -notmatch '^(Net|Net.*)$' -and $cls -ne 'Net') { continue }
  $dv = [regex]::Match($txt, '(?im)^\s*DriverVer\s*=\s*([0-9/]{8,10})\s*,\s*([0-9.]+)')
  $prov = [regex]::Match($txt, '(?im)^\s*Provider\s*=\s*"?([^"\r\n,]+)')
  $dir = Split-Path -Parent $fi.FullName
  $sz = 0
  try { $sz = [math]::Round(((Get-ChildItem -LiteralPath $dir -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum) / 1MB, 2) } catch {}
  $rows += [pscustomobject]@{
    Inf       = $fi.Name.ToLower()
    Dir       = $dir
    Class     = $cls
    DriverVer = $(if ($dv.Success) { $dv.Groups[1].Value + ' ' + $dv.Groups[2].Value } else { '?' })
    Prov      = $(if ($prov.Success) { $prov.Groups[1].Value.Trim() } else { '?' })
    MB        = $sz
  }
}

$rows = @($rows | Sort-Object Inf -Unique)
$rep = @()
$rep += '==== 宿主机 DriverStore 里的 Net 类驱动包 (只读侦察) ===='
$rep += ('生成时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$rep += ('DriverStore : ' + $Ds)
$rep += ('Net 包数 : ' + $rows.Count + ' 个 / 合计 ' + [math]::Round((($rows | Measure-Object MB -Sum).Sum), 1) + ' MB')
$rep += ''
foreach ($r in $rows) { $rep += ('  {0,-28} {1,-24} {2,-14} {3,7:N1} MB  {4}' -f $r.Inf, $r.DriverVer, $r.Prov, $r.MB, (Split-Path -Leaf $r.Dir)) }
Set-Content -LiteralPath $Out -Value $rep -Encoding UTF8
Write-Host ('  Net 包 ' + $rows.Count + ' 个, 已写 ' + $Out) -ForegroundColor Green
