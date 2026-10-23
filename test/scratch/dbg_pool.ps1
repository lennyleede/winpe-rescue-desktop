$ErrorActionPreference = 'Stop'
$Root = 'D:\QoderProject\国内版\生成winpe'
. (Join-Path $Root 'test\NetDrvLib.ps1')
$p = Get-NetDrvPool -DrvDir 'D:\winpe_build\hotpe_net\Lan' -ClassName @()
Write-Output ('type   : ' + $p.GetType().Name)
Write-Output ('keys   : ' + ($p.Keys -join ','))
Write-Output ('rows   : ' + @($p.Rows).Count)
Write-Output ('idx    : ' + $p.Idx.Count)
Write-Output ('bind?  : ' + ($p.ContainsKey('Bind')))
Write-Output ('10D3 decl: ' + $p.Decl.ContainsKey('PCI\VEN_8086&DEV_10D3'))
Write-Output ('10D3 idx : ' + $p.Idx.ContainsKey('PCI\VEN_8086&DEV_10D3'))
Write-Output ('15AD idx : ' + $p.Idx.ContainsKey('PCI\VEN_15AD&DEV_07B0'))
Write-Output ('hostds testpath: ' + (Test-Path (Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository')))
