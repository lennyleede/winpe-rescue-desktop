# 宿主机自测新加的 wifi.exe 子命令(只读, 不需管理员)
$ErrorActionPreference = 'Continue'
$W = Join-Path (Split-Path -Parent $PSScriptRoot) 'overlay\Tools\wifi.exe'
Write-Host ('wifi.exe: ' + (Get-Item $W).Length + ' bytes, ' + (Get-Item $W).LastWriteTime)
Write-Host '=== svc info wlansvc ==='
& $W svc info wlansvc
Write-Host '=== deps wlansvc ==='
& $W deps wlansvc
Write-Host '=== regq DependOnService ==='
& $W regq 'SYSTEM\CurrentControlSet\Services\wlansvc' 'DependOnService'
Write-Host '=== regq Type(DWORD) ==='
& $W regq 'SYSTEM\CurrentControlSet\Services\wlansvc' 'Type'
Write-Host '=== regq Parameters ServiceMain ==='
& $W regq 'SYSTEM\CurrentControlSet\Services\wlansvc\Parameters' 'ServiceMain'
Write-Host '=== dllload wlansvc.dll WlanSvcMain ==='
& $W dllload "$env:SystemRoot\System32\wlansvc.dll" WlanSvcMain
Write-Host '=== dllload 不存在的导出 ==='
& $W dllload "$env:SystemRoot\System32\wlansvc.dll" NotAnExport12345
Write-Host '=== dllload 不存在的文件 ==='
& $W dllload 'C:\Windows\System32\no_such_dll.dll'
Write-Host '=== svc watch wlansvc 1200 (不启动) ==='
& $W svc watch wlansvc 1200
