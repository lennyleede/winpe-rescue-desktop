# ASCII only: how much RAM can a new VM actually get right now?
$os = Get-CimInstance Win32_OperatingSystem
$tot = [int]($os.TotalVisibleMemorySize / 1024)
$free = [int]($os.FreePhysicalMemory / 1024)
Write-Host ('物理内存 总=' + $tot + ' MB  空闲=' + $free + ' MB  已用=' + ($tot - $free) + ' MB')
$pross = Get-CimInstance Win32_Process | Sort-Object -Descending WorkingSetSize | Select-Object -First 12
foreach ($p in $pross) { Write-Host ('  ' + ('{0,8:N0}' -f ($p.WorkingSetSize/1MB)) + ' MB  ' + $p.Name + '  pid=' + $p.ProcessId) }
Write-Host '--- VMMS / 虚拟机占用(能读到就读, 读不到说明没管理员) ---'
try {
  $vms = Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem -Filter 'Caption="Virtual Machine"' -EA Stop
  foreach ($v in $vms) { Write-Host ('  ' + $v.ElementName + ' EnabledState=' + $v.EnabledState) }
} catch { Write-Host ('  读不到: ' + $_.Exception.Message) }
