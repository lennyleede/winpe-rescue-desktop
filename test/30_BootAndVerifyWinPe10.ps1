# ============================================================
# 30_BootAndVerifyWinPe10.ps1 —— Win10 分支 PE 的 Hyper-V 验收一条龙
#   建 VM(Gen2/2GB/2vCPU/Default Switch/只挂 DVD) -> 开机 -> 找到"这台"PE 的 pe-sshd
#   -> 先做身份闸门(必须是 BUILD_TAG 里 product=WinPE10_Desktop_v1 且 OS=10.0.19041.x)
#   -> 再逐项自检, 全过程写 test\vm10_verify.txt(我这边直接读)
#
# 2026-10-07 第一轮踩到的坑: 只是"扫子网找开放 22 的 IP", 结果连上了 10-05 起就没关的
# 旧 v8 测试机(ver=10.0.26100.1 / 没有 BUILD_TAG / 两块网卡)。所以这里改成:
#   (a) 开机前先做一次基线扫描, 已经开着 22 端口的 IP 全部排除;
#   (b) 用本 VM 的 MAC 和 Get-NetNeighbor 做正向确认;
#   (c) SSH 进去第一件事就是身份校验, 对不上直接 abort, 绝不把别人的结果当成本次的结论。
# Secure Boot 先按"开着"试, 起不来自动关掉重试一次并记下结论。
# 需要管理员:
#   powershell -NoProfile -ExecutionPolicy Bypass -File test\30_BootAndVerifyWinPe10.ps1
# ============================================================
param(
  [string]$Iso = 'D:\QoderProject\国内版\生成winpe\dist\WinPE10_Desktop_v1.iso',
  [string]$VMName = 'WinPE10-Test',
  [string]$ExpectProduct = 'WinPE10_Desktop_v1',
  [int]$RAMMB = 2048,
  [int]$WaitSec = 300,
  [string]$User = 'Administrator',
  [switch]$SkipCreate,
  [switch]$NoStopOthers,
  [switch]$ScanOnly
)
$ErrorActionPreference = 'Continue'
$Root = Split-Path $PSScriptRoot -Parent
$Out  = Join-Path $PSScriptRoot $(if ($ScanOnly) { 'vm10_scan.txt' } else { 'vm10_verify.txt' })
$rows = New-Object System.Collections.ArrayList
function L($m) {
  Write-Host $m
  [void]$rows.Add([string]$m)
  try { Set-Content -LiteralPath $Out -Value ($rows -join "`r`n") -Encoding UTF8 } catch { }
}
function Test-Port22([string]$ip) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $r = $c.BeginConnect($ip, 22, $null, $null); $ok = $r.AsyncWaitHandle.WaitOne(120); return ($ok -and $c.Connected) }
  catch { return $false } finally { $c.Close() }
}
function Get-VMIpKvp {
  # 快路径: Hyper-V 集成服务上报的 IP。WinPE 一般没有 KVP, 但试一次不花钱。
  $ips = (Get-VMNetworkAdapter -VMName $VMName -EA SilentlyContinue).IPAddresses
  return @(@($ips) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and (Test-Port22 $_) })
}
function Get-Open22 {
  # 2026-10-07 第一版的致命简化: 只扫宿主所在 /24。可 Default Switch 是 /20,
  # 上一轮 VM 实际拿到 172.17.37.103 而宿主是 172.17.32.x —— 根本不在同一个 /24, 会一直"等不到"。
  # 这里按真实的 prefix 扫整个 /20, 但改成 256 个一批的并发异步连接(串行 4094 次要二十多分钟)。
  $h = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -EA SilentlyContinue | Select-Object -First 1
  if (-not $h) { return @() }
  $pl = [int]$h.PrefixLength
  if ($pl -lt 16 -or $pl -gt 28) { $pl = 20 }
  $p = $h.IPAddress.Split('.') | ForEach-Object { [int64]$_ }
  $ipInt = ($p[0] -shl 24) + ($p[1] -shl 16) + ($p[2] -shl 8) + $p[3]
  $hostBits = 32 - $pl
  $mask = -bnot (([int64]1 -shl $hostBits) - 1)
  $netBase = $ipInt -band $mask
  $total = [int64]1 -shl $hostBits
  $cands = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -lt ($total - 1); $i++) {
    $a = $netBase + $i
    $s = '{0}.{1}.{2}.{3}' -f (($a -shr 24) -band 255), (($a -shr 16) -band 255), (($a -shr 8) -band 255), ($a -band 255)
    if ($s -eq $h.IPAddress) { continue }
    [void]$cands.Add($s)
  }
  $hits = @()
  $batch = 256
  for ($off = 0; $off -lt $cands.Count; $off += $batch) {
    $last = [int]($off + $batch - 1); if ($last -ge $cands.Count) { $last = $cands.Count - 1 }
    $pending = @()
    foreach ($ip in @($cands.GetRange($off, $last - $off + 1))) {
      $c = New-Object System.Net.Sockets.TcpClient
      $ar = $null
      try { $ar = $c.BeginConnect($ip, 22, $null, $null) } catch { try { $c.Close() } catch { }; continue }
      $pending += ,@($ip, $c, $ar)
    }
    $stop = (Get-Date).AddSeconds(2)
    foreach ($t in $pending) {
      $rem = ($stop - (Get-Date)).TotalMilliseconds
      if ($rem -lt 0) { $rem = 0 }
      if (-not $t[2].AsyncWaitHandle.WaitOne([int]$rem)) { continue }
      try { $t[1].EndConnect($t[2]); if ($t[1].Connected) { $hits += $t[0] } } catch { }
    }
    foreach ($t in $pending) { try { $t[1].Close() } catch { } }
  }
  return $hits
}
# ---------- 控制台截图: 不用人肉看 Hyper-V 窗口也能知道卡在哪儿 ----------
# Hyper-V 模块没有截图 cmdlet, 走 WMI 的 Msvm_VideoHeadService.GetScreenImage
# (返回 BITMAPINFOHEADER + 32bpp 位图像素), 自己拼 BMP 头写成 .bmp。
# Gen1 的 legacy 控制台走不通, 本 VM 是 Gen2, 用的是标准的这条路径。
function Build-VideoHeadRef([string]$vmGuid, $head) {
  # CIM 对象的 __PATH 是空的, 引用路径只能自己按 key 拼; key 名从对象上实际存在的属性里挑,
  # 省得不同 Hyper-V 版本 key 集合不一样时拼出非法引用。
  $parts = @()
  foreach ($k in @('SystemCreationClassName', 'SystemName', 'CreationClassName', 'DeviceID', 'Name', 'ID', 'InstanceID')) {
    $v = $head.PSObject.Properties[$k]
    if ($v -and $v.Value) { $parts += ($k + '="' + ([string]$v.Value).Replace('"', '\"') + '"') }
  }
  if (-not $parts.Count) { $parts = @('SystemCreationClassName="Msvm_ComputerSystem"', ('SystemName="' + $vmGuid + '"')) }
  return 'root\virtualization\v2:Msvm_VideoHead.' + ($parts -join ',')
}
function Save-VmScreen([string]$tag) {
  try {
    $ns = 'root\virtualization\v2'
    $st = Get-VM -Name $VMName -EA SilentlyContinue
    if (-not $st -or $st.State -ne 'Running') { L ('    [screen] VM 不在 Running(' + $(if ($st) { $st.State } else { '不存在' }) + '), 跳过截图'); return $false }
    # 取 VideoHead 的写法换掉了: 之前是 ASSOCIATORS OF {引用路径}, 而 Get-CimInstance 回来的对象
    # __PATH 是空的 => 每次都是"无效的对象路径"(2026-10-07 两轮截图全废就因为这个)。
    # 现在按 SystemName = VM 的 GUID 直接查这个类, 不需要引用路径。SWMI 优先, 它的 __PATH 可靠。
    $cs = $null; $head = $null; $headRef = ''
    try {
      $cs = Get-WmiObject -Namespace $ns -Class Msvm_ComputerSystem -EA Stop |
            Where-Object { $_.ElementName -eq $VMName } | Select-Object -First 1
      if ($cs) { $head = Get-WmiObject -Namespace $ns -Class Msvm_VideoHead -Filter ('SystemName=''' + $cs.Name + '''') -EA SilentlyContinue | Select-Object -First 1 }
    } catch { L ('    [screen] SWMI 异常: ' + ($_.Exception.Message -replace '\s+', ' ')) }
    if ($head) { $headRef = [string]$head.__PATH }
    else {
      $cc = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -EA SilentlyContinue |
            Where-Object { $_.ElementName -eq $VMName } | Select-Object -First 1
      if ($cc) {
        $head = Get-CimInstance -Namespace $ns -ClassName Msvm_VideoHead -EA SilentlyContinue |
                Where-Object { $_.SystemName -eq $cc.Name } | Select-Object -First 1
        if ($head) { $headRef = Build-VideoHeadRef $cc.Name $head }
      }
    }
    if (-not $head) {
      $seen = @(Get-CimInstance -Namespace $ns -ClassName Msvm_VideoHead -EA SilentlyContinue | ForEach-Object { $_.SystemName } | Select-Object -First 6)
      L ('    [screen] 没有 Msvm_VideoHead(Gen2 正常不该这样)。当前所有 VideoHead 的 SystemName 前 6 个 = ' + ($seen -join ', ') + ' (' + $tag + ')')
      return $false
    }
    $svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VideoHeadService -EA Stop | Select-Object -First 1
    if (-not $svc) { L ('    [screen] 没有 Msvm_VideoHeadService: ' + $tag); return $false }
    $r = Invoke-CimMethod -InputObject $svc -MethodName GetScreenImage -Arguments @{ VideoHead = $headRef } -EA Stop
    if ($r.ReturnValue -ne 0) { L ('    [screen] GetScreenImage rv=' + $r.ReturnValue + ' (' + $tag + ')'); return $false }
    # 输出参数名在不同文档/版本里有 ScreenImage / ScreenData 两种写法, 两个都认, 全没有就把属性名打出来。
    $d = $null
    foreach ($nm in @('ScreenImage', 'ScreenData')) {
      $v = $r.PSObject.Properties[$nm]
      if ($v -and $v.Value) { $a = @($v.Value); if ($a.Count -ge 54) { $d = [byte[]]$a; break } }
    }
    if (-not $d) {
      L ('    [screen] 返回里没有位图数据, 属性名 = ' + (($r.PSObject.Properties | ForEach-Object { $_.Name }) -join ',') + ' (' + $tag + ')')
      return $false
    }
    $w = [BitConverter]::ToInt32($d, 4); $hgt = [BitConverter]::ToInt32($d, 8)
    $pix = [Math]::Abs($hgt)
    $bf = New-Object byte[] (14 + $d.Length)
    $bf[0] = 0x42; $bf[1] = 0x4D
    $size = [BitConverter]::GetBytes([int](14 + $d.Length)); [Array]::Copy($size, 0, $bf, 2, 4)
    $off = [BitConverter]::GetBytes([int]54); [Array]::Copy($off, 0, $bf, 10, 4)
    [Array]::Copy($d, 0, $bf, 14, $d.Length)
    $p = Join-Path $PSScriptRoot ('vm10_screen_' + $tag + '.bmp')
    [System.IO.File]::WriteAllBytes($p, $bf)
    L ('    [screen] ' + $tag + ' -> ' + (Split-Path $p -Leaf) + ' (' + $w + 'x' + $pix + ', ' + [int]($bf.Length/1024) + ' KB)')
    return $true
  } catch {
    L ('    [screen] 异常: ' + $_.Exception.Message)
    return $false
  }
}

function Get-FreeMemMB {
  $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
  if (-not $os) { return -1 }
  return [int]($os.FreePhysicalMemory / 1024)
}
function Stop-OtherVms {
  # 2026-10-07 那次 20 分钟白跑的直接原因: 宿主 12GB 只剩 2.4GB 空闲, 而 PE-TEST / WinPE-Test /
  # WinPE10-Test 三台同时在跑 —— Start-VM 先报 "Microsoft Video Monitor 资源保留失败 0x80004005",
  # 再报 "系统内存不足 0x8007000E"。这跟镜像一点关系都没有, 但脚本一直傻等到超时。
  if ($NoStopOthers) { L '    (按要求不动别的 VM)'; return }
  $others = @(Get-VM -EA SilentlyContinue | Where-Object { $_.State -eq 'Running' -and $_.Name -ne $VMName })
  if (-not $others.Count) { return }
  foreach ($v in $others) {
    L ('    关掉别的在跑的 VM 腾内存: ' + $v.Name + ' (TurnOff, 不删除)')
    Stop-VM -Name $v.Name -TurnOff -Force -EA SilentlyContinue
  }
  Start-Sleep 5
}
function Set-VmLowVideo([string]$Why) {
  # 显存/视频资源保留在内存吃紧时会先炸(2026-10-07 那次就是 Video Monitor 0x80004005),
  # 降到 1024x768 单显示器最省。Set-VMVideo 的参数集在不同模块版本上不完全一样, 两种写法都试。
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
  Set-VMVideo -VMName $VMName -MonitorCount 1 -LowResolution
  Set-VMVideo -VMName $VMName -MonitorCount 1 -HorizontalResolution 1024 -VerticalResolution 768
  $ErrorActionPreference = $prev
  L ('    已把显存降到 1024x768 单屏 (' + $Why + ')')
}
function Start-PeVm {
  # 起不来就立刻回报原因, 绝不让调用方拿"等不到 22 端口"去猜是不是镜像坏了。
  param([string]$Why)
  $need = $RAMMB + 700
  $free = Get-FreeMemMB
  L ('    启动前 空闲内存=' + $free + ' MB, 本机需要 ' + $RAMMB + ' MB (' + $Why + ')')
  if ($free -ge 0 -and $free -lt $need) { Stop-OtherVms; $free = Get-FreeMemMB; L ('    清理后 空闲内存=' + $free + ' MB') }
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Stop'
  for ($try = 1; $try -le 2; $try++) {
    try {
      Start-VM -VMName $VMName -EA Stop
      $ErrorActionPreference = $prev
      L ('    Start-VM 成功 (' + $Why + ', 第 ' + $try + ' 次尝试)')
      return $true
    } catch {
      $msg = $_.Exception.Message -replace '\s+', ' '
      L ('    !! Start-VM 失败(第 ' + $try + ' 次): ' + $msg)
      if ($msg -match 'Video Monitor') {
        L '    -> 试降显存(Video Monitor 资源保留失败常见于内存吃紧)'
        Set-VmLowVideo '降显存'
      }
      if ($try -eq 1) {
        Stop-OtherVms
        $free = Get-FreeMemMB
        if ($free -lt $need) { L ('    空闲内存仍只有 ' + $free + ' MB(< ' + $need + '), 再试一次但不保证起得来') }
        Stop-VM -Name $VMName -TurnOff -Force -EA SilentlyContinue; Start-Sleep 3
      }
    }
  }
  $ErrorActionPreference = $prev
  L ('    当前所有 VM = ' + ((@(Get-VM -EA SilentlyContinue | ForEach-Object { $_.Name + '(' + $_.State + '/' + [int]($_.MemoryAssigned/1MB) + 'MB)' })) -join ', '))
  return $false
}

function Norm-Mac([string]$s) {  # Get-VMNetworkAdapter 给 "00155D006907", Get-NetNeighbor 给 "00-15-5d-00-69-07", 统一成 12 位大写十六进制再比
  return (($s -replace '[^0-9A-Fa-f]', '').ToUpper())
}
function Get-MacOfNeighbor([string]$ip) {
  $n = Get-NetNeighbor -IPAddress $ip -EA SilentlyContinue | Select-Object -First 1
  if ($n) { return (Norm-Mac $n.LinkLayerAddress) }
  foreach ($line in @(arp -a | Select-String ([regex]::Escape($ip)))) {
    $m = [regex]::Match("$line", '([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}')
    if ($m.Success) { return (Norm-Mac $m.Value) }
  }
  return ''
}

# ---------- 只做一次子网扫描, 不建 VM(普通权限可跑, 用来验证发现逻辑本身) ----------
if ($ScanOnly) {
  $t0 = Get-Date
  $ips = @(Get-Open22)
  L ('ScanOnly: /20 内开放 22 端口的 IP = ' + $(if ($ips.Count) { $ips -join ', ' } else { '无' }) +
     '  用时 ' + [int]((Get-Date).Subtract($t0).TotalSeconds) + 's')
  foreach ($ip in $ips) { L ('    ' + $ip + ' -> MAC ' + (Get-MacOfNeighbor $ip)) }
  exit 0
}

# ---------- 前置 ----------
$winid = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = ([Security.Principal.WindowsPrincipal]$winid).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  if ($SkipCreate) { L '注意: 当前不是管理员 —— -SkipCreate 只做 SSH 验证, 不碰 Hyper-V' }
  else { L 'ERROR: 需要管理员 PowerShell (New-VM / Start-VM / Get-NetNeighbor)'; exit 1 }
}
if (-not (Test-Path $Iso)) { L ('ERROR: 找不到 ISO: ' + $Iso); exit 1 }
Import-Module Hyper-V -EA SilentlyContinue
if (-not (Get-Command Get-VM -EA SilentlyContinue)) { L 'ERROR: 这台机器没有 Hyper-V 模块'; exit 1 }
L ('===== Win10 PE 验收 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' =====')
L ('ISO = ' + (Split-Path $Iso -Leaf) + ' (' + ('{0:N1}' -f ((Get-Item $Iso).Length / 1MB)) + ' MB)')
L ('现有 VM = ' + $(if ($SkipCreate) { '(-SkipCreate 未查询)' } else { (@(Get-VM -EA SilentlyContinue | ForEach-Object { $_.Name + '(' + $_.State + ')' }) -join ', ') }))

$IP = $null
$PeBooted = $false
$FailMode = ''
if ($SkipCreate) {
  $f = Join-Path $PSScriptRoot 'vm_ip.txt'
  if (-not (Test-Path $f)) { L 'ERROR: -SkipCreate 但没有 vm_ip.txt'; exit 1 }
  $IP = (Get-Content $f).Trim()
  $wantMac = ''
  L ('SkipCreate: 沿用 ' + $IP)
} else {
  if (Get-VM -Name $VMName -EA SilentlyContinue) {
    L ('[1] 已存在 ' + $VMName + ', 删掉重建(只动这一台)')
    Stop-VM -Name $VMName -TurnOff -Force -EA SilentlyContinue; Start-Sleep 2
    Remove-VM -Name $VMName -Force
  }
  $switch = Get-VMSwitch | Where-Object { $_.Name -eq 'Default Switch' } | Select-Object -First 1
  if (-not $switch) { $switch = Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' } | Select-Object -First 1 }
  if (-not $switch) { L 'ERROR: 没有可用虚拟交换机'; exit 1 }

  # ---------- 基线: 开机前就已经开放 22 的 IP 全是"别人"(旧测试机) ----------
  L '[2] 开机前基线扫描(排除别的 VM 的 pe-sshd) ...'
  $baseline = @(Get-Open22)
  L ('    已开放 22 的 IP = ' + $(if ($baseline.Count) { $baseline -join ', ' } else { '无' }))
  if ($baseline.Count -gt 0) { L '    提示: 那些是别的仍在运行的 PE 测试机, 本次会跳过它们' }

  $vmPath = Join-Path $PSScriptRoot 'vm'
  New-Item -ItemType Directory -Force -Path $vmPath | Out-Null
  L ('[3] 建 VM ' + $VMName + ' Gen2 / ' + $RAMMB + 'MB 固定 / 2vCPU / 交换机=' + $switch.Name + ' / 不挂硬盘')
  New-VM -Name $VMName -Generation 2 -MemoryStartupBytes ($RAMMB * 1MB) -SwitchName $switch.Name -Path $vmPath | Out-Null
  Set-VM -VMName $VMName -ProcessorCount 2 -AutomaticStopAction TurnOff | Out-Null
  Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes ($RAMMB * 1MB) -EA SilentlyContinue
  # Gen2 且不带 VHD 的 New-VM 根本不会创建 DVD 驱动器, 这时 Set-VMDvdDrive 是静默空操作
  # —— 2026-10-07 两轮"等不到 22 端口"就是这个: VM 里没有光驱介质, EFI 直接停在"无可引导设备",
  # 从没进过 WinPE(证据: 这块静态 MAC 在宿主邻居表里一次都没出现过)。v8 能跑的 04 脚本里有这个守卫。
  if (-not (Get-VMDvdDrive -VMName $VMName -EA SilentlyContinue)) {
    Add-VMDvdDrive -VMName $VMName -ControllerNumber 0 -ControllerLocation 1 -Path $Iso -EA Stop | Out-Null
    L '    DVD 驱动器不存在 -> 已 Add-VMDvdDrive(SCSI 0/1)'
  } else {
    Set-VMDvdDrive -VMName $VMName -Path $Iso
  }
  $dvd = Get-VMDvdDrive -VMName $VMName
  if (-not $dvd -or ($dvd.Path -ne $Iso)) {
    L ('ABORT: 光驱里没插上这张 ISO(实际=' + $(if ($dvd) { $dvd.Path } else { '无 DVD 驱动器' }) + ' / 应为=' + $Iso + ')')
    exit 1
  }
  L ('    光驱介质 = ' + $dvd.Path)
  Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd -EnableSecureBoot On
  Set-VmLowVideo '降显存'
  # 动态 MAC 的 VM 在没开机前 Get-VMNetworkAdapter 只会回 000000000000(2026-10-07 就是这样
  # 让"MAC 正向确认"整个失效的), 所以建完就钉一把静态 MAC, 后面所有判据都以它为准。
  $myMac = '00-15-5D-10-E1-0A'
  Set-VMNetworkAdapter -VMName $VMName -StaticMacAddress $myMac -EA SilentlyContinue
  $wantMac = Norm-Mac ((Get-VMNetworkAdapter -VMName $VMName).MacAddress)
  if ($wantMac -eq '000000000000') { $wantMac = (Norm-Mac $myMac) }
  L ('    本 VM 网卡 MAC = ' + $wantMac + ' (静态, 用它做正向确认)')

  function Wait-OurPe([int]$sec) {
    $deadline = (Get-Date).AddSeconds($sec)
    $started = Get-Date
    $round = 0
    $notRun = 0
    while ((Get-Date) -lt $deadline) {
      Start-Sleep 15
      $round++
      $cands = @(Get-VMIpKvp) + @(Get-Open22)
      $fallback = $null
      foreach ($ip in ($cands | Select-Object -Unique)) {
        $m = Get-MacOfNeighbor $ip
        L ('    候选 ' + $ip + ' MAC=' + $(if ($m) { $m } else { '未知' }))
        if ($wantMac -and $m -and ((Norm-Mac $m) -eq $wantMac)) { return $ip }
        if ($baseline -contains $ip) { continue }
        if ($wantMac -and $m -and ((Norm-Mac $m) -ne $wantMac)) { continue }
        if (-not $fallback) { $fallback = $ip }
      }
      if ($fallback) {
        # MAC 对不上但 IP 是新开的: 极可能是宿主 ARP 缓存里还挂着上一台(已删)VM 的旧 MAC。
        # 与其死等, 不如把它交给后面的身份闸门判定 —— 判定不了顶多空跑一次, 死等则一定超时。
        L ('    没有 MAC 完全吻合的候选, 用新开 22 端口的 ' + $fallback + ' 交给 BUILD_TAG 身份闸门判定')
        return $fallback
      }
      $st = Get-VM -Name $VMName -EA SilentlyContinue
      # 独立于 22 端口的引导证据: HNS 的 DHCP 租约会把这块 MAC 写进宿主邻居表。
      # 看得到它 = 至少引导进了 WinPE 并起了网络栈; 看不到 = 根本没进 WinPE。
      $nb = @(Get-NetNeighbor -EA SilentlyContinue | Where-Object { $wantMac -and (Norm-Mac $_.LinkLayerAddress) -eq $wantMac })
      if ($nb.Count) {
        $script:PeBooted = $true
        L ('    邻居表里有本 VM 的 MAC -> ' + (($nb | ForEach-Object { $_.IPAddress + '(' + $_.AddressState + ')' }) -join ',') + '  => 已引导进 WinPE(网络栈起来了), 只是还没听到 22')
      }
      L ('    等本机 pe-sshd:22 ... VM=' + $(if ($st) { $st.State } else { 'gone' }) + ' 已等 ' + [int]((Get-Date).Subtract($started).TotalSeconds) + 's')
      if ($st -and $st.State -ne 'Running') {
        $notRun++
        if ($notRun -ge 2) { L '    VM 已经不在 Running 了, 继续等没意义 —— 提前收工'; return $null }
      } else { $notRun = 0 }
      if ($round % 2 -eq 0) { Save-VmScreen ('wait' + $round) | Out-Null }
      if (@(2, 5) -contains $round) {
        # 清一次邻居缓存, 免得一直拿着已删 VM 的旧 MAC 不放
        $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        & arp.exe -d * 2>&1 | Out-Null
        $ErrorActionPreference = $prev
      }
    }
    return $null
  }
  L '[4] 第一轮: Secure Boot = On (赌 19041 正式版签名引导)'
  if (-not (Start-PeVm 'SecureBoot=On')) {
    L 'ABORT: VM 根本起不来 —— 这是宿主资源/Hyper-V 的问题, 与镜像无关, 不必再等 22 端口'
    exit 1
  }
  Start-Sleep 25; Save-VmScreen 'r1_25s' | Out-Null
  $IP = Wait-OurPe $WaitSec
  $sbOn = [bool]$IP
  if (-not $IP) {
    Save-VmScreen 'r1_end' | Out-Null
    L '[4] Secure Boot=On 起不来 -> 关掉 Secure Boot 重试'
    Stop-VM -Name $VMName -TurnOff -Force -EA SilentlyContinue; Start-Sleep 3
    Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
    if (-not (Start-PeVm 'SecureBoot=Off')) {
      L 'ABORT: 关掉 Secure Boot 还是起不来 —— 仍然是宿主起 VM 失败, 不是镜像引导失败'
      exit 1
    }
    Start-Sleep 25; Save-VmScreen 'r2_25s' | Out-Null
    $IP = Wait-OurPe $WaitSec
    if (-not $IP) { Save-VmScreen 'r2_end' | Out-Null }
  }
  if ($sbOn) { L '结论: Secure Boot 开着就能启动 = True (19041 正式版签名引导生效, 这是相对 v8 的增量)' }
  else { L ('结论: Secure Boot 开着能启动 = ' + $sbOn + ' (v8 同样需要关闭)') }
  if (-not $IP) {
    if ($PeBooted) {
      L 'ERROR: 邻居表证明 PE 已经引导并起了网络栈, 但 22 端口始终没人听 —— 问题在镜像里的 pe-sshd 自启, 不是引导'
      $script:FailMode = 'sshd'
    } else {
      L 'ERROR: 这块 MAC 从未出现在宿主邻居表 = 这台 VM 至今没引导进 WinPE(与 22 端口无关)。请看截图 vm10_screen_*.bmp'
      $script:FailMode = 'boot'
    }
    L ('VM 状态: ' + ((Get-VM -Name $VMName -EA SilentlyContinue | Format-List Name, State, Status | Out-String) -replace "`r?`n", ' | '))
    exit 1
  }
  Set-Content -Path (Join-Path $PSScriptRoot 'vm_ip.txt') -Value $IP
}
L ('[5] 目标 PE = ' + $User + '@' + $IP)

# ---------- SSH 通道 ----------
$keySrc = Join-Path $Root 'overlay\Scripts\ssh_login_key'
if (-not (Test-Path $keySrc)) { L ('ERROR: 登录私钥不在 ' + $keySrc); exit 1 }
$keyTmp = Join-Path $env:TEMP 'winpe10_test_key'
Copy-Item $keySrc $keyTmp -Force
& icacls $keyTmp /inheritance:r /grant:r ("${env:USERNAME}:R") | Out-Null
$sshBin = 'C:\Windows\System32\OpenSSH\ssh.exe'
if (-not (Test-Path $sshBin)) { $sshBin = 'ssh' }
$sshOpts = @('-i', $keyTmp, '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=NUL',
             '-o', 'ConnectTimeout=15', '-o', 'NumberOfPasswordPrompts=0', '-o', 'LogLevel=ERROR', ($User + '@' + $IP))
function Invoke-Pe([string]$label, [string]$cmd) {
  L ('---------- ' + $label + ' ----------')
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $sshBin @sshOpts $cmd 2>&1
  $script:SshRc = $LASTEXITCODE
  $ErrorActionPreference = $prev
  $txt = @($o | ForEach-Object { "$_" })
  L ('  (rc=' + $script:SshRc + ' 行数=' + $txt.Count + ')')
  $txt | Select-Object -First 70 | ForEach-Object { L ('  ' + $_) }
  if ($txt.Count -gt 70) { L ('  ...(还有 ' + ($txt.Count - 70) + ' 行未打印)') }
  return $txt
}
# PowerShell 检查一律走 -EncodedCommand: pe-sshd 把命令行交给 cmd 时引号会被拆, 管道 | 会漏到 cmd 去
# (2026-10-07 第一轮里 'Get-Process ... | Select' 就变成了 "'Select' 不是内部或外部命令")
function Invoke-PePs([string]$label, [string]$ps) {
  $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps))
  return (Invoke-Pe $label ('X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ' + $b64))
}

# ---------- 身份闸门: 先证明连的是这台 Win10 PE ----------
$gate = Invoke-Pe '00 身份闸门 BUILD_TAG' 'type X:\BUILD_TAG.txt'
if ($script:SshRc -ne 0) {
  L 'ABORT: 没有 X:\BUILD_TAG.txt —— 这台不是 build10 出的镜像(很可能是旧测试机), 本次结论作废'
  Invoke-Pe '    顺手看一眼它是谁' 'ver' | Out-Null
  if (-not $SkipCreate) { Save-VmScreen 'gatefail' | Out-Null }
  exit 1
}
if (-not (@($gate | ForEach-Object { $_ }) -join "`n").Contains($ExpectProduct)) {
  L ('ABORT: BUILD_TAG 里没有 product=' + $ExpectProduct + ', 连错机器了')
  if (-not $SkipCreate) { Save-VmScreen 'gatefail' | Out-Null }
  exit 1
}
$osv = Invoke-PePs '00b OS 版本(必须是 10.0.19041.x)' '[Environment]::OSVersion.Version.ToString(); $PSVersionTable.PSVersion.ToString()'
$osvTxt = (@($osv) -join ' ')
if ($osvTxt -notmatch '10\.0\.1904[0-9]') {
  L ('ABORT: OS 版本不是 19041 世代 —— 这不是 Win10 分支的镜像。看到的内容: ' + ($osvTxt -replace '\s+', ' '))
  if (-not $SkipCreate) { Save-VmScreen 'gatefail' | Out-Null }
  exit 1
}
L '身份校验通过: 这台就是 WinPE10_Desktop_v1 (19041 世代)'
if (-not $SkipCreate) { Save-VmScreen 'desktop' | Out-Null }

# ---------- 功能逐项 ----------
Invoke-Pe '01 status.txt(自启逐项结果)' 'type X:\status.txt' | Out-Null
Invoke-Pe '02 boot.log(启动序列全文)' 'type X:\boot.log' | Out-Null
Invoke-Pe '02b sshd.log + authorized_keys(pe-sshd 侧)' 'type X:\sshd.log & echo ---KEYS--- & dir /b X:\SSH' | Out-Null
Invoke-PePs '03 进程(替代 tasklist)' 'Get-Process | Sort-Object Name | ForEach-Object { "{0} {1}" -f $_.Id, $_.Name } | Out-String -Width 120' | Out-Null
Invoke-PePs '04 关键自启进程判定' 'foreach($n in @("pe-sshd","mshta","SunloginSOS","frpc","wlansvc")){ $p=Get-Process -Name $n -EA SilentlyContinue; "{0}={1}" -f $n, $(if($p){"RUNNING pid "+($p.Id -join "/")}else{"not running"}) }' | Out-Null
Invoke-Pe '05 网络(ipconfig /all)' 'ipconfig /all' | Out-Null
Invoke-Pe '06 netdrvfix.log(开机自动认网卡)' 'type X:\netdrvfix.log' | Out-Null
Invoke-Pe '07 niccheck.cmd(自检工具)' 'X:\Windows\System32\niccheck.cmd' | Out-Null
Invoke-PePs '08 niccheck.ps1 详情' 'if(Test-Path X:\Windows\System32\niccheck.ps1){ & X:\Windows\System32\niccheck.ps1 | Out-String -Width 160 }else{ "NICCHECK_PS1_MISSING" }' | Out-Null
Invoke-Pe '09 组件存在性' 'if exist X:\Windows\System32\mshta.exe (echo HTA_OK) else (echo HTA_MISSING) & if exist X:\Windows\System32\wbem\wmiprvse.exe (echo WMI_OK) else (echo WMI_MISSING) & if exist X:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (echo PS_OK) else (echo PS_MISSING) & if exist X:\Windows\Microsoft.NET\Framework64\v4.0.30319 (echo NETFX_OK) else (echo NETFX_MISSING) & if exist X:\Windows\System32\dot3api.dll (echo DOT3_OK) else (echo DOT3_MISSING) & if exist X:\Windows\System32\netdrv_index.txt (echo DRVINDEX_OK) else (echo DRVINDEX_MISSING)' | Out-Null
Invoke-Pe '10 桌面/向日葵/frp 素材' 'dir /b X:\Desktop & echo ---Frp--- & dir /b X:\Desktop\Frp & echo ---Sunlogin--- & dir /b X:\Sunlogin' | Out-Null
# PE 里没有 Get-Service/tasklist/sc(2026-10-04 实测清单), 服务状态一律走 Get-CimInstance Win32_Service
Invoke-PePs '11 服务状态(wlansvc/dot3svc/Winmgmt/MpsSvc/BFE)' 'foreach($n in @("wlansvc","dot3svc","WcmSvc","Winmgmt","MpsSvc","BFE","netprofm")){ $s=Get-CimInstance Win32_Service -Filter "Name=''$n''" -EA SilentlyContinue; if($s){"{0} = {1} start={2} exit=0x{3:X8}" -f $n,$s.State,$s.StartMode,[int]$s.ExitCode}else{"{0} = ABSENT" -f $n} }' | Out-Null
Invoke-PePs '12 网卡与驱动(PnP 是否绑上)' 'Get-CimInstance Win32_NetworkAdapter -EA SilentlyContinue | ForEach-Object { "{0} | NetEnabled={1} | PNPDeviceID={2} | GUID={3}" -f $_.Name, $_.NetEnabled, $_.PNPDeviceID, $_.GUID } | Out-String -Width 200' | Out-Null
Invoke-Pe '13 私钥绝不能进镜像' 'if exist X:\SSH\ssh_login_key (echo PRIVATE_KEY_LEAK) else (echo NO_PRIVATE_KEY_IN_IMAGE_OK) & dir /b X:\SSH & echo ---S32--- & if exist X:\Windows\System32\ssh_login_key (echo PRIVATE_KEY_LEAK2) else (echo CLEAN2)' | Out-Null
Invoke-PePs '14 磁盘与内存盘' 'Get-PSDrive -PSProvider FileSystem | ForEach-Object { "{0} used={1:N0} free={2:N0}" -f $_.Name, $_.Used, $_.Free } | Out-String' | Out-Null
if (-not $SkipCreate) { Save-VmScreen 'final' | Out-Null }
L ''
L '===== 自检结束 ====='
L ('VM ' + $VMName + ' 仍在运行, 控制台里应能看到 HTA 桌面和向日葵窗口(这两项只能肉眼确认)')
L ('结果文件: ' + $Out)
L ('清理: 管理员 PowerShell 里 Remove-VM -Name ' + $VMName + ' -Force')
