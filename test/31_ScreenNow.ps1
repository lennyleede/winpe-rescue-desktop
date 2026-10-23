# ============================================================
# 31_ScreenNow.ps1 —— 看一台 VM 现在到底是什么状态(不重建、不重启, 十几秒)
#   管理员: powershell -NoProfile -ExecutionPolicy Bypass -File test\31_ScreenNow.ps1
#   可选: -VMName WinPE10-Test -Shots 2 -Every 20 -Scan
# 每一步都单独打印, 某步失败也继续往下跑, 保证一次就拿到足够判读的信息:
#   [A] VM 配置(状态/内存/DVD 里到底有没有插盘/Secure Boot)  <- 2026-10-07 的真凶就在这一项
#   [B] 控制台截图(WMI; 拿不到就打印原因)
#   [C] 22 端口扫描 + 这块 MAC 在邻居表里有没有(= 有没有真的引导到 WinPE 拿过 DHCP)
# 截图实现: Get-CimInstance 的对象上 __PATH 为空(上一版"无效的对象路径"就是这个),
# 这里改用 Get-WmiObject 的 .Path / 自己按 key 拼引用路径两种写法都试。
# ============================================================
param(
  [string]$VMName = 'WinPE10-Test',
  [int]$Shots = 2,
  [int]$Every = 20,
  [int]$ScanWait = 0,
  [string]$OutPrefix = 'vm10_now',
  [switch]$Scan
)
$ErrorActionPreference = 'Continue'
$Rows = New-Object System.Collections.ArrayList
$Out = Join-Path $PSScriptRoot 'vm10_screen_report.txt'
function L($m) {
  Write-Host $m
  [void]$Rows.Add([string]$m)
  try { Set-Content -LiteralPath $Out -Value ($Rows -join "`r`n") -Encoding UTF8 } catch { }
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L ('===== 现场勘查 ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  isAdmin=' + $IsAdmin + ' =====')
Import-Module Hyper-V -EA SilentlyContinue

# ---------- [A] VM 配置 ----------
$vm = Get-VM -Name $VMName -EA SilentlyContinue
if (-not $vm) { L '[A] 找不到这台 VM: ' + $VMName; exit 1 }
L ('[A] State=' + $vm.State + '  内存已分配=' + [int]($vm.MemoryAssigned / 1MB) + 'MB  开机时长=' + $vm.Uptime)
$dvd = Get-VMDvdDrive -VMName $VMName -EA SilentlyContinue
if (-not $dvd) {
  L '[A] !! 这台 VM 根本没有 DVD 驱动器 —— New-VM(Gen2, 不带 VHD) 不会建光驱, 之前 Set-VMDvdDrive 是空操作, 等于没插盘'
} else {
  L ('[A] DVD: Controller=' + $dvd.ControllerNumber + '/' + $dvd.ControllerLocation + '  介质=' + $(if ($dvd.Path) { $dvd.Path } else { '(空, 没插盘)' }) + '  驱动器已连接=' + $dvd.DeviceIsConnected)
}
$fir = Get-VMFirmware -VMName $VMName -EA SilentlyContinue
if ($fir) {
  L ('[A] SecureBoot=' + $fir.EnableSecureBoot + '  Template=' + $fir.SecureBootTemplate + '  FirstBootDevice=' + $fir.FirstBootDevice.Device)
  L ('[A] 引导顺序 = ' + ((@(Get-VMFirmware -VMName $VMName -EA SilentlyContinue).BootOrder | ForEach-Object { $_.Device + '/' + $_.DeviceID }) -join ' , '))
}
$ad = Get-VMNetworkAdapter -VMName $VMName -EA SilentlyContinue | Select-Object -First 1
if ($ad) { L ('[A] 网卡 MAC=' + $ad.MacAddress + '  Switch=' + $ad.SwitchName + '  KVP上报IP=' + $(if ($ad.IPAddresses) { $ad.IPAddresses -join ',' } else { '无' })) }

# ---------- [B] 控制台截图 ----------
# 之前的 ASSOCIATORS OF {引用路径} 一直报"无效的对象路径"(Get-CimInstance 的对象 __PATH 是空的)。
# 改成按 SystemName = VM 的 GUID 直接查 Msvm_VideoHead, 不需要引用路径。
$ns = 'root\virtualization\v2'
$bmps = @()
function Ref-From-Head($head) {
  $parts = @()
  foreach ($k in @('SystemCreationClassName', 'SystemName', 'CreationClassName', 'DeviceID', 'Name', 'ID', 'InstanceID')) {
    $v = $head.PSObject.Properties[$k]
    if ($v -and $v.Value) { $parts += ($k + '="' + ([string]$v.Value).Replace('"', '\"') + '"') }
  }
  return 'root\virtualization\v2:Msvm_VideoHead.' + ($parts -join ',')
}
if ($Shots -gt 0) {
  $cs = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -EA SilentlyContinue |
        Where-Object { $_.ElementName -eq $VMName } | Select-Object -First 1
  if (-not $cs) { L '[B] CIM 里找不到该 VM 的 Msvm_ComputerSystem(没管理员?)' }
  else {
    L ('[B] Msvm_ComputerSystem: Name=' + $cs.Name + ' EnabledState=' + $cs.EnabledState + ' HealthState=' + $cs.HealthState)
    $heads = @(Get-CimInstance -Namespace $ns -ClassName Msvm_VideoHead -EA SilentlyContinue)
    L ('[B] 整机 Msvm_VideoHead 总数=' + $heads.Count + ' ; SystemName 列表 = ' + (($heads | ForEach-Object { $_.SystemName }) -join ', '))
    $head = @($heads | Where-Object { $_.SystemName -eq $cs.Name }) | Select-Object -First 1
    if (-not $head) {
      L '[B] 没有属于这台 VM 的 Msvm_VideoHead —— 截图放弃([A] 的配置信息仍然有效)'
    } else {
      $headRef = [string]$head.__PATH
      if (-not $headRef) { $headRef = Ref-From-Head $head }
      L ('[B] VideoHead 引用 = ' + $headRef)
      $svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VideoHeadService -EA SilentlyContinue | Select-Object -First 1
      if (-not $svc) { L '[B] 没有 Msvm_VideoHeadService, 无法截图' }
      for ($i = 1; $i -le $Shots; $i++) {
        $r = $null
        try { $r = Invoke-CimMethod -InputObject $svc -MethodName GetScreenImage -Arguments @{ VideoHead = $headRef } -EA Stop }
        catch { L ('[B] 第 ' + $i + ' 拍异常: ' + ($_.Exception.Message -replace '\s+', ' ')) }
        if ($r) {
          $d = $null
          foreach ($nm in @('ScreenImage', 'ScreenData')) {
            $v = $r.PSObject.Properties[$nm]
            if ($v -and $v.Value) { $a = @($v.Value); if ($a.Count -ge 54) { $d = [byte[]]$a; break } }
          }
          if (-not $d) {
            L ('[B] 第 ' + $i + ' 拍 rv=' + $r.ReturnValue + ' 但没有位图。返回属性名 = ' +
               (($r.PSObject.Properties | ForEach-Object { $_.Name + '(' + $_.TypeNameOfValue + ')' }) -join ', '))
          } else {
            $w = [BitConverter]::ToInt32($d, 4); $hgt = [BitConverter]::ToInt32($d, 8)
            $bf = New-Object byte[] (14 + $d.Length)
            $bf[0] = 0x42; $bf[1] = 0x4D
            [Array]::Copy([BitConverter]::GetBytes([int](14 + $d.Length)), 0, $bf, 2, 4)
            [Array]::Copy([BitConverter]::GetBytes([int]54), 0, $bf, 10, 4)
            [Array]::Copy($d, 0, $bf, 14, $d.Length)
            $p = Join-Path $PSScriptRoot ($OutPrefix + '_' + $i + '.bmp')
            [System.IO.File]::WriteAllBytes($p, $bf)
            L ('[B] 第 ' + $i + ' 拍 -> ' + (Split-Path $p -Leaf) + ' (' + $w + 'x' + [Math]::Abs($hgt) + ', ' + [int]($bf.Length / 1024) + ' KB)')
            $bmps += $p
          }
        }
        if ($i -lt $Shots) { Start-Sleep $Every }
      }
    }
  }
}

# ---------- [C] 网络痕迹 ----------
if ($ScanWait -gt 0) { Start-Sleep $ScanWait }
function Test-Port22([string]$ip) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $r = $c.BeginConnect($ip, 22, $null, $null); $ok = $r.AsyncWaitHandle.WaitOne(120); return ($ok -and $c.Connected) }
  catch { return $false } finally { $c.Close() }
}
$macFlat = ''
if ($ad) { $macFlat = (($ad.MacAddress -replace '[^0-9A-Fa-f]', '').ToUpper()) }
$all = @(Get-NetNeighbor -AddressFamily IPv4 -EA SilentlyContinue)
$hit = @($all | Where-Object { (($_.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpper()) -eq $macFlat -and $macFlat })
if ($hit.Count) { foreach ($e in $hit) { L ('[C] 邻居表命中 MAC ' + $macFlat + ' -> ' + $e.IPAddress + ' (' + $e.AddressState + ') => PE 已经引导到网络阶段') } }
else { L ('[C] 邻居表里没有 MAC=' + $(if ($macFlat) { $macFlat } else { '(读不到)' }) + ' 的条目 => 这台 VM 至今没拿到 DHCP, 基本可以断定没引导进 WinPE') }
if ($Scan) {
  $h = Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -EA SilentlyContinue | Select-Object -First 1
  if ($h) {
    $pl = [int]$h.PrefixLength; if ($pl -lt 16 -or $pl -gt 28) { $pl = 20 }
    $p = $h.IPAddress.Split('.') | ForEach-Object { [int64]$_ }
    $ipInt = ($p[0] -shl 24) + ($p[1] -shl 16) + ($p[2] -shl 8) + $p[3]
    $hb = 32 - $pl
    $netBase = $ipInt -band (-bnot (([int64]1 -shl $hb) - 1))
    $total = [int64]1 -shl $hb
    $cands = New-Object System.Collections.Generic.List[string]
    for ($j = 1; $j -lt ($total - 1); $j++) {
      $a = $netBase + $j
      $s = '{0}.{1}.{2}.{3}' -f (($a -shr 24) -band 255), (($a -shr 16) -band 255), (($a -shr 8) -band 255), ($a -band 255)
      if ($s -ne $h.IPAddress) { [void]$cands.Add($s) }
    }
    $hits = @()
    for ($off = 0; $off -lt $cands.Count; $off += 256) {
      $last = [int]($off + 255); if ($last -ge $cands.Count) { $last = $cands.Count - 1 }
      $pend = @()
      foreach ($ip in @($cands.GetRange($off, $last - $off + 1))) {
        $c = New-Object System.Net.Sockets.TcpClient
        $ar = $null
        try { $ar = $c.BeginConnect($ip, 22, $null, $null) } catch { try { $c.Close() } catch { }; continue }
        $pend += ,@($ip, $c, $ar)
      }
      $stop = (Get-Date).AddSeconds(2)
      foreach ($t in $pend) {
        $rem = ($stop - (Get-Date)).TotalMilliseconds; if ($rem -lt 0) { $rem = 0 }
        if (-not $t[2].AsyncWaitHandle.WaitOne([int]$rem)) { continue }
        try { $t[1].EndConnect($t[2]); if ($t[1].Connected) { $hits += $t[0] } } catch { }
      }
      foreach ($t in $pend) { try { $t[1].Close() } catch { } }
    }
    L ('[C] /' + $pl + ' 里开放 22 的 IP = ' + $(if ($hits.Count) { $hits -join ', ' } else { '无' }))
  }
}
L '===== 结束 ====='
L ('报告 = ' + $Out)
