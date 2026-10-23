# 离线关闭 WinPE 防火墙: 往挂载镜像的 SYSTEM 配置单元写
#   1) Services\MpsSvc\Start = 4            (防火墙服务从此不自启, WFP 交互策略不会被装载)
#   2) Services\SharedAccess\Parameters\FirewallPolicy\{Domain,Standard,Public}Profile\EnableFirewall = 0
#   依据: 2026-10-05 v8 PE 实测 —— 运行时用 COM 写 FirewallEnabled=False 约 4 秒主机即可直连;
#         PE 里 mpsdrv\BootTimeFilters 缺失、BFE\Parameters\Policy\BootTime 为空, 所以服务不起就没有残留过滤器。
#   由 build.ps1 第 5b 段调用(需管理员, reg load 特权)。overlay 里的 fw_off.ps1 是同一目标的运行时兜底。
#   -SelfTest: 不碰镜像、不改任何注册表, 只对宿主机做只读预览(验证键名/值名/依赖扫描)
# !! 关键教训(2026-10-05 构建就是这么失败的): 对"已加载的临时配置单元"绝对不要用 PowerShell 的
#    注册表提供程序(Get-ChildItem/Get-ItemProperty/Test-Path HKLM:\PE_FW)。它会留下未 Dispose 的
#    键句柄, reg unload 当场失败, 紧接着 build.ps1 的 dism /Unmount-Wim 就报"错误 32 另一个程序正在使用此文件"。
#    本脚本因此全程只调 reg.exe —— 进程一退出句柄就没了。卸载前再做一次 GC 兜底并重试。
param(
  [string]$Mount = '',
  [switch]$SelfTest,
  [switch]$DryRun
)
$ErrorActionPreference = 'Continue'
$HIVE_MP = 'HKLM\PE_FW'
$PROFILES = @('DomainProfile', 'StandardProfile', 'PublicProfile')
$FwLog = @()
# 刻意不写 $global:LOG: 入口脚本的顶层变量在 PowerShell 里就是 global 作用域, 而变量名大小写不敏感,
# 所以调用方那个记录日志文件路径的 $Log 会被这里 += 拼上消息内容 -> 路径作废(2026-10-07 build10 在 [8/8] 提交前就是这样断的)
function Say($s) { Write-Host $s; $script:FwLog += $s }

function Invoke-Reg($args2) {
  # reg.exe 对"未加载的键/不存在的键"会写 stderr 且非零退出, 统一吞掉异常只取文本
  try {
    $o = @(& reg.exe @args2 2>&1 | ForEach-Object { $_.ToString() })
    return @{ rc = $LASTEXITCODE; lines = $o; out = ($o -join ' | ') }
  } catch {
    return @{ rc = -1; lines = @(); out = 'EXCEPTION ' + $_.Exception.Message }
  }
}

function KeyExists($regPath) { return ((Invoke-Reg @('query', $regPath)).rc -eq 0) }

function SubKeys($regPath) {
  # reg query <key> 只列直接子键; 输出行形如 HKEY_LOCAL_MACHINE\PE_FW\ControlSet001
  $r = Invoke-Reg @('query', $regPath)
  if ($r.rc -ne 0) { return @() }
  $pat = '^' + [regex]::Escape($regPath) + '\\[^\\]+$'
  @($r.lines | Where-Object { $_ -match $pat } | ForEach-Object { $_.Trim() })
}

function Plan($csRoot) {
  # 返回要写的条目清单(csRoot 形如 HKLM\PE_FW\ControlSet001\Services)
  $p = @()
  $p += @{ Key = ($csRoot + '\MpsSvc'); Name = 'Start'; Type = 'REG_DWORD'; Data = '4'; Why = '禁用 MpsSvc' }
  foreach ($prof in $PROFILES) {
    $p += @{ Key = ($csRoot + '\SharedAccess\Parameters\FirewallPolicy\' + $prof); Name = 'EnableFirewall'; Type = 'REG_DWORD'; Data = '0'; Why = $prof + ' 关防火墙' }
  }
  $p
}

function Apply-Plan($plan) {
  $bad = 0
  foreach ($e in $plan) {
    if ($DryRun) { Say ('  DRYRUN reg add ' + $e.Key + ' /v ' + $e.Name + ' /t ' + $e.Type + ' /d ' + $e.Data + ' /f   # ' + $e.Why); continue }
    $null = Invoke-Reg @('add', $e.Key, '/v', $e.Name, '/t', $e.Type, '/d', $e.Data, '/f')
    $q = Invoke-Reg @('query', $e.Key, '/v', $e.Name)
    if ($q.rc -eq 0) {
      Say ('  OK ' + ($e.Key -replace '.*\\Services\\', 'Services\') + ' ' + $e.Name + '=' + $e.Data + '  # ' + $e.Why)
    } else {
      Say ('  FAIL ' + $e.Key + ' ' + $e.Name + ' -> ' + $q.out)
      $bad = $bad + 1
    }
  }
  $bad
}

function Dependents($svcRegRoot, $svc) {
  # 谁依赖 MpsSvc? 有就警告, 因为禁用后那个服务会起不来。只用 reg.exe, 一次一个键查询。
  $hits = @()
  $keys = @(SubKeys $svcRegRoot)
  $cap = 900
  if ($keys.Count -gt $cap) { $keys = @($keys[0..($cap - 1)]) }
  foreach ($k in $keys) {
    foreach ($vn in @('DependOnService', 'DependOnServiceEx')) {
      $q = Invoke-Reg @('query', $k, '/v', $vn)
      if ($q.rc -ne 0) { continue }
      if (($q.out) -match ('(?i)' + [regex]::Escape($svc))) { $hits += (Split-Path -Leaf $k); break }
    }
  }
  $hits
}

function Unload-Hive($label) {
  # 先让可能的句柄终结器跑完, 再 unload, 失败重试 4 次
  for ($i = 1; $i -le 4; $i++) {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    $u = Invoke-Reg @('unload', $HIVE_MP)
    if ($u.rc -eq 0 -or -not (KeyExists $HIVE_MP)) {
      Say ('  配置单元已卸载(第 ' + $i + ' 次尝试)' + $(if ($label) { ' ' + $label } else { '' }))
      return $true
    }
    Say ('  卸载第 ' + $i + ' 次失败: ' + $u.out)
    Start-Sleep -Milliseconds 800
  }
  Say '  !! 配置单元仍挂着 —— 后面 dism /Unmount-Wim 会报"错误 32 另一个程序正在使用此文件"。'
  Say '  !! 手工补救: 关闭所有 PowerShell 窗口后在管理员 cmd 里 reg unload HKLM\PE_FW'
  return $false
}

if ($SelfTest) {
  Say '=== fw-offline -SelfTest (宿主机只读, 不写任何东西) ==='
  $cs = 'HKLM\SYSTEM\CurrentControlSet\Services'
  Say ('  Services 键存在=' + (KeyExists $cs))
  $mq = Invoke-Reg @('query', ($cs + '\MpsSvc'), '/v', 'Start')
  Say ('  MpsSvc 键存在=' + (KeyExists ($cs + '\MpsSvc')) + '  查询结果: ' + (($mq.lines | Where-Object { $_ -match 'Start' } | Select-Object -First 1) -join ''))
  foreach ($prof in $PROFILES) {
    $kp = ($cs + '\SharedAccess\Parameters\FirewallPolicy\' + $prof)
    $pq = Invoke-Reg @('query', $kp, '/v', 'EnableFirewall')
    Say ('  ' + $prof + ' 键存在=' + (KeyExists $kp) + '  ' + (($pq.lines | Where-Object { $_ -match 'EnableFirewall' } | Select-Object -First 1) -join '').Trim())
  }
  $dep = Dependents $cs 'MpsSvc'
  Say ('  依赖 MpsSvc 的服务 = ' + (($dep | Select-Object -First 20) -join ',') + '  (共 ' + $dep.Count + ' 个)')
  Say '  将要写进镜像的条目(路径以挂载点为准):'
  foreach ($e in (Plan 'HKLM\PE_FW\ControlSet001\Services')) { Say ('    ' + ($e.Key -replace '.*\\Services\\', 'Services\') + '\' + $e.Name + ' = ' + $e.Data) }
  Say 'SELFTEST DONE'
  return
}

if (-not $Mount) { Say '需要 -Mount <boot.wim 挂载点> (或 -SelfTest)'; return }
$NT_HIVE = Join-Path $Mount 'Windows\System32\Config\SYSTEM'
Say ('=== fw-offline 目标 ' + $NT_HIVE + ' ===')
if (-not (Test-Path $NT_HIVE)) { Say '  SYSTEM 配置单元不存在, 挂载点是否正确?'; return }

if ($DryRun) {
  Say '  DRYRUN: 不加载配置单元'
  foreach ($e in (Plan 'HKLM\PE_FW\ControlSet001\Services')) { Say ('    reg add ' + $e.Key + ' /v ' + $e.Name + ' /t ' + $e.Type + ' /d ' + $e.Data + ' /f') }
  return
}

if (KeyExists $HIVE_MP) { Say ('  ' + $HIVE_MP + ' 已经挂着(上一轮没退干净), 先试着卸掉'); $null = Unload-Hive '(清理残留)' }
$r = Invoke-Reg @('load', $HIVE_MP, $NT_HIVE)
if (-not (KeyExists $HIVE_MP)) {
  Say ('  reg load 失败(需管理员): ' + $r.out)
  throw 'fw-offline: reg load SYSTEM 失败'
}
Say '  SYSTEM 配置单元已加载'
$left = $false
try {
  $csList = @(SubKeys $HIVE_MP | ForEach-Object { Split-Path -Leaf $_ } | Where-Object { $_ -match '^ControlSet\d+$' })
  if ($csList.Count -eq 0) { $csList = @('ControlSet001') }
  Say ('  控制集: ' + ($csList -join ', '))
  $bad = 0
  foreach ($cs in $csList) {
    $svcReg = ($HIVE_MP + '\' + $cs + '\Services')
    if (-not (KeyExists $svcReg)) { Say ('  ' + $cs + ' 没有 Services 键, 跳过'); continue }
    $dep = Dependents $svcReg 'MpsSvc'
    if ($dep.Count -gt 0) { Say ('  警告: ' + $cs + ' 里有服务依赖 MpsSvc -> ' + (($dep | Select-Object -First 10) -join ',') + ' (禁用后它们会起不来)') }
    Say ('  写 ' + $cs + ' ...')
    $bad = $bad + (Apply-Plan (Plan $svcReg))
  }
  if ($bad -gt 0) { throw ('fw-offline: 有 ' + $bad + ' 项写入失败') }
  Say '  防火墙离线关闭完成'
} finally {
  $left = -not (Unload-Hive '')
}
if ($left) { throw 'fw-offline: 值都写进去了, 但配置单元没能卸载(见上面日志)。请立即 reg unload HKLM\PE_FW, 否则 dism 卸载会失败' }
