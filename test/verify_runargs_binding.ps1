# ============================================================
# test\verify_runargs_binding.ps1 —— 门禁: accept_wifi 的 PushRun 拼参数不能因为 -RunArgs 空值而废掉
#
#   为什么要单独立一条(2026-10-12): PushRun 是给"一条命令验收"推探针的公共出口, 三段都走它。
#   以前写成 `-RunArgs $remoteArgs` 摊在命令行上, 而 PowerShell 传给外部 exe 时**空字符串等于没给**,
#   子进程立刻报 "缺少参数 RunArgs" —— 不带开关的 probe42/probe86 两条老路径全废;
#   另一个坑是值本身带减号('-Apply')摊开时容易被当成参数名。本机实测(build\scratch\t_p104*):
#   只有"非空才拼 -RunArgs + 参数走数组展开"这一种写法三种输入都能原样绑定。
#   这个回归只有跑起来才看得见, 语法检查抓不到, 所以进门禁。
#
#   只读+临时文件: 只在本机 spawn 一个假探针(打印它收到的参数), 不连 PE、不碰注册表。
#   用法: powershell -NoProfile -ExecutionPolicy Bypass -File test\verify_runargs_binding.ps1
#   退出码: 0 = 三个用例全对且 accept_wifi 源码仍是"守卫式数组拼法"; 1 = 任何一条不成立
# ============================================================
param([string]$AcceptScript = 'test\accept_wifi.ps1')
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$fails = @()
$note = @()

# ---- 1) 造一个"假探针接收端": 它只负责把自己收到的 -RunArgs 原样打出来 ----
$tmp = Join-Path $Root 'build\scratch\_verify_runargs_child.ps1'
$script:TmpChild = $tmp
New-Item -ItemType Directory -Force -Path (Split-Path $tmp -Parent) | Out-Null
@("param([string]`$RunArgs='', [switch]`$Run)",
  'Write-Output ("CHILD RunArgs=[" + $RunArgs + "] Run=" + [bool]$Run)') |
  Set-Content -LiteralPath $tmp -Encoding UTF8

# ---- 2) 被验对象: accept_wifi 里那套拼法, 逐字复制(改了 PushRun 就得同步这里) ----
function Build-PushArgs([string]$remoteArgs) {
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:TmpChild, '-Run')
  if ($remoteArgs) { $a += @('-RunArgs', $remoteArgs) }
  return $a
}
function Run-Case([string]$remoteArgs) {
  $a = Build-PushArgs $remoteArgs
  $o = @(& powershell @a 2>&1 | ForEach-Object { "$_" })
  $t = ($o -join ' / ')
  # 子进程报"缺少参数 RunArgs"时, 错误记录里一定带 FullyQualifiedErrorId=MissingArgument(英文, 不受控制台码页影响)
  return @{ text = $t; missing = ($t -match 'MissingArgument') }
}

$cases = @(
  @{ in = '';              want = 'CHILD RunArgs=[] Run=True' },
  @{ in = '-Apply';        want = 'CHILD RunArgs=[-Apply] Run=True' },
  @{ in = '-Apply -Only x'; want = 'CHILD RunArgs=[-Apply -Only x] Run=True' }
)
foreach ($c in $cases) {
  $r = Run-Case $c.in
  if ($r.text -notmatch [regex]::Escape($c.want)) {
    $fails += ('case[' + $c.in + '] got: ' + (($r.text -replace '[^\x20-\x7E]', '?') -replace '\s+', ' '))
  }
  if ($r.missing) { $fails += ('case[' + $c.in + '] child reported missing-argument') }
}

# ---- 3) 源码判据: accept_wifi 必须还是"if ($remoteArgs) { ... } + 数组展开", 不许退回裸 -RunArgs $x ----
$src = ''
if (Test-Path -LiteralPath $AcceptScript) { $src = (Get-Content -LiteralPath $AcceptScript -Raw) }
else { $fails += ('accept_wifi absent: ' + $AcceptScript) }
# 只看代码行: PushRun 的注释里就写着 `-RunArgs $remoteArgs` 这个坏例子, 拿全文去匹配会自己判自己红。
$code = (@($src -split "`r?`n" | ForEach-Object { if (($_ -match '^\s*#') -or ($_ -match '^\s*$')) { '' } else { $_ } }) -join "`n")
$guarded = ($code -match 'if \(\$remoteArgs\)')
$arrayform = ($code -match '& powershell @a')
$bare = ($code -match '-RunArgs \$remoteArgs\b')
if (-not $guarded)  { $fails += 'accept_wifi lost the if ($remoteArgs) guard' }
if (-not $arrayform) { $fails += 'accept_wifi no longer passes args as an array (& powershell @a)' }
if ($bare)          { $fails += 'accept_wifi has a bare "-RunArgs $remoteArgs" on the command line' }
$note += ('guarded=' + [int]$guarded + ' array=' + [int]$arrayform + ' bare=' + [int]$bare)

Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue

if ($fails.Count) {
  foreach ($f in $fails) { Write-Output ('  FAIL ' + ($f -replace '[^\x20-\x7E]', '?')) }
  Write-Output ('VERDICT runargs: cases=' + $cases.Count + ' fail=' + $fails.Count + ' ' + ($note -join ' ') + ' RESULT=NOT-READY')
  exit 1
}
Write-Output ('VERDICT runargs: cases=' + $cases.Count + ' fail=0 ' + ($note -join ' ') + ' RESULT=READY')
exit 0
