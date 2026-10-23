# ============================================================
# test\DismReport.ps1 —— 把 DISM /Add-Driver 的日志读成"每个包到底进没进去"。
#
#   为什么需要它(2026-10-08 的教训): /Recurse 是"逐个包"报结果的, 一个包失败时 DISM 仍然
#   把其余包装好、DriverStore 目录数照样涨, 构建脚本只看 rc 和增量的话就会把 6/7 当成成功,
#   于是 iaAHCIC(AHCI/HDC 全家) 静默缺席 ISO —— 日志里明明写着
#     Installing 1 of 7 - ...\iaAHCIC_17.11.3.1010\iaAHCIC.inf: Error - An error occurred...
#   没有一条代码去看它。这个文件就是把那行文字变成结构化结论。
#
#   口径: DISM 的横幅/尾部是中文, 但 "Installing k of N - <path>.inf: <msg>" 这行恒为英文,
#   所以只按这行的形状匹配, 不依赖整机语言。判据是 msg 里有没有 successfully installed。
# ============================================================

function Get-DismPkgReport {
  param([Parameter(Mandatory = $true)][string]$LogPath)

  $r = @{ found = 0; ok = 0; failed = @(); okNames = @(); lines = @(); present = $false }
  if (-not (Test-Path -LiteralPath $LogPath)) { return $r }
  $r.present = $true
  $txt = [IO.File]::ReadAllText($LogPath)
  if ($txt -match '(?i)Found\s+(\d+)\s+driver package') { $r.found = [int]$matches[1] }
  foreach ($m in [regex]::Matches($txt, '(?im)^Installing\s+(\d+)\s+of\s+(\d+)\s+-\s+(.+?\.inf)\s*:\s*(.*)$')) {
    $msg = $m.Groups[4].Value.Trim()
    $pkg = [IO.Path]::GetFileName($m.Groups[3].Value)
    $dir = Split-Path -Parent $m.Groups[3].Value
    $tag = [IO.Path]::GetFileName($dir) + '\' + $pkg
    # "already installed" 也算进去了(重复跑 16_ 时 DISM 会这么写), 不能当失败 —— 失败只认 Error/拒绝类措辞
    $isOk = ($msg -match '(?i)successfully installed|already (been )?(installed|added)|is already installed')
    if ($isOk) { $r.ok++; $r.okNames += $tag } else { $r.failed += ($tag + ' :: ' + $(if ($msg) { $msg } else { '(no message)' })) }
    $r.lines += ('  ' + $m.Groups[1].Value + '/' + $m.Groups[2].Value + ' ' + $tag + ' = ' + $(if ($isOk) { 'ok' } else { 'FAILED' }))
  }
  # 没匹配到任何 "Installing k of N" 行时 DISM 可能是"一个包都没找到"(路径错/目录空), 也要能看出来
  if ($r.okNames.Count + $r.failed.Count -eq 0 -and $txt -match '(?i)(no driver packages to (add|install)|found 0)') {
    $r.lines += '  DISM says there are no driver packages in that folder'
  }
  return $r
}

# 打印给人看的一行总结(fail 时把包名和原文都摊开, 不再只报增量)
function Format-DismPkgReport {
  param([string]$Label, $Rep)
  $o = @()
  $o += ('  ' + $Label + ': DISM 逐包结果 ok ' + $Rep.ok + ' / failed ' + @($Rep.failed).Count + ' / found ' + $Rep.found)
  foreach ($l in @($Rep.lines)) { $o += $l }
  foreach ($f in @($Rep.failed)) { $o += ('  !! FAILED ' + $f) }
  return ($o -join "`r`n")
}
