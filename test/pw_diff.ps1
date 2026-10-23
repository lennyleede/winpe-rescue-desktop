# 把 ping_watch 的时间戳流水压成"状态翻转"列表, 用于归因(哪个时刻通/不通)
param([string]$Path = 'ping_watch5.txt')
$ls = [IO.File]::ReadAllLines((Resolve-Path $Path).Path, [Text.Encoding]::UTF8)
$prev = ''
$n = 0
foreach ($l in $ls) {
  if ($l -match '^(\d\d:\d\d:\d\d)\s+(ping=\S+).*tcp22=(\S+)') {
    $k = $Matches[2] + ' ' + $Matches[3]
    if ($k -ne $prev) {
      $n++
      Write-Output ('  ' + $n + '. ' + $Matches[1] + '  ' + $k)
      $prev = $k
    }
  }
}
Write-Output ('lines=' + $ls.Count + '  transitions=' + $n)
