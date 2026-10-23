# 摘掉 startnet.cmd 里的 sshd 自启 (WinPE 里 privsep 子进程必然 0xC0000142, 十四轮实测)
# .cmd 必须按 GBK(936) + CRLF 字节级读写, 否则中文在 PE 控制台里是乱码
$ErrorActionPreference = 'Stop'
$p = 'D:\QoderProject\国内版\生成winpe\overlay\Scripts\startnet.cmd'
$gbk = [Text.Encoding]::GetEncoding(936)
$t = $gbk.GetString([IO.File]::ReadAllBytes($p))

$pat = '(?s)rem ---------- OpenSSH.*?echo \[2\] sshd started >> %LOG%'
$new = @'
rem ---------- OpenSSH: WinPE 跑不起 sshd(privsep 子进程 0xC0000142, 实机十四轮验证), 只留客户端不自启 ----------
set SSHDIR=X:\OpenSSH
echo [2] sshd autostart removed (WinPE privsep child 0xC0000142), OpenSSH client only >> %LOG%
'@
$new = ($new -replace "`r`n", "`n") -replace "`n", "`r`n"
$new = $new.TrimEnd("`r", "`n")

if ($t -match $pat) {
  $t2 = [regex]::Replace($t, $pat, $new.Replace('$', '$$'))
  [IO.File]::WriteAllBytes($p, $gbk.GetBytes($t2))
  Write-Host 'PATCHED: sshd 自启已摘除'
} else {
  Write-Host 'SKIP: 没匹配到 OpenSSH 自启段(可能已经改过)'
}
$b = [IO.File]::ReadAllBytes($p)
$cr = (@($b | Where-Object { $_ -eq 13 })).Count
$lf = (@($b | Where-Object { $_ -eq 10 })).Count
Write-Host ("CRLF={0} LF={1} 字节={2}" -f $cr, $lf, $b.Length)
