Add-Type -Namespace W -Name E -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint FormatMessage(uint flags, IntPtr src, uint code, uint lang, System.Text.StringBuilder buf, uint size, IntPtr args);' | Out-Null
$lines = foreach ($c in 1057, 1060, 1061, 1062, 1063, 1067, 1069, 1072, 1073, 1076, 1077, 1078, 1079) {
  $sb = New-Object System.Text.StringBuilder 600
  $r = [W.E]::FormatMessage(0x1000 + 0x200, [IntPtr]0, [uint32]$c, 1033, $sb, [uint32]$sb.Capacity, [IntPtr]0)
  $txt = if ($r -gt 0) { $sb.ToString().Trim() } else { '(no message)' }
  '{0,-12} 0x{1:X8} => {2}' -f $c, $c, $txt
}
$lines | Set-Content -Encoding UTF8 (Join-Path $PSScriptRoot 'errtext.txt')
$lines | ForEach-Object { Write-Host $_ }

